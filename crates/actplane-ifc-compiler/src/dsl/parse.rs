// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//! Hand-rolled parser for the taint DSL (docs/rule-language.md §2).

use super::ast::*;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Colon,
    Eq,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
        } else if c == '#' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == '"' {
            i += 1;
            let start = i;
            while i < b.len() && b[i] != b'"' {
                i += 1;
            }
            if i >= b.len() {
                return Err("unterminated string".into());
            }
            out.push(Tok::Str(src[start..i].to_string()));
            i += 1;
        } else if c == ':' {
            out.push(Tok::Colon);
            i += 1;
        } else if c == '=' {
            out.push(Tok::Eq);
            i += 1;
        } else {
            let start = i;
            while i < b.len() {
                let d = b[i] as char;
                if d.is_whitespace() || d == '"' || d == ':' || d == '=' {
                    break;
                }
                i += 1;
            }
            out.push(Tok::Word(src[start..i].to_string()));
        }
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).cloned();
        self.i += 1;
        t
    }
    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x == w)
    }
    fn word(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            o => Err(format!("expected word, got {:?}", o)),
        }
    }
    fn string(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(s),
            o => Err(format!("expected string, got {:?}", o)),
        }
    }
    fn eat(&mut self, w: &str) -> Result<(), String> {
        match self.next() {
            Some(Tok::Word(x)) if x == w => Ok(()),
            o => Err(format!("expected '{}', got {:?}", w, o)),
        }
    }
    fn kind(w: &str) -> Result<Kind, String> {
        match w {
            "file" => Ok(Kind::File),
            "endpoint" => Ok(Kind::Endpoint),
            "exec" => Ok(Kind::Exec),
            _ => Err(format!("unknown kind '{}'", w)),
        }
    }
    fn op(w: &str) -> Result<Op, String> {
        match w {
            "exec" => Ok(Op::Exec),
            "read" => Ok(Op::Read),
            "write" => Ok(Op::Write),
            "unlink" => Ok(Op::Unlink),
            "connect" => Ok(Op::Connect),
            "recv" => Ok(Op::Recv),
            "open" => Ok(Op::Open),
            _ => Err(format!("unknown op '{}'", w)),
        }
    }

    fn target(&mut self, op: Op) -> Result<Target, String> {
        let kind = if let Some(Tok::Word(w)) = self.peek() {
            if w == "file" || w == "endpoint" || w == "exec" {
                let w = self.word()?;
                P::kind(&w)?
            } else {
                return Err(format!("expected kind in target, got '{}'", w));
            }
        } else if op == Op::Exec {
            Kind::Exec
        } else {
            return Err("expected node kind in target".into());
        };
        let mut pattern = self.string()?;
        // Implicit basename matching: if the pattern contains no '/', treat it
        // as a basename match by prepending "**/".
        if kind == Kind::Exec && !pattern.contains('/') {
            pattern = format!("**/{}", pattern);
        }
        // Positional arguments: additional quoted strings after the target
        // pattern are treated as arguments (replaces the old `@arg` syntax).
        let arg = if matches!(self.peek(), Some(Tok::Str(_))) {
            Some(self.string()?)
        } else {
            None
        };
        Ok(Target { kind, pattern, arg })
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut lhs = self.term()?;
        loop {
            if self.is_word("and") {
                self.next();
                lhs = Expr::And(Box::new(lhs), Box::new(self.term()?));
            } else if self.is_word("or") {
                self.next();
                lhs = Expr::Or(Box::new(lhs), Box::new(self.term()?));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn term(&mut self) -> Result<Expr, String> {
        if self.is_word("not") {
            self.next();
            Ok(Expr::Not(self.word()?))
        } else if self.is_word("true") {
            self.next();
            Ok(Expr::True)
        } else {
            Ok(Expr::Label(self.word()?))
        }
    }
    fn cond(&mut self) -> Result<Cond, String> {
        let w = self.word()?;
        match w.as_str() {
            "target" => {
                let negate = self.is_word("not");
                if negate {
                    self.next();
                }
                Ok(Cond::Target {
                    negate,
                    pattern: self.string()?,
                })
            }
            "lineage-includes" => {
                self.eat("exec")?;
                Ok(Cond::LineageIncludes {
                    exec: self.string()?,
                })
            }
            "after" => {
                let gate_op = P::op(&self.word()?)?;
                let gate_pattern = self.string()?;
                let gate_exit = if self.is_word("exits") {
                    self.next();
                    if gate_op != Op::Exec {
                        return Err("`exits` is only valid on `after exec` gates".into());
                    }
                    let raw = self.word()?;
                    let code: u8 = raw
                        .parse()
                        .map_err(|_| format!("expected exit code 0..255, got '{raw}'"))?;
                    Some(code)
                } else {
                    None
                };
                let mut since = Vec::new();
                if self.is_word("since") {
                    self.next();
                    loop {
                        let op = P::op(&self.word()?)?;
                        let pat = self.string()?;
                        let arg = if matches!(self.peek(), Some(Tok::Str(_))) {
                            Some(self.string()?)
                        } else {
                            None
                        };
                        since.push((op, pat, arg));
                        if self.is_word("or") {
                            self.next();
                        } else {
                            break;
                        }
                    }
                }
                Ok(Cond::After {
                    gate_op,
                    gate_pattern,
                    gate_exit,
                    since,
                })
            }
            _ => Err(format!("unknown unless cond '{}'", w)),
        }
    }
    fn clause_effect(w: &str) -> Option<Effect> {
        match w {
            "notify" => Some(Effect::Notify),
            "block" => Some(Effect::Block),
            "kill" => Some(Effect::Kill),
            _ => None,
        }
    }
    fn clause(&mut self) -> Result<Clause, String> {
        let verb = self.word()?;
        let effect = P::clause_effect(&verb)
            .ok_or_else(|| format!("expected 'notify', 'block', or 'kill', got '{}'", verb))?;
        let op = P::op(&self.word()?)?;
        let target = self.target(op)?;
        let when = if self.is_word("if") {
            self.next();
            self.expr()?
        } else {
            Expr::True
        };
        let unless = if self.is_word("unless") {
            self.next();
            Some(self.cond()?)
        } else {
            None
        };
        Ok(Clause {
            op,
            target,
            when,
            unless,
            effect,
            source_index: 0,
        })
    }
}

pub fn parse(src: &str) -> Result<Policy, String> {
    let mut p = P { t: lex(src)?, i: 0 };
    let mut pol = Policy::default();
    while let Some(tok) = p.peek().cloned() {
        let kw = match tok {
            Tok::Word(w) => w,
            o => return Err(format!("expected declaration, got {:?}", o)),
        };
        match kw.as_str() {
            "label" => {
                return Err("the `label` keyword has been removed; use `source` instead (e.g. `source AGENT = exec \"**/your-agent\"`)".into());
            }
            "source" => {
                p.next();
                let label = p.word()?;
                match p.next() {
                    Some(Tok::Eq) => {}
                    o => return Err(format!("expected '=' in source, got {:?}", o)),
                }
                let kind = P::kind(&p.word()?)?;
                let pattern = p.string()?;
                pol.sources.push(Source {
                    label,
                    kind,
                    pattern,
                });
            }
            "declassify" | "endorse" => {
                let endorse = kw == "endorse";
                p.next();
                let label = p.word()?;
                p.eat("by")?;
                p.eat("exec")?;
                let gate = p.string()?;
                pol.xforms.push(Xform {
                    endorse,
                    label,
                    gate,
                });
            }
            "rule" => {
                p.next();
                let name = p.word()?;
                match p.next() {
                    Some(Tok::Colon) => {}
                    o => return Err(format!("expected ':' after rule name, got {:?}", o)),
                }
                let mut clauses = Vec::new();
                let mut reason = String::new();
                while let Some(Tok::Word(w)) = p.peek() {
                    if P::clause_effect(w).is_some() {
                        let mut clause = p.clause()?;
                        clause.source_index = clauses.len();
                        clauses.push(clause);
                    } else if w == "because" {
                        p.next();
                        reason = p.string()?;
                    } else {
                        break;
                    }
                }
                if pol.rules.iter().any(|rule| rule.name == name) {
                    return Err(format!("duplicate rule name `{name}`"));
                }
                pol.rules.push(Rule {
                    name,
                    clauses,
                    reason,
                });
            }
            other => return Err(format!("unknown declaration '{}'", other)),
        }
    }
    Ok(pol)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> P {
        P {
            t: lex(s).unwrap(),
            i: 0,
        }
    }

    #[test]
    fn clause_assembles_effect_op_target_guard_and_unless() {
        // `clause` parses a single rule clause: an action verb (`notify` /
        // `block` / `kill`) that fixes the `Effect`, then the op, target, an
        // optional `if` guard, and an optional `unless` condition. `clause`
        // itself sets `source_index: 0`; the enclosing rule re-stamps it.
        // No test in any open or merged branch pins this assembly directly.
        let c = |s: &str| p(s).clause().expect("clause parses");

        // A bare clause omits both `if` and `unless`.
        assert_eq!(
            c("block exec \"git\""),
            Clause {
                op: Op::Exec,
                target: Target {
                    kind: Kind::Exec,
                    pattern: "**/git".into(),
                    arg: None,
                },
                when: Expr::True,
                unless: None,
                effect: Effect::Block,
                source_index: 0,
            }
        );

        // A full clause carries the `if` guard and an `unless` condition; the
        // verb maps to its `Effect`.
        assert_eq!(
            c("notify open file \"/etc/hosts\" if NET unless target not \"10.0.0.0\""),
            Clause {
                op: Op::Open,
                target: Target {
                    kind: Kind::File,
                    pattern: "/etc/hosts".into(),
                    arg: None,
                },
                when: Expr::Label("NET".into()),
                unless: Some(Cond::Target {
                    negate: true,
                    pattern: "10.0.0.0".into(),
                }),
                effect: Effect::Notify,
                source_index: 0,
            }
        );

        // Each action verb maps to its own `Effect`.
        assert_eq!(c("kill exec \"rm\"").effect, Effect::Kill);

        // A verb that is not an action verb is rejected, naming the word.
        let bad = p("deny exec \"git\"").clause();
        assert_eq!(
            bad.err().as_deref(),
            Some("expected 'notify', 'block', or 'kill', got 'deny'")
        );
    }

    #[test]
    fn clause_effect_classifies_only_the_three_action_verbs() {
        // `P::clause_effect` maps the clause head verb to its `Effect`,
        // accepting exactly the three action verbs (`notify`, `block`,
        // `kill`) and rejecting everything else. No test in any open or
        // merged branch pins this verb-to-effect classification directly.
        assert_eq!(P::clause_effect("notify"), Some(Effect::Notify));
        assert_eq!(P::clause_effect("block"), Some(Effect::Block));
        assert_eq!(P::clause_effect("kill"), Some(Effect::Kill));

        // The match is case-sensitive and vocabulary-closed: a capitalized
        // form, a non-verb, and the empty string all classify to `None`.
        assert_eq!(P::clause_effect("Kill"), None);
        assert_eq!(P::clause_effect("deny"), None);
        assert_eq!(P::clause_effect(""), None);
    }

    fn p_c2(s: &str) -> P {
        P {
            t: lex(s).unwrap(),
            i: 0,
        }
    }

    #[test]
    fn expr_folds_guard_terms_left_associatively_without_precedence() {
        // `expr` parses the `when` guard: a `term` (a `not <label>` / `true`
        // / bare label) folded left-to-right over `and`/`or`. The two
        // operators share a single precedence level, so `and` does not bind
        // tighter than `or`; each folds into a left-associative tree. No
        // test in any open or merged branch pins this fold shape directly.
        let e = |s: &str| p_c2(s).expr().expect("guard parses");

        assert_eq!(e("A"), Expr::Label("A".into()));
        assert_eq!(e("true"), Expr::True);
        assert_eq!(e("not X"), Expr::Not("X".into()));
        assert_eq!(
            e("A and B"),
            Expr::And(
                Box::new(Expr::Label("A".into())),
                Box::new(Expr::Label("B".into()))
            )
        );

        // `and` and `or` are the same precedence: `A and B or C` parses as
        // `Or(And(A, B), C)`, not `Or(A, And(B, C))` and not a precedence
        // tree.
        assert_eq!(
            e("A and B or C"),
            Expr::Or(
                Box::new(Expr::And(
                    Box::new(Expr::Label("A".into())),
                    Box::new(Expr::Label("B".into())),
                )),
                Box::new(Expr::Label("C".into())),
            )
        );

        // Three `and`s nest left-associatively.
        assert_eq!(
            e("A and B and C"),
            Expr::And(
                Box::new(Expr::And(
                    Box::new(Expr::Label("A".into())),
                    Box::new(Expr::Label("B".into())),
                )),
                Box::new(Expr::Label("C".into())),
            )
        );
    }

    #[test]
    fn lex_emits_word_str_colon_eq_and_drops_comments() {
        // `lex` is the pure front-end of the DSL: it turns a policy string
        // into a flat token stream of `Word`, `Str`, `Colon`, and `Eq`
        // tokens, skipping whitespace runs and `#`-to-end-of-line comments.
        // No test in any open or merged branch pins the tokenizer's output
        // stream directly.
        assert_eq!(
            lex("source SECRET = file \"**/.env\""),
            Ok(vec![
                Tok::Word("source".to_string()),
                Tok::Word("SECRET".to_string()),
                Tok::Eq,
                Tok::Word("file".to_string()),
                Tok::Str("**/.env".to_string()),
            ])
        );

        // Whitespace runs and a `#` comment contribute no tokens; a `:` is
        // its own token.
        assert_eq!(
            lex("  rule guard:\n# a comment\n"),
            Ok(vec![
                Tok::Word("rule".to_string()),
                Tok::Word("guard".to_string()),
                Tok::Colon,
            ])
        );

        // A `:` mid-word and an `=` each split into separate tokens.
        assert_eq!(
            lex("a:b = c"),
            Ok(vec![
                Tok::Word("a".to_string()),
                Tok::Colon,
                Tok::Word("b".to_string()),
                Tok::Eq,
                Tok::Word("c".to_string()),
            ])
        );

        // A string literal without a closing quote is a lex error.
        assert_eq!(
            lex("foo \"bar").err().as_deref(),
            Some("unterminated string")
        );
    }

    #[test]
    fn kind_maps_all_three_kind_spellings_to_their_variants() {
        // `P::kind` maps the source-kind verb to its `Kind` variant,
        // accepting exactly the three kind spellings and rejecting anything
        // else with a message that echoes the offending word. No test in any
        // open or merged branch pins this verb-to-kind mapping directly.
        for (w, k) in [
            ("file", Kind::File),
            ("endpoint", Kind::Endpoint),
            ("exec", Kind::Exec),
        ] {
            assert_eq!(P::kind(w).unwrap(), k);
        }

        // An unknown kind is an error whose message carries the offending word.
        assert_eq!(P::kind("socket").unwrap_err(), "unknown kind 'socket'");
        assert_eq!(P::kind("").unwrap_err(), "unknown kind ''");
    }

    #[test]
    fn op_maps_all_seven_verb_spelling_to_its_variant() {
        // `P::op` maps the op verb to its `Op` variant, accepting exactly the
        // seven op spellings and rejecting anything else with a message that
        // echoes the offending word. No test in any open or merged branch
        // pins this verb-to-op mapping directly.
        for (w, op) in [
            ("exec", Op::Exec),
            ("read", Op::Read),
            ("write", Op::Write),
            ("unlink", Op::Unlink),
            ("connect", Op::Connect),
            ("recv", Op::Recv),
            ("open", Op::Open),
        ] {
            assert_eq!(P::op(w).unwrap(), op);
        }

        // An unknown verb is an error whose message carries the offending word.
        assert_eq!(P::op("chmod").unwrap_err(), "unknown op 'chmod'");
        assert_eq!(P::op("").unwrap_err(), "unknown op ''");
    }

    #[test]
    fn parse_builds_the_full_policy_ast_from_sources_xforms_and_rules() {
        // `parse` is the public front-end of the DSL: a policy string becomes
        // a `Policy` of `Source`/`Xform`/`Rule`/`Clause` nodes. No test in
        // any open or merged branch pins the parsed `Policy` structure
        // directly; lower.rs only ever forwards `parse` into `compile` and
        // asserts on the lowered `Compiled` blob.
        let src = r#"
            source AGENT = exec "**/agent"
            source NET = endpoint "10.0.0.0"
            declassify NET by exec "**/sanitize"
            rule guard:
              block exec "git" "refactor" if AGENT and NET unless target "10.0.0.0"
              because "no egress"
        "#;
        let got = parse(src).expect("multi-construct policy parses");
        assert_eq!(
            got,
            Policy {
                labels: Vec::new(),
                sources: vec![
                    Source {
                        label: "AGENT".into(),
                        kind: Kind::Exec,
                        pattern: "**/agent".into(),
                    },
                    Source {
                        label: "NET".into(),
                        kind: Kind::Endpoint,
                        pattern: "10.0.0.0".into(),
                    },
                ],
                rules: vec![Rule {
                    name: "guard".into(),
                    clauses: vec![Clause {
                        op: Op::Exec,
                        target: Target {
                            kind: Kind::Exec,
                            pattern: "**/git".into(),
                            arg: Some("refactor".into()),
                        },
                        when: Expr::And(
                            Box::new(Expr::Label("AGENT".into())),
                            Box::new(Expr::Label("NET".into())),
                        ),
                        unless: Some(Cond::Target {
                            negate: false,
                            pattern: "10.0.0.0".into(),
                        }),
                        effect: Effect::Block,
                        source_index: 0,
                    }],
                    reason: "no egress".into(),
                }],
                xforms: vec![Xform {
                    endorse: false,
                    label: "NET".into(),
                    gate: "**/sanitize".into(),
                }],
            }
        );

        // A second positional string after the target arg is not consumed and
        // surfaces as an "expected declaration" lex/parse error.
        let stray = parse("rule x:\n  block exec \"git\" \"a\" \"b\"");
        assert_eq!(
            stray.err().as_deref(),
            Some("expected declaration, got Str(\"b\")")
        );

        // Re-declaring a rule name is rejected with the offending name.
        let dup = parse("rule x:\n  block exec \"git\" because \"r\"\nrule x:\n  block exec \"g\"");
        assert_eq!(dup.err().as_deref(), Some("duplicate rule name `x`"));
    }

    fn parser(tokens: Vec<Tok>) -> P {
        P { t: tokens, i: 0 }
    }

    #[test]
    fn term_parses_not_true_and_bare_label_atoms() {
        // `term` is the lowest-precedence expression layer lifted by `expr`:
        // it recognizes `not <word>` negation, the `true` literal, and a bare
        // label word. No base or branch test calls `term` directly.

        let mut p = parser(vec![Tok::Word("not".into()), Tok::Word("SECRET".into())]);
        assert_eq!(p.term().unwrap(), Expr::Not("SECRET".to_string()));

        let mut p = parser(vec![Tok::Word("true".into())]);
        assert_eq!(p.term().unwrap(), Expr::True);

        let mut p = parser(vec![Tok::Word("AGENT".into())]);
        assert_eq!(p.term().unwrap(), Expr::Label("AGENT".to_string()));

        // `not` consumes the following word verbatim, even a reserved spelling.
        let mut p = parser(vec![Tok::Word("not".into()), Tok::Word("true".into())]);
        assert_eq!(p.term().unwrap(), Expr::Not("true".to_string()));

        // A non-word token is not a valid atom, and `not` needs a word.
        let mut p = parser(vec![Tok::Colon]);
        assert!(p.term().is_err());
        let mut p = parser(vec![Tok::Word("not".into())]);
        assert!(p.term().is_err());
    }

    fn p_c3(s: &str) -> P {
        P {
            t: lex(s).unwrap(),
            i: 0,
        }
    }

    #[test]
    fn target_prefixes_exec_basenames_and_captures_positional_args() {
        // `target` parses a clause target: an optional kind word, a quoted
        // pattern, and an optional quoted positional argument. No test in
        // any open or merged branch pins these `Target` shapes directly.
        let t = |s: &str, op: Op| p_c3(s).target(op).expect("target parses");

        // file/endpoint targets keep their patterns verbatim.
        assert_eq!(
            t("file \"/etc/passwd\"", Op::Read),
            Target {
                kind: Kind::File,
                pattern: "/etc/passwd".into(),
                arg: None,
            }
        );
        assert_eq!(
            t("endpoint \"10.0.0.0\"", Op::Connect),
            Target {
                kind: Kind::Endpoint,
                pattern: "10.0.0.0".into(),
                arg: None,
            }
        );

        // An exec target whose pattern has no `/` is a basename match,
        // implicit-prefixed with `**/`.
        assert_eq!(
            t("exec \"git\"", Op::Exec),
            Target {
                kind: Kind::Exec,
                pattern: "**/git".into(),
                arg: None,
            }
        );

        // A trailing quoted string after the target pattern is the positional
        // argument; the basename prefix still applies to the pattern.
        assert_eq!(
            t("exec \"git\" \"refactor\"", Op::Exec),
            Target {
                kind: Kind::Exec,
                pattern: "**/git".into(),
                arg: Some("refactor".into()),
            }
        );

        // A full path (contains `/`) is not prefixed.
        assert_eq!(
            t("exec \"/usr/bin/git\"", Op::Exec),
            Target {
                kind: Kind::Exec,
                pattern: "/usr/bin/git".into(),
                arg: None,
            }
        );

        // The kind word may be omitted only for an exec op, where it
        // defaults to `exec`.
        assert_eq!(
            t("\"git\"", Op::Exec),
            Target {
                kind: Kind::Exec,
                pattern: "**/git".into(),
                arg: None,
            }
        );

        // Omitting the kind word on a non-exec op is an error.
        let missing_kind = p_c3("\"f\"").target(Op::Open);
        assert_eq!(
            missing_kind.err().as_deref(),
            Some("expected node kind in target")
        );
    }

    fn mk(s: &str) -> P {
        P {
            t: lex(s).unwrap(),
            i: 0,
        }
    }

    #[test]
    fn peek_next_is_word_word_string_eat_walk_the_token_stream() {
        // The P instance methods are the low-level cursor/verb contracts every
        // higher parser builds on. No test in any open or merged branch pins
        // them directly.

        // `peek` reports the current token without consuming; `next` clones
        // and advances.
        let mut p = mk("a");
        assert_eq!(p.peek(), Some(&Tok::Word("a".into())));
        assert_eq!(p.next(), Some(Tok::Word("a".into())));
        assert_eq!(p.peek(), None);

        // `is_word` matches the current token against an exact word.
        let p = mk("a");
        assert!(p.is_word("a"));
        assert!(!p.is_word("b"));
        assert!(!mk("").is_word("a"));

        // `word` consumes a `Word` token and errors on a non-word, naming the
        // offending token.
        let mut p = mk("x y");
        assert_eq!(p.word(), Ok("x".into()));
        assert_eq!(p.peek(), Some(&Tok::Word("y".into())));
        assert_eq!(
            mk("\"a\"").word(),
            Err("expected word, got Some(Str(\"a\"))".into())
        );
        assert_eq!(mk("").word(), Err("expected word, got None".into()));

        // `string` consumes a `Str` token and errors on a non-string.
        let mut p = mk("\"s\"");
        assert_eq!(p.string(), Ok("s".into()));
        assert_eq!(
            mk("w").string(),
            Err("expected string, got Some(Word(\"w\"))".into())
        );

        // `eat` only succeeds when the current token is the exact word.
        let mut p = mk("k");
        assert_eq!(p.eat("k"), Ok(()));
        let mut p = mk("k");
        assert_eq!(
            p.eat("z"),
            Err("expected 'z', got Some(Word(\"k\"))".into())
        );
        // A same-text string is not the word.
        let mut p = mk("\"q\"");
        assert_eq!(p.eat("q"), Err("expected 'q', got Some(Str(\"q\"))".into()));
    }

    fn p_c4(s: &str) -> P {
        P {
            t: lex(s).unwrap(),
            i: 0,
        }
    }

    #[test]
    fn cond_parses_every_unless_condition_variant() {
        // `cond` parses the `unless` condition following an `unless` keyword:
        // `target ["not"] <pat>`, `lineage-includes exec <pat>`, or
        // `after <op> <pat> ["exits" N] ["since" ...]`. `Cond` is a plain
        // comparable AST node, so the parse result is assertable. No test in
        // any open or merged branch pins these `Cond` shapes directly.
        let c = |s: &str| p_c4(s).cond().expect("unless cond parses");

        // `target` carries a negation flag; a bare `target` does not negate.
        assert_eq!(
            c("target \"10.0.0.0\""),
            Cond::Target {
                negate: false,
                pattern: "10.0.0.0".into(),
            }
        );
        assert_eq!(
            c("target not \"10.0.0.0\""),
            Cond::Target {
                negate: true,
                pattern: "10.0.0.0".into(),
            }
        );

        // `lineage-includes` requires a literal `exec` keyword before the
        // pattern.
        assert_eq!(
            c("lineage-includes exec \"git\""),
            Cond::LineageIncludes { exec: "git".into() }
        );

        // `after` carries an optional gate-exit code and a `since` event
        // list; without them the gate uses v1 latching semantics.
        assert_eq!(
            c("after exec \"git\""),
            Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "git".into(),
                gate_exit: None,
                since: Vec::new(),
            }
        );

        // `exits N` stamps an exit code on an exec gate.
        assert_eq!(
            c("after exec \"git\" exits 3"),
            Cond::After {
                gate_op: Op::Exec,
                gate_pattern: "git".into(),
                gate_exit: Some(3),
                since: Vec::new(),
            }
        );

        // `since` chains (op, pattern, arg) events, split on `or`.
        assert_eq!(
            c("after open \"f\" since exec \"git\" or exec \"go\""),
            Cond::After {
                gate_op: Op::Open,
                gate_pattern: "f".into(),
                gate_exit: None,
                since: vec![
                    (Op::Exec, "git".into(), None),
                    (Op::Exec, "go".into(), None)
                ],
            }
        );

        // `exits` is rejected on a non-exec gate, with a message that names
        // the restriction.
        let bad = p_c4("after open \"f\" exits 3").cond();
        assert_eq!(
            bad.err().as_deref(),
            Some("`exits` is only valid on `after exec` gates")
        );
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    fn err(src: &str) -> String {
        parse(src).expect_err("expected a parse error")
    }

    #[test]
    fn parse_reports_positional_errors_in_declarations() {
        assert_eq!(
            err("source SECRET file \"**\""),
            "expected '=' in source, got Some(Word(\"file\"))"
        );
        assert_eq!(
            err("rule missing_colon\n  notify exec \"x\" if true\n"),
            "expected ':' after rule name, got Some(Word(\"notify\"))"
        );
    }

    #[test]
    fn parse_rejects_removed_and_unknown_declarations() {
        assert_eq!(
            err("label AGENT = exec \"**\""),
            "the `label` keyword has been removed; use `source` instead \
             (e.g. `source AGENT = exec \"**/your-agent\"`)"
        );
        assert_eq!(
            err("banana X = file \"**\""),
            "unknown declaration 'banana'"
        );
    }

    #[test]
    fn parse_rejects_a_dangling_guard_term() {
        // `or` past the end of the rule: the rhs term reads an absent token.
        assert_eq!(
            err("rule r:\n  notify exec \"x\" if COMMAND or\n"),
            "expected word, got None"
        );
    }

    #[test]
    fn parse_rejects_malformed_clause_tokens() {
        // A leading clause word that is not an action verb is not consumed by
        // the clause loop, so it reaches the declaration dispatcher.
        assert_eq!(
            err("rule r:\n  nonsense exec \"x\" if true\n  because \"r\"\n"),
            "unknown declaration 'nonsense'"
        );
        assert_eq!(
            err("rule r:\n  notify nonsense \"x\" if true\n  because \"r\"\n"),
            "unknown op 'nonsense'"
        );
        assert_eq!(
            err("rule r:\n  notify read file bool\n  because \"r\"\n"),
            "expected string, got Some(Word(\"bool\"))"
        );
        assert_eq!(
            err("rule r:\n  notify read\n"),
            "expected node kind in target"
        );
        assert_eq!(err("rule r:\n  notify exec\n"), "expected string, got None");
    }
}
