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
    LParen,
    RParen,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    // Step by char, not by byte: a continuation byte decoded on its own can
    // look like whitespace (`∅`, U+2205, ends in `0x85`, U+0085 NEL), and
    // slicing the word at that byte would split a char boundary and panic.
    // Every delimiter and whitespace test below is ASCII, and no ASCII byte
    // appears inside a multi-byte sequence, so byte comparisons stay valid.
    while i < b.len() {
        let c = src[i..].chars().next().expect("i is a char boundary");
        let clen = c.len_utf8();
        if c.is_whitespace() {
            i += clen;
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
        } else if c == '(' {
            out.push(Tok::LParen);
            i += 1;
        } else if c == ')' {
            out.push(Tok::RParen);
            i += 1;
        } else {
            let start = i;
            while i < b.len() {
                let d = src[i..].chars().next().expect("i is a char boundary");
                if d.is_whitespace() || d == '"' || d == ':' || d == '=' || d == '(' || d == ')' {
                    break;
                }
                i += d.len_utf8();
            }
            out.push(Tok::Word(src[start..i].to_string()));
        }
    }
    Ok(out)
}

/// Canonical keyword for a DSL op, for diagnostics.
fn op_word(op: Op) -> &'static str {
    match op {
        Op::Exec => "exec",
        Op::Read => "read",
        Op::Open => "open",
        Op::Write => "write",
        Op::Unlink => "unlink",
        Op::Connect => "connect",
        Op::Recv => "recv",
    }
}

/// Canonical keyword for a target kind, for diagnostics.
fn kind_word(kind: Kind) -> &'static str {
    match kind {
        Kind::File => "file",
        Kind::Endpoint => "endpoint",
        Kind::Exec => "exec",
    }
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
        let want = match op {
            Op::Exec => Kind::Exec,
            Op::Read | Op::Write | Op::Unlink | Op::Open => Kind::File,
            Op::Connect | Op::Recv => Kind::Endpoint,
        };
        if kind != want {
            return Err(format!(
                "`{}` targets require the `{}` kind, got `{}`",
                op_word(op),
                kind_word(want),
                kind_word(kind)
            ));
        }
        let mut pattern = self.string()?;
        // Normalize a bare exec name to the globstar form, so `exec "git"` and
        // `exec "**/git"` are the same pattern everywhere downstream (notably in
        // the `target_pattern` metadata that policy-approval signatures compare).
        // This does NOT decide the kernel matcher: `lower_exec` reduces every
        // exec pattern to its final path segment, so `exec "/usr/bin/git"` also
        // lowers to `EXACT "git"` and the directory is never enforced.
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

    /// `expr := term (("and"|"or") term)*`, so the two connectives have equal
    /// precedence and associate to the left: `A or B and C` is `(A or B) and C`.
    /// Parentheses override this, which is the readable form for a mixed
    /// condition (`A or (B and C)`); see `docs/rule-language.md` §1.8 and §2.
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
    /// `term := ["not"] IDENT | "true" | "(" expr ")"`. A parenthesized group is
    /// returned as-is (no wrapper node), so `if (A)` and `if A` lower to the same
    /// label set. `not` still binds a single identifier, because `Expr::Not`
    /// carries a label name rather than a sub-expression: `not (A or B)` is
    /// spelled `not A and not B`.
    fn term(&mut self) -> Result<Expr, String> {
        if self.is_word("not") {
            self.next();
            if matches!(self.peek(), Some(Tok::LParen)) {
                return Err(
                    "`not` binds a single label, so `not (...)` is not accepted; write the negation of each label, as in `not A and not B`".into(),
                );
            }
            Ok(Expr::Not(self.word()?))
        } else if self.is_word("true") {
            self.next();
            Ok(Expr::True)
        } else if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            let inner = self.expr()?;
            match self.next() {
                Some(Tok::RParen) => Ok(inner),
                o => Err(format!("expected ')', got {:?}", o)),
            }
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
                // Optional positional argument, mirroring `op_pattern`/`since_event`.
                // A `Tok::Str` can only be the gate arg here: `exits` and `since`
                // are words, so this never swallows them.
                let gate_arg = if matches!(self.peek(), Some(Tok::Str(_))) {
                    Some(self.string()?)
                } else {
                    None
                };
                if gate_arg.is_some() && gate_op != Op::Exec {
                    return Err("a gate argument is only valid on `after exec` gates".into());
                }
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
                            let a = self.string()?;
                            if op != Op::Exec {
                                return Err("a gate argument is only valid on `exec` gates".into());
                            }
                            Some(a)
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
                    gate_arg,
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
                let mut reason: Option<String> = None;
                while let Some(Tok::Word(w)) = p.peek() {
                    if P::clause_effect(w).is_some() {
                        let mut clause = p.clause()?;
                        clause.source_index = clauses.len();
                        clauses.push(clause);
                    } else if w == "because" {
                        p.next();
                        let text = p.string()?;
                        // The grammar carries at most one `because` per rule
                        // (`clause+ ["because" STRING]`), and the string is the
                        // whole corrective-feedback payload. A second one used
                        // to overwrite the first in silence, so the agent was
                        // told why the rule that actually matched stopped it
                        // only if the last-written reason happened to say so.
                        if let Some(first) = &reason {
                            return Err(format!(
                                "rule `{name}` has more than one `because`; the grammar allows one per rule, and each string is the reason forwarded to the agent on a match. The first is `{}`, the second `{}`. Merge them into a single string if both belong, or split the rule so each carries the reason for its own clauses.",
                                first, text
                            ));
                        }
                        reason = Some(text);
                    } else {
                        break;
                    }
                }
                if clauses.is_empty() {
                    return Err(format!(
                        "rule `{name}` has no clauses; the grammar requires at least one (`clause+`), and a clause-less rule lowers to zero kernel matchers"
                    ));
                }
                if pol.rules.iter().any(|rule| rule.name == name) {
                    return Err(format!("duplicate rule name `{name}`"));
                }
                pol.rules.push(Rule {
                    name,
                    clauses,
                    reason: reason.unwrap_or_default(),
                });
            }
            other => return Err(format!("unknown declaration '{}'", other)),
        }
    }
    Ok(pol)
}
