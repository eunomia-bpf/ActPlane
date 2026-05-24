/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 eunomia-bpf org. */
#ifndef __TAINT_H
#define __TAINT_H

/*
 * ActPlane in-kernel taint model (full design, see docs/taint-dsl.md).
 *
 * Taint state is a u64 label set per node (process / file / endpoint). The
 * Rust collector compiles the DSL down to the flat tables below; the kernel
 * propagates labels and evaluates the rules. This header holds the libc/libbpf-
 * free *matching predicates* shared by the eBPF program and the unit tests
 * (test_taint.c); the map-bearing engine is taint_engine.bpf.h.
 *
 * Constructs supported (per taint-dsl.md):
 *   - object + subject sources                          (struct taint_source)
 *   - sinks with boolean label masks (req AND, forbid NOT) and conditions
 *     (lineage-includes / after / target-scope)         (struct taint_rule)
 *   - declassify / endorse on a gate exec               (struct taint_xform)
 *   - lineage/temporal gates                            (struct taint_gate)
 * Globs are lowered to exact/prefix by the compiler; the kernel matches
 * exact (comm) or prefix (path / IPv4 dotted / host).
 */

#if defined(__clang__)
/* Keep the string-match loops as real backedge loops, NOT unrolled. A constant
 * trip count (TAINT_PAT_LEN) would otherwise be fully unrolled; the verifier then
 * re-walks every unrolled copy over symbolic input (path/argv), and the per-rule
 * cost explodes past the 1M-insn limit at >1 rule. As bounded loops the body is
 * verified once with state pruning. */
#define TAINT_UNROLL _Pragma("clang loop unroll(disable)")
#else
#define TAINT_UNROLL
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
/* taint_match is inlined on purpose: the rule's match `kind` and pattern are
 * frozen rodata (concrete to the verifier), so inlining lets the verifier resolve
 * the kind switch to the single matcher a rule actually uses and skip the others.
 * As a noinline subprogram it would instead be verified generically with a
 * symbolic kind — walking ALL four matchers (incl. taint_suffix's symbolic strlen)
 * on every rule, which is what exhausted the 1M-insn budget. Combined with the
 * branchless matchers below (no per-byte state fork on symbolic input), this keeps
 * the per-rule cost tiny so the full ruleset loads. */
#ifndef TAINT_NOINLINE
#define TAINT_NOINLINE __attribute__((noinline))
#endif

#define TAINT_PAT_LEN     64
#define TAINT_ARG_LEN     24
#define TAINT_ARGV_CAP    64   /* must be a power of two; bounds argv scan */
#define TAINT_COMM_LEN    16   /* matches TASK_COMM_LEN */
#define MAX_TAINT_LABELS  64   /* labels are a u64 bitmask */
#define MAX_TAINT_SOURCES 32
#define MAX_TAINT_RULES   32
#define MAX_TAINT_XFORMS  16
#define MAX_TAINT_GATES   16
#define TAINT_LABEL_NONE  0ULL

enum taint_match {
	TAINT_MATCH_EXACT  = 0,
	TAINT_MATCH_PREFIX = 1,
	TAINT_MATCH_SUFFIX = 2, /* text ends with pat (dotfiles, host suffixes) */
	TAINT_MATCH_ANY    = 3, /* always matches (the bare star) */
};

/* source kinds: what touching the node taints, and which node */
enum taint_src_kind {
	TSRC_EXEC     = 0, /* process that execs PAT acquires label */
	TSRC_FILE     = 1, /* file matching PAT intrinsically has label (reader gets it) */
	TSRC_ENDPOINT = 2, /* endpoint matching PAT has label (receiver gets it) */
};

/* sink operations */
enum taint_op {
	TOP_EXEC    = 0, /* exec comm */
	TOP_OPEN    = 1, /* open/read path */
	TOP_WRITE   = 2, /* write/unlink/rename path (mutation) */
	TOP_CONNECT = 3, /* connect host/ip */
};

/* unless-condition kinds */
enum taint_cond {
	TCOND_NONE    = 0,
	TCOND_LINEAGE = 1, /* allowed if gate bit set in lineage (ancestor) mask */
	TCOND_AFTER   = 2, /* allowed if gate bit set in session mask */
	TCOND_TARGET  = 3, /* allowed if object matches cond_pat (neg flips) */
};

/* rule result */
enum taint_effect {
	TEFFECT_AUDIT = 0, /* report only */
	TEFFECT_BLOCK = 1, /* deny at LSM when available */
	TEFFECT_KILL  = 2, /* send SIGKILL to the current task */
};

struct taint_source {
	unsigned char kind;   /* enum taint_src_kind */
	unsigned char match;  /* enum taint_match */
	char pat[TAINT_PAT_LEN];
	unsigned long long label;
	unsigned int ipv4;      /* TSRC_ENDPOINT: network-order IP, matched as */
	unsigned int ipv4_mask; /* (ip & ipv4_mask) == ipv4 */
};

struct taint_rule {
	unsigned char op;         /* enum taint_op */
	unsigned char match;      /* enum taint_match (target) */
	unsigned char cond_kind;  /* enum taint_cond */
	unsigned char cond_neg;   /* for TCOND_TARGET: invert the match */
	unsigned char cond_match; /* enum taint_match for cond_pat */
	unsigned char effect;     /* enum taint_effect */
	char target[TAINT_PAT_LEN];
	char arg[TAINT_ARG_LEN];  /* exec @arg token, "" = ignore */
	char cond_pat[TAINT_PAT_LEN];
	unsigned long long req;    /* all these label bits must be set */
	unsigned long long forbid; /* none of these may be set */
	unsigned long long gate;   /* gate bit for LINEAGE/AFTER */
	unsigned int rule_id;
	/* TOP_CONNECT: numeric IPv4 match (avoids in-kernel string formatting) */
	unsigned int ipv4;
	unsigned int ipv4_mask;
	unsigned int cond_ipv4;      /* TCOND_TARGET on connect */
	unsigned int cond_ipv4_mask;
};

struct taint_xform {
	unsigned char match;
	unsigned char add; /* 1 = endorse (add label), 0 = declassify (remove) */
	char gate[TAINT_PAT_LEN];
	unsigned long long label;
};

struct taint_gate {
	unsigned char match;
	char pat[TAINT_PAT_LEN]; /* exec matching this sets `bit` in lineage+session */
	unsigned long long bit;
};

/* Compiled policy, the ABI between the Rust DSL compiler and the C loader.
 * The compiler writes exactly sizeof(struct taint_config) bytes; the loader
 * freads it and copies the tables into the BPF rodata. Both sides are repr(C)
 * with identical field order/types/sizes. */
struct taint_config {
	unsigned int n_sources;
	unsigned int n_rules;
	unsigned int n_xforms;
	unsigned int n_gates;
	struct taint_source sources[MAX_TAINT_SOURCES];
	struct taint_rule rules[MAX_TAINT_RULES];
	struct taint_xform xforms[MAX_TAINT_XFORMS];
	struct taint_gate gates[MAX_TAINT_GATES];
};

/* ---- pure matching predicates (pattern side is volatile: it lives in rodata
 * in the kernel; tests pass plain pointers, which convert fine) ---- */

/* exact compare up to TAINT_PAT_LEN, NUL-terminated either side.
 *
 * Branchless w.r.t. the *input* `a`: the only data-dependent branch is on `b`,
 * which is the rule pattern (frozen rodata, concrete to the verifier), so it
 * resolves at verification time. Comparing the symbolic input with an XOR
 * accumulator instead of a per-char `if` avoids the state fork on every byte
 * that otherwise exploded verifier complexity per rule. Reads of `a` are bounded
 * by `b`'s NUL, so callers need not zero-pad `a` to TAINT_PAT_LEN. */
static TAINT_NOINLINE int taint_streq(const char *a, const char *b)
{
	long diff = 0;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		char cb = b[i];
		diff |= (unsigned char)(a[i] ^ cb);
		if (cb == '\0')   /* branch on the concrete pattern byte only */
			break;
	}
	return diff == 0;
}

/* does `text` start with non-empty `pre`? Branchless on `text` (see taint_streq). */
static TAINT_NOINLINE int taint_prefix(const char *text, const char *pre)
{
	long diff = 0;
	if (pre[0] == '\0')
		return 0;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		char cp = pre[i];
		if (cp == '\0')   /* concrete pattern byte: prefix consumed */
			break;
		diff |= (unsigned char)(text[i] ^ cp);
	}
	return diff == 0;
}

/* does `text` end with non-empty `suf`? bounded to TAINT_PAT_LEN. Uses explicit
 * bound guards (not index masking, which makes clang emit a verifier-rejected
 * pointer-OR). */
static TAINT_NOINLINE int taint_suffix(const char *text, const char *suf)
{
	int tn = 0, sn = 0;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		if (!text[i]) break;
		tn++;
	}
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		if (!suf[i]) break;
		sn++;
	}
	if (sn == 0 || sn > tn)
		return 0;
	int off = tn - sn; /* >= 0, < TAINT_PAT_LEN */
	/* Branchless compare over the symbolic tail: branch only on the concrete
	 * `suf` byte (resolves at verify) and the bound guard; accumulate the input
	 * difference with XOR instead of a per-char `if` to avoid per-byte state
	 * forks (the cost that limited how many rules could load). */
	long diff = 0;
	TAINT_UNROLL
	for (int j = 0; j < TAINT_PAT_LEN; j++) {
		if (j >= sn)
			break;
		int ti = off + j;
		if (ti < 0 || ti >= TAINT_PAT_LEN)
			return 0;
		diff |= (unsigned char)(text[ti] ^ suf[j]);
	}
	return diff == 0;
}

static __always_inline int taint_match(unsigned int kind, const char *text,
				       const char *pat)
{
	switch (kind) {
	case TAINT_MATCH_PREFIX: return taint_prefix(text, pat);
	case TAINT_MATCH_SUFFIX: return taint_suffix(text, pat);
	case TAINT_MATCH_ANY:    return 1;
	default:                 return taint_streq(text, pat);
	}
}

/* boolean label predicate: required bits all set, forbidden bits all clear */
static __always_inline int taint_mask_ok(unsigned long long labels,
					 unsigned long long req,
					 unsigned long long forbid)
{
	return (labels & req) == req && (labels & forbid) == 0ULL;
}

/* is `tok` (NUL-terminated) present as a whole token in the NUL-separated argv
 * blob `argv` (length `argv_len`, capacity TAINT_ARGV_CAP)? "" matches anything.
 * Indices are masked to TAINT_ARGV_CAP so the verifier sees bounded access. */
/* Is `tok` present as a whole NUL-delimited token in the argv blob? "" matches
 * anything. Single linear pass over argv (O(TAINT_ARGV_CAP)), not a restart-at-
 * every-position O(cap*arglen) scan: argv is symbolic user data, so the nested
 * version's branching exploded verifier state and only ~1 @arg rule could load
 * before -E2BIG. This walks each byte once, tracking whether the current token
 * still matches tok and confirming the match at the token boundary (NUL). */
static TAINT_NOINLINE int taint_arg_match(const char *argv, int argv_len,
					   const char *tok)
{
	int j = 0;        /* compare position within tok for the current token */
	int live = 1;     /* current token still a prefix-match of tok */
	int started = 0;  /* have we consumed any byte of the current token */

	if (tok[0] == '\0')
		return 1;
	if (argv_len > TAINT_ARGV_CAP)
		argv_len = TAINT_ARGV_CAP;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_ARGV_CAP; i++) {
		if (i >= argv_len)
			break;
		char c = argv[i];
		if (c == '\0') {
			/* token boundary: full match iff we consumed tok exactly */
			if (started && live && tok[j] == '\0')
				return 1;
			j = 0;
			live = 1;
			started = 0;
			continue;
		}
		started = 1;
		if (live) {
			char tc = (j < TAINT_ARG_LEN) ? tok[j] : 'x';
			if (tc == '\0' || tc != c)
				live = 0;       /* token longer than / differs from tok */
			else
				j++;
		}
	}
	/* last token may not be NUL-terminated within the scanned window */
	if (started && live && tok[j] == '\0')
		return 1;
	return 0;
}

#endif /* __TAINT_H */
