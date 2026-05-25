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
/* Real backedge loops, NOT unrolled: fully unrolling these branchless matchers
 * (TAINT_PAT_LEN iterations) blew the 512-byte BPF stack via register spills.
 * As bounded loops with a plain induction index a[i] (NOT a computed/symbolic
 * offset) and no data-dependent branches, each matcher is verified once, cheaply,
 * with small stack. Symbolic-offset reads (the aligned suffix tail, the argv
 * token window) are instead fetched with a single bounded TE_COPY, not a
 * per-byte dynamic read. */
#define TAINT_UNROLL _Pragma("clang loop unroll(disable)")
#else
#define TAINT_UNROLL
#endif
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
/* Copy `n` bytes from `src` to `dst`. In BPF a bounded helper read (lets the
 * aligned suffix tail be fetched at a runtime offset without a per-byte dynamic
 * read that would explode verifier state); in the unit tests, plain memcpy. */
#if defined(__bpf__)
#define TE_COPY(dst, n, src) bpf_probe_read_kernel((dst), (n), (src))
#else
#include <string.h>
#define TE_COPY(dst, n, src) memcpy((dst), (src), (n))
#endif
/* The individual matchers are noinline subprograms (verified once each), so the
 * force-unrolled bodies are NOT duplicated into every caller (which blew the BPF
 * stack). taint_match itself stays inline so a concrete `kind` resolves to a
 * single matcher call. */
#ifndef TAINT_NOINLINE
#define TAINT_NOINLINE __attribute__((noinline))
#endif

#define TAINT_PAT_LEN     64
#define TAINT_SUF_MAX     24   /* max suffix-match length (dotfiles/host suffixes are short) */
/* Text/path buffers feeding the matchers are over-allocated by TAINT_SUF_MAX so
 * taint_suffix's constant-size aligned-tail copy at any off < TAINT_PAT_LEN stays
 * in bounds. */
#define TAINT_TEXT_BUF    (TAINT_PAT_LEN + TAINT_SUF_MAX)
#define TAINT_ARG_LEN     24   /* max @arg token length / slot width */
#define TAINT_ARGV_CAP    128  /* bytes of the argv blob tokenized */
#define MAX_ARG_SLOTS     16   /* first N argv tokens kept for @arg matching */
#define TAINT_ARG_SLOTS_BUF (MAX_ARG_SLOTS * TAINT_ARG_LEN)
#define TAINT_COMM_LEN    16   /* matches TASK_COMM_LEN */
#define MAX_TAINT_LABELS  64   /* labels are a u64 bitmask */
/* Sized for 100+ rules in one policy. The rule loop runs via bpf_loop (callback
 * verified once), so these bounds cost program size/memory, not verifier budget. */
#define MAX_TAINT_SOURCES 128
#define MAX_TAINT_RULES   128
#define MAX_TAINT_XFORMS  64
#define MAX_TAINT_GATES   64
/* v2: `since` invalidators. `after exec X since Y` makes the X gate go stale
 * when a later Y-event (write/read/exec matching the invalidator) occurs in the
 * same session — the build-system "stale target" idea. Capped at 64 so the set
 * of invalidators that reset a given rule fits one u64 mask (since_mask). */
#define MAX_TAINT_INVALS  64
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
	TCOND_AFTER   = 2, /* allowed if gate fired; for `since`, also still fresh */
	TCOND_TARGET  = 3, /* allowed if object matches cond_pat (neg flips) */
};

/* v2 `since` invalidator: an event whose later occurrence makes a TCOND_AFTER
 * gate stale. op is the lowered taint_op (TOP_EXEC comm / TOP_OPEN read /
 * TOP_WRITE write); the engine stamps inval_epoch[i] when one matches. */
struct taint_inval {
	unsigned char op;    /* enum taint_op */
	unsigned char match; /* enum taint_match */
	char pat[TAINT_PAT_LEN];
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
	/* v2 staleness (TCOND_AFTER only). gate_idx is the gates[] slot of the X
	 * gate; since_mask is the set of invals[] slots (Y) that reset it. When
	 * since_mask == 0 the rule keeps v1 latching semantics (gate fired ever). */
	unsigned int gate_idx;
	unsigned long long since_mask;
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
	unsigned int n_invals;
	struct taint_source sources[MAX_TAINT_SOURCES];
	struct taint_rule rules[MAX_TAINT_RULES];
	struct taint_xform xforms[MAX_TAINT_XFORMS];
	struct taint_gate gates[MAX_TAINT_GATES];
	struct taint_inval invals[MAX_TAINT_INVALS];
};

/* ---- pure matching predicates ----
 *
 * FULLY BRANCHLESS with COMPILE-TIME-CONSTANT indices (loops unrolled): no
 * control flow depends on byte data, only arithmetic + masks. Required because
 * the kernel runs these inside a bpf_loop callback where the rule index — and so
 * the pattern bytes — are symbolic; a per-byte `if` or a symbolic-offset read
 * would fork/explode verifier state. With no data branches the matchers are
 * verified once, cheaply, regardless of rule count.
 *
 * Operands are compared over the full TAINT_PAT_LEN, so callers MUST pass
 * NUL-padded buffers >= TAINT_PAT_LEN (kernel comm/path buffers are zeroed;
 * rodata patterns are zero-padded). */

/* byte nonzero -> all-ones mask, zero -> 0, branchless. */
static __always_inline long te_nzmask(unsigned char c)
{
	return -(long)(((unsigned int)c + 0xFFu) >> 8);
}
/* x == 0 -> all-ones mask, x != 0 -> 0, branchless. */
static __always_inline long te_iszero64(unsigned long x)
{
	return ((long)((x | (0UL - x)) >> 63)) - 1;
}

/* exact compare: equal over the whole NUL-padded buffer. */
static TAINT_NOINLINE int taint_streq(const char *a, const char *b)
{
	long diff = 0;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++)
		diff |= (unsigned char)(a[i] ^ b[i]);
	return diff == 0;
}

/* does `text` start with non-empty `pre`? Only the leading nonzero bytes of
 * `pre` must match; empty `pre` never matches. */
static TAINT_NOINLINE int taint_prefix(const char *text, const char *pre)
{
	long diff = 0, anynz = 0;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		long m = te_nzmask((unsigned char)pre[i]);
		anynz |= m;
		diff |= m & (unsigned char)(text[i] ^ pre[i]);
	}
	return anynz != 0 && diff == 0;
}

/* does `text` end with non-empty `suf`? Compute both lengths branchlessly, then
 * compare `suf` at every start position with CONSTANT indices and keep only the
 * aligned position p == off (off = |text| - |suf|). Avoids the symbolic-offset
 * read text[off+j] that exploded verifier state. */
static TAINT_NOINLINE int taint_suffix(const char *text, const char *suf)
{
	int tn = 0, sn = 0;
	long tlive = 1, slive = 1;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		tlive &= te_nzmask((unsigned char)text[i]) & 1;
		tn += (int)tlive;
		slive &= te_nzmask((unsigned char)suf[i]) & 1;
		sn += (int)slive;
	}
	if (sn == 0 || sn > tn || sn > TAINT_SUF_MAX)
		return 0;
	int off = tn - sn;
	/* Fetch the aligned tail (text[off .. off+sn)) with ONE bounded copy, then
	 * compare statically. Avoids both the per-byte symbolic-offset read (verifier
	 * state explosion) and a 64xSUF scan-all (BPF stack overflow). The explicit
	 * clamps tell the verifier off and off+cn stay within [0, TAINT_PAT_LEN). */
	char tail[TAINT_SUF_MAX] = {};
	/* Constant-size copy (verifier-friendly: no variable length). off is clamped
	 * to [0, TAINT_PAT_LEN); callers pass TAINT_TEXT_BUF-sized buffers so reading
	 * TAINT_SUF_MAX bytes at off stays in bounds. The compare below only honors
	 * the first `sn` bytes, so the extra bytes are ignored. */
	if (off < 0)
		off = 0;
	if (off > TAINT_PAT_LEN - 1)
		off = TAINT_PAT_LEN - 1;
	TE_COPY(tail, TAINT_SUF_MAX, text + off);
	long diff = 0;
	TAINT_UNROLL
	for (int j = 0; j < TAINT_SUF_MAX; j++) {
		long jm = -(long)(j < sn);
		diff |= jm & (unsigned char)(tail[j] ^ (unsigned char)suf[j]);
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

/* @arg matching is done against PRE-TOKENIZED argv: the loader/exec hook splits
 * the argv blob into MAX_ARG_SLOTS fixed-width NUL-padded slots (te_tokenize_args
 * below), so matching a rule's @arg token is just an equality test against each
 * slot — constant strides, no scan of a symbolic blob (which no amount of
 * branchless coding could verify cheaply per rule). `slots` is MAX_ARG_SLOTS *
 * TAINT_ARG_LEN bytes. "" matches anything. */
static TAINT_NOINLINE int taint_arg_match(const char *slots, const char *tok)
{
	long found = te_iszero64((unsigned char)tok[0]);     /* "" matches */

	TAINT_UNROLL
	for (int s = 0; s < MAX_ARG_SLOTS; s++) {
		long diff = 0;
		const char *slot = slots + s * TAINT_ARG_LEN;
		TAINT_UNROLL
		for (int j = 0; j < TAINT_ARG_LEN; j++)
			diff |= (unsigned char)(slot[j] ^ tok[j]);
		found |= te_iszero64((unsigned long)diff);
	}
	return found != 0;
}

/* Split a NUL-separated argv blob (`blob`, `len` bytes) into MAX_ARG_SLOTS
 * fixed-width NUL-padded slots. Done once per exec, NOT per rule. */
static __always_inline void te_tokenize_args(const char *blob, int len,
					     char *slots)
{
	int si = 0, pj = 0;

	if (len > TAINT_ARGV_CAP)
		len = TAINT_ARGV_CAP;
	for (int i = 0; i < TAINT_ARGV_CAP; i++) {
		if (i >= len)
			break;
		char c = blob[i];
		if (c == '\0') {
			si++;
			pj = 0;
			if (si >= MAX_ARG_SLOTS)
				break;
			continue;
		}
		if (si < MAX_ARG_SLOTS && pj < TAINT_ARG_LEN - 1) {
			int idx = si * TAINT_ARG_LEN + pj;
			if (idx >= 0 && idx < MAX_ARG_SLOTS * TAINT_ARG_LEN)
				slots[idx] = c;
			pj++;
		}
	}
}

#endif /* __TAINT_H */
