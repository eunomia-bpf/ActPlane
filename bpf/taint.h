/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 eunomia-bpf org. */
#ifndef __TAINT_H
#define __TAINT_H

/*
 * ActPlane in-kernel taint analysis.
 *
 * Model (see docs/actplane-research-plan.md):
 *   - Nodes are processes; taint propagates along the process tree.
 *   - A rule names a `source` executable: any process that execs it, and all
 *     of its descendants, acquire the rule's taint `label` (one bit per rule).
 *   - The same rule names one or more `sink` executables: a tainted process
 *     attempting to exec a sink is a violation, reported with `rule_id`.
 *
 * Enforcement note: on kernels with BPF LSM enabled this logic can move into
 * an `lsm/bprm_check_security` hook returning -EPERM. On kernels without it
 * (the common case today) we run it from the exec tracepoint and *report* the
 * violation; userspace turns the report into semantic feedback / a reactive
 * signal. The matching logic below is identical either way, which is why it
 * lives in this shared, libc-free, unit-testable header.
 *
 * This header is intentionally free of libc and libbpf dependencies so that it
 * compiles both inside the eBPF program and inside the plain-C unit test
 * (test_taint.c), mirroring process_filter.h.
 */

/* Fully unroll the bounded loops below when compiled for BPF (clang), so the
 * verifier sees straight-line code. A no-op for the gcc-built unit test. */
#if defined(__clang__)
#define TAINT_UNROLL _Pragma("clang loop unroll(full)")
#else
#define TAINT_UNROLL
#endif

/* Force inlining in BPF so helpers don't become separate subprograms with
 * loops the verifier can't bound. The unit test (gcc) supplies its own. */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define TAINT_COMM_LEN   16   /* matches TASK_COMM_LEN */
#define MAX_TAINT_RULES  16   /* one taint label bit per rule */
#define TAINT_LABEL_NONE 0ULL

/* A compiled rule edge: "processes tainted by `source_comm` may not exec
 * `sink_comm`". The DSL compiler in the collector emits one of these per
 * (source, deny-exec sink) pair. */
struct taint_rule {
	char source_comm[TAINT_COMM_LEN]; /* executable that introduces the taint */
	char sink_comm[TAINT_COMM_LEN];   /* executable forbidden to tainted procs */
	unsigned long long label;         /* taint bit for this rule (1 << rule_id) */
	unsigned int rule_id;             /* index back into the DSL rule table */
};

/* Exact comm comparison, bounded to TAINT_COMM_LEN bytes. comm values are the
 * 16-byte, NUL-padded names from bpf_get_current_comm(); a NUL terminates the
 * comparison early. Returns true on full match. BPF-verifier friendly: the
 * loop bound is a compile-time constant. */
static __always_inline int taint_comm_eq(const char *a, const char *b)
{
	TAINT_UNROLL
	for (int i = 0; i < TAINT_COMM_LEN; i++) {
		if (a[i] != b[i])
			return 0;
		if (a[i] == '\0')
			return 1;
	}
	return 1;
}

/* OR in the taint labels of every rule whose source matches `comm`.
 * `cur_label` is the process's existing (inherited) label. Returns the
 * resulting label. */
static __always_inline unsigned long long taint_apply_sources(const struct taint_rule *rules,
						       unsigned int n_rules,
						       const char *comm,
						       unsigned long long cur_label)
{
	unsigned long long label = cur_label;

	if (n_rules > MAX_TAINT_RULES)
		n_rules = MAX_TAINT_RULES;

	TAINT_UNROLL
	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		if (i >= n_rules)
			break;
		if (rules[i].source_comm[0] != '\0' &&
		    taint_comm_eq(comm, rules[i].source_comm))
			label |= rules[i].label;
	}
	return label;
}

/* Check whether a process carrying `label` is allowed to exec `comm`.
 * If a rule's label is active and `comm` matches that rule's sink, the access
 * is a violation: returns 1 and writes the offending rule_id to *out_rule_id.
 * Returns 0 when allowed. */
static __always_inline int taint_check_sink(const struct taint_rule *rules,
				     unsigned int n_rules,
				     const char *comm,
				     unsigned long long label,
				     unsigned int *out_rule_id)
{
	if (n_rules > MAX_TAINT_RULES)
		n_rules = MAX_TAINT_RULES;

	TAINT_UNROLL
	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		if (i >= n_rules)
			break;
		if ((label & rules[i].label) &&
		    rules[i].sink_comm[0] != '\0' &&
		    taint_comm_eq(comm, rules[i].sink_comm)) {
			if (out_rule_id)
				*out_rule_id = rules[i].rule_id;
			return 1;
		}
	}
	return 0;
}

#endif /* __TAINT_H */
