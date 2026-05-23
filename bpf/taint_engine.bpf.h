/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2026 eunomia-bpf org. */
#ifndef __TAINT_ENGINE_BPF_H
#define __TAINT_ENGINE_BPF_H

/*
 * ActPlane in-kernel taint engine, as a composable header.
 *
 * Owns the taint state (per-pid label map) + compiled rules (rodata) + the
 * propagation/matching transfer functions. A hook program (e.g. process.bpf.c)
 * includes this and calls the te_* helpers from its fork/exec/exit/file hooks,
 * then emits a violation event on its own ring buffer. This is what lets the
 * same engine be wired into more capture programs over time (§10).
 *
 * Requires vmlinux.h + bpf_helpers.h + "taint.h" already included.
 */

/* Per-pid taint label bitmask. Propagated along the process tree. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, __u64);
} taint_labels SEC(".maps");

/* Compiled rules, installed from userspace before load (see taint.h struct). */
const volatile unsigned int n_taint_rules = 0;
const volatile struct taint_rule taint_rules_cfg[MAX_TAINT_RULES] = {};

/* fork: child inherits the parent's taint (the core propagation edge). */
static __always_inline void te_fork(pid_t parent_pid, pid_t child_pid)
{
	__u64 *p = bpf_map_lookup_elem(&taint_labels, &parent_pid);
	if (p && *p) {
		__u64 v = *p;
		bpf_map_update_elem(&taint_labels, &child_pid, &v, BPF_ANY);
	}
}

/* exec: fold any matching source rule into this pid's (inherited) label,
 * persist it, and return the resulting label. */
static __always_inline __u64 te_exec_label(pid_t pid, const char *comm)
{
	__u64 label = 0;
	__u64 *cur = bpf_map_lookup_elem(&taint_labels, &pid);
	if (cur)
		label = *cur;

	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		struct taint_rule r = taint_rules_cfg[i];
		if (r.source_comm[0] != '\0' && taint_comm_eq(comm, r.source_comm))
			label |= r.label;
	}
	if (label)
		bpf_map_update_elem(&taint_labels, &pid, &label, BPF_ANY);
	return label;
}

/* exec sink: does a process carrying `label` exec'ing `comm` violate a rule? */
static __always_inline int te_exec_sink(const char *comm, __u64 label, unsigned int *rid)
{
	if (!label)
		return 0;
	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		struct taint_rule r = taint_rules_cfg[i];
		if (r.sink_kind == TAINT_SINK_EXEC && (label & r.label) &&
		    r.sink[0] != '\0' && taint_comm_eq(comm, r.sink)) {
			*rid = r.rule_id;
			return 1;
		}
	}
	return 0;
}

/* file-open sink: does pid (if tainted) opening `path` violate a rule? */
static __always_inline int te_file_sink(pid_t pid, const char *path, unsigned int *rid)
{
	__u64 *cur = bpf_map_lookup_elem(&taint_labels, &pid);
	__u64 label = cur ? *cur : 0;
	if (!label)
		return 0;
	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		struct taint_rule r = taint_rules_cfg[i];
		if (r.sink_kind == TAINT_SINK_FILE_OPEN && (label & r.label) &&
		    taint_path_has_prefix(path, r.sink)) {
			*rid = r.rule_id;
			return 1;
		}
	}
	return 0;
}

/* exit: drop the pid's label so the map doesn't leak. */
static __always_inline void te_exit(pid_t pid)
{
	bpf_map_delete_elem(&taint_labels, &pid);
}

#endif /* __TAINT_ENGINE_BPF_H */
