/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2026 eunomia-bpf org. */
#ifndef __TAINT_ENGINE_BPF_H
#define __TAINT_ENGINE_BPF_H

/*
 * ActPlane in-kernel taint engine. Owns the label state (process / file /
 * endpoint) + lineage/session gates + the compiled rule tables (rodata, filled
 * from userspace before load), and provides the te_* helpers a hook program
 * calls. Requires vmlinux.h + bpf_helpers.h + "taint.h" already included.
 */

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

struct proc_state {
	__u64 labels;
	__u64 lin_gates; /* gate bits seen in this pid's ancestor chain (incl self) */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct proc_state);
} ts_proc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, pid_t);
} ts_root SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, __u64);
} ts_sess SEC(".maps"); /* root pid -> session gate bits */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* fnv1a(path) */
	__type(value, __u64);
} ts_file SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); /* IPv4 (network order) */
	__type(value, __u64);
} ts_endp SEC(".maps");

/* Compiled tables, set from userspace before load. */
const volatile unsigned int n_sources = 0;
const volatile unsigned int n_rules = 0;
const volatile unsigned int n_xforms = 0;
const volatile unsigned int n_gates = 0;
const volatile struct taint_source taint_sources[MAX_TAINT_SOURCES] = {};
const volatile struct taint_rule taint_rules[MAX_TAINT_RULES] = {};
const volatile struct taint_xform taint_xforms[MAX_TAINT_XFORMS] = {};
const volatile struct taint_gate taint_gates[MAX_TAINT_GATES] = {};

static __always_inline __u64 te_fnv1a(const char *s)
{
	__u64 h = 0xcbf29ce484222325ULL;
	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		char c = s[i];
		if (c == '\0')
			break;
		h ^= (unsigned char)c;
		h *= 0x100000001b3ULL;
	}
	return h;
}

static __always_inline struct proc_state *te_get(pid_t pid)
{
	return bpf_map_lookup_elem(&ts_proc, &pid);
}
static __always_inline __u64 te_labels(pid_t pid)
{
	struct proc_state *p = te_get(pid);
	return p ? p->labels : 0;
}
static __always_inline void te_add_labels(pid_t pid, __u64 add)
{
	struct proc_state *p = te_get(pid);
	if (p) {
		p->labels |= add;
	} else {
		struct proc_state ns = { .labels = add, .lin_gates = 0 };
		bpf_map_update_elem(&ts_proc, &pid, &ns, BPF_ANY);
	}
}
static __always_inline pid_t te_root(pid_t pid)
{
	pid_t *r = bpf_map_lookup_elem(&ts_root, &pid);
	return r ? *r : pid;
}

/* fork: child inherits labels + lineage gates; root carries down. */
static __always_inline void te_fork(pid_t ppid, pid_t cpid)
{
	struct proc_state *pp = te_get(ppid);
	struct proc_state ns = { 0 };
	if (pp)
		ns = *pp;
	bpf_map_update_elem(&ts_proc, &cpid, &ns, BPF_ANY);
	pid_t r = te_root(ppid);
	bpf_map_update_elem(&ts_root, &cpid, &r, BPF_ANY);
}

/* on exec: apply exec sources, xforms (declassify/endorse), and gates (set
 * lineage + session bits). All exec-side patterns are matched on comm. */
static __noinline void te_exec_update(pid_t pid, const char *comm)
{
	__u64 add = 0, del = 0, gbits = 0;

	for (unsigned int i = 0; i < MAX_TAINT_SOURCES; i++) {
		if (i >= n_sources)
			break;
		struct taint_source s = taint_sources[i]; /* local copy: plain reads */
		if (s.kind == TSRC_EXEC && taint_match(s.match, comm, s.pat))
			add |= s.label;
	}
	for (unsigned int i = 0; i < MAX_TAINT_XFORMS; i++) {
		if (i >= n_xforms)
			break;
		struct taint_xform x = taint_xforms[i];
		if (taint_match(x.match, comm, x.gate)) {
			if (x.add)
				add |= x.label;
			else
				del |= x.label;
		}
	}
	for (unsigned int i = 0; i < MAX_TAINT_GATES; i++) {
		if (i >= n_gates)
			break;
		struct taint_gate g = taint_gates[i];
		if (taint_match(g.match, comm, g.pat))
			gbits |= g.bit;
	}

	struct proc_state *p = te_get(pid);
	struct proc_state ns = { 0 };
	if (p)
		ns = *p;
	ns.labels = (ns.labels | add) & ~del;
	ns.lin_gates |= gbits;
	bpf_map_update_elem(&ts_proc, &pid, &ns, BPF_ANY);
	if (gbits) {
		pid_t r = te_root(pid);
		__u64 *s = bpf_map_lookup_elem(&ts_sess, &r);
		__u64 nv = (s ? *s : 0) | gbits;
		bpf_map_update_elem(&ts_sess, &r, &nv, BPF_ANY);
	}
}

/* object sources: reading a matching file / receiving from a matching endpoint
 * taints the subject. */
static __noinline __u64 te_file_src(const char *path)
{
	__u64 add = 0;
	for (unsigned int i = 0; i < MAX_TAINT_SOURCES; i++) {
		if (i >= n_sources)
			break;
		struct taint_source s = taint_sources[i];
		if (s.kind == TSRC_FILE && taint_match(s.match, path, s.pat))
			add |= s.label;
	}
	return add;
}
static __noinline __u64 te_endp_src_ip(__u32 ip)
{
	__u64 add = 0;
	for (unsigned int i = 0; i < MAX_TAINT_SOURCES; i++) {
		if (i >= n_sources)
			break;
		struct taint_source s = taint_sources[i];
		if (s.kind == TSRC_ENDPOINT && (ip & s.ipv4_mask) == s.ipv4)
			add |= s.label;
	}
	return add;
}

/* connect sink: numeric IPv4 match (no string formatting). Returns rule_id/-1. */
static __noinline int te_connect_check_labels(pid_t pid, __u64 labels, __u32 ip)
{
	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		if (i >= n_rules)
			break;
		struct taint_rule r = taint_rules[i];
		if (r.op != TOP_CONNECT)
			continue;
		if (!taint_mask_ok(labels, r.req, r.forbid))
			continue;
		if ((ip & r.ipv4_mask) != r.ipv4)
			continue;
		/* conditions */
		if (r.cond_kind == TCOND_LINEAGE) {
			struct proc_state *p = te_get(pid);
			if (p && (p->lin_gates & r.gate))
				continue;
		} else if (r.cond_kind == TCOND_AFTER) {
			pid_t rt = te_root(pid);
			__u64 *s = bpf_map_lookup_elem(&ts_sess, &rt);
			if (s && (*s & r.gate))
				continue;
		} else if (r.cond_kind == TCOND_TARGET) {
			int m = ((ip & r.cond_ipv4_mask) == r.cond_ipv4);
			if (r.cond_neg ? !m : m)
				continue;
		}
		return (int)r.rule_id;
	}
	return -1;
}

static __always_inline int te_connect_check(pid_t pid, __u32 ip)
{
	return te_connect_check_labels(pid, te_labels(pid), ip);
}

static __always_inline __u64 te_file_labels(const char *path)
{
	__u64 h = te_fnv1a(path);
	__u64 *fl = bpf_map_lookup_elem(&ts_file, &h);

	return (fl ? *fl : 0) | te_file_src(path);
}

/* read: proc absorbs file labels + file source. */
static __always_inline void te_read(pid_t pid, const char *path)
{
	te_add_labels(pid, te_file_labels(path));
}
/* write: file absorbs proc labels. */
static __always_inline void te_write_flow(pid_t pid, const char *path)
{
	__u64 h = te_fnv1a(path);
	__u64 pl = te_labels(pid);
	if (!pl)
		return;
	__u64 *fl = bpf_map_lookup_elem(&ts_file, &h);
	__u64 nv = (fl ? *fl : 0) | pl;
	bpf_map_update_elem(&ts_file, &h, &nv, BPF_ANY);
}
/* connect egress: endpoint records proc labels. */
static __always_inline void te_connect_flow(__u32 ip, pid_t pid)
{
	__u64 pl = te_labels(pid);
	if (!pl)
		return;
	__u64 *el = bpf_map_lookup_elem(&ts_endp, &ip);
	__u64 nv = (el ? *el : 0) | pl;
	bpf_map_update_elem(&ts_endp, &ip, &nv, BPF_ANY);
}

static __always_inline int te_cond_satisfied(const struct taint_rule *r, pid_t pid,
					     const char *target)
{
	if (r->cond_kind == TCOND_NONE)
		return 0;
	if (r->cond_kind == TCOND_LINEAGE) {
		struct proc_state *p = te_get(pid);
		return p && (p->lin_gates & r->gate);
	}
	if (r->cond_kind == TCOND_AFTER) {
		pid_t rt = te_root(pid);
		__u64 *s = bpf_map_lookup_elem(&ts_sess, &rt);
		return s && (*s & r->gate);
	}
	/* TCOND_TARGET */
	int m = taint_match(r->cond_match, target, r->cond_pat);
	return r->cond_neg ? !m : m;
}

/* Evaluate sinks for op `op` on `target` by process `pid`. Returns the matched
 * rule_id, or -1 if none. argv may be NULL (non-exec ops). Limited to 5 args so
 * it can be a bpf2bpf subprogram (own stack frame). */
static __noinline int te_check_labels(pid_t pid, __u64 labels, unsigned int op,
				      const char *target, const char *argv,
				      int argv_len)
{
	for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
		if (i >= n_rules)
			break;
		struct taint_rule r = taint_rules[i]; /* local copy: plain reads */
		if (r.op != op)
			continue;
		if (!taint_mask_ok(labels, r.req, r.forbid))
			continue;
		if (!taint_match(r.match, target, r.target))
			continue;
		if (op == TOP_EXEC && r.arg[0] != '\0') {
			if (!argv || argv_len <= 0)
				continue;
			if (!taint_arg_match(argv, argv_len, r.arg))
				continue;
		}
		if (te_cond_satisfied(&r, pid, target))
			continue;
		return (int)r.rule_id;
	}
	return -1;
}

static __always_inline int te_check(pid_t pid, unsigned int op, const char *target,
				    const char *argv, int argv_len)
{
	return te_check_labels(pid, te_labels(pid), op, target, argv, argv_len);
}

static __always_inline void te_exit(pid_t pid)
{
	bpf_map_delete_elem(&ts_proc, &pid);
	bpf_map_delete_elem(&ts_root, &pid);
}

#endif /* __TAINT_ENGINE_BPF_H */
