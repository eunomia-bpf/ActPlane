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

struct te_rule_eval {
	pid_t pid;
	__u64 labels;
	unsigned int op;
	const char *target;
	const char *argv;
	int argv_len;
	unsigned int effect;
	unsigned int effect_mask;
	int matched_rule;       /* set by te_rule_effect on a hit */
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

/* Loop trip counts in a (non-frozen) map so the verifier treats them as unknown
 * scalars: every table loop runs via bpf_loop(), whose callback is then verified
 * exactly ONCE (a frozen/known count would make the verifier simulate per
 * iteration and -E2BIG at scale). Slots: 0=rules 1=sources 2=xforms 3=gates. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} ts_counts SEC(".maps");

static __always_inline unsigned int te_count(__u32 slot)
{
	__u32 *v = bpf_map_lookup_elem(&ts_counts, &slot);
	return v ? *v : 0;
}

/* Per-CPU scratch for the raw argv blob + tokenized slots (off-stack; the exec
 * hook fills it then matches synchronously, so per-CPU reuse is safe). Both live
 * in the map so the bpf_loop tokenizer can do variable-offset reads/writes, which
 * the verifier rejects on the stack. */
struct te_argslots {
	char blob[TAINT_ARGV_CAP];
	char slots[TAINT_ARG_SLOTS_BUF];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct te_argslots);
} ts_argslots SEC(".maps");

static __always_inline struct te_argslots *te_argslots_buf(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&ts_argslots, &k);
}

/* Tokenize the argv blob into fixed slots via bpf_loop (callback verified once;
 * a plain inlined loop's dynamic-index write exploded the verifier). The callback
 * re-looks-up the per-CPU scratch so the verifier keeps the map_value bound (a
 * pointer carried through the bpf_loop ctx loses it -> "unbounded access"). */
struct te_tok_ctx { int si; int pj; };
static int te_tok_cb(__u32 i, void *vc)
{
	struct te_tok_ctx *c = vc;
	struct te_argslots *a = te_argslots_buf();

	if (!a)
		return 1;
	/* barrier_var keeps clang from eliding the mask (it otherwise proves i<CAP and
	 * reuses an unbounded copy for the access); the AND makes bi<=CAP-1 verifiably. */
	__u32 bi = i;
	barrier_var(bi);
	bi &= (__u32)(TAINT_ARGV_CAP - 1);
	char ch = a->blob[bi];
	if (ch == '\0') {
		c->si++;
		c->pj = 0;
		return c->si >= MAX_ARG_SLOTS ? 1 : 0;
	}
	if (c->si >= 0 && c->si < MAX_ARG_SLOTS && c->pj >= 0 && c->pj < TAINT_ARG_LEN - 1) {
		__u32 sidx = ((__u32)c->si * TAINT_ARG_LEN + (__u32)c->pj);
		if (sidx < TAINT_ARG_SLOTS_BUF)
			a->slots[sidx] = ch;
		c->pj++;
	}
	return 0;
}
static __always_inline void te_tokenize_args_eng(int len)
{
	if (len < 0)
		len = 0;
	if (len > TAINT_ARGV_CAP)        /* so the callback's i < len stays bounded */
		len = TAINT_ARGV_CAP;
	struct te_tok_ctx c = { .si = 0, .pj = 0 };
	bpf_loop((unsigned int)len, te_tok_cb, &c, 0);
}

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

/* All table scans below run via bpf_loop() (count from the ts_counts map) so the
 * callback is verified once regardless of table size — see ts_counts. Each
 * callback range-checks its index for the verifier's static bound. */

struct te_exec_ctx { const char *comm; __u64 add, del, gbits; };

static int te_exec_src_cb(__u32 i, void *vc)
{
	struct te_exec_ctx *c = vc;
	if (i >= MAX_TAINT_SOURCES)
		return 1;
	struct taint_source s = taint_sources[i];
	if (s.kind == TSRC_EXEC && taint_match(s.match, c->comm, s.pat))
		c->add |= s.label;
	return 0;
}
static int te_exec_xform_cb(__u32 i, void *vc)
{
	struct te_exec_ctx *c = vc;
	if (i >= MAX_TAINT_XFORMS)
		return 1;
	struct taint_xform x = taint_xforms[i];
	if (taint_match(x.match, c->comm, x.gate)) {
		if (x.add)
			c->add |= x.label;
		else
			c->del |= x.label;
	}
	return 0;
}
static int te_exec_gate_cb(__u32 i, void *vc)
{
	struct te_exec_ctx *c = vc;
	if (i >= MAX_TAINT_GATES)
		return 1;
	struct taint_gate g = taint_gates[i];
	if (taint_match(g.match, c->comm, g.pat))
		c->gbits |= g.bit;
	return 0;
}

/* on exec: apply exec sources, xforms (declassify/endorse), and gates (set
 * lineage + session bits). All exec-side patterns are matched on comm. */
static __noinline void te_exec_update(pid_t pid, const char *comm)
{
	struct te_exec_ctx c = { .comm = comm };

	bpf_loop(te_count(1), te_exec_src_cb, &c, 0);
	bpf_loop(te_count(2), te_exec_xform_cb, &c, 0);
	bpf_loop(te_count(3), te_exec_gate_cb, &c, 0);

	struct proc_state *p = te_get(pid);
	struct proc_state ns = { 0 };
	if (p)
		ns = *p;
	ns.labels = (ns.labels | c.add) & ~c.del;
	ns.lin_gates |= c.gbits;
	bpf_map_update_elem(&ts_proc, &pid, &ns, BPF_ANY);
	if (c.gbits) {
		pid_t r = te_root(pid);
		__u64 *s = bpf_map_lookup_elem(&ts_sess, &r);
		__u64 nv = (s ? *s : 0) | c.gbits;
		bpf_map_update_elem(&ts_sess, &r, &nv, BPF_ANY);
	}
}

/* object sources: reading a matching file / receiving from a matching endpoint
 * taints the subject. */
struct te_fsrc_ctx { const char *path; __u32 ip; __u64 add; };

static int te_file_src_cb(__u32 i, void *vc)
{
	struct te_fsrc_ctx *c = vc;
	if (i >= MAX_TAINT_SOURCES)
		return 1;
	struct taint_source s = taint_sources[i];
	if (s.kind == TSRC_FILE && taint_match(s.match, c->path, s.pat))
		c->add |= s.label;
	return 0;
}
static int te_endp_src_cb(__u32 i, void *vc)
{
	struct te_fsrc_ctx *c = vc;
	if (i >= MAX_TAINT_SOURCES)
		return 1;
	struct taint_source s = taint_sources[i];
	if (s.kind == TSRC_ENDPOINT && (c->ip & s.ipv4_mask) == s.ipv4)
		c->add |= s.label;
	return 0;
}
static __noinline __u64 te_file_src(const char *path)
{
	struct te_fsrc_ctx c = { .path = path };
	bpf_loop(te_count(1), te_file_src_cb, &c, 0);
	return c.add;
}
static __noinline __u64 te_endp_src_ip(__u32 ip)
{
	struct te_fsrc_ctx c = { .ip = ip };
	bpf_loop(te_count(1), te_endp_src_cb, &c, 0);
	return c.add;
}

/* connect sink: numeric IPv4 match (no string formatting). bpf_loop over rules. */
struct te_conn_ctx {
	struct te_rule_eval *e;
	__u32 ip;
	unsigned int best_effect;
	int best_rule;
};
static int te_conn_rule_cb(__u32 i, void *vc)
{
	struct te_conn_ctx *c = vc;
	if (i >= MAX_TAINT_RULES)
		return 1;
	struct taint_rule r = taint_rules[i];
	struct te_rule_eval *e = c->e;

	if (r.op != TOP_CONNECT)
		return 0;
	if (e->effect_mask) {
		if (r.effect > TEFFECT_KILL)
			return 0;
		if (!(e->effect_mask & (1U << r.effect)))
			return 0;
	}
	if (!taint_mask_ok(e->labels, r.req, r.forbid))
		return 0;
	if ((c->ip & r.ipv4_mask) != r.ipv4)
		return 0;
	if (r.cond_kind == TCOND_LINEAGE) {
		struct proc_state *p = te_get(e->pid);
		if (p && (p->lin_gates & r.gate))
			return 0;
	} else if (r.cond_kind == TCOND_AFTER) {
		pid_t rt = te_root(e->pid);
		__u64 *s = bpf_map_lookup_elem(&ts_sess, &rt);
		if (s && (*s & r.gate))
			return 0;
	} else if (r.cond_kind == TCOND_TARGET) {
		int m = ((c->ip & r.cond_ipv4_mask) == r.cond_ipv4);
		if (r.cond_neg ? !m : m)
			return 0;
	}
	if (c->best_rule < 0 || r.effect > c->best_effect) {
		c->best_rule = (int)r.rule_id;
		c->best_effect = r.effect;
		if (c->best_effect == TEFFECT_KILL)
			return 1;
	}
	return 0;
}
static __noinline int te_connect_check_labels(struct te_rule_eval *e, __u32 ip)
{
	struct te_conn_ctx c = { .e = e, .ip = ip,
				 .best_effect = TEFFECT_AUDIT, .best_rule = -1 };
	bpf_loop(te_count(0), te_conn_rule_cb, &c, 0);
	if (c.best_rule >= 0)
		e->effect = c.best_effect;
	return c.best_rule;
}

static __always_inline int te_connect_check(pid_t pid, __u32 ip)
{
	struct te_rule_eval e = {
		.pid = pid,
		.labels = te_labels(pid),
	};
	return te_connect_check_labels(&e, ip);
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

/* Match event `e` against one rule index; returns the rule's effect (>=0) on a
 * hit, else -1, recording the matched rule_id in e->matched_rule. */
static __noinline int te_rule_effect(struct te_rule_eval *e, unsigned int idx)
{
	if (idx >= MAX_TAINT_RULES)
		return -1;
	struct taint_rule r = taint_rules[idx]; /* local copy: plain reads */

	if (r.op != e->op)
		return -1;
	if (e->effect_mask) {
		if (r.effect > TEFFECT_KILL)
			return -1;
		if (!(e->effect_mask & (1U << r.effect)))
			return -1;
	}
	if (!taint_mask_ok(e->labels, r.req, r.forbid))
		return -1;
	if (!taint_match(r.match, e->target, r.target))
		return -1;
	if (e->op == TOP_EXEC && r.arg[0] != '\0') {
		/* Match against the pre-tokenized arg slots. Re-look-up the per-CPU
		 * scratch here so the verifier keeps the map_value bound (a pointer
		 * carried via e->argv would be treated as unbounded). */
		struct te_argslots *a = te_argslots_buf();
		if (!a || !taint_arg_match(a->slots, r.arg))
			return -1;
	}
	if (te_cond_satisfied(&r, e->pid, e->target))
		return -1;
	e->matched_rule = (int)r.rule_id;
	return (int)r.effect;
}

struct te_rule_ctx { struct te_rule_eval *e; unsigned int best_effect; int best_rule; };
static int te_rule_cb(__u32 i, void *vc)
{
	struct te_rule_ctx *c = vc;
	int eff = te_rule_effect(c->e, i);
	if (eff < 0)
		return 0;
	if (c->best_rule < 0 || (unsigned int)eff > c->best_effect) {
		c->best_rule = c->e->matched_rule;
		c->best_effect = (unsigned int)eff;
		if (c->best_effect == TEFFECT_KILL)
			return 1;
	}
	return 0;
}

/* Evaluate sinks for one normalized event. Returns the matched rule_id, or -1.
 * The rule loop runs via bpf_loop() with the count from the ts_counts map, so
 * the callback is verified ONCE — verifier cost is independent of rule count,
 * which (with the branchless matchers) lets 100+ rules load in one program. */
static __noinline int te_check_labels(struct te_rule_eval *e)
{
	struct te_rule_ctx c = { .e = e, .best_effect = TEFFECT_AUDIT, .best_rule = -1 };
	bpf_loop(te_count(0), te_rule_cb, &c, 0);
	if (c.best_rule >= 0)
		e->effect = c.best_effect;
	return c.best_rule;
}

static __always_inline int te_check(pid_t pid, unsigned int op, const char *target,
				    const char *argv, int argv_len)
{
	struct te_rule_eval e = {
		.pid = pid,
		.labels = te_labels(pid),
		.op = op,
		.target = target,
		.argv = argv,
		.argv_len = argv_len,
	};
	return te_check_labels(&e);
}

static __always_inline void te_exit(pid_t pid)
{
	bpf_map_delete_elem(&ts_proc, &pid);
	bpf_map_delete_elem(&ts_root, &pid);
}

#endif /* __TAINT_ENGINE_BPF_H */
