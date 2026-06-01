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

#include "capability.bpf.h"

/* BPF implementation of taint_contains (substring search via bpf_loop).
 * The outer scan runs through bpf_loop so the callback is verified ONCE (not
 * TAINT_PAT_LEN times).  Inside, TE_COPY fetches the candidate window through
 * the bounded helper read — never a direct variable-offset stack dereference. */
#ifdef __BPF__
struct __taint_contains_ctx {
	const char *text;
	const char *pat;
	int pn;
	int max_pos;
	int found;
};

static long __taint_contains_cb(__u32 idx, void *_ctx)
{
	struct __taint_contains_ctx *c = _ctx;
	if (c->found)
		return 1;
	if (idx > (unsigned int)c->max_pos)
		return 1;

	char window[TAINT_SUF_MAX] = {};
	TE_COPY(window, TAINT_SUF_MAX, c->text + idx);
	char p[TAINT_SUF_MAX] = {};
	TE_COPY(p, TAINT_SUF_MAX, c->pat);

	long diff = 0;
	TAINT_UNROLL
	for (int j = 0; j < TAINT_SUF_MAX; j++) {
		long jm = -(long)(j < c->pn);
		diff |= jm & (unsigned char)(window[j] ^ p[j]);
	}
	if (diff == 0)
		c->found = 1;
	return 0;
}

static __noinline int taint_contains(const char *text, const char *pat)
{
	int tn = 0, pn = 0;
	long tlive = 1, plive = 1;

	TAINT_UNROLL
	for (int i = 0; i < TAINT_PAT_LEN; i++) {
		tlive &= te_nzmask((unsigned char)text[i]) & 1;
		tn += (int)tlive;
		plive &= te_nzmask((unsigned char)pat[i]) & 1;
		pn += (int)plive;
	}
	if (pn == 0 || pn > tn || pn > TAINT_SUF_MAX)
		return 0;

	struct __taint_contains_ctx c = {
		.text = text, .pat = pat,
		.pn = pn, .max_pos = tn - pn, .found = 0
	};
	bpf_loop(TAINT_PAT_LEN, __taint_contains_cb, &c, 0);
	return c.found;
}
#endif /* __BPF__ */

struct proc_state {
	__u64 labels;
	__u64 lin_gates; /* gate bits seen in this pid's ancestor chain (incl self) */
};

/* One causal origin for one label bit on one subject/object. This is intentionally
 * compact: the enforcer keeps the source that introduced the label, then feedback
 * combines it with the violating operation to describe the causal path. */
struct te_prov {
	__u64 label;
	__u64 timestamp_ns;
	pid_t pid;
	__u32 op;
	__u32 ip;
	char target[MAX_FILENAME_LEN];
};

struct pid_label_id {
	pid_t pid;
	__u32 _pad;
	__u64 label;
};

/* Per-session (keyed by root pid) gate + staleness state.
 *  - gate_bits: v1 latching "after exec X" bits (also used by `since_mask==0`).
 *  - epoch:     monotonic per-session event counter.
 *  - gate_epoch[i]:  epoch of the most recent exec matching gate i (0 = never).
 *  - inval_epoch[i]: epoch of the most recent event matching invalidator i.
 * `after X since Y` is satisfied iff gate_epoch[X] > max(inval_epoch[Y in mask]).
 * It is a HASH map value, mutated in place via the lookup pointer. */
struct te_sess {
	__u64 gate_bits;
	__u32 epoch;
	__u32 _pad;
	__u32 gate_epoch[MAX_TAINT_GATES];
	__u32 inval_epoch[MAX_TAINT_INVALS];
};

/* File object identity (Layer A, docs/rule-language.md §1.10). A real (dev, inode)
 * when the hook has an inode (LSM mode); otherwise (0, fnv1a(path)) so the
 * tracepoint path keeps its old path-keyed behavior byte-for-byte. Used as a
 * HASH key, so it MUST be fully zero-initialized (incl _pad) before use. */
struct file_id {
	__u64 ino;
	__u32 dev;
	__u32 _pad;
};
struct file_label_id {
	struct file_id fid;
	__u64 label;
};
/* ts_file value: taint labels (as before) plus the epoch of this object's last
 * observed write. last_write_epoch is infrastructure for staleness precision
 * (Layer B); Layer A only populates it for files that already carry labels. */
struct file_state {
	__u64 labels;
	__u32 last_write_epoch;
	__u32 _pad;
};

struct te_rule_eval {
	pid_t pid;
	__u64 labels;
	unsigned int op;
	const char *target;
	__u32 ip;
	unsigned int effect;
	unsigned int effect_mask;
	int matched_rule;       /* set by te_rule_effect on a hit */
	__u64 matched_req;      /* required label mask for the matched compiled rule */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct proc_state);
} ts_proc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct pid_label_id);
	__type(value, struct te_prov);
} ts_proc_prov SEC(".maps");

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
	__type(value, struct te_sess);
} ts_sess SEC(".maps"); /* root pid -> session gate + staleness state */

/* A single never-written, zero-initialized te_sess used only as the seed value
 * for new ts_sess entries (te_sess is too big to zero on the BPF stack). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct te_sess);
} ts_sess_zero SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct file_id);
	__type(value, struct file_state);
} ts_file SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct file_label_id);
	__type(value, struct te_prov);
} ts_file_prov SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); /* IPv4 (network order) */
	__type(value, __u64);
} ts_endp SEC(".maps");

/* Compiled kernel IR tables, set from userspace before load. */
const volatile unsigned int n_updates = 0;
const volatile unsigned int n_rules = 0;
const volatile struct taint_update taint_updates[MAX_TAINT_UPDATES] = {};
const volatile struct taint_rule taint_rules[MAX_TAINT_RULES] = {};

/* Loop trip counts in a (non-frozen) map so the verifier treats them as unknown
 * scalars: every table loop runs via bpf_loop(), whose callback is then verified
 * exactly ONCE (a frozen/known count would make the verifier simulate per
 * iteration and -E2BIG at scale). Slots: 0=rules 1=updates 5=labels. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__type(value, __u32);
} ts_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct te_prov);
} ts_prov_tmp SEC(".maps");

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
		unsigned char c = (unsigned char)s[i];
		h ^= c;
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
	__u64 labels = p ? p->labels : 0;
	return labels | cap_labels_for_pid(pid);
}

static __always_inline void te_copy_target(char *dst, const char *src)
{
	if (!src) {
		dst[0] = '\0';
		return;
	}
	for (int i = 0; i < MAX_FILENAME_LEN; i++)
		dst[i] = src[i];
	dst[MAX_FILENAME_LEN - 1] = '\0';
}

static __always_inline struct te_prov *te_prov_tmp(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&ts_prov_tmp, &k);
}

static __always_inline struct te_prov *te_lookup_proc_prov(pid_t pid, __u64 label)
{
	struct pid_label_id key = { .pid = pid, .label = label };
	return bpf_map_lookup_elem(&ts_proc_prov, &key);
}

static __always_inline void te_record_proc_prov(pid_t pid, __u64 label,
						unsigned int op, const char *target,
						__u32 ip)
{
	if (!label)
		return;
	struct te_prov *p = te_prov_tmp();
	if (!p)
		return;
	__builtin_memset(p, 0, sizeof(*p));
	p->label = label;
	p->timestamp_ns = bpf_ktime_get_ns();
	p->pid = pid;
	p->op = op;
	p->ip = ip;
	te_copy_target(p->target, target);
	struct pid_label_id key = { .pid = pid, .label = label };
	bpf_map_update_elem(&ts_proc_prov, &key, p, BPF_ANY);
}

struct te_record_proc_prov_ctx {
	pid_t pid;
	__u64 labels;
	unsigned int op;
	const char *target;
	__u32 ip;
};
static int te_record_proc_prov_cb(__u32 i, void *vc)
{
	struct te_record_proc_prov_ctx *c = vc;
	if (i >= MAX_TAINT_LABELS)
		return 1;
	__u64 bit = 1ULL << i;
	if (c->labels & bit)
		te_record_proc_prov(c->pid, bit, c->op, c->target, c->ip);
	return 0;
}
static __noinline void te_record_proc_prov_mask(pid_t pid, __u64 labels,
						unsigned int op,
						const char *target, __u32 ip)
{
	struct te_record_proc_prov_ctx c = {
		.pid = pid,
		.labels = labels,
		.op = op,
		.target = target,
		.ip = ip,
	};
	bpf_loop(te_count(5), te_record_proc_prov_cb, &c, 0);
}

struct te_copy_proc_prov_ctx { pid_t from, to; __u64 labels; };
static int te_copy_proc_prov_cb(__u32 i, void *vc)
{
	struct te_copy_proc_prov_ctx *c = vc;
	if (i >= MAX_TAINT_LABELS)
		return 1;
	__u64 bit = 1ULL << i;
	if (!(c->labels & bit))
		return 0;
	struct te_prov *p = te_lookup_proc_prov(c->from, bit);
	if (!p)
		return 0;
	struct pid_label_id key = { .pid = c->to, .label = bit };
	bpf_map_update_elem(&ts_proc_prov, &key, p, BPF_ANY);
	return 0;
}
static __noinline void te_copy_proc_prov(pid_t from, pid_t to, __u64 labels)
{
	struct te_copy_proc_prov_ctx c = { .from = from, .to = to, .labels = labels };
	bpf_loop(te_count(5), te_copy_proc_prov_cb, &c, 0);
}

struct te_copy_file_to_proc_ctx {
	pid_t pid;
	struct file_id fid;
	__u64 labels;
};
static int te_copy_file_prov_to_proc_cb(__u32 i, void *vc)
{
	struct te_copy_file_to_proc_ctx *c = vc;
	if (i >= MAX_TAINT_LABELS)
		return 1;
	__u64 bit = 1ULL << i;
	if (!(c->labels & bit))
		return 0;
	struct file_label_id fk = { .fid = c->fid, .label = bit };
	struct te_prov *p = bpf_map_lookup_elem(&ts_file_prov, &fk);
	if (!p)
		return 0;
	struct pid_label_id pk = { .pid = c->pid, .label = bit };
	bpf_map_update_elem(&ts_proc_prov, &pk, p, BPF_ANY);
	return 0;
}
static __noinline void te_copy_file_prov_to_proc(pid_t pid, struct file_id *fid,
						 __u64 labels)
{
	struct te_copy_file_to_proc_ctx c = {
		.pid = pid,
		.fid = *fid,
		.labels = labels,
	};
	bpf_loop(te_count(5), te_copy_file_prov_to_proc_cb, &c, 0);
}

struct te_copy_proc_to_file_ctx {
	pid_t pid;
	struct file_id fid;
	__u64 labels;
};
static int te_copy_proc_prov_to_file_cb(__u32 i, void *vc)
{
	struct te_copy_proc_to_file_ctx *c = vc;
	if (i >= MAX_TAINT_LABELS)
		return 1;
	__u64 bit = 1ULL << i;
	if (!(c->labels & bit))
		return 0;
	struct te_prov *p = te_lookup_proc_prov(c->pid, bit);
	if (!p)
		return 0;
	struct file_label_id fk = { .fid = c->fid, .label = bit };
	bpf_map_update_elem(&ts_file_prov, &fk, p, BPF_ANY);
	return 0;
}
static __noinline void te_copy_proc_prov_to_file(pid_t pid, struct file_id *fid,
						 __u64 labels)
{
	struct te_copy_proc_to_file_ctx c = {
		.pid = pid,
		.fid = *fid,
		.labels = labels,
	};
	bpf_loop(te_count(5), te_copy_proc_prov_to_file_cb, &c, 0);
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

static __always_inline struct te_sess *te_sess_get(pid_t root)
{
	return bpf_map_lookup_elem(&ts_sess, &root);
}
static __always_inline struct te_sess *te_sess_init(pid_t root)
{
	struct te_sess *s = bpf_map_lookup_elem(&ts_sess, &root);
	if (s)
		return s;
	/* te_sess is >512B, so a zeroed stack template blows the BPF stack. Seed
	 * the new entry from a never-written, BSS-zeroed per-CPU template instead. */
	__u32 k = 0;
	struct te_sess *z = bpf_map_lookup_elem(&ts_sess_zero, &k);
	if (!z)
		return 0;
	bpf_map_update_elem(&ts_sess, &root, z, BPF_NOEXIST);
	return bpf_map_lookup_elem(&ts_sess, &root);
}

/* Bump and return this session's monotonic event counter, creating the session
 * entry if needed. Returns 0 if the session map is unavailable. Callers tick
 * once per OS event, then stamp every gate/invalidator/file touched at that
 * same epoch — so a write and its invalidator share one ordering point. */
static __noinline __u32 te_tick(pid_t root)
{
	struct te_sess *s = te_sess_init(root);
	if (!s)
		return 0;
	s->epoch += 1;
	return s->epoch;
}

/* Stamp the gates and invalidators that fired in one event at `ep`. gate_hits
 * also latch into gate_bits (v1 `after`). The two scans are constant-bound
 * (<= 64) writes through the in-place map-value pointer. */
static __noinline void te_stamp(pid_t root, __u32 ep, __u64 gate_hits, __u64 inval_hits)
{
	if (!ep || (!gate_hits && !inval_hits))
		return;
	struct te_sess *s = te_sess_get(root);
	if (!s)
		return;
	s->gate_bits |= gate_hits;
	for (int i = 0; i < MAX_TAINT_GATES; i++)
		if (gate_hits & (1ULL << i))
			s->gate_epoch[i] = ep;
	for (int i = 0; i < MAX_TAINT_INVALS; i++)
		if (inval_hits & (1ULL << i))
			s->inval_epoch[i] = ep;
}

/* Is a TCOND_AFTER condition satisfied (i.e. the deny is relaxed / allowed)?
 *  - since_mask == 0 : v1 latching — the gate fired at some point.
 *  - since_mask != 0 : v2 staleness — the gate fired AND is still fresh, i.e.
 *    no invalidator in since_mask has fired more recently. */
static __noinline int te_after_satisfied(const struct taint_rule *r, pid_t pid)
{
	pid_t rt = te_root(pid);
	struct te_sess *s = te_sess_get(rt);

	if (!s)
		return 0;
	if (r->since_mask == 0)
		return (s->gate_bits & r->gate) ? 1 : 0;
	__u32 gidx = r->gate_idx;
	if (gidx >= MAX_TAINT_GATES)
		return 0;
	__u32 ge = s->gate_epoch[gidx];
	if (ge == 0)
		return 0; /* gate never fired -> stale */
	__u32 last_inval = 0;
	for (int i = 0; i < MAX_TAINT_INVALS; i++) {
		if (r->since_mask & (1ULL << i)) {
			__u32 ie = s->inval_epoch[i];
			if (ie > last_inval)
				last_inval = ie;
		}
	}
	return ge > last_inval ? 1 : 0;
}

/* fork: child inherits labels + lineage gates; root carries down. */
static __always_inline void te_fork(pid_t ppid, pid_t cpid)
{
	struct proc_state *pp = te_get(ppid);
	struct proc_state ns = { 0 };
	if (pp)
		ns = *pp;
	bpf_map_update_elem(&ts_proc, &cpid, &ns, BPF_ANY);
	if (ns.labels)
		te_copy_proc_prov(ppid, cpid, ns.labels);
	pid_t r = te_root(ppid);
	bpf_map_update_elem(&ts_root, &cpid, &r, BPF_ANY);
	cap_fork(ppid, cpid);
}

/* All policy table scans below run via bpf_loop() (count from ts_counts) so the
 * callback is verified once regardless of table size. The update table is the
 * single low-level IR for sources, xforms, gates, and since invalidators. */
struct te_update_ctx {
	unsigned int op;
	const char *target;
	__u32 ip;
	__u64 add;
	__u64 del;
	__u64 gates;
	__u64 invals;
};

static int te_update_cb(__u32 i, void *vc)
{
	struct te_update_ctx *c = vc;
	int match = 0;

	if (i >= MAX_TAINT_UPDATES)
		return 1;
	struct taint_update u = taint_updates[i];
	if (u.op != c->op)
		return 0;
	if (u.op == TOP_CONNECT)
		match = ((c->ip & u.ipv4_mask) == u.ipv4);
	else if (u.op == TOP_EXEC)
		match = taint_exec_match(u.match, c->target, u.target);
	else
		match = taint_match(u.match, c->target, u.target);
	if (!match)
		return 0;
	c->add |= u.add;
	c->del |= u.del;
	c->gates |= u.gates;
	c->invals |= u.invals;
	return 0;
}

static __noinline void te_collect_updates(struct te_update_ctx *c)
{
	bpf_loop(te_count(1), te_update_cb, c, 0);
}

/* on exec: apply compiled updates for labels, declassification, gates, and
 * exec-side invalidators. All exec patterns are matched on comm. */
static __noinline void te_exec_update(pid_t pid, const char *comm)
{
	struct te_update_ctx c = { .op = TOP_EXEC, .target = comm };

	te_collect_updates(&c);

	struct proc_state *p = te_get(pid);
	struct proc_state ns = { 0 };
	if (p)
		ns = *p;
	ns.labels = (ns.labels | c.add) & ~c.del;
	ns.lin_gates |= c.gates;
	bpf_map_update_elem(&ts_proc, &pid, &ns, BPF_ANY);
	if (c.add)
		te_record_proc_prov_mask(pid, c.add, TOP_EXEC, comm, 0);
	if (c.gates || c.invals) {
		pid_t r = te_root(pid);
		te_stamp(r, te_tick(r), c.gates, c.invals);
	}
}

static __noinline __u64 te_update_add(unsigned int op, const char *target, __u32 ip)
{
	struct te_update_ctx c = { .op = op, .target = target, .ip = ip };

	te_collect_updates(&c);
	return c.add;
}

static __always_inline __u64 te_file_labels(struct file_id *fid, const char *path)
{
	struct file_state *fs = bpf_map_lookup_elem(&ts_file, fid);

	return (fs ? fs->labels : 0) | te_update_add(TOP_OPEN, path, 0);
}

/* read: proc absorbs file labels + file source; stamp `since read` invalidators. */
static __always_inline void te_read(pid_t pid, struct file_id *fid, const char *path)
{
	struct file_state *fs = bpf_map_lookup_elem(&ts_file, fid);
	__u64 file_labels = fs ? fs->labels : 0;
	struct te_update_ctx u = { .op = TOP_OPEN, .target = path };

	te_collect_updates(&u);
	__u64 src_labels = u.add;
	te_add_labels(pid, file_labels | src_labels);
	if (file_labels)
		te_copy_file_prov_to_proc(pid, fid, file_labels);
	if (src_labels)
		te_record_proc_prov_mask(pid, src_labels, TOP_OPEN, path, 0);
	if (u.invals) {
		pid_t r = te_root(pid);
		te_stamp(r, te_tick(r), 0, u.invals);
	}
}
/* write: file absorbs proc labels; stamp `since write` invalidators (this is
 * what makes a gate go stale when the agent edits an input again). The label
 * flow is gated on pl != 0, but invalidator stamping is not — editing an
 * unlabeled source file must still invalidate a prior gate. Layer A: when the
 * file does carry labels (so we already touch ts_file), record this write's
 * epoch as the object's last_write_epoch. */
static __always_inline void te_write_flow(pid_t pid, struct file_id *fid, const char *path)
{
	struct te_update_ctx u = { .op = TOP_WRITE, .target = path };
	te_collect_updates(&u);
	__u64 pl = te_labels(pid);
	if (!u.invals && !pl)
		return;
	pid_t r = te_root(pid);
	__u32 ep = te_tick(r);
	if (u.invals)
		te_stamp(r, ep, 0, u.invals);
	if (pl) {
		struct file_state *fs = bpf_map_lookup_elem(&ts_file, fid);
		if (fs) {
			fs->labels |= pl;
			fs->last_write_epoch = ep;
		} else {
			struct file_state ns = { .labels = pl, .last_write_epoch = ep };
			bpf_map_update_elem(&ts_file, fid, &ns, BPF_ANY);
		}
		te_copy_proc_prov_to_file(pid, fid, pl);
	}
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

static __always_inline int te_cond_satisfied(const struct taint_rule *r,
					     struct te_rule_eval *e)
{
	if (r->cond_kind == TCOND_NONE)
		return 0;
	if (r->cond_kind == TCOND_LINEAGE) {
		struct proc_state *p = te_get(e->pid);
		return p && (p->lin_gates & r->gate);
	}
	if (r->cond_kind == TCOND_AFTER)
		return te_after_satisfied(r, e->pid);
	/* TCOND_TARGET */
	int m;
	if (e->op == TOP_CONNECT)
		m = ((e->ip & r->cond_ipv4_mask) == r->cond_ipv4);
	else if (e->op == TOP_EXEC)
		m = taint_exec_match(r->cond_match, e->target, r->cond_pat);
	else
		m = taint_match(r->cond_match, e->target, r->cond_pat);
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
	if (e->op == TOP_CONNECT) {
		if ((e->ip & r.ipv4_mask) != r.ipv4)
			return -1;
	} else if (e->op == TOP_EXEC) {
		if (!taint_exec_match(r.match, e->target, r.target))
			return -1;
	} else if (!taint_match(r.match, e->target, r.target)) {
		return -1;
	}
	if (e->op == TOP_EXEC && r.arg[0] != '\0') {
		/* Match against the pre-tokenized arg slots. Re-look-up the per-CPU
		 * scratch here so the verifier keeps the map_value bound. */
		struct te_argslots *a = te_argslots_buf();
		if (!a || !taint_arg_match(a->slots, r.arg))
			return -1;
	}
	if (te_cond_satisfied(&r, e))
		return -1;
	e->matched_rule = (int)r.rule_id;
	e->matched_req = r.req;
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
	struct te_rule_ctx c = { .e = e, .best_effect = TEFFECT_NOTIFY, .best_rule = -1 };
	bpf_loop(te_count(0), te_rule_cb, &c, 0);
	if (c.best_rule >= 0)
		e->effect = c.best_effect;
	return c.best_rule;
}

static __always_inline void te_exit(pid_t pid)
{
	bpf_map_delete_elem(&ts_proc, &pid);
	bpf_map_delete_elem(&ts_root, &pid);
	cap_exit(pid);
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		struct pid_label_id key = { .pid = pid, .label = 1ULL << i };
		bpf_map_delete_elem(&ts_proc_prov, &key);
	}
}

#endif /* __TAINT_ENGINE_BPF_H */
