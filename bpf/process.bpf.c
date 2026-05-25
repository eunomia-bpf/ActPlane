// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 eunomia-bpf org. */
//
// ActPlane in-kernel taint enforcer. Each hook propagates taint and evaluates
// the compiled rules; the ONLY event emitted is a TAINT_VIOLATION, via the
// single emit_violation() function, when a rule matches.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"
#include "taint_engine.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile unsigned int enforce_mode = 0;

#ifndef EPERM
#define EPERM 1
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef O_ACCMODE
#define O_ACCMODE 00000003
#endif
#ifndef O_RDONLY
#define O_RDONLY 00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef MAY_EXEC
#define MAY_EXEC 1
#endif
#ifndef MAY_WRITE
#define MAY_WRITE 2
#endif
#ifndef MAY_READ
#define MAY_READ 4
#endif

#define TE_MODE_AUDIT 0
#define TE_MODE_BLOCK 1
#define TE_MODE_KILL  2
#define TE_MODE_UNSUPPORTED 3

#define TE_ACCESS_READ    (1U << 0)
#define TE_ACCESS_WRITE   (1U << 1)
#define TE_ACCESS_EXEC    (1U << 2)
#define TE_ACCESS_CONNECT (1U << 3)

#define TE_OBJ_EXEC     1
#define TE_OBJ_FILE     2
#define TE_OBJ_ENDPOINT 3

#define TE_REF_FILE          1
#define TE_REF_PATH          2
#define TE_REF_PATH_DENTRY   3
#define TE_REF_USER_PATH     4
#define TE_REF_BPRM          5
#define TE_REF_STRINGS       6
#define TE_REF_SOCKADDR_KERN 7
#define TE_REF_SOCKADDR_USER 8

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Pending open(at) args, stashed at sys_enter and consumed at sys_exit. The
 * sys_enter tracepoint fires before the kernel's copy_from_user faults the path
 * page in, so a non-faulting read of the path there can EFAULT and silently drop
 * the open (notably a fresh exec's own .rodata path, touched first at open()).
 * By sys_exit the page is resident, so the read is reliable. Keyed by tid. */
struct open_pend {
	__u64 path_ptr;
	__u32 flags;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct open_pend);
} ts_openpend SEC(".maps");

/* The one and only output channel. */
static __always_inline void emit_violation(pid_t pid, unsigned int rule_id,
					   const char *target, u32 conn_ip,
					   unsigned int blocked,
					   unsigned int killed,
					   unsigned int effect)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *v = bpf_ringbuf_reserve(&rb, sizeof(*v), 0);
	if (!v)
		return;
	v->type = EVENT_TYPE_TAINT_VIOLATION;
	v->pid = pid;
	v->ppid = BPF_CORE_READ(task, real_parent, tgid);
	v->blocked = blocked;
	v->killed = killed;
	v->effect = effect;
	v->timestamp_ns = bpf_ktime_get_ns();
	v->taint_rule_id = rule_id;
	v->conn_ip = conn_ip;
	v->taint_label = te_labels(pid);
	bpf_get_current_comm(&v->comm, sizeof(v->comm));
	v->filename[0] = '\0';
	if (target)
		bpf_probe_read_kernel_str(&v->filename, sizeof(v->filename), target);
	bpf_ringbuf_submit(v, 0);
}

static __always_inline int file_path(struct file *file, char *path, int path_sz)
{
	struct path fpath;

	__builtin_memset(&fpath, 0, sizeof(fpath));
	BPF_CORE_READ_INTO(&fpath, file, f_path);
	if (bpf_d_path(&fpath, path, path_sz) > 0)
		return 0;

	struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *name = BPF_CORE_READ(de, d_name.name);
	if (name && bpf_probe_read_kernel_str(path, path_sz, name) > 0)
		return 0;
	return -1;
}

static __always_inline int path_to_str(const struct path *src, char *path,
				       int path_sz)
{
	struct path p;

	__builtin_memset(&p, 0, sizeof(p));
	bpf_probe_read_kernel(&p, sizeof(p), src);
	if (bpf_d_path(&p, path, path_sz) > 0)
		return 0;
	return -1;
}

static __always_inline void append_dentry_name(char *path, struct dentry *dentry)
{
	char name_buf[TAINT_PAT_LEN] = {};
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	int off = 0;

	if (!name || bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), name) < 0)
		return;
	for (int i = 0; i < MAX_FILENAME_LEN; i++) {
		if (path[i] == '\0') {
			off = i;
			break;
		}
	}
	if (off <= 0 || off >= MAX_FILENAME_LEN - 1)
		return;
	if (path[off - 1] != '/')
		path[off++] = '/';
	for (int j = 0; j < TAINT_PAT_LEN; j++) {
		if (off + j >= MAX_FILENAME_LEN)
			break;
		path[off + j] = name_buf[j];
		if (name_buf[j] == '\0')
			break;
	}
	path[MAX_FILENAME_LEN - 1] = '\0';
}

static __always_inline int path_dentry_to_str(const struct path *dir,
					      struct dentry *dentry,
					      char *path, int path_sz)
{
	if (path_to_str(dir, path, path_sz) < 0)
		return -1;
	append_dentry_name(path, dentry);
	return 0;
}

static __always_inline int bprm_basename(struct linux_binprm *bprm, char *base,
					 int base_sz)
{
	struct file *file = BPF_CORE_READ(bprm, file);
	struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *name = BPF_CORE_READ(de, d_name.name);

	if (name && bpf_probe_read_kernel_str(base, base_sz, name) > 0)
		return 0;
	return -1;
}

static __always_inline int bprm_filename(struct linux_binprm *bprm, char *path,
					 int path_sz)
{
	const char *filename = BPF_CORE_READ(bprm, filename);

	if (filename && bpf_probe_read_kernel_str(path, path_sz, filename) > 0)
		return 0;
	return -1;
}

struct te_event {
	pid_t pid;
	__u32 obj_kind;
	__u32 access;
	__u32 mode;
	const char *target;
	const char *display;
	const char *argv;
	int argv_len;
	__u32 ip;
};

static __always_inline __u32 te_access_from_open_flags(unsigned int flags)
{
	int acc = flags & O_ACCMODE;
	__u32 access = 0;

	if (acc != O_WRONLY)
		access |= TE_ACCESS_READ;
	if (acc != O_RDONLY || (flags & (O_CREAT | O_TRUNC)))
		access |= TE_ACCESS_WRITE;
	return access;
}

static __always_inline __u32 te_access_from_perm_mask(int mask)
{
	__u32 access = 0;

	if (mask & MAY_READ)
		access |= TE_ACCESS_READ;
	if (mask & MAY_WRITE)
		access |= TE_ACCESS_WRITE;
	return access;
}

static __always_inline __u32 te_tracepoint_mode(void)
{
	return TE_MODE_AUDIT;
}

static __always_inline __u32 te_effect_mode(__u32 backend_mode, __u32 effect)
{
	if (effect == TEFFECT_AUDIT)
		return TE_MODE_AUDIT;
	if (effect == TEFFECT_KILL)
		return TE_MODE_KILL;
	if (effect == TEFFECT_BLOCK && backend_mode == TE_MODE_BLOCK)
		return TE_MODE_BLOCK;
	return TE_MODE_UNSUPPORTED;
}

static __always_inline __u32 te_supported_effects(__u32 backend_mode)
{
	if (backend_mode == TE_MODE_BLOCK)
		return (1U << TEFFECT_AUDIT) |
		       (1U << TEFFECT_BLOCK) |
		       (1U << TEFFECT_KILL);
	return (1U << TEFFECT_AUDIT) | (1U << TEFFECT_KILL);
}

static __always_inline int te_better_match(int candidate_rule, __u32 candidate_effect,
					   int current_rule, __u32 current_effect)
{
	return candidate_rule >= 0 &&
	       (current_rule < 0 || candidate_effect > current_effect);
}

static __always_inline int te_resolve_file_ref(__u32 ref_kind, const void *a,
					       const void *b, char *path,
					       int path_sz)
{
	switch (ref_kind) {
	case TE_REF_FILE:
		return file_path((struct file *)a, path, path_sz);
	case TE_REF_PATH:
		return path_to_str((const struct path *)a, path, path_sz);
	case TE_REF_PATH_DENTRY:
		return path_dentry_to_str((const struct path *)a, (struct dentry *)b,
					  path, path_sz);
	case TE_REF_USER_PATH:
		return bpf_probe_read_user_str(path, path_sz, a) > 0 ? 0 : -1;
	default:
		return -1;
	}
}

static __always_inline int te_resolve_sockaddr(__u32 ref_kind, const void *addr,
					       __u32 *ip)
{
	struct sockaddr_in sa = {};
	u16 family = 0;

	if (ref_kind == TE_REF_SOCKADDR_USER) {
		if (bpf_probe_read_user(&family, sizeof(family), addr) < 0)
			return -1;
		if (family != AF_INET)
			return -1;
		if (bpf_probe_read_user(&sa, sizeof(sa), addr) < 0)
			return -1;
	} else {
		if (bpf_probe_read_kernel(&family, sizeof(family), addr) < 0)
			return -1;
		if (family != AF_INET)
			return -1;
		if (bpf_probe_read_kernel(&sa, sizeof(sa), addr) < 0)
			return -1;
	}
	*ip = sa.sin_addr.s_addr;
	return 0;
}

static __always_inline int te_handle_event(struct te_event *ev)
{
	__u64 labels = te_labels(ev->pid);
	struct te_rule_eval eval = {};
	const char *display = ev->display ? ev->display : ev->target;
	__u32 effect = TEFFECT_AUDIT;
	__u32 action = TE_MODE_AUDIT;
	int rid = -1;
	int candidate = -1;

	if (ev->obj_kind == TE_OBJ_FILE && (ev->access & TE_ACCESS_READ))
		labels |= te_file_labels(ev->target);
	if (ev->obj_kind == TE_OBJ_ENDPOINT && (ev->access & TE_ACCESS_CONNECT))
		labels |= te_endp_src_ip(ev->ip);

	if (ev->obj_kind == TE_OBJ_EXEC) {
		eval.pid = ev->pid;
		eval.labels = labels;
		eval.effect = TEFFECT_BLOCK;
		eval.effect_mask = te_supported_effects(ev->mode);
		eval.op = TOP_EXEC;
		eval.target = ev->target;
		eval.argv = ev->argv;
		eval.argv_len = ev->argv_len;
		rid = te_check_labels(&eval);
		effect = eval.effect;
	} else if (ev->obj_kind == TE_OBJ_FILE) {
		eval.pid = ev->pid;
		eval.labels = labels;
		eval.effect = TEFFECT_BLOCK;
		eval.effect_mask = te_supported_effects(ev->mode);
		eval.target = ev->target;
		if (ev->access & TE_ACCESS_READ) {
			eval.op = TOP_OPEN;
			candidate = te_check_labels(&eval);
			if (te_better_match(candidate, eval.effect, rid, effect)) {
				rid = candidate;
				effect = eval.effect;
			}
		}
		if (ev->access & TE_ACCESS_WRITE) {
			eval.effect = TEFFECT_BLOCK;
			eval.op = TOP_WRITE;
			candidate = te_check_labels(&eval);
			if (te_better_match(candidate, eval.effect, rid, effect)) {
				rid = candidate;
				effect = eval.effect;
			}
		}
	} else if (ev->obj_kind == TE_OBJ_ENDPOINT) {
		eval.pid = ev->pid;
		eval.labels = labels;
		eval.effect = TEFFECT_BLOCK;
		eval.effect_mask = te_supported_effects(ev->mode);
		rid = te_connect_check_labels(&eval, ev->ip);
		effect = eval.effect;
	}

	if (rid >= 0) {
		action = te_effect_mode(ev->mode, effect);
		if (action != TE_MODE_UNSUPPORTED)
			emit_violation(ev->pid, rid, display,
				       ev->obj_kind == TE_OBJ_ENDPOINT ? ev->ip : 0,
				       action == TE_MODE_BLOCK ||
					       (action == TE_MODE_KILL && ev->mode == TE_MODE_BLOCK),
				       action == TE_MODE_KILL, effect);
		if (action == TE_MODE_BLOCK)
			return -EPERM;
		if (action == TE_MODE_KILL) {
			bpf_send_signal(SIGKILL);
			if (ev->mode == TE_MODE_BLOCK)
				return -EPERM;
		}
	}

	if (ev->obj_kind == TE_OBJ_FILE) {
		if (ev->access & TE_ACCESS_READ)
			te_read(ev->pid, ev->target);
		if (ev->access & TE_ACCESS_WRITE)
			te_write_flow(ev->pid, ev->target);
	} else if (ev->obj_kind == TE_OBJ_ENDPOINT) {
		te_add_labels(ev->pid, te_endp_src_ip(ev->ip));
		te_connect_flow(ev->ip, ev->pid);
	}

	return 0;
}

static __always_inline int te_handle_file(__u32 ref_kind, const void *a,
					  const void *b, __u32 access,
					  __u32 mode)
{
	char path[MAX_FILENAME_LEN] = {};
	struct te_event ev = {};

	if ((mode == TE_MODE_BLOCK && !enforce_mode) ||
	    ((mode == TE_MODE_AUDIT || mode == TE_MODE_KILL) && enforce_mode))
		return 0;
	if (!access)
		return 0;
	if (te_resolve_file_ref(ref_kind, a, b, path, sizeof(path)) < 0)
		return 0;

	ev.pid = bpf_get_current_pid_tgid() >> 32;
	ev.obj_kind = TE_OBJ_FILE;
	ev.access = access;
	ev.mode = mode;
	ev.target = path;
	return te_handle_event(&ev);
}

static __always_inline int te_handle_net(__u32 ref_kind, const void *a,
					 const void *b, __u32 access,
					 __u32 mode)
{
	struct te_event ev = {};
	__u32 ip = 0;

	(void)b;
	if ((mode == TE_MODE_BLOCK && !enforce_mode) ||
	    ((mode == TE_MODE_AUDIT || mode == TE_MODE_KILL) && enforce_mode))
		return 0;
	if (!(access & TE_ACCESS_CONNECT))
		return 0;
	if (te_resolve_sockaddr(ref_kind, a, &ip) < 0)
		return 0;

	ev.pid = bpf_get_current_pid_tgid() >> 32;
	ev.obj_kind = TE_OBJ_ENDPOINT;
	ev.access = access;
	ev.mode = mode;
	ev.ip = ip;
	return te_handle_event(&ev);
}

static __always_inline int te_handle_exec(__u32 ref_kind, const void *a,
					  const void *b, const char *argv,
					  int argv_len, __u32 mode)
{
	char match[TAINT_TEXT_BUF] = {}; /* >= PAT_LEN+SUF_MAX for suffix tail copy */
	char display[MAX_FILENAME_LEN] = {};
	const char *target = match;
	const char *shown = display;
	struct te_event ev = {};

	if ((mode == TE_MODE_BLOCK && !enforce_mode) ||
	    ((mode == TE_MODE_AUDIT || mode == TE_MODE_KILL) && enforce_mode))
		return 0;
	if (ref_kind == TE_REF_BPRM) {
		if (bprm_basename((struct linux_binprm *)a, match, sizeof(match)) < 0)
			return 0;
		if (bprm_filename((struct linux_binprm *)a, display, sizeof(display)) < 0)
			__builtin_memcpy(display, match, sizeof(match));
	} else if (ref_kind == TE_REF_STRINGS) {
		target = a;
		shown = b ? b : a;
		if (!target)
			return 0;
	} else {
		return 0;
	}

	ev.pid = bpf_get_current_pid_tgid() >> 32;
	ev.obj_kind = TE_OBJ_EXEC;
	ev.access = TE_ACCESS_EXEC;
	ev.mode = mode;
	ev.target = target;
	ev.display = shown;
	ev.argv = argv;
	ev.argv_len = argv_len;
	return te_handle_event(&ev);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm_check_security, struct linux_binprm *bprm)
{
	return te_handle_exec(TE_REF_BPRM, bprm, 0, 0, 0, TE_MODE_BLOCK);
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	return te_handle_file(TE_REF_FILE, file, 0,
			      te_access_from_open_flags(BPF_CORE_READ(file, f_flags)),
			      TE_MODE_BLOCK);
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_permission, struct file *file, int mask)
{
	return te_handle_file(TE_REF_FILE, file, 0, te_access_from_perm_mask(mask),
			      TE_MODE_BLOCK);
}

SEC("lsm/file_truncate")
int BPF_PROG(enforce_file_truncate, struct file *file)
{
	return te_handle_file(TE_REF_FILE, file, 0, TE_ACCESS_WRITE, TE_MODE_BLOCK);
}

SEC("lsm/path_truncate")
int BPF_PROG(enforce_path_truncate, const struct path *path_arg)
{
	return te_handle_file(TE_REF_PATH, path_arg, 0, TE_ACCESS_WRITE, TE_MODE_BLOCK);
}

SEC("lsm/path_unlink")
int BPF_PROG(enforce_path_unlink, const struct path *dir, struct dentry *dentry)
{
	return te_handle_file(TE_REF_PATH_DENTRY, dir, dentry, TE_ACCESS_WRITE,
			      TE_MODE_BLOCK);
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	(void)flags;
	if (te_handle_file(TE_REF_PATH_DENTRY, old_dir, old_dentry,
			   TE_ACCESS_WRITE, TE_MODE_BLOCK) < 0)
		return -EPERM;
	if (te_handle_file(TE_REF_PATH_DENTRY, new_dir, new_dentry,
			   TE_ACCESS_WRITE, TE_MODE_BLOCK) < 0)
		return -EPERM;
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	(void)sock;
	(void)addrlen;
	return te_handle_net(TE_REF_SOCKADDR_KERN, address, 0,
			     TE_ACCESS_CONNECT, TE_MODE_BLOCK);
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	te_fork(ctx->parent_pid, ctx->child_pid);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	char comm[TAINT_TEXT_BUF] = {}; /* >= PAT_LEN+SUF_MAX so matchers stay in-bounds */
	char fname[MAX_FILENAME_LEN] = {};
	unsigned fname_off;
	int alen = 0;
	char *slots = 0;

	bpf_get_current_comm(&comm, TASK_COMM_LEN);
	te_exec_update(pid, comm);

	/* read argv blob (NUL-separated) into per-CPU scratch, then tokenize into
	 * fixed slots there for @arg matching — see te_tokenize_args_eng / taint_arg_match. */
	struct te_argslots *as = te_argslots_buf();
	if (as) {
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		unsigned long a0 = BPF_CORE_READ(mm, arg_start);
		unsigned long a1 = BPF_CORE_READ(mm, arg_end);
		unsigned long len = a1 - a0;
		if (len > TAINT_ARGV_CAP - 1)
			len = TAINT_ARGV_CAP - 1;
		__builtin_memset(as, 0, sizeof(*as));
		if (len > 0 && bpf_probe_read_user(as->blob, len, (void *)a0) == 0)
			alen = (int)len;
		te_tokenize_args_eng(alen);
		slots = as->slots;
	}

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(fname, sizeof(fname), (void *)ctx + fname_off);
	te_handle_exec(TE_REF_STRINGS, comm, fname, slots, alen, te_tracepoint_mode());
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	if (pid != (u32)id)
		return 0;
	te_exit(pid);
	return 0;
}

/* Stash the path pointer + flags; the actual handling happens at sys_exit, once
 * the path page is resident (see ts_openpend). Tracking opens at exit also means
 * we only act on opens that actually entered the kernel, which is fine for the
 * audit/kill model (kill still terminates the offending process). */
static __always_inline int stash_open(const void *path_ptr, unsigned int flags)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct open_pend p = { .path_ptr = (__u64)path_ptr, .flags = flags };

	bpf_map_update_elem(&ts_openpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_open_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct open_pend *p = bpf_map_lookup_elem(&ts_openpend, &tid);
	int rc = 0;

	if (!p)
		return 0;
	/* On success the kernel has copied the path in, so the user page is now
	 * resident and the read in te_handle_file is reliable. */
	if (ret >= 0)
		rc = te_handle_file(TE_REF_USER_PATH, (const void *)p->path_ptr, 0,
				    te_access_from_open_flags(p->flags),
				    te_tracepoint_mode());
	bpf_map_delete_elem(&ts_openpend, &tid);
	return rc;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	return stash_open((const void *)ctx->args[1], (unsigned int)ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	return stash_open((const void *)ctx->args[0], (unsigned int)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	return te_handle_file(TE_REF_USER_PATH, (const void *)ctx->args[0], 0,
			      TE_ACCESS_WRITE, te_tracepoint_mode());
}
SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return te_handle_file(TE_REF_USER_PATH, (const void *)ctx->args[1], 0,
			      TE_ACCESS_WRITE, te_tracepoint_mode());
}
SEC("tp/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	return te_handle_file(TE_REF_USER_PATH, (const void *)ctx->args[1], 0,
			      TE_ACCESS_WRITE, te_tracepoint_mode());
}
SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return te_handle_file(TE_REF_USER_PATH, (const void *)ctx->args[3], 0,
			      TE_ACCESS_WRITE, te_tracepoint_mode());
}
SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return te_handle_file(TE_REF_USER_PATH, (const void *)ctx->args[3], 0,
			      TE_ACCESS_WRITE, te_tracepoint_mode());
}

/* connect: numeric IPv4 matching (compiler lowers host/IP patterns to net+mask;
 * no in-kernel string formatting, so no verifier-rejected pointer arithmetic).
 * The reported IP is formatted by the userspace loader from conn_ip. */
SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	return te_handle_net(TE_REF_SOCKADDR_USER, (const void *)ctx->args[1], 0,
			     TE_ACCESS_CONNECT, te_tracepoint_mode());
}
