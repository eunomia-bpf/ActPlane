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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* The one and only output channel. */
static __always_inline void emit_violation(pid_t pid, unsigned int rule_id,
					   const char *target, u32 conn_ip,
					   unsigned int blocked)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event *v = bpf_ringbuf_reserve(&rb, sizeof(*v), 0);
	if (!v)
		return;
	v->type = EVENT_TYPE_TAINT_VIOLATION;
	v->pid = pid;
	v->ppid = BPF_CORE_READ(task, real_parent, tgid);
	v->blocked = blocked;
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

static __always_inline int check_file_access(pid_t pid, const char *path,
					     int can_read, int can_write,
					     unsigned int blocked)
{
	int rid;

	if (can_read) {
		rid = te_check(pid, TOP_OPEN, path, 0, 0);
		if (rid >= 0) {
			emit_violation(pid, rid, path, 0, blocked);
			return rid;
		}
	}
	if (can_write) {
		rid = te_check(pid, TOP_WRITE, path, 0, 0);
		if (rid >= 0) {
			emit_violation(pid, rid, path, 0, blocked);
			return rid;
		}
	}
	return -1;
}

static __always_inline int check_write_path(pid_t pid, const char *path,
					    unsigned int blocked)
{
	int rid = te_check(pid, TOP_WRITE, path, 0, 0);

	if (rid >= 0) {
		emit_violation(pid, rid, path, 0, blocked);
		return rid;
	}
	return -1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm_check_security, struct linux_binprm *bprm)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char base[TAINT_PAT_LEN] = {};
	char target[MAX_FILENAME_LEN] = {};
	int rid;

	if (!enforce_mode)
		return 0;
	if (bprm_basename(bprm, base, sizeof(base)) < 0)
		return 0;
	rid = te_check(pid, TOP_EXEC, base, 0, 0);
	if (rid < 0)
		return 0;
	if (bprm_filename(bprm, target, sizeof(target)) < 0)
		__builtin_memcpy(target, base, sizeof(base));
	emit_violation(pid, rid, target, 0, 1);
	return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char path[MAX_FILENAME_LEN] = {};
	unsigned int flags;
	int acc, can_read, can_write;

	if (!enforce_mode)
		return 0;
	if (file_path(file, path, sizeof(path)) < 0)
		return 0;

	flags = BPF_CORE_READ(file, f_flags);
	acc = flags & O_ACCMODE;
	can_read = acc != O_WRONLY;
	can_write = acc != O_RDONLY || (flags & (O_CREAT | O_TRUNC));
	if (check_file_access(pid, path, can_read, can_write, 1) >= 0)
		return -EPERM;

	if (can_read)
		te_read(pid, path);
	if (can_write)
		te_write_flow(pid, path);
	return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_permission, struct file *file, int mask)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char path[MAX_FILENAME_LEN] = {};
	int can_read = mask & MAY_READ;
	int can_write = mask & MAY_WRITE;

	if (!enforce_mode || (!can_read && !can_write))
		return 0;
	if (file_path(file, path, sizeof(path)) < 0)
		return 0;
	if (check_file_access(pid, path, can_read, can_write, 1) >= 0)
		return -EPERM;

	if (can_read)
		te_read(pid, path);
	if (can_write)
		te_write_flow(pid, path);
	return 0;
}

SEC("lsm/file_truncate")
int BPF_PROG(enforce_file_truncate, struct file *file)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char path[MAX_FILENAME_LEN] = {};

	if (!enforce_mode)
		return 0;
	if (file_path(file, path, sizeof(path)) < 0)
		return 0;
	if (check_write_path(pid, path, 1) >= 0)
		return -EPERM;
	te_write_flow(pid, path);
	return 0;
}

SEC("lsm/path_truncate")
int BPF_PROG(enforce_path_truncate, const struct path *path_arg)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char path[MAX_FILENAME_LEN] = {};

	if (!enforce_mode)
		return 0;
	if (path_to_str(path_arg, path, sizeof(path)) < 0)
		return 0;
	if (check_write_path(pid, path, 1) >= 0)
		return -EPERM;
	te_write_flow(pid, path);
	return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(enforce_path_unlink, const struct path *dir, struct dentry *dentry)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char path[MAX_FILENAME_LEN] = {};

	if (!enforce_mode)
		return 0;
	if (path_dentry_to_str(dir, dentry, path, sizeof(path)) < 0)
		return 0;
	if (check_write_path(pid, path, 1) >= 0)
		return -EPERM;
	te_write_flow(pid, path);
	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char old_path[MAX_FILENAME_LEN] = {};
	char new_path[MAX_FILENAME_LEN] = {};

	(void)flags;
	if (!enforce_mode)
		return 0;
	if (path_dentry_to_str(old_dir, old_dentry, old_path, sizeof(old_path)) == 0 &&
	    check_write_path(pid, old_path, 1) >= 0)
		return -EPERM;
	if (path_dentry_to_str(new_dir, new_dentry, new_path, sizeof(new_path)) == 0 &&
	    check_write_path(pid, new_path, 1) >= 0)
		return -EPERM;
	if (old_path[0] != '\0')
		te_write_flow(pid, old_path);
	if (new_path[0] != '\0')
		te_write_flow(pid, new_path);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(enforce_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct sockaddr_in sa = {};
	u16 family = 0;
	u32 ip;
	int rid;

	(void)sock;
	(void)addrlen;
	if (!enforce_mode)
		return 0;
	if (bpf_probe_read_kernel(&family, sizeof(family), address) < 0)
		return 0;
	if (family != AF_INET)
		return 0;
	if (bpf_probe_read_kernel(&sa, sizeof(sa), address) < 0)
		return 0;
	ip = sa.sin_addr.s_addr;

	te_add_labels(pid, te_endp_src_ip(ip));
	rid = te_connect_check(pid, ip);
	if (rid >= 0) {
		emit_violation(pid, rid, 0, ip, 1);
		return -EPERM;
	}
	te_connect_flow(ip, pid);
	return 0;
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
	char comm[TAINT_PAT_LEN] = {}; /* >= pattern len so matchers stay in-bounds */
	char argv[TAINT_ARGV_CAP];
	char fname[MAX_FILENAME_LEN];
	unsigned fname_off;
	int alen = 0, rid;

	bpf_get_current_comm(&comm, TASK_COMM_LEN);
	te_exec_update(pid, comm);

	/* read argv blob (NUL-separated) for @arg matching */
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	unsigned long a0 = BPF_CORE_READ(mm, arg_start);
	unsigned long a1 = BPF_CORE_READ(mm, arg_end);
	unsigned long len = a1 - a0;
	if (len > TAINT_ARGV_CAP - 1)
		len = TAINT_ARGV_CAP - 1;
	if (len > 0 && bpf_probe_read_user(argv, len, (void *)a0) == 0)
		alen = (int)len;

	rid = te_check(pid, TOP_EXEC, comm, argv, alen);
	if (rid >= 0) {
		fname_off = ctx->__data_loc_filename & 0xFFFF;
		bpf_probe_read_str(fname, sizeof(fname), (void *)ctx + fname_off);
		emit_violation(pid, rid, fname, 0, 0);
	}
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

/* open flag bits (not always in vmlinux.h) */
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
#define TAINT_WRITE_FLAGS (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)

static __always_inline void do_open(pid_t pid, const char *upath, u64 flags)
{
	char path[MAX_FILENAME_LEN];
	int rid;
	if (enforce_mode)
		return;
	if (bpf_probe_read_user_str(path, sizeof(path), upath) < 0)
		return;
	te_read(pid, path); /* read(p,f): proc absorbs file labels + file source */
	if (flags & TAINT_WRITE_FLAGS) {
		te_write_flow(pid, path); /* write(p,f): file inherits writer labels */
		rid = te_check(pid, TOP_WRITE, path, 0, 0);
		if (rid >= 0) {
			emit_violation(pid, rid, path, 0, 0);
			return;
		}
	}
	rid = te_check(pid, TOP_OPEN, path, 0, 0);
	if (rid >= 0)
		emit_violation(pid, rid, path, 0, 0);
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	do_open(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[1], ctx->args[2]);
	return 0;
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	do_open(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[0], ctx->args[1]);
	return 0;
}

static __always_inline void do_mutate(pid_t pid, const char *upath)
{
	char path[MAX_FILENAME_LEN];
	int rid;
	if (enforce_mode)
		return;
	if (bpf_probe_read_user_str(path, sizeof(path), upath) < 0)
		return;
	te_write_flow(pid, path); /* proc -> file propagation */
	rid = te_check(pid, TOP_WRITE, path, 0, 0);
	if (rid >= 0)
		emit_violation(pid, rid, path, 0, 0);
}

SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	do_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[0]);
	return 0;
}
SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	do_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[1]);
	return 0;
}
SEC("tp/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	do_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[1]);
	return 0;
}
SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	do_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[3]);
	return 0;
}
SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	do_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[3]);
	return 0;
}

/* connect: numeric IPv4 matching (compiler lowers host/IP patterns to net+mask;
 * no in-kernel string formatting, so no verifier-rejected pointer arithmetic).
 * The reported IP is formatted by the userspace loader from conn_ip. */
SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void *uaddr = (const void *)ctx->args[1];
	int rid;
	u16 family = 0;

	if (enforce_mode)
		return 0;
	if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
		return 0;
	if (family != 2) /* AF_INET */
		return 0;
	struct sockaddr_in sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) < 0)
		return 0;
	u32 ip = sa.sin_addr.s_addr; /* network byte order */

	te_add_labels(pid, te_endp_src_ip(ip));   /* endpoint source taints connector */
	te_connect_flow(ip, pid);                 /* proc -> endpoint */
	rid = te_connect_check(pid, ip);
	if (rid >= 0)
		emit_violation(pid, rid, 0, ip, 0);
	return 0;
}
