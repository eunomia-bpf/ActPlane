// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 eunomia-bpf org. */
//
// ActPlane in-kernel taint enforcer.
//
// Every hook observes an operation, updates taint state, and checks the
// compiled rules. The ONLY event ever emitted to userspace is a
// TAINT_VIOLATION, produced by the single emit_violation() function when a
// rule actually matches. There is no general event tracing here.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"
#include "taint_engine.bpf.h" // taint_labels map, rodata rules, te_* helpers

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* The one and only output channel. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* THE single event-reporting function: emit a TAINT_VIOLATION and nothing
 * else. Called only when a rule has matched. `target` is the offending
 * exe/path/host string. */
static __always_inline void emit_violation(pid_t pid, unsigned int rule_id,
					   const char *target)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u64 *cur = bpf_map_lookup_elem(&taint_labels, &pid);
	struct event *v = bpf_ringbuf_reserve(&rb, sizeof(*v), 0);
	if (!v)
		return;
	v->type = EVENT_TYPE_TAINT_VIOLATION;
	v->pid = pid;
	v->ppid = BPF_CORE_READ(task, real_parent, tgid);
	v->timestamp_ns = bpf_ktime_get_ns();
	v->taint_rule_id = rule_id;
	v->taint_label = cur ? *cur : 0;
	bpf_get_current_comm(&v->comm, sizeof(v->comm));
	bpf_probe_read_kernel_str(&v->filename, sizeof(v->filename), target);
	bpf_ringbuf_submit(v, 0);
}

/* fork: child inherits parent's taint (provenance propagation). */
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	te_fork(ctx->parent_pid, ctx->child_pid);
	return 0;
}

/* exec: acquire any source label this binary introduces, then check exec sink. */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	char comm[TASK_COMM_LEN];
	unsigned int rule_id = 0;
	u64 label;

	bpf_get_current_comm(&comm, sizeof(comm));
	label = te_exec_label(pid, comm);
	if (label && te_exec_sink(comm, label, &rule_id)) {
		unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
		char fname[MAX_FILENAME_LEN];
		bpf_probe_read_str(fname, sizeof(fname), (void *)ctx + fname_off);
		emit_violation(pid, rule_id, fname);
	}
	return 0;
}

/* exit: drop the pid's taint label so the map doesn't leak. */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	if (pid != (u32)id) /* ignore thread exits */
		return 0;
	te_exit(pid);
	return 0;
}

/* file-open sink helper (shared by openat/open). */
static __always_inline void check_open(pid_t pid, const char *upath)
{
	char path[MAX_FILENAME_LEN];
	unsigned int rule_id = 0;
	if (bpf_probe_read_user_str(path, sizeof(path), upath) < 0)
		return;
	if (te_prefix_sink(pid, path, TAINT_SINK_FILE_OPEN, &rule_id))
		emit_violation(pid, rule_id, path);
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	check_open(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[1]);
	return 0;
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	check_open(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[0]);
	return 0;
}

/* file-mutate sink helper (unlink/rename). */
static __always_inline void check_mutate(pid_t pid, const char *upath)
{
	char path[MAX_FILENAME_LEN];
	unsigned int rule_id = 0;
	if (bpf_probe_read_user_str(path, sizeof(path), upath) < 0)
		return;
	if (te_prefix_sink(pid, path, TAINT_SINK_FILE_MUTATE, &rule_id))
		emit_violation(pid, rule_id, path);
}

SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	check_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[0]);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	check_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[1]);
	return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	check_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[1]); /* newpath */
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	check_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[3]); /* newpath */
	return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	check_mutate(bpf_get_current_pid_tgid() >> 32, (const char *)ctx->args[3]); /* newpath */
	return 0;
}

/* Format an IPv4 address (network byte order) into "a.b.c.d". Index is masked
 * to keep the verifier happy (buf must be >= 16 bytes). */
static __always_inline void fmt_ipv4(u32 net_addr, char *buf)
{
	unsigned char *o = (unsigned char *)&net_addr;
	int p = 0;
	TAINT_UNROLL
	for (int k = 0; k < 4; k++) {
		unsigned v = o[k];
		if (v >= 100) {
			buf[p++ & 15] = '0' + v / 100;
			v %= 100;
			buf[p++ & 15] = '0' + v / 10;
			buf[p++ & 15] = '0' + v % 10;
		} else if (v >= 10) {
			buf[p++ & 15] = '0' + v / 10;
			buf[p++ & 15] = '0' + v % 10;
		} else {
			buf[p++ & 15] = '0' + v;
		}
		if (k < 3)
			buf[p++ & 15] = '.';
	}
	buf[p & 15] = '\0';
}

/* connect sink: tainted process connecting to a forbidden IPv4 prefix.
 * (Hostname-level rules need userspace DNS/SNI resolution; out of kernel scope.) */
SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	const void *uaddr = (const void *)ctx->args[1];
	unsigned int rule_id = 0;
	u16 family = 0;
	char ip[16];

	if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
		return 0;
	if (family != 2) /* AF_INET only for the in-kernel IP match */
		return 0;

	struct sockaddr_in sa = {};
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) < 0)
		return 0;
	fmt_ipv4(sa.sin_addr.s_addr, ip);
	if (te_prefix_sink(pid, ip, TAINT_SINK_CONNECT, &rule_id))
		emit_violation(pid, rule_id, ip);
	return 0;
}
