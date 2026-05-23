// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ActPlane: per-pid taint label bitmask. Propagated along the process tree. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} taint_labels SEC(".maps");

/* ActPlane: compiled taint rules, populated from userspace (DSL compiler). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TAINT_RULES);
	__type(key, u32);
	__type(value, struct taint_rule);
} taint_rules SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
/* number of active entries in taint_rules; set from userspace before load */
const volatile unsigned int n_taint_rules = 0;

/* Bash readline uretprobe handler */
SEC("uretprobe//usr/bin/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret)
{
	struct event *e;
	char comm[TASK_COMM_LEN];
	u32 pid;

	if (!ret)
		return 0;

	/* Check if this is actually bash */
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' || comm[3] != 'h' || comm[4] != 0)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the sample with bash readline data */
	e->type = EVENT_TYPE_BASH_READLINE;
	e->pid = pid;
	e->ppid = 0; /* Not relevant for bash commands */
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->command, sizeof(e->command), ret);

	/* Submit to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ActPlane: propagate taint from parent to child at fork time. This is the
 * core of provenance tracking -- a label set on a source process flows to its
 * entire descendant subtree without any runtime graph traversal. */
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	pid_t parent_pid = ctx->parent_pid;
	pid_t child_pid = ctx->child_pid;
	u64 *plabel;

	plabel = bpf_map_lookup_elem(&taint_labels, &parent_pid);
	if (plabel && *plabel) {
		u64 label = *plabel;
		bpf_map_update_elem(&taint_labels, &child_pid, &label, BPF_ANY);
	}
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* Get process info */
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	/* remember time exec() was executed for this PID */
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	e->type = EVENT_TYPE_PROCESS;
	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->timestamp_ns = ts;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* Capture full command line with arguments from mm->arg_start */
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
	unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
	unsigned long arg_len = arg_end - arg_start;

	if (arg_len > MAX_COMMAND_LEN - 1)
		arg_len = MAX_COMMAND_LEN - 1;

	if (arg_len > 0) {
		/*
		 * Read the full argv block using bpf_probe_read_user (not _str).
		 * _str stops at first \0 and only captures argv[0].
		 * _user reads raw bytes: "chmod\0+x\0/path\0" -- we get all args.
		 *
		 * We always read exactly MAX_COMMAND_LEN-1 bytes (a compile-time
		 * constant) so that BPF verifiers on all kernel versions can
		 * prove the access is bounded.  This may read past arg_end into
		 * environment variables, but userspace trims to arg_len.
		 *
		 * NO LOOPS in BPF -- all post-processing (\0->space, trimming)
		 * is done in userspace to stay within the verifier instruction
		 * limit on kernel 5.15 (1,000,000 insns).
		 */
		long ret = bpf_probe_read_user(e->full_command,
					MAX_COMMAND_LEN - 1,
					(void *)arg_start);
		if (ret < 0) {
			bpf_probe_read_kernel_str(e->full_command,
					  sizeof(e->full_command),
					  e->comm);
			e->full_command[MAX_COMMAND_LEN - 1] = '\0';
		} else {
			e->full_command[MAX_COMMAND_LEN - 1] = '\0';
		}
		/* Store actual arg_len in exit_code for userspace trimming.
		 * exec events don't use exit_code, so this field is free. */
		arg_len &= (MAX_COMMAND_LEN - 1);
		e->exit_code = (unsigned)arg_len;
	} else {
		bpf_probe_read_kernel_str(e->full_command,
				  sizeof(e->full_command), e->comm);
		e->exit_code = 0;
	}

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

	/* ActPlane taint evaluation. Done after the exec event is submitted so
	 * the normal trace is unaffected even if no rules are configured. */
	if (n_taint_rules) {
		char tcomm[TASK_COMM_LEN];
		u64 label = 0;
		u64 *cur;
		unsigned int rule_id = 0;

		bpf_get_current_comm(&tcomm, sizeof(tcomm));

		/* inherited taint (via fork) for this pid */
		cur = bpf_map_lookup_elem(&taint_labels, &pid);
		if (cur)
			label = *cur;

		/* Does this executable introduce new taint? We iterate the map
		 * by index here rather than calling taint_apply_sources(): BPF
		 * ARRAY values must be fetched via bpf_map_lookup_elem and can't
		 * be passed as a contiguous C array. The matching predicate
		 * (taint_comm_eq) is the same one the unit test exercises. */
		for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
			struct taint_rule *r;
			if (i >= n_taint_rules)
				break;
			r = bpf_map_lookup_elem(&taint_rules, &i);
			if (!r)
				continue;
			if (r->source_comm[0] != '\0' &&
			    taint_comm_eq(tcomm, r->source_comm))
				label |= r->label;
		}

		if (label) {
			bpf_map_update_elem(&taint_labels, &pid, &label, BPF_ANY);

			/* sink check: is a tainted process running a forbidden exe? */
			for (unsigned int i = 0; i < MAX_TAINT_RULES; i++) {
				struct taint_rule *r;
				if (i >= n_taint_rules)
					break;
				r = bpf_map_lookup_elem(&taint_rules, &i);
				if (!r)
					continue;
				if ((label & r->label) &&
				    r->sink_comm[0] != '\0' &&
				    taint_comm_eq(tcomm, r->sink_comm)) {
					rule_id = r->rule_id;

					struct event *v =
						bpf_ringbuf_reserve(&rb, sizeof(*v), 0);
					if (!v)
						break;
					v->type = EVENT_TYPE_TAINT_VIOLATION;
					v->exit_event = false;
					v->pid = pid;
					v->ppid = BPF_CORE_READ(task, real_parent, tgid);
					v->timestamp_ns = ts;
					v->exit_code = 0;
					v->duration_ns = 0;
					v->taint_rule_id = rule_id;
					v->taint_label = label;
					bpf_get_current_comm(&v->comm, sizeof(v->comm));
					fname_off = ctx->__data_loc_filename & 0xFFFF;
					bpf_probe_read_str(&v->filename,
							   sizeof(v->filename),
							   (void *)ctx + fname_off);
					bpf_ringbuf_submit(v, 0);
					break;
				}
			}
		}
	}
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	ts = bpf_ktime_get_ns();
	if (start_ts)
		duration_ns = ts - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* ActPlane: drop taint label on exit so the map doesn't leak pids */
	bpf_map_delete_elem(&taint_labels, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->type = EVENT_TYPE_PROCESS;
	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->timestamp_ns = ts;
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Syscall tracepoint for openat */
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	char filepath[MAX_FILENAME_LEN];
	int dfd, flags;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments */
	dfd = (int)ctx->args[0];
	filename = (const char *)ctx->args[1];
	flags = (int)ctx->args[2];

	/* Read filename from user space */
	if (bpf_probe_read_user_str(filepath, sizeof(filepath), filename) < 0)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_OPERATION;
	e->pid = pid;
	e->ppid = 0; /* Will be filled if needed */
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy filepath and set file open details */
	bpf_probe_read_kernel_str(e->file_op.filepath, sizeof(e->file_op.filepath), filepath);
	e->file_op.fd = -1; /* Will be set on return if needed */
	e->file_op.flags = flags;
	e->file_op.is_open = true;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Syscall tracepoint for open */
SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	char filepath[MAX_FILENAME_LEN];
	int flags;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments */
	filename = (const char *)ctx->args[0];
	flags = (int)ctx->args[1];

	/* Read filename from user space */
	if (bpf_probe_read_user_str(filepath, sizeof(filepath), filename) < 0)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_OPERATION;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy filepath and set file open details */
	bpf_probe_read_kernel_str(e->file_op.filepath, sizeof(e->file_op.filepath), filepath);
	e->file_op.fd = -1;
	e->file_op.flags = flags;
	e->file_op.is_open = true;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}


