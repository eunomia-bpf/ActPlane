/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 eunomia-bpf org. */
#ifndef __PROCESS_H
#define __PROCESS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#include "taint.h"

/* The kernel emits exactly one kind of event: a taint-rule violation. */
enum event_type {
	EVENT_TYPE_TAINT_VIOLATION = 3,
};

struct event {
	enum event_type type;
	int pid;
	int ppid;
	unsigned int blocked;          /* 1 if an LSM hook denied the operation */
	unsigned long long timestamp_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN]; /* offending exe / path ("" for connect) */
	unsigned int taint_rule_id;
	unsigned int conn_ip;            /* connect: network-order IPv4 (0 otherwise) */
	unsigned long long taint_label;
};

#endif /* __PROCESS_H */
