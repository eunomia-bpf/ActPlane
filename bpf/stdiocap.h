// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __STDIOCAP_H
#define __STDIOCAP_H

#define MAX_BUF_SIZE 8192
#define RING_BUFFER_SIZE (1024 * 1024)
#define TASK_COMM_LEN 16

struct stdiocap_event_t {
	__u64 timestamp_ns;
	__u64 delta_ns;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s32 fd;
	__u32 len;
	__u32 buf_size;
	__u8 is_read;
	char comm[TASK_COMM_LEN];
	__u8 buf[MAX_BUF_SIZE];
};

#endif /* __STDIOCAP_H */
