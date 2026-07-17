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

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile unsigned int enforce_mode = 0;
const volatile unsigned int policy_features = 0;
#ifdef ACTPLANE_LEGACY_KERNEL
/* Kernels before bpf_loop() need verifier-visible policy bounds. The direct
 * loader patches these rodata values before loading any program. */
const volatile unsigned int legacy_n_rules = 0;
const volatile unsigned int legacy_n_updates = 0;
const volatile unsigned int legacy_file_rule_conditions = 0;
#endif

#include "taint_engine.bpf.h"

#ifndef EPERM
#define EPERM 1
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_UNIX
#define AF_UNIX 1
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
#ifndef F_DUPFD
#define F_DUPFD 0
#endif
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif
#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif
#ifndef MAP_TYPE
#define MAP_TYPE 0x0f
#endif
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif
#ifndef VM_SHARED
#define VM_SHARED 0x00000008UL
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif

#define TE_USER_MSGHDR_CONTROL_OFF    32
#define TE_USER_MSGHDR_CONTROLLEN_OFF 40
#define TE_CMSG_HDR_LEN               16
#define TE_CMSG_ALIGN_MASK            7ULL
#define TE_CMSG_SCAN_MAX              2
#define TE_CMSG_CONTROL_MAX           4096ULL
#define TE_SCM_RIGHTS_MAX_FDS         8
/*
 * Tracepoint fallback keeps exact-start records for the recent file-backed
 * mappings of each active pid. mprotect/mremap use a direct (pid,start) lookup
 * instead of scanning a shadow VMA table, because scanning while invoking full
 * file-flow helpers is too expensive for the verifier. BPF-LSM file_mprotect is
 * the precise pre-operation path when LSM is available.
 */
#define TE_MMAP_INDEX_SLOTS           8

#define TE_MODE_NOTIFY 0
#define TE_MODE_BLOCK  1
#define TE_MODE_KILL   2
#define TE_MODE_UNSUPPORTED 3

#define TE_ACCESS_READ    (1U << 0)
#define TE_ACCESS_WRITE   (1U << 1)
#define TE_ACCESS_EXEC    (1U << 2)
#define TE_ACCESS_CONNECT (1U << 3)
#define TE_ACCESS_RECV    (1U << 4)

#define TE_OBJ_EXEC     1
#define TE_OBJ_FILE     2
#define TE_OBJ_ENDPOINT 3

#define TE_FORK_FD_SCAN 64

#define TE_REF_FILE          1
#define TE_REF_PATH          2
#define TE_REF_PATH_DENTRY   3
#define TE_REF_USER_PATH     4
#define TE_REF_BPRM          5
#define TE_REF_STRINGS       6
#define TE_REF_SOCKADDR_KERN 7
#define TE_REF_SOCKADDR_USER 8
#define TE_REF_SOCKET        9

#define TE_IO_ADDR_NONE        0
#define TE_IO_ADDR_SOCKADDR    1
#define TE_IO_ADDR_USER_MSGHDR 2

#include "channel.bpf.h"

struct te_event {
	pid_t pid;
	__u32 obj_kind;
	__u32 access;
	__u32 mode;
	const char *target;
	const char *display;
	__u32 ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Loader/control pids protected from in-domain subjects. Host administrators
 * outside any ActPlane runtime domain remain able to signal or debug them. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, pid_t);
	__type(value, __u32);
} te_protected_pids SEC(".maps");

static __always_inline int te_pid_protected(pid_t pid)
{
	__u32 *v = bpf_map_lookup_elem(&te_protected_pids, &pid);

	return v && *v;
}

static __always_inline int te_pid_can_control_bpf(pid_t pid)
{
	if (te_pid_protected(pid))
		return 1;
	__u32 domain_id = cap_domain_for_pid(pid);
	if (!domain_id)
		return 0;
	struct cap_state *state = bpf_map_lookup_elem(&cap_state, &domain_id);
	return state && state->authority_mask;
}

/* Pending open(at) args, stashed at sys_enter and consumed at sys_exit. The
 * sys_enter tracepoint fires before the kernel's copy_from_user faults the path
 * page in, so a non-faulting read of the path there can EFAULT and silently drop
 * the open (notably a fresh exec's own .rodata path, touched first at open()).
 * By sys_exit the page is resident, so the read is reliable. Keyed by tid. */
struct open_pend {
	__u64 path_ptr;
	__u32 flags;
	__u32 remember_fd;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct open_pend);
} ts_openpend SEC(".maps");

struct rename_pend {
	__u64 old_path_ptr;
	__u64 new_path_ptr;
	__u32 flags;
	__u32 have_old;
	__u32 have_new;
	__u32 _pad;
	char old_path[MAX_FILENAME_LEN];
	char new_path[MAX_FILENAME_LEN];
	struct file_id old_fid;
	struct file_id new_fid;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct rename_pend);
} ts_renamepend SEC(".maps");

struct fd_key {
	pid_t pid;
	int fd;
};
struct fd_ref {
	char path[MAX_FILENAME_LEN];
	struct file_id fid;
};
struct fileptr_ref {
	struct fd_ref ref;
	struct file_id backing;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct fd_key);
	__type(value, struct fd_ref);
} ts_fd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct fileptr_ref);
} ts_fileptr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct fd_key);
	__type(value, __u32);
} ts_sockfd SEC(".maps");

struct connect_pend {
	int fd;
	__u32 ip;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct connect_pend);
} ts_connectpend SEC(".maps");

struct unixsock_pend {
	int fd;
	char path[MAX_FILENAME_LEN];
	struct file_id fid;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct unixsock_pend);
} ts_unixsockpend SEC(".maps");

struct accept_pend {
	int fd;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct accept_pend);
} ts_acceptpend SEC(".maps");

struct io_pend {
	int fd;
	__u32 access;
	__u64 addr_ptr;
	__u32 addr_kind;
	int addr_len;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct io_pend);
} ts_iopend SEC(".maps");

struct mmap_pend {
	int fd;
	__u64 len;
	unsigned long prot;
	unsigned long flags;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct mmap_pend);
} ts_mmappend SEC(".maps");

struct mprotect_pend {
	__u64 start;
	__u64 len;
	unsigned long prot;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct mprotect_pend);
} ts_mprotectpend SEC(".maps");

struct mremap_pend {
	__u64 old_addr;
	__u64 old_size;
	__u64 new_size;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct mremap_pend);
} ts_mremappend SEC(".maps");

struct mmap_key {
	pid_t pid;
	__u64 start;
};
struct mmap_ref {
	char path[MAX_FILENAME_LEN];
	__u64 start;
	__u64 end;
	unsigned long prot;
	unsigned long flags;
	struct file_id fid;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct mmap_key);
	__type(value, struct mmap_ref);
} ts_mmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mmap_ref);
} ts_mmap_scratch SEC(".maps");

struct mmap_index {
	__u64 starts[TE_MMAP_INDEX_SLOTS];
	__u32 next;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, pid_t);
	__type(value, struct mmap_index);
} ts_mmap_index SEC(".maps");

struct dup_pend {
	int oldfd;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct dup_pend);
} ts_duppend SEC(".maps");

struct fd_copy_pend {
	int out_fd;
	int in_fd;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct fd_copy_pend);
} ts_fdcopypend SEC(".maps");

struct pipe_pend {
	__u64 fds_ptr;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct pipe_pend);
} ts_pipepend SEC(".maps");

struct socketpair_pend {
	__u64 fds_ptr;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct socketpair_pend);
} ts_socketpairpend SEC(".maps");

struct exec_scratch {
	char match[TAINT_TEXT_BUF];       /* >= PAT_LEN+SUF_MAX for suffix tail copy */
	char display[MAX_FILENAME_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_scratch);
} ts_exec_scratch SEC(".maps");

enum exec_tail_slot {
	EXEC_TAIL_UPDATE_SIMPLE = 0,
	EXEC_TAIL_UPDATE_PREFIX = 1,
	EXEC_TAIL_RULE_SIMPLE = 2,
	EXEC_TAIL_RULE_COMPLEX = 3,
	EXEC_TAIL_ARG_UPDATE_SIMPLE = 4,
	EXEC_TAIL_ARG_UPDATE_PREFIX = 5,
	EXEC_TAIL_ARG_RULE_SIMPLE = 6,
	EXEC_TAIL_ARG_RULE_COMPLEX = 7,
	EXEC_TAIL_MAX = 8,
};

struct exec_pipe_state {
	pid_t pid;
	__u32 mode;
	__u32 n_domains;
	__u32 domain_ids[CAP_DOMAIN_DEPTH];
	__u64 add[CAP_DOMAIN_DEPTH];
	__u64 del[CAP_DOMAIN_DEPTH];
	__u64 gates[CAP_DOMAIN_DEPTH];
	__u64 exit_gates[CAP_DOMAIN_DEPTH];
	__u64 invals[CAP_DOMAIN_DEPTH];
	int best_rule;
	int best_index;
	__u32 best_effect;
	__u32 best_domain_id;
	__u64 best_req;
	__u64 best_labels;
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, EXEC_TAIL_MAX);
	__type(key, __u32);
	__type(value, __u32);
} exec_tail SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_pipe_state);
} ts_exec_pipe SEC(".maps");

struct file_scratch {
	char path[MAX_FILENAME_LEN];
	struct file_id fid;
};
struct fd_scratch {
	struct fd_key key;
	struct fd_ref ref;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_scratch);
} ts_file_scratch SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fd_scratch);
} ts_fd_scratch SEC(".maps");

static __always_inline struct exec_scratch *exec_scratch_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_exec_scratch, &key);
}

static __always_inline struct exec_pipe_state *exec_pipe_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_exec_pipe, &key);
}

static __always_inline struct file_scratch *file_scratch_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_file_scratch, &key);
}

static __always_inline struct fd_scratch *fd_scratch_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_fd_scratch, &key);
}

static __always_inline struct mmap_ref *mmap_scratch_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_mmap_scratch, &key);
}

static __always_inline struct file *te_current_file_from_fd(int fd);
static __always_inline int te_resolve_file_id_from_file(struct file *file,
							struct file_id *fid);
static __always_inline __u32 te_access_from_mmap(unsigned long prot,
						 unsigned long flags);

static __always_inline void te_fd_key(pid_t pid, int fd, struct fd_key *out)
{
	out->pid = pid;
	out->fd = fd;
}

static __always_inline int te_file_id_equal(const struct file_id *a,
					    const struct file_id *b)
{
	return a->ino == b->ino && a->dev == b->dev;
}

static __noinline void te_store_fileptr_ref(struct file *file,
					    const struct fd_ref *ref)
{
	struct fileptr_ref fpref = {};
	__u64 key;

	if (!file)
		return;
	if (te_resolve_file_id_from_file(file, &fpref.backing) < 0)
		return;
	fpref.ref = *ref;
	key = (__u64)file;
	bpf_map_update_elem(&ts_fileptr, &key, &fpref, BPF_ANY);
}

static __always_inline struct fileptr_ref *te_lookup_fileptr_ref(struct file *file)
{
	struct file_id backing = {};
	struct fileptr_ref *fpref;
	__u64 key;

	if (!file)
		return NULL;
	if (te_resolve_file_id_from_file(file, &backing) < 0)
		return NULL;
	key = (__u64)file;
	fpref = bpf_map_lookup_elem(&ts_fileptr, &key);
	if (!fpref || !te_file_id_equal(&fpref->backing, &backing))
		return NULL;
	return fpref;
}

static __noinline void te_store_fd(pid_t pid, int fd, const char *path,
				   struct file_id *fid)
{
	struct fd_scratch *scratch = fd_scratch_buf();

	if (fd < 0)
		return;
	if (!scratch)
		return;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	te_fd_key(pid, fd, &scratch->key);
	scratch->ref.fid = *fid;
	for (int i = 0; i < MAX_FILENAME_LEN; i++)
		scratch->ref.path[i] = path[i];
	scratch->ref.path[MAX_FILENAME_LEN - 1] = '\0';
	bpf_map_delete_elem(&ts_sockfd, &scratch->key);
	bpf_map_update_elem(&ts_fd, &scratch->key, &scratch->ref, BPF_ANY);
}

static __noinline void te_store_fd_with_current_file(pid_t pid, int fd,
						     const char *path,
						     struct file_id *fid)
{
	struct file *file;
	struct fd_key key = {};
	struct fd_ref *ref;

	te_store_fd(pid, fd, path, fid);
	if (fd < 0)
		return;
	te_fd_key(pid, fd, &key);
	ref = bpf_map_lookup_elem(&ts_fd, &key);
	if (!ref)
		return;
	file = te_current_file_from_fd(fd);
	te_store_fileptr_ref(file, ref);
}

static __always_inline void te_delete_fd(pid_t pid, int fd)
{
	if (fd < 0)
		return;
	struct fd_key key = {};
	te_fd_key(pid, fd, &key);
	bpf_map_delete_elem(&ts_fd, &key);
	bpf_map_delete_elem(&ts_sockfd, &key);
}

static __always_inline struct fd_ref *te_lookup_fd(pid_t pid, int fd)
{
	if (fd < 0)
		return 0;
	struct fd_key key = {};
	te_fd_key(pid, fd, &key);
	return bpf_map_lookup_elem(&ts_fd, &key);
}

static __always_inline void te_store_sockfd(pid_t pid, int fd, __u32 ip)
{
	if (fd < 0 || !ip)
		return;
	struct fd_key key = {};
	te_fd_key(pid, fd, &key);
	bpf_map_update_elem(&ts_sockfd, &key, &ip, BPF_ANY);
}

static __always_inline __u32 *te_lookup_sockfd(pid_t pid, int fd)
{
	if (fd < 0)
		return 0;
	struct fd_key key = {};
	te_fd_key(pid, fd, &key);
	return bpf_map_lookup_elem(&ts_sockfd, &key);
}

static __always_inline void te_store_unix_fd(pid_t pid, int fd, const char *path)
{
	struct file_id fid = {};

	fid.ino = te_fnv1a(path);
	te_store_fd(pid, fd, path, &fid);
}

static __always_inline struct file *te_current_file_from_fd(int fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fd_array;
	struct file *file = NULL;
	unsigned int max_fds;

	if (fd < 0)
		return NULL;
	files = BPF_CORE_READ(task, files);
	if (!files)
		return NULL;
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return NULL;
	max_fds = BPF_CORE_READ(fdt, max_fds);
	if ((__u32)fd >= max_fds)
		return NULL;
	fd_array = BPF_CORE_READ(fdt, fd);
	if (!fd_array)
		return NULL;
	if (bpf_probe_read_kernel(&file, sizeof(file), fd_array + fd) < 0)
		return NULL;
	return file;
}

static __always_inline int te_resolve_file_id_from_file(struct file *file,
							struct file_id *fid)
{
	struct inode *inode;

	fid->ino = 0;
	fid->dev = 0;
	fid->_pad = 0;
	if (!file)
		return -1;
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return -1;
	fid->ino = BPF_CORE_READ(inode, i_ino);
	fid->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return fid->ino ? 0 : -1;
}

static __noinline void te_store_current_fd_file(pid_t pid, int fd)
{
	struct file_scratch *scratch = file_scratch_buf();
	struct fileptr_ref *fpref;
	struct file *file;

	if (!scratch)
		return;
	file = te_current_file_from_fd(fd);
	if (!file)
		return;
	fpref = te_lookup_fileptr_ref(file);
	if (fpref) {
		te_store_fd_with_current_file(pid, fd, fpref->ref.path,
					      &fpref->ref.fid);
		return;
	}
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (te_resolve_file_id_from_file(file, &scratch->fid) < 0)
		return;
	__builtin_memcpy(scratch->path, "fd:scm_rights",
			 sizeof("fd:scm_rights"));
	te_store_fd_with_current_file(pid, fd, scratch->path, &scratch->fid);
}

static __always_inline void te_mmap_key(pid_t pid, __u64 start,
					struct mmap_key *out)
{
	out->pid = pid;
	out->start = start;
}

static __always_inline __u64 te_range_end(__u64 start, __u64 len)
{
	__u64 end = start + len;

	if (end < start)
		return ~0ULL;
	return end;
}

static __always_inline int te_ranges_overlap(__u64 a_start, __u64 a_end,
					     __u64 b_start, __u64 b_end)
{
	return a_start < b_end && b_start < a_end;
}

static __noinline __u64 te_mmap_index_remember(pid_t pid, __u64 start)
{
	struct mmap_index *idx = bpf_map_lookup_elem(&ts_mmap_index, &pid);
	__u64 overwritten = 0;
	__u32 slot = 0;
	__u32 next_slot = 1;

	if (!start)
		return 0;
	if (!idx) {
		struct mmap_index fresh = {};

		fresh.starts[0] = start;
		fresh.next = 1;
		bpf_map_update_elem(&ts_mmap_index, &pid, &fresh, BPF_ANY);
		return 0;
	}
	for (int i = 0; i < TE_MMAP_INDEX_SLOTS; i++) {
		if (idx->starts[i] == start)
			idx->starts[i] = 0;
	}
	slot = idx->next;
	if (slot >= TE_MMAP_INDEX_SLOTS)
		slot = 0;
	overwritten = idx->starts[slot];
	idx->starts[slot] = start;
	next_slot = slot + 1;
	if (next_slot >= TE_MMAP_INDEX_SLOTS)
		next_slot = 0;
	idx->next = next_slot;
	if (overwritten == start)
		return 0;
	return overwritten;
}

static __noinline void te_mmap_index_forget(pid_t pid, __u64 start)
{
	struct mmap_index *idx;

	if (!start)
		return;
	idx = bpf_map_lookup_elem(&ts_mmap_index, &pid);
	if (!idx)
		return;
	for (int i = 0; i < TE_MMAP_INDEX_SLOTS; i++) {
		if (idx->starts[i] == start)
			idx->starts[i] = 0;
	}
}

static __always_inline void te_store_mmap_ref(pid_t pid, __u64 start,
					      const struct mmap_pend *p,
					      const struct fd_ref *fdref)
{
	struct mmap_ref *mref = mmap_scratch_buf();
	struct mmap_key key = {};
	__u64 overwritten;

	if (!mref || !p || !fdref || !p->len || !start)
		return;
	__builtin_memset(mref, 0, sizeof(*mref));
	overwritten = te_mmap_index_remember(pid, start);
	if (overwritten) {
		struct mmap_key old_key = {};

		te_mmap_key(pid, overwritten, &old_key);
		bpf_map_delete_elem(&ts_mmap, &old_key);
	}
	te_mmap_key(pid, start, &key);
	mref->start = start;
	mref->end = te_range_end(start, p->len);
	mref->prot = p->prot;
	mref->flags = p->flags;
	mref->fid = fdref->fid;
	__builtin_memcpy(mref->path, fdref->path, sizeof(mref->path));
	bpf_map_update_elem(&ts_mmap, &key, mref, BPF_ANY);
}

static __noinline void te_apply_mmap_access(pid_t pid, struct mmap_ref *mref,
					    unsigned long prot)
{
	__u32 access;

	if (!mref)
		return;
	access = te_access_from_mmap(prot, mref->flags);
	if (access & TE_ACCESS_READ)
		te_read(pid, &mref->fid, mref->path);
	if (access & TE_ACCESS_WRITE)
		te_write_flow(pid, &mref->fid, mref->path);
}

static __noinline void te_handle_mprotect_range(pid_t pid, __u64 start,
						__u64 len, unsigned long prot)
{
	__u64 end = te_range_end(start, len);
	struct mmap_key key = {};
	struct mmap_ref *mref;

	if (!len)
		return;
	te_mmap_key(pid, start, &key);
	mref = bpf_map_lookup_elem(&ts_mmap, &key);
	if (!mref || !te_ranges_overlap(start, end, mref->start, mref->end))
		return;
	te_apply_mmap_access(pid, mref, prot);
	mref->prot = prot;
}

static __noinline void te_handle_mremap_range(pid_t pid, __u64 old_addr,
					      __u64 old_size, __u64 new_addr,
					      __u64 new_size)
{
	__u64 old_end = te_range_end(old_addr, old_size);
	struct mmap_ref *scratch = mmap_scratch_buf();
	struct mmap_key old_key = {};
	struct mmap_key new_key = {};
	struct mmap_ref *mref;
	__u64 overwritten;

	if (!old_size || !new_size || !new_addr || !scratch)
		return;
	te_mmap_key(pid, old_addr, &old_key);
	mref = bpf_map_lookup_elem(&ts_mmap, &old_key);
	if (!mref ||
	    !te_ranges_overlap(old_addr, old_end, mref->start, mref->end))
		return;
	te_apply_mmap_access(pid, mref, mref->prot);
	__builtin_memcpy(scratch, mref, sizeof(*scratch));
	scratch->start = new_addr;
	scratch->end = te_range_end(new_addr, new_size);
	bpf_map_delete_elem(&ts_mmap, &old_key);
	te_mmap_index_forget(pid, old_addr);
	overwritten = te_mmap_index_remember(pid, new_addr);
	if (overwritten && overwritten != old_addr) {
		struct mmap_key overwritten_key = {};

		te_mmap_key(pid, overwritten, &overwritten_key);
		bpf_map_delete_elem(&ts_mmap, &overwritten_key);
	}
	te_mmap_key(pid, new_addr, &new_key);
	bpf_map_update_elem(&ts_mmap, &new_key, scratch, BPF_ANY);
}

static __noinline void te_delete_mmap_range(pid_t pid, __u64 start, __u64 len)
{
	__u64 end = te_range_end(start, len);
	struct mmap_key key = {};
	struct mmap_ref *mref;

	if (!len)
		return;
	te_mmap_key(pid, start, &key);
	mref = bpf_map_lookup_elem(&ts_mmap, &key);
	if (!mref || !te_ranges_overlap(start, end, mref->start, mref->end))
		return;
	bpf_map_delete_elem(&ts_mmap, &key);
	te_mmap_index_forget(pid, start);
}

static __noinline void te_delete_mmaps(pid_t pid)
{
	struct mmap_index *idx = bpf_map_lookup_elem(&ts_mmap_index, &pid);

	if (!idx)
		return;
	for (int i = 0; i < TE_MMAP_INDEX_SLOTS; i++) {
		struct mmap_key key = {};
		__u64 start = idx->starts[i];

		if (!start)
			continue;
		te_mmap_key(pid, start, &key);
		bpf_map_delete_elem(&ts_mmap, &key);
	}
	bpf_map_delete_elem(&ts_mmap_index, &pid);
}

static __always_inline void te_copy_sockfd(pid_t pid, int oldfd, int newfd)
{
	__u32 *ip = te_lookup_sockfd(pid, oldfd);
	if (!ip)
		return;
	te_store_sockfd(pid, newfd, *ip);
}

static __always_inline void te_copy_fd(pid_t pid, int oldfd, int newfd)
{
	struct fd_ref *ref = te_lookup_fd(pid, oldfd);
	if (!ref)
		return;
	te_store_fd_with_current_file(pid, newfd, ref->path, &ref->fid);
}

static __always_inline void te_copy_sockfd_to_pid(pid_t from, pid_t to, int fd)
{
	__u32 *ip = te_lookup_sockfd(from, fd);
	if (!ip)
		return;
	te_store_sockfd(to, fd, *ip);
}

static __always_inline void te_copy_fd_to_pid(pid_t from, pid_t to, int fd)
{
	struct fd_ref *ref = te_lookup_fd(from, fd);
	if (!ref)
		return;
	te_store_fd(to, fd, ref->path, &ref->fid);
}

static __noinline void te_copy_fork_fds(pid_t from, pid_t to)
{
	if (!te_pid_active(from) || !te_pid_active(to))
		return;
	for (int fd = 0; fd < TE_FORK_FD_SCAN; fd++) {
		te_copy_fd_to_pid(from, to, fd);
		te_copy_sockfd_to_pid(from, to, fd);
	}
}

/* The one and only output channel. */
static __always_inline void copy_violation_provenance(struct event *v,
						      struct te_prov *p)
{
	if (!p)
		return;
	v->prov_label = p->label;
	v->prov_timestamp_ns = p->timestamp_ns;
	v->prov_pid = p->pid;
	v->prov_op = p->op;
	v->prov_ip = p->ip;
	for (int j = 0; j < MAX_FILENAME_LEN; j++)
		v->prov_target[j] = p->target[j];
	v->prov_target[MAX_FILENAME_LEN - 1] = '\0';
}

#ifdef ACTPLANE_LEGACY_KERNEL
struct legacy_violation_prov_ctx {
	pid_t pid;
	__u32 domain_id;
	__u32 obj_kind;
	__u32 ip;
	__u32 have_fid;
	struct file_id fid;
};

static __noinline int fill_legacy_violation_provenance_bit(
	struct event *v, struct legacy_violation_prov_ctx *c, __u64 bit)
{
	struct te_prov *p = te_lookup_proc_prov(c->pid, c->domain_id, bit);

	if (p) {
		copy_violation_provenance(v, p);
		return 1;
	}
	if (c->obj_kind == TE_OBJ_FILE && c->have_fid) {
		struct file_domain_id fdom = {};
		struct file_label_id key;

		te_file_domain_key_for(c->domain_id, &c->fid, &fdom);
		key.fdom = fdom;
		key.label = bit;
		p = bpf_map_lookup_elem(&ts_file_prov, &key);
		if (p) {
			copy_violation_provenance(v, p);
			return 1;
		}
	}
	if (c->obj_kind == TE_OBJ_ENDPOINT && c->ip) {
		struct endp_domain_id edom = {};
		struct endp_label_id key;

		te_endp_domain_key_for(c->domain_id, c->ip, &edom);
		key.edom = edom;
		key.label = bit;
		p = bpf_map_lookup_elem(&ts_endp_prov, &key);
		if (p) {
			copy_violation_provenance(v, p);
			return 1;
		}
	}
	return 0;
}
#endif

static __always_inline void fill_violation_provenance(struct event *v, pid_t pid,
						      __u32 domain_id,
						      __u64 matched_labels,
						      __u32 obj_kind,
						      struct file_id *fid,
						      __u32 ip)
{
	v->matched_label = 0;
	v->prov_label = 0;
	v->prov_timestamp_ns = 0;
	v->prov_pid = 0;
	v->prov_op = 0;
	v->prov_ip = 0;
	v->prov_target[0] = '\0';

#ifndef ACTPLANE_LEGACY_KERNEL
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit = 1ULL << i;
		if (!(matched_labels & bit))
			continue;
		if (!v->matched_label)
			v->matched_label = bit;
		struct te_prov *p = te_lookup_proc_prov(pid, domain_id, bit);
		if (p) {
			copy_violation_provenance(v, p);
			return;
		}
		if (obj_kind == TE_OBJ_FILE && fid) {
			struct file_domain_id *fdom = te_file_domain_tmp();
			if (fdom) {
				te_file_domain_key_for(domain_id, fid, fdom);
				struct file_label_id fk = { .fdom = *fdom, .label = bit };
				p = bpf_map_lookup_elem(&ts_file_prov, &fk);
				if (p) {
					copy_violation_provenance(v, p);
					return;
				}
			}
		}
		if (obj_kind == TE_OBJ_ENDPOINT && ip) {
			struct endp_domain_id edom = {};
			te_endp_domain_key_for(domain_id, ip, &edom);
			struct endp_label_id ek = { .edom = edom, .label = bit };
			p = bpf_map_lookup_elem(&ts_endp_prov, &ek);
			if (p) {
				copy_violation_provenance(v, p);
				return;
			}
		}
	}
#else
	__u64 remaining = matched_labels;
	struct legacy_violation_prov_ctx c = {
		.pid = pid,
		.domain_id = domain_id,
		.obj_kind = obj_kind,
		.ip = ip,
		.have_fid = fid ? 1 : 0,
	};

	if (fid)
		c.fid = *fid;

#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!remaining)
			break;
		bit = remaining & (0ULL - remaining);
		if (!v->matched_label)
			v->matched_label = bit;
		if (fill_legacy_violation_provenance_bit(v, &c, bit))
			return;
		remaining &= ~bit;
	}
#endif
}

static __always_inline void emit_violation(pid_t pid, unsigned int rule_id,
					   const char *target, u32 conn_ip,
					   __u32 obj_kind,
					   struct file_id *fid,
					   __u32 domain_id,
					   __u64 matched_labels,
					   unsigned int op,
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
	v->op = op;
	v->domain_id = domain_id;
	v->session_root = te_root(pid);
	v->timestamp_ns = bpf_ktime_get_ns();
	v->taint_rule_id = rule_id;
	v->conn_ip = conn_ip;
	v->taint_label = te_labels_for_domain(pid, domain_id);
	v->matched_labels = matched_labels;
	fill_violation_provenance(v, pid, domain_id, matched_labels,
				  obj_kind, fid, conn_ip);
	bpf_get_current_comm(&v->comm, sizeof(v->comm));
	v->filename[0] = '\0';
	if (target)
		bpf_probe_read_kernel_str(&v->filename, sizeof(v->filename), target);
	bpf_ringbuf_submit(v, 0);
}

static __always_inline int file_path(struct file *file, char *path, int path_sz)
{
	if (bpf_d_path(&file->f_path, path, path_sz) > 0)
		return 0;

	struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *name = BPF_CORE_READ(de, d_name.name);
	if (name && bpf_probe_read_kernel_str(path, path_sz, name) > 0)
		return 0;
	return -1;
}

static __always_inline int file_basename(struct file *file, char *path,
					 int path_sz)
{
	struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
	const unsigned char *name = BPF_CORE_READ(de, d_name.name);
	if (name && bpf_probe_read_kernel_str(path, path_sz, name) > 0)
		return 0;
	return -1;
}

static __always_inline int path_to_str(const struct path *src, char *path,
				       int path_sz)
{
	int n = bpf_d_path((struct path *)src, path, path_sz);
	if (n > 0)
		return n;
	return -1;
}

static __always_inline int copy_dentry_name_at(char *path, __u32 dst_off,
					       const unsigned char *name)
{
	if (dst_off <= 63) {
		if (bpf_probe_read_kernel_str(path + dst_off, 64, name) < 0)
			return -1;
		return 0;
	}
	if (dst_off <= 95) {
		if (bpf_probe_read_kernel_str(path + dst_off, 32, name) < 0)
			return -1;
		return 0;
	}
	if (dst_off <= 111) {
		if (bpf_probe_read_kernel_str(path + dst_off, 16, name) < 0)
			return -1;
		return 0;
	}
	if (dst_off <= 119) {
		if (bpf_probe_read_kernel_str(path + dst_off, 8, name) < 0)
			return -1;
		return 0;
	}
	if (dst_off <= 123) {
		if (bpf_probe_read_kernel_str(path + dst_off, 4, name) < 0)
			return -1;
		return 0;
	}
	if (dst_off <= 125) {
		if (bpf_probe_read_kernel_str(path + dst_off, 2, name) < 0)
			return -1;
		return 0;
	}
	return -1;
}

static __noinline int append_dentry_name(char *path, struct dentry *dentry,
					 int path_len)
{
	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	__u32 off;
	__u32 prev;
	__u32 dst_off;

	if (!name)
		return -1;
	if (path_len <= 1 || path_len > MAX_FILENAME_LEN)
		return -1;
	off = (__u32)path_len - 1;
	if (off >= MAX_FILENAME_LEN - 1)
		return -1;
	prev = off - 1;
	barrier_var(prev);
	if (prev >= MAX_FILENAME_LEN)
		return -1;
	if (path[prev] != '/') {
		dst_off = off;
		barrier_var(dst_off);
		dst_off &= 0x7f;
		if (dst_off >= MAX_FILENAME_LEN - 1)
			return -1;
		path[dst_off] = '/';
		off = dst_off + 1;
	}
	dst_off = off;
	barrier_var(dst_off);
	dst_off &= 0x7f;
	if (dst_off >= MAX_FILENAME_LEN)
		return -1;
	if (copy_dentry_name_at(path, dst_off, name) < 0)
		return -1;
	path[MAX_FILENAME_LEN - 1] = '\0';
	return 0;
}

static __noinline int path_dentry_to_str(const struct path *dir,
					 struct dentry *dentry,
					 char *path, int path_sz)
{
	int n = path_to_str(dir, path, path_sz);

	if (n < 0)
		return -1;
	if (append_dentry_name(path, dentry, n) < 0)
		return -1;
	return 0;
}

static __noinline void te_store_current_fd_file_path(pid_t pid, int fd)
{
	struct file_scratch *scratch = file_scratch_buf();
	struct file *file;

	if (!scratch)
		return;
	file = te_current_file_from_fd(fd);
	if (!file)
		return;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (file_basename(file, scratch->path, sizeof(scratch->path)) < 0)
		return;
	if (te_resolve_file_id_from_file(file, &scratch->fid) < 0)
		return;
	te_store_fd_with_current_file(pid, fd, scratch->path, &scratch->fid);
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

static __always_inline __u32 te_access_from_mmap(unsigned long prot,
						 unsigned long flags)
{
	__u32 access = 0;
	unsigned long map_type = flags & MAP_TYPE;

	if (prot & (PROT_READ | PROT_EXEC))
		access |= TE_ACCESS_READ;
	if ((prot & PROT_WRITE) &&
	    (map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE))
		access |= TE_ACCESS_WRITE;
	return access;
}

static __always_inline __u32 te_tracepoint_mode(void)
{
	return TE_MODE_NOTIFY;
}

static __always_inline __u32 te_effect_mode(__u32 backend_mode, __u32 effect)
{
	if (effect == TEFFECT_NOTIFY)
		return TE_MODE_NOTIFY;
	if (effect == TEFFECT_KILL)
		return TE_MODE_KILL;
	if (effect == TEFFECT_BLOCK && backend_mode == TE_MODE_BLOCK)
		return TE_MODE_BLOCK;
	return TE_MODE_UNSUPPORTED;
}

static __always_inline __u32 te_supported_effects(__u32 backend_mode)
{
	if (backend_mode == TE_MODE_BLOCK)
		return (1U << TEFFECT_BLOCK);
	return (1U << TEFFECT_NOTIFY) | (1U << TEFFECT_KILL);
}

#ifdef ACTPLANE_LEGACY_KERNEL
#define TE_EXEC_DOMAIN_DEPTH 1
#else
#define TE_EXEC_DOMAIN_DEPTH CAP_DOMAIN_DEPTH
#endif

static __always_inline int exec_pipe_init(pid_t pid, __u32 mode)
{
	struct exec_pipe_state *s = exec_pipe_buf();

	if (!s)
		return -1;
	__builtin_memset(s, 0, sizeof(*s));
	s->pid = pid;
	s->mode = mode;
	s->best_rule = -1;
	s->best_index = -1;
	s->best_effect = TEFFECT_NOTIFY;
	for (int i = 0; i < TE_EXEC_DOMAIN_DEPTH; i++) {
		__u32 domain_id = te_domain_for_depth(pid, i);
		if (i > 0 && !domain_id)
			break;
		s->domain_ids[i] = domain_id;
		s->n_domains = i + 1;
	}
	return 0;
}

static __always_inline void exec_pipe_collect_updates(__u32 prefix, __u32 with_args)
{
	struct exec_pipe_state *s = exec_pipe_buf();
	struct exec_scratch *scratch = exec_scratch_buf();

	if (!s || !scratch)
		return;
	for (int i = 0; i < TE_EXEC_DOMAIN_DEPTH; i++) {
		if (i >= s->n_domains)
			break;
		__u32 domain_id = s->domain_ids[i];
		if (!cap_domain_matches_pid(s->pid, domain_id))
			continue;
		struct te_update_ctx c = {
			.pid = s->pid,
			.domain_id = domain_id,
			.op = TOP_EXEC,
			.target = scratch->match,
		};
		if (!with_args) {
			if (prefix)
				continue;
			te_collect_exec_updates_no_args(&c);
		} else if (prefix) {
			bpf_loop(te_count(1), te_exec_update_prefix_cb, &c, 0);
		} else {
			bpf_loop(te_count(1), te_exec_update_simple_cb, &c, 0);
		}
		s->add[i] |= c.add;
		s->del[i] |= c.del;
		s->gates[i] |= c.gates;
		s->exit_gates[i] |= c.exit_gates;
		s->invals[i] |= c.invals;
	}
}

static __always_inline void exec_pipe_apply_updates(void)
{
	struct exec_pipe_state *s = exec_pipe_buf();
	struct exec_scratch *scratch = exec_scratch_buf();

	if (!s || !scratch)
		return;
	for (int i = 0; i < TE_EXEC_DOMAIN_DEPTH; i++) {
		if (i >= s->n_domains)
			break;
		__u32 domain_id = s->domain_ids[i];
		if (!te_pid_active(s->pid) || !cap_domain_matches_pid(s->pid, domain_id))
			continue;

		struct proc_state *p = te_get_domain(s->pid, domain_id);
		struct proc_state ns = {};
		if (p)
			ns = *p;
		ns.labels = (ns.labels | s->add[i]) & ~s->del[i];
		ns.lin_gates |= s->gates[i];
		te_store_proc_domain(s->pid, domain_id, &ns);
		if (s->add[i]) {
#ifdef ACTPLANE_LEGACY_KERNEL
			te_record_proc_prov_mask(s->pid, domain_id, s->add[i],
						 TOP_EXEC, scratch->match, 0);
#else
			te_record_proc_prov_mask(s->pid, domain_id, s->add[i],
						 TOP_EXEC, scratch->match, 0);
#endif
		}
		if (s->gates[i] || s->exit_gates[i] || s->invals[i]) {
			pid_t r = te_root(s->pid);
			__u32 ep = te_tick(r, domain_id);
			if (s->gates[i] || s->invals[i])
				te_stamp(r, domain_id, ep, s->gates[i], s->invals[i]);
			struct pid_domain_id key = {};
			te_pid_domain_key(s->pid, domain_id, &key);
			if (s->exit_gates[i]) {
				struct te_exit_gate_pending pending = {
					.gates = s->exit_gates[i],
					.epoch = ep,
				};
				bpf_map_update_elem(&ts_exit_gates, &key, &pending, BPF_ANY);
			} else {
				bpf_map_delete_elem(&ts_exit_gates, &key);
			}
		} else {
			struct pid_domain_id key = {};
			te_pid_domain_key(s->pid, domain_id, &key);
			bpf_map_delete_elem(&ts_exit_gates, &key);
		}
	}
}

static __always_inline void exec_pipe_merge_rule(struct exec_pipe_state *s,
						 struct te_rule_eval *eval,
						 int rid)
{
	if (!s || rid < 0)
		return;
	if (s->best_rule < 0 || eval->effect > s->best_effect ||
	    (eval->effect == s->best_effect && eval->matched_index >= 0 &&
	     (s->best_index < 0 || eval->matched_index < s->best_index))) {
		s->best_rule = rid;
		s->best_index = eval->matched_index;
		s->best_effect = eval->effect;
		s->best_domain_id = eval->matched_domain_id;
		s->best_req = eval->matched_req;
		s->best_labels = eval->matched_labels;
	}
}

static __always_inline void exec_pipe_scan_rules(__u32 complex, __u32 with_args)
{
	struct exec_pipe_state *s = exec_pipe_buf();
	struct exec_scratch *scratch = exec_scratch_buf();
	struct eval_scratch *es = eval_scratch_buf();
	struct te_rule_eval *eval;

	if (!s || !scratch || !es)
		return;
	if (s->best_effect == TEFFECT_KILL)
		return;
#ifdef ACTPLANE_LEGACY_KERNEL
	__u32 current_domain_id = 0;
#else
	__u32 current_domain_id = cap_domain_for_pid(s->pid);
#endif
	__builtin_memset(es, 0, sizeof(*es));
	eval = &es->eval;
	eval->pid = s->pid;
	eval->global_labels = te_labels_for_domain(s->pid, 0);
	eval->current_labels = te_labels_for_domain(s->pid, current_domain_id);
	eval->op = TOP_EXEC;
	te_copy_target(eval->target, scratch->match);
	eval->current_domain_id = current_domain_id;
	eval->effect = TEFFECT_BLOCK;
	eval->effect_mask = te_supported_effects(s->mode);
	int rid;
	if (!with_args) {
		if (complex)
			return;
		rid = te_check_labels_no_args(eval);
	} else {
		rid = complex ? te_check_exec_complex(eval) :
				te_check_exec_simple(eval);
	}
	exec_pipe_merge_rule(s, eval, rid);
}

static __always_inline void exec_pipe_finish(void)
{
	struct exec_pipe_state *s = exec_pipe_buf();
	struct exec_scratch *scratch = exec_scratch_buf();

	if (!s || !scratch || s->best_rule < 0)
		return;
	__u32 action = te_effect_mode(s->mode, s->best_effect);
	if (action != TE_MODE_UNSUPPORTED)
		emit_violation(s->pid, s->best_rule, scratch->display, 0,
			       TE_OBJ_EXEC, 0, s->best_domain_id,
			       s->best_labels, TOP_EXEC,
			       action == TE_MODE_BLOCK ||
				       (action == TE_MODE_KILL && s->mode == TE_MODE_BLOCK),
			       action == TE_MODE_KILL, s->best_effect);
	if (action == TE_MODE_KILL)
		bpf_send_signal(SIGKILL);
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

/* Resolve the file's object identity from the same ref. With a real inode
 * (LSM hooks) we use (i_ino, s_dev); the tracepoint USER_PATH path has no
 * inode, so we fall back to (0, fnv1a(path)) — identical to the old path-keyed
 * behavior. The key is fully zeroed first (HASH compares raw key bytes). */
static __always_inline void te_resolve_file_id(__u32 ref_kind, const void *a,
					       const void *b, const char *path,
					       struct file_id *fid)
{
	struct inode *inode = NULL;

	switch (ref_kind) {
	case TE_REF_FILE:
		inode = BPF_CORE_READ((struct file *)a, f_inode);
		break;
	case TE_REF_PATH:
		inode = BPF_CORE_READ((const struct path *)a, dentry, d_inode);
		break;
	case TE_REF_PATH_DENTRY:
		inode = BPF_CORE_READ((struct dentry *)b, d_inode);
		break;
	default:
		break; /* TE_REF_USER_PATH: no inode available */
	}
	fid->ino = 0;
	fid->dev = 0;
	fid->_pad = 0;
	if (inode) {
		fid->ino = BPF_CORE_READ(inode, i_ino);
		fid->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	}
	if (!fid->ino)
		fid->ino = te_fnv1a(path);
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

static __always_inline __u64 te_fnv1a_user_bytes(const void *ptr, int len)
{
	__u64 h = 0xcbf29ce484222325ULL;

	h ^= (__u64)(__u32)len;
	h *= 0x100000001b3ULL;
	TAINT_UNROLL
	for (int i = 0; i < UNIX_PATH_MAX; i++) {
		unsigned char c = 0;

		if (i >= len)
			break;
		if (bpf_probe_read_user(&c, sizeof(c), (const char *)ptr + i) < 0)
			break;
		h ^= c;
		h *= 0x100000001b3ULL;
	}
	return h;
}

static __always_inline int te_resolve_unix_sockaddr_path(const void *addr,
							 int addrlen,
							 char *path,
							 struct file_id *fid)
{
	u16 family = 0;
	unsigned char first = 0;
	int n;
	int name_len = addrlen - 2;

	if (bpf_probe_read_user(&family, sizeof(family), addr) < 0)
		return -1;
	if (family != AF_UNIX)
		return -1;
	if (name_len <= 0)
		return -1;
	if (name_len > UNIX_PATH_MAX)
		name_len = UNIX_PATH_MAX;
	path[0] = 'u';
	path[1] = 'n';
	path[2] = 'i';
	path[3] = 'x';
	path[4] = ':';
	if (bpf_probe_read_user(&first, sizeof(first), ((const char *)addr) + 2) < 0)
		return -1;
	if (first == '\0') {
		__builtin_memcpy(path, "unix:@abstract", sizeof("unix:@abstract"));
		fid->ino = te_fnv1a_user_bytes(((const char *)addr) + 2, name_len);
		fid->dev = 0;
		fid->_pad = 0;
		if (!fid->ino)
			fid->ino = 1;
		return 0;
	}
	n = bpf_probe_read_user_str(path + 5, MAX_FILENAME_LEN - 5,
				    ((const char *)addr) + 2);
	if (n <= 1)
		return -1;
	path[MAX_FILENAME_LEN - 1] = '\0';
	fid->ino = te_fnv1a(path);
	fid->dev = 0;
	fid->_pad = 0;
	return 0;
}

static __always_inline int te_resolve_socket_peer_ipv4(struct socket *sock, __u32 *ip)
{
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return -1;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET)
		return -1;
	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	if (!daddr)
		return -1;
	*ip = daddr;
	return 0;
}

/* `fid` is the file object identity for TE_OBJ_FILE events (NULL otherwise);
 * it is only dereferenced in the FILE branches, which the verifier prunes for
 * the connect/exec programs (obj_kind is a compile-time constant per caller). */
static __always_inline int te_handle_event(struct te_event *ev, struct file_id *fid)
{
	if (!te_pid_active(ev->pid))
		return 0;
	struct eval_scratch *scratch = eval_scratch_buf();
	struct te_rule_eval *eval;
	const char *display = ev->display ? ev->display : ev->target;
	__u32 effect = TEFFECT_NOTIFY;
	__u32 action = TE_MODE_NOTIFY;
	__u64 matched_labels = 0;
	__u32 matched_domain_id = 0;
	__u32 matched_op = 0;
	__u32 current_domain_id = cap_domain_for_pid(ev->pid);
	__u64 global_labels = te_labels_for_domain(ev->pid, 0);
	__u64 current_labels = te_labels_for_domain(ev->pid, current_domain_id);
	int rid = -1;
	int candidate = -1;

	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	eval = &scratch->eval;

	if (ev->obj_kind == TE_OBJ_FILE &&
	    (policy_features & TE_POLICY_FILE_FLOW) &&
	    (ev->access & TE_ACCESS_READ)) {
		global_labels |= te_file_stored_labels_domain(fid, ev->pid, 0);
		current_labels |= te_file_stored_labels_domain(fid, ev->pid, current_domain_id);
	}
	if (ev->obj_kind == TE_OBJ_ENDPOINT && (ev->access & TE_ACCESS_CONNECT)) {
		global_labels |= te_update_add_connect_domain(ev->ip, ev->pid, 0);
		current_labels |= te_update_add_connect_domain(ev->ip, ev->pid,
							       current_domain_id);
	}
	if (ev->obj_kind == TE_OBJ_ENDPOINT && (ev->access & TE_ACCESS_RECV)) {
		global_labels |= te_endpoint_stored_labels_domain(ev->ip, ev->pid, 0) |
				 te_update_add_recv_domain(ev->ip, ev->pid, 0);
		current_labels |=
			te_endpoint_stored_labels_domain(ev->ip, ev->pid,
							 current_domain_id) |
			te_update_add_recv_domain(ev->ip, ev->pid,
						  current_domain_id);
	}

	if (ev->obj_kind == TE_OBJ_EXEC) {
		eval->pid = ev->pid;
		eval->global_labels = global_labels;
		eval->current_labels = current_labels;
		eval->current_domain_id = current_domain_id;
		eval->effect = TEFFECT_BLOCK;
		eval->effect_mask = te_supported_effects(ev->mode);
		eval->op = TOP_EXEC;
		te_copy_target(eval->target, ev->target);
		rid = te_check_labels(eval);
		effect = eval->effect;
		matched_labels = eval->matched_labels;
		matched_domain_id = eval->matched_domain_id;
		matched_op = eval->op;
	} else if (ev->obj_kind == TE_OBJ_FILE) {
		eval->pid = ev->pid;
		eval->global_labels = global_labels;
		eval->current_labels = current_labels;
		eval->current_domain_id = current_domain_id;
		eval->effect = TEFFECT_BLOCK;
		eval->effect_mask = te_supported_effects(ev->mode);
		te_copy_target(eval->target, ev->target);
		if (fid) {
			eval->fid = *fid;
			eval->has_fid = 1;
		}
		eval->include_file_labels = (ev->access & TE_ACCESS_READ) ? 1 : 0;
		if ((ev->access & TE_ACCESS_READ) &&
		    (policy_features & TE_POLICY_OPEN_RULES)) {
			eval->op = TOP_OPEN;
			candidate = te_check_labels(eval);
			if (te_better_match(candidate, eval->effect, rid, effect)) {
				rid = candidate;
				effect = eval->effect;
				matched_labels = eval->matched_labels;
				matched_domain_id = eval->matched_domain_id;
				matched_op = eval->op;
			}
		}
		if ((ev->access & TE_ACCESS_WRITE) &&
		    (policy_features & TE_POLICY_WRITE_RULES)) {
			eval->effect = TEFFECT_BLOCK;
			eval->op = TOP_WRITE;
			candidate = te_check_labels(eval);
			if (te_better_match(candidate, eval->effect, rid, effect)) {
				rid = candidate;
				effect = eval->effect;
				matched_labels = eval->matched_labels;
				matched_domain_id = eval->matched_domain_id;
				matched_op = eval->op;
			}
		}
	} else if (ev->obj_kind == TE_OBJ_ENDPOINT) {
		eval->pid = ev->pid;
		eval->global_labels = global_labels;
		eval->current_labels = current_labels;
		eval->current_domain_id = current_domain_id;
		eval->effect = TEFFECT_BLOCK;
		eval->effect_mask = te_supported_effects(ev->mode);
		eval->op = (ev->access & TE_ACCESS_RECV) ? TOP_RECV : TOP_CONNECT;
		eval->ip = ev->ip;
		rid = te_check_labels(eval);
		effect = eval->effect;
		matched_labels = eval->matched_labels;
		matched_domain_id = eval->matched_domain_id;
		matched_op = eval->op;
	}

	if (rid >= 0) {
		action = te_effect_mode(ev->mode, effect);
		if (action != TE_MODE_UNSUPPORTED)
			emit_violation(ev->pid, rid, display,
				       ev->obj_kind == TE_OBJ_ENDPOINT ? ev->ip : 0,
				       ev->obj_kind, fid,
				       matched_domain_id, matched_labels,
				       matched_op,
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

	if (ev->obj_kind == TE_OBJ_FILE && (policy_features & TE_POLICY_FILE_FLOW)) {
		if (ev->access & TE_ACCESS_READ)
			te_read(ev->pid, fid, ev->target);
		if (ev->access & TE_ACCESS_WRITE)
			te_write_flow(ev->pid, fid, ev->target);
	} else if (ev->obj_kind == TE_OBJ_ENDPOINT) {
		if (ev->access & TE_ACCESS_CONNECT)
			te_connect_flow(ev->ip, ev->pid);
		if (ev->access & TE_ACCESS_RECV)
			te_recv_flow(ev->ip, ev->pid);
	}

	return 0;
}

static __always_inline int te_handle_file_event(pid_t pid, const char *target,
						struct file_id *fid, __u32 access,
						__u32 mode)
{
	struct eval_scratch *scratch = eval_scratch_buf();
	struct te_rule_eval *eval;

	if (!te_pid_active(pid))
		return 0;
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	eval = &scratch->eval;
	__u32 effect = TEFFECT_NOTIFY;
	__u32 action = TE_MODE_NOTIFY;
	__u64 matched_labels = 0;
	__u32 matched_domain_id = 0;
	__u32 matched_op = 0;
	__u32 current_domain_id = cap_domain_for_pid(pid);
	__u64 global_labels = te_labels_for_domain(pid, 0);
	__u64 current_labels = te_labels_for_domain(pid, current_domain_id);
	int rid = -1;
	int candidate = -1;

	if ((policy_features & TE_POLICY_FILE_FLOW) && (access & TE_ACCESS_READ)) {
		global_labels |= te_file_labels_domain(fid, target, pid, 0);
		current_labels |= te_file_labels_domain(fid, target, pid, current_domain_id);
	}

	eval->pid = pid;
	eval->global_labels = global_labels;
	eval->current_labels = current_labels;
	eval->current_domain_id = current_domain_id;
	eval->effect = TEFFECT_BLOCK;
	eval->effect_mask = te_supported_effects(mode);
	te_copy_target(eval->target, target);
	if (fid) {
		eval->fid = *fid;
		eval->has_fid = 1;
	}
	eval->include_file_labels = (access & TE_ACCESS_READ) ? 1 : 0;
	if ((access & TE_ACCESS_READ) && (policy_features & TE_POLICY_OPEN_RULES)) {
		eval->op = TOP_OPEN;
		candidate = te_check_labels(eval);
		if (te_better_match(candidate, eval->effect, rid, effect)) {
			rid = candidate;
			effect = eval->effect;
			matched_labels = eval->matched_labels;
			matched_domain_id = eval->matched_domain_id;
			matched_op = eval->op;
		}
	}
	if ((access & TE_ACCESS_WRITE) && (policy_features & TE_POLICY_WRITE_RULES)) {
		eval->effect = TEFFECT_BLOCK;
		eval->op = TOP_WRITE;
		candidate = te_check_labels(eval);
		if (te_better_match(candidate, eval->effect, rid, effect)) {
			rid = candidate;
			effect = eval->effect;
			matched_labels = eval->matched_labels;
			matched_domain_id = eval->matched_domain_id;
			matched_op = eval->op;
		}
	}

	if (rid >= 0) {
		action = te_effect_mode(mode, effect);
		if (action != TE_MODE_UNSUPPORTED)
			emit_violation(pid, rid, target, 0, TE_OBJ_FILE, fid,
				       matched_domain_id, matched_labels, matched_op,
				       action == TE_MODE_BLOCK ||
					       (action == TE_MODE_KILL && mode == TE_MODE_BLOCK),
				       action == TE_MODE_KILL, effect);
		if (action == TE_MODE_BLOCK)
			return -EPERM;
		if (action == TE_MODE_KILL) {
			bpf_send_signal(SIGKILL);
			if (mode == TE_MODE_BLOCK)
				return -EPERM;
		}
	}

	if ((policy_features & TE_POLICY_FILE_FLOW) && (access & TE_ACCESS_READ))
		te_read(pid, fid, target);
	if ((policy_features & TE_POLICY_FILE_FLOW) && (access & TE_ACCESS_WRITE))
		te_write_flow(pid, fid, target);
	return 0;
}

/*
 * S_IFMT and file type constants from <linux/stat.h>.
 * vmlinux.h (BTF-generated) does not export these preprocessor macros,
 * so we define the raw values here.
 */
#define TE_S_IFMT   0170000
#define TE_S_IFREG  0100000
#define TE_S_IFDIR  0040000
#define TE_S_IFSOCK 0140000

/* Returns true if the inode mode indicates a regular file or directory —
 * the only file types that participate in IFC taint propagation. Character
 * devices (/dev/null, /dev/zero, /dev/pts/star), block devices, pipes, and
 * sockets are excluded: they are shared kernel objects where write/read
 * does not imply meaningful data storage/retrieval across processes. */
static __always_inline int te_is_regular_or_dir(const void *a, const void *b,
						__u32 ref_kind)
{
	struct inode *inode = NULL;
	umode_t i_mode;

	switch (ref_kind) {
	case TE_REF_FILE:
		inode = BPF_CORE_READ((struct file *)a, f_inode);
		break;
	case TE_REF_PATH:
		inode = BPF_CORE_READ((const struct path *)a, dentry, d_inode);
		break;
	case TE_REF_PATH_DENTRY:
		inode = BPF_CORE_READ((struct dentry *)b, d_inode);
		break;
	default:
		return 1; /* TE_REF_USER_PATH: no inode, assume regular */
	}
	if (!inode)
		return 1; /* defensive: if we can't read, don't skip */
	i_mode = BPF_CORE_READ(inode, i_mode);
	return (i_mode & TE_S_IFMT) == TE_S_IFREG ||
	       (i_mode & TE_S_IFMT) == TE_S_IFDIR;
}

static __always_inline int te_handle_file(__u32 ref_kind, const void *a,
					  const void *b, __u32 access,
					  __u32 mode)
{
	struct file_scratch *scratch = file_scratch_buf();
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!access)
		return 0;
	if (!scratch)
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (te_resolve_file_ref(ref_kind, a, b, scratch->path, sizeof(scratch->path)) < 0)
		return 0;
	te_resolve_file_id(ref_kind, a, b, scratch->path, &scratch->fid);

	/* Skip taint for non-regular files (chardev, blockdev, pipe, socket) */
	if (!te_is_regular_or_dir(a, b, ref_kind))
		return 0;
	return te_handle_file_event(pid, scratch->path, &scratch->fid, access, mode);
}

static __always_inline int te_stash_rename_user_paths(const void *old_path,
						      const void *new_path,
						      __u32 flags,
						      __u32 mode)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct file_scratch *scratch = file_scratch_buf();
	struct rename_pend p = {
		.old_path_ptr = (__u64)old_path,
		.new_path_ptr = (__u64)new_path,
		.flags = flags,
	};
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	pid = tid >> 32;
	if (!te_pid_active(pid))
		return 0;
	if (scratch) {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		if (te_resolve_file_ref(TE_REF_USER_PATH, old_path, 0,
					scratch->path, sizeof(scratch->path)) == 0) {
			te_copy_target(p.old_path, scratch->path);
			te_resolve_file_id(TE_REF_USER_PATH, old_path, 0,
					   scratch->path, &p.old_fid);
			p.have_old = 1;
		}
		__builtin_memset(scratch, 0, sizeof(*scratch));
		if (te_resolve_file_ref(TE_REF_USER_PATH, new_path, 0,
					scratch->path, sizeof(scratch->path)) == 0) {
			te_copy_target(p.new_path, scratch->path);
			te_resolve_file_id(TE_REF_USER_PATH, new_path, 0,
					   scratch->path, &p.new_fid);
			p.have_new = 1;
		}
	}
	bpf_map_update_elem(&ts_renamepend, &tid, &p, BPF_ANY);
	return 0;
}

static __noinline int te_handle_rename_exit(long ret, __u32 mode)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct rename_pend *p = bpf_map_lookup_elem(&ts_renamepend, &tid);
	struct file_scratch *scratch = file_scratch_buf();
	int rc = 0;
	int rc2 = 0;
	__u32 exchange = 0;

	if (!p)
		return 0;
	if (ret == 0 && scratch && te_pid_active(pid)) {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		if (!p->have_old && p->old_path_ptr &&
		    te_resolve_file_ref(TE_REF_USER_PATH,
					(const void *)p->old_path_ptr, 0,
					scratch->path, sizeof(scratch->path)) == 0) {
			te_copy_target(p->old_path, scratch->path);
			te_resolve_file_id(TE_REF_USER_PATH,
					   (const void *)p->old_path_ptr, 0,
					   scratch->path, &p->old_fid);
			p->have_old = 1;
		}
		__builtin_memset(scratch, 0, sizeof(*scratch));
		if (!p->have_new && p->new_path_ptr &&
		    te_resolve_file_ref(TE_REF_USER_PATH,
					(const void *)p->new_path_ptr, 0,
					scratch->path, sizeof(scratch->path)) == 0) {
			te_copy_target(p->new_path, scratch->path);
			te_resolve_file_id(TE_REF_USER_PATH,
					   (const void *)p->new_path_ptr, 0,
					   scratch->path, &p->new_fid);
			p->have_new = 1;
		}
		exchange = p->flags & RENAME_EXCHANGE;
		if (p->have_old) {
			if (policy_features & TE_POLICY_FILE_FLOW)
				te_materialize_file_source(pid, &p->old_fid,
							   p->old_path);
			rc = te_handle_file_event(pid, p->old_path, &p->old_fid,
						  TE_ACCESS_WRITE, mode);
		}
		if (p->have_new) {
			if (exchange && (policy_features & TE_POLICY_FILE_FLOW))
				te_materialize_file_source(pid, &p->new_fid,
							   p->new_path);
			rc2 = te_handle_file_event(pid, p->new_path, &p->new_fid,
						   TE_ACCESS_WRITE, mode);
			if (!rc)
				rc = rc2;
		}
		if (p->have_old && p->have_new &&
		    !te_file_id_equal(&p->old_fid, &p->new_fid)) {
			if (exchange)
				te_swap_file_state(pid, &p->old_fid,
						   &p->new_fid);
			else
				te_copy_file_state(pid, &p->old_fid,
						   &p->new_fid, 1);
		}
	}
	bpf_map_delete_elem(&ts_renamepend, &tid);
	return rc;
}

static __always_inline int te_handle_file_permission(struct file *file,
						     __u32 access, __u32 mode)
{
	struct file_scratch *scratch = file_scratch_buf();
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!access)
		return 0;
	if (!scratch)
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	/* bpf_d_path is not accepted by the verifier for file_permission on
	 * some kernels. Use the dentry name for display/target matching but keep
	 * the inode-backed file_id so fd-level flow still joins with open-time
	 * labels for the same file object. */
	if (file_basename(file, scratch->path, sizeof(scratch->path)) < 0)
		return 0;
	te_resolve_file_id(TE_REF_FILE, file, 0, scratch->path, &scratch->fid);

	return te_handle_file_event(pid, scratch->path, &scratch->fid, access, mode);
}

static __always_inline int te_handle_net(__u32 ref_kind, const void *a,
					 const void *b, __u32 access,
					 __u32 mode)
{
	char target[TAINT_PAT_LEN] = {};
	struct te_event ev = {};
	__u32 ip = 0;
	pid_t pid;

	(void)b;
	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!(access & (TE_ACCESS_CONNECT | TE_ACCESS_RECV)))
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;
	if (ref_kind == TE_REF_SOCKET) {
		if (te_resolve_socket_peer_ipv4((struct socket *)a, &ip) < 0)
			return 0;
	} else if (te_resolve_sockaddr(ref_kind, a, &ip) < 0) {
		return 0;
	}

	ev.pid = pid;
	ev.obj_kind = TE_OBJ_ENDPOINT;
	ev.access = access;
	ev.mode = mode;
	ev.target = target;
	ev.ip = ip;
	return te_handle_event(&ev, 0);
}

static __always_inline int te_handle_net_ip(__u32 ip, __u32 access, __u32 mode)
{
	char target[TAINT_PAT_LEN] = {};
	struct te_event ev = {};
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!ip || !(access & (TE_ACCESS_CONNECT | TE_ACCESS_RECV)))
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;

	ev.pid = pid;
	ev.obj_kind = TE_OBJ_ENDPOINT;
	ev.access = access;
	ev.mode = mode;
	ev.target = target;
	ev.ip = ip;
	return te_handle_event(&ev, 0);
}

static __always_inline int te_handle_fd_event(int fd, __u32 access, __u32 mode)
{
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!access)
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;
	struct fd_ref *ref = te_lookup_fd(pid, fd);
	if (!ref)
		return 0;
	return te_handle_file_event(pid, ref->path, &ref->fid, access, mode);
}

static __always_inline int te_handle_channel(int fd, __u32 access, __u32 mode)
{
	struct file_scratch *scratch = file_scratch_buf();
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!scratch)
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (!chan_fd_target(fd, access, scratch->path, sizeof(scratch->path)))
		return 0;

	scratch->fid.ino = te_fnv1a(scratch->path);
	return te_handle_file_event(pid, scratch->path, &scratch->fid, access, mode);
}

static __always_inline int te_handle_exec_event(pid_t pid, const char *target,
						const char *display,
						__u32 mode)
{
	struct eval_scratch *scratch = eval_scratch_buf();
	struct te_rule_eval *eval;
	__u32 effect = TEFFECT_NOTIFY;
	__u32 action;
	__u64 matched_labels;
	__u32 matched_domain_id;
	__u32 current_domain_id;
	__u64 global_labels;
	__u64 current_labels;
	int rid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!te_pid_active(pid))
		return 0;
	if (!target)
		return 0;
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	eval = &scratch->eval;

	current_domain_id = cap_domain_for_pid(pid);
	global_labels = te_labels_for_domain(pid, 0);
	current_labels = te_labels_for_domain(pid, current_domain_id);

	eval->pid = pid;
	eval->global_labels = global_labels;
	eval->current_labels = current_labels;
	eval->current_domain_id = current_domain_id;
	eval->effect = TEFFECT_BLOCK;
	eval->effect_mask = te_supported_effects(mode);
	eval->op = TOP_EXEC;
	te_copy_target(eval->target, target);
	rid = te_check_labels_no_args(eval);
	effect = eval->effect;
	matched_labels = eval->matched_labels;
	matched_domain_id = eval->matched_domain_id;

	if (rid < 0)
		return 0;

	action = te_effect_mode(mode, effect);
	if (action != TE_MODE_UNSUPPORTED)
		emit_violation(pid, rid, display ? display : target, 0,
			       TE_OBJ_EXEC, 0, matched_domain_id, matched_labels,
			       TOP_EXEC,
			       action == TE_MODE_BLOCK ||
				       (action == TE_MODE_KILL && mode == TE_MODE_BLOCK),
			       action == TE_MODE_KILL, effect);
	if (action == TE_MODE_BLOCK)
		return -EPERM;
	if (action == TE_MODE_KILL) {
		bpf_send_signal(SIGKILL);
		if (mode == TE_MODE_BLOCK)
			return -EPERM;
	}
	return 0;
}

static __always_inline int te_handle_exec_event_with_args(pid_t pid,
							  const char *target,
							  const char *display,
							  __u32 mode)
{
	struct eval_scratch *scratch = eval_scratch_buf();
	struct te_rule_eval *eval;
	__u32 effect = TEFFECT_NOTIFY;
	__u32 action;
	__u64 matched_labels;
	__u32 matched_domain_id;
	__u32 current_domain_id;
	__u64 global_labels;
	__u64 current_labels;
	int rid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	if (!te_pid_active(pid))
		return 0;
	if (!target)
		return 0;
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	eval = &scratch->eval;

	current_domain_id = cap_domain_for_pid(pid);
	global_labels = te_labels_for_domain(pid, 0);
	current_labels = te_labels_for_domain(pid, current_domain_id);

	eval->pid = pid;
	eval->global_labels = global_labels;
	eval->current_labels = current_labels;
	eval->current_domain_id = current_domain_id;
	eval->effect = TEFFECT_BLOCK;
	eval->effect_mask = te_supported_effects(mode);
	eval->op = TOP_EXEC;
	te_copy_target(eval->target, target);
	rid = te_check_labels(eval);
	effect = eval->effect;
	matched_labels = eval->matched_labels;
	matched_domain_id = eval->matched_domain_id;

	if (rid < 0)
		return 0;

	action = te_effect_mode(mode, effect);
	if (action != TE_MODE_UNSUPPORTED)
		emit_violation(pid, rid, display ? display : target, 0,
			       TE_OBJ_EXEC, 0, matched_domain_id, matched_labels,
			       TOP_EXEC,
			       action == TE_MODE_BLOCK ||
				       (action == TE_MODE_KILL && mode == TE_MODE_BLOCK),
			       action == TE_MODE_KILL, effect);
	if (action == TE_MODE_BLOCK)
		return -EPERM;
	if (action == TE_MODE_KILL) {
		bpf_send_signal(SIGKILL);
		if (mode == TE_MODE_BLOCK)
			return -EPERM;
	}
	return 0;
}

static __always_inline int te_handle_exec(__u32 ref_kind, const void *a,
					  const void *b, __u32 mode)
{
	const char *target;
	const char *shown;
	pid_t pid;

	if (mode == TE_MODE_BLOCK && !enforce_mode)
		return 0;
	pid = bpf_get_current_pid_tgid() >> 32;
	if (!te_pid_active(pid))
		return 0;
	if (ref_kind == TE_REF_BPRM) {
		struct exec_scratch *scratch = exec_scratch_buf();
		if (!scratch)
			return 0;
		__builtin_memset(scratch, 0, sizeof(*scratch));
		if (bprm_basename((struct linux_binprm *)a, scratch->match,
				  sizeof(scratch->match)) < 0)
			return 0;
		if (bprm_filename((struct linux_binprm *)a, scratch->display,
				  sizeof(scratch->display)) < 0)
			__builtin_memcpy(scratch->display, scratch->match,
					 sizeof(scratch->match));
		if (mode == TE_MODE_BLOCK) {
			struct te_argslots *as = te_argslots_buf();

			if (as)
				__builtin_memset(as, 0, sizeof(*as));
		}
		target = scratch->match;
		shown = scratch->display;
	} else if (ref_kind == TE_REF_STRINGS) {
		target = a;
		shown = b ? b : a;
		if (!target)
			return 0;
	} else {
		return 0;
	}

	return te_handle_exec_event(pid, target, shown, mode);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm_check_security, struct linux_binprm *bprm)
{
	return te_handle_exec(TE_REF_BPRM, bprm, 0, TE_MODE_BLOCK);
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
	return te_handle_file_permission(file, te_access_from_perm_mask(mask),
					 TE_MODE_BLOCK);
}

SEC("lsm/file_truncate")
int BPF_PROG(enforce_file_truncate, struct file *file)
{
	return te_handle_file_permission(file, TE_ACCESS_WRITE, TE_MODE_BLOCK);
}

SEC("lsm/mmap_file")
int BPF_PROG(enforce_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	(void)reqprot;
	if (!file)
		return 0;
	return te_handle_file_permission(file, te_access_from_mmap(prot, flags),
					 TE_MODE_BLOCK);
}

SEC("lsm/file_mprotect")
int BPF_PROG(enforce_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot)
{
	struct file *file;
	unsigned long vm_flags;
	unsigned long map_flags;

	(void)reqprot;
	if (!vma)
		return 0;
	file = BPF_CORE_READ(vma, vm_file);
	if (!file)
		return 0;
	vm_flags = BPF_CORE_READ(vma, vm_flags);
	map_flags = (vm_flags & VM_SHARED) ? MAP_SHARED : MAP_PRIVATE;
	return te_handle_file_permission(file,
					 te_access_from_mmap(prot, map_flags),
					 TE_MODE_BLOCK);
}

SEC("lsm/path_truncate")
int BPF_PROG(enforce_path_truncate, const struct path *path_arg)
{
	return te_handle_file(TE_REF_PATH, path_arg, 0, TE_ACCESS_WRITE,
			      TE_MODE_BLOCK);
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
	int rc = te_handle_file(TE_REF_PATH_DENTRY, old_dir, old_dentry,
				TE_ACCESS_WRITE, TE_MODE_BLOCK);
	if (rc)
		return rc;
	return te_handle_file(TE_REF_PATH_DENTRY, new_dir, new_dentry,
			      TE_ACCESS_WRITE, TE_MODE_BLOCK);
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

SEC("lsm/socket_recvmsg")
int BPF_PROG(enforce_socket_recvmsg, struct socket *sock, struct msghdr *msg,
	     int size, int flags)
{
	(void)msg;
	(void)size;
	(void)flags;
	return te_handle_net(TE_REF_SOCKET, sock, 0, TE_ACCESS_RECV, TE_MODE_BLOCK);
}

static __always_inline int te_protect_control_pid(struct task_struct *target)
{
	pid_t caller = bpf_get_current_pid_tgid() >> 32;
	pid_t target_tgid;

	if (!te_pid_active(caller))
		return 0;
	if (!target)
		return 0;
	target_tgid = BPF_CORE_READ(target, tgid);
	if (target_tgid <= 0 || target_tgid == caller)
		return 0;
	if (!te_pid_protected(target_tgid))
		return 0;
	return -EPERM;
}

SEC("lsm/task_kill")
int BPF_PROG(enforce_task_kill, struct task_struct *target,
	     struct kernel_siginfo *info, int sig, const struct cred *cred)
{
	(void)info;
	(void)cred;
	if (sig == 0)
		return 0;
	return te_protect_control_pid(target);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(enforce_ptrace_access_check, struct task_struct *child,
	     unsigned int mode)
{
	(void)mode;
	return te_protect_control_pid(child);
}

SEC("lsm/bpf")
int BPF_PROG(enforce_bpf_syscall, int cmd, union bpf_attr *attr,
	     unsigned int size, bool privileged)
{
	pid_t caller = bpf_get_current_pid_tgid() >> 32;

	(void)attr;
	(void)size;
	(void)privileged;
	if (!te_pid_active(caller))
		return 0;

	/* Runtime clients may need to open pinned maps while already managed.
	 * Map mutation is limited to protected pids or domains that already carry
	 * runtime authority. */
	switch (cmd) {
	case BPF_MAP_LOOKUP_ELEM:
	case BPF_MAP_GET_NEXT_KEY:
	case BPF_OBJ_GET:
	case BPF_OBJ_GET_INFO_BY_FD:
		return 0;
	case BPF_MAP_UPDATE_ELEM:
	case BPF_MAP_DELETE_ELEM:
		return te_pid_can_control_bpf(caller) ? 0 : -EPERM;
	default:
		return -EPERM;
	}
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	pid_t parent_tgid = bpf_get_current_pid_tgid() >> 32;

	te_fork(parent_tgid, ctx->child_pid);
	te_copy_fork_fds(parent_tgid, ctx->child_pid);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct exec_scratch *scratch = exec_scratch_buf();
	unsigned fname_off;
	const char *target;

	if (!te_pid_active(pid))
		return 0;
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));

	bpf_get_current_comm(&scratch->match, TASK_COMM_LEN);
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(scratch->display, sizeof(scratch->display), (void *)ctx + fname_off);

	target = scratch->match;
	struct te_argslots *as = te_argslots_buf();
	if (as) {
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		unsigned long a0 = 0;

		__builtin_memset(as->blob, 0, sizeof(as->blob));
		if (mm)
			a0 = BPF_CORE_READ(mm, arg_start);
		if (a0 && bpf_probe_read_user_str(as->blob, TAINT_PAT_LEN,
						  (void *)a0) > 0)
			target = as->blob;
	}
	te_exec_update_no_args(pid, target);
	te_handle_exec(TE_REF_STRINGS, target, scratch->display, te_tracepoint_mode());
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec_args(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
#ifndef ACTPLANE_LEGACY_KERNEL
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
#endif
	struct exec_scratch *scratch = exec_scratch_buf();
	unsigned fname_off;
#ifndef ACTPLANE_LEGACY_KERNEL
	int alen = 0;
#endif

	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (!te_pid_active(pid))
		return 0;

	bpf_get_current_comm(&scratch->match, TASK_COMM_LEN);
	__builtin_memcpy(scratch->display, scratch->match, TASK_COMM_LEN);

	/* read argv blob (NUL-separated) into per-CPU scratch, then tokenize into
	 * fixed slots there for @arg matching. */
#ifndef ACTPLANE_LEGACY_KERNEL
	struct te_argslots *as = te_argslots_buf();
	if (as) {
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		unsigned long a0 = 0;
		__builtin_memset(as, 0, sizeof(*as));
		if (mm) {
			a0 = BPF_CORE_READ(mm, arg_start);
			unsigned long a1 = BPF_CORE_READ(mm, arg_end);
			unsigned long len = a1 - a0;
			if (len > TAINT_ARGV_CAP - 1)
				len = TAINT_ARGV_CAP - 1;
			if (len > 0 && bpf_probe_read_user(as->blob, len, (void *)a0) == 0)
				alen = (int)len;
		}
		te_tokenize_args_eng(alen);
	}
#endif

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(scratch->display, sizeof(scratch->display), (void *)ctx + fname_off);
	if (exec_pipe_init(pid, te_tracepoint_mode()) == 0)
		bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_UPDATE_SIMPLE);
	return 0;
}

#ifdef ACTPLANE_LEGACY_KERNEL
static __noinline void te_read_legacy_args(struct task_struct *task)
{
	struct te_argslots *as = te_argslots_buf();
	struct mm_struct *mm;
	unsigned long start;
	unsigned long end;
	unsigned long pos;
	long n;

	if (!as || !task)
		return;
	__builtin_memset(as, 0, sizeof(*as));
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return;
	start = BPF_CORE_READ(mm, arg_start);
	end = BPF_CORE_READ(mm, arg_end);
	pos = start;
	if (!start || end <= start)
		return;

/* Fixed helper calls avoid the data-dependent byte-tokenizer loop that makes
	 * Linux 5.10 exhaust its one-million verifier-state budget. Each wide read
	 * advances over a complete token, while only representable @arg tokens are
	 * copied into matcher slots. arg_end and TAINT_ARGV_CAP keep the scan out of
	 * the environment and aligned with the modern engine's argv byte budget. */
#define TE_READ_ARG_SLOT(slot) do { \
	unsigned long used = pos - start; \
	if (pos >= end || used >= TAINT_ARGV_CAP) \
		return; \
	n = bpf_probe_read_user_str(as->blob, TAINT_ARGV_CAP, (void *)pos); \
	if (n <= 0 || n >= TAINT_ARGV_CAP || \
	    (unsigned long)n > end - pos || \
	    (unsigned long)n > TAINT_ARGV_CAP - used) \
		return; \
	if (n <= TAINT_ARG_LEN) \
		bpf_probe_read_user_str(as->slots + (slot) * TAINT_ARG_LEN, \
					TAINT_ARG_LEN, (void *)pos); \
	pos += n; \
} while (0)
	TE_READ_ARG_SLOT(0);
	TE_READ_ARG_SLOT(1);
	TE_READ_ARG_SLOT(2);
	TE_READ_ARG_SLOT(3);
	TE_READ_ARG_SLOT(4);
	TE_READ_ARG_SLOT(5);
	TE_READ_ARG_SLOT(6);
	TE_READ_ARG_SLOT(7);
	TE_READ_ARG_SLOT(8);
	TE_READ_ARG_SLOT(9);
	TE_READ_ARG_SLOT(10);
	TE_READ_ARG_SLOT(11);
	TE_READ_ARG_SLOT(12);
	TE_READ_ARG_SLOT(13);
	TE_READ_ARG_SLOT(14);
	TE_READ_ARG_SLOT(15);
#undef TE_READ_ARG_SLOT
}

SEC("tp/sched/sched_process_exec")
int handle_exec_legacy_args(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct exec_scratch *scratch = exec_scratch_buf();
	unsigned fname_off;

	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (!te_pid_active(pid))
		return 0;
	bpf_get_current_comm(&scratch->match, TASK_COMM_LEN);
	__builtin_memcpy(scratch->display, scratch->match, TASK_COMM_LEN);
	te_read_legacy_args(task);
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(scratch->display, sizeof(scratch->display), (void *)ctx + fname_off);
	if (exec_pipe_init(pid, te_tracepoint_mode()) == 0)
		bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_ARG_UPDATE_SIMPLE);
	return 0;
}
#endif

SEC("tp/sched/sched_process_exec")
int exec_tp_update_simple(struct trace_event_raw_sched_process_exec *ctx)
{
#ifdef ACTPLANE_LEGACY_KERNEL
	exec_pipe_collect_updates(0, 0);
#else
	exec_pipe_collect_updates(0, 1);
#endif
	bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_UPDATE_PREFIX);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int exec_tp_update_prefix(struct trace_event_raw_sched_process_exec *ctx)
{
#ifdef ACTPLANE_LEGACY_KERNEL
	exec_pipe_collect_updates(1, 0);
#else
	exec_pipe_collect_updates(1, 1);
#endif
	exec_pipe_apply_updates();
	bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_RULE_SIMPLE);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int exec_tp_rule_simple(struct trace_event_raw_sched_process_exec *ctx)
{
#ifdef ACTPLANE_LEGACY_KERNEL
	exec_pipe_scan_rules(0, 0);
#else
	exec_pipe_scan_rules(0, 1);
#endif
	bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_RULE_COMPLEX);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int exec_tp_rule_complex(struct trace_event_raw_sched_process_exec *ctx)
{
	(void)ctx;
#ifdef ACTPLANE_LEGACY_KERNEL
	exec_pipe_scan_rules(1, 0);
#else
	exec_pipe_scan_rules(1, 1);
#endif
	exec_pipe_finish();
	return 0;
}

#ifdef ACTPLANE_LEGACY_KERNEL
SEC("tp/sched/sched_process_exec")
int exec_tp_arg_update_simple(struct trace_event_raw_sched_process_exec *ctx)
{
	exec_pipe_collect_updates(0, 1);
	bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_ARG_UPDATE_PREFIX);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int exec_tp_arg_update_prefix(struct trace_event_raw_sched_process_exec *ctx)
{
	exec_pipe_collect_updates(1, 1);
	exec_pipe_apply_updates();
	bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_ARG_RULE_SIMPLE);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int exec_tp_arg_rule_simple(struct trace_event_raw_sched_process_exec *ctx)
{
	exec_pipe_scan_rules(0, 1);
	bpf_tail_call(ctx, &exec_tail, EXEC_TAIL_ARG_RULE_COMPLEX);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int exec_tp_arg_rule_complex(struct trace_event_raw_sched_process_exec *ctx)
{
	(void)ctx;
	exec_pipe_scan_rules(1, 1);
	exec_pipe_finish();
	return 0;
}
#endif

#ifdef ACTPLANE_LEGACY_KERNEL
struct te_legacy_file_update_ctx {
	__u64 path_hash;
	__u64 add;
	__u64 read_gates;
	__u64 read_invals;
	__u64 write_gates;
	__u64 write_invals;
};

struct te_legacy_file_rule_ctx {
	pid_t pid;
	__u32 access;
	__u64 path_hash;
	__u64 proc_labels;
	__u64 read_labels;
	__u32 effect_mask;
	__u32 best_effect;
	int best_rule;
	int best_index;
	__u32 best_op;
	__u64 best_labels;
};

struct te_legacy_file_eval_scratch {
	struct te_legacy_file_update_ctx updates;
	struct te_legacy_file_rule_ctx rules;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct te_legacy_file_eval_scratch);
} ts_legacy_file_eval_scratch SEC(".maps");

static __always_inline struct te_legacy_file_eval_scratch *
te_legacy_file_eval_scratch_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_legacy_file_eval_scratch, &key);
}

struct te_legacy_file_prov_op {
	struct file_domain_id fdom;
	__u64 source_labels;
	__u64 read_labels;
	__u64 write_labels;
	char target[MAX_FILENAME_LEN];
};

struct te_legacy_file_prov_pipe {
	pid_t pid;
	__u32 n_ops;
	struct te_legacy_file_prov_op ops[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct te_legacy_file_prov_pipe);
} ts_legacy_file_prov_pipe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} legacy_file_tail SEC(".maps");

struct te_legacy_file_pending_op {
	__u32 flags;
	char path[MAX_FILENAME_LEN];
};

struct te_legacy_file_pending {
	__u32 n_ops;
	struct te_legacy_file_pending_op ops[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct te_legacy_file_pending);
} ts_legacy_file_pending SEC(".maps");

static __noinline void te_legacy_apply_rename_pending(void);

static __always_inline struct te_legacy_file_prov_pipe *
te_legacy_file_prov_pipe_buf(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&ts_legacy_file_prov_pipe, &key);
}

static __always_inline void te_legacy_file_prov_pipe_reset(void)
{
	struct te_legacy_file_prov_pipe *pipe =
		te_legacy_file_prov_pipe_buf();

	if (pipe)
		pipe->n_ops = 0;
}

static __always_inline void te_legacy_file_pending_reset(__u64 tid)
{
	bpf_map_delete_elem(&ts_legacy_file_pending, &tid);
	te_legacy_file_prov_pipe_reset();
}

static __noinline int te_legacy_stash_file_pending(
	__u64 tid, const char *path, __u32 flags)
{
	struct te_legacy_file_pending *pending =
		bpf_map_lookup_elem(&ts_legacy_file_pending, &tid);
	struct te_legacy_file_pending initial = {};
	struct te_legacy_file_pending_op *op;

	if (!pending) {
		if (bpf_map_update_elem(&ts_legacy_file_pending, &tid, &initial,
					BPF_NOEXIST) < 0)
			return -1;
		pending = bpf_map_lookup_elem(&ts_legacy_file_pending, &tid);
		if (!pending)
			return -1;
	}
	if (pending->n_ops == 0)
		op = &pending->ops[0];
	else if (pending->n_ops == 1)
		op = &pending->ops[1];
	else
		return -1;
	op->flags = flags;
	bpf_probe_read_kernel_str(op->path, sizeof(op->path), path);
	pending->n_ops++;
	return 0;
}

static int te_legacy_file_update_cb(__u32 i, void *vc)
{
	struct te_legacy_file_update_ctx *c = vc;
	struct taint_update *up;
	__u64 target_hash;

	if (i >= MAX_TAINT_UPDATES)
		return 1;
	up = bpf_map_lookup_elem(&ts_updates, &i);
	if (!up)
		return 1;
	if (up->domain_id != 0 ||
	    (up->op != TOP_OPEN && up->op != TOP_WRITE))
		return 0;
	target_hash = ((__u64)up->ipv4_mask << 32) | up->ipv4;
	if (up->match == TAINT_MATCH_ANY ||
	    (up->match == TAINT_MATCH_EXACT && target_hash == c->path_hash)) {
		if (up->op == TOP_OPEN) {
			c->add |= up->add;
			c->read_gates |= up->gates;
			c->read_invals |= up->invals;
		}
		else {
			c->write_gates |= up->gates;
			c->write_invals |= up->invals;
		}
	}
	return 0;
}

static int te_legacy_file_update_path_cb(__u32 i, void *vc)
{
	struct te_legacy_file_update_ctx *c = vc;
	struct file_scratch *scratch = file_scratch_buf();
	struct taint_update *up;

	if (!scratch || i >= MAX_TAINT_UPDATES)
		return 1;
	up = bpf_map_lookup_elem(&ts_updates, &i);
	if (!up)
		return 1;
	if (up->domain_id != 0 ||
	    (up->op != TOP_OPEN && up->op != TOP_WRITE) ||
	    up->match == TAINT_MATCH_EXACT || up->match == TAINT_MATCH_ANY)
		return 0;
	if (te_path_match(up->match, scratch->path, up->target)) {
		if (up->op == TOP_OPEN) {
			c->add |= up->add;
			c->read_gates |= up->gates;
			c->read_invals |= up->invals;
		}
		else {
			c->write_gates |= up->gates;
			c->write_invals |= up->invals;
		}
	}
	return 0;
}

static __always_inline int te_legacy_file_rule_apply(
	struct te_legacy_file_rule_ctx *c, const struct taint_rule *r, __u32 i)
{
	__u64 labels;

	if (r->domain_id != 0)
		return 0;
	if (r->op == TOP_OPEN) {
		if (!(c->access & TE_ACCESS_READ))
			return 0;
		labels = c->read_labels;
	} else if (r->op == TOP_WRITE) {
		if (!(c->access & TE_ACCESS_WRITE))
			return 0;
		labels = c->proc_labels;
	} else {
		return 0;
	}
	if (!taint_mask_ok(labels, r->req, r->forbid))
		return 0;
	if (r->effect > TEFFECT_KILL ||
	    !(c->effect_mask & (1U << r->effect)))
		return 0;
	if (c->best_rule < 0 || r->effect > c->best_effect ||
	    (r->effect == c->best_effect && (int)i < c->best_index)) {
		c->best_effect = r->effect;
		c->best_rule = (int)r->rule_id;
		c->best_index = (int)i;
		c->best_op = r->op;
		c->best_labels = labels & r->req;
		if (r->effect == TEFFECT_KILL)
			return 1;
	}
	return 0;
}

static int te_legacy_file_rule_cb(__u32 i, void *vc)
{
	struct te_legacy_file_rule_ctx *c = vc;
	struct taint_rule *rp;
	__u64 target_hash;

	if (i >= MAX_TAINT_RULES)
		return 1;
	rp = bpf_map_lookup_elem(&ts_rules, &i);
	if (!rp)
		return 1;
	if (rp->cond_kind != TCOND_NONE)
		return 0;
	target_hash = ((__u64)rp->ipv4_mask << 32) | rp->ipv4;
	if (rp->match != TAINT_MATCH_ANY &&
	    (rp->match != TAINT_MATCH_EXACT || target_hash != c->path_hash))
		return 0;
	return te_legacy_file_rule_apply(c, rp, i);
}

static int te_legacy_file_rule_path_cb(__u32 i, void *vc)
{
	struct te_legacy_file_rule_ctx *c = vc;
	struct file_scratch *scratch = file_scratch_buf();
	struct taint_rule *rp;

	if (!scratch || i >= MAX_TAINT_RULES)
		return 1;
	rp = bpf_map_lookup_elem(&ts_rules, &i);
	if (!rp)
		return 1;
	if (rp->cond_kind != TCOND_NONE)
		return 0;
	if (rp->match == TAINT_MATCH_EXACT || rp->match == TAINT_MATCH_ANY ||
	    !te_path_match(rp->match, scratch->path, rp->target))
		return 0;
	return te_legacy_file_rule_apply(c, rp, i);
}

static int te_legacy_file_rule_condition_cb(__u32 i, void *vc)
{
	struct te_legacy_file_rule_ctx *c = vc;
	struct file_scratch *scratch = file_scratch_buf();
	struct taint_rule *rp;
	struct proc_state *proc;
	__u64 target_hash;
	__u64 cond_hash;
	int target_match;
	int cond_match;

	if (!scratch || i >= MAX_TAINT_RULES)
		return 1;
	rp = bpf_map_lookup_elem(&ts_rules, &i);
	if (!rp)
		return 1;
	if (rp->cond_kind == TCOND_NONE)
		return 0;
	if (rp->match == TAINT_MATCH_EXACT || rp->match == TAINT_MATCH_ANY) {
		target_hash = ((__u64)rp->ipv4_mask << 32) | rp->ipv4;
		target_match = rp->match == TAINT_MATCH_ANY ||
			target_hash == c->path_hash;
	} else {
		target_match = te_path_match(rp->match, scratch->path,
					     rp->target);
	}
	if (!target_match)
		return 0;
	if (rp->cond_kind == TCOND_LINEAGE) {
		proc = te_get(c->pid);
		if (proc && (proc->lin_gates & rp->gate))
			return 0;
	} else if (rp->cond_kind == TCOND_AFTER) {
		if (te_after_satisfied(rp, c->pid))
			return 0;
	} else if (rp->cond_kind == TCOND_TARGET) {
		if (rp->cond_match == TAINT_MATCH_EXACT ||
		    rp->cond_match == TAINT_MATCH_ANY) {
			cond_hash = ((__u64)rp->cond_ipv4_mask << 32) |
				rp->cond_ipv4;
			cond_match = rp->cond_match == TAINT_MATCH_ANY ||
				cond_hash == c->path_hash;
		} else {
			cond_match = te_path_match(rp->cond_match, scratch->path,
						   rp->cond_pat);
		}
		if (rp->cond_neg ? !cond_match : cond_match)
			return 0;
	}
	return te_legacy_file_rule_apply(c, rp, i);
}

static __noinline void te_legacy_record_file_prov(
	pid_t pid, struct file_domain_id *fdom, __u64 labels,
	unsigned int op, const char *target)
{
	struct te_prov *prov;
	struct file_label_id key;

	prov = te_prov_tmp();
	if (!prov)
		return;
	__builtin_memset(prov, 0, sizeof(*prov));
	prov->timestamp_ns = bpf_ktime_get_ns();
	prov->pid = pid;
	prov->op = op;
	bpf_probe_read_kernel_str(prov->target, sizeof(prov->target), target);
	key.fdom = *fdom;
#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!labels)
			break;
		bit = labels & (0ULL - labels);
		prov->label = bit;
		key.label = bit;
		bpf_map_update_elem(&ts_file_prov, &key, prov, BPF_ANY);
		labels &= ~bit;
	}
}

static __noinline void te_legacy_file_prov_to_proc(
	pid_t pid, struct file_domain_id *fdom, __u64 labels)
{
	struct file_label_id from;
	struct pid_label_id to;
	struct te_prov *prov;

#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!labels)
			break;
		bit = labels & (0ULL - labels);
		from.fdom = *fdom;
		from.label = bit;
		prov = bpf_map_lookup_elem(&ts_file_prov, &from);
		if (prov) {
			to.pid = pid;
			to.domain_id = 0;
			to.label = bit;
			bpf_map_update_elem(&ts_proc_prov, &to, prov, BPF_ANY);
		}
		labels &= ~bit;
	}
}

static __noinline void te_legacy_proc_prov_to_file(
	pid_t pid, struct file_domain_id *fdom, __u64 labels)
{
	struct pid_label_id from = { .pid = pid, .domain_id = 0 };
	struct file_label_id to;
	struct te_prov *prov;

#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!labels)
			break;
		bit = labels & (0ULL - labels);
		from.label = bit;
		prov = bpf_map_lookup_elem(&ts_proc_prov, &from);
		if (prov) {
			to.fdom = *fdom;
			to.label = bit;
			bpf_map_update_elem(&ts_file_prov, &to, prov, BPF_ANY);
		}
		labels &= ~bit;
	}
}

static __noinline void te_legacy_record_file_prov_bit(
	pid_t pid, struct file_domain_id *fdom, __u64 bit,
	unsigned int op, const char *target)
{
	struct te_prov *prov = te_prov_tmp();
	struct file_label_id key;

	if (!prov || !bit)
		return;
	__builtin_memset(prov, 0, sizeof(*prov));
	prov->label = bit;
	prov->timestamp_ns = bpf_ktime_get_ns();
	prov->pid = pid;
	prov->op = op;
	bpf_probe_read_kernel_str(prov->target, sizeof(prov->target), target);
	key.fdom = *fdom;
	key.label = bit;
	bpf_map_update_elem(&ts_file_prov, &key, prov, BPF_ANY);
}

static __noinline void te_legacy_file_prov_bit_to_proc(
	pid_t pid, struct file_domain_id *fdom, __u64 bit)
{
	struct file_label_id from;
	struct pid_label_id to;
	struct te_prov *prov;

	if (!bit)
		return;
	from.fdom = *fdom;
	from.label = bit;
	prov = bpf_map_lookup_elem(&ts_file_prov, &from);
	if (!prov)
		return;
	to.pid = pid;
	to.domain_id = 0;
	to.label = bit;
	bpf_map_update_elem(&ts_proc_prov, &to, prov, BPF_ANY);
}

static __always_inline void te_legacy_record_endp_prov(
	pid_t pid, struct endp_domain_id *edom, __u64 labels,
	unsigned int op, __u32 ip)
{
	struct te_prov *prov;
	struct endp_label_id key;

	prov = te_prov_tmp();
	if (!prov)
		return;
	__builtin_memset(prov, 0, sizeof(*prov));
	prov->timestamp_ns = bpf_ktime_get_ns();
	prov->pid = pid;
	prov->op = op;
	prov->ip = ip;
	key.edom = *edom;
#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!labels)
			break;
		bit = labels & (0ULL - labels);
		prov->label = bit;
		key.label = bit;
		bpf_map_update_elem(&ts_endp_prov, &key, prov, BPF_ANY);
		labels &= ~bit;
	}
}

static __always_inline void te_legacy_endp_prov_to_proc(
	pid_t pid, struct endp_domain_id *edom, __u64 labels)
{
	struct endp_label_id from;
	struct pid_label_id to;
	struct te_prov *prov;

#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!labels)
			break;
		bit = labels & (0ULL - labels);
		from.edom = *edom;
		from.label = bit;
		prov = bpf_map_lookup_elem(&ts_endp_prov, &from);
		if (prov) {
			to.pid = pid;
			to.domain_id = 0;
			to.label = bit;
			bpf_map_update_elem(&ts_proc_prov, &to, prov, BPF_ANY);
		}
		labels &= ~bit;
	}
}

static __always_inline void te_legacy_proc_prov_to_endp(
	pid_t pid, struct endp_domain_id *edom, __u64 labels)
{
	struct pid_label_id from = { .pid = pid, .domain_id = 0 };
	struct endp_label_id to;
	struct te_prov *prov;

#pragma clang loop unroll(disable)
	for (int i = 0; i < MAX_TAINT_LABELS; i++) {
		__u64 bit;

		if (!labels)
			break;
		bit = labels & (0ULL - labels);
		from.label = bit;
		prov = bpf_map_lookup_elem(&ts_proc_prov, &from);
		if (prov) {
			to.edom = *edom;
			to.label = bit;
			bpf_map_update_elem(&ts_endp_prov, &to, prov, BPF_ANY);
		}
		labels &= ~bit;
	}
}

static __always_inline void te_legacy_queue_file_prov(
	pid_t pid, struct file_domain_id *fdom, __u64 source_labels,
	__u64 read_labels, __u64 write_labels, const char *target)
{
	struct te_legacy_file_prov_pipe *pipe =
		te_legacy_file_prov_pipe_buf();
	struct te_legacy_file_prov_op *op;

	if (!pipe || pipe->n_ops >= 2 ||
	    !(source_labels || read_labels || write_labels))
		return;
	if (pipe->n_ops == 0)
		op = &pipe->ops[0];
	else
		op = &pipe->ops[1];
	op->fdom = *fdom;
	op->source_labels = source_labels;
	op->read_labels = read_labels;
	op->write_labels = write_labels;
	bpf_probe_read_kernel_str(op->target, sizeof(op->target), target);
	pipe->pid = pid;
	pipe->n_ops++;
}

static __noinline void te_legacy_apply_file_prov_op(
	pid_t pid, struct te_legacy_file_prov_op *op)
{
	if (op->source_labels)
		te_legacy_record_file_prov(pid, &op->fdom,
					   op->source_labels, TOP_OPEN,
					   op->target);
	if (op->read_labels)
		te_legacy_file_prov_to_proc(pid, &op->fdom,
					    op->read_labels);
	if (op->write_labels)
		te_legacy_proc_prov_to_file(pid, &op->fdom,
					    op->write_labels);
}

SEC("tp/syscalls/sys_enter_openat")
int legacy_file_provenance_tail(struct trace_event_raw_sys_enter *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct te_legacy_file_prov_pipe *pipe =
		te_legacy_file_prov_pipe_buf();

	(void)ctx;
	if (!pipe)
		return 0;
	if (pipe->n_ops > 0)
		te_legacy_apply_file_prov_op(pipe->pid, &pipe->ops[0]);
	if (pipe->n_ops > 1)
		te_legacy_apply_file_prov_op(pipe->pid, &pipe->ops[1]);
	pipe->n_ops = 0;
	te_legacy_apply_rename_pending();
	bpf_map_delete_elem(&ts_legacy_file_pending, &tid);
	return 0;
}

static __always_inline void te_legacy_scan_file_rules(
	struct te_legacy_file_rule_ctx *rules)
{
	bpf_loop(te_count(0), te_legacy_file_rule_cb, rules, 0);
	bpf_loop(te_count(0), te_legacy_file_rule_path_cb, rules, 0);
	if (legacy_file_rule_conditions)
		bpf_loop(te_count(0), te_legacy_file_rule_condition_cb, rules, 0);
}

static __always_inline int te_legacy_open_path(const void *path_ptr,
						unsigned int flags,
						int append_pending)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct file_scratch *scratch = file_scratch_buf();

	if (!append_pending)
		te_legacy_file_pending_reset(tid);
	if (!scratch || !te_pid_active(pid))
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (bpf_probe_read_user_str(scratch->path, sizeof(scratch->path), path_ptr) <= 0)
		return 0;
	te_legacy_stash_file_pending(tid, scratch->path, flags);
	return 0;
}

static __noinline void te_legacy_commit_file_path(
	const char *path, unsigned int flags)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct file_scratch *scratch = file_scratch_buf();
	struct proc_state *proc;
	struct file_domain_id key = {};
	struct file_state *file;
	struct file_state next = {};
	struct te_legacy_file_eval_scratch *eval =
		te_legacy_file_eval_scratch_buf();
	struct te_legacy_file_update_ctx *updates;
	struct te_legacy_file_rule_ctx *rules;
	__u32 access = te_access_from_open_flags(flags);
	__u64 path_hash;

	if (!scratch || !eval || !te_pid_active(pid))
		return;
	__builtin_memset(eval, 0, sizeof(*eval));
	updates = &eval->updates;
	rules = &eval->rules;
	rules->pid = pid;
	rules->access = access;
	rules->effect_mask =
		(1U << TEFFECT_NOTIFY) | (1U << TEFFECT_KILL);
	rules->best_effect = TEFFECT_NOTIFY;
	rules->best_rule = -1;
	rules->best_index = -1;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (bpf_probe_read_kernel_str(scratch->path, sizeof(scratch->path), path) <= 0)
		return;
	proc = te_get(pid);
	if (!proc)
		return;
	path_hash = te_fnv1a(scratch->path);
	updates->path_hash = path_hash;
	bpf_loop(te_count(1), te_legacy_file_update_cb, updates, 0);
	bpf_loop(te_count(1), te_legacy_file_update_path_cb, updates, 0);

	key.fid.ino = path_hash;
	file = bpf_map_lookup_elem(&ts_file, &key);
	if (file)
		next = *file;
	next.labels |= updates->add;
	rules->path_hash = path_hash;
	rules->proc_labels = proc->labels;
	rules->read_labels = proc->labels | next.labels;
	if (policy_features & (TE_POLICY_OPEN_RULES | TE_POLICY_WRITE_RULES))
		te_legacy_scan_file_rules(rules);
	if (rules->best_rule >= 0) {
		__u64 matched_file_labels = rules->best_labels & next.labels;
		__u64 matched_bit =
			matched_file_labels & (0ULL - matched_file_labels);

		if (rules->best_op == TOP_OPEN && (next.labels & matched_bit)) {
			if (updates->add & matched_bit)
				te_legacy_record_file_prov_bit(
					pid, &key, matched_bit, TOP_OPEN,
					scratch->path);
			te_legacy_file_prov_bit_to_proc(pid, &key, matched_bit);
		}
		emit_violation(pid, rules->best_rule, scratch->path, 0,
			       TE_OBJ_FILE, &key.fid, 0, rules->best_labels,
			       rules->best_op, 0,
			       rules->best_effect == TEFFECT_KILL,
			       rules->best_effect);
		if (rules->best_effect == TEFFECT_KILL)
			bpf_send_signal(SIGKILL);
	}
	if ((access & TE_ACCESS_WRITE) &&
	    (updates->write_gates || updates->write_invals)) {
		pid_t root = te_root(pid);
		__u32 epoch = te_tick(root, 0);
		te_stamp(root, 0, epoch, updates->write_gates,
			 updates->write_invals);
	}
	if ((access & TE_ACCESS_READ) &&
	    (updates->read_gates || updates->read_invals)) {
		pid_t root = te_root(pid);
		__u32 epoch = te_tick(root, 0);
		te_stamp(root, 0, epoch, updates->read_gates,
			 updates->read_invals);
	}
	if (access & TE_ACCESS_READ) {
		proc->labels |= next.labels;
	}
	if (access & TE_ACCESS_WRITE) {
		next.labels |= proc->labels;
	}
	te_legacy_queue_file_prov(
		pid, &key, updates->add,
		(access & TE_ACCESS_READ) ? next.labels : 0,
		(access & TE_ACCESS_WRITE) ? proc->labels : 0,
		scratch->path);
	if (next.labels)
		bpf_map_update_elem(&ts_file, &key, &next, BPF_ANY);
}

static __noinline void te_legacy_commit_file_pending(__u64 tid)
{
	struct te_legacy_file_pending *pending;
	struct te_legacy_file_pending_op op = {};
	__u32 n_ops;

	pending = bpf_map_lookup_elem(&ts_legacy_file_pending, &tid);
	if (!pending)
		return;
	n_ops = pending->n_ops;
	if (n_ops > 0) {
		bpf_probe_read_kernel(&op, sizeof(op), &pending->ops[0]);
		te_legacy_commit_file_path(op.path, op.flags);
	}
	if (n_ops > 1) {
		__builtin_memset(&op, 0, sizeof(op));
		pending = bpf_map_lookup_elem(&ts_legacy_file_pending, &tid);
		if (pending) {
			bpf_probe_read_kernel(&op, sizeof(op), &pending->ops[1]);
			te_legacy_commit_file_path(op.path, op.flags);
		}
	}
}

static __always_inline int te_legacy_finish_file(
	struct trace_event_raw_sys_exit *ctx, int success)
{
	__u64 tid = bpf_get_current_pid_tgid();

	if (success) {
		te_legacy_file_prov_pipe_reset();
		te_legacy_commit_file_pending(tid);
		bpf_tail_call(ctx, &legacy_file_tail, 0);
	}
	te_legacy_file_pending_reset(tid);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int legacy_trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_open_path((const void *)ctx->args[1],
			    (unsigned int)ctx->args[2], 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_open")
int legacy_trace_open(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_open_path((const void *)ctx->args[0],
			    (unsigned int)ctx->args[1], 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int legacy_trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct open_how how = {};
	bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]);
	te_legacy_open_path((const void *)ctx->args[1],
			    (unsigned int)how.flags, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_creat")
int legacy_trace_creat(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_open_path((const void *)ctx->args[0],
			    O_WRONLY | O_CREAT | O_TRUNC, 0);
	return 0;
}

struct te_legacy_rename_pend {
	__u64 old_hash;
	__u64 new_hash;
	__u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct te_legacy_rename_pend);
} ts_legacy_renamepend SEC(".maps");

static __always_inline int te_legacy_rename_enter(const void *old_path,
						   const void *new_path,
						   __u32 flags)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct file_scratch *scratch = file_scratch_buf();
	struct te_legacy_rename_pend pend = { .flags = flags };

	bpf_map_delete_elem(&ts_legacy_renamepend, &tid);
	te_legacy_file_pending_reset(tid);
	te_legacy_open_path(old_path, O_WRONLY, 1);
	if (scratch && scratch->path[0])
		pend.old_hash = te_fnv1a(scratch->path);
	te_legacy_open_path(new_path, O_WRONLY, 1);
	if (scratch && scratch->path[0])
		pend.new_hash = te_fnv1a(scratch->path);
	if (pend.old_hash && pend.new_hash)
		bpf_map_update_elem(&ts_legacy_renamepend, &tid, &pend, BPF_ANY);
	return 0;
}

static __noinline void te_legacy_apply_rename_pending(void)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct te_legacy_rename_pend *pend =
		bpf_map_lookup_elem(&ts_legacy_renamepend, &tid);
	struct file_domain_id old_key = {};
	struct file_domain_id new_key = {};
	struct file_id tmp = {};
	pid_t pid = tid >> 32;

	if (!pend)
		return;
	if (pend->old_hash == pend->new_hash)
		goto out;
	old_key.fid.ino = pend->old_hash;
	new_key.fid.ino = pend->new_hash;
	if (pend->flags & RENAME_EXCHANGE) {
		tmp.ino = bpf_ktime_get_ns() ^ old_key.fid.ino ^
			(new_key.fid.ino << 1);
		tmp.ino |= 1ULL << 63;
		tmp.dev = 0xffffffffU;
		te_copy_file_state_domain(pid, &new_key.fid, &tmp, 0, 1);
		te_copy_file_state_domain(pid, &old_key.fid, &new_key.fid, 0, 1);
		te_copy_file_state_domain(pid, &tmp, &old_key.fid, 0, 1);
	} else {
		te_copy_file_state_domain(pid, &old_key.fid, &new_key.fid, 0, 1);
	}
out:
	bpf_map_delete_elem(&ts_legacy_renamepend, &tid);
}

SEC("tp/syscalls/sys_enter_truncate")
int legacy_trace_truncate(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_open_path((const void *)ctx->args[0], O_WRONLY, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlink")
int legacy_trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_open_path((const void *)ctx->args[0], O_WRONLY, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int legacy_trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_open_path((const void *)ctx->args[1], O_WRONLY, 0);
	return 0;
}

#define TE_LEGACY_FILE_EXIT(name, event, success) \
	SEC("tp/syscalls/" event) \
	int name(struct trace_event_raw_sys_exit *ctx) \
	{ \
		return te_legacy_finish_file(ctx, (success)); \
	}

TE_LEGACY_FILE_EXIT(legacy_trace_openat_exit, "sys_exit_openat", ctx->ret >= 0)
TE_LEGACY_FILE_EXIT(legacy_trace_open_exit, "sys_exit_open", ctx->ret >= 0)
TE_LEGACY_FILE_EXIT(legacy_trace_openat2_exit, "sys_exit_openat2", ctx->ret >= 0)
TE_LEGACY_FILE_EXIT(legacy_trace_creat_exit, "sys_exit_creat", ctx->ret >= 0)
TE_LEGACY_FILE_EXIT(legacy_trace_truncate_exit, "sys_exit_truncate", ctx->ret == 0)
TE_LEGACY_FILE_EXIT(legacy_trace_unlink_exit, "sys_exit_unlink", ctx->ret == 0)
TE_LEGACY_FILE_EXIT(legacy_trace_unlinkat_exit, "sys_exit_unlinkat", ctx->ret == 0)

#undef TE_LEGACY_FILE_EXIT

SEC("tp/syscalls/sys_enter_rename")
int legacy_trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_rename_enter((const void *)ctx->args[0],
			       (const void *)ctx->args[1], 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_rename")
int legacy_trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	int rc = te_legacy_finish_file(ctx, ctx->ret == 0);

	bpf_map_delete_elem(&ts_legacy_renamepend, &tid);
	return rc;
}

SEC("tp/syscalls/sys_enter_renameat")
int legacy_trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_rename_enter((const void *)ctx->args[1],
			       (const void *)ctx->args[3], 0);
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat")
int legacy_trace_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	int rc = te_legacy_finish_file(ctx, ctx->ret == 0);

	bpf_map_delete_elem(&ts_legacy_renamepend, &tid);
	return rc;
}

SEC("tp/syscalls/sys_enter_renameat2")
int legacy_trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	te_legacy_rename_enter((const void *)ctx->args[1],
			       (const void *)ctx->args[3],
			       (__u32)ctx->args[4]);
	return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int legacy_trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	int rc = te_legacy_finish_file(ctx, ctx->ret == 0);

	bpf_map_delete_elem(&ts_legacy_renamepend, &tid);
	return rc;
}

struct te_legacy_connect_ctx {
	pid_t pid;
	__u32 ip;
	__u32 op;
	__u64 labels;
	__u64 source_labels;
	__u32 effect_mask;
	__u32 best_effect;
	int best_rule;
	__u64 best_labels;
};

static int te_legacy_connect_update_cb(__u32 i, void *vc)
{
	struct te_legacy_connect_ctx *c = vc;
	struct taint_update *up;

	if (i >= MAX_TAINT_UPDATES)
		return 1;
	up = bpf_map_lookup_elem(&ts_updates, &i);
	if (!up)
		return 1;
	if (up->domain_id == 0 && up->op == c->op &&
	    (c->ip & up->ipv4_mask) == up->ipv4) {
		c->labels |= up->add;
		c->source_labels |= up->add;
	}
	return 0;
}

static int te_legacy_connect_rule_cb(__u32 i, void *vc)
{
	struct te_legacy_connect_ctx *c = vc;
	struct taint_rule *rp;
	struct proc_state *proc;
	int cond_match;

	if (i >= MAX_TAINT_RULES)
		return 1;
	rp = bpf_map_lookup_elem(&ts_rules, &i);
	if (!rp)
		return 1;
	if (rp->domain_id != 0 || rp->op != c->op)
		return 0;
	if (!taint_mask_ok(c->labels, rp->req, rp->forbid))
		return 0;
	if (rp->effect > TEFFECT_KILL ||
	    !(c->effect_mask & (1U << rp->effect)))
		return 0;
	if ((c->ip & rp->ipv4_mask) != rp->ipv4)
		return 0;
	if (rp->cond_kind == TCOND_LINEAGE) {
		proc = te_get(c->pid);
		if (proc && (proc->lin_gates & rp->gate))
			return 0;
	} else if (rp->cond_kind == TCOND_AFTER) {
		if (te_after_satisfied(rp, c->pid))
			return 0;
	} else if (rp->cond_kind == TCOND_TARGET) {
		cond_match = (c->ip & rp->cond_ipv4_mask) == rp->cond_ipv4;
		if (rp->cond_neg ? !cond_match : cond_match)
			return 0;
	}
	if (c->best_rule < 0 || rp->effect > c->best_effect) {
		c->best_effect = rp->effect;
		c->best_rule = (int)rp->rule_id;
		c->best_labels = c->labels & rp->req;
		if (rp->effect == TEFFECT_KILL)
			return 1;
	}
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int legacy_trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct proc_state *proc;
	struct te_legacy_connect_ctx event = {
		.pid = pid,
		.op = TOP_CONNECT,
		.effect_mask = (1U << TEFFECT_NOTIFY) | (1U << TEFFECT_KILL),
		.best_effect = TEFFECT_NOTIFY,
		.best_rule = -1,
	};
	struct endp_domain_id key = {};
	struct connect_pend pending;
	__u64 *stored;
	__u64 endpoint_labels;

	if (!te_pid_active(pid) ||
	    te_resolve_sockaddr(TE_REF_SOCKADDR_USER,
				(const void *)ctx->args[1], &event.ip) < 0)
		return 0;
	pending.fd = (int)ctx->args[0];
	pending.ip = event.ip;
	bpf_map_update_elem(&ts_connectpend, &tid, &pending, BPF_ANY);
	proc = te_get(pid);
	if (!proc)
		return 0;
	event.labels = proc->labels;
	bpf_loop(te_count(1), te_legacy_connect_update_cb, &event, 0);
	if (event.source_labels)
		te_record_proc_prov_mask(pid, 0, event.source_labels,
					 TOP_CONNECT, 0, event.ip);
	bpf_loop(te_count(0), te_legacy_connect_rule_cb, &event, 0);
	if (event.best_rule >= 0) {
		emit_violation(pid, event.best_rule, 0, event.ip,
			       TE_OBJ_ENDPOINT, 0, 0, event.best_labels,
			       event.op, 0,
			       event.best_effect == TEFFECT_KILL,
			       event.best_effect);
		if (event.best_effect == TEFFECT_KILL)
			bpf_send_signal(SIGKILL);
	}
	proc->labels = event.labels;
	te_endp_domain_key_for(0, event.ip, &key);
	stored = bpf_map_lookup_elem(&ts_endp, &key);
	endpoint_labels = event.labels | (stored ? *stored : 0);
	if (event.source_labels)
		te_legacy_record_endp_prov(pid, &key, event.source_labels,
					   TOP_CONNECT, event.ip);
	te_legacy_proc_prov_to_endp(pid, &key, event.labels);
	if (endpoint_labels)
		bpf_map_update_elem(&ts_endp, &key, &endpoint_labels, BPF_ANY);
	return 0;
}

static __always_inline int handle_connect_exit(long ret);

SEC("tp/syscalls/sys_exit_connect")
int legacy_trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_connect_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_close")
int legacy_trace_close(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (te_pid_active(pid))
		te_delete_fd(pid, (int)ctx->args[0]);
	return 0;
}

struct te_legacy_recv_pend {
	int fd;
	__u32 kind;
	__u64 addr_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct te_legacy_recv_pend);
} ts_legacy_recvpend SEC(".maps");

#define TE_LEGACY_RECV_SOCKADDR 1
#define TE_LEGACY_RECV_MSGHDR   2
#define TE_LEGACY_RECV_FD       3

static __always_inline int te_legacy_stash_recv(int fd, const void *addr,
						 __u32 kind)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct te_legacy_recv_pend pend = {
		.fd = fd,
		.kind = kind,
		.addr_ptr = (__u64)addr,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_legacy_recvpend, &tid, &pend, BPF_ANY);
	return 0;
}

static __always_inline int te_legacy_recv_ip(
	const struct te_legacy_recv_pend *pend, __u32 *ip)
{
	struct file *file;
	struct inode *inode;
	struct socket *sock;
	umode_t mode;

	if (pend->kind == TE_LEGACY_RECV_SOCKADDR && pend->addr_ptr)
		return te_resolve_sockaddr(TE_REF_SOCKADDR_USER,
					   (const void *)pend->addr_ptr, ip);
	if (pend->kind == TE_LEGACY_RECV_MSGHDR && pend->addr_ptr) {
		__u64 name_ptr = 0;
		if (bpf_probe_read_user(&name_ptr, sizeof(name_ptr),
					(const void *)pend->addr_ptr) == 0 &&
		    name_ptr)
			return te_resolve_sockaddr(TE_REF_SOCKADDR_USER,
						   (const void *)name_ptr, ip);
	}
	file = te_current_file_from_fd(pend->fd);
	if (!file)
		return -1;
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return -1;
	mode = BPF_CORE_READ(inode, i_mode);
	if ((mode & TE_S_IFMT) != TE_S_IFSOCK)
		return -1;
	sock = BPF_CORE_READ(file, private_data);
	if (!sock)
		return -1;
	return te_resolve_socket_peer_ipv4(sock, ip);
}

static __always_inline int te_legacy_handle_recv(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct te_legacy_recv_pend *pend =
		bpf_map_lookup_elem(&ts_legacy_recvpend, &tid);
	struct proc_state *proc;
	struct te_legacy_connect_ctx event = {
		.pid = pid,
		.op = TOP_RECV,
		.effect_mask = (1U << TEFFECT_NOTIFY) | (1U << TEFFECT_KILL),
		.best_effect = TEFFECT_NOTIFY,
		.best_rule = -1,
	};
	struct endp_domain_id key = {};
	__u64 *stored;

	if (!pend)
		return 0;
	if (ret <= 0 || !te_pid_active(pid) ||
	    te_legacy_recv_ip(pend, &event.ip) < 0)
		goto out;
	proc = te_get(pid);
	if (!proc)
		goto out;
	te_endp_domain_key_for(0, event.ip, &key);
	stored = bpf_map_lookup_elem(&ts_endp, &key);
	event.labels = proc->labels | (stored ? *stored : 0);
	if (stored)
		te_legacy_endp_prov_to_proc(pid, &key, *stored);
	bpf_loop(te_count(1), te_legacy_connect_update_cb, &event, 0);
	if (event.source_labels)
		te_record_proc_prov_mask(pid, 0, event.source_labels,
					 TOP_RECV, 0, event.ip);
	bpf_loop(te_count(0), te_legacy_connect_rule_cb, &event, 0);
	if (event.best_rule >= 0) {
		emit_violation(pid, event.best_rule, 0, event.ip,
			       TE_OBJ_ENDPOINT, 0, 0, event.best_labels,
			       event.op, 0,
			       event.best_effect == TEFFECT_KILL,
			       event.best_effect);
		if (event.best_effect == TEFFECT_KILL)
			bpf_send_signal(SIGKILL);
	}
	proc->labels = event.labels;
out:
	bpf_map_delete_elem(&ts_legacy_recvpend, &tid);
	return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int legacy_trace_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	return te_legacy_stash_recv((int)ctx->args[0],
				    (const void *)ctx->args[4],
				    TE_LEGACY_RECV_SOCKADDR);
}

SEC("tp/syscalls/sys_exit_recvfrom")
int legacy_trace_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
	return te_legacy_handle_recv(ctx->ret);
}

SEC("tp/syscalls/sys_enter_recvmsg")
int legacy_trace_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
	return te_legacy_stash_recv((int)ctx->args[0],
				    (const void *)ctx->args[1],
				    TE_LEGACY_RECV_MSGHDR);
}

SEC("tp/syscalls/sys_exit_recvmsg")
int legacy_trace_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
	return te_legacy_handle_recv(ctx->ret);
}

SEC("tp/syscalls/sys_enter_read")
int legacy_trace_read(struct trace_event_raw_sys_enter *ctx)
{
	return te_legacy_stash_recv((int)ctx->args[0], 0,
				    TE_LEGACY_RECV_FD);
}

SEC("tp/syscalls/sys_exit_read")
int legacy_trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	return te_legacy_handle_recv(ctx->ret);
}

struct te_legacy_exec_block_ctx {
	pid_t pid;
	const char *target;
	__u64 labels;
	int rule;
	__u64 matched_labels;
};

static int te_legacy_exec_block_update_cb(__u32 i, void *vc)
{
	struct te_legacy_exec_block_ctx *c = vc;
	struct taint_update *up;

	if (i >= MAX_TAINT_UPDATES)
		return 1;
	up = bpf_map_lookup_elem(&ts_updates, &i);
	if (!up)
		return 1;
	if (up->domain_id != 0 || up->op != TOP_EXEC || up->arg[0] != '\0' ||
	    !taint_exec_match(up->match, c->target, up->target))
		return 0;
	c->labels = (c->labels | up->add) & ~up->del;
	return 0;
}

static int te_legacy_exec_block_rule_cb(__u32 i, void *vc)
{
	struct te_legacy_exec_block_ctx *c = vc;
	struct taint_rule *rp;
	struct proc_state *proc;
	int cond_match;

	if (i >= MAX_TAINT_RULES)
		return 1;
	rp = bpf_map_lookup_elem(&ts_rules, &i);
	if (!rp)
		return 1;
	if (rp->domain_id != 0 || rp->op != TOP_EXEC ||
	    rp->effect != TEFFECT_BLOCK || rp->arg[0] != '\0')
		return 0;
	if (!taint_mask_ok(c->labels, rp->req, rp->forbid) ||
	    !taint_exec_match(rp->match, c->target, rp->target))
		return 0;
	if (rp->cond_kind == TCOND_LINEAGE) {
		proc = te_get(c->pid);
		if (proc && (proc->lin_gates & rp->gate))
			return 0;
	} else if (rp->cond_kind == TCOND_AFTER) {
		if (te_after_satisfied(rp, c->pid))
			return 0;
	} else if (rp->cond_kind == TCOND_TARGET) {
		cond_match = taint_exec_match(rp->cond_match, c->target,
					      rp->cond_pat);
		if (rp->cond_neg ? !cond_match : cond_match)
			return 0;
	}
	c->rule = (int)rp->rule_id;
	c->matched_labels = c->labels & rp->req;
	return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(legacy_enforce_bprm_check_security, struct linux_binprm *bprm)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct exec_scratch *scratch = exec_scratch_buf();
	struct te_legacy_exec_block_ctx event = {
		.pid = pid,
		.rule = -1,
	};
	struct proc_state *proc;

	if (!scratch || !te_pid_active(pid))
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));
	if (bprm_basename(bprm, scratch->match, sizeof(scratch->match)) < 0)
		return 0;
	if (bprm_filename(bprm, scratch->display, sizeof(scratch->display)) < 0)
		te_copy_target(scratch->display, scratch->match);
	proc = te_get(pid);
	if (!proc)
		return 0;
	event.target = scratch->match;
	event.labels = proc->labels;
	bpf_loop(te_count(1), te_legacy_exec_block_update_cb, &event, 0);
	bpf_loop(te_count(0), te_legacy_exec_block_rule_cb, &event, 0);
	if (event.rule < 0)
		return 0;
	emit_violation(pid, event.rule, scratch->display, 0, TE_OBJ_EXEC, 0,
		       0, event.matched_labels, TOP_EXEC, 1, 0, TEFFECT_BLOCK);
	return -EPERM;
}

static __always_inline int te_legacy_block_endpoint(pid_t pid, __u32 ip,
						      __u32 op)
{
	struct proc_state *proc = te_get(pid);
	struct te_legacy_connect_ctx event = {
		.pid = pid,
		.ip = ip,
		.op = op,
		.effect_mask = 1U << TEFFECT_BLOCK,
		.best_effect = TEFFECT_NOTIFY,
		.best_rule = -1,
	};
	struct endp_domain_id key = {};
	__u64 *stored;

	if (!proc)
		return 0;
	event.labels = proc->labels;
	if (op == TOP_RECV) {
		te_endp_domain_key_for(0, ip, &key);
		stored = bpf_map_lookup_elem(&ts_endp, &key);
		if (stored)
			event.labels |= *stored;
	}
	bpf_loop(te_count(1), te_legacy_connect_update_cb, &event, 0);
	bpf_loop(te_count(0), te_legacy_connect_rule_cb, &event, 0);
	if (event.best_rule < 0)
		return 0;
	emit_violation(pid, event.best_rule, 0, ip, TE_OBJ_ENDPOINT, 0, 0,
		       event.best_labels, op, 1, 0, TEFFECT_BLOCK);
	return -EPERM;
}

SEC("lsm/socket_connect")
int BPF_PROG(legacy_enforce_socket_connect, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u32 ip = 0;

	(void)sock;
	(void)addrlen;
	if (!te_pid_active(pid) ||
	    te_resolve_sockaddr(TE_REF_SOCKADDR_KERN, address, &ip) < 0)
		return 0;
	return te_legacy_block_endpoint(pid, ip, TOP_CONNECT);
}

SEC("lsm/socket_recvmsg")
int BPF_PROG(legacy_enforce_socket_recvmsg, struct socket *sock,
	     struct msghdr *msg, int size, int flags)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u32 ip = 0;

	(void)msg;
	(void)size;
	(void)flags;
	if (!te_pid_active(pid) || te_resolve_socket_peer_ipv4(sock, &ip) < 0)
		return 0;
	return te_legacy_block_endpoint(pid, ip, TOP_RECV);
}
#endif

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	pid_t pid = id >> 32;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int exit_code = BPF_CORE_READ(task, exit_code);

	(void)ctx;
	if (pid != (u32)id)
		return 0;
	te_exit(pid, exit_code);
	te_delete_mmaps(pid);
	bpf_map_delete_elem(&te_protected_pids, &pid);
	return 0;
}

/* Stash the path pointer + flags; the actual handling happens at sys_exit, once
 * the path page is resident (see ts_openpend). Tracking opens at exit also means
 * we only act on opens that actually entered the kernel, which is fine for the
 * notify/kill model (kill still terminates the offending process). */
static __always_inline int stash_open(const void *path_ptr, unsigned int flags,
				      __u32 remember_fd)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct open_pend p = {
		.path_ptr = (__u64)path_ptr,
		.flags = flags,
		.remember_fd = remember_fd,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_openpend, &tid, &p, BPF_ANY);
	return 0;
}

static __noinline int handle_open_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct open_pend *p = bpf_map_lookup_elem(&ts_openpend, &tid);
	struct file_scratch *scratch = file_scratch_buf();
	__u64 path_ptr;
	__u32 flags;
	__u32 remember_fd;
	__u32 access;
	int rc = 0;

	if (!p)
		return 0;
	path_ptr = p->path_ptr;
	flags = p->flags;
	remember_fd = p->remember_fd;
	bpf_map_delete_elem(&ts_openpend, &tid);
	/* On success the kernel has copied the path in, so the user page is now
	 * resident and the read in te_handle_file is reliable. */
	if (ret >= 0 && scratch && te_pid_active(pid)) {
		struct file *opened_file = NULL;
		struct file_id path_fid = {};

		__builtin_memset(scratch, 0, sizeof(*scratch));
		if (te_resolve_file_ref(TE_REF_USER_PATH, (const void *)path_ptr,
					0, scratch->path, sizeof(scratch->path)) != 0)
			return 0;
		te_resolve_file_id(TE_REF_USER_PATH, (const void *)path_ptr, 0,
				   scratch->path, &scratch->fid);
		access = te_access_from_open_flags(flags);
		path_fid = scratch->fid;
		if (remember_fd) {
			opened_file = te_current_file_from_fd((int)ret);
			/* Promote labels captured by path-only tracepoints, such as
			 * rename, onto the inode id used after a successful open. */
			if (opened_file &&
			    te_resolve_file_id_from_file(opened_file,
							 &scratch->fid) == 0 &&
			    (policy_features & TE_POLICY_FILE_FLOW) &&
			    !te_file_id_equal(&path_fid, &scratch->fid))
				te_copy_file_state(pid, &path_fid, &scratch->fid, 0);
		}
		if (policy_features & TE_POLICY_FILE_FLOW)
			te_materialize_file_source(pid, &scratch->fid, scratch->path);
		if (remember_fd)
			te_store_fd_with_current_file(pid, (int)ret, scratch->path,
						      &scratch->fid);
		/* Keep pure object-label propagation out of the full rule matcher so
		 * trace_openat_exit stays verifier-small for common file-flow policies. */
		if (!((access & TE_ACCESS_READ) &&
		      (policy_features & TE_POLICY_OPEN_RULES)) &&
		    !((access & TE_ACCESS_WRITE) &&
		      (policy_features & TE_POLICY_WRITE_RULES))) {
			if (policy_features & TE_POLICY_FILE_FLOW) {
				if (access & TE_ACCESS_READ)
					te_read(pid, &scratch->fid, scratch->path);
				if (access & TE_ACCESS_WRITE)
					te_write_flow(pid, &scratch->fid,
						      scratch->path);
			}
			return 0;
		}
		rc = te_handle_file_event(pid, scratch->path, &scratch->fid,
					  access, te_tracepoint_mode());
	}
	return rc;
}

static __always_inline int stash_pipe(const void *fds_ptr)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct pipe_pend p = { .fds_ptr = (__u64)fds_ptr };

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_pipepend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_pipe_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct pipe_pend *p = bpf_map_lookup_elem(&ts_pipepend, &tid);
	struct file_scratch *scratch = file_scratch_buf();
	int fds[2] = {};

	if (!p)
		return 0;
	if (ret == 0 && scratch && te_pid_active(pid) &&
	    bpf_probe_read_user(&fds, sizeof(fds), (void *)p->fds_ptr) == 0) {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		__builtin_memcpy(scratch->path, "pipe", sizeof("pipe"));
		scratch->fid.ino = bpf_ktime_get_ns() ^ ((__u64)pid << 32) ^
				   ((__u64)(__u32)fds[0] << 16) ^
				   (__u64)(__u32)fds[1];
		if (!scratch->fid.ino)
			scratch->fid.ino = 1;
		te_store_fd_with_current_file(pid, fds[0], scratch->path,
					      &scratch->fid);
		te_store_fd_with_current_file(pid, fds[1], scratch->path,
					      &scratch->fid);
	}
	bpf_map_delete_elem(&ts_pipepend, &tid);
	return 0;
}

static __always_inline int stash_socketpair(const void *fds_ptr, int family)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct socketpair_pend p = { .fds_ptr = (__u64)fds_ptr };

	if (family != AF_UNIX)
		return 0;
	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_socketpairpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_socketpair_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct socketpair_pend *p = bpf_map_lookup_elem(&ts_socketpairpend, &tid);
	struct file_scratch *scratch = file_scratch_buf();
	int fds[2] = {};

	if (!p)
		return 0;
	if (ret == 0 && scratch && te_pid_active(pid) &&
	    bpf_probe_read_user(&fds, sizeof(fds), (void *)p->fds_ptr) == 0) {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		__builtin_memcpy(scratch->path, "socketpair", sizeof("socketpair"));
		scratch->fid.ino = bpf_ktime_get_ns() ^ ((__u64)pid << 32) ^
				   ((__u64)(__u32)fds[0] << 16) ^
				   (__u64)(__u32)fds[1];
		if (!scratch->fid.ino)
			scratch->fid.ino = 1;
		te_store_fd_with_current_file(pid, fds[0], scratch->path,
					      &scratch->fid);
		te_store_fd_with_current_file(pid, fds[1], scratch->path,
					      &scratch->fid);
	}
	bpf_map_delete_elem(&ts_socketpairpend, &tid);
	return 0;
}

static __noinline int stash_unixsock(int fd, const void *sockaddr, int addrlen)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct unixsock_pend p = { .fd = fd };

	if (!te_pid_active(pid))
		return 0;
	if (te_resolve_unix_sockaddr_path(sockaddr, addrlen, p.path, &p.fid) < 0)
		return 0;
	bpf_map_update_elem(&ts_unixsockpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_unixsock_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct unixsock_pend *p = bpf_map_lookup_elem(&ts_unixsockpend, &tid);

	if (!p)
		return 0;
	if (ret == 0 && te_pid_active(pid))
		te_store_fd_with_current_file(pid, p->fd, p->path, &p->fid);
	bpf_map_delete_elem(&ts_unixsockpend, &tid);
	return 0;
}

static __always_inline int stash_accept(int fd)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct accept_pend p = { .fd = fd };

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_acceptpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_accept_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct accept_pend *p = bpf_map_lookup_elem(&ts_acceptpend, &tid);

	if (p && ret >= 0 && te_pid_active(pid)) {
		te_copy_fd(pid, p->fd, (int)ret);
		te_copy_sockfd(pid, p->fd, (int)ret);
	}
	bpf_map_delete_elem(&ts_acceptpend, &tid);
	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	return stash_open((const void *)ctx->args[1], (unsigned int)ctx->args[2], 1);
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	return stash_open((const void *)ctx->args[0], (unsigned int)ctx->args[1], 1);
}

SEC("tp/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}

/* openat2(dfd, path, struct open_how *, size): flags live in open_how, not a
 * scalar arg. Without this hook a write/read via openat2 bypasses detection. */
SEC("tp/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct open_how how = {};
	bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]);
	return stash_open((const void *)ctx->args[1], (unsigned int)how.flags, 1);
}
SEC("tp/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}

/* creat(path, mode) == open(path, O_WRONLY|O_CREAT|O_TRUNC): a file write. */
SEC("tp/syscalls/sys_enter_creat")
int trace_creat(struct trace_event_raw_sys_enter *ctx)
{
	return stash_open((const void *)ctx->args[0], O_WRONLY | O_CREAT | O_TRUNC, 1);
}
SEC("tp/syscalls/sys_exit_creat")
int trace_creat_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}

/* truncate(path, len): a file write (size change). */
SEC("tp/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx)
{
	return stash_open((const void *)ctx->args[0], O_WRONLY, 0);
}
SEC("tp/syscalls/sys_exit_truncate")
int trace_truncate_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_open_exit(ctx->ret);
}
/* renameat2 is already hooked below (sys_enter_renameat2 -> write on new path). */

SEC("tp/syscalls/sys_enter_pipe")
int trace_pipe(struct trace_event_raw_sys_enter *ctx)
{
	return stash_pipe((const void *)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_pipe")
int trace_pipe_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_pipe_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_pipe2")
int trace_pipe2(struct trace_event_raw_sys_enter *ctx)
{
	return stash_pipe((const void *)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_pipe2")
int trace_pipe2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_pipe_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_socketpair")
int trace_socketpair(struct trace_event_raw_sys_enter *ctx)
{
	return stash_socketpair((const void *)ctx->args[3], (int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_socketpair")
int trace_socketpair_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_socketpair_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
	return stash_unixsock((int)ctx->args[0], (const void *)ctx->args[1],
			      (int)ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_bind")
int trace_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_unixsock_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_accept")
int trace_accept(struct trace_event_raw_sys_enter *ctx)
{
	return stash_accept((int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_accept")
int trace_accept_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_accept_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_accept4")
int trace_accept4(struct trace_event_raw_sys_enter *ctx)
{
	return stash_accept((int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_accept4")
int trace_accept4_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_accept_exit(ctx->ret);
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
	return te_stash_rename_user_paths((const void *)ctx->args[0],
					  (const void *)ctx->args[1],
					  0,
					  te_tracepoint_mode());
}
SEC("tp/syscalls/sys_exit_rename")
int trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
{
	return te_handle_rename_exit(ctx->ret, te_tracepoint_mode());
}
SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	return te_stash_rename_user_paths((const void *)ctx->args[1],
					  (const void *)ctx->args[3],
					  0,
					  te_tracepoint_mode());
}
SEC("tp/syscalls/sys_exit_renameat")
int trace_renameat_exit(struct trace_event_raw_sys_exit *ctx)
{
	return te_handle_rename_exit(ctx->ret, te_tracepoint_mode());
}
SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	return te_stash_rename_user_paths((const void *)ctx->args[1],
					  (const void *)ctx->args[3],
					  (__u32)ctx->args[4],
					  te_tracepoint_mode());
}
SEC("tp/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return te_handle_rename_exit(ctx->ret, te_tracepoint_mode());
}

/* connect: numeric IPv4 matching (compiler lowers host/IP patterns to net+mask;
 * no in-kernel string formatting, so no verifier-rejected pointer arithmetic).
 * The reported IP is formatted by the userspace loader from conn_ip. */
static __always_inline int stash_connect(int fd, const void *sockaddr)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct connect_pend p = { .fd = fd };

	if (!te_pid_active(pid))
		return 0;
	if (te_resolve_sockaddr(TE_REF_SOCKADDR_USER, sockaddr, &p.ip) < 0)
		return 0;
	bpf_map_update_elem(&ts_connectpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_connect_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct connect_pend *p = bpf_map_lookup_elem(&ts_connectpend, &tid);

	if (p && ret == 0 && te_pid_active(pid))
		te_store_sockfd(pid, p->fd, p->ip);
	bpf_map_delete_elem(&ts_connectpend, &tid);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	stash_connect((int)ctx->args[0], (const void *)ctx->args[1]);
	stash_unixsock((int)ctx->args[0], (const void *)ctx->args[1],
		       (int)ctx->args[2]);
	return te_handle_net(TE_REF_SOCKADDR_USER, (const void *)ctx->args[1], 0,
			     TE_ACCESS_CONNECT, te_tracepoint_mode());
}

SEC("tp/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
	handle_connect_exit(ctx->ret);
	return handle_unixsock_exit(ctx->ret);
}

static __always_inline int stash_io(int fd, __u32 access, const void *addr_ptr,
				    __u32 addr_kind, int addr_len)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct io_pend p = {
		.fd = fd,
		.access = access,
		.addr_ptr = (__u64)addr_ptr,
		.addr_kind = addr_kind,
		.addr_len = addr_len,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_iopend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int te_resolve_io_sockaddr(__u32 addr_kind, __u64 addr_ptr,
						  __u32 *ip)
{
	if (!addr_ptr)
		return -1;
	if (addr_kind == TE_IO_ADDR_USER_MSGHDR) {
		__u64 name_ptr = 0;

		if (bpf_probe_read_user(&name_ptr, sizeof(name_ptr),
					(const void *)addr_ptr) < 0)
			return -1;
		addr_ptr = name_ptr;
	}
	if (addr_kind != TE_IO_ADDR_SOCKADDR &&
	    addr_kind != TE_IO_ADDR_USER_MSGHDR)
		return -1;
	if (!addr_ptr)
		return -1;
	return te_resolve_sockaddr(TE_REF_SOCKADDR_USER, (const void *)addr_ptr,
				   ip);
}

static __always_inline int te_resolve_io_unix_sockaddr(__u32 addr_kind,
						       __u64 addr_ptr,
						       int addr_len,
						       char *path,
						       struct file_id *fid)
{
	if (!addr_ptr)
		return -1;
	if (addr_kind == TE_IO_ADDR_USER_MSGHDR) {
		__u64 name_ptr = 0;
		int name_len = 0;

		if (bpf_probe_read_user(&name_ptr, sizeof(name_ptr),
					(const void *)addr_ptr) < 0)
			return -1;
		if (bpf_probe_read_user(&name_len, sizeof(name_len),
					((const char *)addr_ptr) + 8) < 0)
			return -1;
		addr_ptr = name_ptr;
		addr_len = name_len;
	}
	if (addr_kind != TE_IO_ADDR_SOCKADDR &&
	    addr_kind != TE_IO_ADDR_USER_MSGHDR)
		return -1;
	if (!addr_ptr)
		return -1;
	return te_resolve_unix_sockaddr_path((const void *)addr_ptr, addr_len,
					     path, fid);
}

static __always_inline __u64 te_cmsg_align(__u64 len)
{
	return (len + TE_CMSG_ALIGN_MASK) & ~TE_CMSG_ALIGN_MASK;
}

static __noinline __u64 te_handle_scm_rights_cmsg(pid_t pid, __u64 control_ptr,
						  __u64 controllen, __u64 off)
{
	__u64 cmsg_len = 0;
	int level = 0;
	int type = 0;
	__u64 data_len;
	__u64 base;
	__u64 next;

	if (off + TE_CMSG_HDR_LEN > controllen)
		return 0;
	base = control_ptr + off;
	if (bpf_probe_read_user(&cmsg_len, sizeof(cmsg_len),
				(const void *)base) < 0)
		return 0;
	if (bpf_probe_read_user(&level, sizeof(level),
				(const void *)(base + 8)) < 0)
		return 0;
	if (bpf_probe_read_user(&type, sizeof(type),
				(const void *)(base + 12)) < 0)
		return 0;
	if (cmsg_len < TE_CMSG_HDR_LEN || cmsg_len > controllen - off)
		return 0;
	if (level == SOL_SOCKET && type == SCM_RIGHTS) {
		data_len = cmsg_len - TE_CMSG_HDR_LEN;
		for (int i = 0; i < TE_SCM_RIGHTS_MAX_FDS; i++) {
			int received_fd = -1;
			__u64 data_off = TE_CMSG_HDR_LEN + ((__u64)i * sizeof(int));

			if (data_off + sizeof(int) > data_len + TE_CMSG_HDR_LEN)
				break;
			if (bpf_probe_read_user(&received_fd, sizeof(received_fd),
						(const void *)(base + data_off)) < 0)
				break;
			te_store_current_fd_file(pid, received_fd);
		}
	}
	next = off + te_cmsg_align(cmsg_len);
	if (next <= off || next > controllen)
		return 0;
	return next;
}

static __noinline void te_handle_scm_rights(pid_t pid, __u64 msg_ptr)
{
	__u64 control_ptr = 0;
	__u64 controllen = 0;
	__u64 off = 0;

	if (!msg_ptr)
		return;
	if (bpf_probe_read_user(&control_ptr, sizeof(control_ptr),
				(const void *)(msg_ptr + TE_USER_MSGHDR_CONTROL_OFF)) < 0)
		return;
	if (bpf_probe_read_user(&controllen, sizeof(controllen),
				(const void *)(msg_ptr + TE_USER_MSGHDR_CONTROLLEN_OFF)) < 0)
		return;
	if (!control_ptr || controllen < TE_CMSG_HDR_LEN + sizeof(int))
		return;
	if (controllen > TE_CMSG_CONTROL_MAX)
		controllen = TE_CMSG_CONTROL_MAX;
	for (int i = 0; i < TE_CMSG_SCAN_MAX; i++) {
		off = te_handle_scm_rights_cmsg(pid, control_ptr, controllen, off);
		if (!off)
			break;
	}
}

static __always_inline int handle_io_exit_read(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct io_pend *p = bpf_map_lookup_elem(&ts_iopend, &tid);

	if (!p)
		return 0;
	if (enforce_mode) {
		bpf_map_delete_elem(&ts_iopend, &tid);
		return 0;
	}
	if (ret > 0 && te_pid_active(pid)) {
		int fd = p->fd;
		struct fd_ref *ref = te_lookup_fd(pid, fd);
		__u32 *peer_ip = 0;

		if (ref && (policy_features & TE_POLICY_FILE_FLOW))
			te_read(pid, &ref->fid, ref->path);
		if (policy_features & TE_POLICY_RECV)
			peer_ip = te_lookup_sockfd(pid, fd);
		if (peer_ip) {
			te_handle_net_ip(*peer_ip, TE_ACCESS_RECV,
					 te_tracepoint_mode());
		}
	}
	bpf_map_delete_elem(&ts_iopend, &tid);
	return 0;
}

static __always_inline int handle_io_exit_write(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct io_pend *p = bpf_map_lookup_elem(&ts_iopend, &tid);

	if (!p)
		return 0;
	if (enforce_mode) {
		bpf_map_delete_elem(&ts_iopend, &tid);
		return 0;
	}
	if (ret > 0 && te_pid_active(pid)) {
		int fd = p->fd;
		struct fd_ref *ref = te_lookup_fd(pid, fd);
		__u32 *peer_ip = 0;

		if (ref && (policy_features & TE_POLICY_FILE_FLOW))
			te_write_flow(pid, &ref->fid, ref->path);
		if (policy_features & TE_POLICY_FILE_FLOW)
			peer_ip = te_lookup_sockfd(pid, fd);
		if (peer_ip)
			te_connect_flow(*peer_ip, pid);
	}
	bpf_map_delete_elem(&ts_iopend, &tid);
	return 0;
}

static __always_inline int handle_io_exit_addr(long ret, __u32 access)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct io_pend *p = bpf_map_lookup_elem(&ts_iopend, &tid);

	if (!p)
		return 0;
	if (enforce_mode) {
		bpf_map_delete_elem(&ts_iopend, &tid);
		return 0;
	}
	if (ret > 0 && te_pid_active(pid)) {
		int fd = p->fd;
		__u64 addr_ptr = p->addr_ptr;
		__u32 addr_kind = p->addr_kind;
		int addr_len = p->addr_len;
		struct fd_ref *ref = te_lookup_fd(pid, fd);
		__u32 *peer_ip = 0;

		if (ref && (policy_features & TE_POLICY_FILE_FLOW)) {
			if (access & TE_ACCESS_READ)
				te_read(pid, &ref->fid, ref->path);
			if (access & TE_ACCESS_WRITE)
				te_write_flow(pid, &ref->fid, ref->path);
		}
		if ((access & TE_ACCESS_READ) &&
		    (policy_features & TE_POLICY_FILE_FLOW) &&
		    addr_kind == TE_IO_ADDR_USER_MSGHDR)
			te_handle_scm_rights(pid, addr_ptr);
		if (((access & TE_ACCESS_READ) && (policy_features & TE_POLICY_RECV)) ||
		    ((access & TE_ACCESS_WRITE) && (policy_features & TE_POLICY_FILE_FLOW)))
			peer_ip = te_lookup_sockfd(pid, fd);
		if (peer_ip) {
			if (access & TE_ACCESS_READ)
				te_handle_net_ip(*peer_ip, TE_ACCESS_RECV,
						 te_tracepoint_mode());
			if (access & TE_ACCESS_WRITE)
				te_connect_flow(*peer_ip, pid);
		} else if (addr_ptr) {
			__u32 ip = 0;
			struct file_scratch *scratch = file_scratch_buf();

			if (te_resolve_io_sockaddr(addr_kind, addr_ptr, &ip) ==
			    0) {
				if ((access & TE_ACCESS_READ) &&
				    (policy_features & TE_POLICY_RECV))
					te_handle_net_ip(ip, TE_ACCESS_RECV,
							 te_tracepoint_mode());
				if ((access & TE_ACCESS_WRITE) &&
				    (policy_features & TE_POLICY_CONNECT))
					te_handle_net_ip(ip, TE_ACCESS_CONNECT,
							 te_tracepoint_mode());
			} else if (scratch && (access & TE_ACCESS_WRITE) &&
				   (policy_features & TE_POLICY_FILE_FLOW)) {
				__builtin_memset(scratch, 0, sizeof(*scratch));
				if (te_resolve_io_unix_sockaddr(
					    addr_kind, addr_ptr, addr_len,
					    scratch->path, &scratch->fid) == 0)
					te_write_flow(pid, &scratch->fid,
						      scratch->path);
			}
		}
	}
	bpf_map_delete_elem(&ts_iopend, &tid);
	return 0;
}

static __always_inline int handle_mmap_enter(int fd, unsigned long prot,
					     unsigned long flags, __u64 len)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mmap_pend p = {
		.fd = fd,
		.len = len,
		.prot = prot,
		.flags = flags,
	};

	if (fd < 0 || !te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_mmappend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_mmap_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mmap_pend *p = bpf_map_lookup_elem(&ts_mmappend, &tid);

	if (!p)
		return 0;
	if (ret >= 0 && te_pid_active(pid)) {
		int fd = p->fd;
		__u32 access = te_access_from_mmap(p->prot, p->flags);
		struct fd_ref *ref = te_lookup_fd(pid, fd);

		if (!ref) {
			te_store_current_fd_file_path(pid, fd);
			ref = te_lookup_fd(pid, fd);
		}
		if (ref) {
			te_store_mmap_ref(pid, (__u64)ret, p, ref);
			if (!enforce_mode) {
				if (access & TE_ACCESS_READ)
					te_read(pid, &ref->fid, ref->path);
				if (access & TE_ACCESS_WRITE)
					te_write_flow(pid, &ref->fid, ref->path);
			}
		}
	}
	bpf_map_delete_elem(&ts_mmappend, &tid);
	return 0;
}

static __always_inline int handle_mprotect_enter(__u64 start, __u64 len,
						 unsigned long prot)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mprotect_pend p = {
		.start = start,
		.len = len,
		.prot = prot,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_mprotectpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_mprotect_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mprotect_pend *p = bpf_map_lookup_elem(&ts_mprotectpend, &tid);

	if (!p)
		return 0;
	if (ret == 0 && te_pid_active(pid))
		te_handle_mprotect_range(pid, p->start, p->len, p->prot);
	bpf_map_delete_elem(&ts_mprotectpend, &tid);
	return 0;
}

static __always_inline int handle_mremap_enter(__u64 old_addr, __u64 old_size,
					       __u64 new_size)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mremap_pend p = {
		.old_addr = old_addr,
		.old_size = old_size,
		.new_size = new_size,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_mremappend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_mremap_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mremap_pend *p = bpf_map_lookup_elem(&ts_mremappend, &tid);

	if (!p)
		return 0;
	if (ret >= 0 && te_pid_active(pid))
		te_handle_mremap_range(pid, p->old_addr, p->old_size, (__u64)ret,
				       p->new_size);
	bpf_map_delete_elem(&ts_mremappend, &tid);
	return 0;
}

static __always_inline int handle_munmap_enter(__u64 start, __u64 len)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mprotect_pend p = {
		.start = start,
		.len = len,
		.prot = 0,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_mprotectpend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_munmap_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct mprotect_pend *p = bpf_map_lookup_elem(&ts_mprotectpend, &tid);

	if (!p)
		return 0;
	if (ret == 0 && te_pid_active(pid))
		te_delete_mmap_range(pid, p->start, p->len);
	bpf_map_delete_elem(&ts_mprotectpend, &tid);
	return 0;
}

static __always_inline int handle_io_enter_addr(int fd, __u32 access,
						const void *addr_ptr,
						__u32 addr_kind,
						int addr_len)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int rc = 0;

	if (te_pid_active(pid) && !te_lookup_fd(pid, fd))
		rc = te_handle_channel(fd, access, te_tracepoint_mode());
	stash_io(fd, access, addr_ptr, addr_kind, addr_len);
	return rc;
}

static __always_inline int handle_io_enter(int fd, __u32 access)
{
	return handle_io_enter_addr(fd, access, 0, TE_IO_ADDR_NONE, 0);
}

SEC("tp/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
	return handle_io_enter((int)ctx->args[0], TE_ACCESS_READ);
}

SEC("tp/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_io_exit_read(ctx->ret);
}

SEC("tp/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	return handle_io_enter((int)ctx->args[0], TE_ACCESS_WRITE);
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_io_exit_write(ctx->ret);
}

SEC("tp/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
	return handle_mmap_enter((int)ctx->args[4], ctx->args[2], ctx->args[3],
				 ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_mmap")
int trace_mmap_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_mmap_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx)
{
	return handle_mprotect_enter(ctx->args[0], ctx->args[1], ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_mprotect")
int trace_mprotect_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_mprotect_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_mremap")
int trace_mremap(struct trace_event_raw_sys_enter *ctx)
{
	return handle_mremap_enter(ctx->args[0], ctx->args[1], ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_mremap")
int trace_mremap_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_mremap_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx)
{
	return handle_munmap_enter(ctx->args[0], ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_munmap")
int trace_munmap_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_munmap_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
	return handle_io_enter_addr((int)ctx->args[0], TE_ACCESS_WRITE,
				    (const void *)ctx->args[4],
				    TE_IO_ADDR_SOCKADDR, (int)ctx->args[5]);
}

SEC("tp/syscalls/sys_exit_sendto")
int trace_sendto_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_io_exit_addr(ctx->ret, TE_ACCESS_WRITE);
}

SEC("tp/syscalls/sys_enter_recvfrom")
int trace_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	return handle_io_enter_addr((int)ctx->args[0], TE_ACCESS_READ,
				    (const void *)ctx->args[4],
				    TE_IO_ADDR_SOCKADDR, 0);
}

SEC("tp/syscalls/sys_exit_recvfrom")
int trace_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_io_exit_addr(ctx->ret, TE_ACCESS_READ);
}

SEC("tp/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
	return handle_io_enter_addr((int)ctx->args[0], TE_ACCESS_WRITE,
				    (const void *)ctx->args[1],
				    TE_IO_ADDR_USER_MSGHDR, 0);
}

SEC("tp/syscalls/sys_exit_sendmsg")
int trace_sendmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_io_exit_addr(ctx->ret, TE_ACCESS_WRITE);
}

SEC("tp/syscalls/sys_enter_recvmsg")
int trace_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
	return handle_io_enter_addr((int)ctx->args[0], TE_ACCESS_READ,
				    (const void *)ctx->args[1],
				    TE_IO_ADDR_USER_MSGHDR, 0);
}

SEC("tp/syscalls/sys_exit_recvmsg")
int trace_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_io_exit_addr(ctx->ret, TE_ACCESS_READ);
}

static __always_inline int stash_dup(int oldfd)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct dup_pend p = { .oldfd = oldfd };

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_duppend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_dup_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct dup_pend *p = bpf_map_lookup_elem(&ts_duppend, &tid);

	if (p && ret >= 0 && te_pid_active(pid)) {
		int newfd = (int)ret;
		if (newfd != p->oldfd)
			te_delete_fd(pid, newfd);
		te_copy_fd(pid, p->oldfd, newfd);
		te_copy_sockfd(pid, p->oldfd, newfd);
	}
	bpf_map_delete_elem(&ts_duppend, &tid);
	return 0;
}

SEC("tp/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (te_pid_active(pid))
		te_delete_fd(pid, (int)ctx->args[0]);
	return 0;
}

SEC("tp/syscalls/sys_enter_dup")
int trace_dup(struct trace_event_raw_sys_enter *ctx)
{
	return stash_dup((int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_dup")
int trace_dup_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_dup_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_dup2")
int trace_dup2(struct trace_event_raw_sys_enter *ctx)
{
	return stash_dup((int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_dup2")
int trace_dup2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_dup_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_dup3")
int trace_dup3(struct trace_event_raw_sys_enter *ctx)
{
	return stash_dup((int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_dup3")
int trace_dup3_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_dup_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_fcntl")
int trace_fcntl(struct trace_event_raw_sys_enter *ctx)
{
	int cmd = (int)ctx->args[1];
	if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)
		return stash_dup((int)ctx->args[0]);
	return 0;
}

SEC("tp/syscalls/sys_exit_fcntl")
int trace_fcntl_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_dup_exit(ctx->ret);
}

static __always_inline int stash_fd_copy(int out_fd, int in_fd)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct fd_copy_pend p = {
		.out_fd = out_fd,
		.in_fd = in_fd,
	};

	if (!te_pid_active(pid))
		return 0;
	bpf_map_update_elem(&ts_fdcopypend, &tid, &p, BPF_ANY);
	return 0;
}

static __always_inline int handle_fd_copy_exit(long ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	pid_t pid = tid >> 32;
	struct fd_copy_pend *p = bpf_map_lookup_elem(&ts_fdcopypend, &tid);

	if (!p)
		return 0;
	if (enforce_mode) {
		bpf_map_delete_elem(&ts_fdcopypend, &tid);
		return 0;
	}
	if (ret > 0 && te_pid_active(pid)) {
		struct fd_ref *in_ref = te_lookup_fd(pid, p->in_fd);
		if (in_ref) {
			te_read(pid, &in_ref->fid, in_ref->path);
			struct fd_ref *out_ref = te_lookup_fd(pid, p->out_fd);
			if (out_ref)
				te_write_flow(pid, &out_ref->fid, out_ref->path);
		}
	}
	bpf_map_delete_elem(&ts_fdcopypend, &tid);
	return 0;
}

SEC("tp/syscalls/sys_enter_sendfile64")
int trace_sendfile64(struct trace_event_raw_sys_enter *ctx)
{
	return stash_fd_copy((int)ctx->args[0], (int)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_sendfile64")
int trace_sendfile64_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_fd_copy_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_copy_file_range")
int trace_copy_file_range(struct trace_event_raw_sys_enter *ctx)
{
	return stash_fd_copy((int)ctx->args[2], (int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_copy_file_range")
int trace_copy_file_range_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_fd_copy_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_splice")
int trace_splice(struct trace_event_raw_sys_enter *ctx)
{
	return stash_fd_copy((int)ctx->args[2], (int)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_splice")
int trace_splice_exit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_fd_copy_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_getpid")
int cap_drain_tick(struct trace_event_raw_sys_enter *ctx)
{
	(void)ctx;
	cap_drain_current();
	return 0;
}
