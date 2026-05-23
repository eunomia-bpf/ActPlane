// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 eunomia-bpf org. */
//
// ActPlane taint loader for process.bpf.c. The kernel program enforces the
// compiled taint rules and emits ONLY TAINT_VIOLATION events; this loader
// installs the rules and prints those violations. Taint edges are compiled by
// the collector (DSL/YAML) and passed as `-T` arguments.

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "process.h"
#include "process.skel.h"

static struct env {
	bool verbose;
	struct taint_rule taint_rules[MAX_TAINT_RULES];
	int taint_rule_count;
} env = {0};

const char *argp_program_version = "actplane-taint 1.0";
const char argp_program_doc[] =
"ActPlane in-kernel taint enforcer.\n"
"\n"
"Loads process.bpf.c, installs taint rules, and reports only the violations\n"
"the kernel detects (a tainted descendant performing a forbidden operation).\n"
"\n"
"Taint edge formats (-T, repeatable):\n"
"  SOURCE:SINK            exec sink (comm), default\n"
"  SOURCE:exec:CMD        exec sink (comm)\n"
"  SOURCE:open:PREFIX     file-open sink (path prefix)\n"
"  SOURCE:write:PREFIX    file-mutate sink (unlink/rename path prefix)\n"
"  SOURCE:connect:IPPFX   network-connect sink (IPv4 dotted prefix)\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{ "taint-rule", 'T', "EDGE", 0, "Taint edge (see formats above); repeatable" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'T': {
		if (env.taint_rule_count >= MAX_TAINT_RULES) {
			fprintf(stderr, "Too many taint rules (max %d)\n", MAX_TAINT_RULES);
			argp_usage(state);
		}
		char *colon = strchr(arg, ':');
		if (!colon || colon == arg || *(colon + 1) == '\0') {
			fprintf(stderr, "Invalid taint rule '%s' (expected SOURCE:[KIND:]TARGET)\n", arg);
			argp_usage(state);
		}
		struct taint_rule *r = &env.taint_rules[env.taint_rule_count];
		memset(r, 0, sizeof(*r));
		size_t src_len = (size_t)(colon - arg);
		if (src_len >= TAINT_COMM_LEN)
			src_len = TAINT_COMM_LEN - 1;
		memcpy(r->source_comm, arg, src_len);

		const char *rest = colon + 1;
		if (strncmp(rest, "open:", 5) == 0) {
			r->sink_kind = TAINT_SINK_FILE_OPEN;
			rest += 5;
		} else if (strncmp(rest, "write:", 6) == 0) {
			r->sink_kind = TAINT_SINK_FILE_MUTATE;
			rest += 6;
		} else if (strncmp(rest, "connect:", 8) == 0) {
			r->sink_kind = TAINT_SINK_CONNECT;
			rest += 8;
		} else if (strncmp(rest, "exec:", 5) == 0) {
			r->sink_kind = TAINT_SINK_EXEC;
			rest += 5;
		} else {
			r->sink_kind = TAINT_SINK_EXEC;
		}
		if (*rest == '\0') {
			fprintf(stderr, "Invalid taint rule '%s' (empty sink target)\n", arg);
			argp_usage(state);
		}
		strncpy(r->sink, rest, TAINT_SINK_LEN - 1);
		r->sink[TAINT_SINK_LEN - 1] = '\0';
		r->rule_id = (unsigned int)env.taint_rule_count;
		r->label = 1ULL << env.taint_rule_count;
		env.taint_rule_count++;
		break;
	}
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = argp_program_doc };

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *sink_kind_str(unsigned int k)
{
	switch (k) {
	case TAINT_SINK_FILE_OPEN: return "open";
	case TAINT_SINK_FILE_MUTATE: return "write";
	case TAINT_SINK_CONNECT: return "connect";
	default: return "exec";
	}
}

static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

/* The kernel only ever emits TAINT_VIOLATION; print it as one JSON line. */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	(void)ctx;
	(void)data_sz;
	if (e->type != EVENT_TYPE_TAINT_VIOLATION)
		return 0;
	printf("{");
	printf("\"timestamp\":%llu,", e->timestamp_ns);
	printf("\"event\":\"TAINT_VIOLATION\",");
	printf("\"comm\":\"%s\",", e->comm);
	printf("\"pid\":%d,", e->pid);
	printf("\"ppid\":%d,", e->ppid);
	printf("\"target\":\"%s\",", e->filename);
	printf("\"rule_id\":%u,", e->taint_rule_id);
	printf("\"taint_label\":%llu", e->taint_label);
	printf("}\n");
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct process_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Install compiled taint rules into rodata before load. */
	skel->rodata->n_taint_rules = (unsigned int)env.taint_rule_count;
	for (int i = 0; i < env.taint_rule_count; i++) {
		skel->rodata->taint_rules_cfg[i] = env.taint_rules[i];
		fprintf(stderr, "ActPlane rule %d: '%s' -> deny %s '%s' (label 0x%llx)\n",
			i, env.taint_rules[i].source_comm,
			sink_kind_str(env.taint_rules[i].sink_kind),
			env.taint_rules[i].sink, env.taint_rules[i].label);
	}

	err = process_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto cleanup;
	}
	err = process_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	process_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
