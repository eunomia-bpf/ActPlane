// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 eunomia-bpf org. */
//
// ActPlane taint loader. Reads a compiled policy (struct taint_config, produced
// by the collector's DSL compiler) into the BPF rodata, attaches the enforcer,
// and prints the TAINT_VIOLATION events the kernel emits.

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include "process.h"
#include "process.skel.h"

static struct env {
	bool verbose;
	const char *config;
} env = {0};

const char *argp_program_version = "actplane-taint 2.0";
const char argp_program_doc[] =
"ActPlane in-kernel taint enforcer.\n"
"\n"
"Loads a compiled policy and reports only taint-rule violations.\n"
"USAGE: ./process --config policy.bin\n";

static const struct argp_option opts[] = {
	{ "config", 'c', "FILE", 0, "Compiled policy (struct taint_config blob)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'c': env.config = arg; break;
	case ARGP_KEY_ARG: argp_usage(state); break;
	default: return ARGP_ERR_UNKNOWN;
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

static volatile bool exiting = false;
static void sig_handler(int sig) { (void)sig; exiting = true; }

static bool bpf_lsm_active(void)
{
	FILE *f = fopen("/sys/kernel/security/lsm", "r");
	char buf[512];
	bool active = false;

	if (!f)
		return false;
	if (fgets(buf, sizeof(buf), f))
		active = strstr(buf, "bpf") != NULL;
	fclose(f);
	return active;
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	const struct event *e = data;
	char target[MAX_FILENAME_LEN];
	(void)ctx; (void)sz;
	if (e->type != EVENT_TYPE_TAINT_VIOLATION)
		return 0;
	if (e->conn_ip) { /* connect: format the network-order IPv4 */
		unsigned int ip = e->conn_ip;
		snprintf(target, sizeof(target), "%u.%u.%u.%u",
			 ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
	} else {
		snprintf(target, sizeof(target), "%s", e->filename);
	}
	printf("{\"timestamp\":%llu,\"event\":\"TAINT_VIOLATION\",\"blocked\":%s,"
	       "\"comm\":\"%s\",\"pid\":%d,\"ppid\":%d,\"target\":\"%s\","
	       "\"rule_id\":%u,\"taint_label\":%llu}\n",
	       e->timestamp_ns, e->blocked ? "true" : "false", e->comm, e->pid,
	       e->ppid, target, e->taint_rule_id, e->taint_label);
	fflush(stdout);
	return 0;
}

static int load_config(const char *path, struct taint_config *cfg)
{
	FILE *f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "cannot open config '%s': %s\n", path, strerror(errno));
		return -1;
	}
	memset(cfg, 0, sizeof(*cfg));
	size_t n = fread(cfg, 1, sizeof(*cfg), f);
	fclose(f);
	if (n != sizeof(*cfg)) {
		fprintf(stderr, "config size mismatch: read %zu, expected %zu\n",
			n, sizeof(*cfg));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct process_bpf *skel;
	struct taint_config cfg;
	bool enforce;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if (!env.config) {
		fprintf(stderr, "missing --config <policy.bin>\n");
		return 1;
	}
	if (load_config(env.config, &cfg))
		return 1;
	enforce = bpf_lsm_active();

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	if (!enforce) {
		bpf_program__set_autoload(skel->progs.enforce_bprm_check_security, false);
		bpf_program__set_autoload(skel->progs.enforce_file_open, false);
		bpf_program__set_autoload(skel->progs.enforce_file_permission, false);
		bpf_program__set_autoload(skel->progs.enforce_file_truncate, false);
		bpf_program__set_autoload(skel->progs.enforce_path_truncate, false);
		bpf_program__set_autoload(skel->progs.enforce_path_unlink, false);
		bpf_program__set_autoload(skel->progs.enforce_path_rename, false);
		bpf_program__set_autoload(skel->progs.enforce_socket_connect, false);
	}

	/* install compiled tables into rodata before load */
	skel->rodata->enforce_mode = enforce ? 1 : 0;
	skel->rodata->n_sources = cfg.n_sources;
	skel->rodata->n_rules = cfg.n_rules;
	skel->rodata->n_xforms = cfg.n_xforms;
	skel->rodata->n_gates = cfg.n_gates;
	memcpy((void *)skel->rodata->taint_sources, cfg.sources, sizeof(cfg.sources));
	memcpy((void *)skel->rodata->taint_rules, cfg.rules, sizeof(cfg.rules));
	memcpy((void *)skel->rodata->taint_xforms, cfg.xforms, sizeof(cfg.xforms));
	memcpy((void *)skel->rodata->taint_gates, cfg.gates, sizeof(cfg.gates));
	fprintf(stderr, "ActPlane: %u sources, %u rules, %u xforms, %u gates\n",
		cfg.n_sources, cfg.n_rules, cfg.n_xforms, cfg.n_gates);
	fprintf(stderr, "ActPlane: %s mode (%s)\n",
		enforce ? "enforce" : "audit",
		enforce ? "BPF LSM is active" : "BPF LSM is not active");

	err = process_bpf__load(skel);
	if (err) { fprintf(stderr, "Failed to load BPF skeleton\n"); goto cleanup; }
	err = process_bpf__attach(skel);
	if (err) { fprintf(stderr, "Failed to attach BPF skeleton\n"); goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; fprintf(stderr, "ring buffer failed\n"); goto cleanup; }

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "poll error: %d\n", err); break; }
	}

cleanup:
	ring_buffer__free(rb);
	process_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
