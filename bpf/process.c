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
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "process.h"
#include "process.skel.h"

static struct env {
	bool verbose;
	const char *config;
	pid_t agent_pid;
	unsigned long long agent_label;
} env = {0};

const char *argp_program_version = "actplane-taint 2.0";
const char argp_program_doc[] =
"ActPlane in-kernel taint enforcer.\n"
"\n"
"Loads a compiled policy and reports only taint-rule violations.\n"
"USAGE: ./process --config policy.bin [--agent-pid PID --agent-label BIT]\n";

static const struct argp_option opts[] = {
	{ "config", 'c', "FILE", 0, "Compiled policy (struct taint_config blob)" },
	{ "agent-pid", 1000, "PID", 0, "Seed this pid as the ActPlane AGENT root" },
	{ "agent-label", 1001, "BIT", 0, "Label bit to apply to --agent-pid" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'c': env.config = arg; break;
	case 1000: env.agent_pid = (pid_t)strtol(arg, NULL, 10); break;
	case 1001: env.agent_label = strtoull(arg, NULL, 0); break;
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

static const char *effect_name(unsigned int effect)
{
	switch (effect) {
	case TEFFECT_AUDIT: return "audit";
	case TEFFECT_KILL: return "kill";
	case TEFFECT_BLOCK: return "block";
	default: return "unknown";
	}
}

static bool config_has_effect(const struct taint_config *cfg, unsigned int effect)
{
	for (unsigned int i = 0; i < cfg->n_rules && i < MAX_TAINT_RULES; i++) {
		if (cfg->rules[i].effect == effect)
			return true;
	}
	return false;
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
	printf("{\"timestamp\":%llu,\"event\":\"TAINT_VIOLATION\",\"effect\":\"%s\","
	       "\"blocked\":%s,\"killed\":%s,\"comm\":\"%s\",\"pid\":%d,\"ppid\":%d,"
	       "\"target\":\"%s\",\"rule_id\":%u,\"taint_label\":%llu,"
	       "\"matched_label\":%llu,\"provenance\":{\"label\":%llu,\"timestamp\":%llu,"
	       "\"pid\":%d,\"op\":%u,\"ip\":%u,\"target\":\"%s\"}}\n",
	       e->timestamp_ns, effect_name(e->effect), e->blocked ? "true" : "false",
	       e->killed ? "true" : "false", e->comm, e->pid, e->ppid,
	       target, e->taint_rule_id, e->taint_label, e->matched_label,
	       e->prov_label, e->prov_timestamp_ns, e->prov_pid, e->prov_op,
	       e->prov_ip, e->prov_target);
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

struct proc_state_seed {
	unsigned long long labels;
	unsigned long long lin_gates;
};

static int seed_agent_root(struct process_bpf *skel)
{
	struct proc_state_seed state = {};
	pid_t pid = env.agent_pid;

	if (!env.agent_pid && !env.agent_label)
		return 0;
	if (env.agent_pid <= 0 || env.agent_label == 0) {
		fprintf(stderr, "--agent-pid and --agent-label must be provided together\n");
		return -1;
	}

	state.labels = env.agent_label;
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.ts_proc), &pid, &state, BPF_ANY) < 0) {
		fprintf(stderr, "failed to seed AGENT pid %d in ts_proc: %s\n", pid, strerror(errno));
		return -1;
	}
	if (bpf_map_update_elem(bpf_map__fd(skel->maps.ts_root), &pid, &pid, BPF_ANY) < 0) {
		fprintf(stderr, "failed to seed AGENT pid %d in ts_root: %s\n", pid, strerror(errno));
		return -1;
	}
	/* ts_sess (gate/staleness state) is created lazily by te_sess_init when the
	 * first gate or `since` invalidator fires; an absent entry reads as all-zero
	 * (no gate fired yet), which is the correct initial state. */
	fprintf(stderr, "ActPlane: seeded AGENT pid %d label 0x%llx\n", pid, env.agent_label);
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
	skel->rodata->n_invals = cfg.n_invals;
	memcpy((void *)skel->rodata->taint_sources, cfg.sources, sizeof(cfg.sources));
	memcpy((void *)skel->rodata->taint_rules, cfg.rules, sizeof(cfg.rules));
	memcpy((void *)skel->rodata->taint_xforms, cfg.xforms, sizeof(cfg.xforms));
	memcpy((void *)skel->rodata->taint_gates, cfg.gates, sizeof(cfg.gates));
	memcpy((void *)skel->rodata->taint_invals, cfg.invals, sizeof(cfg.invals));
	fprintf(stderr, "ActPlane: %u sources, %u rules, %u xforms, %u gates, %u invals\n",
		cfg.n_sources, cfg.n_rules, cfg.n_xforms, cfg.n_gates, cfg.n_invals);
	fprintf(stderr, "ActPlane: %s mode (%s)\n",
		enforce ? "enforce" : "tracepoint",
		enforce ? "BPF LSM is active" :
			  "BPF LSM is not active; block effects are unsupported, audit reports, kill terminates");
	if (!enforce && config_has_effect(&cfg, TEFFECT_BLOCK))
		fprintf(stderr,
			"ActPlane: warning: effect block requires BPF LSM; block rules will not fire in tracepoint mode\n");

	err = process_bpf__load(skel);
	if (err) { fprintf(stderr, "Failed to load BPF skeleton\n"); goto cleanup; }

	/* Loop counts in a (non-frozen) map so the verifier checks each bpf_loop
	 * callback once, not once per table entry. Slots: 0=rules 1=sources 2=xforms 3=gates. */
	{
		__u32 ks[5] = {0, 1, 2, 3, 4};
		__u32 vs[5] = { cfg.n_rules, cfg.n_sources, cfg.n_xforms,
				cfg.n_gates, cfg.n_invals };
		int cfd = bpf_map__fd(skel->maps.ts_counts);
		for (int i = 0; i < 5; i++) {
			if (bpf_map_update_elem(cfd, &ks[i], &vs[i], BPF_ANY) < 0) {
				fprintf(stderr, "failed to set loop count %d: %s\n", i, strerror(errno));
				err = -1; goto cleanup;
			}
		}
	}

	err = process_bpf__attach(skel);
	if (err) { fprintf(stderr, "Failed to attach BPF skeleton\n"); goto cleanup; }
	if (seed_agent_root(skel)) { err = -1; goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; fprintf(stderr, "ring buffer failed\n"); goto cleanup; }
	fprintf(stderr, "ActPlane: ready\n");

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
