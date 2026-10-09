// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * ActPlane verifier diagnostic loader.
 *
 * Loads every BPF program in the same skeleton as the `process` loader, one
 * program per `process_bpf__load` so that an oversized verifier log for a
 * single program cannot abort the load of the others. Each program is loaded
 * with a level-1 verifier log; only the summary and rejection lines are
 * reprinted, so a guest console capture stays small while still recording the
 * verified instruction total per program.
 *
 * This is the tool used to prove the 6.8 verifier gate is clear (all programs
 * load, `processed <N> insns` per program, no "Too large"/"invalid mem
 * access") and to record the instruction budget as supporting evidence for the
 * firing audit.
 *
 * Usage:
 *   ./vvload --config policy.bin [same flags as process]
 *
 * Output markers:
 *   VLOAD_PROG <name> fd=<fd> err=<err>
 *   VSTAT <name> processed <N> insns (limit ...) ...
 *   VLOAD_DONE ok=<n> fail=<n> total=<n>
 *   VLOAD_FAIL <name> <reason>   (stderr; a program failed to load)
 *
 * The dump happens BEFORE attach; rodata writes, map fills, and attach are not
 * needed for the diagnostic.
 */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "process.h"
#include "policy_features.h"
#include "process.skel.h"

static struct env {
	bool verbose;
	const char *config;
	pid_t seed_pid;
	unsigned long long seed_label;
} env = {0};

const char *argp_program_version = "actplane-taint-vvload 2.0";

static const struct argp_option opts[] = {
	{ "config", 'c', "FILE", 0, "Compiled policy (struct taint_config blob)" },
	{ "seed-pid", 1000, "PID", 0, "Bind this pid as the active root process" },
	{ "seed-label", 1001, "BIT", 0, "Label bit to apply to --seed-pid" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v': env.verbose = true; break;
	case 'c': env.config = arg; break;
	case 1000: env.seed_pid = (pid_t)strtol(arg, NULL, 10); break;
	case 1001: env.seed_label = strtoull(arg, NULL, 0); break;
	case ARGP_KEY_ARG: argp_usage(state); break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
static const struct argp argp = { .options = opts, .parser = parse_arg };

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
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

/* Print only the summary/rejection lines of a verifier log, not the full
 * per-instruction trace. */
static void emit_stats(const char *name, const char *log)
{
	const char *p = log;

	while (p && *p) {
		const char *nl = strchr(p, '\n');
		size_t len = nl ? (size_t)(nl - p) : strlen(p);

		if ((len > 10 && !strncmp(p, "processed ", 10)) ||
		    strstr(p, "Too large") || strstr(p, "invalid mem access") ||
		    strstr(p, "stack"))
			printf("VSTAT %s %.*s\n", name, (int)len, p);
		p = nl ? nl + 1 : NULL;
	}
	fflush(stdout);
}

static unsigned int cfg_features_cache;

/* Load a single program of a freshly opened skeleton, so an oversized log for
 * one program cannot abort the load of the others. */
static int load_one(const char *want, int *log_level, size_t *log_size)
{
	struct process_bpf *skel;
	struct bpf_program *prog;
	char *log;
	int err, fd;

	log = calloc(1, *log_size);
	if (!log)
		return 1;
	skel = process_bpf__open();
	if (!skel) {
		free(log);
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->enforce_mode = bpf_lsm_active() ? 1 : 0;
	skel->rodata->policy_features = cfg_features_cache;

	bpf_object__for_each_program(prog, skel->obj)
	{
		bool sel = !strcmp(bpf_program__name(prog), want);
		bpf_program__set_autoload(prog, sel);
		if (sel) {
			bpf_program__set_log_buf(prog, log, *log_size);
			bpf_program__set_log_level(prog, *log_level);
		}
	}
	err = process_bpf__load(skel);
	/* A non-ENOSPC load error is a real verifier rejection: report the
	 * program as failed so the caller's VLOAD_DONE reflects it and exits
	 * nonzero. Only -ENOSPC (log buffer too small) is retryable. */
	if (err && err != -ENOSPC) {
		fprintf(stderr, "VLOAD_FAIL %s load error %d\n", want, err);
		fflush(stdout);
		process_bpf__destroy(skel);
		free(log);
		return 1;
	}
	bpf_object__for_each_program(prog, skel->obj)
	{
		if (strcmp(bpf_program__name(prog), want))
			continue;
		fd = bpf_program__fd(prog);
		printf("VLOAD_PROG %s fd=%d err=%d\n", want, fd, err);
		/* -ENOSPC means the log buffer was too small: grow it and
		 * retry, so the stats line is not lost. */
		if (err == -ENOSPC && *log_size < (1u << 30)) {
			*log_size <<= 1;
			fflush(stdout);
			process_bpf__destroy(skel);
			free(log);
			return 2;
		}
		/* A loaded program without an fd would silently drop out of the
		 * measurement; treat it as a failure. */
		if (fd < 0) {
			fprintf(stderr, "VLOAD_FAIL %s no fd after load\n", want);
			fflush(stdout);
			process_bpf__destroy(skel);
			free(log);
			return 1;
		}
		emit_stats(want, log);
	}
	fflush(stdout);
	process_bpf__destroy(skel);
	free(log);
	return 0;
}

int main(int argc, char **argv)
{
	struct process_bpf *skel;
	struct taint_config cfg;
	struct bpf_program *prog;
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
	cfg_features_cache = config_features(&cfg);

	libbpf_set_print(libbpf_print_fn);

	/* Enumerate program names once. */
	char names[256][64];
	int total = 0;

	skel = process_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	bpf_object__for_each_program(prog, skel->obj)
	{
		if (total >= 256)
			break;
		snprintf(names[total], sizeof(names[0]), "%s",
			 bpf_program__name(prog));
		total++;
	}
	process_bpf__destroy(skel);

	int ok = 0, fail = 0;
	for (int i = 0; i < total; i++) {
		int level = 1;
		size_t size = 64u << 20;
		int r;

		do {
			r = load_one(names[i], &level, &size);
		} while (r == 2);
		if (r == 0)
			ok++;
		else
			fail++;
	}
	printf("VLOAD_DONE ok=%d fail=%d total=%d\n", ok, fail, total);
	return fail ? 1 : 0;
}
