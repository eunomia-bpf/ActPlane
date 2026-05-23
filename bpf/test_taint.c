// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//
// Unit tests for ActPlane taint matching (taint.h). These exercise the exact
// predicates the eBPF program uses, without requiring a kernel/BPF load.
// Policy authoring (YAML/DSL -> source:sink edges) lives in the Rust collector
// and is tested there.

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "taint.h"

/* Local helper: copy a comm name into a fixed TAINT_COMM_LEN field. */
static void set_comm(char *dst, const char *src)
{
	strncpy(dst, src, TAINT_COMM_LEN - 1);
	dst[TAINT_COMM_LEN - 1] = '\0';
}

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"

static int tests_passed = 0;
static int tests_failed = 0;

static void check(bool cond, const char *name)
{
	if (cond) {
		printf("[" GREEN "PASS" RESET "] %s\n", name);
		tests_passed++;
	} else {
		printf("[" RED "FAIL" RESET "] %s\n", name);
		tests_failed++;
	}
}

static void test_comm_eq(void)
{
	check(taint_comm_eq("git", "git") == 1, "comm_eq: identical");
	check(taint_comm_eq("git", "ssh") == 0, "comm_eq: different");
	check(taint_comm_eq("git", "gitk") == 0, "comm_eq: prefix is not equal");
	check(taint_comm_eq("", "") == 1, "comm_eq: both empty");
	check(taint_comm_eq("codex", "codex") == 1, "comm_eq: multichar");
	// 15-char names (max comm minus NUL) must still compare fully
	check(taint_comm_eq("abcdefghijklmno", "abcdefghijklmno") == 1,
	      "comm_eq: full-length match");
	check(taint_comm_eq("abcdefghijklmno", "abcdefghijklmnX") == 0,
	      "comm_eq: full-length mismatch at last byte");
}

/* Set a sink operand (exec comm or file path prefix, up to TAINT_SINK_LEN). */
static void set_sink(char *dst, const char *src)
{
	strncpy(dst, src, TAINT_SINK_LEN - 1);
	dst[TAINT_SINK_LEN - 1] = '\0';
}

static void test_apply_sources(void)
{
	struct taint_rule rules[2] = {0};
	set_comm(rules[0].source_comm, "codex");
	rules[0].sink_kind = TAINT_SINK_EXEC;
	set_sink(rules[0].sink, "git");
	rules[0].label = 1ULL << 0;
	rules[0].rule_id = 0;
	set_comm(rules[1].source_comm, "agent");
	rules[1].sink_kind = TAINT_SINK_EXEC;
	set_sink(rules[1].sink, "ssh");
	rules[1].label = 1ULL << 1;
	rules[1].rule_id = 1;

	unsigned long long l;
	l = taint_apply_sources(rules, 2, "codex", TAINT_LABEL_NONE);
	check(l == (1ULL << 0), "apply_sources: codex gets label 0");

	l = taint_apply_sources(rules, 2, "bash", TAINT_LABEL_NONE);
	check(l == TAINT_LABEL_NONE, "apply_sources: unrelated comm untainted");

	// pre-existing (inherited) label is preserved and OR'd
	l = taint_apply_sources(rules, 2, "agent", (1ULL << 0));
	check(l == ((1ULL << 0) | (1ULL << 1)),
	      "apply_sources: inherited label preserved + new added");
}

static void test_exec_sink(void)
{
	struct taint_rule rules[2] = {0};
	set_comm(rules[0].source_comm, "codex");
	rules[0].sink_kind = TAINT_SINK_EXEC;
	set_sink(rules[0].sink, "git");
	rules[0].label = 1ULL << 0;
	rules[0].rule_id = 0;
	set_comm(rules[1].source_comm, "codex");
	rules[1].sink_kind = TAINT_SINK_EXEC;
	set_sink(rules[1].sink, "ssh");
	rules[1].label = 1ULL << 0;   /* same source -> same label */
	rules[1].rule_id = 1;

	unsigned int rid = 999;
	check(taint_check_exec_sink(rules, 2, "git", (1ULL << 0), &rid) == 1 && rid == 0,
	      "exec_sink: tainted process running git is a violation (rule 0)");

	rid = 999;
	check(taint_check_exec_sink(rules, 2, "ssh", (1ULL << 0), &rid) == 1 && rid == 1,
	      "exec_sink: tainted process running ssh is a violation (rule 1)");

	rid = 999;
	check(taint_check_exec_sink(rules, 2, "ls", (1ULL << 0), &rid) == 0,
	      "exec_sink: tainted process running ls is allowed");

	rid = 999;
	check(taint_check_exec_sink(rules, 2, "git", TAINT_LABEL_NONE, &rid) == 0,
	      "exec_sink: untainted process running git is allowed");
}

static void test_path_prefix(void)
{
	check(taint_path_has_prefix("/etc/secrets/key", "/etc/secrets") == 1,
	      "path_prefix: /etc/secrets/key under /etc/secrets");
	check(taint_path_has_prefix("/etc/passwd", "/etc/secrets") == 0,
	      "path_prefix: /etc/passwd not under /etc/secrets");
	check(taint_path_has_prefix("/etc", "/etc/secrets") == 0,
	      "path_prefix: shorter path is not under longer prefix");
	check(taint_path_has_prefix("/anything", "") == 0,
	      "path_prefix: empty prefix never matches");
}

static void test_file_sink(void)
{
	struct taint_rule rules[2] = {0};
	/* exec rule (should be ignored by the file-sink check) */
	set_comm(rules[0].source_comm, "codex");
	rules[0].sink_kind = TAINT_SINK_EXEC;
	set_sink(rules[0].sink, "git");
	rules[0].label = 1ULL << 0;
	rules[0].rule_id = 0;
	/* file-open rule */
	set_comm(rules[1].source_comm, "codex");
	rules[1].sink_kind = TAINT_SINK_FILE_OPEN;
	set_sink(rules[1].sink, "/etc/secrets");
	rules[1].label = 1ULL << 0;
	rules[1].rule_id = 1;

	unsigned int rid = 999;
	check(taint_check_prefix_sink(rules, 2, "/etc/secrets/key", (1ULL << 0), TAINT_SINK_FILE_OPEN, &rid) == 1 && rid == 1,
	      "file_sink: tainted process opening /etc/secrets/* is a violation (rule 1)");

	rid = 999;
	check(taint_check_prefix_sink(rules, 2, "/tmp/ok", (1ULL << 0), TAINT_SINK_FILE_OPEN, &rid) == 0,
	      "file_sink: tainted process opening /tmp/ok is allowed");

	rid = 999;
	check(taint_check_prefix_sink(rules, 2, "/etc/secrets/key", TAINT_LABEL_NONE, TAINT_SINK_FILE_OPEN, &rid) == 0,
	      "file_sink: untainted process opening /etc/secrets is allowed");

	/* the exec sink must NOT fire on a file path, and vice-versa */
	rid = 999;
	check(taint_check_exec_sink(rules, 2, "/etc/secrets/key", (1ULL << 0), &rid) == 0,
	      "file_sink: file path does not trip the exec sink");
}

static void test_mutate_and_connect_sinks(void)
{
	struct taint_rule rules[2] = {0};
	/* file-mutate rule: tainted proc may not unlink/rename under /data */
	set_comm(rules[0].source_comm, "codex");
	rules[0].sink_kind = TAINT_SINK_FILE_MUTATE;
	set_sink(rules[0].sink, "/data");
	rules[0].label = 1ULL << 0;
	rules[0].rule_id = 0;
	/* connect rule: tainted proc may not connect to 10.0.0.* */
	set_comm(rules[1].source_comm, "codex");
	rules[1].sink_kind = TAINT_SINK_CONNECT;
	set_sink(rules[1].sink, "10.0.0.");
	rules[1].label = 1ULL << 0;
	rules[1].rule_id = 1;

	unsigned int rid = 999;
	check(taint_check_prefix_sink(rules, 2, "/data/x", (1ULL << 0), TAINT_SINK_FILE_MUTATE, &rid) == 1 && rid == 0,
	      "mutate_sink: tainted unlink/rename under /data is a violation");
	rid = 999;
	check(taint_check_prefix_sink(rules, 2, "/work/x", (1ULL << 0), TAINT_SINK_FILE_MUTATE, &rid) == 0,
	      "mutate_sink: /work/x allowed");
	rid = 999;
	check(taint_check_prefix_sink(rules, 2, "10.0.0.5", (1ULL << 0), TAINT_SINK_CONNECT, &rid) == 1 && rid == 1,
	      "connect_sink: tainted connect to 10.0.0.5 is a violation");
	rid = 999;
	check(taint_check_prefix_sink(rules, 2, "8.8.8.8", (1ULL << 0), TAINT_SINK_CONNECT, &rid) == 0,
	      "connect_sink: connect to 8.8.8.8 allowed");
	/* kinds don't cross: a path must not trip the connect sink */
	rid = 999;
	check(taint_check_prefix_sink(rules, 2, "/data/x", (1ULL << 0), TAINT_SINK_CONNECT, &rid) == 0,
	      "connect_sink: file path does not trip connect sink");
}

int main(void)
{
	printf("=== ActPlane taint unit tests ===\n");
	test_comm_eq();
	test_apply_sources();
	test_exec_sink();
	test_path_prefix();
	test_file_sink();
	test_mutate_and_connect_sinks();

	printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
	return tests_failed == 0 ? 0 : 1;
}
