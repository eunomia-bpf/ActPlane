// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//
// Unit tests for ActPlane taint matching (taint.h) and YAML config parsing
// (taint_config.h). These exercise the exact predicates the eBPF program uses,
// without requiring a kernel/BPF load.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "taint.h"
#include "taint_config.h"

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

static void test_apply_sources(void)
{
	struct taint_rule rules[2] = {0};
	taint_cfg_set_comm(rules[0].source_comm, "codex");
	taint_cfg_set_comm(rules[0].sink_comm, "git");
	rules[0].label = 1ULL << 0;
	rules[0].rule_id = 0;
	taint_cfg_set_comm(rules[1].source_comm, "agent");
	taint_cfg_set_comm(rules[1].sink_comm, "ssh");
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

static void test_check_sink(void)
{
	struct taint_rule rules[2] = {0};
	taint_cfg_set_comm(rules[0].source_comm, "codex");
	taint_cfg_set_comm(rules[0].sink_comm, "git");
	rules[0].label = 1ULL << 0;
	rules[0].rule_id = 0;
	taint_cfg_set_comm(rules[1].source_comm, "codex");
	taint_cfg_set_comm(rules[1].sink_comm, "ssh");
	rules[1].label = 1ULL << 0;   /* same source -> same label */
	rules[1].rule_id = 1;

	unsigned int rid = 999;
	check(taint_check_sink(rules, 2, "git", (1ULL << 0), &rid) == 1 && rid == 0,
	      "check_sink: tainted process running git is a violation (rule 0)");

	rid = 999;
	check(taint_check_sink(rules, 2, "ssh", (1ULL << 0), &rid) == 1 && rid == 1,
	      "check_sink: tainted process running ssh is a violation (rule 1)");

	rid = 999;
	check(taint_check_sink(rules, 2, "ls", (1ULL << 0), &rid) == 0,
	      "check_sink: tainted process running ls is allowed");

	rid = 999;
	check(taint_check_sink(rules, 2, "git", TAINT_LABEL_NONE, &rid) == 0,
	      "check_sink: untainted process running git is allowed");
}

static void test_config_parse(void)
{
	const char *yaml =
		"# ActPlane taint rules\n"
		"rules:\n"
		"  - source: codex\n"
		"    sink: git\n"
		"    reason: \"no git for codex\"\n"
		"  - source: codex\n"
		"    sink: ssh\n";
	struct taint_rule rules[MAX_TAINT_RULES] = {0};
	int n = taint_config_parse_str(yaml, rules, MAX_TAINT_RULES);

	check(n == 2, "config: parsed two rules");
	check(taint_comm_eq(rules[0].source_comm, "codex") &&
	      taint_comm_eq(rules[0].sink_comm, "git"),
	      "config: rule 0 = codex -> git");
	check(rules[0].label == (1ULL << 0) && rules[0].rule_id == 0,
	      "config: rule 0 label/id");
	check(taint_comm_eq(rules[1].source_comm, "codex") &&
	      taint_comm_eq(rules[1].sink_comm, "ssh"),
	      "config: rule 1 = codex -> ssh");
	check(rules[1].label == (1ULL << 1) && rules[1].rule_id == 1,
	      "config: rule 1 label/id");
}

static void test_config_inline_and_quotes(void)
{
	// "- source:" inline on the dash line, single-quoted value
	const char *yaml =
		"rules:\n"
		"  - source: 'agent'\n"
		"    sink: 'curl'\n";
	struct taint_rule rules[MAX_TAINT_RULES] = {0};
	int n = taint_config_parse_str(yaml, rules, MAX_TAINT_RULES);
	check(n == 1, "config(inline): one rule");
	check(taint_comm_eq(rules[0].source_comm, "agent") &&
	      taint_comm_eq(rules[0].sink_comm, "curl"),
	      "config(inline): quotes stripped, agent -> curl");
}

static void test_config_malformed(void)
{
	// key/value before any list item is malformed
	const char *yaml = "source: codex\n";
	struct taint_rule rules[MAX_TAINT_RULES] = {0};
	int n = taint_config_parse_str(yaml, rules, MAX_TAINT_RULES);
	check(n == -1, "config: kv before list item -> error");

	// empty config yields zero rules
	n = taint_config_parse_str("# nothing here\n", rules, MAX_TAINT_RULES);
	check(n == 0, "config: empty -> zero rules");
}

int main(void)
{
	printf("=== ActPlane taint unit tests ===\n");
	test_comm_eq();
	test_apply_sources();
	test_check_sink();
	test_config_parse();
	test_config_inline_and_quotes();
	test_config_malformed();

	printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
	return tests_failed == 0 ? 0 : 1;
}
