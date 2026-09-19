// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.
//
// Unit tests for the ActPlane taint matching predicates (taint.h) — the exact
// logic the eBPF engine uses for sources, sinks, masks, conditions and @arg.

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include "taint.h"

#define RESET "\033[0m"
#define GREEN "\033[32m"
#define RED   "\033[31m"
static int passed = 0, failed = 0;
static void check(bool c, const char *name)
{
	if (c) { printf("[" GREEN "PASS" RESET "] %s\n", name); passed++; }
	else   { printf("[" RED "FAIL" RESET "] %s\n", name); failed++; }
}

/* The branchless matchers compare the full TAINT_PAT_LEN, so (as in the kernel)
 * they require NUL-padded buffers. These wrappers pad the test's string literals. */
static char pa_[TAINT_PAT_LEN], pb_[TAINT_PAT_LEN];
static void pad2(const char *a, const char *b)
{
	memset(pa_, 0, sizeof(pa_)); memset(pb_, 0, sizeof(pb_));
	strncpy(pa_, a, TAINT_PAT_LEN - 1); strncpy(pb_, b, TAINT_PAT_LEN - 1);
}
static int p_streq(const char *a, const char *b) { pad2(a, b); return taint_streq(pa_, pb_); }
static int p_prefix(const char *t, const char *p) { pad2(t, p); return taint_prefix(pa_, pb_); }
static int p_match(unsigned int k, const char *t, const char *p) { pad2(t, p); return taint_match(k, pa_, pb_); }
static int p_exec_match(unsigned int k, const char *t, const char *p) { pad2(t, p); return taint_exec_match(k, pa_, pb_); }

static void test_streq(void)
{
	check(p_streq("git", "git") == 1, "streq: equal");
	check(p_streq("git", "ssh") == 0, "streq: different");
	check(p_streq("git", "gitk") == 0, "streq: prefix is not equal");
	check(p_streq("", "") == 1, "streq: both empty");
}

static void test_prefix(void)
{
	check(p_prefix("/etc/secrets/key", "/etc/secrets") == 1, "prefix: under");
	check(p_prefix("/etc/passwd", "/etc/secrets") == 0, "prefix: sibling");
	check(p_prefix("/etc", "/etc/secrets") == 0, "prefix: shorter");
	check(p_prefix("10.0.0.5", "10.0.0.") == 1, "prefix: ip");
	check(p_prefix("8.8.8.8", "10.0.0.") == 0, "prefix: ip miss");
	check(p_prefix("/x", "") == 0, "prefix: empty never matches");
}

static void test_match(void)
{
	check(p_match(TAINT_MATCH_EXACT, "git", "git") == 1, "match: exact hit");
	check(p_match(TAINT_MATCH_EXACT, "gitk", "git") == 0, "match: exact miss");
	check(p_match(TAINT_MATCH_PREFIX, "/a/b", "/a") == 1, "match: prefix hit");
	check(p_match(TAINT_MATCH_SUFFIX, "/home/u/.env", ".env") == 1, "match: suffix hit");
	check(p_match(TAINT_MATCH_SUFFIX, "/home/u/app.py", ".env") == 0, "match: suffix miss");
	check(p_match(TAINT_MATCH_SUFFIX, "api.internal", ".internal") == 1, "match: host suffix");
	check(p_match(TAINT_MATCH_ANY, "literally anything", "") == 1, "match: any");
	check(p_match(TAINT_MATCH_CONTAINS, "/home/u/server/app/f", "/server/") == 1, "match: contains hit");
	check(p_match(TAINT_MATCH_CONTAINS, "/home/u/client/app/f", "/server/") == 0, "match: contains miss");
	check(p_match(TAINT_MATCH_CONTAINS, "/server/start", "/server/") == 1, "match: contains at start");
	check(p_match(TAINT_MATCH_CONTAINS, "/x/server/", "/server/") == 1, "match: contains at end");
	check(p_match(TAINT_MATCH_CONTAINS, "server", "/server/") == 0, "match: contains no slashes");
	check(p_exec_match(TAINT_MATCH_EXACT, "git", "git") == 1, "exec match: comm exact hit");
	check(p_exec_match(TAINT_MATCH_EXACT, "redact", "redact") == 1, "exec match: argv0 exact hit");
	check(p_exec_match(TAINT_MATCH_EXACT, "/tmp/ape/git", "git") == 0, "exec match: full path is not exact");
}

static void test_mask(void)
{
	// req = A&B (bits 0,1), forbid = C (bit 2)
	unsigned long long req = 0b011, forbid = 0b100;
	check(taint_mask_ok(0b011, req, forbid) == 1, "mask: A&B, no C -> ok (violation fires)");
	check(taint_mask_ok(0b001, req, forbid) == 0, "mask: only A -> req unmet");
	check(taint_mask_ok(0b111, req, forbid) == 0, "mask: A&B but C set -> forbidden");
	check(taint_mask_ok(0b011, 0, 0) == 1, "mask: empty req/forbid always ok");
	// 'not REVIEWED' style: req=UNTRUST(bit0), forbid=REVIEWED(bit1)
	check(taint_mask_ok(0b01, 0b01, 0b10) == 1, "mask: UNTRUST & not REVIEWED -> fire");
	check(taint_mask_ok(0b11, 0b01, 0b10) == 0, "mask: endorsed REVIEWED -> suppressed");
}

/* rule @arg tokens are NUL-padded to TAINT_ARG_LEN in the kernel; pad here too. */
static int arg_m(const char *slots, const char *tok)
{
	char t[TAINT_ARG_LEN] = {0};
	strncpy(t, tok, TAINT_ARG_LEN - 1);
	return taint_arg_match(slots, t);
}
static void test_arg(void)
{
	// argv blob is NUL-separated tokens; tokenize into fixed slots, then match.
	char blob[TAINT_ARGV_CAP] = {0};
	char slots[TAINT_ARG_SLOTS_BUF] = {0};
	memcpy(blob, "git\0push\0--force", 3 + 1 + 4 + 1 + 7);
	te_tokenize_args(blob, 3 + 1 + 4 + 1 + 7, slots);
	check(arg_m(slots, "push") == 1, "arg: push present");
	check(arg_m(slots, "--force") == 1, "arg: --force present");
	check(arg_m(slots, "commit") == 0, "arg: commit absent");
	check(arg_m(slots, "pus") == 0, "arg: partial token not matched");
	check(arg_m(slots, "") == 1, "arg: empty token matches anything");
	char blob2[TAINT_ARGV_CAP] = {0}, slots2[TAINT_ARG_SLOTS_BUF] = {0};
	memcpy(blob2, "git\0commit", 3 + 1 + 6);
	te_tokenize_args(blob2, 3 + 1 + 6, slots2);
	check(arg_m(slots2, "commit") == 1, "arg: commit present");
	check(arg_m(slots2, "push") == 0, "arg: push absent");
}

/* The config blob is memcpy'd from the Rust `repr(C)` mirror into this struct and
 * read out of BPF rodata, so a field reorder silently reinterprets every field
 * even though the total size is unchanged (the `fixed-size` Rust test only pins
 * the total). Pin the field layout, both structs' sizes, and the nested table
 * offsets. These values are what crates/actplane-ifc-compiler/src/dsl/lower.rs
 * asserts from its own side (`abi_layout_matches_the_c_header`); if this header
 * changes, both must be updated together. */
static void test_abi_layout(void)
{
	check(offsetof(struct taint_update, op) == 0, "abi: update.op @0");
	check(offsetof(struct taint_update, match) == 1, "abi: update.match @1");
	check(offsetof(struct taint_update, target) == 2, "abi: update.target @2");
	check(offsetof(struct taint_update, arg) == 66, "abi: update.arg @66");
	check(offsetof(struct taint_update, add) == 96, "abi: update.add @96");
	check(offsetof(struct taint_update, del) == 104, "abi: update.del @104");
	check(offsetof(struct taint_update, gates) == 112, "abi: update.gates @112");
	check(offsetof(struct taint_update, invals) == 120, "abi: update.invals @120");
	check(offsetof(struct taint_update, ipv4) == 128, "abi: update.ipv4 @128");
	check(offsetof(struct taint_update, ipv4_mask) == 132, "abi: update.ipv4_mask @132");
	check(offsetof(struct taint_update, gate_exit_code) == 136, "abi: update.gate_exit_code @136");
	check(offsetof(struct taint_update, domain_id) == 140, "abi: update.domain_id @140");

	check(offsetof(struct taint_rule, op) == 0, "abi: rule.op @0");
	check(offsetof(struct taint_rule, match) == 1, "abi: rule.match @1");
	check(offsetof(struct taint_rule, cond_kind) == 2, "abi: rule.cond_kind @2");
	check(offsetof(struct taint_rule, cond_neg) == 3, "abi: rule.cond_neg @3");
	check(offsetof(struct taint_rule, cond_match) == 4, "abi: rule.cond_match @4");
	check(offsetof(struct taint_rule, effect) == 5, "abi: rule.effect @5");
	check(offsetof(struct taint_rule, target) == 6, "abi: rule.target @6");
	check(offsetof(struct taint_rule, arg) == 70, "abi: rule.arg @70");
	check(offsetof(struct taint_rule, cond_pat) == 94, "abi: rule.cond_pat @94");
	check(offsetof(struct taint_rule, req) == 160, "abi: rule.req @160");
	check(offsetof(struct taint_rule, forbid) == 168, "abi: rule.forbid @168");
	check(offsetof(struct taint_rule, gate) == 176, "abi: rule.gate @176");
	check(offsetof(struct taint_rule, rule_id) == 184, "abi: rule.rule_id @184");
	check(offsetof(struct taint_rule, ipv4) == 188, "abi: rule.ipv4 @188");
	check(offsetof(struct taint_rule, ipv4_mask) == 192, "abi: rule.ipv4_mask @192");
	check(offsetof(struct taint_rule, cond_ipv4) == 196, "abi: rule.cond_ipv4 @196");
	check(offsetof(struct taint_rule, cond_ipv4_mask) == 200, "abi: rule.cond_ipv4_mask @200");
	check(offsetof(struct taint_rule, gate_idx) == 204, "abi: rule.gate_idx @204");
	check(offsetof(struct taint_rule, domain_id) == 208, "abi: rule.domain_id @208");
	check(offsetof(struct taint_rule, since_mask) == 216, "abi: rule.since_mask @216");

	check(sizeof(struct taint_update) == 144, "abi: sizeof taint_update");
	check(sizeof(struct taint_rule) == 224, "abi: sizeof taint_rule");
	check(offsetof(struct taint_config, n_updates) == 0, "abi: config.n_updates @0");
	check(offsetof(struct taint_config, n_rules) == 4, "abi: config.n_rules @4");
	check(offsetof(struct taint_config, updates) == 8, "abi: config.updates @8");
	check(offsetof(struct taint_config, rules) == 46088, "abi: config.rules @46088");
	check(sizeof(struct taint_config) == 74760, "abi: sizeof taint_config");
}

int main(void)
{
	printf("=== ActPlane taint predicate tests ===\n");
	test_streq();
	test_prefix();
	test_match();
	test_mask();
	test_abi_layout();
	printf("\n%d passed, %d failed\n", passed, failed);
	return failed == 0 ? 0 : 1;
}
