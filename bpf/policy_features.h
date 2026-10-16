/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 eunomia-bpf org. */
/*
 * Single computation of the `policy_features` rodata bits from a compiled
 * `struct taint_config`.
 *
 * The production loader (`process.c`) uses these bits to decide which engine
 * programs to autoload; the verifier diagnostic loader (`vvload.c`) must load
 * exactly the programs the production loader would load, so it must compute the
 * same bits from the same policy. Sharing one definition is the only way to keep
 * the two in lockstep: an earlier copy inside vvload.c omitted the path-match and
 * open/write-rule bits and did not apply the argv-sensitive exec exemption, so
 * its diagnostic runs exercised a different program set than production.
 *
 * Included by user-space loaders and the unit tests only; the eBPF program
 * includes process.h directly and never sees this header.
 */
#ifndef __POLICY_FEATURES_H
#define __POLICY_FEATURES_H

#include "process.h"

static unsigned int path_match_features(unsigned int match)
{
	switch (match) {
	case TAINT_MATCH_CONTAINS: return TE_POLICY_PATH_CONTAINS;
	case TAINT_MATCH_SUFFIX: return TE_POLICY_PATH_SUFFIX;
	default: return 0;
	}
}

static unsigned int config_features(const struct taint_config *cfg)
{
	unsigned int features = 0;

	for (unsigned int i = 0; i < cfg->n_updates && i < MAX_TAINT_UPDATES; i++) {
		if (cfg->updates[i].op == TOP_OPEN || cfg->updates[i].op == TOP_WRITE)
			features |= TE_POLICY_FILE_FLOW |
				    path_match_features(cfg->updates[i].match);
		if (cfg->updates[i].op == TOP_CONNECT)
			features |= TE_POLICY_CONNECT;
		if (cfg->updates[i].op == TOP_RECV)
			features |= TE_POLICY_RECV;
	}
	for (unsigned int i = 0; i < cfg->n_rules && i < MAX_TAINT_RULES; i++) {
		if (cfg->rules[i].effect == TEFFECT_BLOCK) {
			/* argv-sensitive block exec rules cannot block pre-exec, so
			 * they do not pull in the bprm_check_security hook. */
			if (cfg->rules[i].op == TOP_EXEC && cfg->rules[i].arg[0] == '\0')
				features |= TE_POLICY_BLOCK_EXEC;
			if (cfg->rules[i].op == TOP_OPEN ||
			    cfg->rules[i].op == TOP_WRITE)
				features |= TE_POLICY_BLOCK_FILE;
			if (cfg->rules[i].op == TOP_CONNECT)
				features |= TE_POLICY_BLOCK_CONNECT;
		}
		if (cfg->rules[i].op == TOP_OPEN) {
			features |= TE_POLICY_OPEN_RULES |
				    path_match_features(cfg->rules[i].match);
			if (cfg->rules[i].cond_kind == TCOND_TARGET)
				features |= path_match_features(cfg->rules[i].cond_match);
		}
		if (cfg->rules[i].op == TOP_WRITE) {
			features |= TE_POLICY_FILE_FLOW |
				    TE_POLICY_WRITE_RULES |
				    path_match_features(cfg->rules[i].match);
			if (cfg->rules[i].cond_kind == TCOND_TARGET)
				features |= path_match_features(cfg->rules[i].cond_match);
		}
		if (cfg->rules[i].op == TOP_CONNECT)
			features |= TE_POLICY_CONNECT;
		if (cfg->rules[i].op == TOP_RECV)
			features |= TE_POLICY_RECV;
	}
	return features;
}

#endif /* __POLICY_FEATURES_H */
