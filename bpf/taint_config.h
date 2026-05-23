/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2026 eunomia-bpf org. */
#ifndef __TAINT_CONFIG_H
#define __TAINT_CONFIG_H

/*
 * ActPlane taint-rule configuration loader.
 *
 * Taint rules are configured from a YAML file (constrained subset) rather than
 * the command line, e.g.:
 *
 *   # codex and its descendants may not run git or ssh
 *   rules:
 *     - source: codex
 *       sink: git
 *       reason: "Codex may not use git; use the review workflow."
 *     - source: codex
 *       sink: ssh
 *
 * Each entry compiles to one `struct taint_rule` edge (source executable ->
 * forbidden sink executable). rule_id is the entry index and label is
 * (1 << rule_id). A source with several forbidden sinks is written as several
 * entries sharing the same `source`.
 *
 * The parser is libc-only (no libyaml dependency) so it is shared between the
 * userspace loader and the unit test (test_taint.c). It deliberately accepts
 * only the small schema above; richer policy authoring lives in the collector.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "taint.h"

/* Trim leading/trailing ASCII whitespace in place; returns pointer into s. */
static inline char *taint_cfg_trim(char *s)
{
	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;
	if (*s == '\0')
		return s;
	char *end = s + strlen(s) - 1;
	while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
		*end-- = '\0';
	return s;
}

/* Strip a single layer of matching surrounding quotes from s, in place. */
static inline char *taint_cfg_unquote(char *s)
{
	size_t n = strlen(s);
	if (n >= 2 && ((s[0] == '"' && s[n - 1] == '"') ||
		       (s[0] == '\'' && s[n - 1] == '\''))) {
		s[n - 1] = '\0';
		return s + 1;
	}
	return s;
}

/* Copy a comm value into a fixed TAINT_COMM_LEN field (NUL-terminated). */
static inline void taint_cfg_set_comm(char *dst, const char *src)
{
	strncpy(dst, src, TAINT_COMM_LEN - 1);
	dst[TAINT_COMM_LEN - 1] = '\0';
}

/*
 * Parse the YAML text into `out`. Returns the number of rules on success
 * (0..max_rules), or -1 on a malformed entry (a sink without a source).
 * Unknown keys and the top-level `rules:` line are ignored.
 */
static inline int taint_config_parse_str(const char *text, struct taint_rule *out,
					 int max_rules)
{
	int count = 0;
	const char *p = text;
	char line[512];

	while (*p) {
		/* read one line into the buffer */
		size_t i = 0;
		while (*p && *p != '\n' && i < sizeof(line) - 1)
			line[i++] = *p++;
		line[i] = '\0';
		if (*p == '\n')
			p++;

		/* drop comments */
		char *hash = strchr(line, '#');
		if (hash)
			*hash = '\0';

		char *t = taint_cfg_trim(line);
		if (*t == '\0')
			continue;

		int new_item = 0;
		if (t[0] == '-') {
			new_item = 1;
			t++;                       /* skip '-' */
			t = taint_cfg_trim(t);     /* remainder may hold "source: x" */
			if (*t == '\0') {
				/* "-" alone: open a fresh, empty rule */
				if (count >= max_rules)
					break;
				memset(&out[count], 0, sizeof(out[count]));
				out[count].rule_id = (unsigned int)count;
				out[count].label = 1ULL << count;
				count++;
				continue;
			}
		}

		char *colon = strchr(t, ':');
		if (!colon)
			continue;
		*colon = '\0';
		char *key = taint_cfg_trim(t);
		char *val = taint_cfg_unquote(taint_cfg_trim(colon + 1));

		if (strcmp(key, "rules") == 0)
			continue;

		if (new_item) {
			if (count >= max_rules)
				break;
			memset(&out[count], 0, sizeof(out[count]));
			out[count].rule_id = (unsigned int)count;
			out[count].label = 1ULL << count;
			count++;
		}

		if (count == 0)
			return -1; /* key/value before any list item */

		struct taint_rule *r = &out[count - 1];
		if (strcmp(key, "source") == 0)
			taint_cfg_set_comm(r->source_comm, val);
		else if (strcmp(key, "sink") == 0)
			taint_cfg_set_comm(r->sink_comm, val);
		/* "reason" and any other keys are kept in the DSL layer, not here */
	}

	return count;
}

/* Read and parse a config file. Returns rule count, or -1 on error. */
static inline int taint_config_parse_file(const char *path, struct taint_rule *out,
					  int max_rules)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		return -1;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	long sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return -1;
	}
	rewind(f);
	char *buf = (char *)malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return -1;
	}
	size_t rd = fread(buf, 1, (size_t)sz, f);
	buf[rd] = '\0';
	fclose(f);

	int n = taint_config_parse_str(buf, out, max_rules);
	free(buf);
	return n;
}

#endif /* __TAINT_CONFIG_H */
