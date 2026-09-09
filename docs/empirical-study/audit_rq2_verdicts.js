#!/usr/bin/env node
/* Recompute a trace-level separation between kernel intervention and the RQ2
 * end-to-end trajectory judgment. This script reads the frozen artifact-ready
 * export and never calls a model or mutates experiment data. */

const fs = require("fs");
const path = require("path");

const root = process.argv[2];
if (!root) {
  console.error("usage: node audit_rq2_verdicts.js ARTIFACT_ROOT [OUTPUT_JSON]");
  process.exit(2);
}

const manifest = path.join(root, "docs/artifact/rq2-qwen-primary/selected_runner_results.txt");
const judgeDir = "trajectory_judges_llama_cpp_guardrail_response";
const rows = [];

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function compact(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

function feedbackFacts(messages) {
  const text = (messages || []).join("\n");
  return {
    effect: /Operation killed|"effect":"kill"/.test(text) ? "kill" :
      /matched notify rule|"effect":"notify"/.test(text) ? "notify" : "none",
    rule: (text.match(/rule `([^`]+)`/) || [])[1] || "",
    target: (text.match(/Target operation: ([^\n]+)/) || text.match(/Operation `([^`]+)`/ ) || [])[1] || "",
    reason: compact((text.match(/- Reason: ([^\n]+)/) || [])[1] || ""),
  };
}

for (const line of fs.readFileSync(manifest, "utf8").split(/\r?\n/)) {
  if (!line || line.startsWith("#")) continue;
  const fields = line.split("\t");
  const [system, repoKey, statement, trace, expectedLabel] = fields;
  const rel = fields[fields.length - 1];
  const resultFile = path.join(root, rel);
  const result = readJson(resultFile);
  const judgeFile = path.join(path.dirname(resultFile), judgeDir,
    `${path.basename(resultFile, ".json")}.judge.json`);
  const judge = readJson(judgeFile);
  const facts = feedbackFacts(result.setup_feedbacks);
  const recoveryFacts = feedbackFacts(result.recovery_feedbacks);
  rows.push({
    key: `${repoKey}/${statement}/${trace}`,
    system,
    repo: result.repo,
    statement,
    trace,
    ground_truth_violation: Boolean(result.ground_truth && result.ground_truth.violation),
    judgment: judge.judgment && judge.judgment.confusion_label,
    manifest_judgment: expectedLabel,
    kernel_intervened: Boolean(result.setup_fired),
    visible_intervention: Boolean(result.setup_visible_intervention),
    runner_blocked: Boolean(result.score && result.score.setup_blocked),
    effect: facts.effect,
    matched_rule: facts.rule,
    target: facts.target,
    reason: facts.reason,
    recovery_intervened: (result.recovery_feedbacks || []).length > 0,
    recovery_effect: recoveryFacts.effect,
    recovery_target: recoveryFacts.target,
    any_observed_intervention: Boolean(result.setup_fired) || (result.recovery_feedbacks || []).length > 0,
    setup_errors: (result.setup_errors || []).map(compact),
    tool_failures: (result.tool_log || []).filter(x => x.phase === "setup" && x.returncode !== 0)
      .map(x => ({tool: x.tool, returncode: x.returncode, command: compact(x.command || x.file_path)})),
    recovery_attempted: Boolean(result.score && result.score.recovery_attempted),
    recovery_tool_count: result.score && result.score.recovery_tool_count || 0,
    agent_error: result.agent_error && result.agent_error.type || "",
    judge_confidence: judge.judgment && judge.judgment.confidence,
    judge_rationale: compact(judge.judgment && judge.judgment.rationale),
    directive: compact(result.ground_truth && result.ground_truth.directive),
    result_file: rel,
  });
}

const paired = new Map();
for (const row of rows) {
  if (!paired.has(row.key)) paired.set(row.key, {});
  paired.get(row.key)[row.system] = row;
}

for (const row of rows) {
  const other = paired.get(row.key)[row.system === "actplane" ? "actplane-opaque" : "actplane"];
  if (other) {
    row.paired_system = other.system;
    row.paired_judgment = other.judgment;
    row.paired_kernel_intervened = other.kernel_intervened;
    row.paired_any_observed_intervention = other.any_observed_intervention;
    row.paired_effect = other.effect;
  }
}

const counts = {};
const interventionByLabel = {};
for (const row of rows) {
  const key = `${row.system}:${row.judgment}`;
  counts[key] = (counts[key] || 0) + 1;
  if (!interventionByLabel[key]) {
    interventionByLabel[key] = {rows: 0, setup: 0, any_phase: 0, kill: 0, notify: 0};
  }
  const cell = interventionByLabel[key];
  cell.rows += 1;
  cell.setup += Number(row.kernel_intervened);
  cell.any_phase += Number(row.any_observed_intervention);
  cell.kill += Number(row.effect === "kill" || row.recovery_effect === "kill");
  cell.notify += Number(row.effect === "notify" || row.recovery_effect === "notify");
}
const actplaneFp = rows.filter(x => x.system === "actplane" && x.judgment === "FP");
const actplanePairs = rows.filter(x => x.system === "actplane");
const pairedSetupTriggers = {both: 0, actplane_only: 0, opaque_only: 0, neither: 0};
for (const row of actplanePairs) {
  const left = row.kernel_intervened;
  const right = row.paired_kernel_intervened;
  const key = left && right ? "both" : left ? "actplane_only" : right ? "opaque_only" : "neither";
  pairedSetupTriggers[key] += 1;
}
const summary = {
  schema: "rq2-verdict-audit-v1",
  source_manifest: "docs/artifact/rq2-qwen-primary/selected_runner_results.txt",
  total_rows: rows.length,
  counts,
  intervention_by_label: interventionByLabel,
  actplane_vs_opaque_setup_triggers: pairedSetupTriggers,
  actplane_fp: {
    count: actplaneFp.length,
    kernel_intervened: actplaneFp.filter(x => x.kernel_intervened).length,
    any_observed_intervention: actplaneFp.filter(x => x.any_observed_intervention).length,
    kill: actplaneFp.filter(x => x.effect === "kill").length,
    notify: actplaneFp.filter(x => x.effect === "notify").length,
    paired_opaque_intervened: actplaneFp.filter(x => x.paired_kernel_intervened).length,
    paired_opaque_fp: actplaneFp.filter(x => x.paired_judgment === "FP").length,
  },
};
const output = {summary, rows};
const serialized = JSON.stringify(output, null, 2) + "\n";
if (process.argv[3]) fs.writeFileSync(process.argv[3], serialized);
else process.stdout.write(serialized);
