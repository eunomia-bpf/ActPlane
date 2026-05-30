# 规则集提取协议（ActPlane eval 的 benchmark 基石）

> 目的：从 ActPlane 实证语料（`docs/corpus`，144 个真实 agent 项目的 `CLAUDE.md`/`AGENTS.md`）
> **可复现、可 cite** 地提取一组**真实存在、带 provenance**的行为约束规则，作为后续所有实验
> （Exp-A 跨路径覆盖、Exp-C 误报/放行、Exp-D agent 闭环、Exp-E 表达力）的工作负载。
> **这组规则不是自造的**——每条都追溯到具体 repo + 原文引用 + 跨仓频率。

## 1. 采样框（sampling frame）
- 全部 **144 个 in-corpus 仓库**（`docs/corpus/manifest.jsonl` 中 `excluded:false`）。
- 分析对象：每仓的 `CLAUDE.md` 和/或 `AGENTS.md` 原文（采集方法学见 `docs/corpus/README.md`、
  `docs/agent-policy-survey.md`；带 commit SHA + 内容哈希 + raw URL 的 provenance）。

## 2. 分析单元与纳入/排除标准
- **单元**：一条"行为约束"= 约束 agent **可以/必须/禁止**做什么的指令。
- **纳入**：D1 = ActPlane 相关的行为约束（VCS 门禁、secrets/凭据、强制中介、test/lint-before、
  只读、破坏性操作、网络出口、工作区限制、任务隔离、审批门 …）**且可强制**——
  D5 = Observable（syscall 层可观测：exec/open/write/connect）∧ Expressible（可用 DSL 表达）。
- **排除**：纯编码风格/构建说明（"用 TypeScript"、"imports 放顶部"）；纯文档/架构概述；
  **不可在 syscall 层观测**的约束（纯对话式"先问用户"、PR 礼仪、代码质量主观判断）。
  （本轮规则集**只收可强制的**；不可强制的占比在 Exp-E 另用全语料统计交代。）

## 3. 提取流程（两阶段，对齐既有工作）
LLM 辅助编码是 CLAUDE.md 实证研究的既有做法（**Chatlatanagulchai et al. arXiv 2509.14744**、
**arXiv 2511.12884** 均用 LLM 生成标签；**Ahmed et al. MSR'25**："LLMs 能否替代 SE 工件的人工标注"）。
本协议采用两阶段 + 人工验证：

1. **候选抽取（codex）**：`codex exec` 通读 144 仓的指令文件，对每条命中纳入标准的指令产出一条
   候选记录，含**原文逐字引用 + 来源 repo + 文件**。
2. **跨仓聚合**：把语义等价的候选合并为一条 *canonical rule*，记录其**跨仓频率**（出现在多少个
   不同 repo）与若干代表性出处。
3. **人工验证（本作者）**：逐条核验——(a) 引用原文**确实存在**于所标 repo 的所标文件（防 LLM 幻觉）；
   (b) repo 归属正确；(c) 跨仓频率可由语料复算。核验不过的候选**剔除或修正**，记录在
   `verification.md`。
4. **DSL 编码**：为每条 canonical rule 写出 ActPlane DSL，并标注用到的构造、复杂度档、D5 层级。

> 严谨度声明：本轮为**单编码者（codex）+ 人工验证**，与 2509.14744 同级。更强的双编码者 +
> Cohen's κ 信度留作后续（见 `docs/tmp/eval-plan.md`）。

## 4. 复杂度优先
刻意覆盖 ActPlane 引擎的**全部构造**，不止 `deny exec`。每条标 `complexity_tier`：
- **T1**：单 op + 标签（`deny exec "**/git" @arg "push" if AGENT`）。
- **T2**：+ 条件（`unless after exec`、`lineage-includes`、`target` 作用域）或对象源（file/endpoint）。
- **T3**：**信息流**（source→propagate→sink，如 secrets→connect/write）、**declassify/endorse**、
  **多标签**（任务隔离 `if A and B`）。
规则集应包含足量 T2/T3，使 Exp-A/C 真正压满污点传播 / lineage / after / declassify / 多标签。

## 5. 输出格式（`ruleset.jsonl`，每行一条 canonical rule）
```jsonc
{
  "id": "R07",
  "canonical": "禁止把 .env / 凭据内容外发（提交或联网）",
  "category": "secrets-egress",            // D1 类别
  "freq_repos": 40,                        // 跨仓频率（# distinct repos）
  "examples": [
    {"repo":"owner/x","file":"CLAUDE.md","quote":"NEVER commit .env files or hardcode secrets"},
    {"repo":"owner/y","file":"AGENTS.md","quote":"…"}
  ],
  "dsl": "source SECRET = file \"**/.env\"\nrule no-exfil:\n  deny connect endpoint \"*\" if SECRET\n  effect kill\n  reason \"...\"\ndeclassify SECRET by exec \"**/redact\"",
  "dsl_constructs": ["object-source","taint-flow","connect-sink","declassify"],
  "complexity_tier": 3,
  "enforceable": "observable+expressible",  // D5
  "inducible": true                         // D7: 能否在实验里诱发违规（Exp-A/D 需要）
}
```

## 6. 产物
- `ruleset.jsonl`（机读，规范规则集）+ `ruleset.md`（人读汇总表）。
- `raw_codex_extraction.jsonl`（codex 原始候选输出，留痕）。
- `verification.md`（人工核验记录：核过/剔除/修正 + 复算的频率）。
- 目标 **30–50 条** canonical rules，T2/T3 占多数。

## 7. 复现
```bash
# 候选抽取
codex exec --skip-git-repo-check -c 'sandbox_mode="read-only"' < extract_prompt.txt
# 人工核验 + 聚合 + DSL 编码 -> ruleset.jsonl（脚本/手工，记录在 verification.md）
```
所有提取/核验脚本与 codex 原始输出入库，规则可由 `docs/corpus` 复算。
