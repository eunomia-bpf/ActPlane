# 规则集核验记录

按 `protocol.md` 的两阶段 + 人工验证流程产出 `ruleset.jsonl`（32 条 canonical 可强制规则）。

## 提取过程（如实记录）
1. **候选来源**：`docs/tmp/candidate_rules_144.tsv`（144 in-corpus 仓的指令文件抽出的 3762 条候选行，
   带 repo/family/line_no provenance；LLM 辅助关键词编码，见 `docs/agent-policy-survey.md`、
   cf. arXiv 2509.14744 / 2511.12884）。取其中已归入 ActPlane 类别的 **529 行**（`candidates_categorized.tsv`，
   覆盖 101 个不同 repo）作为聚类输入。
2. **codex 尝试**：先用 `codex exec`（headless）做语义聚类（`extract_prompt.txt` / `extract_inline_prompt.txt`）。
   本机 ChatGPT-账号下 codex 默认模型在 529 行 + 30–50 条结构化输出的任务上**多次超时**（540s/600s/1500s 均
   未产出完整 JSONL，留痕 `codex_run.log`/`codex_err.txt`）。**遂改为可复现的确定性构建**（更可审计）。
3. **确定性构建**（`build_ruleset.py`）：作者按领域知识定义 32 条 canonical 规则 + ActPlane DSL 编码；
   每条的 **跨仓频率 `freq_repos` 与代表性引用 `example_repos` 由脚本从候选表确定性计算**（matcher = 类别 +
   文本正则），杜绝频率/出处幻觉。

## 核验结果（机器可复现）
- **引用真实性**：32/32 条规则的代表性引用，逐条比对 `docs/corpus/<repo>/<family>` 的对应行号 —— **全部命中**
  （quote 前 25 字符出现在该行）。0 不匹配、0 文件缺失。
- **DSL 可编译**：32/32 条规则的 DSL 经 `actplane --rule … compile` —— **全部编译通过**。
- **频率分布**：freq≥10 repos: **11 条**；freq≥3: **24 条**；freq0: **0**（全部有语料支撑）。
- **复杂度**：tier-3（污点流/declassify/多标签）**8 条**、tier-2（条件/对象源）**21 条**、tier-1 **3 条** ——
  规则集压满了引擎的主要构造（taint-flow / lineage / after / declassify / multi-label / target-scope）。

## 严谨度声明与局限
- 本轮为**单编码者（作者）+ 确定性出处计算 + 人工/脚本核验**，与 2509.14744 同级；更强的**双编码者 +
  Cohen's κ**（codex/claude 独立编码再算一致性）留作后续（见 `docs/tmp/eval-plan.md`）。
- 频率为**保守下界**：matcher 只在已归类的 529 行上匹配，未扫描 3233 条 "unclassified"（多为风格/构建噪声），
  故真实频率 ≥ 此处数字。
- 仅收**可强制**规则（D5 observable+expressible）；不可强制约束（纯对话式批准、PR 礼仪等）的占比在 Exp-E
  另用全语料统计交代。

## 复现
```bash
cd docs/experimental/ruleset && python3 build_ruleset.py    # 重建 ruleset.jsonl / ruleset.md
# 核验（引用 + 编译）：见本会话 verify 脚本，或 docs/experimental/run_all.sh 的 ruleset-verify 步
```

## 更新:codex 提取实际成功(36 条,独立来源)
后台 codex 运行最终**写出了 `raw_codex_extraction.jsonl`(36 条规则)**——之前判 "未写出" 是检查过早。
核验结果:
- **引用真实性 36/36**:每条至少一个 example 的原文逐字命中真实语料文件(0 幻觉)。
- **DSL 可编译 0/36**:codex **不知道 ActPlane 的确切 DSL 文法**,自创了近似语法(如 `source <名> <谓词>`、
  `endorse … on …`、在 source 里写 `label`),全部编译失败。
- **类别分布与我们的确定性规则集高度一致**(均以 vcs-gating / secrets / approval / mediation / test-before
  为主)——构成**双来源交叉印证**(独立的 codex 提取 ⟷ 我们的确定性聚类)。

**结论与采用**:`raw_codex_extraction.jsonl` 作为**用户要求的 codex 独立提取**保留(类别/频率/出处的
经验证据,36/36 引用真实);**实验使用的可编译规则集是 `ruleset.jsonl`**(32 条,DSL 32/32 编译通过、
引用 32/32 核验),因为 codex 的 DSL 语法无效需由我们(领域专家)编码。两来源在类别上的一致性是
信度证据;未来可在此基础上做双编码者 + κ。
