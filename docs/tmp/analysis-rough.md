# 语料粗略分析（rough pass）

> **方法 & 重要声明**：这是**关键词抽取**的初步分析，**不是**最终的 D1–D7 人工编码（见 [`../docs/agent-policy-survey.md`](../docs/agent-policy-survey.md) §4–§5）。下面的类别计数基于正则匹配，**有噪声、是上界**（例如 `worktree`、`before committing` 很多命中的是构建/环境说明而非行为约束）。精确数字需要后续逐规则编码 + κ 信度。这里只回答一个粗问题：**流行 agent 项目的指令文件里，到底有没有、有多少 ActPlane 想强制的那类行为约束？**

## 0. 语料概览（快照 2026‑05）

- 51 个仓库（top‑50 by stars + `zeroclaw-labs/zeroclaw` 一个生态遗留，均真实），锚点 `openclaw/openclaw`（★374k）。
- 指令文件共 **16,644 行**（`CLAUDE.md`/`AGENTS.md`）。
- 含行为约束信号词（never/must/don't/only/before/without…）的候选行：**866 行**。

## 1. 主体是 coding-style / build，行为约束是少数——但**普遍存在**

抽样确认：866 条候选里**大多数是编码风格 / 构建流程**（"all code must be TypeScript"、"don't use `any`"、"imports at top"、"run pre-commit before committing"…）——这类 ActPlane **不管**（D1 = coding-style，out of scope）。这是预期的、也是诚实要讲的：指令文件主要在规约"怎么写代码"。

但**行为约束（agent 该做/不该做什么）真实且反复出现**：**36 / 50 个仓库**至少写了 1 条 ActPlane 相关的行为约束（粗略并集，上界）。即"用自然语言给 agent 设行为护栏"是流行项目的普遍实践，不是我们臆想的问题。

## 2. ActPlane 相关行为类别的出现频率（# 仓库，of 50；含噪声）

| 类别 | # 仓库 | 对应 ActPlane 例子 |
|------|:---:|------|
| secrets / `.env` / 凭据（勿读勿泄勿提交） | **19** | E1 no-exfil, E7 |
| 提交/推送需审批（不得擅自 commit/push） | **14** | E2, E5, E11 |
| 强制中介：只能经某工具/脚本 | **13** | E3 mandatory-mediation |
| 行动前需人工批准 | **11** | E2 endorse, E11 confirm |
| 破坏性 fs/db 操作（rm -rf / drop table…） | **10** | E11 |
| 提交/推送前必须先测试/lint/typecheck | **10** | E5 test-before-commit |
| git worktree / 分支管控 | **8** | E3/E11（多为噪声，慎用） |
| 不得直接提交/推送到 main/master | **6** | E5/E11 |
| force-push / 改写历史 | **4** | E11 destructive |
| 网络 / 外部调用限制 | **4** | E10, E1 |
| 工作区 / 路径限制 | **2** | E4 confinement |

> 噪声提示：`worktree`(8) 与"测试/lint before commit"(10) 含大量构建说明命中，应视为上界；`secrets`(19)、`审批门禁`(14)、`工具中介`(13)、`破坏性操作`(10) 信号较干净。

## 3. 关键结论：真实规则**落在 ActPlane 的构造类里**（验证 DSL 不是凭空造的）

开发者真正写的护栏 → ActPlane 的 source/sink/lineage/temporal/declassify：
- "**NEVER hardcode API keys**" / "勿提交 `.env`" → `source SECRET = file …` + `deny connect/write if SECRET`（E1/E7）。
- "**MUST NOT commit or push without explicit user request**"、"不得直推 main" → exec 门禁 + `@arg commit/push` + 条件（E5/E11）。
- "**Always run the full suite before pushing**"、"typecheck is critical before committing" → `after exec` 时序（E5）。
- "**must not create git worktrees without approval**"、"行动前先问" → `lineage-includes`/`endorse`（E2/E11）。
- "只能经迁移工具/脚本" → `lineage-includes exec`（E3）。

## 4. 可强制性（D5 粗判）

- **多数可在 ActPlane 强制**（Observable + Expressible）：secrets、commit/push 门禁、force-push、破坏性 fs、test-before-commit、工作区限制、网络出口、工具中介——都对应 exec/file/connect + lineage/temporal。
- **部分（看实现）**："行动前问用户/需人工批准"——若"批准"是一次可观测的 gate（执行某审批工具）则可强制（endorse/lineage）；若纯粹是"在聊天里问一句"则**不可在 syscall 层观测**（E-out）。
- **不可强制（E-out）**：PR 礼仪类（"别给别人的 issue 开 PR"、"别开重复 PR"）、纯代码质量/风格类。

## 5. 威胁有效性 / 下一步

- 关键词法**有噪声**、是上界；真实占比需 §4 的逐规则 D1–D7 编码 + 双编码者 κ。
- 仅 GitHub、仅 `CLAUDE.md`/`AGENTS.md`、英文为主、流行度偏置、单一时点。
- 候选行 `candidate_rules.tsv` 已落盘可复核。
- **下一步**：对每条规则做 D1–D7 编码（落 `rules.jsonl`），算 κ，再把 `D5 全真 ∧ D7 可诱发` 的导出为 eval 场景。
