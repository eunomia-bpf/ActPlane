# ActPlane Agent-Policy Corpus

本目录是 ActPlane 论文用的**实证语料**：流行的 **AI agent 代码项目**（非纯文档/列表）所附带的 `CLAUDE.md` / `AGENTS.md`（agent 指令文件），按 star 从高到低收集。用于回答"开发者实际用自然语言给 agent 写了哪些*行为约束*，其中多少能在内核 IFC 层强制"。完整研究方法学见 [`../docs/agent-policy-survey.md`](../docs/agent-policy-survey.md)；本文件记录**这一份语料是如何收集的、如何复现**。

> 当前快照：采集于 2026‑05（UTC），star 降序扫了 ~349 个候选，**150 个**真实 agent 代码项目带 `CLAUDE.md`/`AGENTS.md`（star 374k→9.7k）。其中 **149 进入语料**，1 个（`cline/cline`，纯 `@`‑指针文件）按"无信息"清理排除。锚点是 **`openclaw/openclaw`**（★374k，2025‑11 起，2026 年的爆发式 agent 平台，formerly Moltbot/ClawdBot）。

## 目录结构（每仓一个文件夹）

```
corpus/
  collect.sh                 # 采集脚本（唯一事实来源，可复现）
  manifest.jsonl             # 150 行，每行一个仓库的 meta（机读聚合，含 excluded 标记）
  queries.log                # 每条 GitHub API 查询串 + 时间戳（可复现）
  exclusions.log             # 被过滤掉的候选 + 原因（可审计）
  <owner>__<repo>/           # 每个仓库一个文件夹
    CLAUDE.md                #   原始文件（如有）
    AGENTS.md                #   原始文件（如有）
    meta.json                #   该仓元数据（见下）
```

`<owner>/<repo>` 中的 `/` 用 `__` 替换作目录名（如 `openclaw__openclaw`）。

## `meta.json` 字段

```jsonc
{
  "repo": "openclaw/openclaw",
  "owner": "openclaw", "name": "openclaw",
  "stars": 374046,                 // 采集时 stargazers_count（流行度主指标，仅代理）
  "forks": ..., "open_issues": ..., // 真实度信号（见过滤规则）
  "created_at": "2025-11-24T...",  // 仓库创建时间（真实度信号）
  "language": "TypeScript",
  "license": "mit",
  "fork": false, "archived": false,
  "pushed_at": "...",              // 最近活跃
  "default_branch": "main",
  "html_url": "...", "description": "...", "topics": [...],
  "seed": true,                    // 是否来自人工种子清单（见下）
  "domain": "",                    // 领域标签，分析阶段人工填（见 survey §2.4）
  "retrieved_at": "2026-05-...Z",  // 采集时间
  "files": [                       // 每个采到的指令文件一条，带完整 provenance
    { "family": "AGENTS.md", "path": "AGENTS.md",
      "blob_sha": "...",           // git blob 内容哈希
      "byte_size": 18138,
      "last_commit_sha": "...",    // 最后修改该文件的 commit（钉死版本，可复现）
      "last_commit_date": "...",
      "content_sha256": "...",     // 本地落盘内容的 sha256（去重 + 校验）
      "raw_url": "https://raw.githubusercontent.com/<repo>/<last_commit_sha>/<path>" }
  ]
}
```

每条数据都带 **provenance**（commit SHA + 内容哈希 + 采集时间 + raw URL），这是可复现/可审计的底线。

## 采集流水线（`collect.sh`）

全程脚本化、用已认证的 `gh` CLI，**不靠 LLM 乱爬**。`bash collect.sh [N]`（N 为目标命中数，可选；本快照用 150，数目不强求，靠下面的过滤而非固定 N 来定语料）：

1. **候选枚举**：对一组 topic/关键词查询调 `search/repositories`（`sort=stars` 降序），如 `topic:ai-agent`、`topic:llm-agent`、`topic:mcp`、`openclaw`、`claw agent`、`AI agent framework` 等。每条查询串 + 时间戳写入 `queries.log`。
2. **人工种子**：一组已确证为真的 agent 代码项目（**OpenClaw 生态** openclaw/lobster/ClawWork/ClawTeam/NemoClaw/HiClaw/ClawX/ClawRouter/OpenClaw‑RL/zeroclaw… + 经典框架/工具 OpenHands/aider/cline/AutoGPT/langchain/dify/codex/gemini‑cli…）。种子**绕过类型/真实度过滤**（已知为真），但仍需真的带指令文件才会被收。
3. **合并去重 + 按 star 降序排名**（`group_by(full_name)|sort_by(-stars)`）。
4. **候选层三道过滤 + 下载后一道"无信息"清理**（见下），逐个候选探测仓库根目录是否有 `CLAUDE.md` / `AGENTS.md`（`contents` API），命中即下载原文、取 blob/commit/内容哈希、写 `meta.json`。
5. 收满 **N 个命中**即停（本快照 N=150，探测了 ~349 个候选，排除 53）。
6. 由所有 `meta.json` 重建 `manifest.jsonl`（带 `excluded` 标记）。

### 过滤规则（关键：AI‑agent 领域 star 造假严重）

> 这个领域是热点、可变现，**fake‑star / SEO 仓库泛滥**。`sort:stars` 原始结果里混入大量刷星/灌水仓（如 1 个月龄就 5 万星的未知仓、"fastest repo in history" 之类）。语料必须显式过滤，否则不可信。

1. **类型过滤（代码项目，非纯文档）**：主语言为 `null`/`Markdown` 直接排除；仓名/topic 命中聚合类正则（`awesome|list|prompt|tutorial|roadmap|book|course|cheatsheet|skills?$|collection|examples?$|boilerplate|template|/agents$|…`）排除。
2. **真实度过滤（反 fake‑star，保守，种子豁免）**，命中任一即排除：
   - `forks > 0.8×stars`（批量刷 fork 机器人，如 daily_stock_analysis 37k forks≈38k stars）；
   - `stars > 40k 且 open_issues < 20`（大体量却零社区互动，如某 188k 星仓仅 14 issues）；
   - `创建 ≤ 2 个月 且 stars > 40k`（不可能的增长速度，如多个 1 月龄 5 万星未知仓）。
3. **人工裁定排除清单 `EXCLUDE_LIST`**：把已确证的 fake/SEO 仓与漏网的 doc/skill 合集显式列出（如 `affaan-m/ECC`、`ultraworkers/claw-code`、各 `awesome-*`、`*-best-practice`、`*-skills`）。

被规则 1–3 排除的候选都写进 `exclusions.log`（含原因），可审计、可复现。

4. **"无信息"清理（下载后，数据质量过滤）**：仅排除**没有任何可分析指令内容**的文件——纯指针（如 `cline/cline` 只有 `@.clinerules/...`）、空文件、纯标题。判据是 **"≥1 条任意类型的指令行"**，**与文件大小无关、与是否是行为约束无关**。150 个里只有 1 个（`cline`）命中，标 `excluded:true` 但保留在盘上（非破坏性）。

> **关键（论文角度）：只清理"无信息"，绝不按"是否有行为约束"过滤。** 后者是"对因变量做筛选"，会把"X% 的 agent 文件含行为约束"这个数字灌水，评审会毙。因此像 `openai-agents-python`(29KB)、`vercel/ai`、`pydantic-ai` 这种**内容很多但 0 条行为约束**（全是 SDK 用法/风格）的文件**必须保留**——它们是诚实的"0 行为约束"数据点，删了就是 cherry-pick。
>
> **报告两个数字**：(a) 在**全语料**（149）上报行为约束的分布（含 0），作为无偏分母——粗测 **~58% 含 ≥1 条行为约束**、~42% 仅风格/构建；(b) 取 **≥3 条行为约束的子集（~46）**做 taxonomy + eval 场景，并**明确声明该子集"以含行为约束为条件"**。两数字严格分离。

> 真实度过滤是**保守**的：宁可漏掉个别真实但"低 issue/激进关 issue"的项目（如某些工具库），也不放进刷星仓。注意 OpenClaw 这类**真实但增长极快**的项目靠"种子豁免"保留——单纯的"年轻+高星=假"启发式在本领域不可靠。

## 复现

```bash
cd corpus && bash collect.sh 150     # 需要已 `gh auth login`
```

结果对采集时点敏感（star 数、HEAD 会变）；`meta.json` 里每个文件都钉了 `last_commit_sha`，可经 `raw_url` 取回当时的精确版本。`queries.log` / `exclusions.log` 记录了完整的查询与排除轨迹。

## 已知局限 / 待办

- **仅 GitHub、仅 `CLAUDE.md`+`AGENTS.md`、英文为主、流行度（star）偏置、单一时点快照**——见 survey §8 威胁有效性。
- **真实度过滤不完美**：有少量假阳（真实工具因 issue 数低被排）、也可能有个别漏网的刷星/doc 仓进入榜单（post‑cutoff 的新仓难以仅凭机器信号判定）。当前榜单中以下几个**待人工确认**（可能是真实的新生 agent，也可能偏 doc/config）：`code-yeongyu/oh-my-openagent`、`Yeachan-Heo/oh-my-claudecode`、`luongnv89/claude-howto`、`earendil-works/pi`、`rtk-ai/rtk`、`abhigyanpatwari/GitNexus`、`multica-ai/multica`。
- 下一步（见 survey §4–§7）：对每个文件抽取规则、按 D1–D7 编码（含可强制性三层 Observable/Expressible/Robust）、算 κ 信度，再导出 eval 场景。
```
