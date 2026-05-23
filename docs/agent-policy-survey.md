# Agent 指令文件实证调研 —— 设计文档（CLAUDE.md / AGENTS.md）

> 状态：**设计稿（尚未执行采集）**。本文件定义"收集什么、如何收集、元数据如何保存、如何分析"的完整方法，目标是达到可写进 OSDI 论文 §2(motivation) 与 §6(evaluation workload) 的严谨程度，并且**可复现 / 可 artifact-evaluate**。

---

## 0. 定位与校准（先把 OSDI 标准说清楚）

这份调研**不是论文的 contribution**。ActPlane 的贡献是"在工具层之下、以内核 IFC taint 强制 agent 行为不变量，并把违规理由回灌做纠偏"。本调研只承担两件事：

1. **Motivation grounding**：用真实数据证明"流行项目确实在用自然语言文件（CLAUDE.md / AGENTS.md）编码 agent 的*行为约束*"，而不是我们臆想的问题。
2. **Eval workload derivation**：把真实规则蒸馏成"可强制 ∧ 可诱发"的子集，作为 §6 的评测负载（policy + 任务），从根上回应"你是不是只测了自己造的、刚好能强制的规则"这一质疑。

因此本调研的严谨度按"系统论文里的实证测量小节"来要求，而不是按一篇独立的 MSR/ICSE 挖掘研究来要求。具体门槛：

- **可复现**：采集脚本化、数据冻结快照、每条记录带 provenance、容器一键复现所有数字（瞄准 AE "Results Reproduced" 徽章）。
- **不过度声称**：语料只能证明"开发者*写了*什么约束"，**不能**证明"agent *违反*了多少"——后者是 eval 才能给的。两类论断在文中严格分离。
- **诚实边界**：文件是 *aspirational*（开发者期望），且我们**刻意不区分**规则是人写还是 LLM 生成的（二者不可靠区分，见 §8）；我们把每个文件当作"该项目对外声明的策略"，无关作者身份。

> 关键诚实风险：若语料最终显示绝大多数规则属于"不可在我们这层强制"（语义/风格类），则*强制*这条故事会变弱，正确做法是据实调整 framing（见 §10 风险）。所以 §10 安排了先做 20 仓库 pilot 再决定是否全量。

---

## 1. 研究问题（驱动每一个字段）

| RQ | 问题 | 服务于 |
|----|------|--------|
| RQ1 | 真实 CLAUDE.md / AGENTS.md 里，*行为约束*相对风格/构建/架构说明各占多少？ | §2：坐实"约束以散文形式存在" |
| RQ2 | 开发者实际写出哪些类别的行为约束？ | §3 DSL 表达力的正当性（E1–E12 不是凭空造的） |
| RQ3 | 其中多大比例在 syscall/LSM 边界*可观测、可表达、可无误报强制*？ | **覆盖率** + 诚实的能力边界 |
| RQ4 | 可强制的那些里，有多少属于"跨 bash/subprocess/SDK"才成立、工具层守卫会漏的？ | 论证"为何要在工具层之下" |
| RQ5 | 哪些规则是*可诱发*的（真实任务里 agent 会自然违反）？ | §6 评测场景集 |

每一个后面报告的数字，都必须能对应到 §2 或 §6 的**某一句具体论断**；没有对应论断的数字不收集。

---

## 2. 采样框架（Sampling frame）

### 2.1 总体（population）
GitHub 上的**公开仓库**，满足：(a) 仓库根目录或约定位置含 `CLAUDE.md` 或 `AGENTS.md`；(b) 是**真实代码项目**（见 2.3 判据），非纯文档/列表/prompt 集合。

### 2.2 流行度定义（"用的人多"如何量化）
"用的人多"≠ star，但 star 是最可得的代理。采用**组合指标**，主用 star、辅以其余做 robustness check：

- **主指标**：GitHub stars（关注度代理；本调研按其降序取前 50）。
- **辅指标（稳健性核查，子样本上看）**：库类项目的下游依赖数 / 包下载量（npm、PyPI、crates）；fork 数；`pushed_at` 近 6 个月活跃度。
- 在文中**明确声明** star 只是代理，并用辅指标核查头部排序是否被 star 严重误导。

### 2.3 "代码项目（非纯文档）"判据 —— 本轮新增的关键过滤
高 star 的"AI agent"结果里有大量 awesome 列表、prompt 合集、教程书、roadmap，它们会污染语料。纳入必须同时满足：

- 仓库**主语言是编程语言**（GitHub 标注的 primary language 不是 `Markdown` / `None` / `Text`）；
- 有**实质源码树**（存在可构建/可运行的代码，而非仅 `.md`）；
- 名称/topics/简介**不属于**纯聚合类：正则排除 `awesome|list|collection|curated|prompts?|cheat\s?sheet|handbook|book|tutorial|roadmap|guide|notes|papers?|spec-only`，命中者进入人工复核而非直接纳入；
- 与 "AI agent / LLM 应用 / coding agent / agent 框架 / agent 工具" 主题相关（见 2.4 领域分层）。

> 例：`OpenHands`、`Aider`、`Cline`、`AutoGPT`、`MetaGPT`、`gpt-engineer`、`Continue`、`goose`、`SWE-agent`、`LangChain`、`LlamaIndex` 这类**真实 agent 代码项目**纳入；`awesome-llm-apps`、`prompt-engineering-guide` 这类**聚合/文档**仓库排除。（最终名单以 §3 脚本枚举 + 人工复核为准，本处仅为判据示例。）

### 2.4 领域分层（避免单一生态垄断）
对纳入仓库按领域打标签并报告分布，防止"前 50 全是 JS web 框架/全是 Python agent 框架"：
`coding-agent`（如 Aider/Cline/OpenHands）/ `agent-framework`（如 LangChain/CrewAI）/ `LLM-app-framework` / `agent-tooling-infra`（如 MCP server、网关）/ `IDE-extension` / `SDK` / `general-OSS-adopter`（主业非 AI 但采用了该文件）。

### 2.5 排除判据
fork（排除）；archived（**保留但打标**，单独看是否影响结论）；纯模板 boilerplate（文件**内容哈希**与他仓重复且仓库本身无实质代码者排除）；2.3 不满足者排除。

### 2.6 规模与快照
- **规模**：满足上述判据的仓库中，按 star 降序取**前 50**（CLAUDE.md 与 AGENTS.md 合并排序；同一仓库两文件都有则都收，去重在文件级）。选 50 的理由：既覆盖头部高影响项目，又是"可做规则级人工编码与信度核查"的现实上限。
- **快照**：固定采集日期；每个文件钉到其 **commit SHA**；原始字节离线留存。数月后重跑脚本可复现同一数据集。

---

## 3. 采集流水线（脚本化、可复现，**不是** agent 乱爬）

工具：已认证的 `gh` CLI（`gh api`）。全过程脚本化，所有 API 查询串与时间戳写入 `queries.log`。

1. **枚举候选**
   - GitHub code search：`filename:CLAUDE.md`、`filename:AGENTS.md`，并按需加 `stars:>N` 缩小；
   - 补充：`search/repositories` 按 star 降序 + 主流 agent 工具的下游依赖；
   - **如实记录 code search 的局限**：只索引部分仓库、单查询结果上限（~1k）、需认证、限流——这些都写进威胁有效性（§8）。
2. **取仓库元数据**：stars、primary language、license、fork、archived、`pushed_at`、topics、size。
3. **应用 2.3/2.5 判据过滤**（自动正则 + 人工复核边界 case）。
4. **取文件 @HEAD**：commit SHA、文件路径、raw 字节、字节数、raw_url、`retrieved_at`、`content_sha256`。
5. **去重**：文件级（content hash）+ 规则级（§4 抽取后对规则归一化文本聚类）。
6. **排序取前 50**（按 §2.2 主指标）。
7. **落盘**：写 `manifest.jsonl` + `raw/<sha256>.md`。
8. 限流/分页/错误处理记录在 `queries.log`，保证重跑等价。

---

## 4. 分析单元与编码方案（codebook）

### 4.1 分析单元 = 规则（rule）
一条"原子规范陈述"：一个 bullet、一句祈使/规范句、或"小标题+正文"。切分细则：复合句按连词拆为多条；列表项各为一条；代码块/命令示例不单独计为规则但作为上下文；表格按行拆。**每条规则保留 verbatim 原文 + 行号区间**，便于人工复核与发布。

### 4.2 抽取方式（半自动，但人工把关）
LLM 负责"切分 + 预编码"以上规模，但：(a) 每条记录保留原文+定位；(b) 人工校验随机子集；(c) LLM 是*规模化助手*而非*事实来源*。

### 4.3 编码维度 D1–D7
| 维 | 取值 | 说明 |
|----|------|------|
| **D1 类型** | behavioral-constraint / coding-style / build-setup / architecture-doc / meta | 仅 behavioral 往下编码（RQ1） |
| **D2 类别** | 机密-secret / 未受信输入-完整性 / VCS-卫生 / 工作区-路径限制 / 破坏性操作-门禁 / 网络出口 / 进程-工具限制 / 强制中介 / 时序 / 资源-sandbox / 其他 | 归纳式 + 以 ActPlane 类别为种子（RQ2） |
| **D3 模态** | 禁止 / 义务 / 条件许可 | 映射 `deny` / 强制时序 / `unless` |
| **D4 通道** | exec / read / write / unlink / network / env-secret / other | 映射 ActPlane 操作 |
| **D5 可强制性（三正交标志，关键）** | **Observable**（syscall/LSM 有对应信号）· **Expressible**（当前 DSL 可表达，记录是哪条构造）· **Robust**（无不可接受误报地可强制） | 覆盖率 = 三者**合取**；三层**分别**报告（RQ3） |
| **D6 绕过面** | yes / partial / no（是否跨 bash/subprocess/SDK 仍成立、工具层守卫会漏） | RQ4 |
| **D7 可诱发性** | {temptable: bool, task_sketch: str}（是否有真实任务自然触发违规 + 任务草图） | RQ5 / eval |

> D5 拆三层是 OSDI 评审的高频攻击点：例如"不要在代码里硬编码密钥"是 *可表达* 但 *不可无误报强制*（硬编码密钥与任意字符串不可区分）→ Observable=部分、Robust=否。必须把"可表达"和"可真正强制"分开报告，否则覆盖率会被认为注水。

---

## 5. 信度与饱和（OSDI 关键，不能省）

- **双编码者 + 人工仲裁**：LLM-coder-A、用不同 prompt 的 LLM-coder-B，再加**人工**对 **≥20% 随机样本**独立编码；报告 D1（是否行为约束）、D2（类别）、D5（可强制性）的 **Cohen's κ**；分歧逐条仲裁，**发布仲裁后标签**。这是把"taxonomy 可信"从口头变成数字的最大杠杆。
- **饱和论证**：画"类别发现曲线"——随仓库数增加，新出现的 D2 类别趋于 0，说明分类体系已覆盖完整。

---

## 6. 元数据存储 schema（具体落地）

格式选 **JSONL**（追加友好、可 diff、每条自包含）+ 原始字节留存 + JSON Schema 校验。**每条数据都带 provenance（URL + commit SHA + 行号区间 + 采集时间）**——这是可信度的底线。

```
corpus/
  raw/<sha256>.md            # 文件原始字节（离线、可复现）
  manifest.jsonl             # 每个 (repo,file) 一条
  rules.jsonl                # 每条抽取出的规则一条
  codebook.md                # D2/D5 的定义、判定细则、正反例（版本化）
  queries.log                # 确切 API 查询串 + 时间戳
schema/{manifest,rule}.schema.json
```

`manifest.jsonl` 记录样例：
```json
{"repo":"All-Hands-AI/OpenHands","stars":41200,"lang":"Python","license":"MIT",
 "fork":false,"archived":false,"pushed_at":"2026-05-10","topics":["agent","llm"],
 "domain":"coding-agent","family":"AGENTS.md","file_path":"AGENTS.md",
 "commit_sha":"a1b2c3…","raw_url":"https://raw.githubusercontent.com/…/a1b2c3…/AGENTS.md",
 "retrieved_at":"2026-05-22T08:00:00Z","content_sha256":"…","byte_size":4211,"dup_of":null}
```

`rules.jsonl` 记录样例（含 eval 桥接字段）：
```json
{"rule_id":"r0481","source_sha256":"…","repo":"All-Hands-AI/OpenHands","span":[42,44],
 "verbatim":"Never commit directly to main; always open a PR.",
 "D1":"behavioral-constraint","D2":"VCS-卫生","D3":"禁止","D4":"exec",
 "D5":{"observable":true,"expressible":true,"robust":true},
 "actplane_construct":"deny exec \"**/git\" @arg \"commit\" if AGENT unless lineage-includes exec \"**/pr-tool\"",
 "D6":"yes","D7":{"temptable":true,"task_sketch":"让 agent 在已 checkout 的 main 上『直接提交修复』"},
 "coder":"llm-A+llm-B+human","kappa_bucket":"D2","confidence":0.9,"adjudicated":true,"notes":""}
```

去重：`manifest.dup_of` 指向首见文件；规则级在 `rules.jsonl` 加 `rule_cluster_id`。**统计一律以"distinct rules"与"表达该规则的仓库数"两种口径报告，绝不报原始规则计数**（否则 boilerplate 会同时灌水 prevalence 与类别分布）。

---

## 7. 从语料到 eval（eval 桥接）

选场景的规则是机械的：**`D5.observable ∧ D5.expressible ∧ D5.robust ∧ D7.temptable`，并按 `D6=yes` 优先排序** → 评测场景。每个场景记录：源规则（带 provenance）、编译后的 `.dsl`、诱发违规的 agent 任务 prompt、期望违规、baseline。

结合当前内核已具备的 **BPF-LSM 强制**（`block` 命中即 `-EPERM`；不可用时降级 tracepoint audit，必要时用 `kill` 让动作失败），每个场景跑四个条件：

1. **prompt-only**（规则只写进 CLAUDE.md，无强制）——测"本就会违反"的基线违规率（这是我们存在的正当性，若此项恒为 0 则该规则对我们无证据价值，需如实剔除）；
2. **audit**（只报不拦）；
3. **fail-no-reason**（LSM `-EPERM` 或 `SIGKILL`，但不回灌 ActPlane reason）；
4. **fail + 纠偏反馈**（让动作失败并把 reason 回灌上下文，看 agent 能否自我纠正并仍完成任务）。

指标：违规率、**误报/过度阻断率**（让正常工作失败的 harness 比 prompt 更糟，此数与命中率同等重要）、任务完成率、纠正迭代数、以及"同一规则在 *工具调用* / `bash -c` / `python -c subprocess` / 直接 syscall 四条路径上是否都被强制失败"（D6 的直接验证）。

> **语料论断与 eval 论断严格分离**：§2 只说"开发者写了什么、其中多少可强制"；§6 才说"agent 实际违反多少、强制后如何"。

---

## 8. 有效性威胁（Threats to validity）

- **构造效度**："是否行为约束""属于哪类"主观 → 用 codebook + κ 缓解。
- **内部效度**：LLM 抽取/编码可能错 → 人工校验随机样本 + 双编码仲裁。
- **外部效度 / 偏置**：仅 GitHub、英文为主、流行度（star）偏置、早期采用者偏置、快照时点、**仅 CLAUDE.md + AGENTS.md 两类文件**、code search 仅索引部分仓库。逐条声明，不掩盖。
- **作者身份不可区分**：人写 vs LLM 生成无法可靠区分，**刻意不编码**；把文件视作项目*声明的*策略。这是有意的 scoping，不是疏漏。
- **aspirational ≠ 观测违规率**：文件只说开发者想要什么；真实违规率由 eval 给出。
- **star ≠ 使用量**：仅代理，用辅指标（下载/依赖）做稳健性核查。

---

## 9. 可复现 / Artifact（瞄准 AE 徽章）

冻结 dated 快照（raw 字节 + commit SHA）；发布采集脚本、`queries.log`、`codebook.md`、标注后的 `rules.jsonl`；提供容器，使 `raw → 所有论文表格/图` 一条命令可复现。目标：OSDI Artifact Evaluation 的 "Results Reproduced"。

---

## 10. 执行计划、里程碑与风险

| 里程碑 | 内容 | 退出判据 |
|--------|------|----------|
| **M0 Pilot（先做）** | 20 个仓库跑通流水线，出**初步 D5 分布 + 初步 κ** | 决定是否值得全量；若可强制比例过低则调整 framing |
| **M1 全量采集** | 按判据取 star 降序前 50，落盘 manifest + raw | 50 个合格代码项目 + 领域分布报告 |
| **M2 编码 + 信度** | D1–D7 双编码 + 人工仲裁 + κ + 饱和曲线 | κ 达可接受区间，标签发布 |
| **M3 分析 + eval 导出** | RQ1–RQ5 数字 + (规则→.dsl→任务) 场景集 | §2/§6 所需的全部数字与负载就绪 |

**主要风险**：若 M0 显示行为约束中"可无误报强制"的比例很小（多为风格/语义类），则"强制"叙事削弱——届时据实把论文重心移向"可强制子集 + 纠偏闭环"，并诚实报告不可强制的占比。**先 pilot 再全量**正是为此设的早停点。

---

## 附录 A：候选种子仓库（示例，非最终名单）

仅用于启动脚本枚举与判据校准，最终以 §3 脚本 + 人工复核结果为准：
OpenHands、Aider、Cline、AutoGPT、MetaGPT、gpt-engineer、Continue、goose、SWE-agent、LangChain、LlamaIndex、CrewAI、Dify、AutoGen、open-interpreter、Cursor 相关、anthropics/claude-code 及其生态、主流 MCP server 等。
