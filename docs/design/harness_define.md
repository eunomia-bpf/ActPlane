# "Agent Harness" 术语调研与定位建议

> 本文汇总 2025-2026 年 "agent harness" 在学术/工业/社区的定义、用法和演化，
> 并给出 ActPlane paper 的术语选择建议。数据来源于 2026-05 的系统性搜索。

**推荐一句话定义**：An AI agent harness is the software around the model
that maintains the agent loop and session state, routes tool calls,
mediates shell, file, network, and sandbox resources, and returns results
or feedback to the model.

---

## 1. 术语起源与时间线

"Agent harness" 是一个非常新的术语。"harness" 在 agent 语境中的系统使用始于 2025-11-26,而 "harness engineering" 这一说法直到 2026-02-05 才被提出。

| 时间 | 事件 | 来源 |
|------|------|------|
| 2025-11-26 | Anthropic 发表 "Effective Harnesses for Long-Running Agents"，首次在 agent 语境中系统使用 "harness" | [anthropic.com](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents) |
| 2026-02-05 | Mitchell Hashimoto (HashiCorp) 发表 "My AI Adoption Journey"，提出 "harness engineering" | [mitchellh.com](https://mitchellh.com/writing/my-ai-adoption-journey) |
| 2026-02-10 | Google DeepMind AutoHarness (arxiv 2603.03329)：自动生成 protective code harness | [arxiv](https://arxiv.org/abs/2603.03329) |
| 2026-02-11 | Ryan Lopopolo (OpenAI) 发布 harness engineering field report | [openai.com](https://openai.com/index/harness-engineering/) |
| 2026-03-10 | LangChain / Vivek Trivedy 发表 "The Anatomy of an Agent Harness"，提出 Agent = Model + Harness | [langchain.com](https://www.langchain.com/blog/the-anatomy-of-an-agent-harness) |
| 2026-03 | "Harness Engineering for Language Agents" (Preprints.org 202603.1756) | [preprints.org](https://www.preprints.org/manuscript/202603.1756) |
| 2026-03 | "Natural-Language Agent Harnesses" (arxiv 2603.25723) | [arxiv](https://arxiv.org/abs/2603.25723) |
| 2026-04-02 | Martin Fowler 发表 "Harness Engineering for Coding Agent Users" | [martinfowler.com](https://martinfowler.com/articles/harness-engineering.html) |
| 2026-04-15 | OpenAI Agents SDK 更新，采用 harness + sandbox 架构 | [techcrunch.com](https://techcrunch.com/2026/04/15/openai-updates-its-agents-sdk-to-help-enterprises-build-safer-more-capable-agents/) |
| 2026-04 | "Agent Harness for LLM Agents: A Survey" (Preprints.org 202604.0428) | [preprints.org](https://www.preprints.org/manuscript/202604.0428) |
| 2026-04 | "The Last Harness You'll Ever Build" (arxiv 2604.21003) | [arxiv](https://arxiv.org/abs/2604.21003) |
| 2026-04-28 | "Agentic Harness Engineering" (arxiv 2604.25850) | [arxiv](https://arxiv.org/abs/2604.25850) |
| 2026-05-14 | "Auditing Agent Harness Safety" (arxiv 2605.14271) | [arxiv](https://arxiv.org/abs/2605.14271) |
| 2026-05-15 | O'Reilly / Addy Osmani 发表 "Agent Harness Engineering" | [oreilly.com](https://www.oreilly.com/radar/agent-harness-engineering/) |
| 2026-05-18 | "Code as Agent Harness" (arxiv 2605.18747, 42 authors) | [arxiv](https://arxiv.org/abs/2605.18747) |

---

## 2. 当前共识定义

### 2.1 主流含义：Orchestration layer

> **Agent = Model + Harness**

Harness = 模型之外的一切：tool dispatch, memory/state, context engineering,
sandbox, guardrails, orchestration logic, feedback loops, observability/tracing.

这是 2026 年 Anthropic / OpenAI / LangChain / Martin Fowler / O'Reilly 的共识。

**关键表述**：

- **Anthropic**："The infrastructure managing multi-context-window sessions, state
  persistence, initializer vs coding agent split." Claude Agent SDK 被描述为
  "a powerful, general-purpose agent harness." Claude Managed Agents = "an agent
  harness tuned for performance with production infrastructure."
  
- **OpenAI**："The harness is the control plane around the model: it owns the agent
  loop, model calls, tool routing, handoffs, approvals, tracing, recovery, and run
  state." OpenAI 区分 harness (control plane) 和 sandbox (isolated execution environment).

- **LangChain (Vivek Trivedy)**："If you're not the model, you're the harness."
  Components: system prompts, tools/skills, infrastructure (filesystem, sandbox),
  orchestration logic, execution hooks.

- **Martin Fowler (Birgitta Boeckeler)**："Everything in an AI agent except the
  model itself." 分解为 guides (feedforward: docs, rules, code tooling) 和
  sensors (feedback: linters, AI-based review).

- **Hugging Face**：明确区分 harness ("what makes the agent run") 和 scaffold
  ("what the model works from" — instructions, tools, format).

- **MongoDB**："The LLM is the engine, the harness is the car."

- **O'Reilly / Addy Osmani**："A decent model with a great harness beats a great
  model with a bad harness."

### 2.2 另一含义：Evaluation/benchmark harness

更早的用法，来自软件测试的 "test harness"：

- **EleutherAI lm-evaluation-harness** (2021+)：跑 LLM benchmark 的框架
- **SWE-bench**：`swebench.harness` 模块，Docker-based 评测基础设施
- **UK AISI Inspect**：注意，AISI **不**叫它 harness，叫 "framework"；sandbox 是单独的

### 2.3 ActPlane 的含义：Enforcement/safety harness

Runtime behavioral enforcement at the OS/kernel level.

**这个含义在行业中不常用 "harness" 一词。** 做 enforcement 的系统用的术语是：

| 系统 | 自称 | 层次 |
|------|------|------|
| AgentSpec (arxiv 2503.18666) | "runtime enforcement" | Tool/agent layer |
| Progent (arxiv 2504.11703) | "privilege control" | Tool/agent layer |
| ARMO / Kubernetes SIG Apps | "agent sandbox", "enforcement" | eBPF/kernel |
| AgentCgroup (arxiv 2602.09345) | "OS resource control" | eBPF + cgroup |
| Sandlock (arxiv 2605.26298) | "confinement" | Kernel (unprivileged) |
| Tetragon / Falco | "runtime security", "enforcement" | eBPF/kernel |
| AISI SandboxEscapeBench | "sandbox" | Container |
| LlamaFirewall (arxiv 2505.03574) | "guardrail" | Application layer |

**没有一个做 enforcement 的系统自称 "harness"。**

---

## 3. "Harness" 的三个 sense

| Sense | 目的 | 代表 | 时代 |
|-------|------|------|------|
| **Evaluation harness** | 测试/评测 agent 能力 | lm-eval-harness, SWE-bench | 2021+ |
| **Orchestration harness**（主流） | 让 agent 能跑起来 | LangChain, Claude Agent SDK, OpenAI Agents SDK | 2025-2026 |
| **Enforcement harness**（ActPlane） | 运行时行为约束 | AgentSpec(?), ActPlane | 未确立 |

---

## 4. 与 ActPlane 直接相关的新 paper

以下 paper 在之前的 `related_work.md` 中可能未覆盖：

### "Auditing Agent Harness Safety" (arxiv 2605.14271, 2026-05)
- **核心发现**：harness 可以产出正确结果但在执行过程中违反 safety constraints；
  现有 benchmark 抓不到这个问题因为只评估最终结果
- **与 ActPlane 的关系**：直接支持 ActPlane 的动机——执行过程中的 behavioral
  rule match 需要 runtime enforcement，不能只看最终输出
- **关键定义**：agent harness = "the execution framework that dispatches tools,
  allocates resources, and routes messages between specialized components"

### "AgentCgroup" (arxiv 2602.09345, 2026)
- 使用 eBPF + cgroup 做 agent confinement
- 扩展自 AgentSight
- 术语用 "OS resource control"，不用 "harness"
- 需要在 related work 讨论

### "Sandlock" (arxiv 2605.26298, 2026)
- Unprivileged kernel-enforced sandboxing for agent code
- 术语用 "confinement"，不用 "harness"
- 需要在 related work 讨论

### "Code as Agent Harness" (arxiv 2605.18747, 42 authors)
- 大型 survey，把 code 重新定位为 agent 的 operational substrate
- 用的是主流 orchestration 含义

### "Agent Harness for LLM Agents: A Survey" (Preprints.org 202604.0428)
- 首个尝试给 agent harness 做形式化定义的 survey
- 使用 labeled-transition-system semantics
- 区分 safety 和 liveness properties
- 110+ papers, 23 systems analyzed

---

## 5. 物理隐喻的张力

"Harness" 的物理含义（马具、安全带）暗示**约束+引导+控制**：

- 马具 harness：控制马的方向和速度，引导它走正确的路
- 安全带 harness（攀岩/高空作业）：约束活动范围，出错时保护
- 测试 harness（软件工程）：在受控条件下运行代码，检查正确性

这些物理含义都更接近 ActPlane 的 enforcement 含义，而不是行业主流的
orchestration 含义。行业把 "harness" 用成了 "wrapper / infrastructure"，
丢失了 "约束" 的原义。

---

## 6. 对 ActPlane paper 的建议

### 选项 A：换词

放弃 "harness"，改用 enforcement 社区实际使用的术语：

- "OS-Enforced Agent Guardrails"
- "Kernel-Level Runtime Enforcement for Agents"
- "OS-Level Agent Confinement with Corrective Feedback"

**优**：不与主流定义冲突，terminology 清晰。
**劣**：失去 "harness" 的 connotation（约束+引导+反馈的整体性）；
"guardrails" 在学术上不如 "harness" 有分量。

### 选项 B：限定词

保留 "harness" 但加限定：

- "OS-Enforced Safety Harness for Agents"
- "Enforcement Harness"
- "Behavioral Harness"

**优**：区分于 orchestration harness，保留 harness 的物理含义。
**劣**：复合术语，读起来不简洁。

### 选项 C：保留原标题，在 paper 中重新定义

保留 "OS-Enforced Agent Harnesses"，但在 introduction 中明确定义：

> 主流 agent harness 指 orchestration layer（Agent = Model + Harness）。
> 本文使用 harness 的原义——约束+引导+反馈：一个 harness 不只是让 agent
> 能跑起来，还要确保 agent 的行为符合契约、违反时提供纠偏反馈让 agent
> 回到正轨。我们因此把 agent harness 定义为：
>
> **一个 enforce behavioral policies 并提供 corrective feedback
> 的运行时设施，覆盖 agent 的整个执行树。**

然后讨论为什么 orchestration-only 的 harness 不够（只在单层，看不到
OS-level effects），从而引出 "OS-enforced" 的 qualifier。

**优**：有 framing 的野心，可以 shape 后续讨论。
**劣**：需要写好，否则 reviewer 会觉得在 abuse 术语。

### 选项 D（推荐）：利用 cross-layer framing 自然引出定义

在 introduction 中先建立 cross-layer gap：

> 现有 agent harness 在 application layer 管理 agent 的执行循环。
> 但 agent 的行为约束天然跨越 intent layer 和 OS layer：约束在
> intent layer 表达，效果在 OS layer 发生，现有 harness 只覆盖
> 中间一层。
>
> ActPlane 是一个跨层 harness：它把 intent-level 的行为约束编译到
> OS-level 的 enforcement，并把 OS-level 的 rule match 翻译回
> intent-level 的 feedback。

这样 "harness" 不是跟主流定义冲突，而是**扩展**它——从单层 orchestration
到跨层 enforcement+feedback。这与 "Auditing Agent Harness Safety"
(arxiv 2605.14271) 的发现（harness safety 需要 runtime enforcement，
不只是最终结果检查）形成互文。

**优**：最自然地连接行业术语和 ActPlane 的 contribution，
同时建立 cross-layer 这个 core insight。
**劣**：依赖 cross-layer framing 的接受度。

---

## 7. 相关术语对比表

| 术语 | 是否 established | 含义 | 与 ActPlane 的关系 |
|------|-----------------|------|-------------------|
| agent harness | 非常新 (2026-02) | 主流 = orchestration layer | ActPlane 用 enforcement 含义 |
| agent sandbox | 成熟 | 隔离执行环境 | ActPlane 不只是 sandbox（有 IFC + feedback） |
| agent guardrails | 成熟 (2023+) | 运行时约束 | 最接近 ActPlane 的通用术语 |
| agent runtime | 成熟 | 执行基础设施 | 常与 orchestration harness 同义 |
| agent framework | 非常成熟 | 构建 agent 的工具包 | LangChain, CrewAI 等 |
| evaluation harness | 非常成熟 (decades) | 测试/评测框架 | 不同含义 |
| runtime enforcement | 成熟 (security) | 运行时策略执行 | AgentSpec, ActPlane 在做的事 |
| confinement | 成熟 (security) | 约束执行范围 | Sandlock 用的词 |
| harness engineering | 非常新 (2026-02) | 构建/优化 harness 的工程实践 | 新兴学科 |
| context engineering | 新 (2025-2026) | 优化 agent 输入的工程实践 | 与 harness engineering 重叠 |
