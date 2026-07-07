# ActPlane Thesis Evolution — Discussion Log

> 本文记录 ActPlane 论文核心 thesis 的演化过程。每一层都保留，因为它展示了为什么
> 浅层 framing 不够。**当前最佳 framing 见第六层（Intent / Action / Behavior）。**

---

## 第一层："Push enforcement to OS layer"（出发点）

最初的 argument：

- Agent 被 NL 指令（CLAUDE.md / AGENTS.md）管着，但 prompt-level 约束是概率性的。
- Tool-layer guard（AgentSpec, Progent）可以被 bash/subprocess/SDK 绕过。
- 因此 enforcement 应该在 OS 层——syscall/LSM 边界，agent 无论怎么走都要过。

**为什么不够**：CamQuery (CCS 2018) 已经在内核做了 labeled IFC + cross-channel +
enforce。光说 "push to OS" 等于说 "CamQuery was right, we reimplemented it on eBPF"。
这是 motivation，不是 contribution。

---

## 第二层："Cooperative threat model changes what enforcement means"

传统 IFC/MAC 的 subject 是 adversary，设计哲学是：

- 目标是 soundness（绝不漏掉攻击）
- 拦住就赢了，subject 困惑无所谓
- Silent `-EPERM` 是正确行为
- 评估指标：rule match caught, false negative rate

但 agent 是 cooperative-but-forgetful。这不是同一个优化问题：

- 目标是 **task completion through correct paths**（不是拦截本身）
- 拦住但 agent 卡死 = 系统失败，不是系统成功
- Feedback 不是锦上添花，是 **load-bearing component**
- 评估指标变成：guided completion rate, task completion, repeated matches

**Insight**：CamQuery 的机制搬过来不够——CamQuery 优化的是 "prevent the bad thing"，
agent harness 优化的是 "enable the correct path despite the agent's tendency to forget"。

---

## 第三层："Provenance-aware remediation — what only the kernel can say"

这一层回答：为什么 feedback 必须跟 OS-level IFC 绑定，而不能在任意层加上去？

考虑一个 rule match："agent 尝试 `curl api.github.com`，被拦了"。

- **Tool-layer guard** 只能说："你不被允许 curl"。它只看到了当前这一步操作。
- **OS-level IFC** 能说："你 30 秒前读了 `.env` 文件，获得了 `SECRET` label，而
  `SECRET` label 的进程不允许连外网。你可以：(1) 先跑 `redactor` 工具去除敏感数据
  （declassify path），(2) 把网络操作交给一个没有 `SECRET` label 的子任务。"

这个 remediation 包含三种只有内核 provenance 才知道的信息：
1. **为什么被拦** — 不是因为 curl 本身被禁，而是因为你携带了 SECRET taint
2. **taint 从哪来** — 你读了 `.env`，这是 source
3. **怎样合法地完成任务** — declassify/gate path 存在，kernel 知道它

**Insight**：kernel provenance state 是产生有效 remediation 的唯一来源。这是
OS-level IFC + feedback 不是 trivial 组合的原因。

---

## 第四层："Action vs Behavior gap"（探索，有局限）

Agent 指令文件里的约束大部分在 **behavior level**：

- "never expose secrets" = 不是禁止 connect，是禁止 "读过 secret 之后 connect"
- "test before commit" = 不是禁止 commit，是禁止 "没跑测试的 commit"

Enforcement 需要把分散的 action 聚合成 behavior，这需要执行历史。Label 是执行历史
的压缩表示。

**局限**：这个 framing 不完全准确——不是所有现有系统都在 action level：
- SELinux 有 type transition（有限的状态机式 behavior）
- Tetragon 有 followChildren（fork/exec 谱系的 boolean flag）
- CamQuery 有完整的跨通道 label 传播（full behavior-level）

所以不能说 "所有人都在 action level，只有我们在 behavior level"。

---

## 第五层："Cross-layer linkage"（过渡 framing）

核心 insight 不是 "在哪一层做 enforcement"，而是 **层与层之间有没有连通**。

现状——三层各自孤立：

```
Intent layer    (CLAUDE.md: "不要泄露 secret")     <-- 孤立
     |  X 断开
Tool layer      (AgentSpec: 检查 tool call)         <-- 孤立
     |  X 断开
OS layer        (seccomp/Landlock: 检查 syscall)    <-- 孤立
```

- Tool-layer guard 拦了一个 tool call，但 agent 用 subprocess 绕过去了它看不见
- OS enforcer 拦了一个 syscall，但只能返回 `Permission denied`，agent 不知道为什么
- Agent 写了 behavioral constraint，既没连到 tool-layer 也没连到 OS-layer

ARMO 博客 (armosec.io/blog/ebpf-based-ai-agent-enforcement/) 的观察：
> "eBPF sees *that* something happened, not *why*."

CamQuery 在 OS 层内做了横向连通（cross-object labels）+ 向下连通（policy -> kernel）。
但没有**向上连通**（kernel rule match -> agent feedback）。

AgentSpec 在 tool 层做了横向检查 + 向上连通（corrective feedback）。
但没有**向下连通**（看不见 tool API 之下的操作）。

**局限**：这个 framing 用的是架构层（intent/tool/OS），说的是 "哪些层断开了"。
但它没有精确定义层之间**断开的是什么**。第六层修正了这个问题。

---

## 第六层："Intent / Action / Behavior"（当前最佳 framing）

### 6.1 三个概念的精确定义

延续 AgentSight 的框架，定义三个抽象层次：

| 概念 | 含义 | 在哪里 | 例子 |
|------|------|--------|------|
| **Intent** | Agent 自己的意图——包括目标和自我约束 | Agent 内部（LLM reasoning） | "我要修这个 bug"；"我不应该泄露 secret" |
| **Action** | Agent 发出的 tool call | Agent runtime / framework | `read_file(".env")`, `run_command("git push")` |
| **Behavior** | 真正在 OS 上执行的操作 | OS / kernel | `open("/path/.env", O_RDONLY)`, `execve("git", ["push"])`, `connect(fd, 1.2.3.4, 80)` |

这跟 AgentSight 完全一致：
- AgentSight 的 Intent Stream = intent
- AgentSight 的 Action Stream = behavior（OS-level 实际操作）
- Action（tool call）是中间层

### 6.1.1 Intent 从哪来：Agent 主动声明，不是被动观测

关键区分：intent 中的行为约束（"我不应该泄露 secret"、"commit 前必须跑测试"）
有两种获取方式：

| 方式 | 做法 | 问题 |
|------|------|------|
| **被动观测**（AgentSight 方式） | Runtime 截获 LLM 流量，推断 agent 想遵守什么 | 脆弱、不完整、依赖截获和解析 |
| **主动声明**（ActPlane 方式） | Agent 自己写出/维护行为契约，交给系统 enforce | 可靠、明确、agent 拥有并维护 |

ActPlane 的设计目标是**后者**：agent（在开发者辅助下）自己写出并维护约束 DSL。
这不是 "开发者给 agent 戴上枷锁"，而是 **"agent 知道自己会忘，主动说
'请按这些规则约束我'"**。

这对应系统领域从被动受限到主动自治的标准演化：

- **SELinux MAC** → **pledge()/unveil()**：程序从 "被管理员写的策略约束" 演化为
  "主动声明我只需要这些能力"
- **OpenSSH 全权限** → **OpenSSH privsep**：程序主动把自己拆成特权/非特权部分
- **Prompt instruction** → **Agent 维护的约束 DSL**：agent 从 "被 prompt 里的
  文字提醒" 演化为 "主动声明行为契约交给内核 enforce"

**为什么主动声明比被动观测更适合 enforcement**：

1. 被动观测的 intent 是推断出来的，不确定——不能作为 enforcement 的依据
2. 主动声明的 intent 是明确的、格式化的——可以编译成确定性规则
3. Agent 自己参与约束维护，违规时的 feedback 不是 "外部权威在拦你"，而是
   "你自己声明的契约在提醒你"——对 cooperative agent 这是更自然的交互模型
4. Agent 可以查询、修改、扩展自己的约束（开发者审批），不是被动接受

### 6.1.2 为什么 intent ↔ behavior 需要桥接

Agent 在长上下文中会**忘记自己声明过的 intent**。这是 cooperative-but-forgetful
的核心问题：agent 在第 1 步说了 "我不应该泄露 secret"，到第 100 步已经忘了。

- Intent-level 的声明是概率性的——写在 prompt/CLAUDE.md 里，会被稀释/遗忘
- Behavior-level 的操作是确定性的——每个 syscall 都会执行

**桥接的含义**：把 agent 主动声明的 intent 变成 behavior-level 的持久承诺。
即使 agent 忘了（在 reasoning 中不再提到这个约束），enforcement 仍然在
behavior level 生效，且 feedback 会提醒 agent "你之前声明过这个约束"。

这就是 ActPlane 做的：**让 agent 的自我声明跨越 intent 和 behavior 两个层次
持久存在**。DSL 是声明的格式，labeled IFC 是持久化的机制，feedback 是提醒。

### 6.2 核心 gap：Action ≠ Behavior

一个 action（tool call）和它产生的 behavior（OS 操作）之间的映射是
**many-to-many 且不透明的**：

- 一个 action 可以产生任意多 behavior：`run_command("make")` → 几百个 syscall
- 同一个 behavior 可以从不同 action 到达：`git push` 可以从 tool call、
  `bash -c`、python subprocess、直接 exec 到达
- Action-level guard 无法预知一个 action 会产生什么 behavior
- Behavior-level guard 无法反推一个 behavior 来自 agent 的什么 intent

### 6.3 Policy / constraint / harness 可以放在任意一层

现状——三层各自有人在做 enforcement：

```
Intent level:     CLAUDE.md prompt 约束         → 概率性的，会忘
Action level:     AgentSpec / Progent tool guard → 确定性的，但 action ≠ behavior
Behavior level:   seccomp / Landlock / Tetragon  → 确定性的，但不连回 intent
```

关键问题不是 "应该在哪层 enforce"。**每一层的 enforcement 都有价值，但每一层
单独都不够**：

- Intent-level：概率性的，agent 会忘
- Action-level：确定性的，但 action ≠ behavior（agent 绕过 tool API 时
  action-level 完全看不到）
- Behavior-level：确定性的且不可绕过，但孤立的 behavior enforcement 只能返回
  `-EPERM`，agent 不知道为什么被拦、不知道怎么修正

### 6.4 ActPlane 的定位：连通 Intent ↔ Behavior

ActPlane 不是 "把 enforcement 推到 OS 层"。它是**连通 intent 和 behavior**：

```
Intent ─────────────────────────────────────── Behavior
  │                                               │
  │  ① 向下：DSL 编译                              │
  │     intent-level constraint                    │
  │     → behavior-level rules (labels + rules)    │
  │                                               │
  │  ② 横向：label propagation                     │
  │     跨 process/file/network 追踪执行历史       │
  │     把分散的 behavior 聚合成可检查的状态        │
  │                                               │
  │  ③ 向上：feedback                              │
  │     behavior-level rule match                   │
  │     → intent-level remediation                 │
  │     ("你因为读了 .env 获得了 SECRET label，     │
  │      跑 redactor 之后就可以连外网")             │
  │                                               │
  └───────────────────────────────────────────────┘
```

- **① 向下连通**：DSL 把 intent-level 的约束（"不要泄露 secret"）编译成
  behavior-level 的规则（source SECRET = file ".env", deny connect if SECRET）
- **② 横向连通**：label propagation 在 behavior level 内跨对象追踪执行历史——
  label 是把分散的 behavior（open, read, fork, exec）聚合成可检查状态的中间表示
- **③ 向上连通**：rule match 发生时，label state 包含了 behavior 的因果历史
  （哪个 source 引入了 label、什么 gate 可以移除），翻译成 intent-level 的
  remediation 返回给 agent

### 6.5 与已有系统的精确对比

| 系统 | 连通了什么 | 缺什么 |
|------|-----------|--------|
| CLAUDE.md (prompt) | intent（声明约束） | 不连 action，不连 behavior |
| AgentSpec | intent ↔ action（tool-call enforcement + feedback） | action ≠ behavior，看不到 OS-level |
| CamQuery | behavior 内部（cross-object labels + enforcement） | 不连回 intent（无 agent feedback） |
| Tetragon | behavior 内部（fork/exec lineage flag） | 只 boolean flag，不跨 file/network，不连回 intent |
| AgentSight | intent ↔ behavior（观测，看到对应关系） | 只观测，不 enforce，不 feedback |
| **ActPlane** | **intent ↔ behavior（enforcement + feedback）** | — |

### 6.6 与 AgentSight 的关系

AgentSight 和 ActPlane 处理同一个 gap（intent ↔ behavior），但方向互补：

| | AgentSight | ActPlane |
|---|---|---|
| 获取 intent | **被动观测**（SSL uprobe 截获 LLM 流量） | **主动声明**（agent 写 DSL 约束） |
| 处理 gap | **观测**（"agent 想做 X，实际做了 Y"） | **enforcement + feedback**（"Y 违反了约束 Z，改成 V"） |
| 对 behavior | 记录，不干预 | 检查 + 阻断/审计 + 反馈 |

不应该说 "ActPlane 是 AgentSight 的延伸"——因为 ActPlane 放弃了 AgentSight
最有特色的能力（intent 的被动观测），换成了一种完全不同的 intent 获取方式
（主动声明）。更准确的关系是：

> AgentSight 证明了 intent ↔ behavior gap 存在且重要。ActPlane 从另一端
> 处理这个 gap：不是被动观测 agent 的 intent，而是让 agent 主动声明 intent
> 并在 behavior level 持久化 enforce。

两者可以组合：AgentSight 的 intent 观测 + ActPlane 的 behavior enforcement
可以形成闭环（观测到 intent 漂移 → 触发约束调整）。这个组合不属于
ActPlane 当前产品声明。

> **反驳 "agent 主动参与未实现" 的 reviewer 攻击**：coding agent（Claude Code,
> Codex CLI 等）本身就有完整的文件编辑和 shell 执行能力。Agent 可以直接编辑
> `actplane.yaml`、可以跑 `actplane` 命令。"Agent 写自己的约束" 不需要额外 API
> ——agent 已经能做到，跟它编辑任何其他项目文件一样。pledge() 类比是成立的：
> agent 编辑 policy file = 程序调用 pledge()，区别只在于 pledge() 是 syscall
> 而 agent 是通过文件编辑。这不是 aspirational，是当前架构已经支持的。

### 6.7 为什么 feedback 必须来自 behavior level

第三层的 insight 在这个 framing 下更清晰：

- Action-level guard 拦了 `run_command("curl api.github.com")`，能说的只是
  "这个 tool call 被禁了"——因为它只看到 action。
- Behavior-level enforcer 拦了 `connect(fd, api.github.com, 443)`，它知道
  这个进程的 label state 是 `SECRET`（因为之前 `open(".env")` 引入的），
  知道 `redactor` 工具是 declassify gate。它能说："你因为读了 .env 获得了
  SECRET label，跑 redactor 之后就可以连外网。"

**Behavior-level 的 label state 是产生有效 remediation 的唯一来源**——
因为只有在 behavior level 才追踪了跨对象的执行历史。

---

## Contribution statement（基于 intent/action/behavior framing）

> Agent 知道自己会在长上下文中遗忘行为约束。它应该能**主动声明**
> "请按这些规则约束我"——就像 pledge() 让程序主动收窄自己的能力。
> 但 agent 的 action（tool call）和真正的 behavior（OS 操作）之间的映射是
> many-to-many 且不透明的：声明在 intent level，效果在 behavior level，
> 现有 enforcement 要么在 action level（确定性但可绕过），要么在 behavior
> level（不可绕过但不连回 intent）。
>
> ActPlane 桥接 intent 和 behavior：agent 主动声明的行为约束通过 DSL 编译成
> behavior-level 的 labeled information-flow rules，在 OS 内核跨
> process/file/network 追踪执行历史，并把 behavior-level 的 rule match
> 翻译成 intent-level 的 corrective feedback——提醒 agent 自己声明过什么、
> 为什么当前操作违反了自己的约束、以及如何修正。

---

## 为什么用 "Harness" 这个词——以及怎么跟主流定义对齐

### 主流定义回顾

2026 年的行业共识（Anthropic, OpenAI, LangChain, Martin Fowler, O'Reilly）：

> **Agent = Model + Harness**

Harness = 模型之外的一切，包括：tool dispatch, memory/state, context engineering,
**sandbox, guardrails/enforcement, feedback loops**, orchestration, observability。

Martin Fowler 的分解：harness = **guides**（feedforward: docs, rules, tooling）
+ **sensors**（feedback: linters, review）。

关键观察：**enforcement 和 feedback 已经是 harness 的公认组件**。主流定义没有
把 harness 限定为 "只是 orchestration"——sandbox、guardrails、feedback 都算在内。

详见 `harness_define.md` 的完整来源和时间线。

### ActPlane 不需要重新定义 harness

ActPlane 不是在说 "harness 应该改成 enforcement 的意思"。而是在说：

> 现有 agent harness 把所有组件——包括 enforcement 和 feedback——都实现在
> application layer。但因为 action ≠ behavior，application layer 的
> enforcement 看不到 OS-level 的行为。**Harness 的 enforcement + feedback
> 组件需要延伸到 OS 层。**

所以 paper 标题 "OS-Enforced Agent Harnesses" 的含义是：

- 不是说 ActPlane 是一个完整的 harness（它不做 orchestration、memory、
  context engineering）
- 而是说 ActPlane 是 **harness 的 OS-enforced 组件**——那些必须在 OS 层
  才能正确工作的部分（enforcement + feedback）
- 这与主流定义不冲突——它是在说 harness 的某些组件需要比 application layer 更深

### 对应 intent/action/behavior 的 framing

```
现有 harness（application layer）：
  orchestration + tools + memory + context
  + enforcement（action-level）     ← 看不到 behavior
  + feedback（action-level）        ← 只能说 "tool call 被禁了"

ActPlane 补充的部分（OS layer）：
  + enforcement（behavior-level）   ← 看到实际 OS 操作
  + feedback（behavior-level）      ← 能说 "你因为读了 .env 所以不能连外网"
```

主流 harness 的 enforcement + feedback 只连通了 intent ↔ action。
ActPlane 的 enforcement + feedback 连通了 intent ↔ behavior。
两者是互补的，不是替代的。

### 在 paper 中怎么写

在 introduction 中用一两句定位：

> The term \emph{agent harness} has come to mean everything around the model:
> tool dispatch, memory, orchestration, guardrails, and
> feedback~\cite{langchain-harness,fowler-harness}. Current harness
> implementations place all of these components at the application layer.
> ActPlane extends the harness to the OS level for the components that
> cannot work at the application layer alone: behavioral enforcement and
> corrective feedback over the agent's actual OS-level behavior.

这样标题 "OS-Enforced Agent Harnesses" 自然地连接到主流定义，不需要 fight it。

---

---

## 第七层：Intro 的 OSDI 结构化（2026-05-30 讨论）

### 7.1 术语统一

论文术语从 "intent-behavior gap" 改为 **semantic gap**（和 AgentSight 一致）。
作为扩展论文，semantic gap 作为本文自己提出的分析框架，不引用 AgentSight。
AgentSight 只在 related work 中以第三人称出现。

Abstract/intro 不再使用三层模型（intent/action/behavior），改为两侧 dichotomy：
- **Intent 侧**：prompt constraints + tool-call guards（都看到 agent 想做什么，但看不到实际 system actions）
- **System 侧**：OS-level enforcement（看到 system actions，但不连回 intent）

Tool-call guard 归入 intent 侧——它看到的是 agent 的 structured intent（tool call），
不是 system actions。

### 7.2 OS 层 related work 的精确分层

OS 层 enforcement 不是铁板一块，分三个梯队：

1. **逐操作 ACL**（seccomp, Landlock, AppArmor, BPF Jailer）：无跨事件状态
2. **有限跨事件**（SELinux type transitions, Tetragon followChildren）：有状态但不是 IFC
3. **完整 IFC**（Flume, HiStar, CamFlow/CamQuery）：标签传播 + 跨事件信息流

ActPlane 相对于第三梯队的增量：时序门、语义反馈、machine-writable DSL、
渐进式部署（notify/block/kill）、O(1) bitmask（不维护 provenance graph）。

**不能说 "OS 层 IFC 是空白"**——Flume/CamFlow 已经做了。
应该说 "OS 层 IFC 已有但不适应 agent 工作负载"。

### 7.3 Policy paralysis 和策略生命周期

来源：ARMO blog "AI Agent Sandboxing — Progressive Enforcement Guide"。

核心问题：agent 行为是非确定性的（prompt 驱动、每次不同），没人能预先写出完整 policy。
写太严 break production，写太松有安全漏洞，很多团队干脆不部署。

这不是 ActPlane 的 thesis 核心（core thesis 是 semantic gap），但它 motivate 了：
- DSL 设计为 machine-writable（LLM/agent 可以生成策略）
- `actplane compile --explain`（机器生成的策略需要 safety net）
- notify 模式（先观测再执行，渐进式部署）

在 intro 中，policy paralysis 放在 gap analysis（¶3）里作为 OS 层方案的共同缺陷：
"all OS-level approaches require policies to be statically pre-written"。
不单独成段论证。

### 7.3.1 Agent as Policy Co-Author — 设计决策，不是独立 Contribution

**核心定位**：这不是一条需要额外 eval 的 contribution，而是 system interface
如何 bridge the gap 的一个 design decision。放在 introduction ¶3（gap analysis）
里写出来：现有 OS-level enforcement 排斥了 agent 参与 policy authoring。

#### 为什么要在 ¶3 里 argue

¶3 现在列出 OS-level enforcement 的缺陷：

1. static pre-written policy — ✅ 已写
2. opaque errors / no semantic feedback — ✅ 已写
3. **policy interface 不对 agent 开放** — ❌ 缺

第三条是根本性的。SELinux/seccomp/Tetragon/CamQuery 的 policy 都是管理员写的，
subject（被管理的程序/agent）没有参与 policy 定义的接口。但 cooperative agent
和 adversarial subject 不同：

- Agent 最清楚自己的 intent（就像 pledge() 里程序最清楚自己需要什么能力）
- Agent 需要理解 policy 才能据 feedback 改道（如果 policy 是 opaque binary blob，
  feedback 的 remediation 也无法具体）
- Developer 和 agent 在实际使用中**共同演化** policy（CLAUDE.md 的每条规则
  背后往往是一次真实违规 → developer 手动加规则 → agent 下次遵守的循环）

#### ActPlane 的设计决策

DSL 是 agent 和 developer **共同面对的接口**：

- Agent 可以**读** policy（理解自己被约束了什么、为什么）
- Agent 可以**写** policy（在 developer 审批下添加/修改规则——跟编辑任何
  项目文件一样，不需要额外 API）
- Agent 据 feedback **理解** policy 含义并选择替代路径
- Sub-agent 的 policy 可以由 parent agent 基于任务上下文指定
  （"这个 sub-agent 只做 code review，不需要 network access"）

这对应系统领域的标准演化：被动受限 → 主动自治：
- SELinux MAC（管理员写） → pledge()/unveil()（程序自己声明）
- Prompt instruction（人写，agent 被动遵守） → Agent-maintained DSL（agent 参与定义）

#### 和 eval 的关系

**不需要额外 eval**。已有的 C4（enforcement + feedback → agent 改道完成任务）
本质上就是在验证 agent 和 policy 的交互能力：

- Agent 读到违规 feedback → 理解规则含义 → 选择替代路径 = agent 能理解 policy
- Agent 据 gate 条件先跑 pytest 再 commit = agent 能按 policy 的结构行动
- 这些已经是 "agent as policy co-author" 的最基本形式

如果 reviewer 问 "agent 真的能写 policy 吗"——这不是 ActPlane 的 claim。Claim 是
**interface design 允许 agent 参与**，不是 agent policy generation capability。
后者跟 LLM code generation 一样，是 agent 自身能力的问题，不是 system
interface 的问题。

#### 在 introduction ¶3 中的具体措辞

在现有 gap analysis 的末尾，加一句：

> All OS-level approaches require policies to be statically pre-written
> **by an administrator who is not the agent**, and return opaque errors
> with no connection to declared intent. The agent—the entity that best
> knows its own goals and constraints—has no interface to participate in
> policy definition, inspect active rules, or act on enforcement feedback.

然后在 ¶5（system description）中呼应：

> ActPlane's DSL serves as a shared interface between developer and agent:
> agents can read, write, and reason about their own behavioral constraints,
> just as \texttt{pledge()} lets a program declare the capabilities it needs
> rather than having an administrator enumerate them externally.

#### 和 7.3 Policy Paralysis 的关系

7.3 说 "没人能预先写出完整 policy"（authoring burden on human）。
本节说 "就算能写出来，agent 也被排斥在 authoring 之外"（interface excludion of agent）。
两者互补：

- Policy paralysis → agent 应该能帮助写 policy（减轻 developer burden）
- Interface exclusion → system 应该让 agent 能参与（design decision）
- 合在一起：ActPlane 的 DSL 既是 machine-writable（7.3）又是 agent-facing（本节）

#### 和 sub-agent 控制的关系

Agent 作为 policy co-author 的一个直接推论是 **parent agent 可以为 sub-agent
定义 policy**。这已经是 CLAUDE.md / AGENTS.md 的常见模式（"sub-agent 不能
直接 commit""sub-agent 只能读不能写"），但没有 enforcement。

ActPlane 让这变得可 enforce：parent agent 在 spawn sub-agent 之前，
写一条 DSL 规则（或 actplane.yaml 里的 scope 配置），内核 enforce 这条规则
对 sub-agent 的整个进程子树生效。这是 "agent as policy co-author" 的
自然延伸——不只约束自己，还约束自己的 delegate。

在 paper 中不需要深入展开（没有 sub-agent eval），但可以在 Design §
Policy Language Scope 里一两句话提到 DSL 支持这种模式。

### 7.4 隔离 ≠ 行为控制

来源：ARMO blog。

容器/microVM/sandbox 控制 agent 在哪运行（containment），不控制做什么（behavioral control）。
"最隔离的 sandbox 中的 agent 仍然可以通过合法 API 调用泄露数据。"

这区分了 ActPlane（harness）和 sandbox（container/VM）的定位。
在 intro 中可以在 gap analysis 或 ¶5 system description 中一句话带过。

### 7.5 信号与噪音

来源：AgentSight paper。

Agent 子进程树产生海量 syscall，绝大部分是 OS 背景噪音。静态过滤器脆弱——
只监测 `git` 的规则，在 agent 用 `curl` 实现同样目的时失败。

ActPlane 的解法：`source AGENT = exec "codex"` 基于进程谱系标记 agent 子进程树，
标签沿 fork 边传播，从噪音中隔离 agent 的因果链。

在 intro 中不需要单独论证——tool-call guard 的 bypass 例子
（"run\_command('make') triggers hundreds of system calls"）已经隐含了这个问题。

### 7.6 Abstract 的结构决策

Abstract 三段，对应 OSDI 骨架：

**¶1 Context + evidence**：agent 需要策略 + corpus study 数据。
不用 "emergent"（太学术），用 "non-deterministic"（具体、可验证）。

**¶2 Gap**：一句话 dichotomy——intent 侧 lose coverage，system 侧 static policy + no semantic context。
"Semantic gap" 作为 dichotomy 的命名出现（冒号后面就是它的内容）。

**¶3 System + results**：ActPlane 桥接 semantic gap + headline numbers。

关键措辞决策：
- "deterministic" 修饰 enforcement/rules，不修饰 system actions
- "connecting intent-level declarations to deterministic system-level rules" = 把非确定性的声明变成确定性的内核规则
- "Enforcing" 不用在 ¶2 开头——它只是单向的；用 "require connecting" 或 "span"

### 7.7 Intro 的 OSDI 骨架

¶1 Context → ¶2 Problem + evidence → ¶3 Gap analysis → ¶4 Key insight → ¶5 System → ¶6 Results → ¶7 Contributions

每段一个职责。Problem 1-2 段讲完。Gap analysis 一段扫清所有现有方案。
不把 problem 拆成 4-5 段——太散。

涌现行为 / 非确定性是 agent 的一个**性质**，在 ¶2 中一两句话带过（"因为 LLM compliance 是概率性的"），
不作为独立 thesis 论证。

---

## 第八层："Agent in the Control Plane" — Shared Policy Lifecycle

> **当前最佳 insight framing。** 第六层（Intent / Action / Behavior）定义了 gap 的
> 结构；第八层回答 **系统应该怎么 bridge 这个 gap**——不是给 agent 套一个 sandbox，
> 而是让 agent 参与 control plane。

### 8.1 核心张力

你需要 **deterministic enforcement**（因为 LLM compliance 是概率性的——
agent 在第 1 步遵守约束，第 100 步可能忘了），但你同时需要 **agent-driven
policy lifecycle**（因为只有 agent 知道当前任务的 intent、哪些 sub-agent
需要什么权限、哪条规则该在什么阶段生效）。

传统安全系统认为这两者不可兼得：deterministic enforcement ⇒ static policy
by admin。原因是传统 subject 是 adversarial——policy author 和 policy subject
**必须分离**（separation of privilege）。

但 cooperative agent 打破了这个前提。Agent 不是要绕过 policy，是要**遵守**
policy 但会忘记。这意味着：

- 分离 policy author 和 subject → policy 是静态的（admin 不在 runtime loop 里）
- Agent 不能参与 → policy 不能适应任务上下文
- Agent 不理解 policy → feedback 无法驱动 self-correction
- Agent 不能为 sub-agent scope policy → 委托链没有 enforcement

**传统安全里 separation 是 feature；cooperative agent 场景里 separation 是 gap 的来源。**

### 8.2 Key Insight（OSDI one-liner 候选）

核心 reframe：不是 "enforcement system that lets agent participate"，
而是 **"programmable interface that lets agent become the control plane"**。

Agent 的 system-level actions 现在是**无人驾驶**的——agent 调了
`run_command("make")`，几百个 syscall 发生了，没人 steering。
每一步都可能触发不可逆的后果（泄密、写错文件、force push），
而 agent 自己对此没有任何 programmatic control。

ActPlane 让 agent 从 passenger 变成 pilot：通过 programmable interface
定义 system-level actions 的规则，让 agent 成为自己行为的 control plane。

**首选（D — programmable interface，agent as control plane，一句话）：**

> **The policy engine should be exposed as a programmable interface that
> lets agents become the control plane of their own system-level actions.**

这一句每个词都在干活：
- "programmable interface" = systems contribution（OSDI vocabulary）
- "lets agents become the control plane" = agent 是主体，不是被管理的 subject
- "of their own system-level actions" = 精确 scope，不是控制一切，是控制自己在 OS 上的行为
- 隐含对比：现有系统是 static sandbox imposed from outside

**备选 B（inversion framing，直接 challenge conventional wisdom）：**

> Our insight is that for cooperative agents, the traditional separation
> between policy author and policy subject is counterproductive: the agent
> itself must participate in the control plane — declaring constraints for
> itself, scoping policies to sub-agents, and evolving rules through
> violation feedback — while the kernel enforces them deterministically
> below the tool layer.

**备选 C（最短）：**

> A behavioral policy engine should be a programmable interface that lets
> agents become the control plane of their own system-level actions, not
> a static sandbox imposed from outside.

**为什么 D 比 B 更好**：

- B 用 "separation is counterproductive" 开头——defensive，在解释为什么旧的不行
- D 用 "programmable interface" 开头——constructive，在说新的应该怎样
- "Programmable" 是 OSDI vocabulary（programmable switches/storage/NICs），
  reviewers 一看就知道这是 systems contribution
- "Agent becomes the control plane" 比 "agent participates in the control plane"
  更有力——agent 是主体，不是被邀请的客人
- "Of their own system-level actions" 精确界定 scope——不是 agent 控制一切，
  是 agent 控制自己在 OS 上的行为

### 8.3 为什么这比第六层更 sharp

第六层说了 **what the gap is**（intent ↔ behavior disconnect）。
第八层回答了一个更 generative 的问题：**系统应该把 agent 放在什么位置？**

传统系统的回答：agent 是被管理的 subject。
第八层的回答：agent 是 control plane——它通过 programmable interface 管理
自己的 system-level actions。

这个 reframe 同时解决了两个问题：
- 为什么现有 OS-level IFC 也不够？（因为它们把 agent 当 passive subject）
- ActPlane 的 contribution 是什么？（不只是 "OS-level IFC + feedback"，
  而是 "一个让 agent 成为自己行为 control plane 的 programmable interface"）

对比：

| 层 | 回答的问题 | 对 reviewer 的说服力 |
|---|---|---|
| 第六层 | gap 的结构是什么？ | 定义清晰，但 "OS-level IFC bridges it" 容易被反驳为 CamQuery already did this |
| 第八层 | agent 在系统中的位置应该是什么？ | "Programmable interface + agent as control plane" 是 constructive 的 systems contribution，CamQuery 没有这个 design goal |

### 8.4 Data Plane / Control Plane 解耦

ActPlane 的架构把两者解耦：

```
Control Plane（agent + developer 协同）：
  ├── agent 读/写 actplane.yaml（DSL policy）
  ├── developer review / approve policy 变更
  ├── parent agent 为 sub-agent scope constraints
  ├── violation feedback → agent 改道 / 提议 policy 修改
  └── violation history → 分析 policy 有效性 / 误报率

Data Plane（kernel，deterministic）：
  ├── DSL → compiled label rules（rodata blob）
  ├── eBPF hooks：fork/exec/open/write/connect
  ├── label propagation（monotonic, O(1) bitmask）
  ├── rule matching → notify / block / kill
  └── violation event → feedback file → agent context
```

关键性质：
- **Data plane 是确定性的**：相同 label state + 相同 operation = 相同结果，
  不管 agent 怎么到达这一步
- **Control plane 是动态的**：policy 可以被 agent/developer 随时修改、
  重新编译、重新加载
- **两者通过 compiled blob 接口连接**：control plane 产出 `taint_config`，
  data plane 消费它。修改 policy 不需要改内核代码

### 8.5 Agent 参与 Control Plane 的三个层次

由浅到深，每一层都已有实现基础（不是 aspirational）：

**层次 1：Agent 理解 policy（读 + feedback）**
- Agent 读 actplane.yaml，理解自己被约束了什么
- 违规时收到 feedback（§6 模板），理解为什么被拦、怎么改道
- **已有 eval 支撑**：C4 condition 就是在测这个

**层次 2：Agent 为 sub-agent scope policy（写 + delegate）**
- Parent agent spawn sub-agent 前，在 policy 里加一条规则
  （如 `source REVIEWER = exec "sub-agent"; rule reviewer-readonly: block write file "*" if REVIEWER`）
- 内核 enforce 这条规则对 sub-agent 的整个进程子树
- **已有实现基础**：DSL 的 source/rule 已支持，agent 可以编辑 actplane.yaml
  跟编辑任何项目文件一样

**层次 3：Agent 据 violation history 提议 policy 修改（evolve）**
- Agent 分析 `.actplane/last-violation.txt` 的历史记录
- 发现某条规则频繁误报 → 提议放宽（developer approve）
- 发现新的风险模式 → 提议加规则
- **不作为核心 claim**：policy evolution 不属于 ActPlane 当前产品声明，
  在 paper 中点到即止

### 8.6 在 Introduction 中怎么放

**¶3（gap analysis）末尾**，加第三个缺陷——agent 被排斥在 control 之外：

> All OS-level approaches require policies to be statically pre-written
> by an administrator external to the agent, and return opaque errors
> with no connection to declared intent. The agent — the entity that
> knows its own goals, that must recover from enforcement, and that
> delegates to sub-agents — has no programmatic interface to define
> or evolve the constraints governing its own system-level actions.

**¶4（key insight）**，用 programmable interface framing：

> Our insight is that the behavioral policy engine should be exposed as
> a programmable kernel-level interface: instead of constraining agents
> from outside with static policy, it lets agents become the control plane
> of their own system-level actions — declaring behavioral constraints
> in a compact DSL, scoping policies to sub-agents, and evolving rules
> through violation feedback — while the kernel enforces them
> deterministically at every syscall.

**¶5（system description）**，pledge() 类比 + programmable interface 呼应：

> ActPlane exposes a programmable OS-level interface for behavioral
> control. Like \texttt{pledge()}, which lets a program declare the
> capabilities it needs rather than having an administrator enumerate
> them, ActPlane lets agents declare the behavioral constraints they
> operate under. Unlike \texttt{pledge()}, these constraints are
> cross-event information-flow rules — not static capability masks —
> and the agent can scope, evolve, and reason about them through
> violation feedback.

### 8.7 和现有 sections 的关系

| ideas.md 章节 | 和第八层的关系 |
|---|---|
| 第六层（6.1.1 主动声明） | 第八层的前身；"主动声明" 是第八层 "参与 control plane" 的一个方面 |
| 7.3 Policy paralysis | Motivates 为什么需要 agent 参与——admin alone can't write complete policy |
| 7.3.1 Co-author design decision | 被第八层 subsume；7.3.1 说的是 "在 intro 哪里放"，第八层说的是 "为什么这是 key insight" |
| 第二层 Cooperative threat model | 第八层的前提——cooperative ⇒ separation is counterproductive |
| 第三层 Provenance-aware remediation | 第八层的推论——agent 参与 control plane 需要 behavior-level feedback |

### 8.8 和 related work 的精确 diff

| 系统 | Agent 在 policy lifecycle 中的角色 |
|---|---|
| SELinux / AppArmor | 无。Admin 写 type enforcement / profile，subject 被动受限 |
| seccomp / Landlock | 程序可以 self-restrict（类似 pledge），但不能 evolve / scope to children dynamically |
| Tetragon / Tracee | 无。Security team 写 TracingPolicy YAML，monitored process 是纯 subject |
| CamFlow / CamQuery | 无。Provenance query 由 admin 写，subject 无 feedback |
| AgentSpec / Progent | 部分。Tool-call rules 可以由 agent framework 配置，但 subject 不参与 authoring |
| FIDES / CaMeL | 部分。Agent loop 内的 IFC / capability separation，但在 application layer，可被 subprocess bypass |
| **ActPlane** | **Agent 是 control plane 参与者**：读/写 DSL、scope sub-agent policy、据 violation feedback 改道 / 提议 policy 修改。Kernel 是 data plane，deterministic enforce |

这张表直接回答 reviewer 的 "how is this different from CamQuery + adding feedback"——
CamQuery 的 subject 没有参与 policy lifecycle 的接口。ActPlane 的 subject（agent）
是 control plane 的一部分。

---

## Open questions（更新）

1. **Abstract/Intro 已重写**：基于 intent/action/behavior framing + harness 定位
2. **Evaluation 的核心 hypothesis**：
   - C3 vs C4 验证 feedback（behavior→intent 提醒）的价值
   - E1 验证 action ≠ behavior 的实证（同一约束通过不同 tool path bypass）
   - 需要一个实验验证 cross-object label propagation 的必要性——
     对比 per-event matching（Tetragon 式）vs cross-object flow（ActPlane 式）
3. **与 AgentSight 的关系**：
   - 不说 "延伸"，说 "互补"：AgentSight 被动观测 intent，ActPlane 主动声明 intent
   - 引用 AgentSight 的 intent/behavior gap 框架
4. **Agent 主动参与不是 vision，是已有实践的系统化**：
   - 应用层已有 paper 让 agent 主动管理自己的约束/能力：
     FIDES（agent loop 内的 IFC）、CaMeL（dual-LLM capability separation）、
     各种 agent framework 的 self-reflection / corrective invocation
   - ActPlane 的贡献不是 "提出 agent 应该主动参与"（这已经有人做了），
     而是**把这个实践放到系统层面**：agent 主动声明的约束由内核持久化 enforce，
     不会因为 context 遗忘、tool bypass、subprocess 改道而失效
   - 因此在 paper 中不应写成 Discussion section 的 future vision，
     而是 design motivation 的一部分：agent 主动参与 + OS 持久化 = ActPlane
