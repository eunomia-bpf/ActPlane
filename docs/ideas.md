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
- 评估指标：violation caught, false negative rate

但 agent 是 cooperative-but-forgetful。这不是同一个优化问题：

- 目标是 **task completion through correct paths**（不是拦截本身）
- 拦住但 agent 卡死 = 系统失败，不是系统成功
- Feedback 不是锦上添花，是 **load-bearing component**
- 评估指标变成：recovery rate, task completion, repeated violations

**Insight**：CamQuery 的机制搬过来不够——CamQuery 优化的是 "prevent the bad thing"，
agent harness 优化的是 "enable the correct path despite the agent's tendency to forget"。

---

## 第三层："Provenance-aware remediation — what only the kernel can say"

这一层回答：为什么 feedback 必须跟 OS-level IFC 绑定，而不能在任意层加上去？

考虑一个 violation："agent 尝试 `curl api.github.com`，被拦了"。

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
但没有**向上连通**（kernel violation -> agent feedback）。

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
  │     behavior-level violation                   │
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
- **③ 向上连通**：violation 发生时，label state 包含了 behavior 的因果历史
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
可以形成闭环（观测到 intent 漂移 → 触发约束调整），但这是 future work。

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
> process/file/network 追踪执行历史，并把 behavior-level 的 violation
> 翻译成 intent-level 的 corrective feedback——提醒 agent 自己声明过什么、
> 为什么当前操作违反了自己的约束、以及如何修正。

---

## Open questions（更新）

1. **Paper 标题**：
   - "OS-Enforced Agent Harnesses" 是否还合适？
   - 主流 "harness" 指 orchestration，不是 enforcement（见 `harness_define.md`）
   - 可能的替代：用 intent/behavior 桥接的语言？或 voluntary confinement？
2. **Abstract 重写**：基于 6.1–6.7 的结构重写 abstract
   - 核心叙事：agent 主动声明约束 → intent/behavior gap → ActPlane 桥接
3. **Evaluation 的核心 hypothesis**：
   - C3 vs C4 验证 feedback（behavior→intent 提醒）的价值
   - E1 验证 action ≠ behavior 的实证（同一约束通过不同 tool path bypass）
   - 需要一个实验验证 cross-object label propagation 的必要性——
     对比 per-event matching（Tetragon 式）vs cross-object flow（ActPlane 式）
4. **与 AgentSight 的关系**：
   - 不说 "延伸"，说 "互补"：AgentSight 被动观测 intent，ActPlane 主动声明 intent
   - 引用 AgentSight 的 intent/behavior gap 框架
5. **Agent 主动参与不是 vision，是已有实践的系统化**：
   - 应用层已有 paper 让 agent 主动管理自己的约束/能力：
     FIDES（agent loop 内的 IFC）、CaMeL（dual-LLM capability separation）、
     各种 agent framework 的 self-reflection / corrective invocation
   - ActPlane 的贡献不是 "提出 agent 应该主动参与"（这已经有人做了），
     而是**把这个实践放到系统层面**：agent 主动声明的约束由内核持久化 enforce，
     不会因为 context 遗忘、tool bypass、subprocess 改道而失效
   - 因此在 paper 中不应写成 Discussion section 的 future vision，
     而是 design motivation 的一部分：agent 主动参与 + OS 持久化 = ActPlane
