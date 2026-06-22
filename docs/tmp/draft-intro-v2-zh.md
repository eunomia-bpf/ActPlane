# ActPlane — 重写 Abstract + Introduction 草稿 (中文 v2)

## Abstract

AI coding agent 作为长时间运行的进程，拥有对 shell、文件系统和网络的直接访问，在跨越数小时的 session 中自主执行复杂任务。项目通过 harness 指令文件声明行为策略——"不要泄露密钥"、"commit 前跑测试"、"不要修改生产数据库"。我们对 64 个项目的实证研究表明：63% 的 harness 指令是约束系统级效果的行为策略，78% 的项目需要跨事件状态追踪——横跨多个操作、跨越进程/文件/网络边界的信息流或时序约束。

执行这些策略远比传统访问控制困难，因为 agent 行为是涌现的：由运行时的自然语言 prompt 决定，而非编译期的源码。这种涌现行为造成了 intent-behavior gap——prompt 层执行是概率性的，tool 层 guard 在 agent spawn subprocess 时被绕过，内核层沙箱执行逐操作 ACL 但既无跨事件状态也无与 agent 声明策略的语义连接。没有现有系统同时提供不可绕过的 OS 层执行、跨事件信息流追踪、和适应涌现行为的策略生命周期。

我们提出 ActPlane，一个面向 agent harness 的可编程 OS 层控制平面。Agent 在一个紧凑的 DSL 中声明行为策略，该 DSL 被设计为既人类可审计也 LLM 可生成；ActPlane 将其编译为标记信息流规则，加载到 eBPF/BPF-LSM 内核后端。命名标签沿进程/文件/网络边界传播，将跨事件执行历史编码为每节点 O(1) 可查的 bitmask。规则匹配时，ActPlane 返回语义反馈，将 OS 层事件重新连接到 agent 声明的策略，使 agent 可以自我修正。每条规则独立选择 notify、block 或 kill，支持从观测到执行的渐进式部署。评估表明 ActPlane 实现了无旁路的跨事件策略执行、提升 agent 任务完成率的语义反馈、和亚微秒级的逐事件开销。

---

## 1 Introduction

AI coding agent 正在成为主流开发工具。Claude Code、Cursor Agent 和 Codex 作为长时间运行的进程，拥有对 shell、源码树、包管理器和外部 API 的完整访问，在持续数小时甚至数天的 session 中自主地写代码、跑测试、管理基础设施。

**Agent 需要行为策略。** 随着 agent 获得自主权，项目通过 harness 指令文件约束其行为：不要直接 push 到 main；不要将 `.env` 内容暴露到网络；每次 commit 前跑 `pytest`。我们对 64 个流行开源项目的实证研究（§X）揭示了一个关键事实：这些指令不是编码风格建议——63% 是约束可观测系统效果的行为策略，其中 80% 涉及系统级行为（文件访问、进程执行、网络连接），78% 的项目包含至少一条需要跨事件状态的策略——需要追踪跨多个操作的信息流或时序顺序。

**Agent 行为是涌现的。** 与传统软件不同——源码在编译期决定行为——agent 的行为由自然语言 prompt 在运行时决定。指令"找到并修复认证模块的 bug"可能产生任意组合的文件读写、代码编辑、编译、测试和网络请求，而且每次调用的组合都不同。这种涌现的、非确定性的特征，是使行为策略执行对 agent 而言远比传统软件困难的根本原因。它导致了三个层层递进的系统问题。

**问题一：Intent-behavior gap。** Agent 的执行跨越三个抽象层：intent（自然语言表达的目标和约束）、action（通过 agent 运行时发出的 tool call）、behavior（实际的 OS 操作——`open`、`execve`、`connect`）。从 intent 到 behavior 的映射是多对多且不透明的。一个 `run_command("make")` 触发数百个 syscall；同一个 `git push` 可以通过直接 tool call、`bash -c` 字符串、Python `subprocess` 或编译好的二进制到达。

现有的可观测性和执行工具被困在这个 gap 的两侧。应用层监测（LangSmith、Langfuse）看到 agent 的 intent——它的 prompt 和 tool 选择——但对这些 tool 产生的系统行为是盲的，因为一个 shell 命令就跳出了它们的视野。内核层监测（Falco、Tracee）看到每个 syscall，但缺乏语义上下文来区分正常的数据分析脚本和恶意的数据窃取——在 syscall 层面它们一模一样。两侧都无法独立判断一系列 syscall 是对 agent 声明意图的忠实执行，还是偏离。

这种不透明性被噪音问题放大了。Agent 的子进程树产生高吞吐量的 syscall 流，其中绝大部分是与 agent 任务无关的 OS 背景活动。静态的预配置过滤器是脆弱的：一条只监测 `git` 命令的规则，在 agent 用 `curl`、Python 脚本或编译二进制实现同样效果时就失败了。有效的观测需要基于进程谱系的动态过滤——将 agent 的因果链从周围的系统噪音中隔离出来。

**问题二：真实策略是跨事件的信息流约束。** 如果策略只是对单个操作的谓词，intent-behavior gap 尚可管理——只要在正确的层级匹配正确的 syscall。但真实策略不是。我们的 corpus study 发现 78% 的项目包含执行依赖于跨多个操作和对象的累积状态的策略。"读过 `.env` 的进程不能连接外部端点"是一个保密性约束，需要追踪从文件读取到网络连接的数据 provenance。"commit 之前跑测试"是一个时序约束，需要知道测试进程在最后一次源码修改之后、commit 之前执行过。"不要在一个 commit 中混合来自不同任务的数据"是一个不干扰约束，需要追踪哪些被标记的数据流到了哪些文件。

这些跨事件策略无法表达为逐操作的访问控制列表。它们需要一种跨进程/文件/网络边界追踪并在每个执行点编码为可查状态的模型。标记信息流控制（labeled IFC）恰好提供了这一点：在来源处赋予的标签沿 fork/exec/read/write/connect 边传播，累积为每节点的 bitmask，以 O(1) 开销编码完整的相关历史。时序门将此模型扩展到带自动失效的因果顺序追踪。

然而，目前没有任何 OS 层执行系统提供跨事件信息流追踪。内核沙箱（seccomp、Landlock、BPF Jailer）执行逐操作 ACL。应用层 IFC 系统（FIDES、CaMeL）在 planner 或解释器层追踪信息流，但在 agent spawn subprocess 的瞬间就失去了可见性——而 subprocess 恰恰是 intent-behavior gap 使之成为常态的操作。

**问题三：涌现行为使静态策略定义失效。** 即使有了正确的执行层和状态模型，还有一个前置问题：谁来写策略？传统安全假设管理员了解软件行为并据此编写策略。但 agent 行为是涌现的——同一个 agent 在每次调用中产生不同的 syscall trace——没有管理员能预先穷举完整的行为空间。业界将此描述为"策略瘫痪"：策略写得太严会破坏正常的 agent 工作流；写得太松留下安全漏洞；而许多团队因为找不到平衡点，干脆不部署任何策略。

这不仅是规范不完备的问题，而是静态策略与动态行为之间的根本不匹配。容器化和 micro-VM 隔离并不能解决它：最隔离的沙箱中的 agent 仍然可以通过合法的 API 调用泄露数据——只要它受到 prompt injection 的影响。隔离控制 agent 在哪运行；行为策略控制 agent 在边界内做什么。两者互补，不可互替。

这个不匹配意味着执行系统不能是一个加载策略并永久执行的静态 runtime。它必须支持策略的完整生命周期：先观测 agent 的行为（不阻断），从观测中生成或精化策略，机械地验证它们，渐进式地执行，并提供驱动迭代的反馈。因此策略语言不仅需要人类可读以支持审计，还需要机器可写——结构化且约束充分，使得 LLM 或监督 agent 可以生成合法的策略。机械验证步骤为机器生成的策略提供安全网。

**ActPlane。** 我们提出 ActPlane，一个面向 agent harness 的可编程 OS 层控制平面，同时回应上述三个问题。Agent 和开发者在一个紧凑的 DSL 中声明行为策略——一种类似 OpenBSD `pledge()` 的自愿约束。ActPlane 将声明编译为标记信息流规则，加载到 eBPF/BPF-LSM 内核后端。

对 intent-behavior gap：ActPlane 在内核 syscall 边界执行——稳定、完整、与框架无关。进程谱系追踪（`source AGENT = exec "codex"`）沿 fork 边传播标签，将 agent 的因果链从系统噪音中隔离。规则匹配时，ActPlane 将 OS 层事件翻译回 intent 层的语义反馈：哪条声明的策略被触发、为什么、以及什么替代路径可以满足它——从 behavior 回到 intent，反向跨越 gap。

对跨事件策略：命名标签沿进程/文件/网络对象在每个内核 hook 处传播，将执行历史编码为每节点 u64 bitmask，O(1) 可查。时序门（`after G since S`）用基于 epoch 的失效追踪因果顺序，捕获"测试必须在最后一次源码修改之后运行"这类新鲜度条件。规则表达为对标签集的布尔谓词——不维护 provenance graph。

对涌现行为：DSL 是声明式的、固定结构的、有限语法的——为 LLM 生成而设计，同等于为人类编写。`actplane compile --explain` 提供不需要 root 权限的编译期验证（语法、标签一致性、矛盾检测），为机器生成的策略提供安全网。每条规则独立选择三种执行模式之一：notify（仅观测和报告，不阻断）、block（通过 BPF-LSM 执行前拒绝）、kill（执行后终止）。三模式设计是支撑渐进式部署的机制：团队从所有规则设为 notify 开始，从观测中建立行为画像，在信心增长后选择性地将规则提升为 block 或 kill。语义反馈闭环完成整个循环：agent 收到策略违规的解释，据此调整自身行为，或在有监督的场景中精化策略本身。

**贡献。** 本文做出三个贡献：

1. 定义 AI agent 的 intent-behavior gap，识别涌现行为为其根本原因，并通过 64 个项目的 corpus study 证明跨事件信息流策略在真实 agent 指令文件中的普遍性（§X）。

2. 提出 ActPlane——可编程 OS 层控制平面，将 agent 声明的行为策略编译为 eBPF/BPF-LSM 标记信息流规则，跨进程/文件/网络边界追踪和执行，提供语义反馈和渐进式部署（§X–§X）。

3. 在五种 tool 调用路径的 bypass 覆盖、四种反馈条件下的 agent 任务完成率、良性负载下的误报率、以及逐事件开销上评估 ActPlane，与 action 层和 behavior 层基线对比（§X）。
