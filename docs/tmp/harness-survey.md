# AI Agent Harness / Guardrail / 运行时强制现状综述

> 一份面向 **ActPlane** 论文的相关工作综述（survey）。聚焦 2024–2026 年的最新进展，
> 围绕"在**哪一层**强制 AI agent 行为"这一核心论点组织，并对每一类工作明确给出
> **与 ActPlane 的异同**。
>
> ActPlane 的卖点（贯穿全文的对照维度）:**内核 IFC 强制 · 工具层之下不可绕过 · 跨通道污点传播
> · 带语义反馈的纠偏闭环 · 面向"合作但健忘"的 agent 而非 adversary**。
>
> **诚实前提（与 `docs/related_work.md` 保持一致,不重复展开）**:ActPlane **不**声称发明
> "内核里跨进程/文件/网络传播标签并在动作前阻断"——**CamQuery (CCS'18)** 已做过这件事;
> 也不声称发明 "eBPF agent 强制" (eBPF-PATROL/OAMAC)、"带反馈的 agent guardrail"
> (AgentSpec/Progent)。本综述系统化地把这些工作放进一个分类法,显示 ActPlane 真正占据的、
> 此前**无单一系统同时填满**的交集格。本文是对 `related_work.md` 的**扩展与系统化**(补 2025–26
> 新工作、加分类法与方法学),凡 `related_work.md` 已逐条注释过的经典工作(TaintDroid/CamFlow/
> CamQuery/SLEUTH/Tetragon/Progent/AgentSpec 等)此处只交叉引用、不复述细节。

---

## 摘要 (Abstract)

随着 LLagent 从"产文本"转向"调 API、写文件、起子进程、发网络请求",**运行时行为强制**
成了独立于内容安全的研究热点。本文综述把现有"agent harness / guardrail / 运行时强制"工作
按**强制所在的系统层次**(prompt → 工具/SDK → 沙箱/隔离 → 内核 IFC)组织成一个分类法,并沿
六个维度刻画每个系统:**强制层、是否做 IFC/污点传播、是否跨通道(进程/文件/网络)、能否被
`bash -c`/subprocess 绕过、是否带语义反馈、是否 agent 导向**。核心论点是:**"在哪一层强制"
直接决定了约束能否被高自由度工具绕过**——工具层 guardrail(AgentSpec、Progent、Invariant、
CaMeL/FIDES、SAFEFLOW)在 agent 的 SDK/工具边界拦截,对 `bash -c git`、`python subprocess`、
直接 syscall 这类**改道**构造性失明;沙箱(Codex Landlock+seccomp、Claude Code bubblewrap、
gVisor、Firecracker)粒度太粗(目录/域名/整盒),做不到"文件 A 必须经脚本 A 访问"这类调用链级
约束;内核 IFC(CamFlow/CamQuery、Tetragon、OAMAC、STBAC)坐在一切之下、不可绕过,但**非
agent 导向、无纠偏反馈**,且多为单通道(进程 lineage)或非 eBPF。我们给出一张 work × dimension
的对比表,指出**唯一未被任何单一系统占据的格**正是 ActPlane 的定位:*多通道类型化污点
(进程+文件+网络)、运行在现代 eBPF/BPF-LSM 基建上、由 agent 导向的 source/sink 规则驱动、
并以语义纠偏反馈闭环回灌给一个合作但健忘的 agent*。最后讨论评测方法(覆盖率、误报、跨路径)
与开放问题。

---

## 1. 引言与分类法 (Taxonomy)

### 1.1 问题:约束在错误的层次上是可绕过的

当前主流的 agent 行为约束是**散文式提示**(`CLAUDE.md` / `AGENTS.md`):这是**概率性
harness**——长上下文会稀释 attention,agent 会**遗忘或即兴改道**(`docs/actplane-research-plan.md`
§1)。把它升级为**确定性强制**有四个候选层次,可绕过性递减:

```
强制层次              典型系统                              能否被 agent 改道绕过?
────────────────────────────────────────────────────────────────────────────
L0 prompt 层      CLAUDE.md / AGENTS.md / system prompt    概率性,易遗忘
L1 工具/SDK 层    AgentSpec, Progent, GuardAgent,          可绕:bash -c / subprocess /
                  Invariant, CaMeL, FIDES, SAFEFLOW,       直接 socket 都不经工具 API
                  LlamaFirewall, Policy-as-Prompt, ARM
L2 沙箱/隔离层    Codex(Landlock+seccomp), Claude Code     不可绕但**粒度粗**:目录/域名/
                  (bubblewrap+proxy), gVisor, Firecracker, 整盒级,无调用链/数据流语义
                  E2B, Landlock, Bubblewrap, seccomp
L3 内核 IFC 层    CamFlow/CamQuery, Tetragon, KubeArmor,   不可绕 + 细粒度:每个 exec/file/
                  bpfbox, OAMAC, STBAC, KRSI/BPF-LSM,      socket 都走 syscall,无论哪条
                  ★ActPlane                                工具路径都拦得到
```

**核心论点**:agent 手里是高自由度工具(Bash、代码执行、子进程、直接 syscall)。L1 只看见
**经过工具 API 的东西**——agent 用 `bash -c 'git push'`、`python -c "subprocess.run([...])"`
或直接 `connect()` 就让 L1 **构造性失明**。这种绕过在 ActPlane 的威胁模型里**通常不是恶意的**
(健忘/即兴),但效果相同:约束失效。L2 不可绕,但只能"全允许/全禁止 + 路径/域名白名单",
做不到调用链级("文件 A 只能经脚本 A 访问"、"refactor 阶段不联网")。**只有 L3 同时满足
"不可绕"与"细粒度"。** ActPlane 是 L3,且补上 L3 普遍缺的两件事:**agent 导向**与**纠偏反馈**。

### 1.2 六个刻画维度

| 维度 | 含义 |
|---|---|
| **Layer** | L0/L1/L2/L3——强制点所在层次,决定可绕性 |
| **IFC / Taint** | 是否携带一个**沿对象流动**的标签(vs 每事件点查/单次匹配) |
| **Cross-channel** | 污点是否跨 **进程 P / 文件 F / 网络 N** 三类通道(vs 仅 fork/exec lineage) |
| **Bypass-resistant** | 能否被 `bash -c`/subprocess/直接 syscall 绕过 |
| **Feedback loop** | 违规时是否给 actor **语义化、可执行的纠偏理由**(vs 静默 `-EPERM`/日志行) |
| **Agent-oriented** | 是否专门建模 AI/LLM agent 的行为与威胁 |

### 1.3 与已有 `related_work.md` 的关系

`docs/related_work.md` 已沿 6 个主题(DIFT、OS provenance、provenance 入侵检测、eBPF/LSM 强制、
agent guardrail、沙箱)给出 30+ 条逐条注释 + 一张对比表 + 诚实的 gap 综合。本综述**不替代它**,
而是:(a) 换一个**以"强制层次"为第一主轴**的组织;(b) 补充 2025–26 的新工作(**CaMeL/FIDES、
SAFEFLOW、"Securing AI Agents with IFC"、"Verifiably Safe Tool Use"、Invariant Guardrails、
BBArmor、eBPF-PATROL、PALADIN/AgentDebug/structured reflection、AgentDojo**);(c) 加一节
**评测方法学**。经典条目(CamQuery、Tetragon、Progent、AgentSpec、AgentSight 等)只交叉引用
`related_work.md`,不复述。

---

## 2. L0/L1:Prompt 层与工具/SDK 层 guardrail

这一层在 agent 框架**内部**、工具调用/SDK/MCP 边界上拦截。共同弱点(已在 `related_work.md`
§5 验证):**bypassable below the framework**——任何不经工具 API 的副作用(raw subprocess、
直接 socket、文件写)它都看不见。

### 2.1 规则/策略式工具守卫

- **AgentSpec** (Wang et al., ICSE 2026; arXiv 2503.18666) —— `trigger → check → enforce` DSL,
  挂进 LangChain 决策管线,强制手段含 action 终止、用户审查、**corrective invocation** 与
  **self-reflection**。
  *vs ActPlane:* ActPlane 的 source/sink 结构与之同形,且 AgentSpec 的 "corrective
  invocation/self-reflection" 是 ActPlane **纠偏反馈**思想的最近邻;但 AgentSpec 在用户态 agent
  runtime 内(可绕),做的是**逐 action 的逻辑检查**,**不做** OS 级跨进程/文件/网络的数据流
  污点。互补,不同层。(详见 `related_work.md` §5。)
- **Progent** (Shi et al., arXiv 2504.11703) —— 基于工具名+参数的符号化 least-privilege,
  LLM 生成策略经 SMT 收紧成 "monotonic confinement"。威胁模型:间接 prompt injection(对抗)。
  *vs ActPlane:* 最接近 ActPlane 规则模型的 agent 安全工作,但**显式假设** "agent 的全部外部
  效果都经 tool call 发生"——这正是健忘 agent 的 `bash`/raw socket 违反的前提。ActPlane 在其下
  的 syscall/LSM 层强制,且加跨对象污点。
- **GuardAgent** (Xiang et al., arXiv 2406.09187) —— 一个独立 "guard" LLM 读安全请求、规划、
  生成 guardrail 代码做确定性检查。*vs ActPlane:* LLM-in-the-loop 风格;ActPlane 是确定性、
  低开销、内核级、不可被被监控 agent 规避的替代。

### 2.2 平台化 guardrail 网关(2025 工业界)

- **Invariant Guardrails / Gateway / MCP-Scan** (Invariant Labs, 2025;
  <https://github.com/invariantlabs-ai/invariant>, <https://invariantlabs.ai/blog/guardrails>)
  —— 一个**透明的 LLM+MCP 代理**,在 agent 与 LLM/MCP server 之间拦截每次交互,支持
  **基于数据流的规则**,如 `(inbox: ToolOutput) -> (call: ToolCall)`,显式建模"从内部敏感系统
  到不可信外部 sink(网页/邮件)的数据流",并检测 "toxic agent flow" 与 MCP tool poisoning。
  *vs ActPlane:* 这是 **agent 原生的、基于数据流模式的 guardrail**,且工程上"改 base URL 即接入"。
  与 ActPlane 共享"数据流策略"直觉,但它在 **MCP/LLM 代理层(L1)**——agent 一旦用 Bash 起子进程
  或直接联网,流就不再经过 gateway,**完全失明**。ActPlane 把同类"source→sink 数据流"约束下沉到
  syscall 层,不可绕。Invariant 是 L1 的最强工业代表,适合作为 ActPlane 的 L1 baseline 与互补层。
- **LlamaFirewall** (Meta, arXiv 2505.03574)、**Policy-as-Prompt** (arXiv 2509.23994)、以及一批
  商业 guardrail 栈(content + tool-call validation + scope/budget caps,见
  <https://generalanalysis.com/guides/best-ai-guardrails>) —— 分层 prompt/tool 守卫,典型 p99
  延迟预算 250–500ms。*vs ActPlane:* 用户态 guardrail 栈;确定但可绕,无 OS 污点,无内核强制。

### 2.3 ★ 2025–26 关键新增:**agent-native IFC**(与 ActPlane 机制最像、层次不同)

这批工作把**信息流控制/污点跟踪**第一次系统性地搬进 **agent 编排/planner 层**,是本综述相对
`related_work.md` 最重要的补充——因为它们和 ActPlane **机制同源(IFC + 污点 + provenance)、
但强制层次不同(L1 vs L3)**,是最需要讲清异同的一类。

- **CaMeL — Defeating Prompt Injections by Design** (Debenedetti et al., Google DeepMind,
  arXiv 2503.18813, 2025) —— "Capabilities, Messages, Links"。从**可信的用户 query** 显式抽取
  控制流与数据流,让 LLM 取回的**不可信数据永远不能影响程序控制流**;给每个 value 附 capability
  元数据,用细粒度策略限制该 value 能被怎么用,由一个**定制解释器**强制。在 AgentDojo 上拦下近
  100% 攻击。
  *vs ActPlane:* 思想上是 CFI+访问控制+IFC 的融合,且"给每个 value 打标签限制其用途"与 ActPlane
  的污点同源。但 CaMeL 在 **agent 程序解释器层(L1)**——它管的是 LLM 程序里 Python 值之间的流,
  **不管 syscall**。一旦 agent 经 Bash/subprocess 落到 OS,CaMeL 的解释器边界外的事它无能为力。
  ActPlane 是其在 OS 层的正交补:CaMeL 防"被注入的计划",ActPlane 防"计划落到 syscall 的实际效果"。
- **Securing AI Agents with Information-Flow Control / FIDES** (Costa, Köpf et al., Microsoft
  Research, arXiv 2505.23643, 2025) —— **本综述发现的最重要新邻居之一**。它(1)**形式化刻画了
  动态污点跟踪能强制的属性类**,(2)给出一个 planner **FIDES**:跟踪机密性/完整性标签、确定性
  强制安全策略、引入"选择性隐藏信息"原语(结合 Dual-LLM/quarantined-LLM/variable hiding),
  在不假设"整个上下文都被污染"的前提下传播标签。
  *vs ActPlane:* 这是迄今**最接近 ActPlane "类型化污点 + 确定性强制" 机制的 agent 安全工作**,
  且它对"动态污点能强制什么"做了 ActPlane 缺的**形式化**(ActPlane 可直接引用其属性类刻画来界定
  自己的能力边界)。但 FIDES 在 **planner/L1 层**对 agent 内部数据值传播标签,**不是 OS 对象**
  (进程/文件/socket),因此(a)对 bash/subprocess 绕过失明,(b)非内核、可绕。ActPlane = FIDES
  的标签传播思想 + OS 对象粒度 + 内核不可绕强制。**这是写作时必须显式对照的一篇。**
- **SAFEFLOW** (arXiv 2506.07564, 2025) —— 协议级框架,对 agent/工具/用户/环境之间交换的**所有
  数据**做细粒度 IFC,跟踪 provenance/完整性/机密性,并加事务性语义。
  *vs ActPlane:* 最 agent-native 的 IFC,但在 **agent 协议/编排层(L1)**;治理的是 agent 组件
  之间的数据,不是 syscall,协议之下可绕。ActPlane 是其内核级补。
- **Towards Verifiably Safe Tool Use for LLM Agents** (arXiv 2601.08012, 2026) —— 2026 年最新,
  把"安全工具使用"推向**可验证**:用形式规则/DSL 指定并强制工具间安全数据流策略,并讨论用
  taint-tracking 风格的运行时机制传播标签。*vs ActPlane:* 同样在工具/数据流层做 IFC 与
  可验证策略,共享 DSL+污点直觉;层次仍是 L1(工具间数据流),不触 OS 对象,可绕。它给 ActPlane
  提供了"DSL→可验证强制"的形式化参照。
- **ARM — Agentic Reference Monitor**(见 "Causality Laundering", arXiv 2604.04035) —— 对工具调用
  agent 的 provenance-aware 运行时强制,把**拒绝**记成一等节点,沿完整性格传播信任。
  *vs ActPlane:* 共享 provenance 图 + 强制 + "拒绝即反馈";但在**工具调用/agent 执行图(L1)**,
  非 OS 对象,同样可绕。它的"denial-as-feedback"与 ActPlane 纠偏反馈思路一致(但层次不同)。

> **本节小结(异同浓缩)**:L1 这批 IFC 工作(CaMeL/FIDES/SAFEFLOW/Verifiably-Safe/ARM)与 ActPlane
> **机制高度同源**(标签传播 + source/sink DSL + provenance + 反馈雏形),区别是**单一且关键**:
> 它们在 **agent 内部数据/工具调用图**上传播标签,ActPlane 在 **OS 进程/文件/socket** 上传播。
> 因此它们对 `bash -c`/subprocess/直接 syscall 一律失明,而那恰是健忘 agent 最常见的改道。
> ActPlane 与它们**正交互补**:理想部署是 L1(防被注入的计划)+ L3 ActPlane(防计划落到 syscall 的
> 实际效果)叠加。

---

## 3. L2:沙箱 / 隔离

不可绕(它们也在 OS 层),但**粒度粗**:目录/域名/整盒级,无调用链与数据流语义。

- **Codex CLI sandbox** (OpenAI) —— **Landlock + seccomp**,是少数**默认开启**沙箱的 agent;
  `sandbox_mode ∈ {read-only, workspace-write, danger-full-access}`,可配 `writable_roots` /
  `network_access`;越界**回落到 approval flow**(启发式从 stderr 关键词+exit code 推断)。
  (<https://developers.openai.com/codex/concepts/sandboxing>)
- **Claude Code sandbox** (Anthropic) —— Linux 用 **bubblewrap**、macOS 用 **seatbelt**,网络靠
  **沙箱外的代理**做域名白名单;**显式覆盖子进程**("not just Claude Code's direct interactions,
  but also any scripts/programs/subprocesses spawned");应用层另有 26 个可编程 hook 事件。
  威胁模型:防被注入的 Claude 改系统文件/外泄 SSH key/连攻击者。
  (<https://www.anthropic.com/engineering/claude-code-sandboxing>)
  *vs ActPlane:* 这是与 ActPlane **同在 OS 层、且都覆盖子进程**的最接近的"产品级"对照,值得专门
  区分:沙箱给的是**目录可写/域名可连的布尔边界**——它能阻止"写 /etc"或"连非白名单域名",但
  **表达不了** "codex 派生链不许碰 git"(git 在可写目录内)、"读了 secret 的进程此后不许联网"
  (数据流污点)、"commit 前必须先 pytest"(调用链阶段)。ActPlane 在同一 OS 层上加**类型化跨
  通道污点 + lineage/after/declassify 条件**,把布尔盒子升级成调用链级数据流策略。两者可叠加:
  沙箱兜底粗隔离,ActPlane 管细粒度行为不变量。
- **gVisor / Firecracker microVM / E2B / Bubblewrap / seccomp / Landlock** —— 用户态内核 / microVM /
  unprivileged self-sandbox 等强隔离边界(综述见
  <https://gist.github.com/wincent/2752d8d97727577050c043e4ff9e386e>)。
  *vs ActPlane:* 一个**盒子**,不是**流跟踪器**。无污点、无 provenance、无调用链 DSL、非 agent
  语义(Landlock 的 descendant-scoped domain 继承像 ActPlane 的 "descendants of X" 范围,但仍是
  静态 path/port 规则)。(详见 `related_work.md` §6。)

> **L2 小结**:沙箱解决"能不能碰整类资源",ActPlane 解决"这条**调用链/数据流**是否守约"。
> 正交;在 Codex/Claude Code 上,沙箱与 ActPlane 是叠加而非竞争关系。

---

## 4. L3:内核 IFC / provenance / eBPF-LSM 强制(ActPlane 所在层)

不可绕 + 细粒度。这是 ActPlane 的层,也是它**最该诚实**的层——核心机制在此**已有前作**。

### 4.1 经典与最近邻(已在 `related_work.md` 详述,此处只定位)

- **CamFlow (SoCC'17) / CamQuery (CCS'18)** —— **最重要的诚实基线**。CamQuery 在内核 LSM 钩子上
  inline 跑用户定义分析,**在动作前 authorize/deny**,其 loss-prevention listing 沿
  write/read/snd/rcv/clone 边传播 `confidential` 标签(即**进程→文件→进程→socket** 跨通道污点)
  并在 socket sink 阻断。**"内核 + enforce + 标签传播 + 跨通道"这一组合 CamQuery 已占据。**
  *vs ActPlane:* ActPlane **不**声称发明该组合。真实差异**窄而具体**:(1)机制——CamQuery 是
  CamFlow LKM/链接内核对象,ActPlane 落在**上游 eBPF/BPF-LSM**(无内核模块、动态加载、verifier
  校验;BPF-LSM 2020 才进 Linux 5.7,CamQuery 时代尚不存在);(2)威胁模型——CamQuery 防远程
  adversary,ActPlane 面向**合作但健忘的 agent**并给 agent 导向规则词汇;(3)**纠偏反馈**——
  CamQuery 只回内核 verdict(deny/RAISE_WARNING),ActPlane 把**语义理由回灌 agent 让其自我纠正**,
  CamQuery 无此能力。
- **OAMAC** (arXiv 2601.14021, 2026) —— **最近的 eBPF-LSM provenance 强制邻居**:把执行 origin
  (本地/远程/服务)作为一等属性,**跨进程创建传播**,在 eBPF-LSM 里对敏感文件接口与 BPF 控制面
  强制,策略存内核 map、运行时可重配。*vs ActPlane:* origin **只跨进程创建传播,不跨文件/网络边**,
  单通道(P only);威胁模型是 post-compromise 攻击面收缩,**非 agent 导向、无反馈**。
- **STBAC**(suspicious-taint-based AC)—— OS 级 taint+enforce 的最老近亲(网络入侵威胁模型,
  预 eBPF,需改内核,非 agent、无反馈)。
- **Tetragon / KubeArmor / bpfbox / bpfcontain / KRSI(BPF-LSM)/ Falco / Tracee / Landlock**
  —— eBPF-LSM 强制的 OSS/机制底座。**Tetragon 的 `followChildren` 是 OSS 里最重叠的特性**,但只沿
  **fork/exec** 传播一个**布尔 lineage flag**,不跨**文件/网络**边传类型化污点,且 64 段上限、
  不匹配既有子进程。**没有一个**沿 进程+文件+网络 三边传类型化污点,**没有一个** agent 导向、
  **没有一个**给语义反馈。它们是 ActPlane 复用的**强制底座**,不是策略模型。
  (以上全部细节见 `related_work.md` §2/§4 与 `reference/oss-landscape.md`,本处不复述。)

### 4.2 2025–26 新增 eBPF runtime enforcement(本综述补充)

- **eBPF-PATROL** (Ghimire et al., arXiv 2511.18155, 2025) —— 面向容器/VM 的 eBPF 运行时安全
  agent:hook syscall(execve/open/clone/ptrace/mount/socket)、查参数与执行上下文、按用户规则
  **Deny/Allow/Kill**;事件富化 UID/PID/comm/cgroup/namespace。
  *vs ActPlane:* 当代 eBPF 强制的直接对照。**已验证局限**:管线是 Probe→Analyzer→Policy→Enforce,
  **逐事件、参数感知的 syscall 匹配,无污点传播、无 provenance 图**——每个决策是单事件匹配。
  威胁模型是容器/VM 内的**主动 adversary**(LOLBins、容器逃逸),**非 agent 导向、无语义反馈**。
  ActPlane 在同一 eBPF 底座上加跨通道污点 + agent 反馈。
- **BBArmor** (Piras et al., CNSM 2025; <https://dl.ifip.org/db/conf/cnsm/cnsm2025/1571197273.pdf>)
  —— **本综述新增**。一个**动态 BPF-to-BPF、基于 LSM 的强制工具**:动态生成/装载 BPF-LSM 程序
  做访问控制强制,强调运行时可变策略而非静态编译。
  *vs ActPlane:* 与 ActPlane **同底座(动态 BPF-LSM 强制)**、同样追求运行时可重配,是很好的机制
  对照;但它是**通用访问控制强制框架**,**无跨通道类型化污点传播、无 agent 导向、无纠偏反馈**——
  即 L3 的"强制基建"又一例,缺的正是 ActPlane 上层(污点 + agent + 反馈)。
- **工业 eBPF 安全的成熟度信号**:Datadog Workload Protection 的 eBPF 加固经验
  (<https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/>)、
  AccuKnox/KubeArmor 的 BPF-LSM 运营化(RHEL ≥ 8.5 backport BPF-LSM,使其"随处可用")、
  以及面向 **AI agent** 的 eBPF 强制专题(ARMO,
  <https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/>:讲清内核级**能拦什么、漏什么**)
  ——共同说明 ActPlane 选的 eBPF/BPF-LSM 底座**已是生产可部署**的,不是研究玩具。

> **L3 小结(诚实定位)**:内核里"污点+跨通道+enforce"由 **CamQuery** 已证可行;eBPF-LSM 强制由
> Tetragon/KRSI/eBPF-PATROL/BBArmor/OAMAC 解决;**但每个 eBPF 强制器都是单通道(进程 lineage flag
> 或逐事件匹配),无一沿文件+网络传类型化污点;CamQuery 有跨通道污点但在 CamFlow LKM(非 eBPF)。**
> 且**全部** L3 系统**非 agent 导向、无语义纠偏反馈**。这两点正是 ActPlane 在 L3 里要填的空。

---

## 5. 横切主题:agent 自我纠错 / 反馈恢复(对应 ActPlane 的纠偏闭环)

ActPlane 的差异化卖点之一是**把内核违规理由回灌 agent 让其自我纠正**(`docs/feedback-design.md`)。
这一节综述支撑该闭环价值的 agent 自纠研究——它们证明"**带定向修复信号**的反馈能显著提升恢复率",
为 ActPlane "block + 语义 remediation" 而非"静默 -EPERM"提供经验依据。

- **PALADIN** (arXiv 2509.25238, 2025) —— 在 5 万+ 失败-恢复轨迹上训练自纠 agent;推理时检测执行
  错误、从 55+ 失败范例库检索最相似案例并执行对应恢复动作。报告**工具失败恢复率 32.76% → 89.68%**。
  *关联 ActPlane:* 强证据——**定向 remediation** 把恢复率从 ~33% 拉到 ~90%,远胜泛泛报错。
  ActPlane 的反馈模板(`feedback-design.md` §6:被拦操作/原因/"OS 层硬约束重试无用"/可执行替代)
  正是"定向修复信号"。
- **AgentDebug** (OpenReview PFR4E8583W) —— 定向反馈使任务成功率**相对最高 +26%**。
- **Where LLM Agents Fail and How They Learn From Failures** (arXiv 2509.25370, 2025) —— 失败归因
  与从失败学习的系统研究;**SHIELDA**(结构化异常处理)、**ToolReflect**(工具错误的反思式纠正)
  等同期工作。
- **Structured Reflection for Reliable Tool Interactions** (arXiv 2509.18847, 2025) —— 结构化反思
  优于启发式自纠。
- **Metacognitive monitoring**(self-corrective agent architecture 综述,
  <https://www.emergentmind.com/topics/self-corrective-agent-architecture>)—— 元认知监控提升任务
  成功率 ~7–8%。

> **关联**:这批工作给 ActPlane 闭环的**量化基线**:纯阻断/泛泛报错收益小(~7–8%),**定向、
> 结构化、可执行**的反馈收益大(+26% 相对,恢复率 33%→90%)。ActPlane 把这套"反馈即修复信号"
> 的发现**从工具层错误下沉到内核强制理由**——这是 §6 评测要验证的核心假设(C3 无理由阻断 vs
> C4 带语义纠偏)。注意:这些是**反馈/恢复**研究,本身不做 OS 强制;ActPlane 的新颖是把它们与
> **内核级跨通道污点强制**融合。

---

## 6. 评测方法学

### 6.1 agent 安全 benchmark 的现状

- **AgentDojo** (Debenedetti et al., NeurIPS 2024; arXiv 2406.13352) —— 动态、有状态、对抗式环境,
  **97 个真实任务 + 629 个安全测试**,跨 banking/Slack/travel/workspace,度量 **benign utility /
  utility-under-attack / attack success rate**。基线 GPT-4o:良性效用 69%,受攻击降到 45%,定向
  攻击成功率 53.1%;加一个二级检测器后攻击成功率降到 8%。被 US/UK AISI 联合红队扩展。
  *关联 ActPlane:* agent 安全评测的事实标准环境,也是 CaMeL/FIDES 报数的基准。**但它评的是
  "agent 框架内的 prompt-injection 抵抗",其威胁模型(对抗注入)与攻击面(工具调用)不直接覆盖
  ActPlane 的"健忘 agent 经 `bash -c`/subprocess 改道"——AgentDojo 里 agent 只通过受控工具集行动,
  不会去 raw syscall。** 因此 ActPlane **不能**直接用 AgentDojo 证明其"工具层之下"卖点,需要自建
  **跨路径覆盖**评测(见下)。

### 6.2 ActPlane 应采用的评测维度(综合 `feedback-design.md` §8、`agent-policy-survey.md`)

1. **跨路径覆盖(卖点的硬证据)**:同一规则在 *工具调用* / `bash -c` / `python -c subprocess` /
   直接 syscall 四条路径上是否都被拦+反馈。直接对比 **L1 hook 通道(只覆盖第一条)** vs
   **L3 内核通道(全覆盖)**——这是"工具层之下"必要性的实证(对应假设 H3)。这是 AgentDojo 等
   现有 benchmark **不测**的维度,ActPlane 必须自建。
2. **四条件对照**:C1 prompt-only / C2 audit(只报) / C3 hard-block(无理由) /
   C4 block + 语义纠偏。C1–C2 隔离"强制净效果",C3–C4 隔离"**纠偏反馈净贡献**"。
3. **任务完成率 + 重复违规率 + 纠正迭代数**:C4 应 完成率 > C3、重复违规 < C3(参照 §5 基线:
   +26% 相对、33%→90%)。
4. **过度阻断 / 误报率**:harness 的误报比 prompt 更糟,与命中率同等重要(`actplane-research-plan.md`
   §7)。
5. **系统开销**:标签传播 + LSM 检查的 ns 级开销;hook 适配器延迟(对照 L1 guardrail 250–500ms
   p99 预算)。

### 6.3 现有 guardrail 评测的通病(本综述观察)

工业 guardrail(§2.2)普遍只报 **content-level 误报/漏报 + 延迟**,极少报 **跨执行路径覆盖**;
agent IFC 工作(CaMeL/FIDES)报 **AgentDojo 攻击成功率 + 效用**,但**默认 agent 只走工具 API**,
因而**结构上不评 `bash -c`/subprocess 绕过**。**"跨工具路径的覆盖完备性"是当前评测的系统性盲点**
——也正是 ActPlane 评测应主打、且能区别于所有 L1 工作的地方。

---

## 7. 对比表 (Gap Analysis)

列:**Layer**(L0–L3)· **IFC/Taint**(标签是否流动)· **Cross-channel**(P=进程,F=文件,N=网络)·
**Bypass-resistant**(能否抗 `bash -c`/subprocess/直接 syscall)· **Agent-oriented** · **Feedback loop**
(对 actor 的语义纠偏)。本表在 `related_work.md` 对比表基础上**重排为以"层次/绕过"为主轴**,并补入
2025–26 新工作。

| 工作 | Layer | IFC/Taint | Cross-channel (P/F/N) | Bypass-resistant | Agent-oriented | Feedback loop |
|---|---|---|---|---|---|---|
| CLAUDE.md/AGENTS.md (prompt) | L0 | 否 | — | 否(概率) | 是 | 否 |
| **AgentSpec** | L1 | 否(逐 action) | agent action | 否 | 是 | **是(corrective/self-reflect)** |
| **Progent** | L1 | 否(逐 tool-call) | tool API | 否 | 是 | 部分(fallback) |
| **GuardAgent** | L1 | 否 | agent action | 否 | 是 | 部分 |
| **Invariant Guardrails** | L1 | 数据流模式 | agent/MCP 数据流 | 否 | 是 | 部分 |
| **CaMeL** | L1(解释器) | **是(capability)** | agent 程序值流 | 否 | 是 | 部分 |
| **FIDES** (Securing w/ IFC) | L1(planner) | **是(类型化标签)** | agent 数据值 | 否 | 是 | 部分 |
| **SAFEFLOW** | L1(协议) | **是(IFC)** | agent 数据流 | 否 | 是 | 部分 |
| **Verifiably-Safe Tool Use** | L1(工具数据流) | **是(taint)** | 工具间数据流 | 否 | 是 | 部分 |
| **ARM** (2026) | L1(工具图) | 是(信任格) | agent exec 图 | 否 | 是 | **是(denial 节点)** |
| LlamaFirewall/Policy-as-Prompt | L1 | 否 | prompt/tool | 否 | 是 | 否 |
| **Codex sandbox** (Landlock+seccomp) | L2 | 否 | 目录/网络(粗) | **是** | 部分(自带) | 部分(approval) |
| **Claude Code sandbox** (bwrap+proxy) | L2 | 否 | 目录/域名(粗) | **是** | 部分(自带) | 否 |
| gVisor/Firecracker/E2B | L2 | 否 | 整盒 | **是** | 部分 | 否 |
| Landlock | L2/L3 | 否 | F/(N) | **是** | 否 | 否 |
| **CamQuery** (CCS'18) | L3(LSM,LKM) | **是(标签传播)** | **P/F/N** | **是** | 否 | 否 |
| **OAMAC** (2026) | L3(eBPF-LSM) | 是(origin,仅进程) | **P only** | **是** | 否 | 否 |
| **STBAC** | L3(内核) | 是(suspicious taint) | P/F/N | **是** | 否 | 否 |
| **Tetragon** | L3(eBPF-LSM) | flag(仅 fork/exec) | **P only** | **是** | 否 | 否 |
| **KubeArmor** | L3(eBPF-LSM) | 否(1-hop fromSource) | P/F/N(逐规则) | **是** | 否 | 否 |
| **eBPF-PATROL** (2025) | L3(eBPF) | 否(逐事件匹配) | P/(F/N 逐事件) | **是** | 否 | 否 |
| **BBArmor** (2025) | L3(eBPF-LSM) | 否(访问控制) | P/F/N(逐规则) | **是** | 否 | 否 |
| KRSI/BPF-LSM | L3(eBPF-LSM) | 否(原语) | 逐 hook | **是** | 否 | 否 |
| **AgentSight** | L3+L1(eBPF) | 否 | P/N(+intent) | 观测(不强制) | 是 | 否 |
| **★ ActPlane** | **L3(eBPF-LSM)** | **是(类型化)** | **P/F/N** | **是** | **是** | **是(语义纠偏)** |

---

## 8. Gap 综合与 ActPlane 的真实新颖性

**逐项诚实**(与 `related_work.md` 的综合一致):

- **内核 + enforce + 标签传播 + 跨通道(P/F/N)** —— **CamQuery 已做**(CCS'18,经其文本与
  loss-prevention listing 验证)。ActPlane **不**声称此组合新颖。
- **eBPF-LSM 强制** —— KRSI/Tetragon/KubeArmor/bpfbox/eBPF-PATROL/**BBArmor(2025)**/OAMAC 已解决。
- **跨进程 lineage 的 eBPF-LSM provenance 强制** —— **OAMAC(2026)** 已做,但**单通道**(仅进程
  创建)。
- **taint + OS 强制** —— 追溯到 **STBAC**。
- **agent 导向、带 corrective/self-reflective 反馈的强制** —— AgentSpec/Progent/GuardAgent/
  **CaMeL/FIDES/SAFEFLOW/Verifiably-Safe/ARM** 在 **L1** 解决,**全部可绕**。
- **agent 的 IFC/污点(标签流动)** —— **2025 已被 CaMeL/FIDES/SAFEFLOW 系统化**,但都在 **L1**
  (agent 数据值/工具图),**不触 OS 对象**。
- **agent 的 eBPF 观测(intent/action 语义 gap)** —— **AgentSight** 解决,但只**观测**。

**真正空着的格 = 三个性质的交集,且对照表里每个前作都至少缺其一:**

> **(L3 内核级,跨通道 P/F/N 类型化污点强制) × (agent 导向) × (语义纠偏反馈闭环)**

- 有跨通道污点+内核强制的(**CamQuery**)→ 缺 agent 导向、缺反馈、且在 LKM 非 eBPF。
- 有 eBPF-LSM 强制的(Tetragon/OAMAC/eBPF-PATROL/BBArmor)→ **单通道或无污点**,缺 agent、缺反馈。
- 有 agent 导向 + IFC/污点 + 反馈雏形的(**CaMeL/FIDES/SAFEFLOW/AgentSpec/ARM**)→ **全在 L1,可绕**,
  不触 OS 对象。
- 有 eBPF agent 语义的(**AgentSight**)→ 只观测,不强制。

**精确 gap 陈述**:ActPlane 的可辩护贡献**不是**"内核里做污点"(CamQuery)、**不是**"eBPF agent
强制"(eBPF-PATROL/OAMAC/BBArmor)、**不是**"带反馈的 agent guardrail"(AgentSpec/CaMeL/FIDES)。
它是**统一**:*多通道类型化污点传播(进程+文件+网络)运行在现代 eBPF/BPF-LSM 底座上、由 agent
导向的 source/sink 规则模型驱动、并以语义纠偏反馈闭环回灌给一个合作但健忘的 agent*。对照表里
**唯一同时填满**(L3 跨通道污点强制)×(agent 导向)×(纠偏反馈)三格的只有 ActPlane 行。

**写作时最该显式对照的几篇**:**CamQuery**(机制最重叠——靠 eBPF 底座/agent 域/反馈区分)、
**FIDES / "Securing AI Agents with IFC"**(2025 最新、机制最像——靠"OS 对象 vs agent 数据值"
与"内核不可绕 vs L1 可绕"区分,且可借其形式化界定能力边界)、**OAMAC**(eBPF-LSM provenance
强制,但单通道、非 agent)、**AgentSight**(eBPF agent 语义,但只观测)、**CaMeL**(防注入设计,
正交补)。

---

## 9. 与 ActPlane 的关系(逐类一句话)

| 类别 | 代表 | ActPlane 与之关系 |
|---|---|---|
| L0 prompt | CLAUDE.md | ActPlane 把概率约束升级为确定强制 |
| L1 工具守卫 | AgentSpec/Progent | 同形规则,但 ActPlane 在其下的 syscall 层,抗绕过 |
| L1 agent IFC | **CaMeL/FIDES/SAFEFLOW** | **机制同源(污点+DSL),正交互补**:它们防"被注入的计划",ActPlane 防"计划落到 syscall 的效果";L1 可绕,L3 不可绕 |
| L1 网关 | Invariant | 数据流策略同直觉,但代理层失明于 bash/subprocess;可叠加 |
| L2 沙箱 | Codex/Claude Code/gVisor | 同 OS 层但粒度粗(盒子 vs 流跟踪);可叠加兜底 |
| L3 内核污点 | **CamQuery** | **最重要诚实基线**:同组合,差在 eBPF 底座 + agent 域 + 反馈 |
| L3 eBPF 强制 | Tetragon/OAMAC/eBPF-PATROL/**BBArmor** | 同底座,但单通道/无污点、非 agent、无反馈 |
| L3 eBPF 观测 | AgentSight | 同底座同 agent 域,但只观测;ActPlane 把它变成强制+反馈 |
| 横切:自纠 | PALADIN/AgentDebug | 给 ActPlane 反馈闭环的量化依据(定向 remediation 收益大) |
| 评测 | AgentDojo | 事实标准,但不评跨路径绕过;ActPlane 需自建跨路径覆盖评测 |

---

## 参考文献(带 URL)

**L1 工具/SDK 层 guardrail 与 agent IFC**
- AgentSpec (ICSE 2026): <https://cposkitt.github.io/files/publications/agentspec_llm_enforcement_icse26.pdf> · arXiv 2503.18666
- Progent: arXiv 2504.11703
- GuardAgent: arXiv 2406.09187 · <https://arxiv.org/abs/2406.09187>
- Invariant Guardrails / Gateway / MCP-Scan: <https://github.com/invariantlabs-ai/invariant> · <https://invariantlabs.ai/blog/guardrails> · <https://invariantlabs-ai.github.io/docs/mcp-scan/guardrails-reference/>
- CaMeL — Defeating Prompt Injections by Design: <https://arxiv.org/abs/2503.18813> · <https://arxiv.org/pdf/2503.18813> · 解读 <https://simonwillison.net/2025/Apr/11/camel/>
- Securing AI Agents with Information-Flow Control (FIDES, Microsoft Research): <https://arxiv.org/abs/2505.23643> · <https://arxiv.org/pdf/2505.23643> · <https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/>
- SAFEFLOW: <https://arxiv.org/abs/2506.07564> · <https://arxiv.org/pdf/2506.07564>
- Towards Verifiably Safe Tool Use for LLM Agents (2026): <https://arxiv.org/html/2601.08012>
- ARM / Causality Laundering: <https://arxiv.org/pdf/2604.04035>
- LlamaFirewall: <https://arxiv.org/pdf/2505.03574>
- Policy-as-Prompt: <https://arxiv.org/html/2509.23994v1>
- AI guardrail 工业现状综述: <https://generalanalysis.com/guides/best-ai-guardrails> · <https://www.getmaxim.ai/articles/the-complete-ai-guardrails-implementation-guide-for-2026/>

**L2 沙箱/隔离**
- Claude Code sandboxing: <https://www.anthropic.com/engineering/claude-code-sandboxing> · <https://code.claude.com/docs/en/sandboxing>
- Codex sandbox: <https://developers.openai.com/codex/concepts/sandboxing> · <https://developers.openai.com/codex/agent-approvals-security>
- Coding agent sandboxes 综述: <https://gist.github.com/wincent/2752d8d97727577050c043e4ff9e386e> · <https://www.bunnyshell.com/guides/coding-agent-sandbox/>
- Landlock 内核文档: <https://docs.kernel.org/userspace-api/landlock.html>

**L3 内核 IFC / provenance / eBPF-LSM 强制**
- CamFlow (SoCC'17): `docs/reference/camflow.pdf`
- CamQuery (CCS'18): `docs/reference/camquery-runtime-provenance.pdf`
- OAMAC (2026): <https://arxiv.org/abs/2601.14021> · <https://arxiv.org/html/2601.14021v1>
- STBAC: <https://www.researchgate.net/publication/307537706_Suspicious-Taint-Based_Access_Control_for_Protecting_OS_from_Network_Attacks>
- eBPF-PATROL (2025): <https://arxiv.org/html/2511.18155v1> · <https://arxiv.org/pdf/2511.18155> · `docs/reference/ebpf-patrol.pdf`
- BBArmor (CNSM 2025): <https://dl.ifip.org/db/conf/cnsm/cnsm2025/1571197273.pdf>
- KRSI / BPF-LSM: `docs/reference/krsi-talk.pdf`
- Tetragon selectors / followChildren: <https://tetragon.io/docs/concepts/tracing-policy/selectors/>
- eBPF for AI agent enforcement (能拦什么/漏什么): <https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/>
- Datadog eBPF workload protection: <https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/>
- AccuKnox BPF-LSM 运行时安全: <https://accuknox.com/blog/runtime-security-ebpf-bpf-lsm>
- AgentSight (eBPF agent 观测,本仓库底座): <https://arxiv.org/html/2508.02736v1>

**经典 IFC / DIFT / provenance(详注见 `docs/reference/papers.md`)**
- TaintDroid (OSDI'10), Dytan (ISSTA'07), libdft (VEE'12), Panorama (CCS'07), Schwartz survey (S&P'10)
- PASS (ATC'06), Hi-Fi (ACSAC'12), LPM (USENIX Sec'15)
- SLEUTH (USENIX Sec'17), HOLMES (S&P'19), RAIN (CCS'17), UNICORN (NDSS'20), StreamSpot (KDD'16)

**横切:agent 自纠 / 反馈恢复**
- PALADIN: <https://arxiv.org/pdf/2509.25238> · <https://arxiv.org/abs/2509.25238>
- AgentDebug: <https://openreview.net/forum?id=PFR4E8583W>
- Where LLM Agents Fail and How They Learn From Failures: <https://huggingface.co/papers/2509.25370>
- Structured Reflection for Reliable Tool Interactions: <https://arxiv.org/html/2509.18847v2>
- Metacognitive monitoring: <https://www.emergentmind.com/topics/self-corrective-agent-architecture>

**评测**
- AgentDojo (NeurIPS 2024): <https://arxiv.org/abs/2406.13352> · <https://arxiv.org/html/2406.13352v3> · <https://openreview.net/forum?id=m1YYAQjO3w>

**ActPlane 内部交叉引用**
- `docs/related_work.md`(逐条注释相关工作 + 原始对比表 + gap 综合)
- `docs/actplane-research-plan.md`(claims、威胁模型、§9.7 缺口)
- `docs/taint-dsl.md`、`docs/feedback-design.md`(能力与纠偏反馈设计)
- `docs/agent-policy-survey.md`(评测 workload 来源)
