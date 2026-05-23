# ActPlane: OS-Enforced Agent Harnesses — Research Plan

> 一句话：用 graph 建模 agent 的约束规则，在 OS 层 enforce，并在 agent 触发规则时给出 semantic feedback。
>
> 本文是研究计划草稿（living doc），不是最终结论。

---

## 1. 问题（Motivation）

当前对 AI agent 的行为约束主要依赖提示词（`CLAUDE.md` / `AGENTS.md`）：

- 这只是**概率性约束**。长上下文等原因会让 agent **遗忘或绕过**这些约束。
- 这种遗忘/绕过通常**不是恶意**的——它是 attention 在长上下文里被稀释的结果，提醒之后 agent 往往能恢复正轨。

现有方案有两类，都不足以覆盖"高自由度工具组合"下的 enforcement：

1. **工具级权限管理**（如 AgentSpec）：在工具层禁用某能力。
   - 缺陷：高自由度工具可绕过。禁了 Git 工具，agent 照样能通过 Bash 调 `git`，或通过 Python SDK 调用 git。
2. **影响隔离 / sandbox**（如 E2B、Modal、Daytona）：把整个 agent 关进隔离环境。
   - 缺陷：粒度太粗。要么全允许、要么全禁止，做不到"文件 A 只能经脚本 A 访问"这类**调用链级别**的细粒度规则。

**核心 gap**：缺少一种能在 OS 层、跨越任意工具组合、对**调用链**做可编程 enforcement 的机制。

---

## 2. 核心想法：把约束建模成 Graph

把权限/约束问题建模成一张图：

- **节点（nodes）**：进程（process）与文件（file）。
- **边（edges / relations）**：
  - 进程 A **访问了**文件 B
  - 可执行文件 C **启动了**进程 D
  - 进程 E **启动了**子进程 F

有了这张图，就可以在其上做分析和算法，写出**可编程的规则（rule）**，而非简单的白名单/黑名单。典型规则：

> 可执行文件 A 启动的进程，无论中间经过几层子进程，都不允许访问文件 B / 执行命令 C。
>
> 例：`codex` 启动的任何进程链都不允许碰 `git`。

**本质**：这是一种 **taint analysis（污点分析）**——从某个源头（可执行文件 / 进程）出发的"污点"沿调用链传播，规则定义被污染的主体不可触达的 sink（文件、命令）。

---

## 3. 为什么放在 OS / eBPF，而不是文件系统层

一个自然的反问：既然主要是文件 permission，为什么不在文件系统层（如 FUSE）做？

- 文件系统层做不到**"哪个进程、在什么时间、访问了什么文件"**这种带主体与时序的信息。
- 它也无法表达**跨进程的调用链**（C 启动 D、D fork F……），而调用链正是规则的主体。
- 我们要的是**可编程 rule**，不是路径白名单。

因此 enforcement 的难点其实不在"拦截"本身——文件系统已有完善的 enforcement 基建。**真正的核心难点、也是论文要回答的核心问题，是调用链追踪（provenance tracking）**：

- 追踪**哪些**内容（进程生命周期、exec、fork、文件 open/read/write……）？
- 在**哪个 interface** 上追踪（kernel function hook vs user function hook）？
- 这个 design choice 的**理由**是什么（覆盖率、绕过难度、开销、可移植性）？

当前的初步答案：用 **eBPF** hook 一组 kernel / user 函数来构建这张图。这条线与 AgentSight 一脉相承。

---

## 4. 系统设计（拆成两层）

### 4.1 追踪层（Tracing / Provenance）
- 基于 eBPF 构建"进程 + 文件"调用链图。
- 复用 / 扩展 AgentSight 的 process tracer 与 SSL/IO 观测能力。
- 输出标准化事件流，增量维护 provenance graph。

### 4.2 Enforcement + Semantic Feedback 层
- 按图规则在 OS 层拦截违规操作。
- **关键差异点**：被拒绝时不是返回一个干巴巴的 syscall 失败，而是给出**语义化的拒绝理由**，把 agent "提醒"回正轨（呼应 motivation 里"提醒后可恢复"的观察）。

### 4.3 规则 / DSL
约束规则用一套 DSL 表达。DSL 工作可拆成两个相对独立的子任务：

1. **自然语言 rule → DSL**：把人写的（或 agent 写的）自然语言约束翻译成 DSL。
2. **设计能约束 OS 行为的 DSL 本身**：DSL 的语义、表达力、到 enforcement 的映射。

> 优先级：**先研究 (2) DSL 本身如何设计**。
>
> 注意："规则是不是 agent 自己写的"并不是关键——关键是**用 graph 建模约束**这个想法本身。

---

## 5. Framing / 命名

- 工作名：**ActPlane: OS-Enforced Agent Harnesses**。
- 关于 "harness" 这个词：
  - 我们做的事——"让 agent follow graph-based rules，并在它犯错/执行某些操作时给出提示"——本身就是 **harness** 的一部分。
  - 前半句是**场景**，场景背后的问题用一个词概括即 harness。
  - 取舍：带 "harness" 更 fancy，但要注意别让读者第一眼 get 不到具体内容，正文需尽早把 graph + OS enforcement + semantic feedback 说清楚。
- 定位：**OS-level harness**，可视为 **AgentSight 的扩展**（observation → observation + enforcement）。

---

## 6. 关系到已有工作

- **AgentSight**（于桐；同时是 eunomia-bpf maintainer）：本工作的观测基础，insight 一脉相承。
- **AgentSpec**：工具级权限，对照说明其在工具组合下的局限。
- **E2B / Modal / Daytona 等 sandbox**：粒度对照。
- 相关 OS / kernel 信号：见 LPC 2025 相关 contributions、`openclaw/AGENTS.md` 等（待整理进 related work）。

---

## 7. 待明确的问题（Open Questions）

1. **规则范围**：目前讨论集中在文件 permission，但目标是**调用链级别**的 enforcement（"文件 A 必须经脚本 A 访问"），而非单纯禁止访问文件 A。需要枚举出一组有代表性的规则类型。
2. **追踪 design choice**：到底 hook 哪些 kernel/user 函数？覆盖率 vs 开销 vs 绕过难度如何权衡？这是论文的技术核心。
3. **Motivation 叙事**：当前 framing 还不够好，需要继续打磨更有说服力的故事。
4. **DSL 表达力边界**：哪些约束可表达、哪些不可，与 enforcement 能力如何对齐。

---

## 8. 下一步

- [ ] 列出一组代表性的 graph rule（覆盖文件访问 + 命令执行 + 调用链传播）。
- [ ] 调研并确定追踪 interface（kernel hook 点清单 + 理由）。
- [ ] 设计 DSL v0：语法 + 到 provenance graph 查询的映射。
- [ ] 在 AgentSight 之上做一个最小 enforcement PoC（例：codex 不能碰 git）。
- [ ] 整理 related work，打磨 motivation 叙事。

---

## 9. 实现计划（映射到当前 codebase）

### 9.1 现状盘点

当前 AgentSight **纯观测、零 enforcement**：

- **bpf/**：所有程序（`process(_new).bpf.c`、`sslsniff`、`stdiocap`、`browsertrace`）只往 ringbuf 发 JSON，**全部 `return 0`，无任何阻断**。没有 LSM hook。
  - `process.bpf.c` 已捕获 `sched_process_exec` / `sched_process_exit` / `sys_enter_openat`/`open`（文件操作）；`process_ext/bpf_fs.h` 已 hook `unlink/rename/mkdir` 等 mutation。**已捕获 fork 信息靠 `ppid` 推断，未直接 hook `sched_process_fork`**。
- **collector/**：`Analyzer` trait 是流式转换（`process(stream) -> stream`），**stateless，不构建任何 graph**。`Event{timestamp, source, pid, comm, data}`。
- **frontend/**：`eventParsers.ts::buildProcessTree()` 已从 `ppid` 建进程树，但纯展示、无 enforcement UI。
- 全局 grep：无 `rule/taint/graph/provenance/policy/enforce/deny` 相关实现（只在 design docs 里）。

**结论**：观测 backbone 完整。**本轮范围约束：eBPF 一律不动，所有新东西落在 Rust collector + 前端**。因此 ActPlane(本仓库本轮) = 在现有 observation-only 事件流之上加 **provenance graph + policy/DSL + 用户态 enforcement + 反馈通道**。

### 9.2 约束的关键后果：用户态只能"检测后反应"

只动 Rust + 前端、消费 observation-only 事件流 → 等用户态看到 `openat`/`exec` 事件时操作**已经发生**(TOCTOU)，**无法同步阻止**。真正同步、无竞态的 `-EPERM` 阻断需要 eBPF LSM，这被划为 **future track，本轮不碰**。

这反而契合 motivation：agent 是**非恶意遗忘/绕过、提醒后能恢复**，所以 enforcement 的本体可以是**检测 + 语义反馈(提醒)**，不必硬阻断。

**taint 传播仍可做，只是放在 Rust 内存里算**(不是 BPF map)：进程树上的 label 继承等价于 fork 时继承，fork 边直接用现有事件里的 `ppid` 推断 —— **无需新 eBPF**。

### 9.3 enforcement 力度三档（用户态可达）

| 档 | 机制 | 强度 | 取舍 |
|---|---|---|---|
| **A. Audit + 语义反馈** | 检测违规 → 把"违反规则 X + 建议"推回 agent loop | 不阻断 | 最贴 motivation，纯 Rust，无竞态顾虑 |
| **B. 反应式进程控制** | 检测 → `SIGSTOP`/`SIGKILL` 违规 pid | 弱阻断 | 有 TOCTOU 竞态，但能演示"真的拦住" |
| **C. Mediated execution** | ActPlane 包住工具调用 / 做 proxy 网关 | 强阻断 | 部分退回 tool-level 耦合 |

> Future track（需动 eBPF，本轮不做）：eBPF LSM `bprm_check_security`/`file_open` 返回 `-EPERM`，同步无竞态。文档保留此方向作为"真 OS enforcement"的升级路径。

### 9.4 要新增/修改的模块（全部 Rust + 前端）

**collector（新增 `framework/provenance/`）**
- `graph.rs`：进程/文件/远端端点 provenance graph（建议 `petgraph`）。节点 `Process{pid,exec_path}` / `File{path}` / `Endpoint{host[,path]}`；边 `Fork`/`Exec`/`Access`/`Connect`。增量维护 + taint label 传播。
- `ProvenanceAnalyzer`（实现现有 `Analyzer::process(stream)->stream`）：消费现有 `process`/`ssl` 事件，更新 graph，事件透传。放进 `analyzers/`。

**collector（新增 `framework/policy/`）**
- `dsl.rs`：解析 DSL → Rule AST。
- `engine.rs`：**用户态评估器**——拿 graph + taint 状态，对 exec/file/connect 事件判定 allow/deny，命中即 emit `source="denial"` 事件（带 rule 名 + 语义 reason）。(原"编译进 BPF map"的 `compiler.rs` 移到 future track。)

**collector（enforcement，新增 `ReactiveEnforcer` + `DenialFeedbackAnalyzer`）**
- `ReactiveEnforcer`(可选，档 B)：消费 denial 事件 → 对违规 pid 发信号。
- `DenialFeedbackAnalyzer`(档 A)：把 denial 格式化成语义消息送回 agent。**送达方式是开放问题**(§7)：被阻断操作 stderr 带理由 / agent harness 能读的 side channel / MCP 注入。

**剪枝（Rust 层，eBPF 输出照用不动）**
- **删**：`SSEProcessor`、HTTPParser 中 **response/对话重建** 部分 —— 我们不分析 prompt。
- **保留**：HTTPParser 的**请求侧**(method/Host/path 解析) → 喂 `Endpoint` 节点，支撑域名/path 级网络规则。
- `AuthHeaderRemover`：按日志脱敏需求决定去留。
- 资源指标相关(`SystemRunner` 消费、`ResourceMetricsView`)：与 enforcement 无关，可不接入。
- **注**：`sslsniff`/`process`/`browsertrace` 等 eBPF 程序**全部保持原样**，只是 Rust 侧选择消费/不消费其输出。

**frontend**
- 在现有 `buildProcessTree`/process tree 上叠加 enforcement：高亮被 taint 的子树、标记 denial、显示触发规则。
- Endpoint 节点接入图视图；Policy editor 放后期。

### 9.5 DSL 草图（v0）

```text
rule "codex-no-git" {
  taint source exec "**/codex"            // label 沿进程树传播到所有后代
  deny  exec    matching "**/git", "git"  // 禁止执行 git
  deny  write   path "**/.git/**"         // 禁止改 .git
  deny  connect host "api.github.com"     // 禁止连 github（用请求 header/SNI 判定）
  reason "Codex 不允许使用 git，请改用 review 流程。"
}
```

用户态语义：`codex_L` ← source matcher `**/codex`；`engine.rs` 对每个 exec/file/connect 事件查"当前 pid 是否带 codex_L 且目标命中 deny-set"，命中即 denial + `reason`。

### 9.6 分阶段路线（本轮 = Phase 0/1，纯 Rust + 前端）

- **Phase 0 — 用户态 audit + 语义反馈（MVP）**：`ProvenanceAnalyzer` 建图、`policy/engine.rs` 评估、emit denial、`DenialFeedbackAnalyzer` 提醒 agent。验证 graph + DSL + 规则 + 反馈闭环，零内核风险。
- **Phase 1 — 反应式 enforce + 前端可视化**：接 `ReactiveEnforcer`(档 B)跑通 **codex-no-git** demo（能演示拦住），前端叠加 taint/denial 视图。
- **Future track（需动 eBPF，本仓库本轮不做）**：eBPF LSM 同步阻断，去掉 TOCTOU，提供"真 OS enforcement"硬证据；可作为后续论文升级点。

Phase 0 已足以支撑核心 claim（graph 建模 + 规则可表达 + 提醒闭环），与 motivation("提醒后恢复")严丝合缝；Phase 1 给出"能拦住"的可演示效果。
