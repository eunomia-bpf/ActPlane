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

> 完整注释书目见 [`reference/papers.md`](reference/papers.md)（21 篇 PDF 在 `reference/`）；开源项目对比见 [`reference/oss-landscape.md`](reference/oss-landscape.md)。本节是综合定位。

把三条线放在一起看，ActPlane 落在它们的**交集**里——没有单一工作同时占据：

**1. 学术界：图 + tag 传播，但只检测/记录。**
- **CamFlow**(SoCC'17) / **CamQuery**(CCS'18, `camquery-runtime-provenance.pdf`)：whole-system provenance + 在 LSM 实时流上跑用户分析。**最接近的 prior art**；差异：ActPlane 用 eBPF/BPF-LSM(非内核模块) + 显式 taint 传播策略 + AI-agent 威胁模型。
- **SLEUTH**(Sec'17)/**HOLMES**(S&P'19)/**RAIN**/**UNICORN**/**NoDoze**/**StreamSpot**：在依赖图上传播 tag 做攻击检测。**SLEUTH 是最接近的 taint 机制**(传播 integrity tag)——但用于检测，不预防。
- **DIFT**：TaintDroid/Dytan/libdft/Panorama（+ Schwartz survey）——真 taint，但在进程内(DBI/JVM/Android)，非 OS 级、无 enforcement。
- **provenance 访问控制**：PASS / Hi-Fi / LPM —— OS 溯源捕获基建，ActPlane 借其"沿系统边传播"的模型。

**2. 工业界 eBPF：内核内 enforce + 后代匹配，但只布尔 lineage、无数据流。**
- **Tetragon**(Cilium)：`matchActions: Sigkill`/`Override(-EPERM)` 内核阻断 + `matchBinaries followChildren` 后代匹配。**重叠最高、应复用其机制**；其局限：只沿 fork/exec 带**布尔** lineage、64 段上限、不匹配已存在子进程、无文件/网络 taint、无统一图 DSL。
- **bpfcontain/bpfbox**(Findlay, GPL-2.0)：eBPF-LSM 默认拒绝；bpfcontain 是 Rust + libbpf-rs（即 §9.2"Rust 直接加载"的现成参考）。做静态 per-process 限制，无 taint、非 agent 导向。
- **Falco**(检测,`proc.aname` 逐事件查祖先不传播)/**Tracee**(用户态签名)/**KubeArmor**(BPF-LSM Block 但 `fromSource` 单跳)。
- **KRSI/BPF-LSM**(LPC'19)、**eBPF-PATROL**：enforcement 底层机制参考。

**3. Agent 圈：dataflow DSL + enforcement，但在用户态工具层、可绕开。**
- **AgentSpec** / **Progent** / **GuardAgent**：agent 原生策略与 dataflow 约束，但作用在 MCP/工具调用层——agent 绕开工具 API（直接 Bash/SDK）即失效，正是本工作 §1 批判的点。
- **AgentSight**（于桐；eunomia-bpf maintainer）：本工作的观测基础，insight 一脉相承。

**ActPlane 的空位 = 三方交集**：把 **fork/exec + 文件 + 网络** 多类型 taint 传播放进一个引擎，用 **CamFlow 式 provenance 图** + **Tetragon 式 BPF-LSM enforcement** 合体，经 **sources/sinks/operation-type DSL**(§10) 表达，面向 **AI agent** 给语义反馈，但在**内核**里 enforce（agent 路由不过去）。

待办：动手验证 Tetragon 的 `followChildren` 与 `Override` 语义，确认复用边界；把 CamQuery、Tetragon 作为 evaluation 的 baseline。

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

## 9. 实现（as-built POC）

ActPlane 已从 AgentSight 的观测框架收敛成一个**专注的 taint-rule 工具**：内核做 taint 传播与检测，用户态只负责策略与上报。本节描述实际构建出来的东西。

### 9.1 内核：in-kernel taint（`bpf/process.bpf.c` + `bpf/taint.h`）

在原 `process` tracer 上**新增** taint 引擎（不删原有 exec/exit/file 功能）：

- **传播**：`sched_process_fork` hook 让子进程继承父进程的 taint label（`taint_labels` HASH map，pid→bitmask）。这等价于"污点沿进程树流动"，O(1)，无运行时图遍历。
- **打标 + 检测**：`sched_process_exec` 里，先取继承的 label，再扫描规则表——exec 命中某规则 `source` 则 OR 上该规则的 label；若当前 label 命中某规则的 `sink`，发一条 `EVENT_TYPE_TAINT_VIOLATION`（带 `rule_id` + `taint_label`）。
- **退出清理**：`sched_process_exit` 删除该 pid 的 label。
- **规则存储**：编译后的规则放在 **rodata 数组** `taint_rules_cfg[MAX_TAINT_RULES]`（不是 BPF map）——因为循环里的 map lookup 会阻止 clang 全展开、进而被 verifier 当成不可终止循环拒绝；rodata 常量索引读取可全展开成直线代码。
- **共享匹配逻辑**：`taint.h`（无 libc/libbpf 依赖）提供 `taint_comm_eq` / `taint_apply_sources` / `taint_check_sink`，同一份代码既被 eBPF 用，也被单测 `test_taint.c` 覆盖（14 个用例）。

> Enforcement 强度：本机内核（6.15）未启用 BPF LSM，故当前是"检测 + 上报"。`taint.h` 注释标明：在启用 BPF LSM 的内核上，同一套匹配逻辑可移进 `lsm/bprm_check_security` 返回 `-EPERM` 做同步阻断——这是升级路径，不改变上层接口。

### 9.2 Rust↔eBPF 交互

进程边界 + NDJSON（沿用仓库既有风格）：

```
taint.yaml ─▶ Rust policy ─(argv: -T source:sink)─▶ process loader ─(rodata)─▶ eBPF
  Rust 解析 violation NDJSON ◀──────── stdout ────────┘ 只打印 TAINT_VIOLATION
```

- **入口（Rust→C）**：`process -T SOURCE:SINK`（可重复）。C **不解析 YAML**，只把每条边塞进 rodata。
- **出口（C→Rust）**：每个违规一行 JSON `{"event":"TAINT_VIOLATION","comm","pid","ppid","filename","rule_id","taint_label"}`。taint 模式下**只有**这一种事件。
- **rule_id 回指**：内核只认边的序号（`rule_id = 边索引`，`label = 1<<索引`）；规则名/reason 留在 Rust，按 `rule_id` 反查。

### 9.3 用户态 loader（`bpf/process.c`）

最小改动：新增 `-T SOURCE:SINK` 选项 → 填 `skel->rodata->taint_rules_cfg` + `n_taint_rules`（load 前）；新增 violation 事件的 JSON 输出；`taint_mode` 下在 `handle_event` 顶部早返回，**抑制全部 exec/exit/file 噪音**，只放行 violation。通用 tracer 路径保持不变。

### 9.4 Rust collector（`collector/src/`，3 个文件）

streaming framework（Runner/Analyzer/EventStream）整体删除——taint 工具用不上。剩下：

- **`policy.rs`**：YAML 策略 → 扁平 `Edge{source,sink,rule_name,reason}` 列表；`edge_args()` 生成 `-T` 参数；按 `rule_id` 反查 reason。手写 YAML 解析（不引入 serde_yaml 依赖），7 个单测。
- **`main.rs`**：解析 `--config <yaml>` / `--rule SOURCE:SINK` → 编译边 → 解出内嵌的 `process` 二进制 → spawn `process -T …` → 读 stdout NDJSON → 带 reason 打印违规。约 130 行，无 trait、无流水线。
- **`binary_extractor.rs`**：解出内嵌的 `process` 二进制（保留）。

YAML 策略 schema：
```yaml
rules:
  - name: codex-no-git
    source: codex            # 此 exe 及其所有后代被打 taint
    deny: [git, ssh]         # 被 taint 的进程不允许 exec 这些
    reason: "Codex 不允许使用 git/ssh，请走 review 流程。"
```

运行：`sudo ./actplane --config taint.yaml`（或 `--rule codex:git`）。

### 9.5 删除清单（瘦身）

- collector：SSE/HTTP/SSL 分析器（sse_processor/http_parser/http_filter/ssl_filter/auth_header_remover，~1900 行）、ssl/stdio/system runners、整个 `server/`、Runner/Analyzer/EventStream 框架、对应子命令与 CLI flag、web 相关依赖。
- `frontend/` 整个删除（taint 工具是 CLI/NDJSON，无 web UI）。
- `docs/` 仅保留本研究计划。

eBPF 程序（`sslsniff`/`stdiocap`/`browsertrace`/`process_new`）按约定**保留功能**，只是 Rust 侧不再消费它们。

### 9.6 验证

- `bpf`：`make test` — 既有套件 + `test_taint` 共 63 项全过；`make process` 0 warning，verifier 通过加载。
- 端到端：`sudo ./actplane --config taint.yaml`，用 `codex`（重命名的 bash）exec `git`/`ssh` → 两条 violation 命中、`ls` 不误报、reason 正确显示。
- `collector`：`cargo test` — policy 7 项全过。

### 9.7 后续

- BPF LSM 同步阻断（`bprm_check_security` 返 `-EPERM`），去掉检测-上报的 TOCTOU。
- 文件/网络 sink（exec 之外）：`lsm/file_open`、socket/SNI/HTTP-请求-header（域名/path 级网络规则）。
- 反应式信号 / 把 reason 作为语义反馈回注 agent。

---

## 10. 通用 DSL 设计（文件 / 网络 / 多规则的 taint）

§9 的 POC 是最小特例：节点只有进程、匹配只有 `comm` 精确相等、传播只有 fork、sink 只有 exec。本节设计把它推广成**任意类型 taint + 多条规则 + 文件/网络**。

### 10.1 推广图模型：带类型的节点，标签放在所有节点上

- **节点类型**：`Process`(pid；身份=comm/exe/cmdline/uid)、`File`((dev,inode)；身份=path)、`Endpoint`(host:port；身份=SNI host/ip/port)。
- **关键推广：taint label 不再只在进程上，而在进程、文件、端点上都有**。这样才能表达"数据污点"——被污染进程写出的文件被污染、读了污染文件的进程被污染。

### 10.2 标准传播（边 → 转移函数，固定，不由 DSL 定义）

DSL 只声明 source/sink，传播规则是固定的一套（dataflow 闭包）：

| 事件 | 边 | 转移 |
|---|---|---|
| fork(p→c) | proc→proc | `L[c] ∪= L[p]` |
| exec(p, file f) | file→proc | `L[p] ∪= L[f]` + 应用命中 f 的 source |
| open/read(p, f) | file→proc | `L[p] ∪= L[f]` |
| write(p, f) | proc→file | `L[f] ∪= L[p]` |
| recv(p ← e) | endpoint→proc | `L[p] ∪= L[e]` |
| connect/send(p → e) | proc→endpoint | `L[e] ∪= L[p]`（或直接当 sink 判定） |

source 在命中节点**注入**标签；sink 在某操作处**检查**标签。

### 10.3 DSL 语法

每条规则 = 一个 label + 若干 source(注入点) + 若干 sink(禁止的操作·目标) + reason：

```text
rule "codex-no-git" {
  label  codex
  taint  process exe ~ "**/codex"        // source：命中的进程被打 codex
  deny   exec    path ~ "**/git"         // sink：带 codex 的进程不许 exec git
  deny   connect host = "api.github.com"
  deny   write   path ~ "/etc/**"
  reason "Codex 不允许碰 git / 改 /etc / 连 github"
}

rule "secret-no-exfil" {
  label  secret
  taint  file path ~ "/etc/secrets/**"   // source：读这些文件的进程被染 secret
  deny   connect host ~ "*"              // 带 secret 的进程不许联网
  deny   write   path ~ "/tmp/**"        // 也不许写 /tmp
  reason "密钥数据不得外泄"
}
```

通用形：
- `taint  <node-type> <attr> <op> <pattern>` —— source。`node-type∈{process,file,endpoint}`，`attr∈{exe,comm,cmdline,path,host,ip,port,uid}`，`op∈{= 精确, ~ glob, ^ 前缀, in 集合}`。
- `deny <operation> <attr> <op> <pattern>` —— sink。`operation∈{exec,open,read,write,connect,…}`；主体隐含为"携带本规则 label 的进程"。
- 多条规则 → 每个 label 占一位（≤64 用 u64 位掩码，O(1)；>64 改用 interned id + 小集合）。

### 10.4 匹配怎么做：两层（kernel / userspace）

不同 pattern 代价差很多。按"能否在内核廉价且同步匹配"分两层，编译器把复杂 pattern **降级**成内核原语：

| pattern | 内核可做 | 做法 |
|---|---|---|
| `comm =` | ✅ | 16B 精确比较（POC 已有） |
| `path =` / `path ^前缀` | ✅ | load 时解析成 `(dev,inode)` 集合 → 内核查 inode-set；或对 dentry path 做有界前缀比较 |
| `path ~ **glob**` | ⚠️ | userspace 用 glob 展开成 inode 集合 + inotify/fanotify 维护，推进内核 map；新建文件无法静态解析的，回落到**用户态逐事件匹配**（失去同步阻断，退化为检测+反馈） |
| `host =` / `host ~` | ⚠️ | 内核拿到的是 ip:port；userspace 经 DNS-snoop / TLS-SNI 维护 host→ip，把 ip-set 推进内核；或在内核对 SNI 串做有界匹配 |
| `ip in` / `port =` | ✅ | 内核集合/比较 |

**结论**：内核负责"能廉价且同步匹配"的部分（精确 comm、inode-set、ip-set、前缀）并可上 LSM 同步阻断；其余（任意 glob、域名）由 userspace 在事件流上评估，做检测+语义反馈。DSL 对用户是统一的，**由编译器决定落在哪一层**。

### 10.5 内核数据结构（推广 `struct taint_rule`）

把单一的 `(source_comm, sink_comm)` 拆成带类型 tag 的 **source matcher** 与 **sink check**：

```c
struct matcher {          // source：命中则注入 label
    __u8  node_type;      // PROCESS / FILE / ENDPOINT
    __u8  attr;           // COMM / EXE / PATH / HOST / PORT ...
    __u8  op;             // EXACT / PREFIX / INSET
    __u64 label;          // 命中后 OR 上的位
    union { char str[…]; __u32 setid; struct {__u32 dev; __u64 ino;} file; } operand;
};
struct sink_check {       // sink：某 operation 上检查 label & 匹配 target
    __u8  operation;      // EXEC / WRITE / CONNECT ...
    __u8  node_type, attr, op;
    __u64 label;          // 本 sink 守护的位
    __u32 rule_id;        // 回指 DSL（取 reason）
    /* operand 同上 */
};
```

标签存储按节点类型分表：`proc_labels`(pid→u64)、`file_labels`((dev,ino)→u64)、`endpoint_labels`。hook 扩展到：fork、exec(bprm)、file_open/read、vfs_write、socket_connect/sendmsg。

### 10.6 每事件的匹配算法（通用）

```
on EVENT(op, subject, target):
    # 1. 传播（若该 op 是传播边）
    if op ∈ {read,exec,recv}:  L[subject] |= L[target]      # object→subject
    if op ∈ {write,send}:      L[target]  |= L[subject]     # subject→object
    if op == fork:             L[child]   |= L[parent]
    # 2. source 注入（对刚触及的节点）
    for m in source_matchers if m.node_type==node.type and match(m, node):
        L[node] |= m.label
    # 3. sink 检查
    for s in sink_checks if s.operation == op:
        if (L[subject] & s.label) and match(s, target):
            report/deny(s.rule_id)
```

`match(m, node)` 按 `(attr, op)` 分派：exact comm / prefix path / inode∈set / ip∈set …。

### 10.7 与 POC 的关系（增量）

当前 POC = 此设计的特例：`node_type=PROCESS, attr=COMM, op=EXACT, operation=EXEC, 传播=仅fork`。推广是**纯增量**：加 `file_labels` 表 + open/write hook；加 endpoint + connect hook；把扁平 `taint_rule` 换成带 tag 的 matcher/sink_check 数组；加 userspace 编译器那一层处理 glob/域名。`taint.h` 的匹配谓词照旧单测。
