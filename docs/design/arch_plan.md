# ActPlane Architecture Plan

ActPlane 的长期定位不是一个 Codex/Claude 插件，也不是一个单点 guardrail。
它应该是一个 **data-flow-aware agent runtime**: 负责运行、委托、限制、反馈和
审计 agent 及其 subagents。

一句话愿景:

> ActPlane is an OS-level runtime and policy hypervisor for AI agents.

换句话说，agent 不应该裸跑在主机上，而应该运行在 ActPlane 管理的 execution
scope 中。ActPlane 负责身份、策略层级、委托边界、数据流约束、恢复反馈和审计。

## Core Product Shape

ActPlane 应该分成三层:

```text
Agent Runtime
  管理 agent / subagent / tool process 的身份、生命周期、父子关系和任务上下文。

Policy Hypervisor
  管理无限层 policy stack，合并 root / project / session / task / delegation policy。

Data-Flow Enforcement Plane
  在 OS 层跟踪 process / file / network 之间的信息流，并执行 notify/block/kill。
```

底层实现可以是 eBPF、BPF-LSM、namespace、cgroup、worktree、mount scope 等，
但这些都不是产品定义本身。产品定义是: **agent 的执行不再只是进程，而是带身份、
策略、边界、反馈和审计的受控 session**。

## Big Features

### 1. Agent Runtime

ActPlane 需要知道“谁在运行”，而不仅仅是“哪个 PID 在运行”。

核心概念:

- `session_id`: 一次受控 agent session。
- `principal_id`: user、main agent、subagent、tool process、background worker。
- `parent_principal`: delegation 关系。
- `task_id`: 当前任务或子任务。
- `policy_layer_id`: 当前 principal 受哪一层 policy 约束。
- `workspace_scope`: 当前 principal 可读写的 workspace 范围。

目标 UX:

```bash
actplane run -- codex
actplane control status
```

用户看到的不是“启动了一个进程”，而是“启动了一个受控 agent session”。

### 2. Layered Policy Hypervisor

Policy 不应该是单个文件的静态规则集合，而应该是可无限扩张的 layer stack/tree。

```text
Layer[0]  ActPlane/root invariants
Layer[1]  user or org policy
Layer[2]  project policy
Layer[3]  session policy
Layer[4]  task policy
Layer[5]  delegated subagent policy
Layer[6]  nested delegated helper policy
...
```

固定的是语义，不是层数:

- child layer 只能收紧 parent layer。
- child layer 不能删除、降级或绕过 parent rules。
- declassify / endorse / approval capability 只能由 parent 授权。
- 每个 layer 都有 authority、principal、scope、policy overlay、capabilities 和 audit
  metadata。

核心公式:

```text
effective_policy(process) =
  merge_monotonic(root, org, project, session, task, delegation_chain(process))
```

这让 ActPlane 可以支持 main agent 创建 subagent policy，也支持 subagent 继续创建
nested helper policy，但任何 delegation 都只能更窄、更严格。

### 3. Delegation and Subagents

这是 ActPlane 最重要的长期 feature。

主 agent 应该能安全地创建 subagent:

```bash
actplane delegate --name reviewer --scope readonly -- codex exec ...
actplane delegate --name builder --scope worktree:feature-x -- claude ...
```

ActPlane 负责:

- 给 subagent 分配 identity。
- 创建或绑定隔离 workspace。
- 加载 delegated policy layer。
- 限制 subagent 的文件、网络、命令和 gate capability。
- 阻止 subagent 修改 parent policy、hooks、MCP config、feedback 和 audit。
- 收集 subagent feedback/audit。
- 回收 subagent session。

这等价于一种 agent-oriented policy sandbox，但不应该把项目收窄成传统 sandbox。
传统 sandbox 主要管资源隔离；ActPlane 还要管 delegation、data flow、provenance
和 corrective feedback。

### 4. Workspace and Resource Scopes

ActPlane 应该把“允许/拒绝”提升成“给 agent 分配正确的工作空间和资源”。

长期需要的 scope:

- read-only main workspace;
- writable delegated worktree;
- per-subagent temp/cache directories;
- secret mounts only for specific principals;
- network egress profiles;
- allowed command profiles;
- artifact output scopes.

例子:

```text
reviewer subagent: read repo, write only review notes
builder subagent: write only delegated worktree
tester subagent: run tests, write test logs, cannot commit
release subagent: deploy only after required gates
```

### 5. Data-Flow Policy

ActPlane 的差异化不是“文件 ACL”，而是 data-flow policy。

长期应该表达:

- secret-derived data cannot reach network;
- untrusted web content cannot directly influence shell/deploy;
- generated code cannot be released until reviewed;
- customer data cannot flow to third-party APIs;
- subagent output cannot enter main branch until validation;
- production credential material cannot enter logs or test artifacts.

这类约束不是普通 sandbox 能自然表达的。它要求 runtime 知道信息从哪里来、经过了谁、
最终要去哪里。

### 6. Gate and Approval System

`after exec pytest` 是 gate 的早期形态。长期需要更高层的 gate model:

- tests passed;
- static analysis passed;
- human approved;
- reviewer approved;
- policy owner approved;
- artifact signed;
- deployment attested.

Policy 应该能表达:

```text
deploy only if TESTED and REVIEWED and HUMAN_APPROVED
```

Gate token 应由 ActPlane 管理和审计，而不只是靠某个 exec pattern。

### 7. Feedback and Recovery

ActPlane 不应该只是让 agent 失败。它应该像 runtime exception handling:

```text
violation -> semantic feedback -> agent changes path -> task continues safely
```

反馈需要包含:

- rule name;
- operation;
- effect;
- reason;
- provenance;
- whether retrying unchanged is useful;
- suggested next step;
- policy layer that introduced the rule.

Agent integration layer 可以用 hook 或 MCP resource 传递反馈，但不应该成为 policy
authority。

### 8. Audit and Accountability

如果 ActPlane 是 agent runtime，audit 是核心 feature，不是附属日志。

需要记录:

- session timeline;
- principal / subagent tree;
- policy layer stack and hashes;
- process tree;
- violation events;
- data-flow provenance;
- gate / approval events;
- feedback delivered to agent;
- final artifact lineage.

目标命令:

```bash
actplane audit show
actplane audit export --jsonl
actplane replay <audit-log>
```

这对 debug、论文评估和真实生产使用都重要。

### 9. Policy Distribution

ActPlane 长期需要支持 policy-as-code:

- org-level baseline policies;
- repo/project policies;
- session overlays;
- signed policy bundles;
- versioned policy packs;
- policy compatibility checks;
- CI validation for policy changes.

Policy distribution 不应该让 agent 自己成为 root authority。agent 可以请求更严格的
delegation policy，但不能放宽上层 policy。

## High-Level CLI Surface

长期 CLI 可以收敛成这些大类:

```bash
actplane init
actplane init --all
actplane run -- <agent>
actplane control status
actplane doctor
actplane compile --explain
actplane compile --json
actplane control launch-child -- <subagent>
actplane control delta add --target-id <id> --delta policy.dsl
cat .actplane/last-violation.txt
```

MCP 保持 resource-first:

```text
actplane:///status
actplane:///policy
actplane:///feedback
actplane:///audit
```

MCP 不应该默认提供大量 policy-mutating tools。修改 policy、创建 delegation、发放
approval 这类动作应该走 ActPlane control plane，并验证 authority 和 monotonicity。

## Non-Goals

ActPlane 不应该变成:

- 普通容器替代品;
- 通用 EDR/SIEM;
- 单纯 Codex/Claude plugin;
- 工具层 PreToolUse guardrail;
- MCP tool collection;
- 只会 deny 的安全监控器。

ActPlane 可以使用 sandbox 技术，但核心价值是 **agent identity + layered policy +
data-flow enforcement + delegation + feedback + audit**。

## Milestones

建议路线:

1. Stabilize setup, doctor, feedback hook, MCP auto-attach.
2. Add `status` and `explain last`.
3. Add built-in control-plane self-protection.
4. Add policy layer metadata and effective policy hash.
5. Add `delegate` for subagent contracts.
6. Add workspace/resource scopes for delegated principals.
7. Add gate/approval tokens.
8. Add audit timeline and replay/export.
9. Add policy tests/simulation.
10. Add policy distribution and signed bundles.

## Summary

ActPlane 长期应该是:

> 一个 data-flow-aware agent runtime，把 agent、subagent、工具进程放进可委托、
> 可审计、可恢复的数据流 policy sandbox 里。

它不是“阻止某个命令”的工具，而是 agent 在真实机器上安全工作的 execution
substrate。
