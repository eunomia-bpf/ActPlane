# ActPlane 纠偏反馈闭环（Corrective-Feedback Loop）设计

> **⚠️ 实现决策更新（2026-05）：通道 (b) 事前 PreToolUse hook 已从实现中移除。**
> 本文下面把通道 (b)（用户态在工具调用前预判命令、返回 `deny`）写成"首选注入通道 / 最高杠杆 MVP"——**这个定位是错的,已废弃**。理由:(b) 不碰 eBPF、评估不了内核里的污点状态、且能被 `bash -c`/混淆命令绕过,本质上就是 ActPlane 要当 baseline 去打败的那类"工具层 guardrail";把它当 feature 会稀释"内核强制、工具层之下、不可绕过"的核心主张。
> **当前唯一实现的通道是 (a1):内核(eBPF 污点 + LSM)检测违规 → `--feedback-file` 按 §6 模板落盘 → agent 在 EPERM 时读取。** 判定永远在内核,集成层只"搬运"已判定的理由,不在用户态重新判定。通道 (b) 若保留,只应作为 §8 eval 的**对照组**(证明纯工具层 hook 漏 `bash -c`/subprocess,反衬内核必要),而非产品功能。落地现状见 [`../script/agent-feedback.md`](../script/agent-feedback.md)。下文 §2/§3/§4/§7 中关于 (b) 的"首选/MVP"表述按此 banner 理解为**历史设计探讨**。

> 目标：把 ActPlane 内核强制器产出的**人类可读违规理由**回灌进 agent 的上下文，让**合作但健忘**的 agent（§威胁模型）自我纠正并重试，把"违规 → 干巴巴的 syscall 失败"升级成"违规 → 语义反馈 → agent 改道完成任务"。
>
> 本文聚焦两个主流 coding agent：**Claude Code** 与 **OpenAI Codex CLI**。先读 `docs/actplane-research-plan.md`（§5/§7/§11）与 `docs/taint-dsl.md`（§1.7 的纠偏反馈定位）。
>
> **定位**：这是 `actplane-research-plan.md` §6 claim 2（纠偏闭环）与 §9.7 第一条"最关键缺口"的落地设计。当前 as-built 只 emit/block，没有把 reason 注回 agent 让其自我纠正——本文补这一步。

---

## 0. 一句话结论

ActPlane 已经在内核侧产出"带理由的违规"（NDJSON 含 `effect` + `blocked`/`killed`，BPF-LSM 可返回 `-EPERM`，tracepoint fallback 可立即 `SIGKILL`）。**这两个 agent 在 2026 年都已经原生支持一套 PreToolUse hook 协议，且都能在 `deny` 时把一段理由字符串回灌给模型让它重试**——这正是纠偏闭环的天然注入点。因此本设计的核心不是"发明注入通道",而是把 ActPlane 的违规流**桥接**到这两条 hook 协议上,并定义清楚 audit/block/kill 的 harness 语义与理由载荷格式。

---

## 1. ActPlane 现状（已有能力，作为设计前提）

来自 `bpf/process.c` / `bpf/process.bpf.c` / `bpf/process.h` / `collector/src/main.rs` 的实际接口：

### 1.1 违规事件 NDJSON（C → Rust，loader stdout）
`bpf/process.c::handle_event` 对每个违规打印一行：
```json
{"timestamp":<ns>,"event":"TAINT_VIOLATION","effect":"audit|block|kill",
 "blocked":<bool>,"killed":<bool>,
 "comm":"<进程名,≤15B>","pid":<i32>,"ppid":<i32>,
 "target":"<被禁的目标:路径/命令/IPv4>","rule_id":<u32>,"taint_label":<u64>}
```
- `effect`：规则声明的结果；`audit` 只报，`block` 期望失败，`kill` 终止任务。
- `blocked=true`：BPF-LSM 钩子已返回 `-EPERM`，操作**被同步阻断**（无 TOCTOU）。
- `killed=true`：OS 给违规任务发出 SIGKILL；对合作 agent 来说，这是 harness-level enforcement，因为该 action 不能作为有效工具动作完成。
- `blocked=false && killed=false`：纯 audit（只报不拦）。
- `rule_id` 回指 DSL 规则；**reason 字符串不在内核**，由 Rust 侧 `compiled.reasons[rule_id]` 反查（见 `main.rs::report`）。

### 1.2 Harness-level enforcement 三档（已实现）
- **block**：`bprm_check_security`(exec) / `file_open` / `socket_connect` 等 BPF-LSM hook 命中即 `-EPERM`，操作在内核提交前失败。
- **kill**：exec 后或 audit fallback 中命中规则时，立即终止违规任务。它不是安全语义里的 pre-operation block，但它让 agent action 失败并触发纠偏反馈。
- **audit**：只上报，操作照常发生。

### 1.3 当前缺口（本文要补）
`main.rs::report` 把违规连同 reason **打印到 actplane 自己的 stdout** —— 给人看，**没有回到 agent 的上下文**。agent 这边只看到：
- enforce 模式：被阻断的 syscall 返回 `-EPERM`，工具层把它表现为"命令失败，exit≠0 + stderr"——但 stderr 里**没有 ActPlane 的 reason**，只有内核默认的 `Permission denied`。
- audit 模式：agent **什么都没看到**，操作成功了。

**关键观察（来自 Claude Code issue 调研）**：一个返回 `exit 1` 却没有任何说明的工具结果，"严格劣于"返回"exit 1, here is what broke"。这正是纠偏闭环的正当性——光阻断不给理由，agent 会困惑、瞎试、甚至放弃；带上 ActPlane 的 reason，agent 能定向改道。

---

## 2. 把 OS 级阻断回灌给 agent 的四条通用路径

任务给出的四条路径，按 ActPlane 的可行性与改造量排序：

| 路径 | 机制 | 同步性 | 改造量 | 适配 |
|---|---|---|---|---|
| **(a) 带理由的 errno** | 被阻断的 syscall 失败时，把 reason 写到进程 **stderr** / 已知文件 / 通过 errno+辅助消息 | 同步（随 LSM 阻断） | 中（需把 reason 送到被阻断进程的 stderr） | 任意 agent，框架无关 |
| **(b) hook/wrapper 注入** | 用 agent 原生 hook 拦截工具调用，注入 system/user 消息 | 同步（工具调用前） | 低（两个 agent 都原生支持 PreToolUse） | Claude Code / Codex 都有 |
| **(c) MCP tool 上报** | 把 ActPlane 暴露成 MCP server，agent 查询/被推送违规 | 异步 | 中 | 支持 MCP 的 agent |
| **(d) 监督循环** | 外部 supervisor 读 ActPlane 违规流，重新 prompt agent（headless `-p` / SDK 注入） | 异步（回合级） | 中 | headless / SDK 场景 |

**设计取舍**：
- **(b) 是首选注入通道**：Claude Code 与 Codex 都已原生支持 PreToolUse/PermissionRequest hook，能在工具调用**前**返回 `deny` + reason 并把 reason 回灌模型。这是同步、低改造、且**模型为之优化过的**纠偏入口。
- **(a) 是覆盖兜底**：hook 只能拦住"经过工具层、且 ActPlane 能预判"的调用；而 ActPlane 的卖点是**工具层之下**的覆盖（`bash -c`、`python subprocess`、直接 syscall）。这些路径 hook 看不见，必须靠 (a) 让被阻断的 syscall **带着 reason 失败**，理由进 stderr → 进工具输出 → 进模型上下文。
- **(c)/(d) 是 headless/无人值守场景的补充**，非主线。

**(a) 与 (b) 是互补而非互斥**：(b) 在工具边界做"事前软纠偏"（agent 还没真执行就被劝回，代价最低）；(a) 在 syscall 边界做"事中带理由硬阻断"（即兴改道也拦得到，但操作已被发起）。完整闭环 = (b) 兜上层 + (a) 兜底层。

---

## 3. Claude Code 集成

### 3.1 机制：hooks（事实依据）
Claude Code 的 hook 系统（`code.claude.com/docs/en/hooks`）关键点：
- **事件**：`PreToolUse`（工具调用前，**可阻断**）、`PostToolUse`/`PostToolUseFailure`（事后，不可阻断，可给反馈）、`UserPromptSubmit`（提交前，可注入 context）、`SessionStart`（可注入 `additionalContext`）、`Stop`/`SubagentStop`（可阻止结束）、`PermissionRequest`/`PermissionDenied`（权限相关，`PermissionDenied` 可返回 `retry:true`）等。
- **stdin**：hook 收到 JSON——`session_id`、`cwd`、`hook_event_name`、`permission_mode`、`tool_name`、`tool_input`（含 Bash 的 `command`、Edit/Write 的 `file_path` 等）、`tool_use_id`。
- **退出码**：`exit 0` → 解析 stdout 的 JSON；`exit 2` → **阻断**，stderr 回灌给 Claude 作为错误消息；其他非零 → 非阻断错误，stderr 只给用户看，**不给 Claude**。
- **PreToolUse 的 JSON 决策**（exit 0 时）：
  ```json
  {"hookSpecificOutput":{
     "hookEventName":"PreToolUse",
     "permissionDecision":"deny",        // allow | deny | ask | defer
     "permissionDecisionReason":"<回灌给模型的理由>",
     "modifiedToolInput":{...}           // 可选：改写工具输入
  }}
  ```
  官方语义："Claude reads the JSON decision, blocks the tool call, and shows Claude the reason." —— **`permissionDecisionReason` 进模型上下文，模型可改命令重试 / 申请审批 / 承认约束**。
- **顶层 `decision:"block"` + `reason`**：用于 `UserPromptSubmit`/`Stop` 等，把 reason 给模型并阻止前进。
- **`hookSpecificOutput.additionalContext`**：给 `SessionStart`/`UserPromptSubmit` 注入上下文（注意：PreToolUse **不支持** additionalContext）。

### 3.2 集成点：ActPlane → Claude Code 的两条注入

ActPlane 不是 Claude Code 进程内的组件，它是内核侧 + 一个 Rust daemon。因此用一个**薄 hook 适配器脚本**把两者接起来（配在用户 `.claude/settings.json` 的 hooks 里）：

**通道 (b) 事前软纠偏 —— PreToolUse hook：**
```
Claude Code ─(PreToolUse JSON: tool_name+tool_input)─▶ actplane-hook.sh
   actplane-hook.sh ──查询──▶ ActPlane policy 引擎（"这个工具调用会不会命中规则?"）
   命中 ─▶ 打印 {permissionDecision:"deny", permissionDecisionReason:<格式化 reason>} ─▶ exit 0
   不命中 ─▶ exit 0 空输出（放行）
```
- 适配器对 `tool_input.command`（Bash）/ `file_path`（Edit/Write）做**与内核同一套规则的预判匹配**（复用 `collector/src/dsl` 的编译产物：reason、target pattern、op）。这是"事前拦截"——agent 还没真跑 `git`，就在工具边界被劝回，代价最低、最干净。
- 这等价于把 ActPlane 的 DSL 当成 Claude Code 的一个 PreToolUse 策略引擎。**它解决不了 `bash -c 'g""it ...'` 之类的工具层混淆，那由通道 (a) 兜底。**

**通道 (a) 事中带理由硬阻断 —— LSM EPERM + reason 进 stderr：**
当 agent 绕过工具层语义（`bash -c`、`subprocess`、直接 syscall）真的发起被禁操作时，BPF-LSM 返回 `-EPERM`。要让 reason 跟着失败回到模型，有两个子方案：
- **(a1) 边车注入 stderr（推荐起步）**：ActPlane daemon 读自己的违规 NDJSON，按 `pid` 找到 agent 子进程，**把格式化 reason 写入该进程能看到的位置**——最简单是写一个**已知反馈文件**（如 `$WORKSPACE/.actplane/last-violation.txt`），并在 `CLAUDE.md`/system prompt 里告诉 agent："任何命令以 EPERM/Operation not permitted 失败时，读 `.actplane/last-violation.txt` 获取原因再决定下一步"。失败的 Bash 命令本就把 exit≠0 + stderr 回灌模型；模型据 CLAUDE.md 指引去读理由文件。
- **(a2) 内核侧带消息阻断（进阶）**：理想态是被阻断 syscall 的 stderr 直接带 ActPlane reason。纯 LSM 无法往用户态 stderr 写串，需配合一个 `LD_PRELOAD` shim 或 seccomp-user-notify 包裹层：拦到 `-EPERM` 时查 ActPlane 最近违规，把 reason 打到 stderr。这去掉了 (a1) 的"读文件"间接层，但改造量大，留作后续。

> **为什么 PostToolUse 不够**：PostToolUse 在工具**已执行后**触发、不可阻断。对 audit 模式可以用它做"事后反馈"（把刚发生的违规作为反馈推给模型），但对 block/kill 模式，失败发生在 syscall 或进程层，Claude Code 根本没把它当成一次"成功的工具调用"，所以纠偏主力是 PreToolUse + (a) 的 stderr/反馈文件路径。

### 3.3 文字版时序图（Claude Code）

**场景 A：工具层可预判（通道 b，事前软纠偏）**
```
1. 模型决定调用 Bash: command="git commit -m fix"
2. Claude Code 触发 PreToolUse hook，把 {tool_name:"Bash", tool_input:{command:"git commit..."}} 经 stdin 交给 actplane-hook.sh
3. actplane-hook.sh 用 ActPlane 规则预判 → 命中 "test-before-commit"（E5）
4. hook 打印:
     {"hookSpecificOutput":{"hookEventName":"PreToolUse",
       "permissionDecision":"deny",
       "permissionDecisionReason":
        "[ActPlane] 该 commit 被规则 test-before-commit 拦截。\n
         原因：本会话尚未运行测试套件。\n
         如何继续：先运行 pytest（或等价测试），通过后再 commit。"}}
   exit 0
5. Claude Code 阻断该 Bash 调用，把 permissionDecisionReason 作为上下文交给模型
6. 模型读到理由 → 改为先跑 pytest → 再 commit（这次 hook 放行）→ 任务完成
```

**场景 B：工具层绕过、内核兜底（通道 a，事中硬阻断 + 理由回灌）**
```
1. 模型调用 Bash: command="python -c \"import subprocess; subprocess.run(['git','push','--force'])\""
   （hook 的预判匹配可能识别不出这条混淆命令 → 放行到 syscall 层）
2. python 子进程 fork/exec git；git exec 命中 BPF-LSM bprm_check_security → 返回 -EPERM
3. git 启动失败；python 抛 "Operation not permitted"；Bash 命令 exit≠0，stderr 含 EPERM
4. 与此同时，ActPlane daemon 收到违规 NDJSON(blocked=true, rule_id=…)，把格式化 reason 写入 .actplane/last-violation.txt
5. Claude Code 把失败的 Bash 结果(exit≠0 + stderr)回灌模型
6. 模型据 CLAUDE.md 指引读取 .actplane/last-violation.txt → 拿到 "force push 被禁，请走 PR review" → 改道发 PR
```

### 3.4 配置形态（`.claude/settings.json`，示意）
```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Edit|Write",
        "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/actplane-hook.sh" } ] }
    ]
  }
}
```
（`actplane-hook.sh` 是 ActPlane 提供的薄适配器；它内部调用编译好的策略做预判，输出上述 JSON。）

---

## 4. Codex CLI 集成

### 4.1 机制：hooks（新）+ notify（旧）（事实依据）

**(1) Hooks（2026 已支持，与 Claude Code 同源协议）** —— `developers.openai.com/codex/config-reference`：
- 用 `features.hooks = true` 开启，规则放 `hooks.json` 或内联 `[hooks]`。
- 事件：`PreToolUse`、`PermissionRequest`、`PostToolUse`、`PreCompact`/`PostCompact`、`SessionStart`、`SubagentStart`/`SubagentStop`、`UserPromptSubmit`、`Stop`。
- `hooks.json` 形态（与 Claude Code 几乎一致）：
  ```json
  {"hooks":{"PreToolUse":[
     {"matcher":"^Bash$",
      "hooks":[{"type":"command","command":"python3 ~/hooks/actplane_gate.py","timeout":10}]}
  ]}}
  ```
- **stdin JSON**：`session_id`、`turn_id`、`transcript_path`、`cwd`、`hook_event_name`、`model`、`permission_mode`、`tool_name`、`tool_input`（含 `command`）、`tool_use_id`。
- **退出码**：`exit 0` → 解析 stdout JSON；`exit 2` → **阻断**，stderr 含理由；其他码 → hook 失败，**fail-open**（操作放行）。
- **JSON 阻断（PreToolUse）**：
  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse",
     "permissionDecision":"deny",
     "permissionDecisionReason":"rm -rf is not allowed in production"}}
  ```
  或 legacy：`{"decision":"block","reason":"..."}`。
  官方语义："The permissionDecisionReason is fed back to the model." —— **理由回灌模型，可改道重试**。
  注意差异：Codex 的 PreToolUse **只支持 `deny`**，`allow`/`ask` 会返回 `Failed`；且 **不支持 `additionalContext`**（返回会失败）。

**(2) notify（旧，仅事件通知，不能阻断）** —— `developers.openai.com/codex/config-advanced`：
- 根级 `notify = ["/bin/bash", "/path/notify.sh"]`，运行外部程序。
- **JSON 作为 `argv[1]` 传入（不是 stdin）**。
- 截至 2026-03，外部 notify 只对 `agent-turn-complete` 触发（`approval-requested` 事件存在但 notify 不为它触发——见 openai/codex#11808）。
- 用途：回合结束的 webhook/桌面提醒。**不能用来事前阻断**，但可做**回合级事后反馈**（通道 d 的触发器）。

**(3) sandbox + approval（Codex 自带的 OS 级隔离，与 ActPlane 互补）** —— `developers.openai.com/codex/concepts/sandboxing`：
- `sandbox_mode`：`read-only` / `workspace-write`（可配 `writable_roots`、`network_access`）/ `danger-full-access`。
- `approval_policy`：`untrusted` / `on-request` / `never`（`on-failure` 已废弃）；可 `granular` 细分 `sandbox_approval`/`rules`/… ；`approvals_reviewer = user | auto_review`。
- **关键行为**：任务在 sandbox 边界内时 Codex 自动推进；**越界时"falls back to the approval flow"（升级到审批）**。沙箱失败检测是**启发式的**（从 stderr 关键词 + exit code 推断）。
- **坑（来自 issue 调研）**：当 shell 在 sandbox setup 阶段就失败、且**没有错误返回给模型**时，模型会在几轮推理后**放弃**而非重试——再次印证"阻断必须带理由"。

### 4.2 集成点：ActPlane → Codex

**通道 (b) 事前软纠偏 —— PreToolUse hook（首选，与 Claude Code 对称）：**
```
Codex ─(PreToolUse JSON via stdin)─▶ actplane_gate.py
   命中 ─▶ 打印 {permissionDecision:"deny", permissionDecisionReason:<格式化 reason>} ─▶ exit 0
        或 exit 2 + reason 进 stderr（等价阻断路径）
   不命中 ─▶ exit 0 空（fail-open 放行）
```
- 与 Claude Code 复用**同一个策略预判核**，只换 I/O 适配（Codex 也走 stdin JSON、同样的退出码/JSON 语义）。
- 注意 Codex PreToolUse 不支持 `additionalContext`/`allow`/`ask`——格式化载荷只能进 `permissionDecisionReason` 或 stderr。

**通道 (a) 事中硬阻断 —— LSM EPERM + reason：**
与 Claude Code 完全相同（ActPlane 在 syscall 层，agent 身份无关）。Codex 的 sandbox 失败检测本就**从 stderr 关键词推断**并可**升级审批**——这给了 ActPlane 一个额外杠杆：让被阻断 syscall 的 stderr 带上可识别前缀（如 `[ActPlane] ...; EPERM`），Codex 更可能把它当成"可恢复的越界"走 approval/重试，而非"硬故障"放弃。reason 文件路径写进 `AGENTS.md`（Codex 的 CLAUDE.md 等价物）。

**通道 (d) 回合级监督 —— notify + headless：**
对无人值守 Codex，可用 `notify` 在 `agent-turn-complete` 触发一个 supervisor：它读 ActPlane 这一回合的违规流，若有未纠正违规，用 headless 方式把"上一回合触发了规则 X，原因 Y，请改道"作为下一条消息喂回。这是异步兜底，非主路径。

### 4.3 文字版时序图（Codex）

**场景 A：PreToolUse 事前软纠偏**
```
1. 模型决定执行 shell: command="git push --force origin main"
2. Codex 触发 PreToolUse hook（features.hooks=true），stdin 交 {tool_name:"Bash"/"shell", tool_input:{command:"git push --force..."}} 给 actplane_gate.py
3. actplane_gate.py 预判命中 "confirm-destructive"（E11）
4. 打印 {"hookSpecificOutput":{"hookEventName":"PreToolUse",
        "permissionDecision":"deny",
        "permissionDecisionReason":
         "[ActPlane] force-push 被规则 confirm-destructive 拦截。\n
          原因：破坏性操作需 lineage 内有显式 confirm 步骤。\n
          如何继续：先运行确认步骤（confirm 工具），或改用非破坏性 push。"}}
   exit 0
5. Codex 阻断该 shell 调用，把 permissionDecisionReason 回灌模型
6. 模型改道（去掉 --force / 走确认）→ 完成
```

**场景 B：sandbox 越界 + ActPlane 内核兜底**
```
1. 模型 shell: 在 read-only / workspace-write 下尝试写 /etc 或联网 exfil
2a. 若命中 Codex 自带 sandbox → Codex 升级到 approval flow（自带行为）
2b. 若用 bash -c/subprocess 绕过 Codex 工具语义 → BPF-LSM file_open/socket_connect 返回 -EPERM
3. 命令以 EPERM 失败；stderr 带 [ActPlane] 前缀 + 内核 Permission denied
4. ActPlane daemon 把 reason 写 .actplane/last-violation.txt
5. Codex 把失败结果(stderr+exit)回灌模型；模型据 AGENTS.md 指引读理由 → 改道
```

---

## 5. 软纠偏 vs 失败强制 vs 允许重试 —— 语义模型

把 `actplane-research-plan.md` §9.7（"对合作 agent，要让违规动作失败 + 给理由 + 允许换路重试"）形式化成**三档 effect × 反馈**的矩阵。每条 DSL 规则带一个 `effect` 标注（默认 `block`）。这里的 enforcement 是 harness 语义：违规动作不能作为有效 agent action 完成；它可以是 LSM pre-op deny，也可以是 immediate SIGKILL。

| 档位 | 内核行为 | agent 看到 | 何时用 | 重试语义 |
|---|---|---|---|---|
| **audit（软纠偏）** | audit-only，操作**照常发生** | 事后反馈："你刚做了 X，违反规则 R（原因 …），后续请避免" | 风格/流程类软约束（如"refactor 阶段尽量不联网"）；误报代价 > 漏报代价 | 无需重试，操作已成功；只塑造后续行为 |
| **block（同步失败 + 纠偏）** | LSM `-EPERM`，操作**被同步拦下**；无 LSM 时可由 `--kill-on-violation` 升级为 kill | 工具失败 + reason（经 hook deny 或 stderr）："X 被拒绝，原因 …，如何改道 …" | 默认档；可逆且有替代路径的操作（git/写文件/联网） | **鼓励重试**：reason 给出可行 alternative，agent 换路再来 |
| **kill（终止失败 + 纠偏）** | SIGKILL；LSM 可用且命中发生在 pre-op hook 时也返回 `-EPERM` | 违规任务被终止，agent 看到失败 + reason | 需要根据 post-exec 参数判断、或无 LSM 时仍要让动作失败 | 重试同一路径无用；按 reason 换路 |

### 5.1 retry 与 declassify/gate 如何交互（核心语义）
ActPlane 的 DSL 已有 `declassify`/`endorse`/`lineage-includes`/`after` 这些"放行条件"（`taint-dsl.md` §1.6/§1.7）。纠偏闭环让这些条件**变成给 agent 的可执行指令**：

- **`block`/`kill` + 替代路径**：reason 里直接写"改用 Y"。agent 重试 Y，不命中规则 → 成功。例：E9 no-git → "不要直接 git；用 PR 工具"。
- **`gate`(lineage-includes/after) + 重试**：reason 写"先执行门 G，再重试原操作"。agent 跑 G（如 `pytest`/`confirm`/`human-approve`）——这会在内核侧改变它的 lineage/after 状态——**然后重试同一操作即被放行**。这是 retry 与 gate 的正向交互：
  ```
  E5 test-before-commit:
    第1次 commit → block，reason="先跑 pytest"
    agent 跑 pytest → 内核记录 after(pytest) 进该 lineage
    第2次 commit → 放行（after 条件满足）
  ```
- **`declassify` + 重试**：对机密外泄类（E1/E8），reason 写"先经 redact 脱敏再发"。agent 跑 redactor → 内核 `declassify SECRET` 清掉污点 → 重试 connect 被放行。
- **防重试风暴**：同一 `(pid-lineage, rule_id)` 的违规要**去重 + 退避**——若 agent 反复撞同一规则 N 次仍不改道，反馈应升级措辞（"你已多次尝试 X 且被拒绝，这是 harness 约束，请彻底换方案"），必要时降级到 `gate`→人工。这避免合作 agent 陷入"失败-重试"死循环（呼应 Codex#... sandbox 反复失败的坑）。

### 5.2 决策表：给定规则，选哪档？
```
操作不可逆 / 高破坏性(force-push, rm 生产数据, drop DB)      → gate（要 confirm/review）
操作可逆且有明确替代(git→PR, 写 /etc→写 workspace, 直连→走代理) → block/kill + 替代路径
约束是软流程/风格(阶段性不联网, 提交信息规范)               → audit（事后反馈）
机密/PII 外泄                                              → block，且仅 declassify 后放行
仅 audit 环境兜底                                          → 默认 audit；需要动作失败时用 kill
```

---

## 6. 理由字符串如何面向模型格式化（纠偏反馈载荷）

reason 现在是给人看的一句话（`compiled.reasons[rule_id]`）。面向模型要**结构化、可执行、克制**。提出固定模板 `[ActPlane] <规则> <发生了什么> <为什么> <怎么继续>`：

### 6.1 模板（block/kill 档）
```
[ActPlane] 操作被规则「{rule_name}」拒绝。
- 目标操作：{op} {target}            （如 exec /usr/bin/git push --force）
- 触发原因：{reason}                  （DSL 里写的人类可读理由）
- 这是一条 OS 层 harness 约束，无论用工具、bash 还是直接调用都会失败，重试相同操作不会成功。
- 如何继续：{remediation}             （可执行的替代/前置步骤）
```

### 6.2 模板（gate 档，强调"先满足门")
```
[ActPlane] 操作「{op} {target}」需要先完成一个前置步骤（规则 {rule_name}）。
- 原因：{reason}
- 放行条件：先执行 {gate_action}（例如：运行 pytest / 调用 confirm / 经 human-approve），然后重试本操作即可通过。
```

### 6.3 设计原则（最大化自我纠正成功率）
1. **可执行的 remediation 比禁令更重要**：不要只说"不许 git"，要说"用 `gh pr create` 走 review"。研究（PALADIN/AgentDebug，§参考）表明定向修复信号能把恢复率从 ~33% 提到 ~90%，泛泛报错收益小。
2. **明确"重试相同操作无用"**（block/kill 档）vs "满足条件后重试有效"（gate 档）——直接消除 agent 的两类常见误判（瞎重试 / 误以为彻底没路）。
3. **声明这是 OS 层、跨路径 harness 约束**：阻止 agent 去试 `bash -c`/`subprocess` 绕过（它绕不过，明说省 token 省轮次）。
4. **短**：模型对长 system 噪声不敏感；4 行以内、字段化。
5. **稳定前缀 `[ActPlane]`**：便于 agent（和我们的 eval 脚本）识别这是强制反馈而非普通报错；也利于 Codex 的 sandbox 启发式把它归类为"可恢复越界"。
6. **机器可读副本（可选）**：在 reason 末尾附一行 JSON（`{"actplane_rule":"...","effect":"block|audit|kill","retry_useful":false}`），供 SDK/监督循环结构化消费。

### 6.4 与现有 DSL 的对接
`reason "..."` 字段保持人类可读不变；**remediation 留在 Rust 侧，effect 进入内核 ABI**，由 `te_handle_event()` 根据命中的 rule 决定 audit/block/kill。`main.rs::report` 保留人类可读 stdout，同时按模板组装载荷并在启用 `--feedback-file` 时写入反馈文件。

---

## 7. 最小原型方案（MVP）：先做哪一步、怎么接

在已有能力（违规 NDJSON 含 `effect`+`blocked`/`killed`、LSM 可 `-EPERM`、fallback 可 `SIGKILL`）之上，**最小、最高杠杆的一步是通道 (b) 的 PreToolUse hook 适配器**——因为两个 agent 都原生支持、改造量最低、且是同步事前纠偏。

### 7.1 MVP 范围（一周量级）
1. **`actplane-hook`（薄适配器，新文件）**：读 stdin 的 hook JSON，提取 `tool_name`+`tool_input.command`/`file_path`，调用一个**策略预判函数**（复用 `collector/src/dsl` 编译产物的 reason + target pattern + op，对命令做保守匹配），命中则按 §6 模板输出 `permissionDecision:"deny"` + `permissionDecisionReason`，exit 0；否则空 exit 0。一个二进制，Claude Code 与 Codex 共用（两者 hook I/O 协议一致）。
2. **`main.rs::report` 改造**：把"打印给人"扩展成"按 §6 模板格式化"，并支持把违规写入 `.actplane/last-violation.txt`（通道 a1 的反馈文件）。新增 `--feedback-file <path>`。
3. **CLAUDE.md/AGENTS.md 片段**：提供一段标准说明，指导 agent "命令以 EPERM 失败时读 `.actplane/last-violation.txt`"。这把通道 (a1) 接通，覆盖 hook 看不见的绕过路径。
4. **rule effect**：DSL 已支持 `effect block|audit|kill`（默认 block）+ `remediation "..."`；`effect` 编译进内核规则表，`remediation` 用于反馈。

### 7.2 MVP 不做（留后续）
- (a2) LD_PRELOAD/seccomp-user-notify 把 reason 直接打进被阻断 syscall 的 stderr（去掉读文件间接层）。
- (c) MCP server 形态。
- hook 预判与内核规则的**完全一致性证明**（MVP 接受 hook 预判是"尽力而为的上层快路径"，内核才是 ground truth）。

### 7.3 为什么这个顺序
- PreToolUse hook 是**两个 agent 共有**的、模型已优化过的纠偏入口，单点接入即可同时覆盖 Claude Code 和 Codex。
- 通道 (a1) 用"反馈文件 + CLAUDE.md 指引"以**零内核改动**接通绕过路径的纠偏，验证闭环价值后再上 (a2)。
- `effect`/`remediation` 已接入后，后续 hook 与反馈文件工作主要停留在 Rust/脚本层，不需要继续扩大内核 ABI。

---

## 8. 评测设计

沿用 `docs/agent-policy-survey.md` §7 已确立的**四条件对照**（本设计据此细化反馈侧指标）。每个评测场景 = {一条 DSL 规则（带 provenance）, 编译后 `.dsl`, 诱发违规的 agent 任务 prompt, 期望违规, baseline}，在 **Claude Code 与 Codex 上各跑一遍**。

### 8.1 四个条件（对照）
| 条件 | 强制 | 反馈 | 测什么 |
|---|---|---|---|
| **C1 prompt-only** | 无（规则只写进 CLAUDE.md/AGENTS.md） | 无 | 基线违规率——"本就会违反"。若恒为 0 则该规则无证据价值，剔除。 |
| **C2 audit** | 只报不拦（操作发生） | 无（agent 看不到） | 隔离"强制本身"的效果 vs prompt |
| **C3 fail-no-reason** | LSM `-EPERM` 或 SIGKILL | **无 ActPlane reason**（只有默认 Permission denied/terminated） | 隔离"光让动作失败不给理由"——agent 能否靠自己恢复 |
| **C4 fail + 纠偏反馈** | LSM `-EPERM` 或 SIGKILL | **有**（§6 模板，经 hook/stderr/反馈文件回灌） | 本设计的核心：反馈是否让 agent 自我纠正并仍完成任务 |

C3 vs C4 的差是**纠偏反馈的净贡献**；C1 vs C2 是强制的净贡献；C2 vs C3 是动作失败强制 vs 事后上报的差。

### 8.2 指标
- **任务完成率**：agent 在被约束下**仍完成原任务**的比例（C4 应显著 > C3；这是反馈的核心价值——把"动作失败"变成"换路完成"）。
- **重复违规率 / 纠正迭代数**：同一规则被反复触发的次数（C4 应 < C3；衡量"提醒后能否定向改道"）。研究基线参照：metacognitive monitor +7~8%、AgentDebug 最高 +26% 相对、PALADIN 恢复率 33%→90%——ActPlane 的反馈应落在这个量级或更好（因为反馈是**定向 remediation**，不是泛泛报错）。
- **过度阻断 / 误报率**：拦住正常工作的比例（与命中率同等重要——`actplane-research-plan.md` §7 反复强调；harness 误报比 prompt 更糟）。audit vs block vs kill/gate 档位选择直接影响此项。
- **跨路径覆盖（D6 直接验证）**：同一规则在 *工具调用* / `bash -c` / `python -c subprocess` / 直接 syscall 四条路径上是否都能失败+反馈。这是"工具层之下覆盖"卖点的硬证据，也直接对比 C4 的 hook 通道(只覆盖前者) vs 内核通道(覆盖全部)。
- **反馈质量消融**：在 C4 内部再对比 reason 格式——(i) 纯禁令 vs (ii) §6 带 remediation 模板 vs (iii) 不声明"重试无用/有用"。验证 §6.3 各原则的贡献。
- **系统开销**：标签传播 + LSM 检查的 ns 级开销、hook 适配器延迟（PreToolUse 在关键路径上，需 < 工具调用本身的噪声）。

### 8.3 场景集
直接取 `taint-dsl.md` 的 E1–E12 作为评测场景（已有编译+e2e），按是否**可诱发违规且有替代路径**筛：
- **block/kill + 替代路径**：E9(no-git→PR)、E4(workspace 限制→写 /work)、E6(只读子 agent)。
- **gate + 重试**：E5(test-before-commit→先 pytest)、E11(force-push→先 confirm)、E3(prod.db→经 migrate)。
- **declassify + 重试**：E1/E8(secret→先 redact)、E10(PII egress→走 internal)。
- **integrity/multi-label**：E2(注入→需 review)、E12(任务隔离)。

### 8.4 关键假设（要验证/证伪）
- **H1**：C4 任务完成率 > C3（带理由的阻断让 agent 换路成功，而非卡死）。
- **H2**：C4 重复违规数 < C3（定向 remediation 减少瞎试）。
- **H3**：内核通道（a）的跨路径覆盖严格优于 hook 通道（b）单独（b 漏 `bash -c`/subprocess，a 全覆盖）——证明"工具层之下"的必要性。
- **H4**：gate 档的"满足条件后重试放行"能在不牺牲约束的前提下保住完成率（vs 无条件 block/kill）。

---

## 9. 风险与开放问题
1. **hook 预判 ≠ 内核 ground truth**：通道 (b) 的命令匹配是上层启发式，可能漏判（混淆命令）或误判（保守误杀）。设计上把它定位成"快路径软纠偏"，内核 (a) 才是完备兜底——两者不要求一致，但要避免 (b) 的误判恶化体验。
2. **(a1) 依赖 agent 配合读反馈文件**：合作 agent（本威胁模型）会读；但若 CLAUDE.md 指引被长上下文稀释，agent 可能忽略理由文件。(a2) 直接进 stderr 更稳，但改造大。需在 eval 里量化 (a1) 的"理由触达率"。
3. **Codex PreToolUse 限制**：不支持 `additionalContext`/`allow`/`ask`，载荷只能进 `permissionDecisionReason`/stderr；且 fail-open（hook 崩溃即放行）——适配器必须健壮、低延迟。
4. **反馈风暴 / 死循环**：§5.1 的去重+退避+升级措辞是必需项，否则合作 agent 可能在硬约束上反复撞墙耗尽预算。
5. **理由可能被注入滥用**：reason 进模型上下文，理论上是一条"可信通道"。本威胁模型（合作非对抗）下风险低，但 reason 文案应避免可被外部内容篡改的拼接（如把被禁 URL 原样回显需转义）。

---

## Sources

- Claude Code — Hooks reference（事件、退出码、`permissionDecision`/`permissionDecisionReason`/`decision:block`/`additionalContext`、stdin 字段、deny→模型反馈语义）：<https://code.claude.com/docs/en/hooks>
- Claude Code — Hook control flow（exit 2 阻断 + stderr 回灌 Claude 的语义）：<https://stevekinney.com/courses/ai-development/claude-code-hook-control-flow>
- Claude Code — Hooks 生命周期事件总览：<https://claudefa.st/blog/tools/hooks/hooks-guide>
- Claude Code — Agent SDK hooks / 权限（headless `-p`、HookJSONOutput、permission deny reason）：<https://platform.claude.com/docs/en/agent-sdk/hooks> ；<https://platform.claude.com/docs/en/agent-sdk/permissions>
- Claude Code — Bash 工具把 exit code/stderr 回灌模型；"exit 1 无说明 严格劣于 带原因失败"（佐证"阻断必须带理由"）：<https://github.com/anthropics/claude-code/issues/51814> ；<https://bjro.dev/posts/claude-code-bash-exit-1-no-output-tmpfs-full/>
- Codex — Configuration Reference（`features.hooks`、`hooks.json`、事件清单、`sandbox_mode`、`approval_policy`、`approvals_reviewer`、`notify`）：<https://developers.openai.com/codex/config-reference>
- Codex — Advanced Configuration（`notify` 程序、JSON 作为 argv[1]、`agent-turn-complete`）：<https://developers.openai.com/codex/config-advanced>
- Codex — CLI Hooks 完整指南（hooks.json 格式、stdin JSON、exit 0/2/其他 + fail-open、`permissionDecision:deny`/`decision:block`、`permissionDecisionReason` 回灌模型；PreToolUse 不支持 allow/ask/additionalContext）：<https://codex.danielvaughan.com/2026/04/15/codex-cli-hooks-complete-guide-events-policy-patterns/>
- Codex — Sandbox 概念（read-only/workspace-write/danger-full-access；越界 falls back to approval flow）：<https://developers.openai.com/codex/concepts/sandboxing>
- Codex — Agent approvals & security（approval policy、justification/reason 在审批与拒绝消息中呈现）：<https://developers.openai.com/codex/agent-approvals-security>
- Codex — Custom instructions with AGENTS.md（项目指令文件，CLAUDE.md 等价物）：<https://developers.openai.com/codex/guides/agents-md>
- Codex — `notify` 仅对 turn-complete 触发、approval-requested 不触发（佐证 notify 只能事后/回合级）：<https://github.com/openai/codex/issues/11808>
- Codex — sandbox 失败时无错误返回模型导致放弃（佐证"阻断必须带理由"）：相关 issue 见 <https://github.com/openai/codex/issues/4934>
- 研究：metacognitive monitor 提升任务成功率 ~7–8%：<https://www.emergentmind.com/topics/self-corrective-agent-architecture>
- 研究：PALADIN 工具失败恢复（恢复率 32.76%→89.68%）：<https://arxiv.org/pdf/2509.25238>
- 研究：AgentDebug 定向反馈使任务成功率最高 +26% 相对：<https://openreview.net/forum?id=PFR4E8583W>
- 研究：Structured Reflection for Reliable Tool Interactions（结构化反思优于启发式自纠）：<https://arxiv.org/html/2509.18847v2>
