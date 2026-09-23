# ActPlane ↔ agent 集成（纠偏反馈闭环）

把 ActPlane **内核强制器**(eBPF 污点传播 + LSM)检测到的违规理由,回灌进
agent 的上下文,让合作型 agent 自我纠正、换路重试,而不是被一个干巴巴的
`Permission denied` 卡死。完整设计见 [`../docs/design/feedback-design.md`](../docs/design/feedback-design.md)。

> **判定永远在内核**:要不要拦、污点怎么传,全部由 eBPF + LSM 在 syscall 层决定
> ——这正是 ActPlane 不可绕过(`bash -c`、subprocess、直接 syscall 都拦得到)的根因。
> 集成层**只负责把内核已判定的违规理由"搬进"模型上下文**,不在用户态重新判定。

## 通道 (a1)：`actplane run` + 反馈文件 + agent 指引 + post-tool hook

`actplane run` 会自动为本次 agent run 创建独立反馈 mailbox:
`.actplane/runs/<run-id>/feedback.txt`,并把
`ACTPLANE_FEEDBACK_FILE` / `ACTPLANE_HOOK_STATE` 传给被运行的 agent。
`hook-state.json` 会记录本次 run 的 root pid,因此 hook 只会消费属于同一
agent 进程树的反馈。每条**内核检测到的**违规按 `docs/design/feedback-design.md`
的模板写入该 mailbox:

```bash
sudo -E actplane run codex --cd /work
sudo -E actplane --policy policies/readonly.yaml run claude -p "review"
```

被禁操作在 syscall 层被 LSM 拦下时返回 `-EPERM`,失败的命令把 exit≠0 + stderr
回灌模型。为了避免模型还要自己想起来读文件,把
`actplane feedback-hook` 配到 Codex/Claude 的 `PostToolUse` 类 hook 里;它每次
只消费一条尚未报告的反馈,把已报告内容从 mailbox 中删除,并以
`additionalContext` 回灌给模型。模型同时也应根据
[`CLAUDE.snippet.md`](CLAUDE.snippet.md)(粘进项目
`CLAUDE.md` / `AGENTS.md`)的指引,在看到 `[ActPlane]` 或 EPERM 时读反馈文件。

这覆盖一切路径——工具调用、`bash -c`、`python -c subprocess`、直接 syscall——
因为判定在内核,与 agent 用什么工具无关。

### Codex

`actplane init --with-codex` 会写入 `.codex/hooks.json`; Codex 会在
每次工具调用后自动运行 `actplane feedback-hook`。

Codex CLI 支持 `PostToolUse` hook。把下面内容写入 `.codex/hooks.json`
或 `~/.codex/hooks.json`,并替换 `actplane` 的绝对路径。

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "actplane feedback-hook",
            "statusMessage": "Checking ActPlane feedback"
          }
        ]
      }
    ]
  }
}
```

`PostToolUse` 发生在工具执行后,所以它不做阻断;它只让 Codex 在下一步推理前
收到内核已经判定好的纠偏理由。
交互式 Codex 需要先用 `/hooks` review/trust 这条 hook;一次性自动化可加
`--dangerously-bypass-hook-trust`。

### MCP autostart

ActPlane 的 MCP server 暴露两个 resource:

- `actplane:///policy`: 当前 `actplane.yaml` 的编译/校验结果。
- `actplane:///feedback`: 最新 `.actplane/last-violation.txt` 纠偏反馈。

优先使用项目 `.mcp.json`: `actplane init --with-mcp` 会自动写好,之后进入 Codex session
时会自动启动。如果你的 Codex 版本不读取项目 `.mcp.json`,再用下面命令注册
global MCP:

```bash
codex mcp add actplane -- actplane mcp --auto-attach-parent
```

不要同时配置 project `.mcp.json` 和 global `codex mcp add`,否则 Codex 可能启动
两个 ActPlane MCP/enforcer。MCP 启动时不新增任何 tool;它只暴露 resource,并在
`--auto-attach-parent` 下尝试 passwordless sudo 加载 eBPF、seed 父 Codex 进程。

### Claude Code

Claude Code 支持 `PostToolUse` 和 `PostToolUseFailure`。把下面内容写入
`.claude/settings.local.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "actplane feedback-hook"
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "actplane feedback-hook"
          }
        ]
      }
    ]
  }
}
```

## 端到端自测

```bash
sudo -E actplane run bash -lc 'git push'
ls .actplane/runs/*/feedback.txt
actplane doctor

# hook adapter smoke test
ACTPLANE_FEEDBACK_FILE="$PWD/.actplane/runs/<run-id>/feedback.txt" \
ACTPLANE_HOOK_STATE="$PWD/.actplane/runs/<run-id>/hook-state.json" \
  actplane feedback-hook <<<'{"cwd":"'"$PWD"'","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"true"}}'
```

## 不做：工具层事前 PreToolUse 预判

曾经考虑过一条 PreToolUse hook(在工具调用前用用户态规则**预判**命令)。已**移除**:
它不碰 eBPF、评估不了污点状态、且能被 `bash -c`/混淆命令绕过——本质上就是
ActPlane 要当 baseline 去打败的那类"工具层 guardrail",作为 feature 会稀释
"内核强制、工具层之下、不可绕过"的核心主张。若论文需要,它只应作为
eval 的**对照组**出现(证明纯工具层 hook 漏 `bash -c`/subprocess,反衬内核的必要),
而不是 ActPlane 的功能。

PostToolUse hook 不属于这类预判 guardrail:它发生在工具执行后,只搬运
ActPlane 已经写出的内核判定结果。
