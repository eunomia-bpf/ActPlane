# ActPlane ↔ agent 集成（纠偏反馈闭环）

把 ActPlane **内核强制器**(eBPF 污点传播 + LSM)检测到的违规理由,回灌进
agent 的上下文,让合作型 agent 自我纠正、换路重试,而不是被一个干巴巴的
`Permission denied` 卡死。完整设计见 [`../docs/feedback-design.md`](../docs/feedback-design.md)。

> **判定永远在内核**:要不要拦、污点怎么传,全部由 eBPF + LSM 在 syscall 层决定
> ——这正是 ActPlane 不可绕过(`bash -c`、subprocess、直接 syscall 都拦得到)的根因。
> 集成层**只负责把内核已判定的违规理由"搬进"模型上下文**,不在用户态重新判定。

## 通道 (a1)：反馈文件 + agent 指引

强制器加 `--feedback-file`,每条**内核检测到的**违规按
`docs/feedback-design.md` §6 模板追加到该文件:

```bash
sudo actplane policy.dsl --feedback-file /work/.actplane/last-violation.txt
```

被禁操作在 syscall 层被 LSM 拦下时返回 `-EPERM`,失败的命令把 exit≠0 + stderr
回灌模型;模型据 [`CLAUDE.snippet.md`](CLAUDE.snippet.md)(粘进项目
`CLAUDE.md` / `AGENTS.md`)的指引,去读反馈文件拿到**这条违规的规则、原因、如何
改道**,定向重试。

这覆盖一切路径——工具调用、`bash -c`、`python -c subprocess`、直接 syscall——
因为判定在内核,与 agent 用什么工具无关。

## 端到端自测

```bash
sudo actplane policy.dsl --feedback-file /tmp/last-violation.txt &
# … 触发被禁操作 …
cat /tmp/last-violation.txt
```

## 不做：工具层事前 hook

曾经考虑过一条 PreToolUse hook(在工具调用前用用户态规则**预判**命令)。已**移除**:
它不碰 eBPF、评估不了污点状态、且能被 `bash -c`/混淆命令绕过——本质上就是
ActPlane 要当 baseline 去打败的那类"工具层 guardrail",作为 feature 会稀释
"内核强制、工具层之下、不可绕过"的核心主张。若论文需要,它只应作为
eval 的**对照组**出现(证明纯工具层 hook 漏 `bash -c`/subprocess,反衬内核的必要),
而不是 ActPlane 的功能。
