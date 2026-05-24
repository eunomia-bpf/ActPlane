# ActPlane 实验(Round-1 结果)

面向 OSDI 的实验。**所有 benchmark 的规则集都从真实语料 `docs/corpus`(144 个流行 AI-agent 仓的
CLAUDE.md/AGENTS.md)提取、带 provenance、可复算**,不是自造 toy 规则。计划书:
`docs/tmp/eval-plan.md`;提取方法学:`ruleset/protocol.md`。

## 硬约束(本轮)
- 本机**无 BPF-LSM**(`/sys/kernel/security/lsm` 无 `bpf`)→ `effect block`(-EPERM 优雅可重试)
  跑不了;**全程只用 `audit`(只报)+ `kill`(终止)**。"不可绕过"由 kill 在各路径终止证明,
  "跨路径检测"由 audit 在各路径上报证明。
- agent 实验小 N(单场景),**非显著性结论**。
- 复现:每个 exp 目录有脚本;`bash docs/experimental/run_all.sh`(需 sudo 的步骤已标注)。

## Phase 0 — 语料派生规则集(基石)
`ruleset/ruleset.jsonl`:**32 条可强制规则**,从 144 仓的 529 条已编码候选行聚类而来。
- **provenance**:每条带跨仓频率 + 真实原文引用。**32/32 引用经真实文件核验,32/32 DSL 经
  `actplane compile` 通过**(`ruleset/verification.md`)。
- freq≥10 仓 11 条、≥3 仓 24 条;复杂度 tier-3(污点流/declassify/多标签)8 条、tier-2 21 条、tier-1 3 条。
- **双来源**:codex 独立提取 36 条(`raw_codex_extraction.jsonl`,**引用 36/36 真实**,但其 DSL 语法无效
  0/36——codex 不知确切文法);我们确定性聚类 + 领域编码 32 条(`ruleset.jsonl`,**DSL 32/32 编译、引用
  32/32 核验**)。两来源**类别分布高度一致**(均以 vcs-gating/secrets/mediation/approval/test 为主)=
  交叉印证。实验用可编译的 `ruleset.jsonl`。

## 结果汇总

| 实验 | 指标 | 结果 |
|---|---|---|
| **A 跨路径覆盖** | (op×path) 检测矩阵 | **ActPlane 11/12**(全 exec 4/4、全 connect 4/4、3/4 write)vs **L1 工具层 baseline 3/12**(仅工具调用路径) |
| **B 真实负载开销** | 稳态墙钟 p50(N=12) | **+1.3%**(git-loop / find-grep);cc-compile −1.9%(噪声内)→ **~1–2%** |
| **C 误报/放行** | 9 项检查 | **9/9**:合法操作 0 误报;declassify/after/lineage 放行路径全部正确(未满足门拦截,满足放行) |
| **D agent 纠偏闭环** | 检测/强制/反馈/恢复(N=5) | 检测 **5/5**、阻止 **4/5**、**反馈送达且 agent 正确识别约束+给出合规替代 5/5**;自主完成 0/5(kill 下保守 agent 回头问用户) |
| **E 表达力漏斗** | 真实约束→可强制 | **70%** 仓含 ≥1 行为约束;其约束全落入 32 条可强制规则覆盖的 12 类 |

详见各 `exp*/` 目录的 `matrix.md` / `overhead.md` / `results.md` / `funnel.md`。

## 核心论点的证据
1. **工具层之下、跨路径**(A):ActPlane 覆盖合作 agent 自然会走的 `bash -c`/subprocess/直接 syscall,
   工具层 baseline 构造性失明(只 3/12)。
2. **低开销**(B):真实负载稳态开销 ~1–2%。
3. **高精度**(C):零误报 + 放行门正确 —— 可靠性而非过度阻断。
4. **纠偏闭环成立**(D):内核可靠检测 + 理由送达 + agent 正确理解并提出合规替代。
5. **问题真实、可强制**(E):70% 真实仓有此类约束,且落在可强制区。

## 诚实的限制(均如实记录)
- **无 BPF-LSM**:未实测 `block`/-EPERM 的优雅可重试;D 用 kill,导致保守 agent"提出替代却回头问用户"
  →自主完成率低,**正向支撑"对合作 agent 应用 block 而非 kill"**(待 LSM 内核)。
- **verifier 复杂度上限**:单程序可靠 ~1 条 `@arg` exec 规则(≥2 趋于 -E2BIG)→ D 用单条
  `@arg "checkout"`;多 `@arg` 的内核优化待办。
- **A 一处漏检**:write 经裸 C `openat` 的快子进程在 `label` 播种下漏检(e2e 的 exec-source 写检测通过)——
  定位在 label 播种传播,列为待修。
- **规则集**:单编码者 + 确定性核验(同级 2509.14744);双编码者 + κ 待后续。仅 audit/kill;仅 claude-haiku;小 N。

## Round-2(待 BPF-LSM 内核 / 更大预算)
`block`/-EPERM 的 C3(无理由)vs C4(带反馈)四条件完成率;SWE-bench-Verified 子集做 oracle 完成率;
规则集双编码 + κ;CamQuery/Tetragon/Progent 实跑对比。
