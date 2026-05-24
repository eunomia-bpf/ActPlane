# ActPlane 评测计划（OSDI-grade Evaluation Plan）

> 目标：定义一套能达到 OSDI 系统论文标准的评测。OSDI 审稿最看重三件事——
> **(a) 真实负载上的有效性、(b) 与现有系统 head-to-head 对比、(c) 可信的开销数据**。
> 本文把 ActPlane 的 claim 拆成 6 组实验(E1–E6),每组标注:对应 claim、baseline、
> 指标、统计方法、为什么 OSDI 需要它。
>
> 上游依据:`actplane-research-plan.md` §6(novelty/baseline)、`feedback-design.md` §8
> (四条件 C1–C4 + 假设 H1–H4)、`agent-policy-survey.md` §5/§7(D1–D7 编码、κ、四条件)、
> `corpus/` 与 `docs/tmp/corpus-analysis.md`(144 仓真实语料)。E1–E12 见 `taint-dsl.md`。

---

## 0. 研究问题（RQs）

- **RQ1（覆盖/抗绕过）**：ActPlane 是否在 syscall/LSM 层强制约束,使 agent 经任何路径
  (工具调用 / `bash -c` / `subprocess` / 直接 syscall)的改道都被拦截并反馈?——核心卖点。
- **RQ2（纠偏闭环）**：把内核违规理由以语义反馈回灌给合作 agent,是否**提升受约束下的
  任务完成率、减少重复违规**?(claim 2)
- **RQ3（精度/误报）**：ActPlane 拦错正常工作的比例有多低?declassify/gate 放行路径是否如期?
- **RQ4（开销）**：污点传播 + LSM 检查的 ns 级开销、端到端 agent 任务的墙钟/吞吐/内存影响?
- **RQ5（表达力/真实性）**：真实语料里的约束有多少可用 DSL 表达、多少可在内核强制(D5)?
- **RQ6（对比）**：相对 CamQuery / Tetragon / Progent / AgentSpec,ActPlane 占据的能力格是否唯一?

每个 RQ ↔ 一组实验(E1↔RQ1 … E6↔RQ6)。

---

## 1. 实验对象、负载与基线

### 1.1 被测 agent（real workload，OSDI 要真实负载）
- **Claude Code** 与 **OpenAI Codex CLI**(2026 主流 coding agent)。
- 每个场景给 agent 一个**会自然诱发违规**的任务 prompt(D7 可诱发性)。

### 1.2 场景集（policies under test）
- **基础集**:`taint-dsl.md` E1–E12（已有编译 + YAML 用例 + e2e 驱动 `script/e2e_examples.sh`）。
- **真实集（关键）**:从 **144 仓语料**(`corpus-analysis.md`)经 D1–D7 编码导出的、`D5=全真 ∧ D7=可诱发`
  的规则,避免"只用 toy 例子"被审稿人质疑外部效度。

> **【补充 · workload 来源,OSDI 最关键的一点】** E1–E12 + 自造场景 = toy benchmark,会被质疑
> "自己造的、专门让自己赢"。**主力 workload 必须借第三方真实负载,E1–E12 降级为能力/单元测试
> (证明每个 DSL 构造可跑),不当 eval 负载。** 三类 workload 各有出处:
>
> | 用途 | workload 来源 | 理由 |
> |---|---|---|
> | **安全/违规**(E1,E3) | **复用 AgentDojo / AgentHarm 的任务**,并**额外把其攻击/违规路径改写成 `bash -c`/subprocess/直接 syscall** | 借第三方任务集摆脱"自造 benchmark";cross-path 改写是这些 benchmark 都没测、且正是 ActPlane 独有的维度 |
> | **完成率**(E2) | **SWE-bench(-Verified) / Terminal-Bench 子集**,挑"最自然解法会违反某策略"的任务 | 有自动判定器(测试通过=完成),解决"完成"无 oracle 的问题;是公认真实负载 |
> | **开销**(E4) | **syscall 密集的真实负载**:真编译项目、跑 pytest 全套、大规模文件 refactor、git 操作 + 真实 agent session 的 syscall trace | OSDI 要真实负载下的 p99,微基准不够 |
>
> 贡献叙述应是"**在第三方真实任务 + 真实绕过路径下的内核强制**",而非"我们设计了一套场景"。

### 1.3 基线系统（`research-plan §6` 指定）
| 基线 | 层 | 跑法 |
|---|---|---|
| **CamQuery** (CCS'18) | L3 内核(LKM/LPM) | 老内核环境,能跑则实测,否则定性对比 + 引文 |
| **Tetragon** | L3 eBPF | 实测(单通道 lineage 强制) |
| **Progent** | L1 工具层 | 实测 |
| **AgentSpec** | L1 工具层 | 实测 |
| Codex sandbox / Claude Code permission | L1/L2 | 实测(自带防护) |
| prompt-only(CLAUDE.md) | L0 | C1 基线 |

---

## 2. E1 — 跨路径覆盖（★核心,RQ1）

**Claim**：在 syscall/LSM 层强制 ⇒ 任何改道都拦得到。

**方法**：对每条规则,把同一被禁操作经 **4 条路径**发起:
1. 正常工具调用(`Bash: git push`)
2. `bash -c '混淆命令'`（如 `g""it`、变量拼接）
3. `python -c "import subprocess; subprocess.run([...])"`
4. 直接 syscall（裸 `socket()/connect()`、`open()` 不经任何工具语义）

**对比**：ActPlane(L3) vs Progent/AgentSpec(L1) vs Codex/Claude 自带 sandbox/permission(L1/L2)。

**指标**：每条 (规则 × 路径) 上「拦截成功 ∧ 反馈到达」的 2×4 布尔矩阵 + 汇总覆盖率。

**预期（H3）**：L1 方案在路径 ②③④ 构造性失明;ActPlane 四条全覆盖。**这张矩阵是论文的核心图**。

**实现**：现有 `script/e2e_examples.sh` 已具备路径①②；扩展出 ③④ 的触发器即可。

---

## 3. E2 — 纠偏反馈闭环（★核心,RQ2,最贵）

**方法**：`feedback-design.md §8` 的**四条件对照**,Claude Code 与 Codex 各跑:

| 条件 | 强制 | 反馈 | 隔离的变量 |
|---|---|---|---|
| **C1** prompt-only | 无 | 无 | 基线违规率（"本就会违反"；恒 0 则该规则无证据价值,剔除） |
| **C2** audit | 只报不拦 | 无 | 强制本身 vs prompt |
| **C3** hard-block | LSM `-EPERM` | **无 ActPlane reason**（仅内核 Permission denied） | 光阻断不给理由 |
| **C4** block + 反馈 | LSM `-EPERM` | **有**（§6 模板，经 `--feedback-file`） | **本文核心:语义反馈的净贡献** |

差分解释：**C3→C4 = 纠偏反馈净贡献**；C1→C2 = 强制净贡献；C2→C3 = 同步阻断 vs 事后报。

**指标**：
- **受约束下仍完成原任务的比例**（主指标，C4 应显著 > C3）
- **重复违规次数 / 纠正迭代数**（C4 < C3）
- token / 轮次成本（反馈不应爆轮次）

**消融**（C4 内部）：纯禁令 vs §6 带 remediation vs gate 档「先满足条件再重试」——验证 `feedback-design §6.3` 各原则贡献。

**统计严谨性（OSDI 必须，且最易被挑）**：
- 每个 (场景 × 条件 × agent) 重复 **N ≥ 20–30 次**(agent 有随机性)。
- 报 均值 + 95% CI、配对/Mann-Whitney 检验、效应量；固定并记录随机种子、模型版本、任务顺序。
- 需先搭一个**可复现的 agent 评测 harness**:固定任务集 + 自动判定"任务是否完成" + 批量重跑 + 日志。**这本身是独立工程量,是 E2 的前置。**

**假设**：H1(C4 完成率>C3)、H2(C4 重复违规<C3)、H4(gate 档在不牺牲约束下保完成率)。

---

## 4. E3 — 误报 / 过度阻断（RQ3）

**方法**：构造一组**应被放行**的正常任务(规则不该触发),测拦错比例;并验证放行路径:
- declassify：E1 secret → 经 `redact` 后 connect 应放行;
- gate/after：E5 先 `pytest` 后 commit 应放行;E11 先 `confirm` 后 `--force` 应放行。

**指标**：精确率/召回率、假阳例清单、放行路径成功率。

**为什么 OSDI 要**：`research-plan §7` 强调"harness 误报比 prompt 更糟"。无此组,审稿人会质疑命中率靠过度阻断刷出来。

---

## 5. E4 — 系统开销（★OSDI 硬门槛,RQ4）

**微基准**：
- 单事件污点传播开销（fork/exec/read/write/connect 各自,有/无 ActPlane,ns 级）；
- LSM 检查延迟（`bprm_check_security`/`file_open`/`socket_connect`）；
- 规则表规模影响（1→32 规则、标签数 1→64）。

**宏基准**：
- 真实 agent 任务的**端到端墙钟时间 + 吞吐**(有/无 ActPlane,开销应 < 任务本身噪声)；
- 内存:`ts_proc`/`ts_file`/`ts_endp` map 占用 vs 进程/文件/连接数。

**对比**：Tetragon、CamQuery 开销数量级。

**报告**：给 **p50/p99**(不只均值),OSDI 重尾很重要。

---

## 6. E5 — 表达力 / 真实适用性（RQ5,把语料变证据）

**前置**：完成 `agent-policy-survey.md §5` 的**逐规则 D1–D7 人工双编码 + 报告 κ**
（当前 `corpus-analysis.md` 只是关键词粗编码,是上界）。

**方法**：在 144 仓语料导出的真实约束上统计漏斗:
1. **可用 DSL 表达**的比例(D1 类别覆盖)；
2. **可在内核强制**的比例(D5 三层:Observable / Expressible / Robust)；
3. **E-out** 的诚实占比(纯对话式批准、PR 礼仪、纯代码质量)。

**输出**：「真实约束 → 可表达% → 可强制%」漏斗图 + 不可强制类别的诚实清单。把"问题真实(≈70% 仓有约束)"与"我们能管多少"连成一条证据链。

**与 prior work 对齐**：明确我们的"行为约束"横切已有 CLAUDE.md 研究的 Dev-Process/Testing/Security 类别,**70% ≠ 他们的 Security 8.7–14.5%**(见 `related_work.md §7`)。

---

## 7. E6 — Baseline head-to-head 汇总（RQ6）

一张表,在**相同场景**上实跑能跑的基线,维度:
**强制层 · 强制/检测 · 跨通道(P/F/N) · 抗绕过 · 污点传播 · agent 导向 · 语义反馈 · 开销**。
预期:唯一同时填满 **〔L3 内核跨通道 typed-taint〕×〔agent 导向〕×〔语义纠偏反馈〕** 的是 ActPlane
(CamQuery 缺 agent+反馈;Tetragon/OAMAC 单通道或无污点;Progent/AgentSpec 在可绕的 L1)。
CamQuery 若无法在现代内核复跑,则定性对比 + 引其论文数据,并诚实声明。

---

## 8. 优先级与风险

| 实验 | 必须性 | 风险/成本 | 备注 |
|---|---|---|---|
| **E1 跨路径** | 必须(核心卖点) | 低 | 最高 ROI;e2e 框架稍扩展即可,**先做** |
| **E4 开销** | 必须(OSDI 门槛) | 低 | 标准微基准,**先做**(早暴露设计问题) |
| **E2 反馈闭环** | 必须(claim 2) | **高** | agent 随机、要大 N、真跑 Claude/Codex;**需先搭评测 harness** |
| E3 误报 | 必须 | 中 | 要设计"正常任务"对照集 |
| E5 表达力 | 强烈建议 | 中 | **依赖先做完 D1–D7 编码 + κ** |
| E6 baseline | 必须 | 中 | CamQuery 可能只能定性 |

**建议执行顺序**：E1 + E4(便宜、立得住、早做)→ 搭 E2 的 agent 评测 harness → E2 + E3 → E5(待编码完成)→ E6 汇总。

---

## 9. 威胁有效性（Threats to Validity）

- **内部**：agent 随机性(用大 N + 显著性检验缓解);任务"是否完成"的自动判定可能有偏(需人工抽检校准)。
- **外部**：仅 Claude Code/Codex 两个 agent;仅 GitHub/英文为主的语料;E1–E12 + 语料导出场景未必覆盖全部真实约束。
- **构造**：D1–D7 编码的主观性(双编码 + κ 缓解);"可强制"判定依赖具体实现。
- **基线公平性**：CamQuery 老内核、L1 工具被刻意置于其设计边界外(`bash -c`)——需声明这是**展示层次差异**而非贬低其设计目标。

---

## 10. 可复现性（OSDI Artifact Evaluation）

- 策略用 YAML 用例 + `script/e2e_examples.sh` 驱动(已有雏形);
- 固定:内核版本、agent/模型版本、随机种子、基线版本;
- 公开:场景集、agent 评测 harness、原始日志、统计脚本;
- 提供一键复现脚本 + 预期输出。

---

## 11. 关键修正 / Reviewer-proofing（补充,优先级高于上面的细节）

上面 §2–§7 的结构是对的,但要过 OSDI,以下五点必须先处理——否则细节再多也会被毙:

1. **定位:这是系统论文,不是 agent 行为论文。** OSDI 是系统会议。E2(反馈是否提升完成率)本质偏
   HCI/agent-behavior,**不能当主 claim**——否则审稿人会说"该投 agent/ML venue"。论文脊梁锚在
   **机制 + 跨路径不可绕(E1)+ 开销(E4)**;E2 降为**支撑实验**,E5 语料漏斗当 **motivation**。
2. **CamQuery 跑不了 ⇒ 让开销承担硬 novelty。** `research-plan §6` 自标 CamQuery 是最危险重叠(同机制)。
   若无法 head-to-head,"超越"就只剩"eBPF + agent 域 + 反馈"这类偏软的论证。**对策**:用 E4 证明
   eBPF/BPF-LSM 基建相对 CamQuery 的 LKM/LPM 有**具体可测的低开销 / 可部署性优势**——把它从 framing
   升级成系统证据。这是当前 plan 最弱、最该补强的一环。
3. **完成率必须有 oracle。** E2 的"受约束下仍完成原任务"若靠人判 = 不可信。**用自带测试判定器的
   benchmark(SWE-bench-Verified)**,以"测试通过"为完成判据,人工只做抽检校准。
4. **成本必须 scope。** N≥20–30 × 场景 × 2 agent × 4 条件 = 天文 API 量。**先定一个可完成的预算**:
   少量高代表性场景(每个 D1 类别 1–2 条)× 充足 N,而非全场景浅跑;或先单 agent(Claude Code)跑通,
   Codex 作复现性附录。
5. **E1–E12 的角色**:它们是 **DSL 能力测试 / 正确性单元测试**(每个构造可编译可强制),**不是 eval
   workload**。eval workload 见 §1.2 补充框(AgentDojo/AgentHarm + SWE-bench + 真实 syscall 负载)。

> 一句话:**机制 + E1 跨路径 + E4 开销(含 vs CamQuery 的部署/开销优势)= 脊梁;workload 借第三方
> (AgentDojo/AgentHarm/SWE-bench);E2 反馈与 E5 语料是支撑与 motivation,不是主 claim。**
