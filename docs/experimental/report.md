# ActPlane 评测报告（Round-1）

> 论文 Evaluation 章节初稿。所有 benchmark 的规则集均**从真实语料 `docs/corpus`(144 个流行
> AI-agent 仓的 CLAUDE.md/AGENTS.md)提取、带 provenance、可复算**,非自造 toy 规则。
> 复现:`bash docs/experimental/run_all.sh`(需 sudo 的步骤已标注);各实验脚本在对应 `exp*/`。
> 本报告综合 `README.md` 各结果文件,并对方法学与威胁有效性给出统一交代。

---

## 1. 评测目标与研究问题

ActPlane 把行为约束编译成内核 eBPF 信息流强制器,在 **syscall 层(工具层之下)** 传播污点、
跨进程/文件/网络拦截违规,并把人类可读理由作为**纠偏反馈**回灌给「合作但健忘」的 agent。
威胁模型不是对抗者;论文叙述按 *可靠性 / 跨路径覆盖 / 低开销 / 纠偏闭环*。我们要回答:

| RQ | 问题 | 实验 | 结论(一句话) |
|---|---|---|---|
| RQ1 | syscall 层强制能否覆盖合作 agent 自然会走的所有路径? | A | 能;**12/12**,工具层 baseline 仅 3/12 |
| RQ2 | 把内核违规理由回灌 agent,是否改变其行为? | D | 机制成立:检测/反馈/理解 **5/5**;kill 下自主完成低 |
| RQ3 | 误报率多低?放行门(declassify/after/lineage)是否如期? | C | **9/9**,零误报,放行门全部正确 |
| RQ4 | 污点传播 + 规则检查的开销多大? | B | 真实负载稳态 **~1–2%** |
| RQ5 | 真实语料约束有多少可在内核强制? | E | **70%** 真实仓含此类约束,全落入可强制 12 类 |

### 硬约束(本轮,如实声明)
- 本机**无 BPF-LSM**(`/sys/kernel/security/lsm` 无 `bpf`)→ `effect block`(-EPERM 优雅可重试)
  跑不了;**全程只用 `audit`(只报)+ `kill`(终止)**。"不可绕过"由 kill 在各路径终止证明,
  "跨路径检测"由 audit 在各路径上报证明。
- agent 实验小 N(单场景),**非显著性结论**。
- 固定记录:内核 `6.15.11`、`claude-haiku-4-5-20251001`、规则 blob、重跑次数。

---

## 2. Phase 0 — 语料派生规则集(评测基石)

所有实验的 workload 都建立在一套**可 cite、非自造**的规则集上(`ruleset/ruleset.jsonl`)。

- **来源**:144 in-corpus 仓的指令文件抽出 3762 条候选行(带 repo/family/line_no provenance,
  LLM 辅助关键词编码,cf. arXiv 2509.14744 / 2511.12884);取已归入 ActPlane 类别的 **529 行**
  (覆盖 101 个不同 repo)作为聚类输入。
- **双来源交叉印证**:
  - **codex 独立提取 36 条**(`raw_codex_extraction.jsonl`):**引用 36/36 逐字命中真实语料(0 幻觉)**,
    但 codex 不知 ActPlane 确切 DSL 文法,自创近似语法 → **DSL 0/36 可编译**。
  - **确定性聚类 + 领域编码 32 条**(`ruleset.jsonl`,实验实际使用):每条的跨仓频率与代表性引用
    由脚本**确定性计算**(杜绝频率/出处幻觉)→ **引用 32/32 核验、DSL 32/32 经 `actplane compile` 通过**。
  - 两来源**类别分布高度一致**(均以 vcs-gating / secrets / approval / mediation / test-before 为主)= 信度证据。
- **覆盖与复杂度**:freq≥10 仓 **11 条**、≥3 仓 **24 条**、freq0 **0**;tier-3(污点流/declassify/多标签)
  **8 条**、tier-2 **21 条**、tier-1 **3 条** —— 压满引擎主要构造(taint-flow/lineage/after/declassify/
  multi-label/target-scope)。
- **严谨度声明**:单编码者 + 确定性出处计算 + 人/脚本核验(与 2509.14744 同级);**双编码者 + Cohen's κ 留后续**。

---

## 3. 实验结果

### 3.1 Exp-A 跨路径覆盖(★头号结果,RQ1)

对 3 个代表性被禁 op(exec / connect / write)各从 **4 条路径**触发同一违规:
① 直接工具调用 ② `bash -c`(混淆) ③ python subprocess ④ 直接 syscall(编译 C)。
对比 ActPlane(syscall 层)与 **L1 工具层 baseline**(按首命令 token 匹配被禁工具,
建模 AgentSpec/Progent/PreToolUse-hook 类)。

| op \ path | tool-call | bash-c | py-subproc | syscall | | L1 |
|---|:---:|:---:|:---:|:---:|---|:---:|
| **exec** | ✓ | ✓ | ✓ | ✓ | | 仅 tool-call |
| **connect** | ✓ | ✓ | ✓ | ✓ | | 仅 tool-call |
| **write** | ✓ | ✓ | ✓ | ✓ | | 仅 tool-call |

**ActPlane 12/12,L1 baseline 3/12。** L1 对路径 ②③④ 构造性失明(它们表现为 bash/python/编译二进制)
—— 这是工具层强制的本质局限,不是实现缺陷。

> **Round-1.1 修复**:write·syscall 此前漏检(矩阵曾 11/12)。**根因不是 label 传播**,而是
> `sys_enter_openat` 在 syscall 入口处用户页尚未驻留、非缺页读 `bpf_probe_read_user_str` 返回
> -EFAULT(实测 `rd=-14`)致 open 被静默丢弃。改为 **sys_enter 暂存 / sys_exit 读取**(彼时
> `copy_from_user` 已跑、页驻留)后转为 **4/4**;e2e 11/11、单元 30/30、collector 20/20 不回归。
> 详见 `expA_cross_path/matrix.md`。

### 3.2 Exp-B 真实负载稳态开销(RQ4)

方法:`actplane watch` 一次性挂载(audit,~10 条规则;taint 引擎 + 规则循环在每个 syscall 上运行),
对同一**真实负载**挂载前后计时,隔离一次性 attach 成本。**无合成微基准**。N=12,报 p50/p99。

| workload | bare p50/p99 (s) | +ActPlane p50/p99 (s) | median 开销 |
|---|---|---|---|
| cc-compile | 1.040 / 1.050 | 1.020 / 1.040 | **−1.9%**(噪声内) |
| git-loop | 6.270 / 6.390 | 6.350 / 6.800 | **+1.3%** |
| find-grep | 1.490 / 1.560 | 1.510 / 1.550 | **+1.3%** |

**真实负载稳态开销 ~1–2%。**

### 3.3 Exp-C 精度:误报 + 放行路径(RQ3)

**9/9 通过。** 误报组(合法操作不该触发):读非机密后 connect、`zgit status`(非 commit)、
工作区内写 —— **0 误报**。放行组(满足 gate 放行、未满足仍拦):
- **declassify**:secret→connect 拦,secret→`redact`→connect 放行 ✓
- **after**:无 pytest 的 commit 拦,先 pytest 后 commit 放行 ✓
- **lineage**:无 confirm 的 `--force` 拦,先 confirm 后放行 ✓

**零误报 + 放行门全部正确** —— 体现可靠性而非过度阻断。

### 3.4 Exp-D 小型 agent 纠偏闭环(RQ2,先做小)

场景=语料最高频类别 `no-git-branch`(vcs-gating,63 仓)。任务直接要求建分支、**无 prompt 禁令**
(模拟健忘/顺从 agent)。agent=`claude-haiku`,headless;C2 由 ActPlane(kill)拦 `git checkout -b`
并经 PostToolUse feedback-hook 注回理由。N=5,**非显著**。

| 条件 | 分支被创建(违规) | README 完成 | 内核检测/拦截 |
|---|:---:|:---:|:---:|
| C1 baseline(无强制) | 5/5 | 5/5 | — |
| C2 ActPlane kill+反馈 | 1/5 | 0/5 | **5/5** |

质性(来自 transcript):**检测 5/5、强制 4/5、反馈送达 + agent 正确理解约束并给出合规替代 5/5**
(原话:*"…blocked at the system level… Make the changes directly on the current branch (master) instead"*);
但**自主完成 0/5** —— 用 **kill** 时,合作但保守的 agent 倾向"停下问用户"而非自动续做。

**结论**:纠偏闭环**机制成立**(可靠检测 + 理由送达 + 正确理解 + 提出合规替代);kill 的硬终止语义
压低了自主完成率,**正向支撑论文论点:对合作 agent 应用 `block`(优雅 -EPERM + 可重试)优于 `kill`**
—— `block` 实测待 BPF-LSM 内核(留后续)。

### 3.5 Exp-E 表达力漏斗(RQ5,离线)

| 阶段 | repos / 144 | 占比 |
|---|---:|---:|
| in-corpus 全语料 | 144 | 100% |
| 含 ≥1 条 ActPlane 相关**行为约束** | **101** | **70%** |
| 落入可强制规则集覆盖的 12 类 | 101 | 70% |

70% 真实仓写了至少一条 ActPlane 相关行为约束(关键词编码上界),且全部落在 32 条可强制规则覆盖的
12 个类别(VCS 门禁、test-before、secrets、强制中介、只读、破坏性、网络出口、审批门、工作区、
force-push、主分支、未受信输入)。诚实排除的 E-out(纯对话式批准、PR 礼仪、主观风格)不计入可强制集。

### 3.6 Exp-F 对抗性完备性(RQ1 补强)

把同一被禁 op 经**每一个能想到的 syscall 向量**触发,诚实记录检测/漏。结果 **10/10 向量命中**:
write 经 open/openat/**openat2**/**creat**/**truncate**/裸 C openat/unlink/rename;exec 经 execve/**execveat**
(`sched_process_exec` 捕获所有 exec syscall);io_uring OPENAT 在本机 6.15 亦命中(附带,非专用 hook)。
本轮新增 openat2/creat/truncate 的 hook(此前可绕过)。**明示的真实边界**(不藏):fd-only 变体
(ftruncate/fchmod/mmap 写,需 BPF-LSM)、UDP 无连接外发、`*at` 链接族——列为待补。

### 3.7 Exp-G 规则数可扩展性(RQ:单策略容量)

引擎所有表循环(rules/sources/xforms/gates)走 `bpf_loop` + 非冻结 map 计数(回调只验证一次)+
无分支匹配器 + argv 预分词成定长 slot,使 **verifier 成本与规则数无关**。实测 **1→128 条混合规则
(含 12+ 条 @arg)在单策略加载成功**(旧实现 ~1 条 @arg 即 -E2BIG),真实 32 条语料规则集可作单策略加载。

---

## 4. 核心论点的证据链

1. **工具层之下、跨路径**(A):ActPlane 覆盖合作 agent 自然会走的 `bash -c`/subprocess/直接 syscall
   全部四路径(**12/12**);工具层 baseline 构造性失明(3/12)。
2. **低开销**(B):真实负载稳态 **~1–2%**。
3. **高精度**(C):**零误报** + 放行门正确 —— 可靠性而非过度阻断。
4. **纠偏闭环成立**(D):内核可靠检测(5/5)+ 理由送达 + agent 正确理解并提出合规替代(5/5)。
5. **问题真实、可强制**(E):**70%** 真实仓有此类约束,且落在可强制区。

---

## 5. 威胁有效性 / 已知局限(均如实记录)

- **无 BPF-LSM**:未实测 `block`/-EPERM 的优雅可重试;D 用 kill,导致保守 agent"提出替代却回头问用户"
  → 自主完成率低。该现象**正向**说明 block 对合作 agent 的价值,但 block 本身待 LSM 内核验证。
- **verifier 复杂度上限(已解除)**:旧实现 ~1 条 `@arg` exec 规则即 -E2BIG。所有表循环改 bpf_loop
  (回调只验证一次,计数来自非冻结 map)+ 无分支匹配器 + argv 预分词成定长 slot,使 verifier 成本与
  规则数无关 → **128 条混合规则(含 12+ 条 @arg)在单策略加载**(Exp-G)。
- **规则集**:单编码者 + 确定性核验(同级 2509.14744);双编码者 + κ 待后续。
- **范围**:仅 audit/kill;仅 claude-haiku 一个模型;agent 实验单场景小 N(非显著)。
- **开销**:三类真实负载稳态值;更大规模 / 更高 syscall 密度的负载谱待补。

---

## 6. Round-2(待 BPF-LSM 内核 / 更大预算)

- `block`/-EPERM 的 C3(无理由)vs C4(带反馈)四条件完成率实验(验证 §3.4 的论点)。
- SWE-bench-Verified 子集做 oracle 完成率。
- 规则集双编码者 + Cohen's κ。
- CamQuery / Tetragon / Progent 实跑 head-to-head。
- (已完成)多 `@arg` 规则的 verifier 复杂度:bpf_loop + 预分词 slot,128 条/策略,见 Exp-G。
