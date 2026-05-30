# Exp-E 表达力漏斗:真实约束 → 可表达 → 可强制

> 把"问题真实(开发者确实写了这些约束)"与"ActPlane 能管多少"连成一条证据链。
> 数据源:`docs/corpus`(144 in-corpus 仓)、`docs/tmp/corpus-analysis.md`(全语料编码)、
> `ruleset/ruleset.jsonl`(32 条可强制规则)。

## 漏斗(repos of 144)
| 阶段 | repos | 占比 |
|---|---:|---:|
| in-corpus 全语料 | 144 | 100% |
| 含 ≥1 条 ActPlane 相关**行为约束** | **101** | **70%** |
| 落入**可强制规则集覆盖的类别** | 101 | 70% |

**两个数字(严守方法学,见 `agent-policy-survey.md`)**:
- **无偏分母**:全 144 仓中 **70%** 至少写了 1 条 ActPlane 相关行为约束(上界,关键词编码;
  与既有 CLAUDE.md 研究的 Security 8.7–14.5% 不可比——我们的"行为约束"横切其
  Dev-Process/Testing/Security 类别,见 `related_work.md §7`)。
- **可强制覆盖**:这 101 仓的约束全部落在 32 条规则覆盖的 **12 个类别**内(VCS 门禁、test-before、
  secrets、强制中介、只读、破坏性、网络出口、审批门、工作区、force-push、主分支、未受信输入)。
  规则集**按构造只收可强制(Observable+Expressible)** 规则,且 32/32 经 `actplane compile` 验证可编译、
  32/32 引用经真实文件核验(见 `ruleset/verification.md`)。

## 可强制性分布(D5)
- **可强制(在本规则集)**:exec/@arg 门禁、file open/write/unlink、connect、污点流(secrets/PII)、
  lineage/after/declassify/多标签 —— 高频类别(VCS 63 仓、test 51、secrets 40、mediation 20…)均落此区。
- **E-out(不可在 syscall 层强制,提取时已排除)**:纯对话式批准("先问用户")、PR 礼仪
  ("别给别人的 issue 开 PR")、主观代码质量/风格(3233 条 "unclassified" 候选行多属此)。
  这些诚实排除,不计入可强制集。

## 工程限制(实测)
- 复杂度档:规则集 tier-3(污点流/declassify/多标签)8 条、tier-2 21 条、tier-1 3 条 —— 压满引擎构造。
- **verifier 上限(已解除)**:旧实现 ~1 条 `@arg` exec 规则即 -E2BIG;改 bpf_loop + 无分支/预分词
  slot 匹配后,整套 32 条规则集(含 12 条 @arg)可在**单策略**加载,Exp-G 实测达 128 条/策略。
