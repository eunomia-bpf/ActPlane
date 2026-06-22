# ActPlane CLI UX 与论文 Artifact 仓库治理建议

本文档给出两个决策：

1. ActPlane 主 CLI 应该收敛成一个通用、稳定、可维护的 OS policy engine 入口。
2. paper artifact，尤其是原始数据和大规模评测输出，不应该长期留在产品主分支。

结论先行：ActPlane 的主分支应该服务开源用户和工业使用者。论文实验资产应该可复现、可引用、可校验，但不应该让主仓库变成论文数据仓库。

## 1. CLI 产品定位

ActPlane 对外应该是一个通用的 OS-level policy engine，而不是 agent 运营平台、rollout 平台、policy 生成平台或实验管理平台。

核心心智模型应保持简单：

```text
policy -> compile -> run/watch -> kernel enforcement -> feedback/control
```

用户需要相信三件事：

1. policy 能被清楚审查。
2. enforcement 在 syscall 边界生效。
3. runtime domain 能隔离不同 agent/session，且不会误伤旁边的 agent。

因此，主 CLI 只应该暴露稳定 engine 概念。组织流程、false-positive triage、rollout promotion、论文实验、LLM 生成 policy 这些都不应该成为主入口。

## 2. 目标顶层命令

建议最终只保留这些顶层命令：

```text
actplane init
actplane compile
actplane run
actplane watch
actplane mcp
actplane control
actplane doctor
```

模板通过 `actplane init --template` 和 `actplane init --generate` 暴露。内置模板是 `init` 的内部能力，不是独立产品入口。

### init

定位：项目 bootstrap。

推荐 UX：

```bash
actplane init
actplane init --out actplane.yaml
actplane init --template no-git-branch
actplane init --template no-secret-egress --set 'secret_paths=**/.env,**/secrets/**'
actplane init --generate
actplane init --with-codex
actplane init --with-mcp
actplane init --all
```

语义：

- `actplane init` 只写一个最小 starter policy。
- `--template` 从内置模板写 policy，替代 `templates write` 的常用路径。
- `--generate` 从项目说明和 manifest 推断候选 policy，替代 `templates generate` 的常用路径。
- `--with-codex` 和 `--with-mcp` 显式写集成配置。
- `--all` 可以做 starter policy 加集成配置，但必须让用户知道它会写哪些文件。

原则：裸 `init` 不应该悄悄改 MCP、Codex hook 或 `AGENTS.md`。这些属于项目集成，必须显式 opt-in。

### compile

定位：policy 编译、静态审查、host support 检查和 kernel blob 输出。

推荐 UX：

```bash
actplane compile
actplane compile --out /tmp/policy.bin
actplane compile --json
actplane compile --explain
actplane compile --explain --report-out docs/actplane-review.txt
actplane compile --domains
```

语义：

- 无权限编译并检查 policy。
- 汇报 rule 摘要、hook budget、backend support、静态限制和运行时限制。
- 不带 `--out` 时只做编译和审查，不写 kernel blob。
- `--out FILE` 写 kernel config blob。`--out` 永远表示编译产物，不表示 review 文档。
- `--json` 输出机器可读 compile report，给 CI 或上层工具消费。
- `--explain` 输出人可读 review artifact。
- `--report-out FILE` 把 `--json` 或 `--explain` 的报告写入文件。
- `--domains` 提供 domain inspection，展示各 policy domain 的有效 policy rules。

这里保留的是静态 review 能力，不保留 `check` 这个顶层命令。这样用户只需要理解一个 policy preparation 命令：`compile`。它可以只验证，可以输出 review，也可以产出真正加载到 kernel 的 blob。

### run

定位：启动一个命令并把它放入 ActPlane enforcement。

推荐 UX：

```bash
sudo -E actplane run codex
sudo -E actplane run --domain review claude -p 'review this repo'
sudo -E actplane run --delta child-policy.dsl subagent ...
sudo -E actplane run --parent-domain bash
```

默认行为应该是：每次 `run` 创建一个新的 runtime session domain。

这不是每个 process 都创建 domain。一次 `run` 里面的 fork/exec 子进程继承同一个 runtime session domain。只有显式 child agent/task 边界才创建 child domain。

为什么这样更合适：

- 默认隔离更符合 agent 使用场景。两个并行 agent 不应该共享 runtime labels、gates、local deltas 或 actor context。
- 用户不需要先理解 domain 才能安全使用。
- 后续 subagent 机制和主 agent 机制一致，都是 domain tree。

`--parent-domain` 是 opt-out，表示不要创建新的 runtime session domain，直接复用选中的父/global policy domain。实现上这仍然需要给 pid 写一个很轻的 active marker，否则 kernel 不会对这个 pid 跑全局规则；但它不创建可追加 runtime delta 的 child/session domain，也不给该 pid 分配 runtime policy authority。不要用 `--parent`，因为它可能被误解成 parent process、YAML parent、runtime parent 或 agent parent。

### watch

定位：加载 engine 并 attach 到现有 shell/agent process tree。

推荐 UX：

```bash
sudo -E actplane watch
sudo -E actplane watch --domain review
sudo -E actplane watch --parent-domain
```

默认行为应与 `run` 一致：为 watched root 创建新的 runtime session domain。普通子进程继承该 domain。`--parent-domain` 才复用父/global policy domain。这个模式适合调试和兼容性测试，不适合作为 runtime delta/child-domain supervisor，因为它刻意不创建有 authority 的父 runtime domain。

### mcp

定位：MCP server 和 agent 集成入口。

推荐 UX：

```bash
actplane mcp
actplane mcp --auto-attach-parent
```

原则：

- `mcp` 是集成面，但不应该膨胀成 policy authoring 或 rollout 平台。
- MCP 自动 attach 后，engine 应该 load 一次。后续 domain bind、child domain、runtime delta 都走 control socket/map updates。

### attach

定位：把已经启动的进程纳入当前已经运行的 ActPlane engine。

推荐 UX：

```bash
actplane attach --pid <pid>
actplane attach --pid <pid> --parent-domain
actplane attach --pid <pid> --child-domain --domain-id <domain-id>
actplane attach --pid <pid> --child-domain --delta child-policy.dsl
```

原则：

- `attach` 是用户可见的一等入口，表达“把这个已有 pid 纳入保护”。
- 默认行为是为该 pid 冷启动一个前台 engine，创建 runtime root domain，并暴露 repo-local control socket。这个模式适合直接保护一个已经启动的 agent。
- 带 `--child-domain`、`--domain-id`、`--child-id`、`--scope-id` 或 delta 参数时，`attach` 复用已有 MCP auto-attach 或 `watch` engine，把该 pid 绑定为 child runtime domain，不重新 load engine。
- child-domain attach 可以同时安装 child-local append-only delta，但 delta 作用域只能是该 attached child domain。
- `attach` 是 post-hoc 操作。它不能补全 attach 前已经发生的文件读写、网络连接、FD 继承和标签传播历史。强隔离和严格启动前控制仍然用 `run --delta` 或 `control launch-child`。
- `control bind-child` 保留为低层控制面和脚本兼容入口，但普通用户文档优先展示 `attach`。

### control

定位：操作已经运行的 engine。

推荐 UX：

```bash
actplane control status
actplane control reload
actplane control delta add --target-id <domain-id> --delta policy-delta.dsl
actplane control bind-child --pid <pid> --child-id <id>
actplane control launch-child --delta child.dsl -- <cmd>
actplane control children
actplane control logs --child-id <id>
actplane control stop --child-id <id>
```

原则：

- 已经 load 过 engine 后，不应该因为创建 domain 或追加 runtime delta 而重新 load engine。
- domain 创建是 runtime state update，不是 policy reload。
- whole-policy reload 是 trusted admin path。append delta 是 domain-scoped, append-only runtime path。这两者要在 CLI 和文档里分清。

### doctor

定位：诊断安装、权限、kernel/backend、集成文件和常见错误。

推荐 UX：

```bash
actplane doctor
```

`doctor` 应该保留。它是工业可用性的一部分，因为 eBPF 权限、BPF-LSM、MCP 配置、反馈 hook 都容易出错。

### 内置模板

模板通过 `actplane init` 暴露。模板是 bootstrap 的输入，不是独立用户工作流。

推荐暴露方式：

```bash
actplane init --template no-secret-egress
actplane init --template no-secret-egress --set 'secret_paths=**/.env,**/secrets/**'
actplane init --generate
actplane init --list-templates
```

处理方式：

- 删除 `templates list/show/write/review/generate` 顶层子命令。
- `templates write` 合并到 `init --template`。
- `templates generate` 合并到 `init --generate`。
- `templates list/show` 不保留为顶层入口。需要可发现性时，用 `init --list-templates` 和 `init --template ID --print`。
- `templates review` 删除。用户可以用 `init --template ...` 写 policy，再用 `compile --explain` 生成 review artifact。

这样模板仍然能帮助初始化，但不会占据用户注意力，也不会让 ActPlane 看起来像模板管理工具。

## 3. 当前命令到目标命令的迁移

| 当前入口 | 建议处理 | 原因 |
| --- | --- | --- |
| `run` | 保留，并默认创建 runtime session domain | 最常用 enforcement 入口 |
| `child-run` | 合并到 `run --delta` 和 `control launch-child` | child domain 是 run/control 的模式，不应是顶层产品概念 |
| `compile` | 保留并吸收 `check` | policy 编译、support review、report 和 blob 输出都属于同一准备阶段 |
| `init` | 扩展为 bootstrap 主入口 | 吸收模板和 setup 的常用路径 |
| `setup` | 合并到 `init --with-codex --with-mcp`，可短期保留 deprecated alias | setup 是 init 的一种集成模式 |
| `check` | 删除顶层入口，合并到 `compile --json/--explain/--domains` | `check` 本质是 compile report，不必独立成命令 |
| `rollout` | 删除或移出主 CLI | rollout promotion 是组织流程，容易分散用户注意力 |
| `doctor` | 保留 | 工业部署需要 |
| `domains` | 合并到 `compile --domains` 或 `control status --domains` | domain 是 policy/runtime inspection，不必顶层 |
| `watch` | 保留，并默认创建 runtime session domain | 适合 attach 现有 agent/shell |
| `feedback-hook` | 隐藏/internal | hook adapter 不是用户心智入口 |
| `mcp` | 保留 | agent 集成入口 |
| `control` | 保留并吸收 runtime 子命令 | 已加载 engine 的统一控制面 |
| `delta` | 合并到 `control delta add` | delta 是 runtime control 操作 |
| `templates list/show/write/generate/review` | 删除顶层入口，能力合并到 `init` 和 `compile` | 模板是 bootstrap helper，不是主 CLI 概念 |

## 4. 应该明确不集成进主 CLI 的东西

这些能力可以在外部脚本、独立实验目录、企业 wrapper 或后续插件里存在，但不应该是 ActPlane 主 CLI 的一等入口：

- rollout promotion。
- false-positive 人工标注管理。
- policy 从 observe 到 block/kill 的自动升级。
- LLM judge 评估流程。
- 论文 RQ 实验 runner。
- 大规模 benchmark 数据下载和处理。
- 组织审批系统。
- dashboard/web UI。
- agent-specific prompt/hook 编排，除了必要的 MCP/feedback adapter。

原因是这些东西变化快、组织差异大，而且会把 ActPlane 从 policy engine 拉向运营平台。开源项目需要一个小而硬的核心面。

## 5. Domain UX 决策

推荐规则：

```text
run/watch root -> 自动创建 runtime session domain
fork/exec child -> 继承当前 runtime domain
显式 child agent/task -> 创建 child domain
--parent-domain -> 复用父/global domain，不创建 session domain
```

创建 domain 不应该 reload engine。正常路径应该是：

```text
load engine once -> bind root domain -> map/control updates -> append delta if needed
```

engine reload 只用于 admin reload whole policy，或者最初 load/attach。domain bind、child domain、runtime delta 都应该在已经运行的 engine 上完成。

实现约束：

- 默认 `run/watch/MCP auto-attach` 创建一个 runtime root domain，fork/exec 后代继承它。
- `run --delta` 和 `control launch-child` 创建 child domain，并可在 child domain 上安装 append-only delta。
- `run --parent-domain` 使用全局 active marker，只让初始全局 policy 对该进程树生效，不允许同时使用 `--delta/--delta-text/--child-id`。
- `watch --parent-domain` 也使用全局 active marker。control server 可以做 status/reload，但 child bind 和 runtime delta 需要默认 watch/MCP 模式下的有 authority parent domain。

这对性能和心智都重要：

- 性能上，load/attach eBPF 是重操作。domain bind 是 map/state 更新，应该是轻操作。
- 心智上，用户会把 `watch` 或 MCP auto-attach 理解成“ActPlane 已经在了”。之后创建 child domain 如果还 reload engine，会让模型变乱。

## 6. Paper artifact 是否应该留在主分支

不建议长期留在主分支。

主分支应该包含：

- 产品代码。
- 小型示例 policy。
- DSL 和安全模型文档。
- 小型测试 fixtures。
- 可维护的 benchmark 脚本。
- paper 结果摘要、图表生成脚本、manifest 和 checksum。

主分支不应该包含：

- 原始大语料。
- 第三方项目完整 checkout。
- 大规模 agent trajectory。
- 大量 judge 输出。
- 重复的 benchmark run 目录。
- 临时 mount、logs、cache、history。
- 论文探索阶段的中间产物。

当前 `docs` 下已经有明显的 artifact 膨胀。一次粗略目录大小检查显示：

| 路径 | 大小 | 建议 |
| --- | ---: | --- |
| `docs/corpus-evaluated` | 8.7G | 移出主分支，放 artifact dataset |
| `docs/OpenAgentSafety` | 6.1G | 分离 scripts/policies 与 raw/results，raw/results 移出 |
| `docs/rq2-performance` | 3.3G | 移出主分支，保留摘要和图表脚本 |
| `docs/OctoBench` | 689M | data/results 移出，必要脚本可保留或复制到 artifact repo |
| `docs/eval_runs` | 158M | 移出主分支，保留 manifest 和 selected summaries |
| `docs/reference` | 91M | paper PDFs 可考虑移出或只保留引用清单 |
| `docs/tmp` | 79M | 临时目录不应长期进入主分支 |
| `docs/corpus-test` | 23M | 只保留小型 fixtures，完整数据移出 |
| `docs/corpus-raw-full` | 4.3M | 原始 corpus 仍应按许可和复现需求单独管理 |

另外，当前存在未跟踪的 `docs/OpenAgentSafety/OpenAgentSafety/`。这个目录不应该被加入主分支，应该先作为本地 raw artifact 处理。

## 7. Artifact 应该怎么移动

### 远端 artifact branch 方案

把原始数据先备份到同一个 remote 的单独 branch 是可以接受的，尤其适合作为清理主分支前的安全备份。推荐这个 branch 是 orphan/history-free 的归档分支，例如：

```text
artifact/raw-2026-06
artifact/osdi26-snapshot
```

这个方案的优点：

- 主分支的可读历史不会继续混入大数据 commit。
- 清理主分支时有远端备份，不依赖本地磁盘。
- 可以保留论文提交时的原始目录结构，便于之后复查。
- 比立刻设计完整 dataset 发布流程更快。

但它不是最终最干净的公开 artifact 发布形态，原因是：

- 同一个 Git remote 的大对象仍然属于同一个仓库对象库。默认 clone/fetch 在不同 Git host 和客户端配置下可能仍会被大对象影响。
- GitHub/GitLab 的仓库体积、备份和 GC 仍会被这些对象占用。
- 许可证、隐私、data card、checksum、DOI 这些 artifact 责任不会因为换 branch 自动解决。

所以建议把 remote artifact branch 作为短期备份和内部可追溯快照。公开发布或长期归档仍应走 release tarball、Zenodo/OSF/Hugging Face Datasets 或独立 artifact repo。

### 主分支应留下的信息

当原始数据已经备份到远端 artifact branch 后，主分支应该只留下这些信息：

```text
docs/artifacts.md
docs/artifacts/MANIFEST.jsonl
docs/artifacts/CHECKSUMS.sha256
docs/artifacts/DATA_CARD.md
docs/artifacts/README.md
docs/eval.md
docs/eval_benchmarks.md
docs/rq1-expressiveness/README.md
docs/rq2-performance/README.md
```

各文件职责：

- `docs/artifacts.md`：总入口，说明 artifact branch 名称、commit SHA、release/tag、外部 DOI、下载方式和验证方式。
- `docs/artifacts/MANIFEST.jsonl`：每个被移走目录的一行记录，包括原路径、artifact branch 路径、类型、大小、文件数、sha256、对应 paper RQ、生成脚本、公开状态。
- `docs/artifacts/CHECKSUMS.sha256`：远端 tarball 或目录快照的 checksum。
- `docs/artifacts/DATA_CARD.md`：数据来源、许可证、隐私处理、不可公开部分、第三方数据说明。
- `docs/artifacts/README.md`：如何恢复本地 artifact，如何只下载某个 RQ 需要的数据。
- `docs/eval.md` 和 `docs/eval_benchmarks.md`：保留实验方法、命令、环境、预期摘要结果，但不保留大输出。
- RQ 子目录 README：解释该 RQ 需要哪些 artifact，主分支保留哪些小 fixture，完整数据在哪里。

主分支还应该保留小型可运行 fixtures：

```text
docs/fixtures/
  policies/
  traces/
  expected/
```

这些 fixtures 应该足够让 CI 和新用户验证格式、policy 编译、报告生成和最小端到端行为，但不能变成完整 paper corpus 的缩小复制。

主分支不应留下：

- raw checkout。
- full trajectory。
- judge raw outputs。
- benchmark mount。
- temporary logs。
- generated result trees。
- 大 PDF dump。
- 任何需要靠 `du -sh docs/*` 才能理解的隐藏数据资产。

### Performance Benchmark 的例外规则

RQ2 performance benchmark 可以比其他 paper artifact 多留一些信息在主分支，但留下的应该是可审查的报告和可复跑的脚本，不是 raw run 数据。

建议保留：

```text
docs/rq2-performance/README.md
docs/rq2-performance/reports/
docs/rq2-performance/scripts/
docs/rq2-performance/configs/
docs/rq2-performance/fixtures/
```

其中 `reports/` 可以 commit 每次完整运行的最终报告，例如：

```text
docs/rq2-performance/reports/2026-06-14-linux-6.15-summary.md
docs/rq2-performance/reports/2026-06-14-linux-6.15-summary.json
docs/rq2-performance/reports/2026-06-14-linux-6.15-figures/
```

报告应该包含：

- git commit。
- kernel version。
- machine summary。
- workload version。
- benchmark command。
- raw artifact branch 或 tarball ref。
- checksum。
- final tables/figures。
- known caveats。

建议忽略或移出：

```text
docs/rq2-performance/raw/
docs/rq2-performance/runs/
docs/rq2-performance/results/
docs/rq2-performance/tmp/
docs/rq2-performance/cache/
```

也就是说，performance benchmark 的主分支资产应该是“复跑说明 + 稳定脚本 + 小 fixtures + 每次完整运行的报告”。Raw measurements 和中间输出可以删或 ignore，但必须先进入远端 artifact branch、release tarball 或独立 benchmark artifact repo。

### 推荐新建独立 artifact 仓库或数据集

推荐新建独立 artifact 仓库或数据集：

```text
ActPlane-artifacts/
  README.md
  MANIFEST.jsonl
  LICENSE-DATA.md
  data-card.md
  raw/
    corpus/
    openagentsafety/
    octobench/
  derived/
    corpus-evaluated/
    rq1-expressiveness/
    rq2-performance/
  runs/
    eval-runs/
  policies/
  scripts/
  figures/
  summaries/
  env/
```

更推荐的发布组合：

- GitHub repo：放 scripts、manifests、small summaries、data card。
- GitHub Releases：放不可变 tarball。
- Zenodo/OSF/Hugging Face Datasets：放可引用 DOI 或大数据下载。
- 主 ActPlane repo：只保留 `docs/artifacts.md`，指向 artifact release tag、commit、DOI 和 checksum。

不建议把大量 raw data 用 Git LFS 继续挂在主 repo 下。LFS 能缓解 checkout 体积，但不能解决主项目心智、许可边界、CI 成本和贡献者噪音。

## 8. 迁移步骤

第一步：冻结 inventory。

生成一个 manifest，记录每个 artifact 的路径、大小、文件数、sha256、来源、许可、是否可公开、是否可重跑、对应 paper RQ。

建议格式：

```json
{"path":"docs/corpus-evaluated","artifact_branch_path":"raw/docs/corpus-evaluated","kind":"derived-corpus","size_bytes":0,"files":0,"sha256":"...","paper_rq":["RQ1"],"move_to":"artifact-branch-now,dataset-later","keep_in_main":false}
```

第二步：先备份到远端 artifact branch。

先把 raw data、derived corpus、large results、trajectories 和 judge outputs 备份到远端 artifact branch。记录 branch 名、commit SHA、目录映射和 checksum。主分支清理必须在远端备份确认后再做。

第三步：分类。

建议三类：

```text
keep-main      小 fixtures、文档、summary、schema、可维护脚本
move-artifact  raw data、derived corpus、large results、trajectories、judge outputs
ignore-local   logs、mounts、cache、temporary histories、failed run scratch
```

第四步：主分支替换为 pointer docs。

主 repo 里新增或更新：

```text
docs/artifacts.md
docs/artifacts/MANIFEST.jsonl
docs/artifacts/CHECKSUMS.sha256
docs/artifacts/DATA_CARD.md
docs/eval.md
docs/eval_benchmarks.md
```

这些文档只描述：

- 论文实验如何复现。
- artifact branch/tag/commit 或外部 DOI 对应哪版 paper。
- 如何验证 checksum。
- 哪些小 fixtures 可直接跑 CI。
- 如何从 artifact branch 恢复某个数据子集。

第五步：建立正式 artifact repo/dataset。

把 raw 和 generated results 移过去，保留目录结构，但补齐 README、data card、license note、checksum manifest、复现实验命令。

第六步：更新 `.gitignore`。

建议忽略：

```gitignore
docs/corpus-evaluated/
docs/rq2-performance/
docs/OpenAgentSafety/OpenAgentSafety/
docs/OpenAgentSafety/logs/
docs/OpenAgentSafety/results/
docs/OctoBench/results*/
docs/eval_runs/
docs/tmp/
```

如果 `docs/tmp` 里还要保留设计文档，需要改成只忽略大输出子目录，或者把正式设计文档移到 `docs/design/`。

第七步：从主分支移除 tracked 大目录。

普通迁移 commit 可以使用：

```bash
git rm -r --cached docs/corpus-evaluated docs/rq2-performance docs/eval_runs
```

然后提交 pointer docs 和 `.gitignore`。注意这只会让未来 checkout 变干净，不会清理历史体积。

第八步：如果需要真正瘦身历史，做一次协调好的 history rewrite。

如果大数据已经进了 git history，而且开源前必须瘦身，需要用 `git filter-repo` 清历史。这是破坏性仓库迁移，必须单独安排窗口，并通知所有协作者重新 clone 或重新对齐本地仓库。不要在普通功能 commit 里顺手做。

## 9. 原始数据的特殊处理

原始数据尤其不应该随主分支发布，原因有四个：

1. 许可边界不清。第三方 repo、benchmark data、agent logs 可能有不同许可证。
2. 隐私和安全风险更高。logs、trajectory、mount history 可能包含路径、token、prompt、环境信息或生成内容。
3. 主项目维护成本高。CI、clone、review、grep、release 都会被拖慢。
4. 论文复现和产品使用是不同用户群。产品用户不需要默认下载原始实验数据。

原始数据迁移时应该做：

- 为每类 raw data 写来源说明和许可说明。
- 清理 obvious secrets、local absolute paths、temporary mount history。
- 给不可公开的数据写 redaction note，而不是假装它是普通 repo 文件。
- 给公开 tarball 加 checksum。
- 主 repo 只保留小样本和数据 schema。

## 10. 推荐落地顺序

第一阶段，CLI 收敛：

1. 删除 `rollout` 顶层入口和对应 help 文案。
2. 删除 `templates` 顶层入口。
3. 把 `templates write` 的主路径迁到 `init --template`。
4. 把 `templates generate` 的主路径迁到 `init --generate`。
5. 用 `init --list-templates` 和 `init --template ID --print` 替代 `templates list/show` 的必要发现能力。
6. 删除 `templates review`，由 `compile --explain` 负责 review artifact。
7. 删除 `check` 顶层入口，把能力合并到 `compile --json/--explain/--domains`。
8. 把 `domains` 合并到 `compile --domains`。
9. 把 `delta add` 合并到 `control delta add`。
10. 把 `child-run` 合并到 `run --delta` 和 `control launch-child`。
11. 隐藏 `feedback-hook`。

第二阶段，domain UX：

1. `run` 默认创建 runtime session domain。
2. `watch` 默认创建 runtime session domain。
3. 增加 `--parent-domain` opt-out。
4. 保证 domain bind 不触发 engine reload。
5. 在 `compile --explain` 和 `control status` 中清楚展示 domain/session/parent。

第三阶段，artifact 分离：

1. 生成 artifact inventory manifest。
2. 新建 artifact repo 或 dataset。
3. 移出 raw 和 large generated outputs。
4. 主 repo 增加 pointer docs 和 checksum。
5. 更新 `.gitignore`。
6. 需要时再安排 history rewrite。

## 11. 最终判断

ActPlane 如果要成为一个良好使用和维护的开源项目，主线应该是“小核心，硬语义，清楚审查，低惊讶度”。

CLI 上，`rollout`、`check`、`templates`、论文实验 runner 和组织流程应该离开主入口。`init/compile/run/watch/mcp/control/doctor` 才是工业用户真正会长期依赖的面。

仓库上，paper artifact 可以公开，但应该作为 artifact release 或独立数据集公开。主分支只保留复现指针、校验信息、小样本和维护脚本。原始数据尤其应该迁出主分支，因为它是许可、隐私、体积和产品心智的共同风险点。
