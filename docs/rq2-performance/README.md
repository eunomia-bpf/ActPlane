# ActPlane Performance Benchmarks

This directory contains the RQ2 performance harness. It is intentionally separate
from the RQ1 corpus statement directories so benchmark inputs, generated
policies, and performance summaries do not change the compliance dataset.

## What It Measures

`syscall_microbench.c` measures per-operation latency for:

- `open`: `open(path, O_RDONLY|O_CLOEXEC)`, with `close` outside the timed region
- `write`: `write(fd, 4096B)` to an already-open temp file
- `connect`: UDP `connect(127.0.0.1:9)` on an already-created socket
- `fork`: `fork()` plus parent `waitpid()`
- `exec`: `fork()` plus child `execve("/bin/true")` plus parent `waitpid()`

The `fork` and `exec` measurements include scheduler and wait overhead. The
paper should report them exactly that way; ActPlane overhead is the paired
difference against the same benchmark without ActPlane.

`run_perf.py` builds the C benchmark, generates no-hit ActPlane policies for
`AP-1`, `AP-10`, `AP-32`, and `AP-100`, runs repeated trials, and writes
per-run summary records plus aggregate CSV/JSON files.

`run_macro.py` runs macro/end-to-end workloads with the same no-hit policy
families: deterministic corpus-derived agent trace replay, Linux kernel build,
fixed-op `stress-ng` workloads, and real repository build/test commands wrapped
with `/usr/bin/time -v`.

`agent_trace_replay.py` replays `trace_{compliant,violation}.jsonl` files from a
corpus trace root without an LLM. The product branch does not keep the full
trace corpus; pass `--trace-root` or run from an artifact branch that provides
`docs/corpus-test/*/*/trace_{compliant,violation}.jsonl`. The replay executes
the Read/Write/Edit/Bash tool actions in a temporary workspace with stubs for
project-local tools such as `uv`, `pytest`, and `git`.

`linux_build_once.py` builds a Linux kernel target in a fresh `O=` directory.
Use a clean source tree. If an existing kernel checkout already contains in-tree
build products, export a clean copy with `git archive` or use another clean
source directory rather than running `make mrproper` on a user's tree.

`plot_rq2.py` generates the three RQ2 figures from a micro result directory and
a macro result directory.

## Recommended Paper Run

Run this on an otherwise idle machine, pin to an isolated CPU, keep the CPU
governor fixed, and preserve the generated summary results:

```bash
python3 docs/rq2-performance/run_perf.py \
  --build-actplane \
  --configs baseline,ap-1,ap-10,ap-32,ap-100 \
  --ops open,write,connect,fork,exec \
  --repeats 7 \
  --cpu 2
```

For a quick local sanity check without eBPF privileges:

```bash
python3 docs/rq2-performance/run_perf.py --smoke --baseline-only
```

For macro workloads:

```bash
python3 docs/rq2-performance/run_macro.py \
  --configs baseline,ap-32,ap-100 \
  --workloads stressng-open,stressng-fork,stressng-exec,stressng-hdd,stressng-mixed,actplane-release-build \
  --repeats 3
```

For the RQ2 paper figures:

```bash
# 1. Syscall microbenchmarks.
python3 docs/rq2-performance/run_perf.py \
  --build-actplane \
  --configs baseline,ap-1,ap-10,ap-32,ap-100 \
  --ops open,write,connect,fork,exec \
  --repeats 7 \
  --cpu 2 \
  --output-dir docs/rq2-performance/results/rq2-micro

# 2. Agent trace replay + Linux build macrobenchmarks.
python3 docs/rq2-performance/run_macro.py \
  --configs baseline,ap-32,ap-100 \
  --workloads agent-trace,linux-build \
  --repeats 3 \
  --timeout-s 9000 \
  --linux-source docs/rq2-performance/tmp/linux-src-clean \
  --linux-target vmlinux \
  --linux-jobs 24 \
  --output-dir docs/rq2-performance/results/rq2-macro

# 3. Figures.
python3 docs/rq2-performance/plot_rq2.py \
  --micro-dir docs/rq2-performance/results/rq2-micro \
  --macro-dir docs/rq2-performance/results/rq2-macro \
  --out-dir docs/rq2-performance/tmp/rq2-overhead-figures
```

## Output

Each run creates `docs/rq2-performance/results/<timestamp>/` with:

- `metadata.json`: hardware, kernel, git revision, active LSMs, command line
- `policies/*.yaml`: exact generated policies used for AP configurations
- `runs.jsonl`: one record per config/op/repeat
- `runs.csv`: flattened per-run statistics
- `aggregate.csv` and `aggregate.json`: median statistics across repeats and
  overhead relative to the median baseline for the same operation

The generated `logs/`, `raw/`, and temporary workload directories are not part
of the checked-in summary artifact. Per-run command lines, exit status,
`/usr/bin/time -v` resource fields, and benchmark summaries are extracted into
`runs.csv` / `runs.jsonl`. If bootstrap confidence intervals are needed, rerun
the microbenchmarks with `--raw-samples` and archive those samples separately.

## OSDI-Style Reporting Notes

- Report machine, kernel, LSM state, CPU governor, CPU pinning, and ActPlane git
  revision from `metadata.json`.
- Report median across repeated trials, not a single run.
- Include p50, p99, and p999 per-operation latency from `runs.*` and
  `aggregate.*`.
- Use no-hit policies for the primary overhead table. That isolates steady-state
  rule-scanning and label propagation from ring-buffer/reporting cost. The
  generated policies label the workload subtree (`source COMMAND = exec "**"`)
  but use unreachable sink targets.
- Treat violation/reporting latency as a separate experiment if needed; it
  exercises a different path (ring buffer + userspace feedback formatting).
