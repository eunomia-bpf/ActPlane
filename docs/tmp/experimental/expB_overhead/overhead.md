# Exp-B 真实负载稳态开销 (audit, attach-once watch, N=12)

ActPlane 经 `watch` 一次性挂载(taint 引擎 + 规则循环在每个 syscall 上运行);对比同一真实负载挂载前后的墙钟。

| workload | bare p50/p99 (s) | +ActPlane p50/p99 (s) | median 开销 |
|---|---|---|---|
| cc-compile | 1.000 / 1.010 | 1.010 / 1.020 | +1.0% |
| git-loop | 2.360 / 2.550 | 2.530 / 2.550 | +7.2% |
| find-grep | 1.530 / 1.540 | 1.520 / 1.560 | -0.7% |
