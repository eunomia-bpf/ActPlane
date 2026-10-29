# Blocking dependencies and explicit deviations

## Widely used OS-backed benchmark

The preferred OS-Harm installation is currently blocked by the shared disk envelope. `scripts/feasibility.py` records filesystem capacity and the official VM archive HEAD. `scripts/image_inventory.py` reads only the ZIP central directory, including ZIP64 sizes. The official download/extract implementation retains both the archive and extracted image. The combined default installation does not fit current free space, before Docker images and guest writes, and cannot respect the user's utilization ceiling. No image download or removal of another lane's data was performed. See `results/feasibility.json` and `results/image_inventory.json` once pulled.

Resolution: a supervisor-provided OS-Harm VM with sufficient storage, plus a verified guest ActPlane BPF enforcement path. Host instrumentation around the VM is insufficient. RTC-Bench has a still larger official service/storage setup. We continue with published RepoGuardBench tasks, explicitly retaining the unverified broad-adoption caveat. This does not close the requested widely-used-benchmark requirement.

## Per-attempt kernel rejection attribution

Current ActPlane runtime may reject invalid policy submissions in a userspace authority precheck before a kernel request is made. Existing JSONL audit records alone cannot attribute such rejections to the kernel. The adapter retains actual caller PID, target, policy text, audit record and kernel admission counters, labels the decision stage, and reports missing attribution. Original kernel checkouts remain unchanged; the lane-owned copied build is described below. A lack of natural weakening attempts in the official attacks will be reported as uncovered, not converted into synthetic attack successes or fabricated rejection evidence.

## Kernel execution setup resolved

The stock supplied artifact could not enforce this experiment unchanged: its advertised matcher profile omitted file sink classes, enabling them exposed verifier complexity, and container PID identities differed from the kernel's identities. A lane-owned copied build and lightweight KVM guest now pass real allow/deny and child-admission preflight. See `KERNEL.md` and `results/kernel-preflight/`. The copied artifact enables implemented file matchers, narrows runtime-domain depth to the tested topology, and adds diagnostic rejection counters. Original checkouts remain unchanged. This is an explicit modified-artifact limitation, not a remaining execution blocker or a claim about the stock binary.
