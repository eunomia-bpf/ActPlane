---
name: oss-change-workflow
description: Workflow for changing code, tests, docs, or examples in the ActPlane OSS repository. Covers scope control, local validation before committing, keeping docs and tests in sync with the change, and the branch/PR/CI handoff.
when_to_use: Before editing code, tests, docs, or examples in this repository; when preparing a commit or pull request
allowed-tools: Read Edit Bash(make *) Bash(cargo *) Bash(git *) Bash(python3 *) Bash(bash *)
---

# OSS Change Workflow

Use this before changing code, tests, docs, or examples in this repository. It is the
scope-control, validation, docs/test-sync, and PR/CI handoff checklist that
`CLAUDE.md` refers to. Read `CLAUDE.md` first for the architecture and the Rust<->C
ABI rules; this skill is the process around a change, not a substitute for it.

## 1. Scope control

- Make the change the task asked for. Do not fold in adjacent cleanups, extra
  validation layers, or speculative abstractions "while you are there".
- Prefer editing an existing file over adding a new one. A new file needs a reason
  the existing files cannot carry.
- Default to a clean cutover: when a behavior or name changes, migrate every
  caller and remove the obsolete path (alias, re-export, deprecated branch) in the
  same change. Do not leave a shim.
- `EPERM` / `Operation not permitted`, or an `[ActPlane]` hook message, is
  authoritative kernel feedback. Read `.actplane/last-violation.txt` for the full
  reason and follow the suggested path. Do not retry the operation unchanged.

## 2. Validation

Run the gate that covers what you touched. Docs-only changes do not need the cargo
suite; a kernel change needs the kernel guards.

```bash
python3 script/check_doc_refs.py        # doc path/command citations resolve
bash script/check_evidence_tsv.sh       # committed evidence TSVs are well-formed
bash script/check_prebuilt_fresh.sh     # committed eBPF objects match the source
make -C bpf test                        # C unit tests (test_taint)
cargo test -p actplane-ifc-compiler     # policy-compiler tests
cargo test -p actplane-runtime          # runtime/control tests
cargo test --workspace --locked         # full Rust workspace
cargo fmt --all -- --check
cargo check --workspace --locked
```

`make test` runs the bpf C unit tests plus the Rust workspace tests. The three
`script/check_*.py|sh` guards are what the `Build and Test` CI job runs, so run the
ones your change implicates before committing rather than discovering them in CI.

Changes to `bpf/` (the eBPF engine) need a privileged run, and the host checkout may
deny `bpf()`. The kernel path is validated by booting a guest of the target kernel
(6.8) and running the loader there. After editing any kernel C, regenerate the
objects and the stamp together:

```bash
ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine
```

Never edit `bpf/prebuilt/source.sha256` by hand; `--update` refuses to stamp unless
the committed objects byte-match a fresh build.

## 3. Docs and tests in sync

- A claim a reader can act on must be tied to the code that enforces it. When a
  doc names a path, a symbol, a line, or a command, verify it still resolves
  (`check_doc_refs.py` covers paths and skill slash-commands; a symbol name needs a
  grep for its definition).
- Changing a documented behavior means updating the doc in the same commit. The
  failure mode is a doc that silently drifts while its guard stays green, so name
  the enforcing location (`file.rs:line`) when you fix such a claim.
- Any change to `bpf/taint.h` MUST be mirrored in
  `crates/actplane-ifc-compiler/src/dsl/lower.rs`, and vice versa. Update the offset
  and size guards together (`config_blob_is_fixed_size`,
  `abi_layout_matches_the_c_header`, `test_abi_layout`); a same-width field
  reorder reinterprets every serialized field, so changing one without the other
  passes the size test and ships a broken blob.
- A test earns its place when a plausible bug fails it. Prefer asserting observable
  behavior over wiring, defaults, or source text.

## 4. Branch, PR, and CI handoff

- Develop on a dedicated non-default branch. Changes reach `master` through a pull
  request; do not push implementation or experiment commits directly to `master`.
- Commit messages in this repo are conventional and scoped (`docs:`, `script:`,
  `bpf:`, ...). Reference exact `file:line` locations for the behavior you changed.
- Stage named files, not `git add -A`, so an unrelated dirty tree (for example the
  `docs/papers` submodule) does not ride along.
- The CI jobs are `Build and Test` (runs the `script/check_*` guards plus the Rust
  suite), `Privileged eBPF Tests` (kernel boot), and `GitGuardian Security Checks`.
  Make them pass locally with the commands in section 2 before opening the PR, then
  confirm they settle green on the pushed head before asking for review.
