#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== ActPlane YAML policy corpus =="
cargo test policy_corpus

echo
echo "== ActPlane CLI UX =="
cargo test --test cli_ux

echo
echo "== ActPlane IFC YAML policy compile microbench =="
ACTPLANE_POLICY_BENCH_ROUNDS="${ACTPLANE_POLICY_BENCH_ROUNDS:-200}" \
  cargo test --release policy_corpus_compile_perf -- --ignored --nocapture
