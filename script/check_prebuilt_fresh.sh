#!/bin/bash
# Fail if the committed eBPF objects do not contain the current kernel C source.
#
# `ebpf-ifc-engine` embeds `bpf/prebuilt/process.bpf.o` with `include_bytes!`, so
# that committed object is the engine production loads. Nothing else ties it to
# the source it was built from: commit 8298d23a added `te_record_file_prov_mask`
# to `taint_engine.bpf.h` and regenerated no object, so `master` shipped an
# engine that omitted the committed file-source-provenance fix (and whose
# `trace_rename_exit` failed the Linux 6.8 verifier where a fresh build loads).
#
# The check is symbol-based, not byte-based. The prebuilt objects are committed
# binaries, and their exact bytes depend on the clang/LLVM that produced them
# (clang 17, 18, and 19 each yield a different size), so a byte-identity gate
# fails spuriously on a checkout whose CI toolchain differs from the
# committer's. What must hold regardless of toolchain is that the object defines
# every function the current source defines; byte drift is reported as a note.
#
# Usage: bash script/check_prebuilt_fresh.sh   (needs clang, llvm, libbpf, bpftool)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NM="${LLVM_NM:-llvm-nm}"
command -v "$NM" >/dev/null || { echo "missing llvm-nm (install llvm)" >&2; exit 2; }
for f in bpf/prebuilt/process.bpf.o bpf/prebuilt/process-legacy.bpf.o; do
  [ -f "$f" ] || { echo "missing committed object: $f" >&2; exit 2; }
done

# Rebuild both objects from the current source.
make -C bpf .output/process.bpf.o .output/process-legacy.bpf.o >/dev/null

# Defined functions in an object.
object_functions() {
  "$NM" --defined-only "$1" 2>/dev/null \
    | awk '$2=="T" || $2=="t" { print $3 }' | sort -u
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

status=0
for obj in process process-legacy; do
  built="bpf/.output/$obj.bpf.o"
  committed="bpf/prebuilt/$obj.bpf.o"

  object_functions "$built" > "$tmp/built.funcs"
  object_functions "$committed" > "$tmp/committed.funcs"

  # Every function a fresh build defines must exist in the committed object. A
  # non-__noinline helper can be inlined away, so a symbol present in only one
  # object is normal in that direction; a symbol the committed object lacks that
  # a build has is the staleness signature (or a different toolchain).
  missing="$(comm -13 "$tmp/committed.funcs" "$tmp/built.funcs" || true)"
  if [ -n "$missing" ]; then
    status=1
    echo "STALE $committed lacks functions a fresh build defines:" >&2
    printf '  %s\n' $missing >&2
  else
    echo "ok   $committed defines every function a fresh build defines"
  fi

  # Byte drift alone is not a failure: it can be a toolchain difference.
  if ! cmp -s "$built" "$committed"; then
    echo "note $committed differs in bytes from a local rebuild" \
         "(toolchain-dependent; see the function sets above):" \
         "committed=$(stat -c%s "$committed") built=$(stat -c%s "$built")" >&2
  fi
done

if [ "$status" -ne 0 ]; then
  cat >&2 <<'EOF'

The committed prebuilt eBPF object(s) do not contain the current kernel C source.
Because `ebpf-ifc-engine` embeds the committed object, production would load
engine code that lacks the current source (a silent correctness gap, not just a
stale binary). Regenerate and commit:

    ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine

or `make -C bpf process .output/process-legacy.bpf.o` and copy `.output/*.bpf.o`
over `prebuilt/`.
EOF
  exit 1
fi

echo "prebuilt eBPF objects contain the current source"
