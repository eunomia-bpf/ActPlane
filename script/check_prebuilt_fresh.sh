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
# The check is symbol-based, and deliberately only over names that come from the
# C source, not over every object symbol. Exact object bytes track the clang/LLVM
# that produced them (clang 17, 18, and 19 each yield a different size), and even
# the raw symbol table is toolchain-dependent: some clang builds emit basic-block
# labels (LBB0_*) as local symbols and others do not. What must hold regardless
# of toolchain is that the object defines every function the source marks
# `__noinline` (and that a build of the source actually emits). Those names come
# from the source text, so the check is stable across compilers while still
# catching a stale object that predates a new source function.
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

# Functions the current source marks `__noinline`. These are emitted as named
# symbols rather than inlined, and the names are source text, so they are stable
# across clang/LLVM versions.
source_noinline() {
  grep -rh '__noinline' bpf/*.h bpf/*.c \
    | grep -oE '[A-Za-z_][A-Za-z0-9_]*\(' | tr -d '(' \
    | grep -vx '__attribute__' | sort -u
}
# Defined function symbols in an object.
object_functions() {
  "$NM" --defined-only "$1" 2>/dev/null \
    | awk '$2=="T" || $2=="t" { print $3 }' | sort -u
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
source_noinline > "$tmp/src.funcs"

status=0
for obj in process process-legacy; do
  built="bpf/.output/$obj.bpf.o"
  committed="bpf/prebuilt/$obj.bpf.o"

  object_functions "$built"     > "$tmp/built.funcs"
  object_functions "$committed" > "$tmp/committed.funcs"

  # Only require functions the source marks __noinline AND that a build of the
  # source actually emits (a __noinline function that is never referenced may be
  # dropped). Intersecting keeps the required set source-derived and portable.
  comm -12 "$tmp/src.funcs" "$tmp/built.funcs" > "$tmp/required.funcs"

  missing="$(comm -23 "$tmp/required.funcs" "$tmp/committed.funcs" || true)"
  if [ -n "$missing" ]; then
    status=1
    echo "STALE $committed lacks __noinline functions the source defines:" >&2
    printf '  %s\n' $missing >&2
  else
    echo "ok   $committed defines every __noinline function the source defines" \
         "($(wc -l < "$tmp/required.funcs") checked)"
  fi

  # Byte drift alone is not a failure: it can be a toolchain difference. Report
  # it so a maintainer can see that the object was produced elsewhere.
  if ! cmp -s "$built" "$committed"; then
    echo "note $committed differs in bytes from a local rebuild (toolchain-dependent):" \
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

or `make -C bpf .output/process.bpf.o .output/process-legacy.bpf.o` and copy
`.output/*.bpf.o` over `prebuilt/`.
EOF
  exit 1
fi

echo "prebuilt eBPF objects contain the current source"
