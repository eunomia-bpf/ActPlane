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
# Two checks, because no single portable one covers both failure modes:
#
#   1. A source-provenance stamp. `bpf/prebuilt/source.sha256` records a digest
#      over the kernel C the committed objects were built from. Any source edit
#      (including a body-only change that adds no function) changes the digest,
#      so the gate fails until the objects and the stamp are regenerated
#      together. The digest is over source bytes, not compiler output, so it is
#      independent of the clang/LLVM version.
#
#   2. A source-derived symbol check. Every function the source marks `__noinline`
#      (and that a build of the source actually emits) must be defined in the
#      committed object. This is what names the specific missing function when an
#      object predates a *new* source function, which is the exact 8298d23a
#      failure mode; it also catches an object and stamp that were regenerated
#      from different sources.
#
# Exact object bytes cannot be the gate: they track the toolchain (clang 17, 18,
# and 19 each yield a different size), as does even the raw symbol table (some
# builds emit basic-block labels `LBB0_*` as local symbols and others do not).
#
# Usage:
#   bash script/check_prebuilt_fresh.sh            # verify (rebuilds, then checks)
#   bash script/check_prebuilt_fresh.sh --update   # restamp, only if the committed
#                                                  # objects byte-match a fresh build
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The inputs that determine the committed object: the kernel C and the Makefile
# that holds the compile flags. `vmlinux.h` is generated from the host BTF and is
# not committed, so it is excluded. This is `bpf/build.rs`'s rerun-input list
# minus `vmlinux.h`; `build.rs` itself only orchestrates and is not a codegen
# input.
SOURCES=(bpf/process.bpf.c bpf/process.h bpf/taint.h bpf/taint_engine.bpf.h \
         bpf/capability.bpf.h bpf/channel.bpf.h bpf/Makefile)
STAMP="bpf/prebuilt/source.sha256"

# Digest over each source path and its content, in a fixed order.
source_digest() {
  for f in "${SOURCES[@]}"; do
    printf '%s\n' "$f"
    cat "$f"
  done | sha256sum | awk '{ print $1 }'
}

NM="${LLVM_NM:-llvm-nm}"

if [ "${1:-}" = "--update" ]; then
  for f in "${SOURCES[@]}"; do
    [ -f "$f" ] || { echo "missing source: $f" >&2; exit 2; }
  done
  # Refuse to stamp unless the committed objects are exactly what a build of the
  # current source produces, so `--update` cannot silence the gate by stamping an
  # object that was never regenerated. Run right after regenerating (as
  # bpf/build.rs does), the bytes match; run on an edited source with stale
  # objects, they do not.
  make -C bpf .output/process.bpf.o .output/process-legacy.bpf.o >/dev/null
  for obj in process process-legacy; do
    if ! cmp -s "bpf/.output/$obj.bpf.o" "bpf/prebuilt/$obj.bpf.o"; then
      echo "refusing to update the stamp: bpf/prebuilt/$obj.bpf.o differs from a" >&2
      echo "fresh build of the source. Regenerate the committed objects first:" >&2
      echo "    ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine" >&2
      exit 1
    fi
  done
  printf '%s\n' "$(source_digest)" > "$STAMP"
  echo "recorded source stamp for the committed prebuilt objects in $STAMP"
  exit 0
fi

command -v "$NM" >/dev/null || { echo "missing llvm-nm (install llvm)" >&2; exit 2; }
for f in bpf/prebuilt/process.bpf.o bpf/prebuilt/process-legacy.bpf.o "$STAMP"; do
  [ -f "$f" ] || { echo "missing committed file: $f" >&2; exit 2; }
done

# Functions the current source marks `__noinline`; these are emitted as named
# symbols and their names come from the source text, so the check is stable
# across compilers.
source_noinline() {
  grep -rh '__noinline' bpf/*.h bpf/*.c \
    | grep -oE '[A-Za-z_][A-Za-z0-9_]*\(' | tr -d '(' \
    | grep -vx '__attribute__' | sort -u
}
object_functions() {
  "$NM" --defined-only "$1" 2>/dev/null \
    | awk '$2=="T" || $2=="t" { print $3 }' | sort -u
}

stale=0

# 1. Source-provenance stamp.
want="$(source_digest)"
have="$(cat "$STAMP")"
if [ "$want" != "$have" ]; then
  stale=1
  echo "STALE the committed objects were built from a different source:" >&2
  echo "      stamp says $have" >&2
  echo "      source is  $want" >&2
fi

# 2. Rebuild and require every emitted __noinline function to be defined.
make -C bpf .output/process.bpf.o .output/process-legacy.bpf.o >/dev/null

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
source_noinline > "$tmp/src.funcs"

for obj in process process-legacy; do
  built="bpf/.output/$obj.bpf.o"
  committed="bpf/prebuilt/$obj.bpf.o"

  object_functions "$built"     > "$tmp/built.funcs"
  object_functions "$committed" > "$tmp/committed.funcs"

  # Only require functions the source marks __noinline AND that a build of the
  # source actually emits (an unreferenced __noinline function may be dropped).
  comm -12 "$tmp/src.funcs" "$tmp/built.funcs" > "$tmp/required.funcs"

  missing="$(comm -23 "$tmp/required.funcs" "$tmp/committed.funcs" || true)"
  if [ -n "$missing" ]; then
    stale=1
    echo "STALE $committed lacks __noinline functions the source defines:" >&2
    printf '  %s\n' $missing >&2
  elif [ "$stale" -eq 0 ]; then
    echo "ok   $committed defines every __noinline function the source defines" \
         "($(wc -l < "$tmp/required.funcs") checked)"
  fi

  # Byte drift alone is not a failure: it can be a toolchain difference.
  if ! cmp -s "$built" "$committed"; then
    echo "note $committed differs in bytes from a local rebuild (toolchain-dependent):" \
         "committed=$(stat -c%s "$committed") built=$(stat -c%s "$built")" >&2
  fi
done

if [ "$stale" -ne 0 ]; then
  cat >&2 <<'EOF'

The committed prebuilt eBPF object(s) do not correspond to the current kernel C
source. Because `ebpf-ifc-engine` embeds the committed object, production would
load engine code that lacks the current source (a silent correctness gap, not
just a stale binary). Regenerate and commit both the objects and the stamp:

    ACTPLANE_REBUILD_BPF=1 cargo build -p ebpf-ifc-engine

or

    make -C bpf .output/process.bpf.o .output/process-legacy.bpf.o &&
      cp bpf/.output/process.bpf.o bpf/.output/process-legacy.bpf.o bpf/prebuilt/ &&
      bash script/check_prebuilt_fresh.sh --update
EOF
  exit 1
fi

echo "prebuilt eBPF objects contain the current source"
