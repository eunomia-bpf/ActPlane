#!/bin/bash
# Fail if the committed empirical-study TSV evidence is malformed.
#
# The result directories under `docs/empirical-study/results/` are the retained
# evidence for the reviewer-facing findings, and several of them are parsed by
# row: the probe's `counts.tsv`/`expectations.tsv`/`summary.tsv` are compared
# case by case, and the runners write them in ground-truth order. A row with a
# different number of columns than its header has no defined field meaning, so
# `awk -F '\t' '$3 == ...'`-style checks either miss the row or read the wrong
# field. This has happened: an `expectations.tsv` was committed with a 4-column
# header and 3-column data rows (flagged in review on PR44), and a
# hand-assembled summary was committed with 2-column metric rows beside
# 3-column failure rows.
#
# Two checks, because the two shapes are both legitimate:
#
#   1. Every data row has the same number of tab-separated fields as its header.
#      This is the malformed-row check, and it is the one that catches the
#      `printf` placeholder/argument mismatch that produced the 4-vs-3 header.
#   2. A file has a header at all. `metadata.tsv` and the free-form `*.tsv`
#      written by hand are the exception, so the check is that any file whose
#      rows are `metric<TAB>value`-like carries one; a file with no tab at all
#      in its first line is a one-column file and is left alone.
#
# Blank lines and `#` comments are ignored, matching how the runners' own
# consumers read these files.
#
# Usage: bash script/check_evidence_tsv.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DIRS=(docs/empirical-study/results)
bad=0
checked=0

for dir in "${DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r -d '' f; do
    checked=$((checked + 1))
    # Report the first mismatching row with its line number, so the fix is
    # local. `awk` strips nothing: fields are counted with -F '\t'.
    awk -F '\t' '
      /^[[:space:]]*$/ { next }
      /^[[:space:]]*#/ { next }
      NR == 1 { header = NF; next }
      NF != header {
        printf "%s:%d: %d field(s), header has %d\n", FILENAME, NR, NF, header
        exit 1
      }
    ' "$f" || { echo "MALFORMED $(basename "$f")" >&2; bad=1; }
  done < <(find "$dir" -type f -name '*.tsv' -print0 | sort -z)
done

if [ "$checked" -eq 0 ]; then
  echo "no TSV evidence found to check" >&2
  exit 2
fi

if [ "$bad" -ne 0 ]; then
  cat >&2 <<'EOF'

A committed evidence TSV has a row whose field count differs from its header, so
that row's fields do not mean what the header says. This is usually a `printf`
format placeholders-vs-arguments mismatch, or a hand-assembled file mixing two
row shapes. Fix the file rather than the check: give every row the header's
count, and give hand-written files a header.
EOF
  exit 1
fi

echo "ok   committed evidence TSVs are well-formed ($checked checked)"
