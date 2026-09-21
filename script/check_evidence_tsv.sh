#!/bin/bash
# Fail if the committed empirical-study TSV evidence is malformed.
#
# The `docs/empirical-study/` tree holds the retained evidence for the
# reviewer-facing findings, and several of its tables are parsed by row: the
# probe's `counts.tsv`/`expectations.tsv`/`summary.tsv` are compared case by
# case, and the runners write them in ground-truth order. The whole tree is
# checked, not only `results/`, because row-oriented evidence also lives beside
# it (`candidate_rules_144.tsv`). A row with a different number of tab-separated
# fields than its neighbours has no defined field meaning, so an
# `awk -F '\t' '$3 == ...'`-style check either misses the row or reads the wrong
# field. This has happened twice: an `expectations.tsv` was committed with a
# 4-field header and 3-field data rows (a `printf` placeholders-vs-arguments
# mismatch, flagged in review on PR44), and a hand-assembled summary was committed
# with 2-field metric rows beside 3-field failure rows and no header at all.
#
# The check is: every non-blank, non-comment row after the first data row has the
# same field count as that first data row. Blank lines and `#` comments are
# skipped and do not become the reference row, matching how the runners'
# consumers read these files. A one-field file (no tab anywhere) is trivially
# consistent and passes.
#
# The reference is the first *data* row rather than a marker for "this is a
# header", because the legitimate files in this tree differ on whether they carry
# one (`metadata.tsv` does not, and `summary.tsv` files are hand-written). A file
# whose data rows disagree is the defect; a file with no header but consistent
# rows is not.
#
# Usage: bash script/check_evidence_tsv.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Everything under the empirical-study tree, not just `results/`: the retained
# artifacts include row-oriented TSVs outside it (`candidate_rules_144.tsv`), and
# an evidence file should be checked wherever it is committed.
DIRS=(docs/empirical-study)
bad=0
checked=0

for dir in "${DIRS[@]}"; do
  [ -d "$dir" ] || continue
  while IFS= read -r -d '' f; do
    checked=$((checked + 1))
    # Report the first mismatching row with its line number, so the fix is local.
    awk -F '\t' '
      /^[[:space:]]*$/ { next }
      /^[[:space:]]*#/ { next }
      !seen { ref = NF; seen = 1; next }
      NF != ref {
        printf "%s:%d: %d field(s), first data row has %d\n", FILENAME, NR, NF, ref
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

A committed evidence TSV has rows with inconsistent field counts, so a row's
fields do not mean what the first data row says. This is usually a `printf`
format placeholders-vs-arguments mismatch, or a hand-assembled file mixing two
row shapes. Fix the file rather than the check: give every row the same count.
EOF
  exit 1
fi

echo "ok   committed evidence TSVs are internally consistent ($checked checked)"
