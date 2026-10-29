#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/corpus-relabel/src
mkdir -p figures
cd layout
/workspaces/exp/corpus-merge/.venv/bin/python -u ../verify_figures.py
cd ..
for pdf in figures/empirical_rq*.pdf; do
    pdffonts "$pdf" > "${pdf%.pdf}.pdffonts.txt"
    if grep -q 'Type 3' "${pdf%.pdf}.pdffonts.txt"; then exit 1; fi
    pdftoppm -png -singlefile -r 120 "$pdf" "${pdf%.pdf}"
done
test "$(find figures -name '*.pdf' | wc -l)" -eq 4
echo 'PASS: four figures, count reconciliation, no Type 3 fonts'
