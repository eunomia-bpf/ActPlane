#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/exp/corpus-merge/src
PY=/workspaces/exp/corpus-merge/.venv/bin/python
"$PY" -u analyze_merge.py
mkdir -p figures
cd layout
"$PY" -u ../verify_figures.py
cd ..
for pdf in figures/empirical_rq*.pdf; do
    pdffonts "$pdf" > "${pdf%.pdf}.pdffonts.txt"
    if grep -q 'Type 3' "${pdf%.pdf}.pdffonts.txt"; then
        echo "Type 3 font in $pdf" >&2
        exit 1
    fi
    pdftoppm -png -singlefile -r 150 "$pdf" "${pdf%.pdf}"
done
printf 'PASS: four PDFs rendered, no Type 3 fonts\n'
