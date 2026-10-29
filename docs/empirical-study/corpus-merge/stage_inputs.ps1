# Stage immutable inputs for ws.sh sync; no analysis runs on the laptop.
$ErrorActionPreference = 'Stop'
$lane = $PSScriptRoot
$source = Join-Path (Split-Path $lane) 'corpus-scale'
$inputs = Join-Path $lane '.inputs'
New-Item -ItemType Directory -Force (Join-Path $inputs 'scale/rescue') | Out-Null
$files = @('README.md', 'labels.csv', 'analysis_statements.csv', 'statements.csv',
    'summary.csv', 'corpus_manifest.csv', 'repositories.csv', 'paper_labels.csv',
    'paper_files.csv', 'paper_provenance.csv', 'paper_audit.csv', 'recover.py',
    'snapshot_overlap.csv', 'format_calibration_summary.csv', 'calibration_summary.csv',
    'rescue/deploy.py', 'rescue/source-adjudicated.csv', 'rescue/deployment_gates.csv',
    'rescue/deployment_manifest.csv', 'rescue/test-r1-scores.csv',
    'rescue/frozen_selection.json', 'rescue/retained_axes.csv')
foreach ($file in $files) {
    Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $inputs "scale/$file")
}
$originalCommit = '63db86945c9b8618a46aa68c8de214bc4b8343d9'
$tree = git -C (Join-Path $lane '../../..') rev-parse "${originalCommit}:docs/corpus"
git -C (Join-Path $lane '../../..') archive --format=tar "--output=$inputs/original.tar" --prefix=docs/corpus/ --mtime=2026-05-23T00:00:00Z $tree
if ($LASTEXITCODE -ne 0) { throw 'Historical git archive failed' }
$paper = Join-Path $lane '../../../../actplane-atc'
Copy-Item -LiteralPath "$paper/scripts/plot_empirical.py" -Destination "$inputs/plot_empirical.original.py"
Copy-Item -LiteralPath "$paper/sections/02-motivation.tex" -Destination "$inputs/02-motivation.tex"
Write-Output "Staged inputs in $inputs"
