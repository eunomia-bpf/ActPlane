# ActPlane ATC 2026 Paper Draft

This directory contains an ACM SIGOPS ATC 2026 paper draft for ActPlane.

## Format Target

ATC 2026 is now the ACM SIGOPS Annual Technical Conference. The official CFP
requires:

- PDF submission.
- Double-blind review; use the assigned paper ID in place of author names.
- Long papers: at most 12 pages, excluding references and appendices.
- Short papers: at most 6 pages, excluding references and appendices.
- A two-page extended abstract submitted with the paper.
- A4 or US letter paper, two columns, a centered 178 x 229 mm text block, 10 pt
  Times-like font on 12 pt leading.
- Page numbers and hyperlinked references.
- Recommended LaTeX class:
  `\documentclass[sigplan,10pt]{acmart}` plus
  `\renewcommand\footnotetextcopyrightpermission[1]{}`,
  `\pagestyle{plain}`, and `\settopmatter{printfolios=true}`.

Sources checked:

- ATC 2026 homepage: https://sigops.org/s/conferences/atc/2026/index.html
- ATC 2026 CFP: https://sigops.org/s/conferences/atc/2026/cfp.html
- ATC 2026 extended abstract guidance:
  https://sigops.org/s/conferences/atc/2026/abstract.html
- ACM LaTeX guidance:
  https://authors.acm.org/proceedings/production-information/preparing-your-article-with-latex
- SIGPLAN author format notes:
  https://sigplan.org/Resources/Author/

## Template

The ACM direct template URL returned HTTP 403 from this environment, so the ACM
`acmart` package was downloaded from CTAN, which ACM and SIGPLAN list as an
accepted distribution channel:

- Downloaded archive: `vendor/acmart-ctan.zip`
- Generated local class: `acmart.cls`
- Local bibliography style: `ACM-Reference-Format.bst`

The draft uses the local class/style files so it can build without requiring a
system-wide `acmart` installation.

The CTAN archive was extracted only to generate the local class/style files; the
expanded template tree is not kept in the repository. Build PDFs are tracked,
while LaTeX scratch files are ignored by `docs/paper/.gitignore`.

The draft follows the CFP's `sigplan,10pt` setup and keeps page numbers enabled
with `\settopmatter{printfolios=true}`.

## Build

```bash
cd docs/paper
make
make abstract
make clean
```

Outputs:

- `main.pdf`: full paper draft.
- `extended-abstract.pdf`: two-page extended abstract draft.

## Draft Status

The evaluation section is intentionally a plan with `TBD` result slots. Do not
fill performance, coverage, or agent success numbers until the corresponding
experiments have been run.
