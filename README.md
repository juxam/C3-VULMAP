# C3-VULMAP

**A LINDDUN-CWE privacy-focused vulnerability dataset for healthcare-relevant C/C++ software.**

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18937798.svg)](https://doi.org/10.5281/zenodo.18937798)

Companion dataset to:

> Ameh, J.E. et al. "C3-VULMAP: A Dataset for Privacy-Aware Vulnerability
> Detection in Healthcare Systems." *Electronics* 2025, 14(13), 2703.
> https://doi.org/10.3390/electronics14132703

**This version accompanies the Applied Sciences resubmission** and is a
substantial rebuild of the original Electronics-paper artifact — see
"What changed" below before assuming v1-era numbers or file layout still
apply.

Dataset files (all versions): https://doi.org/10.5281/zenodo.18937798
(the concept DOI always resolves to the latest version)

---

## What C3-VULMAP is

C/C++ functions mapped through a two-hop chain — CWE → MITRE weakness
category → LINDDUN privacy threat type — so vulnerability findings carry
an explicit privacy dimension, not just a CWE tag. Built for automated,
privacy-aware vulnerability detection research, with a particular
healthcare-systems focus.

## Two tiers, released separately, never pooled

| | rows | label basis |
|---|---|---|
| **Supervised corpus** (`corpus_final.parquet`) | 332,970 | Real, CVE/commit-verified vulnerable or safe |
| **Static-analysis labels** (`starcoder_tier2_static_labels.csv`, over `starcoder_tier2.parquet`) | 2,102,354 flagged of 14,838,026 scanned | flawfinder pattern match — **not** a confirmed vulnerability |

The supervised corpus is what every classification result in the
accompanying paper is built on. The static-analysis tier is bulk,
general C/C++ source with heuristic CWE tags attached — useful for
scale and for future unsupervised work, but its absence of a flagged
pattern is not evidence of safety, and its presence of one is not a
verified vulnerability. Every row carries a `label_source` column
(`cve_verified` vs. `static_analysis`) stating which kind of claim it
actually is — see `CONSTRUCTION.md` for the full reasoning and why
pooling these two would reintroduce the exact defect this rebuild
exists to remove.

## What changed from the original (Electronics-paper) release

The original v1.0 artifact was a single flat file with no source-level
provenance retained — which is precisely what limited its reuse and
auditability. This version:

- **Separates supervised and unsupervised data explicitly**, rather
  than one pooled file, with an explicit `label_source` column stating
  the evidentiary basis of every label.
- **Retains full provenance** — source dataset, project, commit,
  file path — on every row, rather than discarding it after
  construction.
- **Adds 140 targeted synthetic examples**, written to fill the three
  LINDDUN categories the real data left thinnest (Non-repudiation,
  Unawareness, Data Disclosure), verified against the same
  contamination screen as everything else.
- **Corrects the CWE→LINDDUN mapping chain**, including excluding 65
  CWEs that MITRE itself designates too abstract to map to a specific
  vulnerability (confirmed directly against MITRE's own definitions,
  not assumed), and adding coverage MITRE actually endorses (`CWE-416`)
  along with five newly-curated category-level LINDDUN mappings.
- **Adds a genuinely independent 14.8M-row static-analysis tier**
  (StarCoder-derived), clearly separated from the supervised corpus
  rather than risking the provenance-as-label-shortcut problem the
  original release's design was vulnerable to.

Full construction methodology, with every number independently
verifiable by rerunning the pipeline: [`CONSTRUCTION.md`](CONSTRUCTION.md).

## Files

Hosted on Zenodo (see DOI above) — not in this repository, which holds
code and documentation only:

- `corpus_final.parquet` — supervised corpus, 332,970 rows
- `starcoder_tier2.parquet` — tier-2 source text, 14,838,026 rows
- `starcoder_tier2_static_labels.csv` — tier-2 static-analysis labels, 2,102,354 flagged files
- `cwe_category_map.csv`, `category_id_to_linddun.csv`, `excluded_abstract_cwes.csv` — the privacy-category mapping chain in full, for independent verification

## Reproducing this dataset

Every script referenced in `CONSTRUCTION.md` is in this repository,
numbered in pipeline order, runnable against the same public sources
(DiverseVul, ReposVul, StarCoder) this release was built from.

## Citation

If you use this dataset, please cite both the original paper and the
dataset DOI for the version you used:

```bibtex
@article{ameh2025c3vulmap,
  title={C3-VULMAP: A Dataset for Privacy-Aware Vulnerability Detection in Healthcare Systems},
  author={TODO: full author list, verify against the published paper before use},
  journal={Electronics},
  volume={14},
  number={13},
  pages={2703},
  year={2025},
  doi={10.3390/electronics14132703}
}
```

**The author field above is a placeholder, not a verified citation** —
I don't have your full, confirmed co-author list and didn't want to
guess at names/order for something citable. Please fill this in
directly from the published paper before this goes live.

See `CITATION.cff` for the dataset-specific citation, or use GitHub's
"Cite this repository" button above.

## License

CC0-1.0 (see `LICENSE`).
