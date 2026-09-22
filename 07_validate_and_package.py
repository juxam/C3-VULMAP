"""
07_validate_and_package.py — the last checkpoint before anything gets
extracted, trained on, or released.

Three checks, each a direct callback to a specific failure found earlier in
this project:

  1. Metadata-only separability. If length/line-count alone predicts the
     label at high AUROC, the corpus has the same surface-level shortcut
     the old one did (0.71 AUROC from 4 features). Report it as a baseline
     either way — it belongs in the paper regardless of the result.
  2. Provenance-as-label-proxy. If is_synthetic (or source_dataset) predicts
     the label almost perfectly, that's the exact mechanism that made the
     old corpus's synthetic subset a free 35%-of-vulnerable giveaway.
  3. Contamination rate, pulled from 05's report.

This does not extract 512-D features or touch a GPU — it's a pure
metadata/text check, a few minutes at most, meant to catch a structural
problem before you spend hours on the expensive steps.

Run:  python 07_validate_and_package.py > validate_release.txt 2>&1
Out:  RELEASE_MANIFEST.json, corpus_final.parquet (unchanged, just read)
"""

import json
import re
from datetime import datetime, timezone

import numpy as np
import pandas as pd

import config

COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()
    path = outdir / "corpus_final.parquet"
    if not path.exists():
        raise SystemExit(f"{path} not found — run 06_build_splits.py first")

    df = pd.read_parquet(path)
    y = df.label.astype(int).values
    print(f"{len(df):,} rows, {int(y.sum()):,} vulnerable ({y.mean():.2%})")

    # -----------------------------------------------------------------
    head("1. METADATA-ONLY SEPARABILITY")
    df["n_chars"] = df.code.str.len()
    df["n_lines"] = df.code.str.count("\n") + 1
    df["comment_frac"] = [
        sum(len(m) for m in COMMENT_RE.findall(c)) / max(len(c), 1)
        for c in df.code]

    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import roc_auc_score

    tr = df.split_project == "train"
    te = df.split_project == "test"
    Xtr = df.loc[tr, ["n_chars", "n_lines", "comment_frac"]].values
    Xte = df.loc[te, ["n_chars", "n_lines", "comment_frac"]].values
    ytr, yte = y[tr.values], y[te.values]

    w = np.where(ytr == 1, (ytr == 0).sum() / max((ytr == 1).sum(), 1), 1.0)
    clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=42)
    clf.fit(Xtr, ytr, sample_weight=w)
    p = clf.predict_proba(Xte)[:, 1]
    auroc = roc_auc_score(yte, p)
    print(f"Metadata-only AUROC (project split): {auroc:.4f}")
    print("Reference: the old corpus scored 0.7109 here. This is a baseline")
    print("your 512-D model needs to clear, not a pass/fail gate — record")
    print("it as a permanent row in the results table either way.")

    # -----------------------------------------------------------------
    head("2. IS PROVENANCE A LABEL PROXY?")
    # Spread in label rate ACROSS GROUPS, not per-group majority-class
    # accuracy — the latter degenerates to the corpus's overall base rate
    # whenever a column has only one populated group (e.g. is_synthetic
    # before any synthetic rows exist), which then always looks "alarming"
    # on an imbalanced corpus regardless of whether the column carries any
    # real signal. Spread requires at least two groups to even compute, so
    # a single-category column can never trigger a false positive here.
    overall_rate = float(y.mean())
    for col in ("is_synthetic", "source_dataset"):
        if col not in df.columns:
            continue
        print(f"\nBy {col}:")
        ct = pd.crosstab(df[col], df.label, normalize="index")
        counts = df[col].value_counts()
        print(ct.to_string())

        valid_groups = [g for g in counts.index if counts[g] >= 50]
        if len(valid_groups) < 2:
            print(f"  Only {len(valid_groups)} group(s) with >= 50 rows — "
                  f"can't assess {col} as a proxy without at least two "
                  f"groups to compare against each other.")
            continue

        pos_col = 1 if 1 in ct.columns else ct.columns[-1]
        rates = ct.loc[valid_groups, pos_col]
        spread = float(rates.max() - rates.min())
        print(f"  Vulnerable rate by group: " +
              ", ".join(f"{g}={r:.2%}" for g, r in rates.items()))
        print(f"  Spread across groups: {spread:.2%} "
              f"(corpus overall: {overall_rate:.2%})")
        if spread > 0.15:
            ratio = rates.max() / max(rates.min(), 1e-9)
            print(f"  >>> {col} shows a real spread ({ratio:.1f}x between "
                  f"the highest and lowest group). Worth reporting "
                  f"source-stratified metrics in the paper. Check whether "
                  f"this reflects an understood sampling-methodology "
                  f"difference between sources (fine to state as such) or "
                  f"something that needs deeper investigation.")

    # -----------------------------------------------------------------
    head("3. CONTAMINATION (from step 05)")
    creport = outdir / "contamination_report.json"
    if creport.exists():
        rep = json.load(open(creport))
        rate = rep["n_flagged"] / max(rep["n_rows"], 1)
        print(f"Flagged rate: {rate:.2%} ({rep['n_flagged']:,} of "
              f"{rep['n_rows']:,})")
        if rate > 0.02:
            print("Above the 2% guideline — read contamination_flagged.csv "
                  "before release.")
    else:
        print("contamination_report.json not found — run "
              "05_contamination_screen.py before this script for a complete "
              "manifest.")
        rep = None

    # -----------------------------------------------------------------
    head("4. LINDDUN COVERAGE (from step 04)")
    lreport = outdir / "linddun_coverage_report.json"
    linddun_cov = None
    if lreport.exists():
        linddun_cov = json.load(open(lreport))
        # NOT every CWE is expected to map to LINDDUN — it's a PRIVACY threat
        # framework, and only the CWEs/categories the use/misuse document
        # identifies as privacy-relevant belong here. This number describes
        # what fraction of the corpus touches privacy at all; it is not a
        # completeness target, and a low figure is expected, not a defect.
        n_full = linddun_cov["n_rows_full_chain"]
        n_total = linddun_cov["n_rows"]
        print(f"Privacy-relevant (full CWE -> category -> LINDDUN chain): "
              f"{n_full:,} / {n_total:,} rows ({n_full/n_total:.1%})")
        print(f"  no CWE at all (e.g. safe rows)      : "
              f"{linddun_cov['n_rows_no_cwe']:,}")
        print(f"  CWE has no category entry           : "
              f"{linddun_cov['n_rows_hop1_gap']:,}")
        print(f"  category has no LINDDUN entry       : "
              f"{linddun_cov['n_categories_hop2_gap']} categories, "
              f"see unmapped_categories.csv for a spot-check")
    else:
        print("linddun_coverage_report.json not found.")

    # -----------------------------------------------------------------
    head("5. RELEASE MANIFEST")
    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "n_rows": int(len(df)),
        "n_vulnerable": int(y.sum()),
        "prevalence": float(y.mean()),
        "by_source": df.source_dataset.value_counts().to_dict(),
        "by_split_project": df.groupby("split_project").label.agg(
            ["size", "sum"]).to_dict("index"),
        "by_split_random": df.groupby("split_random").label.agg(
            ["size", "sum"]).to_dict("index"),
        "metadata_only_auroc_project_split": float(auroc),
        "contamination_rate": (rep["n_flagged"] / rep["n_rows"]
                               if rep else None),
        "linddun_coverage": (linddun_cov["n_rows_full_chain"] / linddun_cov["n_rows"]
                             if linddun_cov else None),
        "cwe_category_raw_source": str(config.CWE_CATEGORY_RAW_PATH),
        "cwe_category_to_linddun_source": str(config.CWE_CATEGORY_TO_LINDDUN_TABLE),
        "min_code_chars": config.MIN_CODE_CHARS,
        "near_dup_threshold": config.NEAR_DUP_THRESHOLD,
        "seed": config.SEED,
    }
    with open(outdir / "RELEASE_MANIFEST.json", "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    print(json.dumps(manifest, indent=2, default=str))
    print(f"\nWrote {outdir / 'RELEASE_MANIFEST.json'}")
    print("\nThis file is what the GitHub README's dataset-statistics table "
          "should be generated from — not retyped by hand, so it can never "
          "drift from what corpus_final.parquet actually contains.")


if __name__ == "__main__":
    main()
