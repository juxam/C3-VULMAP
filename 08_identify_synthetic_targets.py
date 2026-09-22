"""
08_identify_synthetic_targets.py — data-driven target list for synthetic
generation, instead of guessing which CWEs to write examples for.

Your original methodology's stated purpose for the synthetic slice was
"addressing underrepresented privacy vulnerability categories" — so the
right target set is whichever LINDDUN-mapped categories are thin in the
REAL corpus (vulnerable row count low or zero), not an arbitrary CWE list.

This reads:
  - corpus_final.parquet          (real vulnerable rows, with cwe_id)
  - cwe_category_map.csv          (CWE -> category, hop 1)
  - category_id_to_linddun.csv    (category -> LINDDUN, hop 2)

and reports, per LINDDUN category, how many REAL vulnerable rows currently
support it. Categories at or near zero are the ones synthetic generation
should fill — adding synthetic examples to a category that's already well
represented doesn't serve the stated purpose and just dilutes the real
signal with generated text.

Run:  python 08_identify_synthetic_targets.py > synthetic_targets.txt 2>&1
Out:  synthetic_targets.csv
"""

import csv
from collections import defaultdict

import pandas as pd

import config

SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()

    head("1. LOAD")
    corpus_path = outdir / "corpus_final.parquet"
    if not corpus_path.exists():
        raise SystemExit(f"{corpus_path} not found — run 06_build_splits.py "
                         f"first (ideally rerun it after the 03c self-"
                         f"reference fix so this reflects the final corpus).")
    df = pd.read_parquet(corpus_path)
    print(f"{len(df):,} rows, {int(df.label.sum()):,} vulnerable")

    map_path = outdir / "cwe_category_map.csv"
    ld_path = outdir / "category_id_to_linddun.csv"
    if not map_path.exists() or not ld_path.exists():
        raise SystemExit("cwe_category_map.csv or category_id_to_linddun.csv "
                         "missing — run 03c and 03d first.")

    cwe_to_catids = defaultdict(set)
    with open(map_path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cwe_to_catids[row["cwe_id"].strip().upper()].add(
                row["category_cwe_id"].strip().upper())

    catid_to_linddun = defaultdict(set)
    catid_to_name = {}
    with open(ld_path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cid = row["category_cwe_id"].strip().upper()
            ld = (row.get("linddun_category") or "").strip()
            if ld:
                catid_to_linddun[cid].add(ld)

    with open(map_path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            catid_to_name[row["category_cwe_id"].strip().upper()] = \
                row["category_name"].strip()

    # -----------------------------------------------------------------
    head("2. REAL VULNERABLE ROWS PER LINDDUN CATEGORY")
    vuln = df[(df.label == 1) & df.cwe_id.notna()].copy()

    linddun_counts = defaultdict(int)
    linddun_cwe_examples = defaultdict(set)
    for cwe, n in vuln.cwe_id.value_counts().items():
        cwe_u = str(cwe).upper()
        for cat_id in cwe_to_catids.get(cwe_u, []):
            for ld in catid_to_linddun.get(cat_id, []):
                linddun_counts[ld] += n
                linddun_cwe_examples[ld].add(cwe_u)

    all_linddun = {"Linkability", "Identifiability", "Non-repudiation",
                   "Detectability", "Data Disclosure", "Unawareness",
                   "Non-compliance"}

    rows = []
    for ld in sorted(all_linddun):
        n = linddun_counts.get(ld, 0)
        examples = sorted(linddun_cwe_examples.get(ld, []))[:5]
        rows.append({"linddun_category": ld, "real_vulnerable_rows": n,
                     "example_cwes_present": ";".join(examples)})
        flag = "  <-- THIN, good synthetic target" if n < 200 else ""
        print(f"  {ld:<18} {n:>8,} real rows{flag}")
        if examples:
            print(f"    {'':18} present CWEs (sample): {examples}")

    # -----------------------------------------------------------------
    head("3. WHICH PRIVACY-RELEVANT CATEGORIES (hop 2) ARE THINNEST")
    cat_rows = []
    for cat_id, ld_set in catid_to_linddun.items():
        member_cwes = {c for c, cids in cwe_to_catids.items() if cat_id in cids}
        n = int(vuln.cwe_id.str.upper().isin(member_cwes).sum()) if len(vuln) else 0
        cat_rows.append({
            "category_cwe_id": cat_id,
            "category_name": catid_to_name.get(cat_id, "?"),
            "linddun": ";".join(sorted(ld_set)),
            "real_vulnerable_rows": n,
        })
    cat_df = pd.DataFrame(cat_rows).sort_values("real_vulnerable_rows")
    print(cat_df.to_string(index=False))

    # -----------------------------------------------------------------
    head("4. WRITE")
    out = outdir / "synthetic_targets.csv"
    pd.DataFrame(rows).to_csv(out, index=False)
    cat_df.to_csv(outdir / "synthetic_targets_by_category.csv", index=False)
    print(f"Wrote {out}")
    print(f"Wrote {outdir / 'synthetic_targets_by_category.csv'}")

    thin = [r for r in rows if r["real_vulnerable_rows"] < 200]
    if thin:
        print(f"\n{len(thin)} LINDDUN categories under 200 real rows — "
              f"strongest candidates for synthetic augmentation:")
        for r in thin:
            print(f"  {r['linddun_category']}")
    else:
        print("\nEvery LINDDUN category already has reasonable real "
              "representation. Synthetic generation may not add much here — "
              "worth reconsidering whether it's needed at all before "
              "spending effort writing examples.")


if __name__ == "__main__":
    main()
