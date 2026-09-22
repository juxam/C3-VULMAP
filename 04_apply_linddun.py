"""
04_apply_linddun.py - map every row's CWE to its LINDDUN privacy category,
via the two-hop chain:

    CWE -> category_cwe_id      (cwe_category_map.csv, from
                                 03c_parse_cwe_categories.py)
    category_cwe_id -> LINDDUN  (category_id_to_linddun.csv, from
                                 03d_parse_usemisuse_table.py)

Both hops join on the numeric MITRE category id (e.g. "CWE-1006"), not on
category NAME text - deliberately, after the name-based join proved fragile
(two independently-produced lists of the same ~40 names did not match
exactly). The category id is unambiguous on both sides.

IMPORTANT SCOPE NOTE: not every CWE, or even every one of the 40 MITRE
categories, is expected to have a LINDDUN mapping. LINDDUN is a PRIVACY
threat framework; only the CWEs/categories your use/misuse case document
identifies as privacy-relevant belong in category_id_to_linddun.csv. A row
with no LINDDUN category is not a mapping failure - it correctly reflects
that the underlying weakness has no privacy dimension per your source
document. "Coverage" below is a descriptive fact (how much of the corpus is
privacy-relevant), not a completeness target to chase toward 100%.

Run 03c then 03d first if their outputs do not exist yet. This script
reports, for transparency and spot-checking, which CWEs have no category
entry at all and which categories have no LINDDUN assignment, each ranked
by row impact - useful for confirming an absence was deliberate rather than
an accidental transcription omission, not for treating every absence as
something to fix.

A CWE can belong to more than one category (confirmed real - CWE-322 sits
under four), and a category can map to more than one LINDDUN type
(confirmed real - CWE-1006 spans six). Both are preserved as multi-valued;
linddun_primary is the first one alphabetically, purely for a single-label
view - document which you use for the paper's headline tables, since it is
a choice, not a fact.

Run:  python 04_apply_linddun.py
Out:  merged_with_linddun.jsonl, unmapped_cwes.csv, unmapped_categories.csv,
      linddun_coverage_report.json
"""

import csv
import json
from collections import Counter, defaultdict

import config


def load_excluded_cwes(path):
    """65 CWEs confirmed-or-presumed MITRE-discouraged/abstract (Class or
    Pillar level) - see excluded_abstract_cwes.csv's own verification_status
    column for which were individually checked against MITRE vs presumed
    from the pattern (7 of 8 top-impact gaps checked were confirmed
    discouraged). Deliberately excluded from category/LINDDUN assignment
    here, same as in 13_apply_linddun_to_tier2.py - these describe a CWE
    that MITRE itself says should not be used to characterize a specific
    vulnerability; the real signal is expected to already flow through
    their more specific, already-mapped children. CWE-416 (Use After Free)
    was the one exception found - a genuine, MITRE-allowed gap - and is
    handled by adding it to cwe_category_map.csv directly, not by
    exclusion, so it is correctly absent from this list."""
    excluded = set()
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            excluded.add(row["cwe_id"].strip().upper())
    return excluded


def load_cwe_category_map(path):
    cwe_to_catids = defaultdict(set)
    catid_to_name = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cwe = row["cwe_id"].strip().upper()
            cat_id = row["category_cwe_id"].strip().upper()
            cat_name = row["category_name"].strip()
            cwe_to_catids[cwe].add(cat_id)
            catid_to_name[cat_id] = cat_name
    return dict(cwe_to_catids), catid_to_name


def load_category_linddun_map(path):
    m = defaultdict(set)
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cat_id = row["category_cwe_id"].strip().upper()
            ld = (row.get("linddun_category") or "").strip()
            if ld:
                m[cat_id].add(ld)
    return dict(m)


def main():
    outdir = config.ensure_output_dir()
    merged_path = outdir / "merged_deduped.jsonl"
    if not merged_path.exists():
        raise SystemExit(f"{merged_path} not found - run "
                         f"03_merge_and_dedupe.py first")

    map_path = outdir / "cwe_category_map.csv"
    if not map_path.exists():
        raise SystemExit(f"{map_path} not found - run "
                         f"03c_parse_cwe_categories.py first (hop 1)")
    cwe_to_catids, catid_to_name = load_cwe_category_map(map_path)
    print(f"Loaded {len(cwe_to_catids)} CWEs with a category (hop 1)")

    ld_path = outdir / "category_id_to_linddun.csv"
    if not ld_path.exists():
        raise SystemExit(f"{ld_path} not found - run "
                         f"03d_parse_usemisuse_table.py first (hop 2)")
    catid_to_linddun = load_category_linddun_map(ld_path)
    n_filled = len(catid_to_linddun)
    print(f"Loaded {n_filled} category ids with a LINDDUN mapping (hop 2)")

    excluded_path = outdir / "excluded_abstract_cwes.csv"
    if not excluded_path.exists():
        raise SystemExit(f"{excluded_path} not found - copy it from the "
                         f"pipeline folder first")
    excluded_cwes = load_excluded_cwes(excluded_path)
    print(f"Loaded {len(excluded_cwes)} explicitly excluded (MITRE-"
          f"discouraged/abstract) CWEs - these never contribute a category, "
          f"even if cwe_category_map.csv were to gain an entry for one later")

    rows = []
    with open(merged_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    print(f"{len(rows):,} corpus rows to map")

    cwe_counts = Counter(r["cwe_id"] for r in rows if r.get("cwe_id"))

    present_cwes = set(cwe_counts.keys())
    all_uncategorized = present_cwes - set(cwe_to_catids.keys())
    # Split into genuine gaps (worth checking - might be an accidental
    # transcription omission) vs deliberately excluded (already a
    # documented decision, not something to re-flag every run).
    cwes_without_category = all_uncategorized - excluded_cwes
    cwes_deliberately_excluded_present = all_uncategorized & excluded_cwes
    n_rows_no_category = sum(cwe_counts[c] for c in cwes_without_category)
    n_rows_excluded_cwe = sum(cwe_counts[c] for c in cwes_deliberately_excluded_present)

    cats_without_linddun = Counter()
    for r in rows:
        cwe = r.get("cwe_id")
        if not cwe or cwe not in cwe_to_catids or cwe in excluded_cwes:
            continue
        for cat_id in cwe_to_catids[cwe]:
            if cat_id not in catid_to_linddun:
                cats_without_linddun[cat_id] += 1

    n_rows_no_cwe = sum(1 for r in rows if not r.get("cwe_id"))
    n_rows_full_chain = 0

    for r in rows:
        cwe = r.get("cwe_id")
        # Excluded CWEs never contribute a category, even if
        # cwe_category_map.csv happens to have an entry for one - checked
        # BEFORE the map lookup so this holds regardless of what the map
        # file says, now or after any future regeneration.
        if cwe and cwe not in excluded_cwes:
            cat_ids = cwe_to_catids.get(cwe, set())
        else:
            cat_ids = set()
        cat_names = {catid_to_name.get(c, c) for c in cat_ids}
        linddun = set()
        for cid in cat_ids:
            linddun |= catid_to_linddun.get(cid, set())
        r["cwe_category_ids"] = ";".join(sorted(cat_ids)) if cat_ids else None
        r["cwe_categories"] = ";".join(sorted(cat_names)) if cat_names else None
        r["linddun_categories"] = ";".join(sorted(linddun)) if linddun else None
        r["linddun_primary"] = sorted(linddun)[0] if linddun else None
        if linddun:
            n_rows_full_chain += 1

    print(f"\nCoverage (full chain: CWE -> category -> LINDDUN):")
    print(f"  rows with a complete chain           : {n_rows_full_chain:,} "
          f"({n_rows_full_chain/len(rows):.1%})")
    print(f"  rows with no CWE at all (e.g. safe)  : {n_rows_no_cwe:,} "
          f"({n_rows_no_cwe/len(rows):.1%})")
    print(f"  rows whose CWE has no category entry     : "
          f"{n_rows_no_category:,} ({n_rows_no_category/len(rows):.1%})")
    print(f"  rows whose CWE is explicitly excluded    : "
          f"{n_rows_excluded_cwe:,} ({n_rows_excluded_cwe/len(rows):.1%}) "
          f"- documented decision (MITRE-discouraged/abstract), not a gap")
    n_rows_cat_no_linddun = sum(cats_without_linddun.values())
    print(f"  rows whose category has no LINDDUN entry   : "
          f"~{n_rows_cat_no_linddun:,} (a row can be counted more than once "
          f"here if it belongs to multiple categories)")
    print(f"  Neither of the first two gap lines is necessarily a problem "
          f"— see the scope note at the top of this file. These CSVs are "
          f"for spot-checking that an absence was intentional, not a "
          f"to-do list.")

    out = outdir / "merged_with_linddun.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"\nWrote {out}")

    unmapped_cwes_ranked = sorted(cwes_without_category,
                                  key=lambda c: -cwe_counts[c])
    with open(outdir / "unmapped_cwes.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cwe_id", "n_rows_affected"])
        for c in unmapped_cwes_ranked:
            w.writerow([c, cwe_counts[c]])
    print(f"Wrote unmapped_cwes.csv ({len(unmapped_cwes_ranked)} CWEs with "
          f"no entry in cwe_category_map.csv - genuine gaps only, "
          f"deliberately excluded CWEs are not included here)")

    if cwes_deliberately_excluded_present:
        excluded_ranked = sorted(cwes_deliberately_excluded_present,
                                 key=lambda c: -cwe_counts[c])
        print(f"\n{len(excluded_ranked)} of the 65 explicitly excluded "
              f"CWEs actually appear in tier 1's data ({n_rows_excluded_cwe:,} "
              f"rows total), by row impact:")
        for c in excluded_ranked[:10]:
            print(f"  {c:<12} {cwe_counts[c]:>6,} rows")

    unmapped_cats_ranked = sorted(cats_without_linddun.items(),
                                  key=lambda kv: -kv[1])
    with open(outdir / "unmapped_categories.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["category_cwe_id", "category_name", "n_rows_affected"])
        for cid, n in unmapped_cats_ranked:
            w.writerow([cid, catid_to_name.get(cid, "?"), n])
    print(f"Wrote unmapped_categories.csv ({len(unmapped_cats_ranked)} "
          f"categories present in cwe_category_map.csv with no "
          f"LINDDUN entry in category_id_to_linddun.csv)")

    if unmapped_cats_ranked:
        print(f"\nCategories with no LINDDUN entry, by row impact — worth a "
              f"quick check against the use/misuse document that these were "
              f"deliberately out of scope, not a transcription slip:")
        for cid, n in unmapped_cats_ranked[:10]:
            print(f"  {cid:<10} {catid_to_name.get(cid, '?'):<38} "
                  f"{n:>6,} rows")

    report = {
        "n_rows": len(rows),
        "n_rows_full_chain": n_rows_full_chain,
        "n_rows_no_cwe": n_rows_no_cwe,
        "n_rows_hop1_gap": n_rows_no_category,
        "n_rows_excluded_cwe": n_rows_excluded_cwe,
        "n_cwes_excluded_present": len(cwes_deliberately_excluded_present),
        "n_categories_hop2_filled": n_filled,
        "n_categories_hop2_gap": len(unmapped_cats_ranked),
    }
    with open(outdir / "linddun_coverage_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nFull-chain coverage reflects how much of the corpus is "
          f"privacy-relevant per your use/misuse document — not a "
          f"completeness target. A low number is expected if most CWEs in "
          f"this corpus fall outside LINDDUN's scope.")


if __name__ == "__main__":
    main()
