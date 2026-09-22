"""
13_apply_linddun_to_tier2.py - join tier 2's flawfinder hits through the
SAME CWE -> category -> LINDDUN chain tier 1 uses (03c's cwe_category_map.csv
and 03d's category_id_to_linddun.csv), so static-analysis findings get real
category and privacy labels instead of sitting as bare CWE numbers.

This is NOT the same operation as 04_apply_linddun.py, even though it reuses
the same two mapping tables - that script labels tier 1's per-FUNCTION rows
(one CWE per row, from a verified CVE). This one aggregates PER-FILE, since
flawfinder's output is one row per HIT and a single file can have many hits
across different CWEs - a file with a strcpy hit (CWE-120) and a system()
hit (CWE-78) should end up with BOTH categories/LINDDUN types attached, not
just one.

label_source is always "static_analysis" here, explicitly distinct from
tier 1's "cve_verified" - this is "contains a pattern flawfinder associates
with CWE-X", never "is vulnerable". Never pool these two label sources
together downstream.

KEYED BY row_uid, NOT source_id - matches the corrected
12_flawfinder_scan_tier2.py's output. The original source_id (copied
verbatim from upstream StarCoder's own "id" field) turned out to collide
across 85% of tier 2's rows; aggregating by it would have silently merged
two unrelated files' findings into one record whenever both independently
had hits. row_uid (row position, unique by construction) fixes this.

Run:  python 13_apply_linddun_to_tier2.py
Out:  starcoder_tier2_static_labels.csv - one row per FLAGGED FILE (row_uid),
      not per hit and not per corpus row - most of tier 2's 14.8M rows have
      no hits at all and correctly do not appear here.
"""

import csv
from collections import defaultdict

import config

SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


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


def load_excluded_cwes(path):
    """65 CWEs confirmed-or-presumed MITRE-discouraged/abstract (Class or
    Pillar level) - see excluded_abstract_cwes.csv's own reason/
    verification_status columns for which of these were individually
    checked against MITRE vs presumed from the pattern. Deliberately
    excluded from category/LINDDUN assignment: these describe "contains a
    pattern flawfinder associates with CWE-X" for an X that MITRE itself
    says should not be used to characterize a specific vulnerability -
    the real signal is expected to already flow through their more
    specific, already-mapped children. CWE-416 (Use After Free) was the
    one exception found in this investigation - a genuine, MITRE-allowed
    gap - and is handled separately by adding it to cwe_category_map.csv,
    not by exclusion."""
    excluded = set()
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            excluded.add(row["cwe_id"].strip().upper())
    return excluded


def main():
    outdir = config.ensure_output_dir()
    hits_csv = outdir / "starcoder_tier2_flawfinder.csv"
    map_path = outdir / "cwe_category_map.csv"
    ld_path = outdir / "category_id_to_linddun.csv"
    excluded_path = outdir / "excluded_abstract_cwes.csv"
    out_csv = outdir / "starcoder_tier2_static_labels.csv"

    if not hits_csv.exists():
        raise SystemExit(f"{hits_csv} not found - run "
                         f"12_flawfinder_scan_tier2.py first")
    if not map_path.exists():
        raise SystemExit(f"{map_path} not found - run "
                         f"03c_parse_cwe_categories.py first")
    if not ld_path.exists():
        raise SystemExit(f"{ld_path} not found - run "
                         f"03d_parse_usemisuse_table.py first")
    if not excluded_path.exists():
        raise SystemExit(f"{excluded_path} not found - copy it from the "
                         f"pipeline folder first")

    head("1. LOAD")
    cwe_to_catids, catid_to_name = load_cwe_category_map(map_path)
    catid_to_linddun = load_category_linddun_map(ld_path)
    excluded_cwes = load_excluded_cwes(excluded_path)
    print(f"Loaded {len(cwe_to_catids)} CWEs with a category")
    print(f"Loaded {len(catid_to_linddun)} category ids with a LINDDUN mapping")
    print(f"Loaded {len(excluded_cwes)} explicitly excluded (MITRE-discouraged/"
          f"abstract) CWEs - these never contribute to a category, even if "
          f"cwe_category_map.csv were to gain an entry for one later")

    with open(hits_csv, encoding="utf-8-sig", newline="") as f:
        hits = list(csv.DictReader(f))
    print(f"{len(hits):,} raw hit rows from flawfinder")

    # -----------------------------------------------------------------
    head("2. AGGREGATE PER FILE (row_uid), NOT PER HIT")
    # A file can have many hits across different CWEs - collect the full
    # set of CWEs/categories/LINDDUN types found across ALL of a file's
    # hits, rather than treating each hit independently.
    file_cwes = defaultdict(set)
    file_hit_counts = defaultdict(int)
    all_flagged_files = set()
    n_excluded_hits = 0
    for h in hits:
        # Every hit counts toward this file's total regardless of whether
        # it carries a CWE - a flawfinder finding with no CWE mapping is
        # still a real hit, just one that won't contribute a category.
        all_flagged_files.add(h["row_uid"])
        file_hit_counts[h["row_uid"]] += 1
        cwe = (h.get("cwe_id") or "").strip().upper()
        if not cwe:
            continue
        if cwe in excluded_cwes:
            # Deliberately excluded (MITRE-discouraged/abstract) - does NOT
            # go into file_cwes at all, so it can never contribute a
            # category/LINDDUN label, and never shows up in this file's
            # cwe_ids either. This is a labelling decision only - the
            # underlying hit stays in starcoder_tier2_flawfinder.csv
            # untouched, and no row is removed from the tier-2 corpus.
            n_excluded_hits += 1
            continue
        file_cwes[h["row_uid"]].add(cwe)

    print(f"{len(file_cwes):,} distinct files with at least one CWE-tagged, "
          f"non-excluded hit")
    print(f"{n_excluded_hits:,} raw hits carried only an explicitly excluded "
          f"CWE - not counted here, not deleted from the hits file either")

    # Files flawfinder flagged that have ZERO cwe-tagged, non-excluded hits
    # among them end up with nothing to categorize and are correctly absent
    # from this output - but that absence needs to be stated, not left
    # silent. A file with real hits going missing from the categorized
    # output for a legitimate reason is very different from it going
    # missing because of a bug, and only printing this makes that
    # distinguishable later. This now covers BOTH "no CWE at all" and
    # "only excluded CWEs" - both correctly end up with nothing to show.
    n_no_usable_cwe = len(all_flagged_files) - len(file_cwes)
    print(f"{n_no_usable_cwe:,} additional files were flagged by flawfinder "
          f"but had no CWE-tagged hit that wasn't excluded, so have nothing "
          f"to categorize - correctly absent from this output, not silently "
          f"dropped.")

    n_no_category = 0
    n_no_linddun = 0
    cats_missing_linddun = defaultdict(int)
    cwes_missing_category = defaultdict(int)

    rows_out = []
    for row_uid, cwes in file_cwes.items():
        all_cat_ids = set()
        for cwe in cwes:
            cat_ids = cwe_to_catids.get(cwe)
            if not cat_ids:
                cwes_missing_category[cwe] += 1
                continue
            all_cat_ids |= cat_ids

        all_linddun = set()
        for cid in all_cat_ids:
            ld = catid_to_linddun.get(cid)
            if not ld:
                cats_missing_linddun[cid] += 1
                continue
            all_linddun |= ld

        if not all_cat_ids:
            n_no_category += 1
        if all_cat_ids and not all_linddun:
            n_no_linddun += 1

        cat_names = {catid_to_name.get(c, c) for c in all_cat_ids}
        rows_out.append({
            "row_uid": row_uid,
            "cwe_ids": ";".join(sorted(cwes)),
            "category_ids": ";".join(sorted(all_cat_ids)),
            "category_names": ";".join(sorted(cat_names)),
            "linddun_categories": ";".join(sorted(all_linddun)),
            "linddun_primary": sorted(all_linddun)[0] if all_linddun else "",
            # Precomputed above in one pass over hits, not a full rescan
            # per file - the rescan approach is O(n_files x n_hits), which
            # would be painfully slow at real scale (potentially millions
            # of hit rows across a corpus this size).
            "n_hits": file_hit_counts[row_uid],
            "label_source": "static_analysis",
        })

    print(f"\nFiles with at least one CWE not in cwe_category_map.csv: "
          f"{n_no_category:,} of {len(file_cwes):,}")
    print(f"Files whose category(ies) have no LINDDUN entry: "
          f"{n_no_linddun:,} of {len(file_cwes):,}")

    if cwes_missing_category:
        print(f"\nTop CWEs with no category mapping (by file count):")
        for cwe, n in sorted(cwes_missing_category.items(),
                             key=lambda kv: -kv[1])[:10]:
            print(f"  {cwe:<12} {n:>6,} files")

    if cats_missing_linddun:
        print(f"\nTop categories with no LINDDUN mapping (by file count):")
        for cid, n in sorted(cats_missing_linddun.items(),
                             key=lambda kv: -kv[1])[:10]:
            print(f"  {cid:<10} {catid_to_name.get(cid,'?'):<38} {n:>6,} files")

    # -----------------------------------------------------------------
    head("3. WRITE")
    fieldnames = ["row_uid", "cwe_ids", "category_ids", "category_names",
                  "linddun_categories", "linddun_primary", "n_hits",
                  "label_source"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows_out:
            w.writerow(r)

    n_with_linddun = sum(1 for r in rows_out if r["linddun_categories"])
    print(f"Wrote {out_csv} ({len(rows_out):,} flagged files)")
    print(f"  of which {n_with_linddun:,} ({n_with_linddun/max(len(rows_out),1):.1%}) "
          f"have at least one LINDDUN category attached")
    print(f"\nlabel_source is always 'static_analysis' - this describes "
          f"'contains a pattern flawfinder associates with CWE-X', never "
          f"'is vulnerable'. Keep this fully separate from tier 1's "
          f"cve_verified labels in any downstream analysis or release.")


if __name__ == "__main__":
    main()
