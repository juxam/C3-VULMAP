"""
03b_validate_linddun_table.py — check your completed category -> LINDDUN
table BEFORE 04_apply_linddun.py trusts it.

Two independent risks, both checked here:

  1. Structure. This file was built independently of the seed template
     03c_parse_cwe_categories.py would have generated, so its column names
     are unknown until read. Rather than assume a fixed header contract
     (which has been wrong twice already this project — REPOSVUL_PATH and
     the raw category file both turned out different from what the README/
     assumption suggested), this AUTO-DETECTS which column holds LINDDUN
     values by finding the column whose values best match the 7 canonical
     LINDDUN categories, and treats the other populated column as the
     category name.

  2. Name agreement. The category names in THIS file were transcribed from
     the PDF by hand. The category names in cwe_category_map.csv were
     PARSED from the raw MITRE file by 03c_parse_cwe_categories.py. These
     are two independently-produced lists of the same ~40 names — if they
     don't match exactly (a stray space, different capitalisation, a
     slightly different phrasing than the PDF used), 04_apply_linddun.py's
     join silently finds nothing for that category, with no obvious cause.
     This cross-references both lists directly and reports exact matches,
     near-misses (same after lowercasing/whitespace-stripping — almost
     certainly a formatting difference, not a real mismatch), and complete
     misses on either side.

Run 03c_parse_cwe_categories.py first if cwe_category_map.csv doesn't exist
yet — the cross-reference in section 3 is skipped without it, though the
structure checks in sections 1-2 still run.

Run:  python 03b_validate_linddun_table.py > validate_linddun_table.txt 2>&1
"""

import csv
from collections import Counter

import config

SEP = "=" * 72

CANONICAL_LINDDUN = {
    "Linkability", "Identifiability", "Non-repudiation", "Detectability",
    "Data Disclosure", "Unawareness", "Non-compliance",
}
CANONICAL_NORM = {c.lower().strip(): c for c in CANONICAL_LINDDUN}


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def norm(s):
    return " ".join(str(s).lower().split())


def main():
    p = config.CWE_CATEGORY_TO_LINDDUN_TABLE
    if not p.exists():
        raise SystemExit(f"{p} does not exist. Check "
                         f"config.CWE_CATEGORY_TO_LINDDUN_TABLE points at "
                         f"the right file.")

    head("1. FILE, HEADERS, AND ALL ROWS")
    print(f"Reading {p}")
    with open(p, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        rows = list(reader)
    print(f"Headers found: {headers}")
    print(f"Rows: {len(rows):,}")
    if not rows:
        raise SystemExit("Header row present but zero data rows.")

    print(f"\nAll rows, exactly as read:")
    for i, r in enumerate(rows):
        print(f"  {i+1}: {dict(r)}")

    # -----------------------------------------------------------------
    head("2. AUTO-DETECT WHICH COLUMN IS THE LINDDUN CATEGORY")
    best_col, best_hits = None, -1
    hit_report = {}
    for col in (headers or []):
        vals = [norm(r.get(col, "")) for r in rows]
        # allow multi-value cells (e.g. "Linkability; Data Disclosure" or
        # "Linkability, Data Disclosure") to still count as a hit
        hits = sum(1 for v in vals
                  if any(part.strip() in CANONICAL_NORM
                        for part in v.replace(";", ",").split(",")))
        hit_report[col] = hits
        if hits > best_hits:
            best_col, best_hits = col, hits

    print("Canonical-LINDDUN-value hit count per column:")
    for col, hits in hit_report.items():
        print(f"  {col!r}: {hits} of {len(rows)} rows contain a recognisable "
              f"LINDDUN value")

    if best_hits == 0:
        print(f"\nNo column contains any recognisable LINDDUN value "
              f"(Linkability, Identifiability, Non-repudiation, "
              f"Detectability, Data Disclosure, Unawareness, "
              f"Non-compliance). Look at the raw rows in section 1 above and "
              f"tell me which column holds the LINDDUN assignment and "
              f"exactly how the values are spelled — auto-detection can't "
              f"proceed from here.")
        return

    linddun_col = best_col
    other_cols = [c for c in (headers or []) if c != linddun_col]
    # category-name column: whichever other column has the most non-empty,
    # high-cardinality values — with ~40 rows, category names should be
    # nearly all-distinct.
    cat_col = None
    if other_cols:
        cat_col = max(
            other_cols,
            key=lambda c: len({norm(r.get(c, "")) for r in rows if r.get(c)})
        )

    print(f"\nDetected LINDDUN column: {linddun_col!r} "
          f"({best_hits}/{len(rows)} rows matched)")
    print(f"Detected category-name column: {cat_col!r}")
    print(f"If either guess is wrong, say so directly — this is a guess "
          f"from content, not a certainty.")

    # -----------------------------------------------------------------
    head("3. LINDDUN VALUE FORMAT, USING THE DETECTED COLUMN")
    bad_values = []
    file_categories = []
    for i, r in enumerate(rows):
        raw = r.get(linddun_col, "")
        cat = (r.get(cat_col, "") if cat_col else "").strip()
        if cat:
            file_categories.append(cat)
        parts = [pp.strip() for pp in str(raw).replace(";", ",").split(",")
                if pp.strip()]
        if not parts:
            bad_values.append((i + 2, cat, "(blank)"))
            continue
        for part in parts:
            if norm(part) not in CANONICAL_NORM:
                bad_values.append((i + 2, cat, part))

    print(f"Rows with at least one unrecognised LINDDUN value: "
          f"{len(bad_values)}")
    for ln, cat, val in bad_values[:20]:
        print(f"  line {ln} ({cat!r}): {val!r}")

    # -----------------------------------------------------------------
    head("4. CROSS-REFERENCE AGAINST cwe_category_map.csv")
    map_path = config.OUTPUT_DIR / "cwe_category_map.csv"
    if not map_path.exists():
        print(f"{map_path} doesn't exist yet — run "
              f"03c_parse_cwe_categories.py first, then rerun this script "
              f"for the cross-reference. Structure checks above still stand "
              f"on their own.")
    else:
        with open(map_path, encoding="utf-8-sig", newline="") as f:
            parsed_categories = {row["category_name"].strip()
                                 for row in csv.DictReader(f)}
        file_cat_set = set(file_categories)
        file_norm_to_orig = {norm(c): c for c in file_cat_set}
        parsed_norm_to_orig = {norm(c): c for c in parsed_categories}

        exact = file_cat_set & parsed_categories
        near = {file_norm_to_orig[n] for n in
               (set(file_norm_to_orig) & set(parsed_norm_to_orig))} - exact
        only_in_file = file_cat_set - parsed_categories - near
        only_in_parsed = parsed_categories - file_cat_set - {
            parsed_norm_to_orig[n] for n in
            (set(file_norm_to_orig) & set(parsed_norm_to_orig))}

        print(f"Categories in your file      : {len(file_cat_set)}")
        print(f"Categories parsed from MITRE  : {len(parsed_categories)}")
        print(f"Exact matches                 : {len(exact)}")

        if near:
            print(f"\nNear-misses (match after case/whitespace normalising "
                  f"— almost certainly the SAME category, fix the spelling "
                  f"in one file to match the other exactly):")
            for c in sorted(near):
                print(f"  your file: {c!r}")
                print(f"  parsed   : {parsed_norm_to_orig[norm(c)]!r}")

        if only_in_file:
            print(f"\nIn your file but not found (even loosely) in the "
                  f"parsed MITRE categories — {len(only_in_file)}:")
            for c in sorted(only_in_file):
                print(f"  {c!r}")

        if only_in_parsed:
            print(f"\nParsed from MITRE but missing from your file — "
                  f"{len(only_in_parsed)} (these will show up in "
                  f"unmapped_categories.csv when you run "
                  f"04_apply_linddun.py):")
            for c in sorted(only_in_parsed):
                print(f"  {c!r}")

        if not near and not only_in_file and not only_in_parsed:
            print(f"\nEvery category name matches exactly. Safe to run "
                  f"04_apply_linddun.py.")
        elif near:
            print(f"\n{len(near)} near-miss(es) found — fix these before "
                  f"running 04_apply_linddun.py, since each one currently "
                  f"produces zero matches despite being the same category.")


if __name__ == "__main__":
    main()
