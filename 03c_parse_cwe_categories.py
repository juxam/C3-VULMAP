"""
03c_parse_cwe_categories.py — parse the raw MITRE CWE category file into a
flat, usable CWE -> category map, and generate the fill-in template for the
category -> LINDDUN table.

The file at config.CWE_CATEGORY_RAW_PATH has 3 columns (CWE CATEGORY, CWE,
DESCRIPTION), one row per official CWE category. The CATEGORY column packs a
CWE id + name for the category itself ("1006-Bad Coding Practices"). The CWE
column packs every MEMBER cwe as a newline-delimited list, each line shaped
"NNN-Title" (e.g. "242-Use of Inherently Dangerous Function").

This unpacks that into one row per (member CWE, category) pair. A CWE
legitimately appearing under more than one category is expected and kept —
confirmed in the real file (CWE-322 appears under both Authentication Errors
and Communication Channel Errors, per MITRE's own taxonomy) — same
multi-mapping handling 04_apply_linddun.py already has for the direct case.

Run:  python 03c_parse_cwe_categories.py > parse_cwe_categories.txt 2>&1
Out:  cwe_category_map.csv                 (in OUTPUT_DIR — CWE -> category)
      cwe_category_to_linddun.csv          (in the script folder, IF it
                                            doesn't already exist — the ~40
                                            category names, empty LINDDUN
                                            column for you to fill from the
                                            PDF. Never overwrites an existing
                                            file, so it's safe to rerun this
                                            after the raw file changes.)
"""

import csv
import re
from collections import Counter, defaultdict

import config

SEP = "=" * 72
# "1006-Bad Coding Practices" or "1211- Authentication Errors" (real file has
# an inconsistent space after the hyphen on at least one row) — tolerate both.
CATEGORY_HEADER_RE = re.compile(r"^\s*(\d+)\s*-\s*(.+?)\s*$")
MEMBER_LINE_RE = re.compile(r"^\s*(\d+)\s*-\s*(.+?)\s*$")

TOTAL_CWE_TARGET = 776


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()
    p = config.CWE_CATEGORY_RAW_PATH
    if not p.exists():
        raise SystemExit(f"{p} does not exist.")

    head("1. PARSE")
    with open(p, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    print(f"{len(rows):,} category rows read")

    flat = []          # (cwe_id, category_cwe_id, category_name)
    categories = []     # ordered list of distinct category names, for the seed
    seen_categories = set()
    bad_category_headers = []
    bad_member_lines = []

    for i, r in enumerate(rows):
        cat_raw = (r.get("CWE CATEGORY") or "").strip()
        m = CATEGORY_HEADER_RE.match(cat_raw)
        if not m:
            bad_category_headers.append((i + 2, cat_raw))
            continue
        category_cwe_id = f"CWE-{m.group(1)}"
        category_name = m.group(2).strip()
        if category_name not in seen_categories:
            seen_categories.add(category_name)
            categories.append(category_name)

        # A category belongs to itself. Real corpora tag some functions with
        # the bare category-level CWE number directly rather than one of its
        # listed child members — confirmed by CWE-399 ("Resource Management
        # Errors") and CWE-417 ("Communication Channel Errors") both showing
        # up as "unmapped" against a real corpus despite being known
        # categories, costing 7,380 and 125 rows respectively before this
        # fix. Without this line, a category only ever matched when used as
        # someone else's child, never when used as itself.
        flat.append((category_cwe_id, category_cwe_id, category_name))

        members_raw = r.get("CWE") or ""
        for line in members_raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            mm = MEMBER_LINE_RE.match(line)
            if not mm:
                bad_member_lines.append((i + 2, category_name, line))
                continue
            cwe_id = f"CWE-{mm.group(1)}"
            flat.append((cwe_id, category_cwe_id, category_name))

    print(f"Distinct categories parsed: {len(categories)}")
    print(f"Individual (CWE, category) pairs extracted: {len(flat):,}")
    distinct_cwes = {c for c, _, _ in flat}
    print(f"Distinct member CWEs: {len(distinct_cwes):,}")
    print(f"Canonical target for this project: {TOTAL_CWE_TARGET:,}")
    print(f"Coverage: {len(distinct_cwes)/TOTAL_CWE_TARGET:.1%}")

    if bad_category_headers:
        print(f"\n{len(bad_category_headers)} category header(s) didn't "
              f"parse as 'NUMBER-Name':")
        for ln, val in bad_category_headers[:10]:
            print(f"  line {ln}: {val!r}")
    if bad_member_lines:
        print(f"\n{len(bad_member_lines)} member line(s) didn't parse as "
              f"'NUMBER-Title':")
        for ln, cat, val in bad_member_lines[:10]:
            print(f"  line {ln} ({cat}): {val!r}")

    # -----------------------------------------------------------------
    head("2. MULTI-CATEGORY CWEs (expected — MITRE allows this)")
    cwe_to_cats = defaultdict(set)
    for cwe, _, cat in flat:
        cwe_to_cats[cwe].add(cat)
    multi = {k: v for k, v in cwe_to_cats.items() if len(v) > 1}
    print(f"CWEs belonging to more than one category: {len(multi)}")
    for cwe, cats in list(multi.items())[:10]:
        print(f"  {cwe}: {sorted(cats)}")

    # -----------------------------------------------------------------
    head("3. WRITE FLAT MAP")
    out_map = outdir / "cwe_category_map.csv"
    with open(out_map, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cwe_id", "category_cwe_id", "category_name"])
        for row in flat:
            w.writerow(row)
    print(f"Wrote {out_map} ({len(flat):,} rows)")

    # -----------------------------------------------------------------
    head("4. CATEGORY -> LINDDUN SEED TEMPLATE")
    seed_path = config.CWE_CATEGORY_TO_LINDDUN_TABLE
    if seed_path.exists():
        print(f"{seed_path} already exists — NOT overwritten (in case "
              f"you've already started filling it in). Delete it first if "
              f"you want a fresh template regenerated.")
        with open(seed_path, encoding="utf-8-sig", newline="") as f:
            existing = list(csv.DictReader(f))
        filled = sum(1 for r in existing
                    if (r.get("linddun_category") or "").strip())
        print(f"Current state: {filled} of {len(existing)} rows have a "
              f"linddun_category filled in.")
    else:
        with open(seed_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["category_name", "linddun_category", "source"])
            for cat in categories:
                w.writerow([cat, "", ""])
        print(f"Wrote {seed_path} ({len(categories)} rows, "
              f"linddun_category column empty)")
        print(f"\nFill in linddun_category for each row using \"UseMisuse "
              f"Cases vs CWE Category.pdf\" — the 7 canonical LINDDUN values "
              f"are: Linkability, Identifiability, Non-repudiation, "
              f"Detectability, Data Disclosure, Unawareness, Non-compliance.")
        print(f"A category can map to more than one LINDDUN type — add an "
              f"extra row with the same category_name and a different "
              f"linddun_category, same pattern as the CWE-200 example that "
              f"maps to both Linkability and Data Disclosure.")
        print(f"\nOnce filled in, run 03b_validate_linddun_table.py against "
              f"it before 04_apply_linddun.py.")


if __name__ == "__main__":
    main()
