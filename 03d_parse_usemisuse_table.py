"""
03d_parse_usemisuse_table.py — parse the REAL use/misuse case table you
provided into category_cwe_id -> LINDDUN pairs.

Structure confirmed from the real file (not what 03b/04 assumed before this):

  - 'Privacy Threat Types' is FORWARD-FILLED. A LINDDUN value on one row
    applies to that row AND every following blank row until the next
    non-blank value appears — the standard artifact of a merged-cell PDF
    table transcribed to CSV. Confirmed directly: your file has 22 rows but
    only 6 non-blank 'Privacy Threat Types' cells, each starting a new
    section that covers the rows below it.

  - 'CWE CATEGORY' holds NUMERIC MITRE category ids, comma-separated
    (e.g. "1210, 1211, 1212, 137, 265, 355") — NOT category names. That
    number is exactly category_cwe_id, already captured as its own column
    in cwe_category_map.csv (03c's output), so this joins on NUMBER, never
    on name-matching text that's prone to spelling drift.

  - Some rows have a blank 'CWE CATEGORY' — the misuse case has no formal
    CWE link. Skipped, not an error (6 of 22 rows in your file).

  - One label variant found: 'Detecting' (row 12) where the canonical
    LINDDUN term is 'Detectability'. Normalised here, but printed
    explicitly — confirm this is what was intended rather than trusting it
    silently.

Run:  python 03d_parse_usemisuse_table.py > parse_usemisuse.txt 2>&1
Out:  category_id_to_linddun.csv  (category_cwe_id -> linddun_category,
      in OUTPUT_DIR — this is what 04_apply_linddun.py's hop 2 now reads)
"""

import csv
from collections import defaultdict

import config

SEP = "=" * 72

CANONICAL_LINDDUN = {
    "Linkability", "Identifiability", "Non-repudiation", "Detectability",
    "Data Disclosure", "Unawareness", "Non-compliance",
}
CANONICAL_LOWER = {c.lower(): c for c in CANONICAL_LINDDUN}

# Known variant spellings -> canonical. Extend this if more turn up.
LABEL_NORMALISE = {
    "detecting": "Detectability",
}


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()
    p = config.CWE_CATEGORY_TO_LINDDUN_TABLE
    if not p.exists():
        raise SystemExit(f"{p} does not exist.")

    head("1. READ AND FORWARD-FILL")
    with open(p, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"{len(rows)} rows read")

    current = None
    normalised_log = []
    unrecognised_log = []
    filled_rows = []

    for i, r in enumerate(rows):
        raw = (r.get("Privacy Threat Types") or "").strip()
        if raw:
            key = raw.lower()
            if key in CANONICAL_LOWER:
                current = CANONICAL_LOWER[key]
            elif key in LABEL_NORMALISE:
                current = LABEL_NORMALISE[key]
                normalised_log.append((i + 2, raw, current))
            else:
                current = raw
                unrecognised_log.append((i + 2, raw))
        filled_rows.append((i + 2, current, r))

    print(f"Distinct LINDDUN sections found: "
          f"{len({c for _, c, _ in filled_rows if c})}")
    if normalised_log:
        print(f"\nLabel variants normalised (confirm these are correct):")
        for ln, raw, fixed in normalised_log:
            print(f"  line {ln}: {raw!r} -> {fixed!r}")
    if unrecognised_log:
        print(f"\nLabels NOT recognised as canonical or a known variant "
              f"(used as-is — check these):")
        for ln, raw in unrecognised_log:
            print(f"  line {ln}: {raw!r}")

    # -----------------------------------------------------------------
    head("2. PARSE CWE CATEGORY NUMBERS PER ROW")
    pairs = []          # (category_cwe_id, linddun)
    blank_cwe = 0
    bad_tokens = []
    row_summaries = []

    for ln, linddun, r in filled_rows:
        raw_cats = (r.get("CWE CATEGORY") or "").strip()
        if not raw_cats:
            blank_cwe += 1
            row_summaries.append((ln, linddun, []))
            continue
        ids = []
        for tok in raw_cats.split(","):
            tok = tok.strip().strip('"').strip("'").strip()
            if not tok:
                continue
            if not tok.isdigit():
                bad_tokens.append((ln, tok))
                continue
            cat_id = f"CWE-{tok}"
            ids.append(cat_id)
            pairs.append((cat_id, linddun))
        row_summaries.append((ln, linddun, ids))

    print(f"Rows with a blank CWE CATEGORY (no formal link, skipped): "
          f"{blank_cwe}")
    if bad_tokens:
        print(f"\nTokens that didn't parse as a plain number:")
        for ln, tok in bad_tokens:
            print(f"  line {ln}: {tok!r}")

    print(f"\nPer-row summary:")
    for ln, linddun, ids in row_summaries:
        print(f"  line {ln:>3} [{linddun or '?':<16}] "
              f"{len(ids)} category id(s): {ids}")

    # -----------------------------------------------------------------
    head("3. AGGREGATE INTO category_cwe_id -> {LINDDUN...}")
    agg = defaultdict(set)
    for cat_id, linddun in pairs:
        agg[cat_id].add(linddun)

    print(f"Distinct category ids referenced: {len(agg)}")
    multi = {k: v for k, v in agg.items() if len(v) > 1}
    print(f"Category ids mapped to more than one LINDDUN type: {len(multi)}")
    for cid, lds in sorted(multi.items()):
        print(f"  {cid}: {sorted(lds)}")

    # -----------------------------------------------------------------
    head("4. CROSS-CHECK AGAINST cwe_category_map.csv (BY NUMBER)")
    map_path = config.OUTPUT_DIR / "cwe_category_map.csv"
    if not map_path.exists():
        print(f"{map_path} not found — run 03c_parse_cwe_categories.py "
              f"first for this check. The output below still gets written.")
        known_ids = None
    else:
        with open(map_path, encoding="utf-8-sig", newline="") as f:
            known = {(row["category_cwe_id"], row["category_name"])
                    for row in csv.DictReader(f)}
        known_ids = {cid for cid, _ in known}
        id_to_name = dict(known)

        referenced = set(agg.keys())
        matched = referenced & known_ids
        unmatched = referenced - known_ids
        untouched = known_ids - referenced

        print(f"Category ids referenced in your file : {len(referenced)}")
        print(f"Category ids known from 03c (of 40)   : {len(known_ids)}")
        print(f"Matched by number                     : {len(matched)}")
        print(f"Coverage of the 40 categories          : "
              f"{len(matched)/max(len(known_ids),1):.1%}")

        if unmatched:
            print(f"\nReferenced here but NOT a known category id from 03c "
                  f"— {len(unmatched)} (typo in the number, or a reference "
                  f"to an individual CWE rather than a category id):")
            for cid in sorted(unmatched):
                print(f"  {cid}")

        if untouched:
            print(f"\nKnown categories with NO LINDDUN assignment in this "
                  f"file — {len(untouched)}:")
            for cid in sorted(untouched):
                print(f"  {cid}  ({id_to_name.get(cid, '?')})")

    # -----------------------------------------------------------------
    head("5. WRITE")
    out = config.ensure_output_dir() / "category_id_to_linddun.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category_cwe_id", "linddun_category"])
        for cid in sorted(agg):
            for ld in sorted(agg[cid]):
                w.writerow([cid, ld])
    n_written = sum(len(v) for v in agg.values())
    print(f"Wrote {out} ({n_written} rows)")
    print(f"\nThis replaces the name-keyed hop-2 table 04_apply_linddun.py "
          f"was reading — it now needs to join on category_cwe_id instead "
          f"of category_name.")


if __name__ == "__main__":
    main()
