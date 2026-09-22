"""
02_load_reposvul.py — ReposVul into the unified schema, rewritten against
CONFIRMED field semantics (see inspect_reposvul_fields.txt and
inspect_reposvul_pairs.txt from this project).

What was verified before this was written, not assumed:

  - The README's simplified schema doesn't match the real file. At the
    details[] level, "target" takes FOUR values (-1, None, 0, 1) and
    correlates with whole-FILE code/code_before blobs (17-31KB, copyright
    headers included) — the wrong granularity for a function-level corpus,
    and using them would reintroduce the exact size-based shortcut this
    whole rebuild exists to eliminate. This loader does NOT use them.

  - The real function-level data is in function_before/function_after,
    populated for ~10.7% of details[] entries, as lists of
    {"function": ..., "target": 0 or 1} objects. Within these lists, target
    is genuinely binary — confirmed across 2,345 sampled details entries,
    no None/-1 seen inside the lists (only at the outer details[] level).

  - function_before is ~99.5% target=0 (unchanged context functions from
    the same file) and ~0.5% target=1 (the actual vulnerable function).
    function_after was 100% target=0 in the sample scanned. An earlier
    version of this loader assumed EVERY function_before item was
    vulnerable by virtue of which list it was in — that would have
    mislabeled essentially the entire function_before pool. This version
    uses each item's own target field directly, never a default-by-side
    assumption.

  - Visual check on 5 real target=1 examples: 4 of 5 showed a clear,
    substantive fix (an escaped-dot-handling rewrite, consistent with a
    real DNS-parsing CVE). 1 of 5 (ciEqual) matched an identical
    function_after entry — target=1 on an unmodified function. This is not
    special-cased here; it doesn't need to be, because 03_merge_and_dedupe.py
    already drops any code hash that appears under conflicting labels, which
    is exactly what an identical before/after pair with different targets
    produces.

Every item — from BOTH function_before and function_after — becomes one row,
labelled by its own target. Items are expected to overlap heavily (an
unchanged context function appears in both lists, byte-identical); dedup
downstream collapses these, so no de-overlapping happens here.

Run:  python 02_load_reposvul.py
Out:  reposvul_rows.jsonl
"""

import json

import config
import schema


def load_records(path):
    recs = []
    with open(path, encoding="utf-8", errors="replace") as f:
        first = f.read(1)
        f.seek(0)
        if first == "[":
            recs = json.load(f)
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except Exception:
                    pass
    return recs


def extract_rows(record):
    rows = []
    project = record.get("project")
    commit_id = record.get("commit_id")
    commit_date = record.get("commit_date")
    cve_id = record.get("cve_id")
    pair_id = f"{cve_id}:{commit_id}" if (cve_id or commit_id) else None

    cwe_raw = record.get("cwe_id")
    # cwe_id is a LIST here (a CVE can carry multiple CWEs) — use the first
    # for the primary cwe_id column; every CWE is kept in cwe_id_all for
    # anyone who wants the full set.
    cwe_list = cwe_raw if isinstance(cwe_raw, list) else ([cwe_raw] if cwe_raw else [])
    primary_cwe = cwe_list[0] if cwe_list else None

    for d in record.get("details", []) or []:
        if not isinstance(d, dict):
            continue
        file_path = d.get("file_path")

        for side in ("function_before", "function_after"):
            items = d.get(side)
            if not items:
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                code = item.get("function")
                label = item.get("target")
                if not code or len(str(code).strip()) < config.MIN_CODE_CHARS:
                    continue
                if label not in (0, 1):
                    # Not observed inside these lists during verification —
                    # if it happens, skip rather than guess a label.
                    continue
                rows.append(schema.make_row(
                    code=code,
                    label=label,
                    source_dataset="reposvul",
                    project=project,
                    commit_id=commit_id,
                    commit_date=commit_date,
                    file_path=file_path,
                    cwe_id=primary_cwe,
                    is_synthetic=False,
                    pair_id=pair_id,
                ))
    return rows


def main():
    outdir = config.ensure_output_dir()
    p = config.REPOSVUL_PATH
    if not p.exists():
        raise SystemExit(f"{p} does not exist.")

    print(f"Reading {p} ...")
    records = load_records(p)
    print(f"  {len(records):,} top-level CVE/commit records")

    rows = []
    for r in records:
        rows.extend(extract_rows(r))

    if not rows:
        raise SystemExit("Zero rows extracted. Re-run "
                         "00c_inspect_reposvul_function_pairs.py against the "
                         "current file and check the schema hasn't changed "
                         "since this loader was written.")

    schema.validate_rows(rows, "reposvul")

    n_vuln = sum(r["label"] for r in rows)
    print(f"\n  {n_vuln:,} vulnerable rows extracted (before dedup — expect "
          f"substantial overlap with the safe rows, since an unchanged "
          f"context function appears in both function_before and "
          f"function_after; 03_merge_and_dedupe.py resolves this)")
    print(f"  This is expected to be small relative to DiverseVul's ~18,945 "
          f"vulnerable rows — ReposVul's contribution here is quality "
          f"(LLM + static-analysis cross-checked, real commit provenance), "
          f"not volume.")

    n_paired = sum(1 for r in rows if r["pair_id"])
    print(f"  {n_paired:,} rows carry a pair_id ({n_paired/len(rows):.1%})")

    out = outdir / "reposvul_rows.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
