"""
05_contamination_screen.py — the check that would have caught the old
corpus's problem before release, applied here to the whole v2 corpus
including your new synthetic contribution.

Uses the tightened patterns from config.py (verified in this project against
false positives: a bare "secret" or "is_bad" does not fire; Juliet/STONESOUP
identifiers, GPT-toy naming, and self-describing identifiers do).

This does NOT auto-drop flagged rows — it reports them, broken down by
source_dataset, so you decide. A hit in "reposvul" or "diversevul" (real
code) is far more concerning than a hit in "synthetic_v2", since real code
containing the literal string "secretPassword" might be a legitimate
credential-handling function, not leakage — read the flagged rows before
deciding.

Run:  python 05_contamination_screen.py
Out:  contamination_flagged.csv, contamination_report.json
"""

import json
from collections import defaultdict

import config


def main():
    outdir = config.ensure_output_dir()
    src = outdir / "merged_with_linddun.jsonl"
    if not src.exists():
        src = outdir / "merged_deduped.jsonl"
        print(f"merged_with_linddun.jsonl not found, using {src.name} "
             f"instead (run 04_apply_linddun.py first if you want LINDDUN "
             f"categories in the flagged-row report)")
    if not src.exists():
        raise SystemExit("Neither merged file exists — run 03 (and "
                         "optionally 04) first.")

    rows = [json.loads(l) for l in open(src, encoding="utf-8") if l.strip()]
    print(f"{len(rows):,} rows to screen")

    flagged = []
    for r in rows:
        hits = [name for name, rx in config.CONTAMINATION_PATTERNS.items()
               if rx.search(r["code"])]
        if hits:
            flagged.append((r, hits))

    print(f"\n{len(flagged):,} rows flagged ({len(flagged)/len(rows):.2%})")

    by_source = defaultdict(int)
    by_source_total = defaultdict(int)
    for r in rows:
        by_source_total[r["source_dataset"]] += 1
    for r, hits in flagged:
        by_source[r["source_dataset"]] += 1

    print("\nBy source:")
    for s in sorted(by_source_total):
        n = by_source.get(s, 0)
        tot = by_source_total[s]
        print(f"  {s:<14} {n:>6,} / {tot:>7,} flagged ({n/tot:.2%})")

    print("\nBy pattern:")
    pattern_counts = defaultdict(int)
    for r, hits in flagged:
        for h in hits:
            pattern_counts[h] += 1
    for p, n in sorted(pattern_counts.items(), key=lambda x: -x[1]):
        print(f"  {p:<20} {n:,}")

    import csv
    with open(outdir / "contamination_flagged.csv", "w", newline="",
             encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source_dataset", "cwe_id", "label", "patterns_matched",
                   "code_snippet"])
        for r, hits in flagged:
            w.writerow([r["source_dataset"], r.get("cwe_id"), r["label"],
                       ";".join(hits), r["code"][:300].replace("\n", " ")])
    print(f"\nWrote {outdir / 'contamination_flagged.csv'} — read this "
          f"before deciding what to drop, especially any real-source rows.")

    synth_rate = by_source.get("synthetic_v2", 0) / max(
        by_source_total.get("synthetic_v2", 1), 1)
    real_rate = (by_source.get("diversevul", 0) + by_source.get("reposvul", 0)) / max(
        by_source_total.get("diversevul", 0) + by_source_total.get("reposvul", 0), 1)

    print(f"\n{'='*68}")
    if synth_rate > 0.02:
        print(f"Synthetic contamination rate {synth_rate:.2%} is above the "
              f"2% guideline used earlier in this project. If your new "
              f"synthetic code was meant to avoid self-naming, check the "
              f"flagged rows — this is exactly the failure mode that broke "
              f"the old corpus.")
    else:
        print(f"Synthetic contamination rate {synth_rate:.2%} — the new "
              f"synthetic code looks clean on this screen.")
    if real_rate > 0.02:
        print(f"Real-source contamination rate {real_rate:.2%} is worth a "
              f"manual look — DiverseVul/ReposVul are real commits, so hits "
              f"here are more likely to be legitimate credential-handling "
              f"code than leakage, but check a sample.")

    report = {
        "n_rows": len(rows), "n_flagged": len(flagged),
        "by_source": dict(by_source), "by_source_total": dict(by_source_total),
        "by_pattern": dict(pattern_counts),
    }
    with open(outdir / "contamination_report.json", "w") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
