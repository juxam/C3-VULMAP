"""
03_merge_and_dedupe.py — combine all sources, deduplicate BEFORE any
filtering or splitting.

Reads whichever of diversevul_rows.jsonl / reposvul_rows.jsonl /
synthetic_rows.jsonl exist in the output directory — run only the loaders
you need first, this script adapts to what's present.

Dedup logic:
  1. Hash every row on normalised code (whitespace-collapsed).
  2. Where the SAME code has CONFLICTING labels across duplicates, drop all
     copies — that's label noise, not a decision this script should make
     silently.
  3. Where duplicates agree, keep exactly one, preferring (in order) a row
     with a pair_id, then a row with a project, then the first seen — so a
     ReposVul before/after pair isn't accidentally broken by deduping
     against an unpaired DiverseVul copy of near-identical code.
  4. pair_id is preserved through dedup: the split script uses it directly.

Run:  python 03_merge_and_dedupe.py
Out:  merged_deduped.jsonl, dedup_report.json
"""

import hashlib
import json
import re
from collections import defaultdict

import config

COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def norm_hash(code):
    c = re.sub(r"\s+", " ", str(code)).strip()
    return hashlib.sha256(c.encode("utf-8", "replace")).hexdigest()


def main():
    outdir = config.ensure_output_dir()
    rows = []
    sources_found = []
    for name in ("diversevul", "reposvul", "synthetic"):
        p = outdir / f"{name}_rows.jsonl"
        if p.exists():
            with open(p, encoding="utf-8") as f:
                batch = [json.loads(l) for l in f if l.strip()]
            rows.extend(batch)
            sources_found.append(name)
            print(f"  loaded {len(batch):,} rows from {p.name}")
        else:
            print(f"  {p.name} not found, skipping (run its loader first "
                 f"if this source should be included)")

    if not rows:
        raise SystemExit("No source files found. Run at least one loader "
                         "(01_load_diversevul.py / 02_load_reposvul.py / "
                         "01c_load_synthetic.py) before this script.")

    print(f"\n{len(rows):,} rows total from {sources_found}")

    for r in rows:
        r["_h"] = norm_hash(r["code"])

    groups = defaultdict(list)
    for r in rows:
        groups[r["_h"]].append(r)

    kept = []
    conflicting_dropped = 0
    duplicate_copies_dropped = 0

    for h, group in groups.items():
        labels = {g["label"] for g in group}
        if len(labels) > 1:
            conflicting_dropped += len(group)
            continue
        if len(group) == 1:
            kept.append(group[0])
            continue
        # agree on label, keep one — prefer pair_id, then project, then first
        duplicate_copies_dropped += len(group) - 1
        best = group[0]
        for g in group[1:]:
            if g.get("pair_id") and not best.get("pair_id"):
                best = g
            elif g.get("project") and not best.get("project") and not best.get("pair_id"):
                best = g
        kept.append(best)

    print(f"\nConflicting-label duplicates dropped: {conflicting_dropped:,} "
          f"rows ({len(groups)-len([1 for g in groups.values() if len({x['label'] for x in g})==1]):,} groups)")
    print(f"Redundant copies dropped (agreeing duplicates): "
          f"{duplicate_copies_dropped:,}")
    print(f"Remaining: {len(kept):,} rows")

    by_source = defaultdict(lambda: [0, 0])
    for r in kept:
        by_source[r["source_dataset"]][0] += 1
        by_source[r["source_dataset"]][1] += r["label"]
    print("\nBy source after dedup:")
    for s, (n, v) in sorted(by_source.items()):
        print(f"  {s:<14} {n:>8,} rows, {v:>7,} vulnerable ({v/max(n,1):.1%})")

    out = outdir / "merged_deduped.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for r in kept:
            r2 = {k: v for k, v in r.items() if k != "_h"}
            r2["code_hash"] = r["_h"]
            f.write(json.dumps(r2) + "\n")

    report = {
        "sources_found": sources_found,
        "n_before_dedup": len(rows),
        "n_after_dedup": len(kept),
        "conflicting_dropped": conflicting_dropped,
        "duplicate_copies_dropped": duplicate_copies_dropped,
        "by_source": {s: {"n": n, "n_vulnerable": v}
                     for s, (n, v) in by_source.items()},
    }
    with open(outdir / "dedup_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nWrote {out}")
    print(f"Wrote {outdir / 'dedup_report.json'}")


if __name__ == "__main__":
    main()
