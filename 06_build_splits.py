"""
06_build_splits.py — project-level and random splits, with two constraints
neither of the earlier corpora enforced together:

  1. No project spans train/val/test (as before).
  2. No pair_id spans partitions. A ReposVul function_before/function_after
     pair differs by a few lines — splitting the two sides across train and
     test would leak the fix directly across the boundary. Rows sharing a
     pair_id are treated as ONE unit for allocation purposes and always land
     in the same partition together.

Allocation balances on total row count AND vulnerable count per unit (a
"unit" being either an unpaired row or a whole pair), same corpus-relative-
deficit method verified against a dominant-project fixture earlier in this
project (which produced 70/8.6/21.4% — the naive version failed at 50/11/39%
on the same fixture).

Synthetic rows have no project, so they're allocated by pair-equivalent
units directly (no project grouping needed — allocated individually,
balanced the same way).

Run:  python 06_build_splits.py
Out:  corpus_final.parquet, split_manifest.json
"""

import json
from collections import defaultdict

import numpy as np

import config


def main():
    outdir = config.ensure_output_dir()
    src = outdir / "merged_with_linddun.jsonl"
    if not src.exists():
        raise SystemExit(f"{src} not found — run 04_apply_linddun.py first "
                         f"(or at minimum 03_merge_and_dedupe.py, then point "
                         f"this script at merged_deduped.jsonl instead)")

    rows = [json.loads(l) for l in open(src, encoding="utf-8") if l.strip()]
    print(f"{len(rows):,} rows")

    # -----------------------------------------------------------------
    # Build allocation units: a pair_id group, or a single unpaired row.
    # Real rows with a project but no pair_id are grouped by PROJECT instead,
    # same as the earlier DiverseVul-only rebuild — this is what prevents a
    # repo's train and test copies of similar code from ending up split.
    # -----------------------------------------------------------------
    paired = defaultdict(list)
    by_project = defaultdict(list)
    unpaired_no_project = []

    for i, r in enumerate(rows):
        if r.get("pair_id"):
            paired[r["pair_id"]].append(i)
        elif r.get("project"):
            by_project[r["project"]].append(i)
        else:
            unpaired_no_project.append(i)

    units = []
    for pid, idxs in paired.items():
        units.append(("pair:" + pid, idxs))
    for proj, idxs in by_project.items():
        units.append(("project:" + proj, idxs))
    for i in unpaired_no_project:
        units.append((f"row:{i}", [i]))

    print(f"\nAllocation units: {len(units):,} "
          f"({len(paired):,} pairs, {len(by_project):,} projects, "
          f"{len(unpaired_no_project):,} standalone rows)")

    def unit_stats(idxs):
        n = len(idxs)
        v = sum(rows[i]["label"] for i in idxs)
        return n, v

    tot_n = len(rows)
    tot_v = sum(r["label"] for r in rows)

    # Two-phase allocation. The leakage-critical boundary is TEST — that is
    # the partition whose metrics get reported, so it alone gets the strict
    # pair/project-aware treatment. VAL only affects early stopping /
    # threshold selection, never a reported number, so it is carved from
    # whatever remains using plain stratified sampling on the label — this
    # sidesteps a real failure mode found while testing this allocator: with
    # only TWO targets (test vs the rest) instead of three, the smallest
    # partition is no longer the one most exposed to unit-size granularity,
    # and a three-way greedy split was observed to blow a 10%-target
    # partition out to 50% prevalence and 4x its target size when unit
    # vulnerable-density was bimodal (ReposVul pairs ~50% vulnerable by
    # construction vs DiverseVul projects in the single digits).
    targets = {"trainval": 1.0 - config.TEST_FRAC, "test": config.TEST_FRAC}
    have = {k: {"n": 0, "v": 0} for k in targets}

    rng = np.random.default_rng(config.SEED)
    order = rng.permutation(len(units))
    sizes = [unit_stats(units[i][1])[0] for i in order]
    order = order[np.argsort(-np.array(sizes))]

    assignment = {}
    for oi in order:
        name, idxs = units[oi]
        n, v = unit_stats(idxs)
        best, best_score = None, None
        for k, frac in targets.items():
            dv = (frac * tot_v - have[k]["v"]) / max(tot_v, 1)
            dn = (frac * tot_n - have[k]["n"]) / max(tot_n, 1)
            score = 0.4 * dv + 0.6 * dn
            if best_score is None or score > best_score:
                best, best_score = k, score
        assignment[name] = best
        have[best]["n"] += n
        have[best]["v"] += v

    part2 = [None] * len(rows)   # "trainval" or "test"
    for name, idxs in units:
        part = assignment[name]
        for i in idxs:
            part2[i] = part

    print("\nPhase 1 — test vs trainval (pair/project-aware):")
    for k in ("trainval", "test"):
        n, v = have[k]["n"], have[k]["v"]
        print(f"  {k:<8} {n:>8,} rows ({n/tot_n:.1%})  {v:>6,} vulnerable "
              f"({v/max(n,1):.2%})")

    # Phase 2 — carve val out of trainval by plain stratified sampling.
    trainval_idx = np.array([i for i in range(len(rows)) if part2[i] == "trainval"])
    y_tv = np.array([rows[i]["label"] for i in trainval_idx])
    val_frac_of_trainval = config.VAL_FRAC / (1.0 - config.TEST_FRAC)
    from sklearn.model_selection import train_test_split as _tts
    tr_sub, val_sub = _tts(trainval_idx, test_size=val_frac_of_trainval,
                           random_state=config.SEED, stratify=y_tv)

    split_project = [None] * len(rows)
    for i in tr_sub:
        split_project[i] = "train"
    for i in val_sub:
        split_project[i] = "val"
    for i in range(len(rows)):
        if part2[i] == "test":
            split_project[i] = "test"

    have3 = {k: {"n": 0, "v": 0} for k in ("train", "val", "test")}
    for i, r in enumerate(rows):
        have3[split_project[i]]["n"] += 1
        have3[split_project[i]]["v"] += r["label"]
    have = have3

    print("\nFinal project-level split (pair/project-aware for test; "
          "stratified for the train/val boundary):")
    for k in ("train", "val", "test"):
        n, v = have[k]["n"], have[k]["v"]
        print(f"  {k:<6} {n:>8,} rows ({n/tot_n:.1%})  {v:>6,} vulnerable "
              f"({v/max(n,1):.2%})")

    # Verify no pair or project actually spans partitions
    # The guarantee that matters is TEST isolation: no pair or project may
    # have any row in test while another row of the same pair/project sits
    # in train or val. A pair split between train and val is fine by design
    # (phase 2 above) — that boundary only affects early stopping.
    def side(p):
        return "test" if p == "test" else "nontest"

    pair_parts = defaultdict(set)
    proj_parts = defaultdict(set)
    for i, r in enumerate(rows):
        if r.get("pair_id"):
            pair_parts[r["pair_id"]].add(side(split_project[i]))
        elif r.get("project"):
            proj_parts[r["project"]].add(side(split_project[i]))
    bad_pairs = [p for p, s in pair_parts.items() if len(s) > 1]
    bad_projects = [p for p, s in proj_parts.items() if len(s) > 1]
    print(f"\n  pairs spanning test/non-test   : {len(bad_pairs)} (must be 0)")
    print(f"  projects spanning test/non-test: {len(bad_projects)} (must be 0)")
    if bad_pairs or bad_projects:
        raise SystemExit("Integrity check failed — a pair or project has "
                         "rows in both test and train/val. This is a bug; "
                         "do not proceed to feature extraction with this "
                         "output.")

    overall_prev = tot_v / tot_n
    test_prev = have["test"]["v"] / max(have["test"]["n"], 1)
    if abs(test_prev - overall_prev) > 0.03:
        print(f"\n  Test prevalence ({test_prev:.2%}) differs from the "
              f"corpus average ({overall_prev:.2%}) by more than 3 points. "
              f"This happens when the corpus mixes sources with very "
              f"different inherent vulnerable density (e.g. ReposVul pairs "
              f"at ~50% by construction vs DiverseVul in the single digits) "
              f"and the split has to keep every pair/project intact within "
              f"test — the same trade-off already reported for the earlier "
              f"DiverseVul-only corpus (6.0% train vs 4.5% test). Report "
              f"per-partition prevalence in the paper's dataset table rather "
              f"than assuming train and test match.")

    # -----------------------------------------------------------------
    # Random split, for comparability — no pair/project constraint, plain
    # stratified split. Report the gap between the two as the
    # generalisation result, same framing as the DiverseVul-only rebuild.
    # -----------------------------------------------------------------
    from sklearn.model_selection import train_test_split
    idx = np.arange(len(rows))
    y = np.array([r["label"] for r in rows])
    tr, te = train_test_split(idx, test_size=config.TEST_FRAC,
                              random_state=config.SEED, stratify=y)
    split_random = np.array(["train"] * len(rows), dtype=object)
    split_random[te] = "test"

    print("\nRandom split (no pair/project constraint):")
    for k in ("train", "test"):
        m = split_random == k
        print(f"  {k:<6} {m.sum():>8,} rows  {y[m].sum():>6,} vulnerable "
              f"({y[m].mean():.2%})")

    # -----------------------------------------------------------------
    for i, r in enumerate(rows):
        r["split_project"] = split_project[i]
        r["split_random"] = split_random[i]

    import pandas as pd
    df = pd.DataFrame(rows)
    out = outdir / "corpus_final.parquet"
    df.to_parquet(out, index=False)
    print(f"\nWrote {out} ({len(df):,} rows, {len(df.columns)} columns)")

    manifest = {
        "n_rows": len(rows),
        "n_vulnerable": int(tot_v),
        "n_units": len(units),
        "n_pairs": len(paired),
        "n_projects": len(by_project),
        "split_project": {k: have[k] for k in have},
        "split_random": {k: {"n": int((split_random == k).sum()),
                             "v": int(y[split_random == k].sum())}
                        for k in ("train", "test")},
        "seed": config.SEED,
    }
    with open(outdir / "split_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote {outdir / 'split_manifest.json'}")


if __name__ == "__main__":
    main()
