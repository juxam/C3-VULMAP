"""
11_validate_starcoder_tier2.py - independent check on starcoder_tier2.parquet
against the actual output file, not just the run's console log. Same
instinct behind every validation step in this project: a multi-hour job
across 14.89M rows deserves verification before it goes into a public
release, not just trust in a printed summary.

Checks:
  1. Row count sanity - roughly 14,890,318 minus whatever was dropped as
     too-short. A count far outside that range means something went wrong
     partway through (a shard silently skipped, a resume that double-
     counted, etc).
  2. NO leftover prefix tags in `code` - the exact check already run
     against the test fixture, now applied to the real output at full
     scale via a vectorized string search rather than a row-by-row loop.
  3. Provenance columns (max_stars_repo_name/path) - null rate. These
     should be fully populated regardless of had_prefix, since they come
     from the source schema's own columns, not from parsing content.
  4. had_prefix rate - should land near 36.5%, the rate confirmed by
     09c's 3,000-row sample. A big deviation suggests the sample wasn't
     representative, or something changed between sampling and the full
     run.
  5. Length distribution - sanity check for anything wildly off (e.g. a
     stripping bug that ate real code, which would show up as an
     anomalous cluster of near-40-char rows).

Run:  python 11_validate_starcoder_tier2.py > validate_tier2.txt 2>&1
"""

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

import config

SEP = "=" * 72
EXPECTED_INPUT_ROWS = 14_890_318   # confirmed by 09b against the real data


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()
    path = outdir / "starcoder_tier2.parquet"
    if not path.exists():
        raise SystemExit(f"{path} not found.")

    head("1. ROW COUNT")
    pf = pq.ParquetFile(path)
    n = pf.metadata.num_rows
    print(f"Rows in starcoder_tier2.parquet: {n:,}")
    print(f"Rows in source StarCoder shards (confirmed by 09b): "
          f"{EXPECTED_INPUT_ROWS:,}")
    dropped = EXPECTED_INPUT_ROWS - n
    print(f"Implied dropped (too-short after cleaning): {dropped:,} "
          f"({dropped/EXPECTED_INPUT_ROWS:.2%})")
    if dropped < 0:
        print("  >>> MORE rows in output than input — something is wrong "
              "(duplicate shard processing during a resume?). Investigate "
              "before trusting this file.")
    elif dropped / EXPECTED_INPUT_ROWS > 0.10:
        print("  >>> Over 10% dropped — higher than expected from a simple "
              "length filter. Worth a look at what's actually being "
              "dropped before treating this as final.")
    else:
        print("  Consistent with a normal too-short filter rate.")

    # -----------------------------------------------------------------
    head("2. NO LEFTOVER PREFIX TAGS IN code (vectorized, full scale)")
    table = pq.read_table(path, columns=["code"])
    has_tag = pc.match_substring_regex(
        table.column("code"), r"<reponame>|<filename>|<gh_stars>")
    n_leftover = int(pc.sum(has_tag).as_py() or 0)
    print(f"Rows with a leftover tag in 'code': {n_leftover:,} "
          f"({n_leftover/max(n,1):.4%})")
    if n_leftover > 0:
        print("  >>> Should be exactly 0. The stripping regex missed a "
              "format somewhere at scale that the 3,000-row sample didn't "
              "surface. Do not release this file until resolved — pull a "
              "few of these rows and look at the actual pattern.")
    else:
        print("  Clean. No leftover tags found anywhere in the real output.")

    # -----------------------------------------------------------------
    head("3. PROVENANCE COLUMN COMPLETENESS")
    prov = pq.read_table(path, columns=["max_stars_repo_name",
                                        "max_stars_repo_path",
                                        "max_stars_count"])
    for col in prov.column_names:
        null_n = prov.column(col).null_count
        print(f"  {col:<24} {null_n:,} nulls ({null_n/max(n,1):.2%})")

    # -----------------------------------------------------------------
    head("4. had_prefix RATE vs THE 09c SAMPLE (36.5%)")
    hp = pq.read_table(path, columns=["had_prefix"]).column("had_prefix")
    true_n = int(pc.sum(hp).as_py() or 0)
    rate = true_n / max(n, 1)
    print(f"had_prefix=True: {true_n:,} / {n:,} ({rate:.1%})")
    print(f"09c's sampled estimate: 36.5%")
    if abs(rate - 0.365) > 0.05:
        print(f"  >>> More than 5 points off the sampled estimate. Not "
              f"necessarily wrong — 09c sampled 15 of 210 shards — but "
              f"worth noting the discrepancy rather than assuming the "
              f"sample generalized perfectly.")
    else:
        print("  Consistent with the sampled estimate.")

    # -----------------------------------------------------------------
    head("5. LENGTH DISTRIBUTION")
    lengths = pc.utf8_length(table.column("code"))
    lengths_np = lengths.to_numpy(zero_copy_only=False)
    import numpy as np
    print(f"  min    : {lengths_np.min():,}")
    print(f"  p25    : {np.percentile(lengths_np, 25):,.0f}")
    print(f"  median : {np.percentile(lengths_np, 50):,.0f}")
    print(f"  p75    : {np.percentile(lengths_np, 75):,.0f}")
    print(f"  max    : {lengths_np.max():,}")
    near_min = int((lengths_np < 60).sum())
    print(f"\n  Rows under 60 chars (just above the 40-char floor): "
          f"{near_min:,} ({near_min/n:.2%})")
    print("  A large spike right at the floor would suggest the stripping "
          "regex is sometimes eating real code, not just the tag block — "
          "worth a manual look at a sample of these specifically if this "
          "number looks high.")

    head("SUMMARY")
    print(f"{n:,} rows, {n_leftover:,} leftover-tag rows, "
          f"{rate:.1%} had a prefix stripped.")
    print("If sections 1-2 both came back clean, this file is safe to "
          "treat as final and to fill in CONSTRUCTION.md's tier-2 numbers "
          "from — replace the sampled 36.5%/63.5% figures there with this "
          "run's actual full-corpus rate once confirmed.")


if __name__ == "__main__":
    main()
