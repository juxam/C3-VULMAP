"""
10_load_starcoder_tier2.py - build tier 2 (bulk, unverified-for-vulnerability
provenance) from the local StarCoder C/C++ subset.

Confirmed by 09/09b/09c before this was written:
  - 14,890,318 rows across 210 Arrow shards (streaming format), ~104.55 GB
  - schema: content, max_stars_repo_name, max_stars_repo_path,
    max_stars_count (float64), id
  - "content" carries an OPTIONAL prefix block of up to three tags -
    <reponame>...<filename>...<gh_stars>N-M - present on ~36.5% of rows,
    absent on ~63.5% (a known BigCode technique: teaching the model both
    conditioned and unconditioned generation, not a processing defect).
    The strip regex below is tested against real examples of every
    combination seen, including a <reponame>+<gh_stars> case with no
    <filename> tag.

Tier 2 rows are NEVER pooled into the labelled safe class from
schema.py/03_merge_and_dedupe.py - they carry no vulnerability label at
all (StarCoder's absence of a reported CVE is not evidence of safety, and
treating it as such would reintroduce the exact provenance-as-label-
shortcut problem this whole rebuild exists to eliminate). This writes a
SEPARATE parquet, not merged into the tier-1 corpus pipeline.

Resumable: writes in chunks, skips shards already completed on a rerun.

Run:  python 10_load_starcoder_tier2.py
Out:  starcoder_tier2.parquet (in OUTPUT_DIR)
"""

import re
import time

import pyarrow as pa
import pyarrow.parquet as pq

import config

ROOT = config.DATASET / "StarCoder" / "C_CPP_Subset"
OUT = None  # set in main() once OUTPUT_DIR exists

PREFIX_RE = re.compile(
    r"^(?:<reponame>(?P<repo>.*?))?(?:<filename>(?P<path>.*?))?"
    r"(?:<gh_stars>(?P<stars>[^\n]*?))?\n",
    re.S,
)

MIN_CODE_CHARS = 40


def open_reader(mm):
    try:
        return pa.ipc.open_file(mm), "file"
    except pa.ArrowInvalid:
        mm.seek(0)
        return pa.ipc.open_stream(mm), "stream"


def clean_content(content):
    """Strip the optional reponame/filename/gh_stars prefix block if
    present; return (clean_code, had_prefix, tag_repo_name, tag_path,
    tag_stars). Tested against every real combination found in this
    project's own sampling — see the module docstring."""
    m = PREFIX_RE.match(content)
    if not m:
        return content, False, None, None, None
    return (content[m.end():], True,
            m.group("repo"), m.group("path"), m.group("stars"))


def main():
    global OUT
    outdir = config.ensure_output_dir()
    OUT = outdir / "starcoder_tier2.parquet"
    part_out = outdir / "starcoder_tier2.partial"

    files = sorted(ROOT.glob("*.arrow"))
    print(f"{len(files)} shards to process")

    done_shards = set()
    writer = None
    if part_out.exists():
        # Resume: find which shard-derived parquet part-files already exist.
        existing = sorted(part_out.glob("shard_*.parquet"))
        done_shards = {f.stem for f in existing}
        print(f"Resuming: {len(done_shards)} shard(s) already written")
    part_out.mkdir(exist_ok=True)

    t0 = time.time()
    total_rows = 0
    total_with_prefix = 0
    skipped_short = 0

    for i, f in enumerate(files):
        shard_key = f"shard_{i:04d}"
        out_part = part_out / f"{shard_key}.parquet"
        if shard_key in done_shards:
            continue

        rows = {"code": [], "had_prefix": [], "tag_repo_name": [],
               "tag_path": [], "tag_stars": [], "max_stars_repo_name": [],
               "max_stars_repo_path": [], "max_stars_count": [],
               "source_id": []}

        with pa.memory_map(str(f), "rb") as mm:
            reader, kind = open_reader(mm)
            batches = ((reader.get_batch(b) for b in range(reader.num_record_batches))
                      if kind == "file" else reader)
            for batch in batches:
                cols = {name: batch.column(name) for name in
                        ("content", "max_stars_repo_name",
                         "max_stars_repo_path", "max_stars_count", "id")}
                for j in range(batch.num_rows):
                    raw = cols["content"][j].as_py()
                    if not raw or len(raw) < MIN_CODE_CHARS:
                        skipped_short += 1
                        continue
                    code, had_prefix, repo, path, stars = clean_content(raw)
                    if len(code.strip()) < MIN_CODE_CHARS:
                        skipped_short += 1
                        continue
                    rows["code"].append(code)
                    rows["had_prefix"].append(had_prefix)
                    rows["tag_repo_name"].append(repo)
                    rows["tag_path"].append(path)
                    rows["tag_stars"].append(stars)
                    rows["max_stars_repo_name"].append(
                        cols["max_stars_repo_name"][j].as_py())
                    rows["max_stars_repo_path"].append(
                        cols["max_stars_repo_path"][j].as_py())
                    rows["max_stars_count"].append(
                        cols["max_stars_count"][j].as_py())
                    rows["source_id"].append(cols["id"][j].as_py())
                    total_with_prefix += int(had_prefix)

        table = pa.table(rows)
        pq.write_table(table, out_part)
        total_rows += len(rows["code"])

        if (i + 1) % 10 == 0 or i == len(files) - 1:
            el = time.time() - t0
            done_now = i + 1 - len(done_shards)
            rate = done_now / el if el > 0 else 0
            remaining = len(files) - (i + 1)
            eta = remaining / rate / 60 if rate > 0 else float("inf")
            print(f"  {i+1}/{len(files)} shards, {total_rows:,} rows kept, "
                  f"ETA {eta:.1f} min", flush=True)

    # -----------------------------------------------------------------
    print("\nConsolidating shard parts into one parquet ...")
    part_files = sorted(part_out.glob("shard_*.parquet"))
    tables = [pq.read_table(f) for f in part_files]
    full = pa.concat_tables(tables)
    pq.write_table(full, OUT)

    # Recompute from the FINAL consolidated table, not the in-memory
    # counters — those only reflect shards processed in THIS run, and would
    # under-report on a resumed run where most shards were already done.
    final_with_prefix = int(pa.compute.sum(full.column("had_prefix")).as_py() or 0)
    print(f"\nWrote {OUT} ({full.num_rows:,} rows)")
    print(f"Rows with a stripped prefix tag: {final_with_prefix:,} "
          f"({final_with_prefix/max(full.num_rows,1):.1%})")
    print(f"(This run processed {total_rows:,} new row(s); "
          f"skipped {skipped_short:,} as too short in this run.)")
    print(f"Total time: {(time.time()-t0)/60:.1f} min")
    print(f"\nThis is TIER 2 — no vulnerability label, kept in its own file,")
    print(f"never merged into schema.py's labelled corpus. It carries")
    print(f"project-level provenance (max_stars_repo_name/path) even though")
    print(f"it has no CVE/CWE information at all.")


if __name__ == "__main__":
    main()
