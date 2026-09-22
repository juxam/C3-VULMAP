"""
09b_count_starcoder_rows.py - dataset_info.json didn't have a row count this
time (no 'splits' key), and the first batch of the first shard (1,000 rows)
is not the shard's total, let alone the corpus total - a streaming Arrow
file can hold many batches per shard. This gets the real number by counting
batch sizes across every shard, WITHOUT converting rows to Python objects
(streaming row counts off Arrow batch metadata is far cheaper than
deserializing string content), so this reads sequentially but never holds
more than one batch in memory at a time.

Also confirms, on a sample spread across shards rather than just row 0,
whether the "<reponame>...<filename>...\n<actual content>" prefix pattern
found in the first row is universal - needed before writing a stripping
regex that might otherwise miss a variant format.

This reads all 104.55 GB sequentially (I/O bound, not CPU bound) - expect
real wall-clock time, plausibly 10-30+ minutes depending on disk speed, not
the near-instant metadata-only checks from before.

Run:  python 09b_count_starcoder_rows.py > count_starcoder.txt 2>&1
"""

import re
import time

import pyarrow as pa

import config

ROOT = config.DATASET / "StarCoder" / "C_CPP_Subset"
SEP = "=" * 72

PREFIX_RE = re.compile(r"^<reponame>(.*?)<filename>(.*?)\n", re.S)


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def open_reader(path, mm):
    """Try the random-access file format first, fall back to streaming -
    same detection already confirmed necessary against the real files."""
    try:
        return pa.ipc.open_file(mm), "file"
    except pa.ArrowInvalid:
        mm.seek(0)
        return pa.ipc.open_stream(mm), "stream"


def main():
    files = sorted(ROOT.glob("*.arrow"))
    print(f"{len(files)} shards, "
          f"{sum(f.stat().st_size for f in files)/1e9:.2f} GB total")

    head("1. COUNT ROWS - STREAMING, NO PYTHON CONVERSION")
    t0 = time.time()
    total_rows = 0
    shard_counts = []
    prefix_matches = 0
    prefix_checked = 0
    prefix_misses = []

    for i, f in enumerate(files):
        with pa.memory_map(str(f), "rb") as mm:
            reader, kind = open_reader(f, mm)
            shard_rows = 0
            if kind == "file":
                for b in range(reader.num_record_batches):
                    batch = reader.get_batch(b)
                    shard_rows += batch.num_rows
                    if prefix_checked < 500 and batch.num_rows > 0:
                        c = batch.column("content")[0].as_py()
                        prefix_checked += 1
                        if PREFIX_RE.match(c):
                            prefix_matches += 1
                        elif len(prefix_misses) < 5:
                            prefix_misses.append((f.name, c[:150]))
            else:
                for batch in reader:
                    shard_rows += batch.num_rows
                    if prefix_checked < 500 and batch.num_rows > 0:
                        c = batch.column("content")[0].as_py()
                        prefix_checked += 1
                        if PREFIX_RE.match(c):
                            prefix_matches += 1
                        elif len(prefix_misses) < 5:
                            prefix_misses.append((f.name, c[:150]))

        shard_counts.append(shard_rows)
        total_rows += shard_rows
        if (i + 1) % 20 == 0 or i == len(files) - 1:
            el = time.time() - t0
            rate = (i + 1) / el if el > 0 else 0
            eta = (len(files) - i - 1) / rate / 60 if rate > 0 else float("inf")
            print(f"  {i+1}/{len(files)} shards, {total_rows:,} rows so far, "
                  f"ETA {eta:.1f} min", flush=True)

    print(f"\nTOTAL ROWS: {total_rows:,}")
    print(f"Mean rows/shard: {total_rows/len(files):,.0f}")
    print(f"Min/max shard row count: {min(shard_counts):,} / "
          f"{max(shard_counts):,}")
    print(f"Elapsed: {(time.time()-t0)/60:.1f} min")

    head("2. CONTENT PREFIX PATTERN")
    print(f"Checked {prefix_checked} rows spread across shards")
    print(f"Matched '<reponame>...<filename>...' pattern: "
          f"{prefix_matches} ({prefix_matches/max(prefix_checked,1):.1%})")
    if prefix_misses:
        print(f"\nRows that did NOT match (first {len(prefix_misses)}):")
        for fname, snippet in prefix_misses:
            print(f"  {fname}: {snippet!r}")
        print("\nIf misses are rare, the stripping regex can just pass "
              "through anything that doesn't match rather than erroring.")
    else:
        print("\nNo misses in the sample - the prefix format looks "
              "universal, safe to strip unconditionally.")

    head("3. WHAT THIS MEANS")
    print(f"Real total: {total_rows:,} rows across {len(files)} shards.")
    print("Extraction-time estimate at 40.7 fn/s (if extracting all of it):")
    print(f"  {total_rows/40.7/3600:.1f} hours")
    print("\nThis is FILE-level content (confirmed: apu_want.h is a whole")
    print("header, not a function), and each row needs the reponame/")
    print("filename prefix stripped before the 'content' field is usable")
    print("as code. Both matter for deciding tier 2's scope before writing")
    print("a loader - full extraction at this scale vs. code+metadata only,")
    print("and file-level vs. function-extracted granularity.")


if __name__ == "__main__":
    main()
