"""
09_inspect_starcoder.py — v2, against the REAL format.

The first version only looked for .parquet and fell through to dumping raw
JSON text when it found dataset_info.json instead. The real local copy is a
HuggingFace `datasets` save_to_disk() directory: many data-*.arrow shards
(104.55 GB total) plus dataset_info.json and (usually) state.json — the
standard format datasets.load_dataset(...).save_to_disk() produces.

This is actually convenient: dataset_info.json's "features" and "splits"
fields give the exact schema and exact row count directly, without opening
a single byte of the 104.55 GB of Arrow content. This script reads that
file properly, then opens exactly ONE Arrow shard (memory-mapped, cheap
regardless of shard size) to confirm the schema matches and show a real
sample row — dataset_info.json describes column TYPES, not actual values.

Run:  python 09_inspect_starcoder.py > inspect_starcoder.txt 2>&1
"""

import json

import config

ROOT = config.DATASET / "StarCoder" / "C_CPP_Subset"
SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    if not ROOT.exists():
        raise SystemExit(f"Not found: {ROOT}")

    head("1. WHAT'S IN THE FOLDER")
    files = sorted(ROOT.iterdir())
    by_ext = {}
    for f in files:
        by_ext.setdefault(f.suffix.lower(), []).append(f)
    for ext, fs in sorted(by_ext.items()):
        total = sum(f.stat().st_size for f in fs if f.is_file())
        print(f"  {ext or '(no ext)'}: {len(fs)} files, {total/1e9:.2f} GB")

    arrow_files = sorted(by_ext.get(".arrow", []))
    json_files = by_ext.get(".json", [])
    print(f"\nJSON files present: {[f.name for f in json_files]}")

    # -----------------------------------------------------------------
    head("2. dataset_info.json - SCHEMA AND EXACT ROW COUNT (no Arrow I/O)")
    info_path = ROOT / "dataset_info.json"
    info = None
    if info_path.exists():
        with open(info_path, encoding="utf-8", errors="replace") as f:
            info = json.load(f)

        print("Top-level keys:", sorted(info.keys()))

        features = info.get("features", {})
        print(f"\nFeatures ({len(features)} columns):")
        for name, spec in features.items():
            print(f"  {name:<32} {spec}")

        splits = info.get("splits", {})
        if splits:
            print(f"\nSplits (exact counts from HF metadata, no data read):")
            grand_total = 0
            for split_name, s in splits.items():
                n = s.get("num_examples")
                nb = s.get("num_bytes")
                print(f"  {split_name:<12} {n:,} examples"
                      f"{f', {nb/1e9:.2f} GB' if nb else ''}")
                if isinstance(n, int):
                    grand_total += n
            print(f"\n  TOTAL: {grand_total:,} rows")
        else:
            print("\nNo 'splits' key with example counts found.")

        for k in ("dataset_size", "download_size", "size_in_bytes",
                  "license", "homepage", "builder_name", "config_name"):
            if k in info:
                v = info[k]
                print(f"\n{k}: {str(v)[:200]}")
    else:
        print(f"{info_path} not found - checking arrow shards directly "
              f"instead.")

    # -----------------------------------------------------------------
    head("3. CONFIRM AGAINST ONE ARROW SHARD (schema + a real sample row)")
    if arrow_files:
        import pyarrow as pa
        sample = arrow_files[0]
        print(f"Opening {sample.name} ({sample.stat().st_size/1e9:.2f} GB) "
              f"memory-mapped ...")
        try:
            with pa.memory_map(str(sample), "rb") as mm:
                reader = pa.ipc.open_file(mm)
                print(f"  record batches in this shard: "
                      f"{reader.num_record_batches}")
                print(f"  schema:")
                for field in reader.schema:
                    print(f"    {field.name:<32} {field.type}")

                first_batch = reader.get_batch(0)
                print(f"  rows in first batch: {first_batch.num_rows:,}")
                row0 = first_batch.slice(0, 1).to_pylist()[0]
                print(f"\n  First row (truncated):")
                for k, v in row0.items():
                    print(f"    {k}: {str(v)[:150]}")

            cols = [f.name for f in reader.schema]
            provenance_cols = [c for c in cols if any(
                k in c.lower() for k in
                ("repo", "path", "stars", "url", "license", "hash",
                 "author", "lang"))]
            print(f"\n  Provenance-relevant columns: "
                  f"{provenance_cols if provenance_cols else 'NONE'}")
        except Exception as e:
            print(f"  Could not open as Arrow IPC file: "
                 f"{type(e).__name__}: {e}")
            print(f"  Trying pyarrow.ipc.open_stream instead (streaming "
                 f"format rather than random-access file format) ...")
            try:
                with pa.memory_map(str(sample), "rb") as mm:
                    reader = pa.ipc.open_stream(mm)
                    print(f"  schema:")
                    for field in reader.schema:
                        print(f"    {field.name:<32} {field.type}")
                    batch = next(reader)
                    print(f"  rows in first batch: {batch.num_rows:,}")
                    row0 = batch.slice(0, 1).to_pylist()[0]
                    for k, v in row0.items():
                        print(f"    {k}: {str(v)[:150]}")
            except Exception as e2:
                print(f"  Streaming format also failed: "
                     f"{type(e2).__name__}: {e2}")
                print(f"  If both fail, this may need the 'datasets' "
                     f"library itself (datasets.load_from_disk) rather than "
                     f"raw pyarrow - tell me and I'll write that version.")
    else:
        print("No .arrow files found to confirm against.")

    head("4. WHAT THIS MEANS FOR THE TIER-2 DESIGN")
    print("If dataset_info.json gave an exact row count above, that IS the")
    print("real scale question answered - no need to scan the 104.55 GB.")
    print()
    print("If provenance columns are present, tier 2 can carry project-")
    print("level identity even without a vulnerability label.")
    print()
    print("If the total is in the millions, extracting 512-D CodeT5")
    print("features for all of tier 2 is a much bigger job than the ~2.3")
    print("hours quoted for the 332,830-row supervised tier - decide code+")
    print("metadata-only vs full extraction once the real number is in.")


if __name__ == "__main__":
    main()
