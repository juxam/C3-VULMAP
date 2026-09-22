"""Quick, standalone check: does source_id in starcoder_tier2.parquet
actually uniquely identify one row? Run this directly - no dependency on
the rest of the pipeline."""
import pyarrow.parquet as pq
from collections import Counter

path = r"C:\Users\judea\Downloads\Dataset\c3vulmap_v2_build\starcoder_tier2.parquet"
pf = pq.ParquetFile(path)
total = pf.metadata.num_rows
print(f"{total:,} total rows")

counts = Counter()
for batch in pf.iter_batches(batch_size=500_000, columns=["source_id"]):
    counts.update(batch.column("source_id").to_pylist())

n_distinct = len(counts)
n_duplicated_ids = sum(1 for c in counts.values() if c > 1)
n_extra_rows = sum(c - 1 for c in counts.values() if c > 1)

print(f"{n_distinct:,} distinct source_id values")
print(f"{n_duplicated_ids:,} source_id values appear more than once")
print(f"{n_extra_rows:,} 'extra' rows beyond one-per-id "
      f"(this should be close to 167,270 if this is the explanation)")

if n_duplicated_ids:
    print("\nA few examples of repeated source_id values:")
    shown = 0
    for sid, c in counts.items():
        if c > 1:
            print(f"  {sid!r}: appears {c} times")
            shown += 1
            if shown >= 5:
                break
