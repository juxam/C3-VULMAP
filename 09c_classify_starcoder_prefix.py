"""
09c_classify_starcoder_prefix.py - proper prefix-format classification.

09b's single-pattern test (must match "<reponame>...<filename>...") only
matched 4.6% of 500 rows - not "no pattern found", but a WRONG assumption.
The two visible misses both started with "<filename>PATH\n" directly, no
<reponame> at all - suggesting <filename> is the reliable anchor and
<reponame> is only sometimes present before it, not the other way round.

This classifies every sampled row into one of four buckets instead of a
single yes/no test:
  both       <reponame>X<filename>Y\n...
  filename_only  <filename>Y\n...          (no reponame tag)
  reponame_only  <reponame>X\n...          (no filename tag - unlikely but
                                            checked rather than assumed away)
  neither    no recognisable tag at all

The total row count (14,890,318, confirmed by 09b) does NOT need
re-verifying - this only re-examines the prefix format, sampling a modest
number of shards rather than scanning all 210 again, so it should finish in
well under a minute.

Also fixes 09b's crash: Windows' console encoding (cp1252) can't print some
non-ASCII bytes that turn up in real code comments. Every snippet printed
here goes through a safe-encode step first so this can't happen again.

Run:  python 09c_classify_starcoder_prefix.py > classify_prefix.txt 2>&1
"""

import re

import pyarrow as pa

import config

ROOT = config.DATASET / "StarCoder" / "C_CPP_Subset"
SEP = "=" * 72
N_SHARDS_TO_SAMPLE = 15
N_ROWS_PER_SHARD = 200

RE_BOTH = re.compile(r"^<reponame>.*?<filename>.*?\n", re.S)
RE_FILENAME_ONLY = re.compile(r"^<filename>.*?\n", re.S)
RE_REPONAME_ONLY = re.compile(r"^<reponame>.*?\n", re.S)


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def safe(s, n=200):
    """Never let a print() crash on console encoding again - fall back to
    escaping anything the terminal can't represent rather than raising."""
    s = str(s)[:n]
    try:
        s.encode("cp1252")
        return s
    except UnicodeEncodeError:
        return s.encode("ascii", errors="backslashreplace").decode("ascii")


def classify(content):
    if RE_BOTH.match(content):
        return "both"
    if RE_FILENAME_ONLY.match(content):
        return "filename_only"
    if RE_REPONAME_ONLY.match(content):
        return "reponame_only"
    return "neither"


def open_reader(mm):
    try:
        return pa.ipc.open_file(mm), "file"
    except pa.ArrowInvalid:
        mm.seek(0)
        return pa.ipc.open_stream(mm), "stream"


def main():
    files = sorted(ROOT.glob("*.arrow"))
    import random
    random.seed(42)
    sample_files = random.sample(files, min(N_SHARDS_TO_SAMPLE, len(files)))

    head(f"SAMPLING {len(sample_files)} SHARDS, UP TO {N_ROWS_PER_SHARD} "
         f"ROWS EACH")

    counts = {"both": 0, "filename_only": 0, "reponame_only": 0, "neither": 0}
    examples = {k: [] for k in counts}
    total_checked = 0

    for f in sample_files:
        with pa.memory_map(str(f), "rb") as mm:
            reader, kind = open_reader(mm)
            n_seen = 0
            batches = (reader.get_batch(b) for b in range(reader.num_record_batches)) \
                if kind == "file" else reader
            for batch in batches:
                col = batch.column("content")
                for i in range(min(batch.num_rows, N_ROWS_PER_SHARD - n_seen)):
                    c = col[i].as_py()
                    cls = classify(c)
                    counts[cls] += 1
                    total_checked += 1
                    if len(examples[cls]) < 3:
                        examples[cls].append((f.name, safe(c, 160)))
                    n_seen += 1
                if n_seen >= N_ROWS_PER_SHARD:
                    break

    head("RESULTS")
    print(f"{total_checked:,} rows checked across {len(sample_files)} shards\n")
    for cls, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        pct = n / max(total_checked, 1)
        print(f"  {cls:<16} {n:>6,}  ({pct:.1%})")

    for cls in ("both", "filename_only", "reponame_only", "neither"):
        if examples[cls]:
            print(f"\n{cls} examples:")
            for fname, snippet in examples[cls]:
                print(f"  {fname}: {snippet!r}")

    head("RECOMMENDATION")
    dominant = max(counts, key=counts.get)
    print(f"Dominant pattern: {dominant} "
          f"({counts[dominant]/max(total_checked,1):.1%})")
    if dominant == "filename_only":
        print("Strip '<filename>...\\n' as the primary rule. Handle 'both' "
              "rows the same way (the filename-strip regex should already "
              "consume a leading <reponame> block too, since RE_BOTH is a "
              "superset pattern) - but keep max_stars_repo_name as the "
              "authoritative repo field either way, since it's already a "
              "clean separate column and doesn't depend on parsing the text.")
    print(f"\n'neither' rate ({counts['neither']/max(total_checked,1):.1%}) "
          f"is what would be missed by any single stripping rule - these "
          f"rows likely already ARE clean content, or use a third format "
          f"not covered above and worth a manual look if the rate is high.")


if __name__ == "__main__":
    main()
