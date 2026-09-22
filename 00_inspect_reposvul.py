"""
00_inspect_reposvul.py — run this FIRST, immediately after downloading.

The ReposVul README documents the record schema (project, commit_id,
cwe_id, details[] with function_before/function_after, etc.) but not the
exact file format the Google Drive download unpacks to. This finds out
before 02_load_reposvul.py tries to parse it.

Run:  python 00_inspect_reposvul.py > inspect_reposvul.txt 2>&1
"""

import json
import zipfile
from pathlib import Path

import config

SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def describe_record(rec, depth=0, max_depth=3):
    pad = "  " * depth
    if isinstance(rec, dict):
        print(f"{pad}dict, {len(rec)} keys: {list(rec.keys())}")
        if depth < max_depth:
            for k, v in list(rec.items())[:20]:
                print(f"{pad}  [{k}]:")
                describe_record(v, depth + 2, max_depth)
    elif isinstance(rec, list):
        print(f"{pad}list, {len(rec)} items")
        if rec and depth < max_depth:
            describe_record(rec[0], depth + 1, max_depth)
    else:
        s = str(rec)
        print(f"{pad}{type(rec).__name__}: {s[:200]}")


def main():
    p = config.REPOSVUL_PATH
    head("1. WHAT DID THE DOWNLOAD ACTUALLY PRODUCE?")

    if p.exists() and p.is_file():
        print(f"Single file: {p}  ({p.stat().st_size/1e6:.1f} MB)")
        candidates = [p]
    elif p.parent.exists():
        print(f"{p} not found directly. Listing {p.parent}:")
        candidates = sorted(p.parent.iterdir())
        for f in candidates:
            print(f"  {f.name}  ({f.stat().st_size/1e6:.1f} MB)"
                  if f.is_file() else f"  {f.name}/ (directory)")
    else:
        print(f"Neither {p} nor its parent directory exists. Fix "
              f"config.REPOSVUL_PATH to point at wherever the Google Drive "
              f"download landed, then rerun this script.")
        return

    # -----------------------------------------------------------------
    head("2. FORMAT DETECTION")
    target = None
    for f in candidates:
        if f.is_file() and f.suffix.lower() == ".zip":
            print(f"Found a zip: {f.name}. Contents:")
            with zipfile.ZipFile(f) as z:
                names = z.namelist()
                for n in names[:30]:
                    print(f"  {n}")
                if len(names) > 30:
                    print(f"  ... {len(names)-30} more")
                # Try to find a JSON/JSONL inside
                json_names = [n for n in names
                             if n.lower().endswith((".json", ".jsonl"))]
                if json_names:
                    print(f"\nExtracting first entry from {json_names[0]} "
                          f"inside the zip ...")
                    with z.open(json_names[0]) as inner:
                        first_line = inner.readline().decode("utf-8", "replace")
                        try:
                            rec = json.loads(first_line)
                            target = ("zip_member", f, json_names[0])
                        except json.JSONDecodeError:
                            # maybe it's a single big JSON array — read more
                            inner.seek(0)
                            txt = inner.read(2_000_000).decode("utf-8", "replace")
                            if txt.strip().startswith("["):
                                print("  Looks like a single JSON array inside "
                                      "the zip, not JSONL.")
                                target = ("zip_array", f, json_names[0])
            break
        if f.is_file() and f.suffix.lower() in (".json", ".jsonl"):
            target = ("file", f, None)
            break

    if target is None:
        print("\nNo zip or json/jsonl found among candidates. If the "
              "download is a folder of many small files (one per CVE), "
              "list a few filenames and their extensions here and tell me — "
              "the loader needs a different strategy for that layout.")
        return

    kind, fpath, member = target
    print(f"\nDetected: kind={kind}, file={fpath.name}"
          f"{', member=' + member if member else ''}")

    # -----------------------------------------------------------------
    head("3. FIRST RECORD, FULL STRUCTURE")
    if kind == "file":
        with open(fpath, encoding="utf-8", errors="replace") as f:
            first_char = f.read(1)
            f.seek(0)
            if first_char == "[":
                data = json.load(f)
                rec = data[0]
                print(f"Single JSON array, {len(data):,} top-level entries")
            else:
                line = f.readline()
                rec = json.loads(line)
                n = 1 + sum(1 for _ in f)
                print(f"JSONL, approximately {n:,} lines")
    elif kind in ("zip_member", "zip_array"):
        with zipfile.ZipFile(fpath) as z:
            with z.open(member) as inner:
                if kind == "zip_array":
                    data = json.load(inner)
                    rec = data[0]
                    print(f"JSON array inside zip, {len(data):,} entries")
                else:
                    line = inner.readline()
                    rec = json.loads(line)

    describe_record(rec)

    # -----------------------------------------------------------------
    head("4. WHERE ARE THE FUNCTION-LEVEL RECORDS?")
    print("The README schema nests function_before/function_after inside "
          "details[]. Checking whether that structure is actually here:")
    if isinstance(rec, dict) and "details" in rec:
        details = rec["details"]
        if isinstance(details, list) and details:
            d0 = details[0]
            print(f"\n  details[0] keys: "
                  f"{list(d0.keys()) if isinstance(d0, dict) else type(d0)}")
            for side in ("function_before", "function_after"):
                if isinstance(d0, dict) and side in d0:
                    fb = d0[side]
                    print(f"\n  {side}: {list(fb.keys()) if isinstance(fb, dict) else fb}")
        else:
            print("  'details' present but empty or not a list — inspect "
                  "manually.")
    else:
        print("  No top-level 'details' key found. The actual structure may "
              "differ from the README, or this is already a flattened, "
              "function-level format (in which case check for 'code'/'func' "
              "and 'target'/'label' directly at the top level, shown above "
              "in section 3).")

    print(f"\n{SEP}\nUpdate config.REPOSVUL_PATH and, if the structure above "
          f"differs from what 02_load_reposvul.py expects, tell me what "
          f"changed before running it.\n{SEP}")


if __name__ == "__main__":
    main()
