"""
01c_load_synthetic.py — your new synthetic code into the unified schema.

Accepts EITHER layout under config.SYNTHETIC_DIR:

  (a) One file per function: vulnerable/CWE-120/sample_001.c,
      safe/sample_002.c — label taken from being under a "vulnerable"
      or "safe" top-level folder, CWE from the next path component if
      present under vulnerable/.

  (b) One JSON or JSONL file with records shaped like:
      {"code": "...", "label": 1, "cwe_id": "CWE-120",
       "generation_method": "gpt-4o-controlled-naming-v1"}
      generation_method is optional; defaults to "synthetic_v2_unspecified"
      if omitted, so every row is still traceable to a batch even if you
      forget to tag it, and you'll see that default in the coverage report
      below as a prompt to go back and tag it properly.

Whichever layout you use, EVERY row entering this pipeline is screened by
04_contamination_check.py before release — the point of a clean loader is
so the screen finds nothing, not so the screen can be skipped.

Run:  python 01c_load_synthetic.py
Out:  synthetic_rows.jsonl
"""

import json

import config
import schema


def load_from_files(root):
    rows = []
    for label_name, label in (("vulnerable", 1), ("safe", 0)):
        d = root / label_name
        if not d.exists():
            continue
        for f in d.rglob("*"):
            if not f.is_file() or f.suffix.lower() not in (".c", ".cpp", ".h", ".hpp", ".txt"):
                continue
            code = f.read_text(encoding="utf-8", errors="replace")
            if len(code.strip()) < config.MIN_CODE_CHARS:
                continue
            # CWE from the first path component under vulnerable/, if it
            # looks like one (e.g. vulnerable/CWE-120/sample_001.c)
            cwe = None
            rel = f.relative_to(d)
            if len(rel.parts) > 1:
                m = schema.CWE_RE.search(rel.parts[0])
                if m:
                    cwe = m.group(0)
            rows.append(schema.make_row(
                code=code, label=label, source_dataset="synthetic_v2",
                cwe_id=cwe, is_synthetic=True,
                generation_method="synthetic_v2_unspecified",
            ))
    return rows


def load_from_json(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        first = f.read(1)
        f.seek(0)
        if first == "[":
            recs = json.load(f)
        else:
            recs = [json.loads(l) for l in f if l.strip()]

    rows = []
    for r in recs:
        code = r.get("code", "")
        if len(str(code).strip()) < config.MIN_CODE_CHARS:
            continue
        rows.append(schema.make_row(
            code=code,
            label=r.get("label", 0),
            source_dataset="synthetic_v2",
            cwe_id=r.get("cwe_id"),
            is_synthetic=True,
            generation_method=r.get("generation_method",
                                    "synthetic_v2_unspecified"),
        ))
    return rows


def main():
    outdir = config.ensure_output_dir()
    root = config.SYNTHETIC_DIR
    if not root.exists():
        raise SystemExit(f"{root} does not exist. Set config.SYNTHETIC_DIR "
                         f"to wherever your synthetic code lives.")

    json_files = list(root.glob("*.json")) + list(root.glob("*.jsonl"))
    if json_files:
        print(f"Found {json_files[0].name}, loading as JSON/JSONL")
        rows = load_from_json(json_files[0])
    else:
        print(f"Loading as one-file-per-function under {root}")
        rows = load_from_files(root)

    if not rows:
        raise SystemExit("Zero rows loaded. Check config.SYNTHETIC_DIR "
                         "matches one of the two layouts documented at the "
                         "top of this file.")

    schema.validate_rows(rows, "synthetic_v2")

    untagged = sum(1 for r in rows
                  if r["generation_method"] == "synthetic_v2_unspecified")
    if untagged:
        print(f"\n  {untagged:,} rows have no explicit generation_method "
              f"tag. Fine to proceed, but tagging batches (e.g. by prompt "
              f"version) makes it possible to compare batches later if you "
              f"end up iterating on the generation approach.")

    out = outdir / "synthetic_rows.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
