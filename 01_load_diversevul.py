"""
01_load_diversevul.py — DiverseVul into the unified schema.

Schema confirmed earlier in this project (real file, real keys):
    func, target, project, commit_id, cwe, hash, size, message

label = target directly. Every DiverseVul row is real code (is_synthetic is
always False here) since DiverseVul contains no generated examples.

Run:  python 01_load_diversevul.py
Out:  diversevul_rows.jsonl  (one unified-schema row per line)
"""

import json

import config
import schema


def load_diversevul(path):
    recs = []
    with open(path, encoding="utf-8", errors="replace") as f:
        first = f.read(1)
        f.seek(0)
        if first == "[":
            recs = json.load(f)
        else:
            for line in f:
                line = line.strip().rstrip(",")
                if not line or line in "[]":
                    continue
                try:
                    recs.append(json.loads(line))
                except Exception:
                    pass
    return recs


def main():
    outdir = config.ensure_output_dir()
    print(f"Reading {config.DIVERSEVUL_PATH} ...")
    recs = load_diversevul(config.DIVERSEVUL_PATH)
    print(f"  {len(recs):,} raw records")

    rows = []
    skipped = 0
    for r in recs:
        code = r.get("func", "")
        if not code or len(code.strip()) < config.MIN_CODE_CHARS:
            skipped += 1
            continue
        cwe_raw = r.get("cwe")
        # DiverseVul stores cwe as a list-like string, e.g. "['CWE-119']"
        cwe = None
        if cwe_raw:
            m = schema.CWE_RE.search(str(cwe_raw))
            if m:
                cwe = m.group(0)
        rows.append(schema.make_row(
            code=code,
            label=r.get("target", 0),
            source_dataset="diversevul",
            project=r.get("project"),
            commit_id=r.get("commit_id"),
            commit_date=None,   # not present in this source
            file_path=None,     # not present in this source
            cwe_id=cwe,
            is_synthetic=False,
        ))

    print(f"  {skipped:,} skipped (empty or under {config.MIN_CODE_CHARS} chars)")
    schema.validate_rows(rows, "diversevul")

    out = outdir / "diversevul_rows.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
