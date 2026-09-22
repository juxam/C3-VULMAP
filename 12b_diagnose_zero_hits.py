"""
12b_diagnose_zero_hits.py - fast diagnosis of the "0 hits across 14.8M
files" result. Scans only 500 real rows, printing every piece of
diagnostic information 12_flawfinder_scan_tier2.py's main run silently
discarded: subprocess return code, stderr, raw stdout length, and the
combined file's actual on-disk content (to catch any newline-translation
mismatch between what was written and what the line-counting logic
assumed).

Also tests BOTH write modes - default (platform line-ending translation)
and newline="" (no translation) - so if the write mode is the cause, this
proves it directly rather than guessing.

Run:  python 12b_diagnose_zero_hits.py > diagnose_zero_hits.txt 2>&1
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pyarrow.parquet as pq

import config

N_ROWS = 500
SEP = "=" * 72

CWE_RE = re.compile(r"CWE-\d+")


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def build_combined(rows):
    parts = []
    ranges = []
    line_no = 1
    for source_id, code in rows:
        marker = "/* __FF_SOURCE_ID__:%s */\n" % source_id
        parts.append(marker)
        line_no += 1
        block = code if code.endswith("\n") else code + "\n"
        n_lines = block.count("\n")
        parts.append(block)
        ranges.append((line_no, line_no + max(n_lines, 1) - 1, source_id))
        line_no += n_lines
        parts.append("\n")
        line_no += 1
    return "".join(parts), ranges


def try_write_and_scan(text, tmpdir, newline_mode, label):
    print(f"\n--- write mode: {label} (newline={newline_mode!r}) ---")
    p = tmpdir / f"batch_{label}.cpp"
    if newline_mode == "SKIP":
        p.write_text(text, encoding="utf-8", errors="replace")
    else:
        p.write_text(text, encoding="utf-8", errors="replace",
                     newline=newline_mode)

    raw = p.read_bytes()
    print(f"  file size on disk: {len(raw):,} bytes")
    print(f"  contains \\r\\n : {b'\\r\\n' in raw}")
    print(f"  contains bare \\n (no preceding \\r): "
          f"{re.search(rb'(?<!\\r)\\n', raw) is not None}")

    r = subprocess.run(
        [sys.executable, "-m", "flawfinder", "--csv", "--quiet", str(p)],
        capture_output=True, text=True,
    )
    print(f"  return code: {r.returncode}")
    print(f"  stdout length: {len(r.stdout)} chars")
    print(f"  stderr: {r.stderr[:500]!r}" if r.stderr else "  stderr: (empty)")
    if r.stdout.strip():
        lines = r.stdout.strip().split("\n")
        print(f"  CSV lines returned: {len(lines)} (incl. header)")
        print(f"  first data line: {lines[1] if len(lines) > 1 else '(none)'}")
    else:
        print(f"  stdout is EMPTY - flawfinder found nothing in this file")


def main():
    outdir = config.ensure_output_dir()
    src = outdir / "starcoder_tier2.parquet"

    head("1. LOAD A SAMPLE OF REAL ROWS")
    pf = pq.ParquetFile(src)
    batch = next(pf.iter_batches(batch_size=N_ROWS, columns=["source_id", "code"]))
    rows = list(zip(batch.column("source_id").to_pylist(),
                    batch.column("code").to_pylist()))
    print(f"Loaded {len(rows)} real rows")

    # crude pre-check: how many rows contain an obvious risky call at all?
    risky = re.compile(r"\b(strcpy|strcat|sprintf|system|gets)\s*\(")
    n_risky = sum(1 for _, c in rows if risky.search(c))
    print(f"Rows containing an obvious risky call (strcpy/sprintf/system/"
          f"etc) by simple regex: {n_risky} of {len(rows)}")
    if n_risky == 0:
        print("None in this particular sample by chance - not conclusive on "
              "its own, real C/C++ code doesn't guarantee these patterns "
              "every 500 rows, but worth knowing.")

    head("2. BUILD COMBINED FILE, TEST BOTH WRITE MODES")
    combined_text, ranges = build_combined(rows)
    print(f"Combined text: {len(combined_text):,} chars, {len(ranges)} row "
          f"ranges tracked")

    with tempfile.TemporaryDirectory(prefix="ff_diag_") as td:
        tmpdir = Path(td)
        try_write_and_scan(combined_text, tmpdir, "", "no_translation")
        try_write_and_scan(combined_text, tmpdir, "SKIP", "default_platform")

    head("3. SANITY CHECK: SCAN A SINGLE KNOWN-BAD ROW DIRECTLY")
    known_bad = ("#include <string.h>\n"
                "int f(char *s){\n"
                "    char buf[8];\n"
                "    strcpy(buf, s);\n"
                "    return 0;\n"
                "}\n")
    with tempfile.TemporaryDirectory(prefix="ff_sanity_") as td:
        p = Path(td) / "sanity.cpp"
        p.write_text(known_bad, encoding="utf-8", newline="")
        r = subprocess.run(
            [sys.executable, "-m", "flawfinder", "--csv", "--quiet", str(p)],
            capture_output=True, text=True,
        )
        print(f"return code: {r.returncode}")
        print(f"stdout:\n{r.stdout}")
        print(f"stderr: {r.stderr[:500]!r}" if r.stderr else "stderr: (empty)")
        if "CWE-120" in r.stdout:
            print("\nPASS - flawfinder correctly found the strcpy issue on "
                  "this machine, in this environment. The scanning engine "
                  "itself works here.")
        else:
            print("\nFAIL - flawfinder did NOT find a textbook strcpy issue "
                  "on a hand-written test file. This points at something "
                  "environmental (flawfinder installation, Python "
                  "environment, or a config/rule-loading problem) rather "
                  "than anything about the real corpus data.")


if __name__ == "__main__":
    main()
