"""
check_progress.py - check on a running 12_flawfinder_scan_tier2.py job
without touching it. Reads the redirected log file and the skipped-rows
CSV; does not need the main job to be stopped or paused.

Run in a SECOND terminal window, leaving the running job alone:
  python check_progress.py
  python check_progress.py path\to\flawfinder_scan.txt   (if not run from
                                                           the same folder)
"""

import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import config

PROGRESS_RE = re.compile(
    r"^\s*([\d,]+)/([\d,]+) scanned, ([\d,]+) hits so far, "
    r"([\d.]+) rows/sec, ETA ([\d.]+) min"
)


def to_int(s):
    return int(s.replace(",", ""))


def main():
    log_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("flawfinder_scan.txt")

    if not log_path.exists():
        print(f"{log_path} not found. Pass the log file path as an "
              f"argument if it's not in the current directory:")
        print(f"  python check_progress.py path\\to\\flawfinder_scan.txt")
        return

    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        print(f"Could not read {log_path} right now (sharing violation) - "
              f"this can happen mid-write on Windows. Try again in a "
              f"couple of seconds.")
        return

    mtime = log_path.stat().st_mtime
    age_sec = time.time() - mtime
    last_modified = datetime.fromtimestamp(mtime).strftime("%H:%M:%S")

    print(f"Log file: {log_path}")
    print(f"Last written: {last_modified} ({age_sec:.0f}s ago)")
    if age_sec > 300:
        print(f"  >>> Over 5 minutes since the log last updated. The "
              f"script only prints every 100,000 rows, so this can be "
              f"normal if throughput is slow right now - but if it's been "
              f"MUCH longer than the recent per-100k-rows pace, it may be "
              f"stalled rather than just slow.")

    progress_lines = [l for l in lines if PROGRESS_RE.match(l)]
    if not progress_lines:
        print("\nNo progress lines found yet - the job may still be on "
              "its first 100,000 rows, or hasn't started scanning yet.")
    else:
        m = PROGRESS_RE.match(progress_lines[-1])
        scanned, total, hits, rate, eta = m.groups()
        scanned_n, total_n = to_int(scanned), to_int(total)
        pct = scanned_n / total_n * 100 if total_n else 0
        print(f"\nLatest progress:")
        print(f"  {scanned} / {total} rows scanned ({pct:.1f}%)")
        print(f"  {hits} hits so far")
        print(f"  {rate} rows/sec")
        print(f"  ETA {eta} min from that point")

        if len(progress_lines) >= 2:
            m0 = PROGRESS_RE.match(progress_lines[-2])
            prev_scanned = to_int(m0.group(1))
            delta = scanned_n - prev_scanned
            print(f"  (+{delta:,} rows since the previous printed line)")

    tripped = [l for l in lines if "Circuit breaker tripped" in l]
    if tripped:
        print(f"\n{tripped[-1].strip()}")

    outdir = config.ensure_output_dir()
    skipped_csv = outdir / "starcoder_tier2_flawfinder_skipped.csv"
    if skipped_csv.exists():
        try:
            with open(skipped_csv, encoding="utf-8", errors="replace") as f:
                n_skipped = sum(1 for _ in f) - 1   # minus header
        except PermissionError:
            n_skipped = None
        if n_skipped is not None:
            print(f"\nRows skipped so far (see {skipped_csv.name}): "
                  f"{max(n_skipped, 0):,}")

    done_lines = [l for l in lines if l.strip().startswith("Done.")]
    if done_lines:
        print(f"\n>>> The job has FINISHED: {done_lines[-1].strip()}")


if __name__ == "__main__":
    main()
