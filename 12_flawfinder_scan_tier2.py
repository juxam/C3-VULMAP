"""
12_flawfinder_scan_tier2.py - static-analysis labelling for tier 2, using
flawfinder's own real CWE tags rather than any model we trained.

WHY THIS APPROACH: using our own tier-1-trained classifier to label tier 2
would be circular - the "labels" would just be the model's own opinion,
dressed up as ground truth. flawfinder's rule-based CWE tags are a
different, defensible kind of claim: not "this function is vulnerable",
but "this function contains a pattern flawfinder associates with CWE-X".
Weaker than tier 1's CVE-verified labels, but real and reproducible - kept
as a clearly separate label_source, never pooled with tier 1.

PERFORMANCE AND ROBUSTNESS HISTORY (this script's actual debugging arc,
kept here since it explains every design choice below):
  - one flawfinder subprocess per file: 59.3ms/file -> 244 hours. Not viable.
  - one flawfinder invocation per batch of 5,000 small files: benchmarked
    at 0.23ms/file on Linux, but ~34 rows/sec on the real Windows run (a
    ~5-day job) - almost certainly Linux's /tmp being RAM-backed (tmpfs)
    vs Windows' real disk, likely compounded by antivirus scanning on
    every small-file create.
  - one COMBINED file per batch instead: cut filesystem operations by
    ~5,000x, ran the full 14.8M rows in 40.7 minutes - but returned 0
    hits everywhere, because the script only checked whether stdout was
    empty and silently treated any subprocess failure as "found nothing".
    flawfinder was actually failing on every batch with return code 15.
  - traced return code 15 to flawfinder's own expand_ruleset() function
    (Error: Rule ..., when expanded, overlaps ...) - a ruleset-consistency
    check that runs ONCE per invocation, before any file scanning, and by
    flawfinder's own source is NOT supposed to depend on input content at
    all. Reproducing this with a large SYNTHETIC file (3.71 MB) did NOT
    trigger it - only real StarCoder content did. Root cause not fully
    resolved; something about real scraped GitHub content appears to
    trigger a genuine flawfinder edge case that could not be reproduced
    with synthetic test data.
  - RESULT: rather than keep chasing an elusive root cause blind, this
    version makes the pipeline resilient to it. A failing batch is
    bisected and retried; failures are isolated down to whichever specific
    rows actually cause them (capped at a minimum sub-batch size so this
    can't degrade into thousands of single-row invocations if the trigger
    turns out to be common), logged with their content preserved for
    later investigation, and everything else proceeds normally. The
    majority of batches - which the synthetic large-file test suggests
    should be the common case - pay zero overhead for this: one
    invocation, success, done.

CSV OUTPUT FORMAT, confirmed directly against real flawfinder 2.0.20
output:
    File,Line,Column,DefaultLevel,Level,Category,Name,Warning,Suggestion,
    Note,CWEs,Context,Fingerprint,ToolVersion,RuleId,HelpUri
The CWEs field can be a single id ("CWE-120") or an ambiguous combined
form ("CWE-119!/CWE-120") - both are split into individual ids below.

KEYED BY row_uid, NOT source_id. Confirmed after the first full scan: the
original source_id field was copied verbatim from upstream StarCoder's own
"id" column (10_load_starcoder_tier2.py), which turned out to be unique
only within whatever grouping StarCoder itself used, not across this
project's full 210-shard local download - 85% of all 14,838,026 rows
shared their source_id with exactly one other row. row_uid (added by
patch_row_uid.py, run once against the already-consolidated parquet) is
just row position - unique by construction, independent of anything
upstream. Every output column and internal variable here says row_uid,
never source_id, specifically so a CSV from this corrected version can
never be silently confused with one from the original run.

Run:  python 12_flawfinder_scan_tier2.py
Out:  starcoder_tier2_flawfinder.csv (one row per flawfinder HIT, not per
      file - most files will have zero rows, meaning flawfinder found
      nothing to flag, not that the file was skipped)
      starcoder_tier2_flawfinder_skipped.csv (rows that could not be
      scanned even after bisection, with the exact error and their code,
      for later investigation - should be empty or near-empty)
"""

import bisect
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pyarrow.parquet as pq

import config

BATCH_SIZE = 5000
# Stop bisecting below this size; skip and log the whole sub-batch rather
# than recursing all the way down to single rows.
MIN_BISECT_SIZE = 25
# ~12x the ~10s a healthy 5,000-row batch takes - generous margin, but
# nowhere near the hours a genuinely stuck batch (confirmed: one ran for
# ~22.7 hours of actual CPU time without finishing) can otherwise burn.
FLAWFINDER_TIMEOUT_SEC = 120
CWE_RE = re.compile(r"CWE-\d+")

# Fixed, predictable scratch directory instead of tempfile.TemporaryDirectory's
# randomly-named folder each run. A security-tool exclusion (Windows Defender,
# HP Wolf, etc) needs one stable path to target - excluding a different
# randomly-named folder every run defeats the point of setting the exclusion
# at all. Cleaned at the start of each run rather than left to accumulate.
SCRATCH_DIR_NAME = "ff_scratch"

# Adaptive circuit breaker: bisecting a failing batch is cheap when failures
# are RARE (the original design assumption) - one bad row costs ~13 extra
# invocations to isolate out of 5,000. It's actively harmful when failures
# are FREQUENT, e.g. if a security product is intercepting many batches
# with real slow behavioural scanning - re-triggering that interception at
# every level of the bisection multiplies the cost instead of containing
# it. If the recent top-level failure rate crosses this threshold, stop
# bisecting new failures and skip them whole instead - trading isolation
# precision for not compounding an already-expensive interception.
FAILURE_RATE_WINDOW = 20
FAILURE_RATE_THRESHOLD = 0.30

EXT_MAP = {
    ".c": ".c", ".h": ".h",
    ".cc": ".cc", ".cpp": ".cpp", ".cxx": ".cpp", ".c++": ".cpp",
    ".hh": ".hpp", ".hpp": ".hpp", ".hxx": ".hpp",
}


def infer_ext(repo_path):
    if not repo_path:
        return ".c"
    suffix = Path(str(repo_path)).suffix.lower()
    return EXT_MAP.get(suffix, ".c")


def build_combined_file(rows):
    """rows: list of (row_uid, code, repo_path). Returns (combined_text,
    ranges) where ranges is a sorted-by-start-line list of (start_line,
    end_line, row_uid), 1-indexed inclusive."""
    parts = []
    ranges = []
    line_no = 1
    for row_uid, code, repo_path in rows:
        marker = "/* __FF_ROW_UID__:%s */\n" % row_uid
        parts.append(marker)
        line_no += 1
        block = code if code.endswith("\n") else code + "\n"
        n_lines = block.count("\n")
        parts.append(block)
        ranges.append((line_no, line_no + max(n_lines, 1) - 1, row_uid))
        line_no += n_lines
        parts.append("\n")
        line_no += 1
    return "".join(parts), ranges


class FailureBreaker:
    """Tracks the recent TOP-LEVEL batch failure rate over a sliding
    window and reports whether it has crossed FAILURE_RATE_THRESHOLD.
    Only top-level batch outcomes count towards the window - a bisected
    sub-batch's outcome doesn't, since bisection outcomes are downstream
    consequences of a top-level failure already recorded, not independent
    evidence about how often fresh batches are failing."""

    def __init__(self, window=FAILURE_RATE_WINDOW,
                threshold=FAILURE_RATE_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.recent = []   # True = success, False = failure

    def record(self, success):
        self.recent.append(success)
        if len(self.recent) > self.window:
            self.recent.pop(0)

    def tripped(self):
        if len(self.recent) < self.window:
            return False   # not enough data yet - default to full bisection
        failure_rate = 1 - (sum(self.recent) / len(self.recent))
        return failure_rate >= self.threshold


def attribute_line(ranges, starts, line_no):
    i = bisect.bisect_right(starts, line_no) - 1
    if i < 0:
        return None
    start, end, row_uid = ranges[i]
    return row_uid if start <= line_no <= end else None


def invoke_flawfinder(path):
    """Single flawfinder call on one file. Returns the CompletedProcess -
    caller decides how to interpret return code / stderr.

    THE REAL ROOT CAUSE of most of this script's "return code 15" failures,
    confirmed against real skipped-row error text: flawfinder opens its
    input with plain open(f, "r") - no explicit encoding (confirmed in
    flawfinder's own source, which even has a pylint directive
    acknowledging this: "disable-next=unspecified-encoding"). On Windows
    that defaults to cp1252 ("charmap"). This script's own combined-file
    output is guaranteed valid UTF-8 (write_text(encoding="utf-8",
    errors="replace") on a Python string can never produce anything else),
    but valid UTF-8 containing non-ASCII text (any non-English comment -
    StarCoder is scraped from all of GitHub, so this is common, not rare)
    frequently is NOT valid cp1252, and specific byte positions that are
    undefined in cp1252's mapping table (0x81, 0x8D, 0x8F, 0x90, 0x9D)
    crash flawfinder's read outright rather than just mangling the text.

    PYTHONUTF8=1 (PEP 540 UTF-8 mode) forces Python's default open()
    encoding to UTF-8 regardless of the OS locale - confirmed directly: a
    file written exactly the way this script writes it, containing real
    non-ASCII content, reads cleanly under this mode with zero risk of the
    crash, since valid UTF-8 always decodes successfully under a UTF-8
    codec by definition. Earlier hardening for antivirus interception
    (fixed scratch dir, circuit breaker, bisection isolation) stays in
    place - that was real, evidenced by actual quarantine events - but
    this fixes what was very likely the dominant cause of the skip counts
    seen so far, which had nothing to do with antivirus at all.

    SECOND HALF OF THE SAME BUG, found after the above was already deployed:
    PYTHONUTF8=1 above fixes how the CHILD (flawfinder) reads ITS OWN input
    file. It does nothing for how the PARENT (this script) decodes the
    CHILD's stdout back into a Python string - that is a completely
    separate decode step, performed by subprocess.run's internal reader
    thread, governed by the PARENT interpreter's own default encoding
    (still cp1252 on Windows) unless told otherwise via encoding=/errors=
    here. Once flawfinder could successfully read non-ASCII StarCoder
    content (thanks to the fix above), it started successfully MATCHING on
    lines near that content and echoing it back in the CSV "Context"
    column as valid UTF-8 - which then crashed THIS process's decode of
    that output, inside subprocess.py's own reader thread, an exception
    that doesn't propagate normally and left r.stdout as None downstream.
    encoding="utf-8" here closes that other half; errors="replace" is a
    second-layer safety net so any further encoding surprise degrades to
    a mangled Context string rather than crashing the whole run - Context
    is informational only, never used for CWE/line/category parsing.

    TIMEOUT, added after a real hang: one batch ran for ~22.7 hours of
    actual CPU time (confirmed via Get-Process - not just wall-clock idle
    time) without finishing, on what should be a ~10-second operation at
    healthy throughput. subprocess.run has no timeout by default, so
    nothing detected this - the script just waited, indefinitely, on a
    single pathological batch (most likely triggered by the 11.6-million-
    character file already confirmed present in this corpus, or a
    catastrophic-backtracking regex case inside flawfinder itself). A
    timeout turns "hangs forever" into "fails like any other batch",
    which the EXISTING bisection logic already knows how to isolate and
    skip - so a future pathological file costs one bisection's worth of
    extra time, not another lost day."""
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    try:
        return subprocess.run(
            [sys.executable, "-m", "flawfinder", "--csv", "--quiet", str(path)],
            capture_output=True, text=True, env=env,
            encoding="utf-8", errors="replace",
            timeout=FLAWFINDER_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        # Shaped like a normal failed CompletedProcess so callers (scan_rows,
        # which only ever looks at .returncode/.stdout/.stderr) don't need
        # a separate code path for "timed out" vs "returned an error code" -
        # it flows into the same bisect-and-isolate logic either way.
        class _TimedOut:
            returncode = -1
            stdout = ""
            stderr = f"TIMEOUT after {FLAWFINDER_TIMEOUT_SEC}s"
        return _TimedOut()


def parse_hits(stdout, ranges, starts):
    # Defensive: stdout can legitimately be None if subprocess's own
    # reader thread hit a decode error before this script's encoding=
    # fix was in place - confirmed as the real cause of a crash here.
    # errors="replace" on the subprocess call above should prevent that
    # going forward, but treating an unexpected None the same as "no
    # output" costs nothing and means a future, different surprise here
    # degrades gracefully instead of crashing the whole multi-hour run.
    if not stdout or not stdout.strip():
        return []
    reader = csv.DictReader(io.StringIO(stdout))
    hits = []
    for row in reader:
        try:
            line_no = int(row.get("Line") or 0)
        except ValueError:
            continue
        row_uid = attribute_line(ranges, starts, line_no)
        if row_uid is None:
            continue
        # csv.DictReader fills any TRAILING field with None (not "") when
        # a row has fewer columns than the header - its documented restval
        # behaviour. "or ''" guards every field pulled from a row here.
        cwes = CWE_RE.findall(row.get("CWEs") or "")
        for cwe in cwes or [None]:
            hits.append({
                "row_uid": row_uid,
                "line": row.get("Line") or "",
                "cwe_id": cwe,
                "level": row.get("Level") or "",
                "category": row.get("Category") or "",
                "name": row.get("Name") or "",
                "warning": row.get("Warning") or "",
            })
    return hits


def scan_rows(rows, tmpdir, skipped_log, breaker, depth=0, top_level=False):
    """Try one combined-file invocation for `rows`. On failure, bisect and
    retry each half, recursing until success, or until MIN_BISECT_SIZE is
    reached, at which point the whole remaining sub-batch is logged to
    skipped_log (row_uid, error, code) and dropped rather than recursed
    further.

    `breaker` is a FailureBreaker tracking the recent TOP-LEVEL failure
    rate. If that rate is high, a new top-level failure skips straight to
    logging the whole batch instead of bisecting - bisection only helps
    when failures are rare enough that most of a split batch is fine; when
    they're common, splitting just re-triggers the same expensive
    interception at every level for no added isolation benefit."""
    if not rows:
        return []

    combined_text, ranges = build_combined_file(rows)
    combined_path = tmpdir / f"batch_{depth}_{len(rows)}.cpp"
    # newline="" disables platform line-ending translation (Windows would
    # otherwise rewrite "\n" to "\r\n" on write) so the physical file
    # matches exactly what build_combined_file's line counting assumed.
    combined_path.write_text(combined_text, encoding="utf-8",
                             errors="replace", newline="")
    starts = [r[0] for r in ranges]

    r = invoke_flawfinder(combined_path)
    # Return code alone decides success - NOT "and stderr is empty" as this
    # used to require. flawfinder routinely writes benign parsing warnings
    # to stderr on a completely successful scan (confirmed against real
    # skipped-row data: returncode=0 with a "Parsing failed to find end of
    # parameter list" warning about a tricky macro, still producing valid
    # CSV output on stdout). The old stricter check was treating every such
    # warning as a hard failure and needlessly bisecting/skipping good
    # batches - a real bug, not a data or environment problem, and likely
    # the dominant cause of the slow rate rather than antivirus or
    # encoding. Genuine crashes (the earlier encoding-related failures,
    # confirmed against real data) return a NONZERO code, so this still
    # catches those correctly.
    success = r.returncode == 0

    if top_level:
        breaker.record(success)

    if success:
        return parse_hits(r.stdout, ranges, starts)

    # Failure. Skip immediately (no bisection) if either we're already at
    # the minimum size, or the circuit breaker says failures are too
    # frequent right now for bisection to be worth its cost.
    skip_whole = len(rows) <= MIN_BISECT_SIZE or breaker.tripped()
    if skip_whole:
        for row_uid, code, _ in rows:
            skipped_log.writerow({
                "row_uid": row_uid,
                "returncode": r.returncode,
                "error": (r.stderr or r.stdout)[:500],
                "code_sample": code[:300],
            })
        return []

    mid = len(rows) // 2
    left = scan_rows(rows[:mid], tmpdir, skipped_log, breaker, depth + 1)
    right = scan_rows(rows[mid:], tmpdir, skipped_log, breaker, depth + 1)
    return left + right


def render_progress_bar(n_scanned, total, n_hits, rate, eta_min, width=30):
    """A single overwritable console line - only meaningful when stdout is
    an actual live terminal (isatty()). Writing carriage returns into a
    redirected log file just clutters it with '\r' characters and breaks
    check_progress.py's line-based parsing, so this is never used when
    output is redirected - see the isatty() gate at the call site."""
    pct = n_scanned / total if total else 0
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    eta_str = f"{eta_min:.1f}m" if eta_min < float("inf") else "?"
    line = (f"\r[{bar}] {pct:.1%}  {n_scanned:,}/{total:,}  "
           f"{n_hits:,} hits  {rate:.1f} rows/s  ETA {eta_str}   ")
    sys.stdout.write(line)
    sys.stdout.flush()


def main():
    outdir = config.ensure_output_dir()
    src = outdir / "starcoder_tier2.parquet"
    out_csv = outdir / "starcoder_tier2_flawfinder.csv"
    skipped_csv = outdir / "starcoder_tier2_flawfinder_skipped.csv"

    # Fixed, predictable scratch directory rather than a fresh randomly-
    # named tempfile.TemporaryDirectory() every run - a security-tool
    # exclusion needs one stable path to target. Cleared at the start of
    # each run so old batch files never accumulate across restarts.
    scratch_root = outdir / SCRATCH_DIR_NAME
    if scratch_root.exists():
        shutil.rmtree(scratch_root, ignore_errors=True)
    scratch_root.mkdir(parents=True, exist_ok=True)
    print(f"Scratch directory (point an AV/HP Wolf exclusion here if "
          f"needed): {scratch_root}")

    print(f"Reading row groups from {src} ...")
    pf = pq.ParquetFile(src)
    total_rows = pf.metadata.num_rows
    print(f"{total_rows:,} rows to scan, batch size {BATCH_SIZE}, "
          f"min bisect size {MIN_BISECT_SIZE}, circuit breaker at "
          f"{FAILURE_RATE_THRESHOLD:.0%} failure rate over "
          f"{FAILURE_RATE_WINDOW} batches")

    # Resume support, added after a real ~24-hour hang required a full
    # restart from row 0. Checkpoint is written after every COMPLETED
    # top-level batch, so it always lands exactly on a batch boundary -
    # pyarrow's iter_batches over a given file with a given batch_size is
    # deterministic (fixed row-group structure, walked in fixed order), so
    # replaying the same iteration and skipping whole batches until the
    # checkpoint is reached lines up exactly with where the previous run
    # actually stopped, with no risk of a partial-batch gap or overlap.
    # Checkpoint stores n_scanned, n_hits, AND n_files_with_hits as JSON -
    # NOT just n_scanned. A real bug, found after a real restart: the first
    # version only persisted the row count, so resuming correctly SKIPPED
    # already-done rows (that part worked) but silently reset the hit
    # counters to zero, making the final "Done." summary undercount by
    # everything found before the restart - confirmed directly: a resumed
    # run reported 6,073,225 hits when the true cumulative total (verified
    # against the actual CSV row count) was ~18.7 million. The underlying
    # CSV file itself was never at risk - it's opened in append mode either
    # way - only the in-memory counters used for the printed summary were
    # wrong. Old-format checkpoints (a bare integer, from before this fix)
    # are still read correctly, just without their hit counters - there is
    # no way to recover those retroactively, only to stop losing them going
    # forward.
    checkpoint_path = outdir / "starcoder_tier2_flawfinder_checkpoint.txt"
    resume_from = 0
    n_scanned = 0
    n_hits = 0
    n_files_with_hits = 0
    if checkpoint_path.exists():
        raw = checkpoint_path.read_text().strip()
        try:
            state = json.loads(raw)
            resume_from = int(state.get("n_scanned", 0))
            n_scanned = resume_from
            n_hits = int(state.get("n_hits", 0))
            n_files_with_hits = int(state.get("n_files_with_hits", 0))
        except (json.JSONDecodeError, ValueError, AttributeError):
            try:
                resume_from = int(raw)   # old bare-integer format
                n_scanned = resume_from
            except ValueError:
                resume_from = 0
    if resume_from > 0:
        print(f"Resuming from checkpoint: {resume_from:,} rows already "
              f"completed in a previous run - skipping ahead rather than "
              f"reprocessing them. Carrying forward {n_hits:,} hits and "
              f"{n_files_with_hits:,} files-with-hits already counted.")

    write_header = not out_csv.exists()
    fieldnames = ["row_uid", "line", "cwe_id", "level", "category",
                  "name", "warning"]
    skipped_header = not skipped_csv.exists()
    skipped_fieldnames = ["row_uid", "returncode", "error", "code_sample"]

    t0 = time.time()
    breaker = FailureBreaker()
    breaker_was_tripped = False
    print_interval = BATCH_SIZE * 20
    next_print_at = print_interval
    # Threshold-CROSSING check, not exact equality. pyarrow's iter_batches
    # does not guarantee every batch is exactly BATCH_SIZE rows - row-group
    # boundaries in the source parquet can produce a smaller or larger
    # batch. If n_scanned ever jumps past a round multiple in one
    # increment instead of landing on it exactly, "n_scanned % interval ==
    # 0" silently never fires again for the rest of the run - real
    # progress keeps happening with zero visible log lines. Confirmed this
    # was happening on the real corpus: 500,000+ rows genuinely processed
    # (and logged to the skipped-rows file) with not one progress line
    # printed.

    with open(out_csv, "a", newline="", encoding="utf-8") as f, \
         open(skipped_csv, "a", newline="", encoding="utf-8") as sf:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        raw_skipped_writer = csv.DictWriter(sf, fieldnames=skipped_fieldnames)
        if skipped_header:
            raw_skipped_writer.writeheader()

        class CountingWriter:
            """Wraps the CSV writer to track how many rows were actually
            skipped, independent of the file's on-disk size - opening the
            file in append mode creates it (with a header) regardless of
            whether anything gets skipped, so checking file size alone
            would report a "problem" on every run, even a clean one."""
            def __init__(self, inner):
                self.inner = inner
                self.count = 0

            def writerow(self, d):
                self.inner.writerow(d)
                self.count += 1

        skipped_writer = CountingWriter(raw_skipped_writer)

        # Separate from n_scanned on purpose - a real bug, found by testing
        # the checkpoint fix, not just trusting it: n_scanned now STARTS at
        # resume_from (needed so reporting/ETA are correct across a resumed
        # run), but the skip-decision needs a counter that starts at 0 and
        # tracks raw iteration position - using n_scanned for both meant
        # the very first batch's check became "resume_from + batch_size <=
        # resume_from", which is never true, so nothing ever got skipped
        # and every already-completed row was silently reprocessed.
        iter_position = 0
        for batch in pf.iter_batches(
                batch_size=BATCH_SIZE,
                columns=["row_uid", "code", "max_stars_repo_path"]):
            rows = list(zip(batch.column("row_uid").to_pylist(),
                            batch.column("code").to_pylist(),
                            batch.column("max_stars_repo_path").to_pylist()))

            # Skip whole batches already covered by the checkpoint - cheap,
            # since no flawfinder work happens for a skipped batch, just
            # the parquet iteration itself.
            if iter_position + len(rows) <= resume_from:
                iter_position += len(rows)
                continue
            iter_position += len(rows)

            batch_dir = scratch_root / f"b{n_scanned}"
            batch_dir.mkdir(exist_ok=True)
            try:
                hits = scan_rows(rows, batch_dir, skipped_writer, breaker,
                                 top_level=True)
            finally:
                shutil.rmtree(batch_dir, ignore_errors=True)

            if breaker.tripped() and not breaker_was_tripped:
                breaker_was_tripped = True
                print(f"  >>> Circuit breaker tripped at {n_scanned:,} rows "
                      f"scanned - recent failure rate crossed "
                      f"{FAILURE_RATE_THRESHOLD:.0%}. New failures will be "
                      f"skipped whole rather than bisected from here on, "
                      f"to avoid repeatedly re-triggering an expensive "
                      f"interception.", flush=True)

            file_ids_with_hits = {h["row_uid"] for h in hits}
            n_files_with_hits += len(file_ids_with_hits)
            for h in hits:
                writer.writerow(h)
            n_hits += len(hits)
            n_scanned += len(rows)
            sf.flush()
            # Checkpoint written after this batch is FULLY committed to
            # both output files above - never mid-batch, so a checkpoint
            # value always represents "everything up to here is safely on
            # disk", not a partially-written state a resume could corrupt.
            checkpoint_path.write_text(json.dumps({
                "n_scanned": n_scanned,
                "n_hits": n_hits,
                "n_files_with_hits": n_files_with_hits,
            }))

            el = time.time() - t0
            rate = n_scanned / el if el > 0 else 0
            eta = (total_rows - n_scanned) / rate / 60 if rate > 0 else float("inf")

            # Live-updating single line, only in an actual interactive
            # terminal - every batch, not just every 100,000 rows, so it
            # genuinely feels live rather than choppy.
            if sys.stdout.isatty():
                render_progress_bar(n_scanned, total_rows, n_hits, rate, eta)

            # Real newline-terminated checkpoint lines, unconditionally -
            # this is what check_progress.py parses, and what a redirected
            # log file needs regardless of whether the bar above is also
            # showing. Printing this after a \r bar update correctly
            # overwrites that line's content with the checkpoint text in a
            # real terminal, then moves to a fresh line as normal.
            if n_scanned >= next_print_at or n_scanned >= total_rows:
                print(f"  {n_scanned:,}/{total_rows:,} scanned, "
                      f"{n_hits:,} hits so far, {rate:.1f} rows/sec, "
                      f"ETA {eta:.1f} min", flush=True)
                while next_print_at <= n_scanned:
                    next_print_at += print_interval

    print(f"\nDone. {n_scanned:,} files scanned, {n_hits:,} total hits "
          f"across {n_files_with_hits:,} files "
          f"({n_files_with_hits/max(n_scanned,1):.1%} of files flagged).")
    print(f"Wrote {out_csv}")
    if breaker_was_tripped:
        print(f"\nThe circuit breaker tripped during this run - a "
              f"meaningful fraction of batches were failing (recent rate "
              f"crossed {FAILURE_RATE_THRESHOLD:.0%}), consistent with "
              f"something (e.g. HP Wolf or another security product) "
              f"intercepting content frequently rather than rarely. "
              f"Setting an exclusion for {scratch_root} before the next "
              f"run, if you have the access to do so, should restore "
              f"normal throughput.")
    if skipped_writer.count > 0:
        print(f"\n{skipped_writer.count:,} row(s) could not be scanned even "
              f"after bisection - see {skipped_csv}. If this number is "
              f"large, the flawfinder issue traced during debugging "
              f"(return code 15, expand_ruleset overlap) may be more "
              f"common than the synthetic-file test suggested, and is "
              f"worth sending back for further investigation. If it's "
              f"small, this was rare, as expected.")
    else:
        print(f"\nNo rows were skipped - every batch scanned cleanly.")
    print(f"Total time: {(time.time()-t0)/60:.1f} min")
    print(f"\nThis is a per-HIT file, not per-FILE — most files have zero")
    print(f"rows here (flawfinder found nothing), which is expected, not")
    print(f"a processing failure. Next: join cwe_id through")
    print(f"cwe_category_map.csv -> category_id_to_linddun.csv, the same")
    print(f"chain tier 1 uses, to attach category and LINDDUN labels.")
    print(f"\nRemember: this is 'contains a pattern flawfinder associates")
    print(f"with CWE-X', not 'is vulnerable' — document label_source as")
    print(f"'static_analysis', kept separate from tier 1's CVE-verified")
    print(f"labels, in CONSTRUCTION.md and in the release schema.")


if __name__ == "__main__":
    main()
