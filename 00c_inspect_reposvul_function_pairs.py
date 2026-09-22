"""
00c_inspect_reposvul_function_pairs.py — confirm the function_before /
function_after lists actually mean what I think they mean, before
02_load_reposvul.py extracts a single row from them.

00b showed: file-level code/code_before entries (target -1/None/0) are whole
FILES (17-31KB, copyright headers included) — wrong granularity for a
function-level corpus, and using them would reintroduce a size-based
shortcut of exactly the kind this whole project exists to eliminate. The
real function-level data lives in function_before/function_after, populated
for only ~9% of details[] entries, as LISTS of {function, target} objects.

Unconfirmed:
  1. Does target=1 ever actually appear inside these lists? (the one example
     seen so far showed only target=0 items)
  2. When it does, does the SAME function (by name) appear in function_after
     with target=0 — i.e. is this genuinely a before/after fix pair, matched
     by function identity, not just two unrelated lists?
  3. Are function_before and function_after the same length / positionally
     aligned, or independent lists needing matching by function signature?
  4. At realistic scale, how many usable function-level rows does this
     actually yield?

Scans more records than 00b (function-level entries are rare) specifically
to find and print real target=1 examples.

Run:  python 00c_inspect_reposvul_function_pairs.py > inspect_reposvul_pairs.txt 2>&1
"""

import json
import re
from collections import Counter

import config

N_SAMPLE = 5000
SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def func_name(code):
    """Best-effort function name/signature extraction for matching
    before/after by identity rather than list position."""
    m = re.search(r"([A-Za-z_:~][\w:~<>]*)\s*\([^;{]*\)\s*\{", str(code))
    return m.group(1) if m else None


def main():
    p = config.REPOSVUL_PATH
    print(f"Scanning up to {N_SAMPLE:,} records from {p}")

    n_records = 0
    n_details = 0
    n_with_fb = 0
    fb_target_counts = Counter()
    fa_target_counts = Counter()
    fb_lengths = []
    fa_lengths = []
    len_mismatch = 0

    vuln_examples = []   # (fb_item, fa_items, details_context)

    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f:
            if n_records >= N_SAMPLE:
                break
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            n_records += 1

            for d in r.get("details", []) or []:
                if not isinstance(d, dict):
                    continue
                n_details += 1
                fb = d.get("function_before")
                fa = d.get("function_after")
                if not fb:
                    continue
                n_with_fb += 1
                fb_lengths.append(len(fb))
                fa_lengths.append(len(fa) if fa else 0)
                if fa and len(fb) != len(fa):
                    len_mismatch += 1

                for item in fb:
                    if isinstance(item, dict):
                        fb_target_counts[str(item.get("target"))] += 1
                        if item.get("target") == 1 and len(vuln_examples) < 5:
                            vuln_examples.append((item, fa, r.get("cve_id"),
                                                  d.get("file_path")))
                for item in (fa or []):
                    if isinstance(item, dict):
                        fa_target_counts[str(item.get("target"))] += 1

    print(f"\n{n_records:,} records scanned, {n_details:,} details entries, "
          f"{n_with_fb:,} with non-empty function_before "
          f"({n_with_fb/max(n_details,1):.1%})")

    # -----------------------------------------------------------------
    head("1. TARGET DISTRIBUTION *WITHIN* function_before / function_after")
    print(f"function_before items: {dict(fb_target_counts)}")
    print(f"function_after items : {dict(fa_target_counts)}")

    # -----------------------------------------------------------------
    head("2. LIST LENGTHS — POSITIONAL PAIRING OR NAME-BASED MATCHING?")
    if fb_lengths:
        import statistics
        print(f"function_before list length: mean {statistics.mean(fb_lengths):.1f}, "
              f"median {statistics.median(fb_lengths):.0f}, "
              f"max {max(fb_lengths)}")
        print(f"function_after list length : mean "
              f"{statistics.mean(fa_lengths):.1f}, "
              f"median {statistics.median(fa_lengths):.0f}, "
              f"max {max(fa_lengths) if fa_lengths else 0}")
        print(f"entries where len(function_before) != len(function_after): "
              f"{len_mismatch:,} of {n_with_fb:,}")
        print("If lengths usually match, positional pairing MIGHT be safe.")
        print("If they often differ, matching must be done by function name,")
        print("not list position — checked directly in section 3.")

    # -----------------------------------------------------------------
    head("3. DOES A target=1 FUNCTION HAVE A MATCHING, FIXED function_after ENTRY?")
    if not vuln_examples:
        print(f"No target=1 items found in function_before across "
              f"{n_records:,} records scanned. Two possibilities:")
        print(f"  (a) target=1 is genuinely rare in this field — increase "
              f"N_SAMPLE and rerun, or")
        print(f"  (b) target inside function_before/function_after doesn't "
              f"mean 'vulnerable' at all, and means something else (e.g. "
              f"'function changed' vs 'function unchanged', independent of "
              f"vulnerability). If (b), function-level vulnerability status "
              f"has to come from elsewhere — worth checking the ReposVul "
              f"paper itself rather than guessing further from field values "
              f"alone.")
    else:
        for i, (fb_item, fa_items, cve, path) in enumerate(vuln_examples):
            print(f"\n--- vulnerable example {i+1} ({cve}, {path}) ---")
            name = func_name(fb_item.get("function"))
            print(f"function_before name guess: {name}")
            print(f"function_before code:\n{fb_item.get('function')[:500]}")

            match = None
            if fa_items and name:
                for fa_item in fa_items:
                    if isinstance(fa_item, dict) and \
                       func_name(fa_item.get("function")) == name:
                        match = fa_item
                        break
            if match:
                print(f"\nMATCHED function_after entry (target="
                      f"{match.get('target')}):")
                print(f"{match.get('function')[:500]}")
            else:
                print("\nNo function_after entry with a matching name found.")
                if fa_items:
                    print(f"function_after DOES have {len(fa_items)} other "
                          f"entries though — matching by name may need a "
                          f"looser comparison than exact signature text.")

    print(f"\n{SEP}\nDo these before/after pairs (where matched) look like a")
    print(f"function and its patched version to you? That visual read is")
    print(f"the actual confirmation this needs before the loader is written.")
    print(SEP)

    # -----------------------------------------------------------------
    head("4. EXTRAPOLATED YIELD AT FULL FILE SCALE")
    with open(p, "rb") as f:
        sample_bytes = sum(len(l) for l in [f.readline() for _ in range(min(1000, n_records))])
    import os
    total_bytes = os.path.getsize(p)
    if sample_bytes > 0 and n_records > 0:
        approx_total_records = int(total_bytes / (sample_bytes / min(1000, n_records)))
        n_vuln_seen = fb_target_counts.get("1", 0)
        rate_per_record = n_vuln_seen / n_records
        print(f"File size: {total_bytes/1e6:.1f} MB")
        print(f"Approx total records: {approx_total_records:,} "
              f"(rough estimate from average line size)")
        print(f"target=1 function-level rows seen per record scanned: "
              f"{rate_per_record:.4f}")
        print(f"Extrapolated target=1 rows across full file: "
              f"~{int(rate_per_record * approx_total_records):,}")
        print("Treat this as an order-of-magnitude estimate, not a precise")
        print("count — confirm against the real total after the loader runs.")


if __name__ == "__main__":
    main()
