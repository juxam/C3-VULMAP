"""
00b_inspect_reposvul_fields.py — pin down what code / code_before / target /
function_before / function_after actually MEAN, with real values, before
02_load_reposvul.py extracts a single row from them.

00_inspect_reposvul.py showed the real schema differs from the README: at
the details[] level, function_before/function_after were EMPTY LISTS for the
first record, while code/code_before/target sit alongside them. Guessing
which of code/code_before is "vulnerable" and which is "fixed", or what
target's value space is, risks silently mislabeling the whole corpus — so
this prints actual values across a sample rather than assuming.

Answers:
  1. Is target binary (0/1)? What's its distribution?
  2. Do code and code_before actually differ (they should, if one is
     pre-patch and one is post-patch)?
  3. When ARE function_before/function_after non-empty, and what do they
     look like when they are?
  4. What do llm_check / static_check / static contain — usable as a
     quality filter?
  5. How often does a record carry more than one CWE?

Run:  python 00b_inspect_reposvul_fields.py > inspect_reposvul_fields.txt 2>&1
"""

import json
from collections import Counter

import config

N_SAMPLE = 300
SEP = "=" * 72


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def load_sample(path, n):
    recs = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= n:
                break
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                pass
    return recs


def snippet(s, n=200):
    if s is None:
        return "None"
    s = str(s)
    return s[:n].replace("\n", "\\n") + ("..." if len(s) > n else "")


def main():
    p = config.REPOSVUL_PATH
    print(f"Reading first {N_SAMPLE} records from {p}")
    recs = load_sample(p, N_SAMPLE)
    print(f"  {len(recs):,} records loaded")

    # -----------------------------------------------------------------
    head("1. TARGET — VALUE SPACE AT THE details[] LEVEL")
    detail_targets = Counter()
    for r in recs:
        for d in r.get("details", []) or []:
            if isinstance(d, dict):
                detail_targets[str(d.get("target"))] += 1
    print(f"details[].target distribution: {dict(detail_targets)}")

    # -----------------------------------------------------------------
    head("2. CODE vs CODE_BEFORE — DO THEY DIFFER? WHICH LOOKS PATCHED?")
    shown = 0
    identical = 0
    both_present = 0
    only_code = 0
    only_before = 0
    neither = 0
    for r in recs:
        for d in r.get("details", []) or []:
            if not isinstance(d, dict):
                continue
            code = d.get("code")
            code_before = d.get("code_before")
            if code and code_before:
                both_present += 1
                if code == code_before:
                    identical += 1
                elif shown < 3:
                    print(f"\n--- example {shown+1} "
                         f"(target={d.get('target')}) ---")
                    print(f"code         [{len(str(code))} chars]: "
                          f"{snippet(code)}")
                    print(f"code_before  [{len(str(code_before))} chars]: "
                          f"{snippet(code_before)}")
                    print(f"llm_check: {snippet(d.get('llm_check'), 150)}")
                    print(f"static_check: {snippet(d.get('static_check'), 150)}")
                    print(f"static: {snippet(d.get('static'), 150)}")
                    shown += 1
            elif code and not code_before:
                only_code += 1
            elif code_before and not code:
                only_before += 1
            else:
                neither += 1

    print(f"\nboth code and code_before present : {both_present:,}")
    print(f"  of which identical (suspicious)   : {identical:,}")
    print(f"only code present                  : {only_code:,}")
    print(f"only code_before present           : {only_before:,}")
    print(f"neither present                    : {neither:,}")

    # -----------------------------------------------------------------
    head("3. WHEN ARE function_before / function_after NON-EMPTY?")
    fb_nonempty = 0
    fa_nonempty = 0
    fb_example = None
    for r in recs:
        for d in r.get("details", []) or []:
            if not isinstance(d, dict):
                continue
            fb = d.get("function_before")
            fa = d.get("function_after")
            if fb:
                fb_nonempty += 1
                if fb_example is None:
                    fb_example = fb
            if fa:
                fa_nonempty += 1

    print(f"details[] with non-empty function_before: {fb_nonempty:,}")
    print(f"details[] with non-empty function_after : {fa_nonempty:,}")
    if fb_example is not None:
        print(f"\nExample non-empty function_before (type "
              f"{type(fb_example).__name__}):")
        print(json.dumps(fb_example, indent=2, default=str)[:1500])
    else:
        print("\nNever non-empty in this sample — function_before/"
              "function_after may only populate for a subset of records "
              "(e.g. multi-function diffs) not represented in the first "
              f"{N_SAMPLE}. Try increasing N_SAMPLE if code/code_before "
              "coverage above also looks incomplete.")

    # -----------------------------------------------------------------
    head("4. QUALITY-FLAG FIELDS — llm_check / static_check / static")
    llm_vals = Counter()
    static_check_types = Counter()
    static_keys_seen = set()
    for r in recs:
        for d in r.get("details", []) or []:
            if not isinstance(d, dict):
                continue
            llm_vals[snippet(d.get("llm_check"), 60)] += 1
            static_check_types[type(d.get("static_check")).__name__] += 1
            sc = d.get("static")
            if isinstance(sc, dict):
                static_keys_seen.update(sc.keys())

    print("llm_check value samples (top 10):")
    for v, n in llm_vals.most_common(10):
        print(f"  {n:>5}  {v}")
    print(f"\nstatic_check field types seen: {dict(static_check_types)}")
    print(f"static{{}} sub-keys seen across sample: {sorted(static_keys_seen)}")

    # -----------------------------------------------------------------
    head("5. CWE COUNT PER RECORD")
    cwe_counts = Counter()
    for r in recs:
        c = r.get("cwe_id")
        n = len(c) if isinstance(c, list) else (1 if c else 0)
        cwe_counts[n] += 1
    print(f"Number of CWEs per record: {dict(sorted(cwe_counts.items()))}")

    # -----------------------------------------------------------------
    head("6. RECOMMENDATION")
    if both_present > 0 and identical < both_present * 0.5:
        print("code and code_before are both present and usually differ —")
        print("consistent with 'code_before' = pre-patch (vulnerable) and")
        print("'code' = post-patch (fixed), IF that naming convention holds.")
        print("This still needs a human read of the 3 examples printed in")
        print("section 2 before trusting it — 'before/after' could equally")
        print("mean 'before/after some OTHER transformation, not the fix'.")
    if fb_nonempty == 0:
        print("\nfunction_before/function_after are empty throughout this")
        print("sample. The loader should be rewritten to extract from")
        print("code/code_before at the details[] level instead, once the")
        print("semantics above are confirmed by reading the examples.")


if __name__ == "__main__":
    main()
