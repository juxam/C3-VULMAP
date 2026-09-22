"""
11b_diagnose_leftover_tags.py - are the 7,253 "leftover tag" rows genuine
cleaning failures, or false positives from an unanchored substring check?

11's check (pc.match_substring_regex) flags any row where <filename>,
<reponame>, or <gh_stars> appears ANYWHERE in the text. Across 14.8M C/C++
files scraped from all of GitHub, some of that code is plausibly ABOUT
parsing/generating this exact StarCoder tag format - a comment, a string
literal, someone's own data-processing tool - which would hit an unanchored
substring search without being a cleaning failure at all.

The check that actually matters: does `code` still match the prefix regex
ANCHORED at the start? That's the only thing that means stripping genuinely
failed. This re-applies PREFIX_RE.match (the same regex 10_load_starcoder_
tier2.py used to clean in the first place) to every flagged row and splits
them into:

    genuine_leftover   - code STILL matches the anchored prefix regex.
                         A real cleaning miss - a tag format that survived.
    tag_in_content     - substring present, but NOT at the start. Likely
                         real code content that happens to mention these
                         tokens, not a cleaning failure.

Fast: only re-examines the ~7,253 already-flagged rows, not the full 14.8M.

Run:  python 11b_diagnose_leftover_tags.py > diagnose_leftover.txt 2>&1
"""

import re

import pyarrow.compute as pc
import pyarrow.parquet as pq

import config

SEP = "=" * 72

# Identical to 10_load_starcoder_tier2.py's PREFIX_RE - re-used deliberately
# so this checks against the EXACT rule that did the original cleaning, not
# a redefinition that could silently drift from it.
PREFIX_RE = re.compile(
    r"^(?:<reponame>(?P<repo>.*?))?(?:<filename>(?P<path>.*?))?"
    r"(?:<gh_stars>(?P<stars>[^\n]*?))?\n",
    re.S,
)


def head(t):
    print(f"\n{SEP}\n{t}\n{SEP}")


def main():
    outdir = config.ensure_output_dir()
    path = outdir / "starcoder_tier2.parquet"

    head("1. RE-ISOLATE THE FLAGGED ROWS")
    table = pq.read_table(path, columns=["code", "source_id"])
    has_tag = pc.match_substring_regex(
        table.column("code"), r"<reponame>|<filename>|<gh_stars>")
    flagged = table.filter(has_tag)
    print(f"Flagged by the unanchored substring check: {flagged.num_rows:,}")

    head("2. CLASSIFY: GENUINE CLEANING MISS vs TAG MENTIONED IN CONTENT")
    genuine = []
    in_content = []
    for i in range(flagged.num_rows):
        code = flagged.column("code")[i].as_py()
        sid = flagged.column("source_id")[i].as_py()
        if PREFIX_RE.match(code):
            genuine.append((sid, code))
        else:
            in_content.append((sid, code))

    n_genuine = len(genuine)
    n_content = len(in_content)
    print(f"genuine_leftover (still matches anchored at start): "
          f"{n_genuine:,} ({n_genuine/max(flagged.num_rows,1):.1%} of "
          f"flagged)")
    print(f"tag_in_content (substring present, not at start)  : "
          f"{n_content:,} ({n_content/max(flagged.num_rows,1):.1%} of "
          f"flagged)")

    head("3. EXAMPLES")
    if genuine:
        print("genuine_leftover examples (real cleaning misses):")
        for sid, code in genuine[:10]:
            print(f"  id={sid}: {code[:180]!r}")
    else:
        print("No genuine leftover-at-start cases found in this run.")

    if in_content:
        print("\ntag_in_content examples (tag mentioned mid-file, not a "
              "cleaning failure):")
        for sid, code in in_content[:5]:
            idx = min((code.find(t) for t in
                      ("<reponame>", "<filename>", "<gh_stars>")
                      if code.find(t) >= 0), default=-1)
            context = code[max(0, idx - 60):idx + 100] if idx >= 0 else code[:160]
            print(f"  id={sid}, tag found at position {idx}: ...{context!r}...")

    head("4. VERDICT")
    print(f"Real, current leftover-tag rate: {n_genuine:,} / "
          f"{table.num_rows:,} ({n_genuine/max(table.num_rows,1):.4%})")
    print(f"False-positive rate from the original unanchored check: "
          f"{n_content:,} / {flagged.num_rows:,} "
          f"({n_content/max(flagged.num_rows,1):.1%} of what was flagged)")
    if n_genuine == 0:
        print("\nZero genuine cleaning failures. The 7,253 figure was "
              "entirely false positives from an imprecise check — the "
              "stripping regex is correct as written, no fix needed. "
              "Safe to treat starcoder_tier2.parquet as final.")
    elif n_genuine < 100:
        print(f"\n{n_genuine} genuine misses out of 14.8M rows is a "
              f"negligible rate ({n_genuine/table.num_rows:.5%}) — worth "
              f"noting in CONSTRUCTION.md as a known, tiny residual rather "
              f"than blocking release, unless the examples above reveal an "
              f"easy additional pattern worth handling.")
    else:
        print(f"\n{n_genuine} genuine misses is enough to look for a "
              f"pattern in the examples above — likely a tag variant "
              f"(different ordering, a typo'd tag name, or something "
              f"BigCode's format changed between shards) worth adding to "
              f"the regex before calling this file final.")


if __name__ == "__main__":
    main()
