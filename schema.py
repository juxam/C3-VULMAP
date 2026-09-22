"""
schema.py — the ONE unified row format every loader produces.

Every source (DiverseVul, ReposVul, your new synthetic code) gets converted
into rows with exactly these columns. Nothing downstream ever branches on
source type — it just reads these columns. That's what makes dedup, the
LINDDUN mapping, the contamination screen, and the splits source-agnostic.

    code            str    the function text, unmodified
    label           int    1 = vulnerable, 0 = not
    source_dataset  str    "diversevul" | "reposvul" | "synthetic_v2"
    project         str    repo identifier, or None if unavailable
    commit_id       str    or None
    commit_date     str    ISO date if known, else None
    file_path       str    or None
    cwe_id          str    normalised "CWE-NNN", or None
    is_synthetic    bool
    generation_method str  None for real code; a short tag for synthetic
                           (e.g. "gpt-4o-controlled-naming-v1") so different
                           synthetic batches stay distinguishable
    pair_id         str    or None. Set for ReposVul before/after pairs so
                           the two sides of one commit are forced into the
                           SAME split partition — otherwise a near-identical
                           pair split across train/test is a leakage channel
                           of exactly the kind this whole rebuild exists to
                           close.

code_hash is computed once, centrally, in 03_merge_and_dedupe.py — not per
loader — so the normalisation is guaranteed identical everywhere it's used.
"""

import re

COLUMNS = [
    "code", "label", "source_dataset", "project", "commit_id", "commit_date",
    "file_path", "cwe_id", "is_synthetic", "generation_method", "pair_id",
]

CWE_RE = re.compile(r"CWE[-_]?(\d+)", re.I)


def normalise_cwe(raw):
    """Accepts 'CWE-119', 'CWE_119', '119', 119, "['CWE-119']", None."""
    if raw is None:
        return None
    m = CWE_RE.search(str(raw))
    if m:
        return f"CWE-{m.group(1)}"
    if str(raw).strip().isdigit():
        return f"CWE-{raw}"
    return None


def make_row(code, label, source_dataset, project=None, commit_id=None,
             commit_date=None, file_path=None, cwe_id=None,
             is_synthetic=False, generation_method=None, pair_id=None):
    return {
        "code": code,
        "label": int(label),
        "source_dataset": source_dataset,
        "project": project,
        "commit_id": commit_id,
        "commit_date": commit_date,
        "file_path": file_path,
        "cwe_id": normalise_cwe(cwe_id),
        "is_synthetic": bool(is_synthetic),
        "generation_method": generation_method,
        "pair_id": pair_id,
    }


def validate_rows(rows, source_name):
    """Cheap sanity check every loader should call before returning."""
    if not rows:
        raise ValueError(f"{source_name}: produced zero rows")
    bad_label = [r for i, r in enumerate(rows) if r["label"] not in (0, 1)]
    if bad_label:
        raise ValueError(f"{source_name}: {len(bad_label)} rows with a label "
                         f"outside {{0,1}}")
    empty_code = sum(1 for r in rows if not r["code"] or not str(r["code"]).strip())
    if empty_code:
        raise ValueError(f"{source_name}: {empty_code} rows with empty code")
    for c in COLUMNS:
        missing = [r for r in rows if c not in r]
        if missing:
            raise ValueError(f"{source_name}: {len(missing)} rows missing "
                             f"column '{c}'")
    n_vuln = sum(r["label"] for r in rows)
    print(f"  {source_name}: {len(rows):,} rows, {n_vuln:,} vulnerable "
          f"({n_vuln/len(rows):.1%})")
    return True
