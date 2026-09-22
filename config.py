"""
config.py — every path and constant for the C3-VULMAP v2 rebuild.

Fill in the paths in Section 1, then run the scripts in numeric order — see
RUNGUIDE.md for the full sequence and what to check at each step.

Design principle carried through the whole pipeline: provenance is a first-
class column from the moment a row is created, never bolted on afterward.
Every row entering the unified schema knows which source it came from, which
project/commit if real, and which generation method if synthetic — because
the old corpus's central defect was that this information existed at
construction time and was discarded before release.
"""

from pathlib import Path

# =====================================================================
# 1. PATHS — EDIT THESE
# =====================================================================

DATASET = Path("/Volumes/seagate backup plus/FRESH DATASET")

# DiverseVul — already on disk, confirmed schema (func, target, project,
# commit_id, cwe, hash, size, message).
DIVERSEVUL_PATH = DATASET / "DiverseVul" / "diversevul_20230702.json"

# ReposVul — download the C++ split from the link in the README:
#   https://drive.google.com/file/d/1jYwIOXJUHhbTA0UkKVLQYyuxKBlv2kKO
# Format on disk is unknown until you look — could be one JSON file, JSONL,
# or a zip of per-CVE files. Run 00_inspect_reposvul.py FIRST and fix this
# path (and the loader in 02_load_reposvul.py if needed) before parsing.
#
# IF YOU EDIT THIS TO A FULL WINDOWS PATH: prefix the string with r before
# the opening quote — r"C:\Users\..." — or use forward slashes instead:
# "C:/Users/judea/...". A plain "C:\Users\..." string crashes with a
# SyntaxError the moment the path contains \U, \n, \t or similar, because
# Python reads those as escape sequences, not literal backslash-letter pairs.
# Safest option: keep using the DATASET / "sub" / "file" pattern below —
# each piece is a plain name with no backslashes in it, so this problem
# can't happen.
REPOSVUL_PATH = DATASET / "ReposVul" / "ReposVul_cpp.jsonl"

# The CWE -> LINDDUN mapping is now a TWO-HOP chain, not a single table —
# discovered when the file at this path turned out to be MITRE's own CWE
# category taxonomy (40 rows, one per official CWE category, each packing
# every member CWE into a newline-delimited list), not a per-CWE LINDDUN
# table. That's actually useful: it gives CWE -> CATEGORY for most of the
# 776 canonical CWEs from one file, and shrinks the real transcription task
# down to ~40 category names against the PDF instead of 776 individual CWEs.
#
# Hop 1: CWE_CATEGORY_RAW_PATH (this file, as-is) -> parsed by
#        03c_parse_cwe_categories.py into a flat cwe_category_map.csv
#        (CWE -> category name), plus a ready-to-fill seed for hop 2.
# Hop 2: CWE_CATEGORY_TO_LINDDUN_TABLE (~40 rows, category name ->
#        LINDDUN category) -> you fill this in from "UseMisuse Cases vs
#        CWE Category.pdf", validated by 03b_validate_linddun_table.py.
# 04_apply_linddun.py joins both hops to get CWE -> LINDDUN.
CWE_CATEGORY_RAW_PATH = Path(__file__).parent / "cwe_linddun_mapping main.csv"
CWE_CATEGORY_TO_LINDDUN_TABLE = Path(__file__).parent / "actual mapping to linddun.csv"

# Your new synthetic code. One function per file, or one JSON/JSONL with a
# `code` field per entry — 01c_load_synthetic.py handles both; see its
# docstring for the exact expected shape. Same backslash warning if hand-edited.
SYNTHETIC_DIR = DATASET / "synthetic_v2"

# Overridden to a separate local path, not DATASET-relative like the other
# paths above - raw sources (DiverseVul/ReposVul/StarCoder/synthetic_v2,
# all still resolved via DATASET) live on the read-only external drive,
# while build outputs need to be somewhere actually writable, on the
# internal disk. These are no longer siblings under one common root the
# way they were on the original Windows machine.
OUTPUT_DIR = Path("/Users/judeameh/c3vulmap_v2_data/c3vulmap_v2_build")
FEATURES_CACHE = OUTPUT_DIR / "features_512d.npy"   # filled in later, not by this pipeline

# =====================================================================
# 2. DEDUPLICATION AND SPLITS
# =====================================================================

# Functions with this many normalised-whitespace characters or fewer are
# almost never meaningful (stubs, forward declarations, one-liners) and
# inflate near-duplicate rates without adding signal.
MIN_CODE_CHARS = 40

TEST_FRAC = 0.20
VAL_FRAC = 0.10
SEED = 42

# Near-duplicate threshold for the leakage check (Jaccard over 5-token
# shingles). Verified in this conversation: pure reformatting -> 1.0,
# genuine multi-identifier renaming -> ~0.4. 0.7 sits strictly between.
NEAR_DUP_THRESHOLD = 0.70

# =====================================================================
# 3. CONTAMINATION SCREEN
# =====================================================================
# Same patterns that caught the old corpus's synthetic leakage, tightened
# after the false-positive check in this conversation (no bare "secret",
# no bare "is_bad" match). Applied to the WHOLE v2 corpus including your
# new synthetic contribution — the point is to catch this earlier next time,
# not to assume it can't happen again.

import re  # noqa: E402

CONTAMINATION_PATTERNS = {
    "juliet_stonesoup": re.compile(
        r"badSink|goodSink|goodG2B|goodB2G|CWE\d{2,4}_[A-Za-z]|stonesoup", re.I),
    "toy_secret_leaky": re.compile(
        r"(?:my|super|stored|saved|admin)_?secret|secret_?(?:password|passwd)|"
        r"supersecret", re.I),
    "toy_user_leaky": re.compile(
        r"john_?doe|input_?username|input_?password|authenticate_?user\b|"
        r"my_?password", re.I),
    "self_naming_leaky": re.compile(
        r"vulnerable_?(?:function|code|buffer)|insecure_?func|bad_?buffer|"
        r"process_?sensitive", re.I),
}


# -----------------------------------------------------------------------
# Guard against hand-edited paths losing their Path(...) wrapper.
#
# This has now bitten twice: REPOSVUL_PATH once crashed on a raw backslash
# string (missing r"..." prefix), and CWE_LINDDUN_TABLE once silently became
# a plain str (probably from a direct assignment made before or instead of
# the Path(...) version above), which doesn't fail until something calls
# .exists() on it three scripts later. Rather than rely on every path being
# hand-typed correctly, every path-like variable below is coerced to a real
# Path here, once, regardless of how it was written above — a plain string,
# a raw string, or an actual Path all end up the same.
for _name in ("DATASET", "DIVERSEVUL_PATH", "REPOSVUL_PATH",
             "CWE_CATEGORY_RAW_PATH", "CWE_CATEGORY_TO_LINDDUN_TABLE",
             "SYNTHETIC_DIR", "OUTPUT_DIR",
             "FEATURES_CACHE"):
    _val = globals().get(_name)
    if _val is not None and not isinstance(_val, Path):
        globals()[_name] = Path(_val)
del _name, _val


def ensure_output_dir():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR
