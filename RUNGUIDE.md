# C3-VULMAP v2 — build guide

Every script below is tested end to end against fixtures matching each
source's documented schema. What isn't tested is the *exact* file layout the
ReposVul Google Drive download unpacks to — that's genuinely unknown until
you look, which is why step 1 is an inspection step, not a parse step.

Put everything in one folder and run from there, same as the revision
scripts — `import config` silently resolves to a PyPI package of the same
name if you're not in the right directory, and every script will fail with
a confusing `AttributeError` if that happens. Confirm you're picking up the
right file before starting:

```powershell
mkdir C:\Users\judea\c3vulmap_v2
cd C:\Users\judea\c3vulmap_v2
python -c "import config; print(config.__file__)"
```

Should print a path inside `c3vulmap_v2`, not `site-packages`.

---

## Step 0 — download ReposVul

C++ split, from the README:
```
https://drive.google.com/file/d/1jYwIOXJUHhbTA0UkKVLQYyuxKBlv2kKO/view?usp=drive_link
```

Save it under `Dataset\ReposVul\` and update `config.REPOSVUL_PATH` to match
whatever it's actually called once downloaded.

## Step 1 — inspect ReposVul's real structure

```powershell
python 00_inspect_reposvul.py > inspect_reposvul.txt 2>&1
```

Send me this output if the structure printed in section 4 doesn't match what
`02_load_reposvul.py`'s docstring describes (nested `details[]` with
`function_before`/`function_after`). If it matches, skip straight to step 3.

## Step 2 — complete the LINDDUN mapping table

Copy `cwe_linddun_mapping_SEED.csv` to the path in
`config.CWE_LINDDUN_TABLE`, then add rows from **UseMisuse Cases vs CWE
Category.pdf**. The seed has only the 10 example mappings quoted in
`dataset_description.md` — nowhere near your full 776-CWE catalog. You don't
need this complete before running the pipeline once (step 6 will report
exactly which CWEs are still unmapped, ranked by how many rows they affect)
but don't treat a low-coverage run as final.

## Step 3 — drop in your synthetic code

Either layout works — see the docstring at the top of `01c_load_synthetic.py`:
- `synthetic_v2/vulnerable/CWE-XXX/*.c` and `synthetic_v2/safe/*.c`, or
- one `synthetic_v2/*.json` with `code`, `label`, `cwe_id`,
  `generation_method` per record.

Set `config.SYNTHETIC_DIR` accordingly.

## Step 4 — load each source

```powershell
python 01_load_diversevul.py
python 02_load_reposvul.py
python 01c_load_synthetic.py
```

Each prints row counts and vulnerable rate — sanity-check these against what
you expect before moving on. `02_load_reposvul.py` will refuse to run with
zero extracted rows and tell you to fix `extract_functions()` rather than
silently producing an empty output.

## Step 5 — merge and deduplicate

```powershell
python 03_merge_and_dedupe.py
```

Reads whichever of the three loader outputs exist — you don't have to run
all three sources every time. Watch `conflicting_dropped`: this is the
count of rows where identical code appeared with different labels across
sources, and all copies get dropped rather than picking one arbitrarily.

## Step 6 — apply the LINDDUN mapping

```powershell
python 04_apply_linddun.py
```

Prints coverage and writes `unmapped_cwes.csv` ranked by impact — the CWEs
worth prioritising when filling in the table from the PDF are at the top of
that file, not scattered through 776 entries.

## Step 7 — contamination screen

```powershell
python 05_contamination_screen.py
```

This is the check the old corpus never had before release. Read
`contamination_flagged.csv` if anything above 2% shows up, especially in
`diversevul` or `reposvul` — real code containing a flagged string might be
legitimate (credential-handling functions do exist), so this needs a human
look, not an automatic drop.

## Step 8 — build splits

```powershell
python 06_build_splits.py
```

Two-phase: test is carved out first with full pair/project awareness (no
ReposVul before/after pair or DiverseVul project can span train and test),
then val is carved from what's left by ordinary stratified sampling. Watch
for the prevalence-gap warning — if test's prevalence differs from the
corpus average by more than 3 points, the script explains why (source
density mismatch) rather than leaving it unexplained; report per-partition
prevalence in the paper's dataset table rather than assuming they match.

## Step 9 — validate before anything downstream touches this

```powershell
python 07_validate_and_package.py > validate_release.txt 2>&1
```

Three checks, each a direct callback to a specific failure this project
found: metadata-only separability (the old corpus's 0.71 AUROC baseline),
whether `is_synthetic` or `source_dataset` is acting as a label proxy (the
old corpus's 100%-of-synthetic-was-vulnerable problem), and the
contamination rate from step 7. Writes `RELEASE_MANIFEST.json` — generate
the GitHub README's dataset-statistics table from this file, not by hand,
so the two can never drift apart.

**Send me `validate_release.txt` before doing anything else with this
corpus** — feature extraction, training, or publishing. If either of the
first two checks comes back looking like the old corpus's failure modes,
better to catch it here than after a GPU run.

---

## What happens after validation clears

Once `07` looks clean, the next stage is feature extraction and model
retraining — same shape as the DiverseVul-only rebuild's `12_extract_corpus.py`
and `13_train_binary_512d.py`, adapted to read `corpus_final.parquet`'s
`split_project`/`split_random` columns instead. I'll write those once I see
the validation output, since whether anything needs adjusting depends on
what that run actually shows — no point designing the next stage around a
guess at numbers I haven't seen.

## For the GitHub release itself

`RELEASE_MANIFEST.json` plus a short `CONSTRUCTION.md` explaining the
pipeline (source list, dedup method, split method, LINDDUN mapping
methodology, contamination screen) is what makes this update to the repo
different from the original — a reader can see exactly how the corpus was
built and rerun it themselves. I can draft `CONSTRUCTION.md` once the real
`RELEASE_MANIFEST.json` exists, since it should describe what actually
happened, not what was planned to happen.
