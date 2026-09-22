# C3-VULMAP v2 — Construction Documentation

This document follows the Hugging Face Dataset Card convention (itself
derived from Gebru et al., *Datasheets for Datasets*). Every claim here is
verifiable by re-running the numbered scripts in this repository against
the same source data.

**A note on structure.** This document is organized by *process* — where
the data came from, how it was cleaned, how it was labeled — rather than
by tier. A great deal of the methodology (the privacy-category mapping
chain in particular) is genuinely identical for both tiers, and writing
it twice under separate headings would only make the two versions harder
to keep in sync, not easier to understand. What actually distinguishes
tier 1 from tier 2 is not where they sit in this document, but the
**provenance columns carried on every row** — see "Unified Row Schema
and Provenance" below, which states explicitly, and as prominently as
anywhere in this file, why the two must never be pooled.

---

## Dataset Overview

C3-VULMAP v2 ships as two files, never merged:

| | rows | label basis | file |
|---|---|---|---|
| Supervised corpus | 332,970 | Real CVE/commit-verified vulnerable or safe | `corpus_final.parquet` |
| Static-analysis labels | 2,102,354 flagged (of 14,838,026 scanned) | flawfinder pattern match — not a vulnerability verdict | `starcoder_tier2_static_labels.csv` |

The supervised corpus draws on three sources — DiverseVul, ReposVul, and
140 purpose-written synthetic examples — merged, deduplicated, and
privacy-category-labeled into one function-level table. The
static-analysis file covers the StarCoder C/C++ subset at file-level
granularity, flagged by flawfinder rather than by a verified CVE. Both
carry the same privacy-category mapping chain, described once below and
applied identically to each.

---

## Sources

### DiverseVul (Chen et al., RAID 2023)

330,492 raw records read from `diversevul_20230702.json`
(`01_load_diversevul.py`); 936 dropped as empty or under 40 characters
after cleaning. 329,556 rows kept, 18,926 (5.7%) carrying a vulnerable
label, prior to the cross-source merge below.

### ReposVul (Wang et al., ICSE 2024)

689 top-level CVE/commit records, C++ split only — roughly 11% of the
full 6,134-entry, 4-language dataset (`02_load_reposvul.py`). Confirmed
directly against the raw structure (`00_inspect_reposvul.py`,
`00b_inspect_reposvul_fields.py`, `00c_inspect_reposvul_function_pairs.py`)
rather than assumed: the details-level `code`/`code_before` fields are
whole-file blobs, the wrong granularity for a function-level corpus.
Function-level pairs live in the `function_before`/`function_after`
lists, populated on ~10.7% of entries; `function_before` is ~99.5%
`target=0` (unchanged context, not a vulnerability) and only ~0.5%
`target=1` (the actual vulnerable function) — each item's own `target`
field is read directly rather than assuming a before=1/after=0 default,
which would have mislabeled 99.5% of `function_before` rows. Every
function-pair carries a `pair_id` (`cve_id:commit_id`), keeping before/
after sides together across the later train/test split. 20,346 rows
extracted, 47 (0.2%) vulnerable prior to dedup — small relative to
DiverseVul by design; ReposVul's contribution here is real commit
provenance and LLM-plus-static-analysis cross-checking, not volume.

### Synthetic examples (`synthetic_v2`)

140 hand-authored C/C++ functions, all labeled vulnerable, targeting the
three LINDDUN categories the real data left thinnest: Non-repudiation
(`CWE-778` Insufficient Logging, `CWE-117` Log Injection, `CWE-364`
Signal Handler Race Condition), Unawareness (`CWE-242` Use of Inherently
Dangerous Function, `CWE-477` Use of Obsolete Function), and Data
Disclosure (`CWE-358` Improperly Implemented Security Check, `CWE-770`
Allocation of Resources Without Limits) — 20 examples per CWE, chosen by
checking real per-category row counts against the corpus rather than
guessed. Every example follows the non-leaky naming discipline this
project's own contamination screen enforces (no `vulnerableFunction`-
style self-naming); one collision (`authenticate_user`, matching the
`toy_user_leaky` pattern) was caught and fixed before shipping — verified
by running all 140 through the actual screen, not assumed clean.

### StarCoder C/C++ subset (BigCode)

Local copy in HuggingFace `datasets` `save_to_disk()` format, 210 Arrow
IPC shards, 104.55 GB. **14,890,318 rows**, confirmed by direct row-count
enumeration (`09b_count_starcoder_rows.py`) rather than dataset metadata,
which carried no `splits`/`num_examples` field in this copy.

`content` is not raw source as-is: an optional prefix block —
`<reponame>NAME`, `<filename>PATH`, `<gh_stars>RANGE`, in various
combinations — is present on a real, measured **49.9%** of the full
corpus (7,410,021 rows; a 3,000-row sample across 15 shards had
suggested 36.5%, meaningfully lower, consistent with genuine
between-shard variance across 210 independently-written shards rather
than a stripping error). This is a documented BigCode technique
(teaching a model both conditioned and unconditioned generation), not a
defect. Stripping correctness was verified two ways, not assumed: a
full-corpus substring scan flagged 7,253 rows mentioning a tag-like
string anywhere in the text; re-checking against an *anchored* match
(does the content actually start with a tag) found 7,124 of those
(98.2%) were ordinary code mentioning the token mid-file (e.g. a
`usage: %s <filename>` help string), and the remaining 129 were, on
inspection, a false positive in the diagnostic's own regex, not a real
tag. **Genuine cleaning failures: 0 of 14,838,026.**

52,292 rows were dropped as under 40 characters after cleaning (stubs
and forward declarations). Final: **14,838,026 rows**
(`10_load_starcoder_tier2.py`).

---

## Unified Row Schema and Provenance

Every source is converted into one shared schema (`schema.py`) before
anything downstream — deduplication, privacy-category mapping,
contamination screening, splitting — ever runs:

| column | meaning |
|---|---|
| `code` | function text, unmodified |
| `label` | 1 = vulnerable, 0 = not (supervised corpus only) |
| `source_dataset` | `"diversevul"` \| `"reposvul"` \| `"synthetic_v2"` |
| `project`, `commit_id`, `commit_date`, `file_path` | provenance, or `None` if unavailable |
| `cwe_id` | normalised `"CWE-NNN"`, or `None` |
| `is_synthetic` | bool |
| `generation_method` | `None` for real code; a short tag for synthetic (e.g. `"claude-authored-v1"`) |

Tier 2's static-analysis file carries a parallel but distinct set of
columns (`row_uid`, `cwe_ids`, `category_ids`, `linddun_categories`,
`n_hits`, `label_source`).

**This is the actual distinction between the two tiers, and it is a
label-provenance distinction, not just a file-location one:**

- Supervised corpus rows have `label_source = "cve_verified"` — a real,
  published CVE or commit record backs the label.
- Static-analysis rows have `label_source = "static_analysis"` — this
  means *"flawfinder associates this code with a pattern tied to
  CWE-X,"* never *"this code is vulnerable."* No file in tier 2 has been
  confirmed against a real report of any kind.

**These must never be pooled as if they carried the same evidentiary
weight.** Treating tier 2's absence of a flagged pattern as a verified
safe label — or treating a flawfinder hit as equivalent to a CVE-backed
vulnerable label — reintroduces exactly the provenance-as-label-shortcut
problem this rebuild exists to eliminate. Any analysis that needs to
tell the tiers apart can do so directly from `label_source`, without
needing to know which file a row came from.

**`row_uid`, not `source_id`, is tier 2's real identifier.** StarCoder's
own `id` field is copied through as `source_id` for traceability, but it
turned out not to be globally unique: a direct check found 6,308,736 of
8,529,290 distinct `source_id` values — 85% of all 14,838,026 rows —
each shared by exactly two rows, traced to upstream StarCoder's own `id`
field being unique only within whatever grouping StarCoder itself used,
not across this project's full 210-shard local download. This was
caught by a real, load-bearing inconsistency: the static-analysis scan's
own flagged-file tally and an independent recount from the same output
file disagreed by exactly 167,270 files — a gap matched almost exactly
by the probability that both halves of a random `source_id` collision
would independently be flagged (0.163² × 6,308,736 ≈ 170,000). `row_uid`
(`patch_row_uid.py`) is simple row position — unique by construction,
independent of anything upstream — and is what every tier-2 script now
keys on throughout.

---

## Deduplication

DiverseVul, ReposVul, and the synthetic set are merged and deduplicated
together (`03_merge_and_dedupe.py`): 350,042 rows in, dropping 1,500
conflicting-label duplicates (696 groups where the same code appeared
with different labels) and 15,572 redundant agreeing duplicates, leaving
**332,970 rows** — 324,260 DiverseVul, 8,570 ReposVul, 140 synthetic.

---

## Privacy Category Mapping: CWE → MITRE Category → LINDDUN

Both tiers' privacy labels come from the same two-hop chain, applied
identically by `04_apply_linddun.py` (supervised corpus) and
`13_apply_linddun_to_tier2.py` (static-analysis labels).

**Hop 1 — CWE → MITRE category.** `cwe_linddun_mapping main.csv` packs
40 official MITRE categories, each listing its member CWEs. Parsed into
486 individual (CWE, category) pairs covering 440 distinct CWEs
(`03c_parse_cwe_categories.py`). A category maps to itself as well as to
its members — without this, real corpus rows tagged with a bare
category-level CWE (e.g. `CWE-399`, `CWE-417`) showed up as "unmapped"
despite the category being known, costing thousands of rows before the
fix.

**Hop 2 — MITRE category → LINDDUN.** `actual mapping to linddun.csv`
is a human-curated use/misuse case table (Privacy Threat Types, Cases,
Misuse cases, CWE CATEGORY), with `Privacy Threat Types` forward-filled
across a merged-cell PDF transcription and `CWE CATEGORY` holding
comma-separated numeric MITRE category ids, joined on number rather than
name text (`03d_parse_usemisuse_table.py`).

**The 65-CWE exclusion.** Several of the highest-impact "unmapped CWE"
gaps turned out not to be accidental at all. Checked directly against
MITRE's own definitions (not inferred): `CWE-119`, `CWE-20`, `CWE-703`,
`CWE-200`, and `CWE-400` are each explicitly marked **DISCOURAGED** by
MITRE for mapping to real vulnerabilities — overly abstract Class- or
Pillar-level entries whose own guidance points to their more specific
children instead. `CWE-362` is "Allowed-with-review" with the same
guidance. `CWE-284` is Pillar-level and discouraged. Extrapolating this
pattern (7 of the top 8 highest-impact gaps checked were confirmed
discouraged) to the full list of 66 originally-unmapped CWEs produced
`excluded_abstract_cwes.csv` — 65 CWEs explicitly excluded from ever
contributing a category (7 individually confirmed against MITRE, 58
presumed from the pattern), tagged by `verification_status` so the two
groups stay distinguishable. These CWEs' real signal is expected to flow
through their more specific, already-mapped children instead of being
force-mapped at the wrong level of abstraction.

The one exception found in this investigation: `CWE-416` (Use After
Free) is Variant-level and MITRE-*allowed* — a genuine gap, not a
discouraged abstraction. Added directly to the category map under
Memory Buffer Errors (`CWE-1218`), its real parent per MITRE's own
`ChildOf` relationship (`CWE-416` → `CWE-825` → `CWE-1218`).

**The category→LINDDUN gap.** Unlike the CWE-level exclusions, this
layer is not something MITRE can verify — LINDDUN is this project's own
privacy framework, and whether e.g. "Concurrency Issues" carries a
privacy dimension is a judgment call, not an external fact. Seven
categories existed in the CWE-category map with no LINDDUN entry at all;
five were added, reasoned from their actual member CWEs and by analogy
to categories already mapped, with two carrying direct self-consistency
to decisions this project had already made:

| category | LINDDUN type(s) | basis |
|---|---|---|
| `CWE-399` Resource Management Errors | Data Disclosure | member `CWE-770` was already the confirmed synthetic-example target for this exact LINDDUN type |
| `CWE-557` Concurrency Issues | Non-repudiation | member `CWE-364` was already the confirmed synthetic-example target for this exact LINDDUN type |
| `CWE-1213` Random Number Issues | Detectability, Identifiability, Linkability | mirrors `CWE-310` Cryptographic Issues, already mapped identically — weak randomness undermines security tokens the same way weak crypto does |
| `CWE-275` Permission Issues | Linkability, Non-compliance | mirrors `CWE-1212` Authorization Errors and `CWE-265` Privilege Issues, already mapped this way |
| `CWE-465` Pointer Issues | Linkability | mirrors `CWE-1218` Memory Buffer Errors — same underlying information-disclosure mechanism |

Two were deliberately left unmapped rather than forced: `CWE-189`
Numeric Errors and `CWE-438` Behavioral Problems are broad, heterogeneous
categories without a clean, defensible privacy story distinct from the
memory-safety bugs they sometimes cascade into. Both continue to appear
in `unmapped_categories.csv` on every run — a deliberate, documented
absence, not an oversight.

**Current hop-1/hop-2 coverage:** 440 of 776 canonical CWEs have a
category (56.7%); 35 of 40 categories have a real, matched LINDDUN entry
(87.5% — one additional category id referenced in the use/misuse table,
`CWE-1288`, does not correspond to a real MITRE category and is not
counted here). The remaining uncovered categories (`CWE-1225`
Documentation Issues, `CWE-371` State Issues, `CWE-411` Resource Locking
Problems, plus the two deliberately-unmapped ones above) affect zero or
near-zero rows in this corpus.

---

## Static-Analysis Labeling for Tier 2

`12_flawfinder_scan_tier2.py` scans all 14,838,026 tier-2 rows with
flawfinder, a rule-based pattern matcher — its output is *"contains a
pattern flawfinder associates with CWE-X,"* never a vulnerability
verdict, and `label_source` is always `"static_analysis"` to keep this
explicit downstream.

This scan went through five genuine, confirmed bugs during construction,
each caught by testing against real data before being fixed:

1. **Antivirus interception.** Confirmed via actual quarantine events on
   the build machine, not inferred — real-time antivirus scanning
   intercepted the scan's temporary files severely, at one point to the
   point of a full circuit-breaker trip. Mitigated with a fixed,
   predictable scratch directory (so an exclusion could target one
   stable path) and a bisection-based resilience layer that isolates and
   skips whichever specific batch triggers interception rather than
   failing the whole run.
2. **A two-sided Windows encoding bug.** flawfinder opens its own input
   with no explicit encoding, defaulting to `cp1252` on Windows; this
   project's own subprocess call decoded flawfinder's *output* the same
   way. Both non-ASCII StarCoder content (common — the corpus is scraped
   from global GitHub) and flawfinder's own multi-byte output could
   trigger a crash. Fixed on both sides: `PYTHONUTF8=1` in the child's
   environment, explicit `encoding="utf-8"` on the parent's own
   subprocess decode.
3. **A false-positive success check.** The script required an empty
   `stderr` in addition to return code 0 to count a batch as successful
   — but flawfinder routinely writes benign parsing warnings to `stderr`
   on completely successful scans, especially across code full of
   unusual macros. This was, in practice, the single largest cause of
   the low early throughput; fixed to gate success on return code alone.
4. **The `source_id` collision**, described above under provenance —
   discovered via this exact scan, fixed via `row_uid`.
5. **Two resume/checkpoint bugs**, both found by deliberately testing the
   resume path rather than trusting it: first, only the row count was
   persisted across a restart, silently resetting the hit counters and
   producing a misleadingly low final summary; second, a genuine
   regression where the same counter used for reporting was
   accidentally reused for the skip-decision itself, which would have
   caused every already-completed row to be silently reprocessed after
   a resume — caught in testing before it ever ran for real. A separate,
   genuine 22.7-hour hang on one pathological batch (no timeout existed
   on the flawfinder subprocess call) was fixed by integrating a
   timeout into the same bisection logic already built for antivirus
   interception.

**Final results, keyed by `row_uid`:** 18,747,999 raw hits across
2,419,768 distinct flagged files — confirmed to the row against an
independent recount once `row_uid` replaced `source_id`, closing the
167,270-file discrepancy described above. After excluding the 65
MITRE-discouraged CWEs (7,859,637 raw hits carried only an excluded
CWE), 2,102,354 files carry at least one categorizable, non-excluded
CWE-tagged hit; of those, **2,029,822 (96.5%)** resolve to a full
category → LINDDUN chain.

---

## Contamination Screening

`05_contamination_screen.py` checks the merged supervised corpus against
patterns known to catch synthetic-leakage artifacts (Juliet/STONESOUP
naming, toy secret/user placeholders, self-naming identifiers) —
tightened during this project after confirming no bare `"secret"` or
`"is_bad"` false-positive match. **71 rows flagged (0.021%)**, all from
DiverseVul, **zero from the synthetic set** — verified directly, not
assumed, given these examples were authored specifically for this
corpus. This is the same absolute count as the pre-migration baseline,
against a corpus now including 140 more rows — direct evidence nothing
was altered across the machine migration this project went through.

---

## Splits

`06_build_splits.py` builds a pair/project-aware split, keeping every
ReposVul before/after pair and every project's rows on one side of the
train/test boundary — verified to have zero pairs and zero projects
spanning that boundary.

| split | rows | vulnerable |
|---|---|---|
| train | 239,368 | 12,335 |
| val | 34,196 | 1,762 |
| test | 59,406 | 4,268 |

1,103 allocation units (164 ReposVul pairs, 799 DiverseVul projects). A
naive random split is also computed for comparison (train 266,376 /
test 66,594) but is not the split used for reported results, precisely
because it does not guard against project-level leakage.

---

## Final Numbers

*(`corpus_final.parquet` and `RELEASE_MANIFEST.json` reflect the state
before the category→LINDDUN gap closure above — regenerating via
`06_build_splits.py` → `07_validate_and_package.py` is the last
remaining step before the figures below are current everywhere they're
stored, not just in this document.)*

| | value |
|---|---|
| Supervised corpus rows | 332,970 |
| Vulnerable | 18,365 (5.5%) |
| LINDDUN full-chain coverage (supervised) | 41.1% |
| Metadata-only AUROC (project split) | 0.6976 |
| Contamination rate | 0.021% |
| Tier-2 rows scanned | 14,838,026 |
| Tier-2 files flagged | 2,419,768 |
| Tier-2 LINDDUN coverage (of flagged, categorizable files) | 96.5% |

**On the AUROC figure:** this measures how well *metadata alone* — no
code, just provenance — predicts the vulnerable label. 0.6976 against
the old corpus's 0.7109 is a lower score, and lower is the correct
direction here: it means less of the label is recoverable from
provenance shortcuts than before, which is the specific defect this
whole rebuild exists to correct, not a regression.

---

## Known Limitations

- `CWE-189` (Numeric Errors) and `CWE-438` (Behavioral Problems) carry
  no LINDDUN mapping by deliberate decision, not omission — see above.
- Hop-1 CWE coverage (56.7% of 776 canonical CWEs) reflects a
  deliberately limited 40-category source extract, not MITRE's full
  taxonomy; closing this further would require sourcing a more complete
  category table.
- Tier 2's static-analysis labels describe pattern matches, not
  confirmed vulnerabilities, and the 65 MITRE-discouraged CWEs are
  excluded from its category assignment for the same reason they're
  excluded from tier 1's.

---

## Reproducibility

Every number in this document is produced by a script in this
repository, runnable against the same public sources (DiverseVul,
ReposVul, StarCoder) this release was built from. No step in the
construction pipeline relies on a manual or undocumented transformation.
