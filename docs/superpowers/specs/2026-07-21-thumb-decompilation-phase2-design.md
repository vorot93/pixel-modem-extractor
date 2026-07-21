# Phase 2 — Thumb decompilation coverage (tighten TameAnalysis, hybrid output)

Status: approved 2026-07-21
Scope: Phase 2 of a multi-phase effort to maximize the readability of the decompiled
modem output. Phase 1 (closed loop via `ApplySymbols` + regenerated `decompiled.c`)
is shipped; Phase 3 (types & globals recovery) is independent and out of scope here.

## Context

Phase 1 closed the symbol loop for ARM code: recovered names and inline evidence now
reach `decompiled.c` via a two-pass Ghidra run. The ~141k Thumb-2 protocol-stack
functions in `02_MAIN` are still assembly-only, because today's `TameAnalysis.java`
**marks every detected dense-Thumb region as data** before Ghidra auto-analysis
runs — without that, Ghidra spins forever in `ClearFlowAndRepairCmd`'s overlapping-
function repair loop (~10M+ repair messages on `02_MAIN`). radare2 (`-a arm -b 16`)
disassembles those regions and emits `thumb_functions.json` (v1) with
`body_kind: "thumb_disassembly"` and raw assembly in `body`.

Phase 1's `symbol_map.json` schema carries `arch: "arm" | "thumb"`, but Phase 1
documented that "Thumb entries in the map are inert in Phase 1" — `ApplySymbols.java`
cannot find them in the program because `TameAnalysis` had marked their regions as
data. Phase 2 removes that inertness.

## Goals

In scope for Phase 2:

1. **Replace the data-mark-everything `TameAnalysis` with a tighter variant** that
   lets Ghidra attempt Thumb function discovery and decompilation in `02_MAIN`,
   falling back per-function to today's radare2 disassembly where Ghidra fails to
   converge.
2. **Per-function hybrid output.** Every Thumb function in `thumb_functions.json`
   either has a Ghidra-decompiled C body or today's radare2 assembly body — never
   neither, never lost.
3. **Investigation protocol with concrete stop conditions.** Identify a tightened
   Ghidra option set on a sample region first, then deploy statically to full
   `02_MAIN` (no per-region adaptive control loop in production).
4. **Phase 1's symbol pipeline lights up automatically for Thumb.** With Thumb
   functions no longer data-marked, `ApplySymbols.java` finds them in-program and
   applies names + plate comments to them just like ARM. The `symbol_map.json`
   schema is unchanged; the Phase-1 "inert Thumb entries" caveat is retired.

## Fidelity posture

Carries forward from Phase 1. When readability and fidelity conflict, fidelity wins.

- **No lossy decompiler options.** `EliminateUnreachable`, `Simplify`, etc. stay off
  for the same reasons Phase 1 documented. The investigation only changes
  analysis-time options (function discovery, overlap-repair), never decompiler
  output-shaping options.
- **No relaxation of symbolication criteria.** Tier rules unchanged; Phase 2 only
  changes *which functions Ghidra can see*, not *which names are considered safe*.
- **Hybrid output is strictly additive.** Today's `thumb_disassembly` consumers keep
  working; the new C body is additional signal.
- **Provenance preserved.** The Phase-1 `original_name` rule (sourced from the
  `Symbol` record, not from `functions.json`'s `name` field) extends naturally to
  Thumb functions now that they appear in `functions.json`.
- **Negative-result path is honest.** If no tightened config converges without spin
  and meets the bar, the implementation sections of this spec do not deploy; we
  re-spec. A negative outcome closes the question with evidence — it is a valid
  Phase-2 result.

## Non-goals (deferred)

- **Per-region adaptive back-off (strategy B).** If the chosen static config
  under-covers in practice, a per-region control loop is a small delta pickable as
  Phase 2.1.
- **Measure-then-fill two-pass (strategy C).** Same — a Phase 2.1 candidate.
- **Types and globals recovery.** Still Phase 3.
- **Encrypted / opaque-image detection (`01_PSP`).** Still separate future work.
  Phase 2 handles `01_PSP` defensively via the runtime watch (see Error handling,
  Surface B), not by classifying it up front.

## Approaches considered

- **Approach 1 (chosen): tighten `TameAnalysis`, sample-first investigation, static
  config.** Investigate on a small dense-Thumb sample to pick the best tightened
  Ghidra option set; deploy that single setting to full `02_MAIN`. The per-function
  hybrid output emerges naturally (Ghidra converges on what it can; the rest fall
  through to today's radare2 asm). Smallest implementation surface; investigation
  iterates fast (sample, not full image); matches Phase 1's "one Ghidra invocation
  per image" style.
- **Approach 2: r2ghidra `pdg` per function.** Stays in the radare2 workflow; adds
  per-function C via the r2ghidra plugin. Heavy on 141k functions (hours of
  per-function `pdg`); requires the plugin installed; renames happen in the r2
  session, not in Ghidra's program (diverges from Phase 1's symbol pipeline).
- **Approach 3: carve dense regions into a standalone Ghidra program** that converges
  without `TameAnalysis`'s data-marks. Reuses Phase 1's `ApplySymbols`+`ExportDecomp`
  toolchain but needs a separate program/project per region; risk that convergence
  still requires a `TameAnalysis`-equivalent inside the carve.

Approach 1 is cheapest if it works (the investigation decides), reuses the Phase 1
toolchain unchanged, and falls back gracefully to today's behavior per-function. If
its measured coverage is too low, Approach 2 or 3 — or strategy B/C from the design
discussion — can be picked up as Phase 2.1.

## Investigation protocol

A concrete, bounded experiment that produces a written finding **before any change
to the production pipeline**.

### Sample selection

From a real `02_MAIN` image (lawfully obtained, supplied via `PME_RADIO_IMG`), pick
the **smallest** dense-Thumb region detected by today's `thumb_regions` (entropy ≥
6.5, ≥ 1 MiB). Carve it to a standalone `.bin` at its load address. The goal is a
real Thumb payload small enough that one Ghidra run finishes in minutes, not hours.

### Baseline

Run today's radare2 path on the same sample region; record the function count
`N_r2`. This is the coverage target.

### Candidate option sets (tried in order)

Each candidate is one Ghidra headless run on the same carved sample, with a
*candidate* `TameAnalysis.java` variant and the existing `ExportDecomp.java`. Stop
on the first that passes all stop conditions.

1. **Status-quo control.** Today's `TameAnalysis` (disable Aggressive Instruction
   Finder + mark region as data). Expected outcome: 0 functions discovered
   (because data-marked) — confirms experiment wiring.
2. **No data-marks.** Disable Aggressive Instruction Finder only; leave the region
   as code. Measure.
3. **No data-marks + disable `ClearFlowAndRepairCmd`.** Same as 2, plus the analysis
   option that controls overlapping-function repair. The exact option name is TBD
   — `javap` Ghidra 12's analysis options at investigation time (per
   `CONTRIBUTING.md`'s Ghidra 12 headless API notes).
4. **No data-marks + cap repair effort.** If candidate 3 loses too many functions
   (disabling repair entirely tends to over-merge), instead try keeping repair on
   but bounding it (e.g., a repair-strategy option that fails fast instead of
   spinning).

### Per-candidate measurements

Function count discovered `N_ghidra`; wall-clock; count of
`ClearFlowAndRepairCmd`-related log lines; spot-check of 3 random decompiled
functions for non-empty, syntactically-plausible C.

### Stop conditions

- **Success:** `N_ghidra ≥ 0.5 × N_r2` AND wall-clock < 30 min on the sample AND
  < 1000 repair-related log lines AND all 3 spot-checks produce non-empty C.
  Record the winning option set; freeze it as the production `TameAnalysis`
  variant.
- **Failure:** all 4 candidates exhausted without meeting the bar. Record the
  negative result with measurements; do **not** deploy; the implementation
  sections of this spec do not execute.

### Bounded effort

Investigation is one session: if no candidate passes within ~half a day of
experiments on the sample, declare negative result. No escalation to
full-`02_MAIN` experiments inside the investigation — that is a Phase 2.1
question.

### Deliverable

A findings appendix committed under
`docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md`:
candidate tried, measurements, winning config (or negative result with
reasoning). This spec links to it.

## Architecture

### Tightened `TameAnalysis.java`

`TameAnalysis.java` gains a mode argument:

- `tighten` (new default): disable Aggressive Instruction Finder + the winning
  candidate options from the investigation. Does **not** data-mark the regions.
- `datamark`: today's behavior — disable Aggressive Instruction Finder + mark each
  `addrHex:lenHex` arg as data. Used by `--no-thumb-decompile` (below) and by any
  Phase-1-fallback path.

The Rust host (`decompile::headless_args`) passes `tighten` by default and
`datamark` when the escape hatch is set. The script's existing `addrHex:lenHex`
arg format is preserved.

### New pipeline step: `thumb_enrich`

A pure-Rust step after pass-1 radare2:

1. Parse pass-1 `decompiled.c` into a map `{entry_address → C body text}`.
2. For each entry in the v1 `thumb_functions.json`, look up its `entry` in the map.
   If present, set `body_c` and bump `format` to v2.
3. Fail-closed: a parse error on `decompiled.c` is recorded as
   `thumb_enrich_error: Option<String>`; the asm `body` and `format` v1 are left
   intact so downstream stages keep working.

After pass 2 (`--no-symbol-pass` unset), the step re-runs against pass-2's
regenerated `decompiled.c` to refresh `body_c` with recovered names. With
`--no-symbol-pass`, pass 2 doesn't run, so `body_c` keeps pass-1 placeholder
names — the same Phase-1 contract as `decompiled.c` itself.

### Phase-2 `decompose` pipeline (delta on Phase 1)

```
extract
  → decompile pass 1 (tightened TameAnalysis; decompiled.c now contains Thumb fns)
  → radare2 over detected Thumb regions  →  thumb_functions.json (v1, asm-only)
  → thumb_enrich                          ← NEW: parse pass-1 decompiled.c, fill body_c, bump v2
  → source_tree, recover_source, decode_tokens
  → symbolicate::build_map (unchanged schema; Thumb entries no longer inert)
  → decompile pass 2 (ApplySymbols now applies to Thumb fns in-program too)
  → thumb_enrich re-run                   ← NEW: refresh body_c from pass-2 decompiled.c
  → symbolicate::finalize (rewrites thumb_functions.json `name` fields in place;
       body_c names are already correct from pass 2, so no text substitution on body_c)
  → decode_rf, hardware_config
  → prune (if --prune)
```

### New flag: `--no-thumb-decompile`

Opts-gated escape hatch. When set, `decompose` and `decompile --run` use
`TameAnalysis mode=datamark` (today's behavior), no `thumb_enrich` step runs, and
`thumb_functions.json` stays at v1. Default off. This is the safety net for
shipping — if the tightened `TameAnalysis` regresses on some firmware version, the
user can fall back to Phase-1 behavior without downgrading.

## Artifacts and contracts

### Modified: `thumb_functions.json` (v1 → v2)

The hybrid output means every Thumb function still has assembly (radare2,
unchanged) and *some* have additional C (Ghidra). The schema bumps from v1 to v2
with one optional field; **no breaking changes for v1 readers**.

```json
{
  "format": "pixel-modem-extractor-thumb-functions-v2",
  "functions": [
    {
      "entry": "0x40e1200",
      "name": "LteRrc_Reestab",
      "size": 64,
      "body_kind": "thumb_disassembly",
      "body": "movw r0, 0xa2 ; …",
      "body_c": "int LteRrc_Reestab(...) { … }",
      "data_refs": ["0x40e1ffc8"]
    }
  ]
}
```

**Field rules:**
- `format` bumps to `pixel-modem-extractor-thumb-functions-v2`. v1 readers ignore
  unknown keys, so the file stays consumable by today's tooling.
- `body_kind` stays `"thumb_disassembly"` for **every** function. The asm `body`
  is always populated (radare2 runs unchanged on every detected Thumb region —
  preserves today's behavior and lets `symbolicate`'s `movw`/`movt` scanner keep
  working uniformly).
- `body_c` is **new and optional** — present iff Ghidra decompiled that function.
  Absent means "Ghidra didn't converge on this function; asm is all you get."
  Consumers check `body_c` presence; nothing else changes.
- `name` continues to come from Phase 1's symbol pipeline (`ApplySymbols` runs
  against the Ghidra program where Thumb functions now live); radare2's
  `sym.thumb_*` placeholder is the pre-rename default.

### Unified `decompiled.c` (grows, no schema change)

ExportDecomp.java already emits one unified `decompiled.c` for every function
Ghidra discovered. In Phase 2, that file now also contains Thumb functions (since
they're no longer data-marked). The Rust host parses `decompiled.c` and, for each
entry in `thumb_functions.json` whose address matches a Thumb function Ghidra
emitted, populates `body_c`. No new Ghidra script; one new Rust parser
(well-bounded: entry-address → function text).

The unified `decompiled.c` will grow (potentially many MB). No schema change;
documented; no action.

### Modified: `decompose::ImageResult`

Gains three fields, all `Option`, all surfaced in `report.json`:

- `thumb_decompiled: Option<usize>` — Phase 2's headline metric; count of
  functions where `body_c` was populated.
- `thumb_tighten_error: Option<String>` — set when the runtime watch (Error
  handling, Surface B) killed the tightened run and fell back to `datamark`.
- `thumb_enrich_error: Option<String>` — set when `thumb_enrich` parse failed
  (Error handling, Surface C).

Missing fields mean "didn't run for this image" (e.g., no Thumb regions
detected). A tighten/enrich failure never marks the image `failed` — pass-1 ARM
C is still valid.

### Scale posture

Today's `thumb_functions.json` for `02_MAIN` is ~600 MB. Inline `body_c` could
roughly double it. We accept that for v2 — `symbolicate`'s whole-file rewrite
already peaks at ~3 GB and tolerates the increase. If measurement shows it
doesn't, a Phase 2.1 follow-up can split C into a `thumb_decompiled.c` sidecar
with byte-offset references; we do not pre-engineer that here.

## Error handling and edge cases

Three failure surfaces, each fail-closed.

### Surface A: investigation returns negative

No candidate meets the bar in the stop conditions. The implementation sections of
this spec **do not execute**. The findings appendix records measurements for each
candidate. The repo stays at Phase 1 behavior — no `TameAnalysis.java` change,
no `thumb_enrich`, no schema bump. We re-spec: a new Phase 2 picks Approach 2
(r2ghidra), Approach 3 (carve), or strategy B/C from the design discussion.

### Surface B: investigation passes sample, full `02_MAIN` spins at runtime

A real risk — the sample is bounded; the full image has more varied Thumb
patterns. Mitigation is a per-image Ghidra watch inside `decompose::run`:

- Wall-clock budget per image: default 4× the pass-1 wall-clock recorded for that
  image (so it scales with image size). For `02_MAIN` this is generous; for small
  images it stays tight. A hidden, test-only flag `--tighten-wall-clock-budget-sec
  <N>` overrides the budget for verifying Surface B in Section 7 (production users
  do not normally need to change it — `--no-thumb-decompile` is the right escape
  hatch for a problematic image).
- Log-spam budget: < 100k `ClearFlowAndRepairCmd`-related lines (the
  investigation's threshold, scaled).
- On either budget exceeded: kill `analyzeHeadless`, mark the image's tightened
  run failed, **re-spawn pass 1 with `TameAnalysis mode=datamark`** (today's
  behavior), record `thumb_decompiled: Some(0)` + `thumb_tighten_error:
  Option<String>` in `ImageResult`.
- Cost: one failed run + one successful data-marked run on the worst-affected
  image. Acceptable; only fires on regression.
- The escape hatch `--no-thumb-decompile` skips the watch entirely (starts in
  `datamark` mode).

### Surface C: `thumb_enrich` parse failure

A malformed `decompiled.c` (Ghidra emits something the parser rejects). Step
records `thumb_enrich_error: Option<String>`, leaves `thumb_functions.json` at v1
(no `body_c`, no format bump), and the rest of the pipeline continues against v1
— exactly today's contract. Other images are unaffected (per-image fail-closed,
like Phase 1's `pass2_error`).

### `01_PSP` (encrypted) concern, addressed

Today `thumb_regions` detects one giant dense region on `01_PSP` (uniform entropy
≈ 8.0); `TameAnalysis mode=datamark` neutralizes it. In Phase 2's tightened mode,
that region is no longer data-marked — Ghidra *might* spin. Surface B handles
this: if it spins on `01_PSP`, the kill + datamark retry recovers exactly today's
behavior. No opaque-data classifier needed (that stays deferred future work).

### Phase-1 invariants preserved (called out because they are easy to break)

1. `run_two_pass` still takes the pass-1 `DecompileReport` as a parameter; it
   does not re-run `run_report`.
2. `refresh_decompiled` still runs per-image after `run_two_pass` returns `Ok`.
3. `decode_tokens` still runs before the `symbol_map` stage.
4. `functions.json` provenance (`original_name` from the `Symbol` record, not
   from the program's `name` field) — unchanged. After Phase 2, pass-2
   regenerates `functions.json` with recovered names for both ARM *and* Thumb;
   the existing rule covers both.
5. The Phase-1 invariant "Thumb entries in the symbol_map are inert" is
   **dropped** in Phase 2 — that is the point. Documented as the headline
   change.

### What does NOT fail-closed

The `thumb_enrich` step itself is pure file I/O + parsing. If it panics (bug),
that is a real bug, not a fail-closed surface, and crashes the run. Same posture
as the rest of the Rust core.

## Testing

Mirrors `CONTRIBUTING.md`'s tiered structure: inline Rust unit tests for pure
logic; self-contained Ghidra e2e tests for pipeline behavior; env-gated golden
tests for real-image coverage.

### Inline Rust unit tests (in `decompile.rs`)

- `thumb_enrich` populates `body_c` for an entry whose `entry` matches a function
  in `decompiled.c`; leaves non-matching entries alone.
- Format bump is **conditional**: v1 → v2 only when at least one `body_c` is
  populated; stays v1 if zero matches (so an image where Ghidra converged on
  zero Thumb functions emits today's v1 file byte-equivalently).
- Idempotent: running `thumb_enrich` twice yields the same file (same addresses
  → same C bodies → same output).
- Fail-closed: malformed `decompiled.c` returns `Err`; the v1
  `thumb_functions.json` on disk is unchanged.
- Empty `thumb_functions.json` (no Thumb regions detected) is a no-op.
- `parse_pass2_summary` and existing radare2 parsers unchanged (regression
  baseline).

### `tests/decompile_golden.rs` (self-contained TOC fixture; real Ghidra; skips when absent)

- Existing `run_drives_ghidra_end_to_end` and
  `pass2_renames_function_and_bakes_plate_comment` keep passing unchanged —
  regression baseline for Phase 1.
- **New: `tightened_tame_analysis_emits_thumb_function`** — craft a TOC fixture
  containing one small hand-assembled valid Thumb-2 function (a few
  `push {r7,lr}; …; pop {r7}; bx lr`-style bytes), run `decompile::run_report`
  with `TameAnalysis mode=tighten`, assert `decompiled.c` contains a function at
  the Thumb entry. Canonical regression test for the tightened script.
- **New: `thumb_enrich_populates_body_c`** — given a synthetic `decompiled.c`
  with one function and a matching v1 `thumb_functions.json`, run
  `thumb_enrich`, assert v2 + `body_c` populated.
- **New: `no_thumb_decompile_flag_falls_back_to_datamark`** — same fixture as
  above, but with `--no-thumb-decompile`. Assert `decompiled.c` does **not**
  contain the Thumb function (it was data-marked) and `thumb_functions.json`
  stays at v1. Doubles as the "Phase-1 behavior preserved" regression test.

### `tests/decompose_golden.rs` (env-gated by `PME_RADIO_IMG` + `PME_GOLDEN_DIR`)

- Assert `report.json` includes the new fields: `thumb_decompiled`,
  `thumb_tighten_error`, `thumb_enrich_error`. Missing fields must round-trip
  cleanly through `serde` `Option`s.
- Manual spot-check (in the verification script, not an automated test):
  `images/02_MAIN/decompiled/thumb_functions.json` has
  `"format": "pixel-modem-extractor-thumb-functions-v2"` and at least one
  function with `body_c` populated.

### Inline tests in `symbolicate.rs`

- Existing `rewrite_text_*` tests still pass (no regression in asm `body`
  parsing).
- New: `body_c` is left byte-identical by `finalize_image` when called with
  `rewrite_decompiled_c=false` (Phase 2 decompose path) — names are already
  correct post-pass-2.
- New: `body_c` is touched (renames applied) when called with
  `rewrite_decompiled_c=true` (standalone `symbolicate` subcommand path against
  a pre-Phase-2 tree) — symmetric with today's `decompiled.c` rewrite behavior.

### CLI tests (in `cli.rs`)

- `--no-thumb-decompile` appears in `decompose --help` and `decompile --help`.
- Default behavior (flag absent) is tighten mode.

### What is NOT unit-tested

- The wall-clock / log-spam watch in Surface B is inherently non-deterministic.
  Its data structures (`thumb_tighten_error`) are covered structurally; the
  watch behavior itself is verified manually on a real `02_MAIN` (see
  Verification).
- The investigation itself — it is a one-off experiment producing a written
  finding, not a regression-tested code path.

## Verification

### Standard Rust gate (mirrors `CONTRIBUTING.md`)

```
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

A change is done only when all three pass. The new Ghidra e2e tests in
`decompile_golden.rs` need a real Ghidra (`GHIDRA_INSTALL_DIR` or `/opt/ghidra`);
they skip cleanly otherwise and run in CI's nightly `ghidra-e2e` workflow.

### Investigation verification (one-off, on a real image)

- Carve the smallest dense-Thumb region from a lawfully-obtained `02_MAIN`.
- Run the four candidates from the Investigation protocol in order; record
  per-candidate `N_ghidra`, wall-clock, repair log count, 3 spot-checks.
- Stop at the first success; commit the findings appendix under
  `docs/superpowers/specs/2026-07-21-thumb-decompilation-phase2-findings.md`
  with the winning option set and the measurements that justify it.
- If all four fail: commit the negative-result appendix; Phase 2 implementation
  does not proceed; re-spec.

### Implementation verification (on a real image, after the investigation succeeds)

- `pixel-modem-extractor decompose radio.img` on a disposable copy of a real
  `02_MAIN`.
- Confirm: (a) `report.json` shows `thumb_decompiled > 0` for `02_MAIN`; (b)
  `images/02_MAIN/decompiled/thumb_functions.json` has
  `"format": "pixel-modem-extractor-thumb-functions-v2"` and a non-empty count
  of entries with `body_c`; (c) the unified
  `images/02_MAIN/decompiled/decompiled.c` contains Thumb function bodies
  (sample a few); (d) `images/02_MAIN/decompiled/decompiled.c` spot-check shows
  recovered names + plate comments on at least one Thumb function (Phase-1
  symbol pipeline lit up for Thumb).
- Confirm Surface B: artificially lower the wall-clock budget
  (`--tighten-wall-clock-budget-sec 1` or an env var, gated behind a test-only
  flag) on `02_MAIN` to verify the kill + datamark-retry fallback fires and
  `thumb_tighten_error` lands in `report.json` without marking the image
  `failed`.
- Confirm escape hatch: `pixel-modem-extractor decompose --no-thumb-decompile
  radio.img` reproduces today's v1 `thumb_functions.json` byte-equivalently and
  `decompiled.c` does not contain Thumb functions.
- Confirm Phase 1 non-regression:
  `pixel-modem-extractor decompose --no-symbol-pass radio.img` still produces a
  valid Phase-1-shaped tree (only the symbol-pass delta is off).

### Docs to keep in sync in the same change (per `CONTRIBUTING.md`)

- `README.md` — note the hybrid Thumb output in the `decompose` description and
  the new `--no-thumb-decompile` flag in the Commands table; note the `body_c`
  field and `format: v2` in the Output layout section.
- `CONTRIBUTING.md` — replace the future-work mention of "Phase 2: Thumb
  decompilation coverage" with a pointer to this spec; update the Domain map's
  note that "Thumb entries in the map are inert in Phase 1" to reflect Phase 2
  (entries now live); add `thumb_enrich` and
  `thumb_decompiled`/`thumb_tighten_error`/`thumb_enrich_error` to the relevant
  invariants list; record the winning `TameAnalysis` option set and why each
  losing candidate was rejected.

## Done criteria

Phase 2 is done when:

1. The investigation finding is committed (success or negative).
2. If success: all Rust gates pass; the implementation verification above
   passes on a real image; the docs are updated.
3. If negative: the negative-result appendix is committed and a re-spec path is
   agreed.

A negative investigation result is a valid Phase-2 outcome — it closes the
question with evidence.

## Future phases (context only)

- **Phase 2.1 (conditional).** If Phase 2's static tighten config under-covers
  in practice, pick up strategy B (per-region adaptive) or C (measure-then-fill
  two-pass), or pivot to Approach 2 (r2ghidra `pdg`) or Approach 3
  (carve-and-standalone-Ghidra).
- **Phase 3: types and globals recovery.** Struct layout inference, MMIO region
  labeling, global variable naming. Carries the highest fidelity risk and will
  need its own per-annotation provenance and an opt-in/opt-out surface — same
  posture as Phase 1, applied more strictly.
