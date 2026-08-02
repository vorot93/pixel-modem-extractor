# Contributing guidelines

Guide for anyone — human or AI — changing this repository. For *using* the CLI, see
[`README.md`](README.md); this file is about developing it.

`pixel-modem-extractor` is a pure-Rust CLI that extracts and analyzes the Samsung Exynos
"Shannon" S5400 baseband firmware from a Pixel radio FBPK image. Extraction needs no
runtime dependencies; the `--run` / `decompose` analysis paths drive a local Ghidra and
radare2.

## Ground rules (read first)

- **No proprietary data, ever.** Only magic numbers, offsets, and format structure
  belong in the repo — never firmware bytes or third-party code. Extraction output,
  decompiled C, and golden trees are derived artifacts and stay out of git.
- **Keep the legal posture intact.** This is an independent interoperability,
  security-research, and educational tool. Do not weaken the nominative-use, trademark,
  or licensing wording in `README.md`, `LICENSE`, or `NOTICE`. New code must be
  Apache-2.0 compatible.
- **Fail closed.** Parsers and decoders reject malformed or ambiguous binary input and
  return an error rather than emitting silent, plausible-looking garbage. Preserve this —
  much of the recent history is hardening exactly this behavior. This applies to the
  decoder shell-outs too: a truncated `RF_CFG_*` (< 0x90 bytes) returns
  `Error::SizeMismatch` rather than indexing OOB; radare2 stdout > 256 MiB is rejected
  rather than OOMing the host.

## Build, lint, test

Latest stable Rust, edition 2024. These commands mirror CI
(`.github/workflows/ci.yml`); a change is done only when all pass:

    cargo build                                                  # or: cargo build --release
    cargo fmt --all                                              # CI runs --all --check
    cargo clippy --all-targets --all-features -- -D warnings     # warnings are errors
    cargo test --all-targets

CI runs lint plus the test suite on Linux (x86_64 and arm), macOS, and Windows.

## Tests

- **Unit tests** are inline (`#[cfg(test)] mod tests`) next to the code they cover.
- **Golden integration tests** (`tests/*_golden.rs`) compare against a real extraction you
  supply from *outside* the repo via two env vars, and skip cleanly when either is unset
  or the inputs are absent — so `cargo test` is green with no fixtures:

      PME_RADIO_IMG=/path/to/radio.img \
      PME_GOLDEN_DIR=/path/to/modem_extracted \
      cargo test

  Obtain any radio image lawfully (e.g. Google's public Pixel factory images).
- **Symbolicate golden** (`tests/symbolicate_golden.rs`) needs `PME_DECOMPOSED_DIR` (a
  `decompose` output root) and `PME_TOKEN_DB` (the raw `pw_token_db`); it **rewrites that
  tree in place** (idempotently), so point it at a disposable copy, not your only reference.
- **Ghidra end-to-end** (`tests/decompile_golden.rs`) is self-contained — it crafts a
  tiny ARM blob in a valid TOC, so it needs **no firmware** — but it needs a real Ghidra.
  It locates one via `GHIDRA_INSTALL_DIR` or `/opt/ghidra` (looking for
  `support/analyzeHeadless`) and skips otherwise. CI runs it nightly / on demand via the
  `ghidra-e2e` workflow. Two tests live there: `run_drives_ghidra_end_to_end` (pass-1
  only, exercises `decompile::run`) and `pass2_renames_function_and_bakes_plate_comment`
  (Phase 1+; crafts a one-symbol `symbol_map.json`, drives `decompile::run_two_pass`,
  and asserts the rename + plate comment land in the regenerated `decompiled.c` —
  the canonical regression test for the two-pass pipeline).
- **Phase 3.0 production goldens** (`tests/globals_golden.rs` and
  `report_json_includes_globals_field` in `tests/decompose_golden.rs`) need
  `PME_RADIO_IMG`, Ghidra, and radare2. Run production-scale cases with
  `cargo test --release`: debug `symbolicate_finalize` exceeded three hours on
  the real ~630 MB `thumb_functions.json`, while release runs completed in
  roughly 2h12m–2h19m. Both tests skip cleanly when prerequisites are absent.
- **External tools:** the `--run` and `decompose` paths shell out to Ghidra
  (`analyzeHeadless`) and radare2 (`r2`); both are probed up front.
- Write the failing test first (TDD), then the minimal code to pass it.

## Repository layout

`src/*.rs` is a flat set of focused modules — one concern each:

| Path | Responsibility |
|---|---|
| `pipeline.rs` | Orchestrates the `extract` stages end to end |
| `fbpk.rs` | FBPK radio-image parser |
| `ext4.rs` | ext4 filesystem reader (via `ext4-view`) |
| `archive.rs` | `ustar`/tar handling around the ext4 payload |
| `gzip.rs` | Gunzip the `RF_CFG_*` calibration blobs |
| `toc.rs` | `modem.bin` TOC parse + split into the six images |
| `source_tree.rs` | Reconstruct the source-tree layout from `__FILE__` strings |
| `recover_source.rs` | Attribute recovered Ghidra/radare2 functions to source paths |
| `decode_rf.rs` | Decode the RF_CFG calibration databases |
| `hwcfg.rs` | Summarize `hardware_config.json` + RF_CFG coverage |
| `tokens.rs` | Decode the Pigweed `pw_token_db` |
| `decompile.rs` | Ghidra import kit + `--run` (analyzeHeadless) + radare2 Thumb |
| `symbolicate.rs` | Recover names + log/assert annotations into the decompiled artifacts (+ `symbols.json`) |
| `globals.rs` | Phase 3.0 record-only global-name recovery (+ per-image `globals.json`) |
| `decompose.rs` | One-shot pipeline over all decoders |
| `manifest.rs` | `manifest.json` writing + `sha256` helpers |
| `error.rs` | Error types |
| `cli.rs` | `clap` subcommands + dispatch |
| `bin/main.rs` | Binary entry point |
| `ghidra/*.java` | Ghidra headless scripts (`ExportDecomp`, `TameAnalysis`, `ApplySymbols`) |

Also: `tests/` holds the golden integration tests. Keep one clear responsibility per
module; when a file outgrows that, split it.

## Domain map & code conventions

- **The six TOC images** are `00_BOOT`, `01_PSP`, `02_MAIN`, `03_APM`, `04_VSS`, and
  `05_DBGCORE` (parsed in `toc.rs`). `02_MAIN` is the primary code image — `source-tree`
  reconstruction and recovered-source attribution operate on it; `05_DBGCORE` is the
  small debug image. **`01_PSP` is encrypted** (uniform entropy ≈ 8.0, no ARM code, no
  readable strings), so Ghidra reports **0 functions** — expected, not a bug. Detecting and
  classifying opaque/encrypted images is future work (see the symbolication design spec).
- **TOC CRCs are advisory.** Every image's stored TOC CRC currently mismatches a plain
  CRC-32 over `[offset, size)` (the algorithm/coverage is unconfirmed); `split_to_dir` only
  `warn!`s and still writes, and `manifest.verified` means "checks were attempted," not
  "CRCs matched." Don't read `verified: true` as CRC validation.
- **CLI dispatch is thin.** `cli.rs` only parses args and resolves the `--out` default,
  then delegates to a module-level `run(...)`. Put new logic in the module, not in
  `cli.rs`. The decoder subcommands' `run()` prints its own console report; the pipeline
  commands (`extract`, `source-tree`, `decompose`) return a path that `cli.rs` prints.
- **Errors and logging.** The library core returns the typed `crate::error::Error` and
  its `crate::error::Result<T>` alias (`thiserror`; fail-closed variants such as
  `BadMagic`, `BadToc`, `SizeMismatch`, `ToolNotFound`). `anyhow` is used only at the CLI
  edge (`cli::run() -> anyhow::Result<()>`). `bin/main.rs` initializes `tracing` on
  stderr, prints `error: {e:#}` on failure, and exits 1.
- **Symbolication is fail-closed.** `symbolicate.rs` only *renames* from a
  recovered `__func__` (an assert site referencing both its `__FILE__` and a
  unique identifier string); a pw_tokenizer token match yields a *marked*
  `guess_<slug>_<addr>` name (never unmarked); attributed strings / file
  attribution are comments only. Token immediates are recovered by `movw`/`movt`
  reconstruction over the emitted disasm; string evidence needs the raw split
  image (`images/<label>/<label>.bin`), so the `decompose` stage runs before
  `--prune`. It rewrites in place **idempotently** — a sentinel guards `.c`/`.lst`, an
  `original_name` key guards the JSONs, and the loaders prefer `original_name` on a re-run
  (so `symbols.json` provenance stays stable); preserve this if you touch the rewrite path.
  Name substitution in the rewrite is **whole-identifier** (`[A-Za-z0-9_]+` match +
  exact-key lookup), not `str::replace` — `FUN_10` must never fire inside `FUN_100`; the
  `apply_rename_map_does_not_substring_match` test is the regression sentinel. The token
  map prefers the first **live** (non-`date_removed`) entry per token (a stale removed
  entry must not win over a live one for the same token); recover_func_name dedups
  `data_refs` by string content before the "exactly one identifier" check so a repeated
  `__func__` reference doesn't look ambiguous.
  Scale note: `02_MAIN`'s `thumb_functions.json` is large (~600 MB, ~141k Thumb functions)
  and is loaded/rewritten whole (~4 s, ~3 GB peak); pw_tokenizer strings are structured
  `■format♦…■domain♦…`, and tokens appear as `movw`/`movt` immediates (not raw literals, so
  a byte search won't find them).
- **Two-pass decompile (Phase 1+).** `decompose` runs decompile twice per
  image: pass 1 (`decompile::run_report`) analyzes and exports an initial
  inventory + `decompiled.c`. Between passes, `decompose::build_and_write_symbol_maps`
  builds a `symbol_map.json` per image from pass-1 outputs (using
  `symbolicate::build_map`, the pure builder split out of `symbolicate_image`).
  Pass 2 (`decompile::run_two_pass`) drives `analyzeHeadless -process` on the
  same project, running `ApplySymbols.java` (renames + plate comments) followed
  by `ExportDecomp.java` (regenerates `decompiled.c` with names + comments baked
  in). `--no-symbol-pass` skips pass 2 entirely. `decompile --run` (the
  standalone subcommand) is single-pass and unchanged. The standalone
  `symbolicate` subcommand still does today's in-place text substitution
  (controlled by `Opts.rewrite_decompiled_c`, which is `true` for the
  standalone path, `true` for the decompose path under `--no-symbol-pass`, and
  `false` otherwise — pass 2 already baked the names in).
- **Phase 2 + 2.1: Thumb decompilation.** Dense Thumb regions in `02_MAIN`
  are no longer data-marked for Ghidra; the tightened `TameAnalysis`
  (`mode=tighten`) lets Ghidra attempt function discovery and decompilation.
  Per-function hybrid output: `thumb_functions.json` v2 with optional
  per-function `body_c`; the asm `body` is always populated (radare2
  unchanged). `thumb_enrich` parses `decompiled.c` and fills `body_c` by
  **entry address** (Phase 2.1's matching fix — Phase 2 shipped name-based
  matching, which never aligned radare2's `thumb_<addr>` / `sym.thumb_<addr>`
  with Ghidra's `FUN_<addr>` / recovered names; Phase 2.1 switched to
  address-based matching per the spec's original intent; see Phase 2.1
  invariants below). `thumb_enrich` is pure Rust, idempotent, runs after pass
  1 and again after pass 2. `--no-thumb-decompile` reverts to Phase-1 datamark
  behavior. A runtime wall-clock + log-spam watch kills Ghidra on
  overlapping-function-repair spin and falls back to datamark per image
  (recorded as `thumb_tighten_error`, image not marked `failed`); see
  **Surface B mechanics** below for the kill path and budget calibration.
  **Production status (verified end-to-end on a real `02_MAIN`, Pixel 6 Pro
  mustang):** Phase 2.1's winning `TIGHTEN_EXTRA` (`"Non-Returning Functions -
  Discovered.Repair Flow Damage"`) lets Ghidra 12 converge in 1398 s (23.3
  min) with 0 `ClearFlowAndRepairCmd` repair-log lines and 71 % radare2
  coverage (`N_ghidra` = 107,955 of `N_r2_full` = 151,411 across 5
  dense-Thumb regions). Surface B's budget (~112 min wall-clock, 100k log-spam
  lines) is never approached. Full `decompose` (full pipeline, observed in
  `report.json`): `thumb_decompiled` = 81,763 for `02_MAIN`;
  `thumb_tighten_error` absent (Surface B did not fire); 81,763 entries in
  `thumb_functions.json` carry `body_c`; decompiled.c contains Thumb-region
  function bodies (sample: `// FUN_40e18dfe @ 40e18dfe` etc.). The Phase 2
  fields are surfaced in the `decompile` stage's per-image entry via
  `refresh_decompile_stage_images` (called after both pass-1 and post-pass-2
  `thumb_enrich` sweeps); without that refresh, the decompile StageReport
  carries the pre-enrich snapshot and Phase 2's headline metric is invisible
  in report.json. (Phase 2 originally shipped with an empty `TIGHTEN_EXTRA`;
  on production `02_MAIN`, that config triggered Ghidra's overlap-repair spin
  (>100k log lines, ~28 min) and Surface B's watch fired + fell back to
  datamark. Phase 2.1 picked the winning option via a multi-candidate
  investigation; see **Winning TameAnalysis options (Phase 2.1)** below.)
- **Don't try to add a synthetic CI fixture for the Thumb→C pipeline.**
  Phase 2.1 attempted a 14-byte ARM `BLX`-to-Thumb hand-assembled fixture to
  prove Ghidra's Thumb discovery end-to-end in `tests/decompile_golden.rs`.
  Empirical verification: Ghidra's `ARM:LE:32:v7` auto-analysis does **not**
  follow an immediate BLX into Thumb mode for a small synthetic blob. Real-
  firmware Thumb discovery is driven by radare2 region hints + Ghidra's flow
  analysis over megabytes of code, not by any single mode-switch instruction
  a synthetic fixture could carry. Even a working fixture would test an
  artificial path that could pass CI while production breaks. CI coverage for
  the matching fix lives in `thumb_enrich`'s inline Rust tests; production
  verification lives in the full `decompose` on a real `02_MAIN` (see the
  Phase 2 / 2.1 findings docs in `~/.superpowers/pixel-modem-extractor/`).
  If you must add CI coverage for Thumb discovery, gate it on a real image
  (env-gated golden test) — do not spend time on a hand-assembled BLX
  fixture.
- **Two-pass sequencing invariants.** Three structural facts a fresh change
  can easily break:
  (1) **`run_two_pass` accepts the pass-1 `DecompileReport` as a parameter; it
  does NOT call `run_report` itself.** The caller (`decompose::run`) already
  has the report — calling `run_report` again would triple Ghidra time on
  `02_MAIN`. Don't "helpfully" add a fallback `run_report` call inside
  `run_two_pass`.
  (2) **`refresh_decompiled` must run per-image after `run_two_pass` returns
  `Ok`.** Pass 2 writes back to `<ghidra_dir>/export/<label>/`; the per-image
  tree (`images/<label>/decompiled/`) still has pass-1 output until that
  helper moves the regenerated files over. Downstream stages
  (`symbolicate_finalize`) and users read from the per-image tree.
  (3) **`decode_tokens` runs BEFORE the `symbol_map` stage in `decompose::run`**
  — the token DB is an input to `symbolicate::build_map`. The other decoders
  (`decode_rf`, `hardware_config`) are independent and stay late.
- **Phase 2 invariants.** Three structural facts a fresh change can easily break:
  (1) **`thumb_enrich` runs after pass 1 AND after `run_two_pass` returns
  `Ok`.** Skipping the second run leaves `body_c` with placeholder names —
  same contract as pass-2 skipping on `--no-symbol-pass`. Don't "helpfully"
  drop the post-pass-2 enrich when adding a fast path.
  (2) **`--no-thumb-decompile` skips both `thumb_enrich` runs** and forces
  `TameAnalysis mode=datamark` end-to-end. The output is byte-equivalent to
  today's Phase-1 behavior (modulo the v2 format bump on `thumb_functions.json`,
  which is informational-only at load time).
  (3) **The runtime watch (Surface B) is non-deterministic.** Its data fields
  (`thumb_tighten_error`) are structurally tested at the report-shape level;
  the kill behavior itself is verified manually via
  `--tighten-wall-clock-budget-sec 1`. Don't assert on the kill firing in a
  unit test — it depends on Ghidra's repair-log cadence against real firmware.
-   **Phase 2.1 invariants.** Two structural facts a fresh change can easily break:
  (1) **`thumb_enrich` matches by entry address, not by name.** The matching
  gate fires on the normalized entry address (strip `0x`, strip leading zeros,
  clear low bit for Ghidra's Thumb T-bit) — both the parser (over
  `decompiled.c`'s `// <name> @ <addr>` headers) and the matcher (over
  `thumb_functions.json`'s `entry` fields) must apply the same normalization.
  The inline `thumb_enrich_populates_body_c_with_tbit_set` test is the
  regression sentinel. A future change that flips back to name-based matching
  silently breaks body_c on every image — Phase 2's bug.
  (2) **`TIGHTEN_EXTRA` is sourced verbatim from a Phase 2.1 investigation
  findings doc.** If the production config needs to change (e.g. a new firmware
  variant regresses), re-run the multi-candidate investigation; do not edit
  `TIGHTEN_EXTRA` ad hoc. The findings doc lives at
  `~/.superpowers/pixel-modem-extractor/2026-07-21-thumb-decompilation-phase2-1-findings.md`.
-   **Phase 2.1 parser lookahead (8 lines, calibrated to real
  ExportDecomp.java).** `parse_decompiled_c_function_bodies_by_addr` commits
  to a `// FUN_<addr> @ <addr>` header only when `{` appears within the next
  1–8 lines. Real `ExportDecomp.java` output is bi-modal: offset-4 headers
  (single-line signatures like `void FUN_x(void)` between two blank lines,
  ~58% of `02_MAIN`) and offset-6 headers (2-line signatures like
  `void FUN_x(\n    int a)`, ~35%). The 8-line bound captures 99.6% of real
  headers; the long tail (offset >8, <0.5%) is accepted loss. Production
  verification on a real `02_MAIN` confirmed 81,763 body_c populated against
  80,396 measured address overlap (consistent with the histogram prediction
  of 99.6% header capture; the 1.7% excess reflects duplicate radare2
  entries at shared addresses). Two inline regression sentinels
  (`thumb_enrich_handles_real_exportdecomp_format_with_two_blank_lines` for
  offset-4 and `thumb_enrich_handles_real_exportdecomp_offset_6_multiline_sig`
  for offset-6) catch a future regression to the original 2-line bound, which
  silently populated 0 body_c on production data because the synthetic-fixture
  test shape (`<sig>\n{\n`, 1-line gap) didn't match real ExportDecomp output
  (`<header>\n\n<sig>\n\n{\n`, 2-line gaps). Don't tighten this bound without
  re-running production verification on real `02_MAIN` output.
-   **Phase 2 report-surface wiring.** `decompose::run` pushes the `decompile`
  StageReport with per-image entries BEFORE `thumb_enrich` runs, so the
  pre-enrich snapshot has `thumb_decompiled = None`. Both pass-1 and
  post-pass-2 `thumb_enrich` sweeps MUST call `refresh_decompile_stage_images`
  after mutating `ImageResult.thumb_decompiled` / `thumb_enrich_error`,
  otherwise the Phase 2 headline metric is invisible in `report.json` (the
  count is computed but never surfaced). Inline regression:
  `refresh_decompile_stage_images_surfaces_post_enrich_fields`. A 2026-07-22
  followup found this was wired for the post-pass-2 path but missing on the
  pass-1-only path (e.g. under `--no-symbol-pass`), hiding Phase 2.1's
  production body_c count from `report.json`.
- **Phase 3.0: globals recovery (record-only).** After
  `symbolicate_finalize`, `decompose` writes
  `images/<label>/decompiled/globals.json` with format
  `pixel-modem-extractor-globals-v1`. For each ARM or Thumb function, the
  algorithm requires exactly one non-string `data_ref` at or above the image
  load address and exactly one unique identifier surviving across referenced
  strings. Tokens match `^[a-zA-Z_][a-zA-Z0-9_]{2,}$`, must contain an
  underscore, and are
  filtered through the generic-token blocklist. Reinforcing functions combine
  evidence; conflicting names for one address are dropped rather than
  arbitrated. `ImageReport.globals_recovered` surfaces the per-image count and
  `globals_error` carries per-image failures. Current production verification
  recovered 968 globals on the real `02_MAIN`; the full six-image sweep dropped
  100 conflicts. These are observations, not stable count guarantees.
  Coverage is intentionally conservative; disassembly-pattern disambiguation
  belongs to Phase 3.0.1 rather than this direct-evidence stage.
- **Phase 3.0 invariants.** Four structural facts are easy to break:
  (1) **Record-only.** The stage does not modify the Ghidra program or
  `decompiled.c`; `DAT_<addr>` placeholders remain. Applying names in-program
  belongs to a later phase.
  (2) **Recovered-only and strict-single-source-of-truth.** Every Phase 3.0
  entry has `tier: "recovered"`; provisional/function-name inference belongs
  to a later phase. Multiple names proposed for one address are dropped, not
  ranked or guessed.
  (3) **Empty-output-is-valid.** A successful zero-match sweep still writes
  `globals.json` with format v1 and `"globals": []`; absence means the stage
  did not complete.
  (4) **Use the extract manifest contract.** Load addresses come from numeric
  `toc[].load_addr` entries keyed by `toc[].name`. Globals deliberately reuses
  `symbolicate::load_load_addr`; do not add a second parser or revive the
  obsolete synthetic `images[]`/hex-string fixture shape.
  After mutating per-image results, the sweep MUST call
  `refresh_decompile_stage_images`; otherwise the decompile stage retains its
  pre-globals snapshot and the Phase 3.0 fields disappear from `report.json`.
- **Winning TameAnalysis options (Phase 2).** On the smallest dense-Thumb region
  of a real `02_MAIN` (2.06 MiB sample, `N_r2 = 11023`), `TIGHTEN_EXTRA = {}`
  (empty) won — the shared `DISABLE` loop (Aggressive Instruction Finder +
  ARM Aggressive Instruction Finder) is sufficient for Ghidra 12.1.2 to
  converge in 80 s with 0 repair-log lines and 70 % radare2 coverage. Losing
  candidates (one-line rationale each): **Candidate 3** (disable
  `ClearFlowAndRepairCmd`) and **Candidate 4** (cap repair) were never run —
  Candidate 2 hit every stop condition first, so neither option name was
  resolved against Ghidra 12's analysis-properties sheet. Production verification
  on a real `02_MAIN` (Pixel 6 Pro mustang) confirmed the sample did not predict
  the full image: Surface B's watch fires after ~28 min (>100k overlap-repair log
  lines), the datamark retry succeeds, and `thumb_decompiled` stays at 0 — Phase
  2.1 picks up from here.
- **Winning TameAnalysis options (Phase 2.1, on success).** On the full
  `02_MAIN` (~87 MB, Pixel 6 Pro mustang), Phase 2's empty `TIGHTEN_EXTRA` was
  insufficient — Surface B's watch fired after ~28 min with >100k repair-log
  lines. The Phase 2.1 investigation found that disabling
  `"Non-Returning Functions - Discovered.Repair Flow Damage"` (a
  `ClearFlowAndRepairCmd`-gating sub-option under `FindNoReturnFunctionsAnalyzer`,
  on top of the Phase 2 `DISABLE` list) lets Ghidra 12.1.2 converge in 1398 s
  (23.3 min) with 0 repair-log lines and 71 % radare2 coverage of `N_r2_full`
  (`N_ghidra` = 107,955 of `N_r2_full` = 151,411 across 5 dense-Thumb regions);
  3/3 spot-checks PASS. Root cause: `ClearFlowAndRepairCmd` is invoked from
  three places in Ghidra 12 (`FindNoReturnFunctionsAnalyzer`,
  `CallFixupAnalyzer`, `ArmAggressiveInstructionFinderAnalyzer`); the third is
  already disabled by `DISABLE`, and the first one's "Repair Flow Damage"
  sub-option (default ON) was the spin source — disabling it removes the spin at
  its source while leaving non-return *detection* running, so `N_ghidra` is
  essentially unaffected. Losing candidates (one-line rationale each):
  **Candidate 6** (disable `Function Start Search` entirely), **Candidate 7**
  (cap repair effort), and **Candidate 8** (bounded-analysis timeout) were not
  run — Candidate 5 hit every stop condition first. The full investigation lives
  at
  `~/.superpowers/pixel-modem-extractor/2026-07-21-thumb-decompilation-phase2-1-findings.md`.
- **Surface B mechanics (Phase 2+).** The watch in `decompile::run_report`'s
  tighten branch fires on wall-clock or log-spam excess, then re-spawns the
  image as datamark. Two hard-won properties a fresh change can break:
  (1) **Process-group kill (`cfg(unix)`).** `analyzeHeadless` is a bash launcher
  that forks a JVM; `child.kill()` only reaps the bash and orphans the Java
  grandchild, which keeps holding the Ghidra project lock and breaks the
  datamark retry with `LockException`. The spawn path puts the child in its
  own process group (`spawn_in_own_process_group` →
  `CommandExt::process_group(0)`); the kill path then calls
  `kill_process_group(child.id())` → `libc::kill(-pgid, SIGKILL)` to reach the
  whole tree, and `child.wait()` reaps the launcher. The kernel releases the
  OS `FileChannel` project lock as soon as the JVM is reaped, so no userspace
  wait is needed (a prior `Path::exists()`-polling spin-wait on the sentinel
  `.lock` file was removed — it always hit its 10 s cap because no JVM
  shutdown hook runs to delete the sentinel after `SIGKILL`). On non-Unix the
  spawn is a no-op; `child.kill()` only `TerminateProcess`es the immediate
  child and the JVM is orphaned (Windows users fall back to
  `--no-thumb-decompile` if Surface B fires).
  (2) **Per-image byte-count budget.** The tighten baseline is extrapolated
  from the image's `dense_thumb_bytes` (`tighten_baseline_for_dense_thumb_bytes`):
  `max(60s, bytes / 1MiB × 40s)`, grounded in Task 1's measurement
  (2 MiB → 80 s on Ghidra 12.1.2). With the default `wall_clock_multiplier=4`,
  a real `02_MAIN` (~42 MiB dense Thumb) gets baseline ≈ 1 680 s and a budget
  of ~112 min — generous enough to not fire prematurely on production,
  tight enough to catch a true overlap-repair spin (hours otherwise). The
  test-only `--tighten-wall-clock-budget-sec` override bypasses this.
  (3) **Wall-clock budget must fire on silent hangs too.** Ghidra's stdout is
  drained on a thread (`mpsc::channel` + `recv_timeout(500ms)`); the main loop
  checks the budget on every poll, not only after each line, so a GC storm or
  deadlock that stops emitting stdout is still killed. Do not switch back to a
  blocking `BufRead::lines` loop — that would re-introduce the blind spot.
- **Provenance invariant for `functions.json`.** Pass 2 regenerates
  `functions.json` with recovered names in the `name` field (because
  `ApplySymbols.java` renamed in-program first). `rewrite_functions_json`
  sources `original_name` from the `Symbol` record, not from `functions.json`'s
  `name` field, so the original name is preserved across (a) re-running
  decompose and (b) running the standalone `symbolicate` against a Phase-1
  decompose tree.
- **Fidelity over readability.** No lossy `DecompInterface.setOptions(...)` call
  in `ExportDecomp.java` — see the script's header comment for the analysis.
  `Tier::Recovered`'s strict single-identifier-plus-`__FILE__` rule and
  `Tier::Provisional`'s `guess_…` marker convention are preserved as-is; Phase
  1 only changes *where* names are applied, not *which* are considered safe.
- **Ghidra 12 headless API notes (Phase 1+).** Hard-won; verified against
  `/opt/ghidra` (Ghidra 12.1.2). Don't trust older API recall — `javap` the
  bundled jars under `/opt/ghidra/Ghidra/Framework/*/lib/*.jar` when in doubt.
  - **No `Listing.setPlateComment(Address, String)`.** Use
    `listing.setComment(addr, CodeUnit.PLATE_COMMENT, s)` with
    `import ghidra.program.model.listing.CodeUnit;`. (Other setXxxComment
    convenience methods don't exist either — only `setComment(addr, int, String)`
    and the `CommentType` overload.)
  - **No `SourceType.USER`.** The enum is `DEFAULT, ANALYSIS, AI, IMPORTED,
    USER_DEFINED`. The user-settable, highest-priority constant is
    `USER_DEFINED` (use for `Tier::Recovered`); `ANALYSIS` is the right choice
    for `Tier::Provisional` (so Ghidra's re-analysis can displace it).
  - **`GhidraScript.println(String)` log4j-wraps the line** as
    `INFO  <scriptname>> <msg> (GhidraScript)`. Anything the Rust host parses
    from stdout by prefix-stripping must also be written via
    `System.out.println(...)` to land unadorned. (See `ApplySymbols.summarize`
    for the dual-emit pattern.)
  - **Gson IS bundled** with Ghidra (`Ghidra/Framework/Generic/lib/gson-*.jar`)
    and on the headless script classpath — use it for JSON in scripts.
  - **`-process` mode, not `-import`, for pass 2.** Arg vector:
    `<projectDir> <projectName> -process <label> -noanalysis -scriptPath … -postScript ApplySymbols.java <map> -postScript ExportDecomp.java <out>`.
    `-noanalysis` is mandatory — re-running auto-analysis would (a) undo
    `ApplySymbols` renames that aren't `USER_DEFINED`, and (b) re-trigger the
    Thumb overlap-repair spin that `TameAnalysis` exists to prevent. Pass 2
    operates on the existing program — no re-import, no CRC re-check.
  - **`DecompInterface.setOptions(...)` *replaces* the program's "Decompiler"
    property sheet** rather than merging. Any call clobbers user/environment
    defaults; this is why `ExportDecomp.java` doesn't call it.
- **Pass-2 fail-closed surface.** `decompile::ImageResult` carries
  `pass2_applied: Option<usize>` (count of names `ApplySymbols.java` reported
  applying — parsed from its summary line on stdout) and `pass2_error:
  Option<String>` (set when analyzeHeadless exits non-zero *or* the spawn
  itself fails; includes a ~2 KB tail of stderr). A pass-2 failure does **not**
  mark the image `failed` in `report.json` — pass 1 already produced a valid
  `decompiled.c`. Per-stage `Err` from `run_two_pass` is recorded as a
  separate `decompile_pass2` failed stage; the pass-1 `decompile` stage stays.

## How we work here

- **Design before code.** Non-trivial work gets a written design spec and an
  implementation plan before implementation begins. The agent that drives this
  repo keeps those artifacts in its own private data directory
  (`~/.superpowers/pixel-modem-extractor/`,
  `YYYY-MM-DD-<topic>-{design,plan,findings}.md`) — they are the *process trail*,
  not committed documentation. The durable *outcomes* of each iteration land in
  this file, the README, and code comments. Read this CONTRIBUTING.md and the
  README before starting non-trivial work — they capture why approaches were
  chosen or rejected, which the code alone can't tell you.
- **Test first**, keep changes small and reviewable.
- **Verify before claiming done.** Run fmt + clippy + test, and for a behavior change
  exercise the actual affected command — don't infer success from tests alone.
- **Keep docs in sync:** a change to a command or convention updates `README.md`
  (user-facing) and/or this file (contributor-facing) in the same change.
- **Docs are the durable memory.** Here that means the facts this codebase makes you learn
  the hard way: a newly-pinned magic number or struct offset (→ README **Formats**, or a
  comment in the parser module), non-obvious Ghidra / `analyzeHeadless` or radare2 Thumb
  behavior and its failure modes (→ this file, or README **Ghidra + radare2**), and why a
  reconstruction or attribution threshold (`--gap`, `--shared-pct`, `--min-run`) sits where
  it does (→ a comment beside it). Record structure, offsets, and behavior only — never
  proprietary firmware bytes (see **Ground rules**).
- **Worktrees for non-trivial work.** Multi-task implementation happens in a
  git worktree under `.worktrees/<branch>/` (gitignored). The branch is the
  unit of review and merge; master stays shippable. The subagent-driven
  execution ledger (per-worktree, gitignored under `.superpowers/sdd/`) is
  scratch — don't commit it; recover from `git log` if destroyed.

## Recipe: adding a subcommand or decoder

1. Add a focused module under `src/` and expose it in `src/lib.rs`.
2. Add a `Commands::` variant and match arm in `src/cli.rs`, with a sensible `--out`
   default.
3. Add a parse/`--help` test — the existing tests in `src/cli.rs` are the pattern.
4. If it emits artifacts, add env-gated golden coverage like the other `*_golden.rs`.
5. Update the `## Commands` table in `README.md`, and keep the decoder fail-closed
   (return an error on malformed input rather than emitting garbage — see the error
   convention above).
