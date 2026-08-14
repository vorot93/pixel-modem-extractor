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
  `Error::SizeMismatch` rather than indexing OOB; radare2 stdout > 4 GiB is rejected
  rather than OOMing the host.

## Build, lint, test

Latest stable Rust, edition 2024. These commands mirror CI
(`.github/workflows/ci.yml`); a change is done only when all pass:

    cargo build                                                  # or: cargo build --release
    cargo fmt --all --check
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
  `ghidra-e2e` workflow. The focused pass-2 application test is:

      cargo test --test decompile_golden \
        pass2_applies_functions_and_strict_globals_in_one_process -- --nocapture

  It drives the real scripts against a synthetic ARM program and skips cleanly when Ghidra is
  unavailable. `run_drives_ghidra_end_to_end` covers pass 1; the focused test covers function and
  global application, strict ownership, atomic map rejection, and the independent final export.
- **Phase 3.0 production goldens** (`tests/globals_golden.rs` and
  `report_json_includes_globals_field` in `tests/decompose_golden.rs`) need
  `PME_RADIO_IMG`, Ghidra, and radare2. Run production-scale cases with
  `cargo test --release`: debug `symbolicate_finalize` exceeded three hours on
  the real ~630 MB `thumb_functions.json`, while release runs completed in
  roughly 2h12m–2h19m. Both tests skip cleanly when prerequisites are absent.
- **Phase 3.0.1 goldens** (the last three tests in `tests/globals_golden.rs`
  and `report_json_includes_phase3_0_1_fields` in `tests/decompose_golden.rs`)
  read pre-existing decompose output from `$PME_GOLDEN_DIR` and never auto-run
  decompose — the dedicated production verification supplies the env.
  All four skip cleanly when `PME_GOLDEN_DIR` is unset, so `cargo test
  --all-targets` stays green without a real image. The optional
  `$PME_GOLDEN_DIR_PROVISIONAL` (a second decompose output produced with
  `--globals-provisional`) gates the opt-in consistency leg of
  `phase3_0_1_provisional_emitted_only_with_opt_in`.
- **Phase 3.2 goldens** (`tests/global_shapes_golden.rs` and
  `report_json_includes_global_shapes_fields` in `tests/decompose_golden.rs`)
  read a retained or fresh decompose tree from `$PME_GOLDEN_DIR` and never
  auto-run decompose. They skip cleanly when the env is unset, the directory
  is absent, or the tree predates `global_shapes`. The ignored retained-tree
  replay (`global_shapes::tests::retained_tree_replay_is_deterministic_and_non_mutating`)
  also needs `$PME_GLOBAL_SHAPES_REPLAY=1` and an unpruned tree that still has
  the raw per-image slices; it analyzes twice in memory, does not write, and
  asserts the tree is unchanged. Point it at a disposable complete tree, not
  a pruned golden.
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
| `disasm_index.rs` | Shared address-indexed `disasm.lst` view (O(log L + k) slice lookup); consumed by `symbolicate::load_functions` and `globals::run`'s Phase 3.0.1 path |
| `symbolicate.rs` | Recover names + log/assert annotations into the decompiled artifacts (+ `symbols.json`) |
| `globals.rs` | Phase 3.0 global-name recovery + Phase 3.0.1 disasm-anchored Recovered + name-prior Provisional (+ per-image `globals.json`) |
| `execution_ranges.rs` | Tagged execution-range projection (`decode_ranges` / `decode_range_errors`) shared by the Ghidra and radare2 producers and `global_shapes` |
| `global_shapes/mod.rs` | Phase 3.2 per-image coordinator: one-function decode/track/aggregate, panic containment, atomic sidecar commit |
| `global_shapes/decoder.rs` | Pure-Rust adapter over `scaleservers-arm32-assembly` 1.0.0; project-owned instructions only |
| `global_shapes/tracker.rs` | Conservative per-block fact tracking and Recovered-global access observations |
| `global_shapes/aggregate.rs` | Same-PC agreement/conflict grouping and conservative summaries |
| `global_shapes/artifact.rs` | Input validation, source hashes, v2 schema, deterministic serialize, atomic replace |
| `global_shapes/validate.rs` | Shared v2 sidecar checks for goldens and retained-tree replay |
| `decompose.rs` | One-shot pipeline over all decoders; owns `global_shapes` route placement and report fields |
| `manifest.rs` | `manifest.json` writing + `sha256` helpers |
| `error.rs` | Error types |
| `cli.rs` | `clap` subcommands + dispatch |
| `bin/main.rs` | Binary entry point |
| `ghidra/*.java` | Ghidra headless scripts (`ExportDecomp`, `TameAnalysis`, `ApplySymbols`, `ApplyGlobals`) |

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
- **String-reference name guesses.** Beyond `__func__` (Recovered) and token
  matches (Provisional `guess_`), `symbolicate` recovers a third, lowest-
  precedence evidence source: a function's single *distinct* referenced
  identifier string (`name_guess::unique_ident`), when that identifier is
  referenced by exactly one function image-wide and is not an all-caps message
  constant, a recovered global name (`globals.json`), or another function's
  name. Survivors become marked `guess_<ident>_<addr>` `Provisional` names with
  a `string_ref` evidence entry (`class`: `fn_name` | `type_label`); like all
  Provisional names they are never applied in Ghidra (`ApplySymbols.java`
  renames only `recovered`). The tier is gated on `globals.json` and the raw
  image being present, and that gate is route-dependent. In the normal
  `decompose` route, Phase 3.0 writes `globals.json` before
  `symbolicate_finalize` runs, so the tier is inert at the earlier
  `symbol_map` stage and active at finalize. Under `--no-symbol-pass`,
  `symbol_map` is skipped entirely and `symbolicate_finalize` runs *before*
  the record-only globals stage writes `globals.json`, so on a fresh run the
  tier is inert there too — it activates only when a `globals.json` from a
  prior run is already present on disk. Measured on `02_MAIN`: ~8,700
  string-ref guesses, audited ~53% the function's own name / ~85% useful
  (see the design spec). Precision knobs live in `name_guess::string_ref_guess`.
- **`disasm_index::DisasmIndex` (shared infra).** Address-indexed view of a
  `disasm.lst`-format file, O(log L + k) per `slice_for` lookup. Built ONCE
  per image; consumed by `symbolicate::load_functions` (the ARM function
  disasm-slice source) and `globals::run`'s Phase 3.0.1 disasm-anchored
  Recovered path. **Sortedness invariant** — backing lines must be in
  non-decreasing address order (Ghidra's `ExportDecomp.java` emits
  address-ordered; 0 of 7.6M lines out of order on `02_MAIN`); a future
  emitter that breaks sortedness would silently produce wrong slices.
  Replaces the O(N×L) linear scans that previously made `symbolicate` and
  `globals::run` take 100+ min on `02_MAIN`.
- **Two-pass decompile (Phase 1+).** `decompose` runs decompile twice per
  eligible image: pass 1 (`decompile::run_report`) analyzes and exports an
  initial inventory + `decompiled.c`. Between passes,
  `decompose::build_and_write_symbol_maps` writes each function map and retains
  an in-memory entry-to-name index containing every non-null built name. Global
  recovery consumes that index and writes `globals.json` before pass 2 on the
  normal route. `decompile::run_two_pass` accepts a typed per-image input with
  optional function and global maps. Each map is constructed only from a
  non-empty regular file, stores its canonical absolute path and non-zero
  count, and is revalidated immediately before Ghidra arguments are built.
  Initial validation is component-local (an invalid function or global map is
  omitted without suppressing its valid sibling); a late identity/type change
  fails the whole scheduled image rather than changing its script set. It starts
  exactly one `analyzeHeadless -process -noanalysis` saved-project process for
  each image having either input and orders post-scripts as follows:

      functions + globals: ApplySymbols.java -> ApplyGlobals.java -> ExportDecomp.java
      functions only:       ApplySymbols.java -> ExportDecomp.java
      globals only:         ApplyGlobals.java -> ExportDecomp.java
      neither:              no pass-2 process

  Symbol-map preparation is also fail-closed without discarding partial work:
  any per-component error makes the aggregate `symbol_map` stage failed, every
  labelled error is Unicode-bounded and sorted deterministically into the
  report, and surviving typed maps still continue to pass 2. Partial output
  remains visible as `ghidra/symbol_maps/`.

  There is no second import, auto-analysis, or third export pass. The
  `--no-symbol-pass` route instead finalizes the existing text rewrite, loads
  every non-null name from `symbols.json`, runs the same globals helper once,
  and retains no application input; its `globals.json` is record-only.
  `decompile --run` remains single-pass, and the standalone `symbolicate`
  subcommand still performs in-place text substitution.
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
  **Production status (verified end-to-end on a real `02_MAIN`):** Phase 2.1's
  winning `TIGHTEN_EXTRA` (`"Non-Returning Functions - Discovered.Repair Flow
  Damage"`) lets Ghidra 12 converge in ~23 min with 0
  `ClearFlowAndRepairCmd` repair-log lines. Surface B's budget (~112 min
  wall-clock, 100k log-spam lines) is never approached. Full `decompose`
  (full pipeline, ~1 h 37 m wall, exit 0, `report.ok=true`): `functions` =
  107,955; `thumb_functions` = 117,444; `thumb_decompiled` = 77,456;
  `pass2_applied` = 3,461;
  `globals_recovered` = 915 (arch: arm 367 / thumb 545 / mixed 3);
  `thumb_tighten_error` / `thumb_error` / `thumb_enrich_error` /
  `pass2_error` absent. Do not re-assert older `thumb_decompiled` = 10,965
  figures as current HEAD. Ownership-aware `refresh_decompiled` preserves
  `thumb_functions.json` and `thumb/*.stdout` across pass 2. The Phase 2
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
  verification lives in the full `decompose` on a real `02_MAIN`.
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
  (2) **Pass-2 refresh is process-outcome-aware and ownership-aware.** Only an
  explicitly scheduled image whose Ghidra process exited successfully may be
  refreshed; unscheduled and process-failed images leave even stale exports
  untouched. A successful process must produce the exact export below, and a
  missing or invalid export is a failed `decompile_pass2` outcome. Pass 2's
  `ExportDecomp.java` owns exactly
  `decompiled.c`, `disasm.lst`, and `functions.json` under
  `<ghidra_dir>/export/<label>/`. The helper validates that exact three-file
  set before any destination mutation, then replaces only those three paths
  under `images/<label>/decompiled/`. Every other destination entry
  (`globals.json`, `global_shapes.json`, `thumb_functions.json`, `thumb/`,
  and future non-Ghidra sidecars) is left byte-for-byte unchanged. An incomplete or unexpected
  export returns an error and leaves the destination untouched. A successful
  process whose `ApplyGlobals` summary reports an independent map error still
  refreshes a successfully exported function result; `decompile_pass2` remains
  successful while `globals_apply` fails separately. Every normal route emits
  exactly one `decompile_pass2` stage (`skipped`, `ok`, or `failed`), so a
  function-only process/export/refresh failure makes the final report non-OK.
  Downstream
  stages (`thumb_enrich_post_pass2`, `symbolicate_finalize`) and users read
  from the per-image tree.
  (3) **`decode_tokens` runs BEFORE the `symbol_map` stage in `decompose::run`**
  — the token DB is an input to `symbolicate::build_map`. The other decoders
  (`decode_rf`, `hardware_config`) are independent and stay late.
- **Phase 2 invariants.** Four structural facts a fresh change can easily break:
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
  (4) **Missing `thumb_functions.json` after radare2 success is an error.**
  `run_thumb_enrich_per_image` treats `thumb_functions == None` as legitimate
  "no Thumb regions" and skips; `thumb_functions == Some(_)` with a missing
  JSON records `thumb_enrich_error` and fails the `thumb_enrich` /
  `thumb_enrich_post_pass2` stage. Do not restore the silent-skip-on-missing-file
  path — that is how a destroyed pass-1 artifact looked green.
-   **Phase 2.1 invariants.** Two structural facts a fresh change can easily break:
  (1) **`thumb_enrich` matches by entry address, not by name.** The matching
  gate fires on the normalized entry address (strip `0x`, strip leading zeros,
  clear low bit for Ghidra's Thumb T-bit) — both the parser (over
  `decompiled.c`'s `// <name> @ <addr>` headers) and the matcher (over
  `thumb_functions.json`'s `entry` fields) must apply the same normalization.
  The inline `thumb_enrich_populates_body_c_with_tbit_set` test is the
  regression sentinel. A future change that flips back to name-based matching
  silently breaks body_c on every image — Phase 2's bug.
  (2) **`TIGHTEN_EXTRA` is grounded in a Phase 2.1 multi-candidate
  investigation.** If a new firmware variant regresses, repeat that
  investigation; do not edit `TIGHTEN_EXTRA` ad hoc.
-   **Phase 2.1 parser lookahead (8 lines, calibrated to real
  ExportDecomp.java).** `parse_decompiled_c_function_bodies_by_addr` commits
  to a `// FUN_<addr> @ <addr>` header only when `{` appears within the next
  1–8 lines. Real `ExportDecomp.java` output is bi-modal: offset-4 headers
  (single-line signatures like `void FUN_x(void)` between two blank lines,
  ~58% of `02_MAIN`) and offset-6 headers (2-line signatures like
  `void FUN_x(\n    int a)`, ~35%). The 8-line bound captures 99.6% of real
  headers; the long tail (offset >8, <0.5%) is accepted loss. Production
  verification on a real `02_MAIN` (full two-pass `decompose`) measured
  `thumb_decompiled` = 77,456 after pass-2 regeneration + post-pass-2 enrich
  (do not re-assert older 10,965 or pass-1-shaped ~81k figures as current
  HEAD). Two inline regression sentinels
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
- **Phase 3.0: globals recovery and strict application.** On normal
  `decompose`, global recovery runs after function-map preparation and before
  pass 2. It writes `images/<label>/decompiled/globals.json` with format
  `pixel-modem-extractor-globals-v1`; the file remains evidence-only and has no
  application-status fields. For each ARM or Thumb function, the direct rule
  requires exactly one non-string `data_ref` at or above the image load address
  and exactly one unique underscored identifier across referenced strings.
  Reinforcing functions combine evidence; conflicting names for one address
  are dropped rather than arbitrated. Successful Recovered records become the
  optional global input to the same saved-project pass 2 that applies function
  names. Under `--no-symbol-pass`, recovery runs once after finalization and
  `globals.json` remains record-only.
- **Phase 3.0 application ownership.** `ApplyGlobals.java` preflights the full
  selected Recovered map before its first mutation. Provisional and unknown
  tiers are never selected. A selected address is parsed as unsigned
  hexadecimal and duplicate detection uses that canonical numeric value, so
  `0x20` and `00000020` conflict and reject the whole map atomically. For an
  in-memory candidate, application owns only a primary symbol whose source is
  exactly `SourceType.DEFAULT`, whose type is exactly `LABEL`, and whose
  case-insensitive name is exactly `DAT_<hex>` with a suffix numerically equal
  to the candidate address. It never creates a label or replaces analysis,
  imported, user-defined, function, or differently generated symbols. A
  well-formed address outside defined program memory is an individual
  `skipped_outside_memory` result; the script does not inspect or mutate a
  symbol there. Invalid or colliding requested names are skips, never renamed
  variants invented by the tool.
- **Phase 3.0 failure and reporting contract.** Global preparation is isolated
  per image: set `globals_error`, omit only that global map, keep any valid
  function-only input, and continue later images. The script emits exactly one
  unwrapped `ApplyGlobals: {json}` interface line. A successful summary reports
  `candidates`, `applied`, and the four skip categories, which must conserve
  candidates. A map-level failure reports `status: "error"`, applies zero
  globals, and bounds its non-empty reason to 2,048 Unicode characters; Rust
  enforces the same bound and rejects missing, duplicate, malformed,
  wrong-image, unknown-status, non-integer, overflowing, or non-conserving
  summaries. The independent `ExportDecomp.java` still runs after a reported
  map error, preserving successfully applied functions. A process failure
  leaves the valid pass-1 destination untouched.

  `ImageReport.globals_applied` and `globals_apply_skipped` distinguish
  `None` (not invoked) from `Some(0)` (executed zero), while
  `globals_apply_error` carries reason-only per-image detail. The aggregate
  `globals_apply` stage is skipped for `--no-symbol-pass` or no Recovered
  inputs, succeeds only when every invoked image has a valid conserving
  summary, and otherwise fails. Aggregate errors are prefixed with the
  prepared image label in deterministic pipeline-image order; successful
  totals before a later failure remain visible. `pass2_applied` continues to
  count function names only. After the outcome is known,
  `refresh_decompile_stage_images` installs the final per-image snapshot so the
  preparation and application fields reach `report.json`.
- **Phase 3.0 evidence invariants.** Default `globals.json` serialization stays
  format v1 and Recovered-only; `--globals-provisional` may materialize
  Provisional records, but those never affect application candidates or
  `globals_recovered`. A successful zero-match sweep still writes
  `"globals": []`; absence means recovery did not complete. Load addresses
  come from numeric `toc[].load_addr` entries keyed by `toc[].name` through
  `manifest::load_addr_for_image`; do not add a second manifest parser. The
  writer serializes the complete v1 document before opening a same-directory
  atomic temporary file, then commits it as one replacement. An interrupted or
  failed pre-commit write therefore leaves an existing `globals.json` intact:
  consumers observe the complete old file or the complete new file, never a
  truncate-in-progress intermediate.
- **Phase 3.0.1: disasm-anchored Recovered + name-prior Provisional.** Extends
  Phase 3.0's strict-rule loop without changing it. For each function, the
  disasm is scanned for `movw`/`movt` load pairs (PC-tagged via
  `symbolicate::reconstruct_load_events`); when a global-address load sits
  within K load-events of a string-address load whose extracted identifier
  survives Phase 3.0's rule, that identifier pins the global's name —
  *regardless of the function's `data_ref` cardinality*, so functions Phase
  3.0 rejected (≠1 non-string `data_ref`) become eligible. Conflicts and
  cross-tier suppression use the same strict-drop posture as Phase 3.0.
  `--globals-provisional` additionally admits name-prior-derived
  `tier: "provisional"` entries (see Scenario 2 caveat); it is default-off
  and the bare output is byte-equivalent to Phase 3.0's for the Recovered set.
- **Phase 3.0.1 invariants.** Five structural facts a fresh change can break:
  (1) **Disasm grounding is necessary for Recovered — name-prior alone never
  promotes.** A Provisional name with no Recovered at the same address stays
  Provisional (and is withheld without `--globals-provisional`); it must not
  be silently upgraded. The disasm-anchored path is the only Recovered
  promotion vector Phase 3.0.1 adds over Phase 3.0's strict-string rule.
  (2) **Recovered beats Provisional at the same address.** When both name the
  same address, Provisional is suppressed and counted into
  `globals_provisional_suppressed`; the Recovered entry wins verbatim. Do not
  "harmonize" the two tiers.
  (3) **`--globals-provisional` is default-off and the bare `globals.json` is
  byte-equivalent to Phase 3.0's** for the Recovered set — same top-level
  `format`/`globals`/`image`, no `provisional_suppressed` field, no
  `tier: "provisional"` entries. A regression here is a wire-level
  behavioral change masquerading as additive.
  (4) **K_ARM / K_THUMB are sourced verbatim from the Phase 3.0.1 pre-check
  findings doc** (`2026-08-02-globals-phase3-0-1-findings.md`) and baked as
  named constants in `globals.rs`. Do not edit them ad hoc — re-run the
  pre-check if a new firmware variant regresses. Mirrors Phase 2.1's
  `TIGHTEN_EXTRA` provenance rule. The pre-check pinned K_ARM = K_THUMB = 4
  on the accepted production image.
  (5) **The K distance metric is load-event count, not instruction count.**
  K counts `movw`/`movt` load-events strictly between the global load and the
  string load — an approximation of the design spec's "disasm lines between
  two PCs" metric. The pre-check confirmed this approximation grounds the K
  pinning; do not silently switch back to a raw line count, and re-run the
  pre-check if it changes.
- **movw/movt load-event reconstruction shares the register tracker.**
  `symbolicate::reconstruct_load_events` (PC-tagged sibling for Phase 3.0.1)
  and `symbolicate::reconstruct_immediates` (Phase 1's token-immediate
  recovery) walk the same disasm with the same register-state machine. A
  future change to either's `movw`/`movt` handling must keep them in sync
  (the inline `reconstruct_load_events_matches_reconstruct_immediates_values`
  sentinel guards the value-set equivalence) — or unify them; the cleanup is
  intentionally deferred.
- **Phase 3.0 strict-rule path is unchanged.** Phase-3.0 Recovered entries
  still emit with `[String, Function]` evidence; Phase 3.0.1 adds
  `global_load`/`string_load` only on the disasm-anchored path and does not
  backfill them onto Phase 3.0 entries. A future "unify the evidence shape"
  change is a separate decision; don't fold it into an unrelated fix.
  (Current production total on `02_MAIN` is 915 Recovered across both
  paths — see the Phase 3.0.1 production-state bullet.)
- **Surface 3.0.1-A: visibility when disasm is unreadable/absent.** When
  `disasm.lst` is missing or its read returns `Err`, `globals.json` is still
  written with Phase 3.0-only content (strict-string-rule Recovered) plus a
  top-level `phase3_0_1_error` field carrying the io error string; Phase 3.0's
  own per-image failure surface (`globals_error` on `report.json`) stays
  `None` — Phase 3.0.1's inability to run is non-fatal. Consumers distinguish
  "Phase 3.0.1 ran and found nothing" (no field) from "Phase 3.0.1 couldn't
  run" (field present). Note: a zero-byte but present `disasm.lst` is a valid
  empty state and does NOT set the field.
- **Scenario 2 caveat: name-prior is inert on real `02_MAIN`.** The
  pre-check found the name-prior helper generates only ~4 Provisional
  candidates on this firmware, all dropped by strict-drop /
  cross-tier-suppression, so `--globals-provisional` materializes zero
  `tier: "provisional"` entries regardless of the flag. The flag and schema
  exist per the surface contract (and would materialize >0 on Scenario-1
  firmware); the `phase3_0_1_provisional_emitted_only_with_opt_in` golden
  test asserts the always-true upper bound `materialized <= generated`
  rather than nonzero, precisely because of this.
- **Thumb data_refs augmentation.** radare2's per-function `refs` exclude
  movw/movt-constructed addresses (only direct `LDR`/`STR` refs surface);
  the Thumb path augments `non_string_refs` with
  `reconstruct_immediates`-style results before applying Phase 3.0's
  cardinality rule, mirroring the ARM-side `data_refs` source
  (`symbolicate.rs`'s `data_refs_for` / inline `non_string_refs`
  augmentation around the Thumb branch).
- **Phase 3.0.1 report-surface wiring.** Same lesson as Phase 2.1: after
  the globals sweep mutates `ImageResult.globals_provisional` /
  `globals_provisional_suppressed`, the sweep MUST call
  `refresh_decompile_stage_images`; otherwise the decompile stage carries
  the pre-sweep snapshot and the Phase 3.0.1 fields are invisible in
  `report.json`. The `report_json_includes_phase3_0_1_fields` golden test
  (env-gated on `PME_GOLDEN_DIR`) is the regression sentinel.
- **Phase 3.0.1 production state on `02_MAIN` is ARM+Thumb.** Full two-pass
  `decompose` with ownership-aware pass-2 refresh and 4 GiB radare2 streaming
  closed Thumb through pass 2: `globals_recovered` = **915** on `02_MAIN`
  (arch: arm 367 / thumb 545 / mixed 3); stage total recovered 921 with 194
  conflicts dropped. Older ARM-only figures (370 post-`__FILE__`-fragment
  filter; 933 unfiltered; Phase 3.0's 424 ARM-only / 968 ARM+Thumb) are
  historical pre-fix observations — do not cite them as current HEAD
  production. The `phase3_0_1_recovered_exceeds_phase3_0_baseline` golden
  sentinel still asserts `> PHASE3_0_ARM_ONLY_BASELINE` (424) and is
  env-gated (`PME_GOLDEN_DIR`); it holds under the verified 915 total.
- **Cross-path conflict characterization.** Of the 223
  same-address proposals dropped by strict-single-source on an earlier
  ARM-only production `02_MAIN`, **17 are genuine Phase-3.0-strict-vs-
  Phase-3.0.1-disasm disagreements** (the rest are same-path internal
  conflicts). Strict-precedence would gain +11 Recovered; disasm-precedence
  +9; **both propagate clearly-wrong names** on the cases they flip. Current
  strict-drop (drop both on disagreement) is the right call — neither path
  is reliable enough to arbitrate the other. The verified post-fix net
  on `02_MAIN` is 915 Recovered (see the production-state bullet above).
- **radare2 4 GiB `R2_STDOUT_CAP` streaming is verified live.** The former
  256 MiB in-memory cap blocked Thumb on production; stdout is now streamed
  to `thumb/<addr:08x>.stdout` with `R2_STDOUT_CAP_BYTES = 4 GiB` (see
  **radare2 stdout streaming** below). The verified full `decompose` did not
  hit the cap (`thumb_functions` = 117,444; no `thumb_error`) and closed
  Thumb through pass 2 (`thumb_decompiled` = 77,456; globals thumb-majority).
- **Phase 3.2: global storage-shape recovery.** Default-on in every
  `decompose` (normal, `--no-symbol-pass`, and valid pass-2 fallback). The
  stage runs **once**, immediately after the complete symbol route returns
  and before `decode_rf` / `hardware_config`, via one shared
  `PostSymbolStep::GlobalShapes` call. That placement is binding: pass 2
  replaces `functions.json`, so an earlier run would bind evidence to an
  inventory that is no longer on disk. Both routes therefore analyze the
  **terminal** `images/<label>/<label>.bin`, `globals.json`,
  `functions.json`, and (when the current decompile result reports a Thumb
  inventory) `thumb_functions.json`. A valid empty Recovered set still
  writes a source-hashed empty sidecar; it is not a skipped analysis.
  `globals.json` is never rewritten. `--prune` retains
  `decompiled/global_shapes.json`. Pass-2 refresh still owns only
  `decompiled.c` / `disasm.lst` / `functions.json` and must not touch this
  sidecar.
- **Phase 3.2 currentness.** The stage does not infer readiness from file
  existence. `current_global_shapes_run` copies the current decompile
  snapshot: raw Ghidra `functions` plus both Ghidra projection counters
  (their sum must equal `functions`); Thumb substantial / accepted /
  quarantined either all absent or all present; `thumb_error` absent;
  `globals_error` absent; `globals_recovered: Some` (zero is invoked, not
  skipped). Missing current-run markers, a stale `globals.json` from an
  earlier failed rerun, or a count mismatch is a per-image hard failure:
  the analyzer is not called, an existing sidecar is left byte-identical,
  later images continue, and the aggregate `global_shapes` stage is
  `failed`. **Absent versus stale Thumb:** no current Thumb inventory plus
  no file is valid (`thumb_functions_sha256` is JSON `null`). No current
  Thumb inventory plus an unexpected old `thumb_functions.json` is a hard
  currentness error. A reported Thumb count requires a present, valid file
  whose substantial / accepted / quarantined counts match the current
  request. `ImageReport.thumb_functions` remains the substantial-size
  metric (`size >= 32`); every retained record is still validated.
- **Phase 3.2 tagged projections.** Every `functions.json` and
  `thumb_functions.json` record is a strict tagged union. Accepted:
  non-empty `decode_ranges`, empty `decode_range_errors`. Quarantined:
  empty ranges, one or more errors. Both empty, both non-empty, or a
  missing field is an unsupported/malformed producer schema, not an
  implicit empty. Any record-local defect quarantines that **complete**
  record; prefixes are not salvaged and the other inventory cannot rescue
  it. The closed error `kind` set is:
  `missing_instruction_at_entry`, `missing_isa_context`,
  `invalid_isa_context`, `overridden_instruction_length`,
  `invalid_instruction_length`, `misaligned_instruction`,
  `extent_outside_function`, `extent_outside_image`,
  `missing_operation_body`, `invalid_operation_address`,
  `invalid_operation_bytes`, `raw_byte_mismatch`, `duplicate_extent`,
  `overlapping_extent`, `entry_not_range_start`, `empty_projection`.
  Each inventory conserves `raw = accepted + quarantined`. Execution
  identity is entry plus the complete ordered range list; identical
  identities union `(entry, name)` contexts and are decoded once. Distinct
  identities coexist even when their bytes overlap across ISAs — no
  source, alignment, decoder result, order, or support count wins.
  Quarantined records never reach the decoder. Quarantine counters stay
  separate from accepted-range `decode_failures`.
- **Phase 3.2 decoder.** The only production adapter is
  `scaleservers-arm32-assembly` **1.0.0** (`ArmA32Instruction::decode` /
  `ArmT32Instruction::decode`). It is a current, correct, pure-Rust crate
  with no C/C++/FFI/native build. Dependency-specific enums stay inside
  `decoder.rs`; the rest of the crate sees only the project-owned
  instruction. The sidecar records `decoder.crate` and `decoder.version`
  from the adapter identity; those constants must stay in lockstep with
  `Cargo.toml`. Revalidation after analysis rejects a v1 artifact whose
  status, source order, hashes, or conservation invariants do not match
  the loaded inputs. VFP/NEON/MVE/unrecognized encodings are explicit
  unsupported/decode-failure events, never guessed. An accepted identity
  whose **entry** is not a decoded instruction PC is recoverable evidence
  loss: `reachable_blocks` returns `Ok([])`, the coordinator counts one
  `decode_failure` if no range already recorded one, later identities
  still run, and the sidecar may commit. Adapter-invariant errors
  (duplicate PC, PC regression, wrong ISA, zero/impossible length,
  overrun) remain hard per-image failures and preserve any older sidecar.
- **Phase 3.2 state model.** The coordinator keeps at most one function's
  decoded instruction map and releases it before the next. Blocks are
  **direct-only**: boundaries are the function entry, every valid direct
  branch target that is an instruction PC in the same map, and the
  fallthrough after a control transfer when that PC exists. Traversal
  starts only at the entry. No edge is invented across a gap, into an
  undecoded suffix, or for a call / return / indirect transfer. A call's
  fallthrough block may be visited but begins unknown; the callee is not
  entered. Every reachable block starts with all registers unknown; no
  fact crosses an edge. `state_barriers` counts a non-entry block start
  plus every instruction that kills at least one known fact or clears
  unbounded state.
- **Phase 3.2 anchoring.** A fact becomes a Recovered global only when an
  exact 32-bit value equals a Recovered address. There is no
  nearest-global attribution. Once anchored, copy/arithmetic keep that
  identity and never retarget just because the numeric result equals
  another Recovered base. `movw` establishes an exact value; `movt`
  updates an already-exact low half and otherwise leaves the destination
  unknown. Observations are collected against the pre-write state;
  writeback and leftover destinations are applied afterwards. Negative
  offsets, overflowing `offset + width`, and u32 address wrap kill the
  fact and do not observe.
- **Phase 3.2 aggregation and artifact.** Observations that agree at one
  `(ISA, PC)` union contexts and provenance. Two or more semantic
  alternatives at that PC are a conflict; every implicated Recovered
  target receives the complete alternative group. Support count and
  function order never choose a winner. Distinct cross-ISA PCs never
  collapse because their byte intervals overlap. Status invariants:
  `inferred` has observations, no conflicts, and a summary; `no_evidence`
  has empty observations/conflicts and `summary: null`; `conflicting` has
  non-empty conflicts and `summary: null`. `inferred + no_evidence +
  conflicting` equals the Recovered count. `minimum_size` is the maximum
  checked `offset + width`. Provisional labels are
  `scalar_candidate { width }`, `array_candidate { element_width,
  minimum_elements }`, or `unknown` — never an allocation size or C type.
  Wire field order is the struct declaration order. Serialization is
  `serde_json` pretty (two-space) with **no trailing newline**. Addresses
  are canonical lowercase `0x…`; SHA-256 values are lowercase 64-hex.
  The complete byte vector is serialized before the destination is opened,
  then atomically replaced. A decoder/adapter panic is caught, bounded to
  2,048 Unicode characters, fails that image, and does not prevent later
  images. Per-image `None` vs `Some(0)`: the nine `global_shapes_*`
  numeric `ImageReport` fields (including `global_shape_observations`)
  omit when analysis did not complete and emit `0` for a completed zero;
  `global_shapes_error` is reason-only and exclusive with those counts.
- **Phase 3.2 depth-1 interprocedural pass.** After Pass 1's intra-procedural
  tracking, `analyze_loaded_inputs` (`mod.rs`) runs a second pass that extends
  Recovered-global evidence across one direct call hop. Load-bearing
  invariants:
  (1) **Depth-1.** Call-facts are harvested only from Pass 1's unseeded run;
  Pass 2 re-tracks a seeded callee with the same `track_function` and so
  emits call-facts of its own, but the coordinator discards them — no seed
  ever originates from an already-seeded run, so the harvest cannot recurse
  past one hop.
  (2) **Direct `bl` + AAPCS r0–r3 only.** `ControlFlow::Call { target:
  Option<CallTarget> }` resolves to `Some` only for direct `bl` (A32 `Bl_A1` /
  T32 `Bl_T1`, same-ISA entry); `blx`-immediate (cross-ISA resolution
  deferred) and `blx`-register / `blxns`-register (indirect) always carry
  `target: None` and harvest nothing. A call-fact's seed draws only from
  r0–r3, and only a register holding a bare recovered-global address
  (displacement 0) counts — an interior `&global + k` does not seed.
  (3) **Strict entry+ISA callee resolution.** `resolve_callee` requires the
  call's target to equal an accepted identity's entry exactly, with that
  identity's first decode-range ISA matching the call's resolved ISA; zero or
  more than one surviving match is unresolved and counted into
  `call_facts_unresolved`, never guessed.
  (4) **Entry-block-only seeding.** The seed is installed only into the
  callee's entry-block state; every other block still starts empty, matching
  the existing per-block model.
  (5) **Attribution, not conflict.** An interprocedural observation is
  attributed directly to the global that seeded it and never enters the
  cross-global same-`(ISA, PC)` conflict pool intra evidence uses — a shared
  callee instruction seeded from two different globals yields two independent
  observations, never a conflict.
  (6) **Additive-only.** Intra is authoritative: an interprocedural
  observation that collides with a different intra semantic key at the same
  `(ISA, PC)` is dropped and counted (`interprocedural_dropped`) rather than
  overriding it; interprocedural evidence alone never demotes an `inferred`
  global and never produces `conflicting`.
  (7) **`via` iff interprocedural.** A non-empty `via` (caller→callee call
  hops: `caller_entry`, `caller_name`, `call_pc`, `arg_register` as
  `"r0"`–`"r3"`) marks an observation as interprocedural; `aggregate`'s
  `validate` recomputes `interprocedural_observations` from the via-bearing
  observation count and fails that image's `global_shapes` stage closed on
  any mismatch.
- **Phase 3.2 focused tests and replay.**
  ```
  cargo test global_shapes:: -- --nocapture
  cargo test execution_ranges::tests -- --nocapture
  cargo test decompose::tests::global_shapes_stage_ -- --nocapture
  cargo test decompose::tests::image_report_serializes_global_shapes -- --nocapture
  cargo test decompose::tests::refresh_decompiled_replaces_ghidra_outputs_and_preserves_sidecars -- --nocapture
  cargo test decompose::tests::prune_keeps_only_leaves -- --nocapture
  cargo test --test global_shapes_golden -- --nocapture
  cargo test --test decompose_golden report_json_includes_global_shapes_fields -- --nocapture
  PME_GLOBAL_SHAPES_REPLAY=1 PME_GOLDEN_DIR=/path/to/unpruned/decompose \
    cargo test --release \
    global_shapes::tests::retained_tree_replay_is_deterministic_and_non_mutating \
    -- --ignored --nocapture
  PME_GLOBAL_SHAPES_MEASURE=1 PME_GOLDEN_DIR=/path/to/unpruned/decompose \
    cargo test --release -p pixel-modem-extractor --lib \
    global_shapes::tests::interprocedural_yield_on_retained_tree \
    -- --ignored --nocapture
  ```
  Goldens skip when `$PME_GOLDEN_DIR` is unset. Replay also needs the raw
  image slices and does not write. The interprocedural yield measurement
  reuses the same replay machinery (two in-memory
  `analyze_to_bytes_without_commit` passes, no write) and only `println!`s
  the status split plus the six new `analysis` counters — see **Phase 3.2
  interprocedural measured reality** below for the recorded numbers.
- **Phase 3.2 production baselines (verified full `decompose`, ~1 h 37 m,
  exit 0).** Decoder `scaleservers-arm32-assembly` 1.0.0. Recovered shapes
  915 MAIN / 921 total; MAIN observations 32 ARM + 907 Thumb; 125 inferred
  / 787 `no_evidence` / 3 conflicting; MAIN `decode_failures` = 37,629
  (recoverable; the image still succeeds). Producer conservation on MAIN:
  Ghidra 107,955 = 107,785 accepted + 170 quarantined; Thumb 151,411 =
  149,169 accepted + 2,242 quarantined. Established MAIN
  `functions` = 107,955, `thumb_functions` = 117,444,
  `thumb_decompiled` = 77,456, `globals_recovered` = 915. `globals.json`
  is unchanged by the new stage. `--prune` keeps the sidecar. Do not cite
  `thumb_decompiled` = 10,965 as current HEAD.
- **Phase 3.2 interprocedural measured reality.** The depth-1 pass above is
  correct, deterministic, and fail-closed, but its measured net yield on the
  same production `02_MAIN` tree as the baselines above is **zero**.
  `inferred`/`no_evidence`/`conflicting` held at 125/787/3 — identical to the
  intra-only baseline — even though the pass did real work:
  `direct_calls_resolved` 191, `call_facts_unresolved` 287, `seeded_callees`
  52, `seed_vectors` 60, `interprocedural_observations` 3,
  `interprocedural_dropped` 0. All 3 interprocedural observations
  corroborated globals that were already `inferred` from intra-procedural
  evidence; none converted a `no_evidence` global. Two compounding v1
  limitations explain the zero: (1) **store-not-dereference** — the
  pass-by-reference call sites this pass targets are registration/logging
  tables, and the callee typically *stores* `&global` into the table rather
  than dereferencing it, so the evidence it reveals is the table's shape, not
  the global's; the dereferences that would reveal the global's own shape
  happen later, through the stored pointer (pointer/alias following — a v1
  non-goal); (2) **entry-block-only seeding** — a dereference after the
  callee's first branch is invisible to the seed (callee-side cross-block
  seeding — also a v1 non-goal). Meaningful yield on this firmware needs one
  or both of those, both larger efforts than depth-1 argument propagation;
  the call-fact primitive and the six counters above are the foundation for
  them, not a finished win by themselves. Corollary for whoever picks this up:
  because the barrier is store-not-dereference (not call depth), **deeper
  (depth-K) argument propagation would not help** — and neither would the
  targeted pointer/alias analysis this note once proposed as the successor
  lever. A 2026-08-13 ceiling spike (throwaway instrumentation of the real
  decoder/tracker over production r2, funnel over the `&global` → store → slot
  → load → dereference chain) measured that lever at **≤ 1 recoverable global
  on `02_MAIN`**: of 787 stuck globals only 80 store `&global` as a value at
  all, 27 reach a static (constant-address) slot (53 use dynamic `[table,
  rIndex]` slots), and just 1 of the 26 static slots is ever read back. An
  unsound "seed every callee block" upper bound leaves that funnel unchanged,
  so it is a true ceiling, not a seeding artifact; the other deferred lever,
  callee-side cross-block, is ≤ 3. **Treat interprocedural shape recovery as
  closed at ~0 for this firmware and do not build it** — the only lever with
  measured yield is the sound *intra*-procedural cross-block dataflow pass
  (~+5%, ~41 globals). Do not cite this pass as recovering shapes on production
  `02_MAIN` — cite it as correct, additive-only, and honestly measured at zero.
  Full design: `2026-08-13-interprocedural-global-shapes-design.md`;
  interprocedural root-cause: `2026-08-13-no-evidence-dominance-findings.md`;
  pointer-tracking ceiling: `2026-08-13-pointer-tracking-ceiling-findings.md`
  (all process artifacts under `~/.superpowers/pixel-modem-extractor/`, not
  part of this repo).
- **Phase 3.2 environment traps.** Currentness comes from the current-run
  markers, not leftover files. A Ghidra 12 output root must stay
  canonically dot-free (see **Ghidra 12 headless API notes**). Replay and
  goldens need a complete unpruned tree; a pruned golden has no raw
  `.bin` slices. The dense-Thumb memory envelope (~56 GiB RSS) still
  applies — shape recovery is not the peak. Do not parse Ghidra/radare2
  disassembly text, infer ISA from alignment or inventory name, attribute
  an address to the nearest global, or leak decoder-crate enums outside
  `decoder.rs`.
- **Winning TameAnalysis options (Phase 2).** On the smallest dense-Thumb region
  of a real `02_MAIN` (2.06 MiB sample, `N_r2 = 11023`), `TIGHTEN_EXTRA = {}`
  (empty) won — the shared `DISABLE` loop (Aggressive Instruction Finder +
  ARM Aggressive Instruction Finder) is sufficient for Ghidra 12.1.2 to
  converge in 80 s with 0 repair-log lines and 70 % radare2 coverage. Losing
  candidates (one-line rationale each): **Candidate 3** (disable
  `ClearFlowAndRepairCmd`) and **Candidate 4** (cap repair) were never run —
  Candidate 2 hit every stop condition first, so neither option name was
  resolved against Ghidra 12's analysis-properties sheet. Production verification
  on a real `02_MAIN` confirmed the sample did not predict
  the full image: Surface B's watch fires after ~28 min (>100k overlap-repair log
  lines), the datamark retry succeeds, and `thumb_decompiled` stays at 0 — Phase
  2.1 picks up from here.
- **Winning TameAnalysis options (Phase 2.1, on success).** On the full
  production `02_MAIN` (~87 MB), Phase 2's empty `TIGHTEN_EXTRA` was
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
  run — Candidate 5 hit every stop condition first.
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
  `max(60s, bytes / 1MiB × 40s)`, grounded in the dense-Thumb measurement
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
- **radare2 stdout streaming (Phase 2+).** `run_radare2_thumb` streams
  r2 stdout to `thumb/<addr:08x>.stdout` in 8 KiB chunks via the
  pure-I/O `stream_to_cap` helper, accumulating a byte counter;
  exceeding `R2_STDOUT_CAP_BYTES = 4 GiB` fails closed (kill + reap +
  remove partial file + `Error::ToolNotFound`). The 4 GiB value is
  grounded in production: `02_MAIN`'s `410b0000` region emits ~1.82 GiB
  of `aflj;pdfj @@f` JSON (~25 KiB/function × ~71 k functions); 4 GiB
  is ~2× headroom. Do not lower this cap without confirming the
  largest real image's region still fits — the failure mode
  (`thumb_error` on the image, no `thumb_functions.json` written) is
  silent at the JSON level. Do not raise it casually — pathological r2
  output is what the cap exists to defend against.
- **`thumb/<addr:08x>.stdout` retention.** The streamed file is kept
  after parse (not deleted). Disk is cheap; the debugging value
  (inspect r2 output when `data_refs` look wrong or parse fails)
  outweighs storage cost. `--prune` drops it with the rest of the
  `thumb/` tree.
- **Why streaming-to-disk.** Three reasons: (1) decouples r2's write
  rate from Rust's read rate (no pipe-stall during slow parse); (2)
  persistent artifact for post-hoc inspection; (3) sets up future
  streaming-parse optionality. Raw `.stdout` captures remain on disk.
  **Memory profile is NOT reduced** — `run_radare2_thumb` reads and parses the
  current capture while retaining the normalized `serde_json::Value` function
  collection accumulated from completed regions. A full dense-Thumb
  `decompose` can therefore peak around 56 GiB RSS. The 4 GiB cap limits each
  raw capture, not the accumulated normalized collection plus the current
  capture's read/parse allocations. Plan for at least 64 GiB RAM plus swap or
  other headroom; smaller images without dense Thumb regions stay under 1 GiB.
  `--no-thumb-decompile` only selects Ghidra `datamark` mode and skips both
  `body_c` enrichment sweeps; it still invokes the dense-region radare2
  capture/read/parse loop and therefore does not avoid the full dense-Thumb
  memory envelope. Reducing memory requires streaming parsing plus bounded
  normalized accumulation (deferred follow-up).
- **`stream_to_cap` helper.** The pure-I/O streaming loop is extracted
  into `fn stream_to_cap<R, W>(reader, writer, cap) -> io::Result<usize>`
  so it's unit-testable without spawning r2 (`Cursor<Vec<u8>>` readers,
  `Vec<u8>` writers). Callers own process lifecycle (kill, reap,
  file removal). Five inline unit tests cover happy path, cap-exceed,
  empty input, exact-cap boundary, and the constant value.
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
  - **Headless project paths must be canonically dot-free.**
    `pixel-modem-extractor` canonicalizes the output root before appending the
    Ghidra project path. Ghidra 12 rejects any dot-prefixed component in that
    resulting path. Because canonicalization happens first, a symlink cannot
    hide a dot-prefixed canonical ancestor from this pipeline. Put production
    output and Ghidra project state under a root whose canonical path contains
    no dot-prefixed components.
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
  - **`-process` mode, not `-import`, for pass 2.** Applicable post-script
    vectors, all after `<projectDir> <projectName> -process <label> -noanalysis
    -scriptPath …`, are:

        functions + globals: -postScript ApplySymbols.java <function_map> -postScript ApplyGlobals.java <global_map> -postScript ExportDecomp.java <out>
        functions only:      -postScript ApplySymbols.java <function_map> -postScript ExportDecomp.java <out>
        globals only:        -postScript ApplyGlobals.java <global_map> -postScript ExportDecomp.java <out>

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
  Option<String>` (set for late typed-map validation, analyzeHeadless spawn or
  non-zero process failure, or the caller's owned-export refresh failure;
  process failures include a ~2 KB tail of stderr). A pass-2 failure does **not**
  mark the pass-1 image `failed` in `report.json` — pass 1 already produced a
  valid `decompiled.c`. `run_two_pass` returns an explicit outcome for every
  scheduled label, including labels absent from the pass-1 report. The caller
  combines process outcomes with exact-export refresh outcomes into the
  separate `decompile_pass2` stage; the pass-1 `decompile` stage stays intact.

## How we work here

- **Design before code.** Non-trivial work gets a written design spec and an
  implementation plan before implementation begins. Keep process artifacts
  outside the repository; durable outcomes land in this file, the README, and
  code comments. Read this CONTRIBUTING.md and the
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
  unit of review and merge; master stays shippable. Execution ledgers are
  external scratch — don't commit them; recover from `git log` if destroyed.

## Recipe: adding a subcommand or decoder

1. Add a focused module under `src/` and expose it in `src/lib.rs`.
2. Add a `Commands::` variant and match arm in `src/cli.rs`, with a sensible `--out`
   default.
3. Add a parse/`--help` test — the existing tests in `src/cli.rs` are the pattern.
4. If it emits artifacts, add env-gated golden coverage like the other `*_golden.rs`.
5. Update the `## Commands` table in `README.md`, and keep the decoder fail-closed
   (return an error on malformed input rather than emitting garbage — see the error
   convention above).
