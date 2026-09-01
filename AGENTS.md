# Contributing guidelines

Guide for anyone — human or AI — changing this repository. For *using* the CLI, see
[`README.md`](README.md); this file is about developing it.

`pixel-modem-extractor` is a Rust CLI that extracts and analyzes the Samsung Exynos
"Shannon" S5300 / S5400 baseband family from a Pixel radio FBPK image. Extraction and the
decoders need no runtime dependencies. `decompile --run` and `decompose` require local Ghidra
and radare2; explicit `--rizin-fallback` additionally preflights Rizin for failed Thumb regions.

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
  `Error::SizeMismatch` rather than indexing OOB. Every Thumb analyzer attempt rejects
  stdout beyond 4 GiB and receives a 16 GiB Unix `RLIMIT_AS`; a failed region is recorded
  durably when another region succeeds, while all-region failure publishes no new sidecar.

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
  An explicit `GHIDRA_INSTALL_DIR` is authoritative: that exact root must contain a regular launcher
  at either the upstream `support/analyzeHeadless` path or Homebrew's
  `libexec/support/analyzeHeadless` path. If neither is valid, every real-Ghidra test fails its
  prerequisite without probing or substituting `/opt/ghidra`. Only when the variable is unset does
  the resolver probe `/opt/ghidra/support/analyzeHeadless` and skip cleanly if it is absent. CI runs
  the binary nightly / on demand via the `ghidra-e2e` workflow. Run it serially:

      cargo test --test decompile_golden -- --nocapture --test-threads=1

  Parallel tests share Ghidra launcher/JDK state and have produced a baseline exit-127
  failure even though focused and full serial runs pass. The focused pass-2 application
  test is below. When other worktrees may build concurrently, give a long all-target run an
  isolated `CARGO_TARGET_DIR`: a shared target can replace prebuilt integration-test executables
  while the serial Ghidra binary is still running.

  The focused pass-2 application test is:

      cargo test --test decompile_golden \
        pass2_applies_functions_and_strict_globals_in_one_process -- --nocapture --test-threads=1

  It drives the real scripts against a synthetic ARM program and skips cleanly when Ghidra is
  unavailable. `run_drives_ghidra_end_to_end` covers pass 1; the focused test covers function and
  global application, strict ownership, atomic map rejection, and the independent final export.
  The sibling `pass2_applies_global_types_and_skips_span_collision` covers `ApplyGlobalTypes.java`
  the same way (applied + span-collision skip); see **Phase 3.2 type application** below.
  The exception-root cases in this binary use one production-generated synthetic fixture to cover
  ARM/Thumb roots, shared handlers, foreign primaries, exact replay, malformed/ambiguous maps,
  rollback, both datamark and tighten survival with exact bodies/flow, stronger pass-2 transitions,
  stale ownership, and the v4 export marker. Every case shares the resolver above: a selected
  installation that is unavailable or broken fails rather than skipping.
- **Runtime-scatter corpus goldens** (`tests/scatter_golden.rs`) authenticate and validate
  retained MAIN files supplied explicitly from outside the repository:

      PME_S5400_MAIN=/path/to/s5400/MAIN.bin \
      PME_S5300_MAIN=/path/to/s5300/MAIN.bin \
      cargo test --release --test scatter_golden -- --nocapture

  Each test is gated only by its own variable and skips cleanly when that variable is unset
  or its input is absent, so one available corpus still runs independently. Verify the
  no-corpus path with
  `env -u PME_S5400_MAIN -u PME_S5300_MAIN cargo test --test scatter_golden -- --nocapture`.
  These inputs and every generated payload remain outside git; tests commit only structural
  metadata, addresses, counts, and hashes, never proprietary firmware or derived bytes.
- **Private-corpus PAL task goldens** (`tests/pal_tasks_golden.rs`) consume the *same* two
  retained MAIN files (`PME_S5400_MAIN` / `PME_S5300_MAIN`) through the complete production
  generation path (scatter + PAL manifest) and pin the corrected 133/162 baseline — see
  **Runtime PAL task inventory** below for the commands, the digest-population procedure, and
  the gating test (`no_corpus_environment_skips_independently`) that proves each leg skips
  only on unset/missing input.
- **Private-corpus exception-root goldens** (`tests/exception_roots_golden.rs`) consume those
  same independently configured `PME_S5400_MAIN` / `PME_S5300_MAIN` inputs at load
  `0x40010000` through production runtime generation, materialization, and strict on-disk reading:

      PME_S5400_MAIN=/path/to/s5400/MAIN.bin \
      PME_S5300_MAIN=/path/to/s5300/MAIN.bin \
      cargo test --test exception_roots_golden -- --nocapture --test-threads=1

  Each variable gates only its own model, and **only an unset variable skips** (printing that named
  leg as UNRUN). Every set value must be valid Unicode and name a regular, non-symlink file under
  non-following metadata; missing paths, directories, symlinks (including links to regular files),
  special files, and metadata/path errors fail that named leg. One valid configured corpus still
  runs when its sibling is unset. Verify the forced no-corpus path with
  `env -u PME_S5400_MAIN -u PME_S5300_MAIN cargo test --test exception_roots_golden -- --nocapture`.
  Pins are structural only: one complete initial table, eight literal slots in architectural role
  order, confirmed-initial VBAR, eight distinct roots, canonical ordering/conservation, and the
  canonical manifest BLAKE3. Never commit firmware bytes, generated manifests, recovered names,
  messages, source paths, or absolute corpus paths. To populate a new lawful corpus pin, leave its
  digest sentinel empty, run that configured leg once, copy only the printed manifest BLAKE3, and
  rerun it to PASS; an unavailable leg remains unpopulated by leaving its variable unset.
- **Private-corpus DBT debug-trace goldens** (`tests/dbt_traces_golden.rs`) consume the *same*
  two retained MAIN files (`PME_S5400_MAIN` / `PME_S5300_MAIN`) through a TOC wrap (name
  `MAIN`, base `0x40010000`, toc_index 3 for S5400 / 2 for S5300) and pin catalog counts,
  fourth-word variants, and the populated `manifest_metadata_blake3`. Unique-message pins are
  174,243 / 165,051. Each catalog test is gated only by its own variable and skips cleanly
  when that variable is unset or its input is absent; a set path that is not a regular file
  fails. `PME_DECOMPOSED_GOLDEN_DIR` gates the refs inventory lookup and skips when unset,
  absent, or lacking `functions.json`. Serial-test note: none needed — no Ghidra legs.
  Verify the no-corpus path with
  `env -u PME_S5400_MAIN -u PME_S5300_MAIN -u PME_DECOMPOSED_GOLDEN_DIR cargo test --test dbt_traces_golden -- --nocapture`.
  These inputs and every generated payload remain outside git; tests commit only structural
  metadata, addresses, counts, and hashes.
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
- **External tools:** `decompile --run` and `decompose` require and preflight Ghidra
  (`analyzeHeadless`) plus radare2 (`r2`). Rizin is neither discovered nor version-probed
  by default; it is a third preflight requirement only with `--rizin-fallback`.
- **Dense-Thumb hermetic coverage:** `decompile::tests::fake_radare2_route_emits_strict_v3_and_all_region_failure_preserves_sidecars`
  drives the real route with synthetic image bytes and fake Ghidra/radare2; `thumb_analysis`
  tests cover exact argv, fallback ordering, timeout/process-tree cleanup, caps, xref adaptation,
  and mixed ownership. `globals_golden::synthetic_rizin_v3_ownership_and_data_refs_reach_downstream_consumers`
  proves Rizin attribution and canonical `data_refs` without firmware or external tools. Do not
  move process-level fallback duplication into a Ghidra route test.
- **Two-model Thumb acceptance:** run `scripts/rizin-thumb-acceptance.sh`. It is the recipe — a
  transcript of shell commands can fall through a reused root, a missing wrapper, or a failed
  build and still look like it ran, so every provenance gate lives in one `set -euo pipefail`
  script instead:

      scripts/rizin-thumb-acceptance.sh \
          --root /absolute/non-hidden/disk-backed/rizin-thumb-fallback-acceptance \
          --mustang /absolute/path/to/mustang-radio.img \
          --cheetah /absolute/path/to/cheetah-radio.img

  `--print-legs` performs every gate and prints the four leg commands without running them; `--rizin`
  overrides the wrapped executable. What the script enforces, and why each gate exists:

  - The acceptance root must be absolute, outside the repository, non-hidden, not under `/tmp`, and
    **must not already exist** — a reused root is invalid provenance.
  - It creates the `rizin` audit wrapper under the root and puts it first on `PATH` for *all four*
    legs, so an empty default log proves no discovery/probe/spawn rather than only no analysis. Each
    enabled-log `-v` entry is a version probe and each `-c` entry an analyzer process, so a
    configured-but-unused Rizin has one probe and zero analyzer calls.
  - The binary is built `--release --locked` into an isolated `CARGO_TARGET_DIR` under the root, with
    `--manifest-path` anchored to the worktree holding the script. Linked worktrees can overwrite a
    shared `target/release` or shared `CARGO_TARGET_DIR`, so such a binary is invalid provenance, and
    a path selected by mtime is never a substitute.
  - Before the first leg it records HEAD, the worktree-diff hash, `cargo pkgid`, the resolved binary
    path and its hash into `provenance.txt`, and checks the binary really carries this feature: the
    strict-v3 format marker, the Rizin `aaa;aflj;pdfj @@F;axlj` command, and `--rizin-fallback` in
    `decompose --help`.
  - The four legs (mustang/cheetah × default/fallback) run sequentially under `/usr/bin/time -v`.
    After each one, and before the next starts, the completed `report.json` must carry the audited
    package `tool_version`, an exact radare2 path and version, the leg's `rizin_fallback` value, and
    (when enabled) the wrapper as the Rizin executable plus its exact version.

  The script stops at measurement; the analysis gates are still yours. Keep inputs, trees, captures,
  logs, and `/usr/bin/time -v` output outside git. Record canonical tool identities, wall time, and
  maximum RSS. For each fresh sidecar compare raw/substantial/accepted/quarantined counts and accepted
  execution identities with the retained pre-v3 tree; explain size changes from `realsz` and
  source-attribution changes from `decode_ranges`. Prove healthy regions and mustang's largest region
  remain radare2-owned. On cheetah, require `0x42310000` to show failed radare2 then successful Rizin,
  non-empty adapted refs, downstream `AnalysisTool::Rizin`, and globals yield/conflicts against the
  valid no-xref baseline. Never infer a corpus pass from a clean env-gated skip, and never hardcode
  analyzer-version-dependent inventory counts into unit tests.
- Write the failing test first (TDD), then the minimal code to pass it.

### Hashing and golden identity

- Per-file/per-bytes digests are **blake3** (`manifest::blake3_bytes` /
  `blake3_file`), serialized as `*_blake3` JSON fields. The `sha2` crate is
  gone. Exception: `hwcfg`'s `present_shas`/`referenced_shas`/`entries[].sha`
  are RF_CFG blob identifiers (corpus nomenclature), not digests. Related
  provenance rule: `coverage.rf_dir` in `rf/hwcfg_summary/summary.json` is
  recorded as `"rf_cfg_decompressed"` (tree-relative) when produced by
  `decompose`, so the pinned `rf/` surface carries no absolute output path;
  the standalone `hardware-config` subcommand records the user's path
  spelling verbatim.
- Whole-tree identity is **`pme-paq-v1`** (`src/tree_hash.rs`): `paq::hash_source`
  blake3 leaf-set, hidden entries included, zero exclusions, fail-closed
  (missing/non-dir/symlink/non-UTF-8 → `Error::BadTree`, no hash). Pinned test
  vector locks the scheme; any `paq` crate bump that moves it requires a named
  `pme-paq-v2` revision plus fresh goldens.
- Golden pinning: the `extract` output tree is pinned whole-tree
  (`extract_tree_matches_golden_paqs`); `decompose` pins only its
  **measured-deterministic** surfaces (two fresh mustang runs, 2026-08-18):
  `manifest.json` (blake3 content — pme-paq-v1 is directory-only), `tokens/`,
  `rf/`, and `ghidra/global_types_maps/`. Unpinned, with the measured reason:
  `report.json` (wall-clock `duration_ms`), `ghidra/` project residue,
  `ghidra/symbol_maps/` (embeds the pass-1 `functions.json` digest, whose
  content carries Ghidra run-to-run jitter — ~8 lines in 00_BOOT's
  `functions.json` between two runs; the symbol arrays themselves reproduced
  byte-identically), `images/*/source_tree/` (recovered-code enrichment
  derives from the same jittery Ghidra evidence), and everything under
  `images/*/decompiled/`. Mustang thus joins pe-decompose's SC4/XWA corpora
  with measured Ghidra decompile nondeterminism; BEA-style byte-stable
  Ghidra output was **not** observed here.
- **Re-baselining goldens** (last done 2026-08-19, for the opaque-image
  battery — the manifest `battery` fields and the skipped-PSP report row
  changed both trees' shape): run `extract` + `decompose` on a real radio
  image with the current binary, then `pixel-modem-extractor tree-hash <dir>` each pinned
  surface/tree and record the values. `PME_GOLDEN_DIR` is dual-mode and the
  golden lives in **two trees**, so verification is two invocations:

  1. `radio-mustang-extracted-v3` — a pristine fresh `extract` output. It must
     contain *nothing beyond* what `extract` writes (the whole-tree paq pin
     hashes every leaf). Verify with
     `PME_GOLDEN_DIR=…/radio-mustang-extracted-v3 PME_RADIO_IMG=… cargo test --test golden`.
     (`radio-mustang-extracted` is archived as `radio-mustang-extracted.pre-opaque`
     — pre-battery manifest; the classify corpus test reads this v3 tree's
     `modem.bin.split`.)
  2. `radio-mustang-decomposed-v3` — a fresh full `decompose` output (the current
     re-baseline tree: the manifest `battery` fields and the skipped-PSP
     report row shifted the pinned `manifest.json` hash and report shape,
     superseding `radio-mustang-decomposed`, archived as
     `radio-mustang-decomposed.pre-opaque`). Verify with
      `PME_GOLDEN_DIR=PME_DECOMPOSED_GOLDEN_DIR=…/radio-mustang-decomposed-v3
      PME_RADIO_IMG=… cargo test --release --test decompose_golden
      decompose_pinned_surfaces_match_reference` plus the read-only
     decompose-layout legs (`global_shapes_golden`, the `PME_GOLDEN_DIR` legs
     of `globals_golden`). `tests/symbolicate_golden.rs` rewrites its tree in
     place — point `PME_DECOMPOSED_DIR` at a disposable copy, never the golden.
     Running the full `--test decompose_golden` suite (not just the named
     pinned-surfaces test) makes its three e2e legs each stage a full decompose
     output under `std::env::temp_dir()` (~7G apiece); on a host whose `/tmp`
     is a small tmpfs that exhausts it and every leg fails fast with ENOSPC
     ("No space left on device") — set `TMPDIR` to a disk-backed directory
     before running them.

  Use the same `PME_RADIO_IMG` path *spelling* (e.g. one fixed absolute path)
  for the re-baseline and every verification run — `manifest.json` embeds the
  path string as passed (`pipeline.rs` `source_image`), so a
  relative-vs-absolute difference shifts the pinned hashes. Old goldens embed
  sha256/v3 fields and cannot be reused (the pre-blake3 decompose tree is kept
  as `radio-mustang-decomposed.pre-blake3`). The legacy `PIXELMODEM_rootfs/…`
  extract-layout legs (`extract_matches_golden` per-file compares, and the
  source-tree/hwcfg/decode-rf/decode-tokens goldens' input paths) refer to a
  pre-modern layout no golden carries — they skip cleanly; the whole-tree paq
  pin supersedes the per-file extract compare.

## Repository layout

`src/` is a set of focused modules and small subsystems — one concern each:

| Path | Responsibility |
|---|---|
| `pipeline.rs` | Orchestrates the `extract` stages end to end |
| `fbpk.rs` | FBPK radio-image parser |
| `ext4.rs` | ext4 filesystem reader (via `ext4-view`) |
| `archive.rs` | `ustar`/tar handling around the ext4 payload |
| `gzip.rs` | Gunzip the `RF_CFG_*` calibration blobs |
| `toc.rs` | `modem.bin` TOC parse + split into the model-dependent embedded images |
| `classify.rs` | 5-test opaque battery — whole-image H, χ²/df, serial correlation, 64-KiB window entropies; unanimous fail-closed verdict |
| `semantic_cfg.rs` | Shared bounded A32/T32 direct-edge CFG, compact dominance, typed handoffs, and exact must-value dataflow used by PAL and exception roots |
| `scatter/mod.rs` | Semantic A32 scatter discovery, exact bounded-table classification, and checked runtime planning |
| `scatter/decompress.rs` | Strict corpus-validated `decompress1` decoder and cumulative decode-work budget |
| `scatter/artifact.rs` | Deterministic load-map manifest/payload materialization and staged publication |
| `exception_roots/mod.rs` | Architectural exception-root types, strict limits, and subsystem boundary |
| `exception_roots/discover.rs` | A32 vector-table classification plus reset-side VBAR relocation proof |
| `exception_roots/artifact.rs` | Canonical authenticated root manifest materialization, reading, and fixture provenance |
| `exception_pass2.rs` | Strict ApplyExceptionRoots summary parsing and opaque authenticated pass-2 context construction |
| `terminal_pass2.rs` | One immutable per-label canonical-kit snapshot: retained raw/scatter/exception/PAL staging, shared runtime contexts, map binding, and final spawn validation |
| `pal_tasks/mod.rs` | PAL shared types, named resource limits, the structured domain error, and the `discover` plan boundary |
| `pal_tasks/cfg.rs` | Entry-rooted local CFG decode and its definition-aware dataflow/graph queries |
| `pal_tasks/discover.rs` | Bounded anchor sweep, unique-prologue root selection, initializer proofs (loop/guard/suffix/slot base) |
| `pal_tasks/table.rs` | Slot parsing, descriptor-v1 field relationships, and the deterministic application/label allocator |
| `pal_tasks/artifact.rs` | Canonical authenticated v1 task manifest: serialize, strict typed reader, materialize, and clear |
| `dbt_traces/mod.rs` | DBT debug-trace limits, `DbtTraceError`, standalone `decode-traces` run (this-run scatter bind only) |
| `dbt_traces/discover.rs` | `DBT:` sweep, threshold, quarantine, record-spill staging |
| `dbt_traces/artifact.rs` | Five-table catalog serialize, staging rename, identity |
| `dbt_traces/reader.rs` | Strict streaming catalog reader |
| `dbt_traces/refs.rs` | Semantic record-address attribution over authenticated ranges |
| `dbt_traces/exact.rs` | Exact-index consumer for `dbt_exact` / `dbt-source` |
| `dbt_traces/wire.rs` | Canonical JSON writer shared by catalog and refs |
| `source_tree.rs` | Reconstruct the source-tree layout from `__FILE__` strings |
| `analysis_tool.rs` | Shared `AnalysisTool::{Ghidra, Radare2, Rizin}` downstream identity |
| `recover_source.rs` | Attribute producer-owned Ghidra/Thumb functions to source paths; union dbt-only paths into the recovered index |
| `decode_rf.rs` | Decode the RF_CFG calibration databases |
| `hwcfg.rs` | Summarize `hardware_config.json` + RF_CFG coverage |
| `tokens.rs` | Decode the Pigweed `pw_token_db` |
| `decompile.rs` | Ghidra import kit, `--run` orchestration, Thumb summary/currentness, and streaming v3-preserving enrichment |
| `thumb_analysis/mod.rs` | Stable producer/tool types, public configuration and summaries, and subsystem exports |
| `thumb_analysis/identity.rs` | Canonical cross-platform executable identity, discovery, bounded version probing, and probe-process cleanup |
| `thumb_analysis/stream.rs` | Request validation, fallback coordination, process supervision, bounded capture/scanning, normalization, and spills |
| `thumb_analysis/artifact.rs` | Sole v1/v2/v3 parser, read-only legacy replay, strict run ownership, typed consumer streaming, canonical assembly, terminal validation, and v3 streaming atomic mutation |
| `thumb_analysis/radare2.rs` | radare2 command profile, inventory aliases/bounds, and per-operation reference adaptation |
| `thumb_analysis/rizin.rs` | Rizin command profile, inventory aliases/bounds, trailing `axlj` streaming, filtering, and range assignment |
| `disasm_index.rs` | Shared address-indexed `disasm.lst` view (O(log L + k) slice lookup); consumed by `symbolicate::load_functions` and `globals::run`'s Phase 3.0.1 path |
| `symbolicate.rs` | Recover names + log/assert annotations into the decompiled artifacts (+ `symbols.json`) |
| `globals.rs` | Phase 3.0 global-name recovery + Phase 3.0.1 disasm-anchored Recovered + name-prior Provisional (+ per-image `globals.json`) |
| `execution_ranges.rs` | Tagged execution-range projection (`decode_ranges` / `decode_range_errors`) shared by Ghidra, both Thumb backends, and `global_shapes` |
| `global_shapes/mod.rs` | Phase 3.2 per-image coordinator: one-function decode/track/aggregate, panic containment, atomic sidecar commit |
| `global_shapes/decoder.rs` | Pure-Rust adapter over `scaleservers-arm32-assembly` 1.0.0; project-owned instructions only |
| `global_shapes/tracker.rs` | Sound cross-block must-facts dataflow over direct CFG edges (worklist join), Recovered-global access observations, v3 barriers, cross-block counters |
| `global_shapes/aggregate.rs` | Same-PC agreement/conflict grouping and conservative summaries |
| `global_shapes/artifact.rs` | Input validation, source hashes, v4 schema, deterministic serialize, atomic replace |
| `global_shapes/validate.rs` | Shared v4 sidecar checks for goldens and retained-tree replay |
| `global_types.rs` | Selects apply-worthy scalar shapes from `global_shapes.json` (width 1/2/4/8 `inferred` scalars only) and writes the strict `ApplyGlobalTypes.java` apply-map |
| `decompose.rs` | One-shot pipeline over all decoders; owns `global_shapes` and `global_types_apply` route placement and report fields |
| `manifest.rs` | `manifest.json` writing + `blake3` helpers |
| `tree_hash.rs` | `pme-paq-v1` whole-tree hash behind the `tree-hash` subcommand (fail-closed tree validation) |
| `trusted_fs.rs` | Retained directory capabilities, no-follow traversal, and platform-specific atomic leaf mutation |
| `error.rs` | Error types |
| `cli.rs` | `clap` subcommands + dispatch |
| `bin/main.rs` | Binary entry point |
| `ghidra/*.java` | Ghidra headless scripts (`ApplyScatterLoad`, `ApplyExceptionRoots` + `ExceptionRootsSupport`, `ApplyPalTasks` + `PalTasksSupport`, `TameAnalysis`, `ApplyThumbNames`, `ApplySymbols`, `ApplyGlobals`, `ApplyGlobalTypes`, `ExportDecomp`) |

Also: `tests/` holds the golden integration tests. Keep one clear responsibility per
module; when a file outgrows that, split it.

### Trusted artifact filesystem

- **The capability is the authority.** `TrustedDirectory` acquires the requested root with one
  final-component no-follow/reparse-point open and uses that same object for every descendant
  operation. Never reintroduce a metadata/canonicalize check followed by a path reopen: a rename
  between those calls can redirect a reader, publication, or clear into a replacement tree.
- **Publication guarantees are platform-specific.** Unix creates a 128-bit OS-random staging leaf
  with `openat(O_EXCL)` relative to the retained parent, retries at most 128 collisions, syncs the
  complete file, and atomically replaces the target with parent-relative `renameat` before syncing
  the directory. Existing mode/owner preservation remains. POSIX has no operation that renames an
  open source descriptor over an existing name: the Unix threat model covers ancestor/directory
  replacement, symlink escape, crash-safe replacement, and cooperative concurrency, but excludes a
  malicious writer changing children inside the already-retained directory. Never describe the
  Unix source rename as object-bound. Once a Unix staging leaf exists, a failed or abandoned write
  deliberately leaves it because pathname cleanup could remove a replacement. Windows instead uses
  `NtCreateFile` plus handle-bound `NtSetInformationFile` rename/disposition and may clean the exact
  open object.
- **Clear commits at the owned leaf and stops there.** Once the regular manifest was unlinked or
  confirmed absent through the retained label handle, clear succeeds and performs no label-directory
  removal. Empty label directories are allowed noncanonical residue.
- **Terminal publication is capability-bound and exhaustive.** Exception/PAL publication opens the
  current source through a retained kit capability, authenticates those exact bytes against the
  already-terminal raw/scatter runtime, then opens the destination label through a retained image
  capability. It verifies that destination's pathname still names the retained directory before and
  after an exact-length/BLAKE3 atomic leaf replacement. Validation and copy failures before commit
  preserve the prior target; a namespace swap never mutates the replacement tree, and a swap detected
  after commit leaves the copied bytes only in the detached retained directory and marks publication
  non-current. Every foreign sibling is preserved. Marshalling records explicit raw/export/scatter/
  exception/PAL outcomes for every image and never stops at the first failed label; only dependent
  authority is cleared. Report reasons are bounded to 2,048 Unicode scalar values including
  ` [truncated]`, and an earlier actionable exception cause is sticky.
- **One terminal snapshot owns pass 2, at one precise time.** Exhaustive pass-1 marshalling first
  records the complete raw/export/scatter/exception/PAL outcome matrix for every image. Later, after
  pass-1 enrichment/source stages and immediately before symbol-map construction, each eligible
  current image gets at most one `TerminalPass2Snapshot` in the existing Ghidra kit: raw is staged
  once, one authenticated scatter object stages every payload before `load_map.json`, and current
  exception/PAL manifests stage once. It snapshots pass-2 inputs, not final pass-2 outputs, and is
  not deferred until `DispatchPass2`.
  Both opaque application contexts derive from that snapshot's single `RuntimeImage`; failed
  construction returns no object. `Pass2Input` owns an `Arc` to the snapshot plus typed function,
  global, and global-type maps. A function map must match the snapshot's original raw digest and full
  terminal binding. After stale export invalidation, `run_two_pass` validates the kit-root binding,
  raw/scatter/manifests, contexts, and maps immediately before constructing argv and spawning, with no
  intervening filesystem mutation. Path existence never establishes currentness.

### Architectural exception roots

- **Discovery is all-image, default-on, and has no CLI bypass.** Generation examines every
  `Toc::embedded()` image before `--image` filtering or opaque skipping. TOC label, load address,
  and that image's `RuntimeImage` are inputs, never model selectors; scatter remains structurally
  MAIN-only and analyzer inventories never nominate roots. The sole initial candidate is the image
  load address. Arbitrary image scanning is forbidden, and a relocated candidate can arise only
  from reset-side VBAR proof after the initial table has validated.
- **The threshold is exactly eight supported A32 slots.** Architectural order is reset, undefined
  instruction, supervisor call, prefetch abort, data abort, reserved, IRQ, and FIQ. Every slot must
  be either an unconditional non-linking direct A32 branch or an unconditional literal word load to
  PC with architectural-PC base, decoded immediate offset, and no unsupported writeback. Calls,
  conditional forms, register-indirect/computed PC writes, returns, exception calls, and table
  branches are unsupported. Zero through seven supported forms is clean `NoCandidate`; after all
  eight forms survive, every literal and target must be byte-backed in the same raw/scatter runtime,
  architecturally aligned, and decode one complete selected-ISA instruction with no cross-ISA
  fallback. Same-ISA duplicate targets are valid; ARM/Thumb identities normalizing to one address
  are malformed. Every post-threshold discovery failure uses the closed typed
  `ExceptionRootError::{Malformed, Ambiguous, Decode, Runtime, ResourceLimit}` outcome and publishes
  no current plan rather than truncating to a prefix.
- **VBAR conclusions are explicit and bounded to the reset prefix.** Shared `semantic_cfg` follows
  direct edges, does not enter callees, applies the call-clobber boundary, and joins an exact value
  only when every incoming path agrees. An unconditional VBAR write establishes active-table state
  only when it dominates every explored startup handoff. `confirmed_initial` selects the image-base
  table; `relocated` validates one second table under the identical rules; `unresolved` records a
  real write whose value or table cannot be proven; `not_observed` records a complete prefix with no
  VBAR write; `analysis_incomplete` records a decode/control boundary before a dominance conclusion.
  A later indirect/decode boundary does not downgrade an already-proven dominating write, while a
  boundary outside its dominance remains incomplete. Conflicting exact selections are ambiguous.
- **Resource limits are part of validity.** Per image: at most 2 tables, exactly 8 slots per table,
  at most 16 distinct roots, 64 KiB non-refundable charged reset-CFG bytes, 32,768 decoded CFG
  instructions, 4,096 CFG blocks, 64 VBAR observations, and a 1 MiB manifest. Java symbol leaves
  retain the shared 2,000-byte cap. Exhaustion after threshold fails the generation and preserves
  any previous complete artifact without reporting it current.
- **Canonical means exact production bytes.** `ExceptionRootsSupport` first applies its ordered,
  typed v1 grammar, then rewrites the same JSON generically to Rust `serde_json`'s two-space pretty
  spelling and compares exact UTF-8 bytes. This rejects changed key/string escaping, minification,
  internal whitespace, noncanonical numeric tokens, and any trailing byte; canonical output has no
  trailing newline. All manifest/raw/scatter/payload handles remain open from preflight through
  commit or abort. Every partially completed acquisition and close path catches `Throwable`, closes
  the remaining handles, and preserves cleanup failures as suppressed diagnostics.
- **The script-owned transaction is the authority.** `ApplyExceptionRoots` is a `HeadlessScript` and
  must not open a nested program transaction: Ghidra already starts its outer transaction before
  `run()`. Success is apply → complete postflight → retained-file recheck → conservation/summary
  construction → `end(true)` → close retained handles → print one summary. Failure runs the
  pre-registered reverse journal, calls `end(false)` as the authoritative exact rollback, closes
  handles, and rethrows so no later headless script runs. A close failure after `end(true)` leaves
  valid committed/replayable state but emits no success summary and still stops continuation.
- **Mutation cleanup is registered before mutation.** Context, disassembly, function, primary,
  namespace, role-label, registry-map, and registry-record undo actions all exist before their
  Ghidra command runs, because commands may mutate and then fail. TMode snapshots preserve exact
  non-default `RegisterValue` runs and gaps rather than flattening one value across the instruction.
  The journal is defensive cleanup and diagnostics only; transaction abort remains authoritative.
- **One ownership validator serves replay and terminal postflight.** Every resulting primary,
  including `not_requested`, is bound by symbol ID, source, and name BLAKE3. Validation rechecks the
  exact function entry, instruction length/override/bytes/ISA, complete instruction-span body
  containment, primary disposition, role-label IDs/source/type/namespace, registry bijection, and
  manifest identity. Fresh classification consults the actual primary symbol even when no function
  exists, so a meaningful pre-existing label is preserved. Unshipped old registry records without
  primary identity fields are invalid; there is no compatibility grammar.
- **Exception pass-2 context is opaque and currentness-explicit.** The public
  `read_exception_pass2_context(ExceptionPass2ContextInput)` constructor receives the exact manifest,
  image directory/label/TOC/base, expected identity/scatter digest, and parsed current-run summary;
  it rebuilds `RuntimeImage`, calls the strict artifact reader, and compares manifest-derived table,
  role, application, shared-entry, and `(entry, DecodeIsa)` state before returning the opaque
  `ExceptionPass2Context`. The context has no public fields, `Default`, deserializer, literal, or
  path-existence fallback. `ApplyExceptionRoots` summaries are closed typed state, not aggregate
  hints: at most 256 KiB, 1–2 tables, and 1–16 strictly ordered application rows, with bounded
  IDs/names, exact name BLAKE3, closed source/result/disposition enums, row-derived counters, and
  first-apply/replay conservation.
  The parsed state retains its image and manifest identity privately; context construction requires
  both to equal the independently authenticated artifact, so same-shaped summaries cannot be mixed
  across images or manifests. `function_result: existing` plus `name_result: reapplied` is valid:
  pass 1 may adopt a pre-existing foreign function while owning and later replaying only its primary.
  Shared means exactly `desired_primary == null` with multiple claims; repeated initial/relocated
  claims for one role remain non-shared and keep their unique primary.
- **Exception naming survives pass 2 through closed primary dispositions.** Symbolication attaches
  `exception_root` evidence only on exact normalized `(entry, decode ISA)` keys and ranks names as
  `__func__ > registration > exception_root > pal_task > token > string_ref`. The summary supplies
  exactly `exception_owned`, `preserved`, `not_requested`, or `pass2_owned` state. Only
  `exception_owned` may create a `func`/`registration` transition; preserved and shared label-only
  applications force exact preservation and cannot acquire generic, PAL, or thunk-mirror renames.
  A replayed `pass2_owned` row reproduces its exact authority plus original/final symbol ID, source,
  name, and digest. Current-primary equality applies only to the Ghidra-owned execution at that key;
  radare2/Rizin records may retain the role evidence without becoming program-state authority.
- **Pass-2 lineage is strict v3 and transition-complete.** Fresh symbol maps are v4 and require the
  nullable `predecessor_symbol_pass2` field. `PixelModemExtractor.SymbolPass2` has only
  `v3:<map-blake3>:<functions-blake3>:<execution-count>` grammar; there is no v2 reader. The current
  property must equal the map's explicit predecessor or its exact current token. Any existing
  `pass2_owned` exception registry row requires a non-null property — missing lineage is partial
  state, never a fresh application, and mapless Export rejects it. ApplySymbols rejects any
  already-`pass2_owned` exception registry key omitted by a successor map before mutation, then
  requires exact bidirectional `(entry, first decode-range ISA)` transition equality postflight;
  independent Export repeats the exact check. Immediately before publishing the token,
  ApplySymbols revalidates the complete exception state, PAL state, every map-owned Thumb row, and
  every final decision primary, then rechecks and successfully closes the retained map/functions/
  exception files as the last fallible step before the property write. A clean replay performs zero
  renames; stale/partial ownership emits no success summary and leaves prior program/export state
  intact.
- **The wire/currentness bumps are inseparable.** Exception evidence writes
  `pixel-modem-extractor-symbols-v4`; application input writes
  `pixel-modem-extractor-symbol-map-v4`; `PixelModemExtractor.SymbolPass2` accepts only its strict
  v3 token; and every current export ends with `pixel-modem-extractor-ghidra-export-v4` carrying
  `exception_roots`, `pal_tasks`, and `symbol_map` identities. There is no compatibility grammar for
  the unshipped exception semantics in older symbol/map/export state.
- **One retained pass-2 state serves all three phases.** `ApplyThumbNames` receives exactly ten
  arguments: kit root, image label/hash, exception identity/manifest/scatter, retained
  `functions.json` path/hash, and symbol-map path/hash. It opens the full retained map state and runs
  `BEFORE_MUTATION` before classifying or mutating any creation. `ApplySymbols` runs the same
  `BEFORE_MUTATION` and `AFTER_MUTATION` validator; `ExportDecomp` retains the map handle and runs
  `TERMINAL` both before and after staging its outputs. Present and absent exception state,
  authenticated runtime files, lineage, transition conservation, Thumb ownership, and current
  decisions therefore have one implementation rather than script-local partial checks.
- **Thumb ownership migrates forward without predecessor artifacts.** Every
  `PixelModemExtractor.ThumbNames.v1.Ownership` row must be represented exactly once by a current
  map creation or authenticated execution and must bind the concrete function/symbol IDs, producer
  execution, current Ghidra execution, and phase-appropriate primary. A predecessor run has the
  predecessor SymbolPass2 token and predecessor-hash rows; `ApplyThumbNames` journals each exact
  row, rewrites only its map-hash field to the current hash, and deliberately leaves the property at
  the predecessor token for `ApplySymbols` to publish. The only accepted intermediate is that
  predecessor token plus an all-current row set, and only an identical current-map retry may consume
  it. Current token plus current rows is terminal. Mixed, omitted, foreign-hash, or unrepresented
  rows fail closed; no script opens a predecessor map or deletes a project-created function merely
  because a successor map omits it.
- **Successor Thumb lineage is sparse and dual-authenticated.** Terminal `ExportDecomp` adds the
  optional `thumb_creation_producer_blake3` selector only to a function whose ownership row passed
  the shared terminal validator; ordinary records omit it. The selector grants no authority. The
  centralized Rust inventory reader collects it outside the per-function record, and the v4 symbol
  map requires `thumb_creation_lineage` immediately after `executions` (before `symbols`), including
  an empty array when nothing is owned. Each row links one Ghidra execution index to one exact
  current strict-v3 radare2/Rizin `(entry, producer digest)` and carries canonical authenticated
  Thumb ranges beginning at the entry. Java requires an exact lineage/registry bijection, rehashes
  those producer ranges and digest, proves the current Ghidra body is contained by them, and then
  independently recomputes the Ghidra execution digest; the two digests may and normally do differ.
  Rust's streamed Ghidra inventory carries its exact aggregate range count and charged bytes into
  lineage validation: both sides share the 1,048,576-range and 512 MiB sum-of-exclusive-extent-byte
  limits across those two map sections. Function/lineage row limits remain independent, matching
  Java; never restart the aggregate range/byte budget at the lineage boundary.
  This owned-only surface is materially bounded. Mustang conserves 169 = 165 created + 4
  `skipped_existing`; only the 165 created candidates own lineage. Cheetah conserves 64 = 64 created
  lineage rows. The conservative all-overlap projections were 88,349 and 72,893 rows. The sparse
  choice does not change execution, creation, report, or SymbolPass2 counts and does not relax the
  Task 9 boundary: no predecessor map bytes, compatibility reader, or omitted-function deletion.
- **Ghidra-only constraints stay Ghidra-only.** Java preflight rejects intersections among the
  complete derived instruction spans before mutation and computes A32 architectural `PC + 8` before
  applying a signed branch/literal displacement, with each step checked in the u32 domain. Rust
  discovery does not reject overlapping roots: producer evidence may describe them, while Ghidra's
  single instruction/listing model cannot apply them simultaneously.
- **VBAR proof ends at the startup handoff.** A later indirect/decode boundary does not downgrade an
  exact unconditional VBAR write that dominates every startup handoff; a boundary outside that
  dominance remains `analysis_incomplete`. Both retained MAIN corpora depend on this distinction:
  their initial-table write precedes and dominates the later indirect startup handoff.
- **Generation and pass-1 currentness are explicit.** After splitting every TOC image, `decompile`
  discovers MAIN scatter once, builds one `RuntimeImage` per embedded image, discovers exception
  roots for every image, then discovers MAIN PAL against the shared runtime. Every label records
  `RuntimeExceptionState::{Present, Absent, Unmanaged}`; filters, opaque skips, and stale files never
  fabricate currentness. Exception discovery, materialization, strict on-disk reading, and clear
  must each finish before state insertion. Discovery/publication/clear failure preserves an earlier
  complete manifest; a post-publication read failure still returns no `RuntimeAnalysis` and never
  reports the bytes current. Present pass-1 order is `ApplyScatterLoad` →
  `ApplyExceptionRoots` → `ApplyPalTasks` → `TameAnalysis` → auto-analysis → `ExportDecomp`.
  Generated and in-process routes pass the same explicit identities, and the Java applicator emits
  exactly one conserving exception summary in either route. Only the Rust-driven in-process route
  captures and host-parses that line into `ImageResult`; generated `run_ghidra.sh` deliberately does
  not parse stdout and instead requires process success, all three exports, and the exact v4 marker
  whose Java preconditions include summary conservation and complete postflight. Host summary
  coordination commits a valid exception result before parsing PAL: a later PAL-summary failure
  preserves the exception counts but leaves the image terminal-invalid and the export non-current.
  `TameAnalysis` validates root
  ownership before and after both modes, so datamark treats root instructions as protected code. `ExportDecomp`
  retains both exception and PAL inputs, reauthenticates both manifest/program states before and
  after generating sibling staging files, closes both retained states successfully, then moves the
  three outputs and writes the exact four-line `pixel-modem-extractor-ghidra-export-v4` marker last;
  old v3 bytes are stale. An opaque
  skip retains generation state but has no application summary.
- **Terminal exception state remains generation-owned.** `decompose` authenticates every present
  generation manifest against the terminal raw image and its explicit scatter dependency before
  committing `images/<label>/exception_roots/roots.json`; absence clears only that owned leaf and
  `--prune` retains it. A later Ghidra or PAL failure does not downgrade independently completed
  exception generation or prevent later images from marshalling. Scatter is structurally MAIN-only:
  non-MAIN `RuntimeScatterState::Unmanaged` means the exception runtime was deliberately raw-only,
  so terminal validation and pass-2 context construction ignore any stale scatter path without
  deleting it. The one per-label terminal snapshot copies exact terminal raw/scatter/exception/PAL
  bytes into canonical kit locations, including every file-backed `blocks/*.bin` dependency; the
  shared strict scatter restager authenticates retained handles, writes payloads first, and commits
  `load_map.json` last. Exception and PAL contexts are rebuilt from the same staged runtime and
  explicit application state. The snapshot and its map binding reject drift at the final pre-spawn
  gate; path existence alone never establishes currentness. The adjacent
  `exception_roots` report stage tallies terminal images/tables/roots, while eleven application
  counters are all-or-none and exclusive with reason-only `exception_error`. `None` means no current
  Ghidra invocation result; `Some(0)` means the application ran and produced zero in that category.
  Exception application fields live on `decompile::ImageResult`, so every later report snapshot
  rebuild preserves them rather than requiring a post-pass-2 patch.
- **Real-Ghidra fixtures have one production oracle.** Everything under
  `tests/fixtures/exception_roots/` is wholly synthetic. The private
  `committed_ghidra_fixture_matches_production_discovery_and_serialization` test regenerates the
  canonical, shared-role, relocated, and scatter-backed raw/manifests through production Rust
  discovery and serialization and compares every committed byte. Set
  `PME_UPDATE_EXCEPTION_ROOT_FIXTURE=1` only when intentionally regenerating those fixtures. The
  integration suite loads them directly; malformed cases are focused text/byte mutations, never a
  parallel test-owned wire schema.
- **Two-model Phase 3A acceptance is closed (2026-09-01).** Fresh locked release-mode `decompose`
  with pixel-modem-extractor 2.0.0, Ghidra 12.1.2 DEV, and radare2 6.1.4 produced exactly one
  current MAIN manifest on each reference model and clean current absence on Mustang's other five
  images and Cheetah's other three. Both tables are at `0x40010000`, all eight slots are literal
  A32 loads, every root is distinct A32, and exact dominating VBAR writes at `0x40010180`
  (Mustang) / `0x40010100` (Cheetah) select the initial table. In architectural order (reset,
  undefined, SVC, prefetch abort, data abort, reserved, IRQ, FIQ), the targets are
  `[0x4001017c, 0x400100b4, 0x400100c0, 0x400100cc, 0x40010140, 0x40010168,
  0x4001016c, 0x40010174]` on Mustang and
  `[0x400100fc, 0x400100b0, 0x400100bc, 0x400100c8, 0x400100d8, 0x400100e8,
  0x400100ec, 0x400100f4]` on Cheetah. Canonical manifest BLAKE3 values remain
  `dfb5b19229432824e86394798a1545ce28cbceebe103aef02922b0cad391f402` and
  `2597eab66f60c7be950c9671e4f14d443eca4b7c826446f5e2bd65ae4c12516f`.
  Each run created and named all eight functions, preserved all eight role labels through pass 2,
  and emitted the identity-bound export-v4 marker. End-to-end wall/RSS was 2:05:11 / 5,184,752 KiB
  for Mustang and 1:34:30 / 16,751,636 KiB for Cheetah, with no swap; the Cheetah peak includes the
  documented `0x42310000` radare2 `RLIMIT_AS` failure, durably recorded while six regions
  succeeded. PAL, Thumb creation, globals, global shapes/types, DBT, terminal inventories, and all
  conservation gates passed; the overlap-repair fallback did not recur. This lands Shannon-loader
  roadmap Phase 3A alongside landed Phases 1 and 2. Phase 3B is the next focused design: hardware-init
  roots, compiler metadata, stack non-return proof/application, and broader privileged-operation
  evidence over the improved mutable final inventories; it remains architecturally separate from
  immutable pre-analysis Phase 3A.
- **Focused verification is explicit.** Run exception discovery/artifact/CFG/PAL unit batteries,
  both independently configured corpus legs, the complete serial real-Ghidra binary, and the
  retained-tree report-shape gate:

      cargo test exception_roots:: -- --nocapture
      cargo test semantic_cfg:: -- --nocapture
      cargo test pal_tasks:: -- --nocapture
      cargo test --test exception_roots_golden -- --nocapture --test-threads=1
      GHIDRA_INSTALL_DIR=/opt/ghidra \
        cargo test --test decompile_golden -- --nocapture --test-threads=1
      cargo test --test decompose_golden \
        report_json_includes_exception_roots_fields -- --exact --nocapture

  A configured corpus/Ghidra prerequisite must run or fail; only an unset corpus variable or an
  unset Ghidra variable with no default installation can produce its documented UNRUN/skip state.

### Dense Thumb analyzer invariants

- **Preflight and identity.** radare2 remains mandatory and Rizin cannot substitute for it.
  Rizin discovery occurs only for explicit `--rizin-fallback`. Both backends are canonicalized
  before a direct `-v` probe with a 10-second deadline. A probe requires successful UTF-8 stdout
  and retains the first non-empty trimmed line, at most 1,024 bytes. `decompose` preflights all
  required/configured tools before creating output and passes those exact `ProducerIdentity`
  values through analysis and `report.json`; nested decompile must not rediscover them.
- **Requests are valid before effects.** The complete `(start, length)` list is checked before
  creating `thumb/`, carving bytes, or spawning: length is positive, checked addition fits the
  canonical u32 address domain, every range lies in the mapped image, and ranges are sorted and
  non-overlapping. Every backend receives the same prevalidated `thumb/<start:08x>.bin` carve.
- **Backend adaptation is strict.** Inventory, top-level `pdfj`, and operation addresses accept
  the live modern/legacy `addr|offset` aliases. V3 radare2 bounds require `maxaddr`; Rizin bounds
  require `maxbound`; both require positive `realsz`. Normalized `end` is that exclusive bound and
  normalized `size` is `realsz`; never derive either from `entry +` raw `aflj.size`. Raw `size` is
  diagnostic bounding span only. Each v3 `decode_range` carries a lowercase BLAKE3 over its exact
  runtime bytes; the authenticated ranges and aggregate execution digest are authoritative for
  execution identity and source-range attribution.
- **Body integrity fails the attempt.** Pair inventory and `pdfj` by entry before positional
  fallback. A non-empty inventory with zero paired bodies is a region failure; an empty inventory,
  orphan bodies, malformed boundaries, projection errors that break conservation, and unusable
  process output also fail the attempt. Once at least one body pairs, individual missing/invalid
  bodies may remain whole-record quarantines. Do not turn a command/schema failure into an empty
  successful sidecar.
- **Commands and fallback policy are fixed.** radare2 runs exactly
  `aaa;aflj;pdfj @@f`; Rizin runs exactly `aaa;aflj;pdfj @@F;axlj` in one process.
  radare2 is attempted first for every region. Rizin is attempted once only after that region's
  radare2 attempt fails. Healthy, all-quarantined, or low-coverage radare2 output never triggers
  fallback. Production retains the first successful producer run and never unions backends within
  a region.
- **Partial and total failure differ.** If any requested region succeeds, canonical v3 commits
  atomically with every requested region and its ordered attempts; partial success remains analyzed
  with no `thumb_error`. If all regions fail, return one ordered aggregate error, remove temporary
  fragments, publish no sidecar, and leave any prior `thumb_functions.json` byte-identical. Callers
  must never treat that old file as current after the error.
- **Capture provenance is durable.** Analyzer stdout paths are
  `thumb/<start:08x>.radare2.stdout` and `thumb/<start:08x>.rizin.stdout`; temporary spills use the
  same producer qualification and are never terminal. Captures stream to disk while exact bytes and
  BLAKE3 are accumulated. A successful attempt requires capture metadata. A failed attempt retains
  finalized partial stdout when possible; spawn/capture-finalization failures record `stdout: null`.
  `--prune` removes capture files, but v3 preserves their relative path, byte count, and hash.
- **Analyzer runtime and pipe-finalization bounds are distinct.** Both backends have a 4 GiB stdout
  cap and a 16 GiB Unix `RLIMIT_AS`. Rizin has a 30-minute per-region analysis deadline; radare2 has
  no analysis deadline. After the immediate analyzer exit is observed, either backend may spend at
  most 1 second idle (new bytes reset this window) and 30 seconds absolute finalizing inherited
  stdout pipes (progress cannot extend this window). Reaching either post-exit bound forces pipe
  finalization and fails the attempt; neither bound is an analyzer runtime deadline.
- **Cleanup guarantees are platform-specific terminal contracts.** On Unix, each analyzer runs in
  its own process group. Exit observation uses identity-stable `WNOWAIT` ordering so the leader
  remains waitable while the anchored group is signaled; cleanup then reaps the leader exactly once
  and verifies that the process group is absent. On non-Unix platforms, the portable contract is
  limited to terminating/reaping the immediate child and cancelling/joining its stdout drain; it
  does not claim descendant process-group cleanup. If the applicable cleanup proof fails, the
  coordinator aborts the stage: it must not start Rizin fallback or a later region after a
  potentially surviving analyzer.
- **One typed terminal path, and it is wider than "cleanup".** `FailedRegion::terminal` marks any
  attempt that left unverified process or on-disk state; the coordinator then records **no attempt
  record**, no fallback, no later region, and no publication. It covers pre-attempt housekeeping
  (`FailedRegion::setup` — nothing was spawned, so recording an attempt would claim a process that
  never ran), output that could not be removed (`remove_stale_output` treats only an absent path as
  success), a drain that would not stop, and unverified process cleanup. The design's one *ordinary*
  case is narrow and must stay so: a partial capture whose finalization failed but which was
  **provably removed** records `stdout: null` and stays fallback-eligible.
- **Declared bounds must bound the return, not the cancellation.** The 10-second version probe and
  the post-exit pipe-finalization limits are meaningless if cleanup then blocks forever, so
  `kill_and_reap`, `ProbeReaders::cancel_and_join`, and `AnalyzerProcess::cancel_drain_and_wait` are
  all bounded and report their failures. A reader that never observes cancellation is **detached**,
  not joined; `join_drain` on a detached drain is an error, so a detached reader can never yield a
  capture identity. `CancelSynchronousIo` failures are reported except `ERROR_NOT_FOUND`, which just
  means no synchronous read was pending.
- **Rizin xrefs are bounded outgoing evidence.** The one trailing `axlj` array must be final and is
  streamed rather than materialized. Types are case-insensitive: include `data`, `str`, `string`,
  `mem`, `ptr`, or `read`; deny `code`, `call`, `jump`, or `exec`. Selected records require a u32
  `from` and u64 `to|addr`; incoming `xrefs_to`/`codexrefs` are ignored. The cap is exactly 1,000,000
  selected input records per region, checked before sorting/dedup so duplicate floods remain bounded.
  Binary searches assign each target only where `from` lies in an accepted `decode_range`; targets
  sort/dedup per function, overlapping functions each receive the edge, and quarantined/unmapped
  records contribute no false function reference. `RizinXrefIndex` records which sources an accepted
  range claimed, so unmapped selected xrefs are counted and logged per region rather than failing
  the attempt. Every `pdfj` body must carry an array-valued `ops` field: without that check, schema
  drift emitting bare objects pairs positionally, quarantines every function as `empty_projection`,
  and publishes an all-quarantined "successful" run.
- **V3 owns provenance and mutation.** Canonical top-level order is `format`, `producers`, `regions`,
  `functions`. Producers are actually attempted identities; regions stay in request order; attempts
  stay in process order. Every successful attempt owns one non-empty contiguous `function_runs`
  slice, all slices cover the flat function array exactly once, and stored substantial/accepted/
  quarantined counts are rederived. Readers accept multiple successful runs for a future union mode,
  but the current writer emits at most one per region. Currentness compares strict v3 format, full
  producer identity, requested ranges, run ownership, and all summary totals. Mutators may change only
  `body_c`, `name`, `original_name`, and `annotations`; format/provenance/order/count/execution fields
  are immutable, writes are atomic, and a no-op is byte-identical.
- **All consumers share ownership.** Only `thumb_analysis::artifact` recognizes Thumb formats. V1/v2
  remain readable and infer radare2; v3 resolves each function through validated runs. Source
  attribution and symbolication preserve `AnalysisTool::Rizin`; globals consumes Rizin-adapted
  `data_refs` through the same canonical record path; `global_shapes` validates provenance before
  flattening execution identities. Typed source recovery and enrichment/symbolication mutations
  stream function records; `global_shapes` intentionally retains the complete validated function
  set because its decoder analyzes those records together.
- **Ownership survives all the way to mutation.** `(FunctionOwner, entry, execution_blake3)` is the
  record identity, not the entry or producer alone: a valid v3 artifact can hold two records from
  different region/run coordinates at the same entry, including two runs from the same producer.
  `Symbol` and recovered-function evidence carry the concrete owner and execution digest;
  `stream_rewrite_thumb_functions` hands the mutator that validated owner; Ghidra records use
  `FunctionOwner::Ghidra`; and attribution/name projections fail closed rather than collapsing an
  ambiguous address.
- **Every execution consumer validates through `RuntimeImage`.** `parse_thumb_artifact`,
  `read_thumb_artifact`, and `read_thumb_functions_streaming` require the runtime mapping. They check
  v3 region bounds and authenticate every accepted range against byte-backed storage (including
  scatter mappings), rejecting gaps, zero-fill, or digest mismatches. Function `end` and `size`
  remain analyzer metadata and never expand the authenticated executable domain.
  `global_shapes`, `globals`, symbolication, and `recover_source` all construct and supply the same
  runtime view; no consumer reconstructs executable coverage from `[entry,end)`. The per-image
  `scatter/load_map.json` convention has exactly one constructor,
  `RuntimeImage::for_image_dir(raw, base, image_dir)` — never re-derive the map path or existence
  probe at a call site. Record digests parse through the one
  `execution_ranges::parse_blake3` (64 lowercase hex) so acceptance cannot drift between stages.
- **Producer identity has two modes, and legacy records have neither.** One validator
  (`identity::producer_identity_error`) serves both: `IdentityMode::Runtime` for identities the
  coordinator will spawn (this host's path family, `canonicalize` equality with the recorded
  spelling, an executable file) and `IdentityMode::Artifact` for retained artifacts, which record a
  possibly foreign host and can only be checked lexically. Both reject what discovery cannot produce:
  versions past the 1,024-byte probe bound, and Windows reserved device names, Win32-reserved
  characters, trailing space/dot components, or an unusable verbatim prefix. Separately, the typed
  consumer record requires only `name` and `entry`, because retained v1/v2 artifacts carry no v3
  semantic contract and legacy symbolication defaulted the rest; v3 stays strict through
  `FunctionWire`.
- **Report conservation.** Current runs copy `regions_requested`, `regions_succeeded`,
  `regions_failed`, `radare2_runs`, and `rizin_runs` into the five `thumb_*` image fields. Require
  requested = succeeded + failed and succeeded = radare2 runs + Rizin runs under the no-union policy.
  The report's tool object describes configured identities; the sidecar describes actual attempts.
- **Failures name their own stage.** `ImageOutcome::Failed(code)` is an `analyzeHeadless` process
  failure and is the only outcome that reports `exit`; `ImageOutcome::TerminalInvalid` is a
  completed Ghidra run whose export terminal/currentness validation rejected, and it reports
  reason-only `terminal_error`. `TerminalValidationFailure` records which stage rejected the pair, so
  a Thumb-side rejection also populates `thumb_error` (keeping any root-cause reason the analysis
  stage already recorded) while a Ghidra-side one does not. `Error::GhidraFailed` is reserved for
  real process failures. `report.json` likewise separates `prune_requested` (the flag) from `pruned`
  (the sweep completed); a failed sweep records a failed `prune` stage and `pruned: false`.
- **Both analyzers preflight before output.** radare2 discovery is a hard preflight on the
  standalone `decompile --run` route as well as `decompose`: it propagates before Rizin discovery
  and before any modem parsing, output creation, or Ghidra work. Deferring it once allowed an image
  with no dense Thumb region to succeed without the required primary.

## Multiple models (model-agnostic design)

- **Version drops are full recompiles — cross-build name transfer is closed.**
  Measured on the only same-variant pair obtainable (`g5400i` Jun 2025 ↔ Apr
  2026, ~10 months): strict 1:1 exact-byte function matching transfers zero
  names in either direction (MAIN survives ~5% byte-identical; drift p50 is
  207 differing words with 0% ≤2-word; the matched set carries no naming
  evidence). Cross-model (mustang↔cheetah) measured identically closed
  (2026-08-16). Do not build name-transfer/knowledge-diff features on
  exact-byte matching; structural matching stays rejected under the
  fail-closed naming discipline. (Process artifacts under `~/.superpowers`.)

The extractor targets the Shannon **S5300 / S5400** family and adds **no per-model code** — the core
is TOC-driven and structural, and everything model-specific is *derived* from the image, never
hardcoded. Two reference images exercise both models end-to-end:

- **mustang** — `g5400i`, **S5400**: `…/reference/radio-mustang-g5400i-260317-260429-b-15308590.img`
- **cheetah** — `g5300q`, **S5300**: `…/reference/radio-cheetah-g5300q-260317-260505-b-15346003.img`

- **Firmware-directory detection is by content, never by name** (`ext4::select_firmware_subdir`): the
  firmware dir is "the `/images/*` subdir that contains `modem.bin`" (lexicographically-first such
  entry). Essential, not a nicety — on cheetah that directory is literally named `default`, so no
  prefix heuristic (`g5300q-…`) could find it. The rest of `extract` is TOC-driven and model-agnostic.
- **MAIN-image identity is model-dependent.** The MAIN code image's split dir is `02_MAIN` on mustang
  and `01_MAIN` on cheetah — the index prefix varies, but the TOC name `MAIN` is stable. Decompose's
  source-tree and source-attribution stages select it via `decompose::main_image_dir_name` by the
  `_MAIN` suffix; every other analysis stage (decompile, symbolicate, globals, `global_shapes`) is
  already generic and iterates all images. `source_tree` derives its human-facing image label (README,
  `summary.md`, per-leaf node comments) from the input filename's stem, so the labels name the real
  image (`01_MAIN`) rather than a hardcoded `02_MAIN`.
- **Truthful generation label from the container, never a guess** (`src/model.rs`). `firmware_prefix`
  returns the leading `g<digits><letter>` of the FBPK/firmware-dir name; `modem_generation` derives
  the Shannon label from the digits (`g5300q…` → `S5300`, `g5400i…` → `S5400`). The label flows into
  `report.json` `modem_generation` and the source-tree README, read ad hoc from the FBPK **container**
  name via `manifest::read_fbpk_name` — which still carries the `g…` prefix even when the internal
  `/images` dir is `default`. When it cannot be derived, wording stays generic with no number. There
  is no model registry and no `Manifest` schema field.
- **Not every model ships every artifact.** cheetah has no `hardware_config.json` and no `RF_CFG_*`
  blobs, so `decode_rf` and `hardware_config` legitimately report `skipped` (not failed) and `rf/` /
  `rf_cfg_decompressed/` are empty. A skipped decoder stage here is a model difference, not a regression.
- **Testing across models.** The env-gated tests (`PME_RADIO_IMG`, `PME_GOLDEN_DIR`) are
  model-independent — point them at either reference image and both pass. Assertions are structural
  (the firmware dir contains `modem.bin`; a `*_MAIN` split exists; `firmware_prefix` parses;
  `modem.size > 0`), never a literal model name or byte size.
- **cheetah / S5300 as the second reference data point** (historical pre-v3 full
  `decompose`, ~84 min, exit 0; retain these measurements as comparison data, not current output):
  four images `00_BOOT / 01_MAIN / 02_VSS / 03_APM` (no PSP/DBGCORE), MAIN = `01_MAIN`. Headline
  `report.json` counts: `functions` = 104,395 (MAIN); `thumb_functions` = 87,026; `thumb_decompiled`
  = 70,906 (dense-Thumb converged on S5300 — the primary risk); `globals_recovered` = 1,061;
  `global_shapes` 1046 obs / 274 inferred / 784 `no_evidence` / 3 conflicting (that retained
  global-shapes sidecar is stale-vintage by design; the newer in-memory engine split is 295/766/0).
  In this historical run, where radare2 was the only host producer, region `0x42310000` hit the
  16 GiB `RLIMIT_AS` and contributed no
  Thumb records while six regions survived. Current default v3 records that failure as an ordered
  region attempt; opt-in acceptance additionally expects a successful Rizin-owned run there. The
  old warning-only loss is not current behavior.

## Domain map & code conventions

- **Em-dashes in prose.** The plan-level ASCII constraint applies to code, wire
  fixtures, and generated output — not to documentation prose. Em-dashes in `.md`
  files follow each file's established style (this file uses them); new Rust/Java
  code and test lines remain ASCII-only.
- **The TOC images** (parsed in `toc.rs`) are model-dependent. mustang/S5400 has six —
  `00_BOOT`, `01_PSP`, `02_MAIN`, `03_APM`, `04_VSS`, `05_DBGCORE`; cheetah/S5300 has four —
  `00_BOOT`, `01_MAIN`, `02_VSS`, `03_APM` (no PSP/DBGCORE). **MAIN** is the primary code image —
  `source-tree` reconstruction and recovered-source attribution operate on it — but its split-dir
  index varies (`02_MAIN` vs `01_MAIN`); the stable key is the TOC name `MAIN` (see *Multiple
  models* above). `05_DBGCORE` is the small debug image. On mustang, **`01_PSP` is opaque** (uniform
  entropy ≈ 8.0, no ARM code, no readable strings — consistent with encryption), so Ghidra
  reports **0 functions** — expected, not a bug. This is now measured, not assumed:
  `classify.rs` runs a 5-test battery per TOC image — whole-image Shannon entropy `H`,
  χ²/df, serial correlation, and 64-KiB window entropies (`window_min` plus
  `frac_windows_high`, the fraction of windows with H > 7.5) — under a unanimous,
  fail-closed verdict: `opaque` iff H ≥ 7.5 ∧ χ²/df ≤ 64.0 ∧ |SCC| ≤ 0.10 ∧
  window_min ≥ 7.7 ∧ frac_windows_high ≥ 0.99; any single refusal (including zero
  windows) yields `not_opaque`. On the reference corpus, mustang `01_PSP` is the only
  opaque image on both models (H = 7.9918, χ²/df = 16.7987, SCC = 0.0196,
  window_min = 7.9135, frac = 1.0); the other nine images are `not_opaque`, separating
  from PSP on every test with worst-case headroom of 1.26 entropy bits. `decompile --run`
  and `decompose` therefore skip unanimously-opaque images before any Ghidra work
  (`--no-skip-opaque` restores run-everything). Confirmed by a 2026-08-19 Ghidra spike:
  a direct run on `01_PSP` produced 0-byte `decompiled.c`/`disasm.lst` and an empty
  `functions.json` (~90 s) — nothing recovers.
- **Opaque-skip invariant.** Ghidra is skipped for an image only on a **unanimous** battery
  verdict; a single test refusal fails closed to `not_opaque` and the image is analyzed
  exactly as today — a partially-encrypted image is never skipped. The verdict is measured
  before any Ghidra work regardless of `--no-skip-opaque`, so `report.json`'s per-image
  `classification` always agrees with `manifest.json`'s `battery.label`, and a skipped row
  also carries `skipped_reason: "opaque"`. The pure gate is `decompile::opaque_skip`; the
  wiring tests `opaque_skip_decision_is_the_pure_gate` and
  `skipped_opaque_result_is_not_a_failure_and_expects_no_export` pin it.
- **Battery determinism.** `classify::classify` is single-threaded over a fixed window order
  (64-KiB chunks; a trailing window counts iff ≥ 4 KiB), and the stats are full-precision
  internally — rounding to 4 decimals happens only at manifest serialization
  (`manifest::BatteryInfo::from_stats`). The env-gated `mustang_corpus_pins_classify`
  (`PME_GOLDEN_DIR`) pins the rounded corpus values, so a change that moves a 4th decimal
  is a wire-level `manifest.json` change: re-pin deliberately and re-baseline the pinned
  manifest hash.
- **TOC CRCs are advisory.** Every image's stored TOC CRC currently mismatches a plain
  CRC-32 over `[offset, size)` (the algorithm/coverage is unconfirmed); `split_to_dir` only
  `warn!`s and still writes, and `manifest.verified` means "checks were attempted," not
  "CRCs matched." Don't read `verified: true` as CRC validation. A 2026-08-19 spike
  (32 CRC-32 variants × 6 coverage windows × both reference models: zero matches) plus RE
  showing no code in any image ever reads the field confirms the values are offline
  build-tool output — treat the field as opaque (findings under `~/.superpowers`).

### Runtime scatter load maps

- **Discovery is semantic and exactly bounded.** `scatter::discover` scans 4-byte-aligned
  offsets with `scaleservers-arm32-assembly` for the decoded unconditional A32 sequence
  `ADD base, PC, #imm; LDMIA base, {r10, r11}; ADD r10, r10, base; ADD r11, r11, base`.
  `base` is an operand relationship, not a fixed register. A32's visible PC (`loader + 8`)
  and the decoded immediate locate two little-endian relative words; wrapping addition
  against that literal-pair address yields the exact table start and exclusive end. Never
  replace this with retained byte signatures, loader/table/handler addresses, model names,
  fixed registers, or fixed immediates. Those would turn structural discovery into
  model-specific matching and silently miss valid firmware variants.
- **The plausibility threshold separates absence from damage.** A lookalike remains
  `NoCandidate` until it has a readable literal pair, an ordered in-image nonempty range
  whose length is an exact multiple of the 16-byte
  `{source, destination, size, handler}` descriptor, no more than 256 entries, and the exact
  two-record null sentinel: `{nonzero, 0, 0, nonzero}` followed by
  `{0, first.source, 0, first.handler}`. Once that threshold is crossed, every record through
  the resolved exclusive end must validate; malformed tails are not truncated or ignored.
  A plausible failure wins over another valid-looking anchor, and multiple valid anchors or
  handler assignments are ambiguity errors rather than score- or order-based choices.
- **Topology classifies opaque handlers without addresses.** The sentinel handler is `null`
  and cannot recur after the first two records. Useful entries have nonzero sizes and
  destinations; the table has exactly four raw handler identities; a nonempty `zero` suffix
  reaches the exact table end; `copy` and `decompress1` may interleave before it; and the copy
  class must contain an exact self-copy. The two remaining handler assignments are tested
  behaviorally and exactly one must survive. Handler identity uses the stored value verbatim;
  bit 0 is masked only to check that handler code points into the raw image.
- **`decompress1` is exact.** For each token, set `literal_code = token & 7`; if zero, read a
  nonzero extension byte; then copy `literal_code - 1` literal bytes. Set `run = token >> 4`
  and read an extension when zero. When `token & 8 == 0`, append `run` zeroes; otherwise read
  a one-byte nonzero distance no greater than current output and copy `run + 2` bytes with
  overlapping LZ semantics. Every read and output extension is checked, a no-progress token
  is rejected, and success requires exactly the descriptor's output size while recording the
  actual compressed bytes consumed. Do not copy `shannon_modem_loader`'s `token & 3`
  interpretation: ShannonBaseband independently corrected and emulator-validated `token & 7`,
  and only that form reproduces both authenticated retained corpora.
- **Planning is immutable-raw and resource bounded.** Null records and exact self-copies stay
  as metadata; other copies, decoded outputs, and zero ranges become runtime destinations.
  Reject out-of-image sources, sources dependent on an earlier runtime write, 32-bit endpoint
  wrap, destination overlap, and every non-self destination intersecting the retained raw
  mapping. The accepted logical output has a 512 MiB per-image limit, and speculative
  decompression across attempted classifications has a separate cumulative 512 MiB limit.
  Candidate validation retains checked raw ranges for non-self copies rather than cloned
  bytes; only the sole candidate remaining after malformed/ambiguity resolution becomes the
  public `LoadPlan` and materializes those copy bytes. Decoded outputs remain cached under the
  shared speculative budget.
- **Artifacts publish before Ghidra consumes them.** Standalone output stages and then
  publishes `scatter/<label>/load_map.json` plus only the needed
  `blocks/<entry>-<operation>.bin` payloads. `decompose::marshal_image` moves the owned
  per-image directory to `images/<label>/scatter/`; it is a terminal artifact and survives
  `--prune`. Explicit current state drives marshalling: a present map replaces the owned
  terminal directory, a successful current `NoCandidate` removes it, and failed/unmanaged
  production preserves prior terminal state. Metadata errors never masquerade as absence.
  The literal `2.0.0` artifact golden is intentional: package-version changes alter serialized
  wire output and must explicitly rebaseline the byte-for-byte fixture.
- **Ghidra preflights before mutation and retains both views.** `ApplyScatterLoad.java`
  strictly validates the complete schema, raw-image identity, contained payload paths and
  open-file identities, hashes, entry topology (including `index == array position`), sizes,
  and all existing/requested memory collisions before creating a block. Mutation consumes
  those same validated open streams.
  If creation, permission setting, hashing, or cleanup fails, it removes created blocks in
  reverse order and explicitly aborts Ghidra's script transaction; throwing alone is
  insufficient because Ghidra can otherwise commit a failed script transaction. The original
  raw block remains mapped. Added blocks are loaded, initialized, readable, writable,
  non-executable, and non-volatile; the scatter table has no trustworthy MPU evidence, so
  granting execute permission would manufacture analysis evidence.
- **Research provenance is MIT-compatible, not a copied oracle.** Structural prior art is
  [`alexander-pick/shannon_modem_loader`](https://github.com/alexander-pick/shannon_modem_loader)
  commit `2dc27f01782eaaa55ef626e15ef6b4154bf0e392` (MIT-style license),
  [`grant-h/ShannonBaseband`](https://github.com/grant-h/ShannonBaseband) commit
  `8ebffcd0ae47d1f2e3ac938ea42b3944537cbd1e` (MIT license), and BaseSpec's
  scatter-table research as a secondary reference. The production implementation is an
  idiomatic, independently tested Rust reconstruction; never import upstream code, firmware
  excerpts, or generated corpus payloads.

### Runtime PAL task inventory

- **`count_global` names runtime-writable RAM, not a statically readable address.**
  The initializer only *stores* the task count there; the real Mustang plan
  points it ~11 MB past the raw image, outside every scatter destination, and
  the write is real (133 named tasks validate against hashed slots). The
  strict reader therefore maps-checks every address the proof must *read*
  (CFG, guard branch, table slots, entries, names) but deliberately not
  `count_global` — treat it as store-only provenance.
- **Discovery proves the initializer semantically; nothing else nominates a candidate.**
  `pal_tasks::discover` finds every materialization of the nine-byte anchor `PALTskTm\0`
  (`ADR`-family, PC-relative literal load, or register-consistent `MOVW`/`MOVT`), keeps the ones
  that survive unique-prologue root selection and bounded CFG closure, then proves a counting
  loop: a reaching zero definition of the count register, a decoded `count >> shift` unsigned
  capacity guard whose `(compare_value + 1) << shift == capacity` under checked arithmetic, both
  loop exits sharing one count global, an exact suffix loop, and a common join. The slot base
  comes from a backward-sliced direct constant or side-effect-free leaf accessor; geometry
  (slot base, name/index offsets, stride, capacity) is *derived from code*, never scanned raw.
  Raw shape scanning is unusably permissive (it finds exact-stride harmonics); a fixed threshold
  or analyzer-inventory gate would both reject valid firmware and bless invalid lookalikes —
  neither is anywhere in the code. `Ok(None)` is clean absence; a candidate that crosses the
  first-slot plausibility threshold and then fails is the contextual malformed error; several
  complete survivors are the typed ambiguity error. A malformed sibling never lets a valid one
  pass silently.
- **Unknown values do not erase precise write sets.** `ValueEffect::Unsupported` means the decoder
  cannot model the written value; it does not mean a known instruction writes every register.
  PAL preservation queries must use that instruction's conservative exact core-register `writes`
  set while retaining the existing predication and call-boundary rules. The genuinely unsupported
  fallback already declares all core registers writable and therefore remains fail-closed. This
  distinction is required by Cheetah's valid suffix: a Thumb `MLA` writes `r0` with an unsupported
  value transform but still proves that induction registers `r4` and `r7` survive.
- **The corrected corpus baseline is 133/162 from true slot 0.** Earlier research described
  Cheetah as 161 records from `0x441c8398` — that is slot 1's descriptor projection, not the
  table start (`FUN_42118f76(0)` returns `slot_base + 0x118`, and a forward-only margin search
  from it skipped slot 0). Mustang/S5400: slot base `0x43d61f60`, stride `0x1f8`, 133 tasks,
  terminal `0x43d72538`. Cheetah/S5300: slot base `0x441c8198`, stride `0x1d8`, 162 tasks,
  terminal `0x441dac48`. Every entry on both corpora is a uniquely addressed, uniquely named
  odd (Thumb) pointer; 57 Cheetah entries sit at `2 mod 4` (Thumb needs halfword, not word,
  alignment). The regression `cheetah_slot_zero_regression_parses_162_slots`
  (`pal_tasks/table.rs`) reproduces the interior-accessor shape and pins table start at true
  slot 0; production contains no forward margin search.
- **Descriptor-v1 field relationships.** Within each slot: `+0x0c` runtime task index (static
  zero), `+0x4c` name pointer (the initializer's tested termination field), `+0x50` priority
  byte (upper 24 bits zero), `+0x54` nonzero stack size divisible by four (not necessarily a
  power of two), `+0x58` entry pointer with the ISA tag in bit 0, `+0x5c` optional
  callback-like pointer, `+0x60` optional unknown pointer. The descriptor projection at slot
  `+0x28` (name/priority/stack/entry at `+0x24/+0x28/+0x2c/+0x30`) is an artifact view, not the
  table boundary. The large zero regions inside each slot are *not* padding — consumers use
  fields deep in the runtime object; uninterpreted bytes stay opaque static runtime state and
  contribute to the slot hash only.
- **One runtime view, shared execution identities.** PAL discovery validates against the same
  `RuntimeImage` every other execution consumer uses: byte-backed storage spans resolve raw
  bytes *or* scatter-materialized bytes, a task's name/entry/slot may live in either, and every
  accepted entry instruction decodes through the project-owned
  `scaleservers-arm32-assembly` adapter with strict ISA tagging — no cross-ISA fallback. ARM
  and Thumb pointers normalizing to one address reject the candidate; shared entries with one
  ISA stay valid. The manifest binds the scatter load-map BLAKE3 it was validated against plus
  the sorted unique scatter entries used, and readers re-authenticate both.
- **PAL identity counts semantic applications, not storage dependencies.** The final component of
  `v1:<manifest-blake3>:<task-records>:<distinct-entries>` is the strictly revalidated canonical
  application count. It must never come from task-record count (shared entries are valid) or
  `scatter_entries_used` (storage provenance is independent). Both accepted corpora use zero
  scatter dependencies yet correctly emit `:133:133` and `:162:162`.
- **Resource limits are named constants** (`pal_tasks/mod.rs`): 4096 anchor occurrences, 16384
  anchor references, 4096 bytes anchor-reference distance, 32 instructions per `MOVW`/`MOVT`
  span, 256-byte prologue window, 512-byte/256-instruction entry-rooted CFG, 64 candidate
  tuples, 512 MiB *non-refundable* shared validation budget (charged bytes never return, even
  for rejected candidates), 16 instructions per slot-base leaf, 4096 table capacity, 64 KiB
  stride, 128-byte names, and 2000-byte symbol leaves (Ghidra's own bound). Exceeding any limit
  is a typed resource error, never a silent miss.
- **Ghidra seeding is transactional and ordered.** Script order is `ApplyScatterLoad` →
  `ApplyExceptionRoots` → `ApplyPalTasks` → `TameAnalysis` → analysis → export, with each optional
  application script present only for its explicit current state; a PAL map without a scatter map passes
  `-` as the scatter argument. `ApplyPalTasks.java` strictly revalidates the manifest (image
  identity, scatter dependency, hashes, label policy recomputation) before any mutation, seeds
  one function per entry inside one transaction, records ownership in the
  `PixelModemExtractor.PalTasks.v1.Ownership` property map plus the reserved
  `PixelModemExtractor_PalTasks_v1` namespace, and on any failure rolls back every created
  function/label/comment in reverse and explicitly aborts the Ghidra transaction (throwing
  alone is insufficient — Ghidra can commit a failed script transaction). Re-application is
  idempotent. In datamark mode (`--no-thumb-decompile`) authoritative task code is carved out
  as code before undefined regions are marked data — task functions survive both modes.
- **Ownership survives pass 2.** Pass-2 name application matches PAL applications by decode
  ISA; stronger recovered evidence replaces only project-owned task primaries (recording the
  transition) while PAL evidence and role labels persist, a meaningful pre-existing name is
  preserved and counted, and any stale registry entry, unregistered owned comment, merged or
  retagged task function, or identity mismatch is a hard failure — never a silent overwrite.
  The export completion marker binds the exact PAL identity
  (`pal_tasks=v1:<manifest-blake3>:<tasks>:<distinct-entries>`); the postflight re-reads the
  program state and rejects drift. `PalTasksSupport.ValidatedPal` retains the exact task-manifest,
  optional scatter-map, and raw-image handles through final export postflight, rechecks those same
  path identities without reopening them, and closes every partial or complete acquisition in
  reverse order with suppressed cleanup diagnostics.
- **Terminal state is ownership-explicit.** `decompose` marshals the validated manifest to
  `images/<MAIN>/pal_tasks/tasks.json` after authenticating it against the terminal
  raw/scatter bytes (validation precedes any terminal byte change; `rename` is the commit).
  A successful no-candidate run removes the terminal directory; failed or unmanaged runs
  leave prior terminal state untouched. Currentness never comes from artifact existence.
  `--prune` retains the terminal manifest.
- **Corpus and real-Ghidra commands.** The generated-fixture battery and every apply/rollback/
  pass-2/postflight leg run inside the serial real-Ghidra suite:

      cargo test --test decompile_golden -- --nocapture --test-threads=1

  The private-corpus PAL goldens (`tests/pal_tasks_golden.rs`) wrap the retained MAIN slices
  from `PME_S5400_MAIN` / `PME_S5300_MAIN` through the complete production generation path and
  pin semantic addresses, geometry, counts, distributions, uniqueness, ISA totals, inventory
  diagnostics, and two aggregate digests:

      cargo test --test pal_tasks_golden -- --nocapture --test-threads=1
      env -u PME_S5400_MAIN -u PME_S5300_MAIN \
        cargo test --test pal_tasks_golden no_corpus_environment_skips_independently \
        -- --exact --nocapture --test-threads=1

  The `manifest_blake3` / `metadata_blake3` pins commit no names or firmware bytes, so they
  are population points: run once with the corpus, copy the digests the unpopulated pins print,
  and every later run enforces them. Never infer a corpus pass from a clean env-gated skip.
  The pre-implementation research proof stays reproducible outside Git with
  `rust-script --test ~/.superpowers/pixel-modem-extractor/2026-08-20-pal-task-semantic-validation.rs`
  (and its two corpus invocations; see the design trail). The release acceptance matrix —
  both semantic-proof legs plus fresh release-mode decompose in tighten and datamark modes
  for both retained images, with isolated-build provenance and per-leg report/manifest
  consistency gates — is `scripts/pal-acceptance.sh`; a missing input leaves that named
  gate UNRUN, never passed (`--partial` runs the subset and prints every unrun gate).
- **Rejected approaches, keep rejecting them.** Upstream's forward padding/margin search
  (it manufactured the Cheetah slot-0 omission), inventory-gated task acceptance (retained
  Ghidra matched 0/3 and radare2 11/19 of the true entries — inventories are producer-tagged
  evidence, never validity), fixed per-model addresses or strides, raw shape scanning, byte
  signatures for the loader, and any artifact-only or opt-in seeding fallback (a MAIN either
  proves its initializer or the command fails; it never ships half-seeded).

### Debug-trace catalog

- **Scan threshold then quarantine.** `dbt_traces::discover` sweeps every offset of every
  byte-backed range for the four-byte `DBT:` header (alignment is recorded, never assumed).
  An occurrence becomes a candidate only when the complete 28-byte record is byte-backed, word
  7 resolves to a NUL-terminated string that satisfies the shared `is_src_path` classifier,
  and word 6 (source line) is in `1..=MAX_LINE` (`1_048_575`). Below threshold is noise —
  never a record, never an error. A candidate that then fails a message-pointer invariant is
  quarantined as `{address, reason, raw_words}` with a typed reason:
  `message_unterminated`, `message_over_cap`, `message_invalid_bytes`, `pointer_wrap`.
  Crossing `MAX_QUARANTINED` fails the stage (sustained quarantine is structural). An
  unmapped or scatter-zero message pointer is *not* a violation: it publishes as
  `message.unresolved` with `storage ∈ {unmapped, scatter_zero}`. Message charset is
  `0x20..=0x7e` plus `\t`/`\n`/`\r`; any other control or non-ASCII byte is
  `message_invalid_bytes`. Source-path reads stay the shared printable-ASCII classifier.
- **Named caps** (`dbt_traces/mod.rs`), all typed errors checked before allocation:

  | Limit | Value | Rationale |
  |---|---:|---|
  | `MAX_OCCURRENCES` | 1,048,576 | 4× largest corpus sweep noise headroom |
  | `MAX_RECORDS` | 1,048,576 | 4× corpus (247,205) |
  | `MAX_UNIQUE_FILES` | 65,536 | 13× corpus (4,820) |
  | `MAX_UNIQUE_MESSAGES` | 2,097,152 | 12× corpus (174,243) |
  | `MAX_QUARANTINED` | 4,096 | sustained quarantine is structural |
  | `MAX_MESSAGE_BYTES` | 4,096 | bounded string read window |
  | `MAX_LINE` | 1,048,575 | threshold plausibility bound |
  | `MAX_REFERENCES` | 4,194,304 | 16× records headroom |

- **Standalone scatter bind is this-run only.** `decode-traces` binds
  `scatter/MAIN/load_map.json` only when this invocation just materialized it.
  Clean absence (`discover → Ok(None)`) clears the owned `scatter/MAIN`
  directory and uses a raw-only view — leftover maps from a prior `--out`
  reuse are never rebound. Other files under `--out` are left alone.
- **`dbt_exact` index rows are not gated on `__FILE__`.**
  `recover_source::build_index` unions attribution keys that are absent from
  the source-tree scan so a DBT-claimed path still gets a `dbt_exact` row.
  No source leaf is invented on disk for those paths.
- **Record-spill staging.** Discovery writes each accepted record as a 30-byte frame to
  `dbt_spill+{pid}/records.spill` and never accumulates the record set in memory. The only
  in-memory tables are the interned unique files/messages (bounded by the caps above) and the
  later sorted record-address vector. The spill directory is removed after publish on every
  exit path; it is a different name from the catalog staging dir
  (`debug_traces.staging+{pid}`) so the two cannot collide.
- **Corpus pins and serial tests.** See the `dbt_traces_golden` bullet under **Tests**. The
  populated `manifest_metadata_blake3` pins are the `pal_tasks_golden` empty-sentinel pattern
  after population. No serial-test note is required: this increment has no Ghidra legs.

- **CLI dispatch is thin.** `cli.rs` only parses args and resolves the `--out` default,
  then delegates to a module-level `run(...)`. Put new logic in the module, not in
  `cli.rs`. The decoder subcommands' `run()` prints its own console report; the pipeline
  commands (`extract`, `source-tree`, `decompose`) return a path that `cli.rs` prints.
- **Errors and logging.** The library core returns the typed `crate::error::Error` and
  its `crate::error::Result<T>` alias (`thiserror`; fail-closed variants such as
  `BadMagic`, `BadToc`, `SizeMismatch`, `ToolNotFound`). `anyhow` is used only at the CLI
  edge (`cli::run() -> anyhow::Result<()>`). `bin/main.rs` initializes `tracing` on
  stderr, prints `error: {e:#}` on failure, and exits 1.
- **Symbolication is fail-closed.** Every primary-name decision uses one order:
  `__func__ > registration > exception_root > pal_task > token > string_ref`. A recovered
  `__func__` (an assert site referencing both its `__FILE__` and a unique identifier string) and a
  registration-table match are authoritative `Recovered` names. Exception-root and PAL-task names
  are durable role evidence below those firmware-native names. Token and string-ref survivors are
  marked `Provisional` `guess_*_<addr>` names, never unmarked; file attribution and DBT evidence
  are annotations only and never primary names. Token immediates are recovered by `movw`/`movt`
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
  Scale note: `02_MAIN`'s `thumb_functions.json` is large (632 MB with
  `body_c`, ~141k Thumb functions). `thumb_enrich` no longer loads/rewrites
  it whole — the Stage-2 streaming rewrite is bounded by the ~86 MB
  `decompiled.c` bodies map plus one function record (measured production
  A/B on the real inputs: 130 s, 2.29 GB peak, byte-identical to the
  whole-file oracle; see the radare2 streaming bullets) — and `symbolicate`'s
  finalize rewrites stream too (Stage 4: element-wise stamps and `body_c`
  renames through `thumb_analysis::stream_rewrite_json_array` /
  `stream_rewrite_thumb_functions`, byte-identical to the whole-file
  rewriters on the real production tree); and the ARM loader holds zero-copy
  borrowed views of `disasm.lst` (Stage 5), so the pathological wide-range
  Ghidra records no longer copy ~190 MB each — see the radare2 streaming
  bullets; pw_tokenizer strings are structured
  `■format♦…■domain♦…`, and tokens appear as `movw`/`movt` immediates (not
  raw literals, so a byte search won't find them).
- **String-reference name guesses.** At the lowest naming precedence, `symbolicate` may recover a
  function's single *distinct* referenced identifier string (`name_guess::unique_ident`), when it is
  referenced by exactly one function image-wide and is not an all-caps message
  constant, a recovered global name (`globals.json`), or another function's
  name. Survivors become marked `guess_<ident>_<addr>` `Provisional` names with
  a `string_ref` evidence entry (`class`: `fn_name` | `type_label`). They never
  reach Ghidra's pass-2 output — not because `ApplySymbols.java` skips them
  (it doesn't: it renames every symbol it's given a `name` for, applying
  `recovered` as `USER_DEFINED` and everything else, including token-tier
  guesses, as `ANALYSIS`), but because this tier is computed only at the
  post-globals `symbolicate_finalize` stage, never at the pre-globals
  `symbol_map` stage that produces ApplySymbols' input. That gate
  (`globals.json` and the raw image present) is route-dependent. In the normal
  `decompose` route, Phase 3.0 writes `globals.json` before
  `symbolicate_finalize` runs, so the tier is inert at the earlier
  `symbol_map` stage and active at finalize. Under `--no-symbol-pass`,
  `symbol_map` is skipped and the route runs `symbolicate_finalize` *twice*:
  first to produce recovered/token names for the record-only globals stage to
  consume (deferring the `decompiled.c` rewrite so its idempotency sentinel does
  not block the second pass), then again after that stage has written
  `globals.json` — the second finalize is where the string-ref tier activates
  and rewrites `decompiled.c`. So this route produces string-ref guesses too, at
  the cost of a second `build_map` pass. Measured on `02_MAIN`: ~8,700
  string-ref guesses, audited ~53% the function's own name / ~85% useful
  (see the design spec). Precision knobs live in `name_guess::string_ref_guess`.
- **Registration-table names (authoritative).** `symbolicate/reg_table.rs`
  scans the raw split image for contiguous `{name_ptr, fn_ptr}` tables — the
  AT-command dispatch, ISR, and protocol-handler tables baseband firmware is
  full of — and mints a **bare `Recovered` name** for each. The same global order applies:
  `__func__ > registration > exception_root > pal_task > token > string_ref`. The **fail-closed gate
  is the function inventory**: the pointer (Thumb bit stripped) must resolve to a
  known ARM/Thumb entry, so a name is only minted for a confirmed function — no
  prologue heuristics. Further fail-closed rules: the name must be a clean
  `is_ident`; strict **1:1** (a name at >1 function, or a function under >1
  distinct name, is dropped); a name that aliases a recovered global or another
  function's name is rejected; and a table entry never overrides a function's
  pre-existing *real* (non-`FUN_`) name — it defers, like string-ref. (The
  recovered-global rejection is best-effort at the `symbol_map` stage since
  `globals.json` does not exist yet there; any residual collision is handled by
  `finalize_names`, which suffixes duplicate `Recovered` names with `_<addr>`.)
  **All-caps names are accepted here** (unlike the
  string-ref tier) — `PICH_HISR` is a real ISR name, and the table structure
  earns that trust. Layout: both stride-8 orders (`{name,fn}` and `{fn,name}`)
  occur and carry comparable yield; detection is **longest-run-first** so a
  reversed table is never misread by the forward layout shifted one word in
  (its true run is one record longer than the shifted misread, so it claims the
  span — see `scan_detects_reversed_layout_without_mispairing`). Runs must be
  ≥3 records. Wider strides were measured to contribute nothing and are omitted.
  **Ordering (why it reaches Ghidra and string-ref does not):** the scan needs
  only the raw image + the entry sets, *not* `globals.json`, so it runs inside
  `build_map` at the pre-globals `symbol_map` stage — its `Recovered` names land
  in ApplySymbols' pass-2 input and are applied as `USER_DEFINED`, baked into
  the regenerated `decompiled.c`. (Global-alias rejection is therefore
  best-effort at that stage: `globals.json` does not exist yet, so `global_names`
  is empty there; the finalize re-run and the standalone `symbolicate` subcommand
  do have it.) **Measured yield on the 2026-08-25 fresh goldens: 113 mustang /
  77 cheetah registration evidence names, all `Recovered`, ~100% precision**
  (e.g. `AtiParsePlusCUSD`, `AtiQuePlusCPLS`, `RCSSH_SessMgr_*`). The older
  ~233/101 figures measured the pre-regeneration corpus state and are not
  reproducible on it — the ISR-named pairs (`PICH_HISR` etc.) have no
  pointer materialization in the current image (2026-08-26 ISR spike).
  Fresh clean-root pass-2 acceptance on both models (2026-08-27, Ghidra
  12.1.2_DEV, radare2 6.1.4) closes the old final-application gap: bounded
  registration representatives nominated through rename and creation routes
  all reached the final `functions.json`. Final symbolication can legitimately
  omit their `kind: "registration"` evidence after pass 2 because the scanner
  defers when the refreshed program already carries the applied real name.
  Audit a rename through its symbol-map `symbols[]` decision, the
  `ApplySymbols` summary, and the final inventory. Audit a creation or owned
  replay through its symbol-map `creations[]` request, the conserving
  `ApplyThumbNames` summary, and the final inventory; `report.json` pairs the
  bound map count (`pass2_creation_candidates`) with its classification as
  `pass2_created`, `pass2_creation_reapplied`,
  `pass2_creation_skipped_existing`, and `pass2_creation_skipped_collision`.
  A smaller final registration-evidence set does not by itself mean the name
  was lost. This remains a small, high-value, precision-over-volume lever
  (contrast string-ref's ~8.7k @ 53%).
  **Deliberately not built:** call-site `Register(name, fn)` registration
  (validated yield ~10 — the pointer is rarely materialized into a catchable arg
  register; see the `2026-08-14-registration-naming` findings). Per-function
  discovery-time provenance is the `kind:"registration"` evidence in
  `symbols.json`; rename decisions also retain a `registration: "<base>"`
  annotation in the symbol map. A `creations[]` record retains the exact
  nominated entry, execution, name, and source but not the registration evidence
  kind, and final symbolication may omit that original `symbols.json` evidence as
  described above. After finalization, use final `symbols.json` evidence where it
  remains, the map annotation for a rename, or a retained pre-finalization
  `symbols.json` for a creation's registration provenance; the creation map,
  `ApplyThumbNames`/report classification, and final inventory prove application.
  There is no standalone table-level sidecar (the `RegScan::entries` inventory is
  its natural source if one is ever wanted).
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
  normal route; on that same route, global-*shape* recovery also runs before
  pass 2 and can feed a global-types map (see **Phase 3.2 type application**
  below). `decompile::run_two_pass` accepts a typed per-image input with up to
  three optional maps — function, global, and global-types. Each map is
  constructed only from a non-empty regular file, stores its canonical
  absolute path, and is revalidated immediately before Ghidra arguments are
  built. Global/global-type maps have non-zero counts; a function map may have
  zero Ghidra executions when its non-empty `creations` section alone schedules
  pass 2, and retains those exact entry/name/source requests. Initial validation is component-local (an
  invalid map is omitted without suppressing its valid siblings); a late
  identity/type change fails the whole scheduled image rather than changing
  its script set. It starts exactly one `analyzeHeadless -process -noanalysis`
  saved-project process for each image having at least one of the three
  inputs. With all maps present, the fixed post-script order is
  `ApplyThumbNames.java -> ApplySymbols.java -> ApplyGlobals.java ->
  ApplyGlobalTypes.java -> ExportDecomp.java`. Each map remains independently
  optional; `ApplyThumbNames.java` rides in the function map and runs first
  whenever one is present (a no-op on an empty `creations` array), while an
  image with none of the three inputs starts no pass-2 process at all. Creation
  runs first so malformed producer or ownership state cannot follow another
  pass-2 mutation. Ghidra rolls back earlier post-scripts when a later script
  fails in the same headless invocation. A separately committed
  `ApplyThumbNames`-only staged state is still accepted only by an identical
  current-map retry, which must revalidate it as `reapplied` before Rust
  publishes an export. See **Ghidra 12 headless API notes** below for the
  argument-construction details and the all-three example.

  **Pass-2 creation of named producer-owned Thumb functions.** The symbol map
  is `pixel-modem-extractor-symbol-map-v4` with a `creations` section: named
  (`Recovered` or provisional) Thumb executions authenticated by a validated
  producer inventory (radare2/Rizin strict v3) whose entry Ghidra's own
  inventory never discovered. Readable v1/v2 legacy records remain valid
  consumer evidence but are never creation authority; only a concrete
  strict-v3 radare2/Rizin producer run may enter `creations`. Fresh clean-root
  acceptance (2026-08-27) observed Mustang MAIN conservation of 169 candidates = 165 created + 4
  `skipped_existing`, and Cheetah conservation of 64 candidates = 64 created; these are corpus/tool
  observations, not universal inventory promises. The earlier ~4.2k / ~2.8k development-tree
  estimates are superseded and are not fresh-root acceptance baselines.
  Every validated retained Ghidra entry excludes creation, whether its
  projection is accepted or quarantined: both mean Ghidra discovered the
  function. Quarantined records remain excluded from map executions and
  decisions; they supply only this entry-level creation exclusion.
  `ApplyThumbNames.java` first classifies every request without mutation:
  exact replay, existing-function/authenticated-span overlap, invalid or
  colliding name, or planned creation (earlier canonical plans reserve their
  authenticated spans). It then declares TMode, disassembles only inside the
  authenticated address set (flow-enabled, analysis disabled, budgeted), and
  passes the explicit returned disassembly set to `CreateFunctionCmd` before
  naming each planned function (`USER_DEFINED` for recovered, `ANALYSIS` for
  provisional). The final function body must remain wholly inside the
  authenticated ranges and never expands through unconstrained control flow.
  The script rolls back transactionally on any failure. Fail-closed rules:
  existing-entry handling is exhaustive and ordered: an owned matching existing
  function is fully revalidated and counted `reapplied`; an exact name/source
  existing function without ownership is a hard failure; any other existing
  entry function is preserved and counted `skipped_existing`;
  duplicate requested names are skips (never suffixed variants); ambiguous
  same-entry names and name collisions are counted at map-build; a creation
  whose first authenticated decode range does not start at the entry is skipped
  at map-build (`not_entry_start`) rather than emitted — radare2 multi-chunk
  records can carry a prior range (68 named on mustang MAIN, 2026-08-26) and
  the Java reader rejects the whole map if any one fails that check.

  Every created function is registered in
  `PixelModemExtractor.ThumbNames.v1.Ownership` as
  `v1:<map_blake3>:<producer_execution_blake3>:<function_id>:<primary_symbol_id>:<ghidra_execution_blake3>`.
  A saved-project retry counts an identical creation as `reapplied` only after
  revalidating that ownership value, the concrete function and symbol, the
  primary/source, the accepted Thumb projection, current memory, and the Ghidra
  execution digest.

  The script emits exactly one strict conserving `ApplyThumbNames: {json}`
  summary. Rust requires the scheduled image and candidate count, classifies
  `created + reapplied + skipped_existing + skipped_collision == candidates`,
  and treats a missing, duplicate, malformed, wrong-image, or non-conserving
  summary as a pass-2 failure before marking the export current. Rust terminal
  validation uses the pass-1 producer inventory as its baseline, accounts for
  both newly created and same-map owned-replayed functions, proves every
  retained Ghidra execution survived, and permits only accepted Thumb additions
  with the exact requested entry/name/source; aggregate growth can never
  authorize identity substitution. It validates and publishes exactly
  `decompiled.c`, `disasm.lst`, and `functions.json`, preserving every sidecar,
  then refreshes the current `ImageResult` raw/accepted/quarantined inventory
  and report counters from the committed terminal summary. `ExportDecomp`'s
  identity postflight exempts creation entries from the pass-1 digest comparison
  only because these Java and Rust checks own them. Its tiny-anchorless
  image-base entry fallback is pass-1/single-pass only: a present symbol map may
  validly retain zero functions, and the exporter never mutates that
  map-authenticated pass-2 state after postflight. Report surface: map planning
  (`pass2_creation_candidates`, nested `pass2_creation_map_skips`) plus runtime
  `pass2_created`, `pass2_creation_reapplied`,
  `pass2_creation_skipped_existing`, and
  `pass2_creation_skipped_collision`; the four runtime counts conserve the
  candidate count. Budgets: `PME_THUMB_CREATE_ENTRY_BUDGET_MS` (30 s) /
  `PME_THUMB_CREATE_PHASE_BUDGET_MS` (60 min). Downstream,
  `thumb_enrich_post_pass2` fills the new functions' `body_c` for free.

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
  Per-function hybrid output is strict v3 with optional per-function `body_c`;
  the asm `body` comes from the owning radare2 or Rizin run. `thumb_enrich`
  parses `decompiled.c` and fills `body_c` by
  **entry address** (Phase 2.1's matching fix — Phase 2 shipped name-based
  matching, which never aligned analyzer-generated names with Ghidra's
  `FUN_<addr>` / recovered names; Phase 2.1 switched to
  address-based matching per the spec's original intent; see Phase 2.1
  invariants below). `thumb_enrich` is pure Rust, idempotent, runs after pass
  1 and again after pass 2. `--no-thumb-decompile` reverts to Phase-1 datamark
  behavior. A runtime wall-clock + log-spam watch kills Ghidra on
  overlapping-function-repair spin and falls back to datamark per image
  (recorded as `thumb_tighten_error`, image not marked `failed`); see
  **Surface B mechanics** below for the kill path and budget calibration.
  **Historical pre-v3 production status (verified end-to-end on a real `02_MAIN`):** Phase 2.1's
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
  figures as current HEAD. These inventory counts predate corrected `realsz` and Rizin fallback;
  use them only as a measured Ghidra-enrichment baseline. Ownership-aware
  `refresh_decompiled` preserves `thumb_functions.json` and producer-qualified
  `thumb/*.stdout` across pass 2. The Phase 2
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
  firmware Thumb discovery is driven by host-detected dense regions + Ghidra's flow
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
  `TameAnalysis mode=datamark` end-to-end. The host analyzer still emits the
  same strict v3 artifact; this flag changes Ghidra discovery/`body_c`, not
  producer provenance or fallback policy.
  (3) **The runtime watch (Surface B) is non-deterministic.** Its data fields
  (`thumb_tighten_error`) are structurally tested at the report-shape level;
  the kill behavior itself is verified manually via
  `--tighten-wall-clock-budget-sec 1`. Don't assert on the kill firing in a
  unit test — it depends on Ghidra's repair-log cadence against real firmware.
  (4) **Missing `thumb_functions.json` after successful Thumb analysis is an error.**
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
  Fresh Task 11 acceptance on the retained Mustang/S5400 image with
  pixel-modem-extractor 2.0.0, Ghidra 12.1.2_DEV, and radare2 6.1.4 measured
  919 Recovered on `02_MAIN` and 925 stage-wide in both default and
  `--rizin-fallback` runs; the fallback leg preflighted Rizin 0.8.2 but made no
  Rizin analyzer call. These are corpus/tool-version observations, not universal invariants.
  The 915 MAIN result below remains useful only as labeled historical pre-v3
  evidence.
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
- **Thumb data_refs augmentation.** Producer references already share one canonical field:
  radare2 adapts selected per-operation refs and Rizin adapts selected trailing `axlj` edges.
  Neither source is guaranteed to include every movw/movt-constructed address, so the globals
  Thumb path additionally augments `non_string_refs` with
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
- **Historical pre-v3 Phase 3.0.1 production state on `02_MAIN` is ARM+Thumb.** Full two-pass
  `decompose` with ownership-aware pass-2 refresh and 4 GiB radare2 streaming
  closed Thumb through pass 2: `globals_recovered` = **915** on `02_MAIN`
  (arch: arm 367 / thumb 545 / mixed 3); stage total recovered 921 with 194
  conflicts dropped. Older ARM-only figures (370 post-`__FILE__`-fragment
  filter; 933 unfiltered; Phase 3.0's 424 ARM-only / 968 ARM+Thumb) are
  historical pre-fix observations — do not cite them as current HEAD
  production. These numbers predate corrected v3 boundaries and Rizin fallback; retain them as
  a comparison baseline, not a current inventory promise. The
  `phase3_0_1_recovered_exceeds_phase3_0_baseline` golden
  sentinel still asserts `> PHASE3_0_ARM_ONLY_BASELINE` (424) and is
  env-gated (`PME_GOLDEN_DIR`); it held under the historical 915 total.
- **Cross-path conflict characterization.** Of the 223
  same-address proposals dropped by strict-single-source on an earlier
  ARM-only production `02_MAIN`, **17 are genuine Phase-3.0-strict-vs-
  Phase-3.0.1-disasm disagreements** (the rest are same-path internal
  conflicts). Strict-precedence would gain +11 Recovered; disasm-precedence
  +9; **both propagate clearly-wrong names** on the cases they flip. Current
  strict-drop (drop both on disagreement) is the right call — neither path
  is reliable enough to arbitrate the other. The historically verified pre-v3
  post-fix net on `02_MAIN` was 915 Recovered (see the production-state bullet
  above).
- **Historical cap calibration remains valid for both backends.** The former 256 MiB
  in-memory cap blocked production radare2. A healthy mustang region emitted ~1.82 GiB and the
  complete old run emitted ~3.65 GiB across captures, grounding the current shared 4 GiB
  per-attempt stdout cap. The producer now records backend-qualified capture identity in v3;
  do not reintroduce backend-specific cap names or unqualified capture paths.
- **The cheetah runaway is the fallback acceptance case, not a silent skip.** Measured:
  cheetah `01_MAIN`'s
  `0x42310000` (a 4 MiB blob) runs `aaa` away to ~93.5 GiB, while every other
  region on both reference models peaks ≤ ~2.3 GiB *virtual* under the full
  `aaa;aflj;pdfj @@f` command. The shared Unix child setup applies 16 GiB `RLIMIT_AS`, so
  radare2 exits fail-closed instead of exhausting the host. Default v3 retains that failed
  attempt when another region succeeds. With opt-in fallback, Rizin then recovers the region
  under its own command/deadline and owns its function run. Windows has no portable child
  address-space limit, so run this corpus gate on Unix. **Root cause of `0x42310000`
  (investigated):** it is *not* misclassified data — the region is genuine dense
  Thumb (entropy ≈ 7.05 and real `bx lr`/`push`/`pop` markers, indistinguishable
  from the healthy regions). Isolating r2's analysis passes under the cap shows a
  single culprit: `aac` (recursive call-graph analysis) runs away, while `aa`,
  `aab`, `aar`, and `aae` all complete. But those lighter passes find only 0–1
  functions here — the region's functions are *only* discoverable via `aac`'s
  call-following, which is the very pass that explodes — so no lighter-analysis
  radare2 profile can recover it. The primary fix still belongs upstream in radare2's `aac`;
  failure-only Rizin is the bounded downstream recovery path, not a lighter-r2 substitute.
- **Phase 3.2: global storage-shape recovery.** Default-on in every
  `decompose` (normal, `--no-symbol-pass`, and valid pass-2 fallback), via
  the shared `run_global_shapes_stage` wrapper — but the two symbol routes
  now reach it at different points in `orchestrate_symbol_route`
  (`SymbolRouteStep::RunGlobalShapes`). On the **normal route** it runs
  right after `RunGlobals(PrepareApplicationInput)`
  writes `globals.json` and **before** `DispatchPass2` — i.e. shape recovery
  now happens ahead of pass 2, not after it, so the same pass-2 process can
  apply the recovered shapes as `undefinedN` types via `ApplyGlobalTypes.java`
  alongside `ApplyGlobals` (see **Phase 3.2 type application** below; this
  stage itself only produces the sidecar) — and then **once more** via
  `SymbolRouteStep::RefreshGlobalShapes`, after the route's closing
  `Finalize`, because three later steps rewrite the files the sidecar
  hashes: pass 2's ownership-aware refresh (`functions.json`),
  `thumb_enrich_post_pass2` (`thumb_functions.json`), and — the last of
  them, measured e2e — `symbolicate_finalize`, whose
  `rewrite_functions_json` stamps `name`/`original_name`/`annotations` into
  BOTH files. A re-commit placed anywhere before `Finalize` is re-staled by
  finalize's writes, so the FINAL sweep's re-commit (after `Finalize`,
  before the post-symbol RF/hwcfg stages, which write no hashed input) is
   the tree's truth. The re-run is idempotent (identical inventories →
   identical decode inputs and totals; the input hashes and the observation
   context names — `functions.json` names rewritten by pass 2 / finalize —
   may differ) and replaces the single `global_shapes` stage entry in place
  (`record_global_shapes_stage`) so the report carries exactly one entry
  with the final sweep's totals. On **`--no-symbol-pass`** it still
  runs last, after the route's second `Finalize`, exactly once — that route
  has no pass 2 to feed and nothing rewrites the sidecar's inputs after it,
  so its timing is unchanged from before the reorder. The pre-pass-2 move is
  input-safe: `global_shapes::run_image` reads only the raw image,
  `globals.json`, and the pass-1 `functions.json` / `thumb_functions.json`
  inventory — never `decompiled.c` — and pass 2 is `-process -noanalysis`, so
  it never changes function boundaries. The pass-1 inventory the shape stage
  consumes is therefore identical before and after pass 2; only names and
  types differ (both applied downstream, by pass 2), and shape recovery
  itself is name- and type-independent (previously both routes ran the stage
  once via a shared `PostSymbolStep::GlobalShapes` call immediately after the
  whole symbol route returned, i.e. after pass 2 on the normal route). A
  valid empty Recovered set still writes a source-hashed empty sidecar; it is
  not a skipped analysis. `globals.json` is never rewritten. `--prune` retains
  `decompiled/global_shapes.json`. Pass-2 refresh still owns only
  `decompiled.c` / `disasm.lst` / `functions.json` and must not touch this
  sidecar. **Provenance consequence of the reorder + re-commit:** the
  committed sidecar's `functions_blake3` / `thumb_functions_blake3` hash the
  FINAL post-finalize files (recovered names, post-enrich Thumb,
  finalize-stamped), exactly as pre-reorder trees did — trees produced
  between the reorder and the re-commit fix, or by the re-commit's first
  version (which ran before `symbolicate_finalize`), carry stale hashes and
  are born failing `validate_artifact`; re-run `decompose` to regenerate
  them. The
  recovered/counted shape set is unaffected either way (the decoder never
  reads names). Re-baseline any golden or fixture that pins a literal
  `functions_blake3` string.
- **Phase 3.2 currentness.** The stage does not infer readiness from file
  existence. Currentness binds from the post-globals
  `decompile::ImageResult`s — `run_global_shapes_stage` matches them by
  label — never from the stage-report `ImageReport`s: the stage report
  deliberately withholds the globals-preparation fields until pass 2's
  outcome, so a stage-report read at the normal route's pre-pass-2
  position failed every e2e run before that binding fix (a stage-report
  image with no matching `ImageResult` still fails closed, "missing
  current image result"). `current_global_shapes_run` copies the current
  decompile snapshot: raw Ghidra `functions` plus both Ghidra projection
  counters (their sum must equal `functions`); Thumb substantial /
  accepted / quarantined either all absent or all present;
  `thumb_error` absent; `globals_error` absent; `globals_recovered:
  Some` (zero is invoked, not skipped). Missing current-run markers, a
  stale `globals.json` from an earlier failed rerun, or a count mismatch
  is a per-image hard failure:
  the analyzer is not called, an existing sidecar is left byte-identical,
  later images continue, and the aggregate `global_shapes` stage is
  `failed`. **Absent versus stale Thumb:** no current Thumb inventory plus
  no file is valid (`thumb_functions_blake3` is JSON `null`). No current
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
  identity is entry plus the complete ordered authenticated range list and its
  framed aggregate BLAKE3; identical identities union `(entry, name)` contexts
  and are decoded once. Distinct
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
  fallthrough after a control transfer when that PC exists; each block
  exposes its `successors` edges. Traversal starts only at the entry. No
  edge is invented across a gap, into an undecoded suffix, or for a call /
  return / indirect transfer. A call's fallthrough block may be visited
  but begins unknown; the callee is not entered. Facts cross these direct
  edges by a **must-facts join**: every incoming edge must agree on the
  fact — `(target_address, displacement)` for a Global fact, exact
  `value` for an Exact fact — and a fact absent on any in-edge leaves
  that register Unknown at the block entry. There is no per-block reset
  (the v2 "every block starts empty" model is gone); only an unreached
  block or a fully-killed/joined-out fact is empty. Provenance unions
  across agreeing edges, deduped at the join. The depth-1 seed (below)
  joins as a **virtual predecessor** of the entry block: a disagreeing
  real predecessor kills it; it never wins by fiat. The solver is a
  deterministic round-robin worklist over address-sorted blocks; facts
  only die and provenance only grows, so the fixpoint terminates
  monotonically. `state_barriers` (v3 semantics) counts instruction kills
  plus join kills — each `(block, register)` join that ever killed a
  fact, counted once; v2's per-non-entry-block-start +1 is gone.
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
- **Phase 3.2 aggregation and artifact.** Format string is
  `pixel-modem-extractor-global-shapes-v4`; validators and loaders gate
  on it, and a v2 sidecar is stale-vintage — regenerate it, never
  silently read it. Observations that agree at one `(ISA, PC)` union
  contexts and provenance; an agreement subgroup spans every key sharing
  `(target, conditional, kind, width)` at that PC. Same-instruction
  multi-offset accesses are **observations, not conflicts**: one
  instruction's transfers (LDM/STM/LDRD) all evaluate against the same
  register state and share one base register, so a single instruction
  can only produce same-target, same-kind, same-width keys differing by
  offset — honest array evidence, one observation per offset. Two or
  more subgroups at that PC — disagreement on target, conditional,
  kind, or width — are a conflict; every implicated Recovered
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
  The `analysis` block appends six cross-block counters (units in
  parentheses): `cross_block_join_kills` ((block, register) joins where
  some in-edge held a fact but the join left it Unknown),
  `cross_block_join_facts` ((block, register) joins that ever held a
  fact), `cross_block_entry_facts` (facts in final non-entry in-states),
  `cross_block_propagated_facts` (observations whose provenance crosses
  a block boundary), `cross_block_functions` (functions with a join
  survivor), and `cross_block_seeded_functions` (pass-2 seeded callees
  with a survivor). Wire field order is the struct declaration order. Serialization is
  `serde_json` pretty (two-space) with **no trailing newline**. Addresses
  are canonical lowercase `0x…`; blake3 values are lowercase 64-hex.
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
  (4) **Seeds propagate by the same must-join.** The seed joins as a
  virtual predecessor of the callee's entry block (see the state model
  above); from there the v3 cross-block engine carries it past the entry
  block exactly like any other fact — every path to a later block must
  agree, or the join kills it. The v2 entry-block-only seeding (and the
  per-block reset it matched) is gone.
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
  cargo test global_types:: -- --nocapture
  cargo test decompose::tests::global_types_apply_stage_ -- --nocapture
  cargo test decompose::tests::image_report_serializes_global_types -- --nocapture
  cargo test decompile::tests::parse_apply_global_types_summary -- --nocapture
  cargo test decompose::tests::refresh_decompiled_replaces_ghidra_outputs_and_preserves_sidecars -- --nocapture
  cargo test decompose::tests::prune_keeps_only_leaves -- --nocapture
  cargo test --test global_shapes_golden -- --nocapture
  cargo test --test decompose_golden report_json_includes_global_shapes_fields -- --nocapture
  cargo test --test decompile_golden \
    pass2_applies_global_types_and_skips_span_collision -- --nocapture
  cargo test --test decompose_golden global_types_applied_on_retained_tree -- --nocapture
  PME_GLOBAL_SHAPES_REPLAY=1 PME_GOLDEN_DIR=/path/to/unpruned/decompose \
    cargo test --release \
    global_shapes::tests::retained_tree_replay_is_deterministic_and_non_mutating \
    -- --ignored --nocapture
  PME_GLOBAL_SHAPES_MEASURE=1 PME_GOLDEN_DIR=/path/to/unpruned/decompose \
    PME_GLOBAL_SHAPES_MEASURE_LABEL=<image> \
    cargo test --release -p pixel-modem-extractor --lib \
    global_shapes::tests::interprocedural_yield_on_retained_tree \
    -- --ignored --nocapture
  ```
  Goldens skip when `$PME_GOLDEN_DIR` is unset. Replay also needs the raw
  image slices and does not write. The interprocedural yield measurement
  reuses the same replay machinery (two in-memory
  `analyze_to_bytes_without_commit` passes, no write), selects the image
  by `PME_GLOBAL_SHAPES_MEASURE_LABEL` (default `02_MAIN`; e.g. `01_MAIN`
  on cheetah), and only `println!`s the status split plus the six
  depth-1 and six cross-block `analysis` counters — see **Phase 3.2
  interprocedural measured reality** below for the recorded numbers.
- **Phase 3.2 production baselines, v2 engine (verified full `decompose`,
  ~1 h 37 m, exit 0; superseded by the v3 row below — kept as the
  monotonicity baseline, do not cite as current).** Decoder
  `scaleservers-arm32-assembly` 1.0.0. Recovered shapes
  915 MAIN / 921 total; MAIN observations 32 ARM + 907 Thumb; 125 inferred
  / 787 `no_evidence` / 3 conflicting; MAIN `decode_failures` = 37,629
  (recoverable; the image still succeeds). Producer conservation on MAIN:
  Ghidra 107,955 = 107,785 accepted + 170 quarantined; Thumb 151,411 =
  149,169 accepted + 2,242 quarantined. Established MAIN
  `functions` = 107,955, `thumb_functions` = 117,444,
  `thumb_decompiled` = 77,456, `globals_recovered` = 915. `globals.json`
  is unchanged by the new stage. `--prune` keeps the sidecar. Do not cite
  `thumb_decompiled` = 10,965 as current HEAD.
- **Phase 3.2 production baselines, v3 cross-block engine (fresh mustang
  `02_MAIN` tree, engine + multi-offset aggregation fix; measured with
  the replay/measurement commands above).** **154 inferred / 761
  `no_evidence` / 0 conflicting** — net **+29** recovered shapes over
  v2's 125/787/3: +25 from the sound cross-block engine, +4 from the
  same-instruction multi-offset aggregation fix (v2's three conflicts
  were the same artifact). The move is monotone: `inferred` grew 125→154
  only out of `no_evidence`, and `conflicting` fell 3→0. Replay wall
  ~13 s (MAIN; deterministic, non-mutating) vs ~8.7 s at the v2
  baseline. Cross-block funnel (MAIN): `join_facts` 3,903,434 /
  `join_kills` 898,225 / `entry_facts` 3,005,209 /
  `propagated_facts` 1,063 / `functions` 99,693 / `seeded_functions` 40.
  Depth-1: `direct_calls_resolved` 315, `call_facts_unresolved` 403,
  `seeded_callees` 98, `seed_vectors` 119,
  `interprocedural_observations` 58, dropped 0 (v2-era: 191/287/52/60/3/0
  — the v3 engine's in-callee propagation absorbed the old "callee-side
  cross-block ≤ 3" ceiling; interprocedural evidence grew 3→58).
  `state_barriers` (v3 semantics) 1,523,364; `decode_failures` 37,629
  (unchanged); `instructions_decoded` 11,254,219. `global_types_apply`
  now applies on MAIN: 94 applied / 42 skipped of 136 candidates — v3's
  extra inferred scalars fed it. Opportunistic cheetah `01_MAIN`
  (same measurement, in-memory; that tree's retained sidecar is
  stale-vintage v2 by design): 295 inferred / 766 `no_evidence` /
  0 conflicting (v2-era 274/784/3), wall ~12.4 s.
- **Phase 3.2 interprocedural measured reality.** Under the v2 per-block
  model the depth-1 pass above was correct, deterministic, and
  fail-closed, but its measured net yield on the same production
  `02_MAIN` tree as the v2 baseline was **zero**.
  `inferred`/`no_evidence`/`conflicting` held at 125/787/3 — identical
  to the intra-only baseline — even though the pass did real work:
  `direct_calls_resolved` 191, `call_facts_unresolved` 287,
  `seeded_callees` 52, `seed_vectors` 60, `interprocedural_observations`
  3, `interprocedural_dropped` 0. All 3 interprocedural observations
  corroborated globals that were already `inferred` from intra-procedural
  evidence; none converted a `no_evidence` global. Two compounding
  limitations explained the zero: (1) **store-not-dereference** — the
  pass-by-reference call sites this pass targets are registration/logging
  tables, and the callee typically *stores* `&global` into the table
  rather than dereferencing it, so the evidence it reveals is the
  table's shape, not the global's; the dereferences that would reveal
  the global's own shape happen later, through the stored pointer
  (pointer/alias following — still closed, ceiling below); (2)
  **entry-block-only seeding** — a dereference after the callee's first
  branch was invisible to the v2 seed. Limitation (2) is what the v3
  engine fixed: seeds now propagate in-callee by the same must-facts
  join, the old "callee-side cross-block ≤ 3" ceiling is absorbed, and
  interprocedural evidence grew 3→58 observations (v3 depth-1 counters:
  315 resolved / 403 unresolved / 98 seeded / 119 vectors / 58
  observations / 0 dropped). Outcome: the lever that note left as the
  only one with measured yield — the sound *intra*-procedural cross-block
  dataflow pass (~+5%, ~41 globals) — **shipped as the v3 cross-block
  engine, measured at +25 sound (ceiling was 41); with the
  multi-offset aggregation fix the net is +29** (see the v3 baseline
  row above). Still closed, with measured ceilings: pointer/alias
  tracking and deeper (depth-K) argument propagation. Because the
  remaining barrier is store-not-dereference (not call depth),
  **depth-K would not help**. A 2026-08-13 ceiling spike (throwaway
  instrumentation of the real decoder/tracker over production r2,
  funnel over the `&global` → store → slot → load → dereference chain)
  measured the pointer lever at **≤ 1 recoverable global on `02_MAIN`**:
  of 787 then-stuck globals only 80 store `&global` as a value at all,
  27 reach a static (constant-address) slot (53 use dynamic `[table,
  rIndex]` slots), and just 1 of the 26 static slots is ever read back.
  An unsound "seed every callee block" upper bound leaves that funnel
  unchanged, so it is a true ceiling, not a seeding artifact. Cite the
  depth-1 pass as correct, additive-only, and — since v3 — a real
  contributor through the engine's in-callee seed propagation.
  Full design: `2026-08-13-interprocedural-global-shapes-design.md`;
  interprocedural root-cause: `2026-08-13-no-evidence-dominance-findings.md`;
  pointer-tracking ceiling: `2026-08-13-pointer-tracking-ceiling-findings.md`
  (all process artifacts under `~/.superpowers/pixel-modem-extractor/`, not
  part of this repo).
- **Phase 3.2 environment traps.** Currentness comes from the current-run
  markers, not leftover files. A retained `global_shapes.json` that fails
  hash validation is not necessarily corrupt: trees produced between the
  pre-pass-2 reorder and the `RefreshGlobalShapes` re-commit fix (or by the
  first version of that fix, which re-committed after
  `thumb_enrich_post_pass2` but before `symbolicate_finalize`) are born
  hash-stale by construction (pass 2, `thumb_enrich_post_pass2`, and
  `symbolicate_finalize` rewrote the hashed inputs after those commits; the
  final re-commit after the last rewrite is the tree's truth, and the report
  carries exactly one `global_shapes` stage entry with its totals) — re-run
  `decompose` to regenerate rather than debug (see the stage-placement
  bullet above).
  A retained v2 `global_shapes.json` (e.g. the cheetah reference tree,
  stale-vintage by design) is rejected by the v4 validators — measure
  current behavior in-memory with
  `PME_GLOBAL_SHAPES_MEASURE_LABEL=01_MAIN`, do not read the sidecar.
  A Ghidra 12 output root must stay
  canonically dot-free (see **Ghidra 12 headless API notes**). Replay and
  goldens need a complete unpruned tree; a pruned golden has no raw
  `.bin` slices. The historical dense-Thumb memory envelope (~56 GiB RSS,
  former whole-buffer r2 path) is gone. Both Thumb backends, enrichment,
  typed `recover_source` loading, and symbolication's artifact mutations
  stream; ARM disassembly records borrow zero-copy ranges from the shared
  buffer. The full-`decompose` peak is ~7.7 GB in Ghidra's own analyze/export
  phase (2026-08-21 probe; the Rust process peaks near ~2.5 GB). Outside the
  existing canonical adapters, do not parse Ghidra/radare2/Rizin disassembly
  text, infer ISA from alignment or inventory name, attribute an address to
  the nearest global, or leak decoder-crate enums outside `decoder.rs`.
- **Phase 3.2 type application.** Default-on in every normal-route `decompose`
  (there is no pass 2 on `--no-symbol-pass`, so this never runs there —
  shapes are still recovered into the sidecar on that route). **Fidelity is
  width-only by design:** we apply `undefined<width>` — asserting only the
  proven byte width, never signedness or a concrete interpretation, since no
  evidence supports one (a wrong sign would mis-render every read of the
  global). Ghidra still coalesces the bytes into one typed slot and the
  decompiler renders each read as a single value; the type name simply stays
  "N bytes, interpretation unknown" — the same "assert only what you proved"
  discipline as the rest of the fail-closed pipeline. **Scope is
  scalar-only by measured evidence:** on the retained cheetah `01_MAIN`
  tree (v2-vintage sidecar — stale-vintage for validation, still valid
  as a distribution sample; the v3 in-memory split there is
  295/766/0), of 274 `inferred` globals, 270 are `scalar_candidate`
  (widths skew to 4-byte: 243, plus 23×1-byte and 4×2-byte), 1 is
  `array_candidate`, and 3 are `unknown` — arrays are statistically
  negligible, so v1 defers the array-application span-overlap machinery
  rather than build it for one record. Measured on the v3 mustang MAIN
  tree, `global_types_apply` applies 94 / skips 42 of 136 candidates —
  v3's extra inferred scalars fed the apply map. After `RunGlobalShapes` writes `decompiled/global_shapes.json` and before pass 2
  dispatches, `decompose::run`'s `DispatchPass2` handler calls
  `derive_global_types_maps(images_dir, ghidra_dir)`: for each image with a
  `global_shapes.json`, `global_types::select_from_shapes_json` selects only
  `status: "inferred"` entries whose `provisional_shape` is
  `scalar_candidate` at width 1/2/4/8 (never `array_candidate`, `unknown`,
  `no_evidence`, or `conflicting`) as `TypeCandidate`s; everything else is
  counted into `Selection::ineligible`. `write_type_map` writes the strict
  `pixel-modem-extractor-global-types-v1` map to
  `ghidra_dir/global_types_maps/<label>.json` (mirroring
  `ghidra_dir/symbol_maps/<label>.json`) and returns `None` for zero
  candidates (no map written, no pass-2 input for that image — not an
  error). `ApplyGlobalTypes.java` preflights the whole map (malformed/
  duplicate-address/wrong-image/bad-width is a map-level `status: "error"`,
  zero mutation), then per candidate creates `undefined<width>` at the
  address, widening **only** already-undefined bytes
  (`ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA`) — never a committed
  data type or an instruction. A span outside program memory or a
  `CodeUnitInsertionException` conflict is skipped and counted
  (`skipped_outside_memory` / `skipped_collision`, both Ghidra-side
  categories that sum into `global_types_apply_skipped`); `candidates =
  applied + skipped_outside_memory + skipped_collision` is enforced with
  `Math.addExact` before the summary emits. `--no-apply-global-types` skips
  `derive_global_types_maps` entirely (pass 2 gets no global-type input for
  any image, so `ApplyGlobalTypes.java` does not run) without disabling
  shape recovery itself — only the `decompiled.c` `undefinedN` application
  is skipped. **Real-Ghidra coverage:** `tests/decompile_golden.rs`'s
  `pass2_applies_global_types_and_skips_span_collision` exercises
  `ApplyGlobalTypes.java` end-to-end against a real Ghidra headless process,
  alongside `pass2_applies_functions_and_strict_globals_in_one_process`'s
  `ApplySymbols`/`ApplyGlobals` coverage. It reuses that same test's crafted
  ARM fixture with two type candidates — the genuine undefined data word at
  `0x20` (applies) and the live `Reset` LDR instruction at `0x0` (span
  collision, skipped) — asserting the parsed summary
  (`global_types_applied: Some(1)`, `global_types_apply_skipped: Some(1)`)
  and that the regenerated `decompiled.c` reads `undefined4` at the applied
  site. `global_types_applied_on_retained_tree` (`tests/decompose_golden.rs`,
  `PME_GOLDEN_DIR`-gated) additionally measures a non-zero applied count and
  the `candidates = applied + skipped` conservation on a real retained MAIN
  tree.
- **Phase 3.2 type-application report surface.** `decompile::ImageResult`
  carries `global_types_applied` / `global_types_apply_skipped` /
  `global_types_apply_error`, parsed from `ApplyGlobalTypes: {json}` exactly
  like `ApplyGlobals.java`'s summary (see **Phase 3.0 failure and reporting
  contract**). `report.json`'s per-image entry carries five renamed/derived
  fields instead: `global_types_applied`, `global_types_skipped`,
  `global_types_error`, `global_types_candidates` (`applied + skipped`, the
  `global_types_maps` entry's `count()`), and `global_types_ineligible`
  (from `derive_global_types_maps`'s `ineligible` map — present whenever
  type-map derivation ran; `None` under `--no-apply-global-types` or
  `--no-symbol-pass`; it has no `decompile::ImageResult` counterpart at all).
  Unlike `globals_applied`, none of the five are copied by
  `ImageReport::from_result` (always `None` there, same as the nine
  `global_shapes_*` fields) — `decompose::global_types_apply_stage` patches
  them onto the already-installed `ImageReport`s directly. This patch **must
  run after** `DispatchPass2`'s final `refresh_decompile_stage_images` call,
  not alongside the `globals_apply_stage` calls next to
  `decompile_pass2_stage`: that refresh rebuilds
  `stages[decompile_pos].images` from `decompile::ImageResult` via
  `ImageReport::from_result`, which unconditionally nulls all five fields,
  so a patch applied earlier is silently discarded. `decompose::run` reads
  `pass1_report` once after that refresh (rather than threading a captured
  image slice through each pass-2 branch) — by that point `pass1_report` is
  already `Some` in exactly the branches that passed `Some(&images)` to
  `globals_apply_stage` (scheduled-zero and successful pass 2) and `None` in
  exactly the branches that passed `None` (a `run_two_pass` error, or no
  pass-1 report at all), so it already carries the right value per branch.
  The aggregate `global_types_apply` stage is skipped for `--no-symbol-pass`,
  `--no-apply-global-types`, or zero derived candidates (`"no recovered
  scalar shapes"`), and otherwise mirrors `globals_apply_stage`'s strict
  per-label conservation check (`applied + skipped` must equal the prepared
  map's `count()`) and first-actionable-error-in-pipeline-order policy.
  **`global_shapes_*` fields carry the same hazard.** On the normal route,
  `RunGlobalShapes` patches `global_shapes_*` onto
  `stages[decompile_pos].images` right after it runs — before either
  `DispatchPass2` rebuild site above (the final `refresh_decompile_stage_images`,
  and the `Err(error)` branch's earlier `install_decompile_stage_image_snapshot`),
  so those patches are exposed to the identical `from_result`-nulls-anything-
  `decompile::ImageResult`-doesn't-carry hazard described above
  (`--no-symbol-pass` is unaffected: nothing refreshes after its own
  `RunGlobalShapes`, which runs last on that route). The binding fix mirrors
  `global_types_apply_stage`'s design: `run_global_shapes_stage_with` retains
  each image's outcome (`decompose::GlobalShapesOutcome`, keyed by label), and
  `reapply_global_shapes_outcomes` re-applies it exactly once, unconditionally,
  at the same point `global_types_apply_stage` runs — after every
  `DispatchPass2` rebuild site, regardless of which branch fired. (Re-reading
  the sidecar from disk instead of retaining in memory was considered and
  rejected: a per-image failure never writes a new `global_shapes.json` — an
  existing sidecar, if any, is left byte-identical per the currentness
  contract above — so a re-read can't recover `global_shapes_error` or
  distinguish "this run failed" from "this file predates any run.")
  Regression-pinned by the plain unit test
  `global_shapes_outcomes_survive_refresh_decompile_stage_images` (no
  `PME_GOLDEN_DIR` needed, so CI catches a re-regression) and by
  `report_json_includes_global_shapes_fields`'s route-aware stage-order
  assertion (keyed on `decompile_pass2`'s stage `reason`, covering both
  routes instead of only `--no-symbol-pass`).
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
- **Shared Thumb capture streaming (Phase 2+).** `thumb_analysis::stream`
  incrementally drains either analyzer into
  `thumb/<addr:08x>.<producer>.stdout`, hashing the exact bytes while enforcing
  `ANALYZER_STDOUT_CAP_BYTES = 4 GiB`. The backend-qualified capture is retained
  after a successful attempt and its relative path, length, and lowercase BLAKE3
  are committed to v3. Failed attempts retain finalized partial captures when possible;
  spawn or capture-finalization failures record `stdout: null`. `--prune` removes the
  retained `thumb/` tree while leaving that v3 identity intact. The cap remains grounded
  in the historical mustang radare2 measurements (~1.82 GiB for the largest region and
  ~3.65 GiB across five captures); do not lower or raise it without re-running the corpus gate.
- **Streaming normalization is backend-aware.** `ValueScanner` consumes each
  capture, pairs inventories and bodies with backend-specific rules, validates
  boundaries, and spills normalized records to producer-qualified `.frags` files
  before atomically assembling strict v3. Rizin additionally streams `axlj` values
  through the selected-xref cap. Producer peak RSS is bounded by one JSON value;
  enrichment, typed source recovery, and symbolication mutations also stream as
  described below.
- **Historical retained-capture replay is a boundary/conservation gate, not a byte
  identity oracle.** The env-gated
  `streaming_replays_retained_production_thumb_captures_with_v3_boundaries` test
  accepts producer-qualified captures and old unqualified radare2 captures from
  the retained pre-v3 tree, then proves that real inventories normalize under the
  current v3 rules with conserving counts. Corrected boundaries and provenance
  intentionally make byte comparison with the old v2 artifact invalid.
- **`--no-thumb-decompile` does not disable the host analyzer.** It selects Ghidra
  `datamark` mode and skips both `body_c` enrichment sweeps; dense-region radare2
  analysis and opt-in failure-only Rizin fallback otherwise follow the same shared
  route and limits.
- **`thumb_enrich` is streaming, atomic, and bounded (memory-envelope Stage
  2).** `decompile::thumb_enrich` collects `decompiled.c` bodies line-by-line
  (~86 MB map on `02_MAIN`) and delegates the artifact rewrite to
  `thumb_analysis::artifact`, which retains one function `Value` at a time.
  Strict v3 metadata, concrete run ownership, and authenticated execution fields
  are validated and preserved. Retained v1/v2 artifacts are read-only replay
  inputs: enrichment rejects them before opening the atomic writer. A semantic
  v3 no-op leaves the original bytes untouched. The production A/B over a 632 MB
  artifact plus 86 MB C file measured 130 seconds and 2.29 GB peak RSS with
  byte-identical output and equal populated counts versus the whole-file oracle.
- **Typed source loading and zero-copy ARM disassembly complete Stages 3 and
  5.** `RecoveredFunctions::load` reads `functions.json` and producer-owned
  Thumb records through typed buffered readers; strict v3 run ownership is
  resolved before records are exposed, with no document-wide `Value` tree.
  The measured in-pipeline load fell to ~0.6 GB from ~20 GB. `FuncRec.disasm`
  is a `Cow` view: `DisasmIndex::slice_cow` borrows ordinary newline-terminated
  ranges and falls back to an owned `slice_for` copy only for CRLF or a missing
  final newline. The standalone symbolication A/B was byte-identical and fell
  from 24 GB to 1.8 GB; a full `decompose` now peaks near ~7.7 GB in Ghidra,
  while the Rust process peaks near ~2.5 GB (mostly real owned Thumb bodies).
- **Finalize rewrites stream and preserve strict v3 (Stage 4).** Symbolication's
  `functions.json` stamps and Thumb `name`/`original_name`/`annotations`/`body_c`
  changes use `stream_rewrite_json_array` and
  `stream_rewrite_thumb_functions`. The latter validates metadata-first v3,
  ordered run ownership and derived counts, rejects producer-field or unknown
  field changes, and writes canonical metadata plus one function at a time.
  Every rewrite is atomic and a no-op is byte-identical. Legacy mutation is
  rejected before writer creation. Differential whole-file oracles remain
  test-only; the production-scale enrich replay is
  `streaming_enrich_ab_matches_oracle_on_production_inputs`.
- **Golden/production `body_c` embeds TWO enrich generations.** A completed
  tree's `thumb_functions.json` carries pass-1 residue (addresses whose
  bodies left the final `decompiled.c` when pass 2 overwrote it) plus the
  post-pass-2 bodies — so no single-sweep enrich over any reconstructible
  input can byte-match a completed tree's file. Verification of enrich
  changes is therefore the in-test oracle A/B on real inputs
  (`streaming_enrich_ab_matches_oracle_on_production_inputs`), not a golden
  byte-compare. Anyone re-baselining goldens or writing enrich tests must
  know this, or they will chase a phantom mismatch.
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
  - **A `HeadlessScript` abort does not imply a nonzero Ghidra exit.** It stops
    follow-on analysis/scripts, which is why scatter preflight failures use it,
    but `analyzeHeadless` can still exit 0. Current-run provenance therefore
    cannot rely on process status or a surviving old inventory. Before every
    generated, direct (including datamark fallback), or pass-2 invocation, remove
    all three owned exports — `functions.json`, `disasm.lst`, and `decompiled.c`
    — plus the sibling `export/<label>.complete` marker; opaque skips invalidate too,
    and any invalidation failure prevents launch. Unsuccessful, aborted, missing-marker,
    and invalid-output attempts scrub every removable owned path before marshalling.
    `ExportDecomp.java` checks each `PrintWriter` after its write/flush/close path while all three
    outputs remain sibling staging files. It repeats exception and PAL postflight, closes retained
    inputs, atomically moves the three destinations, then atomically renames a sibling temp marker
    into place. A pre-move validation or close failure removes only staging and leaves prior
    destinations untouched; a later partial move or marker failure remains non-current for host
    cleanup. Direct and generated validation require the exact marker bytes,
    including its one trailing newline. Keep the marker outside `export/<label>/` so
    ownership-aware refresh still consumes exactly the three exports, and marshal only
    exports explicitly marked current by the producing report.
  - **Gson IS bundled** with Ghidra (`Ghidra/Framework/Generic/lib/gson-*.jar`)
    and on the headless script classpath — use it for JSON in scripts.
  - **Ghidra mirrors renames onto thunks, recursively, but only auto-named
    ones.** Renaming a function re-points every thunk that forwards to it
    (chains included — `getFunctionThunkAddresses(true)`) to the new primary,
    while leaving each thunk's own symbol source untouched. A thunk carrying
    a *custom* primary (e.g. an applied `pal_TaskEntry_*` label) is NOT
    mirrored. The pass-2 map encodes this as explicit `mirror` decisions
    (`thunk_of` is exported per function record; the builder chain-walks
    renamed targets), and `ApplySymbols` postflight accepts exactly the two
    deterministic outcomes — the mirrored final primary or the untouched
    original — with the source pinned to the thunk's own. Pass-2 renames are
    ordered non-thunk-first so an authorized independent thunk rename
    deterministically overrides the mirror. Verified empirically with a
    minimal headless probe; do not "fix" the either/or acceptance without
    re-probing the exact mirroring rule.
  - **Wall-clock budgets are env-overridable.** `PME_PAL_ENTRY_BUDGET_MS`,
    `PME_PAL_PHASE_BUDGET_MS`, `PME_EXPORT_VALIDATION_BUDGET_MS`,
    `PME_TAME_PHASE_BUDGET_MS`, `PME_THUMB_CREATE_ENTRY_BUDGET_MS`,
    `PME_THUMB_CREATE_PHASE_BUDGET_MS` (positive whole ms; malformed values fail the
    script loudly). Defaults stay source-pinned by contract tests. The real
    Mustang MAIN exceeds the stock defaults legitimately (one PAL entry
    disassembly >30 s at `432e1838`; export verification >15 min), so
    acceptance-scale runs set these — budgets gate wall-clock only and change
    no output bytes. `ExportDecomp` lazily derives one parented timeout monitor
    from the remaining export budget and reuses it for every monitor-aware
    validation, projection/hash, and decompilation operation. One shared monitor
    is load-bearing: Ghidra 12's completed `TimeoutTaskMonitor`s retain their
    scheduled timer, while cancelling one also cancels its parent. The exporter
    checks each long operation on return and gates every temporary-to-terminal
    move, including the v4 completion marker. Deadline expiry can therefore
    leave no current marker without accumulating one pending timer per function.
  - **Pass-2 manifest arguments must sit inside the Ghidra kit root.**
    `readPal` authenticates the task manifest, the complete scatter artifact
    (load map plus every referenced payload), and the raw image
    (`<ghidra>/images/<label>`) by canonical containment. The single
    `TerminalPass2Snapshot` stages those bytes once from explicit terminal outcomes and owns every
    Java terminal argument; there is no independent PAL or exception loader. Map-only restaging is
    invalid because both readers open file-backed `blocks/*.bin` entries relative to the map.
  - **`-process` mode, not `-import`, for pass 2.** Applicable post-script
    vectors all follow `<projectDir> <projectName> -process <label> -noanalysis
    -scriptPath …`. A function map appends `ApplyThumbNames.java` first and
    then `ApplySymbols.java`; global and global-types maps independently append
    `ApplyGlobals.java` and `ApplyGlobalTypes.java`. Every scheduled vector
    ends with `ExportDecomp.java`, so the all-map order is exactly
    `ApplyThumbNames.java -> ApplySymbols.java -> ApplyGlobals.java ->
    ApplyGlobalTypes.java -> ExportDecomp.java`. All-three example:

        -postScript ApplyThumbNames.java <kit-root> <label> <image-blake3> <exception-identity> <exception-manifest> <scatter-map> <functions-json> <functions-blake3> <function-map> <map-blake3> -postScript ApplySymbols.java <function-map> -postScript ApplyGlobals.java <global-map> -postScript ApplyGlobalTypes.java <global-types-map> -postScript ExportDecomp.java <out>

    At least one of the three typed maps must be `Some` or
    `headless_process_args` returns `Ok(None)` (nothing scheduled for that
    image — see `prepare_pass2_inputs`, which only creates a `Pass2Input`
    entry for a label present in at least one of `function_maps` /
    `global_maps` / `global_types_maps`).

    `-noanalysis` is mandatory — re-running auto-analysis would (a) undo
    `ApplySymbols` renames that aren't `USER_DEFINED`, and (b) re-trigger the
    Thumb overlap-repair spin that `TameAnalysis` exists to prevent. Pass 2
    operates on the existing program — no re-import, no CRC re-check.
  - **`DecompInterface.setOptions(...)` *replaces* the program's "Decompiler"
    property sheet** rather than merging. Any call clobbers user/environment
    defaults; this is why `ExportDecomp.java` doesn't call it.
- **Pass-2 fail-closed surface.** `decompile::ImageResult` carries
  `pass2_applied: Option<usize>` (count of names `ApplySymbols.java` reported
  applying — parsed from its summary line on stdout), the typed conserving
  `pass2_thumb_names` result plus its prepared creation plan, and `pass2_error:
  Option<String>` (set for late typed-map validation, analyzeHeadless spawn or
  non-zero process failure, or the caller's owned-export refresh failure;
  process failures include a ~2 KB tail of stderr). A pass-2 failure does **not**
  mark the pass-1 image `failed` in `report.json` — pass 1 already produced a
  valid `decompiled.c`. `run_two_pass` returns an explicit outcome for every
  scheduled label, including labels absent from the pass-1 report. The caller
  combines process outcomes with exact-export refresh outcomes into the
  separate `decompile_pass2` stage; a committed refresh updates the current
  inventory counters from its validated terminal summary, while the pass-1
  `decompile` stage stays intact.

## How we work here

- **Design before code.** Non-trivial work gets a written design spec and an
  implementation plan before implementation begins. Keep process artifacts
  outside the repository; durable outcomes land in this file, the README, and
  code comments. Read this AGENTS.md and the
  README before starting non-trivial work — they capture why approaches were
  chosen or rejected, which the code alone can't tell you.
- **Test first**, keep changes small and reviewable.
- **Verify before claiming done.** Run fmt + clippy + test, and for a behavior change
  exercise the actual affected command — don't infer success from tests alone.
- **Keep docs in sync:** a change to a command or convention updates `README.md`
  (user-facing) and/or this file (contributor-facing) in the same change.
- **Docs are the durable memory.** Here that means the facts this codebase makes you learn
  the hard way: a newly-pinned magic number or struct offset (→ README **Formats**, or a
  comment in the parser module), non-obvious Ghidra / `analyzeHeadless` or host Thumb-analyzer
  behavior and its failure modes (→ this file, or README **External code analysis**), and why a
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
