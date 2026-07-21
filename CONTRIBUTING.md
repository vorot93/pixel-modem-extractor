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
  much of the recent history is hardening exactly this behavior.

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
  `ghidra-e2e` workflow.
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
| `decompose.rs` | One-shot pipeline over all decoders |
| `manifest.rs` | `manifest.json` writing + `sha256` helpers |
| `error.rs` | Error types |
| `cli.rs` | `clap` subcommands + dispatch |
| `bin/main.rs` | Binary entry point |
| `ghidra/*.java` | Ghidra headless scripts (`ExportDecomp`, `TameAnalysis`) |

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
  Scale note: `02_MAIN`'s `thumb_functions.json` is large (~600 MB, ~141k Thumb functions)
  and is loaded/rewritten whole (~4 s, ~3 GB peak); pw_tokenizer strings are structured
  `■format♦…■domain♦…`, and tokens appear as `movw`/`movt` immediates (not raw literals, so
  a byte search won't find them).

## How we work here

- **Design before code.** Non-trivial work gets a written design spec and an
  implementation plan before implementation begins.
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

## Recipe: adding a subcommand or decoder

1. Add a focused module under `src/` and expose it in `src/lib.rs`.
2. Add a `Commands::` variant and match arm in `src/cli.rs`, with a sensible `--out`
   default.
3. Add a parse/`--help` test — the existing tests in `src/cli.rs` are the pattern.
4. If it emits artifacts, add env-gated golden coverage like the other `*_golden.rs`.
5. Update the `## Commands` table in `README.md`, and keep the decoder fail-closed
   (return an error on malformed input rather than emitting garbage — see the error
   convention above).
