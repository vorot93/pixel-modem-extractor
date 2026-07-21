# Phase 1 — Readable decompiled code (close the symbol loop, tune decompiler, inline evidence)

Status: approved 2026-07-21
Scope: Phase 1 of a multi-phase effort to maximize the readability of the decompiled
modem output. Phases 2 (Thumb decompilation coverage) and 3 (types & globals recovery)
are summarized at the end for context but are out of scope here.

## Context

`pixel-modem-extractor` already produces a decompiled C listing per modem image
(`decompiled.c`), a function inventory (`functions.json`), a disassembly listing
(`disasm.lst`), and — for the dense Thumb-2 regions that Ghidra cannot converge on —
a radare2-derived `thumb_functions.json` containing assembly bodies. The standalone
`symbolicate` subcommand and the matching `decompose` stage recover function names and
inline log/assert/file annotations from the pw_tokenizer DB, `__func__` strings, and
the source-tree attribution, then rewrite those artifacts **in place** as a text
substitution.

The pipeline order is the root constraint on readability today:

```
extract → decompile → source_tree → recover_source → decoders → symbolicate → prune
```

Symbols flow the wrong way: Ghidra produces `decompiled.c` first and symbolicate
renames functions inside that text afterward. Ghidra never sees the recovered names
or the inline evidence, so it cannot use them during analysis or decompilation. As a
consequence:

- The decompiled C is born with `FUN_…` / `thumb_…` placeholders.
- Inline evidence (token format strings, `__FILE__` paths, attributed strings) lives
  only in `symbols.json` — it never appears next to the relevant call/load sites.
- Any future decompilation pass (Phase 2 — Thumb) inherits none of this work.

Phase 1 closes that loop.

## Goals

In scope for Phase 1:

1. **Apply recovered symbols during a second Ghidra pass**, so the C is produced with
   real names already in place (not text-substituted afterward).
2. **Tune Ghidra's decompiler options** for readability where it does not cost
   fidelity — keep casts, keep parameter names; do **not** enable options that can
   silently drop firmware code paths (see Fidelity posture).
3. **Surface inline evidence as plate comments** above functions in `decompiled.c`
   (token format strings, `__FILE__` paths, attributed strings) — via Ghidra's
   built-in plate-comment emission, not a separate annotation pipeline.

## Fidelity posture

**When readability and fidelity conflict, fidelity wins.** Phase 1 must not lose or
distort information from the decompiler output. Specifically:

- **No lossy decompiler options.** `EliminateUnreachable` and `Simplify` can both
  drop real firmware code (jump tables, computed branches, tail-call dispatch,
  signal-style handlers — all common in baseband code). They stay off. Only
  fidelity-positive or display-only knobs are touched (see `ExportDecomp.java`).
- **No relaxation of symbolication criteria.** `Tier::Recovered`'s strict
  single-identifier-plus-`__FILE__` rule and `Tier::Provisional`'s `guess_…`
  marker convention are preserved as-is. Phase 1 only changes *where* the names
  are applied (Ghidra vs. text-substitution), not *which* names are considered
  safe.
- **Plate comments are additive.** Inline evidence reaches `decompiled.c` only as
  comments above functions; nothing is removed or rewritten in the decompiler's
  own output to make room for it.
- **Provenance is preserved.** `original_name` is kept alongside `name` in every
  artifact (see the Provenance invariant below) so any rename is reversible and
  auditable.

## Non-goals (deferred)

- **Thumb decompilation to C.** The ~141k Thumb-2 functions in `02_MAIN` continue to
  have assembly bodies in Phase 1. The symbol-map schema is forward-compatible so a
  Phase-2 Thumb decompiler can consume the same evidence; Phase 1's ApplySymbols
  leaves Thumb entries inert.
- **Types and globals recovery.** `*(int*)(0x40e1c000) = …` continues to appear as raw
  addresses. Struct layout / MMIO labeling / global naming is Phase 3.
- **Replacing the text-substitution `symbolicate` path.** The standalone
  `symbolicate` subcommand keeps today's behavior (rewrite in place, no Ghidra
  required) for users who cannot or will not re-run Ghidra.

## Architecture

### Two-pass decompile on `decompose`; one-pass unchanged on `decompile --run`

`decompile --run` (the standalone subcommand) keeps today's single-pass behavior.
Its contract is "drive Ghidra once and produce C," not "produce maximally-readable C."
The Phase-1 work plugs into `decompose` only, where the evidence is available.

The Phase-1 `decompose` pipeline becomes:

```
extract
  → decompile pass 1 (analyze + inventory + disasm + initial decompiled.c)
  → source_tree (02_MAIN)
  → recover_source (02_MAIN)
  → decode_tokens                  [moved earlier so the DB is available to the map]
  → symbolicate::build_map per image; write symbol_map.json per image
  → decompile pass 2 (per image, only where the map is non-empty)
  → symbolicate::finalize per image (rewrites thumb_functions.json + symbols.json;
      leaves decompiled.c alone on this path — pass 2 regenerated it)
  → decode_rf, hardware_config
  → prune (if --prune)
```

Pass 2 runs `analyzeHeadless` in `-process` mode on the **same project** (no
re-import, no CRC re-check), with `-postScript ApplySymbols.java <map>` followed by
`-postScript ExportDecomp.java <out>`. Pass 1's `decompiled.c` is overwritten in
place by pass 2.

A new `decompose` flag `--no-symbol-pass` skips pass 2 entirely (escape hatch for
misbehavior or for users who want today's behavior). Default is on.

### Approaches considered

- **Approach 1 (chosen): two `analyzeHeadless` passes; new `ApplySymbols.java`;
  `ExportDecomp.java` unchanged (tuning investigation concluded no fiducial-safe
  default change exists).** Clean separation; `decompile --run` unaffected; the
  heavy lifting stays in Rust (testable). Cost: roughly doubles Ghidra time on
  `decompose` for images with non-empty maps.
- **Approach 2: two passes but pass 2 is a fresh `-import`.** Doubles analysis
  time as well as decompile time. Strictly worse.
- **Approach 3: do everything in one pass in Java.** Port token parsing,
  source-tree reconstruction, and attribution to Ghidra scripts. High
  implementation risk; loses the tested Rust core.

## Artifacts and contracts

### New: `<out>/ghidra/symbol_maps/<label>.json`

One per image. Written by `symbolicate::write_symbol_map` between the two passes,
consumed by `ApplySymbols.java` during pass 2.

```json
{
  "tool_version": "1.0.0",
  "image": "02_MAIN",
  "source_sha256": "<sha256 of the image bytes>",
  "functions_sha256": "<sha256 of pass-1 functions.json>",
  "symbols": [
    {
      "entry": "0x40e1bff4",
      "arch": "arm",
      "original_name": "FUN_40e1bff4",
      "name": "LteRrc_Reestab",
      "tier": "recovered",
      "annotations": [
        "logs: \"RRC Reestab (%d)\" [LTE_RRC_METRICS]",
        "file: HEDGE/LteRrc.c"
      ]
    }
  ]
}
```

- `name` omitted or null means "no rename" (today's `Tier::None`). ApplySymbols
  leaves that function's name alone.
- `arch` is informational in Phase 1 (the program is ARM-only). The field stays in
  the schema so Phase 2's Thumb decompiler can consume the same map.
- `tier` is one of `recovered | provisional | none`, matching today's `Tier` enum.
- `tool_version` lets ApplySymbols fail-closed on a future schema incompatibility.

### New: `src/ghidra/ApplySymbols.java`

Pre-post-script in pass 2 (runs before `ExportDecomp.java`). Contract:

- **Arg[0]** = absolute path to `symbol_map.json`.
- Loads via Ghidra's bundled Gson.
- For each symbol: resolve the function by entry address. If `name` is non-empty,
  call `fn.setName(name, sourceType)` where `sourceType = USER` for `recovered`,
  `ANALYSIS` for `provisional` (so Ghidra's own re-analysis cannot override a
  recovered name later).
- Sets a **plate comment** at the entry address from `annotations` joined by
  `\n// `. Ghidra's decompiler emits plate comments above the function in
  `decompiled.c` — this is how inline evidence reaches the C output with no extra
  plumbing.
- Fail-closed **per symbol, not per script**: a missing function, an invalid name,
  or a name collision is logged via `println` and skipped. The script always
  returns normally so `ExportDecomp` still runs and `decompiled.c` is complete.
- Prints a one-line summary at the end: `ApplySymbols: applied N names, M plate
  comments, skipped K (reasons …)`. The Rust host parses this for
  `pass2_applied`.

### Modified: `src/ghidra/ExportDecomp.java`

**No `DecompInterface.setOptions(...)` call is added in Phase 1.** Ghidra's
decompiler defaults are already a fiducial baseline. Investigation of the
candidate readability knobs came out fidelity-first:

- `EliminateUnreachable` — **off (default).** Enabling it can drop real firmware
  code reached via jump tables, computed branches, or tail-call dispatch.
- `Simplify` — **off (default).** Extended simplification can elide semantically
  relevant intermediate state.
- `NoCasts` — **off (default).** The alternative would hide real type
  conversions; today's default preserves them.
- `DisableDecompilerParameterNames` — **off (default).** The alternative would
  strip parameter names; today's default preserves them.
- `UseHexadecimal` — **true (default).** Display-only; matches the existing
  `disasm.lst` convention. No pin needed — it's already Ghidra's default.

Beyond the no-op tuning outcome, `setOptions` is intentionally avoided because it
*replaces* the program's "Decompiler" property sheet rather than merging with it,
which would clobber any user/environment default for zero fiducial benefit.

**No functional change to `ExportDecomp.java` in Phase 1.** Pass 2 simply re-runs
the script unchanged after `ApplySymbols.java` has renamed functions in the
program — `DecompiledFunction.getC()` then emits the regenerated C with the new
names + plate comments baked in. A documentation comment at the top of the script
records the fidelity-first analysis above so future tuning starts from the right
baseline. No change to `writeFunctionsJson`, `writeDisassembly`, or
`writeDecompiledC`'s emission logic.

### Refactor: `src/symbolicate.rs`

Extract today's `symbolicate_image` body into a pure builder and split the file
rewrite into a separate step:

- `build_map(image_dir, image_label, tokens, manifest) -> Result<Vec<Symbol>>` —
  pure, no file writes. Uses today's recovery logic unchanged.
- `write_symbol_map(out_path, image_label, symbols, image_sha, funcs_sha)
  -> Result<PathBuf>` — serializes the schema above.
- `finalize_image(image_dir, image_label, symbols, opts) -> Result<PathBuf>` —
  does today's `rewrite_functions_json` + `rewrite_text_files` (the latter
  controlled by `Opts { rewrite_decompiled_c: bool }`) + `write_symbols_json`.
- `run(root, opts)` — unchanged behavior for the standalone subcommand: build_map
  per image → write_symbols_json + full rewrite (including `decompiled.c`).

### New: `decompile::run_two_pass(modem_bin, opts, out, symbol_maps) -> Result<DecompileReport>`

Phase-1 entry point. Same per-image loop as `run_report`, but after pass 1 for each
image it:

1. Looks up `symbol_maps.get(&label)`. If absent or empty of non-null names, skip
   pass 2 for this image.
2. Otherwise runs a second `analyzeHeadless` invocation in `-process` mode on the
   same project, with `-postScript ApplySymbols.java <map>` followed by
   `-postScript ExportDecomp.java <out>`.
3. Parses ApplySymbols.java's one-line summary for `pass2_applied`; captures any
   execution failure as `pass2_error`.

`decompile::run_report` (used by `decompile --run`) is untouched.

### `decompose.rs` reordering and stage reporting

The `symbolicate` stage in today's `decompose.rs` splits into two:

- A `symbol_map` stage between source-tree/recover-source and pass 2 (calls
  `symbolicate::build_map` per image, writes the maps, records per-image counts in
  `StageReport`).
- A `symbolicate` stage after pass 2 (calls `symbolicate::finalize` per image with
  `rewrite_decompiled_c = false`).

`decompile::ImageResult` and `decompose::ImageReport` gain two fields:
`pass2_applied: Option<usize>` and `pass2_error: Option<String>`. A pass-2 failure
does **not** mark the image `failed` in the report — pass 1 already produced a
valid `decompiled.c`.

**Provenance invariant for `functions.json` after pass 2.** Pass 2's
`ExportDecomp.java` regenerates `functions.json` with the *recovered* names
already in the `name` field (because `ApplySymbols.java` renamed them in the
Ghidra program first). The existing `rewrite_functions_json` logic sources
`original_name` from the current `name` field — that would record the recovered
name as `original_name` and corrupt provenance on the decompose path. The Phase-1
refactor must therefore source `original_name` from the `Symbol` record (which
preserves it) rather than from `functions.json`. This keeps the field stable
across (a) re-running decompose, and (b) running the standalone `symbolicate`
subcommand against a Phase-1 decompose tree.

## Error handling and edge cases

- **Per-image fail-closed policy on pass 2.** Every image's pass 2 is attempted; a
  failure is recorded as `pass2_error`, not propagated. `decompiled.c` is always
  valid (whether pass-1 or pass-2 output).
- **Empty map → pass 2 skipped.** `00_BOOT`, `04_VSS`, etc. typically produce no
  names — no second pass. Saves the cost.
- **`01_PSP` (encrypted) → 0 functions in pass 1 → empty map → no pass 2.**
  Unchanged from today.
- **Function entry moved between pass 1 and pass 2** — cannot happen, pass 2 does
  not re-run analysis. ApplySymbols.java resolves by entry address and tolerates a
  missing function (log + continue) defensively.
- **Name collision in ApplySymbols.java** — `symbolicate::finalize_names` already
  disambiguates `Recovered` collisions with `_<addr>` before the map is written.
  If Ghidra still rejects a name (e.g., a reserved identifier), the script logs
  and skips; the function keeps its `FUN_…` name; `decompiled.c` still emits.
- **Thumb symbols in the map** — Phase 1's map contains them (schema is
  forward-compatible), but ApplySymbols.java will not find them in the program
  because `TameAnalysis` marked those regions as data. Documented behavior: "Thumb
  entries in the map are inert in Phase 1; Phase 2 will consume them when it
  decompiles Thumb."
- **Idempotency.** Pass 2 regenerates `decompiled.c` from scratch each run, so the
  sentinel-based idempotency that protects a hand-edited file is not needed on
  this path. The standalone `symbolicate` subcommand still uses the sentinel.

## Testing

- **Rust unit tests (inline in `symbolicate.rs`):**
  - `build_map` produces the same `Symbol` set as today's `symbolicate_image` did
    (port the existing `symbolicate_image_end_to_end` test onto `build_map`).
  - `write_symbol_map` round-trip: serialize → parse with `serde_json` → matches
    input.
  - `finalize_image` with `rewrite_decompiled_c=false` rewrites
    `thumb_functions.json` and emits `symbols.json` but leaves `decompiled.c`
    untouched.
  - `finalize_image` with `rewrite_decompiled_c=true` matches today's behavior
    (the existing `rewrite_text_*` tests cover the mechanism).
- **`tests/decompile_golden.rs`** (self-contained TOC fixture; real Ghidra;
  skips when absent): add a test that runs pass 1, writes a one-symbol map (one
  rename + one annotation), runs pass 2, and asserts (a) the renamed function
  appears in `decompiled.c`, (b) the annotation appears as a comment line, (c)
  `pass2_applied == 1`.
- **`tests/symbolicate_golden.rs`** (standalone rewrite): unchanged — proves the
  text-substitution path still works for users who do not re-run Ghidra.
- **`tests/decompose_golden.rs`** (real radio image, env-gated): assert
  `report.json` includes the new `pass2_applied` / `pass2_error` fields, and
  (manual spot-check) that `images/02_MAIN/decompiled/decompiled.c` contains
  recovered names and `// logs:` / `// file:` plate comments.

## Verification

Before claiming Phase 1 done (mirrors `CONTRIBUTING.md`):

```
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Plus, on a real radio image (user-supplied, lawfully obtained):

- `pixel-modem-extractor decompose radio.img` on a disposable copy.
- Confirm (a) pass 2 ran on `02_MAIN` (per `report.json`), (b) `decompiled.c`
  contains real function names where the map had them, (c) `// logs:` / `// file:`
  plate comments appear above functions, (d) `decompose --no-symbol-pass
  radio.img` reproduces today's `decompiled.c` byte-for-byte on the same image.

Docs to keep in sync in the same change (per `CONTRIBUTING.md`):

- `README.md` — note the two-pass behavior in the `decompose` description and the
  new `--no-symbol-pass` flag in the Commands table.
- `CONTRIBUTING.md` — note the pipeline reordering and the
  `--no-symbol-pass` flag in the Domain map section; note the new
  `symbol_map.json` artifact.

## Future phases (context only)

- **Phase 2: Thumb decompilation coverage.** Get the ~141k Thumb-2 protocol-stack
  functions into C form (likely via r2ghidra `pdg`, or by carving the dense
  regions into a standalone Ghidra program that converges without `TameAnalysis`'s
  data-marks). Consumes the same `symbol_map.json` produced here.
- **Phase 3: types and globals recovery.** Struct layout inference, MMIO region
  labeling, global variable naming. Independent track that compounds with Phases
  1–2. Carries the highest fidelity risk (speculative type assignment can corrupt
  decompiler output) and will need its own per-annotation provenance and an
  opt-in/opt-out surface — same posture as Phase 1, applied more strictly.
