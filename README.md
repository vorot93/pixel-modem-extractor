# pixel-modem-extractor

Pure-Rust CLI that extracts and analyzes **Pixel modem** firmware — the Samsung Exynos Modem 5400
("Shannon" S5400) baseband — from a radio **FBPK** `.img`. One command unpacks the image down to the
raw modem code and configuration; further subcommands decode the RF calibration databases and the
Pigweed token database, reconstruct the firmware's source-tree layout, and generate decompile kits
without external runtime dependencies. `--run`/`decompose` can also drive local Ghidra plus radare2
for code-image analysis.

## Install

Requires the latest stable Rust (2024 edition).

    cargo install pixel-modem-extractor      # from crates.io
    cargo install --path .                   # from a local checkout
    cargo build --release                    # binary at target/release/pixel-modem-extractor

## Ghidra + radare2 (for `--run` and `decompose`)

Extraction and the decoders are pure-Rust and need nothing external. The optional
code-analysis paths — `decompile --run` and `decompose` — additionally require a local
**Ghidra** and **radare2** (`r2` on `PATH`); on macOS, `brew install ghidra radare2`.

Ghidra is located, in order, from `--ghidra-home`, `$GHIDRA_INSTALL_DIR`, or `PATH` (its
`ghidraRun` launcher), and **both the upstream release-tarball and Homebrew layouts are
supported** — a `brew install ghidra` is discovered automatically. Its bundled JDK is used
to launch the headless analyzer unless you set your own `JAVA_HOME`.

**Memory:** a full dense-Thumb `decompose` can peak around 56 GiB RSS. Raw
per-region radare2 JSON captures remain on disk; normalized function values
from completed regions accumulate in memory while the current capture is read
and parsed. Plan for at least 64 GiB RAM plus swap or other headroom. The 4 GiB
radare2 stdout cap applies per capture and does not cap aggregate process
memory. Smaller images without dense Thumb regions (`00_BOOT`, `01_PSP`, etc.)
stay under 1 GiB. `--no-thumb-decompile` switches Ghidra to `datamark` mode and
skips `body_c` enrichment, but it still runs the dense-region radare2
capture/read/parse path and therefore does not avoid the full dense-Thumb
memory envelope.

**Project path:** `pixel-modem-extractor` canonicalizes its output root before
constructing the Ghidra headless project path. Ghidra 12 rejects any
dot-prefixed component in that resulting path, so a symlink cannot hide a
dot-prefixed canonical ancestor from this pipeline. Choose an output root whose
canonical path contains no dot-prefixed components.

## Quickstart

    # 1. Extract everything from a radio image (default out: ./radio.extracted/)
    pixel-modem-extractor extract radio.img

    # 2. Analyze the extracted artifacts, e.g.:
    cd radio.extracted
    pixel-modem-extractor decode-tokens rootfs/images/g5400i-*/pw_token_db
    pixel-modem-extractor source-tree   modem.bin.split/02_MAIN
    pixel-modem-extractor decompile     rootfs/images/g5400i-*/modem.bin   # add --run for Ghidra + radare2 Thumb analysis

    # Or do all of the above in one shot (needs local Ghidra + radare2):
    pixel-modem-extractor decompose radio.img          # add --prune for leaves only

Every subcommand accepts `--out DIR` (a sensible default is used otherwise); run any with `--help` for
its full set of flags.

## Commands

| Command | What it does |
|---|---|
| `extract <radio.img>` | **Main entry.** Full pipeline: FBPK → ext4 → rootfs → gunzip `RF_CFG_*` → split TOC. Default out `./<img>.extracted/`. `--no-verify` skips CRC/size checks. |
| `decompose <radio.img>` | **Everything, one shot.** Runs `extract`, decompiles all six images (Ghidra), enriches `02_MAIN/source_tree` with recovered-code evidence when attribution is possible, and runs every decoder into one per-image tree (`images/NN_NAME/{decompiled,…}`, `rf/`, `tokens/`) with a `report.json`. **Requires a local Ghidra and radare2** (`r2`), probed up front. `--prune` keeps only the terminal artifacts; `--out`, `--ghidra-home`, `--processor`, `--no-verify` as elsewhere. Default out `./<img>.decomposed/`. **Phase 1:** decompile runs **twice** per eligible image — pass 1 analyzes and exports an initial inventory; pass 2 runs the applicable `ApplySymbols.java` and/or `ApplyGlobals.java` scripts, then `ExportDecomp.java`, in one saved-project process. Recovered function and strict Recovered global names are therefore baked into regenerated `decompiled.c` and disassembly instead of text-substituted afterward. Global application renames only exact Ghidra-default `DAT_<addr>` labels at the matching address; missing, non-default, rejected-name, and outside-memory candidates are preserved and reported as skips. Pass 2's ownership-aware refresh replaces only `decompiled.c` / `disasm.lst` / `functions.json` and leaves `globals.json`, `global_shapes.json`, `thumb_functions.json`, `thumb/`, and other sidecars byte-for-byte unchanged. `--no-symbol-pass` skips pass 2 entirely: it still writes `globals.json`, but globals remain record-only and `DAT_<addr>` placeholders are not changed in Ghidra. **Phase 2:** Dense Thumb regions in `02_MAIN` are decompiled by Ghidra (tightened `TameAnalysis`). A runtime Surface B watch kills Ghidra on overlap-repair spin and falls back to Phase-1 datamark per image (`thumb_tighten_error`, image not failed). Phase 2.1 closed both dormancy causes: `thumb_enrich` matches by entry address, and `TameAnalysis mode=tighten` carries the winning `TIGHTEN_EXTRA` (`"Non-Returning Functions - Discovered.Repair Flow Damage"`) so Ghidra converges on full `02_MAIN` in ~23 min without Surface B firing. **Production (verified full `decompose`, ~1 h 37 m wall, exit 0):** `functions` = 107,955; `thumb_functions` = 117,444; `thumb_decompiled` = 77,456; five `thumb/*.stdout` preserved across pass 2; radare2 4 GiB streaming path did not hit the cap. `thumb_functions.json` is v2 (optional per-function `body_c`). `--no-thumb-decompile` skips Phase 2 (Phase-1 datamark behavior end-to-end). **Phase 3.0:** Global names are recovered from direct string evidence when a function has exactly one non-string `data_ref` and exactly one unique underscored identifier across its referenced strings. The per-image `decompiled/globals.json` is Recovered-only by default and remains the strict evidence source of truth; conflicting names for one address are dropped. In normal `decompose`, eligible Recovered records feed the existing pass 2. **Phase 3.0.1:** Disasm-anchored Recovered globals — a `movw`+`movt` load pair within K=4 load-events of a string load pins that string's identifier as the global's name, regardless of `data_ref` cardinality. On production `02_MAIN` (Thumb through pass 2) `globals_recovered` = **915** (arch: arm 367 / thumb 545 / mixed 3); stage total recovered 921 with 194 conflicts dropped. `--globals-provisional` opts in to additionally emitting name-prior-derived `tier: "provisional"` entries (default off; bare `globals.json` is byte-equivalent to Phase 3.0's for the Recovered set). Provisional records are always record-only and never application candidates. **Phase 3.2:** After the complete symbol route (normal pass 2, `--no-symbol-pass`, or a valid pass-2 fallback inventory), `decompose` always runs a record-only `global_shapes` stage against the terminal per-image files. It decodes accepted A32/T32 function bytes with the pure-Rust `scaleservers-arm32-assembly` 1.0.0 adapter and writes `decompiled/global_shapes.json` v2 — one record per Recovered global. `globals.json` is not rewritten. `--prune` retains the sidecar. Each record is `inferred`, `no_evidence`, or `conflicting`; summaries carry only `minimum_size` and a provisional `scalar_candidate` / `array_candidate` / `unknown` label. No exact allocation size or authoritative type is inferred. Quarantined producer records never reach the decoder and are counted separately from accepted-range `decode_failures`. Distinct ARM and Thumb identities may cover the same bytes and remain independent interpretations. **Production (same verified run):** Recovered shapes 915 MAIN / 921 total; MAIN observations 32 ARM + 907 Thumb; 125 inferred / 787 `no_evidence` / 3 conflicting; `decode_failures` = 37,629 (recoverable; the image still succeeds); `globals.json` unchanged. `decompose` now also runs a **default-on depth-1 interprocedural pass** (direct `bl` only, AAPCS r0–r3, callee entry-block seed) that re-runs the shape tracker inside directly-called functions with the argument register seeded; it is **record-only and additive-only** (it never demotes an `inferred` global and never produces `conflicting`). On the reference Shannon image its net yield was **0 new shapes** — the pass-by-reference callees store, not dereference, the pointer; see CONTRIBUTING for the mechanism and limitations. |
| `source-tree <02_MAIN>` | Reconstruct the firmware source-tree layout from embedded `__FILE__` strings — **names and structure only, not original source**. `--no-attribution`, `--gap`, `--shared-pct`, `--min-run` tune the heuristics. |
| `decode-rf <RF_CFG_dir> --hwcfg <hardware_config.json>` | Semantic decode of the RF_CFG calibration databases (heuristic calibration-vector extraction + per-variant mapping). Default out `./decoded_rf/`. |
| `decode-tokens <pw_token_db>` | Decode the Pigweed `pw_tokenizer` token database to canonical CSV + `summary.json`. Default out `./decoded_tokens/`. |
| `hardware-config <hardware_config.json>` | Structural stats + RF_CFG-coverage summary. `--rf-dir` cross-checks which calibration blobs are actually present. Default out `./hwcfg_summary/`. |
| `decompile <modem.bin>` | Write a Ghidra import kit for all six code images at their load addresses. `--run` drives `analyzeHeadless` (needs a local Ghidra) to export decompiled C, a disassembly listing, and a function inventory; selected images with dense Thumb regions also use radare2 (`r2`) and fail if those regions cannot be analyzed. `--image`, `--ghidra-home`, `--processor` (default `ARM:LE:32:v7`). `--no-thumb-decompile` reverts Phase-2 Thumb decompilation to Phase-1 datamark behavior. |
| `symbolicate <decomposed_dir>` | Recover function names + inline log/assert/file annotations from evidence already produced (pw_tokenizer DB, `__func__`, attributed strings), rewriting `decompiled.c`/`disasm.lst`/`functions.json`/`thumb_functions.json` **in place** and emitting `symbols.json`. Tiered + fail-closed: only `__func__` renames; token matches become marked `guess_…` names; strings/files are comments. `--token-db` gives the raw `pw_token_db` (TOKENS); without it, token evidence is skipped. Also runs automatically as a `decompose` stage. |
| `unpack-fbpk <radio.img>` | Lower-level: emit `modem.ext4` (a partial-pipeline shortcut — currently runs the full `extract` under the hood). |
| `split-toc <modem.bin>` | Lower-level: split a `modem.bin` into its TOC images (stage 5 of `extract`). |

## Output layout

`extract` writes (default `./<img>.extracted/`):

    radio.extracted/
    ├── modem.ext4               # the modem partition's ext4 filesystem
    ├── rootfs/images/g5400i-*/  # modem.bin, hardware_config.json, pw_token_db, RF_CFG_*.gz
    ├── rf_cfg_decompressed/     # gunzipped RF_CFG_* calibration blobs
    ├── modem.bin.split/         # 00_BOOT 01_PSP 02_MAIN 03_APM 04_VSS 05_DBGCORE
    └── manifest.json            # input/output sizes, SHA-256, and the TOC image table

`decompose` writes (default `./<img>.decomposed/`; `--prune` keeps only these leaf artifacts):

    radio.decomposed/
    ├── images/
    │   ├── 00_BOOT/decompiled/       # decompiled.c, disasm.lst, functions.json, symbols.json, globals.json, global_shapes.json
    │   ├── 01_PSP/decompiled/
    │   ├── 02_MAIN/
    │   │   ├── decompiled/           # …+ thumb_functions.json (Phase-2 v2), thumb/, symbols.json, globals.json, global_shapes.json
    │   │   └── source_tree/          # reconstructed tree + recovered_index.json (02_MAIN only)
    │   ├── 03_APM/decompiled/
    │   ├── 04_VSS/decompiled/
    │   └── 05_DBGCORE/decompiled/
    ├── rf/                           # decoded/  +  hwcfg_summary/
    ├── tokens/                       # pw_token_db.csv + summary.json
    ├── manifest.json
    ├── ghidra/symbol_maps/           # per-image symbol_map.json (input to pass 2; Phase 1+)
    └── report.json

## Formats

Reverse-engineered; magic numbers and offsets only (no proprietary data is embedded).

- **FBPK** — magic `0x4b504246`; 0x54-byte header `{magic, version, name[0x44], numParts, totalSize}`;
  0x38-byte partition entries `{type, label[32], …, payload_size@0x28, …, next@0x30, checksum@0x34}`.
  The `modem` partition payload is a `ustar` tar wrapping the ext4.
- **TOC** (`modem.bin`) — magic `TOC\0`, count@0x1C; 32-byte entries
  `{name[12], offset, load_addr, size, crc, index}`; the embedded code images are index 1–6.
- **pw_token_db** — Pigweed `pw_tokenizer` binary DB: magic `TOKENS\0\0`, `u32` count + reserved,
  8-byte entries `{u32 token, u32 date_removed}`, then a NUL-terminated UTF-8 string table. Decoded to
  canonical Pigweed CSV (`token,date,string`) + `summary.json`.
- **globals.json** — `pixel-modem-extractor-globals-v1`; the evidence-only source of truth for
  per-image recovered global names, with address, architecture, tier, and direct
  string/function evidence. It contains no application status. Normal `decompose` may apply its
  Recovered records in Ghidra; `--no-symbol-pass` and every Provisional record remain record-only.
  Phase 3.0.1 adds two evidence variants — `global_load` and `string_load` (a `movw`+`movt` pair
  that materializes the global's / a naming string's address into a register, with the movw PC) —
  and a top-level `provisional_suppressed` count (set whenever any Provisional
  globals were generated, regardless of `--globals-provisional`; absent only
  when none were generated).
- **global_shapes.json** — `pixel-modem-extractor-global-shapes-v2`; record-only
  storage-shape evidence for Recovered globals, written by the default-on
  `global_shapes` stage after the complete symbol route. One record per Recovered
  `globals.json` entry, in source order. Status is `inferred` (observations,
  no conflicts, summary present), `no_evidence` (empty observations and
  conflicts, summary `null`), or `conflicting` (non-empty conflicts, summary
  `null`). Observations keep ISA, instruction PC, conditionality, kind, width,
  byte offset, function contexts, and provenance paths, plus — only when
  interprocedural evidence contributed — a `via` array of caller→callee call
  hops. Conflicts group incompatible same-`(ISA, PC)` alternatives without
  choosing a winner.
  A summary, when present, reports `minimum_size` (the maximum observed
  `offset + width`), sorted widths and offsets, unique-instruction read/write
  counts, and a provisional `scalar_candidate` / `array_candidate` / `unknown`
  label. Neither `minimum_size` nor that label is an allocation size or an
  authoritative type. The file hashes its source image, `globals.json`,
  `functions.json`, and `thumb_functions.json` (or explicit `null`), names the
  decoder crate and version, and reports accepted ARM/Thumb identities,
  quarantined source records, quarantine errors, decode failures, and state
  barriers separately, plus six depth-1 interprocedural counters covering call
  resolution, callee seeding, and evidence merge (see CONTRIBUTING for the
  mechanism and the measured net yield on the reference image). Quarantined
  producer records are never decoded; distinct ARM and Thumb identities may
  cover the same bytes and stay independent. `globals.json` is not rewritten.
  `--prune` keeps this sidecar.

## Contributing

Build, test, and development conventions for contributors — human or AI — live in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Legal & license

An independent interoperability, security-research, and educational tool — **not affiliated with,
authorized, or endorsed by Google or Samsung**. "Pixel" is a trademark of Google LLC; "Exynos" is a
trademark of Samsung Electronics ("Shannon" is the common community name for its baseband modem line) —
all used nominatively to describe the firmware this tool interoperates with.

It ships **no proprietary firmware or third-party code**: it operates only on a radio image that
**you supply and must obtain lawfully** (e.g. Google's publicly distributed Pixel factory images). Any
artifacts it produces are derived from your own input and are your responsibility.

Licensed under the [Apache License, Version 2.0](LICENSE); see [`NOTICE`](NOTICE).

## Acknowledgements & prior art

Prior work on Shannon/Exynos baseband reverse engineering:
- [grant-h/ShannonBaseband](https://github.com/grant-h/ShannonBaseband),
- [Comsecuris/shannonRE](https://github.com/Comsecuris/shannonRE), and
- [alexander-pick/shannon_modem_loader](https://github.com/alexander-pick/shannon_modem_loader).
