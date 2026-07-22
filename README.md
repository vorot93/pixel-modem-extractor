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
| `decompose <radio.img>` | **Everything, one shot.** Runs `extract`, decompiles all six images (Ghidra), enriches `02_MAIN/source_tree` with recovered-code evidence when attribution is possible, and runs every decoder into one per-image tree (`images/NN_NAME/{decompiled,…}`, `rf/`, `tokens/`) with a `report.json`. **Requires a local Ghidra and radare2** (`r2`), probed up front. `--prune` keeps only the terminal artifacts; `--out`, `--ghidra-home`, `--processor`, `--no-verify` as elsewhere. Default out `./<img>.decomposed/`. **Phase 1:** decompile runs **twice** per image — pass 1 analyzes and exports an initial inventory; pass 2 (`ApplySymbols.java` + `ExportDecomp.java`) applies the recovered function names and inline-evidence plate comments so the regenerated `decompiled.c` is born with names baked in (instead of text-substituted afterward). `--no-symbol-pass` skips pass 2. **Phase 2:** Dense Thumb regions in `02_MAIN` are decompiled by Ghidra (tightened `TameAnalysis`). **On production `02_MAIN`, the runtime Surface B watch detects that the larger dense-Thumb regions trigger Ghidra's overlap-repair spin (Phase 1's data-marks existed to prevent exactly this) and falls back to today's Phase-1 datamark behavior** — recording `thumb_tighten_error` without marking the image failed. Phase 2.1 closed both dormancy causes: `thumb_enrich` now matches by entry address (Phase 2's intended contract), and `TameAnalysis mode=tighten` carries the winning `TIGHTEN_EXTRA` (`"Non-Returning Functions - Discovered.Repair Flow Damage"`) which lets Ghidra converge on the full `02_MAIN` in ~23 min without Surface B firing. `body_c` is populated on production (81,763 entries on a real `02_MAIN` via direct `thumb_enrich` verification; full `decompose` end-to-end pending). `thumb_functions.json` is v2 (optional per-function `body_c`). `--no-thumb-decompile` skips Phase 2 (Phase-1 datamark behavior end-to-end). |
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
    │   ├── 00_BOOT/decompiled/       # decompiled.c, disasm.lst, functions.json, symbols.json
    │   ├── 01_PSP/decompiled/
    │   ├── 02_MAIN/
    │   │   ├── decompiled/           # …+ thumb_functions.json (Phase-2 v2: optional per-function body_c), thumb/, symbols.json
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
