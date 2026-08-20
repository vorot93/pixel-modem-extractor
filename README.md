# pixel-modem-extractor

Pure-Rust CLI that extracts and analyzes **Pixel modem** firmware — the Samsung Exynos "Shannon"
baseband, across the **S5300 / S5400** family — from any Pixel radio **FBPK** `.img`. One command
unpacks the image down to the raw modem code and configuration; further subcommands decode the RF
calibration databases and the Pigweed token database, reconstruct the firmware's source-tree layout,
and generate decompile kits without external runtime dependencies. `--run`/`decompose` can also drive
local Ghidra plus radare2 for code-image analysis.

The pipeline is structural (TOC-driven), with **no per-model code**: the firmware directory inside the
image is detected by *content* — the `/images/*` subdir that contains `modem.bin` — not by a hardcoded
name, because on some models that directory is literally named `default` rather than `g<model>-…`. The
Shannon generation label in human-facing output (`report.json` `modem_generation`, the source-tree
README) is derived from the FBPK container name (`g5300q…` → `S5300`); when it can't be derived, the
wording stays generic — never a guessed number. Validated end-to-end on two models: mustang
(`g5400i`, **S5400**) and cheetah (`g5300q`, **S5300**).

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

**Memory:** the dense-Thumb Rust path is fully streaming (Stages 1–2 of the
memory-envelope lever). Each region's radare2 stdout capture is parsed
value-by-value from disk, functions are normalized and spilled one at a time,
and `thumb_functions.json` is assembled atomically from the spills —
byte-identical to the previous whole-buffer rendering (env-gated replay of
mustang `02_MAIN`'s five retained captures: ~3.65 GiB of r2 stdout → 151,411
functions, 582,543,970 output bytes, ~248 s wall, ~2.8 GB peak RSS for the
replay+compare; the producer itself measured ~0.3 GB during the captures) —
and `thumb_enrich` now rewrites `thumb_functions.json` through a JSON stream
visitor into an atomic-replace temp file, bounded by the ~86 MB
`decompiled.c` bodies map plus one function record: byte-identical to the
retired whole-file rewriter on the real production inputs (632 MB
`thumb_functions.json` + 86 MB `decompiled.c`: 130 s, 2.29 GB peak RSS in
the streaming-vs-oracle A/B). Those two whole-file enrich sweeps previously
held a ~24.9 GB full-`decompose` peak (the 632 MB JSON parsed to a ~20+ GB
in-memory tree, twice — itself down from ~56 GiB when the r2 parse was also
whole-buffer); with them streaming, the measured full-`decompose` peak is
still ~24.5 GB (2026-08-20 probe: 23.5 GB pre-pass-2 and 24.5 GB
post-pass-2 spikes, both in the recovered-source attribution windows) — now
held by `recover_source`'s whole-file parse of `thumb_functions.json`, the
Stage-3 target. Ghidra's own phases peak ~8 GB; the radare2 producer,
`thumb_enrich`, and `symbolicate` (~3 GB) all sit below that. The 4 GiB
radare2 stdout cap applies per capture. radare2's *own* analysis memory is
separately bounded to 16 GiB
(`RLIMIT_AS`) per dense-Thumb region: a pathological region whose `aaa` would
otherwise run away (seen on one 4 MiB region of cheetah's MAIN, ~90+ GiB) fails
closed and is skipped, so the rest of the image's Thumb still decompiles instead
of the host OOM-ing. Smaller images without dense Thumb regions (`00_BOOT`,
`01_PSP`, etc.) stay under 1 GiB. `--no-thumb-decompile` switches Ghidra to
`datamark` mode and skips `body_c` enrichment, but it still runs the
(now-streaming) dense-region radare2 capture/parse path — without the old
dense-Thumb memory envelope.

**Project path:** `pixel-modem-extractor` canonicalizes its output root before
constructing the Ghidra headless project path. Ghidra 12 rejects any
dot-prefixed component in that resulting path, so a symlink cannot hide a
dot-prefixed canonical ancestor from this pipeline. Choose an output root whose
canonical path contains no dot-prefixed components.

## Quickstart

    # 1. Extract everything from a radio image (default out: ./radio.extracted/)
    pixel-modem-extractor extract radio.img

    # 2. Analyze the extracted artifacts, e.g. (the firmware dir and the *_MAIN
    #    split name are model-dependent — glob them; see Output layout):
    cd radio.extracted
    pixel-modem-extractor decode-tokens rootfs/images/*/pw_token_db
    pixel-modem-extractor source-tree   modem.bin.split/*_MAIN
    pixel-modem-extractor decompile     rootfs/images/*/modem.bin   # add --run for Ghidra + radare2 Thumb analysis

    # Or do all of the above in one shot (needs local Ghidra + radare2):
    pixel-modem-extractor decompose radio.img          # add --prune for leaves only

Every subcommand accepts `--out DIR` (a sensible default is used otherwise); run any with `--help` for
its full set of flags.

## Commands

| Command | What it does |
|---|---|
| `extract <radio.img>` | **Main entry.** Full pipeline: FBPK → ext4 → rootfs → gunzip `RF_CFG_*` → split TOC, recording a per-image opaque battery (see Formats) in `manifest.json`. Default out `./<img>.extracted/`. `--no-verify` skips CRC/size checks. |
| `decompose <radio.img>` | **Everything, one shot.** Runs `extract`, decompiles all code images (Ghidra; the image set is model-dependent — six on mustang, four on cheetah), enriches the MAIN image's `source_tree` with recovered-code evidence when attribution is possible, and runs every decoder into one per-image tree (`images/NN_NAME/{decompiled,…}`, `rf/`, `tokens/`) with a `report.json`. A MAIN with exactly one validated runtime scatter map retains its flat raw mapping and gains reconstructed runtime blocks before Ghidra analysis; no candidate stays raw-only, while a plausible malformed or ambiguous map aborts the command. Unanimously-opaque images (per the battery; see Formats) are skipped without spawning Ghidra — `--no-skip-opaque` forces a run. The MAIN split name varies by model (`02_MAIN` on mustang, `01_MAIN` on cheetah); the tool selects the `*_MAIN` split dir, so `02_MAIN` below denotes the mustang concrete path. **Requires a local Ghidra and radare2** (`r2`), probed up front. `--prune` keeps only the terminal artifacts; `--out`, `--ghidra-home`, `--processor`, `--no-verify` as elsewhere. Default out `./<img>.decomposed/`. **Phase 1:** decompile runs **twice** per eligible image — pass 1 analyzes and exports an initial inventory; pass 2 runs the applicable `ApplySymbols.java`, `ApplyGlobals.java`, and/or `ApplyGlobalTypes.java` scripts, then `ExportDecomp.java`, in one saved-project process. Recovered function and strict Recovered global names — and, since Phase 3.2, recovered global storage widths — are therefore baked into regenerated `decompiled.c` and disassembly instead of text-substituted afterward. Global application renames only exact Ghidra-default `DAT_<addr>` labels at the matching address; missing, non-default, rejected-name, and outside-memory candidates are preserved and reported as skips. Pass 2's ownership-aware refresh replaces only `decompiled.c` / `disasm.lst` / `functions.json` and leaves `globals.json`, `global_shapes.json`, `thumb_functions.json`, `thumb/`, and other sidecars byte-for-byte unchanged. `--no-symbol-pass` skips pass 2 entirely: it still writes `globals.json`, but globals remain record-only and `DAT_<addr>` placeholders are not changed in Ghidra. **Phase 2:** Dense Thumb regions in `02_MAIN` are decompiled by Ghidra (tightened `TameAnalysis`). A runtime Surface B watch kills Ghidra on overlap-repair spin and falls back to Phase-1 datamark per image (`thumb_tighten_error`, image not failed). Phase 2.1 closed both dormancy causes: `thumb_enrich` matches by entry address, and `TameAnalysis mode=tighten` carries the winning `TIGHTEN_EXTRA` (`"Non-Returning Functions - Discovered.Repair Flow Damage"`) so Ghidra converges on full `02_MAIN` in ~23 min without Surface B firing. **Production — mustang / S5400 (verified full `decompose`, ~1 h 37 m wall, exit 0):** `functions` = 107,955; `thumb_functions` = 117,444; `thumb_decompiled` = 77,456; five `thumb/*.stdout` preserved across pass 2; radare2 4 GiB streaming path did not hit the cap. **Second model — cheetah / S5300 (verified, ~84 min, exit 0):** MAIN is `01_MAIN`; `functions` = 104,395; `thumb_functions` = 87,026; `thumb_decompiled` = 70,906; `globals_recovered` = 1,061; one 4 MiB dense-Thumb region hit the 16 GiB radare2 address-space cap and was skipped (the rest decompiled); four images (no PSP/DBGCORE); no RF_CFG blobs, so `decode_rf`/`hardware_config` skipped. `thumb_functions.json` is v2 (optional per-function `body_c`). `--no-thumb-decompile` skips Phase 2 (Phase-1 datamark behavior end-to-end). **Phase 3.0:** Global names are recovered from direct string evidence when a function has exactly one non-string `data_ref` and exactly one unique underscored identifier across its referenced strings. The per-image `decompiled/globals.json` is Recovered-only by default and remains the strict evidence source of truth; conflicting names for one address are dropped. In normal `decompose`, eligible Recovered records feed the existing pass 2. **Phase 3.0.1:** Disasm-anchored Recovered globals — a `movw`+`movt` load pair within K=4 load-events of a string load pins that string's identifier as the global's name, regardless of `data_ref` cardinality. On production `02_MAIN` (Thumb through pass 2) `globals_recovered` = **915** (arch: arm 367 / thumb 545 / mixed 3); stage total recovered 921 with 194 conflicts dropped. `--globals-provisional` opts in to additionally emitting name-prior-derived `tier: "provisional"` entries (default off; bare `globals.json` is byte-equivalent to Phase 3.0's for the Recovered set). Provisional records are always record-only and never application candidates. **Phase 3.2:** `decompose` always runs a record-only `global_shapes` stage exactly once per route: on the normal route it now runs right after `globals.json` is written and **before** pass 2, so the recovered shapes are ready for a pass-2 script to consume; on `--no-symbol-pass` (which has no pass 2) it still runs last. It decodes accepted A32/T32 function bytes with the pure-Rust `scaleservers-arm32-assembly` 1.0.0 adapter and writes `decompiled/global_shapes.json` v4 — one record per Recovered global; facts cross direct CFG edges by a must-facts join (every incoming path must agree; join kills counted). `globals.json` is not rewritten. `--prune` retains the sidecar. Each record is `inferred`, `no_evidence`, or `conflicting`; summaries carry only `minimum_size` and a provisional `scalar_candidate` / `array_candidate` / `unknown` label. No exact allocation size or authoritative type is inferred. Quarantined producer records never reach the decoder and are counted separately from accepted-range `decode_failures`. Distinct ARM and Thumb identities may cover the same bytes and remain independent interpretations. **Production (mustang `02_MAIN`):** Recovered shapes 915 MAIN / 921 total; **154 inferred / 761 `no_evidence` / 0 conflicting** under the v3 cross-block engine + same-instruction multi-offset fix (v2-era: 125/787/3 — net +29 recovered shapes, `conflicting` → 0; the v2-era verified run's MAIN observations were 32 ARM + 907 Thumb); `decode_failures` = 37,629 (recoverable; the image still succeeds); `globals.json` unchanged. `decompose` now also runs a **default-on depth-1 interprocedural pass** (direct `bl` only, AAPCS r0–r3) that re-runs the shape tracker inside directly-called functions with the argument register seeded — the seed joins at the callee entry and propagates cross-block by the same must-facts join; it is **record-only and additive-only** (it never demotes an `inferred` global and never produces `conflicting`). The v2-era pass alone yielded **0 new shapes** (the pass-by-reference callees store, not dereference, the pointer); since the v3 engine propagates seeds in-callee, interprocedural evidence grew 3→58 observations — see CONTRIBUTING for the mechanism and limitations. Eligible recovered shapes are also **applied**, by default, as Ghidra `undefinedN` types in that same pass 2 — a scalar `inferred` global (width 1/2/4/8) reads in `decompiled.c` as one correctly-sized typed value instead of raw `DAT_` bytes; arrays, `unknown`, `conflicting`, and `no_evidence` shapes are never applied, only counted. `--no-apply-global-types` turns off just this application step — `global_shapes.json` is still produced either way. `--no-symbol-pass` has no pass 2 to apply into, so its `global_shapes.json` never carries applied types regardless of this flag. |
| `source-tree <MAIN_image>` | Reconstruct the firmware source-tree layout from embedded `__FILE__` strings — **names and structure only, not original source**. The input is the MAIN code image; its split name is model-dependent (`02_MAIN` on mustang, `01_MAIN` on cheetah) and the generated labels name whichever image you pass. `--modem <LABEL>` sets the Shannon generation in the generated README (e.g. `S5300`; auto-derived under `decompose`). `--no-attribution`, `--gap`, `--shared-pct`, `--min-run` tune the heuristics. |
| `decode-rf <RF_CFG_dir> --hwcfg <hardware_config.json>` | Semantic decode of the RF_CFG calibration databases (heuristic calibration-vector extraction + per-variant mapping). Default out `./decoded_rf/`. |
| `decode-tokens <pw_token_db>` | Decode the Pigweed `pw_tokenizer` token database to canonical CSV + `summary.json`. Default out `./decoded_tokens/`. |
| `hardware-config <hardware_config.json>` | Structural stats + RF_CFG-coverage summary. `--rf-dir` cross-checks which calibration blobs are actually present. Default out `./hwcfg_summary/`. |
| `decompile <modem.bin>` | Write a Ghidra import kit for all code images at their load addresses (the image set is model-dependent — six on mustang, four on cheetah). For a recognized MAIN, generation validates and emits a runtime scatter map; Ghidra retains the raw mapping and applies those runtime blocks before analysis. No candidate leaves the image raw-only, while a plausible malformed or ambiguous map fails the command. `--run` drives `analyzeHeadless` (needs a local Ghidra) to export decompiled C, a disassembly listing, and a function inventory; unanimously-opaque images are skipped without spawning Ghidra (`--no-skip-opaque` forces a run); selected images with dense Thumb regions also use radare2 (`r2`) and fail if those regions cannot be analyzed. `--image`, `--ghidra-home`, `--processor` (default `ARM:LE:32:v7`). `--no-thumb-decompile` reverts Phase-2 Thumb decompilation to Phase-1 datamark behavior. |
| `symbolicate <decomposed_dir>` | Recover function names + inline log/assert/file annotations from evidence already produced (pw_tokenizer DB, `__func__`, attributed strings), rewriting `decompiled.c`/`disasm.lst`/`functions.json`/`thumb_functions.json` **in place** and emitting `symbols.json`. Tiered + fail-closed (precedence `__func__` > registration > token > string-ref): `__func__` and `{name,fn}` **registration-table** matches yield authoritative (`Recovered`) renames; token matches become marked `guess_…` names; strings/files are comments. `--token-db` gives the raw `pw_token_db` (TOKENS); without it, token evidence is skipped. Registration names come from scanning the raw image for handler/dispatch tables (AT-command, ISR, protocol) whose pointer resolves to a known function entry — the crown-jewel names (e.g. `AtiParsePlusCOPS`, `PICH_HISR`), ~100% precision but a small set (~233 mustang / 101 cheetah). Also derives lowest-precedence `guess_*` names from a function's uniquely-referenced identifier string (fail-closed: dropped if all-caps, a recovered global, or another function's name), recorded as `string_ref` evidence. It also runs automatically as a `decompose` stage. |
| `tree-hash <dir>` | Print the whole-tree `pme-paq-v1` hash of `<dir>` — one lowercase 64-hex value — and write nothing. Fails closed with no hash printed if the target is missing, not a directory, contains a symlink, or has any non-UTF-8 path component. No external tools. |
| `unpack-fbpk <radio.img>` | Lower-level: emit `modem.ext4` (a partial-pipeline shortcut — currently runs the full `extract` under the hood). |
| `split-toc <modem.bin>` | Lower-level: split a `modem.bin` into its TOC images (stage 5 of `extract`). |

## Output layout

`extract` writes (default `./<img>.extracted/`):

    radio.extracted/
    ├── modem.ext4               # the modem partition's ext4 filesystem
    ├── rootfs/images/<fw>/      # modem.bin, [hardware_config.json], pw_token_db, [RF_CFG_*.gz]
    │                            #   <fw> is content-detected: `g5400i-…` (mustang), `default` (cheetah)
    │                            #   hardware_config.json / RF_CFG_* are absent on some models (cheetah)
    ├── rf_cfg_decompressed/     # gunzipped RF_CFG_* calibration blobs (empty when the model has none)
    ├── modem.bin.split/         # TOC images; set is model-dependent:
    │                            #   mustang: 00_BOOT 01_PSP 02_MAIN 03_APM 04_VSS 05_DBGCORE
    │                            #   cheetah: 00_BOOT 01_MAIN 02_VSS 03_APM   (MAIN is *_MAIN)
    └── manifest.json            # input/output sizes, blake3 digests, and the TOC image table
                                 #   (each TOC image row carries its opaque battery)

`decompile` writes a standalone Ghidra import kit. A MAIN with one validated runtime map adds:

    scatter/<label>/load_map.json
    scatter/<label>/blocks/<entry>-<operation>.bin

The manifest is the auditable map; payload files exist only for materialized copy or nonzero
`decompress1` outputs. Zero-filled outputs and self-copies remain compact manifest entries.
In `ghidra_load.json`, a recognized MAIN image gains optional `runtime_load_map` with the
import-kit-relative path `scatter/<label>/load_map.json`; raw-only images omit the field.

`decompose` writes (default `./<img>.decomposed/`; `--prune` keeps only these leaf artifacts):

    radio.decomposed/
    ├── images/
    │   ├── 00_BOOT/decompiled/       # decompiled.c, disasm.lst, functions.json, symbols.json, globals.json, global_shapes.json
    │   ├── 01_PSP/decompiled/
    │   ├── 02_MAIN/
    │   │   ├── decompiled/           # …+ thumb_functions.json (Phase-2 v2), thumb/, symbols.json, globals.json, global_shapes.json
    │   │   ├── source_tree/          # reconstructed tree + recovered_index.json (MAIN image only)
    │   │   └── scatter/              # load_map.json + blocks/; retained by --prune (MAIN when recognized)
    │   ├── 03_APM/decompiled/
    │   ├── 04_VSS/decompiled/
    │   └── 05_DBGCORE/decompiled/
    ├── rf/                           # decoded/  +  hwcfg_summary/  (only when the model ships RF_CFG)
    ├── tokens/                       # pw_token_db.csv + summary.json
    ├── manifest.json
    ├── ghidra/symbol_maps/           # per-image symbol_map.json (input to pass 2; Phase 1+)
    └── report.json                   # includes modem_generation (e.g. "S5300"/"S5400")

The `images/` set above is the mustang (S5400) layout. The image set and the MAIN dir are
model-dependent: cheetah (S5300) has `00_BOOT 01_MAIN 02_VSS 03_APM`, with `source_tree/` under
`01_MAIN`. A recognized map lives at `images/<MAIN>/scatter/` on either model and survives
`--prune`. `rf/` appears only when the model ships RF_CFG blobs (cheetah has none).

## Formats

Reverse-engineered; magic numbers and offsets only (no proprietary data is embedded).

- **FBPK** — magic `0x4b504246`; 0x54-byte header `{magic, version, name[0x44], numParts, totalSize}`;
  0x38-byte partition entries `{type, label[32], …, payload_size@0x28, …, next@0x30, checksum@0x34}`.
  The `modem` partition payload is a `ustar` tar wrapping the ext4.
- **TOC** (`modem.bin`) — magic `TOC\0`, count@0x1C; 32-byte entries
  `{name[12], offset, load_addr, size, crc, index}`; the embedded code images are index 1–6.
- **Runtime scatter map** — discovered from the semantically decoded, unconditional A32 sequence
  `ADD base, PC, #imm; LDMIA base, {r10, r11}; ADD r10, r10, base; ADD r11, r11, base`,
  not a byte signature or model address. Its literal pair resolves the exact table start and exclusive
  end; that bounded range is a nonempty multiple of the 16-byte descriptor
  `{u32 source, u32 destination, u32 size, u32 handler}` and contains at most 256 entries. Supported
  operations are exactly `null`, `copy`, `decompress1`, and `zero`. For `decompress1`, each token uses
  `literal_code = token & 7` (an extension byte when zero), copies `literal_code - 1` literals, and uses
  `run = token >> 4` (also extended when zero); bit 3 clear appends `run` zeroes, while bit 3 set reads a
  one-byte distance and performs an overlapping `run + 2` byte back-reference. Decoding is bounded to
  the exact declared output. The accepted logical output and cumulative speculative decoded work have
  independent 512 MiB per-image limits. Ghidra keeps the raw image and adds only initialized, readable,
  writable, non-executable, non-volatile runtime blocks because the table carries no trustworthy MPU
  permissions. No candidate remains raw-only; a candidate that reaches the structural threshold but is
  malformed or ambiguous fails closed.
- **manifest.json `battery`** — per-TOC-image opaque battery, recorded by `extract` for every
  embedded image: whole-image Shannon entropy `H`, χ²/df over the byte histogram, serial
  correlation, 64-KiB window entropies (`window_min`/`window_mean`/`window_max`, trailing
  window < 4 KiB ignored), and `frac_windows_high` (windows with H > 7.5). The verdict is
  unanimous and fail-closed: `opaque` iff H ≥ 7.5 ∧ χ²/df ≤ 64.0 ∧ |SCC| ≤ 0.10 ∧
  `window_min` ≥ 7.7 ∧ `frac_windows_high` ≥ 0.99 — any single refusal (including zero
  windows) yields `not_opaque`. `opaque` means the measurement is consistent with encryption —
  the label states the measurement, not the mechanism. Floats are rounded to 4 decimals. On
  the reference corpus (both models) only mustang `01_PSP` measures `opaque` (H = 7.9918);
  `report.json`'s per-image `classification` always agrees with `battery.label`, and skipped
  rows add `skipped_reason: "opaque"`.
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
- **global_shapes.json** — `pixel-modem-extractor-global-shapes-v4`; record-only
  storage-shape evidence for Recovered globals, written by the default-on
  `global_shapes` stage (on the normal route, before pass 2; on
  `--no-symbol-pass`, last — see Phase 3.2 above). Facts cross direct CFG
  edges by a must-facts join — a register fact survives into a block only
  when every incoming path agrees, and join kills are counted (inside
  `state_barriers`). One record per Recovered `globals.json` entry, in
  source order. Status is `inferred` (observations,
  no conflicts, summary present), `no_evidence` (empty observations and
  conflicts, summary `null`), or `conflicting` (non-empty conflicts, summary
  `null`). Observations keep ISA, instruction PC, conditionality, kind, width,
  byte offset, function contexts, and provenance paths, plus — only when
  interprocedural evidence contributed — a `via` array of caller→callee call
  hops. Conflicts group incompatible same-`(ISA, PC)` alternatives without
  choosing a winner (same-instruction multi-offset accesses are observations,
  not conflicts).
  A summary, when present, reports `minimum_size` (the maximum observed
  `offset + width`), sorted widths and offsets, unique-instruction read/write
  counts, and a provisional `scalar_candidate` / `array_candidate` / `unknown`
  label. Neither `minimum_size` nor that label is an allocation size or an
  authoritative type. The file hashes its source image, `globals.json`,
  `functions.json`, and `thumb_functions.json` (or explicit `null`), names the
  decoder crate and version, and reports accepted ARM/Thumb identities,
  quarantined source records, quarantine errors, decode failures, and state
  barriers separately, plus six depth-1 interprocedural counters covering
  call resolution, callee seeding, and evidence merge and six cross-block
  counters covering join kills, surviving facts, and propagation (see
  CONTRIBUTING for the mechanism and the measured yield on the reference
  image). Quarantined
  producer records are never decoded; distinct ARM and Thumb identities may
  cover the same bytes and stay independent. `globals.json` is not rewritten.
  `--prune` keeps this sidecar. On the normal route, eligible `inferred` /
  `scalar_candidate` records (width 1/2/4/8) are also applied as `undefinedN`
  types in `decompiled.c` during that same pass 2 (`--no-apply-global-types`
  skips only that application step); this sidecar's own content reflects
  shape evidence only and is unaffected either way — see the `decompose` row
  above.
- **pme-paq-v1** — blake3 leaf-set (root-relative path + file bytes) over an entire tree, hidden
  entries included, no exclusion list; produced by the `tree-hash` subcommand and used for golden
  reproducibility pinning.

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
