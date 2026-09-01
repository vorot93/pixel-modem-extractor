# pixel-modem-extractor

Rust CLI that extracts and analyzes **Pixel modem** firmware — the Samsung Exynos "Shannon"
baseband, across the **S5300 / S5400** family — from any Pixel radio **FBPK** `.img`. Extraction,
format parsing, and the decoders are pure Rust. One command unpacks the image down to the raw modem
code and configuration; further subcommands decode the RF calibration databases, the Pigweed token
database, and the MAIN debug-trace catalog, reconstruct the firmware's source-tree
layout, and generate decompile kits. The optional
code-analysis routes drive local Ghidra and radare2, with opt-in Rizin fallback.

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

## External code analysis

Extraction, generation-only `decompile`, and the decoders need no external runtime. The
`decompile --run` and `decompose` analysis routes require both local **Ghidra** and
**radare2** (`r2` on `PATH`). Rizin never substitutes for a missing radare2 primary.
On macOS, install the required tools with `brew install ghidra radare2`; optionally install
Rizin with `brew install rizin` when you intend to use `--rizin-fallback`.

Ghidra is located, in order, from `--ghidra-home`, `$GHIDRA_INSTALL_DIR`, or `PATH` (its
`ghidraRun` launcher), with `/opt/ghidra` as the final Linux fallback. Both the upstream
release-tarball and Homebrew layouts are supported. Its bundled JDK is used unless you set
`JAVA_HOME`. radare2 is discovered, canonicalized, and version-probed as a hard preflight: both
`decompile --run` and `decompose` fail immediately when it is missing, before Rizin is probed and
before any output is written, so a run can never succeed without its required primary. Rizin is not
discovered or probed in the default mode; it is preflighted only when `--rizin-fallback` is
present.

**Dense Thumb policy:** radare2 runs `aaa;aflj;pdfj @@f` first for every detected region.
With `--rizin-fallback`, and only after that region's radare2 attempt fails, Rizin runs
`aaa;aflj;pdfj @@F;axlj`. A healthy radare2 result stops the region even if it has low
coverage, many quarantined functions, or different boundaries from Rizin. The coordinator
retains one successful producer run per region and never unions analyzer output.

A valid partial result is published when at least one region succeeds: failed attempts remain
visible in the v3 region ledger and `report.json` reports the failed-region count without a
`thumb_error`. If every requested region fails, the Thumb stage fails and publishes no new
`thumb_functions.json`; an existing sidecar is left byte-identical and is not current for that
run.

Fresh Thumb output is strict `pixel-modem-extractor-thumb-functions-v3`. Its ordered
`producers`, `regions`, and `attempts` identify the canonical executable, version, exact command,
attempt outcome, and retained capture. Each successful attempt owns one contiguous slice of the
flat `functions` array through `function_runs`; consumers derive radare2 or Rizin ownership from
those validated region/run coordinates. Every accepted range carries a lowercase BLAKE3 over its
exact runtime bytes, and the concrete run plus framed aggregate execution digest remains attached
through downstream attribution and mutation. Retained v1/v2 files remain readable as legacy
radare2 evidence, but are read-only; new analysis and enrichment never write them.

**Resources and captures:** every radare2 or Rizin attempt has a 4 GiB stdout cap and, on
Unix, a 16 GiB child `RLIMIT_AS`. Rizin additionally has a fixed 30-minute deadline per
region. Analyzer stdout is drained to `thumb/<start:08x>.<producer>.stdout`, hashed incrementally,
parsed value-by-value, normalized into bounded fragment spills, and assembled atomically; the
capture is never buffered whole. Rizin's trailing `axlj` is streamed, with an exact cap of
1,000,000 selected xref records before sorting and deduplication. Successful attempts always record
the capture's relative path, exact byte count, and lowercase BLAKE3. Failed attempts retain the same
metadata when partial stdout can be finalized; spawn or capture-finalization failure records
`stdout: null`. `--prune` removes all captures and carved region inputs while v3 retains their
recorded identity.

**Memory:** the dense-Thumb producer and every downstream mutation are streaming. Each backend
capture is parsed value-by-value, functions are normalized and spilled one at a time, and strict v3
is assembled atomically. One analyzer inventory is limited to 262,144 functions, 1,048,576 accepted
ranges, 65,536 ranges per function, and 512 MiB of charged executable bytes. One consumer is
deliberately whole-file: `global_shapes` retains the
complete validated function set because its decoder analyzes those records together. The retained Mustang replay measured ~3.65 GiB of radare2 stdout, 151,411 functions,
582,543,970 output bytes, ~248 seconds, and ~2.8 GB peak RSS for replay plus comparison; capture
production itself measured ~0.3 GB. `thumb_enrich` streams `decompiled.c` and rewrites one function
at a time, bounded by its ~86 MB body map plus one record (632 MB artifact A/B: 130 seconds,
2.29 GB peak, byte-identical). Ghidra `functions.json` loads through
`read_ghidra_inventory_streaming` (one record at a time; the in-memory slice
validator remains test-only). `recover_source` uses a typed streaming reader, symbolication's
artifact rewrites stream through atomic v3-preserving writers, and ARM disassembly ranges are
zero-copy borrowed views. The standalone symbolication A/B dropped from 24 GB to 1.8 GB with
byte-identical output. A full dense-Thumb `decompose` now peaks at ~7.7 GB in Ghidra's own
analyze/export phase; the Rust process peaks near ~2.5 GB, mostly owned function bodies.

`--no-thumb-decompile` changes only Ghidra to `datamark` mode and skips `body_c` enrichment. The
streaming host Thumb analyzer, including opt-in failure-only Rizin fallback, still runs. In datamark
mode every architectural exception-root instruction and authoritative PAL task function (see below)
stays code — only undefined regions that neither subsystem owns are marked as data.

**Architectural exception-root seeding (default on, with no disable flag).** Every generation-only
`decompile`, `decompile --run`, and `decompose` examines every embedded TOC image before image
selection and the opaque skip. The sole initial candidate is the image load address. Fewer than eight
supported A32 slots is clean absence and clears stale owned output; the threshold is all eight slots,
each an unconditional non-linking direct branch or an unconditional literal `LDR PC`. Once that
threshold is crossed, every literal, target, ISA, first instruction, and resource bound must validate
through the image's raw-plus-scatter runtime view or generation fails closed. A second table is accepted
only when exact reset-prefix dataflow proves its address through VBAR; partial vector-like prefixes are
never promoted by scanning arbitrary image bytes or consulting an analyzer inventory.

A validated plan publishes `exception_roots/<label>/roots.json` in a standalone decompile kit and is
named by optional `ghidra_load.json.images[].exception_root_map`. `decompose` authenticates and moves
the same manifest to `images/<label>/exception_roots/roots.json`. With Ghidra enabled, the pass-1 order
is exactly `ApplyScatterLoad.java` -> `ApplyExceptionRoots.java` -> `ApplyPalTasks.java` ->
`TameAnalysis.java` -> auto-analysis -> `ExportDecomp.java`, omitting only optional scripts whose
explicit current state is absent. The exception transaction creates or reuses each exact-entry
ARM/Thumb function, records concrete ownership, and always preserves an architectural role label in
`PixelModemExtractor_ExceptionRoots_v1`. A conventional role primary is requested only for an
unshared one-to-one role, never over a meaningful foreign primary. Firmware-native names remain
stronger: `__func__` > registration > exception root > PAL task > token > string reference; a stronger
pass-2 primary does not remove the role label.

Immediate Rust-driven runs capture stdout and require exactly one identity-bound, conserving
`ApplyExceptionRoots: {json}` summary. Generated `run_ghidra.sh` exposes that script output but does
not parse it in shell; instead it requires process success, all three exports, and the exact four-line
`pixel-modem-extractor-ghidra-export-v4` marker that Java writes only after complete root postflight.
Both routes bind the same manifest identity through `TameAnalysis` and export. Missing, malformed,
stale, removed, merged, retagged, role-changed, or ownership-inconsistent root state therefore
publishes no current export. An opaque-skipped image can still retain a current generation manifest,
but has no Ghidra application counts because no process ran.

**PAL task seeding (default on).** Every recognized MAIN image is probed, at generation time and on
every run, for a PAL task initializer: a semantic proof (anchor materialization of `PALTskTm\0`,
a counting loop with a decoded capacity guard, and a backward-sliced slot-base constant) — never a
byte signature, model address, or analyzer inventory. A validated plan publishes
`pal_tasks/<label>/tasks.json` and, on `--run`/`decompose`, seeds Ghidra with one function per task
entry **before auto-analysis** (`ApplyPalTasks.java`, after scatter application, before
`TameAnalysis`), giving the analyzer authoritative roots for the scheduler topology. Stored task
entry pointers carry the ISA tag in bit 0 (odd = Thumb); both ISAs decode strictly through the
project-owned ARM decoder with no cross-ISA fallback, and pointers resolve through raw **or**
scatter-materialized storage. Each entry receives a global primary `pal_TaskEntry_<name>` (shared
entries: `pal_TaskEntry_shared_<entry-hex>`; sanitized collisions: deterministic
`_pme_<entry>_<index>_<nonce>` suffixes) plus a per-task role label in a reserved namespace; a
Ghidra-side ownership registry makes every applied task identity durable across pass 2. Names with
independent meaning are never overwritten, and later stronger evidence replaces only these
project-owned primaries while retaining the PAL evidence. A MAIN with no discoverable initializer
is clean absence (no manifest, recorded as such); a plausible-but-malformed or ambiguous
initializer **fails the command** — there is no partial, best-effort, or artifact-only fallback.

**Project path:** `pixel-modem-extractor` canonicalizes its output root before
constructing the Ghidra headless project path. Ghidra 12 rejects any
dot-prefixed component in that resulting path, so a symlink cannot hide a
dot-prefixed canonical ancestor from this pipeline. Choose an output root whose
canonical path contains no dot-prefixed components. Separately, the generated
`run_ghidra.sh` survives spaces and parentheses in its kit root, but upstream
`analyzeHeadless`'s own launcher mangles roots containing quotes, `&`, `;`,
backtick, `!`, or `$` — avoid those characters in output paths.

## Quickstart

    # 1. Extract everything from a radio image (default out: ./radio.extracted/)
    pixel-modem-extractor extract radio.img

    # 2. Analyze the extracted artifacts, e.g. (the firmware dir and the *_MAIN
    #    split name are model-dependent — glob them; see Output layout):
    cd radio.extracted
    pixel-modem-extractor decode-tokens rootfs/images/*/pw_token_db
    pixel-modem-extractor source-tree   modem.bin.split/*_MAIN
    pixel-modem-extractor decompile rootfs/images/*/modem.bin
    pixel-modem-extractor decompile rootfs/images/*/modem.bin --run
    pixel-modem-extractor decompile rootfs/images/*/modem.bin --run --rizin-fallback

    # Or do all of the above in one shot (Ghidra + radare2 required):
    pixel-modem-extractor decompose radio.img
    pixel-modem-extractor decompose radio.img --rizin-fallback
    pixel-modem-extractor decompose radio.img --prune

Every subcommand accepts `--out DIR` (a sensible default is used otherwise); run any with `--help` for
its full set of flags.

## Commands

| Command | What it does |
|---|---|
| `extract <radio.img>` | **Main entry.** Full pipeline: FBPK → ext4 → rootfs → gunzip `RF_CFG_*` → split TOC, recording a per-image opaque battery (see Formats) in `manifest.json`. Default out `./<img>.extracted/`. `--no-verify` skips CRC/size checks. |
| `decompose <radio.img>` | **Everything, one shot.** Runs `extract`, decompiles all code images (Ghidra; the image set is model-dependent — six on mustang, four on cheetah), enriches the MAIN image's `source_tree` with recovered-code evidence when attribution is possible, and runs every decoder into one per-image tree (`images/NN_NAME/{decompiled,…}`, `rf/`, `tokens/`) with a `report.json`. A MAIN with exactly one validated runtime scatter map retains its flat raw mapping and gains reconstructed runtime blocks before Ghidra analysis; no candidate stays raw-only, while a plausible malformed or ambiguous map aborts the command. The validated PAL task plan (default-on semantic discovery, same rules as `decompile`) seeds every task entry into Ghidra before analysis; its terminal manifest lands at `images/<MAIN>/pal_tasks/tasks.json` (retained by `--prune`), and pass 2 preserves PAL evidence while applying stronger names only over project-owned task primaries. DBT exact source evidence outranks adjacency attribution and surfaces as `dbt-source` annotations. Unanimously-opaque images (per the battery; see Formats) are skipped without spawning Ghidra — `--no-skip-opaque` forces a run. The MAIN split name varies by model (`02_MAIN` on mustang, `01_MAIN` on cheetah); the tool selects the `*_MAIN` split dir, so `02_MAIN` below denotes the mustang concrete path. **Requires local Ghidra and radare2** (`r2`), probed up front; `--rizin-fallback` also preflights Rizin. `--prune` keeps only the terminal artifacts; `--out`, `--ghidra-home`, `--processor`, `--no-verify` as elsewhere. Default out `./<img>.decomposed/`. **Phase 1:** decompile runs **twice** per eligible image — pass 1 analyzes and exports an initial inventory; with all maps present, pass 2 runs `ApplyThumbNames.java` (creating + naming named producer-authenticated Thumb functions Ghidra's analyzer never discovered — e.g. the AT-command handlers — reported as `pass2_created`) -> `ApplySymbols.java` -> `ApplyGlobals.java` -> `ApplyGlobalTypes.java` -> `ExportDecomp.java` in one saved-project process; each map remains independently optional. Recovered function and strict Recovered global names — and, since Phase 3.2, recovered global storage widths — are therefore baked into regenerated `decompiled.c` and disassembly instead of text-substituted afterward. Global application renames only exact Ghidra-default `DAT_<addr>` labels at the matching address; missing, non-default, rejected-name, and outside-memory candidates are preserved and reported as skips. Pass 2's ownership-aware refresh replaces only `decompiled.c` / `disasm.lst` / `functions.json` and leaves `globals.json`, `global_shapes.json`, `thumb_functions.json`, `thumb/`, and other sidecars byte-for-byte unchanged. `--no-symbol-pass` skips pass 2 entirely: it still writes `globals.json`, but globals remain record-only and `DAT_<addr>` placeholders are not changed in Ghidra. **Phase 2:** Dense Thumb regions in `02_MAIN` are decompiled by Ghidra (tightened `TameAnalysis`). A runtime Surface B watch kills Ghidra on overlap-repair spin and falls back to Phase-1 datamark per image (`thumb_tighten_error`, image not failed). Phase 2.1 closed both dormancy causes: `thumb_enrich` matches by entry address, and `TameAnalysis mode=tighten` carries the winning `TIGHTEN_EXTRA` (`"Non-Returning Functions - Discovered.Repair Flow Damage"`) so Ghidra converges on full `02_MAIN` in ~23 min without Surface B firing. **Historical pre-v3 production — mustang / S5400 (verified full `decompose`, ~1 h 37 m wall, exit 0):** `functions` = 107,955; `thumb_functions` = 117,444; `thumb_decompiled` = 77,456; five `thumb/*.stdout` preserved across pass 2; radare2 4 GiB streaming path did not hit the cap. **Historical pre-v3 second model — cheetah / S5300 (verified, ~84 min, exit 0):** MAIN is `01_MAIN`; `functions` = 104,395; `thumb_functions` = 87,026; `thumb_decompiled` = 70,906; `globals_recovered` = 1,061; one 4 MiB dense-Thumb region hit the 16 GiB radare2 address-space cap and was skipped (the rest decompiled); four images (no PSP/DBGCORE); no RF_CFG blobs, so `decode_rf`/`hardware_config` skipped. Those historical runs wrote v2 with optional per-function `body_c`; fresh output is strict v3 with producer-owned runs and capture provenance. `--no-thumb-decompile` selects Ghidra datamark mode and skips `body_c` enrichment, but host Thumb analysis still emits strict v3. **Phase 3.0:** Global names are recovered from direct string evidence when a function has exactly one non-string `data_ref` and exactly one unique underscored identifier across its referenced strings. The per-image `decompiled/globals.json` is Recovered-only by default and remains the strict evidence source of truth; conflicting names for one address are dropped. In normal `decompose`, eligible Recovered records feed the existing pass 2. **Phase 3.0.1:** Disasm-anchored Recovered globals — a `movw`+`movt` load pair within K=4 load-events of a string load pins that string's identifier as the global's name, regardless of `data_ref` cardinality. On production `02_MAIN` (Thumb through pass 2) `globals_recovered` = **915** (arch: arm 367 / thumb 545 / mixed 3); stage total recovered 921 with 194 conflicts dropped. `--globals-provisional` opts in to additionally emitting name-prior-derived `tier: "provisional"` entries (default off; bare `globals.json` is byte-equivalent to Phase 3.0's for the Recovered set). Provisional records are always record-only and never application candidates. **Phase 3.2:** `decompose` always runs a record-only `global_shapes` stage exactly once per route: on the normal route it now runs right after `globals.json` is written and **before** pass 2, so the recovered shapes are ready for a pass-2 script to consume; on `--no-symbol-pass` (which has no pass 2) it still runs last. It decodes accepted A32/T32 function bytes with the pure-Rust `scaleservers-arm32-assembly` 1.0.0 adapter and writes `decompiled/global_shapes.json` v4 — one record per Recovered global; facts cross direct CFG edges by a must-facts join (every incoming path must agree; join kills counted). `globals.json` is not rewritten. `--prune` retains the sidecar. Each record is `inferred`, `no_evidence`, or `conflicting`; summaries carry only `minimum_size` and a provisional `scalar_candidate` / `array_candidate` / `unknown` label. No exact allocation size or authoritative type is inferred. Quarantined producer records never reach the decoder and are counted separately from accepted-range `decode_failures`. Distinct ARM and Thumb identities may cover the same bytes and remain independent interpretations. **Production (mustang `02_MAIN`):** Recovered shapes 915 MAIN / 921 total; **154 inferred / 761 `no_evidence` / 0 conflicting** under the v3 cross-block engine + same-instruction multi-offset fix (v2-era: 125/787/3 — net +29 recovered shapes, `conflicting` → 0; the v2-era verified run's MAIN observations were 32 ARM + 907 Thumb); `decode_failures` = 37,629 (recoverable; the image still succeeds); `globals.json` unchanged. `decompose` now also runs a **default-on depth-1 interprocedural pass** (direct `bl` only, AAPCS r0–r3) that re-runs the shape tracker inside directly-called functions with the argument register seeded — the seed joins at the callee entry and propagates cross-block by the same must-facts join; it is **record-only and additive-only** (it never demotes an `inferred` global and never produces `conflicting`). The v2-era pass alone yielded **0 new shapes** (the pass-by-reference callees store, not dereference, the pointer); since the v3 engine propagates seeds in-callee, interprocedural evidence grew 3→58 observations — see AGENTS for the mechanism and limitations. Eligible recovered shapes are also **applied**, by default, as Ghidra `undefinedN` types in that same pass 2 — a scalar `inferred` global (width 1/2/4/8) reads in `decompiled.c` as one correctly-sized typed value instead of raw `DAT_` bytes; arrays, `unknown`, `conflicting`, and `no_evidence` shapes are never applied, only counted. `--no-apply-global-types` turns off just this application step — `global_shapes.json` is still produced either way. `--no-symbol-pass` has no pass 2 to apply into, so its `global_shapes.json` never carries applied types regardless of this flag. |
| `source-tree <MAIN_image>` | Reconstruct the firmware source-tree layout from embedded `__FILE__` strings — **names and structure only, not original source**. The input is the MAIN code image; its split name is model-dependent (`02_MAIN` on mustang, `01_MAIN` on cheetah) and the generated labels name whichever image you pass. `--modem <LABEL>` sets the Shannon generation in the generated README (e.g. `S5300`; auto-derived under `decompose`). `--no-attribution`, `--gap`, `--shared-pct`, `--min-run` tune the heuristics. |
| `decode-rf <RF_CFG_dir> --hwcfg <hardware_config.json>` | Semantic decode of the RF_CFG calibration databases (heuristic calibration-vector extraction + per-variant mapping). Default out `./decoded_rf/`. |
| `decode-tokens <pw_token_db>` | Decode the Pigweed `pw_tokenizer` token database to canonical CSV + `summary.json`. Default out `./decoded_tokens/`. |
| `decode-traces <modem.bin>` | Decode the MAIN image's DBT debug-trace catalog (28-byte `DBT:` records) to `debug_traces/`: five catalog tables. `references.json` is published only when function inventories exist (standalone is catalog-only). The input is a `modem.bin` TOC; the tool selects the entry named `MAIN` and binds only a scatter map this run materializes (a leftover `scatter/MAIN` under `--out` is not rebound; a plausible malformed or ambiguous map fails the command). Default out `./decoded_traces/`. |
| `hardware-config <hardware_config.json>` | Structural stats + RF_CFG-coverage summary. `--rf-dir` cross-checks which calibration blobs are actually present. Default out `./hwcfg_summary/`. |
| `decompile <modem.bin>` | Write a Ghidra import kit for all code images at their load addresses (the image set is model-dependent — six on mustang, four on cheetah). For a recognized MAIN, generation validates and emits a runtime scatter map; Ghidra retains the raw mapping and applies those runtime blocks before analysis. No candidate leaves the image raw-only, while a plausible malformed or ambiguous map fails the command. Generation also discovers the PAL task plan semantically (default on): a validated plan publishes `pal_tasks/<label>/tasks.json` and seeds one Ghidra function per task entry before auto-analysis; no initializer is clean absence, and a plausible malformed or ambiguous one fails the command. `--run` drives `analyzeHeadless` (needs a local Ghidra) to export decompiled C, a disassembly listing, and a function inventory; unanimously-opaque images are skipped without spawning Ghidra (`--no-skip-opaque` forces a run); selected images with dense Thumb regions use radare2 primary and, with `--rizin-fallback`, one Rizin attempt after a region failure. The Thumb stage fails if every requested region fails and publishes no new sidecar. `--image`, `--ghidra-home`, `--processor` (default `ARM:LE:32:v7`). `--no-thumb-decompile` selects Ghidra datamark mode and skips `body_c` enrichment; host Thumb analysis and strict-v3 output remain enabled, and every authoritative PAL task function stays code. |
| `symbolicate <decomposed_dir>` | Recover function names + inline log/assert/file annotations from evidence already produced (pw_tokenizer DB, `__func__`, attributed strings), rewriting `decompiled.c`/`disasm.lst`/`functions.json`/`thumb_functions.json` **in place** and emitting `symbols.json`. Tiered + fail-closed (precedence `__func__` > registration > exception-root role > PAL-task role > token > string-ref): `__func__` and `{name,fn}` **registration-table** matches yield authoritative (`Recovered`) renames; architectural/task roles remain durable evidence below firmware-native names; token matches become marked `guess_…` names; strings/files are comments. `--token-db` gives the raw `pw_token_db` (TOKENS); without it, token evidence is skipped. Registration names come from scanning the raw image for handler/dispatch tables (AT-command, protocol) whose pointer resolves to a known function entry — the crown-jewel names (e.g. `AtiParsePlusCOPS`), ~100% precision but a small set (113 mustang / 77 cheetah evidence names on the 2026-08-25 goldens). Also derives lowest-precedence `guess_*` names from a function's uniquely-referenced identifier string (fail-closed: dropped if all-caps, a recovered global, or another function's name), recorded as `string_ref` evidence. It also runs automatically as a `decompose` stage. |
| `tree-hash <dir>` | Print the whole-tree `pme-paq-v1` hash of `<dir>` — one lowercase 64-hex value — and write nothing. Fails closed with no hash printed if the target is missing, not a directory, contains a symlink, or has any non-UTF-8 path component. No external tools. |
| `unpack-fbpk <radio.img>` | Lower-level: emit `modem.ext4` (a partial-pipeline shortcut — currently runs the full `extract` under the hood). |
| `split-toc <modem.bin>` | Lower-level: split a `modem.bin` into its TOC images (stage 5 of `extract`). |

Both `decompile` and `decompose` always perform architectural exception-root discovery for every
embedded image before image filtering or opaque skipping; there is no feature flag. A validated
image adds the authenticated manifest and, when Ghidra runs, seeds its exact ARM/Thumb roots before
auto-analysis using the ordering and currentness contract described above. `decompile` keeps the
standalone manifest under `exception_roots/<label>/`, while `decompose` publishes the terminal copy
under `images/<label>/exception_roots/` and reports generation separately from application.

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

`decompile` writes a standalone Ghidra import kit. Any image with validated architectural roots adds
`exception_roots/<label>/roots.json`. A MAIN with one validated runtime map adds:

    scatter/<label>/load_map.json
    scatter/<label>/blocks/<entry>-<operation>.bin

and a MAIN with a validated PAL task plan adds `pal_tasks/<label>/tasks.json` (see Formats). These
are wired into `ghidra_load.json`: each image can gain optional `exception_root_map`; a recognized
MAIN can additionally gain optional `runtime_load_map` and `pal_task_map`. Images without a given
artifact omit its field.

The manifest is the auditable map; payload files exist only for materialized copy or nonzero
`decompress1` outputs. Zero-filled outputs and self-copies remain compact manifest entries.

`decompose` writes (default `./<img>.decomposed/`; this shows the unpruned tree):

    radio.decomposed/
    ├── images/
    │   ├── 00_BOOT/decompiled/       # decompiled.c, disasm.lst, functions.json, symbols.json, globals.json, global_shapes.json
    │   ├── 01_PSP/decompiled/
    │   ├── 02_MAIN/
    │   │   ├── decompiled/           # …+ strict-v3 thumb_functions.json, thumb/ captures, symbols.json, globals.json, global_shapes.json
    │   │   ├── source_tree/          # reconstructed tree + recovered_index.json (MAIN image only)
    │   │   ├── scatter/              # load_map.json + blocks/; retained by --prune (MAIN when recognized)
    │   │   ├── exception_roots/      # roots.json when validated; retained by --prune (any image)
    │   │   ├── pal_tasks/            # tasks.json; retained by --prune (MAIN when recognized)
    │   │   └── debug_traces/         # five catalog tables + separately published references.json
    │   ├── 03_APM/decompiled/
    │   ├── 04_VSS/decompiled/
    │   └── 05_DBGCORE/decompiled/
    ├── rf/                           # decoded/  +  hwcfg_summary/  (only when the model ships RF_CFG)
    ├── tokens/                       # pw_token_db.csv + summary.json
    ├── manifest.json
    ├── ghidra/symbol_maps/           # per-image symbol_map.json (intermediate input to pass 2)
    └── report.json                   # includes modem_generation (e.g. "S5300"/"S5400")

The `images/` set above is the mustang (S5400) layout. The image set and the MAIN dir are
model-dependent: cheetah (S5300) has `00_BOOT 01_MAIN 02_VSS 03_APM`, with `source_tree/` under
`01_MAIN`. A recognized map lives at `images/<MAIN>/scatter/`, a validated exception plan at
`images/<label>/exception_roots/roots.json` for whichever image proved one, a validated PAL plan at
`images/<MAIN>/pal_tasks/tasks.json`, and a published debug-trace catalog at
`images/<MAIN>/debug_traces/` on either model; all four terminal surfaces survive `--prune`. `rf/`
appears only when the model ships RF_CFG blobs (cheetah has none). Pruning retains
`thumb_functions.json` but removes `decompiled/thumb/` captures and carved inputs.

`report.json` keeps its top-level `ghidra` object. It always records `headless`, `radare2`,
`radare2_version`, and boolean `rizin_fallback`; enabled runs additionally record `rizin` and
`rizin_version`, even when no failed region needed Rizin. Per analyzed image, a current Thumb
run reports `thumb_regions_requested`, `thumb_regions_succeeded`, `thumb_regions_failed`,
`thumb_radare2_runs`, and `thumb_rizin_runs`; a seeded PAL plan reports `pal_applied`
(`tasks`, `entries`, `functions_created`, `functions_existing`, `names_applied`,
`names_preserved`, `shared_entries`) and `decompose` adds the per-image `pal_tasks` counter.
The adjacent `exception_roots` stage follows `decompile` and precedes `pal_tasks`; it tallies
terminal manifests, tables, and roots after reauthentication. A completed Ghidra application emits
the all-or-none per-image fields `exception_tables`, `exception_roles`, `exception_roots`,
`exception_functions_created`, `exception_functions_reapplied`,
`exception_functions_existing`, `exception_names_applied`, `exception_names_reapplied`,
`exception_names_preserved`, `exception_names_not_requested`, and `exception_shared_entries`.
Omitted means application was not invoked/current; `0` means it ran and produced zero in that
category. Reason-only `exception_error` is exclusive with every numeric exception field. Generation
and application are intentionally separate, so an opaque-skipped image may contribute to the stage
tally while carrying no application fields.
A built pass-2 function map reports `pass2_creation_candidates` and the nested
`pass2_creation_map_skips`; an invoked `ApplyThumbNames` additionally reports
`pass2_created`, `pass2_creation_reapplied`, `pass2_creation_skipped_existing`, and
`pass2_creation_skipped_collision`. Those four runtime counts must sum to the candidate count.
Creation runs before every other pass-2 mutation so malformed producer or ownership state cannot
follow another mutation. Ghidra disassembles only inside each authenticated address set, passes the
explicit returned set to `CreateFunctionCmd`, and rejects a final body outside those ranges.
Persistent ownership is stored in
`PixelModemExtractor.ThumbNames.v1.Ownership` as
`v1:<map_blake3>:<producer_execution_blake3>:<function_id>:<primary_symbol_id>:<ghidra_execution_blake3>`.
Ghidra rolls back earlier post-scripts when a later script fails in the same headless invocation.
A separately committed `ApplyThumbNames`-only staged state is accepted only by an identical retry,
which must fully revalidate it before reporting `reapplied`. A missing, malformed, wrong-image, or
non-conserving summary fails `decompile_pass2` and publishes no replacement export. Rust terminal validation
accounts for newly created and owned-replayed functions against the pass-1 producer baseline,
publishes exactly `decompiled.c`, `disasm.lst`, and `functions.json` while preserving sidecars, and
refreshes current inventory/report counters from the committed summary.
A published MAIN catalog reports the all-or-none `dbt_*` group (`dbt_records`,
`dbt_files`, `dbt_messages`, `dbt_quarantined`, `dbt_unresolved_messages`,
`dbt_references`, `dbt_refs_producers`): omitted means the `debug_traces` /
`debug_traces_refs` stages did not run; `0` means they ran with zero results.
Those two stage rows sit between `thumb_enrich` and `source_tree`.
The v3 sidecar, rather than the report's configured tool list, is the source of truth for
producers actually attempted and functions they own.

Failure reporting distinguishes its stages. `exit` appears only for an `analyzeHeadless` process
failure. When Ghidra completes but the terminal execution inventory or the current-run Thumb
validation rejects the export, the image is `failed` with no `exit` and a reason-only
`terminal_error`; if the Thumb sidecar was the stage that rejected it, `thumb_error` carries a
reason too. A stale or failed Thumb result is therefore never reported as "Ghidra failed".
Top-level `prune_requested` records whether `--prune` was asked for and `pruned` whether the
leaves-only sweep actually completed — a failed sweep also records a failed `prune` stage.

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
- **Architectural exception-root manifest** — `pixel-modem-extractor-exception-roots-v1`: the
  authenticated canonical manifest for one image's complete initial exception-vector table and any
  semantically proven VBAR relocation, written at `exception_roots/<label>/roots.json`
  (`images/<label>/exception_roots/roots.json` under `decompose`, retained by `--prune`). It binds the
  raw image, optional scatter load map, supported slot instructions and literal targets, root entry
  bytes/ISA/storage, role relationships, and deterministic Ghidra application groups. Its external
  identity is `v1:<manifest-blake3>:<tables>:<roots>`. Ghidra applies it transactionally before
  auto-analysis and records concrete function, primary-symbol, and role-label ownership; the v4
  export marker binds the same identity as `exception_roots=<identity>`. Strict readers and Ghidra
  postflight rederive all identities and reject stale or partial state. After pass-1 terminal
  marshalling completes, and immediately before symbol-map construction, `decompose` builds at most
  one immutable per-image pass-2 input snapshot gated by the exact completed marshal outcomes. It
  retained-copies the exact raw image, complete optional scatter artifact (including every referenced
  `blocks/*.bin` payload), and current exception/PAL manifests into the existing Ghidra kit once,
  then derives both strict application contexts from that one runtime. It is not a snapshot of
  post-pass-2 output. Symbol maps bind these input identities. After invalidating stale exports, the
  host revalidates the complete snapshot and map binding immediately before spawning Ghidra; drift
  blocks the process and leaves no old export current. `report.json` carries one
  adjacent `exception_roots` stage plus an all-or-none per-image application-counter group; a
  reason-only `exception_error` is exclusive with those counters.
- **PAL task manifest** — `pixel-modem-extractor-pal-tasks-v1`: the authenticated canonical
  manifest of one validated PAL task plan, written at `pal_tasks/<label>/tasks.json`
  (`images/<MAIN>/pal_tasks/tasks.json` under `decompose`). It binds the image identity (BLAKE3),
  the runtime view (the scatter load-map BLAKE3 it was validated against, plus the sorted unique
  scatter entries used), the complete initializer proof (CFG entry, anchors, references, loop,
  exits, capacity guard, suffix loop, join, count global, and derived geometry), the descriptor
  table (field offsets, stride, capacity, count, terminal slot with its BLAKE3), every task record
  (slot/name/entry fields, ISA, entry-instruction BLAKE3, storage provenance, and the allocated
  label), and the application groups that partition tasks by normalized `(entry, ISA)` with their
  desired primaries and role labels. Its identity is exactly
  `v1:<manifest-blake3>:<task-records>:<distinct-entries>`, and the Ghidra export completion marker
  binds it (`pal_tasks=<identity>`). Readers re-validate the image, scatter dependency, hashes,
  and label-allocation policy; stale, tampered, or partially applied state is a hard failure, never
  silently reused.
- **debug_traces** (`pixel-modem-extractor-debug-traces-v1`) — the authenticated catalog of one
  MAIN image's 28-byte `DBT:` records, written at `debug_traces/` (standalone `decode-traces`)
  or `images/<MAIN>/debug_traces/` under `decompose` (retained by `--prune`). Five tables share
  one envelope (`format`, `schema_version: 1`, `tool_version`, image identity): `manifest.json`,
  `files.json`, `messages.json`, `records.json`, `quarantine.json`. A lookalike is noise until
  the scan threshold: the complete 28-byte record is byte-backed, word 7 resolves to a
  NUL-terminated source path that satisfies the shared `is_src_path` classifier, and word 6
  (source line) is in `1..=1048575`. Below threshold is silently dropped. A candidate that then
  fails a message-pointer invariant is quarantined with a typed reason (`message_unterminated`,
  `message_over_cap`, `message_invalid_bytes`, `pointer_wrap`); crossing 4,096 quarantined
  records fails the stage. Message charset is printable ASCII `0x20..=0x7e` plus `\t`/`\n`/`\r`.
  An unmapped or scatter-zero message pointer is not a violation — it publishes as
  `{"unresolved": {"pointer": "0x…", "storage": "unmapped"|"scatter_zero"}}`. Catalog identity
  is `v1:<manifest-blake3>:<records>:<files>:<messages>`. Strict readers re-validate envelope,
  hashes, ordering, and identity; stale or tampered state is a hard failure.
- **debug-trace-refs-v1** (`pixel-modem-extractor-debug-trace-refs-v1`) — separately published
  `references.json` inside the catalog directory. The envelope binds the catalog
  `manifest_blake3` + `identity`, the image blake3, `functions_blake3`, optional
  `thumb_functions_blake3`, and the reference count. Rows attribute record-address
  materializations (`movw_movt`, `literal_load`, `pc_relative`) to producer-identified
  functions. The refs file regenerates independently of the catalog; a refs failure removes
  `references.json` and leaves the catalog current. Standalone `decode-traces` publishes the
  catalog only.
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
- **thumb_functions.json** — fresh output is strict
  `pixel-modem-extractor-thumb-functions-v3`: producer identities, requested regions, ordered
  attempts, capture provenance, contiguous producer-owned function runs, then normalized
  functions. `end` is the backend's exclusive `maxaddr`/`maxbound`, `size` is positive `realsz`,
  and each authoritative executable `decode_range` has ordered `isa`, `start`, `end`, and `blake3`
  fields. v1/v2 remain legacy readable, read-only inputs.
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
  AGENTS for the mechanism and the measured yield on the reference
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
[`AGENTS.md`](AGENTS.md).

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
