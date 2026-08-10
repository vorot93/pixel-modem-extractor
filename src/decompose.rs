//! `decompose` — the exhaustive one-command pipeline. Runs extraction, decompiles
//! every modem image (Ghidra + radare2), and runs every decoder, marshaling all
//! outputs into one per-image tree with a machine-readable `report.json`. Best-effort:
//! a stage failure is recorded and the run continues; the process exits non-zero if
//! anything failed. `--prune` reduces the tree to only the terminal ("leaf") artifacts.

use crate::decompile::{self, ImageOutcome};
use crate::error::{Error, Result};
use crate::{
    decode_rf, globals, hwcfg, manifest, pipeline, recover_source, source_tree, symbolicate, tokens,
};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Opts {
    pub no_verify: bool,
    pub prune: bool,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
    /// Skip the Phase-1 symbolication pass 2 (escape hatch). When true, decompose
    /// uses today's single-pass decompile behavior and emits no symbol_map or
    /// pass-2 artifacts.
    pub no_symbol_pass: bool,
    /// Phase 2 escape hatch: when true, `TameAnalysis` runs in `datamark` mode
    /// (Phase-1 behavior) and `thumb_enrich` does not run for either pass.
    /// The public `--no-thumb-decompile` clap flag wires to this field.
    pub no_thumb_decompile: bool,
    /// Phase 2 / Surface B: test-only override that bypasses
    /// `baseline * wall_clock_multiplier` and supplies an absolute wall-clock
    /// budget for the tighten-watch kill decision. Wired to the hidden
    /// `--tighten-wall-clock-budget-sec` flag. Production callers leave `None`.
    pub tighten_wall_clock_budget_override: Option<std::time::Duration>,
    /// Phase 3.0.1: emit tier:"provisional" globals (name-prior tiebreakers).
    /// Wired to `--globals-provisional`. Off by default; Recovered-tier
    /// globals always emit.
    pub globals_provisional: bool,
    /// Phase 3.0.1 test-only: override the ARM proximity window (`K_ARM`).
    /// Wired to the hidden `--globals-k-arm`. `None` -> use `globals::K_ARM`.
    pub globals_k_arm: Option<usize>,
    /// Phase 3.0.1 test-only: override the Thumb proximity window (`K_THUMB`).
    /// Wired to the hidden `--globals-k-thumb`. `None` -> use `globals::K_THUMB`.
    pub globals_k_thumb: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ImageReport {
    pub image: String,
    pub status: &'static str, // "analyzed" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_functions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass2_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_decompiled: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_tighten_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumb_enrich_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_recovered: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_provisional: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_provisional_suppressed: Option<usize>,
}

impl ImageReport {
    pub fn from_result(r: &decompile::ImageResult) -> Self {
        match r.outcome {
            ImageOutcome::Analyzed(n) => ImageReport {
                image: r.label.clone(),
                status: if r.thumb_error.is_some() {
                    "failed"
                } else {
                    "analyzed"
                },
                functions: Some(n),
                thumb_functions: r.thumb_functions,
                thumb_error: r.thumb_error.clone(),
                exit: None,
                pass2_applied: r.pass2_applied,
                pass2_error: r.pass2_error.clone(),
                thumb_decompiled: r.thumb_decompiled,
                thumb_tighten_error: r.thumb_tighten_error.clone(),
                thumb_enrich_error: r.thumb_enrich_error.clone(),
                globals_error: r.globals_error.clone(),
                globals_recovered: r.globals_recovered,
                globals_provisional: r.globals_provisional,
                globals_provisional_suppressed: r.globals_provisional_suppressed,
            },
            ImageOutcome::Failed(code) => ImageReport {
                image: r.label.clone(),
                status: "failed",
                functions: None,
                thumb_functions: r.thumb_functions,
                thumb_error: r.thumb_error.clone(),
                exit: Some(code),
                pass2_applied: r.pass2_applied,
                pass2_error: r.pass2_error.clone(),
                thumb_decompiled: r.thumb_decompiled,
                thumb_tighten_error: r.thumb_tighten_error.clone(),
                thumb_enrich_error: r.thumb_enrich_error.clone(),
                globals_error: r.globals_error.clone(),
                globals_recovered: r.globals_recovered,
                globals_provisional: r.globals_provisional,
                globals_provisional_suppressed: r.globals_provisional_suppressed,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StageReport {
    pub stage: &'static str,
    pub status: &'static str, // "ok" | "skipped" | "failed"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<ImageReport>,
    pub duration_ms: u128,
}

impl StageReport {
    fn ok(stage: &'static str, output: &str, ms: u128) -> Self {
        StageReport {
            stage,
            status: "ok",
            output: Some(output.to_string()),
            reason: None,
            error: None,
            images: Vec::new(),
            duration_ms: ms,
        }
    }
    fn skipped(stage: &'static str, reason: &str) -> Self {
        StageReport {
            stage,
            status: "skipped",
            output: None,
            reason: Some(reason.to_string()),
            error: None,
            images: Vec::new(),
            duration_ms: 0,
        }
    }
    fn failed(stage: &'static str, error: String, ms: u128) -> Self {
        StageReport {
            stage,
            status: "failed",
            output: None,
            reason: None,
            error: Some(error),
            images: Vec::new(),
            duration_ms: ms,
        }
    }
    fn decompile(images: Vec<ImageReport>, ms: u128) -> Self {
        let any_failed = images.iter().any(|i| i.status == "failed");
        StageReport {
            stage: "decompile",
            status: if any_failed { "failed" } else { "ok" },
            output: Some("images/".to_string()),
            reason: None,
            error: None,
            images,
            duration_ms: ms,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GhidraTools {
    pub headless: String,
    pub radare2: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tool_version: String,
    pub source_image: String,
    pub source_sha256: String,
    pub out: String,
    pub ghidra: GhidraTools,
    pub pruned: bool,
    pub ok: bool,
    pub stages: Vec<StageReport>,
}

impl Report {
    fn is_ok(stages: &[StageReport]) -> bool {
        !stages.iter().any(|s| s.status == "failed")
    }
}

/// Both tools are hard requirements; error before anything is written if either is absent.
fn preflight(headless: Result<PathBuf>, r2: Option<PathBuf>) -> Result<(PathBuf, PathBuf)> {
    let headless = headless?;
    let r2 = r2.ok_or_else(|| {
        Error::ToolNotFound("radare2 (r2) on PATH — required by `decompose`".into())
    })?;
    Ok((headless, r2))
}

/// The single `<out>/rootfs/images/<sub>/` directory `extract` produced.
fn rootfs_image_dir(out: &Path) -> Result<PathBuf> {
    let base = out.join("rootfs").join("images");
    // Guard the read so a wholly-absent base yields a typed NotFound (not a raw Io error),
    // matching the empty-directory case below.
    if base.is_dir() {
        for entry in std::fs::read_dir(&base)? {
            let p = entry?.path();
            if p.is_dir() {
                return Ok(p);
            }
        }
    }
    Err(Error::NotFound(format!(
        "no rootfs image dir under {}",
        base.display()
    )))
}

/// Move one image's decompile artifacts into its unified folder:
///   `<ghidra>/images/<label>`   (slice file) -> `<images>/<label>/<label>.bin`
///   `<ghidra>/export/<label>/`  (export dir)  -> `<images>/<label>/decompiled/`
fn marshal_image(ghidra_dir: &Path, images_dir: &Path, label: &str) -> Result<()> {
    let dest = images_dir.join(label);
    std::fs::create_dir_all(&dest)?;
    let slice = ghidra_dir.join("images").join(label);
    if slice.exists() {
        std::fs::rename(&slice, dest.join(format!("{label}.bin")))?;
    }
    let export = ghidra_dir.join("export").join(label);
    if export.exists() {
        std::fs::rename(&export, dest.join("decompiled"))?;
    }
    Ok(())
}

/// After pass 2, ExportDecomp.java has overwritten {ghidra}/export/{label}/
/// with exactly three files it owns: `decompiled.c`, `disasm.lst`,
/// `functions.json`. Merge those into `images/<label>/decompiled/`, replacing
/// only the three owned paths. Every other destination entry (e.g.
/// `thumb_functions.json`, `thumb/`) is owned by another stage and must remain
/// byte-for-byte unchanged. The slice file (`<label>.bin`) is already in place
/// from pass 1; do not touch it.
fn refresh_decompiled(ghidra_dir: &Path, images_dir: &Path, label: &str) -> Result<()> {
    const OWNED: &[&str] = &["decompiled.c", "disasm.lst", "functions.json"];

    let export = ghidra_dir.join("export").join(label);
    if !export.exists() {
        return Ok(());
    }

    // Validate the full export set before any destination mutation.
    let mut entries = Vec::new();
    for ent in std::fs::read_dir(&export)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy().into_owned();
        let ft = ent.file_type()?;
        if !ft.is_file() {
            return Err(Error::DecomposeIncomplete(format!(
                "invalid pass-2 export for {label}: entry `{name}` is not a regular file"
            )));
        }
        entries.push(name);
    }
    entries.sort();
    let mut expected: Vec<String> = OWNED.iter().map(|s| (*s).to_string()).collect();
    expected.sort();
    if entries != expected {
        return Err(Error::DecomposeIncomplete(format!(
            "invalid pass-2 export for {label}: expected exactly {OWNED:?}, found {entries:?}"
        )));
    }

    let dest = images_dir.join(label).join("decompiled");
    if !dest.exists() {
        // First-time placement (no pass-1 tree): rename the whole validated
        // export directory into place, same as the historical happy path.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&export, &dest)?;
        return Ok(());
    }

    // Destination exists: replace only the three owned files. Sidecars stay put.
    for name in OWNED {
        let from = export.join(name);
        let to = dest.join(name);
        // On Unix rename overwrites an existing file; remove first for
        // portability across platforms where rename refuses to replace.
        if to.exists() {
            std::fs::remove_file(&to)?;
        }
        std::fs::rename(&from, &to)?;
    }
    std::fs::remove_dir(&export)?;
    Ok(())
}

/// Phase 2: run `decompile::thumb_enrich` against each image's
/// `images/<label>/decompiled/{decompiled.c,thumb_functions.json}`. Mutates each
/// `ImageResult.thumb_decompiled` (count) or `thumb_enrich_error` (failure text)
/// in place. Returns the per-image outcome so the caller can build a StageReport.
///
/// Missing `thumb_functions.json`:
/// - `thumb_functions == None` → legitimate "no Thumb regions"; skip silently.
/// - `thumb_functions == Some(_)` → radare2 reported Thumb output but the JSON
///   is gone (e.g. destroyed by a buggy pass-2 refresh); record
///   `thumb_enrich_error` and a stage error so the loss cannot go green.
fn run_thumb_enrich_per_image(
    images: &mut [decompile::ImageResult],
    images_dir: &Path,
) -> ThumbEnrichOutcome {
    let mut outcome = ThumbEnrichOutcome::default();
    for ir in images {
        let label = &ir.label;
        let decompiled_c = images_dir
            .join(label)
            .join("decompiled")
            .join("decompiled.c");
        let thumb_json = images_dir
            .join(label)
            .join("decompiled")
            .join("thumb_functions.json");
        if !thumb_json.exists() {
            if ir.thumb_functions.is_some() {
                let msg = "thumb_functions.json missing after radare2 reported Thumb functions"
                    .to_string();
                ir.thumb_enrich_error = Some(msg.clone());
                outcome.errors.push((label.clone(), msg));
            }
            continue;
        }
        match decompile::thumb_enrich(&decompiled_c, &thumb_json) {
            Ok(n) => {
                ir.thumb_decompiled = Some(n);
                outcome.counts.push((label.clone(), n));
            }
            Err(e) => {
                let msg = format!("{e:#}");
                ir.thumb_enrich_error = Some(msg.clone());
                outcome.errors.push((label.clone(), msg));
            }
        }
    }
    outcome
}

/// Per-image outcome of a `thumb_enrich` sweep.
#[derive(Default)]
struct ThumbEnrichOutcome {
    errors: Vec<(String, String)>,
    counts: Vec<(String, usize)>,
}

/// Build a `thumb_enrich` StageReport from the per-image loop output.
fn thumb_enrich_stage(
    stage: &'static str,
    outcome: ThumbEnrichOutcome,
    duration_ms: u128,
) -> StageReport {
    let ThumbEnrichOutcome { errors, counts } = outcome;
    StageReport {
        stage,
        status: if errors.is_empty() { "ok" } else { "failed" },
        output: Some(format!("{} image(s) enriched", counts.len())),
        reason: None,
        error: errors.first().map(|(_, e)| e.clone()),
        images: Vec::new(),
        duration_ms,
    }
}

/// Refresh the last `decompile` stage's per-image entries from the current
/// `ImageResult` slice. Used after `thumb_enrich` (pass 1 and post-pass-2)
/// mutates each `ImageResult`'s Phase 2 fields (`thumb_decompiled`,
/// `thumb_enrich_error`) so the report surfaces the post-enrich state rather
/// than the pre-enrich snapshot captured when the `decompile` StageReport was
/// first pushed. Preserves the stage's other fields (status, duration_ms,
/// output, etc.).
fn refresh_decompile_stage_images(stages: &mut [StageReport], images: &[decompile::ImageResult]) {
    let Some(pos) = stages.iter().rposition(|s| s.stage == "decompile") else {
        return;
    };
    stages[pos].images = images.iter().map(ImageReport::from_result).collect();
}

/// Phase 3.0 helper: load Phase 1's `symbols.json` and build a lookup map
/// from function entry address (canonical: lowercase hex, no `0x`, no
/// leading zeros) to recovered name. Used to enrich `globals::run`'s
/// evidence with `recovered_name`. Returns an empty map if `symbols.json`
/// is absent or unreadable (defensive — globals stage degrades gracefully).
fn load_recovered_function_names(symbols_path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(bytes) = std::fs::read(symbols_path) else {
        return out;
    };
    let Ok(v): std::result::Result<serde_json::Value, _> = serde_json::from_slice(&bytes) else {
        return out;
    };
    let Some(symbols) = v.get("symbols").and_then(|s| s.as_array()) else {
        return out;
    };
    for sym in symbols {
        let Some(addr_str) = sym.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let Some(canonical) = canonical_function_address(addr_str) else {
            continue;
        };
        if let Some(name) = sym.get("name").and_then(|n| n.as_str()) {
            out.insert(canonical, name.to_string());
        }
    }
    out
}

/// Canonicalize a function address exactly as the `symbols.json` loader does:
/// strip a lowercase `0x` prefix, parse hexadecimal, then format as lowercase
/// hexadecimal without a prefix or leading zeroes.
fn canonical_function_address(address: &str) -> Option<String> {
    let addr = u64::from_str_radix(address.trim_start_matches("0x"), 16).ok()?;
    Some(format!("{addr:x}"))
}

/// Remove a file or directory if present; a missing path is not an error.
fn remove_any(path: &Path) -> Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Leaves-only sweep: drop every intermediate, keep terminal artifacts + report/manifest.
fn prune(out: &Path) -> Result<()> {
    remove_any(&out.join("modem.ext4"))?;
    remove_any(&out.join("rootfs"))?;
    remove_any(&out.join("rf_cfg_decompressed"))?;
    remove_any(&out.join("ghidra"))?;
    let images = out.join("images");
    if images.is_dir() {
        for entry in std::fs::read_dir(&images)? {
            let dir = entry?.path();
            if dir.is_dir()
                && let Some(label) = dir.file_name().and_then(|n| n.to_str())
            {
                remove_any(&dir.join(format!("{label}.bin")))?;
            }
        }
    }
    Ok(())
}

/// Run a `Result<PathBuf>`-returning stage, recording ok/failed with timing.
fn run_stage(
    stages: &mut Vec<StageReport>,
    name: &'static str,
    output: &str,
    f: impl FnOnce() -> Result<PathBuf>,
) {
    let t = Instant::now();
    match f() {
        Ok(_) => stages.push(StageReport::ok(name, output, t.elapsed().as_millis())),
        Err(e) => stages.push(StageReport::failed(
            name,
            e.to_string(),
            t.elapsed().as_millis(),
        )),
    }
}

/// Write `report.json`; return its path on full success, or `Err` if any stage failed.
fn finalize(
    out: &Path,
    img: &Path,
    opts: &Opts,
    headless: &Path,
    r2: &Path,
    stages: Vec<StageReport>,
) -> Result<PathBuf> {
    let ok = Report::is_ok(&stages);
    let report = Report {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        source_image: img.display().to_string(),
        source_sha256: manifest::sha256_file(img).unwrap_or_default(),
        out: out.display().to_string(),
        ghidra: GhidraTools {
            headless: headless.display().to_string(),
            radare2: r2.display().to_string(),
        },
        pruned: opts.prune,
        ok,
        stages,
    };
    let path = out.join("report.json");
    let json =
        serde_json::to_string_pretty(&report).map_err(|e| Error::Serialize(e.to_string()))?;
    std::fs::write(&path, json)?;
    if ok {
        Ok(path)
    } else {
        Err(Error::DecomposeIncomplete(format!(
            "one or more stages failed; see {}",
            path.display()
        )))
    }
}

/// A successfully written function symbol map and the canonical name index
/// retained for downstream orchestration.
struct PreparedFunctionMap {
    map_path: PathBuf,
    named_count: usize,
    function_names: HashMap<String, String>,
}

type FunctionNameIndexes = HashMap<String, HashMap<String, String>>;

/// A successfully written globals map retained for pass-2 application.
#[allow(
    dead_code,
    reason = "Task 4 consumes these retained map inputs after ApplyGlobals lands."
)]
struct PreparedGlobalMap {
    map_path: PathBuf,
    recovered_count: usize,
}

/// One complete globals sweep: typed pass-2 inputs and the aggregate report.
struct GlobalsStageOutcome {
    maps: HashMap<String, PreparedGlobalMap>,
    stage: StageReport,
}

/// Per-image symbol map outcome from [`build_and_write_symbol_maps`]: the
/// successful `(label, prepared map)` entries plus any per-image errors.
type SymbolMapsResult = (HashMap<String, PreparedFunctionMap>, Vec<(String, String)>);

/// Prepare the in-memory result for a function symbol map that was written from
/// `symbols`. Every non-null name is retained regardless of tier; malformed
/// addresses are excluded with the same acceptance rules as `symbols.json`.
fn prepare_function_map(map_path: PathBuf, symbols: &[symbolicate::Symbol]) -> PreparedFunctionMap {
    let named_count = symbols
        .iter()
        .filter(|symbol| symbol.name.is_some())
        .count();
    let function_names = symbols
        .iter()
        .filter_map(|symbol| {
            let name = symbol.name.as_ref()?;
            let address = canonical_function_address(&symbol.address)?;
            Some((address, name.clone()))
        })
        .collect();
    PreparedFunctionMap {
        map_path,
        named_count,
        function_names,
    }
}

fn prepare_function_name_indexes(
    function_maps: &HashMap<String, PreparedFunctionMap>,
) -> FunctionNameIndexes {
    function_maps
        .iter()
        .map(|(label, prepared)| (label.clone(), prepared.function_names.clone()))
        .collect()
}

fn load_finalized_function_name_indexes(
    images_dir: &Path,
    images: &[decompile::ImageResult],
) -> FunctionNameIndexes {
    images
        .iter()
        .map(|image| {
            let symbols_path = images_dir
                .join(&image.label)
                .join("decompiled")
                .join("symbols.json");
            (
                image.label.clone(),
                load_recovered_function_names(&symbols_path),
            )
        })
        .collect()
}

fn run_globals_stage_with<F>(
    images: &mut [decompile::ImageResult],
    images_dir: &Path,
    manifest: &Path,
    function_name_indexes: &FunctionNameIndexes,
    opts: &globals::GlobalsOpts,
    mut run_image: F,
) -> GlobalsStageOutcome
where
    F: FnMut(
        &Path,
        &str,
        &Path,
        &HashMap<String, String>,
        &globals::GlobalsOpts,
    ) -> Result<globals::GlobalsReport>,
{
    let started = Instant::now();
    let mut maps = HashMap::new();
    let mut errors: Vec<(String, String)> = Vec::new();
    let mut counts: Vec<(String, usize)> = Vec::new();
    let mut conflicts = 0usize;
    let mut provisional_total = 0usize;
    let mut provisional_suppressed_total = 0usize;
    let empty_names = HashMap::new();

    for image in images {
        let label = image.label.clone();
        let image_dir = images_dir.join(&label);
        if !image_dir.join(format!("{label}.bin")).exists() {
            continue;
        }
        let names = function_name_indexes.get(&label).unwrap_or(&empty_names);
        match run_image(&image_dir, &label, manifest, names, opts) {
            Ok(report) => {
                image.globals_recovered = Some(report.recovered_count);
                image.globals_provisional = Some(report.provisional_generated);
                image.globals_provisional_suppressed =
                    Some(report.provisional_suppressed_by_recovered);
                conflicts += report.conflicts_dropped;
                provisional_total += report.provisional_generated;
                provisional_suppressed_total += report.provisional_suppressed_by_recovered;
                counts.push((label.clone(), report.recovered_count));
                if report.recovered_count > 0 {
                    maps.insert(
                        label,
                        PreparedGlobalMap {
                            map_path: image_dir.join("decompiled").join("globals.json"),
                            recovered_count: report.recovered_count,
                        },
                    );
                }
            }
            Err(error) => {
                let message = format!("{error:#}");
                image.globals_error = Some(message.clone());
                errors.push((label, message));
            }
        }
    }

    let recovered_total: usize = counts.iter().map(|(_, count)| count).sum();
    let stage = StageReport {
        stage: "globals",
        status: if errors.is_empty() { "ok" } else { "failed" },
        output: Some(format!(
            "{} image(s) processed; {} recovered globals total; {} conflicts dropped; \
             {} provisional generated ({} suppressed by Recovered)",
            counts.len(),
            recovered_total,
            conflicts,
            provisional_total,
            provisional_suppressed_total,
        )),
        reason: None,
        error: errors.first().map(|(_, error)| error.clone()),
        images: Vec::new(),
        duration_ms: started.elapsed().as_millis(),
    };

    GlobalsStageOutcome { maps, stage }
}

fn run_globals_stage(
    images: &mut [decompile::ImageResult],
    images_dir: &Path,
    manifest: &Path,
    function_name_indexes: &FunctionNameIndexes,
    opts: &globals::GlobalsOpts,
) -> GlobalsStageOutcome {
    run_globals_stage_with(
        images,
        images_dir,
        manifest,
        function_name_indexes,
        opts,
        globals::run,
    )
}

/// Build the per-image symbol map from pass-1 outputs and write each to
/// `<out>/ghidra/symbol_maps/<label>.json`. Returns `(successes, errors)`:
/// each success is `(label, PreparedFunctionMap)`; each error is `(label,
/// message)`. Surfaces
/// I/O / parse failures (token DB, build_map, write_symbol_map) so the caller
/// can distinguish "no symbols recovered" from "stage errored" — the previous
/// all-`unwrap_or_default` / `.is_ok()` shape silently swallowed real failures
/// into a benign-looking `symbol_map: skipped`.
fn build_and_write_symbol_maps(
    out: &Path,
    images_dir: &Path,
    token_db: &Path,
    manifest: &Path,
) -> SymbolMapsResult {
    let mut errors: Vec<(String, String)> = Vec::new();
    let tokens = if token_db.exists() {
        match std::fs::read(token_db)
            .map_err(|e| e.to_string())
            .and_then(|b| crate::tokens::parse(&b).map_err(|e| e.to_string()))
        {
            Ok(db) => symbolicate::token_map(&db),
            Err(msg) => {
                errors.push((
                    "<token_db>".to_string(),
                    format!("failed to load token db {}: {msg}", token_db.display()),
                ));
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };
    let maps_dir = out.join("ghidra").join("symbol_maps");
    if let Err(e) = std::fs::create_dir_all(&maps_dir) {
        // Without the maps dir we can't write anything; record once and bail.
        errors.push(("<maps_dir>".into(), format!("create_dir_all: {e}")));
        return (HashMap::new(), errors);
    }
    let mut out_maps = HashMap::new();
    let entries = match std::fs::read_dir(images_dir) {
        Ok(e) => e,
        Err(e) => {
            errors.push((
                "<images_dir>".into(),
                format!("read_dir {}: {e}", images_dir.display()),
            ));
            return (out_maps, errors);
        }
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let Some(label) = dir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        if !dir.join("decompiled").join("functions.json").exists() {
            continue;
        }
        let funcs_sha = std::fs::read(dir.join("decompiled").join("functions.json"))
            .ok()
            .map(|b| crate::manifest::sha256_bytes(&b))
            .unwrap_or_default();
        let image_sha = std::fs::read(dir.join(format!("{label}.bin")))
            .ok()
            .map(|b| crate::manifest::sha256_bytes(&b))
            .unwrap_or_default();
        let symbols = match symbolicate::build_map(&dir, &label, &tokens, manifest) {
            Ok(s) => s,
            Err(e) => {
                errors.push((label.clone(), format!("build_map: {e}")));
                continue;
            }
        };
        let map_path = maps_dir.join(format!("{label}.json"));
        if let Err(e) =
            symbolicate::write_symbol_map(&map_path, &label, &symbols, &image_sha, &funcs_sha)
        {
            errors.push((label.clone(), format!("write_symbol_map: {e}")));
            continue;
        }
        out_maps.insert(label, prepare_function_map(map_path, &symbols));
    }
    (out_maps, errors)
}

/// Exhaustive pipeline into one per-image tree. Ghidra + radare2 required (probed
/// first). Best-effort across stages; writes `report.json`; `Err` if any stage failed.
pub fn run(img: &Path, opts: &Opts, out: &Path) -> Result<PathBuf> {
    // 1. Preflight — both tools required, before anything is written.
    let (headless, r2) = preflight(
        decompile::find_headless(opts.ghidra_home.as_deref()).map(|g| g.headless),
        decompile::find_radare2(),
    )?;
    std::fs::create_dir_all(out)?;
    let mut stages: Vec<StageReport> = Vec::new();

    // 2. Extract.
    let t = Instant::now();
    match pipeline::extract(img, out, !opts.no_verify) {
        Ok(_) => {
            let _ = std::fs::remove_dir_all(out.join("modem.bin.split")); // superseded by images/
            stages.push(StageReport::ok(
                "extract",
                "manifest.json",
                t.elapsed().as_millis(),
            ));
        }
        Err(e) => {
            stages.push(StageReport::failed(
                "extract",
                e.to_string(),
                t.elapsed().as_millis(),
            ));
            return finalize(out, img, opts, &headless, &r2, stages); // nothing to analyze
        }
    }
    let rootfs = match rootfs_image_dir(out) {
        Ok(p) => p,
        Err(e) => {
            stages.push(StageReport::failed("locate_rootfs", e.to_string(), 0));
            return finalize(out, img, opts, &headless, &r2, stages);
        }
    };
    let modem_bin = rootfs.join("modem.bin");
    let images_dir = out.join("images");

    // 3. Decompile pass 1 (analyze + inventory + initial decompiled.c) into
    //    out/ghidra, then marshal into per-image folders.
    let t = Instant::now();
    let ghidra_dir = out.join("ghidra");
    let dopts = decompile::Opts {
        run: true,
        image: None,
        ghidra_home: opts.ghidra_home.clone(),
        processor: opts.processor.clone(),
        no_thumb_decompile: opts.no_thumb_decompile,
        tighten_wall_clock_budget_override: opts.tighten_wall_clock_budget_override,
    };
    let mut pass1_report = match decompile::run_report(&modem_bin, &dopts, &ghidra_dir) {
        Ok(rep) => {
            let mut image_reports = Vec::new();
            let mut marshal_err = None;
            for ir in &rep.images {
                if let Err(e) = marshal_image(&ghidra_dir, &images_dir, &ir.label) {
                    marshal_err = Some(e.to_string());
                    break;
                }
                image_reports.push(ImageReport::from_result(ir));
            }
            match marshal_err {
                None => stages.push(StageReport::decompile(
                    image_reports,
                    t.elapsed().as_millis(),
                )),
                Some(err) => stages.push(StageReport::failed(
                    "decompile",
                    format!("marshal: {err}"),
                    t.elapsed().as_millis(),
                )),
            }
            Some(rep)
        }
        Err(e) => {
            stages.push(StageReport::failed(
                "decompile",
                e.to_string(),
                t.elapsed().as_millis(),
            ));
            None
        }
    };

    // 3b. Phase 2 — thumb_enrich (pass 1). Pure-Rust pass over each image's
    //     pass-1 `decompiled.c` to populate `body_c` in `thumb_functions.json`.
    //     Skipped entirely when `--no-thumb-decompile` is set (Stage 10 wires
    //     the public flag; today it defaults to false). Mutates `pass1_report`
    //     in place so the counts flow into the pass-2 input.
    if opts.no_thumb_decompile {
        stages.push(StageReport::skipped("thumb_enrich", "--no-thumb-decompile"));
    } else if let Some(rep) = pass1_report.as_mut() {
        let enrich_started = Instant::now();
        let outcome = run_thumb_enrich_per_image(&mut rep.images, &images_dir);
        stages.push(thumb_enrich_stage(
            "thumb_enrich",
            outcome,
            enrich_started.elapsed().as_millis(),
        ));
        // Refresh the decompile stage's per-image reports with Phase 2 fields
        // (`thumb_decompiled` / `thumb_enrich_error`). Without this refresh,
        // the decompile StageReport carries the pre-enrich snapshot and the
        // Phase 2 headline metric is invisible in report.json — `thumb_enrich`
        // populated 80k+ body_c on production but the count never surfaced
        // (found during Phase 2.1 followup verification on a real `02_MAIN`
        // under `--no-symbol-pass`). Mirrors the post-pass-2 refresh below.
        refresh_decompile_stage_images(&mut stages, &rep.images);
    } else {
        // Pass 1 failed entirely (no pass1_report). Record explicit skipped
        // entries so the report shape stays predictable. The post-pass-2
        // enrich is also unreachable here; record it once. (When
        // --no-symbol-pass is also set, step 7 records thumb_enrich_post_pass2
        // with "--no-symbol-pass" — guard to avoid a duplicate entry.)
        stages.push(StageReport::skipped("thumb_enrich", "pass 1 failed"));
        if !opts.no_symbol_pass {
            stages.push(StageReport::skipped(
                "thumb_enrich_post_pass2",
                "pass 1 failed",
            ));
        }
    }

    // 4. Source tree — 02_MAIN only.
    let main_bin = images_dir.join("02_MAIN").join("02_MAIN.bin");
    if main_bin.exists() {
        let st_out = images_dir.join("02_MAIN").join("source_tree");
        let st_opts = source_tree::Opts {
            no_attribution: false,
            gap: 4,
            shared_pct: 0.05,
            min_run: 3,
        };
        run_stage(
            &mut stages,
            "source_tree",
            "images/02_MAIN/source_tree",
            || source_tree::run(&main_bin, &st_out, &st_opts),
        );
    } else {
        stages.push(StageReport::skipped("source_tree", "no 02_MAIN image"));
    }

    let source_tree_dir = images_dir.join("02_MAIN").join("source_tree");
    let decompiled_dir = images_dir.join("02_MAIN").join("decompiled");
    if source_tree_dir.join("manifest.json").exists()
        && source_tree_dir.join("tree").is_dir()
        && decompiled_dir.join("functions.json").exists()
        && decompiled_dir.join("decompiled.c").exists()
    {
        run_stage(
            &mut stages,
            "source_attribution",
            "images/02_MAIN/source_tree/recovered_index.json",
            || {
                recover_source::run(
                    &source_tree_dir,
                    &decompiled_dir,
                    &source_tree_dir.join("recovered_index.json"),
                    &recover_source::Opts::default(),
                )
            },
        );
    } else {
        stages.push(StageReport::skipped(
            "source_attribution",
            "no 02_MAIN source tree or decompiler artifacts",
        ));
    }

    // 5. decode_tokens — MOVED EARLIER (Phase 1) so the symbol map can use it.
    let token_db = rootfs.join("pw_token_db");
    if token_db.exists() {
        run_stage(&mut stages, "decode_tokens", "tokens", || {
            tokens::run(&token_db, &out.join("tokens"))
        });
    } else {
        stages.push(StageReport::skipped("decode_tokens", "no pw_token_db"));
    }

    // 6. Build the per-image symbol map from pass-1 outputs + attribution +
    //    tokens. Writes <out>/ghidra/symbol_maps/<label>.json per image.
    let t = Instant::now();
    let (function_maps, symbol_map_errors) = if opts.no_symbol_pass {
        (HashMap::new(), Vec::new())
    } else {
        build_and_write_symbol_maps(out, &images_dir, &token_db, &out.join("manifest.json"))
    };
    if opts.no_symbol_pass {
        stages.push(StageReport::skipped("symbol_map", "--no-symbol-pass"));
    } else {
        let total: usize = function_maps
            .values()
            .map(|prepared| prepared.named_count)
            .sum();
        // Real failures surface as a `failed` stage (the prior shape collapsed
        // them into `skipped, "no symbols recovered"` — a violation of the
        // fail-closed posture). If there are successes we still report `ok` so
        // a transient per-image error doesn't poison the headline metric, but
        // the errors are preserved for the user to see in `report.json`.
        let stage = if !symbol_map_errors.is_empty() && total == 0 {
            StageReport::failed(
                "symbol_map",
                format!(
                    "{} error(s); first: {}",
                    symbol_map_errors.len(),
                    symbol_map_errors
                        .first()
                        .map(|(_, m)| m.as_str())
                        .unwrap_or("")
                ),
                t.elapsed().as_millis(),
            )
        } else if total == 0 {
            StageReport::skipped("symbol_map", "no symbols recovered")
        } else {
            StageReport::ok("symbol_map", "ghidra/symbol_maps/", t.elapsed().as_millis())
        };
        stages.push(stage);
    }

    // Phase 3.0 globals options are route-independent. Normal decompose uses
    // the in-memory all-tier names prepared alongside the function maps; the
    // --no-symbol-pass route loads its indexes from finalized symbols.json
    // later, after the legacy text rewrite has completed.
    let globals_opts = globals::GlobalsOpts {
        include_provisional: opts.globals_provisional,
        k_arm: opts.globals_k_arm.unwrap_or(globals::K_ARM),
        k_thumb: opts.globals_k_thumb.unwrap_or(globals::K_THUMB),
    };
    let function_name_indexes = prepare_function_name_indexes(&function_maps);

    // Normal route: prepare globals before pass 2 so these ImageResult values
    // carry their globals fields through run_two_pass. Task 4 consumes the
    // retained typed maps alongside the function maps.
    let mut _prepared_global_maps = HashMap::new();
    if !opts.no_symbol_pass {
        let active_images = if let Some(report) = pass1_report.as_mut() {
            report.images.as_mut_slice()
        } else {
            &mut []
        };
        let outcome = run_globals_stage(
            active_images,
            &images_dir,
            &out.join("manifest.json"),
            &function_name_indexes,
            &globals_opts,
        );
        _prepared_global_maps = outcome.maps;
        stages.push(outcome.stage);
        let refresh_source = pass1_report
            .as_ref()
            .map(|report| report.images.as_slice())
            .unwrap_or(&[]);
        refresh_decompile_stage_images(&mut stages, refresh_source);
    }

    // 7. Decompile pass 2 — ApplySymbols + ExportDecomp on each image with a
    //    non-empty map. Consumes pass1_report (pass 1 already ran in step 3).
    //    Per-image pass-2 failures land in ImageResult.pass2_error and do not
    //    abort the orchestrator — pass 1 already produced a valid decompiled.c.
    //
    if !opts.no_symbol_pass {
        if let Some(rep) = pass1_report.take() {
            let t = Instant::now();
            let map_paths: HashMap<String, PathBuf> = function_maps
                .iter()
                .map(|(label, prepared)| (label.clone(), prepared.map_path.clone()))
                .collect();
            match decompile::run_two_pass(rep, &dopts, &ghidra_dir, &map_paths) {
                Ok(mut rep2) => {
                    // Pass 2 overwrote {ghidra}/export/<label>/; re-marshal each
                    // image's fresh export into the per-image tree so it does
                    // not still hold pass 1's FUN_-placeholder decompiled.c.
                    for ir in &rep2.images {
                        if let Err(e) = refresh_decompiled(&ghidra_dir, &images_dir, &ir.label) {
                            tracing::warn!(
                                "decompose: refresh_decompiled for {} failed: {e}",
                                ir.label
                            );
                        }
                    }
                    // 7b. Phase 2 — thumb_enrich re-run against the post-pass-2
                    //     decompiled.c (now baked with recovered names). Overwrites
                    //     each ImageResult.thumb_decompiled from pass 1. Skipped on
                    //     `--no-thumb-decompile` (Phase 2 disabled end-to-end).
                    if opts.no_thumb_decompile {
                        stages.push(StageReport::skipped(
                            "thumb_enrich_post_pass2",
                            "--no-thumb-decompile",
                        ));
                    } else {
                        let enrich_started = Instant::now();
                        let outcome = run_thumb_enrich_per_image(&mut rep2.images, &images_dir);
                        stages.push(thumb_enrich_stage(
                            "thumb_enrich_post_pass2",
                            outcome,
                            enrich_started.elapsed().as_millis(),
                        ));
                    }
                    // Refresh the decompile stage's per-image reports with pass-2 fields.
                    refresh_decompile_stage_images(&mut stages, &rep2.images);
                }
                Err(e) => stages.push(StageReport::failed(
                    "decompile_pass2",
                    e.to_string(),
                    t.elapsed().as_millis(),
                )),
            }
        }
    } else {
        stages.push(StageReport::skipped("decompile_pass2", "--no-symbol-pass"));
        stages.push(StageReport::skipped(
            "thumb_enrich_post_pass2",
            "--no-symbol-pass",
        ));
    }

    // 8. Finalize symbolication per image: rewrite thumb_functions.json (still
    //    asm in Phase 1) and write symbols.json. decompiled.c is left alone on
    //    the pass-2 path — pass 2 regenerated it with names baked in. With
    //    --no-symbol-pass (pass 2 skipped), fall back to today's standalone-style
    //    text substitution so users get the same FUN_ recovery as before, not
    //    raw Ghidra output.
    run_stage(
        &mut stages,
        "symbolicate_finalize",
        "images/*/decompiled/symbols.json",
        || {
            symbolicate::run(
                out,
                &symbolicate::Opts {
                    token_db: token_db.exists().then(|| token_db.clone()),
                    rewrite_decompiled_c: opts.no_symbol_pass,
                },
            )
        },
    );

    // --no-symbol-pass keeps the legacy order: symbolication finalizes and
    // rewrites text first, then globals consumes every non-null finalized name
    // through the defensive loader. Its maps are deliberately not retained as
    // application inputs because pass 2 is disabled.
    if opts.no_symbol_pass {
        let late_function_name_indexes = pass1_report
            .as_ref()
            .map(|report| load_finalized_function_name_indexes(&images_dir, &report.images))
            .unwrap_or_default();
        let active_images = if let Some(report) = pass1_report.as_mut() {
            report.images.as_mut_slice()
        } else {
            &mut []
        };
        let outcome = run_globals_stage(
            active_images,
            &images_dir,
            &out.join("manifest.json"),
            &late_function_name_indexes,
            &globals_opts,
        );
        stages.push(outcome.stage);
        let refresh_source = pass1_report
            .as_ref()
            .map(|report| report.images.as_slice())
            .unwrap_or(&[]);
        refresh_decompile_stage_images(&mut stages, refresh_source);
    }

    // 9. Remaining decoders (independent of symbolication).
    let rf_dir = out.join("rf_cfg_decompressed");
    let hwcfg_path = rootfs.join("hardware_config.json");
    let rf_present = std::fs::read_dir(&rf_dir)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false);

    if hwcfg_path.exists() && rf_present {
        run_stage(&mut stages, "decode_rf", "rf/decoded", || {
            decode_rf::run(&rf_dir, &hwcfg_path, &out.join("rf").join("decoded"))
        });
    } else {
        stages.push(StageReport::skipped(
            "decode_rf",
            "no hardware_config.json or no RF_CFG_* blobs",
        ));
    }

    if hwcfg_path.exists() {
        let rf_arg = rf_present.then(|| rf_dir.clone());
        run_stage(&mut stages, "hardware_config", "rf/hwcfg_summary", || {
            hwcfg::run(
                &hwcfg_path,
                rf_arg.as_deref(),
                &out.join("rf").join("hwcfg_summary"),
            )
        });
    } else {
        stages.push(StageReport::skipped(
            "hardware_config",
            "no hardware_config.json",
        ));
    }

    // 6. Prune (opt-in) then write the report.
    if opts.prune
        && let Err(e) = prune(out)
    {
        stages.push(StageReport::failed("prune", e.to_string(), 0));
    }
    finalize(out, img, opts, &headless, &r2, stages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyzed_image(label: &str) -> decompile::ImageResult {
        decompile::ImageResult {
            label: label.into(),
            outcome: ImageOutcome::Analyzed(1),
            thumb_functions: None,
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        }
    }

    #[test]
    fn prepared_function_map_keeps_every_named_symbol_with_loader_canonical_addresses() {
        // This catches a preparation path that either filters to Recovered symbols
        // or retains the source address spelling instead of the symbols.json
        // loader's canonical lowercase, unprefixed hexadecimal key.
        let symbols = vec![
            symbolicate::Symbol {
                address: "0x0000ABCD".into(),
                arch: "arm",
                original_name: "FUN_abcd".into(),
                name: Some("recovered_name".into()),
                tier: symbolicate::Tier::Recovered,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "000000EF".into(),
                arch: "thumb",
                original_name: "thumb_ef".into(),
                name: Some("provisional_name".into()),
                tier: symbolicate::Tier::Provisional,
                evidence: vec![],
                annotations: vec![],
            },
            symbolicate::Symbol {
                address: "0x00000012".into(),
                arch: "arm",
                original_name: "FUN_12".into(),
                name: None,
                tier: symbolicate::Tier::None,
                evidence: vec![],
                annotations: vec![],
            },
        ];

        let prepared = prepare_function_map(PathBuf::from("maps/02_MAIN.json"), &symbols);

        assert_eq!(prepared.map_path, PathBuf::from("maps/02_MAIN.json"));
        assert_eq!(prepared.named_count, 2);
        assert_eq!(
            prepared.function_names,
            HashMap::from([
                ("abcd".to_string(), "recovered_name".to_string()),
                ("ef".to_string(), "provisional_name".to_string()),
            ])
        );
    }

    #[test]
    fn globals_stage_runs_each_raw_image_once_and_prepares_only_recovered_inputs() {
        // This catches a sweep that skips or repeats an eligible raw image, loses
        // the prepared all-tier function-name index, creates an application input
        // for zero Recovered globals, or counts Provisional globals as applicable.
        let root =
            std::env::temp_dir().join(format!("pme_globals_stage_success_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        for (label, bytes) in [
            ("02_MAIN", b"main bytes".as_slice()),
            ("03_APM", b"apm bytes".as_slice()),
            ("04_VSS", b"vss bytes".as_slice()),
        ] {
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
            std::fs::write(image_dir.join(format!("{label}.bin")), bytes).unwrap();
        }
        let mut images = vec![
            analyzed_image("02_MAIN"),
            analyzed_image("03_APM"),
            analyzed_image("04_VSS"),
            analyzed_image("05_DBGCORE"),
        ];
        let function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                map_path: PathBuf::from("maps/02_MAIN.json"),
                named_count: 2,
                function_names: HashMap::from([
                    ("40".to_string(), "RecoveredMain".to_string()),
                    ("44".to_string(), "guess_main_44".to_string()),
                ]),
            },
        )]);
        let function_name_indexes = prepare_function_name_indexes(&function_maps);
        let mut calls = Vec::new();

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_name_indexes,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, names, _| {
                calls.push((
                    label.to_string(),
                    std::fs::read(image_dir.join(format!("{label}.bin"))).unwrap(),
                    names.clone(),
                ));
                Ok(match label {
                    "02_MAIN" => globals::GlobalsReport {
                        recovered_count: 2,
                        conflicts_dropped: 1,
                        provisional_generated: 5,
                        provisional_suppressed_by_recovered: 1,
                    },
                    "03_APM" => globals::GlobalsReport {
                        recovered_count: 0,
                        conflicts_dropped: 2,
                        provisional_generated: 3,
                        provisional_suppressed_by_recovered: 2,
                    },
                    "04_VSS" => globals::GlobalsReport {
                        recovered_count: 4,
                        conflicts_dropped: 0,
                        provisional_generated: 9,
                        provisional_suppressed_by_recovered: 0,
                    },
                    _ => unreachable!("image without raw bytes must not run"),
                })
            },
        );

        assert_eq!(
            calls,
            vec![
                (
                    "02_MAIN".to_string(),
                    b"main bytes".to_vec(),
                    HashMap::from([
                        ("40".to_string(), "RecoveredMain".to_string()),
                        ("44".to_string(), "guess_main_44".to_string()),
                    ]),
                ),
                ("03_APM".to_string(), b"apm bytes".to_vec(), HashMap::new()),
                ("04_VSS".to_string(), b"vss bytes".to_vec(), HashMap::new()),
            ],
            "each image with raw bytes must run exactly once with its prepared names"
        );
        assert_eq!(images[0].globals_recovered, Some(2));
        assert_eq!(images[0].globals_provisional, Some(5));
        assert_eq!(images[0].globals_provisional_suppressed, Some(1));
        assert_eq!(images[1].globals_recovered, Some(0));
        assert_eq!(images[2].globals_recovered, Some(4));
        assert_eq!(images[2].globals_provisional, Some(9));
        assert!(images[3].globals_recovered.is_none());
        assert_eq!(outcome.maps.len(), 2);
        assert_eq!(outcome.maps["02_MAIN"].recovered_count, 2);
        assert_eq!(outcome.maps["04_VSS"].recovered_count, 4);
        assert_eq!(
            outcome.maps["04_VSS"].map_path,
            images_dir
                .join("04_VSS")
                .join("decompiled")
                .join("globals.json")
        );
        assert!(!outcome.maps.contains_key("03_APM"));
        assert_eq!(outcome.stage.stage, "globals");
        assert_eq!(outcome.stage.status, "ok");
        assert_eq!(
            outcome.stage.output.as_deref(),
            Some(
                "3 image(s) processed; 6 recovered globals total; 3 conflicts dropped; \
                 17 provisional generated (3 suppressed by Recovered)"
            )
        );
        assert!(outcome.stage.error.is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn globals_stage_failure_keeps_function_map_and_surfaces_failed_image() {
        // This catches an image-level globals error that consumes or deletes its
        // function-only pass-2 input, suppresses the error/report failure, or
        // prevents later images from producing usable globals inputs.
        let root =
            std::env::temp_dir().join(format!("pme_globals_stage_failure_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        for label in ["02_MAIN", "04_VSS"] {
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
            std::fs::write(image_dir.join(format!("{label}.bin")), label).unwrap();
        }
        let mut images = vec![analyzed_image("02_MAIN"), analyzed_image("04_VSS")];
        let function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                map_path: PathBuf::from("maps/02_MAIN.json"),
                named_count: 1,
                function_names: HashMap::from([("40".to_string(), "RecoveredMain".to_string())]),
            },
        )]);
        let function_name_indexes = prepare_function_name_indexes(&function_maps);

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_name_indexes,
            &globals::GlobalsOpts::default(),
            |_, label, _, _, _| {
                if label == "02_MAIN" {
                    Err(Error::Serialize("malformed functions.json".into()))
                } else {
                    Ok(globals::GlobalsReport {
                        recovered_count: 1,
                        conflicts_dropped: 0,
                        provisional_generated: 0,
                        provisional_suppressed_by_recovered: 0,
                    })
                }
            },
        );

        assert_eq!(
            function_maps["02_MAIN"].map_path,
            PathBuf::from("maps/02_MAIN.json"),
            "globals failure must preserve the function-only pass-2 input"
        );
        assert!(!outcome.maps.contains_key("02_MAIN"));
        assert_eq!(outcome.maps["04_VSS"].recovered_count, 1);
        assert_eq!(
            images[0].globals_error.as_deref(),
            Some("serialize: malformed functions.json")
        );
        assert!(images[0].globals_recovered.is_none());
        assert_eq!(images[1].globals_recovered, Some(1));
        assert_eq!(outcome.stage.status, "failed");
        assert_eq!(
            outcome.stage.error.as_deref(),
            Some("serialize: malformed functions.json")
        );
        assert_eq!(
            outcome.stage.output.as_deref(),
            Some(
                "1 image(s) processed; 1 recovered globals total; 0 conflicts dropped; \
                 0 provisional generated (0 suppressed by Recovered)"
            )
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn late_no_symbol_globals_uses_every_finalized_non_null_name_once() {
        // This catches the --no-symbol-pass route running globals before
        // symbolicate_finalize, bypassing the defensive symbols.json loader, or
        // filtering finalized Provisional names out of the cross-reference.
        let root = std::env::temp_dir().join(format!(
            "pme_globals_stage_no_symbol_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let image_dir = images_dir.join("02_MAIN");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"raw bytes").unwrap();
        std::fs::write(
            image_dir.join("decompiled").join("symbols.json"),
            r#"{"symbols":[
                {"address":"0x00000040","name":"RecoveredMain"},
                {"address":"00000044","name":"guess_main_44"},
                {"address":"0x48","name":null},
                {"address":"not-hex","name":"MalformedAddress"}
            ]}"#,
        )
        .unwrap();
        let mut images = vec![analyzed_image("02_MAIN")];
        let function_name_indexes = load_finalized_function_name_indexes(&images_dir, &images);
        let mut calls = 0usize;

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_name_indexes,
            &globals::GlobalsOpts::default(),
            |_, label, _, names, _| {
                calls += 1;
                assert_eq!(label, "02_MAIN");
                assert_eq!(
                    names,
                    &HashMap::from([
                        ("40".to_string(), "RecoveredMain".to_string()),
                        ("44".to_string(), "guess_main_44".to_string()),
                    ])
                );
                Ok(globals::GlobalsReport {
                    recovered_count: 1,
                    conflicts_dropped: 0,
                    provisional_generated: 0,
                    provisional_suppressed_by_recovered: 0,
                })
            },
        );

        assert_eq!(calls, 1);
        assert_eq!(outcome.maps["02_MAIN"].recovered_count, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn report_serializes_and_ok_reflects_failure() {
        let stages = vec![
            StageReport::ok("extract", "manifest.json", 5),
            StageReport::decompile(
                vec![
                    ImageReport {
                        image: "02_MAIN".into(),
                        status: "analyzed",
                        functions: Some(3),
                        thumb_functions: Some(1),
                        thumb_error: None,
                        exit: None,
                        pass2_applied: None,
                        pass2_error: None,
                        thumb_decompiled: None,
                        thumb_tighten_error: None,
                        thumb_enrich_error: None,
                        globals_error: None,
                        globals_recovered: None,
                        globals_provisional: None,
                        globals_provisional_suppressed: None,
                    },
                    ImageReport {
                        image: "04_VSS".into(),
                        status: "failed",
                        functions: None,
                        thumb_functions: None,
                        thumb_error: None,
                        exit: Some(1),
                        pass2_applied: None,
                        pass2_error: None,
                        thumb_decompiled: None,
                        thumb_tighten_error: None,
                        thumb_enrich_error: None,
                        globals_error: None,
                        globals_recovered: None,
                        globals_provisional: None,
                        globals_provisional_suppressed: None,
                    },
                ],
                10,
            ),
            StageReport::skipped("decode_tokens", "no pw_token_db"),
            StageReport::ok(
                "source_attribution",
                "images/02_MAIN/source_tree/recovered_index.json",
                7,
            ),
        ];
        assert!(!Report::is_ok(&stages), "a failed image => not ok");

        let report = Report {
            tool_version: "1.0.0".into(),
            source_image: "radio.img".into(),
            source_sha256: "abc".into(),
            out: "radio.decomposed".into(),
            ghidra: GhidraTools {
                headless: "/g/analyzeHeadless".into(),
                radare2: "/usr/bin/r2".into(),
            },
            pruned: false,
            ok: Report::is_ok(&stages),
            stages,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["stages"][0]["stage"], "extract");
        assert_eq!(v["stages"][1]["status"], "failed");
        assert_eq!(v["stages"][1]["images"][0]["functions"], 3);
        assert_eq!(v["stages"][1]["images"][1]["exit"], 1);
        assert_eq!(v["stages"][2]["status"], "skipped");
        assert_eq!(v["stages"][2]["reason"], "no pw_token_db");
        let stage = |name: &str| {
            v["stages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["stage"] == name)
                .unwrap_or_else(|| panic!("missing stage {name}"))
        };
        assert_eq!(
            stage("source_attribution")["output"],
            "images/02_MAIN/source_tree/recovered_index.json"
        );

        // skip_serializing_if must actually omit fields — guards against the attrs being dropped
        assert!(
            v["stages"][0].get("images").is_none(),
            "ok stage omits empty images"
        );
        assert!(
            v["stages"][0].get("reason").is_none(),
            "ok stage omits reason"
        );
        assert!(
            v["stages"][0].get("error").is_none(),
            "ok stage omits error"
        );
        assert!(
            v["stages"][1]["images"][0].get("exit").is_none(),
            "analyzed image omits exit"
        );
        assert!(
            v["stages"][1]["images"][0].get("thumb_error").is_none(),
            "successful image omits thumb_error"
        );
        assert!(
            v["stages"][1]["images"][1].get("functions").is_none(),
            "failed image omits functions"
        );
        assert!(
            v["stages"][1]["images"][1].get("thumb_functions").is_none(),
            "failed image omits thumb_functions"
        );
        assert!(
            v["stages"][2].get("output").is_none(),
            "skipped stage omits output"
        );
        assert!(
            v["stages"][2].get("images").is_none(),
            "skipped stage omits images"
        );
    }

    #[test]
    fn report_ok_when_no_failures() {
        let stages = vec![
            StageReport::ok("extract", "manifest.json", 1),
            StageReport::skipped("decode_tokens", "no pw_token_db"),
        ];
        assert!(Report::is_ok(&stages));
    }

    #[test]
    fn decompile_report_marks_analyzed_image_failed_on_thumb_error() {
        let image = ImageReport::from_result(&decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(42),
            thumb_functions: None,
            thumb_error: Some("radare2 parser rejected empty stdout".into()),
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        });
        assert_eq!(image.status, "failed");
        assert_eq!(image.functions, Some(42));
        assert_eq!(
            image.thumb_error.as_deref(),
            Some("radare2 parser rejected empty stdout")
        );

        let stage = StageReport::decompile(vec![image], 3);
        assert_eq!(stage.status, "failed");

        let v: serde_json::Value = serde_json::to_value(&stage).unwrap();
        assert_eq!(
            v["images"][0]["thumb_error"],
            "radare2 parser rejected empty stdout"
        );
    }

    #[test]
    fn decompile_report_keeps_analyzed_status_without_thumb_outcome() {
        let image = ImageReport::from_result(&decompile::ImageResult {
            label: "01_BOOT".into(),
            outcome: ImageOutcome::Analyzed(7),
            thumb_functions: None,
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        });

        assert_eq!(image.status, "analyzed");
        assert_eq!(image.functions, Some(7));
        assert!(image.thumb_functions.is_none());
        assert!(image.thumb_error.is_none());
    }

    #[test]
    fn run_thumb_enrich_per_image_populates_count_and_skips_images_without_thumb_json() {
        let root =
            std::env::temp_dir().join(format!("pme_thumb_enrich_loop_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // Image A: has thumb_functions.json + matching decompiled.c.
        let dec_a = root.join("images").join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&dec_a).unwrap();
        std::fs::write(
            dec_a.join("decompiled.c"),
            // Phase 2.1: thumb_enrich parses ExportDecomp.java's
            // `// <name> @ <addr>` header (address-keyed, T-bit normalized);
            // the function entry `0x40e1200` matches the normalized `00040e1200`.
            "// FUN_40e1200 @ 00040e1200\nvoid FUN_40e1200(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();
        std::fs::write(
            dec_a.join("thumb_functions.json"),
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[
                {"entry":"0x40e1200","name":"thumb_40e1200","size":4,
                 "body_kind":"thumb_disassembly","body":"bx lr","data_refs":[]}]}"#,
        )
        .unwrap();
        // Image B: no thumb_functions.json (no Thumb regions on this image).
        let dec_b = root.join("images").join("01_BOOT").join("decompiled");
        std::fs::create_dir_all(&dec_b).unwrap();

        let mut images = vec![
            decompile::ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(10),
                thumb_functions: Some(1),
                thumb_error: None,
                pass2_applied: None,
                pass2_error: None,
                thumb_decompiled: None,
                thumb_tighten_error: None,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
            },
            decompile::ImageResult {
                label: "01_BOOT".into(),
                outcome: ImageOutcome::Analyzed(3),
                thumb_functions: None,
                thumb_error: None,
                pass2_applied: None,
                pass2_error: None,
                thumb_decompiled: None,
                thumb_tighten_error: None,
                thumb_enrich_error: None,
                globals_error: None,
                globals_recovered: None,
                globals_provisional: None,
                globals_provisional_suppressed: None,
            },
        ];
        let images_dir = root.join("images");
        let outcome = run_thumb_enrich_per_image(&mut images, &images_dir);

        assert_eq!(outcome.counts.len(), 1, "only 02_MAIN had a thumb json");
        assert_eq!(outcome.counts[0].0, "02_MAIN");
        assert_eq!(outcome.counts[0].1, 1, "one body_c populated");
        assert!(outcome.errors.is_empty());
        assert_eq!(images[0].thumb_decompiled, Some(1));
        assert!(images[0].thumb_enrich_error.is_none());
        // Image B without thumb json is unchanged.
        assert!(images[1].thumb_decompiled.is_none());
        assert!(images[1].thumb_enrich_error.is_none());

        // The StageReport shape produced from this outcome.
        let stage = thumb_enrich_stage("thumb_enrich", outcome, 0);
        assert_eq!(stage.stage, "thumb_enrich");
        assert_eq!(stage.status, "ok");
        assert_eq!(stage.output.as_deref(), Some("1 image(s) enriched"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_thumb_enrich_per_image_reports_missing_json_after_thumb_success() {
        let root = std::env::temp_dir().join(format!(
            "pme_thumb_enrich_missing_json_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        // decompiled.c present; thumb_functions.json deliberately absent.
        let dec = root.join("images").join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        std::fs::write(
            dec.join("decompiled.c"),
            "// FUN_40e1200 @ 00040e1200\nvoid FUN_40e1200(void)\n{\n  return;\n}\n\n",
        )
        .unwrap();

        let mut images = vec![decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(10),
            // In-memory result says radare2 produced Thumb output.
            thumb_functions: Some(5),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        }];
        let outcome = run_thumb_enrich_per_image(&mut images, &root.join("images"));

        assert!(
            outcome.counts.is_empty(),
            "missing JSON must not count as enriched"
        );
        assert_eq!(outcome.errors.len(), 1, "must surface one per-image error");
        assert_eq!(outcome.errors[0].0, "02_MAIN");
        assert!(
            outcome.errors[0].1.contains("thumb_functions.json")
                || outcome.errors[0].1.contains("missing"),
            "error text must name the missing artifact, got: {}",
            outcome.errors[0].1
        );
        assert!(images[0].thumb_decompiled.is_none());
        assert!(
            images[0].thumb_enrich_error.is_some(),
            "ImageResult.thumb_enrich_error must be set"
        );

        let stage = thumb_enrich_stage("thumb_enrich_post_pass2", outcome, 0);
        assert_eq!(stage.status, "failed");
        assert!(stage.error.is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompile_stage_images_surfaces_post_enrich_fields() {
        // Phase 2.1 followup regression: the `decompile` StageReport is pushed
        // before thumb_enrich runs, so its per-image entries carry pre-enrich
        // state (thumb_decompiled = None). After thumb_enrich mutates each
        // ImageResult.thumb_decompiled, refresh_decompile_stage_images must
        // re-marshal the image entries from the updated ImageResult slice so
        // the report surfaces the post-enrich count. Without this refresh,
        // thumb_enrich populated 80k+ body_c on production but the count was
        // invisible in report.json under `--no-symbol-pass`.
        let pre_enrich_images = vec![ImageReport {
            image: "02_MAIN".into(),
            status: "analyzed",
            functions: Some(107_955),
            thumb_functions: Some(117_444),
            thumb_error: None,
            exit: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None, // pre-enrich
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        }];
        let mut stages = vec![StageReport::decompile(pre_enrich_images, 12345)];

        // Simulate thumb_enrich mutating ImageResult.
        let post_enrich_images = vec![decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(107_955),
            thumb_functions: Some(117_444),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: Some(81_763), // post-enrich
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        }];

        refresh_decompile_stage_images(&mut stages, &post_enrich_images);

        // The decompile stage entry is updated in place; duration_ms preserved.
        assert_eq!(stages[0].stage, "decompile");
        assert_eq!(stages[0].duration_ms, 12345);
        assert_eq!(stages[0].images.len(), 1);
        assert_eq!(
            stages[0].images[0].thumb_decompiled,
            Some(81_763),
            "refresh must surface the post-enrich thumb_decompiled count"
        );
    }

    #[test]
    fn refresh_decompile_stage_images_no_op_when_no_decompile_stage() {
        // Defensive: if no `decompile` stage exists (e.g. earlier marshal
        // failure pushed a `failed` stage instead), refresh is a no-op.
        let mut stages: Vec<StageReport> = vec![StageReport::skipped("extract", "test")];
        let images = vec![];
        refresh_decompile_stage_images(&mut stages, &images);
        assert_eq!(stages.len(), 1, "no decompile stage to refresh");
    }

    #[test]
    fn run_thumb_enrich_per_image_records_error_on_missing_decompiled_c() {
        let root =
            std::env::temp_dir().join(format!("pme_thumb_enrich_err_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dec = root.join("images").join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        // thumb_functions.json exists but decompiled.c is absent -> Err.
        std::fs::write(
            dec.join("thumb_functions.json"),
            r#"{"format":"pixel-modem-extractor-thumb-functions-v1","functions":[]}"#,
        )
        .unwrap();

        let mut images = vec![decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: ImageOutcome::Analyzed(0),
            thumb_functions: Some(0),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        }];
        let outcome = run_thumb_enrich_per_image(&mut images, &root.join("images"));
        assert_eq!(outcome.counts.len(), 0);
        assert_eq!(
            outcome.errors.len(),
            1,
            "missing decompiled.c surfaces as error"
        );
        assert!(images[0].thumb_decompiled.is_none());
        assert!(images[0].thumb_enrich_error.is_some());

        let stage = thumb_enrich_stage("thumb_enrich", outcome, 0);
        assert_eq!(stage.status, "failed");
        assert!(stage.error.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn preflight_requires_both_tools() {
        let g = PathBuf::from("/opt/ghidra/support/analyzeHeadless");
        let r = PathBuf::from("/usr/bin/r2");
        assert!(preflight(Ok(g.clone()), Some(r.clone())).is_ok());
        assert!(matches!(
            preflight(Err(Error::GhidraNotFound("x".into())), Some(r.clone())),
            Err(Error::GhidraNotFound(_))
        ));
        assert!(matches!(
            preflight(Ok(g), None),
            Err(Error::ToolNotFound(_))
        ));
    }

    #[test]
    fn marshal_moves_slice_and_export() {
        let root = std::env::temp_dir().join(format!("pme_marshal_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        std::fs::create_dir_all(ghidra.join("images")).unwrap();
        std::fs::create_dir_all(ghidra.join("export").join("02_MAIN")).unwrap();
        std::fs::write(ghidra.join("images").join("02_MAIN"), b"slice").unwrap();
        std::fs::write(ghidra.join("export").join("02_MAIN").join("out.c"), b"// c").unwrap();

        let images = root.join("images");
        marshal_image(&ghidra, &images, "02_MAIN").unwrap();

        assert_eq!(
            std::fs::read(images.join("02_MAIN").join("02_MAIN.bin")).unwrap(),
            b"slice"
        );
        assert!(
            images
                .join("02_MAIN")
                .join("decompiled")
                .join("out.c")
                .exists()
        );
        assert!(
            !ghidra.join("images").join("02_MAIN").exists(),
            "moved, not copied"
        );
    }

    #[test]
    fn refresh_decompiled_replaces_ghidra_outputs_and_preserves_sidecars() {
        let root =
            std::env::temp_dir().join(format!("pme_refresh_preserve_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";

        // Destination: pass-1 tree with old Ghidra trio + Thumb sidecars.
        let dest = images.join(label).join("decompiled");
        std::fs::create_dir_all(dest.join("thumb")).unwrap();
        std::fs::write(dest.join("decompiled.c"), b"OLD_C").unwrap();
        std::fs::write(dest.join("disasm.lst"), b"OLD_LST").unwrap();
        std::fs::write(dest.join("functions.json"), b"OLD_FN").unwrap();
        let thumb_json = b"{\"format\":\"thumb-v1\",\"functions\":[]}";
        let thumb_stdout = b"r2-stdout-bytes-must-survive";
        std::fs::write(dest.join("thumb_functions.json"), thumb_json).unwrap();
        std::fs::write(dest.join("thumb").join("410b0000.stdout"), thumb_stdout).unwrap();

        // Pass-2 export: exactly the three Ghidra-owned files, new contents.
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&export).unwrap();
        std::fs::write(export.join("decompiled.c"), b"NEW_C").unwrap();
        std::fs::write(export.join("disasm.lst"), b"NEW_LST").unwrap();
        std::fs::write(export.join("functions.json"), b"NEW_FN").unwrap();

        refresh_decompiled(&ghidra, &images, label).unwrap();

        assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), b"NEW_C");
        assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), b"NEW_LST");
        assert_eq!(
            std::fs::read(dest.join("functions.json")).unwrap(),
            b"NEW_FN"
        );
        assert_eq!(
            std::fs::read(dest.join("thumb_functions.json")).unwrap(),
            thumb_json,
            "thumb_functions.json must be byte-identical"
        );
        assert_eq!(
            std::fs::read(dest.join("thumb").join("410b0000.stdout")).unwrap(),
            thumb_stdout,
            "thumb/*.stdout must be byte-identical"
        );
        assert!(
            !export.exists(),
            "validated export dir must be removed after successful replace"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refresh_decompiled_rejects_invalid_export_without_mutating_destination() {
        let root = std::env::temp_dir().join(format!("pme_refresh_reject_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let ghidra = root.join("ghidra");
        let images = root.join("images");
        let label = "02_MAIN";
        let dest = images.join(label).join("decompiled");
        std::fs::create_dir_all(dest.join("thumb")).unwrap();

        // Snapshot-worthy destination contents.
        let old_c = b"KEEP_C";
        let old_lst = b"KEEP_LST";
        let old_fn = b"KEEP_FN";
        let thumb_json = b"KEEP_THUMB_JSON";
        let thumb_stdout = b"KEEP_STDOUT";
        std::fs::write(dest.join("decompiled.c"), old_c).unwrap();
        std::fs::write(dest.join("disasm.lst"), old_lst).unwrap();
        std::fs::write(dest.join("functions.json"), old_fn).unwrap();
        std::fs::write(dest.join("thumb_functions.json"), thumb_json).unwrap();
        std::fs::write(dest.join("thumb").join("410b0000.stdout"), thumb_stdout).unwrap();

        let assert_dest_untouched = |dest: &std::path::Path| {
            assert_eq!(std::fs::read(dest.join("decompiled.c")).unwrap(), old_c);
            assert_eq!(std::fs::read(dest.join("disasm.lst")).unwrap(), old_lst);
            assert_eq!(std::fs::read(dest.join("functions.json")).unwrap(), old_fn);
            assert_eq!(
                std::fs::read(dest.join("thumb_functions.json")).unwrap(),
                thumb_json
            );
            assert_eq!(
                std::fs::read(dest.join("thumb").join("410b0000.stdout")).unwrap(),
                thumb_stdout
            );
        };

        // Case A: incomplete export (missing functions.json).
        let export = ghidra.join("export").join(label);
        std::fs::create_dir_all(&export).unwrap();
        std::fs::write(export.join("decompiled.c"), b"NEW_C").unwrap();
        std::fs::write(export.join("disasm.lst"), b"NEW_LST").unwrap();
        // deliberately omit functions.json
        let err = refresh_decompiled(&ghidra, &images, label).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid pass-2 export") || msg.contains("expected exactly"),
            "incomplete export must error clearly, got: {msg}"
        );
        assert_dest_untouched(&dest);
        assert!(export.exists(), "failed validation must not consume export");

        // Case B: unexpected extra entry.
        std::fs::write(export.join("functions.json"), b"NEW_FN").unwrap();
        std::fs::write(export.join("extra.txt"), b"nope").unwrap();
        let err = refresh_decompiled(&ghidra, &images, label).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid pass-2 export") || msg.contains("expected exactly"),
            "unexpected entry must error clearly, got: {msg}"
        );
        assert_dest_untouched(&dest);

        // Case C: non-file entry (subdirectory) in export.
        let _ = std::fs::remove_file(export.join("extra.txt"));
        std::fs::create_dir(export.join("subdir")).unwrap();
        let err = refresh_decompiled(&ghidra, &images, label).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a regular file") || msg.contains("invalid pass-2 export"),
            "non-file export entry must error clearly, got: {msg}"
        );
        assert_dest_untouched(&dest);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prune_keeps_only_leaves() {
        let out = std::env::temp_dir().join(format!("pme_prune_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(out.join("rootfs").join("images").join("g5400i")).unwrap();
        std::fs::create_dir_all(out.join("rf_cfg_decompressed")).unwrap();
        std::fs::create_dir_all(out.join("ghidra").join("ghidra_project")).unwrap();
        std::fs::write(out.join("modem.ext4"), b"ext4").unwrap();
        std::fs::create_dir_all(out.join("images").join("02_MAIN").join("decompiled")).unwrap();
        std::fs::write(
            out.join("images").join("02_MAIN").join("02_MAIN.bin"),
            b"slice",
        )
        .unwrap();
        std::fs::write(
            out.join("images")
                .join("02_MAIN")
                .join("decompiled")
                .join("out.c"),
            b"// c",
        )
        .unwrap();
        std::fs::create_dir_all(out.join("rf").join("decoded")).unwrap();
        std::fs::create_dir_all(out.join("tokens")).unwrap();
        std::fs::write(out.join("manifest.json"), b"{}").unwrap();

        prune(&out).unwrap();

        assert!(!out.join("modem.ext4").exists());
        assert!(!out.join("rootfs").exists());
        assert!(!out.join("rf_cfg_decompressed").exists());
        assert!(!out.join("ghidra").exists());
        assert!(
            !out.join("images")
                .join("02_MAIN")
                .join("02_MAIN.bin")
                .exists()
        );
        assert!(
            out.join("images")
                .join("02_MAIN")
                .join("decompiled")
                .join("out.c")
                .exists()
        );
        assert!(out.join("rf").join("decoded").exists());
        assert!(out.join("tokens").exists());
        assert!(out.join("manifest.json").exists());
    }

    #[test]
    fn rootfs_image_dir_finds_single_subdir() {
        let out = std::env::temp_dir().join(format!("pme_rootfs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(out.join("rootfs").join("images").join("g5400i-abc")).unwrap();
        let d = rootfs_image_dir(&out).unwrap();
        assert!(d.ends_with("g5400i-abc"));
    }

    #[test]
    fn rootfs_image_dir_errors_notfound_when_absent() {
        let out = std::env::temp_dir().join(format!("pme_rootfs_absent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        // <out>/rootfs/images/ doesn't exist at all -> typed NotFound, not a raw Io error
        assert!(matches!(rootfs_image_dir(&out), Err(Error::NotFound(_))));
    }

    #[test]
    fn image_report_serializes_phase2_fields_as_none_when_absent() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            thumb_functions: Some(5),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        // New fields must serialize as absent (skip_serializing_if = Option::is_none).
        assert!(!json.contains("thumb_decompiled"));
        assert!(!json.contains("thumb_tighten_error"));
        assert!(!json.contains("thumb_enrich_error"));
    }

    #[test]
    fn image_report_serializes_phase2_fields_when_set() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            thumb_functions: Some(5),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: Some(3),
            thumb_tighten_error: None,
            thumb_enrich_error: Some("malformed decompiled.c".into()),
            globals_error: None,
            globals_recovered: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"thumb_decompiled\":3"));
        assert!(!json.contains("thumb_tighten_error"));
        assert!(json.contains("\"thumb_enrich_error\":\"malformed decompiled.c\""));
    }

    #[test]
    fn image_report_serializes_phase3_globals_fields_as_none_when_absent() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            thumb_functions: Some(5),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_recovered: None,
            globals_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("globals_recovered"));
        assert!(!json.contains("globals_error"));
        assert!(!json.contains("\"globals_provisional\""));
        assert!(!json.contains("\"globals_provisional_suppressed\""));
    }

    #[test]
    fn image_report_serializes_phase3_globals_fields_when_set() {
        let r = decompile::ImageResult {
            label: "02_MAIN".into(),
            outcome: decompile::ImageOutcome::Analyzed(10),
            thumb_functions: Some(5),
            thumb_error: None,
            pass2_applied: None,
            pass2_error: None,
            thumb_decompiled: None,
            thumb_tighten_error: None,
            thumb_enrich_error: None,
            globals_recovered: Some(137),
            globals_error: Some("malformed functions.json".into()),
            globals_provisional: Some(50),
            globals_provisional_suppressed: Some(3),
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"globals_recovered\":137"));
        assert!(json.contains("\"globals_error\":\"malformed functions.json\""));
        assert!(json.contains("\"globals_provisional\":50"));
        assert!(json.contains("\"globals_provisional_suppressed\":3"));
    }

    #[test]
    fn symbolicate_stage_runs_over_a_crafted_tree() {
        let root = std::env::temp_dir().join(format!("pme_decompose_sym_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dec = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&dec).unwrap();
        std::fs::write(
            dec.join("functions.json"),
            r#"[{"name":"FUN_10","entry":"0x10","end":"0x18","data_refs":[]}]"#,
        )
        .unwrap();
        std::fs::write(dec.join("disasm.lst"), "0x10: movw r0, 0xcc9\n").unwrap();
        std::fs::write(
            root.join("manifest.json"),
            r#"{"toc":[{"name":"MAIN","load_addr":0}]}"#,
        )
        .unwrap();

        // no token DB -> token evidence skipped, but the pass still writes symbols.json
        let out = crate::symbolicate::run(
            &root,
            &crate::symbolicate::Opts {
                token_db: None,
                rewrite_decompiled_c: true,
            },
        )
        .unwrap();
        assert_eq!(out, root);
        assert!(dec.join("symbols.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
