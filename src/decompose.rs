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
use std::num::NonZeroUsize;
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
    pub globals_applied: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_apply_skipped: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub globals_apply_error: Option<String>,
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
                globals_applied: r.globals_applied,
                globals_apply_skipped: r.globals_apply_skipped,
                globals_apply_error: r.globals_apply_error.clone(),
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
                globals_applied: r.globals_applied,
                globals_apply_skipped: r.globals_apply_skipped,
                globals_apply_error: r.globals_apply_error.clone(),
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
        return Err(Error::DecomposeIncomplete(format!(
            "missing pass-2 export for {label}: {}",
            export.display()
        )));
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

fn refresh_pass2_outputs_with<F>(
    outcomes: &HashMap<String, decompile::Pass2ProcessOutcome>,
    images: &mut [decompile::ImageResult],
    mut refresh: F,
) -> (usize, Vec<(String, String)>)
where
    F: FnMut(&str) -> Result<()>,
{
    let mut labels: Vec<&str> = outcomes.keys().map(String::as_str).collect();
    labels.sort_unstable();
    let mut refreshed = 0usize;
    let mut errors = Vec::new();

    for label in labels {
        match &outcomes[label] {
            decompile::Pass2ProcessOutcome::Failed(reason) => {
                errors.push((label.to_string(), reason.clone()));
            }
            decompile::Pass2ProcessOutcome::ProcessSucceeded => match refresh(label) {
                Ok(()) => refreshed += 1,
                Err(error) => {
                    let reason = format!("refresh: {error}");
                    if let Some(image) = images.iter_mut().find(|image| image.label == label) {
                        image.pass2_error = Some(reason.clone());
                    }
                    errors.push((label.to_string(), reason));
                }
            },
        }
    }
    (refreshed, errors)
}

fn decompile_pass2_stage(
    scheduled_count: usize,
    refreshed_count: usize,
    mut errors: Vec<(String, String)>,
    duration_ms: u128,
) -> StageReport {
    if scheduled_count == 0 {
        return StageReport::skipped("decompile_pass2", "no prepared maps");
    }
    errors.sort();
    if errors.is_empty() && refreshed_count == scheduled_count {
        return StageReport::ok(
            "decompile_pass2",
            &format!("{refreshed_count} image(s) refreshed"),
            duration_ms,
        );
    }
    if errors.is_empty() {
        errors.push((
            "<pass2>".to_string(),
            format!("refreshed {refreshed_count} of {scheduled_count} scheduled images"),
        ));
    }
    StageReport {
        stage: "decompile_pass2",
        status: "failed",
        output: Some(format!(
            "{refreshed_count} of {scheduled_count} image(s) refreshed"
        )),
        reason: None,
        error: Some(
            errors
                .into_iter()
                .map(|(label, message)| format!("{label}: {message}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        images: Vec::new(),
        duration_ms,
    }
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
/// `ImageResult` slice. Used after later orchestration mutates reporting fields
/// (globals preparation/application and both `thumb_enrich` sweeps) so the
/// serialized stage does not retain its initial pass-1 snapshot. Preserves the
/// stage's other fields (status, duration_ms, output, etc.).
fn refresh_decompile_stage_images(stages: &mut [StageReport], images: &[decompile::ImageResult]) {
    install_decompile_stage_image_snapshot(
        stages,
        images.iter().map(ImageReport::from_result).collect(),
    );
}

fn install_decompile_stage_image_snapshot(stages: &mut [StageReport], images: Vec<ImageReport>) {
    let Some(pos) = stages.iter().rposition(|s| s.stage == "decompile") else {
        return;
    };
    stages[pos].images = images;
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
    pass2_map: Option<decompile::PreparedPass2Map>,
    function_names: HashMap<String, String>,
    evidence_name_projection: globals::FunctionEvidenceNameProjection,
}

type FunctionNameIndexes = HashMap<String, HashMap<String, String>>;

#[derive(Default)]
struct PreparedGlobalsFunctionInputs {
    recovered_names: FunctionNameIndexes,
    evidence_names: HashMap<String, globals::FunctionEvidenceNameProjection>,
}

/// A successfully written globals map retained for pass-2 application.
struct PreparedGlobalMap {
    pass2_map: decompile::PreparedPass2Map,
}

/// One complete globals sweep: typed pass-2 inputs and the aggregate report.
struct GlobalsStageOutcome {
    maps: HashMap<String, PreparedGlobalMap>,
    stage: StageReport,
}

/// Per-image symbol map outcome from [`build_and_write_symbol_maps`]: the
/// successful `(label, prepared map)` entries plus any per-image errors.
type SymbolMapsResult = (HashMap<String, PreparedFunctionMap>, Vec<(String, String)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobalsRouteMode {
    PrepareApplicationInput,
    RecordOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolRouteStep {
    PrepareNamesAndProjection,
    Finalize { rewrite_decompiled_c: bool },
    LoadFinalizedNames,
    RunGlobals(GlobalsRouteMode),
    DispatchPass2,
}

fn orchestrate_symbol_route(no_symbol_pass: bool, mut run_step: impl FnMut(SymbolRouteStep)) {
    if no_symbol_pass {
        run_step(SymbolRouteStep::Finalize {
            rewrite_decompiled_c: true,
        });
        run_step(SymbolRouteStep::LoadFinalizedNames);
        run_step(SymbolRouteStep::RunGlobals(GlobalsRouteMode::RecordOnly));
    } else {
        run_step(SymbolRouteStep::PrepareNamesAndProjection);
        run_step(SymbolRouteStep::RunGlobals(
            GlobalsRouteMode::PrepareApplicationInput,
        ));
        run_step(SymbolRouteStep::DispatchPass2);
        run_step(SymbolRouteStep::Finalize {
            rewrite_decompiled_c: false,
        });
    }
}

const SYMBOL_MAP_ERROR_MAX_CHARS: usize = 2_048;
const SYMBOL_MAP_ERROR_TRUNCATION_MARKER: &str = " [truncated]";

fn truncate_symbol_map_error(message: String) -> String {
    if message.chars().count() <= SYMBOL_MAP_ERROR_MAX_CHARS {
        return message;
    }
    let keep = SYMBOL_MAP_ERROR_MAX_CHARS - SYMBOL_MAP_ERROR_TRUNCATION_MARKER.chars().count();
    let mut truncated: String = message.chars().take(keep).collect();
    truncated.push_str(SYMBOL_MAP_ERROR_TRUNCATION_MARKER);
    truncated
}

fn symbol_map_stage(
    function_maps: &HashMap<String, PreparedFunctionMap>,
    mut errors: Vec<(String, String)>,
    duration_ms: u128,
) -> StageReport {
    let total: usize = function_maps
        .values()
        .filter_map(|prepared| prepared.pass2_map.as_ref())
        .map(decompile::PreparedPass2Map::count)
        .sum();
    if !errors.is_empty() {
        errors.sort();
        let error = errors
            .into_iter()
            .map(|(label, message)| format!("{label}: {}", truncate_symbol_map_error(message)))
            .collect::<Vec<_>>()
            .join("\n");
        return StageReport {
            stage: "symbol_map",
            status: "failed",
            output: (total > 0).then(|| "ghidra/symbol_maps/".to_string()),
            reason: None,
            error: Some(error),
            images: Vec::new(),
            duration_ms,
        };
    }
    if total == 0 {
        StageReport::skipped("symbol_map", "no symbols recovered")
    } else {
        StageReport::ok("symbol_map", "ghidra/symbol_maps/", duration_ms)
    }
}

/// Prepare the in-memory result for a function symbol map that was written from
/// `symbols`. Every non-null name is retained regardless of tier; malformed
/// addresses are excluded with the same acceptance rules as `symbols.json`.
fn prepare_function_map(
    map_path: &Path,
    symbols: &[symbolicate::Symbol],
) -> (PreparedFunctionMap, Option<String>) {
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
    let (pass2_map, validation_error) = match NonZeroUsize::new(named_count) {
        Some(count) => match decompile::PreparedPass2Map::new(map_path, count) {
            Ok(map) => (Some(map), None),
            Err(error) => (None, Some(format!("function map validation: {error}"))),
        },
        None => (None, None),
    };
    (
        PreparedFunctionMap {
            pass2_map,
            function_names,
            evidence_name_projection: globals::FunctionEvidenceNameProjection::from_symbols(
                symbols,
            ),
        },
        validation_error,
    )
}

fn take_globals_function_inputs(
    function_maps: &mut HashMap<String, PreparedFunctionMap>,
) -> PreparedGlobalsFunctionInputs {
    let mut inputs = PreparedGlobalsFunctionInputs::default();
    for (label, prepared) in function_maps {
        inputs
            .recovered_names
            .insert(label.clone(), std::mem::take(&mut prepared.function_names));
        inputs.evidence_names.insert(
            label.clone(),
            std::mem::take(&mut prepared.evidence_name_projection),
        );
    }
    inputs
}

fn prepare_pass2_inputs(
    function_maps: &HashMap<String, PreparedFunctionMap>,
    global_maps: &HashMap<String, PreparedGlobalMap>,
) -> HashMap<String, decompile::Pass2Input> {
    let mut inputs = HashMap::new();
    for (label, prepared) in function_maps {
        let Some(pass2_map) = &prepared.pass2_map else {
            continue;
        };
        let input = inputs
            .entry(label.clone())
            .or_insert_with(decompile::Pass2Input::default);
        input.function_map = Some(pass2_map.clone());
    }
    for (label, prepared) in global_maps {
        let input = inputs
            .entry(label.clone())
            .or_insert_with(decompile::Pass2Input::default);
        input.global_map = Some(prepared.pass2_map.clone());
    }
    inputs
}

fn globals_apply_stage(
    no_symbol_pass: bool,
    prepared_globals: &HashMap<String, PreparedGlobalMap>,
    images: Option<&[decompile::ImageResult]>,
    duration_ms: u128,
) -> StageReport {
    if no_symbol_pass {
        return StageReport::skipped("globals_apply", "--no-symbol-pass");
    }
    if prepared_globals.is_empty() {
        return StageReport::skipped("globals_apply", "no recovered globals");
    }

    let mut labels: Vec<&str> = prepared_globals.keys().map(String::as_str).collect();
    labels.sort_unstable();
    let mut processed = 0usize;
    let mut applied_total = 0usize;
    let mut skipped_total = 0usize;
    let mut first_error = None;

    if let Some(images) = images {
        for image in images {
            let Ok(index) = labels.binary_search(&image.label.as_str()) else {
                continue;
            };
            let label = labels.remove(index);
            if let Some(error) = &image.pass2_error {
                first_error.get_or_insert_with(|| format!("{label}: {error}"));
                continue;
            }
            if let Some(error) = &image.globals_apply_error {
                first_error.get_or_insert_with(|| format!("{label}: {error}"));
                continue;
            }
            let (Some(applied), Some(skipped)) =
                (image.globals_applied, image.globals_apply_skipped)
            else {
                first_error.get_or_insert_with(|| {
                    format!("{label}: no valid ApplyGlobals success summary")
                });
                continue;
            };
            let Some(classified) = applied.checked_add(skipped) else {
                first_error
                    .get_or_insert_with(|| format!("{label}: global application counts overflow"));
                continue;
            };
            let expected = prepared_globals[label].pass2_map.count();
            if classified != expected {
                first_error.get_or_insert_with(|| {
                    format!(
                        "{label}: global application counts do not match prepared globals: \
                         {classified} != {expected}"
                    )
                });
                continue;
            }
            let (Some(next_applied), Some(next_skipped)) = (
                applied_total.checked_add(applied),
                skipped_total.checked_add(skipped),
            ) else {
                first_error
                    .get_or_insert_with(|| format!("{label}: global application totals overflow"));
                continue;
            };
            applied_total = next_applied;
            skipped_total = next_skipped;
            processed += 1;
        }
    }
    for label in labels {
        first_error.get_or_insert_with(|| format!("{label}: missing pass-2 image result"));
    }

    StageReport {
        stage: "globals_apply",
        status: if first_error.is_some() {
            "failed"
        } else {
            "ok"
        },
        output: Some(format!(
            "{processed} image(s) processed; {applied_total} globals applied; \
             {skipped_total} skipped"
        )),
        reason: None,
        error: first_error,
        images: Vec::new(),
        duration_ms,
    }
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
    function_inputs: &PreparedGlobalsFunctionInputs,
    opts: &globals::GlobalsOpts,
    mut run_image: F,
) -> GlobalsStageOutcome
where
    F: FnMut(
        &Path,
        &str,
        &Path,
        &HashMap<String, String>,
        Option<&globals::FunctionEvidenceNameProjection>,
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
        let names = function_inputs
            .recovered_names
            .get(&label)
            .unwrap_or(&empty_names);
        let evidence_names = function_inputs.evidence_names.get(&label);
        match run_image(&image_dir, &label, manifest, names, evidence_names, opts) {
            Ok(report) => {
                image.globals_recovered = Some(report.recovered_count);
                image.globals_provisional = Some(report.provisional_generated);
                image.globals_provisional_suppressed =
                    Some(report.provisional_suppressed_by_recovered);
                conflicts += report.conflicts_dropped;
                provisional_total += report.provisional_generated;
                provisional_suppressed_total += report.provisional_suppressed_by_recovered;
                counts.push((label.clone(), report.recovered_count));
                if let Some(count) = NonZeroUsize::new(report.recovered_count) {
                    let map_path = image_dir.join("decompiled").join("globals.json");
                    match decompile::PreparedPass2Map::new(&map_path, count) {
                        Ok(pass2_map) => {
                            maps.insert(label, PreparedGlobalMap { pass2_map });
                        }
                        Err(error) => {
                            let message = format!("globals map validation: {error}");
                            image.globals_error = Some(message.clone());
                            errors.push((label, message));
                        }
                    }
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
    function_inputs: &PreparedGlobalsFunctionInputs,
    opts: &globals::GlobalsOpts,
) -> GlobalsStageOutcome {
    run_globals_stage_with(
        images,
        images_dir,
        manifest,
        function_inputs,
        opts,
        globals::run_with_evidence_projection,
    )
}

/// Record global preparation without exposing a normal-route intermediate
/// image snapshot. The disabled route may refresh here because application is
/// conclusively uninvoked; the normal route must wait for its pass-2 outcome.
fn record_globals_stage(
    stages: &mut Vec<StageReport>,
    outcome: GlobalsStageOutcome,
    images: &[decompile::ImageResult],
    application_uninvoked: bool,
) -> HashMap<String, PreparedGlobalMap> {
    stages.push(outcome.stage);
    if application_uninvoked {
        refresh_decompile_stage_images(stages, images);
    }
    outcome.maps
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
        let (prepared, validation_error) = prepare_function_map(&map_path, &symbols);
        if let Some(error) = validation_error {
            errors.push((label.clone(), error));
        }
        out_maps.insert(label, prepared);
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
    let (mut function_maps, symbol_map_errors) = if opts.no_symbol_pass {
        (HashMap::new(), Vec::new())
    } else {
        build_and_write_symbol_maps(out, &images_dir, &token_db, &out.join("manifest.json"))
    };
    if opts.no_symbol_pass {
        stages.push(StageReport::skipped("symbol_map", "--no-symbol-pass"));
    } else {
        stages.push(symbol_map_stage(
            &function_maps,
            symbol_map_errors,
            t.elapsed().as_millis(),
        ));
    }

    // Phase 3.0 globals options are route-independent.
    let globals_opts = globals::GlobalsOpts {
        include_provisional: opts.globals_provisional,
        k_arm: opts.globals_k_arm.unwrap_or(globals::K_ARM),
        k_thumb: opts.globals_k_thumb.unwrap_or(globals::K_THUMB),
    };

    let mut function_inputs = None;
    let mut prepared_global_maps = HashMap::new();
    orchestrate_symbol_route(opts.no_symbol_pass, |step| match step {
        SymbolRouteStep::PrepareNamesAndProjection => {
            function_inputs = Some(take_globals_function_inputs(&mut function_maps));
        }
        SymbolRouteStep::Finalize {
            rewrite_decompiled_c,
        } => {
            run_stage(
                &mut stages,
                "symbolicate_finalize",
                "images/*/decompiled/symbols.json",
                || {
                    symbolicate::run(
                        out,
                        &symbolicate::Opts {
                            token_db: token_db.exists().then(|| token_db.clone()),
                            rewrite_decompiled_c,
                        },
                    )
                },
            );
        }
        SymbolRouteStep::LoadFinalizedNames => {
            let recovered_names = pass1_report
                .as_ref()
                .map(|report| load_finalized_function_name_indexes(&images_dir, &report.images))
                .unwrap_or_default();
            function_inputs = Some(PreparedGlobalsFunctionInputs {
                recovered_names,
                evidence_names: HashMap::new(),
            });
        }
        SymbolRouteStep::RunGlobals(mode) => {
            let function_inputs = function_inputs
                .take()
                .expect("route prepares function inputs before globals");
            let active_images = pass1_report
                .as_mut()
                .map(|report| report.images.as_mut_slice())
                .unwrap_or(&mut []);
            let globals_outcome = run_globals_stage(
                active_images,
                &images_dir,
                &out.join("manifest.json"),
                &function_inputs,
                &globals_opts,
            );
            drop(function_inputs);
            let refresh_source = pass1_report
                .as_ref()
                .map(|report| report.images.as_slice())
                .unwrap_or(&[]);
            let application_uninvoked = mode == GlobalsRouteMode::RecordOnly;
            let maps = record_globals_stage(
                &mut stages,
                globals_outcome,
                refresh_source,
                application_uninvoked,
            );
            if application_uninvoked {
                stages.push(StageReport::skipped("decompile_pass2", "--no-symbol-pass"));
                stages.push(globals_apply_stage(true, &HashMap::new(), None, 0));
                stages.push(StageReport::skipped(
                    "thumb_enrich_post_pass2",
                    "--no-symbol-pass",
                ));
            } else {
                prepared_global_maps = maps;
            }
        }
        SymbolRouteStep::DispatchPass2 => {
            let inputs = prepare_pass2_inputs(&function_maps, &prepared_global_maps);
            let scheduled_count = inputs.len();
            drop(std::mem::take(&mut function_maps));

            if let Some(rep) = pass1_report.take() {
                let fallback_images: Vec<ImageReport> =
                    rep.images.iter().map(ImageReport::from_result).collect();
                let pass2_started = Instant::now();
                if scheduled_count == 0 {
                    stages.push(decompile_pass2_stage(0, 0, Vec::new(), 0));
                    stages.push(globals_apply_stage(
                        false,
                        &prepared_global_maps,
                        Some(&rep.images),
                        0,
                    ));
                    pass1_report = Some(rep);
                } else {
                    match decompile::run_two_pass(rep, &dopts, &ghidra_dir, &inputs) {
                        Ok(mut pass2) => {
                            let (refreshed_count, errors) = refresh_pass2_outputs_with(
                                &pass2.outcomes,
                                &mut pass2.report.images,
                                |label| refresh_decompiled(&ghidra_dir, &images_dir, label),
                            );
                            let elapsed = pass2_started.elapsed().as_millis();
                            stages.push(decompile_pass2_stage(
                                scheduled_count,
                                refreshed_count,
                                errors,
                                elapsed,
                            ));
                            stages.push(globals_apply_stage(
                                false,
                                &prepared_global_maps,
                                Some(&pass2.report.images),
                                elapsed,
                            ));
                            pass1_report = Some(pass2.report);
                        }
                        Err(error) => {
                            let elapsed = pass2_started.elapsed().as_millis();
                            stages.push(decompile_pass2_stage(
                                scheduled_count,
                                0,
                                vec![("<pass2>".to_string(), error.to_string())],
                                elapsed,
                            ));
                            install_decompile_stage_image_snapshot(&mut stages, fallback_images);
                            stages.push(globals_apply_stage(
                                false,
                                &prepared_global_maps,
                                None,
                                elapsed,
                            ));
                        }
                    }
                }
            } else {
                let errors = if scheduled_count > 0 {
                    vec![(
                        "<pass2>".to_string(),
                        "missing pass-1 decompile report".to_string(),
                    )]
                } else {
                    Vec::new()
                };
                stages.push(decompile_pass2_stage(scheduled_count, 0, errors, 0));
                stages.push(globals_apply_stage(false, &prepared_global_maps, None, 0));
            }

            if let Some(report) = pass1_report.as_mut() {
                if opts.no_thumb_decompile {
                    stages.push(StageReport::skipped(
                        "thumb_enrich_post_pass2",
                        "--no-thumb-decompile",
                    ));
                } else {
                    let enrich_started = Instant::now();
                    let outcome = run_thumb_enrich_per_image(&mut report.images, &images_dir);
                    stages.push(thumb_enrich_stage(
                        "thumb_enrich_post_pass2",
                        outcome,
                        enrich_started.elapsed().as_millis(),
                    ));
                }
                refresh_decompile_stage_images(&mut stages, &report.images);
            }
        }
    });

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

    fn test_symbol(
        address: &str,
        arch: &'static str,
        name: Option<&str>,
        tier: symbolicate::Tier,
    ) -> symbolicate::Symbol {
        symbolicate::Symbol {
            address: address.to_string(),
            arch,
            original_name: format!("original_{address}"),
            name: name.map(str::to_string),
            tier,
            evidence: Vec::new(),
            annotations: Vec::new(),
        }
    }

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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
            globals_provisional: None,
            globals_provisional_suppressed: None,
        }
    }

    fn prepared_test_map(name: &str, count: usize) -> decompile::PreparedPass2Map {
        let dir = PathBuf::from("target").join("pme_task8r_decompose_maps");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, name).unwrap();
        decompile::PreparedPass2Map::new(&path, NonZeroUsize::new(count).unwrap()).unwrap()
    }

    fn prepared_global_map(name: &str, count: usize) -> PreparedGlobalMap {
        PreparedGlobalMap {
            pass2_map: prepared_test_map(name, count),
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

        let map_path = PathBuf::from("target/pme_task8r_decompose_maps/function-index.json");
        std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
        std::fs::write(&map_path, b"map").unwrap();
        let (prepared, validation_error) = prepare_function_map(&map_path, &symbols);

        assert!(validation_error.is_none());
        assert_eq!(prepared.pass2_map.as_ref().unwrap().count(), 2);
        assert_eq!(
            prepared.function_names,
            HashMap::from([
                ("abcd".to_string(), "recovered_name".to_string()),
                ("ef".to_string(), "provisional_name".to_string()),
            ])
        );
    }

    #[test]
    fn prepared_function_map_builds_writer_faithful_evidence_name_projection() {
        // This catches collapsing the writer-finalized Function evidence name
        // into the all-tier recovered-name index. ARM applies the last non-null
        // map entry, while Thumb rewrite observes a final null as a barrier.
        let symbols = vec![
            test_symbol(
                "0x0000ABCD",
                "arm",
                Some("ARM_SHARED"),
                symbolicate::Tier::Recovered,
            ),
            test_symbol("0000abcd", "thumb", None, symbolicate::Tier::None),
            test_symbol(
                "0x000000EF",
                "arm",
                Some("RECOVERED_EF"),
                symbolicate::Tier::Recovered,
            ),
            test_symbol(
                "000000ef",
                "thumb",
                Some("PROVISIONAL_EF"),
                symbolicate::Tier::Provisional,
            ),
            test_symbol(
                "0x000000A2",
                "arm",
                Some("UPPER_A2"),
                symbolicate::Tier::Recovered,
            ),
            test_symbol(
                "not-hex",
                "thumb",
                Some("MALFORMED"),
                symbolicate::Tier::Recovered,
            ),
        ];

        let map_path = PathBuf::from("target/pme_task8r_decompose_maps/function-projection.json");
        std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
        std::fs::write(&map_path, b"map").unwrap();
        let (prepared, validation_error) = prepare_function_map(&map_path, &symbols);

        assert!(validation_error.is_none());
        assert_eq!(
            prepared.function_names,
            HashMap::from([
                ("abcd".to_string(), "ARM_SHARED".to_string()),
                ("ef".to_string(), "PROVISIONAL_EF".to_string()),
                ("a2".to_string(), "UPPER_A2".to_string()),
            ])
        );
        let projection = &prepared.evidence_name_projection;
        assert_eq!(
            projection.name_for(globals::Arch::Arm, 0xabcd),
            Some("ARM_SHARED")
        );
        assert_eq!(
            projection.name_for(globals::Arch::Arm, 0xef),
            Some("PROVISIONAL_EF")
        );
        assert_eq!(
            projection.name_for(globals::Arch::Arm, 0xa2),
            Some("UPPER_A2")
        );
        assert_eq!(projection.name_for(globals::Arch::Thumb, 0xabcd), None);
        assert_eq!(
            projection.name_for(globals::Arch::Thumb, 0xef),
            Some("PROVISIONAL_EF")
        );
        assert_eq!(
            projection.name_for(globals::Arch::Thumb, 0xa2),
            Some("UPPER_A2")
        );
    }

    #[test]
    fn prepared_pass2_inputs_preserve_combined_function_only_and_globals_only_images() {
        // This catches a union that drops an image present on only one side,
        // loses a prepared count, or attaches the wrong image's map path.
        let function_maps = HashMap::from([
            (
                "02_MAIN".to_string(),
                PreparedFunctionMap {
                    pass2_map: Some(prepared_test_map("functions-02_MAIN.json", 3)),
                    function_names: HashMap::new(),
                    evidence_name_projection: Default::default(),
                },
            ),
            (
                "03_APM".to_string(),
                PreparedFunctionMap {
                    pass2_map: Some(prepared_test_map("functions-03_APM.json", 2)),
                    function_names: HashMap::new(),
                    evidence_name_projection: Default::default(),
                },
            ),
        ]);
        let global_maps = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("globals-02_MAIN.json", 5),
            ),
            (
                "04_VSS".to_string(),
                prepared_global_map("globals-04_VSS.json", 7),
            ),
        ]);

        let inputs = prepare_pass2_inputs(&function_maps, &global_maps);

        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs["02_MAIN"].function_map.as_ref().unwrap().count(), 3);
        assert_eq!(inputs["02_MAIN"].global_map.as_ref().unwrap().count(), 5);
        assert_eq!(inputs["03_APM"].function_map.as_ref().unwrap().count(), 2);
        assert!(inputs["03_APM"].global_map.is_none());
        assert!(inputs["04_VSS"].function_map.is_none());
        assert_eq!(inputs["04_VSS"].global_map.as_ref().unwrap().count(), 7);
    }

    #[test]
    fn initial_map_validation_isolates_function_and_global_inputs() {
        let root = std::env::temp_dir().join(format!(
            "pmetask8rinitialmapvalidation{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let main_symbols = vec![test_symbol(
            "0x40",
            "arm",
            Some("RecoveredMain"),
            symbolicate::Tier::Recovered,
        )];
        let other_symbols = vec![test_symbol(
            "0x80",
            "arm",
            Some("RecoveredOther"),
            symbolicate::Tier::Recovered,
        )];

        // An invalid function map omits only that component. Its names and
        // writer-faithful projection survive, while the valid global sibling
        // and both components of an unaffected image remain schedulable.
        let (invalid_function, function_error) =
            prepare_function_map(&root.join("missing-functions.json"), &main_symbols);
        assert!(function_error.is_some());
        assert!(invalid_function.pass2_map.is_none());
        assert_eq!(invalid_function.function_names["40"], "RecoveredMain");
        assert_eq!(
            invalid_function
                .evidence_name_projection
                .name_for(globals::Arch::Arm, 0x40),
            Some("RecoveredMain")
        );

        let main_globals_path = root.join("globals-main.json");
        let other_globals_path = root.join("globals-other.json");
        let other_functions_path = root.join("functions-other.json");
        std::fs::write(&main_globals_path, b"globals main").unwrap();
        std::fs::write(&other_globals_path, b"globals other").unwrap();
        std::fs::write(&other_functions_path, b"functions other").unwrap();
        let valid_main_global = PreparedGlobalMap {
            pass2_map: decompile::PreparedPass2Map::new(
                &main_globals_path,
                NonZeroUsize::new(1).unwrap(),
            )
            .unwrap(),
        };
        let valid_other_global = PreparedGlobalMap {
            pass2_map: decompile::PreparedPass2Map::new(
                &other_globals_path,
                NonZeroUsize::new(2).unwrap(),
            )
            .unwrap(),
        };
        let (valid_other_function, other_function_error) =
            prepare_function_map(&other_functions_path, &other_symbols);
        assert!(other_function_error.is_none());
        let inputs = prepare_pass2_inputs(
            &HashMap::from([
                ("02_MAIN".to_string(), invalid_function),
                ("03_APM".to_string(), valid_other_function),
            ]),
            &HashMap::from([
                ("02_MAIN".to_string(), valid_main_global),
                ("03_APM".to_string(), valid_other_global),
            ]),
        );
        assert!(inputs["02_MAIN"].function_map.is_none());
        assert_eq!(inputs["02_MAIN"].global_map.as_ref().unwrap().count(), 1);
        assert_eq!(inputs["03_APM"].function_map.as_ref().unwrap().count(), 1);
        assert_eq!(inputs["03_APM"].global_map.as_ref().unwrap().count(), 2);

        // A valid function map survives a global-map validation failure. The
        // failed image retains its counts and labelled error, while a second
        // image retains its independently valid global map and accounting.
        let main_functions_path = root.join("functions-main.json");
        std::fs::write(&main_functions_path, b"functions main").unwrap();
        let (valid_main_function, main_function_error) =
            prepare_function_map(&main_functions_path, &main_symbols);
        assert!(main_function_error.is_none());
        let other_functions_path = root.join("functions-other-second.json");
        std::fs::write(&other_functions_path, b"functions other second").unwrap();
        let (valid_other_function, other_function_error) =
            prepare_function_map(&other_functions_path, &other_symbols);
        assert!(other_function_error.is_none());
        let images_dir = root.join("images");
        for label in ["02_MAIN", "03_APM"] {
            let image_dir = images_dir.join(label);
            std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
            std::fs::write(image_dir.join(format!("{label}.bin")), b"image").unwrap();
        }
        let mut images = vec![analyzed_image("02_MAIN"), analyzed_image("03_APM")];
        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &PreparedGlobalsFunctionInputs::default(),
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, _, _, _| {
                let (recovered_count, provisional_generated) = if label == "02_MAIN" {
                    (1, 3)
                } else {
                    std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                    (2, 4)
                };
                Ok(globals::GlobalsReport {
                    recovered_count,
                    conflicts_dropped: 0,
                    provisional_generated,
                    provisional_suppressed_by_recovered: 1,
                })
            },
        );
        assert!(!outcome.maps.contains_key("02_MAIN"));
        assert_eq!(outcome.maps["03_APM"].pass2_map.count(), 2);
        assert_eq!(outcome.stage.status, "failed");
        assert!(
            images[0]
                .globals_error
                .as_deref()
                .is_some_and(|error| error.contains("globals map validation"))
        );
        assert_eq!(images[0].globals_recovered, Some(1));
        assert_eq!(images[0].globals_provisional, Some(3));
        assert_eq!(images[0].globals_provisional_suppressed, Some(1));
        assert_eq!(images[1].globals_error, None);
        assert_eq!(images[1].globals_recovered, Some(2));
        assert_eq!(images[1].globals_provisional, Some(4));
        assert_eq!(images[1].globals_provisional_suppressed, Some(1));
        let inputs = prepare_pass2_inputs(
            &HashMap::from([
                ("02_MAIN".to_string(), valid_main_function),
                ("03_APM".to_string(), valid_other_function),
            ]),
            &outcome.maps,
        );
        assert_eq!(inputs["02_MAIN"].function_map.as_ref().unwrap().count(), 1);
        assert!(inputs["02_MAIN"].global_map.is_none());
        assert_eq!(inputs["03_APM"].function_map.as_ref().unwrap().count(), 1);
        assert_eq!(inputs["03_APM"].global_map.as_ref().unwrap().count(), 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn symbol_map_stage_preserves_all_mixed_errors_and_survivors() {
        let function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_test_map("mixed-survivor.json", 3)),
                function_names: HashMap::new(),
                evidence_name_projection: Default::default(),
            },
        )]);
        let long_message = "界".repeat(2_100);
        let stage = symbol_map_stage(
            &function_maps,
            vec![
                ("04_VSS".to_string(), "zeta failure".to_string()),
                ("02_MAIN".to_string(), "beta failure".to_string()),
                ("01_PSP".to_string(), long_message),
                ("02_MAIN".to_string(), "alpha failure".to_string()),
            ],
            11,
        );

        assert_eq!(stage.status, "failed");
        assert_eq!(stage.output.as_deref(), Some("ghidra/symbol_maps/"));
        let error = stage.error.as_deref().unwrap();
        let lines: Vec<&str> = error.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("01_PSP: "));
        assert!(lines[0].ends_with(" [truncated]"));
        assert!(lines[0].strip_prefix("01_PSP: ").unwrap().chars().count() <= 2_048);
        assert_eq!(lines[1], "02_MAIN: alpha failure");
        assert_eq!(lines[2], "02_MAIN: beta failure");
        assert_eq!(lines[3], "04_VSS: zeta failure");
        assert_eq!(error.matches("02_MAIN: alpha failure").count(), 1);
        assert_eq!(error.matches("02_MAIN: beta failure").count(), 1);
        assert_eq!(error.matches("04_VSS: zeta failure").count(), 1);
        assert!(!Report::is_ok(&[stage]));

        let inputs = prepare_pass2_inputs(&function_maps, &HashMap::new());
        assert_eq!(inputs["02_MAIN"].function_map.as_ref().unwrap().count(), 3);
    }

    #[test]
    fn pass2_refresh_skips_unscheduled_stale_export() {
        let mut images = vec![analyzed_image("02_MAIN")];
        let mut calls = Vec::new();

        let (refreshed, errors) =
            refresh_pass2_outputs_with(&HashMap::new(), &mut images, |label| {
                calls.push(label.to_string());
                Ok(())
            });

        assert_eq!(refreshed, 0);
        assert!(errors.is_empty());
        assert!(calls.is_empty());
    }

    #[test]
    fn pass2_refresh_skips_failed_process_export() {
        let mut images = vec![analyzed_image("02_MAIN")];
        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::Failed("analyzeHeadless exit 7".to_string()),
        )]);
        let mut calls = Vec::new();

        let (refreshed, errors) = refresh_pass2_outputs_with(&outcomes, &mut images, |label| {
            calls.push(label.to_string());
            Ok(())
        });

        assert_eq!(refreshed, 0);
        assert_eq!(
            errors,
            vec![("02_MAIN".to_string(), "analyzeHeadless exit 7".to_string())]
        );
        assert!(calls.is_empty());
    }

    #[test]
    fn pass2_refresh_requires_export_after_success() {
        let root =
            std::env::temp_dir().join(format!("pme_task8r_missing_export_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut images = vec![analyzed_image("02_MAIN")];
        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);

        let (refreshed, errors) = refresh_pass2_outputs_with(&outcomes, &mut images, |label| {
            refresh_decompiled(&root.join("ghidra"), &root.join("images"), label)
        });

        assert_eq!(refreshed, 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("missing pass-2 export"));
        assert!(images[0].pass2_error.as_deref().is_some_and(
            |error| error.contains("refresh:") && error.contains("missing pass-2 export")
        ));
    }

    #[test]
    fn pass2_refresh_records_invalid_export_failure() {
        let root =
            std::env::temp_dir().join(format!("pme_task8r_invalid_export_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let export = root.join("ghidra/export/02_MAIN");
        let destination = root.join("images/02_MAIN/decompiled");
        std::fs::create_dir_all(&export).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(export.join("decompiled.c"), b"new").unwrap();
        std::fs::write(destination.join("decompiled.c"), b"old").unwrap();
        let mut images = vec![analyzed_image("02_MAIN")];
        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);

        let (refreshed, errors) = refresh_pass2_outputs_with(&outcomes, &mut images, |label| {
            refresh_decompiled(&root.join("ghidra"), &root.join("images"), label)
        });

        assert_eq!(refreshed, 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].1.contains("invalid pass-2 export"));
        assert_eq!(
            std::fs::read(destination.join("decompiled.c")).unwrap(),
            b"old"
        );
        assert!(images[0].pass2_error.as_deref().is_some_and(
            |error| error.contains("refresh:") && error.contains("invalid pass-2 export")
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn decompile_pass2_stage_fails_function_only_errors() {
        let stage = decompile_pass2_stage(
            1,
            0,
            vec![("02_MAIN".to_string(), "function process failed".to_string())],
            7,
        );

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: function process failed")
        );
        assert!(!Report::is_ok(&[stage]));
    }

    #[test]
    fn globals_apply_stage_uses_exact_skip_policies() {
        // This catches disabled application being reported as an executed
        // result, or the normal zero-input route losing its distinct reason.
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("skip-globals-02_MAIN.json", 1),
        )]);
        let images = vec![analyzed_image("02_MAIN")];

        let disabled = globals_apply_stage(true, &prepared, Some(&images), 99);
        assert_eq!(
            serde_json::to_value(disabled).unwrap(),
            serde_json::json!({
                "stage": "globals_apply",
                "status": "skipped",
                "reason": "--no-symbol-pass",
                "duration_ms": 0
            })
        );

        let no_recovered = globals_apply_stage(false, &HashMap::new(), Some(&images), 99);
        assert_eq!(
            serde_json::to_value(no_recovered).unwrap(),
            serde_json::json!({
                "stage": "globals_apply",
                "status": "skipped",
                "reason": "no recovered globals",
                "duration_ms": 0
            })
        );
    }

    #[test]
    fn globals_apply_stage_aggregates_valid_executed_zero_and_skips_without_function_metrics() {
        // This catches legitimate skips being treated as failure, executed zero
        // being treated as absent, or global counts being folded into the
        // independent function-only pass2_applied metric.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("aggregate-globals-02_MAIN.json", 2),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("aggregate-globals-03_APM.json", 4),
            ),
        ]);
        let mut main = analyzed_image("02_MAIN");
        main.pass2_applied = Some(7);
        main.globals_applied = Some(2);
        main.globals_apply_skipped = Some(0);
        let mut apm = analyzed_image("03_APM");
        apm.pass2_applied = None;
        apm.globals_applied = Some(0);
        apm.globals_apply_skipped = Some(4);
        let mut unrelated = analyzed_image("04_VSS");
        unrelated.pass2_error = Some("unrelated function-only failure".into());
        let images = vec![main, apm, unrelated];

        let stage = globals_apply_stage(false, &prepared, Some(&images), 17);
        assert_eq!(
            serde_json::to_value(stage).unwrap(),
            serde_json::json!({
                "stage": "globals_apply",
                "status": "ok",
                "output": "2 image(s) processed; 2 globals applied; 4 skipped",
                "duration_ms": 17
            })
        );
        assert_eq!(images[0].pass2_applied, Some(7));
        assert_eq!(images[1].pass2_applied, None);
    }

    #[test]
    fn globals_apply_stage_fails_closed_for_every_invalid_prepared_image_outcome() {
        // These are the real reason-only outcomes produced by pass-2 parsing for a
        // status:error line and each strict success-summary contract failure.
        let summary_errors = [
            "global map rejected",
            "missing ApplyGlobals summary",
            "malformed ApplyGlobals summary: expected value at line 1 column 1",
            "ApplyGlobals summary image \"04_VSS\" does not match \"02_MAIN\"",
            "ApplyGlobals summary does not conserve candidates: 1 != 2",
        ];
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("invalid-globals-02_MAIN.json", 2),
        )]);

        for reason in summary_errors {
            let mut image = analyzed_image("02_MAIN");
            image.globals_apply_error = Some(reason.into());
            let stage = globals_apply_stage(false, &prepared, Some(&[image]), 5);
            assert_eq!(stage.status, "failed", "reason: {reason}");
            assert_eq!(
                stage.error.as_deref(),
                Some(format!("02_MAIN: {reason}").as_str()),
                "first actionable summary error must be retained"
            );
            assert_eq!(
                stage.output.as_deref(),
                Some("0 image(s) processed; 0 globals applied; 0 skipped")
            );
        }

        let mut process_failed = analyzed_image("02_MAIN");
        process_failed.pass2_error = Some("analyzeHeadless exit 7; stderr tail:\nboom".into());
        let stage = globals_apply_stage(false, &prepared, Some(&[process_failed]), 6);
        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: analyzeHeadless exit 7; stderr tail:\nboom")
        );

        let no_summary = analyzed_image("02_MAIN");
        let stage = globals_apply_stage(false, &prepared, Some(&[no_summary]), 7);
        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: no valid ApplyGlobals success summary")
        );

        let stage = globals_apply_stage(false, &prepared, None, 8);
        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("02_MAIN: missing pass-2 image result")
        );
    }

    #[test]
    fn globals_apply_stage_keeps_first_actionable_error_in_image_order() {
        // This catches HashMap iteration or label sorting replacing the first
        // pipeline image's actionable failure with a later image's error.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("order-globals-02_MAIN.json", 1),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("order-globals-03_APM.json", 1),
            ),
        ]);
        let mut apm = analyzed_image("03_APM");
        apm.globals_apply_error = Some("first pipeline-image error".into());
        let mut main = analyzed_image("02_MAIN");
        main.pass2_error = Some("later pipeline-image error".into());

        let stage = globals_apply_stage(false, &prepared, Some(&[apm, main]), 4);

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("03_APM: first pipeline-image error")
        );
    }

    #[test]
    fn globals_apply_stage_rejects_either_one_sided_success_pair() {
        // This catches either half of the applied/skipped pair being accepted
        // as an executed success when the other half is absent.
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("pair-globals-02_MAIN.json", 1),
        )]);

        for (applied, skipped) in [(Some(1), None), (None, Some(1))] {
            let mut image = analyzed_image("02_MAIN");
            image.globals_applied = applied;
            image.globals_apply_skipped = skipped;

            let stage = globals_apply_stage(false, &prepared, Some(&[image]), 3);

            assert_eq!(stage.status, "failed");
            assert_eq!(
                stage.error.as_deref(),
                Some("02_MAIN: no valid ApplyGlobals success summary")
            );
            assert_eq!(
                stage.output.as_deref(),
                Some("0 image(s) processed; 0 globals applied; 0 skipped")
            );
        }
    }

    #[test]
    fn globals_apply_stage_rejects_per_image_overflow_and_prepared_count_mismatch() {
        // This catches wrapping the per-image applied+skipped sum or accepting
        // a conserving pair for a different prepared Recovered count.
        let overflow_prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("overflow-globals-02_MAIN.json", usize::MAX),
        )]);
        let mut overflow = analyzed_image("02_MAIN");
        overflow.globals_applied = Some(usize::MAX);
        overflow.globals_apply_skipped = Some(1);
        let overflow_stage = globals_apply_stage(false, &overflow_prepared, Some(&[overflow]), 4);
        assert_eq!(overflow_stage.status, "failed");
        assert_eq!(
            overflow_stage.error.as_deref(),
            Some("02_MAIN: global application counts overflow")
        );

        let mismatch_prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("mismatch-globals-02_MAIN.json", 3),
        )]);
        let mut mismatch = analyzed_image("02_MAIN");
        mismatch.globals_applied = Some(1);
        mismatch.globals_apply_skipped = Some(1);
        let mismatch_stage = globals_apply_stage(false, &mismatch_prepared, Some(&[mismatch]), 5);
        assert_eq!(mismatch_stage.status, "failed");
        assert_eq!(
            mismatch_stage.error.as_deref(),
            Some("02_MAIN: global application counts do not match prepared globals: 2 != 3")
        );
    }

    #[test]
    fn globals_apply_stage_rejects_aggregate_overflow_and_keeps_prior_totals() {
        // This catches wrapping aggregate totals. The first valid image's
        // contribution remains visible when the next addition overflows.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("aggregate-overflow-globals-02_MAIN.json", usize::MAX),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("aggregate-overflow-globals-03_APM.json", 1),
            ),
        ]);
        let mut main = analyzed_image("02_MAIN");
        main.globals_applied = Some(usize::MAX);
        main.globals_apply_skipped = Some(0);
        let mut apm = analyzed_image("03_APM");
        apm.globals_applied = Some(1);
        apm.globals_apply_skipped = Some(0);

        let stage = globals_apply_stage(false, &prepared, Some(&[main, apm]), 6);

        assert_eq!(stage.status, "failed");
        assert_eq!(
            stage.error.as_deref(),
            Some("03_APM: global application totals overflow")
        );
        let expected_output = format!(
            "1 image(s) processed; {} globals applied; 0 skipped",
            usize::MAX
        );
        assert_eq!(stage.output.as_deref(), Some(expected_output.as_str()));
    }

    #[test]
    fn globals_apply_failure_retains_other_success_totals_and_fails_overall_report() {
        // This catches an error zeroing a prior prepared image's successful
        // totals or failing to propagate through the top-level report policy.
        let prepared = HashMap::from([
            (
                "02_MAIN".to_string(),
                prepared_global_map("partial-globals-02_MAIN.json", 5),
            ),
            (
                "03_APM".to_string(),
                prepared_global_map("partial-globals-03_APM.json", 1),
            ),
        ]);
        let mut main = analyzed_image("02_MAIN");
        main.globals_applied = Some(2);
        main.globals_apply_skipped = Some(3);
        let mut apm = analyzed_image("03_APM");
        apm.globals_apply_error = Some("global map rejected".into());

        let stage = globals_apply_stage(false, &prepared, Some(&[main, apm]), 7);

        assert_eq!(stage.status, "failed");
        assert_eq!(stage.error.as_deref(), Some("03_APM: global map rejected"));
        assert_eq!(
            stage.output.as_deref(),
            Some("1 image(s) processed; 2 globals applied; 3 skipped")
        );
        assert!(!Report::is_ok(&[stage]));
    }

    #[test]
    fn globals_stage_refreshes_only_when_application_is_known_uninvoked() {
        // This catches the normal route installing a pre-application snapshot
        // and relying on a later overwrite. The disabled route may refresh
        // immediately because application is known not to run.
        let mut raw = analyzed_image("02_MAIN");
        raw.globals_recovered = Some(2);
        let initial = vec![ImageReport::from_result(&analyzed_image("02_MAIN"))];
        let outcome = || GlobalsStageOutcome {
            maps: HashMap::new(),
            stage: StageReport::ok("globals", "globals.json", 1),
        };

        let mut normal_stages = vec![StageReport::decompile(initial, 10)];
        let _ = record_globals_stage(
            &mut normal_stages,
            outcome(),
            std::slice::from_ref(&raw),
            false,
        );
        assert_eq!(normal_stages[0].images[0].globals_recovered, None);

        let mut disabled_stages = vec![StageReport::decompile(
            vec![ImageReport::from_result(&analyzed_image("02_MAIN"))],
            10,
        )];
        let _ = record_globals_stage(
            &mut disabled_stages,
            outcome(),
            std::slice::from_ref(&raw),
            true,
        );
        assert_eq!(disabled_stages[0].images[0].globals_recovered, Some(2));
    }

    #[test]
    fn pass2_error_installs_captured_post_globals_snapshot_only_after_outcome() {
        // This catches removal of the forbidden pre-application refresh also
        // losing global-preparation fields when run_two_pass consumes the raw
        // report and returns an early Err.
        let mut raw = analyzed_image("02_MAIN");
        raw.globals_recovered = Some(2);
        let fallback = vec![ImageReport::from_result(&raw)];
        let mut stages = vec![StageReport::decompile(
            vec![ImageReport::from_result(&analyzed_image("02_MAIN"))],
            10,
        )];
        assert_eq!(stages[0].images[0].globals_recovered, None);

        install_decompile_stage_image_snapshot(&mut stages, fallback);

        assert_eq!(stages[0].images[0].globals_recovered, Some(2));
        assert!(stages[0].images[0].globals_applied.is_none());
        assert!(stages[0].images[0].globals_apply_skipped.is_none());
        assert!(stages[0].images[0].globals_apply_error.is_none());
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
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_test_map("globals-stage-functions.json", 2)),
                function_names: HashMap::from([
                    ("40".to_string(), "RecoveredMain".to_string()),
                    ("44".to_string(), "guess_main_44".to_string()),
                ]),
                evidence_name_projection: Default::default(),
            },
        )]);
        let function_inputs = take_globals_function_inputs(&mut function_maps);
        let mut calls = Vec::new();

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, names, evidence_names, _| {
                assert_eq!(evidence_names.is_some(), label == "02_MAIN");
                calls.push((
                    label.to_string(),
                    std::fs::read(image_dir.join(format!("{label}.bin"))).unwrap(),
                    names.clone(),
                ));
                let report = match label {
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
                };
                if report.recovered_count > 0 {
                    std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                }
                Ok(report)
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
        assert_eq!(outcome.maps["02_MAIN"].pass2_map.count(), 2);
        assert_eq!(outcome.maps["04_VSS"].pass2_map.count(), 4);
        assert_eq!(
            outcome.maps["04_VSS"].pass2_map.path(),
            images_dir
                .join("04_VSS")
                .join("decompiled")
                .join("globals.json")
                .canonicalize()
                .unwrap()
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
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_test_map("failure-functions.json", 1)),
                function_names: HashMap::from([("40".to_string(), "RecoveredMain".to_string())]),
                evidence_name_projection: Default::default(),
            },
        )]);
        let function_inputs = take_globals_function_inputs(&mut function_maps);

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, _, _, _| {
                if label == "02_MAIN" {
                    Err(Error::Serialize("malformed functions.json".into()))
                } else {
                    std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
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
            function_maps["02_MAIN"].pass2_map.as_ref().unwrap().count(),
            1
        );
        assert!(!outcome.maps.contains_key("02_MAIN"));
        assert_eq!(outcome.maps["04_VSS"].pass2_map.count(), 1);
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

        let inputs = prepare_pass2_inputs(&function_maps, &outcome.maps);
        assert_eq!(inputs["02_MAIN"].function_map.as_ref().unwrap().count(), 1);
        assert!(inputs["02_MAIN"].function_map.is_some());
        assert!(inputs["02_MAIN"].global_map.is_none());
        images[1].globals_applied = Some(0);
        images[1].globals_apply_skipped = Some(1);
        let apply_stage = globals_apply_stage(false, &outcome.maps, Some(&images), 0);
        assert_eq!(apply_stage.status, "ok");
        assert_eq!(
            apply_stage.output.as_deref(),
            Some("1 image(s) processed; 0 globals applied; 1 skipped")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sole_global_preparation_failure_skips_application_but_keeps_function_only_input() {
        // This catches the separate `globals` preparation failure being
        // misreported as an invocation, or consuming the same image's valid
        // function-only pass-2 work.
        let root = std::env::temp_dir().join(format!(
            "pme_globals_stage_sole_failure_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let images_dir = root.join("images");
        let image_dir = images_dir.join("02_MAIN");
        std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
        std::fs::write(image_dir.join("02_MAIN.bin"), b"main bytes").unwrap();
        let mut images = vec![analyzed_image("02_MAIN")];
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_test_map("sole-failure-functions.json", 3)),
                function_names: HashMap::new(),
                evidence_name_projection: Default::default(),
            },
        )]);

        let function_inputs = take_globals_function_inputs(&mut function_maps);
        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |_, _, _, _, _, _| Err(Error::Serialize("malformed functions.json".into())),
        );
        let inputs = prepare_pass2_inputs(&function_maps, &outcome.maps);
        let apply_stage = globals_apply_stage(false, &outcome.maps, Some(&images), 12);

        assert_eq!(outcome.stage.status, "failed");
        assert!(outcome.maps.is_empty());
        assert_eq!(inputs["02_MAIN"].function_map.as_ref().unwrap().count(), 3);
        assert!(inputs["02_MAIN"].function_map.is_some());
        assert!(inputs["02_MAIN"].global_map.is_none());
        assert_eq!(apply_stage.status, "skipped");
        assert_eq!(apply_stage.reason.as_deref(), Some("no recovered globals"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pass2_success_refreshes_despite_globals_summary_error() {
        // This catches aggregate reporting short-circuiting the already-safe
        // refresh of an independently successful same-process function export.
        let root = std::env::temp_dir().join(format!(
            "pme_globals_apply_refresh_isolation_{}",
            std::process::id()
        ));
        let ghidra_dir = root.join("ghidra");
        let images_dir = root.join("images");
        let export = ghidra_dir.join("export").join("02_MAIN");
        let destination = images_dir.join("02_MAIN").join("decompiled");
        std::fs::create_dir_all(&export).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        for (name, contents) in [
            ("decompiled.c", "void refreshed_function(void) {}"),
            ("disasm.lst", "refreshed disassembly"),
            ("functions.json", "[]"),
        ] {
            std::fs::write(export.join(name), contents).unwrap();
            std::fs::write(destination.join(name), format!("stale {name}")).unwrap();
        }
        std::fs::write(destination.join("thumb_functions.json"), b"sidecar").unwrap();
        let prepared = HashMap::from([(
            "02_MAIN".to_string(),
            prepared_global_map("refresh-globals-02_MAIN.json", 1),
        )]);
        let mut image = analyzed_image("02_MAIN");
        image.pass2_applied = Some(1);
        image.globals_apply_error = Some("global map rejected".into());

        let outcomes = HashMap::from([(
            "02_MAIN".to_string(),
            decompile::Pass2ProcessOutcome::ProcessSucceeded,
        )]);
        let (refreshed, refresh_errors) =
            refresh_pass2_outputs_with(&outcomes, std::slice::from_mut(&mut image), |label| {
                refresh_decompiled(&ghidra_dir, &images_dir, label)
            });
        let pass2_stage = decompile_pass2_stage(1, refreshed, refresh_errors, 8);
        let stage = globals_apply_stage(false, &prepared, Some(&[image]), 9);

        assert_eq!(pass2_stage.status, "ok");
        assert_eq!(stage.status, "failed");
        assert_eq!(stage.error.as_deref(), Some("02_MAIN: global map rejected"));
        assert_eq!(
            std::fs::read_to_string(destination.join("decompiled.c")).unwrap(),
            "void refreshed_function(void) {}"
        );
        assert_eq!(
            std::fs::read(destination.join("thumb_functions.json")).unwrap(),
            b"sidecar"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn direct_symbol_routes_preserve_exact_once_order() {
        let mut normal = Vec::new();
        orchestrate_symbol_route(false, |step| normal.push(step));
        assert_eq!(
            normal,
            vec![
                SymbolRouteStep::PrepareNamesAndProjection,
                SymbolRouteStep::RunGlobals(GlobalsRouteMode::PrepareApplicationInput),
                SymbolRouteStep::DispatchPass2,
                SymbolRouteStep::Finalize {
                    rewrite_decompiled_c: false,
                },
            ]
        );
        assert_eq!(
            normal
                .iter()
                .filter(|step| matches!(step, SymbolRouteStep::RunGlobals(_)))
                .count(),
            1
        );
        assert_eq!(
            normal
                .iter()
                .filter(|step| matches!(step, SymbolRouteStep::DispatchPass2))
                .count(),
            1
        );

        let mut disabled = Vec::new();
        orchestrate_symbol_route(true, |step| disabled.push(step));
        assert_eq!(
            disabled,
            vec![
                SymbolRouteStep::Finalize {
                    rewrite_decompiled_c: true,
                },
                SymbolRouteStep::LoadFinalizedNames,
                SymbolRouteStep::RunGlobals(GlobalsRouteMode::RecordOnly),
            ]
        );
        assert_eq!(
            disabled
                .iter()
                .filter(|step| matches!(step, SymbolRouteStep::RunGlobals(_)))
                .count(),
            1
        );
        assert!(!disabled.iter().any(|step| matches!(
            step,
            SymbolRouteStep::RunGlobals(GlobalsRouteMode::PrepareApplicationInput)
                | SymbolRouteStep::DispatchPass2
        )));
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
        let function_inputs = PreparedGlobalsFunctionInputs {
            recovered_names: load_finalized_function_name_indexes(&images_dir, &images),
            evidence_names: HashMap::new(),
        };
        let mut calls = 0usize;

        let outcome = run_globals_stage_with(
            &mut images,
            &images_dir,
            &root.join("manifest.json"),
            &function_inputs,
            &globals::GlobalsOpts::default(),
            |image_dir, label, _, names, evidence_names, _| {
                calls += 1;
                assert_eq!(label, "02_MAIN");
                assert!(evidence_names.is_none());
                assert_eq!(
                    names,
                    &HashMap::from([
                        ("40".to_string(), "RecoveredMain".to_string()),
                        ("44".to_string(), "guess_main_44".to_string()),
                    ])
                );
                std::fs::write(image_dir.join("decompiled/globals.json"), b"globals").unwrap();
                Ok(globals::GlobalsReport {
                    recovered_count: 1,
                    conflicts_dropped: 0,
                    provisional_generated: 0,
                    provisional_suppressed_by_recovered: 0,
                })
            },
        );

        assert_eq!(calls, 1);
        assert_eq!(outcome.maps["02_MAIN"].pass2_map.count(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn direct_normal_route_moves_globals_payload_and_retains_only_typed_maps() {
        let mut function_maps = HashMap::from([(
            "02_MAIN".to_string(),
            PreparedFunctionMap {
                pass2_map: Some(prepared_test_map("moved-functions.json", 1)),
                function_names: HashMap::from([("40".to_string(), "RecoveredMain".to_string())]),
                evidence_name_projection: globals::FunctionEvidenceNameProjection::default(),
            },
        )]);

        let function_inputs = take_globals_function_inputs(&mut function_maps);

        assert_eq!(
            function_inputs.recovered_names["02_MAIN"]["40"],
            "RecoveredMain"
        );
        assert!(function_inputs.evidence_names.contains_key("02_MAIN"));
        assert!(function_maps["02_MAIN"].function_names.is_empty());
        assert!(
            function_maps["02_MAIN"]
                .evidence_name_projection
                .name_for(globals::Arch::Arm, 0x40)
                .is_none()
        );
        assert_eq!(
            function_maps["02_MAIN"].pass2_map.as_ref().unwrap().count(),
            1
        );
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
                        globals_applied: None,
                        globals_apply_skipped: None,
                        globals_apply_error: None,
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
                        globals_applied: None,
                        globals_apply_skipped: None,
                        globals_apply_error: None,
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
    fn image_report_distinguishes_uninvoked_executed_zero_and_failed_global_application() {
        // This catches the ImageReport mirror dropping the raw pass-2 outcome,
        // collapsing executed zero into absent, or serializing stale success
        // counts together with an application error.
        let mut uninvoked = analyzed_image("02_MAIN");
        uninvoked.pass2_applied = Some(3);
        let uninvoked_json = serde_json::to_value(ImageReport::from_result(&uninvoked)).unwrap();
        assert_eq!(
            uninvoked_json,
            serde_json::json!({
                "image": "02_MAIN",
                "status": "analyzed",
                "functions": 1,
                "pass2_applied": 3
            })
        );

        let mut executed_zero = analyzed_image("03_APM");
        executed_zero.pass2_applied = Some(2);
        executed_zero.globals_applied = Some(0);
        executed_zero.globals_apply_skipped = Some(4);
        let executed_zero_json =
            serde_json::to_value(ImageReport::from_result(&executed_zero)).unwrap();
        assert_eq!(
            executed_zero_json,
            serde_json::json!({
                "image": "03_APM",
                "status": "analyzed",
                "functions": 1,
                "pass2_applied": 2,
                "globals_applied": 0,
                "globals_apply_skipped": 4
            })
        );

        let mut failed = analyzed_image("04_VSS");
        failed.globals_apply_error = Some("missing ApplyGlobals summary".into());
        let failed_json = serde_json::to_value(ImageReport::from_result(&failed)).unwrap();
        assert_eq!(
            failed_json,
            serde_json::json!({
                "image": "04_VSS",
                "status": "analyzed",
                "functions": 1,
                "globals_apply_error": "missing ApplyGlobals summary"
            })
        );
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
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
                globals_applied: None,
                globals_apply_skipped: None,
                globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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

        // Destination: pass-1 tree with old Ghidra trio plus globals, Thumb,
        // and an unrelated future sidecar.
        let dest = images.join(label).join("decompiled");
        std::fs::create_dir_all(dest.join("thumb")).unwrap();
        std::fs::write(dest.join("decompiled.c"), b"OLD_C").unwrap();
        std::fs::write(dest.join("disasm.lst"), b"OLD_LST").unwrap();
        std::fs::write(dest.join("functions.json"), b"OLD_FN").unwrap();
        let thumb_json = b"{\"format\":\"thumb-v1\",\"functions\":[]}";
        let thumb_stdout = b"r2-stdout-bytes-must-survive";
        let globals_json = b"{\"format\":\"pixel-modem-extractor-globals-v1\",\"globals\":[]}";
        let future_sidecar = b"future-sidecar-bytes-must-survive";
        std::fs::write(dest.join("thumb_functions.json"), thumb_json).unwrap();
        std::fs::write(dest.join("thumb").join("410b0000.stdout"), thumb_stdout).unwrap();
        std::fs::write(dest.join("globals.json"), globals_json).unwrap();
        std::fs::write(dest.join("future-sidecar.bin"), future_sidecar).unwrap();

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
        assert_eq!(
            std::fs::read(dest.join("globals.json")).unwrap(),
            globals_json,
            "globals.json must be byte-identical"
        );
        assert_eq!(
            std::fs::read(dest.join("future-sidecar.bin")).unwrap(),
            future_sidecar,
            "unrelated sidecars must be byte-identical"
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
            globals_applied: None,
            globals_apply_skipped: None,
            globals_apply_error: None,
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
