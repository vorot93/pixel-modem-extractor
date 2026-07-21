//! `decompose` — the exhaustive one-command pipeline. Runs extraction, decompiles
//! every modem image (Ghidra + radare2), and runs every decoder, marshaling all
//! outputs into one per-image tree with a machine-readable `report.json`. Best-effort:
//! a stage failure is recorded and the run continues; the process exits non-zero if
//! anything failed. `--prune` reduces the tree to only the terminal ("leaf") artifacts.

use crate::decompile::{self, ImageOutcome};
use crate::error::{Error, Result};
use crate::{
    decode_rf, hwcfg, manifest, pipeline, recover_source, source_tree, symbolicate, tokens,
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
    /// Task 10 wires the public `--no-thumb-decompile` clap flag to this field.
    pub no_thumb_decompile: bool,
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

/// After pass 2, ExportDecomp.java has overwritten {ghidra}/export/{label}/.
/// Move the fresh files into images/<label>/decompiled/ (replacing pass 1's).
/// The slice file (<label>.bin) is already in place from pass 1; do not touch it.
fn refresh_decompiled(ghidra_dir: &Path, images_dir: &Path, label: &str) -> Result<()> {
    let export = ghidra_dir.join("export").join(label);
    if !export.exists() {
        return Ok(());
    }
    let dest = images_dir.join(label).join("decompiled");
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }
    std::fs::rename(&export, dest)?;
    Ok(())
}

/// Phase 2: run `decompile::thumb_enrich` against each image's
/// `images/<label>/decompiled/{decompiled.c,thumb_functions.json}`. Mutates each
/// `ImageResult.thumb_decompiled` (count) or `thumb_enrich_error` (failure text)
/// in place. Returns the per-image outcome so the caller can build a StageReport.
///
/// Images without a `thumb_functions.json` (no Thumb regions) are silently
/// skipped — Phase 2 only fires for images where radare2 carved Thumb.
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
            continue; // No Thumb regions on this image.
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

/// Build the per-image symbol map from pass-1 outputs and write each to
/// `<out>/ghidra/symbol_maps/<label>.json`. Returns `(label, (path, count))`
/// per image where `count` is the number of symbols with non-null names.
fn build_and_write_symbol_maps(
    out: &Path,
    images_dir: &Path,
    token_db: &Path,
    manifest: &Path,
) -> Vec<(String, (PathBuf, usize))> {
    let tokens = if token_db.exists() {
        std::fs::read(token_db)
            .ok()
            .and_then(|b| crate::tokens::parse(&b).ok())
            .map(|db| symbolicate::token_map(&db))
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    let maps_dir = out.join("ghidra").join("symbol_maps");
    let _ = std::fs::create_dir_all(&maps_dir);
    let mut out_vec = Vec::new();
    if let Ok(entries) = std::fs::read_dir(images_dir) {
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
                Err(_) => continue,
            };
            let with_names = symbols.iter().filter(|s| s.name.is_some()).count();
            let map_path = maps_dir.join(format!("{label}.json"));
            if symbolicate::write_symbol_map(&map_path, &label, &symbols, &image_sha, &funcs_sha)
                .is_ok()
            {
                out_vec.push((label, (map_path, with_names)));
            }
        }
    }
    out_vec
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
        tighten_wall_clock_budget_override: None,
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
    let symbol_maps = if opts.no_symbol_pass {
        Vec::new()
    } else {
        build_and_write_symbol_maps(out, &images_dir, &token_db, &out.join("manifest.json"))
    };
    if opts.no_symbol_pass {
        stages.push(StageReport::skipped("symbol_map", "--no-symbol-pass"));
    } else {
        let total: usize = symbol_maps.iter().map(|(_, (_, n))| *n).sum();
        let stage = if total == 0 {
            StageReport::skipped("symbol_map", "no symbols recovered")
        } else {
            StageReport::ok("symbol_map", "ghidra/symbol_maps/", t.elapsed().as_millis())
        };
        stages.push(stage);
    }

    // 7. Decompile pass 2 — ApplySymbols + ExportDecomp on each image with a
    //    non-empty map. Consumes pass1_report (pass 1 already ran in step 3).
    //    Per-image pass-2 failures land in ImageResult.pass2_error and do not
    //    abort the orchestrator — pass 1 already produced a valid decompiled.c.
    if !opts.no_symbol_pass {
        if let Some(rep) = pass1_report {
            let t = Instant::now();
            let map_paths: HashMap<String, PathBuf> = symbol_maps
                .into_iter()
                .map(|(label, (path, _))| (label, path))
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
                    let image_reports: Vec<ImageReport> =
                        rep2.images.iter().map(ImageReport::from_result).collect();
                    // Replace the last decompile stage entry.
                    if let Some(pos) = stages.iter().rposition(|s| s.stage == "decompile") {
                        stages[pos] =
                            StageReport::decompile(image_reports, t.elapsed().as_millis());
                    }
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
            "void thumb_40e1200(void)\n{\n  return;\n}\n",
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
        };
        let report = ImageReport::from_result(&r);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"thumb_decompiled\":3"));
        assert!(!json.contains("thumb_tighten_error"));
        assert!(json.contains("\"thumb_enrich_error\":\"malformed decompiled.c\""));
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
