//! Decompile the modem TOC code images with Ghidra. Pure-Rust generation always
//! emits a self-contained Ghidra import kit (per-image slices, a machine-readable
//! `ghidra_load.json` load spec, a turnkey `run_ghidra.sh`, and an embedded Java
//! exporter); the opt-in `--run` drives `analyzeHeadless` headless to export
//! decompiled C, a disassembly listing, a function inventory, and a saved project,
//! with radare2 covering dense Thumb regions that Ghidra cannot converge on.

use crate::{
    error::{Error, Result},
    toc::Toc,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

const EXPORT_DECOMP_JAVA: &str = include_str!("ghidra/ExportDecomp.java");
const TAME_ANALYSIS_JAVA: &str = include_str!("ghidra/TameAnalysis.java");
const APPLY_SYMBOLS_JAVA: &str = include_str!("ghidra/ApplySymbols.java");

#[derive(Debug, Clone)]
pub struct Opts {
    pub run: bool,
    pub image: Option<String>,
    pub ghidra_home: Option<PathBuf>,
    pub processor: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SourceRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct ImageSpec {
    pub name: String,
    pub file: String,
    pub size: u32,
    pub base_addr: String,
    pub entry_point: String,
    pub sha256: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct LoadSpec {
    pub tool_version: String,
    pub source: SourceRef,
    pub processor: String,
    pub images: Vec<ImageSpec>,
}

pub fn build_load_spec(
    toc: &Toc,
    data: &[u8],
    source_name: &str,
    processor: &str,
) -> Result<LoadSpec> {
    let images = toc
        .embedded()
        .into_iter()
        .map(|e| {
            let label = e.label();
            let start = e.offset as usize;
            let end = start + e.size as usize;
            // Defensive: a directly-constructed / malformed TOC could point past the
            // buffer. (The wired path validates ranges via `split_to_dir` first, so
            // this never trips there — it only protects a direct caller.)
            if end > data.len() {
                return Err(Error::SizeMismatch {
                    name: label,
                    expected: e.size as u64,
                    actual: data.len().saturating_sub(start) as u64,
                });
            }
            let file = format!("images/{label}");
            Ok(ImageSpec {
                name: label,
                file,
                size: e.size,
                base_addr: format!("0x{:08x}", e.load_addr),
                entry_point: format!("0x{:08x}", e.load_addr),
                sha256: crate::manifest::sha256_bytes(&data[start..end]),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LoadSpec {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        source: SourceRef {
            path: source_name.to_string(),
            sha256: crate::manifest::sha256_bytes(data),
        },
        processor: processor.to_string(),
        images,
    })
}

/// The `analyzeHeadless` argument vector for one image — the single source of
/// truth used both to serialize `run_ghidra.sh` and to spawn under `--run`.
/// `root` is the path prefix (an absolute out dir for `--run`, or `$HERE` in the
/// shell script). NOTE: `-loader-baseAddr` is hex WITHOUT a `0x` prefix.
fn headless_args(
    root: &str,
    label: &str,
    processor: &str,
    base_addr: u32,
    thumb_regions: &[(u32, u32)],
) -> Vec<String> {
    let mut args = vec![
        format!("{root}/ghidra_project"),
        "pixel-modem".to_string(),
        "-import".to_string(),
        format!("{root}/images/{label}"),
        "-processor".to_string(),
        processor.to_string(),
        "-loader".to_string(),
        "BinaryLoader".to_string(),
        "-loader-baseAddr".to_string(),
        format!("{base_addr:08x}"),
        "-scriptPath".to_string(),
        format!("{root}/scripts"),
        // Pre-script (runs before auto-analysis): disables the Aggressive Instruction
        // Finder and marks the dense high-entropy regions passed below (each as
        // "addrHex:lenHex") as data — Thumb-2 protocol-stack code Ghidra can't converge
        // on, so radare2 analyzes it separately.
        "-preScript".to_string(),
        "TameAnalysis.java".to_string(),
    ];
    for (addr, len) in thumb_regions {
        args.push(format!("{addr:08x}:{len:x}"));
    }
    args.extend([
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
        "-overwrite".to_string(),
    ]);
    args
}

fn ghidra_config_home(root: &Path) -> PathBuf {
    root.join("ghidra_config")
}

fn ghidra_cache_home(root: &Path) -> PathBuf {
    root.join("ghidra_cache")
}

fn ghidra_temp_home(root: &Path) -> PathBuf {
    root.join("ghidra_tmp")
}

fn ghidra_java_options(root: &Path, existing: Option<&OsStr>) -> OsString {
    let local = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        ghidra_config_home(root).display(),
        ghidra_cache_home(root).display(),
        ghidra_temp_home(root).display(),
        ghidra_temp_home(root).display()
    );
    let mut options = OsString::new();
    if let Some(existing) = existing.filter(|s| !s.is_empty()) {
        options.push(existing);
        options.push(" ");
    }
    options.push(local);
    options
}

fn headless_command(
    headless: &Path,
    args: &[String],
    root: &Path,
    java_home: Option<&Path>,
) -> std::process::Command {
    let mut command = std::process::Command::new(headless);
    command.args(args);
    command.env("XDG_CONFIG_HOME", ghidra_config_home(root));
    command.env("XDG_CACHE_HOME", ghidra_cache_home(root));
    command.env(
        "GHIDRA_HEADLESS_JAVA_OPTIONS",
        ghidra_java_options(
            root,
            std::env::var_os("GHIDRA_HEADLESS_JAVA_OPTIONS").as_deref(),
        ),
    );
    // Homebrew's analyzeHeadless (unlike its ghidraRun wrapper) doesn't pin a JDK; supply
    // one only when discovery found a wrapper that pins it and the caller left JAVA_HOME unset.
    if let Some(jh) = java_home {
        command.env("JAVA_HOME", jh);
    }
    command
}

/// True if this image should be analyzed under `--run`: no `--image` filter, or
/// the filter matches the canonical label (e.g. "02_MAIN") or the bare TOC name (e.g. "MAIN").
fn image_matches(want: Option<&str>, label: &str, name: &str) -> bool {
    want.is_none() || want == Some(label) || want == Some(name)
}

/// One image's `--run` result: either analyzed (with the function count ExportDecomp
/// recorded) or `analyzeHeadless` exited non-zero. Recorded per image so a full run
/// reports every partition instead of aborting on the first failure.
#[derive(Debug)]
pub enum ImageOutcome {
    Analyzed(usize),
    Failed(i32),
}

/// One image's structured `--run` outcome, surfaced for callers that orchestrate
/// (e.g. `decompose`) rather than just print.
#[derive(Debug)]
pub struct ImageResult {
    pub label: String,
    pub outcome: ImageOutcome,
    pub thumb_functions: Option<usize>,
    /// Reason-only Thumb/radare2 failure text; `label` already identifies the image.
    pub thumb_error: Option<String>,
    /// Pass-2 (symbolication) outcome: count of names `ApplySymbols.java`
    /// reported applying. `None` when pass 2 did not run for this image.
    pub pass2_applied: Option<usize>,
    /// Reason-only pass-2 failure text (e.g. analyzeHeadless exited non-zero).
    pub pass2_error: Option<String>,
}

/// A decompile run's per-image outcomes plus the `ghidra_load.json` path.
#[derive(Debug)]
pub struct DecompileReport {
    pub images: Vec<ImageResult>,
    pub spec_path: PathBuf,
}

/// Count the functions ExportDecomp.java recorded for an image — its `functions.json`
/// is a JSON array. A missing or unparseable file counts as 0, so a silently-empty
/// partition (e.g. a compressed/encrypted one, which yields no disassembly) reads as
/// 0 functions rather than erroring.
fn count_functions(export_dir: &Path) -> usize {
    std::fs::read(export_dir.join("functions.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

fn generation_only_hint(out: &Path) -> String {
    format!(
        "(generation only; pass --run to drive Ghidra plus radare2 for dense Thumb regions, or run {}/run_ghidra.sh for Ghidra-only import/export)",
        out.display()
    )
}

/// Shannon entropy (bits/byte) of a window. Native ARM code sits around 5–6;
/// compressed/encrypted data sits near 7–8, giving a clean split for §`thumb_regions`.
fn window_entropy(w: &[u8]) -> f64 {
    if w.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in w {
        counts[b as usize] += 1;
    }
    let n = w.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Detect large dense-Thumb regions in an image by entropy. MAIN interleaves ARM/A32
/// code with multi-MB Thumb-2 blobs — the upper protocol stack (IMS/VoLTE/SIP, RRC,
/// NAS, L1/PHY, 5G-NR). Thumb-2 is denser than A32 (~7 bits/byte vs ~5-6), so high
/// entropy marks the Thumb regions. Ghidra cannot converge on them (it spins forever
/// in a `ClearFlowAndRepairCmd` overlapping-function loop — ~10M+ repair messages on
/// MAIN), so the pre-script marks them as data for Ghidra and the host analyzes them
/// with radare2 instead.
///
/// Windows above `ENTROPY_THRESHOLD` are merged; only regions ≥ `MIN_REGION` are
/// returned, so small high-entropy spans (A32 constant pools) aren't misclassified.
/// Returns `(absolute_address, length)` per region.
fn thumb_regions(bytes: &[u8], load_addr: u32) -> Vec<(u32, u32)> {
    const WINDOW: usize = 64 * 1024;
    const ENTROPY_THRESHOLD: f64 = 6.5;
    const MIN_REGION: usize = 1024 * 1024; // 1 MiB

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut open: Option<usize> = None;
    let mut off = 0;
    while off < bytes.len() {
        let end = (off + WINDOW).min(bytes.len());
        if window_entropy(&bytes[off..end]) > ENTROPY_THRESHOLD {
            open.get_or_insert(off);
        } else if let Some(start) = open.take() {
            spans.push((start, off));
        }
        off = end;
    }
    if let Some(start) = open.take() {
        spans.push((start, bytes.len()));
    }
    spans
        .into_iter()
        .filter(|(s, e)| e - s >= MIN_REGION)
        .map(|(s, e)| (load_addr.wrapping_add(s as u32), (e - s) as u32))
        .collect()
}

/// Write a turnkey `run_ghidra.sh` (one `analyzeHeadless` invocation per image),
/// built from `headless_args` against a relocatable `$HERE` root.
fn write_run_script(out: &Path, toc: &Toc, data: &[u8], processor: &str) -> Result<()> {
    let mut s = String::new();
    s.push_str("#!/usr/bin/env sh\n");
    s.push_str(
        "# Generated by pixel-modem-extractor decompile. Drives Ghidra headless per image.\n",
    );
    s.push_str("set -eu\n");
    s.push_str(": \"${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to your Ghidra install root}\"\n");
    // Upstream ships analyzeHeadless under support/; Homebrew nests it under libexec/support/.
    s.push_str("if [ -x \"$GHIDRA_INSTALL_DIR/support/analyzeHeadless\" ]; then\n");
    s.push_str("  HEADLESS=\"$GHIDRA_INSTALL_DIR/support/analyzeHeadless\"\n");
    s.push_str("elif [ -x \"$GHIDRA_INSTALL_DIR/libexec/support/analyzeHeadless\" ]; then\n");
    s.push_str("  HEADLESS=\"$GHIDRA_INSTALL_DIR/libexec/support/analyzeHeadless\"\n");
    s.push_str("else\n");
    s.push_str("  echo \"analyzeHeadless not found under $GHIDRA_INSTALL_DIR (looked in support/ and libexec/support/)\" >&2\n");
    s.push_str("  exit 1\n");
    s.push_str("fi\n");
    s.push_str("HERE=\"$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\"\n");
    s.push_str("export XDG_CONFIG_HOME=\"$HERE/ghidra_config\"\n");
    s.push_str("export XDG_CACHE_HOME=\"$HERE/ghidra_cache\"\n");
    s.push_str("GHIDRA_LOCAL_JAVA_OPTIONS=\"-Dapplication.settingsdir=$HERE/ghidra_config -Dapplication.cachedir=$HERE/ghidra_cache -Dapplication.tempdir=$HERE/ghidra_tmp -Djava.io.tmpdir=$HERE/ghidra_tmp\"\n");
    s.push_str("if [ \"${GHIDRA_HEADLESS_JAVA_OPTIONS+x}\" ]; then\n");
    s.push_str("  export GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_HEADLESS_JAVA_OPTIONS $GHIDRA_LOCAL_JAVA_OPTIONS\"\n");
    s.push_str("else\n");
    s.push_str("  export GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_LOCAL_JAVA_OPTIONS\"\n");
    s.push_str("fi\n");
    s.push_str("mkdir -p \"$HERE/ghidra_project\" \"$HERE/export\" \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$HERE/ghidra_tmp\"\n");
    for e in toc.embedded() {
        let start = (e.offset as usize).min(data.len());
        let end = (e.offset as usize + e.size as usize).min(data.len());
        let regions = thumb_regions(&data[start..end], e.load_addr);
        let args = headless_args("$HERE", &e.label(), processor, e.load_addr, &regions);
        s.push_str("\"$HEADLESS\"");
        for a in &args {
            s.push_str(" \"");
            s.push_str(a);
            s.push('"');
        }
        s.push('\n');
    }
    let path = out.join("run_ghidra.sh");
    std::fs::write(&path, s)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&path)?.permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&path, perm)?;
    }
    Ok(())
}

/// Build the Ghidra import kit (always) and, with `--run`, drive `analyzeHeadless` per
/// image — returning the structured per-image outcomes plus the `ghidra_load.json` path.
/// Unlike [`run`], this never errors on a per-image analysis failure: every partition is
/// attempted and recorded, so an orchestrator (e.g. `decompose`) decides what a failure means.
pub fn run_report(modem_bin: &Path, opts: &Opts, out: &Path) -> Result<DecompileReport> {
    let data = std::fs::read(modem_bin)?;
    let toc = Toc::parse(&data)?;
    std::fs::create_dir_all(out)?;

    // 1. per-image slices -> out/images/NN_NAME (validates ranges; CRC advisory only)
    toc.split_to_dir(&data, &out.join("images"), false)?;

    // 2. embedded Java scripts -> out/scripts/{TameAnalysis,ExportDecomp}.java
    //    (TameAnalysis pre-script tames Ghidra's auto-analysis; ExportDecomp post-script
    //    writes the decompiled C / disasm listing / function inventory)
    let scripts = out.join("scripts");
    std::fs::create_dir_all(&scripts)?;
    std::fs::write(scripts.join("TameAnalysis.java"), TAME_ANALYSIS_JAVA)?;
    std::fs::write(scripts.join("ExportDecomp.java"), EXPORT_DECOMP_JAVA)?;
    std::fs::write(scripts.join("ApplySymbols.java"), APPLY_SYMBOLS_JAVA)?;

    // 3. machine-readable load spec -> out/ghidra_load.json
    let source_name = modem_bin
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("modem.bin");
    let spec = build_load_spec(&toc, &data, source_name, &opts.processor)?;
    let spec_path = out.join("ghidra_load.json");
    std::fs::write(
        &spec_path,
        serde_json::to_string_pretty(&spec).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;

    // 4. turnkey shell script -> out/run_ghidra.sh
    write_run_script(out, &toc, &data, &opts.processor)?;

    // 5. optional: drive Ghidra headless per selected image, plus radare2 for dense Thumb regions
    let mut image_results: Vec<ImageResult> = Vec::new();
    if opts.run {
        let install = find_ghidra(opts)?;
        let java_home =
            resolve_java_home(std::env::var_os("JAVA_HOME"), install.ghidra_run.as_deref());
        // analyzeHeadless needs the project dir to exist; use an absolute (canonical) root so
        // the spawned invocation is cwd-independent (the generated run_ghidra.sh uses $HERE).
        let root = std::fs::canonicalize(out)?;
        std::fs::create_dir_all(root.join("ghidra_project"))?;
        std::fs::create_dir_all(ghidra_config_home(&root))?;
        std::fs::create_dir_all(ghidra_cache_home(&root))?;
        std::fs::create_dir_all(ghidra_temp_home(&root))?;
        let root_str = root.to_string_lossy().into_owned();
        let want = opts.image.as_deref();
        let r2_bin = find_radare2();
        // Analyze every selected image, recording each outcome rather than aborting on the
        // first failure — so a heavy or unanalyzable partition (the ~87 MB MAIN, or an
        // encrypted one) can't sink the rest of a full run. Tuple per image:
        // (label, A32 Ghidra outcome, Thumb radare2 function count, Thumb radare2 error).
        let mut results: Vec<(String, ImageOutcome, Option<usize>, Option<String>)> = Vec::new();
        for e in toc.embedded() {
            let label = e.label();
            if !image_matches(want, &label, &e.name) {
                continue;
            }
            let start = (e.offset as usize).min(data.len());
            let end = (e.offset as usize + e.size as usize).min(data.len());
            let img = &data[start..end];
            let regions = thumb_regions(img, e.load_addr);
            tracing::info!("ghidra: analyzing {label} (base 0x{:08x})", e.load_addr);
            if !regions.is_empty() {
                tracing::info!(
                    "ghidra: {label} has {} dense Thumb-2 region(s) — marked as data (radare2 handles them)",
                    regions.len()
                );
            }
            let args = headless_args(&root_str, &label, &opts.processor, e.load_addr, &regions);
            let status =
                headless_command(&install.headless, &args, &root, java_home.as_deref()).status()?;
            let outcome = if status.success() {
                let n = count_functions(&root.join("export").join(&label));
                if n == 0 {
                    tracing::warn!(
                        "ghidra: {label} yielded 0 functions — no decompilable code (e.g. a compressed/encrypted partition)"
                    );
                }
                ImageOutcome::Analyzed(n)
            } else {
                let code = status.code().unwrap_or(-1);
                tracing::warn!("ghidra: {label} failed (analyzeHeadless exit {code})");
                ImageOutcome::Failed(code)
            };
            // Ghidra can't converge on the dense Thumb-2 regions (overlap-repair loop) and
            // marked them as data — hand them to radare2 for the protocol stack.
            let (thumb_functions, thumb_error) = if regions.is_empty() {
                (None, None)
            } else if let Some(r2) = &r2_bin {
                match run_radare2_thumb(
                    r2,
                    img,
                    e.load_addr,
                    &regions,
                    &root.join("export").join(&label),
                ) {
                    Ok(n) => {
                        tracing::info!("radare2: {label} Thumb stack -> {n} function(s)");
                        (Some(n), None)
                    }
                    Err(err) => {
                        tracing::warn!("radare2: {label} failed: {err}");
                        (None, Some(err.to_string()))
                    }
                }
            } else {
                let err = format!(
                    "{} Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them",
                    regions.len()
                );
                tracing::warn!("{label}: {err}");
                (None, Some(err))
            };
            results.push((label, outcome, thumb_functions, thumb_error));
        }
        if results.is_empty() {
            return Err(Error::NotFound(match &opts.image {
                Some(img) => format!("no image matched --image {img}"),
                None => "no embedded images found in TOC".to_string(),
            }));
        }
        println!(
            "ghidra: analyzed {} image(s) -> {}",
            results.len(),
            out.join("export").display()
        );
        for (label, outcome, thumb_functions, thumb_error) in &results {
            let t = if let Some(n) = thumb_functions {
                format!("  + {n} Thumb fn(s) [radare2]")
            } else if let Some(err) = thumb_error {
                format!("  + Thumb FAILED [radare2: {err}]")
            } else {
                String::new()
            };
            match outcome {
                ImageOutcome::Analyzed(n) => println!("  {label:<11} {n} A32 function(s){t}"),
                ImageOutcome::Failed(code) => println!("  {label:<11} FAILED (exit {code}){t}"),
            }
        }
        image_results = results
            .into_iter()
            .map(
                |(label, outcome, thumb_functions, thumb_error)| ImageResult {
                    label,
                    outcome,
                    thumb_functions,
                    thumb_error,
                    pass2_applied: None,
                    pass2_error: None,
                },
            )
            .collect();
    }

    println!("decompile kit -> {}", out.display());
    for img in &spec.images {
        println!(
            "  {:<11} base {}  size {}",
            img.name, img.base_addr, img.size
        );
    }
    if !opts.run {
        println!("{}", generation_only_hint(out));
    }
    Ok(DecompileReport {
        images: image_results,
        spec_path,
    })
}

/// Convert structured per-image outcomes into the standalone `decompile` failure,
/// after every selected image has had a chance to run.
fn report_failure(report: &DecompileReport) -> Option<Error> {
    if let Some(code) = report.images.iter().find_map(|r| match r.outcome {
        ImageOutcome::Failed(c) => Some(c),
        ImageOutcome::Analyzed(_) => None,
    }) {
        let failed: Vec<&str> = report
            .images
            .iter()
            .filter_map(|r| {
                matches!(r.outcome, ImageOutcome::Failed(_)).then_some(r.label.as_str())
            })
            .collect();
        return Some(Error::GhidraFailed {
            image: failed.join(", "),
            code,
        });
    }
    let thumb_failed: Vec<String> = report
        .images
        .iter()
        .filter_map(|r| {
            r.thumb_error
                .as_ref()
                .map(|err| format!("{}: {err}", r.label))
        })
        .collect();
    if !thumb_failed.is_empty() {
        return Some(Error::DecomposeIncomplete(format!(
            "radare2 failed on {}",
            thumb_failed.join(", ")
        )));
    }
    None
}

/// The `analyzeHeadless` argument vector for pass 2 of `run_two_pass`. Runs in
/// `-process` mode on the existing project so there is no re-import and no
/// re-analysis: `ApplySymbols.java` renames functions and sets plate comments,
/// then `ExportDecomp.java` regenerates `decompiled.c` with the new names and
/// comments baked in.
fn headless_process_args(root: &str, label: &str, map_path: &Path) -> Vec<String> {
    vec![
        format!("{root}/ghidra_project"),
        "pixel-modem".to_string(),
        "-process".to_string(),
        label.to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        format!("{root}/scripts"),
        "-postScript".to_string(),
        "ApplySymbols.java".to_string(),
        map_path.to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        format!("{root}/export/{label}"),
    ]
}

/// Extract the `N` from the summary line
/// `ApplySymbols: image=<image> applied N names, M plate comments, skipped K`.
/// `None` when the line is missing or the count is not an integer — the caller
/// treats `None` as "no information from pass 2".
fn parse_pass2_summary(stdout: &str) -> Option<usize> {
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("ApplySymbols:") else {
            continue;
        };
        let Some(idx) = rest.find("applied ") else {
            continue;
        };
        let after = &rest[idx + "applied ".len()..];
        let end = after.find(' ').unwrap_or(after.len());
        if let Ok(n) = after[..end].parse::<usize>() {
            return Some(n);
        }
    }
    None
}

/// Two-pass decompile. Pass 1 is exactly today's `run_report`. Pass 2 runs only
/// for images whose `symbol_maps.get(&label)` exists, points at a readable file,
/// and contains at least one non-null `name`. Per-image pass-2 failures are
/// recorded into `ImageResult.pass2_error`, not propagated — pass 1 already
/// produced a valid `decompiled.c`.
pub fn run_two_pass(
    modem_bin: &Path,
    opts: &Opts,
    out: &Path,
    symbol_maps: &HashMap<String, PathBuf>,
) -> Result<DecompileReport> {
    let mut report = run_report(modem_bin, opts, out)?;
    if !opts.run {
        return Ok(report);
    }
    let install = find_ghidra(opts)?;
    let java_home = resolve_java_home(std::env::var_os("JAVA_HOME"), install.ghidra_run.as_deref());
    let root = std::fs::canonicalize(out)?;
    let root_str = root.to_string_lossy().into_owned();

    for ir in &mut report.images {
        let Some(map_path) = symbol_maps.get(&ir.label) else {
            continue;
        };
        if !map_path.exists() {
            continue;
        }
        // Skip pass 2 when the map has no non-null names — pass 1's decompiled.c
        // is already fine for that image.
        let map_str = std::fs::read_to_string(map_path).unwrap_or_default();
        let map_json: serde_json::Value =
            serde_json::from_str(&map_str).unwrap_or(serde_json::Value::Null);
        let has_names = map_json["symbols"]
            .as_array()
            .map(|arr| arr.iter().any(|s| !s["name"].is_null()))
            .unwrap_or(false);
        if !has_names {
            continue;
        }

        tracing::info!("ghidra: pass 2 symbolication for {}", ir.label);
        let args = headless_process_args(&root_str, &ir.label, map_path);
        let output = headless_command(&install.headless, &args, &root, java_home.as_deref())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            ir.pass2_applied = parse_pass2_summary(&stdout);
        } else {
            let code = output.status.code().unwrap_or(-1);
            tracing::warn!("ghidra: pass 2 for {} failed (exit {code})", ir.label);
            ir.pass2_error = Some(format!("analyzeHeadless exit {code}"));
        }
    }
    Ok(report)
}

/// Generate the kit and (with `--run`) drive Ghidra plus radare2 for dense Thumb
/// regions; non-zero if any selected image failed either analysis path.
pub fn run(modem_bin: &Path, opts: &Opts, out: &Path) -> Result<PathBuf> {
    let report = run_report(modem_bin, opts, out)?;
    // Non-zero exit if any image failed — but only after all were attempted (run_report
    // records every partition), so a CI/script run still sees failure while keeping every
    // partition's results.
    if let Some(err) = report_failure(&report) {
        return Err(err);
    }
    Ok(report.spec_path)
}

/// A located Ghidra headless launcher plus the `ghidraRun` wrapper it was found
/// through, if any. The wrapper is the only source of a packager-pinned `JAVA_HOME`
/// (Homebrew's), read by the `--run` path — never by pure discovery.
#[derive(Debug, Clone, PartialEq)]
pub struct GhidraInstall {
    pub headless: PathBuf,
    pub ghidra_run: Option<PathBuf>,
}

/// First existing `analyzeHeadless` under `root`: the upstream tarball layout
/// (`support/`), then Homebrew's, which nests the whole dist under `libexec/`.
fn headless_in_root(root: &Path) -> Option<PathBuf> {
    [
        root.join("support").join("analyzeHeadless"),
        root.join("libexec").join("support").join("analyzeHeadless"),
    ]
    .into_iter()
    .find(|p| p.exists())
}

/// The `ghidraRun` wrapper for a discovered root, if present: Homebrew ships it at
/// `bin/ghidraRun`, upstream at the dist root. Only Homebrew's pins a `JAVA_HOME`.
fn wrapper_in_root(root: &Path) -> Option<PathBuf> {
    [root.join("bin").join("ghidraRun"), root.join("ghidraRun")]
        .into_iter()
        .find(|p| p.exists())
}

/// Candidate install roots implied by a (canonicalized) `ghidraRun` path: the directory
/// holding it (upstream ships it at the dist root) and that directory's parent (Homebrew
/// ships it at `<root>/bin/ghidraRun`).
fn roots_from_ghidra_run(run: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dir) = run.parent() {
        roots.push(dir.to_path_buf());
        if let Some(parent) = dir.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    roots
}

/// The `JAVA_HOME` a `ghidraRun` wrapper pins, if any. Homebrew's wrapper assigns
/// `JAVA_HOME="${JAVA_HOME:-<path>}"` (respecting an existing value); upstream's pins
/// nothing. Returns the default only when it parses unambiguously and the directory
/// exists — so a bad parse never overrides Ghidra's own JDK search.
fn java_home_from_ghidra_run(run: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(run).ok()?;
    for line in text.lines() {
        // Prefer the `${JAVA_HOME:-<default>}` form; fall back to a plain assignment.
        let candidate = if let Some(i) = line.find("${JAVA_HOME:-") {
            let rest = &line[i + "${JAVA_HOME:-".len()..];
            rest.find('}').map(|j| &rest[..j])
        } else if let Some(i) = line.find("JAVA_HOME=\"") {
            let rest = &line[i + "JAVA_HOME=\"".len()..];
            rest.find('"').map(|j| &rest[..j])
        } else {
            None
        };
        if let Some(c) = candidate {
            let c = c.trim();
            if !c.is_empty() && Path::new(c).exists() {
                return Some(PathBuf::from(c));
            }
        }
    }
    None
}

/// The `JAVA_HOME` to inject into the `analyzeHeadless` child, or `None` to leave it to
/// Ghidra. Ghidra rejects a mismatched `JAVA_HOME` rather than falling back, so never
/// override one the caller already set; otherwise reuse the wrapper's pinned JDK if any.
fn resolve_java_home(
    env_java_home: Option<OsString>,
    ghidra_run: Option<&Path>,
) -> Option<PathBuf> {
    if env_java_home.is_some() {
        return None;
    }
    ghidra_run.and_then(java_home_from_ghidra_run)
}

/// Pure discovery (no env reads — see `find_headless`): the first of (`--ghidra-home`,
/// `$GHIDRA_INSTALL_DIR`, a `PATH` dir) that yields an `analyzeHeadless`. Each `--ghidra-home`
/// / env candidate is treated as an install *root* and probed for both the upstream and
/// Homebrew layouts; on `PATH`, a bare `analyzeHeadless` wins, else a `ghidraRun` wrapper is
/// canonicalized and its root probed.
fn locate_tools(
    ghidra_home: Option<&Path>,
    env_dir: Option<&Path>,
    path_dirs: &[PathBuf],
) -> Option<GhidraInstall> {
    for root in [ghidra_home, env_dir].into_iter().flatten() {
        if let Some(headless) = headless_in_root(root) {
            return Some(GhidraInstall {
                headless,
                ghidra_run: wrapper_in_root(root),
            });
        }
    }
    for dir in path_dirs {
        let bare = dir.join("analyzeHeadless");
        if bare.exists() {
            return Some(GhidraInstall {
                headless: bare,
                ghidra_run: None,
            });
        }
        // Homebrew exposes only a `ghidraRun` symlink on PATH; resolve it to the real
        // install root. A missing or dangling wrapper canonicalizes to Err -> skip.
        let Ok(canon) = std::fs::canonicalize(dir.join("ghidraRun")) else {
            continue;
        };
        for root in roots_from_ghidra_run(&canon) {
            if let Some(headless) = headless_in_root(&root) {
                return Some(GhidraInstall {
                    headless,
                    ghidra_run: Some(canon),
                });
            }
        }
    }
    None
}

/// Locate the Ghidra headless launcher: `--ghidra-home` → `$GHIDRA_INSTALL_DIR` → `PATH`
/// (a bare `analyzeHeadless`, or resolved from a `ghidraRun` wrapper). Each root is probed
/// for both the upstream (`support/`) and Homebrew (`libexec/support/`) layouts.
pub fn find_headless(ghidra_home: Option<&Path>) -> Result<GhidraInstall> {
    let env_dir = std::env::var_os("GHIDRA_INSTALL_DIR").map(PathBuf::from);
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    locate_tools(ghidra_home, env_dir.as_deref(), &path_dirs).ok_or_else(|| {
        Error::GhidraNotFound(
            "tried --ghidra-home, $GHIDRA_INSTALL_DIR, and PATH; if Ghidra was installed via \
             Homebrew, pass --ghidra-home \"$(brew --prefix ghidra)\" or add its bin to PATH"
                .into(),
        )
    })
}

fn find_ghidra(opts: &Opts) -> Result<GhidraInstall> {
    find_headless(opts.ghidra_home.as_deref())
}

/// Locate the `radare2` binary (`r2`) on `PATH` — used to analyze the Thumb-2 regions
/// Ghidra cannot. `None` if not installed (those regions are then left unanalyzed).
pub fn find_radare2() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join("r2"))
        .find(|p| p.exists())
}

fn json_hex(v: u64) -> String {
    format!("0x{v:x}")
}

fn json_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(n) = v.as_i64() {
        return (n >= 0).then_some(n as u64);
    }
    let s = v.as_str()?;
    s.strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| s.parse::<u64>().ok())
}

fn data_refs_from_pdfj(pdfj: &serde_json::Value) -> Vec<String> {
    fn is_data_ref(ref_obj: &serde_json::Map<String, serde_json::Value>) -> bool {
        let mut saw_data_hint = false;
        for field in ["type", "kind", "perm", "name"] {
            let Some(value) = ref_obj.get(field).and_then(serde_json::Value::as_str) else {
                continue;
            };
            let value = value.to_ascii_lowercase();
            if ["code", "call", "jump", "cjmp", "ujmp", "exec"]
                .iter()
                .any(|needle| value.contains(needle))
            {
                return false;
            }
            saw_data_hint |= ["data", "str", "string", "mem", "ptr", "read"]
                .iter()
                .any(|needle| value.contains(needle));
        }
        saw_data_hint
    }

    let mut refs = std::collections::BTreeSet::new();
    if let Some(ops) = pdfj.get("ops").and_then(serde_json::Value::as_array) {
        for op in ops {
            let Some(op_obj) = op.as_object() else {
                continue;
            };
            let Some(op_refs) = op_obj.get("refs").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for op_ref in op_refs {
                let Some(ref_obj) = op_ref.as_object() else {
                    continue;
                };
                if !is_data_ref(ref_obj) {
                    continue;
                }
                if let Some(addr) = ref_obj
                    .get("addr")
                    .or_else(|| ref_obj.get("to"))
                    .and_then(json_u64)
                {
                    refs.insert(addr);
                }
            }
        }
    }
    refs.into_iter().map(json_hex).collect()
}

fn pdfj_body(pdfj: &serde_json::Value) -> String {
    let mut body = String::new();
    if let Some(ops) = pdfj.get("ops").and_then(serde_json::Value::as_array) {
        for op in ops {
            let Some(offset) = op
                .get("offset")
                .or_else(|| op.get("addr"))
                .and_then(json_u64)
            else {
                continue;
            };
            let bytes = op
                .get("bytes")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let disasm = op
                .get("disasm")
                .or_else(|| op.get("opcode"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if bytes.is_empty() {
                body.push_str(&format!("0x{offset:08x}      {disasm}\n"));
            } else {
                body.push_str(&format!("0x{offset:08x}      {bytes:<8}  {disasm}\n"));
            }
        }
    }
    body
}

fn radare2_function_entry(raw: &serde_json::Value) -> Option<u64> {
    raw.get("offset")
        .or_else(|| raw.get("addr"))
        .and_then(json_u64)
}

fn pdfj_entry(pdfj: &serde_json::Value) -> Option<u64> {
    pdfj.get("addr")
        .or_else(|| pdfj.get("offset"))
        .and_then(json_u64)
        .or_else(|| {
            pdfj.get("ops")
                .and_then(serde_json::Value::as_array)
                .and_then(|ops| ops.first())
                .and_then(|op| op.get("offset").or_else(|| op.get("addr")))
                .and_then(json_u64)
        })
}

fn balanced_json_end(text: &str, start: usize) -> Option<usize> {
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (rel_idx, ch) in text[start..].char_indices() {
        let idx = start + rel_idx;
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' => {
                if stack.pop() != Some(ch) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(idx + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

fn radare2_json_values(stdout: &[u8]) -> Vec<serde_json::Value> {
    let text = String::from_utf8_lossy(stdout);
    let mut values = Vec::new();
    let mut pos = 0;

    while pos < text.len() {
        let Some((start, opener)) = text[pos..]
            .char_indices()
            .find(|(_, ch)| matches!(ch, '{' | '['))
            .map(|(rel_idx, ch)| (pos + rel_idx, ch))
        else {
            break;
        };

        if let Some(end) = balanced_json_end(&text, start)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text[start..end])
        {
            values.push(value);
            pos = end;
            continue;
        }

        pos = start + opener.len_utf8();
    }

    values
}

fn pdfj_values_from_radare2_output(values: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut pdfjs = Vec::new();
    let start = values
        .iter()
        .position(is_aflj_function_inventory)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    for value in values.iter().skip(start) {
        if value
            .get("ops")
            .and_then(serde_json::Value::as_array)
            .is_some()
        {
            pdfjs.push(value.clone());
        } else if let Some(values) = value.as_array() {
            pdfjs.extend(
                values
                    .iter()
                    .filter(|value| {
                        value
                            .get("ops")
                            .and_then(serde_json::Value::as_array)
                            .is_some()
                    })
                    .cloned(),
            );
        }
    }
    pdfjs
}

fn is_aflj_function_inventory(value: &serde_json::Value) -> bool {
    let Some(values) = value.as_array() else {
        return false;
    };
    !values.is_empty()
        && values.iter().all(|value| {
            value
                .as_object()
                .map(|obj| !obj.contains_key("ops"))
                .unwrap_or(false)
        })
}

#[derive(Debug)]
struct Radare2ThumbOutput {
    json_value_count: usize,
    has_function_inventory: bool,
    function_count: usize,
    pdfj_count: usize,
    missing_pdfj_count: usize,
    pairs: Vec<(serde_json::Value, serde_json::Value)>,
}

fn parse_radare2_thumb_output(stdout: &[u8]) -> Radare2ThumbOutput {
    let values = radare2_json_values(stdout);
    let Some(fns) = values
        .iter()
        .find(|value| is_aflj_function_inventory(value))
        .and_then(serde_json::Value::as_array)
    else {
        return Radare2ThumbOutput {
            json_value_count: values.len(),
            has_function_inventory: false,
            function_count: 0,
            pdfj_count: 0,
            missing_pdfj_count: 0,
            pairs: Vec::new(),
        };
    };
    let pdfjs = pdfj_values_from_radare2_output(&values);
    let mut used_pdfjs = vec![false; pdfjs.len()];
    let mut paired_pdfjs: Vec<Option<serde_json::Value>> = vec![None; fns.len()];

    for (idx, f) in fns.iter().enumerate() {
        let Some(entry) = radare2_function_entry(f) else {
            continue;
        };
        let Some(pdfj_idx) = pdfjs.iter().enumerate().find_map(|(pdfj_idx, pdfj)| {
            (!used_pdfjs[pdfj_idx] && pdfj_entry(pdfj) == Some(entry)).then_some(pdfj_idx)
        }) else {
            continue;
        };
        used_pdfjs[pdfj_idx] = true;
        paired_pdfjs[idx] = Some(pdfjs[pdfj_idx].clone());
    }

    for (idx, paired_pdfj) in paired_pdfjs.iter_mut().enumerate() {
        if paired_pdfj.is_some() {
            continue;
        }
        let Some(pdfj) = pdfjs.get(idx) else {
            continue;
        };
        if used_pdfjs[idx] {
            continue;
        }
        let fn_entry = fns.get(idx).and_then(radare2_function_entry);
        let candidate_entry = pdfj_entry(pdfj);
        if candidate_entry.is_none() || candidate_entry == fn_entry {
            used_pdfjs[idx] = true;
            *paired_pdfj = Some(pdfj.clone());
        }
    }

    let pairs: Vec<_> = fns
        .iter()
        .cloned()
        .zip(paired_pdfjs)
        .filter_map(|(f, pdfj)| pdfj.map(|pdfj| (f, pdfj)))
        .collect();
    let missing_pdfj_count = fns.len().saturating_sub(pairs.len());

    Radare2ThumbOutput {
        json_value_count: values.len(),
        has_function_inventory: true,
        function_count: fns.len(),
        pdfj_count: pdfjs.len(),
        missing_pdfj_count,
        pairs,
    }
}

#[cfg(test)]
fn radare2_thumb_function_pdfjs(stdout: &[u8]) -> Vec<(serde_json::Value, serde_json::Value)> {
    parse_radare2_thumb_output(stdout).pairs
}

fn parse_checked_radare2_thumb_output(stdout: &[u8], addr: u32) -> Result<Radare2ThumbOutput> {
    let parsed = parse_radare2_thumb_output(stdout);
    if parsed.json_value_count == 0 {
        return Err(Error::Serialize(format!(
            "radare2 produced no parseable JSON for Thumb region 0x{addr:x}"
        )));
    }
    if !parsed.has_function_inventory {
        return Err(Error::Serialize(format!(
            "radare2 produced parseable JSON but no aflj function inventory for Thumb region 0x{addr:x}"
        )));
    }
    if parsed.missing_pdfj_count > 0 {
        let pdfj_detail = if parsed.pdfj_count == 0 {
            "no parseable pdfj bodies".to_string()
        } else {
            format!(
                "missing {} pdfj {}",
                parsed.missing_pdfj_count,
                if parsed.missing_pdfj_count == 1 {
                    "body"
                } else {
                    "bodies"
                }
            )
        };
        return Err(Error::Serialize(format!(
            "radare2 reported {} functions but {pdfj_detail} for Thumb region 0x{addr:x}",
            parsed.function_count,
        )));
    }
    let empty_body_count = parsed
        .pairs
        .iter()
        .filter(|(_, pdfj)| pdfj_body(pdfj).is_empty())
        .count();
    if empty_body_count > 0 {
        return Err(Error::Serialize(format!(
            "radare2 reported {} functions but {} paired pdfj {} had an empty pdfj body for Thumb region 0x{addr:x}",
            parsed.function_count,
            empty_body_count,
            if empty_body_count == 1 {
                "body"
            } else {
                "bodies"
            }
        )));
    }
    Ok(parsed)
}

fn check_radare2_thumb_status(success: bool, code: Option<i32>, addr: u32) -> Result<()> {
    if success {
        return Ok(());
    }
    let status = code
        .map(|code| format!("status {code}"))
        .unwrap_or_else(|| "unknown status".to_string());
    Err(Error::Serialize(format!(
        "radare2 exited with {status} for Thumb region 0x{addr:x}"
    )))
}

#[cfg(test)]
fn normalize_radare2_function(
    raw: &serde_json::Value,
    pdfj: &serde_json::Value,
) -> Result<serde_json::Value> {
    normalize_radare2_function_checked(raw, pdfj, 0)
}

fn normalize_radare2_function_checked(
    raw: &serde_json::Value,
    pdfj: &serde_json::Value,
    region_addr: u32,
) -> Result<serde_json::Value> {
    let entry = radare2_function_entry(raw).ok_or_else(|| {
        Error::Serialize(format!(
            "radare2 function lacks entry/addr for Thumb region 0x{region_addr:x}"
        ))
    })?;
    let size = raw.get("size").and_then(json_u64).unwrap_or(0);
    let name = raw
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("thumb_{entry:x}"));
    let body = pdfj_body(pdfj);
    if body.is_empty() {
        return Err(Error::Serialize(format!(
            "radare2 function 0x{entry:x} has empty pdfj body for Thumb region 0x{region_addr:x}"
        )));
    }
    Ok(serde_json::json!({
        "name": name,
        "entry": json_hex(entry),
        "end": json_hex(entry.saturating_add(size)),
        "size": size,
        "body_kind": "thumb_disassembly",
        "body": body,
        "data_refs": data_refs_from_pdfj(pdfj),
    }))
}

/// Analyze an image's dense Thumb-2 regions with radare2. Each region is carved out,
/// analyzed as ARM/Thumb (`-a arm -b 16`) based at its load address, and its
/// `aflj`/`pdfj` function output merged into `out_dir/thumb_functions.json` (the carved
/// blobs are kept under `out_dir/thumb/` for follow-up). Returns the count of substantial
/// (>= 32-byte) functions recovered.
fn run_radare2_thumb(
    r2: &Path,
    image: &[u8],
    load_addr: u32,
    regions: &[(u32, u32)],
    out_dir: &Path,
) -> Result<usize> {
    let thumb_dir = out_dir.join("thumb");
    std::fs::create_dir_all(&thumb_dir)?;
    let mut all: Vec<serde_json::Value> = Vec::new();
    for &(addr, len) in regions {
        let off = addr.wrapping_sub(load_addr) as usize;
        if off >= image.len() {
            continue;
        }
        let end = off.saturating_add(len as usize).min(image.len());
        let bin = thumb_dir.join(format!("{addr:08x}.bin"));
        std::fs::write(&bin, &image[off..end])?;
        let output = std::process::Command::new(r2)
            .args(["-a", "arm", "-b", "16", "-m"])
            .arg(format!("0x{addr:x}"))
            .args(["-q", "-c", "aaa;aflj;pdfj @@f"])
            .arg(&bin)
            .stderr(std::process::Stdio::null())
            .output()?;
        check_radare2_thumb_status(output.status.success(), output.status.code(), addr)?;
        let parsed = parse_checked_radare2_thumb_output(&output.stdout, addr)?;
        for (f, pdfj) in parsed.pairs {
            all.push(normalize_radare2_function_checked(&f, &pdfj, addr)?);
        }
    }
    let substantial = all
        .iter()
        .filter(|f| {
            f.get("size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                >= 32
        })
        .count();
    let wrapped = serde_json::json!({
        "format": "pixel-modem-extractor-thumb-functions-v1",
        "functions": all,
    });
    std::fs::write(
        out_dir.join("thumb_functions.json"),
        serde_json::to_string_pretty(&wrapped).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;
    Ok(substantial)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid `modem.bin`: a `TOC\0` header + one 32-byte entry per
    /// image (name, offset, load_addr, size, crc=0, index), with payloads packed
    /// directly after the entry table.
    fn craft_modem_bin(images: &[(&str, u32, u32, &[u8])]) -> Vec<u8> {
        let entry_off = 0x20usize;
        let stride = 0x20usize;
        let table_end = entry_off + images.len() * stride;
        let mut offsets = Vec::new();
        let mut total = table_end;
        for (_, _, _, p) in images {
            offsets.push(total);
            total += p.len();
        }
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(b"TOC\0");
        buf[0x1c..0x20].copy_from_slice(&(images.len() as u32).to_le_bytes());
        for (i, (name, addr, index, payload)) in images.iter().enumerate() {
            let e = entry_off + i * stride;
            let nb = name.as_bytes();
            let n = nb.len().min(12);
            buf[e..e + n].copy_from_slice(&nb[..n]);
            buf[e + 12..e + 16].copy_from_slice(&(offsets[i] as u32).to_le_bytes());
            buf[e + 16..e + 20].copy_from_slice(&addr.to_le_bytes());
            buf[e + 20..e + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            buf[e + 24..e + 28].copy_from_slice(&0u32.to_le_bytes());
            buf[e + 28..e + 32].copy_from_slice(&index.to_le_bytes());
            buf[offsets[i]..offsets[i] + payload.len()].copy_from_slice(payload);
        }
        buf
    }

    #[test]
    fn headless_args_base_addr_is_hex_without_0x() {
        let args = headless_args(
            "/out",
            "02_MAIN",
            "ARM:LE:32:v7",
            0x4001_0000,
            &[(0x4109_0000, 0x288_0000)],
        );
        assert_eq!(args[0], "/out/ghidra_project");
        assert_eq!(args[1], "pixel-modem");
        let imp = args.iter().position(|a| a == "-import").unwrap();
        assert_eq!(args[imp + 1], "/out/images/02_MAIN");
        let proc = args.iter().position(|a| a == "-processor").unwrap();
        assert_eq!(args[proc + 1], "ARM:LE:32:v7");
        let ld = args.iter().position(|a| a == "-loader").unwrap();
        assert_eq!(args[ld + 1], "BinaryLoader");
        let ba = args.iter().position(|a| a == "-loader-baseAddr").unwrap();
        assert_eq!(args[ba + 1], "40010000"); // hex, NO 0x
        assert!(!args[ba + 1].contains("0x"));
        let ps = args.iter().position(|a| a == "-postScript").unwrap();
        assert_eq!(args[ps + 1], "ExportDecomp.java");
        assert_eq!(args[ps + 2], "/out/export/02_MAIN");
        // pre-script wires TameAnalysis.java, then the data-region args, before the post-script
        let pre = args.iter().position(|a| a == "-preScript").unwrap();
        assert_eq!(args[pre + 1], "TameAnalysis.java");
        assert_eq!(args[pre + 2], "41090000:2880000"); // addrHex:lenHex
        assert!(pre < ps, "pre-script must precede post-script");
        assert!(args.iter().any(|a| a == "-overwrite"));
        // base 0 -> zero-padded "00000000"; no data regions -> -postScript directly follows
        let z = headless_args("/o", "00_BOOT", "ARM:LE:32:v7", 0, &[]);
        let zpre = z.iter().position(|a| a == "-preScript").unwrap();
        assert_eq!(z[zpre + 1], "TameAnalysis.java");
        assert_eq!(z[zpre + 2], "-postScript");
        let bz = z.iter().position(|a| a == "-loader-baseAddr").unwrap();
        assert_eq!(z[bz + 1], "00000000");
    }

    #[test]
    fn headless_process_args_wires_process_mode_and_post_scripts() {
        let args = headless_process_args(
            "/out",
            "02_MAIN",
            std::path::Path::new("/out/ghidra/symbol_maps/02_MAIN.json"),
        );
        // <projectDir> <projectName> -process <label> -noanalysis -scriptPath <root>/scripts
        assert_eq!(args[0], "/out/ghidra_project");
        assert_eq!(args[1], "pixel-modem");
        let proc = args.iter().position(|a| a == "-process").unwrap();
        assert_eq!(args[proc + 1], "02_MAIN");
        let na = args.iter().position(|a| a == "-noanalysis").unwrap();
        assert!(na > proc);
        let sp = args.iter().position(|a| a == "-scriptPath").unwrap();
        assert_eq!(args[sp + 1], "/out/scripts");
        // ApplySymbols.java comes before ExportDecomp.java, with map path between.
        let ps1 = args.iter().position(|a| a == "-postScript").unwrap();
        assert_eq!(args[ps1 + 1], "ApplySymbols.java");
        assert_eq!(args[ps1 + 2], "/out/ghidra/symbol_maps/02_MAIN.json");
        // Second -postScript is ExportDecomp.java with the per-image export dir.
        let ps2 = args.iter().rposition(|a| a == "-postScript").unwrap();
        assert!(ps2 > ps1);
        assert_eq!(args[ps2 + 1], "ExportDecomp.java");
        assert_eq!(args[ps2 + 2], "/out/export/02_MAIN");
    }

    #[test]
    fn parse_pass2_summary_reads_applied_count() {
        let stdout =
            "...\nApplySymbols: image=02_MAIN applied 42 names, 7 plate comments, skipped 3\n";
        assert_eq!(parse_pass2_summary(stdout), Some(42));
        // Missing / malformed summary -> None (caller treats as "no info").
        assert_eq!(parse_pass2_summary("nothing useful\n"), None);
        assert_eq!(parse_pass2_summary(""), None);
    }

    #[test]
    fn headless_command_uses_output_local_ghidra_config() {
        let root = PathBuf::from("/tmp/pme-out");
        let args = vec!["/tmp/pme-out/ghidra_project".to_string()];
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &root,
            None,
        );

        assert_eq!(
            cmd.get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("XDG_CONFIG_HOME")),
            Some((
                std::ffi::OsStr::new("XDG_CONFIG_HOME"),
                Some(ghidra_config_home(&root).as_os_str())
            ))
        );
        assert_eq!(
            cmd.get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new("XDG_CACHE_HOME")),
            Some((
                std::ffi::OsStr::new("XDG_CACHE_HOME"),
                Some(ghidra_cache_home(&root).as_os_str())
            ))
        );
    }

    #[test]
    fn java_home_from_ghidra_run_reads_homebrew_pin() {
        let base = std::env::temp_dir().join(format!("pme_jh_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        // A real directory to stand in for the JDK (must exist to be accepted).
        let jdk = base.join("jdk21");
        std::fs::create_dir_all(&jdk).unwrap();
        let wrapper = base.join("ghidraRun");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/bash\nJAVA_HOME=\"${{JAVA_HOME:-{}}}\" exec \"/x/libexec/ghidraRun\" \"$@\"\n",
                jdk.display()
            ),
        )
        .unwrap();
        assert_eq!(java_home_from_ghidra_run(&wrapper), Some(jdk.clone()));

        // Unpinned (upstream-style) wrapper -> None.
        let plain = base.join("ghidraRun_plain");
        std::fs::write(&plain, b"#!/bin/bash\nexec ghidraRun \"$@\"\n").unwrap();
        assert!(java_home_from_ghidra_run(&plain).is_none());

        // Pinned but nonexistent path -> None (never inject a bad JAVA_HOME).
        let missing = base.join("ghidraRun_missing");
        std::fs::write(
            &missing,
            b"#!/bin/bash\nJAVA_HOME=\"${JAVA_HOME:-/no/such/jdk/here}\" exec x\n",
        )
        .unwrap();
        assert!(java_home_from_ghidra_run(&missing).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_java_home_never_overrides_existing_env() {
        let base = std::env::temp_dir().join(format!("pme_rjh_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let jdk = base.join("jdk");
        std::fs::create_dir_all(&jdk).unwrap();
        let wrapper = base.join("ghidraRun");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/bash\nJAVA_HOME=\"${{JAVA_HOME:-{}}}\" exec x\n",
                jdk.display()
            ),
        )
        .unwrap();

        // env already sets JAVA_HOME -> do not override, regardless of the wrapper.
        assert!(resolve_java_home(Some(OsString::from("/whatever")), Some(&wrapper)).is_none());
        // env unset + pinned wrapper -> use the wrapper's JDK.
        assert_eq!(resolve_java_home(None, Some(&wrapper)), Some(jdk.clone()));
        // env unset + no wrapper -> None.
        assert!(resolve_java_home(None, None).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn headless_command_injects_java_home_when_given() {
        let root = PathBuf::from("/tmp/pme-out");
        let args = vec!["/tmp/pme-out/ghidra_project".to_string()];
        let jh = PathBuf::from("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home");
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &root,
            Some(&jh),
        );
        assert_eq!(
            cmd.get_envs()
                .find(|(k, _)| *k == std::ffi::OsStr::new("JAVA_HOME")),
            Some((std::ffi::OsStr::new("JAVA_HOME"), Some(jh.as_os_str())))
        );

        // Without a java_home, no JAVA_HOME override is added to the child.
        let cmd = headless_command(
            Path::new("/opt/ghidra/support/analyzeHeadless"),
            &args,
            &root,
            None,
        );
        assert!(
            cmd.get_envs()
                .all(|(k, _)| k != std::ffi::OsStr::new("JAVA_HOME"))
        );
    }

    #[test]
    fn generation_only_hint_mentions_radare2_thumb_regions() {
        let hint = generation_only_hint(Path::new("/tmp/pme-out"));

        assert!(hint.contains("--run"), "hint:\n{hint}");
        assert!(hint.contains("Ghidra"), "hint:\n{hint}");
        assert!(hint.contains("radare2"), "hint:\n{hint}");
        assert!(hint.contains("Thumb"), "hint:\n{hint}");
        assert!(hint.contains("Ghidra-only"), "hint:\n{hint}");
    }

    #[test]
    fn ghidra_java_options_preserve_existing_and_add_output_local_dirs() {
        let root = PathBuf::from("/tmp/pme-out");
        let options = ghidra_java_options(&root, Some(std::ffi::OsStr::new("-Dexisting.option=1")));
        let options = options.to_string_lossy();

        assert!(
            options.contains("-Dexisting.option=1"),
            "options: {options}"
        );
        assert!(
            options.contains("-Dapplication.settingsdir=/tmp/pme-out/ghidra_config"),
            "options: {options}"
        );
        assert!(
            options.contains("-Dapplication.cachedir=/tmp/pme-out/ghidra_cache"),
            "options: {options}"
        );
        assert!(
            options.contains("-Dapplication.tempdir=/tmp/pme-out/ghidra_tmp"),
            "options: {options}"
        );
    }

    #[test]
    fn thumb_regions_detect_large_high_entropy_blob() {
        // 0.5 MiB zeros | 1.5 MiB high-entropy (0..=255 repeating) | 0.5 MiB zeros
        let mut buf = vec![0u8; 512 * 1024];
        buf.extend((0u32..1536 * 1024).map(|i| (i % 256) as u8));
        buf.resize(buf.len() + 512 * 1024, 0);

        let regions = thumb_regions(&buf, 0x4001_0000);
        assert_eq!(regions.len(), 1, "exactly one dense Thumb region");
        let (addr, len) = regions[0];
        assert_eq!(addr, 0x4001_0000 + 512 * 1024); // starts after the zero prefix
        assert_eq!(len, 1536 * 1024); // the 1.5 MiB blob

        // nothing for an all-zero buffer, nor for a sub-1MiB high-entropy span
        assert!(thumb_regions(&[0u8; 4096], 0).is_empty());
        let small: Vec<u8> = (0u32..256 * 1024).map(|i| (i % 256) as u8).collect();
        assert!(thumb_regions(&small, 0).is_empty());
    }

    #[test]
    fn normalize_radare2_function_records_body_and_refs() {
        let raw = serde_json::json!({
            "name": "sym.thumb_func",
            "offset": 0x4120u64,
            "size": 48u64
        });
        let pdfj = serde_json::json!({
            "ops": [
                {
                    "offset": 0x4120u64,
                    "bytes": "b5f0",
                    "disasm": "push {r4, lr}",
                    "refs": [{"addr": 0x9000u64, "type": "DATA"}]
                },
                {
                    "offset": 0x4122u64,
                    "bytes": "4770",
                    "disasm": "bx lr",
                    "refs": [{"to": 0x9004u64, "kind": "string"}]
                }
            ]
        });

        let body = "0x00004120      b5f0      push {r4, lr}\n0x00004122      4770      bx lr\n";
        let entry = normalize_radare2_function(&raw, &pdfj).unwrap();

        assert_eq!(entry["name"], "sym.thumb_func");
        assert_eq!(entry["entry"], "0x4120");
        assert_eq!(entry["end"], "0x4150");
        assert_eq!(entry["size"], 48);
        assert_eq!(entry["body_kind"], "thumb_disassembly");
        assert_eq!(entry["body"], body);
        assert_eq!(entry["data_refs"][0], "0x9000");
        assert_eq!(entry["data_refs"][1], "0x9004");
    }

    #[test]
    fn noisy_radare2_stdout_still_pairs_and_normalizes_pdfj() {
        let stdout = br#"Warning: run r2 with -e bin.cache=true
[{"name":"sym.thumb_func","offset":16672,"size":48}]
INFO: analyzing functions
{"addr":16672,"ops":[{"offset":16672,"bytes":"b5f0","disasm":"push {r4, lr}","refs":[{"addr":36864,"type":"DATA"}]}]}
Warning: analysis completed
"#;

        let pairs = radare2_thumb_function_pdfjs(stdout);
        assert_eq!(pairs.len(), 1);
        let entry = normalize_radare2_function(&pairs[0].0, &pairs[0].1).unwrap();

        assert_eq!(entry["name"], "sym.thumb_func");
        assert_eq!(entry["entry"], "0x4120");
        assert_eq!(entry["body"], "0x00004120      b5f0      push {r4, lr}\n");
        assert_eq!(entry["data_refs"][0], "0x9000");
    }

    #[test]
    fn radare2_thumb_rejects_non_empty_stdout_without_parseable_json() {
        let stdout =
            b"Warning: analysis recovered functions but emitted logs only\nINFO: no JSON here\n";

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable JSON")));
    }

    #[test]
    fn radare2_thumb_rejects_empty_stdout() {
        let err = parse_checked_radare2_thumb_output(b"", 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable JSON")));
    }

    #[test]
    fn radare2_thumb_rejects_whitespace_only_stdout() {
        let err = parse_checked_radare2_thumb_output(b" \n\t\r", 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable JSON")));
    }

    #[test]
    fn radare2_thumb_rejects_parseable_json_without_function_inventory_array() {
        let stdout = br#"Warning: noisy prelude
{"addr":16384,"ops":[{"offset":16384,"bytes":"b5f0","disasm":"push {r4, lr}"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("no aflj function inventory"))
        );
    }

    #[test]
    fn radare2_thumb_rejects_empty_function_inventory_array() {
        let err = parse_checked_radare2_thumb_output(b"[]", 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("no aflj function inventory"))
        );
    }

    #[test]
    fn radare2_thumb_rejects_functions_without_parseable_pdfj_bodies() {
        let stdout = b"Warning: noisy prelude
[{\"name\":\"sym.thumb_func\",\"offset\":16384,\"size\":64}]
INFO: no pdfj body followed
";

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("no parseable pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_paired_pdfj_with_empty_rendered_body() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.thumb_func","offset":16384,"size":64}]
{"addr":16384,"ops":[]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("empty pdfj body")));
    }

    #[test]
    fn radare2_thumb_rejects_partial_pdfj_recovery() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":16384,"ops":[{"offset":16384,"bytes":"b5f0","disasm":"push {r4, lr}"}]}
INFO: second pdfj body was noisy and not parseable
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("missing 1 pdfj")));
    }

    #[test]
    fn radare2_thumb_does_not_reuse_entry_matched_pdfj_as_positional_fallback() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("missing 1 pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_positional_pdfj_with_different_parseable_entry() {
        let stdout = br#"Warning: noisy prelude
[{"name":"sym.first","offset":16384,"size":64},{"name":"sym.second","offset":16448,"size":64}]
{"addr":20480,"ops":[{"offset":20480,"bytes":"00bf","disasm":"nop"}]}
{"addr":16448,"ops":[{"offset":16448,"bytes":"4770","disasm":"bx lr"}]}
"#;

        let err = parse_checked_radare2_thumb_output(stdout, 0x4000).unwrap_err();

        assert!(matches!(err, Error::Serialize(message) if message.contains("missing 1 pdfj")));
    }

    #[test]
    fn radare2_thumb_rejects_non_zero_process_status() {
        let err = check_radare2_thumb_status(false, Some(7), 0x4000).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("exited with status 7"))
        );
    }

    #[test]
    fn radare2_thumb_maps_raw_blob_at_region_address() {
        let dir = std::env::temp_dir().join(format!("pme_r2_map_addr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat <<'EOF'\n[{\"name\":\"sym.thumb_func\",\"offset\":16672,\"size\":64}]\n{\"addr\":16672,\"ops\":[{\"offset\":16672,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let count = run_radare2_thumb(&r2, &[0u8; 0x180], 0x4000, &[(0x4120, 0x20)], &out).unwrap();

        assert_eq!(count, 1);
        let argv = std::fs::read_to_string(r2.with_file_name("r2.argv")).unwrap();
        let args: Vec<_> = argv.lines().collect();
        assert_eq!(args[0..4], ["-a", "arm", "-b", "16"]);
        let map = args.iter().position(|arg| *arg == "-m").unwrap();
        assert_eq!(args[map + 1], "0x4120");
        assert!(
            !args.contains(&"-B"),
            "raw carved blobs must use r2 map address (-m), not binary base (-B): {args:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_radare2_thumb_rejects_unnormalizable_raw_function() {
        let dir = std::env::temp_dir().join(format!("pme_r2_bad_normalize_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r2 = dir.join("r2");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            &r2,
            "#!/usr/bin/env sh\ncat <<'EOF'\n[{\"name\":\"sym.no_entry\",\"size\":64}]\n{\"ops\":[{\"type\":\"nop\"},{\"offset\":16416,\"bytes\":\"b5f0\",\"disasm\":\"push {r4, lr}\"}]}\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&r2).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&r2, perm).unwrap();
        }

        let err = run_radare2_thumb(&r2, &[0u8; 16], 0x4000, &[(0x4000, 16)], &out).unwrap_err();

        assert!(
            matches!(err, Error::Serialize(message) if message.contains("lacks entry/addr") && message.contains("0x4000"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pdfj_refs_and_body_use_realistic_ops() {
        let pdfj = serde_json::json!({
            "ops": [
                {
                    "addr": 0x4120u64,
                    "bytes": "b5f0",
                    "disasm": "push {r4, lr}",
                    "ptr": 0xaaaa_u64,
                    "refs": [
                        {"to": 0x9004u64, "type": "DATA"},
                        {"to": 0x8120u64, "type": "code"}
                    ]
                },
                {
                    "addr": 0x4122u64,
                    "bytes": "4b02",
                    "disasm": "ldr r3, [pc, 8]",
                    "refptr": 4u64,
                    "refs": [
                        {"addr": 0x9000u64, "kind": "str"},
                        {"to": 0x9008u64, "perm": "read"},
                        {"to": 0xbeef_u64}
                    ],
                    "xrefs": [{"to": 0x7000u64, "type": "DATA"}]
                },
                {
                    "addr": 0x4124u64,
                    "bytes": "d001",
                    "disasm": "beq 0x412a",
                    "jump": 0x412au64,
                    "fail": 0x4126u64,
                    "refs": [{"to": 0x412au64, "type": "jump"}]
                },
                {
                    "addr": 0x4126u64,
                    "bytes": "4770",
                    "disasm": "bx lr",
                    "refs": [{"to": 0x9004u64, "name": "str.duplicate"}]
                }
            ]
        });

        assert_eq!(
            data_refs_from_pdfj(&pdfj),
            vec!["0x9000", "0x9004", "0x9008"]
        );
        assert_eq!(
            pdfj_body(&pdfj),
            "0x00004120      b5f0      push {r4, lr}\n\
             0x00004122      4b02      ldr r3, [pc, 8]\n\
             0x00004124      d001      beq 0x412a\n\
             0x00004126      4770      bx lr\n"
        );
    }

    #[test]
    fn run_report_without_run_has_spec_and_empty_images() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0x0, 1, &[0u8; 4]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 8]),
        ]);
        let dir = std::env::temp_dir().join(format!("pme_run_report_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let opts = Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
        };

        let rep = run_report(&modem, &opts, &dir.join("out")).unwrap();

        assert!(rep.spec_path.ends_with("ghidra_load.json"));
        assert!(rep.spec_path.exists());
        assert!(rep.images.is_empty(), "no images analyzed without --run");
    }

    #[test]
    fn report_failure_returns_thumb_error_when_only_thumb_failed() {
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(12),
                thumb_functions: None,
                thumb_error: Some("radare2 parser rejected empty stdout".into()),
                pass2_applied: None,
                pass2_error: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
        };

        let err = report_failure(&report).expect("thumb error should fail standalone run");
        assert_eq!(
            err.to_string(),
            "decompose incomplete: radare2 failed on 02_MAIN: radare2 parser rejected empty stdout"
        );
    }

    #[test]
    fn report_failure_does_not_duplicate_label_for_missing_radare2() {
        let report = DecompileReport {
            images: vec![ImageResult {
                label: "02_MAIN".into(),
                outcome: ImageOutcome::Analyzed(12),
                thumb_functions: None,
                thumb_error: Some(
                    "1 Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them"
                        .into(),
                ),
                pass2_applied: None,
                pass2_error: None,
            }],
            spec_path: PathBuf::from("ghidra_load.json"),
        };

        let err = report_failure(&report).expect("thumb error should fail standalone run");
        assert_eq!(
            err.to_string(),
            "decompose incomplete: radare2 failed on 02_MAIN: 1 Thumb region(s) left unanalyzed — radare2 (r2) not on PATH; Ghidra can't analyze them"
        );
    }

    #[test]
    fn run_generation_only_writes_kit() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0x0, 1, &[0u8; 4]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 8]),
        ]);
        let dir = std::env::temp_dir().join(format!("pme_decompile_gen_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem = dir.join("modem.bin");
        std::fs::write(&modem, &buf).unwrap();
        let out = dir.join("out");
        let opts = Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".into(),
        };
        run(&modem, &opts, &out).unwrap();

        assert!(out.join("images").join("00_BOOT").exists());
        assert!(out.join("images").join("02_MAIN").exists());
        assert!(out.join("scripts").join("TameAnalysis.java").exists());
        assert!(out.join("scripts").join("ExportDecomp.java").exists());

        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert_eq!(spec["processor"], "ARM:LE:32:v7");
        assert_eq!(spec["images"][0]["name"], "00_BOOT");
        assert_eq!(spec["images"][0]["base_addr"], "0x00000000");
        assert_eq!(spec["images"][0]["file"], "images/00_BOOT");
        assert_eq!(spec["images"][1]["base_addr"], "0x40010000");

        let sh = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(sh.contains("analyzeHeadless"));
        assert!(
            sh.contains("TameAnalysis.java"),
            "run script must wire the pre-script:\n{sh}"
        );
        assert!(
            sh.contains("\"-loader-baseAddr\" \"40010000\""),
            "sh:\n{sh}"
        );
        assert!(!sh.contains("0x40010000"));
        assert!(
            sh.contains("mkdir -p \"$HERE/ghidra_project\""),
            "run_ghidra.sh must create the project dir:\n{sh}"
        );
        assert!(
            sh.contains("export XDG_CONFIG_HOME=\"$HERE/ghidra_config\""),
            "run_ghidra.sh must keep Ghidra config under the output dir:\n{sh}"
        );
        assert!(
            sh.contains("export XDG_CACHE_HOME=\"$HERE/ghidra_cache\""),
            "run_ghidra.sh must keep Ghidra cache under the output dir:\n{sh}"
        );
        assert!(
            sh.contains("-Dapplication.tempdir=$HERE/ghidra_tmp"),
            "run_ghidra.sh must keep Ghidra temp files under the output dir:\n{sh}"
        );
        assert!(
            sh.contains("GHIDRA_HEADLESS_JAVA_OPTIONS=\"$GHIDRA_HEADLESS_JAVA_OPTIONS $GHIDRA_LOCAL_JAVA_OPTIONS\""),
            "run_ghidra.sh must preserve caller-provided headless Java options:\n{sh}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locate_tools_respects_precedence() {
        let base = std::env::temp_dir().join(format!("pme_ghidra_locate_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(home.join("support")).unwrap();
        std::fs::write(home.join("support").join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        let want = home.join("support").join("analyzeHeadless");

        // --ghidra-home wins
        assert_eq!(
            locate_tools(Some(&home), None, &[])
                .map(|g| g.headless)
                .as_ref(),
            Some(&want)
        );
        // $GHIDRA_INSTALL_DIR used when --ghidra-home is None
        assert_eq!(
            locate_tools(None, Some(&home), &[])
                .map(|g| g.headless)
                .as_ref(),
            Some(&want)
        );
        // PATH dir used as last resort (analyzeHeadless directly in the dir)
        let pdir = base.join("pbin");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            locate_tools(None, None, std::slice::from_ref(&pdir)).map(|g| g.headless),
            Some(pdir.join("analyzeHeadless"))
        );
        // nothing found -> None
        assert!(locate_tools(None, None, &[]).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn headless_in_root_finds_upstream_and_homebrew_layouts() {
        let base = std::env::temp_dir().join(format!("pme_hir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // upstream: <root>/support/analyzeHeadless
        let up = base.join("upstream");
        std::fs::create_dir_all(up.join("support")).unwrap();
        std::fs::write(up.join("support").join("analyzeHeadless"), b"#!/bin/sh\n").unwrap();
        assert_eq!(
            headless_in_root(&up),
            Some(up.join("support").join("analyzeHeadless"))
        );

        // homebrew: <root>/libexec/support/analyzeHeadless
        let brew = base.join("brew");
        std::fs::create_dir_all(brew.join("libexec").join("support")).unwrap();
        std::fs::write(
            brew.join("libexec").join("support").join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        assert_eq!(
            headless_in_root(&brew),
            Some(brew.join("libexec").join("support").join("analyzeHeadless"))
        );

        // neither -> None
        assert!(headless_in_root(&base.join("empty")).is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ghidra_home_accepts_homebrew_layout() {
        // A Homebrew-style prefix: analyzeHeadless under libexec/support, wrapper under bin/.
        let base = std::env::temp_dir().join(format!("pme_hbhome_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("opt").join("ghidra");
        std::fs::create_dir_all(root.join("libexec").join("support")).unwrap();
        std::fs::write(
            root.join("libexec").join("support").join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin").join("ghidraRun"), b"#!/bin/bash\n").unwrap();

        let got = locate_tools(Some(&root), None, &[]).unwrap();
        assert_eq!(
            got.headless,
            root.join("libexec").join("support").join("analyzeHeadless")
        );
        assert_eq!(got.ghidra_run, Some(root.join("bin").join("ghidraRun")));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn roots_from_ghidra_run_yields_dir_then_parent() {
        let run = PathBuf::from("/opt/homebrew/Cellar/ghidra/12.1.2/bin/ghidraRun");
        assert_eq!(
            roots_from_ghidra_run(&run),
            vec![
                PathBuf::from("/opt/homebrew/Cellar/ghidra/12.1.2/bin"),
                PathBuf::from("/opt/homebrew/Cellar/ghidra/12.1.2"),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_ghidra_run_symlink_resolves_to_homebrew_headless() {
        // Mimic Homebrew: PATH holds a `ghidraRun` symlink into a Cellar-like tree whose
        // analyzeHeadless lives under libexec/support. Discovery must canonicalize the
        // symlink, derive the root, and find the launcher there.
        let base = std::env::temp_dir().join(format!("pme_pathrun_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let cellar = base.join("Cellar").join("ghidra").join("12.1.2");
        std::fs::create_dir_all(cellar.join("libexec").join("support")).unwrap();
        std::fs::write(
            cellar
                .join("libexec")
                .join("support")
                .join("analyzeHeadless"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        std::fs::create_dir_all(cellar.join("bin")).unwrap();
        std::fs::write(cellar.join("bin").join("ghidraRun"), b"#!/bin/bash\n").unwrap();

        let pbin = base.join("bin");
        std::fs::create_dir_all(&pbin).unwrap();
        std::os::unix::fs::symlink(cellar.join("bin").join("ghidraRun"), pbin.join("ghidraRun"))
            .unwrap();

        let got = locate_tools(None, None, std::slice::from_ref(&pbin)).unwrap();
        assert_eq!(
            got.headless,
            std::fs::canonicalize(
                cellar
                    .join("libexec")
                    .join("support")
                    .join("analyzeHeadless")
            )
            .unwrap()
        );
        assert!(got.ghidra_run.is_some());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn build_load_spec_maps_toc_addresses() {
        let buf = craft_modem_bin(&[
            ("BOOT", 0x0, 1, &[0xaa, 0xbb, 0xcc, 0xdd]),
            ("MAIN", 0x4001_0000, 3, &[0u8; 8]),
        ]);
        let toc = Toc::parse(&buf).unwrap();
        let spec = build_load_spec(&toc, &buf, "modem.bin", "ARM:LE:32:v7").unwrap();
        assert_eq!(spec.processor, "ARM:LE:32:v7");
        assert_eq!(spec.source.path, "modem.bin");
        assert_eq!(spec.source.sha256.len(), 64);
        assert_eq!(spec.images.len(), 2);
        assert_eq!(spec.images[0].name, "00_BOOT");
        assert_eq!(spec.images[0].file, "images/00_BOOT");
        assert_eq!(spec.images[0].base_addr, "0x00000000");
        assert_eq!(spec.images[0].entry_point, "0x00000000");
        assert_eq!(spec.images[0].size, 4);
        assert_eq!(spec.images[0].sha256.len(), 64);
        assert_eq!(spec.images[1].name, "02_MAIN");
        assert_eq!(spec.images[1].file, "images/02_MAIN");
        assert_eq!(spec.images[1].base_addr, "0x40010000");
        assert_eq!(spec.images[1].entry_point, "0x40010000");
        assert_eq!(spec.images[1].size, 8);
        assert_eq!(spec.images[1].sha256.len(), 64);
    }

    #[test]
    fn build_load_spec_errors_on_out_of_range_image() {
        // valid TOC, then corrupt entry 0's size field (@0x34) to exceed the buffer.
        let mut buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0u8; 4])]);
        buf[0x34..0x38].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let toc = Toc::parse(&buf).unwrap();
        assert!(build_load_spec(&toc, &buf, "modem.bin", "ARM:LE:32:v7").is_err());
    }

    #[test]
    fn image_matches_label_or_bare_name_or_all() {
        assert!(image_matches(None, "02_MAIN", "MAIN")); // no filter → all
        assert!(image_matches(Some("02_MAIN"), "02_MAIN", "MAIN")); // canonical label
        assert!(image_matches(Some("MAIN"), "02_MAIN", "MAIN")); // bare name
        assert!(!image_matches(Some("BOOT"), "02_MAIN", "MAIN")); // no match
    }

    #[test]
    fn count_functions_reads_array_len() {
        let dir = std::env::temp_dir().join(format!("pme_count_fns_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // populated array → element count
        std::fs::write(
            dir.join("functions.json"),
            br#"[{"name":"a","entry":"0x0","size":4},{"name":"b","entry":"0x4","size":8}]"#,
        )
        .unwrap();
        assert_eq!(count_functions(&dir), 2);
        // empty array (an encrypted/compressed partition: no disassembly) → 0
        std::fs::write(dir.join("functions.json"), b"[\n]\n").unwrap();
        assert_eq!(count_functions(&dir), 0);
        // missing file → 0 (no panic)
        std::fs::remove_file(dir.join("functions.json")).unwrap();
        assert_eq!(count_functions(&dir), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_script_probes_both_ghidra_layouts() {
        let base = std::env::temp_dir().join(format!("pme_runscript_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let buf = craft_modem_bin(&[("BOOT", 0x0, 1, &[0xaa, 0xbb, 0xcc, 0xdd])]);
        let toc = Toc::parse(&buf).unwrap();
        write_run_script(&base, &toc, &buf, "ARM:LE:32:v7").unwrap();
        let sh = std::fs::read_to_string(base.join("run_ghidra.sh")).unwrap();
        assert!(
            sh.contains("$GHIDRA_INSTALL_DIR/support/analyzeHeadless"),
            "sh:\n{sh}"
        );
        assert!(
            sh.contains("$GHIDRA_INSTALL_DIR/libexec/support/analyzeHeadless"),
            "sh:\n{sh}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
