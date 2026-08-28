//! Self-contained end-to-end test of the `--run` path: craft a tiny ARM blob in a
//! valid TOC, drive real Ghidra headless, and assert the export. Gated on locating
//! Ghidra ($GHIDRA_INSTALL_DIR or /opt/ghidra); skips cleanly otherwise. No
//! proprietary firmware needed.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;

#[path = "support/pal_fixture.rs"]
mod pal_fixture;

const SCATTER_BASE: u32 = 0x4001_0000;
const SCATTER_IMAGE_LEN: usize = 0x1000;
const SCATTER_COPY_DESTINATION: u32 = SCATTER_BASE + SCATTER_IMAGE_LEN as u32;
const SCATTER_DECOMPRESS1_DESTINATION: u32 = SCATTER_COPY_DESTINATION + 0x10;
const SCATTER_ZERO_DESTINATION: u32 = SCATTER_COPY_DESTINATION + 0x20;

fn analyze_headless_in_home(home: &std::path::Path) -> Option<PathBuf> {
    [
        home.join("support/analyzeHeadless"),
        home.join("libexec/support/analyzeHeadless"),
    ]
    .into_iter()
    .find(|launcher| launcher.exists())
}

fn find_ghidra_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        let p = PathBuf::from(dir);
        if analyze_headless_in_home(&p).is_some() {
            return Some(p);
        }
    }
    let opt = PathBuf::from("/opt/ghidra");
    if analyze_headless_in_home(&opt).is_some() {
        return Some(opt);
    }
    None
}

fn craft_single_image_modem_bin(name: &str, load_addr: u32, index: u32, payload: &[u8]) -> Vec<u8> {
    assert!(name.len() <= 12);
    let entry_off = 0x20usize;
    let payload_off = entry_off + 0x20; // one 32-byte entry
    let mut buf = vec![0u8; payload_off + payload.len()];
    buf[0..4].copy_from_slice(b"TOC\0");
    buf[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[entry_off..entry_off + name.len()].copy_from_slice(name.as_bytes());
    buf[entry_off + 12..entry_off + 16].copy_from_slice(&(payload_off as u32).to_le_bytes()); // offset
    buf[entry_off + 16..entry_off + 20].copy_from_slice(&load_addr.to_le_bytes());
    buf[entry_off + 20..entry_off + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes()); // size
    buf[entry_off + 28..entry_off + 32].copy_from_slice(&index.to_le_bytes());
    buf[payload_off..].copy_from_slice(payload);
    buf
}

/// Minimal valid `modem.bin`: TOC + one embedded image (index 1, "BOOT", base 0).
fn craft_modem_bin(payload: &[u8]) -> Vec<u8> {
    craft_single_image_modem_bin("BOOT", 0, 1, payload)
}

fn write_scatter_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_scatter_descriptor(
    image: &mut [u8],
    table_offset: usize,
    index: usize,
    source: u32,
    destination: u32,
    size: u32,
    handler: u32,
) {
    let offset = table_offset + index * 16;
    for (field_offset, value) in [source, destination, size, handler].into_iter().enumerate() {
        write_scatter_u32(image, offset + field_offset * 4, value);
    }
}

fn craft_scatter_main_modem_bin() -> Vec<u8> {
    const LOADER_OFFSET: usize = 0x40;
    const LOADER_IMMEDIATE: u32 = 0x38;
    const LITERAL_OFFSET: usize = LOADER_OFFSET + 8 + LOADER_IMMEDIATE as usize;
    const TABLE_OFFSET: usize = 0x200;
    const TABLE_LEN: u32 = 6 * 16;
    const NULL_HANDLER: u32 = SCATTER_BASE + 0x600;
    const COPY_HANDLER: u32 = SCATTER_BASE + 0x601;
    const DECOMPRESS1_HANDLER: u32 = SCATTER_BASE + 0x604;
    const ZERO_HANDLER: u32 = SCATTER_BASE + 0x609;
    const SENTINEL_SOURCE: u32 = SCATTER_BASE + 0x680;
    const SELF_COPY_SOURCE: u32 = SCATTER_BASE + 0x700;
    const COPY_SOURCE: u32 = SCATTER_BASE + 0x710;
    const DECOMPRESS1_SOURCE: u32 = SCATTER_BASE + 0x720;
    const ZERO_SOURCE: u32 = SCATTER_BASE + 0x730;

    let mut image = vec![0; SCATTER_IMAGE_LEN];
    // add r0, pc, #0x38; ldmia r0, {r10, r11}; add r10, r10, r0; add r11, r11, r0
    for (offset, instruction) in [0xe28f_0038, 0xe890_0c00, 0xe08a_a000, 0xe08b_b000]
        .into_iter()
        .enumerate()
    {
        write_scatter_u32(&mut image, LOADER_OFFSET + offset * 4, instruction);
    }
    let literal_address = SCATTER_BASE + LITERAL_OFFSET as u32;
    let table_address = SCATTER_BASE + TABLE_OFFSET as u32;
    write_scatter_u32(
        &mut image,
        LITERAL_OFFSET,
        table_address.wrapping_sub(literal_address),
    );
    write_scatter_u32(
        &mut image,
        LITERAL_OFFSET + 4,
        (table_address + TABLE_LEN).wrapping_sub(literal_address),
    );

    image[0x700..0x704].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    image[0x710..0x714].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    image[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);
    for (index, source, destination, size, handler) in [
        (0, SENTINEL_SOURCE, 0, 0, NULL_HANDLER),
        (1, 0, SENTINEL_SOURCE, 0, NULL_HANDLER),
        (2, SELF_COPY_SOURCE, SELF_COPY_SOURCE, 4, COPY_HANDLER),
        (3, COPY_SOURCE, SCATTER_COPY_DESTINATION, 4, COPY_HANDLER),
        (
            4,
            DECOMPRESS1_SOURCE,
            SCATTER_DECOMPRESS1_DESTINATION,
            3,
            DECOMPRESS1_HANDLER,
        ),
        (5, ZERO_SOURCE, SCATTER_ZERO_DESTINATION, 5, ZERO_HANDLER),
    ] {
        write_scatter_descriptor(
            &mut image,
            TABLE_OFFSET,
            index,
            source,
            destination,
            size,
            handler,
        );
    }

    craft_single_image_modem_bin("MAIN", SCATTER_BASE, 3, &image)
}

const INSPECT_SCATTER_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.Locale;

public class InspectScatter extends GhidraScript {
    private void requireRuntimeBlock(MemoryBlock block, String name, long start, long size,
            int[] expected) throws Exception {
        if (block == null) throw new AssertionError(name + " missing");
        if (!block.getStart().equals(toAddr(start)) || block.getSize() != size) {
            throw new AssertionError(name + " range wrong");
        }
        if (!block.isInitialized() || !block.isRead() || !block.isWrite()
                || block.isExecute() || block.isVolatile()) {
            throw new AssertionError(name + " permissions wrong");
        }
        for (int offset = 0; offset < expected.length; offset++) {
            if ((currentProgram.getMemory().getByte(block.getStart().add(offset)) & 0xff)
                    != expected[offset]) {
                throw new AssertionError(name + " bytes wrong at offset " + offset);
            }
        }
    }

    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock raw = memory.getBlock(toAddr(0x40010000L));
        if (raw == null || !raw.getStart().equals(toAddr(0x40010000L))
                || raw.getSize() != 0x1000L) {
            throw new AssertionError("raw block missing or changed");
        }
        requireRuntimeBlock(memory.getBlock("SCATTER_COPY_03"), "SCATTER_COPY_03",
                0x40011000L, 4, new int[] {0x11, 0x22, 0x33, 0x44});
        requireRuntimeBlock(memory.getBlock("SCATTER_DECOMPRESS1_04"),
                "SCATTER_DECOMPRESS1_04", 0x40011010L, 3, new int[] {0xaa, 0, 0});
        requireRuntimeBlock(memory.getBlock("SCATTER_ZERO_05"), "SCATTER_ZERO_05",
                0x40011020L, 5, new int[] {0, 0, 0, 0, 0});
        int scatterBlocks = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().toUpperCase(Locale.ROOT).startsWith("SCATTER_")) scatterBlocks++;
        }
        if (scatterBlocks != 3) {
            throw new AssertionError("expected exactly three SCATTER_* blocks, found "
                    + scatterBlocks);
        }
        println("InspectScatter: valid raw and scatter memory map");
    }
}
"#;

const INSPECT_NO_SCATTER_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.Locale;

public class InspectNoScatter extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        MemoryBlock raw = memory.getBlock(toAddr(0x40010000L));
        if (raw == null || !raw.getStart().equals(toAddr(0x40010000L))
                || raw.getSize() != 0x1000L) {
            throw new AssertionError("saved raw block missing or changed");
        }
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().toUpperCase(Locale.ROOT).startsWith("SCATTER_")) {
                throw new AssertionError("partial scatter block survived: " + block.getName());
            }
        }
        println("InspectNoScatter: saved raw map has no SCATTER_* blocks");
    }
}
"#;

fn inspect_saved_project(
    home: &std::path::Path,
    out: &std::path::Path,
    label: &str,
    script: &str,
) -> std::process::Output {
    inspect_saved_project_with_args(home, out, label, script, &[])
}

fn inspect_saved_project_with_args(
    home: &std::path::Path,
    out: &std::path::Path,
    label: &str,
    script: &str,
    script_args: &[String],
) -> std::process::Output {
    inspect_saved_project_with_args_and_env(home, out, label, script, script_args, &[])
}

fn inspect_saved_project_with_args_and_env(
    home: &std::path::Path,
    out: &std::path::Path,
    label: &str,
    script: &str,
    script_args: &[String],
    environment: &[(&str, &str)],
) -> std::process::Output {
    let config = out.join("ghidra_config");
    let cache = out.join("ghidra_cache");
    let temp = out.join("ghidra_tmp");
    let java_options = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        config.display(),
        cache.display(),
        temp.display(),
        temp.display()
    );
    std::process::Command::new(
        analyze_headless_in_home(home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(out.join("ghidra_project"))
    .arg("pixel-modem")
    .arg("-process")
    .arg(label)
    .arg("-noanalysis")
    .arg("-scriptPath")
    .arg(out.join("scripts"))
    .arg("-postScript")
    .arg(script)
    .args(script_args)
    .env("XDG_CONFIG_HOME", config)
    .env("XDG_CACHE_HOME", cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
    .envs(environment.iter().copied())
    .output()
    .unwrap()
}

fn process_diagnostics(output: &std::process::Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn test_launcher_finds_homebrew_libexec_layout() {
    let root = tempfile::tempdir().unwrap();
    let launcher = root.path().join("libexec/support/analyzeHeadless");
    std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
    std::fs::write(&launcher, b"launcher\n").unwrap();

    assert_eq!(analyze_headless_in_home(root.path()), Some(launcher));
}

fn generate_scatter_kit(home: &std::path::Path, case: &str) -> (PathBuf, PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("pme_scatter_{case}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, craft_scatter_main_modem_bin()).unwrap();
    let out = dir.join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.to_path_buf()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();
    let spec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report.spec_path).unwrap()).unwrap();
    let label = spec["images"][0]["name"].as_str().unwrap().to_string();
    assert_eq!(label, "02_MAIN");
    (dir, out, label)
}

fn run_generated_scatter_kit(
    home: &std::path::Path,
    out: &std::path::Path,
) -> std::process::Output {
    std::process::Command::new(out.join("run_ghidra.sh"))
        .env("GHIDRA_INSTALL_DIR", home)
        .output()
        .unwrap()
}

fn assert_generated_scatter_failure_is_closed(
    home: &std::path::Path,
    case: &str,
    expected_failure: &str,
    mutate: impl FnOnce(&std::path::Path),
) {
    let (dir, out, label) = generate_scatter_kit(home, case);
    mutate(&out);

    let failed_run = run_generated_scatter_kit(home, &out);
    let failure_diagnostics = process_diagnostics(&failed_run);
    assert!(
        !failed_run.status.success(),
        "malformed generated kit unexpectedly succeeded:\n{failure_diagnostics}"
    );
    assert!(
        failure_diagnostics.contains(expected_failure),
        "generated kit failed for the wrong reason; expected {expected_failure:?}:\n{failure_diagnostics}"
    );

    std::fs::write(
        out.join("scripts/InspectNoScatter.java"),
        INSPECT_NO_SCATTER_JAVA,
    )
    .unwrap();
    let inspection = inspect_saved_project(home, &out, &label, "InspectNoScatter.java");
    assert!(
        inspection.status.success(),
        "failed project did not retain an inspectable raw-only map:\nfailed run:\n{failure_diagnostics}\ninspection:\n{}",
        process_diagnostics(&inspection)
    );
    assert!(
        String::from_utf8_lossy(&inspection.stdout)
            .contains("InspectNoScatter: saved raw map has no SCATTER_* blocks"),
        "raw-only inspection script did not complete:\n{}",
        process_diagnostics(&inspection)
    );
    eprintln!(
        "scatter fail-closed [{case}]: generated shell {}; saved raw-only inspection passed",
        failed_run.status
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn relative_spelling_from_current(path: &std::path::Path) -> PathBuf {
    let current = std::fs::canonicalize(".").unwrap();
    let target = std::fs::canonicalize(path).unwrap();
    let current_components: Vec<_> = current.components().collect();
    let target_components: Vec<_> = target.components().collect();
    let shared = current_components
        .iter()
        .zip(&target_components)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in shared..current_components.len() {
        relative.push("..");
    }
    for component in &target_components[shared..] {
        relative.push(component.as_os_str());
    }
    relative
}

fn prepared_pass2_map(
    path: &std::path::Path,
    count: usize,
) -> pixel_modem_extractor::decompile::PreparedPass2Map {
    let relative = relative_spelling_from_current(path);
    assert!(relative.is_relative());
    pixel_modem_extractor::decompile::PreparedPass2Map::new(
        &relative,
        NonZeroUsize::new(count).unwrap(),
    )
    .unwrap()
}

/// Drives one saved-project `-process` run with an optional seeding
/// post-script followed by the shipping `ExportDecomp.java` under its
/// pass-1-style argv (`-`/`none`), asserting success.
fn run_saved_project_export(
    home: &std::path::Path,
    out: &std::path::Path,
    label: &str,
    seed: Option<&str>,
) -> std::process::Output {
    let canonical_root = std::fs::canonicalize(out).unwrap();
    let headless =
        analyze_headless_in_home(home).expect("located Ghidra home still has analyzeHeadless");
    let mut command = std::process::Command::new(headless);
    command
        .arg(out.join("ghidra_project"))
        .arg("pixel-modem")
        .arg("-process")
        .arg(label)
        .arg("-noanalysis")
        .arg("-scriptPath")
        .arg(out.join("scripts"));
    if let Some(script) = seed {
        command.arg("-postScript").arg(script);
    }
    command
        .arg("-postScript")
        .arg("ExportDecomp.java")
        .arg(out.join("export").join(label))
        .arg(&canonical_root)
        .arg(label)
        .arg("none")
        .arg("-")
        .arg("none")
        .arg("-")
        .arg("-")
        .arg("-")
        .arg("none")
        .output()
        .unwrap()
}

/// A `PreparedSymbolPass2Map` over the retained pass-1 files of a small
/// synthesized image tree: `<dir>/<label>/{<label>.bin, decompiled/
/// functions.json}` plus the written v3 map at `map_path`.
fn prepared_symbol_map(
    dir: &std::path::Path,
    label: &str,
    map_path: &std::path::Path,
    execution_count: usize,
    creation_requests: Vec<pixel_modem_extractor::symbolicate::Pass2CreationRequest>,
) -> pixel_modem_extractor::decompile::PreparedSymbolPass2Map {
    let image_dir = dir.join(label);
    pixel_modem_extractor::decompile::PreparedSymbolPass2Map::new(
        map_path,
        &image_dir.join("decompiled/functions.json"),
        &image_dir.join(format!("{label}.bin")),
        label,
        execution_count,
        usize::from(execution_count != 0),
        creation_requests,
    )
    .unwrap()
}

#[test]
fn run_drives_ghidra_end_to_end() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    // ARM: `add r0, r0, r1` ; `bx lr`  (little-endian)
    let arm = [0x01u8, 0x00, 0x80, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
    let modem = craft_modem_bin(&arm);

    let dir = std::env::temp_dir().join(format!("pme_decompile_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    pixel_modem_extractor::decompile::run(&modem_path, &opts, &out).unwrap();

    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(!c.trim().is_empty(), "decompiled.c is empty");
    let lst = std::fs::read_to_string(exp.join("disasm.lst")).unwrap();
    assert!(!lst.trim().is_empty(), "disasm.lst is empty");
    // §5.3 format "address: bytes  mnemonic": the first ARM word's bytes (01 00 80 e0) appear.
    assert!(
        lst.contains("010080e0"),
        "disasm.lst missing the instruction-bytes column:\n{lst}"
    );
    let functions_bytes = std::fs::read(exp.join("functions.json")).unwrap();
    let funcs: serde_json::Value = serde_json::from_slice(&functions_bytes).unwrap();
    assert!(
        funcs.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "functions.json has no functions: {funcs}"
    );
    let first = funcs
        .as_array()
        .and_then(|a| a.first())
        .expect("functions.json has at least one function");
    assert!(
        first
            .get("end")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "functions.json entry missing end: {first}"
    );
    assert!(
        first
            .get("data_refs")
            .and_then(serde_json::Value::as_array)
            .is_some(),
        "functions.json entry missing data_refs array: {first}"
    );
    assert!(
        matches!(
            first
                .get("primary_source")
                .and_then(serde_json::Value::as_str),
            Some("default" | "analysis" | "imported" | "user_defined")
        ),
        "functions.json entry missing a canonical primary source: {first}"
    );
    assert_eq!(
        first["decode_ranges"],
        serde_json::json!([{
            "isa":"arm",
            "start":"0x0",
            "end":"0x4",
            "blake3":"586d05e48ce74c78b4e74cefcc5a27a6d5f446dac3324152df360e51db9c2ae9"
        }]),
        "the normal A32 fixture must export its exact instruction-backed range: {first}"
    );
    assert_eq!(first["decode_range_errors"], serde_json::json!([]));

    // generation artifacts exist alongside the export
    assert!(out.join("ghidra_load.json").exists());
    assert!(out.join("run_ghidra.sh").exists());
    assert!(out.join("scripts").join("ExportDecomp.java").exists());
    assert!(out.join("images").join("00_BOOT").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scatter_load_map_is_applied_before_analysis() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pme_scatter_valid_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, craft_scatter_main_modem_bin()).unwrap();
    let out = dir.join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home.clone()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();
    let image = report.images.first().expect("synthetic MAIN was selected");
    assert_eq!(image.label, "02_MAIN");
    assert!(
        matches!(
            image.outcome,
            pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
        ),
        "synthetic MAIN analysis failed: {:?}",
        image.outcome
    );

    std::fs::write(
        out.join("scripts/InspectScatter.java"),
        INSPECT_SCATTER_JAVA,
    )
    .unwrap();
    let inspection = inspect_saved_project(&home, &out, &image.label, "InspectScatter.java");
    assert!(
        inspection.status.success(),
        "saved scatter map inspection failed:\n{}",
        process_diagnostics(&inspection)
    );
    assert!(
        String::from_utf8_lossy(&inspection.stdout)
            .contains("InspectScatter: valid raw and scatter memory map"),
        "valid scatter inspection script did not complete:\n{}",
        process_diagnostics(&inspection)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Task 12: the generation-only route materializes the PAL task manifest
/// and wires it into `ghidra_load.json` and `run_ghidra.sh` with no flag —
/// `--no-thumb-decompile` changes nothing about PAL seeding.
#[test]
fn generated_only_pal_seeding_is_default_on() {
    for no_thumb_decompile in [false, true] {
        let dir = std::env::temp_dir().join(format!(
            "pme_pal_gen_{}_{no_thumb_decompile}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem_path = dir.join("modem.bin");
        std::fs::write(
            &modem_path,
            pal_fixture::discoverable::craft_pal_main_modem_bin(),
        )
        .unwrap();
        let out = dir.join("out");
        pixel_modem_extractor::decompile::run_report(
            &modem_path,
            &pixel_modem_extractor::decompile::Opts {
                run: false,
                image: None,
                ghidra_home: None,
                processor: "ARM:LE:32:v7".to_string(),
                no_thumb_decompile,
                rizin_fallback: false,
                tighten_wall_clock_budget_override: None,
                no_skip_opaque: true,
            },
            &out,
        )
        .unwrap();

        let manifest_path = out.join("pal_tasks/02_MAIN/tasks.json");
        let manifest_bytes = std::fs::read(&manifest_path).unwrap_or_else(|_| {
            panic!("PAL manifest missing under no_thumb_decompile={no_thumb_decompile}")
        });
        let identity = format!("v1:{}:2:0", blake3::hash(&manifest_bytes));
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("ghidra_load.json")).unwrap()).unwrap();
        assert_eq!(
            spec["images"][0]["pal_task_map"], "pal_tasks/02_MAIN/tasks.json",
            "no_thumb_decompile={no_thumb_decompile}"
        );
        let script = std::fs::read_to_string(out.join("run_ghidra.sh")).unwrap();
        assert!(
            script.contains("ApplyPalTasks.java"),
            "no_thumb_decompile={no_thumb_decompile}: script must schedule PAL seeding:\n{script}"
        );
        assert!(
            script.contains("\"${HERE}/pal_tasks/02_MAIN/tasks.json\""),
            "no_thumb_decompile={no_thumb_decompile}: script must pass the manifest:\n{script}"
        );
        assert!(
            script.contains(&format!("'pal_tasks={identity}'")),
            "no_thumb_decompile={no_thumb_decompile}: script marker must bind the identity:\n{script}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Task 12: the immediate `--run` route discovers, materializes, applies,
/// and certifies PAL task seeding under real Ghidra with no flag — the
/// tighten default. The strict `ApplyPalTasks` summary is parsed into the
/// report and the identity-bound v4 marker is validated.
#[test]
fn immediate_run_applies_pal_tasks_by_default() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pme_pal_run_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        pal_fixture::discoverable::craft_pal_main_modem_bin(),
    )
    .unwrap();
    let out = dir.join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();
    let image = report
        .images
        .first()
        .expect("discoverable MAIN was selected");
    assert_eq!(image.label, "02_MAIN");
    assert!(
        matches!(
            image.outcome,
            pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
        ),
        "PAL-seeded tighten run failed: {:?} (terminal_error={:?})",
        image.outcome,
        image.terminal_error
    );
    assert_eq!(
        image.pal_applied,
        Some(pixel_modem_extractor::decompile::AppliedPalTasks {
            tasks: 2,
            entries: 2,
            functions_created: 2,
            functions_existing: 0,
            names_applied: 2,
            names_preserved: 0,
            shared_entries: 0,
        }),
        "the strict ApplyPalTasks summary must be parsed from this run"
    );
    assert!(out.join("pal_tasks/02_MAIN/tasks.json").is_file());
    let marker = std::fs::read_to_string(out.join("export/02_MAIN.complete")).unwrap_or_default();
    assert!(
        marker.starts_with(
            "pixel-modem-extractor-ghidra-export-v4\nexception_roots=none\npal_tasks=v1:"
        ),
        "the current marker must bind the applied PAL identity: {marker:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Task 12: the same immediate route under `--no-thumb-decompile`
/// (datamark mode) — PAL seeding stays default-on in both modes.
#[test]
fn immediate_run_applies_pal_tasks_under_no_thumb_decompile() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pme_pal_dmk_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        pal_fixture::discoverable::craft_pal_main_modem_bin(),
    )
    .unwrap();
    let out = dir.join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: true,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();
    let image = report
        .images
        .first()
        .expect("discoverable MAIN was selected");
    assert!(
        matches!(
            image.outcome,
            pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
        ),
        "PAL-seeded datamark run failed: {:?} (terminal_error={:?})",
        image.outcome,
        image.terminal_error
    );
    assert_eq!(
        image.pal_applied,
        Some(pixel_modem_extractor::decompile::AppliedPalTasks {
            tasks: 2,
            entries: 2,
            functions_created: 2,
            functions_existing: 0,
            names_applied: 2,
            names_preserved: 0,
            shared_entries: 0,
        }),
        "datamark mode must apply and parse the same PAL seeding"
    );
    let marker = std::fs::read_to_string(out.join("export/02_MAIN.complete")).unwrap_or_default();
    assert!(
        marker.starts_with(
            "pixel-modem-extractor-ghidra-export-v4\nexception_roots=none\npal_tasks=v1:"
        ),
        "the datamark marker must bind the applied PAL identity: {marker:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Task 14: the full tighten and datamark routes over one discoverable
/// image carrying a controlled undefined gap — every task function and
/// its authoritative code survives both modes while the gap is
/// partitioned as data only in datamark mode.
#[test]
fn tighten_and_datamark_runs_preserve_tasks_and_partition_controlled_gap() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let manifest_entries = |out: &std::path::Path| {
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(out.join("pal_tasks/02_MAIN/tasks.json"))
                .expect("generated PAL manifest exists"),
        )
        .expect("generated PAL manifest parses");
        let mut entries: Vec<(u64, String)> = manifest["tasks"]
            .as_array()
            .expect("tasks array")
            .iter()
            .map(|task| {
                (
                    u64::from_str_radix(
                        task["entry"]
                            .as_str()
                            .expect("entry address")
                            .trim_start_matches("0x"),
                        16,
                    )
                    .unwrap(),
                    task["task_label"].as_str().expect("task label").to_string(),
                )
            })
            .collect();
        entries.sort();
        assert_eq!(entries.len(), 2, "the two-task fixture is expected");
        entries
    };
    let inspect_gap = |out: &std::path::Path, case: &str, expect_data: bool| {
        for directory in ["ghidra_config", "ghidra_cache", "ghidra_tmp"] {
            std::fs::create_dir_all(out.join(directory)).unwrap();
        }
        std::fs::write(out.join("scripts/PalInspectGap.java"), PAL_INSPECT_GAP_JAVA).unwrap();
        let output = inspect_saved_project_with_args(
            &home,
            out,
            "02_MAIN",
            "PalInspectGap.java",
            &[
                out.to_string_lossy().into_owned(),
                format!("{:#x}", pal_fixture::discoverable::GAP_ADDR),
                expect_data.to_string(),
            ],
        );
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            stdout.contains("PalInspectGap: ok"),
            "gap inspection failed for {case}:\nstatus: {}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    for (case, no_thumb_decompile) in [("tighten", false), ("datamark", true)] {
        let dir = std::env::temp_dir().join(format!("pme_pal_gap_{case}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let modem_path = dir.join("modem.bin");
        std::fs::write(
            &modem_path,
            pal_fixture::discoverable::craft_pal_main_modem_bin(),
        )
        .unwrap();
        let out = dir.join("out");
        let report = pixel_modem_extractor::decompile::run_report(
            &modem_path,
            &pixel_modem_extractor::decompile::Opts {
                run: true,
                image: None,
                ghidra_home: Some(home.clone()),
                processor: "ARM:LE:32:v7".to_string(),
                no_thumb_decompile,
                rizin_fallback: false,
                tighten_wall_clock_budget_override: None,
                no_skip_opaque: true,
            },
            &out,
        )
        .unwrap();
        let image = report
            .images
            .first()
            .expect("discoverable MAIN was selected");
        assert!(
            matches!(
                image.outcome,
                pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
            ),
            "{case} run failed: {:?} (terminal_error={:?})",
            image.outcome,
            image.terminal_error
        );
        assert_eq!(
            image.pal_applied,
            Some(pixel_modem_extractor::decompile::AppliedPalTasks {
                tasks: 2,
                entries: 2,
                functions_created: 2,
                functions_existing: 0,
                names_applied: 2,
                names_preserved: 0,
                shared_entries: 0,
            }),
            "{case} mode must seed every task"
        );
        let entries = manifest_entries(&out);
        let functions: serde_json::Value = serde_json::from_slice(
            &std::fs::read(out.join("export/02_MAIN/functions.json"))
                .expect("exported functions.json"),
        )
        .unwrap();
        let exported: Vec<&str> = functions
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["name"].as_str().unwrap())
            .collect();
        for (_, label) in &entries {
            assert!(
                exported.contains(&label.as_str()),
                "{case} export lost the task primary {label}: {exported:?}"
            );
        }
        // The gap is partitioned as data only in datamark mode; tighten
        // must still keep every task function.
        inspect_gap(&out, case, no_thumb_decompile);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn truncated_scatter_payload_fails_closed_without_partial_map() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_generated_scatter_failure_is_closed(
        &home,
        "truncated_payload",
        "does not have the declared size",
        |out| {
            let payload = out.join("scatter/02_MAIN/blocks/04-decompress1.bin");
            let length = std::fs::metadata(&payload).unwrap().len();
            assert!(length > 1);
            std::fs::OpenOptions::new()
                .write(true)
                .open(payload)
                .unwrap()
                .set_len(length - 1)
                .unwrap();
        },
    );
}

#[test]
fn scatter_raw_collision_fails_closed_without_partial_map() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_generated_scatter_failure_is_closed(
        &home,
        "raw_collision",
        "overlaps existing memory block",
        |out| {
            let map_path = out.join("scatter/02_MAIN/load_map.json");
            let mut map: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
            assert_eq!(
                map["entries"][3]["destination"],
                format!("{SCATTER_COPY_DESTINATION:#010x}")
            );
            map["entries"][3]["destination"] = serde_json::json!("0x40010000");
            let mut bytes = serde_json::to_vec_pretty(&map).unwrap();
            bytes.push(b'\n');
            std::fs::write(map_path, bytes).unwrap();
        },
    );
}

#[test]
fn lenient_scatter_json_fails_closed_without_partial_map() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_generated_scatter_failure_is_closed(
        &home,
        "lenient_json",
        "scatter load map is not strict JSON",
        |out| {
            let map_path = out.join("scatter/02_MAIN/load_map.json");
            let document = std::fs::read_to_string(&map_path).unwrap();
            let lenient_only = document.replacen("  \"format\":", "  format:", 1);
            assert_ne!(lenient_only, document);
            std::fs::write(map_path, lenient_only).unwrap();
        },
    );
}

#[test]
fn duplicate_scatter_json_member_fails_closed_without_partial_map() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_generated_scatter_failure_is_closed(
        &home,
        "duplicate_json_member",
        "duplicate JSON member format",
        |out| {
            let map_path = out.join("scatter/02_MAIN/load_map.json");
            let document = std::fs::read_to_string(&map_path).unwrap();
            let duplicate = document.replacen(
                "{\n",
                "{\n  \"format\": \"pixel-modem-extractor-scatter-load-v1\",\n",
                1,
            );
            assert_ne!(duplicate, document);
            std::fs::write(map_path, duplicate).unwrap();
        },
    );
}

#[test]
fn out_of_order_scatter_indices_fail_closed_without_partial_map() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_generated_scatter_failure_is_closed(
        &home,
        "out_of_order_indices",
        "index does not match its array position",
        |out| {
            let map_path = out.join("scatter/02_MAIN/load_map.json");
            let mut map: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&map_path).unwrap()).unwrap();
            map["entries"].as_array_mut().unwrap().swap(3, 4);
            let mut bytes = serde_json::to_vec_pretty(&map).unwrap();
            bytes.push(b'\n');
            std::fs::write(map_path, bytes).unwrap();
        },
    );
}

#[test]
fn scatter_post_preflight_failure_rolls_back_created_blocks() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_generated_scatter_failure_is_closed(
        &home,
        "rollback",
        "deterministic rollback fault after first create",
        |out| {
            let script_path = out.join("scripts/ApplyScatterLoad.java");
            let script = std::fs::read_to_string(&script_path).unwrap();
            let mutation_point = "                block.setRead(true);\n";
            assert_eq!(script.matches(mutation_point).count(), 1);
            let injected = script.replacen(
                mutation_point,
                concat!(
                    "                if (created.size() == 1) {\n",
                    "                    throw new MapError(\n",
                    "                            \"deterministic rollback fault after first create\");\n",
                    "                }\n",
                    "                block.setRead(true);\n"
                ),
                1,
            );
            std::fs::write(script_path, injected).unwrap();
        },
    );
}

#[test]
fn generated_shell_rejects_partial_export_after_functions_json() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let (dir, out, _) = generate_scatter_kit(&home, "partial_export");
    let export = out.join("export/02_MAIN");
    std::fs::create_dir_all(&export).unwrap();
    std::fs::write(export.join("functions.json"), b"[]\n").unwrap();
    std::fs::write(export.join("disasm.lst"), b"stale disassembly\n").unwrap();
    std::fs::write(export.join("decompiled.c"), b"stale decompilation\n").unwrap();
    let completion = out.join("export/02_MAIN.complete");
    std::fs::write(&completion, b"pixel-modem-extractor-ghidra-export-v1\n").unwrap();

    let script_path = out.join("scripts/ExportDecomp.java");
    let script = std::fs::read_to_string(&script_path).unwrap();
    let mutation_point = concat!(
        "            Files.move(output.temporary.toPath(), output.destination.toPath(),\n",
        "                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);\n"
    );
    assert_eq!(script.matches(mutation_point).count(), 1);
    let injected = script.replacen(
        mutation_point,
        concat!(
            "            Files.move(output.temporary.toPath(), output.destination.toPath(),\n",
            "                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);\n",
            "            if (output.destination.getName().equals(\"functions.json\")) {\n",
            "                throw new RuntimeException(\n",
            "                        \"deterministic partial export fault after functions.json\");\n",
            "            }\n"
        ),
        1,
    );
    std::fs::write(script_path, injected).unwrap();

    let failed_run = run_generated_scatter_kit(&home, &out);
    let diagnostics = process_diagnostics(&failed_run);
    assert!(
        !failed_run.status.success(),
        "generated shell accepted a partial current export:\n{diagnostics}"
    );
    assert!(
        diagnostics.contains("deterministic partial export fault after functions.json"),
        "missing injected ExportDecomp failure:\n{diagnostics}"
    );
    assert!(!export.join("functions.json").exists());
    assert!(!export.join("disasm.lst").exists());
    assert!(!export.join("decompiled.c").exists());
    assert!(!completion.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generated_shell_rejects_suppressed_print_writer_error() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let (dir, out, _) = generate_scatter_kit(&home, "print_writer_error");
    let export = out.join("export/02_MAIN");
    let completion = out.join("export/02_MAIN.complete");

    let script_path = out.join("scripts/ExportDecomp.java");
    let script = std::fs::read_to_string(&script_path).unwrap();
    let mutation_point = "        w.println(\"[\");\n";
    assert_eq!(script.matches(mutation_point).count(), 1);
    let injected = script.replacen(
        mutation_point,
        concat!("        w.close();\n", "        w.println(\"[\");\n"),
        1,
    );
    std::fs::write(script_path, injected).unwrap();

    let failed_run = run_generated_scatter_kit(&home, &out);
    let diagnostics = process_diagnostics(&failed_run);
    assert!(
        !failed_run.status.success(),
        "generated shell accepted a suppressed PrintWriter error (completion marker published={}):\n{diagnostics}",
        completion.exists()
    );
    assert!(
        diagnostics.contains("ExportDecomp: failed to write")
            && diagnostics.contains("functions.json"),
        "missing checked PrintWriter failure:\n{diagnostics}"
    );
    assert!(!export.join("functions.json").exists());
    assert!(!export.join("disasm.lst").exists());
    assert!(!export.join("decompiled.c").exists());
    assert!(!completion.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn direct_run_rejects_stale_valid_inventory_when_invalidation_fails() {
    let dir = std::env::temp_dir().join(format!("pme_scatter_direct_stale_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.join("fake-ghidra");
    std::fs::create_dir_all(home.join("support")).unwrap();
    std::fs::write(home.join("support/analyzeHeadless"), b"not launched\n").unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, craft_scatter_main_modem_bin()).unwrap();
    let out = dir.join("out");
    let export = out.join("export/02_MAIN");
    std::fs::create_dir_all(&export).unwrap();
    std::fs::create_dir(export.join("functions.json")).unwrap();
    std::fs::write(export.join("disasm.lst"), b"stale disassembly\n").unwrap();
    std::fs::write(export.join("decompiled.c"), b"stale decompilation\n").unwrap();
    std::fs::write(export.join("unrelated.sidecar"), b"preserve\n").unwrap();
    let completion = out.join("export/02_MAIN.complete");
    std::fs::write(&completion, b"pixel-modem-extractor-ghidra-export-v1\n").unwrap();

    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();

    let image = report.images.first().expect("synthetic MAIN was selected");
    assert!(
        matches!(
            image.outcome,
            pixel_modem_extractor::decompile::ImageOutcome::Failed(_)
        ),
        "direct run accepted stale functions.json without current completion: {:?}",
        image.outcome
    );
    assert!(!completion.exists(), "stale completion marker survived");
    assert!(export.join("functions.json").is_dir());
    assert!(!export.join("disasm.lst").exists());
    assert!(!export.join("decompiled.c").exists());
    assert_eq!(
        std::fs::read(export.join("unrelated.sidecar")).unwrap(),
        b"preserve\n"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn generated_shell_rejects_extra_marker_bytes_and_scrubs_owned_exports() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("pme_marker_exact_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("fake-ghidra");
    std::fs::create_dir_all(home.join("support")).unwrap();
    let launcher = home.join("support/analyzeHeadless");
    std::fs::write(
        &launcher,
        br#"#!/bin/sh
want_export=0
for arg in "$@"; do
  if [ "$want_export" = 1 ]; then
    export_dir=$arg
    break
  fi
  if [ "$arg" = ExportDecomp.java ]; then
    want_export=1
  fi
done
mkdir -p "$export_dir"
printf '[]\n' > "$export_dir/functions.json"
printf 'disassembly\n' > "$export_dir/disasm.lst"
printf 'decompiled\n' > "$export_dir/decompiled.c"
printf 'pixel-modem-extractor-ghidra-export-v1\n\n' > "$export_dir.complete"
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&launcher).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&launcher, permissions).unwrap();

    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, craft_scatter_main_modem_bin()).unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();

    let result = std::process::Command::new(out.join("run_ghidra.sh"))
        .env("GHIDRA_INSTALL_DIR", &home)
        .output()
        .unwrap();
    assert!(
        !result.status.success(),
        "generated shell normalized and accepted extra marker bytes:\n{}",
        process_diagnostics(&result)
    );
    for path in [
        out.join("export/02_MAIN/functions.json"),
        out.join("export/02_MAIN/disasm.lst"),
        out.join("export/02_MAIN/decompiled.c"),
        out.join("export/02_MAIN.complete"),
    ] {
        assert!(
            !path.exists(),
            "partial owned export survived: {}",
            path.display()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Task 14: the generated shell runs the complete PAL-seeded pass from a
/// kit root whose path contains spaces and parentheses — the quoted
/// `$HERE` rooting, the PAL-aware argv, and the exact v4 marker
/// comparison must all survive them. The remaining shell-active
/// characters (quotes, `&`, `;`, backtick, `!`, `$`) are mangled by
/// upstream `analyzeHeadless`'s own launcher before our quoting can
/// matter, so they are an upstream path constraint (documented in
/// README), not a quoting defect here.
#[test]
fn generated_shell_completes_pal_run_from_root_with_spaces_and_metacharacters() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pme_pal_shell_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("pal kit (roots) meta char");
    std::fs::create_dir_all(&out).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        pal_fixture::discoverable::craft_pal_main_modem_bin(),
    )
    .unwrap();
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.clone()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();
    let manifest_path = out.join("pal_tasks/02_MAIN/tasks.json");
    assert!(
        manifest_path.is_file(),
        "generation must publish the manifest"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let labels: Vec<&str> = manifest["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|task| task["task_label"].as_str().unwrap())
        .collect();
    let identity = format!(
        "v1:{}:2:0",
        blake3::hash(&std::fs::read(&manifest_path).unwrap()).to_hex()
    );

    let run = std::process::Command::new(out.join("run_ghidra.sh"))
        .env("GHIDRA_INSTALL_DIR", &home)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "generated shell failed from a metacharacter root:\n{}",
        process_diagnostics(&run)
    );
    let marker = std::fs::read(out.join("export/02_MAIN.complete")).unwrap();
    assert_eq!(
        marker,
        pixel_modem_extractor::decompile::export_completion_marker("none", &identity, "none"),
        "the shell must compare the exact PAL-aware v4 marker"
    );
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/02_MAIN/functions.json")).unwrap())
            .unwrap();
    let exported: Vec<&str> = functions
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    for label in labels {
        assert!(
            exported.contains(&label),
            "shell-root run lost task primary {label}: {exported:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Task 12's deferred guard: the generated shell fails closed with a clear
/// message when TMPDIR contains whitespace — the `-D` Java tokens are
/// word-split unquoted by analyzeHeadless itself, so a spaced state home
/// would otherwise fail obscurely inside Ghidra. The stub launcher proves
/// the guard fires before any Ghidra work; no real Ghidra is needed.
#[cfg(unix)]
#[test]
fn generated_shell_fails_closed_on_spaced_tmpdir() {
    let dir = std::env::temp_dir().join(format!("pme_pal_tmpdir_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        pal_fixture::discoverable::craft_pal_main_modem_bin(),
    )
    .unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();
    let stub_home = dir.join("ghidra-home");
    std::fs::create_dir_all(stub_home.join("support")).unwrap();
    std::fs::write(
        stub_home.join("support/analyzeHeadless"),
        "#!/bin/sh\necho 'stub analyzeHeadless must not run' >&2\nexit 99\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            stub_home.join("support/analyzeHeadless"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let spaced_tmp = dir.join("tmp with spaces");
    std::fs::create_dir_all(&spaced_tmp).unwrap();
    let run = std::process::Command::new(out.join("run_ghidra.sh"))
        .env("GHIDRA_INSTALL_DIR", &stub_home)
        .env("TMPDIR", &spaced_tmp)
        .output()
        .unwrap();
    assert!(
        !run.status.success(),
        "a spaced TMPDIR must fail the generated shell"
    );
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("whitespace") && stderr.contains("TMPDIR"),
        "the failure must name the whitespace TMPDIR clearly:\n{stderr}"
    );
    assert!(
        !stderr.contains("stub analyzeHeadless must not run"),
        "the guard must fire before any Ghidra work:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exporter_quarantines_instruction_when_tmode_register_is_missing() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let modem = craft_modem_bin(&[0xc3]); // x86 `ret`; language has no ARM TMode register.
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_missing_tmode_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let report = pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home),
            processor: "x86:LE:32:default".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        },
        &out,
    )
    .unwrap();
    let boot = report
        .images
        .iter()
        .find(|image| image.label == "00_BOOT")
        .unwrap();
    assert_eq!(boot.ghidra_execution_accepted, Some(0));
    assert_eq!(boot.ghidra_execution_quarantined, Some(1));
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert_eq!(functions.as_array().unwrap().len(), 1, "{functions}");
    assert_eq!(functions[0]["decode_ranges"], serde_json::json!([]));
    assert_eq!(
        functions[0]["decode_range_errors"],
        serde_json::json!([
            {"kind":"empty_projection","address":"0x0","end":null},
            {"kind":"missing_isa_context","address":"0x0","end":"0x1"}
        ])
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_exports_mixed_isa_ranges_and_preserves_body_gap() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let payload = [
        0x1eu8, 0xff, 0x2f, 0xe1, // A32: bx lr
        0, 0, 0, 0, // exact Function-body gap
        0x70, 0x47, // T32: bx lr
    ];
    let modem = craft_modem_bin(&payload);
    let dir = std::env::temp_dir().join(format!("pme_decompile_mixed_gap_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home.clone()),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    drop(pass1);
    // Seed the mixed-ISA function directly, then drive the shipping
    // ExportDecomp with its pass-1-style argv (`-`/`none`: no map, no
    // SymbolPass2 property) — the strict exporter must derive the mixed
    // execution identity from the current body.
    std::fs::write(
        out.join("scripts/SeedMixedGap.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class SeedMixedGap extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        Address arm = toAddr(0);
        Address thumb = toAddr(8);
        clearListing(arm, toAddr(9));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setValue(tMode, arm, toAddr(3), BigInteger.ZERO);
        if (!disassemble(arm)) throw new Exception("failed to disassemble A32 fixture");
        context.setValue(tMode, thumb, toAddr(9), BigInteger.ONE);
        if (!disassemble(thumb)) throw new Exception("failed to disassemble T32 fixture");
        AddressSet body = new AddressSet();
        body.addRange(arm, toAddr(3));
        body.addRange(thumb, toAddr(9));
        functions.createFunction("mixed_gap", arm, body, SourceType.USER_DEFINED);
        println("SeedMixedGap: ok");
    }
}
"#,
    )
    .unwrap();
    let canonical_root = std::fs::canonicalize(&out).unwrap();
    let seeded = std::process::Command::new(
        analyze_headless_in_home(&home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(out.join("ghidra_project"))
    .arg("pixel-modem")
    .arg("-process")
    .arg("00_BOOT")
    .arg("-noanalysis")
    .arg("-scriptPath")
    .arg(out.join("scripts"))
    .arg("-postScript")
    .arg("SeedMixedGap.java")
    .arg("-postScript")
    .arg("ExportDecomp.java")
    .arg(out.join("export/00_BOOT"))
    .arg(&canonical_root)
    .arg("00_BOOT")
    .arg("none")
    .arg("-")
    .arg("none")
    .arg("-")
    .arg("-")
    .arg("-")
    .arg("none")
    .output()
    .unwrap();
    assert!(
        seeded.status.success(),
        "mixed-gap export run failed:\n{}",
        process_diagnostics(&seeded)
    );

    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert_eq!(functions.as_array().unwrap().len(), 1, "{functions}");
    assert_eq!(functions[0]["name"], "mixed_gap");
    assert_eq!(functions[0]["entry"], "0x0");
    assert_eq!(functions[0]["end"], "0xa");
    assert_eq!(functions[0]["size"], 6);
    assert_eq!(
        functions[0]["decode_ranges"],
        serde_json::json!([
            {
                "isa":"arm",
                "start":"0x0",
                "end":"0x4",
                "blake3":"bb05c128192d9feb3efd889a7572f5283753e943d3dfb9da55d02f2fe9e6dee2"
            },
            {
                "isa":"thumb",
                "start":"0x8",
                "end":"0xa",
                "blake3":"8a09f486717eda865dd286162039792980cf32f77517e0c4fb472529f72e5e8c"
            }
        ])
    );
    assert_eq!(functions[0]["decode_range_errors"], serde_json::json!([]));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_quarantines_when_same_isa_merge_makes_entry_interior() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let payload = [
        0x1eu8, 0xff, 0x2f, 0xe1, // A32: bx lr before the function entry
        0x1e, 0xff, 0x2f, 0xe1, // A32: bx lr at the function entry
    ];
    let modem = craft_modem_bin(&payload);
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_entry_interior_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home.clone()),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    drop(pass1);
    std::fs::write(
        out.join("scripts/SeedSavedProgram.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class SeedSavedProgram extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        clearListing(toAddr(0), toAddr(7));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setValue(tMode, toAddr(0), toAddr(7), BigInteger.ZERO);
        if (!disassemble(toAddr(0)) || !disassemble(toAddr(4))) {
            throw new Exception("failed to disassemble adjacent A32 fixture");
        }
        AddressSet body = new AddressSet(toAddr(0), toAddr(7));
        functions.createFunction(
            "entry_interior", toAddr(4), body, SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let seeded = run_saved_project_export(&home, &out, "00_BOOT", Some("SeedSavedProgram.java"));
    assert!(
        seeded.status.success(),
        "saved-project export run failed:\n{}",
        process_diagnostics(&seeded)
    );

    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert_eq!(functions.as_array().unwrap().len(), 1, "{functions}");
    assert_eq!(functions[0]["entry"], "0x4");
    assert_eq!(functions[0]["decode_ranges"], serde_json::json!([]));
    assert_eq!(
        functions[0]["decode_range_errors"],
        serde_json::json!([
            {"kind":"entry_not_range_start","address":"0x4","end":null}
        ])
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_rejects_function_entry_outside_u32() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let modem = craft_modem_bin(&[0xc3]); // x86-64 `ret`
    let dir = std::env::temp_dir().join(format!(
        "pme_decompile_body_outside_u32_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home.clone()),
        processor: "x86:LE:64:default".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    drop(pass1);
    std::fs::write(
        out.join("scripts/SeedSavedProgram.java"),
        r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class SeedSavedProgram extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        Address high = toAddr(0x1_0000_0000L);
        try {
            currentProgram.getMemory().createInitializedBlock(
                    "outside_u32", high, 4, (byte) 0, monitor, false);
        }
        catch (ghidra.program.model.mem.MemoryConflictException already) {
            // The block persisted from the seed's transaction; reuse it.
        }
        if (!disassemble(high)) throw new Exception("failed to disassemble high fixture");
        AddressSet body = new AddressSet(high, high.add(3));
        if (functions.createFunction(
                "entry_outside_u32", high, body, SourceType.USER_DEFINED) == null) {
            throw new Exception("failed to create the high-entry function");
        }
        System.out.println("SeedSavedProgram: ok");
    }
}
"#,
    )
    .unwrap();
    let seeded = run_saved_project_export(&home, &out, "00_BOOT", Some("SeedSavedProgram.java"));
    let diagnostics = process_diagnostics(&seeded);
    assert!(
        diagnostics.contains("REPORT SCRIPT ERROR")
            && (diagnostics.contains("outside [0, 4294967295]")
                || diagnostics.contains("outside the u32")),
        "a function entry outside the u32 domain must fail the strict exporter:\n{diagnostics}"
    );
    // The pass-1 export (from the direct run, not invalidated by a
    // `run_two_pass` wrapper) keeps its v4 marker; the failed re-export
    // published nothing new.
    let marker_after = std::fs::read(out.join("export/00_BOOT.complete")).unwrap();
    assert_eq!(
        marker_after,
        pixel_modem_extractor::decompile::export_completion_marker("none", "none", "none")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_program_quarantines_complete_defective_records_and_continues() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let mut payload = Vec::new();
    for _ in 0..7 {
        payload.extend([0x1e, 0xff, 0x2f, 0xe1]); // A32: bx lr
    }
    let modem = craft_modem_bin(&payload);
    let dir = std::env::temp_dir().join(format!("pme_decompile_quarantine_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");
    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home.clone()),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let _pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    std::fs::write(
        out.join("scripts/SeedSavedProgram.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class SeedSavedProgram extends GhidraScript {
    private AddressSet body(long min, long max) {
        AddressSet body = new AddressSet();
        body.addRange(toAddr(min), toAddr(max));
        return body;
    }

    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        clearListing(toAddr(0), toAddr(27));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setValue(tMode, toAddr(0), toAddr(27), BigInteger.ZERO);
        for (long address : new long[] {0, 8, 12, 20, 24}) {
            if (!disassemble(toAddr(address))) {
                throw new Exception("failed to disassemble fixture at " + address);
            }
        }
        Instruction overridden = currentProgram.getListing().getInstructionAt(toAddr(8));
        overridden.setLengthOverride(2);
        functions.createFunction("accepted_before", toAddr(0), body(0, 3), SourceType.USER_DEFINED);
        functions.createFunction("overridden", toAddr(8), body(8, 11), SourceType.USER_DEFINED);
        functions.createFunction("body_escape", toAddr(12), body(12, 13), SourceType.USER_DEFINED);
        AddressSet missingEntryBody = body(16, 16);
        missingEntryBody.addRange(toAddr(20), toAddr(23));
        functions.createFunction("missing_entry", toAddr(16), missingEntryBody, SourceType.USER_DEFINED);
        functions.createFunction("accepted_after", toAddr(24), body(24, 27), SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let seeded = run_saved_project_export(&home, &out, "00_BOOT", Some("SeedSavedProgram.java"));
    assert!(
        seeded.status.success(),
        "saved-project export run failed:\n{}",
        process_diagnostics(&seeded)
    );
    let functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    let by_name: HashMap<&str, &serde_json::Value> = functions
        .as_array()
        .unwrap()
        .iter()
        .map(|function| (function["name"].as_str().unwrap(), function))
        .collect();
    assert_eq!(
        by_name["accepted_before"]["decode_ranges"],
        serde_json::json!([{
            "isa":"arm",
            "start":"0x0",
            "end":"0x4",
            "blake3":"bb05c128192d9feb3efd889a7572f5283753e943d3dfb9da55d02f2fe9e6dee2"
        }])
    );
    assert_eq!(
        by_name["overridden"]["decode_ranges"],
        serde_json::json!([]),
        "a defective record must not retain a valid-looking range prefix"
    );
    assert_eq!(
        by_name["overridden"]["decode_range_errors"],
        serde_json::json!([
            {"kind":"misaligned_instruction","address":"0x8","end":"0xa"},
            {"kind":"overridden_instruction_length","address":"0x8","end":"0xa"}
        ])
    );
    assert_eq!(
        by_name["body_escape"]["decode_range_errors"],
        serde_json::json!([
            {"kind":"extent_outside_function","address":"0xc","end":"0x10"}
        ])
    );
    assert_eq!(
        by_name["missing_entry"]["decode_range_errors"],
        serde_json::json!([
            {"kind":"missing_instruction_at_entry","address":"0x10","end":null}
        ])
    );
    assert_eq!(
        by_name["accepted_after"]["decode_ranges"],
        serde_json::json!([{
            "isa":"arm",
            "start":"0x18",
            "end":"0x1c",
            "blake3":"bb05c128192d9feb3efd889a7572f5283753e943d3dfb9da55d02f2fe9e6dee2"
        }]),
        "later functions must still export after record-local quarantines"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Pass-2 application end-to-end: drive pass 1 via `run_report`, then apply a
/// function and strict Recovered globals in the same saved-project process.
/// Subsequent attempts prove non-default preservation and invalid-map isolation.
#[test]
fn pass2_applies_functions_and_strict_globals_in_one_process() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    // ARM: `ldr r0, [pc, #0x18]`; `bx lr`; six vector-slot self-branches;
    // one data word at 0x20. The LDR genuinely references 0x20, while the
    // self-branches keep vector analysis from flowing into that data word.
    let mut arm = vec![0x18u8, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1];
    for _ in 0..6 {
        arm.extend([0xfe, 0xff, 0xff, 0xea]); // b .
    }
    arm.extend([0x78, 0x56, 0x34, 0x12]);
    // Two Thumb halfwords at 0x24 (`push {r7}`; `pop {r7,pc}`): real,
    // flow-through Thumb code that nothing references, so Ghidra's own
    // inventory never discovers it — the pass-2 creation path
    // (ApplyThumbNames) must carve it from the authenticated producer record
    // and name it.
    arm.extend([0x80, 0xb5, 0x80, 0xbd]);
    arm.extend([0; 8]);
    arm.extend([0x70, 0x47]); // bx lr at 0x30: isolated collision-skip fixture.
    // Ghidra's ARM vector analysis names the image-start functions with
    // IMPORTED-sourced primaries; the strict pass-2 contract protects them
    // (the token rename downgrades to preserve) while the decision's token
    // annotation still applies as a plate comment.
    let modem = craft_modem_bin(&arm);

    let dir = std::env::temp_dir().join(format!("pme_decompile_p2_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home.clone()),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };

    // Pass 1: analyze + initial decompiled.c (with FUN_ placeholder).
    let pass1_report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    assert!(
        pass1_report.images.iter().any(|r| r.label == "00_BOOT"),
        "pass 1 should have analyzed 00_BOOT"
    );
    let pass1_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert!(
        pass1_functions
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["data_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| reference == "0x20")),
        "fixture did not produce a genuine data reference: {pass1_functions}"
    );
    let pass1_projections: HashMap<String, serde_json::Value> = pass1_functions
        .as_array()
        .unwrap()
        .iter()
        .map(|function| {
            (
                function["entry"].as_str().unwrap().to_string(),
                serde_json::json!({
                    "decode_ranges": function["decode_ranges"],
                    "decode_range_errors": function["decode_range_errors"],
                }),
            )
        })
        .collect();
    let retained_thumb = std::str::from_utf8(br#"{
  "format": "pixel-modem-extractor-thumb-functions-v3",
  "producers": [
    {"id":"radare2","executable":"/usr/bin/r2","version":"radare2 fixture","command":"aaa;aflj;pdfj @@f"},
    {"id":"rizin","executable":"/usr/bin/rizin","version":"rizin fixture","command":"aaa;aflj;pdfj @@F;axlj"}
  ],
  "regions": [{
    "start":"0x0","end":"0x32",
    "attempts":[
      {"producer":"radare2","status":"failed","stdout":null,"error":"radare2 fixture failure"},
      {"producer":"rizin","status":"succeeded","stdout":{"path":"thumb/00000000.rizin.stdout","bytes":1,"blake3":"0000000000000000000000000000000000000000000000000000000000000000"},"error":null}
    ],
    "function_runs":[{"producer":"rizin","first_function":0,"function_count":4,"substantial":0,"accepted":4,"quarantined":0}]
  }],
  "functions": [{
    "name":"retained_thumb_fixture","entry":"0x0","end":"0x2","size":2,
    "decode_ranges":[{"isa":"thumb","start":"0x0","end":"0x2","blake3":"__RANGE_BLAKE3__"}],
    "decode_range_errors":[],"body_kind":"thumb_disassembly","body":"","data_refs":[]
  }, {
    "name":"retained_thumb_created","entry":"0x24","end":"0x28","size":4,
    "decode_ranges":[{"isa":"thumb","start":"0x24","end":"0x28","blake3":"__CREATED_BLAKE3__"}],
    "decode_range_errors":[],"body_kind":"thumb_disassembly","body":"","data_refs":["0x20"]
  }, {
    "name":"retained_thumb_overlap","entry":"0x26","end":"0x28","size":2,
    "decode_ranges":[{"isa":"thumb","start":"0x26","end":"0x28","blake3":"__OVERLAP_BLAKE3__"}],
    "decode_range_errors":[],"body_kind":"thumb_disassembly","body":"","data_refs":["0x20"]
  }, {
    "name":"retained_thumb_collision","entry":"0x30","end":"0x32","size":2,
    "decode_ranges":[{"isa":"thumb","start":"0x30","end":"0x32","blake3":"__COLLISION_BLAKE3__"}],
    "decode_range_errors":[],"body_kind":"thumb_disassembly","body":"","data_refs":["0x20"]
  }]
}"#)
    .unwrap()
    .replace(
        "__RANGE_BLAKE3__",
        blake3::hash(&arm[..2]).to_hex().as_ref(),
    )
    .replace(
        "__CREATED_BLAKE3__",
        blake3::hash(&arm[0x24..0x28]).to_hex().as_ref(),
    )
    .replace(
        "__OVERLAP_BLAKE3__",
        blake3::hash(&arm[0x26..0x28]).to_hex().as_ref(),
    )
    .replace(
        "__COLLISION_BLAKE3__",
        blake3::hash(&arm[0x30..0x32]).to_hex().as_ref(),
    )
    .into_bytes();
    std::fs::write(
        out.join("export/00_BOOT/thumb_functions.json"),
        &retained_thumb,
    )
    .unwrap();

    // Build the strict v3 symbol map from the retained pass-1 tree. Token
    // 0x20 (a genuine LDR data reference) drives one provisional rename; the
    // retained file is hashed verbatim through the same builder the decompose
    // pipeline uses.
    let images_dir = dir.join("images");
    let boot_dir = images_dir.join("00_BOOT");
    std::fs::create_dir_all(boot_dir.join("decompiled")).unwrap();
    std::fs::write(boot_dir.join("00_BOOT.bin"), &arm).unwrap();
    std::fs::copy(
        out.join("export/00_BOOT/functions.json"),
        boot_dir.join("decompiled/functions.json"),
    )
    .unwrap();
    std::fs::copy(
        out.join("export/00_BOOT/disasm.lst"),
        boot_dir.join("decompiled/disasm.lst"),
    )
    .unwrap();
    // The retained Thumb artifact must be visible to the map builder so the
    // named thumb-only record reaches the creation section.
    std::fs::copy(
        out.join("export/00_BOOT/thumb_functions.json"),
        boot_dir.join("decompiled/thumb_functions.json"),
    )
    .unwrap();
    let tree_manifest = dir.join("manifest.json");
    std::fs::write(&tree_manifest, r#"{"toc":[{"name":"BOOT","load_addr":0}]}"#).unwrap();
    let tokens = pixel_modem_extractor::symbolicate::token_map(&parse_token_db(&[(
        0x20,
        "■format♦reset handler (%d)■domain♦BOOT",
    )]));
    let maps_dir = out.join("symbol_maps");
    std::fs::create_dir_all(&maps_dir).unwrap();
    let map_path = maps_dir.join("00_BOOT.json");
    let bundle = pixel_modem_extractor::symbolicate::prepare_pass2_symbol_map(
        &map_path,
        &boot_dir,
        "00_BOOT",
        &tokens,
        &tree_manifest,
        None,
    )
    .unwrap();
    assert!(
        bundle.map.applied_decision_count >= 1,
        "the token reference must schedule pass 2"
    );
    assert_eq!(
        bundle.map.creation_count, 3,
        "all authenticated Thumb entries must reach the runtime classifier"
    );
    let map_text = std::fs::read_to_string(&map_path).unwrap();
    let written: serde_json::Value = serde_json::from_str(&map_text).unwrap();
    assert_eq!(
        written["executions"].as_array().map(Vec::len),
        Some(bundle.map.execution_count),
        "the written map must carry the measured execution count"
    );
    let valid_primary = "\"final_primary\": \"guess_boot_reset_handler_d_00000030\"";
    assert_eq!(map_text.matches(valid_primary).count(), 1);
    let created_execution_blake3 = written["creations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|creation| creation["entry"] == "0x00000024")
        .and_then(|creation| creation["execution_blake3"].as_str())
        .expect("the creation fixture must carry its execution identity")
        .to_string();
    // A valid global symbol elsewhere in memory reserves the requested 0x30
    // primary. ApplyThumbNames must classify it as a collision without
    // touching the candidate entry.
    let seed_collision = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class SeedThumbCreationCollision extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getSymbolTable().createLabel(toAddr(0x2c),
                "guess_boot_reset_handler_d_00000030", SourceType.USER_DEFINED);
    }
}
"#;
    std::fs::write(
        out.join("scripts/SeedThumbCreationCollision.java"),
        seed_collision,
    )
    .unwrap();
    let seeded = inspect_saved_project(&home, &out, "00_BOOT", "SeedThumbCreationCollision.java");
    assert!(
        seeded.status.success(),
        "collision seeding failed:\n{}",
        process_diagnostics(&seeded)
    );
    let symbol_map = prepared_symbol_map(
        &images_dir,
        "00_BOOT",
        &map_path,
        bundle.map.execution_count,
        bundle.map.creation_requests.clone(),
    );

    // A separate creation-only saved project proves that ExportDecomp never
    // inserts its pass-1 entry fallback after a map-authenticated zero-function
    // postflight. Every creation name is reserved by an unrelated global
    // label, so ApplyThumbNames must classify all requests as collisions.
    let creation_only_out = dir.join("creation-only-out");
    let creation_only_pass1 =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &creation_only_out)
            .unwrap();
    assert!(
        creation_only_pass1
            .images
            .iter()
            .any(|result| result.label == "00_BOOT"),
        "creation-only fixture pass 1 did not analyze 00_BOOT"
    );
    let creation_only_functions_path = creation_only_out.join("export/00_BOOT/functions.json");
    let creation_only_functions = std::fs::read(&creation_only_functions_path).unwrap();
    let creation_only_functions_blake3 =
        blake3::hash(&creation_only_functions).to_hex().to_string();
    let retained_functions_blake3 = written["functions_blake3"].as_str().unwrap();
    let retained_hash_field = format!("\"functions_blake3\": \"{retained_functions_blake3}\"");
    assert_eq!(map_text.matches(&retained_hash_field).count(), 1);
    let creation_only_map = map_text.replacen(
        &retained_hash_field,
        &format!("\"functions_blake3\": \"{creation_only_functions_blake3}\""),
        1,
    );
    let executions_start = creation_only_map.find("  \"executions\": [").unwrap();
    let creations_start = creation_only_map.find("  \"creations\": [").unwrap();
    assert!(executions_start < creations_start);
    let creation_only_map = format!(
        "{}  \"executions\": [],\n  \"symbols\": [],\n{}",
        &creation_only_map[..executions_start],
        &creation_only_map[creations_start..],
    );
    let creation_only_maps_dir = creation_only_out.join("symbol_maps");
    std::fs::create_dir_all(&creation_only_maps_dir).unwrap();
    let creation_only_map_path = creation_only_maps_dir.join("00_BOOT-creation-only.json");
    let creation_only_map_bytes = creation_only_map.into_bytes();
    std::fs::write(&creation_only_map_path, &creation_only_map_bytes).unwrap();
    let creation_only_symbol_map = pixel_modem_extractor::decompile::PreparedSymbolPass2Map::new(
        &creation_only_map_path,
        &creation_only_functions_path,
        &boot_dir.join("00_BOOT.bin"),
        "00_BOOT",
        0,
        0,
        bundle.map.creation_requests.clone(),
    )
    .unwrap();
    assert_eq!(creation_only_symbol_map.execution_count(), 0);
    assert_eq!(creation_only_symbol_map.applied_decision_count(), 0);
    assert_eq!(creation_only_symbol_map.creation_count(), 3);

    let collision_names = bundle
        .map
        .creation_requests
        .iter()
        .map(|request| format!("\"{}\"", request.final_primary))
        .collect::<Vec<_>>()
        .join(", ");
    let seed_creation_only = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import java.util.ArrayList;
import java.util.List;

public class SeedCreationOnlyCollisionProject extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        List<Address> entries = new ArrayList<Address>();
        FunctionIterator current = functions.getFunctions(true);
        while (current.hasNext()) {
            entries.add(current.next().getEntryPoint());
        }
        for (Address entry : entries) {
            if (!functions.removeFunction(entry)) {
                throw new AssertionError("could not remove function at " + entry);
            }
        }
        if (functions.getFunctionCount() != 0) {
            throw new AssertionError("saved project still has functions");
        }
        String[] names = new String[] { __COLLISION_NAMES__ };
        long[] addresses = new long[] { 0x28L, 0x2aL, 0x2cL };
        if (names.length != addresses.length) {
            throw new AssertionError("creation collision fixture count changed");
        }
        for (int index = 0; index < names.length; index++) {
            currentProgram.getSymbolTable().createLabel(toAddr(addresses[index]), names[index],
                    SourceType.USER_DEFINED);
        }
        System.out.println("SeedCreationOnlyCollisionProject: ready");
    }
}
"#
    .replace("__COLLISION_NAMES__", &collision_names);
    std::fs::write(
        creation_only_out.join("scripts/SeedCreationOnlyCollisionProject.java"),
        seed_creation_only,
    )
    .unwrap();
    let creation_only_seeded = inspect_saved_project(
        &home,
        &creation_only_out,
        "00_BOOT",
        "SeedCreationOnlyCollisionProject.java",
    );
    let creation_only_seed_diagnostics = process_diagnostics(&creation_only_seeded);
    let creation_only_seed_stdout = String::from_utf8_lossy(&creation_only_seeded.stdout);
    assert!(
        creation_only_seeded.status.success()
            && creation_only_seed_stdout
                .lines()
                .any(|line| line == "SeedCreationOnlyCollisionProject: ready"),
        "creation-only project seeding did not complete:\n{creation_only_seed_diagnostics}"
    );

    let creation_only_root = std::fs::canonicalize(&creation_only_out).unwrap();
    let creation_only_config = creation_only_out.join("ghidra_config");
    let creation_only_cache = creation_only_out.join("ghidra_cache");
    let creation_only_temp = creation_only_out.join("ghidra_tmp");
    let creation_only_java_options = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        creation_only_config.display(),
        creation_only_cache.display(),
        creation_only_temp.display(),
        creation_only_temp.display()
    );
    let creation_only_attempt = std::process::Command::new(
        analyze_headless_in_home(&home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(creation_only_out.join("ghidra_project"))
    .arg("pixel-modem")
    .arg("-process")
    .arg("00_BOOT")
    .arg("-noanalysis")
    .arg("-scriptPath")
    .arg(creation_only_out.join("scripts"))
    .arg("-postScript")
    .arg("ApplyThumbNames.java")
    .arg("00_BOOT")
    .arg(creation_only_symbol_map.image_blake3())
    .arg(creation_only_symbol_map.path())
    .arg(creation_only_symbol_map.map_blake3())
    .arg("-postScript")
    .arg("ApplySymbols.java")
    .arg(&creation_only_root)
    .arg("00_BOOT")
    .arg(creation_only_symbol_map.image_blake3())
    .arg("none")
    .arg("-")
    .arg("-")
    .arg(&creation_only_functions_path)
    .arg(creation_only_symbol_map.functions_blake3())
    .arg(creation_only_symbol_map.path())
    .arg(creation_only_symbol_map.map_blake3())
    .arg("-postScript")
    .arg("ExportDecomp.java")
    .arg(creation_only_out.join("export/00_BOOT"))
    .arg(&creation_only_root)
    .arg("00_BOOT")
    .arg("none")
    .arg("-")
    .arg("none")
    .arg("-")
    .arg("-")
    .arg(creation_only_symbol_map.path())
    .arg(creation_only_symbol_map.map_blake3())
    .env("XDG_CONFIG_HOME", creation_only_config)
    .env("XDG_CACHE_HOME", creation_only_cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", creation_only_java_options)
    .output()
    .unwrap();
    let creation_only_diagnostics = process_diagnostics(&creation_only_attempt);
    assert!(
        creation_only_attempt.status.success(),
        "creation-only pass 2 failed:\n{creation_only_diagnostics}"
    );
    let creation_only_stdout = String::from_utf8_lossy(&creation_only_attempt.stdout);
    let creation_only_summary: serde_json::Value = creation_only_stdout
        .lines()
        .find_map(|line| line.strip_prefix("ApplyThumbNames: "))
        .map(|payload| serde_json::from_str(payload).unwrap())
        .unwrap_or_else(|| {
            panic!("creation-only pass 2 emitted no Thumb summary:\n{creation_only_diagnostics}")
        });
    assert_eq!(
        creation_only_summary,
        serde_json::json!({
            "image": "00_BOOT",
            "status": "ok",
            "candidates": 3,
            "created": 0,
            "reapplied": 0,
            "skipped_existing": 0,
            "skipped_collision": 3,
        }),
        "creation-only runtime classification changed:\n{creation_only_diagnostics}"
    );
    let creation_only_export = creation_only_out.join("export/00_BOOT");
    assert_eq!(
        std::fs::read(creation_only_out.join("export/00_BOOT.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            "none",
            "none",
            creation_only_symbol_map.map_blake3(),
        ),
        "creation-only export marker did not bind the strict-v3 map"
    );
    let creation_only_functions: serde_json::Value = serde_json::from_slice(
        &std::fs::read(creation_only_export.join("functions.json")).unwrap(),
    )
    .unwrap();
    assert!(
        creation_only_functions.as_array().unwrap().is_empty(),
        "map-authenticated pass 2 inserted an unowned fallback function:\n{creation_only_functions}"
    );

    let global_map_path = maps_dir.join("00_BOOT-globals.json");
    let global_map = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [
            {
                "address": "0x20",
                "name": "recovered_global_word",
                "tier": "recovered",
            },
            {
                "address": "0x20",
                "name": "provisional_must_not_apply",
                "tier": "provisional",
            },
            {
                "address": "0x1000",
                "name": "outside_memory_global",
                "tier": "recovered",
            },
        ],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&global_map).unwrap(),
    )
    .unwrap();

    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_symbol_map(
                &images_dir,
                "00_BOOT",
                &map_path,
                bundle.map.execution_count,
                bundle.map.creation_requests.clone(),
            )),
            global_map: Some(prepared_pass2_map(&global_map_path, 2)),
            global_types_map: None,
            ..Default::default()
        },
    )]);

    let apply_thumb_path = out.join("scripts/ApplyThumbNames.java");
    let apply_thumb_source = std::fs::read_to_string(&apply_thumb_path).unwrap();
    let thumb_apply_args = vec![
        "00_BOOT".to_string(),
        symbol_map.image_blake3().to_string(),
        symbol_map.path().to_string_lossy().into_owned(),
        symbol_map.map_blake3().to_string(),
    ];
    let rollback_probe = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;
import java.math.BigInteger;

public class ProbeThumbCreationRollback extends GhidraScript {
    @Override
    public void run() throws Exception {
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        for (long raw = 0x24; raw <= 0x27; raw++) {
            Address address = toAddr(raw);
            if (currentProgram.getFunctionManager().getFunctionContaining(address) != null) {
                throw new AssertionError("the failed creation left a function at "
                        + address);
            }
            if (currentProgram.getListing().getInstructionContaining(address) != null) {
                throw new AssertionError("the failed creation left an instruction at "
                        + address);
            }
            RegisterValue value = currentProgram.getProgramContext()
                    .getRegisterValue(tMode, address);
            if (value != null && value.hasValue()
                    && BigInteger.ONE.equals(value.getUnsignedValue())) {
                throw new AssertionError("the failed creation left Thumb context at "
                        + address);
            }
        }
        StringPropertyMap ownership = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ThumbNames.v1.Ownership");
        if (ownership != null) {
            throw new AssertionError("the failed creation left an ownership property map");
        }
        if (currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString("PixelModemExtractor.SymbolPass2", null) != null) {
            throw new AssertionError("ApplySymbols ran before creation preflight completed");
        }
        System.out.println("ProbeThumbCreationRollback: clean");
    }
}
"#;
    std::fs::write(
        out.join("scripts/ProbeThumbCreationRollback.java"),
        rollback_probe,
    )
    .unwrap();

    // Expiry while the ownership value is finalized must remain bound to the
    // original per-entry mutation monitor. The helper computes the digest,
    // emits an exact marker, then sleeps beyond this command's positive entry
    // budget; accepting the returned value would incorrectly reset the clock
    // at postflight.
    let pal_support_path = out.join("scripts/PalTasksSupport.java");
    let pal_support_source = std::fs::read_to_string(&pal_support_path).unwrap();
    let ownership_value_site = concat!(
        "        return \"v1:\" + map.mapBlake3 + \":\" + creation.executionBlake3 + \":\"\n",
        "                + function.getID() + \":\" + function.getSymbol().getID() + \":\"\n",
        "                + currentExecutionDigest(function.getProgram(), monitor, function);\n",
    );
    assert_eq!(pal_support_source.matches(ownership_value_site).count(), 1);
    let ownership_value_fault = concat!(
        "        String value = \"v1:\" + map.mapBlake3 + \":\" + creation.executionBlake3 + \":\"\n",
        "                + function.getID() + \":\" + function.getSymbol().getID() + \":\"\n",
        "                + currentExecutionDigest(function.getProgram(), monitor, function);\n",
        "        System.out.println(\"ThumbCreationOwnershipDeadlineFault: hashed\");\n",
        "        long budget = Long.parseLong(\n",
        "                System.getenv(\"PME_THUMB_CREATE_ENTRY_BUDGET_MS\"));\n",
        "        Thread.sleep(Math.addExact(budget, 100L));\n",
        "        return value;\n",
    );
    std::fs::write(
        &pal_support_path,
        pal_support_source.replace(ownership_value_site, ownership_value_fault),
    )
    .unwrap();
    let ownership_deadline_attempt = inspect_saved_project_with_args_and_env(
        &home,
        &out,
        "00_BOOT",
        "ApplyThumbNames.java",
        &thumb_apply_args,
        &[("PME_THUMB_CREATE_ENTRY_BUDGET_MS", "1000")],
    );
    let ownership_deadline_diagnostics = process_diagnostics(&ownership_deadline_attempt);
    let ownership_deadline_stdout = String::from_utf8_lossy(&ownership_deadline_attempt.stdout);
    assert!(
        ownership_deadline_stdout
            .lines()
            .any(|line| line == "ThumbCreationOwnershipDeadlineFault: hashed"),
        "ownership deadline fault did not finish hashing:\n{ownership_deadline_diagnostics}"
    );
    assert!(
        ownership_deadline_diagnostics
            .contains("the per-entry ApplyThumbNames ownership budget was exhausted at 00000024"),
        "the expired ownership monitor was accepted:\n{ownership_deadline_diagnostics}"
    );
    assert!(
        !ownership_deadline_stdout
            .lines()
            .any(|line| line.starts_with("ApplyThumbNames: {")),
        "an expired ownership monitor emitted a success summary:\n{ownership_deadline_diagnostics}"
    );
    let ownership_deadline_rolled_back =
        inspect_saved_project(&home, &out, "00_BOOT", "ProbeThumbCreationRollback.java");
    let ownership_rollback_diagnostics = process_diagnostics(&ownership_deadline_rolled_back);
    let ownership_rollback_stdout = String::from_utf8_lossy(&ownership_deadline_rolled_back.stdout);
    assert!(
        ownership_deadline_rolled_back.status.success()
            && ownership_rollback_stdout
                .lines()
                .any(|line| line == "ProbeThumbCreationRollback: clean"),
        "ownership deadline left pass-2 creation residue:\n{ownership_rollback_diagnostics}"
    );
    std::fs::write(&pal_support_path, &pal_support_source).unwrap();

    // Expiry after postflight and conservation must still enter the mutation
    // catch, reverse the journal, and abort the saved-project transaction.
    let deadline_fault_site = concat!(
        "            if (classified != map.creations.size()) {\n",
        "                fail(\"the ApplyThumbNames classification did not conserve candidates\");\n",
        "            }\n",
    );
    assert_eq!(apply_thumb_source.matches(deadline_fault_site).count(), 1);
    let deadline_fault = format!(
        r#"{deadline_fault_site}            System.out.println("ApplyThumbNamesDeadlineFault: reached");
            while (System.currentTimeMillis() <= phaseDeadline) {{
                Thread.sleep(1L);
            }}
"#
    );
    std::fs::write(
        &apply_thumb_path,
        apply_thumb_source.replace(deadline_fault_site, &deadline_fault),
    )
    .unwrap();
    let deadline_attempt = inspect_saved_project_with_args_and_env(
        &home,
        &out,
        "00_BOOT",
        "ApplyThumbNames.java",
        &thumb_apply_args,
        &[("PME_THUMB_CREATE_PHASE_BUDGET_MS", "5000")],
    );
    let deadline_diagnostics = process_diagnostics(&deadline_attempt);
    let deadline_stdout = String::from_utf8_lossy(&deadline_attempt.stdout);
    assert!(
        deadline_stdout
            .lines()
            .any(|line| line == "ApplyThumbNamesDeadlineFault: reached"),
        "deadline fault did not reach the final phase gate:\n{deadline_diagnostics}"
    );
    assert!(
        !deadline_stdout
            .lines()
            .any(|line| line.starts_with("ApplyThumbNames: {")),
        "an expired creation phase emitted a success summary:\n{deadline_diagnostics}"
    );
    assert!(
        deadline_diagnostics.contains("the ApplyThumbNames phase budget was exhausted before"),
        "the deadline attempt failed for the wrong reason:\n{deadline_diagnostics}"
    );
    let deadline_rolled_back =
        inspect_saved_project(&home, &out, "00_BOOT", "ProbeThumbCreationRollback.java");
    let deadline_rollback_diagnostics = process_diagnostics(&deadline_rolled_back);
    let deadline_rollback_stdout = String::from_utf8_lossy(&deadline_rolled_back.stdout);
    assert!(
        deadline_rolled_back.status.success(),
        "deadline expiry left pass-2 creation residue:\n{deadline_rollback_diagnostics}"
    );
    assert!(
        deadline_rollback_stdout
            .lines()
            .any(|line| line == "ProbeThumbCreationRollback: clean"),
        "deadline rollback probe did not complete cleanly:\n{deadline_rollback_diagnostics}"
    );
    std::fs::write(&apply_thumb_path, &apply_thumb_source).unwrap();

    // A deterministic failure after the first creation must roll the whole
    // script transaction back before the successful pass-2 attempt.
    let fault_site = "                created++;\n";
    assert_eq!(apply_thumb_source.matches(fault_site).count(), 1);
    std::fs::write(
        &apply_thumb_path,
        apply_thumb_source.replace(
            fault_site,
            "                created++;\n                throw new RuntimeException(\"injected post-create rollback\");\n",
        ),
    )
    .unwrap();
    let mut fault_inputs = inputs.clone();
    fault_inputs.get_mut("00_BOOT").unwrap().global_map = None;
    let failed_attempt =
        pixel_modem_extractor::decompile::run_two_pass(pass1_report, &opts, &out, &fault_inputs)
            .unwrap()
            .report;
    let failed_boot = failed_attempt
        .images
        .iter()
        .find(|result| result.label == "00_BOOT")
        .unwrap();
    assert!(
        failed_boot.pass2_error.is_some(),
        "injected rollback fault unexpectedly produced a current export"
    );
    let rolled_back =
        inspect_saved_project(&home, &out, "00_BOOT", "ProbeThumbCreationRollback.java");
    let rollback_diagnostics = process_diagnostics(&rolled_back);
    let rollback_stdout = String::from_utf8_lossy(&rolled_back.stdout);
    assert!(
        rolled_back.status.success(),
        "creation rollback probe failed:\n{rollback_diagnostics}"
    );
    assert!(
        rollback_stdout
            .lines()
            .any(|line| line == "ProbeThumbCreationRollback: clean"),
        "creation rollback probe did not complete cleanly:\n{rollback_diagnostics}"
    );
    std::fs::write(&apply_thumb_path, apply_thumb_source).unwrap();

    // Pass 2: pass the failed attempt's report in (do NOT re-run pass 1).
    let rep2 = pixel_modem_extractor::decompile::run_two_pass(failed_attempt, &opts, &out, &inputs)
        .unwrap()
        .report;
    let exp = out.join("export").join("00_BOOT");

    // (c) The imported-sourced vector primaries stay protected: the token
    // rename downgrades to preserve (zero applied renames) while the
    // decision's token annotation still lands as a plate comment.
    let boot = rep2
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .expect("00_BOOT in pass-2 report");
    assert_eq!(
        boot.pass2_applied,
        Some(0),
        "pass2_applied should be Some(0): {:?}",
        boot.pass2_error
    );
    assert!(
        boot.pass2_error.is_none(),
        "pass2_error: {:?}",
        boot.pass2_error
    );
    assert_eq!(boot.globals_applied, Some(1));
    assert_eq!(boot.globals_apply_skipped, Some(1));
    // The named thumb-only record (token evidence on an entry Ghidra never
    // discovered) must be carved and named in this same pass-2 process.
    assert_eq!(
        boot.pass2_thumb_names,
        Some(pixel_modem_extractor::decompile::AppliedThumbNames {
            candidates: 3,
            created: 1,
            reapplied: 0,
            skipped_existing: 1,
            skipped_collision: 1,
        }),
        "ApplyThumbNames summary: {:?}",
        boot.pass2_error
    );
    assert!(
        boot.globals_apply_error.is_none(),
        "globals_apply_error: {:?}",
        boot.globals_apply_error
    );

    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(
        c.contains("Reset"),
        "the imported vector primary must survive pass 2:\n{c}"
    );
    assert!(
        !c.contains("guess_boot_reset_handler_00000000"),
        "a guess name displaced a protected imported primary:\n{c}"
    );
    let annotation = "logs: \"reset handler (%d)\" [BOOT]";
    let block = format!("/* {annotation} */");
    let line = format!("// {annotation}");
    assert!(
        c.lines().any(|l| l.trim() == block || l.trim() == line),
        "the token annotation plate comment is missing:\n{c}"
    );
    assert!(
        c.contains("recovered_global_word"),
        "Recovered global missing at the decompiled reference site:\n{c}"
    );
    assert!(!c.contains("provisional_must_not_apply"));
    assert!(!c.contains("outside_memory_global"));

    // The completion marker binds identity none and the exact map hash.
    assert_eq!(
        std::fs::read(exp.join("..").join("00_BOOT.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            "none",
            "none",
            symbol_map.map_blake3(),
        ),
    );

    // The strict pass-2 property survived in the saved program.
    let property_probe = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;

public class ProbeProperty extends GhidraScript {
    @Override
    public void run() throws Exception {
        System.out.println("ProbeProperty: " + currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString("PixelModemExtractor.SymbolPass2", null));
        StringPropertyMap ownership = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ThumbNames.v1.Ownership");
        System.out.println("ProbeThumbOwnership: "
                + (ownership == null ? null : ownership.getString(toAddr(0x24))));
    }
}
"#;
    std::fs::write(out.join("scripts/ProbeProperty.java"), property_probe).unwrap();
    let probed = inspect_saved_project(&home, &out, "00_BOOT", "ProbeProperty.java");
    assert!(
        probed.status.success(),
        "property probe failed:\n{}",
        process_diagnostics(&probed)
    );
    let stdout = String::from_utf8_lossy(&probed.stdout);
    let reported_property = stdout
        .lines()
        .find_map(|l| l.strip_prefix("ProbeProperty: "))
        .unwrap_or_else(|| panic!("no property line:\n{stdout}"))
        .trim_end_matches(" (GhidraScript)")
        .to_string();
    assert_eq!(
        reported_property,
        symbol_map.pass2_property(),
        "the SymbolPass2 property must bind the map, functions hash, and count"
    );
    let reported_ownership = stdout
        .lines()
        .find_map(|line| line.strip_prefix("ProbeThumbOwnership: "))
        .unwrap_or_else(|| panic!("no ownership line:\n{stdout}"))
        .trim_end_matches(" (GhidraScript)");
    let ownership_parts = reported_ownership.split(':').collect::<Vec<_>>();
    assert_eq!(ownership_parts.len(), 6, "ownership grammar");
    assert_eq!(ownership_parts[0], "v1");
    assert_eq!(ownership_parts[1], symbol_map.map_blake3());
    assert_eq!(ownership_parts[2], created_execution_blake3);
    assert!(ownership_parts[3].parse::<u64>().is_ok(), "function ID");
    assert!(
        ownership_parts[4].parse::<u64>().is_ok(),
        "primary symbol ID"
    );
    assert!(
        ownership_parts[5].len() == 64
            && ownership_parts[5]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Ghidra execution digest"
    );

    // The export's mandatory execution projections are unchanged from pass 1
    // and the retained Thumb sidecar is preserved byte-for-byte.
    let final_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exp.join("functions.json")).unwrap()).unwrap();
    for function in final_functions.as_array().unwrap() {
        let entry = function["entry"].as_str().unwrap();
        // The carved creation has no pass-1 projection; every pass-1 record
        // must keep its exact projection.
        if entry == "0x24" {
            assert_eq!(
                function["name"], "guess_boot_reset_handler_d_00000024",
                "the created function must carry its token name"
            );
            assert_eq!(function["primary_source"], "analysis");
            continue;
        }
        assert_eq!(
            serde_json::json!({
                "decode_ranges": function["decode_ranges"],
                "decode_range_errors": function["decode_range_errors"],
            }),
            pass1_projections[entry],
            "pass 2 changed mandatory execution projection for {entry}"
        );
    }
    assert!(
        final_functions
            .as_array()
            .unwrap()
            .iter()
            .all(|function| function["entry"] != "0x26" && function["entry"] != "0x30"),
        "runtime skips must not create overlapping or colliding functions"
    );
    let probe_skips = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.util.StringPropertyMap;
import java.math.BigInteger;

public class ProbeThumbCreationSkips extends GhidraScript {
    @Override
    public void run() throws Exception {
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        StringPropertyMap ownership = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ThumbNames.v1.Ownership");
        long[][] ranges = new long[][] { { 0x26L, 0x27L }, { 0x30L, 0x31L } };
        for (long[] range : ranges) {
            Address entry = toAddr(range[0]);
            boolean acceptedOverlap = range[0] == 0x26L;
            if (currentProgram.getFunctionManager().getFunctionAt(entry) != null) {
                throw new AssertionError("a skipped creation left a function at " + entry);
            }
            Function containing =
                    currentProgram.getFunctionManager().getFunctionContaining(entry);
            if (acceptedOverlap
                    ? containing == null || !containing.getEntryPoint().equals(toAddr(0x24))
                    : containing != null) {
                throw new AssertionError("a skipped creation changed containing-function state at "
                        + entry);
            }
            if (ownership != null && ownership.getString(entry) != null) {
                throw new AssertionError("a skipped creation left ownership at " + entry);
            }
            for (long raw = range[0]; raw <= range[1]; raw++) {
                Address address = toAddr(raw);
                boolean hasInstruction =
                        currentProgram.getListing().getInstructionContaining(address) != null;
                if (hasInstruction != acceptedOverlap) {
                    throw new AssertionError("a skipped creation changed instruction state at "
                            + address);
                }
                RegisterValue value = currentProgram.getProgramContext()
                        .getRegisterValue(tMode, address);
                boolean isThumb = value != null && value.hasValue()
                        && BigInteger.ONE.equals(value.getUnsignedValue());
                if (isThumb != acceptedOverlap) {
                    throw new AssertionError("a skipped creation changed TMode state at "
                            + address);
                }
            }
        }
        System.out.println("ProbeThumbCreationSkips: clean");
    }
}
"#;
    std::fs::write(
        out.join("scripts/ProbeThumbCreationSkips.java"),
        probe_skips,
    )
    .unwrap();
    let probed = inspect_saved_project(&home, &out, "00_BOOT", "ProbeThumbCreationSkips.java");
    let probe_diagnostics = process_diagnostics(&probed);
    let probe_stdout = String::from_utf8_lossy(&probed.stdout);
    assert!(
        probed.status.success(),
        "creation-skip probe failed:\n{probe_diagnostics}"
    );
    assert!(
        probe_stdout
            .lines()
            .any(|line| line == "ProbeThumbCreationSkips: clean"),
        "creation-skip probe did not complete cleanly:\n{probe_diagnostics}"
    );
    assert_eq!(
        std::fs::read(exp.join("thumb_functions.json")).unwrap(),
        retained_thumb,
        "pass 2 must preserve the retained tagged Thumb sidecar byte-for-byte"
    );

    // Replay: the identical map re-applies cleanly (property already equal),
    // reporting zero new renames.
    let replay_inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_symbol_map(
                &images_dir,
                "00_BOOT",
                &map_path,
                bundle.map.execution_count,
                bundle.map.creation_requests.clone(),
            )),
            global_map: None,
            global_types_map: None,
            ..Default::default()
        },
    )]);
    let replay = pixel_modem_extractor::decompile::run_two_pass(rep2, &opts, &out, &replay_inputs)
        .unwrap()
        .report;
    let boot = replay.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.pass2_applied, Some(0), "{:?}", boot.pass2_error);
    assert_eq!(
        boot.pass2_thumb_names,
        Some(pixel_modem_extractor::decompile::AppliedThumbNames {
            candidates: 3,
            created: 0,
            reapplied: 1,
            skipped_existing: 1,
            skipped_collision: 1,
        })
    );
    assert!(boot.pass2_error.is_none());
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(c.contains("Reset"));

    // Current program bytes, not map text alone, authenticate a creation.
    let mutate_creation = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;

public class MutateThumbCreation extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getListing().clearCodeUnits(toAddr(0x24), toAddr(0x25), false);
        currentProgram.getMemory().setByte(toAddr(0x24), (byte) 0x81);
        System.out.println("MutateThumbCreation: "
                + Integer.toHexString(currentProgram.getMemory().getByte(toAddr(0x24)) & 0xff));
    }
}
"#;
    std::fs::write(
        out.join("scripts/MutateThumbCreation.java"),
        mutate_creation,
    )
    .unwrap();
    let mutated = inspect_saved_project(&home, &out, "00_BOOT", "MutateThumbCreation.java");
    assert!(
        mutated.status.success(),
        "creation byte mutation failed:\n{}",
        process_diagnostics(&mutated)
    );
    assert!(
        String::from_utf8_lossy(&mutated.stdout).contains("MutateThumbCreation: 81"),
        "creation byte mutation did not persist in-process:\n{}",
        process_diagnostics(&mutated)
    );
    let rejected_bytes = inspect_saved_project_with_args(
        &home,
        &out,
        "00_BOOT",
        "ApplyThumbNames.java",
        &thumb_apply_args,
    );
    let diagnostics = process_diagnostics(&rejected_bytes);
    assert!(
        diagnostics.contains("creation decode range BLAKE3 changed"),
        "mutated creation bytes were not rejected:\n{diagnostics}"
    );
    assert!(
        !diagnostics.contains("ApplyThumbNames: {"),
        "a rejected byte identity emitted a success summary:\n{diagnostics}"
    );

    // Repair the externally-mutated byte, then remove only the ownership
    // record. An exact current name/source without that binding is not replay.
    let remove_ownership = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.StringPropertyMap;

public class RemoveThumbCreationOwnership extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getListing().clearCodeUnits(toAddr(0x24), toAddr(0x25), false);
        currentProgram.getMemory().setByte(toAddr(0x24), (byte) 0x80);
        StringPropertyMap ownership = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ThumbNames.v1.Ownership");
        if (ownership == null || !ownership.remove(toAddr(0x24))) {
            throw new AssertionError("the creation ownership was not present");
        }
    }
}
"#;
    std::fs::write(
        out.join("scripts/RemoveThumbCreationOwnership.java"),
        remove_ownership,
    )
    .unwrap();
    let removed =
        inspect_saved_project(&home, &out, "00_BOOT", "RemoveThumbCreationOwnership.java");
    assert!(
        removed.status.success(),
        "ownership removal failed:\n{}",
        process_diagnostics(&removed)
    );
    let rejected_unowned = inspect_saved_project_with_args(
        &home,
        &out,
        "00_BOOT",
        "ApplyThumbNames.java",
        &thumb_apply_args,
    );
    let diagnostics = process_diagnostics(&rejected_unowned);
    assert!(
        diagnostics.contains("exact Thumb creation replay lacks ownership"),
        "unowned exact replay was not rejected:\n{diagnostics}"
    );
    assert!(
        !diagnostics.contains("ApplyThumbNames: {"),
        "an unowned replay emitted a success summary:\n{diagnostics}"
    );

    // Restoring the old registry bytes cannot bless a replacement function:
    // concrete function and primary-symbol IDs are part of ownership.
    let replace_creation = r#"//@category PixelModemTest
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;

public class ReplaceThumbCreation extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new AssertionError("expected the prior ownership value");
        }
        Address entry = toAddr(0x24);
        StringPropertyMap ownership = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ThumbNames.v1.Ownership");
        ownership.add(entry, args[0]);
        currentProgram.getFunctionManager().removeFunction(entry);
        currentProgram.getListing().clearCodeUnits(entry, toAddr(0x27), false);
        AddressSet authenticated = new AddressSet(entry, toAddr(0x27));
        DisassembleCommand disassemble = new DisassembleCommand(entry, authenticated, true);
        disassemble.enableCodeAnalysis(false);
        if (!disassemble.applyTo(currentProgram, monitor)) {
            throw new AssertionError("replacement disassembly failed");
        }
        CreateFunctionCmd create = new CreateFunctionCmd(null, entry,
                disassemble.getDisassembledAddressSet(), SourceType.ANALYSIS);
        if (!create.applyTo(currentProgram, monitor)) {
            throw new AssertionError("replacement function creation failed");
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        function.setName("guess_boot_reset_handler_d_00000024", SourceType.ANALYSIS);
        System.out.println("ReplaceThumbCreation: replaced");
    }
}
"#;
    std::fs::write(
        out.join("scripts/ReplaceThumbCreation.java"),
        replace_creation,
    )
    .unwrap();
    let replaced = inspect_saved_project_with_args(
        &home,
        &out,
        "00_BOOT",
        "ReplaceThumbCreation.java",
        &[reported_ownership.to_string()],
    );
    assert!(
        String::from_utf8_lossy(&replaced.stdout).contains("ReplaceThumbCreation: replaced"),
        "creation replacement failed:\n{}",
        process_diagnostics(&replaced)
    );
    let rejected_replacement = inspect_saved_project_with_args(
        &home,
        &out,
        "00_BOOT",
        "ApplyThumbNames.java",
        &thumb_apply_args,
    );
    let diagnostics = process_diagnostics(&rejected_replacement);
    assert!(
        diagnostics.contains("owned Thumb creation identity changed"),
        "replacement function inherited ownership:\n{diagnostics}"
    );
    assert!(
        !diagnostics.contains("ApplyThumbNames: {"),
        "a replacement function emitted a replay summary:\n{diagnostics}"
    );

    // --- Second kit: the ApplyGlobals ownership battery without a function
    // map (the SymbolPass2 property of the first kit would reject a
    // map-less export in the same project).
    let dir2 = std::env::temp_dir().join(format!("pme_decompile_p2g_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir2);
    std::fs::create_dir_all(&dir2).unwrap();
    let modem_path2 = dir2.join("modem.bin");
    std::fs::write(&modem_path2, &modem).unwrap();
    let out2 = dir2.join("out");
    let pass1b = pixel_modem_extractor::decompile::run_report(&modem_path2, &opts, &out2).unwrap();
    let global_map_path2 = out2.join("globals.json");

    // First apply: the Recovered global lands as USER_DEFINED.
    let first_globals = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [{
            "address": "0x20",
            "name": "recovered_global_word",
            "tier": "recovered",
        }],
    });
    std::fs::write(
        &global_map_path2,
        serde_json::to_string_pretty(&first_globals).unwrap(),
    )
    .unwrap();
    let globals_only = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: Some(prepared_pass2_map(&global_map_path2, 1)),
            global_types_map: None,
            ..Default::default()
        },
    )]);
    let rep3 = pixel_modem_extractor::decompile::run_two_pass(pass1b, &opts, &out2, &globals_only)
        .unwrap()
        .report;
    let boot = rep3.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.globals_applied, Some(1));
    assert_eq!(boot.globals_apply_skipped, Some(0));
    assert!(boot.globals_apply_error.is_none());

    // Second attempt: the symbol is now USER_DEFINED, so strict ownership
    // preserves it and classifies the candidate as non-default.
    let second_globals = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [{
            "address": "0x20",
            "name": "second_attempt_must_not_replace",
            "tier": "recovered",
        }],
    });
    std::fs::write(
        &global_map_path2,
        serde_json::to_string_pretty(&second_globals).unwrap(),
    )
    .unwrap();
    let rep4 = pixel_modem_extractor::decompile::run_two_pass(rep3, &opts, &out2, &globals_only)
        .unwrap()
        .report;
    let boot = rep4.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.globals_applied, Some(0));
    assert_eq!(boot.globals_apply_skipped, Some(1));
    assert!(boot.globals_apply_error.is_none());
    let c = std::fs::read_to_string(out2.join("export/00_BOOT/decompiled.c")).unwrap();
    assert!(c.contains("recovered_global_word"));
    assert!(!c.contains("second_attempt_must_not_replace"));

    // A fail-whole-map preflight error returns normally, allowing the final
    // export to complete in this same process while applying zero globals.
    let invalid_global_map = serde_json::json!({
        "format": "wrong-format",
        "image": "00_BOOT",
        "globals": [{
            "address": "0x20",
            "name": "invalid_map_must_apply_zero",
            "tier": "recovered",
        }],
    });
    std::fs::write(
        &global_map_path2,
        serde_json::to_string_pretty(&invalid_global_map).unwrap(),
    )
    .unwrap();
    let invalid_run =
        pixel_modem_extractor::decompile::run_two_pass(rep4, &opts, &out2, &globals_only).unwrap();
    assert_eq!(
        invalid_run.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );
    let rep5 = invalid_run.report;
    let boot = rep5.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert!(boot.globals_applied.is_none());
    assert!(boot.globals_apply_skipped.is_none());
    assert!(boot.globals_apply_error.is_some());
    let c = std::fs::read_to_string(out2.join("export/00_BOOT/decompiled.c")).unwrap();
    assert!(c.contains("recovered_global_word"));
    assert!(!c.contains("invalid_map_must_apply_zero"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Build the raw pw_token DB byte stream the token parser accepts for
/// `(token, string)` pairs (the decode_tokens fixture grammar).
fn parse_token_db(entries: &[(u32, &str)]) -> pixel_modem_extractor::tokens::Database {
    pixel_modem_extractor::tokens::Database {
        reserved: 0,
        entries: entries
            .iter()
            .map(|(token, string)| pixel_modem_extractor::tokens::Entry {
                token: *token,
                date_removed: None,
                string: string.to_string(),
            })
            .collect(),
    }
}

/// Pass-2 global-types end-to-end: proves `ApplyGlobalTypes.java` widens
/// undefined bytes into an `undefinedN` type against real Ghidra, and that a
/// span colliding with a defined instruction is skipped rather than applied.
///
/// Reuses the exact crafted blob from
/// `pass2_applies_functions_and_strict_globals_in_one_process` (LDR-from-
/// data-word + six vector-slot self-branches), whose comment establishes that
/// address 0x20 is a genuine data word real Ghidra's auto-analysis leaves
/// undefined — the self-branches keep vector/flow analysis from ever reaching
/// it, and it is exactly the `DAT_00000020` address that test's `ApplyGlobals`
/// case renames. That same address is this test's type-application target.
/// Ghidra additionally recognizes the 8x4-byte lead-in as an ARM exception
/// vector table (`Reset`, `UndefinedInstruction`, `SupervisorCall`, ...),
/// which only sharpens the fixture: `Reset` (0x0..0x4) is a real, disassembled
/// instruction (the LDR) that a second type candidate is aimed at to force a
/// span collision.
///
/// Note on the `decompiled.c` assertion below: Ghidra's decompiler infers
/// `undefined4` for the `DAT_00000020` read from the LDR's own 4-byte access
/// size, independent of whatever the Listing's committed data type is — so
/// `decompiled.c` already reads `undefined4` even in the pass-1-only export,
/// before `ApplyGlobalTypes.java` ever runs (verified while developing this
/// test). The authoritative, discriminating proof that real
/// `DataUtilities.createData` calls actually ran against the Listing is the
/// parsed `global_types_applied`/`global_types_apply_skipped` counts below,
/// which can only be `Some(1)`/`Some(1)` if the captured `analyzeHeadless`
/// stdout contained a conserving `ApplyGlobalTypes: {"image":"00_BOOT",
/// "status":"ok",...}` line (see `parse_apply_global_types_summary`) — i.e.
/// one `DataUtilities.createData` call succeeded (0x20, no conflict) and one
/// threw `CodeUnitInsertionException` (0x0, the live LDR instruction), which
/// is only possible if `Undefined.getUndefinedDataType`, `DataUtilities.
/// createData`, `ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA`, and the
/// `CodeUnitInsertionException` catch all resolved and worked as intended
/// under the installed Ghidra. The `decompiled.c` check is kept as the
/// brief's requested supplementary/visible confirmation that the export
/// reflects the applied type at the right site, not as the primary signal.
#[test]
fn pass2_applies_global_types_and_skips_span_collision() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    // ldr r0, [pc, #0x18]; bx lr; six vector-slot self-branches; one data word
    // at 0x20 — identical to the ApplyGlobals pass-2 test's fixture.
    let mut arm = vec![0x18u8, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1];
    for _ in 0..6 {
        arm.extend([0xfe, 0xff, 0xff, 0xea]); // b .
    }
    arm.extend([0x78, 0x56, 0x34, 0x12]);
    let modem = craft_modem_bin(&arm);

    let dir = std::env::temp_dir().join(format!("pme_decompile_gtypes_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, &modem).unwrap();
    let out = dir.join("out");

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };

    // Pass 1: analyze. Confirm the fixture still produces the genuine 0x20
    // data reference this test's type-application target depends on.
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    let pass1_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("export/00_BOOT/functions.json")).unwrap())
            .unwrap();
    assert!(
        pass1_functions
            .as_array()
            .unwrap()
            .iter()
            .any(|function| function["data_refs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|reference| reference == "0x20")),
        "fixture did not produce a genuine data reference: {pass1_functions}"
    );

    // Two candidates: 0x20 (undefined data word -> applies), 0x0 (the live
    // `Reset` LDR instruction -> its span collides and is skipped).
    let map_path = out.join("global-types-map.json");
    let types_map = serde_json::json!({
        "format": "pixel-modem-extractor-global-types-v1",
        "image": "00_BOOT",
        "types": [
            {"address": "0x20", "width": 4},
            {"address": "0x0", "width": 4},
        ],
    });
    std::fs::write(&map_path, serde_json::to_string_pretty(&types_map).unwrap()).unwrap();

    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: None,
            global_types_map: Some(prepared_pass2_map(&map_path, 2)),
            ..Default::default()
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );
    let boot = pass2
        .report
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .expect("00_BOOT in pass-2 report");
    // Corresponds to a captured analyzeHeadless stdout line
    // `ApplyGlobalTypes: {"image":"00_BOOT","status":"ok","candidates":2,
    // "applied":1,"skipped_outside_memory":0,"skipped_collision":1}` —
    // verified verbatim against real Ghidra while developing this test.
    assert_eq!(
        boot.global_types_applied,
        Some(1),
        "global_types_apply_error: {:?}",
        boot.global_types_apply_error
    );
    assert_eq!(
        boot.global_types_apply_skipped,
        Some(1),
        "expected exactly the 0x0/Reset-instruction span collision to be skipped"
    );
    assert!(
        boot.global_types_apply_error.is_none(),
        "global_types_apply_error: {:?}",
        boot.global_types_apply_error
    );

    // The regenerated export reflects the applied undefined4 at the typed
    // global's reference site (see the doc comment above for why this is
    // supplementary, not the discriminating, proof).
    let c = std::fs::read_to_string(out.join("export/00_BOOT/decompiled.c")).unwrap();
    assert!(
        c.contains("undefined4 Reset(void)") && c.contains("return DAT_00000020;"),
        "decompiled.c missing the undefined4 global at its 0x20 reference site:\n{c}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Uniform pseudo-random blob (xorshift64*, top byte — the same generator as
/// classify.rs's cfg(test) helper, replicated here because integration tests
/// cannot reach pub(crate) cfg(test) items). 256 KiB = 4 full 64-KiB windows,
/// so every battery gate (including the window tests) engages unanimously.
fn uniform_test_blob(len: usize) -> Vec<u8> {
    struct Xorshift64Star(u64);

    impl Xorshift64Star {
        fn byte(&mut self) -> u8 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
        }
    }

    let mut rng = Xorshift64Star(0x9E3779B97F4A7C15);
    (0..len).map(|_| rng.byte()).collect()
}

/// Pins the opaque-skip WIRING at the real seam: `run_report` with `--run`
/// and a located Ghidra install, over a TOC whose only image is unanimously
/// opaque. The skip branch must fire before any Ghidra work, so no
/// `analyzeHeadless` process is ever spawned — observable as no `export/`
/// directory (only ExportDecomp.java creates it) and an empty
/// `ghidra_project/` (a real run writes `pixel-modem.rep` into it). If the
/// skip branch were deleted, Ghidra would import + analyze the blob and every
/// assertion below fails. Reused output must lose only the owned stale export
/// trio and completion marker before the skip is reported. The battery verdict
/// must also label the row "opaque", agreeing with what manifest.json would
/// record for the same bytes.
#[test]
fn run_report_skips_opaque_image_without_spawning_ghidra() {
    let dir = std::env::temp_dir().join(format!("pme_opaque_skip_wiring_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.join("fake-ghidra");
    std::fs::create_dir_all(home.join("support")).unwrap();
    std::fs::write(home.join("support/analyzeHeadless"), b"not launched\n").unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, craft_modem_bin(&uniform_test_blob(256 * 1024))).unwrap();
    let out = dir.join("out");
    let stale_export = out.join("export/00_BOOT");
    std::fs::create_dir_all(&stale_export).unwrap();
    for name in ["functions.json", "disasm.lst", "decompiled.c"] {
        std::fs::write(stale_export.join(name), b"stale\n").unwrap();
    }
    std::fs::write(stale_export.join("unrelated.sidecar"), b"preserve\n").unwrap();
    let completion = out.join("export/00_BOOT.complete");
    std::fs::write(&completion, b"pixel-modem-extractor-ghidra-export-v1\n").unwrap();

    let opts = pixel_modem_extractor::decompile::Opts {
        run: true,
        image: None,
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).expect("run_report");

    assert_eq!(report.images.len(), 1, "the sole image must be selected");
    let image = &report.images[0];
    assert!(
        matches!(
            image.outcome,
            pixel_modem_extractor::decompile::ImageOutcome::SkippedOpaque(_)
        ),
        "uniform-blob image must be SkippedOpaque, got {:?}",
        image.outcome
    );
    assert_eq!(image.classification, Some("opaque"));

    for name in ["functions.json", "disasm.lst", "decompiled.c"] {
        assert!(
            !stale_export.join(name).exists(),
            "opaque skip retained stale owned export {name}"
        );
    }
    assert!(
        !completion.exists(),
        "opaque skip retained stale completion"
    );
    assert_eq!(
        std::fs::read(stale_export.join("unrelated.sidecar")).unwrap(),
        b"preserve\n"
    );
    let project_entries: Vec<_> = std::fs::read_dir(out.join("ghidra_project"))
        .expect("run_report pre-creates ghidra_project")
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        project_entries.is_empty(),
        "no analyzeHeadless run may touch the project dir; found {project_entries:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Shared PAL support (Task 8): non-proprietary fixture + real-Ghidra probe
// ---------------------------------------------------------------------------

/// Drives `PalTasksSupport` inside real Ghidra against the canonical
/// fixture kit and malformed variants: digest vectors, strict parsing,
/// path containment, raw/scatter byte tampering, storage/task/application
/// partition rejections, the v3 symbol-map reader, and the applied-state
/// registry lifecycle (absence, application, identity-only, corruptions).
const PAL_SUPPORT_PROBE_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.StringPropertyMap;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PalSupportProbe extends GhidraScript {
    private interface IoAction {
        void run() throws Exception;
    }

    private int passed = 0;

    private void ok(String what) {
        println("PalSupportProbe ok " + what);
        passed++;
    }

    private void expectFail(String what, String expected, IoAction action) {
        try {
            action.run();
        }
        catch (Exception failure) {
            String message = String.valueOf(failure.getMessage());
            if (!message.contains(expected)) {
                throw new AssertionError(what + ": wrong rejection, expected ["
                        + expected + "] in: " + message);
            }
            ok(what + " [" + expected + "]");
            return;
        }
        throw new AssertionError(what + ": unexpectedly accepted");
    }

    private static String readTrimmed(File file) throws Exception {
        return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8).trim();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new AssertionError("expected exactly four probe arguments");
        }
        File kitRoot = new File(args[0]);
        String label = args[1];
        File caseRoot = new File(args[2]);
        int caseCount = Integer.parseInt(args[3]);

        digestVectors();
        sanitizeVectors();

        File palFile = new File(kitRoot, "pal_tasks/" + label + "/tasks.json");
        File scatterFile = new File(kitRoot, "scatter/" + label + "/load_map.json");
        File rawFile = new File(kitRoot, "images/" + label);

        PalTasksSupport.PalManifest manifest =
                PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile);
        if (manifest.taskRecords != 2 || manifest.distinctEntries != 0
                || manifest.applications.size() != 2) {
            throw new AssertionError("canonical manifest shape is wrong");
        }
        String identity = PalTasksSupport.expectedPalIdentity(manifest);
        if (!identity.startsWith("v1:") || !identity.endsWith(":2:0")) {
            throw new AssertionError("identity grammar is wrong: " + identity);
        }
        ok("readPal canonical");

        for (int index = 0; index < caseCount; index++) {
            File dir = new File(caseRoot, "case" + index);
            final File casePal = new File(readTrimmed(new File(dir, "pal_path.txt")));
            String scatterMode = readTrimmed(new File(dir, "scatter_mode.txt"));
            final File caseScatter = "none".equals(scatterMode) ? null : scatterFile;
            String expected = readTrimmed(new File(dir, "expected.txt"));
            expectFail("case" + index, expected,
                    () -> PalTasksSupport.readPal(kitRoot, label, casePal, caseScatter));
        }

        tamperByte(rawFile, () -> expectFail("changed raw bytes", "image BLAKE3",
                () -> PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile)));
        tamperByte(scatterFile, () -> expectFail("changed scatter bytes", "scatter",
                () -> PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile)));
        PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile);
        ok("restored canonical still reads");

        symbolMapChecks(caseRoot, identity);
        appliedStateChecks(manifest, identity);

        println("PalSupportProbe: all " + passed + " checks passed");
    }

    private void digestVectors() throws Exception {
        byte[] empty = new byte[0];
        // The four Rust golden digest vectors, byte for byte.
        if (!PalTasksSupport.blake3Hex(empty, new byte[] {1, 2, 3, 4})
                .equals("63781d171425a36312fa058d8712d5d05135a991ec20351ce9d65cdb19a05432")) {
            throw new AssertionError("plain BLAKE3 vector mismatch");
        }
        PalTasksSupport.ExecutionRangeWire range = new PalTasksSupport.ExecutionRangeWire(
                "thumb", 0x4001_0400L, 0x4001_0404L,
                "63781d171425a36312fa058d8712d5d05135a991ec20351ce9d65cdb19a05432");
        if (!PalTasksSupport.executionDigestHex(0x4001_0400L, Arrays.asList(range))
                .equals("1383ca88fa4bb8d58aedbac50f7e298be9dd15ad8553eb565ac14848cfd771dd")) {
            throw new AssertionError("execution digest vector mismatch");
        }
        List<PalTasksSupport.LabelEntry> labels = new ArrayList<>();
        labels.add(new PalTasksSupport.LabelEntry(3L, "pal_TaskEntry_beta"));
        labels.add(new PalTasksSupport.LabelEntry(7L, "pal_TaskEntry_alpha"));
        if (!PalTasksSupport.labelsDigestHex(labels)
                .equals("77747c233b288a5f01b755c5307f19f190fc342952891c39f5bd813923a27052")) {
            throw new AssertionError("label-set digest vector mismatch");
        }
        if (!PalTasksSupport.primaryDigestHex("pal_TaskEntry_alpha")
                .equals("8538942936387e769666d449ac837a35a0c7bbeac557c8e2467bc7b75bf0edba")) {
            throw new AssertionError("primary-name digest vector mismatch");
        }
        String manifestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String section = "[[pixel-modem-extractor:pal-tasks:v1]]\nmanifest=" + manifestHex
                + " tasks=1\n"
                + "task index=0 name=\"alpha\" slot=0x40010800 priority=30 stack=4096\n"
                + "[[/pixel-modem-extractor:pal-tasks:v1]]";
        if (!PalTasksSupport.commentDigestHex(section)
                .equals("dcf724f43e1550d495b847e96e2ce17d00eb4674fb988a908f2e956142550c2b")) {
            throw new AssertionError("owned-comment digest vector mismatch");
        }
        String surrounded = "kept user text\n" + section + "\nkept suffix";
        if (!PalTasksSupport.findOwnedSection(surrounded).equals(section)) {
            throw new AssertionError("owned-comment extraction mismatch");
        }
        expectFail("duplicate owned markers", "owned comment",
                () -> PalTasksSupport.findOwnedSection(section + "\n" + section));
        expectFail("unterminated owned marker", "owned comment",
                () -> PalTasksSupport.findOwnedSection("prefix\n" + section.substring(0, 40)));
        ok("four golden digest vectors");
    }

    private void sanitizeVectors() throws Exception {
        String[][] vectors = {
            {"alpha_9", "alpha_9"},
            {"a--b", "a_b"},
            {"a.b c", "a_b_c"},
            {"!lead", "_lead"},
            {"9lives", "_9lives"},
            {"!!", "_"},
            {"\u00e9x", "_x"},
        };
        for (String[] vector : vectors) {
            if (!vector[1].equals(PalTasksSupport.sanitizeTaskName(vector[0]))) {
                throw new AssertionError("sanitize mismatch for " + vector[0]);
            }
        }
        if (PalTasksSupport.sanitizeTaskName("") != null) {
            throw new AssertionError("empty name must sanitize to null");
        }
        ok("sanitization rule matches Rust");
    }

    private void symbolMapChecks(File caseRoot, String palIdentity) throws Exception {
        File functionsFile = new File(caseRoot, "functions.json");
        File mapFile = new File(caseRoot, "symbol_map.json");
        File badMapFile = new File(caseRoot, "symbol_map_bad.json");
        byte[] empty = new byte[0];
        String functionsHash = PalTasksSupport.blake3Hex(empty,
                Files.readAllBytes(functionsFile.toPath()));
        String mapHash = PalTasksSupport.blake3Hex(empty, Files.readAllBytes(mapFile.toPath()));
        String badMapHash = PalTasksSupport.blake3Hex(empty,
                Files.readAllBytes(badMapFile.toPath()));

        PalTasksSupport.SymbolMap map =
                PalTasksSupport.readSymbolMap(functionsFile, functionsHash, mapFile, mapHash);
        if (!palIdentity.equals(map.palIdentity) || map.executions.size() != 2
                || map.decisions.size() != 2 || !map.functionsBlake3.equals(functionsHash)) {
            throw new AssertionError("symbol map shape is wrong");
        }
        // Cross-language vector: the parsed execution digest must equal the
        // digest recomputed through the Java framing.
        PalTasksSupport.MapExecution execution = map.executions.get(0);
        if (!execution.executionBlake3.equals(
                PalTasksSupport.executionDigestHex(execution.entry, execution.decodeRanges))) {
            throw new AssertionError("execution digest cross-check failed");
        }
        ok("readSymbolMap canonical");

        expectFail("wrong functions hash", "functions.json BLAKE3",
                () -> PalTasksSupport.readSymbolMap(functionsFile,
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        mapFile, mapHash));
        expectFail("wrong map hash", "symbol map BLAKE3",
                () -> PalTasksSupport.readSymbolMap(functionsFile, functionsHash, mapFile,
                        "0000000000000000000000000000000000000000000000000000000000000000"));
        expectFail("unknown map key", "expected key",
                () -> PalTasksSupport.readSymbolMap(functionsFile, functionsHash, badMapFile,
                        badMapHash));
    }

    private void appliedStateChecks(PalTasksSupport.PalManifest manifest, String identity)
            throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        FunctionManager functions = currentProgram.getFunctionManager();

        PalTasksSupport.validateAbsent(currentProgram);
        ok("validateAbsent pristine program");

        StringPropertyMap registry = buildAppliedState(manifest, identity);

        PalTasksSupport.AppliedState state =
                PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        if (state.applications != 2 || state.createdFunctions != 2
                || state.preexistingFunctions != 0 || state.palOwnedPrimaries != 2
                || state.preservedPrimaries != 0 || state.pass2OwnedPrimaries != 0
                || state.reservedLabels != 2) {
            throw new AssertionError("applied state counts are wrong: " + state.applications
                    + " applications, " + state.createdFunctions + " created");
        }
        ok("validateApplied canonical");

        PalTasksSupport.validateAppliedIdentity(currentProgram, identity);
        ok("validateAppliedIdentity canonical");

        expectFail("validateAbsent with applied state", "PAL property",
                () -> PalTasksSupport.validateAbsent(currentProgram));

        // (a) A registered reserved label is deleted: digest and enumeration fail.
        Address entryA = toAddr(manifest.applications.get(0).entry);
        Symbol labelA = symbols.getSymbol(
                manifest.applications.get(0).labels.get(0).label, entryA,
                reservedNamespace());
        if (labelA == null) {
            throw new AssertionError("probe lost the reserved label");
        }
        int tx = currentProgram.startTransaction("probe-corrupt-a");
        try {
            labelA.delete();
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        expectFail("deleted reserved label", "label",
                () -> PalTasksSupport.validateAppliedIdentity(currentProgram, identity));
        tx = currentProgram.startTransaction("probe-restore-a");
        try {
            symbols.createLabel(entryA, manifest.applications.get(0).labels.get(0).label,
                    reservedNamespace(), SourceType.ANALYSIS);
            refreshRegistryLabels(entryA);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        ok("label corruption restored");

        // (b) The primary name drifts without a registry update.
        Function functionA = functions.getFunctionAt(entryA);
        tx = currentProgram.startTransaction("probe-corrupt-b");
        try {
            functionA.setName("probe_drifted_name", SourceType.USER_DEFINED);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        expectFail("renamed primary without registry update", "primary",
                () -> PalTasksSupport.validateAppliedIdentity(currentProgram, identity));
        tx = currentProgram.startTransaction("probe-restore-b");
        try {
            functionA.setName(manifest.applications.get(0).desiredPrimary, SourceType.ANALYSIS);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        ok("primary corruption restored");

        // (c) An unregistered reserved label appears at another address.
        Address stranger = toAddr(0x4001_0480L);
        tx = currentProgram.startTransaction("probe-corrupt-c");
        try {
            symbols.createLabel(stranger, "pal_TaskEntry_stranger", reservedNamespace(),
                    SourceType.ANALYSIS);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        expectFail("unregistered reserved label", "unregistered",
                () -> PalTasksSupport.validateAppliedIdentity(currentProgram, identity));
        for (Symbol strangerSymbol : symbols.getSymbols(stranger)) {
            strangerSymbol.delete();
        }
        PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        ok("orphan label corruption restored");

        // (d) The owned comment section is edited in place.
        String original = functionA.getRepeatableComment();
        tx = currentProgram.startTransaction("probe-corrupt-d");
        try {
            functionA.setRepeatableComment(original.replace("priority=100", "priority=101"));
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        expectFail("tampered owned comment", "owned comment",
                () -> PalTasksSupport.validateAppliedIdentity(currentProgram, identity));
        tx = currentProgram.startTransaction("probe-restore-d");
        try {
            functionA.setRepeatableComment(original);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        ok("comment corruption restored");

        // (e) A stale foreign program property is rejected, not overwritten.
        tx = currentProgram.startTransaction("probe-corrupt-e");
        try {
            currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO).setString(PalTasksSupport.PAL_PROPERTY,
                    "v1:0000000000000000000000000000000000000000000000000000000000000000:9:9");
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        expectFail("stale program property", "stale PAL property",
                () -> PalTasksSupport.validateApplied(currentProgram, manifest, identity));
        tx = currentProgram.startTransaction("probe-restore-e");
        try {
            currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO).setString(PalTasksSupport.PAL_PROPERTY, identity);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        PalTasksSupport.validateAppliedIdentity(currentProgram, identity);
        ok("stale property corruption restored");

        // (f) An orphan registry entry names an address without a function.
        tx = currentProgram.startTransaction("probe-corrupt-f");
        try {
            registry.add(stranger, registry.get(entryA));
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        expectFail("orphan registry entry", "registry",
                () -> PalTasksSupport.validateAppliedIdentity(currentProgram, identity));
        tx = currentProgram.startTransaction("probe-restore-f");
        try {
            registry.remove(stranger);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        ok("registry corruption restored");
    }

    // Re-binds the registry's label digest to the current namespace symbols:
    // a deleted-and-recreated label carries a new symbol ID, and a legitimate
    // restoration must re-publish the registry exactly like a reapplication.
    private void refreshRegistryLabels(Address entry) throws Exception {
        ghidra.program.model.util.PropertyMapManager manager =
                currentProgram.getUsrPropertyManager();
        StringPropertyMap registry = manager.getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        PalTasksSupport.RegistryEntry previous =
                PalTasksSupport.parseRegistry(registry.getString(entry));
        List<PalTasksSupport.LabelEntry> current = new ArrayList<>();
        ghidra.program.model.symbol.SymbolIterator iterator =
                currentProgram.getSymbolTable().getSymbols(reservedNamespace());
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol.getAddress().equals(entry)) {
                current.add(new PalTasksSupport.LabelEntry(symbol.getID(), symbol.getName()));
            }
        }
        registry.add(entry, PalTasksSupport.registryValue(new PalTasksSupport.RegistryEntry(
                previous.manifestBlake3, previous.isa, previous.functionId,
                previous.functionDisposition, previous.commentBlake3,
                previous.primaryDisposition, previous.primarySymbolId, previous.primarySource,
                previous.primaryNameBlake3, current.size(),
                PalTasksSupport.labelsDigestHex(current))));
    }

    private Namespace reservedNamespace() throws Exception {
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
        if (namespace == null) {
            throw new AssertionError("reserved namespace is missing");
        }
        return namespace;
    }

    private StringPropertyMap buildAppliedState(PalTasksSupport.PalManifest manifest,
            String identity) throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        StringPropertyMap registry;
        try {
            registry = currentProgram.getUsrPropertyManager()
                    .createStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        }
        catch (Exception duplicate) {
            throw new AssertionError("probe expected a fresh ownership map", duplicate);
        }
        int tx = currentProgram.startTransaction("probe-apply");
        try {
            Namespace namespace = symbols.createNameSpace(currentProgram.getGlobalNamespace(),
                    PalTasksSupport.RESERVED_NAMESPACE, SourceType.ANALYSIS);
            for (PalTasksSupport.PalApplication application : manifest.applications) {
                Address entry = toAddr(application.entry);
                disassemble(entry);
                Function function = createFunction(entry, null);
                if (function == null) {
                    throw new AssertionError("probe could not create the function at " + entry);
                }
                function.setName(application.desiredPrimary, SourceType.ANALYSIS);
                List<PalTasksSupport.PalTask> attached = new ArrayList<>();
                for (long index : application.taskIndices) {
                    attached.add(manifest.tasks.get((int) index));
                }
                List<PalTasksSupport.LabelEntry> created = new ArrayList<>();
                for (PalTasksSupport.PalLabel label : application.labels) {
                    Symbol symbol = symbols.createLabel(entry, label.label, namespace,
                            SourceType.ANALYSIS);
                    created.add(new PalTasksSupport.LabelEntry(symbol.getID(), label.label));
                }
                String comment = PalTasksSupport.ownedCommentSection(manifest.manifestBlake3,
                        attached);
                function.setRepeatableComment(comment);
                Symbol primary = function.getSymbol();
                registry.add(entry, PalTasksSupport.registryValue(new PalTasksSupport.RegistryEntry(
                        manifest.manifestBlake3, application.isa, primary.getID(), "created",
                        PalTasksSupport.commentDigestHex(comment), "pal_owned", primary.getID(),
                        PalTasksSupport.primarySource(primary.getSource()),
                        PalTasksSupport.primaryDigestHex(primary.getName()), created.size(),
                        PalTasksSupport.labelsDigestHex(created))));
            }
            currentProgram.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO).setString(PalTasksSupport.PAL_PROPERTY, identity);
        }
        finally {
            currentProgram.endTransaction(tx, true);
        }
        return registry;
    }

    private void tamperByte(File file, IoAction action) throws Exception {
        byte[] original = Files.readAllBytes(file.toPath());
        byte[] mutated = original.clone();
        mutated[mutated.length - 1] ^= 0x5a;
        Files.write(file.toPath(), mutated);
        try {
            action.run();
        }
        finally {
            Files.write(file.toPath(), original);
        }
    }
}
"#;

fn replace_once(text: &str, from: &str, to: &str) -> String {
    let count = text.matches(from).count();
    assert_eq!(count, 1, "mutation source {from:?} matched {count} times");
    text.replacen(from, to, 1)
}

fn inject_before_final_export_postflight(out: &std::path::Path, injection: &str) {
    let path = out.join("scripts/ExportDecomp.java");
    let source = std::fs::read_to_string(&path).unwrap();
    let anchors = [
        "                validateExceptionState(roots);\n",
        "            validateExceptionState(roots);\n",
        "            if (roots == null) {\n",
    ];
    let (offset, anchor) = anchors
        .iter()
        .find_map(|anchor| source.rfind(anchor).map(|offset| (offset, *anchor)))
        .expect("ExportDecomp final postflight anchor");
    let mut patched = String::with_capacity(source.len() + injection.len());
    patched.push_str(&source[..offset]);
    patched.push_str(injection);
    patched.push_str(&source[offset..]);
    assert!(
        patched[offset + injection.len()..].starts_with(anchor),
        "injection did not preserve the final postflight anchor"
    );
    std::fs::write(path, patched).unwrap();
}

fn clear_owned_export(out: &std::path::Path, label: &str) {
    let export = out.join("export").join(label);
    let _ = std::fs::remove_file(out.join("export").join(format!("{label}.complete")));
    for name in ["functions.json", "disasm.lst", "decompiled.c"] {
        let _ = std::fs::remove_file(export.join(name));
    }
}

fn minify_json_whitespace(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for character in text.chars() {
        if in_string {
            output.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
            output.push(character);
        } else if !character.is_ascii_whitespace() {
            output.push(character);
        }
    }
    assert!(
        !in_string && !escaped,
        "canonical JSON ended inside a string"
    );
    output
}

#[test]
fn pal_support_strict_parsers_registry_and_digests() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    let dir = std::env::temp_dir().join(format!("pme_pal_support_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(&modem_path, pal_fixture::craft_pal_main_modem_bin()).unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.clone()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        },
        &out,
    )
    .unwrap();
    assert!(
        out.join("scripts/PmeScriptSupport.java").is_file(),
        "generated PAL kit is missing its shared script support"
    );

    let scatter_path = out.join("scatter/02_MAIN/load_map.json");
    assert!(
        scatter_path.exists(),
        "kit must materialize the scatter load map"
    );
    let scatter_hash = pal_fixture::blake3_hex(&std::fs::read(&scatter_path).unwrap());

    let image = pal_fixture::craft_main_image();
    let manifest = pal_fixture::canonical_manifest(&image, &scatter_hash);
    let manifest_dir = out.join("pal_tasks/02_MAIN");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    std::fs::write(manifest_dir.join("tasks.json"), &manifest).unwrap();
    let identity = pal_fixture::identity(&manifest);
    let manifest_blake3 = &identity[3..67];

    // Malformed variants: each case directory carries the manifest path to
    // parse, the scatter mode, and the required failure substring.
    let overlap_slot_storage = replace_once(
        &manifest,
        "\"slot_storage\": [\n        {\n          \"kind\": \"raw\",\n          \"address\": \"0x40010100\",\n          \"size\": 64\n        }\n      ]",
        "\"slot_storage\": [\n        {\n          \"kind\": \"raw\",\n          \"address\": \"0x40010100\",\n          \"size\": 64\n        },\n        {\n          \"kind\": \"raw\",\n          \"address\": \"0x40010120\",\n          \"size\": 64\n        }\n      ]",
    );
    let cases: Vec<(String, &str)> = vec![
        (
            replace_once(
                &manifest,
                "\"schema_version\": 1,",
                "\"schema_version\": 1,\n  \"unexpected\": true,",
            ),
            "expected key",
        ),
        (
            replace_once(&manifest, "\"capacity\": 8", "\"capacity\": 8.0"),
            "canonical unsigned decimal",
        ),
        (
            replace_once(
                &manifest,
                "\"kind\": \"raw\",\n          \"address\": \"0x40010500\",",
                "\"kind\": \"scatter_bytes\",\n          \"address\": \"0x40010500\",",
            ),
            "scatter_entry",
        ),
        (
            replace_once(
                &manifest,
                "\"scatter_entries_used\": []",
                "\"scatter_entries_used\": [0]",
            ),
            "scatter_entries_used",
        ),
        (overlap_slot_storage, "sorted or overlap"),
        (
            replace_once(
                &manifest,
                "\"labels\": [\n        {\n          \"label\": \"pal_TaskEntry_beta\",\n          \"task_indices\": [\n            1\n          ]\n        }\n      ]",
                "\"labels\": []",
            ),
            "partition",
        ),
        (
            replace_once(&manifest, "\"count\": 2", "\"count\": 3"),
            "task count",
        ),
    ];
    let case_root = out.join("pal_malformed");
    let outside_root = dir.join("pal_outside");
    let probe_case_count = cases.len() + 1;
    for (index, (bytes, expected)) in cases.iter().enumerate() {
        let case_dir = case_root.join(format!("case{index}"));
        std::fs::create_dir_all(&case_dir).unwrap();
        let path = case_dir.join("tasks.json");
        std::fs::write(&path, bytes).unwrap();
        std::fs::write(
            case_dir.join("pal_path.txt"),
            std::fs::canonicalize(&path).unwrap().to_str().unwrap(),
        )
        .unwrap();
        std::fs::write(case_dir.join("scatter_mode.txt"), "canonical").unwrap();
        std::fs::write(case_dir.join("expected.txt"), expected).unwrap();
    }
    {
        let index = cases.len();
        let case_dir = case_root.join(format!("case{index}"));
        std::fs::create_dir_all(&case_dir).unwrap();
        let outside_dir = outside_root.join("tasks");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let path = outside_dir.join("tasks.json");
        std::fs::write(&path, &manifest).unwrap();
        std::fs::write(
            case_dir.join("pal_path.txt"),
            std::fs::canonicalize(&path).unwrap().to_str().unwrap(),
        )
        .unwrap();
        std::fs::write(case_dir.join("scatter_mode.txt"), "canonical").unwrap();
        std::fs::write(case_dir.join("expected.txt"), "escapes the import-kit root").unwrap();
    }

    // The strict v3 symbol-map fixtures.
    let functions_bytes = b"[{\"name\": \"FUN_40010400\"}]\n".as_slice();
    let functions_hash = pal_fixture::blake3_hex(functions_bytes);
    std::fs::write(case_root.join("functions.json"), functions_bytes).unwrap();
    let symbol_map = pal_fixture::canonical_symbol_map(
        &image,
        &identity,
        manifest_blake3,
        &scatter_hash,
        &functions_hash,
    );
    std::fs::write(case_root.join("symbol_map.json"), &symbol_map).unwrap();
    let bad_symbol_map = replace_once(
        &symbol_map,
        "\"format\": \"pixel-modem-extractor-symbol-map-v3\",",
        "\"format\": \"pixel-modem-extractor-symbol-map-v3\",\n  \"unexpected\": true,",
    );
    std::fs::write(case_root.join("symbol_map_bad.json"), &bad_symbol_map).unwrap();

    std::fs::write(
        out.join("scripts/PalSupportProbe.java"),
        PAL_SUPPORT_PROBE_JAVA,
    )
    .unwrap();

    let config = out.join("ghidra_config");
    let cache = out.join("ghidra_cache");
    let temp = out.join("ghidra_tmp");
    std::fs::create_dir_all(out.join("ghidra_project")).unwrap();
    for directory in [&config, &cache, &temp] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let kit_root = std::fs::canonicalize(&out).unwrap();
    let case_root_canonical = std::fs::canonicalize(&case_root).unwrap();
    let java_options = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        config.display(),
        cache.display(),
        temp.display(),
        temp.display()
    );
    let output = std::process::Command::new(
        analyze_headless_in_home(&home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(out.join("ghidra_project"))
    .arg("pixel-modem")
    .arg("-import")
    .arg(out.join("images/02_MAIN"))
    .arg("-processor")
    .arg("ARM:LE:32:v7")
    .arg("-loader")
    .arg("BinaryLoader")
    .arg("-loader-baseAddr")
    .arg("40010000")
    .arg("-noanalysis")
    .arg("-scriptPath")
    .arg(out.join("scripts"))
    .arg("-postScript")
    .arg("PalSupportProbe.java")
    .arg(&kit_root)
    .arg("02_MAIN")
    .arg(&case_root_canonical)
    .arg(probe_case_count.to_string())
    .arg("-overwrite")
    .env("XDG_CONFIG_HOME", &config)
    .env("XDG_CACHE_HOME", &cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
    .output()
    .unwrap();
    let diagnostics = process_diagnostics(&output);
    assert!(
        output.status.success(),
        "PalSupportProbe run failed:\n{diagnostics}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PalSupportProbe: all "),
        "probe did not summarize:\n{diagnostics}"
    );
    let passed: usize = stdout
        .lines()
        .filter(|line| line.contains("PalSupportProbe ok "))
        .count();
    assert_eq!(
        passed, 36,
        "expected the full probe battery, got {passed}:\n{diagnostics}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// -------------------------------------------------------------------------
// Task 9: transactional ApplyPalTasks
// -------------------------------------------------------------------------

/// Seeds the meaningful-name targets: a pre-existing function at the zeta
/// entry with a USER_DEFINED name and a user repeatable comment that the
/// owned section must not disturb, plus a pre-existing function at the
/// beta entry whose ANALYSIS primary coincidentally carries the desired
/// PAL text - both must remain `preserved`, never `pal_owned`.
const PAL_SEED_MEANINGFUL_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class PalSeedMeaningful extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address zetaEntry = toAddr(0x4001_0438L);
        disassemble(zetaEntry);
        Function zeta = createFunction(zetaEntry, null);
        if (zeta == null) {
            throw new AssertionError("meaningful-name seed could not create the zeta function");
        }
        zeta.setName("zetaKeptName", SourceType.USER_DEFINED);
        zeta.setRepeatableComment("user zeta note");

        Address betaEntry = toAddr(0x4001_0410L);
        disassemble(betaEntry);
        Function beta = createFunction(betaEntry, null);
        if (beta == null) {
            throw new AssertionError("meaningful-name seed could not create the beta function");
        }
        beta.setName("pal_TaskEntry_beta", SourceType.ANALYSIS);

        println("PalSeedMeaningful: seeded zetaKeptName and coincident ANALYSIS pal_TaskEntry_beta");
    }
}
"#;

/// Seeds a stray owned-comment closing marker: a pre-existing function at
/// the alpha entry carries a repeatable comment with the close marker but
/// no open marker, which preflight must reject before any mutation.
const PAL_SEED_STRAY_CLOSE_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class PalSeedStrayClose extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x4001_0400L);
        disassemble(entry);
        Function function = createFunction(entry, null);
        if (function == null) {
            throw new AssertionError("stray-close seed could not create the function");
        }
        function.setRepeatableComment("user note\n"
                + PalTasksSupport.COMMENT_CLOSE_MARKER);
        println("PalSeedStrayClose: seeded stray closing marker at " + entry);
    }
}
"#;

/// Seeds a wrong-ISA entry: the alpha entry instruction is disassembled
/// in Thumb context although the manifest declares ARM.
const PAL_SEED_WRONG_ISA_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;

public class PalSeedWrongIsa extends GhidraScript {
    @Override
    public void run() throws Exception {
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        if (tMode == null) {
            throw new AssertionError("language lacks the TMode context register");
        }
        Address entry = toAddr(0x4001_0400L);
        currentProgram.getProgramContext()
                .setValue(tMode, entry, entry.add(3), BigInteger.ONE);
        disassemble(entry);
        if (currentProgram.getListing().getInstructionAt(entry) == null) {
            throw new AssertionError("wrong-ISA seed disassembled nothing");
        }
        println("PalSeedWrongIsa: seeded Thumb context at the ARM entry " + entry);
    }
}
"#;

/// Seeds a containing function: a function beginning at 0x40010428 flows
/// into the shared entry 0x40010430 without beginning there.
const PAL_SEED_CONTAINING_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class PalSeedContaining extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x4001_0428L);
        disassemble(start);
        Function function = createFunction(start, null);
        if (function == null) {
            throw new AssertionError("containing-function seed could not create the function");
        }
        if (!function.getBody().contains(toAddr(0x4001_0430L))) {
            throw new AssertionError("containing-function seed does not cover the shared entry");
        }
        println("PalSeedContaining: seeded function at " + start);
    }
}
"#;

/// Seeds an unrelated reserved-namespace label so the canonical labels
/// collide with pre-existing state.
const PAL_SEED_LABEL_COLLISION_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

public class PalSeedLabelCollision extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        Namespace namespace = symbols.createNameSpace(currentProgram.getGlobalNamespace(),
                PalTasksSupport.RESERVED_NAMESPACE, SourceType.ANALYSIS);
        symbols.createLabel(toAddr(0x4001_0460L), "pal_TaskEntry_alpha", namespace,
                SourceType.ANALYSIS);
        println("PalSeedLabelCollision: seeded reserved-namespace collision label");
    }
}
"#;

/// Corrupts one registry entry's manifest binding so a reapplication of
/// the same manifest must fail as stale.
const PAL_SEED_STALE_REGISTRY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.util.StringPropertyMap;

public class PalSeedStaleRegistry extends GhidraScript {
    @Override
    public void run() throws Exception {
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        if (registry == null) {
            throw new AssertionError("stale-registry seed requires an applied registry");
        }
        Address entry = toAddr(0x4001_0400L);
        String value = registry.getString(entry);
        if (value == null) {
            throw new AssertionError("stale-registry seed lost the alpha entry");
        }
        char digit = value.charAt(3);
        char flipped = digit == '0' ? '1' : '0';
        registry.add(entry, value.substring(0, 3) + flipped + value.substring(4));
        println("PalSeedStaleRegistry: tampered the alpha manifest binding");
    }
}
"#;

/// Postflight inspector for a successful application (and reapplication):
/// validates the complete applied state, pins the disposition counts, and
/// prints registry/label fingerprints that must be identical across runs.
const PAL_INSPECT_APPLIED_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class InspectApplied extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) {
            throw new AssertionError("expected four InspectApplied arguments");
        }
        File kitRoot = new File(args[0]);
        String label = args[1];
        File palFile = new File(args[2]);
        File scatterFile = new File(args[3]);
        PalTasksSupport.PalManifest manifest =
                PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile);
        String identity = PalTasksSupport.expectedPalIdentity(manifest);
        PalTasksSupport.AppliedState state =
                PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        if (state.applications != 6 || state.createdFunctions != 4
                || state.preexistingFunctions != 2 || state.palOwnedPrimaries != 4
                || state.preservedPrimaries != 2 || state.pass2OwnedPrimaries != 0
                || state.reservedLabels != 7) {
            throw new AssertionError("applied-state counts are wrong: " + state.applications
                    + " applications, " + state.createdFunctions + " created, "
                    + state.preexistingFunctions + " preexisting, " + state.palOwnedPrimaries
                    + " pal_owned, " + state.preservedPrimaries + " preserved, "
                    + state.reservedLabels + " labels");
        }
        FunctionManager functions = currentProgram.getFunctionManager();
        Function zeta = functions.getFunctionAt(toAddr(0x4001_0438L));
        if (zeta == null || !"zetaKeptName".equals(zeta.getName())
                || zeta.getSymbol().getSource() != SourceType.USER_DEFINED) {
            throw new AssertionError("the meaningful primary was not preserved");
        }
        List<PalTasksSupport.PalTask> zetaTasks = new ArrayList<>();
        zetaTasks.add(manifest.tasks.get(6));
        String zetaSection =
                PalTasksSupport.ownedCommentSection(manifest.manifestBlake3, zetaTasks);
        if (!("user zeta note\n" + zetaSection).equals(zeta.getRepeatableComment())) {
            throw new AssertionError("the owned comment disturbed the user text");
        }
        Function beta = functions.getFunctionAt(toAddr(0x4001_0410L));
        if (beta == null || !"pal_TaskEntry_beta".equals(beta.getName())
                || beta.getSymbol().getSource() != SourceType.ANALYSIS) {
            throw new AssertionError(
                    "the coincident ANALYSIS primary was not preserved verbatim");
        }
        Function shared = functions.getFunctionAt(toAddr(0x4001_0430L));
        if (shared == null || !"pal_TaskEntry_shared_40010430".equals(shared.getName())) {
            throw new AssertionError("the shared-entry primary is wrong");
        }
        Function scatter = functions.getFunctionAt(toAddr(0x4001_1000L));
        if (scatter == null) {
            throw new AssertionError("the scatter-backed task function is missing");
        }
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        if (tMode == null || currentProgram.getProgramContext()
                .getRegisterValue(tMode, scatter.getEntryPoint())
                .getUnsignedValue().intValue() != 1) {
            throw new AssertionError("the scatter-backed task function is not in Thumb context");
        }
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        if (registry == null) {
            throw new AssertionError("the ownership registry is missing");
        }
        List<String> values = new ArrayList<>();
        AddressIterator entries = registry.getPropertyIterator();
        while (entries.hasNext()) {
            Address address = entries.next();
            values.add(registry.getString(address));
        }
        Collections.sort(values);
        println("InspectApplied: registry " + String.join("|", values));
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
        List<Long> labelIds = new ArrayList<>();
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(namespace);
        while (symbols.hasNext()) {
            labelIds.add(symbols.next().getID());
        }
        Collections.sort(labelIds);
        StringBuilder ids = new StringBuilder();
        for (Long id : labelIds) {
            if (ids.length() > 0) {
                ids.append(',');
            }
            ids.append(id);
        }
        println("InspectApplied: labels " + ids);
        println("InspectApplied: ok");
    }
}
"#;

/// Saved-project inspector after an expected ApplyPalTasks failure. All
/// modes assert no task function exists at any application entry.
/// `pristine` additionally requires no surviving instructions at the
/// entries; `seeded` allows pre-seeded code; `collision` allows the
/// seeded collision label but no other PAL surface; `stale` requires the
/// previously applied state to be completely undisturbed.
const PAL_INSPECT_ABSENT_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;

public class InspectAbsent extends GhidraScript {
    private static final long[] ENTRIES = {0x4001_0400L, 0x4001_0410L, 0x4001_0420L,
        0x4001_0430L, 0x4001_0438L, 0x4001_1000L};

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new AssertionError("expected one or two InspectAbsent arguments");
        }
        String mode = args[0];
        if (!"stale".equals(mode) && !"seeded_fn".equals(mode)) {
            // The stale mode certifies an intact applied state; every other
            // mode must show no task function at any application entry. The
            // seeded_fn mode allows a pre-existing function at an entry
            // (the stray-close-marker probe seeds one) but still requires
            // the complete PAL absence.
            for (long entry : ENTRIES) {
                if (currentProgram.getFunctionManager().getFunctionAt(toAddr(entry)) != null) {
                    throw new AssertionError("a task function survived at 0x"
                            + Long.toHexString(entry));
                }
            }
        }
        if ("pristine".equals(mode)) {
            // Probe: an empty-but-present ownership registry and reserved
            // namespace are equivalent to absent for the expected `none`
            // identity.
            int probeTx = currentProgram.startTransaction("probe-empty-present");
            try {
                currentProgram.getUsrPropertyManager()
                        .createStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
            }
            catch (Exception duplicate) {
                // An already-present map is the empty-but-present probe.
            }
            try {
                currentProgram.getSymbolTable().createNameSpace(
                        currentProgram.getGlobalNamespace(),
                        PalTasksSupport.RESERVED_NAMESPACE,
                        ghidra.program.model.symbol.SourceType.ANALYSIS);
            }
            catch (Exception duplicate) {
                // An already-present namespace is the probe.
            }
            currentProgram.endTransaction(probeTx, true);
            PalTasksSupport.validateAbsent(currentProgram);
            for (long entry : ENTRIES) {
                if (currentProgram.getListing().getInstructionAt(toAddr(entry)) != null) {
                    throw new AssertionError("a task instruction survived at 0x"
                            + Long.toHexString(entry));
                }
            }
        }
        else if ("seeded".equals(mode)) {
            PalTasksSupport.validateAbsent(currentProgram);
        }
        else if ("seeded_fn".equals(mode)) {
            PalTasksSupport.validateAbsent(currentProgram);
        }
        else if ("collision".equals(mode)) {
            StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                    .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
            if (registry != null && registry.getSize() > 0) {
                throw new AssertionError("a registry entry survived the failed application");
            }
            if (currentProgram.getOptions(Program.PROGRAM_INFO)
                    .getString(PalTasksSupport.PAL_PROPERTY, null) != null) {
                throw new AssertionError("the PAL property survived the failed application");
            }
            if (ownedCommentCount() != 0) {
                throw new AssertionError("an owned comment survived the failed application");
            }
            Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                    PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
            int labels = 0;
            if (namespace != null) {
                SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(namespace);
                while (symbols.hasNext()) {
                    symbols.next();
                    labels++;
                }
            }
            if (labels != 1) {
                throw new AssertionError("expected only the seeded collision label, found "
                        + labels);
            }
        }
        else if ("stale".equals(mode)) {
            if (args.length != 2) {
                throw new AssertionError("stale inspection requires the identity argument");
            }
            StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                    .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
            if (registry == null || registry.getSize() != 6) {
                throw new AssertionError("the applied registry was disturbed");
            }
            if (!args[1].equals(currentProgram.getOptions(Program.PROGRAM_INFO)
                    .getString(PalTasksSupport.PAL_PROPERTY, null))) {
                throw new AssertionError("the applied PAL property was disturbed");
            }
            if (ownedCommentCount() != 6) {
                throw new AssertionError("the applied owned comments were disturbed");
            }
            Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                    PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
            int labels = 0;
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(namespace);
            while (symbols.hasNext()) {
                symbols.next();
                labels++;
            }
            if (labels != 7) {
                throw new AssertionError("the applied labels were disturbed");
            }
        }
        else {
            throw new AssertionError("unknown inspection mode " + mode);
        }
        println("InspectAbsent: " + mode + " ok");
    }

    private int ownedCommentCount() {
        Listing listing = currentProgram.getListing();
        AddressIterator iterator = listing.getCommentAddressIterator(CommentType.REPEATABLE,
                currentProgram.getMemory(), true);
        int count = 0;
        while (iterator.hasNext()) {
            Address address = iterator.next();
            String comment = listing.getCodeUnitContaining(address)
                    .getComment(CommentType.REPEATABLE);
            if (comment != null
                    && comment.contains(PalTasksSupport.COMMENT_OPEN_MARKER)) {
                count++;
            }
        }
        return count;
    }
}
"#;

/// Saved-project inspector for the controlled-gap battery: validates the
/// complete applied PAL state, then proves no mode turns the gap into a
/// fabricated instruction while datamark partitions exactly it as data.
const PAL_INSPECT_GAP_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import java.io.File;

public class PalInspectGap extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new AssertionError("expected kit root, gap address, and expect-data flag");
        }
        File kitRoot = new File(args[0]);
        long gap = Long.parseLong(args[1].replaceFirst("^0x", ""), 16);
        boolean expectData = Boolean.parseBoolean(args[2]);

        PalTasksSupport.PalManifest manifest = PalTasksSupport.readPal(
                kitRoot, "02_MAIN", new File(kitRoot, "pal_tasks/02_MAIN/tasks.json"), null);
        PalTasksSupport.validateApplied(currentProgram, manifest,
                PalTasksSupport.expectedPalIdentity(manifest));

        Listing listing = currentProgram.getListing();
        for (long offset = 0; offset < 0x80; offset += 0x20) {
            Address address = toAddr(gap + offset);
            if (listing.getInstructionAt(address) != null) {
                throw new AssertionError("the controlled gap was disassembled at " + address);
            }
            if (expectData && listing.getDataAt(address) == null) {
                throw new AssertionError("datamark did not partition the gap at " + address);
            }
        }
        println("PalInspectGap: ok");
    }
}
"#;

/// Saved-project inspector for the colliding/shared leaf policy: the
/// complete applied state plus every deterministic `_pme_` role label,
/// `_pme_` global primary, and `shared_` global primary derived from the
/// manifest the production allocator produced.
const PAL_INSPECT_COLLIDING_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class PalInspectColliding extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new AssertionError("expected kit root and PAL manifest path");
        }
        File kitRoot = new File(args[0]);
        File palFile = new File(args[1]);
        PalTasksSupport.PalManifest manifest =
                PalTasksSupport.readPal(kitRoot, "02_MAIN", palFile, null);
        String identity = PalTasksSupport.expectedPalIdentity(manifest);
        PalTasksSupport.AppliedState state =
                PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        if (state.applications != 3 || state.createdFunctions != 3
                || state.preexistingFunctions != 0 || state.palOwnedPrimaries != 3
                || state.preservedPrimaries != 0 || state.pass2OwnedPrimaries != 0
                || state.reservedLabels != 4) {
            throw new AssertionError("colliding applied-state counts are wrong: " + state.applications
                    + " applications, " + state.createdFunctions + " created, "
                    + state.reservedLabels + " labels");
        }

        FunctionManager functions = currentProgram.getFunctionManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        Namespace namespace = symbols.getNamespace(PalTasksSupport.RESERVED_NAMESPACE,
                currentProgram.getGlobalNamespace());
        if (namespace == null) {
            throw new AssertionError("the reserved namespace is missing");
        }
        int pmeLabels = 0;
        int sharedPrimaries = 0;
        for (PalTasksSupport.PalApplication application : manifest.applications) {
            Function function = functions.getFunctionAt(toAddr(application.entry));
            if (function == null) {
                throw new AssertionError("missing function at 0x"
                        + Long.toHexString(application.entry));
            }
            if (!function.getName().equals(application.desiredPrimary)) {
                throw new AssertionError("primary at 0x" + Long.toHexString(application.entry)
                        + " is " + function.getName() + ", expected " + application.desiredPrimary);
            }
            if (application.desiredPrimary.contains("_pme_")) {
                pmeLabels++;
            }
            if (application.desiredPrimary.startsWith("pal_TaskEntry_shared_")) {
                sharedPrimaries++;
            }
        }
        for (PalTasksSupport.PalTask task : manifest.tasks) {
            List<String> at = new ArrayList<>();
            for (Symbol symbol : symbols.getSymbols(toAddr(task.entry))) {
                if (symbol.getParentNamespace() == namespace) {
                    at.add(symbol.getName());
                }
            }
            if (!at.contains(task.taskLabel)) {
                throw new AssertionError("role label " + task.taskLabel
                        + " missing at 0x" + Long.toHexString(task.entry) + ": " + at);
            }
            if (task.taskLabel.contains("_pme_")) {
                pmeLabels++;
            }
        }
        if (pmeLabels != 4 || sharedPrimaries != 1) {
            throw new AssertionError("leaf-policy counts wrong: " + pmeLabels
                    + " _pme_ leaves, " + sharedPrimaries + " shared primaries");
        }
        println("PalInspectColliding: ok");
    }
}
"#;

#[derive(Clone)]
struct PalApplyKit {
    dir: PathBuf,
    out: PathBuf,
    identity: String,
    manifest_path: PathBuf,
    scatter_path: PathBuf,
    kit_root: PathBuf,
}

/// Generates the extended seven-task PAL kit for the canonical fixture
/// image.
fn generate_pal_apply_kit(home: &std::path::Path, case: &str) -> PalApplyKit {
    let image = pal_fixture::craft_main_image();
    generate_pal_apply_kit_manifests(home, case, &image, |scatter_hash| {
        pal_fixture::extended_manifest(&image, scatter_hash)
    })
}

/// Generates the PAL kit for an explicit fixture image; the manifest is
/// built from the kit's own materialized scatter load-map hash.
fn generate_pal_apply_kit_manifests(
    home: &std::path::Path,
    case: &str,
    image: &[u8],
    manifest_for: impl FnOnce(&str) -> String,
) -> PalApplyKit {
    let dir = std::env::temp_dir().join(format!("pme_pal_apply_{case}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    let mut wrapped = pal_fixture::craft_pal_main_modem_bin();
    // Rebuild the modem payload around the explicit image bytes.
    wrapped.truncate(wrapped.len() - pal_fixture::craft_main_image().len());
    wrapped.extend_from_slice(image);
    std::fs::write(&modem_path, &wrapped).unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.to_path_buf()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        },
        &out,
    )
    .unwrap();

    let scatter_path = out.join("scatter/02_MAIN/load_map.json");
    assert!(
        scatter_path.exists(),
        "kit must materialize the scatter load map"
    );
    let scatter_hash = blake3_of(&scatter_path);
    let manifest = manifest_for(&scatter_hash);
    let manifest_dir = out.join("pal_tasks/02_MAIN");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let manifest_path = manifest_dir.join("tasks.json");
    std::fs::write(&manifest_path, &manifest).unwrap();
    let identity = pal_fixture::extended_identity(&manifest);

    for (name, source) in [
        ("PalSeedMeaningful.java", PAL_SEED_MEANINGFUL_JAVA),
        ("PalSeedWrongIsa.java", PAL_SEED_WRONG_ISA_JAVA),
        ("PalSeedStrayClose.java", PAL_SEED_STRAY_CLOSE_JAVA),
        ("PalSeedContaining.java", PAL_SEED_CONTAINING_JAVA),
        ("PalSeedLabelCollision.java", PAL_SEED_LABEL_COLLISION_JAVA),
        ("PalSeedStaleRegistry.java", PAL_SEED_STALE_REGISTRY_JAVA),
        ("InspectApplied.java", PAL_INSPECT_APPLIED_JAVA),
        ("InspectAbsent.java", PAL_INSPECT_ABSENT_JAVA),
    ] {
        std::fs::write(out.join("scripts").join(name), source).unwrap();
    }
    std::fs::create_dir_all(out.join("ghidra_project")).unwrap();
    for directory in ["ghidra_config", "ghidra_cache", "ghidra_tmp"] {
        std::fs::create_dir_all(out.join(directory)).unwrap();
    }

    PalApplyKit {
        kit_root: std::fs::canonicalize(&out).unwrap(),
        manifest_path: std::fs::canonicalize(&manifest_path).unwrap(),
        scatter_path: std::fs::canonicalize(&scatter_path).unwrap(),
        dir,
        out,
        identity,
    }
}

/// Patches the staged ApplySymbols source once per anchor pair.
fn patch_apply_symbols_script(out: &std::path::Path, replacements: &[(&str, &str)]) {
    let path = out.join("scripts/ApplySymbols.java");
    let mut script = std::fs::read_to_string(&path).unwrap();
    for (from, to) in replacements {
        assert_eq!(
            script.matches(from).count(),
            1,
            "patch anchor {from:?} must be unique"
        );
        script = script.replacen(from, to, 1);
    }
    std::fs::write(&path, script).unwrap();
}

fn pal_headless(home: &std::path::Path, kit: &PalApplyKit, args: &[String]) -> String {
    let config = kit.out.join("ghidra_config");
    let cache = kit.out.join("ghidra_cache");
    let temp = kit.out.join("ghidra_tmp");
    let java_options = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        config.display(),
        cache.display(),
        temp.display(),
        temp.display()
    );
    let output = std::process::Command::new(
        analyze_headless_in_home(home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(kit.out.join("ghidra_project"))
    .arg("pixel-modem")
    .args(args)
    .env("XDG_CONFIG_HOME", &config)
    .env("XDG_CACHE_HOME", &cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
    .output()
    .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The initial `-import` run: applies the scatter load map and optionally
/// runs one seeding post-script.
fn pal_import(home: &std::path::Path, kit: &PalApplyKit, seed: Option<&str>) -> String {
    let mut args: Vec<String> = [
        "-import".to_string(),
        kit.out
            .join("images/02_MAIN")
            .to_string_lossy()
            .into_owned(),
        "-processor".to_string(),
        "ARM:LE:32:v7".to_string(),
        "-loader".to_string(),
        "BinaryLoader".to_string(),
        "-loader-baseAddr".to_string(),
        "40010000".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-preScript".to_string(),
        "ApplyScatterLoad.java".to_string(),
        kit.kit_root.to_string_lossy().into_owned(),
        "02_MAIN".to_string(),
        kit.scatter_path.to_string_lossy().into_owned(),
    ]
    .into();
    if let Some(script) = seed {
        args.extend(["-postScript".to_string(), script.to_string()]);
    }
    pal_headless(home, kit, &args)
}

/// The `-process` run driving ApplyPalTasks with its four canonical
/// arguments, plus an optional post-script that receives the same four.
fn pal_apply(home: &std::path::Path, kit: &PalApplyKit, post: Option<&str>) -> String {
    let mut args: Vec<String> = [
        "-process".to_string(),
        "02_MAIN".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-preScript".to_string(),
        "ApplyPalTasks.java".to_string(),
        kit.kit_root.to_string_lossy().into_owned(),
        "02_MAIN".to_string(),
        kit.manifest_path.to_string_lossy().into_owned(),
        kit.scatter_path.to_string_lossy().into_owned(),
    ]
    .into();
    if let Some(script) = post {
        args.extend([
            "-postScript".to_string(),
            script.to_string(),
            kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".to_string(),
            kit.manifest_path.to_string_lossy().into_owned(),
            kit.scatter_path.to_string_lossy().into_owned(),
        ]);
    }
    pal_headless(home, kit, &args)
}

/// InspectAbsent as its own `-process` run with an optional extra argument.
fn pal_inspect_absent(
    home: &std::path::Path,
    kit: &PalApplyKit,
    mode: &str,
    extra: &str,
) -> String {
    let mut args: Vec<String> = [
        "-process".to_string(),
        "02_MAIN".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "InspectAbsent.java".to_string(),
        mode.to_string(),
    ]
    .into();
    if !extra.is_empty() {
        args.push(extra.to_string());
    }
    pal_headless(home, kit, &args)
}

/// Patches the staged ApplyPalTasks source once per anchor pair.
fn patch_apply_script(out: &std::path::Path, replacements: &[(&str, &str)]) {
    let path = out.join("scripts/ApplyPalTasks.java");
    let mut script = std::fs::read_to_string(&path).unwrap();
    for (from, to) in replacements {
        assert_eq!(
            script.matches(from).count(),
            1,
            "patch anchor {from:?} must be unique"
        );
        script = script.replacen(from, to, 1);
    }
    std::fs::write(&path, script).unwrap();
}

fn pal_expected_summary(
    kit: &PalApplyKit,
    created: usize,
    existing: usize,
    applied: usize,
    preserved: usize,
) -> String {
    format!(
        "ApplyPalTasks: {{\"image\":\"02_MAIN\",\"status\":\"ok\",\"identity\":\"{}\",\"tasks\":7,\"entries\":6,\"functions_created\":{},\"functions_existing\":{},\"names_applied\":{},\"names_preserved\":{},\"shared_entries\":1}}",
        kit.identity, created, existing, applied, preserved
    )
}

#[test]
fn apply_pal_tasks_seeds_state_and_reapplies_idempotently() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let kit = generate_pal_apply_kit(&home, "ok");
    let import = pal_import(&home, &kit, Some("PalSeedMeaningful.java"));
    assert!(
        import.contains("PalSeedMeaningful: seeded zetaKeptName and coincident"),
        "meaningful-name seed did not run:\n{import}"
    );

    let first = pal_apply(&home, &kit, Some("InspectApplied.java"));
    assert!(
        first.contains(&pal_expected_summary(&kit, 4, 2, 4, 2)),
        "first application summary mismatch:\n{first}"
    );
    assert!(
        first.contains("InspectApplied: ok"),
        "inspection failed:\n{first}"
    );

    let second = pal_apply(&home, &kit, Some("InspectApplied.java"));
    assert!(
        second.contains(&pal_expected_summary(&kit, 0, 6, 4, 2)),
        "reapplication summary mismatch:\n{second}"
    );
    assert!(
        second.contains("InspectApplied: ok"),
        "reapply inspection failed:\n{second}"
    );
    let first_fingerprint: Vec<&str> = first
        .lines()
        .filter(|line| {
            line.starts_with("InspectApplied: registry ")
                || line.starts_with("InspectApplied: labels ")
        })
        .collect();
    let second_fingerprint: Vec<&str> = second
        .lines()
        .filter(|line| {
            line.starts_with("InspectApplied: registry ")
                || line.starts_with("InspectApplied: labels ")
        })
        .collect();
    assert_eq!(
        first_fingerprint, second_fingerprint,
        "reapplication created new registry or label state"
    );

    let _ = std::fs::remove_dir_all(&kit.dir);
}

fn assert_apply_fails_without_partial_state(
    home: &std::path::Path,
    case: &str,
    seed: Option<&str>,
    patches: &[(&str, &str)],
    expected_failure: &str,
    absent_mode: &str,
) {
    let kit = generate_pal_apply_kit(home, case);
    let import = pal_import(home, &kit, seed);
    assert!(
        !import.contains("REPORT SCRIPT ERROR"),
        "seed run failed for {case}:\n{import}"
    );
    if let Some(script) = seed {
        let marker = script.trim_end_matches(".java");
        assert!(
            import.contains(marker),
            "seed {script} did not run for {case}:\n{import}"
        );
    }
    if !patches.is_empty() {
        patch_apply_script(&kit.out, patches);
    }
    let failed = pal_apply(home, &kit, None);
    assert!(
        failed.contains(expected_failure),
        "apply run for {case} missed {expected_failure:?}:\n{failed}"
    );
    let inspected = pal_inspect_absent(home, &kit, absent_mode, "");
    assert!(
        inspected.contains(&format!("InspectAbsent: {absent_mode} ok")),
        "saved project retained partial PAL state after {case}:\napplied:\n{failed}\ninspected:\n{inspected}"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn apply_pal_tasks_rolls_back_injected_failure_after_several_functions() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "rollback",
        None,
        &[(
            "chargeNewlyDefinedAddresses(disassembled);",
            concat!(
                "if (appliedCount == 2) {\n",
                "                    throw new IllegalStateException(\n",
                "                            \"injected failure after several functions\");\n",
                "                }\n",
                "                chargeNewlyDefinedAddresses(disassembled);"
            ),
        )],
        "injected failure after several functions",
        "pristine",
    );
}

#[test]
fn apply_pal_tasks_rejects_entry_timeout_and_rolls_back() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "timeout",
        None,
        &[
            (
                "budgetOverride(\"PME_PAL_ENTRY_BUDGET_MS\", 30_000L)",
                "budgetOverride(\"PME_PAL_ENTRY_BUDGET_MS\", 1L)",
            ),
            (
                "TimeoutTaskMonitor entryMonitor = newEntryMonitor(remainingPhaseMs);",
                concat!(
                    "TimeoutTaskMonitor entryMonitor = newEntryMonitor(remainingPhaseMs);\n",
                    "                Thread.sleep(50);"
                ),
            ),
        ],
        "the per-entry PAL budget was exhausted",
        "pristine",
    );
}

#[test]
fn apply_pal_tasks_rejects_code_byte_exhaustion_and_rolls_back() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "bytes",
        None,
        &[(
            "MAX_NEWLY_DEFINED_BYTES = 64L * 1024L * 1024L",
            "MAX_NEWLY_DEFINED_BYTES = 24L",
        )],
        "the newly-defined address budget was exhausted",
        "pristine",
    );
}

#[test]
fn apply_pal_tasks_rejects_wrong_isa_context() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "wrong_isa",
        Some("PalSeedWrongIsa.java"),
        &[],
        "the entry ISA context does not match the declared",
        "seeded",
    );
}

#[test]
fn apply_pal_tasks_rejects_stray_close_marker_before_mutation() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "stray_close",
        Some("PalSeedStrayClose.java"),
        &[],
        "a stray owned-comment closing marker exists",
        "seeded_fn",
    );
}

#[test]
fn apply_pal_tasks_rejects_containing_function() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "containing",
        Some("PalSeedContaining.java"),
        &[],
        "a function contains the task entry but does not begin there",
        "seeded",
    );
}

#[test]
fn apply_pal_tasks_rejects_label_collision() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_apply_fails_without_partial_state(
        &home,
        "collision",
        Some("PalSeedLabelCollision.java"),
        &[],
        "the reserved namespace is not empty",
        "collision",
    );
}

#[test]
fn apply_pal_tasks_rejects_stale_registry() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let kit = generate_pal_apply_kit(&home, "stale");
    let import = pal_import(&home, &kit, None);
    assert!(
        !import.contains("REPORT SCRIPT ERROR"),
        "import failed:\n{import}"
    );
    let applied = pal_apply(&home, &kit, None);
    assert!(
        applied.contains(&pal_expected_summary(&kit, 6, 0, 6, 0)),
        "initial application failed:\n{applied}"
    );
    let seeded = pal_headless(
        &home,
        &kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "PalSeedStaleRegistry.java".to_string(),
        ],
    );
    assert!(
        seeded.contains("PalSeedStaleRegistry: tampered the alpha manifest binding"),
        "stale seed did not run:\n{seeded}"
    );
    let failed = pal_apply(&home, &kit, None);
    assert!(
        failed.contains("binds a different manifest than the identity"),
        "stale registry was not rejected:\n{failed}"
    );
    let inspected = pal_inspect_absent(&home, &kit, "stale", &kit.identity);
    assert!(
        inspected.contains("InspectAbsent: stale ok"),
        "failed reapplication disturbed the applied state:\n{inspected}"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

/// Task 14 (Task 8's deferred leaf-policy probe): a discoverable image
/// whose `co.llide` and `co llide` tasks sanitize to the same preferred
/// leaf from different entries (the `_pme_` suffix branch) while
/// `dup_one`/`dup_two` share one entry (the `shared_` primary branch).
/// The production allocator's decisions are pinned from the generated
/// manifest, then applied and validated inside real Ghidra.
#[test]
fn colliding_and_shared_names_allocate_deterministic_leaves() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pme_pal_collide_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        pal_fixture::discoverable::craft_colliding_names_modem_bin(),
    )
    .unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.clone()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &out,
    )
    .unwrap();

    let manifest_path = out.join("pal_tasks/02_MAIN/tasks.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .unwrap_or_else(|error| panic!("colliding fixture produced no manifest: {error}"));
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let tasks = manifest["tasks"].as_array().unwrap();
    let names: Vec<&str> = tasks.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["co.llide", "co llide", "dup_one", "dup_two"]);
    let entry_hex = |task: &serde_json::Value| {
        task["entry"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x")
            .to_string()
    };
    let entries: Vec<String> = tasks.iter().map(entry_hex).collect();
    assert_eq!(entries[2], entries[3], "dup tasks must share one entry");

    // The colliding sanitized leaves are suffix-allocated by identity
    // key: entry then lowest colliding index, nonce 0.
    assert_eq!(
        tasks[0]["task_label"].as_str().unwrap(),
        format!(
            "pal_TaskEntry_co_llide_pme_{}_00000000_00000000",
            entries[0]
        ),
        "the first colliding leaf must take the deterministic suffix"
    );
    assert_eq!(
        tasks[1]["task_label"].as_str().unwrap(),
        format!(
            "pal_TaskEntry_co_llide_pme_{}_00000001_00000000",
            entries[1]
        ),
        "the second colliding leaf must take the next identity key"
    );
    assert_eq!(
        tasks[2]["task_label"].as_str().unwrap(),
        "pal_TaskEntry_dup_one",
        "unique names keep their exact leaves"
    );
    assert_eq!(
        tasks[3]["task_label"].as_str().unwrap(),
        "pal_TaskEntry_dup_two",
        "shared entries still keep every role label"
    );

    let applications = manifest["applications"].as_array().unwrap();
    assert_eq!(applications.len(), 3, "three normalized entry groups");
    let mut by_entry: std::collections::BTreeMap<&str, &serde_json::Value> = applications
        .iter()
        .map(|app| (app["entry"].as_str().unwrap(), app))
        .collect();
    for (index, entry) in entries[0..2].iter().enumerate() {
        let key = format!("0x{entry}");
        let app = by_entry.remove(key.as_str()).unwrap_or_else(|| {
            panic!("no application for colliding entry {key}: {applications:?}")
        });
        assert_eq!(
            app["desired_primary"].as_str().unwrap(),
            format!("pal_TaskEntry_co_llide_pme_{entry}_{:08x}_00000000", index),
            "colliding global primaries take the same deterministic suffixes"
        );
    }
    let shared_key = format!("0x{}", entries[2]);
    let shared = by_entry.remove(shared_key.as_str()).unwrap();
    assert_eq!(
        shared["desired_primary"].as_str().unwrap(),
        format!("pal_TaskEntry_shared_{}", entries[2]),
        "the shared entry must take the shared primary"
    );
    assert_eq!(
        manifest["table"]["count"].as_u64().unwrap(),
        4,
        "four tasks entered the table"
    );
    let identity = format!("v1:{}:4:0", blake3::hash(&manifest_bytes).to_hex());
    let modem = pal_fixture::discoverable::craft_colliding_names_modem_bin();
    let main_slice = &modem[0x40..];
    assert_eq!(
        manifest["image"]["blake3"].as_str().unwrap(),
        blake3::hash(main_slice).to_hex().to_string(),
        "the manifest must authenticate the exact MAIN slice"
    );
    assert!(
        manifest["runtime_view"]["scatter_load_map_blake3"].is_null(),
        "the colliding fixture has no scatter dependency"
    );

    // Real Ghidra: import raw, apply the discovered manifest, validate
    // every deterministic leaf inside the saved project.
    std::fs::write(
        out.join("scripts/PalInspectColliding.java"),
        PAL_INSPECT_COLLIDING_JAVA,
    )
    .unwrap();
    for directory in [
        "ghidra_project",
        "ghidra_config",
        "ghidra_cache",
        "ghidra_tmp",
    ] {
        std::fs::create_dir_all(out.join(directory)).unwrap();
    }
    let kit_root = std::fs::canonicalize(&out).unwrap();
    let manifest_canon = std::fs::canonicalize(&manifest_path).unwrap();
    let mut import_args: Vec<String> = [
        "-import".to_string(),
        out.join("images/02_MAIN").to_string_lossy().into_owned(),
        "-processor".to_string(),
        "ARM:LE:32:v7".to_string(),
        "-loader".to_string(),
        "BinaryLoader".to_string(),
        "-loader-baseAddr".to_string(),
        format!("{:#x}", pal_fixture::discoverable::BASE),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        out.join("scripts").to_string_lossy().into_owned(),
    ]
    .into();
    let headless = |args: &[String]| -> String {
        let config = out.join("ghidra_config");
        let cache = out.join("ghidra_cache");
        let temp = out.join("ghidra_tmp");
        let java_options = format!(
            "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
            config.display(),
            cache.display(),
            temp.display(),
            temp.display()
        );
        let output = std::process::Command::new(
            analyze_headless_in_home(&home).expect("located Ghidra home still has analyzeHeadless"),
        )
        .arg(out.join("ghidra_project"))
        .arg("pixel-modem")
        .args(args)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_CACHE_HOME", cache)
        .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
        .output()
        .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        format!("{stdout}\n--- stderr ---\n{stderr}")
    };
    let imported = headless(&import_args);
    assert!(
        !imported.contains("REPORT SCRIPT ERROR") && !imported.contains("ERROR "),
        "raw import failed:\n{imported}"
    );
    import_args = [
        "-process".to_string(),
        "02_MAIN".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        out.join("scripts").to_string_lossy().into_owned(),
        "-preScript".to_string(),
        "ApplyPalTasks.java".to_string(),
        kit_root.to_string_lossy().into_owned(),
        "02_MAIN".to_string(),
        manifest_canon.to_string_lossy().into_owned(),
        "-".to_string(),
        "-postScript".to_string(),
        "PalInspectColliding.java".to_string(),
        kit_root.to_string_lossy().into_owned(),
        manifest_canon.to_string_lossy().into_owned(),
    ]
    .into();
    let applied = headless(&import_args);
    assert!(
        applied.contains(&format!("\"identity\":\"{identity}\"")),
        "the applied summary must bind the generated identity:\n{applied}"
    );
    assert!(
        applied.contains("PalInspectColliding: ok"),
        "colliding application failed:\n{applied}"
    );
    assert!(
        !applied.contains("REPORT SCRIPT ERROR"),
        "colliding inspection failed:\n{applied}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// -------------------------------------------------------------------------
// Task 10: transactional TameAnalysis datamark gap preservation
// -------------------------------------------------------------------------

/// Fixture image (0x1000 bytes at 0x40010000): two ARM instructions at the
/// base (the seeded function body), eight undefined bytes, a seeded dword
/// data unit at +0x10, then undefined bytes through +0x40 (with a nonzero
/// marker word at +0x20 so the second gap's digest is not a zeros digest).
fn tame_fixture_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x1000];
    image[0x00..0x04].copy_from_slice(&[0x00, 0x00, 0xa0, 0xe3]); // mov r0, #0
    image[0x04..0x08].copy_from_slice(&[0x1e, 0xff, 0x2f, 0xe1]); // bx lr
    image[0x10..0x14].copy_from_slice(&[0xef, 0xbe, 0xad, 0xde]); // seeded dword
    image[0x20..0x24].copy_from_slice(&[0x5a, 0xc3, 0x3c, 0x5a]); // nonzero gap bytes
    image
}

/// Rust-side pin of the `pixel-modem-extractor-code-units-v1` digest grammar:
/// domain + NUL, LE u64 count, then per address-ordered unit tag 0x00
/// instruction / 0x01 data, LE u32 address, LE u32 byte length, exact bytes,
/// and for data the LE u32 UTF-8 data-type-path length plus exact path bytes.
fn tame_code_units_digest(units: &[(bool, u32, &[u8], &str)]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"pixel-modem-extractor-code-units-v1\0");
    bytes.extend_from_slice(&(units.len() as u64).to_le_bytes());
    for (is_data, address, data, path) in units {
        bytes.push(u8::from(*is_data));
        bytes.extend_from_slice(&address.to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(data);
        if *is_data {
            bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
            bytes.extend_from_slice(path.as_bytes());
        }
    }
    pal_fixture::blake3_hex(&bytes)
}

/// One function for the digest pin: (ID, entry u32, body ranges as
/// (start, exclusive-end) u32 pairs).
type TameDigestFunction = (u64, u32, &'static [(u32, u32)]);

/// Rust-side pin of the `pixel-modem-extractor-function-bodies-v1` digest
/// grammar: domain + NUL, LE u64 count, then per address-ordered function the
/// non-negative ID as LE u64, entry u32, range count u32, and each range's
/// start / exclusive-end u32 pair.
fn tame_function_bodies_digest(functions: &[TameDigestFunction]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"pixel-modem-extractor-function-bodies-v1\0");
    bytes.extend_from_slice(&(functions.len() as u64).to_le_bytes());
    for (id, entry, ranges) in functions {
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&entry.to_le_bytes());
        bytes.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
        for (start, end_exclusive) in *ranges {
            bytes.extend_from_slice(&start.to_le_bytes());
            bytes.extend_from_slice(&end_exclusive.to_le_bytes());
        }
    }
    pal_fixture::blake3_hex(&bytes)
}

/// Extracts the value printed after `marker` on its script log line, trimming
/// Ghidra's `(GhidraScript)` suffix decoration.
fn tame_script_value(stdout: &str, marker: &str) -> String {
    let line = stdout
        .lines()
        .find(|line| line.contains(marker))
        .unwrap_or_else(|| panic!("no {marker} line in:\n{stdout}"));
    let start = line.find(marker).unwrap() + marker.len();
    let end = line.rfind(" (GhidraScript)").unwrap_or(line.len());
    line[start..end].trim().to_string()
}

/// Parses the single `TameAnalysis: {json}` datamark summary line.
fn tame_summary(stdout: &str) -> serde_json::Value {
    let line = stdout
        .lines()
        .find(|line| line.contains("TameAnalysis: {"))
        .unwrap_or_else(|| panic!("no TameAnalysis summary line in:\n{stdout}"));
    let start = line.find("TameAnalysis: ").unwrap() + "TameAnalysis: ".len();
    let end = line.rfind('}').unwrap();
    serde_json::from_str(&line[start..=end])
        .unwrap_or_else(|error| panic!("summary is not JSON ({error}): {}", &line[start..=end]))
}

/// Seeds the fixture state: two ARM instructions and a function at
/// 0x40010000, a dword data unit at 0x40010010, and the Aggressive
/// Instruction Finder options pinned ON so a rolled-back datamark run must
/// restore them (and a successful one must disable them observably). Prints
/// the canonical preflight digests for the Rust-side grammar pin.
const TAME_SEED_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

public class TameSeed extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x40010000L);
        disassemble(entry);
        Instruction second = currentProgram.getListing().getInstructionAt(entry.add(4));
        if (second == null) {
            throw new AssertionError("tame seed did not disassemble both instructions");
        }
        Function function = createFunction(entry, null);
        if (function == null || !function.getBody().getMinAddress().equals(entry)
                || function.getBody().getMaxAddress().compareTo(entry.add(7)) != 0) {
            throw new AssertionError("tame seed function body is not the 8-byte entry run");
        }
        Data dword = createData(toAddr(0x40010010L), DWordDataType.dataType);
        if (dword == null || dword.getLength() != 4
                || !"/dword".equals(dword.getDataType().getPathName())) {
            throw new AssertionError("tame seed dword is not exact");
        }
        if (currentProgram.getListing().getNumCodeUnits() != 3) {
            throw new AssertionError("tame seed expects exactly three defined units");
        }
        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        opts.setBoolean("ARM Aggressive Instruction Finder", true);
        opts.setBoolean("Aggressive Instruction Finder", true);
        println("TameSeed: units_digest "
                + PalTasksSupport.codeUnitsDigestHex(currentProgram, null));
        println("TameSeed: function_id " + function.getID());
        println("TameSeed: function_digest "
                + PalTasksSupport.functionBodiesDigestHex(currentProgram));
        println("TameSeed: ok");
    }
}
"#;

/// Postflight for a successful datamark run: the seeded instructions, dword,
/// and function survive verbatim; the two maximal gaps carry exactly one byte
/// array each (byte[8] and byte[44]); the total unit count is additive; the
/// options were disabled; the PAL state stays absent; and the recomputed
/// digests (excluding the created gap arrays) are printed for comparison.
const INSPECT_DATAMARK_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class InspectDatamark extends GhidraScript {
    private Data requireArray(long address, int length) {
        Data array = currentProgram.getListing().getDefinedDataAt(toAddr(address));
        if (array == null || array.getLength() != length || !array.getDataType()
                .isEquivalent(new ArrayDataType(ByteDataType.dataType, length, 1))) {
            throw new AssertionError("expected an exact byte[" + length + "] array at 0x"
                    + Long.toHexString(address));
        }
        return array;
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        if (listing.getInstructionAt(toAddr(0x40010000L)) == null
                || listing.getInstructionAt(toAddr(0x40010004L)) == null) {
            throw new AssertionError("a seeded instruction was cleared");
        }
        Data dword = listing.getDefinedDataAt(toAddr(0x40010010L));
        if (dword == null || dword.getLength() != 4
                || !"/dword".equals(dword.getDataType().getPathName())) {
            throw new AssertionError("the seeded dword was disturbed");
        }
        Function function = currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010000L));
        if (function == null || !function.getBody().getMinAddress().equals(toAddr(0x40010000L))
                || function.getBody().getMaxAddress().compareTo(toAddr(0x40010007L)) != 0) {
            throw new AssertionError("the seeded function was disturbed");
        }
        requireArray(0x40010008L, 8);
        requireArray(0x40010014L, 44);
        if (listing.getDefinedDataAt(toAddr(0x4001000cL)) != null) {
            throw new AssertionError("the first gap is not covered by one array");
        }
        if (listing.getNumCodeUnits() != 5) {
            throw new AssertionError("the unit count is not additive: "
                    + listing.getNumCodeUnits());
        }
        PalTasksSupport.validateAbsent(currentProgram);
        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        if (opts.getBoolean("ARM Aggressive Instruction Finder", true)
                || opts.getBoolean("Aggressive Instruction Finder", true)) {
            throw new AssertionError("datamark did not disable the aggressive finders");
        }
        AddressSet gaps = new AddressSet(toAddr(0x40010008L), toAddr(0x4001000fL));
        gaps.add(toAddr(0x40010014L), toAddr(0x4001003fL));
        println("InspectDatamark: units_digest "
                + PalTasksSupport.codeUnitsDigestHex(currentProgram, gaps));
        println("InspectDatamark: function_id " + function.getID());
        println("InspectDatamark: function_digest "
                + PalTasksSupport.functionBodiesDigestHex(currentProgram));
        println("InspectDatamark: ok");
    }
}
"#;

/// Postflight for the scaled-down multi-chunk datamark run (the staged
/// TameAnalysis patched to MAX_ARRAY_BYTES = 8): the 44-byte gap must be
/// partitioned into exact 8/8/8/8/8/4 arrays with nothing defined at any
/// chunk-internal offset.
const INSPECT_DATAMARK_CHUNKS_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class InspectDatamarkChunks extends GhidraScript {
    private void requireArray(long address, int length) {
        Data array = currentProgram.getListing().getDefinedDataAt(toAddr(address));
        if (array == null || array.getLength() != length || !array.getDataType()
                .isEquivalent(new ArrayDataType(ByteDataType.dataType, length, 1))) {
            throw new AssertionError("expected an exact byte[" + length + "] array at 0x"
                    + Long.toHexString(address));
        }
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        if (listing.getInstructionAt(toAddr(0x40010000L)) == null
                || listing.getInstructionAt(toAddr(0x40010004L)) == null) {
            throw new AssertionError("a seeded instruction was cleared");
        }
        Data dword = listing.getDefinedDataAt(toAddr(0x40010010L));
        if (dword == null || dword.getLength() != 4
                || !"/dword".equals(dword.getDataType().getPathName())) {
            throw new AssertionError("the seeded dword was disturbed");
        }
        Function function = currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010000L));
        if (function == null || !function.getBody().getMinAddress().equals(toAddr(0x40010000L))
                || function.getBody().getMaxAddress().compareTo(toAddr(0x40010007L)) != 0) {
            throw new AssertionError("the seeded function was disturbed");
        }
        requireArray(0x40010008L, 8);
        requireArray(0x40010014L, 8);
        requireArray(0x4001001cL, 8);
        requireArray(0x40010024L, 8);
        requireArray(0x4001002cL, 8);
        requireArray(0x40010034L, 8);
        requireArray(0x4001003cL, 4);
        // Nothing is defined at any chunk-internal offset: the arrays
        // exactly partition both gaps.
        long[][] chunks = {{0x40010008L, 8}, {0x40010014L, 8}, {0x4001001cL, 8},
            {0x40010024L, 8}, {0x4001002cL, 8}, {0x40010034L, 8}, {0x4001003cL, 4}};
        for (long[] chunk : chunks) {
            for (long offset = 1; offset < chunk[1]; offset++) {
                long address = chunk[0] + offset;
                if (currentProgram.getListing().getDefinedDataAt(toAddr(address)) != null) {
                    throw new AssertionError("a chunk-internal offset is defined at 0x"
                            + Long.toHexString(address));
                }
            }
        }
        if (listing.getNumCodeUnits() != 10) {
            throw new AssertionError("the unit count is not additive: "
                    + listing.getNumCodeUnits());
        }
        PalTasksSupport.validateAbsent(currentProgram);
        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        if (opts.getBoolean("ARM Aggressive Instruction Finder", true)
                || opts.getBoolean("Aggressive Instruction Finder", true)) {
            throw new AssertionError("datamark did not disable the aggressive finders");
        }
        AddressSet gaps = new AddressSet(toAddr(0x40010008L), toAddr(0x4001000fL));
        gaps.add(toAddr(0x40010014L), toAddr(0x4001003fL));
        println("InspectDatamarkChunks: units_digest "
                + PalTasksSupport.codeUnitsDigestHex(currentProgram, gaps));
        println("InspectDatamarkChunks: function_digest "
                + PalTasksSupport.functionBodiesDigestHex(currentProgram));
        println("InspectDatamarkChunks: ok");
    }
}
"#;

/// Postflight for a failed datamark run: no data-mark array survives (both
/// gap starts are undefined), the seeded code/function/dword are intact, the
/// unit count is back to three, the PAL state is absent, and the aggressive
/// finder options were restored to the seeded ON state.
const INSPECT_PRISTINE_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class InspectPristine extends GhidraScript {
    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        if (listing.getInstructionAt(toAddr(0x40010000L)) == null
                || listing.getInstructionAt(toAddr(0x40010004L)) == null) {
            throw new AssertionError("a seeded instruction was lost");
        }
        Data dword = listing.getDefinedDataAt(toAddr(0x40010010L));
        if (dword == null || dword.getLength() != 4
                || !"/dword".equals(dword.getDataType().getPathName())) {
            throw new AssertionError("the seeded dword was lost");
        }
        Function function = currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010000L));
        if (function == null || !function.getBody().getMinAddress().equals(toAddr(0x40010000L))
                || function.getBody().getMaxAddress().compareTo(toAddr(0x40010007L)) != 0) {
            throw new AssertionError("the seeded function was lost");
        }
        if (listing.getDefinedDataAt(toAddr(0x40010008L)) != null
                || listing.getDefinedDataAt(toAddr(0x40010014L)) != null) {
            throw new AssertionError("a data-mark array survived the failed run");
        }
        if (listing.getNumCodeUnits() != 3) {
            throw new AssertionError("the unit count did not roll back: "
                    + listing.getNumCodeUnits());
        }
        PalTasksSupport.validateAbsent(currentProgram);
        Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        if (!opts.getBoolean("ARM Aggressive Instruction Finder", true)
                || !opts.getBoolean("Aggressive Instruction Finder", true)) {
            throw new AssertionError("the analyzer options did not roll back");
        }
        println("InspectPristine: ok");
    }
}
"#;

struct TameKit {
    dir: std::path::PathBuf,
    out: std::path::PathBuf,
}

/// Generates the TameAnalysis fixture kit: a real import kit for the fixture
/// image plus the staged seed/inspector scripts.
fn generate_tame_kit(home: &std::path::Path, case: &str) -> TameKit {
    let dir = std::env::temp_dir().join(format!("pme_tame_{case}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        craft_single_image_modem_bin("BOOT", 0x4001_0000, 1, &tame_fixture_image()),
    )
    .unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.to_path_buf()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        },
        &out,
    )
    .unwrap();
    assert!(
        out.join("scripts/TameAnalysis.java").exists(),
        "kit must stage TameAnalysis.java"
    );
    for (name, source) in [
        ("TameSeed.java", TAME_SEED_JAVA),
        ("InspectDatamark.java", INSPECT_DATAMARK_JAVA),
        ("InspectPristine.java", INSPECT_PRISTINE_JAVA),
    ] {
        std::fs::write(out.join("scripts").join(name), source).unwrap();
    }
    std::fs::create_dir_all(out.join("ghidra_project")).unwrap();
    for directory in ["ghidra_config", "ghidra_cache", "ghidra_tmp"] {
        std::fs::create_dir_all(out.join(directory)).unwrap();
    }
    TameKit { dir, out }
}

fn tame_headless(home: &std::path::Path, kit: &TameKit, args: &[String]) -> std::process::Output {
    let config = kit.out.join("ghidra_config");
    let cache = kit.out.join("ghidra_cache");
    let temp = kit.out.join("ghidra_tmp");
    let java_options = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        config.display(),
        cache.display(),
        temp.display(),
        temp.display()
    );
    std::process::Command::new(
        analyze_headless_in_home(home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(kit.out.join("ghidra_project"))
    .arg("pixel-modem")
    .args(args)
    .env("XDG_CONFIG_HOME", &config)
    .env("XDG_CACHE_HOME", &cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
    .output()
    .unwrap()
}

fn tame_stdout(output: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// The initial `-import` run, optionally seeding the fixture state.
fn tame_import(home: &std::path::Path, kit: &TameKit, seed: bool) -> String {
    let mut args: Vec<String> = [
        "-import".to_string(),
        kit.out
            .join("images/00_BOOT")
            .to_string_lossy()
            .into_owned(),
        "-processor".to_string(),
        "ARM:LE:32:v7".to_string(),
        "-loader".to_string(),
        "BinaryLoader".to_string(),
        "-loader-baseAddr".to_string(),
        "40010000".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
    ]
    .into();
    if seed {
        args.extend(["-postScript".to_string(), "TameSeed.java".to_string()]);
    }
    tame_stdout(&tame_headless(home, kit, &args))
}

/// A `-process` run driving TameAnalysis with the given script arguments
/// (mode, exception identity, PAL identity, regions), optionally followed by
/// one post-script. A
/// pre-script failure makes Ghidra print `REPORT SCRIPT ERROR`, abort the
/// rest of the run, and skip the post-script — while still exiting zero, so
/// callers assert on the report text rather than the exit status.
fn tame_datamark(
    home: &std::path::Path,
    kit: &TameKit,
    script_args: &[&str],
    post: Option<&str>,
) -> String {
    let mut args: Vec<String> = [
        "-process".to_string(),
        "00_BOOT".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-preScript".to_string(),
        "TameAnalysis.java".to_string(),
    ]
    .into();
    args.extend(script_args.iter().map(|arg| arg.to_string()));
    if let Some(script) = post {
        args.extend(["-postScript".to_string(), script.to_string()]);
    }
    tame_stdout(&tame_headless(home, kit, &args))
}

fn tame_inspect_pristine(home: &std::path::Path, kit: &TameKit) -> String {
    let args: Vec<String> = [
        "-process".to_string(),
        "00_BOOT".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "InspectPristine.java".to_string(),
    ]
    .into();
    tame_stdout(&tame_headless(home, kit, &args))
}

/// Patches the staged TameAnalysis source once per anchor pair.
fn patch_tame_script(out: &std::path::Path, replacements: &[(&str, &str)]) {
    let path = out.join("scripts/TameAnalysis.java");
    let mut script = std::fs::read_to_string(&path).unwrap();
    for (from, to) in replacements {
        assert_eq!(
            script.matches(from).count(),
            1,
            "patch anchor {from:?} must be unique"
        );
        script = script.replacen(from, to, 1);
    }
    std::fs::write(&path, script).unwrap();
}

#[test]
fn datamark_preserves_code_functions_and_partitions_gaps() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let kit = generate_tame_kit(&home, "preserve");
    let seeded = tame_import(&home, &kit, true);
    assert!(
        seeded.contains("TameSeed: ok"),
        "seed run failed:\n{seeded}"
    );

    // Rust-side grammar pin: the digests printed by the seed run must equal
    // the digests recomputed here from the fixture bytes alone.
    let image = tame_fixture_image();
    let expected_units = tame_code_units_digest(&[
        (false, 0x4001_0000, &image[0x00..0x04], ""),
        (false, 0x4001_0004, &image[0x04..0x08], ""),
        (true, 0x4001_0010, &image[0x10..0x14], "/dword"),
    ]);
    assert_eq!(
        tame_script_value(&seeded, "TameSeed: units_digest "),
        expected_units,
        "the Ghidra code-units digest does not match the Rust-side grammar pin"
    );
    let function_id: u64 = tame_script_value(&seeded, "TameSeed: function_id ")
        .parse()
        .unwrap();
    let expected_functions =
        tame_function_bodies_digest(&[(function_id, 0x4001_0000, &[(0x4001_0000, 0x4001_0008)])]);
    assert_eq!(
        tame_script_value(&seeded, "TameSeed: function_digest "),
        expected_functions,
        "the Ghidra function-bodies digest does not match the Rust-side grammar pin"
    );

    let run = tame_datamark(
        &home,
        &kit,
        &["datamark", "none", "none", "40010000:40"],
        Some("InspectDatamark.java"),
    );
    assert!(
        !run.contains("REPORT SCRIPT ERROR"),
        "datamark run failed:\n{run}"
    );
    assert!(
        run.contains("TameAnalysis: mode=datamark (Phase-1 fallback)"),
        "the datamark mode line is missing:\n{run}"
    );
    let summary = tame_summary(&run);
    assert_eq!(summary["mode"], "datamark");
    assert_eq!(summary["identity"], "none");
    assert_eq!(summary["regions"], 1);
    assert_eq!(summary["region_bytes"], 0x40);
    assert_eq!(summary["gaps"], 2);
    assert_eq!(summary["gap_bytes"], 52);
    assert_eq!(summary["arrays"], 2);
    assert_eq!(summary["units_before"], 3);
    assert_eq!(summary["units_after"], 5);
    assert_eq!(summary["code_units_digest"], expected_units);
    assert_eq!(summary["functions_before"], 1);
    assert_eq!(summary["function_digest"], expected_functions);
    let gap_digests = summary["gap_digests"].as_array().unwrap();
    let expected_gap_digests = [
        pal_fixture::blake3_hex(&image[0x08..0x10]),
        pal_fixture::blake3_hex(&image[0x14..0x40]),
    ];
    assert_eq!(gap_digests.len(), expected_gap_digests.len());
    for (actual, expected) in gap_digests.iter().zip(&expected_gap_digests) {
        assert_eq!(
            actual, expected,
            "the gap digest does not reproduce the bytes"
        );
    }
    assert!(
        run.contains("InspectDatamark: ok"),
        "postflight failed:\n{run}"
    );
    assert_eq!(
        tame_script_value(&run, "InspectDatamark: units_digest "),
        expected_units,
        "the preserved code units changed during data-marking"
    );
    assert_eq!(
        tame_script_value(&run, "InspectDatamark: function_digest "),
        expected_functions,
        "the function bodies changed during data-marking"
    );
    assert_eq!(
        tame_script_value(&run, "InspectDatamark: function_id ")
            .parse::<u64>()
            .unwrap(),
        function_id,
        "the seeded function identity changed during data-marking"
    );

    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn datamark_partitions_large_gaps_into_chunks_and_caps_digest_listing() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let kit = generate_tame_kit(&home, "chunks");
    let seeded = tame_import(&home, &kit, true);
    assert!(
        seeded.contains("TameSeed: ok"),
        "seed run failed:\n{seeded}"
    );

    // Scale the chunk boundary down through the staged-source seam (the
    // production constant stays untouched) so one gap exceeds one chunk
    // and must be partitioned into several exact arrays; also cap the
    // inlined digest listing at one entry to prove the summary cap.
    patch_tame_script(
        &kit.out,
        &[
            (
                "MAX_ARRAY_BYTES = 16 * 1024 * 1024;",
                "MAX_ARRAY_BYTES = 8;",
            ),
            (
                "MAX_SUMMARY_GAP_DIGESTS = 64;",
                "MAX_SUMMARY_GAP_DIGESTS = 1;",
            ),
        ],
    );
    std::fs::write(
        kit.out.join("scripts/InspectDatamarkChunks.java"),
        INSPECT_DATAMARK_CHUNKS_JAVA,
    )
    .unwrap();

    let run = tame_datamark(
        &home,
        &kit,
        &["datamark", "none", "none", "40010000:40"],
        Some("InspectDatamarkChunks.java"),
    );
    assert!(
        !run.contains("REPORT SCRIPT ERROR"),
        "datamark multi-chunk run failed:\n{run}"
    );
    let summary = tame_summary(&run);
    // The seeded fixture has two gaps (8 bytes and 44 bytes): the first
    // is exactly one 8-byte chunk, the second partitions into
    // 8+8+8+8+8+4 across six arrays.
    assert_eq!(summary["gaps"], 2);
    assert_eq!(summary["gap_bytes"], 52);
    assert_eq!(summary["arrays"], 7);
    assert_eq!(summary["units_after"], 3 + 7);
    // The digest listing is capped at one inlined digest, while the gap
    // count and aggregate still cover every gap.
    assert_eq!(summary["gap_digests"].as_array().unwrap().len(), 1);
    assert_eq!(summary["gap_digests_listed"], 1);
    assert!(
        run.contains("InspectDatamarkChunks: ok"),
        "postflight failed:\n{run}"
    );
    assert_eq!(
        tame_script_value(&run, "InspectDatamarkChunks: units_digest "),
        tame_script_value(&seeded, "TameSeed: units_digest "),
        "the preserved code units changed during multi-chunk data-marking"
    );
    assert_eq!(
        tame_script_value(&run, "InspectDatamarkChunks: function_digest "),
        tame_script_value(&seeded, "TameSeed: function_digest "),
        "the function bodies changed during multi-chunk data-marking"
    );

    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn datamark_rejects_strict_argument_contract_before_mutation() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let kit = generate_tame_kit(&home, "strict");
    let seeded = tame_import(&home, &kit, true);
    assert!(
        seeded.contains("TameSeed: ok"),
        "seed run failed:\n{seeded}"
    );

    let present_identity = format!("v1:{}:1:1", "a".repeat(64));
    let mut regions_4097: Vec<&str> = vec!["datamark", "none", "none"];
    regions_4097.extend(
        (0..4097).map(|index| {
            Box::leak(format!("{:08x}:1", 0x4001_0000 + index).into_boxed_str()) as &str
        }),
    );
    let over_aggregate = ["00000100:10000001", "10000200:10000001"];
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["explode", "none", "none"], "unknown mode"),
        (vec!["tighten"], "exception-root identity"),
        (vec!["datamark", "none"], "PAL identity"),
        (
            vec!["tighten", "none", "none", "40010000:4"],
            "tighten mode accepts no region arguments",
        ),
        (
            vec!["datamark", "bogus", "none"],
            "exception-root identity is not the v1 grammar",
        ),
        (
            vec!["datamark", &present_identity, "none"],
            "exception-root terminal ownership state is incomplete",
        ),
        (
            vec!["datamark", "none", "bogus"],
            "PAL identity is not the v1 grammar",
        ),
        (
            vec!["datamark", "none", &present_identity],
            "stale PAL property",
        ),
        (
            vec!["datamark", "none", "none", "40010000"],
            "malformed region",
        ),
        (
            vec!["datamark", "none", "none", "4001000g:4"],
            "malformed region",
        ),
        (
            vec!["datamark", "none", "none", "40010000:0"],
            "the region length is zero",
        ),
        (
            vec!["datamark", "none", "none", "ffffffff:2"],
            "wraps the 32-bit address space",
        ),
        // 16-hex-digit fields parse to negative longs; they must hit the
        // wrap rejection, never a silent no-op or an obscure address error.
        (
            vec!["datamark", "none", "none", "40010000:ffffffffffffffff"],
            "wraps the 32-bit address space",
        ),
        (
            vec!["datamark", "none", "none", "ffffffffffffffff:1"],
            "wraps the 32-bit address space",
        ),
        (
            vec!["datamark", "none", "none", "40010020:4", "40010010:4"],
            "not sorted",
        ),
        (
            vec!["datamark", "none", "none", "40010000:20", "40010010:8"],
            "overlap",
        ),
        (
            vec!["datamark", "none", "none", "50010000:4"],
            "not fully inside initialized memory",
        ),
        (regions_4097, "region count exceeds"),
        (
            vec![
                "datamark",
                "none",
                "none",
                over_aggregate[0],
                over_aggregate[1],
            ],
            "aggregate region bytes exceed",
        ),
    ];
    for (script_args, expected) in &cases {
        let run = tame_datamark(&home, &kit, script_args, None);
        let shown = &script_args[..script_args.len().min(3)].join(" ");
        assert!(
            run.contains("REPORT SCRIPT ERROR"),
            "case {shown:?} did not fail the headless run:\n{run}"
        );
        assert!(
            run.contains(expected),
            "case {shown:?} missed {expected:?}:\n{run}"
        );
        assert!(
            !run.contains("TameAnalysis: mode="),
            "case {shown:?} reached the mutation phase:\n{run}"
        );
    }

    let inspected = tame_inspect_pristine(&home, &kit);
    assert!(
        inspected.contains("InspectPristine: ok"),
        "a rejected run mutated the program:\n{inspected}"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

fn assert_datamark_fails_pristine(
    home: &std::path::Path,
    case: &str,
    patches: &[(&str, &str)],
    expected_failure: &str,
) {
    let kit = generate_tame_kit(home, case);
    let seeded = tame_import(home, &kit, true);
    assert!(
        seeded.contains("TameSeed: ok"),
        "seed run failed for {case}:\n{seeded}"
    );
    patch_tame_script(&kit.out, patches);
    let failed = tame_datamark(
        home,
        &kit,
        &["datamark", "none", "none", "40010000:40"],
        None,
    );
    assert!(
        failed.contains("REPORT SCRIPT ERROR"),
        "patched datamark run for {case} did not fail the headless run:\n{failed}"
    );
    assert!(
        failed.contains(expected_failure),
        "patched run for {case} missed {expected_failure:?}:\n{failed}"
    );
    let inspected = tame_inspect_pristine(home, &kit);
    assert!(
        inspected.contains("InspectPristine: ok"),
        "failed {case} run left partial state:\n{inspected}"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn datamark_rolls_back_injected_partial_failure() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_datamark_fails_pristine(
        &home,
        "rollback",
        &[(
            "arraysCreated++;",
            concat!(
                "arraysCreated++;\n",
                "                if (arraysCreated == 1) {\n",
                "                    throw new IllegalStateException(\n",
                "                            \"injected datamark failure after the first array\");\n",
                "                }"
            ),
        )],
        "injected datamark failure after the first array",
    );
}

#[test]
fn datamark_rejects_deadline_and_rolls_back() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_datamark_fails_pristine(
        &home,
        "deadline",
        &[
            (
                "budgetMsOverride(\"PME_TAME_PHASE_BUDGET_MS\", 15 * 60_000L)",
                "budgetMsOverride(\"PME_TAME_PHASE_BUDGET_MS\", 1L)",
            ),
            ("planGaps();", "Thread.sleep(50);\n            planGaps();"),
        ],
        "the TameAnalysis phase budget was exhausted",
    );
}

#[test]
fn datamark_rejects_aggregate_limit_and_rolls_back() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    assert_datamark_fails_pristine(
        &home,
        "limit",
        &[(
            "MAX_REGION_AGGREGATE_BYTES = 512L * 1024L * 1024L",
            "MAX_REGION_AGGREGATE_BYTES = 24L",
        )],
        "the aggregate region bytes exceed the limit",
    );
}

/// Removing the deadline gate after the final decompiler call and before its
/// temporary is published lets an expired export write a current completion
/// marker. The one-function fixture makes that final-operation boundary exact.
#[test]
fn export_rejects_deadline_expiry_after_final_decompile_operation() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let kit = generate_tame_kit(&home, "export_final_deadline");
    let seeded = tame_import(&home, &kit, true);
    assert!(
        seeded.contains("TameSeed: ok"),
        "seed run failed:\n{seeded}"
    );

    let script_path = kit.out.join("scripts/ExportDecomp.java");
    let script = std::fs::read_to_string(&script_path).unwrap();
    let final_operation = concat!(
        "                if (res != null && res.decompileCompleted() ",
        "&& res.getDecompiledFunction() != null) {\n",
    );
    assert_eq!(script.matches(final_operation).count(), 1);
    let deadline_fault = concat!(
        "                System.out.println(\"ExportDecompFinalOperationDeadlineFault: expired\");\n",
        "                deadline = System.currentTimeMillis();\n",
        "                if (res != null && res.decompileCompleted() ",
        "&& res.getDecompiledFunction() != null) {\n",
    );
    std::fs::write(
        &script_path,
        script.replacen(final_operation, deadline_fault, 1),
    )
    .unwrap();

    let root = std::fs::canonicalize(&kit.out).unwrap();
    let completion = kit.out.join("export/00_BOOT.complete");
    assert!(
        !completion.exists(),
        "fixture started with a completion marker"
    );
    let args: Vec<String> = [
        "-process".to_string(),
        "00_BOOT".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        kit.out
            .join("export/00_BOOT")
            .to_string_lossy()
            .into_owned(),
        root.to_string_lossy().into_owned(),
        "00_BOOT".to_string(),
        "none".to_string(),
        "-".to_string(),
        "none".to_string(),
        "-".to_string(),
        "-".to_string(),
        "-".to_string(),
        "none".to_string(),
    ]
    .into();
    let diagnostics = tame_stdout(&tame_headless(&home, &kit, &args));
    assert!(
        diagnostics
            .lines()
            .any(|line| line == "ExportDecompFinalOperationDeadlineFault: expired"),
        "deadline fault did not return from the final decompiler call:\n{diagnostics}"
    );
    assert!(
        diagnostics.contains("REPORT SCRIPT ERROR")
            && diagnostics.contains("the export verification deadline was exhausted"),
        "the expired final operation was accepted:\n{diagnostics}"
    );
    assert!(
        !kit.out.join("export/00_BOOT/decompiled.c").exists(),
        "the expired final operation published decompiled.c"
    );
    assert!(
        !completion.exists(),
        "the expired final operation published a current completion marker"
    );

    let _ = std::fs::remove_dir_all(&kit.dir);
}

// -------------------------------------------------------------------------
// Task 11: authenticated symbol pass 2 and export cutover
// -------------------------------------------------------------------------

/// The canonical pass-2 kit state: PAL applied, pass-1 export produced, and
/// the strict v3 map built from the retained tree with the registration-rank
/// rename of the alpha task primary.
struct Pass2Kit {
    kit: PalApplyKit,
    map_path: PathBuf,
    map_hash: String,
    functions_path: PathBuf,
    functions_hash: String,
    image_hash: String,
    execution_count: usize,
}

fn blake3_of(path: &std::path::Path) -> String {
    blake3::hash(&std::fs::read(path).unwrap()).to_string()
}

/// Builds the retained images tree and derives the strict v3 symbol map with
/// the PAL context from the fixture manifest geometry.
fn build_pal_pass2_kit(
    home: &std::path::Path,
    case: &str,
    image: &[u8],
    manifest_for: impl FnOnce(&str) -> String,
    seed: Option<&str>,
    export_pass1: bool,
) -> Pass2Kit {
    let kit = generate_pal_apply_kit_manifests(home, case, image, manifest_for);
    let manifest = std::fs::read_to_string(&kit.manifest_path).unwrap();
    let identity = kit.identity.clone();
    let scatter_hash = blake3_of(&kit.scatter_path);
    let import = pal_import(home, &kit, seed);
    assert!(
        !import.contains("REPORT SCRIPT ERROR"),
        "seeded import failed for {case}:\n{import}"
    );
    if let Some(script) = seed {
        assert!(
            import.contains(script.trim_end_matches(".java")),
            "seed {script:?} did not run for {case}:\n{import}"
        );
    }
    if export_pass1 {
        // One -process run applies PAL transactionally and exports pass 1
        // under the strict ten-argument contract.
        // The seed (pre-existing meaningful/coincident primaries) ran at
        // import time; this run only applies PAL and exports pass 1.
        let args: Vec<String> = [
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            kit.out.join("scripts").to_string_lossy().into_owned(),
            "-preScript".to_string(),
            "ApplyPalTasks.java".to_string(),
            kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".to_string(),
            kit.manifest_path.to_string_lossy().into_owned(),
            kit.scatter_path.to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "ExportDecomp.java".to_string(),
            kit.out
                .join("export/02_MAIN")
                .to_string_lossy()
                .into_owned(),
            kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".to_string(),
            "none".to_string(),
            "-".to_string(),
            kit.identity.clone(),
            kit.manifest_path.to_string_lossy().into_owned(),
            kit.scatter_path.to_string_lossy().into_owned(),
            "-".to_string(),
            "none".to_string(),
        ]
        .into();
        let exported = pal_headless(home, &kit, &args);
        let expected = if seed.is_some() {
            pal_expected_summary(&kit, 4, 2, 4, 2)
        } else {
            pal_expected_summary(&kit, 6, 0, 6, 0)
        };
        assert!(
            exported.contains(&expected),
            "pass-1 PAL application failed for {case}:\n{exported}"
        );
        assert!(
            !exported.contains("REPORT SCRIPT ERROR"),
            "pass-1 export failed for {case}:\n{exported}"
        );
        assert!(
            kit.out.join("export/02_MAIN/functions.json").exists(),
            "pass-1 export produced no functions.json for {case}"
        );
        assert_eq!(
            std::fs::read(kit.out.join("export/02_MAIN.complete")).unwrap(),
            pixel_modem_extractor::decompile::export_completion_marker(
                "none",
                &kit.identity,
                "none",
            ),
            "the pass-1 marker must bind the PAL identity and no symbol map"
        );
    }

    // The retained tree the map binds: exact raw image bytes, the
    // pass-1-exported functions.json (copied verbatim), and the scatter load
    // map in the terminal-tree convention (`<image>/scatter/`) so the runtime
    // authenticates the scatter-backed task execution.
    let tree = kit.dir.join("tree");
    let image_dir = tree.join("images/02_MAIN");
    std::fs::create_dir_all(image_dir.join("decompiled")).unwrap();
    std::fs::write(image_dir.join("02_MAIN.bin"), image).unwrap();
    copy_dir(&kit.out.join("scatter/02_MAIN"), &image_dir.join("scatter"));
    std::fs::copy(
        kit.out.join("export/02_MAIN/functions.json"),
        image_dir.join("decompiled/functions.json"),
    )
    .unwrap();
    std::fs::write(
        tree.join("manifest.json"),
        format!(
            r#"{{"toc":[{{"name":"MAIN","load_addr":{}}}]}}"#,
            pal_fixture::BASE
        ),
    )
    .unwrap();

    let mut applications = std::collections::BTreeMap::new();
    for (entry, isa, desired, tasks) in pal_fixture::extended_application_summaries() {
        let applied = std::fs::read(image_dir.join("decompiled/functions.json"))
            .map(|bytes| {
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|record| {
                        record["entry"].as_str() == Some(&format!("0x{entry:08x}"))
                            && record["name"].as_str() == Some(desired)
                    })
            })
            .unwrap_or(false);
        applications.insert(
            entry,
            pixel_modem_extractor::symbolicate::PalApplicationRef {
                isa,
                desired_primary: desired.to_string(),
                applied,
                tasks: tasks
                    .into_iter()
                    .map(|(index, name, slot, priority, stack)| {
                        pixel_modem_extractor::symbolicate::PalTaskRef {
                            manifest_blake3: blake3::hash(manifest.as_bytes()).to_string(),
                            task_index: index,
                            name: name.to_string(),
                            slot,
                            priority,
                            stack_size: stack,
                        }
                    })
                    .collect(),
            },
        );
    }
    let pal = pixel_modem_extractor::symbolicate::PalPass2Context {
        identity: identity.to_string(),
        manifest_blake3: blake3::hash(manifest.as_bytes()).to_string(),
        scatter_load_map_blake3: Some(scatter_hash.to_string()),
        applications,
    };
    let tokens = HashMap::new();
    let map_path = kit.out.join("symbol_maps/02_MAIN.json");
    std::fs::create_dir_all(map_path.parent().unwrap()).unwrap();
    let bundle = pixel_modem_extractor::symbolicate::prepare_pass2_symbol_map(
        &map_path,
        &image_dir,
        "02_MAIN",
        &tokens,
        &tree.join("manifest.json"),
        Some(&pal),
    )
    .unwrap();

    let functions_path = image_dir.join("decompiled/functions.json");
    Pass2Kit {
        map_hash: bundle.map.map_blake3.clone(),
        functions_hash: bundle.map.functions_blake3.clone(),
        functions_path,
        image_hash: blake3_of(&kit.kit_root.join("images/02_MAIN")),
        map_path,
        execution_count: bundle.map.execution_count,
        kit,
    }
}

/// Recursive directory copy for fixture trees.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let destination = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&destination).unwrap();
            copy_dir(&entry.path(), &destination);
        } else {
            std::fs::create_dir_all(to).unwrap();
            std::fs::copy(entry.path(), destination).unwrap();
        }
    }
}

/// A `-process` run driving ApplySymbols with its ten canonical arguments,
/// optionally followed by one extra post-script (with its own arguments) and
/// the pass-2 ExportDecomp.
fn pal_apply_symbols(
    home: &std::path::Path,
    state: &Pass2Kit,
    extra_post: Option<(&str, Vec<String>)>,
    with_export: bool,
) -> String {
    let kit = &state.kit;
    let mut args: Vec<String> = [
        "-process".to_string(),
        "02_MAIN".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "ApplySymbols.java".to_string(),
        kit.kit_root.to_string_lossy().into_owned(),
        "02_MAIN".to_string(),
        state.image_hash.clone(),
        kit.identity.clone(),
        kit.manifest_path.to_string_lossy().into_owned(),
        kit.scatter_path.to_string_lossy().into_owned(),
        state.functions_path.to_string_lossy().into_owned(),
        state.functions_hash.clone(),
        state.map_path.to_string_lossy().into_owned(),
        state.map_hash.clone(),
    ]
    .into();
    if let Some((script, script_args)) = extra_post {
        args.push("-postScript".to_string());
        args.push(script.to_string());
        args.extend(script_args);
    }
    if with_export {
        args.extend([
            "-postScript".to_string(),
            "ExportDecomp.java".to_string(),
            kit.out
                .join("export/02_MAIN")
                .to_string_lossy()
                .into_owned(),
            kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".to_string(),
            "none".to_string(),
            "-".to_string(),
            kit.identity.clone(),
            kit.manifest_path.to_string_lossy().into_owned(),
            kit.scatter_path.to_string_lossy().into_owned(),
            state.map_path.to_string_lossy().into_owned(),
            state.map_hash.clone(),
        ]);
    }
    pal_headless(home, kit, &args)
}

/// A `-process` run driving only ExportDecomp with explicit map arguments.
fn pal_export_only(home: &std::path::Path, state: &Pass2Kit, map: Option<(&str, &str)>) -> String {
    let kit = &state.kit;
    let (map_argument, map_hash) = match map {
        Some((path, hash)) => (path.to_string(), hash.to_string()),
        None => ("-".to_string(), "none".to_string()),
    };
    let args: Vec<String> = [
        "-process".to_string(),
        "02_MAIN".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        kit.out
            .join("export/02_MAIN")
            .to_string_lossy()
            .into_owned(),
        kit.kit_root.to_string_lossy().into_owned(),
        "02_MAIN".to_string(),
        "none".to_string(),
        "-".to_string(),
        kit.identity.clone(),
        kit.manifest_path.to_string_lossy().into_owned(),
        kit.scatter_path.to_string_lossy().into_owned(),
        map_argument,
        map_hash,
    ]
    .into();
    pal_headless(home, kit, &args)
}

fn pal_export_pass1_only(home: &std::path::Path, kit: &PalApplyKit) -> String {
    let args: Vec<String> = [
        "-process".to_string(),
        "02_MAIN".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        "ExportDecomp.java".to_string(),
        kit.out
            .join("export/02_MAIN")
            .to_string_lossy()
            .into_owned(),
        kit.kit_root.to_string_lossy().into_owned(),
        "02_MAIN".to_string(),
        "none".to_string(),
        "-".to_string(),
        kit.identity.clone(),
        kit.manifest_path.to_string_lossy().into_owned(),
        kit.scatter_path.to_string_lossy().into_owned(),
        "-".to_string(),
        "none".to_string(),
    ]
    .into();
    pal_headless(home, kit, &args)
}

/// Postflight inspector after a successful PAL-aware pass 2: the complete
/// applied state still validates, the alpha primary was renamed by its
/// registration evidence with the exact registry transition, the coincident
/// ANALYSIS beta and meaningful zeta primaries were preserved, the property
/// binds the exact v2 grammar, and every reserved label survived.
const INSPECT_PASS2_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class InspectPass2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 7) {
            throw new AssertionError("expected seven InspectPass2 arguments");
        }
        File kitRoot = new File(args[0]);
        String label = args[1];
        File palFile = new File(args[2]);
        File scatterFile = new File(args[3]);
        PalTasksSupport.PalManifest manifest =
                PalTasksSupport.readPal(kitRoot, label, palFile, scatterFile);
        String identity = PalTasksSupport.expectedPalIdentity(manifest);
        PalTasksSupport.AppliedState state =
                PalTasksSupport.validateApplied(currentProgram, manifest, identity);
        if (state.applications != 6 || state.palOwnedPrimaries != 3
                || state.preservedPrimaries != 2 || state.pass2OwnedPrimaries != 1
                || state.reservedLabels != 7) {
            throw new AssertionError("post-pass-2 dispositions are wrong: "
                    + state.palOwnedPrimaries + " pal_owned, "
                    + state.preservedPrimaries + " preserved, "
                    + state.pass2OwnedPrimaries + " pass2_owned");
        }

        FunctionManager functions = currentProgram.getFunctionManager();
        Function alpha = functions.getFunctionAt(toAddr(0x4001_0400L));
        if (alpha == null || !"alpha_task_fn".equals(alpha.getName())
                || alpha.getSymbol().getSource() != SourceType.USER_DEFINED) {
            throw new AssertionError("the registration rename of the pal_owned primary failed: "
                    + (alpha == null ? "missing" : alpha.getName()));
        }
        if (!alpha.getRepeatableComment().contains("task index=0 name=\"alpha\"")) {
            throw new AssertionError("the owned comment did not survive the stronger rename");
        }
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        PalTasksSupport.RegistryEntry entry =
                PalTasksSupport.parseRegistry(registry.getString(toAddr(0x4001_0400L)));
        if (!"pass2_owned".equals(entry.primaryDisposition)
                || !"user_defined".equals(entry.primarySource)
                || !entry.primaryNameBlake3.equals(
                        PalTasksSupport.primaryDigestHex("alpha_task_fn"))) {
            throw new AssertionError("the registry transition subrecord is wrong");
        }
        PalTasksSupport.RegistryEntry beta =
                PalTasksSupport.parseRegistry(registry.getString(toAddr(0x4001_0410L)));
        if (!"preserved".equals(beta.primaryDisposition)) {
            throw new AssertionError("the coincident ANALYSIS beta was reclassified");
        }
        Function betaFunction = functions.getFunctionAt(toAddr(0x4001_0410L));
        if (!"pal_TaskEntry_beta".equals(betaFunction.getName())
                || betaFunction.getSymbol().getSource() != SourceType.ANALYSIS) {
            throw new AssertionError("the coincident ANALYSIS primary changed");
        }
        Function zeta = functions.getFunctionAt(toAddr(0x4001_0438L));
        if (!"zetaKeptName".equals(zeta.getName())
                || zeta.getSymbol().getSource() != SourceType.USER_DEFINED) {
            throw new AssertionError("the meaningful primary did not survive pass 2");
        }
        PalTasksSupport.RegistryEntry zetaEntry =
                PalTasksSupport.parseRegistry(registry.getString(toAddr(0x4001_0438L)));
        if (!"preserved".equals(zetaEntry.primaryDisposition)) {
            throw new AssertionError("the meaningful primary was reclassified");
        }
        if (!functions.getFunctionAt(toAddr(0x4001_0430L)).getName()
                .equals("pal_TaskEntry_shared_40010430")) {
            throw new AssertionError("the shared neutral primary changed");
        }
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
        int labels = 0;
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(namespace);
        while (symbols.hasNext()) {
            symbols.next();
            labels++;
        }
        if (labels != 7) {
            throw new AssertionError("a reserved label did not survive pass 2: " + labels);
        }
        String property = currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString(PalTasksSupport.SYMBOL_PASS2_PROPERTY, null);
        String expected = "v2:" + args[4] + ":" + args[5] + ":" + args[6];
        if (!expected.equals(property)) {
            throw new AssertionError("the SymbolPass2 property is " + property
                    + ", expected " + expected);
        }
        System.out.println("InspectPass2: ok");
    }
}
"#;

/// Seeds a stale, different prior SymbolPass2 property.
const PAL_SEED_STALE_PASS2_PROPERTY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class SeedStalePass2Property extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getOptions(Program.PROGRAM_INFO).setString(
                PalTasksSupport.SYMBOL_PASS2_PROPERTY,
                "v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:9:9");
        System.out.println("SeedStalePass2Property: ok");
    }
}
"#;

/// Clears the SymbolPass2 property (test tooling between rejection cases).
const PAL_SEED_CLEAR_PASS2_PROPERTY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class SeedClearPass2Property extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getOptions(Program.PROGRAM_INFO)
                .putObject("PixelModemExtractor.SymbolPass2", null);
        System.out.println("SeedClearPass2Property: ok");
    }
}
"#;

/// Renames the alpha primary so the retained map's original no longer matches
/// (the changed-primary rejection).
const PAL_SEED_RENAME_ALPHA_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;

public class SeedRenameAlpha extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function alpha = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x4001_0400L));
        if (alpha == null) {
            throw new AssertionError("rename seed lost the alpha function");
        }
        alpha.setName("drifted_alpha_name", SourceType.USER_DEFINED);
        // Keep the registry self-consistent with the drift so the rejection
        // under test is ApplySymbols' retained-original binding, not the
        // shared registry validator.
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        PalTasksSupport.RegistryEntry previous = PalTasksSupport.parseRegistry(
                registry.getString(alpha.getEntryPoint()));
        registry.add(alpha.getEntryPoint(), PalTasksSupport.registryValue(
                new PalTasksSupport.RegistryEntry(
                        previous.manifestBlake3, previous.isa, previous.functionId,
                        previous.functionDisposition, previous.commentBlake3,
                        previous.primaryDisposition, previous.primarySymbolId,
                        "user_defined",
                        PalTasksSupport.primaryDigestHex("drifted_alpha_name"),
                        previous.labelCount, previous.labelsBlake3)));
        System.out.println("SeedRenameAlpha: ok");
    }
}
"#;

/// Changes only the alpha primary's source (same name, USER_DEFINED) so the
/// retained map's original-source binding rejects it (the changed-source
/// rejection).
const PAL_SEED_CHANGE_ALPHA_SOURCE_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;

public class SeedChangeAlphaSource extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function alpha = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x4001_0400L));
        if (alpha == null) {
            throw new AssertionError("source-change seed lost the alpha function");
        }
        String name = alpha.getName();
        alpha.setName(name, SourceType.USER_DEFINED);
        // Keep the registry self-consistent with the source drift so the
        // rejection under test is ApplySymbols' retained-original binding,
        // not the shared registry validator.
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        PalTasksSupport.RegistryEntry previous = PalTasksSupport.parseRegistry(
                registry.getString(alpha.getEntryPoint()));
        registry.add(alpha.getEntryPoint(), PalTasksSupport.registryValue(
                new PalTasksSupport.RegistryEntry(
                        previous.manifestBlake3, previous.isa, previous.functionId,
                        previous.functionDisposition, previous.commentBlake3,
                        previous.primaryDisposition, previous.primarySymbolId,
                        "user_defined",
                        PalTasksSupport.primaryDigestHex(name),
                        previous.labelCount, previous.labelsBlake3)));
        System.out.println("SeedChangeAlphaSource: ok");
    }
}
"#;

/// Clears the first instruction of the alpha body so its authenticated decode
/// projection no longer matches the retained map (the changed-body rejection).
const PAL_SEED_CLEAR_ALPHA_BODY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;

public class SeedClearAlphaBody extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getListing().clearCodeUnits(toAddr(0x4001_0400L), toAddr(0x4001_0403L), false);
        System.out.println("SeedClearAlphaBody: ok");
    }
}
"#;

/// Mode-driven corruption seed for the export postflight battery. Each mode
/// first restores the pristine applied state (as PalSupportProbe proved
/// restorable) and then applies exactly one corruption.
const PAL_SEED_CORRUPT_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.StringPropertyMap;
import java.util.ArrayList;
import java.util.List;

public class SeedCorrupt extends GhidraScript {
    private static final long ALPHA = 0x4001_0400L;

    private StringPropertyMap registry() throws Exception {
        StringPropertyMap map = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap(PalTasksSupport.OWNERSHIP_MAP);
        if (map == null) {
            throw new AssertionError("corrupt seed requires an applied registry");
        }
        return map;
    }

    private void restoreRegistryLabels(Address entry) throws Exception {
        StringPropertyMap registry = registry();
        PalTasksSupport.RegistryEntry previous =
                PalTasksSupport.parseRegistry(registry.getString(entry));
        List<PalTasksSupport.LabelEntry> current = new ArrayList<>();
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
        ghidra.program.model.symbol.SymbolIterator iterator =
                currentProgram.getSymbolTable().getSymbols(namespace);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol.getAddress().equals(entry)) {
                current.add(new PalTasksSupport.LabelEntry(symbol.getID(), symbol.getName()));
            }
        }
        registry.add(entry, PalTasksSupport.registryValue(new PalTasksSupport.RegistryEntry(
                previous.manifestBlake3, previous.isa, previous.functionId,
                previous.functionDisposition, previous.commentBlake3,
                previous.primaryDisposition, previous.primarySymbolId, previous.primarySource,
                previous.primaryNameBlake3, current.size(),
                PalTasksSupport.labelsDigestHex(current))));
    }

    private void restoreBaseline() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        Function alpha = functions.getFunctionAt(toAddr(ALPHA));
        if (alpha == null) {
            alpha = createFunction(toAddr(ALPHA), null);
        }
        if (!"pal_TaskEntry_alpha".equals(alpha.getName())) {
            alpha.setName("pal_TaskEntry_alpha", SourceType.ANALYSIS);
        }
        if (currentProgram.getListing().getInstructionAt(toAddr(ALPHA)) == null) {
            disassemble(toAddr(ALPHA));
        }
        alpha.setRepeatableComment(alpha.getRepeatableComment());
        restoreRegistryLabels(toAddr(ALPHA));
        // Remove any stray reserved-namespace label outside the registry.
        StringPropertyMap registry = registry();
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
        if (namespace != null) {
            List<Symbol> strangers = new ArrayList<>();
            ghidra.program.model.symbol.SymbolIterator symbols =
                    currentProgram.getSymbolTable().getSymbols(namespace);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (registry.getString(symbol.getAddress()) == null) {
                    strangers.add(symbol);
                }
            }
            for (Symbol stranger : strangers) {
                stranger.delete();
            }
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new AssertionError("expected the corruption mode argument");
        }
        String mode = args[0];
        if (!"remove_function".equals(mode)) {
            restoreBaseline();
        }
        SymbolTable symbols = currentProgram.getSymbolTable();
        FunctionManager functions = currentProgram.getFunctionManager();
        switch (mode) {
            case "remove_function":
                Function alpha = functions.getFunctionAt(toAddr(ALPHA));
                if (alpha == null) {
                    throw new AssertionError("corrupt seed lost the alpha function");
                }
                functions.removeFunction(toAddr(ALPHA));
                break;
            case "delete_label": {
                Namespace namespace = symbols.getNamespace(
                        PalTasksSupport.RESERVED_NAMESPACE, currentProgram.getGlobalNamespace());
                Symbol label = symbols.getSymbol("pal_TaskEntry_alpha", toAddr(ALPHA), namespace);
                if (label == null) {
                    throw new AssertionError("corrupt seed lost the alpha label");
                }
                label.delete();
                break;
            }
            case "tamper_registry": {
                StringPropertyMap registry = registry();
                String value = registry.getString(toAddr(ALPHA));
                char digit = value.charAt(3);
                char flipped = digit == '0' ? '1' : '0';
                registry.add(toAddr(ALPHA),
                        value.substring(0, 3) + flipped + value.substring(4));
                break;
            }
            case "edit_comment": {
                Function fn = functions.getFunctionAt(toAddr(ALPHA));
                String comment = fn.getRepeatableComment();
                fn.setRepeatableComment(comment.replace("priority=100", "priority=101"));
                break;
            }
            case "rename_primary": {
                Function fn = functions.getFunctionAt(toAddr(ALPHA));
                fn.setName("probe_drifted_name", SourceType.USER_DEFINED);
                break;
            }
            case "corrupt_task_bytes": {
                // Corrupt the alpha task entry's instruction extent: the
                // applied registry and function stay intact, so the
                // export-side re-validation alone must catch the drifted
                // task bytes (the apply-side instruction-blake3 check is
                // not on this path).
                currentProgram.getListing()
                        .clearCodeUnits(toAddr(ALPHA), toAddr(ALPHA + 3), false);
                break;
            }
            case "orphan_label": {
                Namespace namespace = symbols.getNamespace(
                        PalTasksSupport.RESERVED_NAMESPACE,
                        currentProgram.getGlobalNamespace());
                if (namespace == null) {
                    throw new AssertionError("corrupt seed lost the reserved namespace");
                }
                symbols.createLabel(toAddr(0x4001_0480L), "pal_TaskEntry_stranger", namespace,
                        SourceType.ANALYSIS);
                break;
            }
            default:
                throw new AssertionError("unknown corruption mode " + mode);
        }
        System.out.println("SeedCorrupt: " + mode + " ok");
    }
}
"#;

/// The end-to-end PAL-aware pass-2 battery: the registration-rank rename of
/// the registry-bound alpha primary, preservation of the meaningful and
/// coincident primaries, idempotent replay, and the preflight rejection
/// matrix (argument contract, stale hashes, tampered decisions, changed
/// bodies/primaries, prior property, unauthorized disposition) with a
/// rollback after several mutations.
#[test]
fn apply_symbols_pal_ownership_transitions_are_transactional() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let image = pal_fixture::craft_main_image();

    for (name, source) in [
        ("InspectPass2.java", INSPECT_PASS2_JAVA),
        (
            "SeedStalePass2Property.java",
            PAL_SEED_STALE_PASS2_PROPERTY_JAVA,
        ),
        (
            "SeedClearPass2Property.java",
            PAL_SEED_CLEAR_PASS2_PROPERTY_JAVA,
        ),
        ("SeedRenameAlpha.java", PAL_SEED_RENAME_ALPHA_JAVA),
        ("SeedClearAlphaBody.java", PAL_SEED_CLEAR_ALPHA_BODY_JAVA),
        (
            "SeedChangeAlphaSource.java",
            PAL_SEED_CHANGE_ALPHA_SOURCE_JAVA,
        ),
    ] {
        std::fs::write(
            {
                // Staged later per kit; written into every kit's scripts dir.
                let dir =
                    std::env::temp_dir().join(format!("pme_task11_scripts_{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                dir.join(name)
            },
            source,
        )
        .unwrap();
    }
    let script_staging =
        std::env::temp_dir().join(format!("pme_task11_scripts_{}", std::process::id()));

    // --- The success path -----------------------------------------------
    let state = build_pal_pass2_kit(
        &home,
        "pass2_ok",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        Some("PalSeedMeaningful.java"),
        true,
    );
    for name in [
        "InspectPass2.java",
        "SeedStalePass2Property.java",
        "SeedClearPass2Property.java",
        "SeedRenameAlpha.java",
        "SeedClearAlphaBody.java",
    ] {
        std::fs::copy(
            script_staging.join(name),
            state.kit.out.join("scripts").join(name),
        )
        .unwrap();
    }

    // The map itself carries the exact PAL binding and the authorized
    // transition on the registration rename.
    let map_text = std::fs::read_to_string(&state.map_path).unwrap();
    assert!(map_text.contains("\"format\": \"pixel-modem-extractor-symbol-map-v3\""));
    assert!(map_text.contains(&format!("\"identity\": \"{}\"", state.kit.identity)));
    assert!(map_text.contains("\"from\": \"pal_owned\""));
    assert!(map_text.contains("\"to\": \"pass2_owned\""));

    let first = pal_apply_symbols(
        &home,
        &state,
        Some((
            "InspectPass2.java",
            vec![
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".to_string(),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                state.map_hash.clone(),
                state.functions_hash.clone(),
                state.execution_count.to_string(),
            ],
        )),
        true,
    );
    assert!(
        first.contains("InspectPass2: ok"),
        "pass-2 application/inspection failed:\n{first}"
    );
    assert!(
        first.contains("ApplySymbols: image=02_MAIN applied 1 names"),
        "unexpected pass-2 summary:\n{first}"
    );
    // The pass-2 export published under the v4 marker binding PAL and map.
    assert_eq!(
        std::fs::read(state.kit.out.join("export/02_MAIN.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            "none",
            &state.kit.identity,
            &state.map_hash
        )
    );

    // Idempotent replay: the identical map re-applies with zero renames and
    // the same property.
    let replay = pal_apply_symbols(
        &home,
        &state,
        Some((
            "InspectPass2.java",
            vec![
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".to_string(),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                state.map_hash.clone(),
                state.functions_hash.clone(),
                state.execution_count.to_string(),
            ],
        )),
        true,
    );
    assert!(
        replay.contains("ApplySymbols: image=02_MAIN applied 0 names"),
        "replay summary mismatch:\n{replay}"
    );
    assert!(
        replay.contains("InspectPass2: ok"),
        "replay inspection failed:\n{replay}"
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);

    // --- The rejection matrix (all preflight, no state change) ----------
    let state = build_pal_pass2_kit(
        &home,
        "pass2_reject",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        None,
        true,
    );
    for name in [
        "SeedStalePass2Property.java",
        "SeedClearPass2Property.java",
        "SeedRenameAlpha.java",
        "SeedClearAlphaBody.java",
        "SeedChangeAlphaSource.java",
    ] {
        std::fs::copy(
            script_staging.join(name),
            state.kit.out.join("scripts").join(name),
        )
        .unwrap();
    }
    let functions_arg = state.functions_path.to_string_lossy().into_owned();
    let map_arg = state.map_path.to_string_lossy().into_owned();
    let cases: Vec<(Vec<String>, &str)> = vec![
        // Malformed ten-arg input: nine arguments.
        (
            vec![
                "-postScript".into(),
                "ApplySymbols.java".into(),
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".into(),
                state.image_hash.clone(),
                state.kit.identity.clone(),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                functions_arg.clone(),
                state.functions_hash.clone(),
                map_arg.clone(),
            ],
            "expected exactly ten arguments",
        ),
        // Stale image BLAKE3.
        (
            vec![
                "-postScript".into(),
                "ApplySymbols.java".into(),
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".into(),
                "0".repeat(64),
                state.kit.identity.clone(),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                functions_arg.clone(),
                state.functions_hash.clone(),
                map_arg.clone(),
                state.map_hash.clone(),
            ],
            "image BLAKE3 does not match the symbol map",
        ),
        // Stale PAL identity argument: a well-formed v1 identity that is
        // not the manifest's own (a direct argument rejection, never a
        // silent override).
        (
            vec![
                "-postScript".into(),
                "ApplySymbols.java".into(),
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".into(),
                state.image_hash.clone(),
                format!("v1:{}:9:9", "b".repeat(64)),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                functions_arg.clone(),
                state.functions_hash.clone(),
                map_arg.clone(),
                state.map_hash.clone(),
            ],
            "the expected PAL identity does not match the manifest",
        ),
        // Stale functions BLAKE3.
        (
            vec![
                "-postScript".into(),
                "ApplySymbols.java".into(),
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".into(),
                state.image_hash.clone(),
                state.kit.identity.clone(),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                functions_arg.clone(),
                "0".repeat(64),
                map_arg.clone(),
                state.map_hash.clone(),
            ],
            "functions.json BLAKE3 does not match",
        ),
        // Stale map BLAKE3.
        (
            vec![
                "-postScript".into(),
                "ApplySymbols.java".into(),
                state.kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".into(),
                state.image_hash.clone(),
                state.kit.identity.clone(),
                state.kit.manifest_path.to_string_lossy().into_owned(),
                state.kit.scatter_path.to_string_lossy().into_owned(),
                functions_arg.clone(),
                state.functions_hash.clone(),
                map_arg.clone(),
                "0".repeat(64),
            ],
            "symbol map BLAKE3 does not match",
        ),
    ];
    for (mut tail, expected) in cases {
        let mut args: Vec<String> = [
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
        ]
        .into();
        args.append(&mut tail);
        let failed = pal_headless(&home, &state.kit, &args);
        assert!(
            failed.contains("REPORT SCRIPT ERROR") && failed.contains(expected),
            "rejection case missed {expected:?}:\n{failed}"
        );
    }

    // A dangling decision (an execution index beyond the map's executions)
    // is a strict-parse failure; a duplicate decision the same way.
    {
        let needle = "\"execution\": 1,\n      \"original_primary\"";
        let expected = "symbol decisions are not the exact execution order";
        let tampered_path = state.kit.out.join("symbol_maps/tampered.json");
        let mut text = map_text.clone();
        assert!(
            text.matches(needle).count() >= 1,
            "tamper anchor {needle:?} not found"
        );
        text = text.replacen(needle, "\"execution\": 9,\n      \"original_primary\"", 1);
        std::fs::write(&tampered_path, text).unwrap();
        let tampered_arg = tampered_path.to_string_lossy().into_owned();
        let args: Vec<String> = [
            "-process".into(),
            "02_MAIN".into(),
            "-noanalysis".into(),
            "-scriptPath".into(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".into(),
            "ApplySymbols.java".into(),
            state.kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".into(),
            state.image_hash.clone(),
            state.kit.identity.clone(),
            state.kit.manifest_path.to_string_lossy().into_owned(),
            state.kit.scatter_path.to_string_lossy().into_owned(),
            functions_arg.clone(),
            state.functions_hash.clone(),
            tampered_arg,
            blake3_of(&tampered_path),
        ]
        .into();
        let failed = pal_headless(&home, &state.kit, &args);
        assert!(
            failed.contains("REPORT SCRIPT ERROR") && failed.contains(expected),
            "tampered-decision case missed {expected:?}:\n{failed}"
        );
        // A duplicated decision (the index repeated) fails the same way.
        let duplicated_path = state.kit.out.join("symbol_maps/duplicated.json");
        let mut text = map_text.clone();
        assert!(
            text.matches(needle).count() >= 1,
            "duplicate anchor not found"
        );
        text = text.replacen(needle, "\"execution\": 0,\n      \"original_primary\"", 1);
        std::fs::write(&duplicated_path, text).unwrap();
        let duplicated_arg = duplicated_path.to_string_lossy().into_owned();
        let args: Vec<String> = [
            "-process".into(),
            "02_MAIN".into(),
            "-noanalysis".into(),
            "-scriptPath".into(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".into(),
            "ApplySymbols.java".into(),
            state.kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".into(),
            state.image_hash.clone(),
            state.kit.identity.clone(),
            state.kit.manifest_path.to_string_lossy().into_owned(),
            state.kit.scatter_path.to_string_lossy().into_owned(),
            functions_arg.clone(),
            state.functions_hash.clone(),
            duplicated_arg,
            blake3_of(&duplicated_path),
        ]
        .into();
        let failed = pal_headless(&home, &state.kit, &args);
        assert!(
            failed.contains("REPORT SCRIPT ERROR") && failed.contains(expected),
            "duplicate-decision case missed {expected:?}:\n{failed}"
        );
    }

    // A different prior SymbolPass2 property is stale, never overwritten.
    let seeded = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "SeedStalePass2Property.java".to_string(),
        ],
    );
    assert!(
        seeded.contains("SeedStalePass2Property: ok"),
        "stale-property seed did not run:\n{seeded}"
    );
    let failed = pal_apply_symbols(&home, &state, None, false);
    assert!(
        failed.contains("stale SymbolPass2 property"),
        "a different prior property was not rejected:\n{failed}"
    );
    // Clear the stale property so the remaining cases run from absence.
    let cleared = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "SeedClearPass2Property.java".to_string(),
        ],
    );
    assert!(
        cleared.contains("SeedClearPass2Property: ok"),
        "property-clear seed did not run:\n{cleared}"
    );

    // A changed current primary (renamed after pass 1) fails the retained
    // map's original binding.
    let seeded = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "SeedRenameAlpha.java".to_string(),
        ],
    );
    assert!(
        seeded.contains("SeedRenameAlpha: ok"),
        "rename seed did not run:\n{seeded}"
    );
    let failed = pal_apply_symbols(&home, &state, None, false);
    assert!(
        failed.contains("current primary changed")
            || failed.contains("primary symbol binding does not match the registry")
            || failed.contains("no longer carries the desired task name"),
        "a changed primary was not rejected:\n{failed}"
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);

    // A changed primary SOURCE (the same name re-applied as USER_DEFINED)
    // fails the retained map's original-source binding.
    let state = build_pal_pass2_kit(
        &home,
        "pass2_source",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        None,
        true,
    );
    std::fs::copy(
        script_staging.join("SeedChangeAlphaSource.java"),
        state.kit.out.join("scripts/SeedChangeAlphaSource.java"),
    )
    .unwrap();
    let seeded = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "SeedChangeAlphaSource.java".to_string(),
        ],
    );
    assert!(
        seeded.contains("SeedChangeAlphaSource: ok"),
        "source-change seed did not run:\n{seeded}"
    );
    let failed = pal_apply_symbols(&home, &state, None, false);
    assert!(
        failed.contains("the current primary changed")
            || failed.contains("primary symbol binding does not match the registry"),
        "a changed primary source was not rejected:\n{failed}"
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);

    // A changed current body (cleared instruction bytes) fails the map's
    // authenticated execution identity.
    let state = build_pal_pass2_kit(
        &home,
        "pass2_body",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        None,
        true,
    );
    std::fs::copy(
        script_staging.join("SeedClearAlphaBody.java"),
        state.kit.out.join("scripts/SeedClearAlphaBody.java"),
    )
    .unwrap();
    let seeded = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "SeedClearAlphaBody.java".to_string(),
        ],
    );
    assert!(
        seeded.contains("SeedClearAlphaBody: ok"),
        "body seed did not run:\n{seeded}"
    );
    let failed = pal_apply_symbols(&home, &state, None, false);
    assert!(
        failed.contains("decode projection")
            || failed.contains("decode range")
            || failed.contains("no instruction exists at the task entry")
            || failed.contains("quarantined"),
        "a changed body was not rejected:\n{failed}"
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);

    // --- Rollback after several mutations -------------------------------
    let state = build_pal_pass2_kit(
        &home,
        "pass2_rollback",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        Some("PalSeedMeaningful.java"),
        true,
    );
    patch_apply_symbols_script(
        &state.kit.out,
        &[(
            "                comments++;",
            concat!(
                "                comments++;",
                "\n                    if (comments == 1) {",
                "\n                        throw new IllegalStateException(",
                "\n                                \"injected pass-2 failure after several mutations\");",
                "\n                    }"
            ),
        )],
    );
    let failed = pal_apply_symbols(&home, &state, None, false);
    assert!(
        failed.contains("injected pass-2 failure after several mutations"),
        "injected pass-2 failure did not fire:\n{failed}"
    );
    // The applied PAL state is completely undisturbed: names, labels,
    // comments, registry, and no pass-2 property.
    let inspected = pal_apply(&home, &state.kit, Some("InspectApplied.java"));
    assert!(
        inspected.contains("InspectApplied: ok"),
        "a failed pass 2 left partial state:\n{inspected}"
    );
    let property_probe = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class ProbeProperty extends GhidraScript {
    @Override
    public void run() throws Exception {
        System.out.println("ProbeProperty: " + currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString("PixelModemExtractor.SymbolPass2", null));
    }
}
"#;
    std::fs::write(
        state.kit.out.join("scripts/ProbeProperty.java"),
        property_probe,
    )
    .unwrap();
    let probed = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "ProbeProperty.java".to_string(),
        ],
    );
    assert!(
        probed.contains("ProbeProperty: null"),
        "a failed pass 2 left the property set:\n{probed}"
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);

    // --- Unauthorized disposition: a hand-crafted map renaming the
    // registry-preserved meaningful zeta primary (no transition, the exact
    // shape the Rust writer never emits) ------------------------------------
    {
        let state = build_pal_pass2_kit(
            &home,
            "pass2_unauthorized",
            &image,
            |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
            Some("PalSeedMeaningful.java"),
            true,
        );
        let unauthorized_path = state.kit.out.join("symbol_maps/unauthorized.json");
        let mut text = std::fs::read_to_string(&state.map_path).unwrap();
        let final_needle = "\"final_primary\": \"zetaKeptName\"";
        let action_needle = "\"final_source\": \"user_defined\",\n      \"action\": \"preserve\"";
        assert_eq!(text.matches(final_needle).count(), 1);
        assert_eq!(text.matches(action_needle).count(), 1);
        text = text.replacen(final_needle, "\"final_primary\": \"zeta_task_fn\"", 1);
        text = text.replacen(
            action_needle,
            "\"final_source\": \"user_defined\",\n      \"action\": \"rename\"",
            1,
        );
        std::fs::write(&unauthorized_path, text).unwrap();
        let unauthorized = Pass2Kit {
            map_path: unauthorized_path.clone(),
            map_hash: blake3_of(&unauthorized_path),
            kit: state.kit.clone(),
            functions_path: state.functions_path.clone(),
            functions_hash: state.functions_hash.clone(),
            image_hash: state.image_hash.clone(),
            execution_count: state.execution_count,
        };
        let failed = pal_apply_symbols(&home, &unauthorized, None, false);
        assert!(
            failed.contains("registry preserved primary is not replaceable"),
            "an unauthorized disposition was not rejected:\n{failed}"
        );
        let inspected = pal_apply(&home, &state.kit, Some("InspectApplied.java"));
        assert!(
            inspected.contains("InspectApplied: ok"),
            "the rejected map disturbed the applied state:\n{inspected}"
        );
        let _ = std::fs::remove_dir_all(&state.kit.dir);
    }
    let _ = std::fs::remove_dir_all(&script_staging);
}

/// The v4 marker binds exception roots, PAL, and map exactly: pass 1 writes
/// `exception_roots=none`/`pal_tasks=<identity>`/`symbol_map=none`, pass 2 the
/// exact map BLAKE3, and the stale-input rejections (wrong map hash, map-less
/// run under a set property, identity none under an applied state) never
/// publish.
#[test]
fn export_pal_postflight_writes_v4_marker_and_rejects_stale_inputs() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let image = pal_fixture::craft_main_image();
    let state = build_pal_pass2_kit(
        &home,
        "export_marker",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        None,
        true,
    );

    // Pass 1 marker: identity bound, no symbol map.
    assert_eq!(
        std::fs::read(state.kit.out.join("export/02_MAIN.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            "none",
            &state.kit.identity,
            "none",
        )
    );

    // Pass 2: ApplySymbols then the map-bound export; the marker now carries
    // the exact lowercase map BLAKE3.
    let applied = pal_apply_symbols(&home, &state, None, true);
    assert!(
        !applied.contains("REPORT SCRIPT ERROR"),
        "pass-2 export failed:\n{applied}"
    );
    assert!(applied.contains("ApplySymbols: image=02_MAIN applied"));
    assert_eq!(
        std::fs::read(state.kit.out.join("export/02_MAIN.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            "none",
            &state.kit.identity,
            &state.map_hash
        )
    );
    let export_dir = state.kit.out.join("export/02_MAIN");
    for name in ["functions.json", "disasm.lst", "decompiled.c"] {
        assert!(export_dir.join(name).is_file(), "{name} missing");
    }

    // A wrong expected map hash never publishes a new export.
    let map_arg = state.map_path.to_string_lossy().into_owned();
    let wrong = pal_export_only(&home, &state, Some((&map_arg, &"0".repeat(64))));
    assert!(
        wrong.contains("REPORT SCRIPT ERROR")
            && wrong.contains("symbol map BLAKE3 does not match the expected value"),
        "a stale map hash was not rejected:\n{wrong}"
    );
    // A map-less export under the set property is rejected.
    let dashed = pal_export_only(&home, &state, None);
    assert!(
        dashed.contains("REPORT SCRIPT ERROR")
            && dashed.contains("requires the SymbolPass2 property absent"),
        "a pass-1 export under a set property was not rejected:\n{dashed}"
    );
    // Identity none under the applied PAL state scans every detectable
    // surface and fails.
    let none_identity = {
        let kit = &state.kit;
        let args: Vec<String> = [
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "ExportDecomp.java".to_string(),
            kit.out
                .join("export/02_MAIN")
                .to_string_lossy()
                .into_owned(),
            kit.kit_root.to_string_lossy().into_owned(),
            "02_MAIN".to_string(),
            "none".to_string(),
            "-".to_string(),
            "none".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "none".to_string(),
        ]
        .into();
        pal_headless(&home, kit, &args)
    };
    assert!(
        none_identity.contains("REPORT SCRIPT ERROR")
            && none_identity.contains("PAL property is not absent or none"),
        "identity none did not scan the applied surfaces:\n{none_identity}"
    );
    // None of the rejected runs republished the export: the marker still
    // binds the pass-2 values.
    assert_eq!(
        std::fs::read(state.kit.out.join("export/02_MAIN.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            "none",
            &state.kit.identity,
            &state.map_hash
        )
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);
}

/// The export postflight re-validates the complete PAL state: a removed task
/// function, a deleted reserved label, a tampered registry, an edited owned
/// comment, a renamed task primary, an orphan reserved label, a corrupted
/// task entry byte extent, a drifted
/// non-task body under the pass-2 comparison, and the task-body/deadline
/// limits each fail before any output is published.
#[test]
fn export_pal_postflight_rejects_program_drift() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };
    let image = pal_fixture::craft_main_image();
    let corrupt_dir = {
        let staging =
            std::env::temp_dir().join(format!("pme_task11_corrupt_{}", std::process::id()));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("SeedCorrupt.java"), PAL_SEED_CORRUPT_JAVA).unwrap();
        staging
    };

    // Each corruption mutates the applied state in its own kit; every run
    // drives the pass-1-style export (identity present, no map).
    for (case, mode, expected) in [
        (
            "remove_function",
            "remove_function",
            "no function at its entry",
        ),
        (
            "delete_label",
            "delete_label",
            "the reserved label set does not match",
        ),
        (
            "tamper_registry",
            "tamper_registry",
            "registry entry binds a different manifest",
        ),
        (
            "edit_comment",
            "edit_comment",
            "owned comment digest does not match the registry",
        ),
        (
            "rename_primary",
            "rename_primary",
            "primary symbol binding does not match the registry",
        ),
        (
            "corrupt_task_bytes",
            "corrupt_task_bytes",
            "no instruction exists at the task entry",
        ),
        (
            "orphan_label",
            "orphan_label",
            "an unregistered reserved label is stale state",
        ),
    ] {
        let state = build_pal_pass2_kit(
            &home,
            &format!("drift_{case}"),
            &image,
            |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
            None,
            true,
        );
        std::fs::copy(
            corrupt_dir.join("SeedCorrupt.java"),
            state.kit.out.join("scripts/SeedCorrupt.java"),
        )
        .unwrap();
        let kit = &state.kit;
        let failed = pal_headless(
            &home,
            kit,
            &[
                "-process".to_string(),
                "02_MAIN".to_string(),
                "-noanalysis".to_string(),
                "-scriptPath".to_string(),
                kit.out.join("scripts").to_string_lossy().into_owned(),
                "-postScript".to_string(),
                "SeedCorrupt.java".to_string(),
                mode.to_string(),
                "-postScript".to_string(),
                "ExportDecomp.java".to_string(),
                kit.out
                    .join("export/02_MAIN")
                    .to_string_lossy()
                    .into_owned(),
                kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".to_string(),
                "none".to_string(),
                "-".to_string(),
                kit.identity.clone(),
                kit.manifest_path.to_string_lossy().into_owned(),
                kit.scatter_path.to_string_lossy().into_owned(),
                "-".to_string(),
                "none".to_string(),
            ],
        );
        assert!(
            failed.contains("REPORT SCRIPT ERROR") && failed.contains(expected),
            "corruption {case} missed {expected:?}:\n{failed}"
        );
        let _ = std::fs::remove_dir_all(&state.kit.dir);
    }

    // A drifted body under the pass-2 comparison: seed a fresh non-task
    // function after pass 2; every current function must match the map
    // exactly, so the export fails.
    let state = build_pal_pass2_kit(
        &home,
        "drift_pass2_body",
        &image,
        |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
        None,
        true,
    );
    std::fs::write(
        state.kit.out.join("scripts/SeedExtraFunction.java"),
        r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class SeedExtraFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        disassemble(toAddr(0x4001_0500L));
        Function created = createFunction(toAddr(0x4001_0500L), "drift_extra_fn");
        if (created == null) {
            throw new AssertionError("extra-function seed failed");
        }
        created.getSymbol().setSource(SourceType.USER_DEFINED);
        System.out.println("SeedExtraFunction: ok");
    }
}

"#,
    )
    .unwrap();
    let applied = pal_apply_symbols(&home, &state, None, false);
    assert!(
        !applied.contains("REPORT SCRIPT ERROR"),
        "pass-2 application failed:\n{applied}"
    );
    let seeded = pal_headless(
        &home,
        &state.kit,
        &[
            "-process".to_string(),
            "02_MAIN".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            state.kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "SeedExtraFunction.java".to_string(),
        ],
    );
    assert!(
        seeded.contains("SeedExtraFunction: ok"),
        "extra-function seed did not run:\n{seeded}"
    );
    let map_arg = state.map_path.to_string_lossy().into_owned();
    let map_hash = state.map_hash.clone();
    let failed = pal_export_only(&home, &state, Some((&map_arg, &map_hash)));
    assert!(
        failed.contains("REPORT SCRIPT ERROR")
            && (failed.contains("no pass-1 execution identity")
                || failed.contains("drifted from the pass-1 identity")),
        "a drifted body was not rejected under the pass-2 comparison:\n{failed}"
    );
    let _ = std::fs::remove_dir_all(&state.kit.dir);

    // The task-body and deadline limits fail before publication (patched
    // constants; the program state itself is pristine).
    for (case, patches, expected) in [
        (
            "body_limit",
            [(
                "TASK_BODY_BYTES = PalTasksSupport.MAX_TASK_BODY_BYTES",
                "TASK_BODY_BYTES = 4L",
            )],
            "task-function-body bytes exceed",
        ),
        (
            "deadline",
            [(
                "VALIDATION_BUDGET_MS =\n            PalTasksSupport.EXPORT_VALIDATION_BUDGET_MS",
                "VALIDATION_BUDGET_MS = 1L",
            )],
            "deadline was exhausted",
        ),
    ] {
        let state = build_pal_pass2_kit(
            &home,
            &format!("limit_{case}"),
            &image,
            |scatter_hash| pal_fixture::extended_manifest(&image, scatter_hash),
            None,
            true,
        );
        let script_path = state.kit.out.join("scripts/ExportDecomp.java");
        let mut script = std::fs::read_to_string(&script_path).unwrap();
        for (from, to) in patches {
            assert_eq!(
                script.matches(from).count(),
                1,
                "patch anchor {from:?} must be unique"
            );
            script = script.replacen(from, to, 1);
        }
        if case == "deadline" {
            // Burn the 1ms budget before the first deadline check.
            script = script.replacen(
                "        deadline = Math.addExact(System.currentTimeMillis(), VALIDATION_BUDGET_MS);",
                concat!(
                    "        deadline = Math.addExact(System.currentTimeMillis(), VALIDATION_BUDGET_MS);",
                    "\n        Thread.sleep(50);"
                ),
                1,
            );
        }
        std::fs::write(&script_path, script).unwrap();
        let kit = &state.kit;
        let failed = pal_headless(
            &home,
            kit,
            &[
                "-process".to_string(),
                "02_MAIN".to_string(),
                "-noanalysis".to_string(),
                "-scriptPath".to_string(),
                kit.out.join("scripts").to_string_lossy().into_owned(),
                "-preScript".to_string(),
                "ApplyPalTasks.java".to_string(),
                kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".to_string(),
                kit.manifest_path.to_string_lossy().into_owned(),
                kit.scatter_path.to_string_lossy().into_owned(),
                "-postScript".to_string(),
                "ExportDecomp.java".to_string(),
                kit.out
                    .join("export/02_MAIN")
                    .to_string_lossy()
                    .into_owned(),
                kit.kit_root.to_string_lossy().into_owned(),
                "02_MAIN".to_string(),
                "none".to_string(),
                "-".to_string(),
                kit.identity.clone(),
                kit.manifest_path.to_string_lossy().into_owned(),
                kit.scatter_path.to_string_lossy().into_owned(),
                "-".to_string(),
                "none".to_string(),
            ],
        );
        assert!(
            failed.contains("REPORT SCRIPT ERROR") && failed.contains(expected),
            "limit {case} missed {expected:?}:\n{failed}"
        );
        let _ = std::fs::remove_dir_all(&state.kit.dir);
    }
    let _ = std::fs::remove_dir_all(&corrupt_dir);
}

#[test]
fn export_revalidates_pal_after_output_generation_before_publication() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra PAL final-postflight test requires /opt/ghidra");
    };
    let image = pal_fixture::craft_main_image();
    for (case, injection, expected) in [
        (
            "label_drift",
            concat!(
                "            ghidra.program.model.symbol.Namespace driftNamespace =\n",
                "                    currentProgram.getSymbolTable().getNamespace(\n",
                "                            PalTasksSupport.RESERVED_NAMESPACE,\n",
                "                            currentProgram.getGlobalNamespace());\n",
                "            ghidra.program.model.symbol.Symbol driftLabel =\n",
                "                    currentProgram.getSymbolTable().getSymbol(\n",
                "                            \"pal_TaskEntry_alpha\", toAddr(0x40010400L),\n",
                "                            driftNamespace);\n",
                "            if (driftLabel == null || !driftLabel.delete()) {\n",
                "                throw new AssertionError(\"PAL final label drift injection failed\");\n",
                "            }\n",
                "            System.out.println(\"ExportFinalPalDrift: label\");\n",
            ),
            "the reserved label set does not match the registry",
        ),
        (
            "file_identity_drift",
            concat!(
                "            java.nio.file.attribute.FileTime driftTime =\n",
                "                    java.nio.file.Files.getLastModifiedTime(taskManifest.toPath());\n",
                "            java.nio.file.Files.setLastModifiedTime(taskManifest.toPath(),\n",
                "                    java.nio.file.attribute.FileTime.fromMillis(\n",
                "                            Math.addExact(driftTime.toMillis(), 120000L)));\n",
                "            System.out.println(\"ExportFinalPalDrift: file\");\n",
            ),
            "task manifest no longer names the retained regular file",
        ),
    ] {
        let kit = generate_pal_apply_kit_manifests(&home, case, &image, |scatter_hash| {
            pal_fixture::extended_manifest(&image, scatter_hash)
        });
        let imported = pal_import(&home, &kit, None);
        assert!(
            !imported.contains("REPORT SCRIPT ERROR"),
            "PAL final-postflight import failed for {case}:\n{imported}"
        );
        let applied = pal_apply(&home, &kit, None);
        assert!(
            applied.contains("ApplyPalTasks:") && !applied.contains("REPORT SCRIPT ERROR"),
            "PAL final-postflight application failed for {case}:\n{applied}"
        );
        clear_owned_export(&kit.out, "02_MAIN");
        inject_before_final_export_postflight(&kit.out, injection);

        let rejected = pal_export_pass1_only(&home, &kit);

        assert!(
            rejected.contains("ExportFinalPalDrift:")
                && rejected.contains("REPORT SCRIPT ERROR")
                && rejected.contains(expected),
            "ExportDecomp accepted PAL {case} after output generation:\n{rejected}"
        );
        assert!(
            !kit.out.join("export/02_MAIN.complete").exists(),
            "PAL {case} published a v4 marker"
        );
        for name in ["functions.json", "disasm.lst", "decompiled.c"] {
            assert!(
                !kit.out.join("export/02_MAIN").join(name).exists(),
                "PAL {case} published {name}"
            );
        }
        let _ = std::fs::remove_dir_all(&kit.dir);
    }
}

// -----------------------------------------------------------------------------
// Exception-root transactional applicator
// -----------------------------------------------------------------------------

const EXCEPTION_BASE: u32 = 0x4001_0000;

struct ExceptionFixture {
    raw: Vec<u8>,
    manifest: String,
    identity: String,
}

fn exception_manifest_identity(manifest: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(manifest).unwrap();
    let tables = value["tables"].as_array().unwrap().len();
    let roots = value["roots"].as_array().unwrap().len();
    format!(
        "v1:{}:{tables}:{roots}",
        blake3::hash(manifest.as_bytes()).to_hex()
    )
}

fn exception_fixture() -> ExceptionFixture {
    exception_fixture_from_committed(
        include_bytes!("fixtures/exception_roots/synthetic.bin"),
        include_str!("fixtures/exception_roots/roots.json"),
    )
}

fn exception_nonlexical_shared_fixture() -> ExceptionFixture {
    exception_fixture_from_committed(
        include_bytes!("fixtures/exception_roots/nonlexical_shared/synthetic.bin"),
        include_str!("fixtures/exception_roots/nonlexical_shared/roots.json"),
    )
}

fn exception_relocated_same_targets_fixture() -> ExceptionFixture {
    exception_fixture_from_committed(
        include_bytes!("fixtures/exception_roots/relocated_same_targets/synthetic.bin"),
        include_str!("fixtures/exception_roots/relocated_same_targets/roots.json"),
    )
}

fn exception_scatter_fixture() -> ExceptionFixture {
    exception_fixture_from_committed(
        include_bytes!("fixtures/exception_roots/scatter/synthetic.bin"),
        include_str!("fixtures/exception_roots/scatter/roots.json"),
    )
}

fn exception_fixture_from_committed(raw: &[u8], manifest: &str) -> ExceptionFixture {
    let raw = raw.to_vec();
    let manifest = manifest.to_string();
    let identity = exception_manifest_identity(&manifest);
    ExceptionFixture {
        raw,
        manifest,
        identity,
    }
}

const EXCEPTION_SEED_FOREIGN_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;

public class ExceptionSeedForeign extends GhidraScript {
    private void seed(long raw, String name, boolean createFunction) throws Exception {
        Address entry = toAddr(raw);
        Address end = entry.add(3);
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        currentProgram.getProgramContext().setValue(tMode, entry, end, BigInteger.ZERO);
        AddressSet one = new AddressSet(entry, end);
        DisassembleCommand disassemble = new DisassembleCommand(entry, one, false);
        disassemble.enableCodeAnalysis(false);
        if (!disassemble.applyTo(currentProgram, monitor)) {
            throw new AssertionError("foreign fixture disassembly failed at " + entry);
        }
        if (!createFunction) {
            return;
        }
        CreateFunctionCmd create =
                new CreateFunctionCmd(null, entry, one, SourceType.ANALYSIS);
        if (!create.applyTo(currentProgram, monitor)) {
            throw new AssertionError("foreign fixture function failed at " + entry);
        }
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null) {
            throw new AssertionError("foreign fixture function is missing at " + entry);
        }
        if (name != null) {
            function.setName(name, SourceType.USER_DEFINED);
        }
    }

    @Override
    public void run() throws Exception {
        seed(0x40010200L, null, true);
        seed(0x40010240L, "firmwareSupervisor", true);
        seed(0x400102a0L, null, false);
        System.out.println("ExceptionSeedForeign: ready");
    }
}
"#;

const EXCEPTION_INSPECT_APPLIED_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExceptionInspectApplied extends GhidraScript {
    private static final long[] ENTRIES = {
        0x40010200L, 0x40010220L, 0x40010240L, 0x40010260L,
        0x40010280L, 0x400102a0L, 0x400102c0L
    };
    private static final boolean[] THUMB = {
        false, true, false, true, false, false, true
    };
    private static final int[] LENGTHS = {
        4, 4, 4, 2, 4, 4, 2
    };

    @Override
    public void run() throws Exception {
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ExceptionRoots.v1.Ownership");
        if (registry == null || registry.getSize() != ENTRIES.length) {
            throw new AssertionError("exception ownership registry is not complete");
        }
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                "PixelModemExtractor_ExceptionRoots_v1",
                currentProgram.getGlobalNamespace());
        if (namespace == null) {
            throw new AssertionError("exception namespace is missing");
        }
        Map<Long, Set<String>> expected = new HashMap<Long, Set<String>>();
        expected.put(0x40010200L, Set.of("exception_reset_40010000"));
        expected.put(0x40010220L, Set.of("exception_undefined_instruction_40010000"));
        expected.put(0x40010240L, Set.of("exception_supervisor_call_40010000"));
        expected.put(0x40010260L, Set.of("exception_prefetch_abort_40010000"));
        expected.put(0x40010280L, Set.of(
                "exception_data_abort_40010000", "exception_reserved_40010000"));
        expected.put(0x400102a0L, Set.of("exception_irq_40010000"));
        expected.put(0x400102c0L, Set.of("exception_fiq_40010000"));
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        List<String> fingerprint = new ArrayList<String>();
        for (int index = 0; index < ENTRIES.length; index++) {
            Address entry = toAddr(ENTRIES[index]);
            Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
            if (function == null || !function.getEntryPoint().equals(entry)) {
                throw new AssertionError("exception function is missing at " + entry);
            }
            Instruction instruction = currentProgram.getListing().getInstructionAt(entry);
            if (instruction == null || instruction.getLength() != LENGTHS[index]) {
                throw new AssertionError("exception first instruction changed at " + entry);
            }
            RegisterValue mode = instruction.getRegisterValue(tMode);
            BigInteger wanted = THUMB[index] ? BigInteger.ONE : BigInteger.ZERO;
            if (mode == null || !mode.hasValue() || !wanted.equals(mode.getUnsignedValue())) {
                throw new AssertionError("exception ISA changed at " + entry);
            }
            Set<String> labels = new HashSet<String>();
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolsAsIterator(entry);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (namespace.equals(symbol.getParentNamespace())) {
                    if (symbol.getID() == function.getID()) {
                        throw new AssertionError(
                                "exception role label absorbed the function primary at " + entry);
                    }
                    labels.add(symbol.getName());
                    fingerprint.add(entry + ":" + symbol.getName() + ":" + symbol.getID());
                }
            }
            if (!labels.equals(expected.get(ENTRIES[index]))) {
                throw new AssertionError("exception labels changed at " + entry + ": " + labels);
            }
            String ownership = registry.getString(entry);
            if (ownership == null || !ownership.contains(":" + function.getID() + ":")) {
                throw new AssertionError("ownership does not bind the function at " + entry);
            }
            fingerprint.add(entry + ":registry:" + ownership);
        }
        if (!"Reset".equals(currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010200L)).getName())) {
            throw new AssertionError("default Reset primary was not applied");
        }
        if (!"firmwareSupervisor".equals(currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010240L)).getName())) {
            throw new AssertionError("meaningful foreign primary was overwritten");
        }
        Function shared = currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010280L));
        if (!"FUN_40010280".equals(shared.getName())
                || shared.getSymbol().getSource() != SourceType.DEFAULT
                || !currentProgram.getGlobalNamespace().equals(
                        shared.getSymbol().getParentNamespace())) {
            throw new AssertionError("shared handler did not preserve its default primary");
        }
        Collections.sort(fingerprint);
        System.out.println("ExceptionInspectApplied: fingerprint " + fingerprint);
        System.out.println("ExceptionInspectApplied: ok");
    }
}
"#;

const EXCEPTION_INSPECT_STATE_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ExceptionInspectState extends GhidraScript {
    private static final long[] ENTRIES = {
        0x40010200L, 0x40010220L, 0x40010222L, 0x40010240L, 0x40010260L,
        0x40010280L, 0x400102a0L, 0x400102c0L
    };

    @Override
    public void run() throws Exception {
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ExceptionRoots.v1.Ownership");
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                "PixelModemExtractor_ExceptionRoots_v1",
                currentProgram.getGlobalNamespace());
        List<String> state = new ArrayList<String>();
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        state.add("registry=" + (registry == null ? "none" : registry.getSize()));
        state.add("namespace=" + (namespace == null ? "none" : namespace.getID()));
        for (long raw : ENTRIES) {
            Address entry = toAddr(raw);
            Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
            state.add(entry + ":fn=" + (function == null ? "none"
                    : function.getID() + "/" + function.getName() + "/"
                            + function.getSymbol().getSource()));
            CodeUnit unit = currentProgram.getListing().getCodeUnitContaining(entry);
            state.add(entry + ":unit=" + (unit == null ? "none"
                    : unit.getClass().getSimpleName() + "/" + unit.getMinAddress()
                            + "/" + unit.getLength()));
            RegisterValue mode = currentProgram.getProgramContext()
                    .getRegisterValue(tMode, entry);
            state.add(entry + ":tmode=" + (mode == null || !mode.hasValue()
                    ? "none" : mode.getUnsignedValue().toString()));
            List<String> labels = new ArrayList<String>();
            if (namespace != null) {
                SymbolIterator symbols = currentProgram.getSymbolTable()
                        .getSymbolsAsIterator(entry);
                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    if (namespace.equals(symbol.getParentNamespace())) {
                        labels.add(symbol.getName() + "/" + symbol.getID() + "/"
                                + symbol.getSource());
                    }
                }
            }
            Collections.sort(labels);
            state.add(entry + ":labels=" + labels);
            state.add(entry + ":ownership="
                    + (registry == null ? "none" : registry.getString(entry)));
        }
        System.out.println("ExceptionInspectState: " + state);
    }
}
"#;

const EXCEPTION_SEED_LATE_COLLISION_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ByteDataType;

public class ExceptionSeedLateCollision extends GhidraScript {
    @Override
    public void run() throws Exception {
        createData(toAddr(0x40010222L), ByteDataType.dataType);
        System.out.println("ExceptionSeedLateCollision: ready");
    }
}
"#;

const EXCEPTION_TAMPER_REGISTRY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.StringPropertyMap;

public class ExceptionTamperRegistry extends GhidraScript {
    @Override
    public void run() throws Exception {
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ExceptionRoots.v1.Ownership");
        if (registry == null || registry.getSize() != 7) {
            throw new AssertionError("complete exception registry is unavailable");
        }
        registry.remove(toAddr(0x400102c0L));
        if (registry.getSize() != 6) {
            throw new AssertionError("exception registry tamper did not persist");
        }
        System.out.println("ExceptionTamperRegistry: ready");
    }
}
"#;

const EXCEPTION_SEED_PRIMARY_WITHOUT_FUNCTION_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ExceptionSeedPrimaryWithoutFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x40010220L);
        if (currentProgram.getFunctionManager().getFunctionAt(entry) != null) {
            throw new AssertionError("fixture unexpectedly has a function");
        }
        Symbol primary = currentProgram.getSymbolTable().createLabel(entry,
                "firmwareUndefined", currentProgram.getGlobalNamespace(),
                SourceType.USER_DEFINED);
        if (primary == null || (!primary.isPrimary() && !primary.setPrimary())) {
            throw new AssertionError("meaningful no-function primary was not seeded");
        }
        System.out.println("ExceptionSeedPrimaryWithoutFunction: ready " + primary.getID());
    }
}
"#;

const EXCEPTION_INSPECT_PRESERVED_PRIMARY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;

public class ExceptionInspectPreservedPrimary extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x40010220L);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null || !"firmwareUndefined".equals(function.getName())
                || function.getSymbol().getSource() != SourceType.USER_DEFINED) {
            throw new AssertionError("meaningful no-function primary was not preserved");
        }
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ExceptionRoots.v1.Ownership");
        String value = registry == null ? null : registry.getString(entry);
        String binding = ":preserved:" + function.getSymbol().getID()
                + ":user_defined:";
        if (value == null || !value.contains(binding)) {
            throw new AssertionError("preserved primary identity is absent from registry: " + value);
        }
        System.out.println("ExceptionInspectPreservedPrimary: ok");
    }
}
"#;

const EXCEPTION_TAMPER_NOT_REQUESTED_PRIMARY_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ExceptionTamperNotRequestedPrimary extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function function = currentProgram.getFunctionManager()
                .getFunctionAt(toAddr(0x40010280L));
        if (function == null) {
            throw new AssertionError("shared exception function is missing");
        }
        function.setName("foreignSharedHandler", SourceType.USER_DEFINED);
        System.out.println("ExceptionTamperNotRequestedPrimary: ready");
    }
}
"#;

const EXCEPTION_CORRUPT_TERMINAL_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import java.math.BigInteger;

public class ExceptionCorruptTerminal extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new AssertionError("expected one corruption mode");
        Address first = toAddr(0x40010200L);
        Address second = toAddr(0x40010220L);
        switch (args[0]) {
            case "removed":
                if (!currentProgram.getFunctionManager().removeFunction(second)) {
                    throw new AssertionError("root function removal failed");
                }
                break;
            case "merged":
                Function owner = currentProgram.getFunctionManager().getFunctionAt(first);
                if (owner == null
                        || !currentProgram.getFunctionManager().removeFunction(second)) {
                    throw new AssertionError("merge fixture functions are missing");
                }
                AddressSet merged = new AddressSet(owner.getBody());
                merged.addRange(second, second.add(3));
                owner.setBody(merged);
                break;
            case "retagged":
                currentProgram.getListing().clearCodeUnits(second, second.add(3), false);
                Register tMode = currentProgram.getLanguage().getRegister("TMode");
                currentProgram.getProgramContext().setValue(
                        tMode, second, second.add(3), BigInteger.ZERO);
                AddressSet range = new AddressSet(second, second.add(3));
                DisassembleCommand disassemble = new DisassembleCommand(second, range, false);
                disassemble.enableCodeAnalysis(false);
                if (!disassemble.applyTo(currentProgram, monitor)) {
                    throw new AssertionError("retagged disassembly failed: "
                            + disassemble.getStatusMsg());
                }
                break;
            default:
                throw new AssertionError("unknown corruption mode " + args[0]);
        }
        System.out.println("ExceptionCorruptTerminal: ready " + args[0]);
    }
}
"#;

const EXCEPTION_SENTINEL_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;

public class ExceptionSentinel extends GhidraScript {
    @Override
    public void run() throws Exception {
        System.out.println("ExceptionSentinel: RAN");
    }
}
"#;

const EXCEPTION_SUPPORT_PROBE_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;

public class ExceptionSupportProbe extends GhidraScript {
    private static Throwable cause(InvocationTargetException error) {
        return error.getCause() == null ? error : error.getCause();
    }

    private static void pc() throws Exception {
        Method checked = ExceptionRootsSupport.class.getDeclaredMethod(
                "checkedPcRelative", long.class, long.class, String.class);
        checked.setAccessible(true);
        try {
            checked.invoke(null, 0xfffffff8L, -8L, "probe");
            throw new AssertionError("overflowing architectural PC was accepted");
        }
        catch (InvocationTargetException error) {
            if (!(cause(error) instanceof ExceptionRootsSupport.RootError)) throw error;
        }
        long boundary = ((Long) checked.invoke(null, 0xfffffff7L, 0L, "probe")).longValue();
        if (boundary != 0xffffffffL) {
            throw new AssertionError("valid architectural PC boundary changed");
        }
    }

    private static void spans() throws Exception {
        ExceptionRootsSupport.Root arm = new ExceptionRootsSupport.Root(
                0x40010200L, "arm", 4,
                "0000000000000000000000000000000000000000000000000000000000000000",
                List.of(), List.of());
        ExceptionRootsSupport.Root thumb = new ExceptionRootsSupport.Root(
                0x40010202L, "thumb", 2,
                "0000000000000000000000000000000000000000000000000000000000000000",
                List.of(), List.of());
        Method validate = ExceptionRootsSupport.class.getDeclaredMethod(
                "validateRequestedInstructionSpans", List.class);
        validate.setAccessible(true);
        try {
            validate.invoke(null, List.of(arm, thumb));
            throw new AssertionError("intersecting requested instruction spans were accepted");
        }
        catch (InvocationTargetException error) {
            if (!(cause(error) instanceof ExceptionRootsSupport.RootError)) throw error;
        }
        validate.invoke(null, List.of(arm, new ExceptionRootsSupport.Root(
                0x40010204L, "thumb", 2,
                "0000000000000000000000000000000000000000000000000000000000000000",
                List.of(), List.of())));
    }

    private static void unicode() throws Exception {
        String supplementary = new String(Character.toChars(0x1f600));
        if (PmeScriptSupport.boundedUtf8(supplementary, 4, "generic").length != 4) {
            throw new AssertionError("generic UTF-8 rejected a valid surrogate pair");
        }
        Method pal = PalTasksSupport.class.getDeclaredMethod("utf8NoSurrogates", String.class);
        pal.setAccessible(true);
        try {
            pal.invoke(null, supplementary);
            throw new AssertionError("PAL accepted a surrogate code unit");
        }
        catch (InvocationTargetException error) {
            if (!(cause(error) instanceof PalTasksSupport.PalError)) throw error;
        }
        try {
            PmeScriptSupport.boundedUtf8("\ud800", 4, "generic");
            throw new AssertionError("generic UTF-8 accepted an unpaired surrogate");
        }
        catch (PmeScriptSupport.SupportError expected) {
            // Expected.
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new AssertionError("expected one probe mode");
        switch (args[0]) {
            case "pc": pc(); break;
            case "spans": spans(); break;
            case "unicode": unicode(); break;
            default: throw new AssertionError("unknown probe mode " + args[0]);
        }
        System.out.println("ExceptionSupportProbe: " + args[0] + " ok");
    }
}
"#;

const EXCEPTION_SEED_HETEROGENEOUS_CONTEXT_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ProgramContext;
import java.math.BigInteger;

public class ExceptionSeedHeterogeneousContext extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x40010220L);
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        context.setRegisterValue(entry, entry, new RegisterValue(tMode, BigInteger.ZERO));
        context.setRegisterValue(entry.add(2), entry.add(3),
                new RegisterValue(tMode, BigInteger.ONE));
        System.out.println("ExceptionSeedHeterogeneousContext: ready");
    }
}
"#;

const EXCEPTION_INSPECT_HETEROGENEOUS_CONTEXT_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ProgramContext;

public class ExceptionInspectHeterogeneousContext extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x40010220L);
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        ProgramContext context = currentProgram.getProgramContext();
        StringBuilder state = new StringBuilder();
        for (int offset = 0; offset < 4; offset++) {
            if (offset != 0) state.append(',');
            RegisterValue value = context.getNonDefaultValue(tMode, entry.add(offset));
            state.append(value == null || !value.hasValue()
                    ? "none" : value.getUnsignedValue().toString());
        }
        state.append(":instruction=")
                .append(currentProgram.getListing().getInstructionAt(entry) == null ? "none" : "set");
        state.append(":function=")
                .append(currentProgram.getFunctionManager().getFunctionAt(entry) == null ? "none" : "set");
        System.out.println("ExceptionInspectHeterogeneousContext: " + state);
    }
}
"#;

const EXCEPTION_INSPECT_SCATTER_APPLIED_JAVA: &str = r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.util.StringPropertyMap;
import java.math.BigInteger;

public class ExceptionInspectScatterApplied extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = toAddr(0x40011000L);
        Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null || !"FIQ".equals(function.getName())) {
            throw new AssertionError("scatter-backed FIQ function is missing");
        }
        Register tMode = currentProgram.getLanguage().getRegister("TMode");
        RegisterValue mode = currentProgram.getListing().getInstructionAt(entry)
                .getRegisterValue(tMode);
        if (mode == null || !mode.hasValue()
                || !BigInteger.ONE.equals(mode.getUnsignedValue())) {
            throw new AssertionError("scatter-backed FIQ function is not Thumb");
        }
        Address directEntry = toAddr(0x40011008L);
        Function direct = currentProgram.getFunctionManager().getFunctionAt(directEntry);
        if (direct == null || !"Reset".equals(direct.getName())) {
            throw new AssertionError("scatter-backed direct Reset function is missing");
        }
        RegisterValue directMode = currentProgram.getListing().getInstructionAt(directEntry)
                .getRegisterValue(tMode);
        if (directMode == null || !directMode.hasValue()
                || !BigInteger.ZERO.equals(directMode.getUnsignedValue())) {
            throw new AssertionError("scatter-backed direct Reset function is not A32");
        }
        Namespace namespace = currentProgram.getSymbolTable().getNamespace(
                "PixelModemExtractor_ExceptionRoots_v1",
                currentProgram.getGlobalNamespace());
        boolean role = false;
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolsAsIterator(entry);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (namespace.equals(symbol.getParentNamespace())
                    && "exception_fiq_40010000".equals(symbol.getName())) {
                role = true;
            }
        }
        boolean directRole = false;
        symbols = currentProgram.getSymbolTable().getSymbolsAsIterator(directEntry);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (namespace.equals(symbol.getParentNamespace())
                    && "exception_reset_40010000".equals(symbol.getName())) {
                directRole = true;
            }
        }
        StringPropertyMap registry = currentProgram.getUsrPropertyManager()
                .getStringPropertyMap("PixelModemExtractor.ExceptionRoots.v1.Ownership");
        if (!role || !directRole || registry == null || registry.getSize() != 7
                || registry.getString(entry) == null
                || registry.getString(directEntry) == null) {
            throw new AssertionError("scatter-backed exception ownership is incomplete");
        }
        System.out.println("ExceptionInspectScatterApplied: ok");
    }
}
"#;

struct ExceptionApplyKit {
    dir: PathBuf,
    out: PathBuf,
    kit_root: PathBuf,
    manifest_path: PathBuf,
    scatter_path: Option<PathBuf>,
    identity: String,
}

fn generate_exception_apply_kit(
    home: &std::path::Path,
    case: &str,
    fixture: &ExceptionFixture,
) -> ExceptionApplyKit {
    generate_exception_apply_kit_inner(
        home,
        case,
        &fixture.raw,
        &fixture.manifest,
        &fixture.identity,
    )
}

fn generate_exception_apply_kit_inner(
    home: &std::path::Path,
    case: &str,
    raw: &[u8],
    manifest: &str,
    identity: &str,
) -> ExceptionApplyKit {
    let dir =
        std::env::temp_dir().join(format!("pme_exception_apply_{case}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    std::fs::write(
        &modem_path,
        craft_single_image_modem_bin("BOOT", EXCEPTION_BASE, 1, raw),
    )
    .unwrap();
    let out = dir.join("out");
    pixel_modem_extractor::decompile::run_report(
        &modem_path,
        &pixel_modem_extractor::decompile::Opts {
            run: false,
            image: None,
            ghidra_home: Some(home.to_path_buf()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: false,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: false,
        },
        &out,
    )
    .unwrap();
    let manifest_dir = out.join("exception_roots/00_BOOT");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let manifest_path = manifest_dir.join("roots.json");
    std::fs::write(&manifest_path, manifest).unwrap();
    let scatter_path = out.join("scatter/00_BOOT/load_map.json");
    let scatter_path = scatter_path
        .is_file()
        .then(|| std::fs::canonicalize(scatter_path).unwrap());
    for script in [
        "PmeScriptSupport.java",
        "PalTasksSupport.java",
        "ExceptionRootsSupport.java",
        "ApplyExceptionRoots.java",
    ] {
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/ghidra")
                .join(script),
            out.join("scripts").join(script),
        )
        .unwrap_or_else(|error| panic!("could not stage {script}: {error}"));
    }
    for (name, source) in [
        ("ExceptionSeedForeign.java", EXCEPTION_SEED_FOREIGN_JAVA),
        (
            "ExceptionInspectApplied.java",
            EXCEPTION_INSPECT_APPLIED_JAVA,
        ),
        ("ExceptionInspectState.java", EXCEPTION_INSPECT_STATE_JAVA),
        (
            "ExceptionSeedLateCollision.java",
            EXCEPTION_SEED_LATE_COLLISION_JAVA,
        ),
        (
            "ExceptionTamperRegistry.java",
            EXCEPTION_TAMPER_REGISTRY_JAVA,
        ),
        (
            "ExceptionInspectScatterApplied.java",
            EXCEPTION_INSPECT_SCATTER_APPLIED_JAVA,
        ),
        (
            "ExceptionSeedPrimaryWithoutFunction.java",
            EXCEPTION_SEED_PRIMARY_WITHOUT_FUNCTION_JAVA,
        ),
        (
            "ExceptionInspectPreservedPrimary.java",
            EXCEPTION_INSPECT_PRESERVED_PRIMARY_JAVA,
        ),
        (
            "ExceptionTamperNotRequestedPrimary.java",
            EXCEPTION_TAMPER_NOT_REQUESTED_PRIMARY_JAVA,
        ),
        (
            "ExceptionCorruptTerminal.java",
            EXCEPTION_CORRUPT_TERMINAL_JAVA,
        ),
        ("ExceptionSentinel.java", EXCEPTION_SENTINEL_JAVA),
        ("ExceptionSupportProbe.java", EXCEPTION_SUPPORT_PROBE_JAVA),
        (
            "ExceptionSeedHeterogeneousContext.java",
            EXCEPTION_SEED_HETEROGENEOUS_CONTEXT_JAVA,
        ),
        (
            "ExceptionInspectHeterogeneousContext.java",
            EXCEPTION_INSPECT_HETEROGENEOUS_CONTEXT_JAVA,
        ),
    ] {
        std::fs::write(out.join("scripts").join(name), source).unwrap();
    }
    std::fs::create_dir_all(out.join("ghidra_project")).unwrap();
    for directory in ["ghidra_config", "ghidra_cache", "ghidra_tmp"] {
        std::fs::create_dir_all(out.join(directory)).unwrap();
    }
    ExceptionApplyKit {
        kit_root: std::fs::canonicalize(&out).unwrap(),
        manifest_path: std::fs::canonicalize(&manifest_path).unwrap(),
        scatter_path,
        identity: identity.to_string(),
        dir,
        out,
    }
}

fn generate_exception_scatter_apply_kit(
    home: &std::path::Path,
    case: &str,
) -> (ExceptionApplyKit, ExceptionFixture) {
    let fixture = exception_scatter_fixture();
    let plan = pixel_modem_extractor::scatter::discover(&fixture.raw, EXCEPTION_BASE)
        .expect("synthetic exception scatter discovery")
        .expect("synthetic exception scatter loader was not structurally discoverable");
    // Production scatter discovery is intentionally MAIN-only. This Java
    // boundary fixture instead exercises an explicit test-only BOOT scatter
    // map, so stage the generic kit from a same-sized no-candidate image before
    // installing the intended raw bytes and materialized map.
    let staging_raw = vec![0; fixture.raw.len()];
    let mut kit = generate_exception_apply_kit_inner(
        home,
        case,
        &staging_raw,
        &fixture.manifest,
        &fixture.identity,
    );
    std::fs::write(kit.out.join("images/00_BOOT"), &fixture.raw)
        .expect("install synthetic exception scatter image");
    if kit.scatter_path.is_none() {
        pixel_modem_extractor::scatter::materialize(&plan, &fixture.raw, "00_BOOT", &kit.out)
            .expect("materialize synthetic exception scatter map");
        kit.scatter_path =
            Some(std::fs::canonicalize(kit.out.join("scatter/00_BOOT/load_map.json")).unwrap());
    }
    assert!(
        kit.scatter_path.is_some(),
        "synthetic exception scatter map was not materialized"
    );
    (kit, fixture)
}

fn exception_headless(
    home: &std::path::Path,
    kit: &ExceptionApplyKit,
    args: &[String],
) -> std::process::Output {
    let config = kit.out.join("ghidra_config");
    let cache = kit.out.join("ghidra_cache");
    let temp = kit.out.join("ghidra_tmp");
    let java_options = format!(
        "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
        config.display(),
        cache.display(),
        temp.display(),
        temp.display()
    );
    std::process::Command::new(
        analyze_headless_in_home(home).expect("located Ghidra home still has analyzeHeadless"),
    )
    .arg(kit.out.join("ghidra_project"))
    .arg("pixel-modem")
    .args(args)
    .env("XDG_CONFIG_HOME", &config)
    .env("XDG_CACHE_HOME", &cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
    .output()
    .unwrap()
}

fn exception_import(home: &std::path::Path, kit: &ExceptionApplyKit) -> std::process::Output {
    let mut args = vec![
        "-import".to_string(),
        kit.out
            .join("images/00_BOOT")
            .to_string_lossy()
            .into_owned(),
        "-processor".to_string(),
        "ARM:LE:32:v7".to_string(),
        "-loader".to_string(),
        "BinaryLoader".to_string(),
        "-loader-baseAddr".to_string(),
        "40010000".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
    ];
    if let Some(scatter) = &kit.scatter_path {
        args.extend([
            "-preScript".to_string(),
            "ApplyScatterLoad.java".to_string(),
            kit.kit_root.to_string_lossy().into_owned(),
            "00_BOOT".to_string(),
            scatter.to_string_lossy().into_owned(),
        ]);
    }
    args.extend([
        "-postScript".to_string(),
        "ExceptionSeedForeign.java".to_string(),
    ]);
    exception_headless(home, kit, &args)
}

fn exception_apply(home: &std::path::Path, kit: &ExceptionApplyKit) -> std::process::Output {
    exception_apply_with(home, kit, &kit.identity, "ExceptionInspectApplied.java")
}

fn exception_apply_with(
    home: &std::path::Path,
    kit: &ExceptionApplyKit,
    identity: &str,
    post_script: &str,
) -> std::process::Output {
    exception_headless(
        home,
        kit,
        &[
            "-process".to_string(),
            "00_BOOT".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            kit.out.join("scripts").to_string_lossy().into_owned(),
            "-preScript".to_string(),
            "ApplyExceptionRoots.java".to_string(),
            kit.kit_root.to_string_lossy().into_owned(),
            "00_BOOT".to_string(),
            kit.manifest_path.to_string_lossy().into_owned(),
            kit.scatter_path.as_ref().map_or_else(
                || "-".to_string(),
                |path| path.to_string_lossy().into_owned(),
            ),
            identity.to_string(),
            "-postScript".to_string(),
            post_script.to_string(),
        ],
    )
}

fn exception_corrupt_and_export(
    home: &std::path::Path,
    kit: &ExceptionApplyKit,
    mode: &str,
) -> std::process::Output {
    let export = kit.out.join("export/00_BOOT");
    let _ = std::fs::remove_file(kit.out.join("export/00_BOOT.complete"));
    for name in ["functions.json", "disasm.lst", "decompiled.c"] {
        let _ = std::fs::remove_file(export.join(name));
    }
    exception_headless(
        home,
        kit,
        &[
            "-process".to_string(),
            "00_BOOT".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "ExceptionCorruptTerminal.java".to_string(),
            mode.to_string(),
            "-postScript".to_string(),
            "ExportDecomp.java".to_string(),
            export.to_string_lossy().into_owned(),
            kit.kit_root.to_string_lossy().into_owned(),
            "00_BOOT".to_string(),
            kit.identity.clone(),
            kit.manifest_path.to_string_lossy().into_owned(),
            "none".to_string(),
            "-".to_string(),
            kit.scatter_path.as_ref().map_or_else(
                || "-".to_string(),
                |path| path.to_string_lossy().into_owned(),
            ),
            "-".to_string(),
            "none".to_string(),
        ],
    )
}

fn exception_export_only(home: &std::path::Path, kit: &ExceptionApplyKit) -> std::process::Output {
    exception_headless(
        home,
        kit,
        &[
            "-process".to_string(),
            "00_BOOT".to_string(),
            "-noanalysis".to_string(),
            "-scriptPath".to_string(),
            kit.out.join("scripts").to_string_lossy().into_owned(),
            "-postScript".to_string(),
            "ExportDecomp.java".to_string(),
            kit.out
                .join("export/00_BOOT")
                .to_string_lossy()
                .into_owned(),
            kit.kit_root.to_string_lossy().into_owned(),
            "00_BOOT".to_string(),
            kit.identity.clone(),
            kit.manifest_path.to_string_lossy().into_owned(),
            "none".to_string(),
            "-".to_string(),
            kit.scatter_path.as_ref().map_or_else(
                || "-".to_string(),
                |path| path.to_string_lossy().into_owned(),
            ),
            "-".to_string(),
            "none".to_string(),
        ],
    )
}

fn exception_run_script(
    home: &std::path::Path,
    kit: &ExceptionApplyKit,
    script: &str,
) -> std::process::Output {
    exception_run_script_with(home, kit, script, &[])
}

fn exception_run_script_with(
    home: &std::path::Path,
    kit: &ExceptionApplyKit,
    script: &str,
    args: &[&str],
) -> std::process::Output {
    let mut command = vec![
        "-process".to_string(),
        "00_BOOT".to_string(),
        "-noanalysis".to_string(),
        "-scriptPath".to_string(),
        kit.out.join("scripts").to_string_lossy().into_owned(),
        "-postScript".to_string(),
        script.to_string(),
    ];
    command.extend(args.iter().map(|value| (*value).to_string()));
    exception_headless(home, kit, &command)
}

fn exception_state(output: &std::process::Output) -> String {
    let diagnostics = process_diagnostics(output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let states = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ExceptionInspectState: "))
        .collect::<Vec<_>>();
    assert_eq!(
        states.len(),
        1,
        "expected one exception state fingerprint:\n{diagnostics}"
    );
    states[0].to_string()
}

fn exception_context_state(output: &std::process::Output) -> String {
    let diagnostics = process_diagnostics(output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let states = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ExceptionInspectHeterogeneousContext: "))
        .collect::<Vec<_>>();
    assert_eq!(
        states.len(),
        1,
        "expected one heterogeneous-context fingerprint:\n{diagnostics}"
    );
    states[0].to_string()
}

fn exception_fixture_with_manifest(
    fixture: ExceptionFixture,
    manifest: String,
) -> ExceptionFixture {
    ExceptionFixture {
        raw: fixture.raw,
        identity: exception_manifest_identity(&manifest),
        manifest,
    }
}

fn exception_summary(output: &std::process::Output) -> serde_json::Value {
    let diagnostics = process_diagnostics(output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let summaries = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("ApplyExceptionRoots: "))
        .collect::<Vec<_>>();
    assert_eq!(
        summaries.len(),
        1,
        "expected exactly one unwrapped exception summary:\n{diagnostics}"
    );
    serde_json::from_str(summaries[0])
        .unwrap_or_else(|error| panic!("malformed exception summary ({error}):\n{diagnostics}"))
}

fn assert_exception_conservation(summary: &serde_json::Value) {
    let count = |field: &str| summary[field].as_u64().unwrap();
    assert_eq!(
        count("entries"),
        count("functions_created") + count("functions_reapplied") + count("functions_existing")
    );
    assert_eq!(
        count("entries"),
        count("names_applied")
            + count("names_reapplied")
            + count("names_preserved")
            + count("names_not_requested")
    );
    assert!(count("shared_entries") <= count("names_not_requested"));
}

fn assert_exception_rejected_unchanged(
    home: &std::path::Path,
    case: &str,
    fixture: &ExceptionFixture,
    identity: &str,
    seed_script: Option<&str>,
    expected_error: &str,
) {
    let kit = generate_exception_apply_kit(home, case, fixture);
    let imported = exception_import(home, &kit);
    assert!(
        imported.status.success(),
        "exception rejection fixture import failed:\n{}",
        process_diagnostics(&imported)
    );
    if let Some(script) = seed_script {
        let seeded = exception_run_script(home, &kit, script);
        assert!(
            seeded.status.success(),
            "exception rejection fixture seeding failed:\n{}",
            process_diagnostics(&seeded)
        );
    }
    let before = exception_run_script(home, &kit, "ExceptionInspectState.java");
    assert!(
        before.status.success(),
        "exception baseline inspection failed:\n{}",
        process_diagnostics(&before)
    );
    let before = exception_state(&before);
    let rejected = exception_apply_with(home, &kit, identity, "ExceptionSentinel.java");
    let diagnostics = process_diagnostics(&rejected);
    assert!(
        diagnostics.contains(expected_error),
        "exception case {case} missed {expected_error:?}:\n{diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&rejected.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")
                || line == "ExceptionSentinel: RAN"),
        "exception case {case} emitted success or continued:\n{diagnostics}"
    );
    let after = exception_run_script(home, &kit, "ExceptionInspectState.java");
    assert!(
        after.status.success(),
        "exception post-rejection inspection failed:\n{}",
        process_diagnostics(&after)
    );
    assert_eq!(
        exception_state(&after),
        before,
        "exception case {case} changed the saved program"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn pass1_applies_exception_roots_transactionally() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();

    // Drive the shipping pass-1 route, including generated discovery state,
    // ApplyExceptionRoots -> TameAnalysis(datamark) -> auto-analysis ->
    // ExportDecomp, before the focused transaction/replay checks below.
    let production_dir = std::env::temp_dir().join(format!(
        "pme_exception_production_pass1_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&production_dir);
    std::fs::create_dir_all(&production_dir).unwrap();
    let production_modem = production_dir.join("modem.bin");
    std::fs::write(
        &production_modem,
        craft_single_image_modem_bin("BOOT", EXCEPTION_BASE, 1, &fixture.raw),
    )
    .unwrap();
    let production_out = production_dir.join("out");
    let production = pixel_modem_extractor::decompile::run_report(
        &production_modem,
        &pixel_modem_extractor::decompile::Opts {
            run: true,
            image: None,
            ghidra_home: Some(home.clone()),
            processor: "ARM:LE:32:v7".to_string(),
            no_thumb_decompile: true,
            rizin_fallback: false,
            tighten_wall_clock_budget_override: None,
            no_skip_opaque: true,
        },
        &production_out,
    )
    .unwrap();
    let image = &production.images[0];
    assert!(matches!(
        image.outcome,
        pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
    ));
    assert_eq!(
        image.exception_roots_applied,
        Some(pixel_modem_extractor::decompile::AppliedExceptionRoots {
            tables: 1,
            roles: 8,
            entries: 7,
            functions_created: 7,
            functions_reapplied: 0,
            functions_existing: 0,
            names_applied: 6,
            names_reapplied: 0,
            names_preserved: 0,
            names_not_requested: 1,
            shared_entries: 1,
        })
    );
    assert_eq!(image.exception_error, None);
    let production_manifest =
        std::fs::read_to_string(production_out.join("exception_roots/00_BOOT/roots.json")).unwrap();
    let production_identity = exception_manifest_identity(&production_manifest);
    assert_eq!(production_identity, fixture.identity);
    assert_eq!(
        std::fs::read(production_out.join("export/00_BOOT.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            &production_identity,
            "none",
            "none",
        )
    );
    let exported: serde_json::Value = serde_json::from_slice(
        &std::fs::read(production_out.join("export/00_BOOT/functions.json")).unwrap(),
    )
    .unwrap();
    let entries = exported
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|function| function["entry"].as_str())
        .collect::<std::collections::HashSet<_>>();
    for entry in [
        "0x40010200",
        "0x40010220",
        "0x40010240",
        "0x40010260",
        "0x40010280",
        "0x400102a0",
        "0x400102c0",
    ] {
        assert!(
            entries.contains(entry),
            "datamark lost exception root {entry}"
        );
    }
    let _ = std::fs::remove_dir_all(&production_dir);

    let generated_kit = generate_exception_apply_kit(&home, "generated_script", &fixture);
    let generated = std::process::Command::new(generated_kit.out.join("run_ghidra.sh"))
        .env("GHIDRA_INSTALL_DIR", &home)
        .output()
        .unwrap();
    let generated_diagnostics = process_diagnostics(&generated);
    assert!(
        generated.status.success()
            && String::from_utf8_lossy(&generated.stdout)
                .lines()
                .any(|line| line.starts_with("ApplyExceptionRoots: ")),
        "generated run_ghidra.sh failed:\n{generated_diagnostics}"
    );
    assert_eq!(
        std::fs::read(generated_kit.out.join("export/00_BOOT.complete")).unwrap(),
        pixel_modem_extractor::decompile::export_completion_marker(
            &fixture.identity,
            "none",
            "none",
        )
    );
    let _ = std::fs::remove_dir_all(&generated_kit.dir);

    let kit = generate_exception_apply_kit(&home, "ok", &fixture);
    let imported = exception_import(&home, &kit);
    let import_diagnostics = process_diagnostics(&imported);
    assert!(
        imported.status.success()
            && String::from_utf8_lossy(&imported.stdout)
                .lines()
                .any(|line| line == "ExceptionSeedForeign: ready"),
        "exception fixture import failed:\n{import_diagnostics}"
    );

    let first = exception_apply(&home, &kit);
    let first_diagnostics = process_diagnostics(&first);
    assert!(
        first.status.success()
            && String::from_utf8_lossy(&first.stdout)
                .lines()
                .any(|line| line == "ExceptionInspectApplied: ok"),
        "first exception application failed:\n{first_diagnostics}"
    );
    let first_summary = exception_summary(&first);
    assert_eq!(
        first_summary,
        serde_json::json!({
            "image": "00_BOOT",
            "status": "ok",
            "identity": fixture.identity,
            "tables": 1,
            "roles": 8,
            "entries": 7,
            "functions_created": 5,
            "functions_reapplied": 0,
            "functions_existing": 2,
            "names_applied": 5,
            "names_reapplied": 0,
            "names_preserved": 1,
            "names_not_requested": 1,
            "shared_entries": 1,
        })
    );
    assert_exception_conservation(&first_summary);

    let replay = exception_apply(&home, &kit);
    let replay_diagnostics = process_diagnostics(&replay);
    assert!(
        replay.status.success()
            && String::from_utf8_lossy(&replay.stdout)
                .lines()
                .any(|line| line == "ExceptionInspectApplied: ok"),
        "exception replay failed:\n{replay_diagnostics}"
    );
    let replay_summary = exception_summary(&replay);
    assert_eq!(
        replay_summary,
        serde_json::json!({
            "image": "00_BOOT",
            "status": "ok",
            "identity": fixture.identity,
            "tables": 1,
            "roles": 8,
            "entries": 7,
            "functions_created": 0,
            "functions_reapplied": 5,
            "functions_existing": 2,
            "names_applied": 0,
            "names_reapplied": 5,
            "names_preserved": 1,
            "names_not_requested": 1,
            "shared_entries": 1,
        })
    );
    assert_exception_conservation(&replay_summary);
    let fingerprint = |output: &std::process::Output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.starts_with("ExceptionInspectApplied: fingerprint "))
            .unwrap()
            .to_string()
    };
    assert_eq!(fingerprint(&first), fingerprint(&replay));

    let tampered = exception_run_script(&home, &kit, "ExceptionTamperRegistry.java");
    assert!(
        tampered.status.success()
            && String::from_utf8_lossy(&tampered.stdout)
                .lines()
                .any(|line| line == "ExceptionTamperRegistry: ready"),
        "exception registry tamper failed:\n{}",
        process_diagnostics(&tampered)
    );
    let partial = exception_run_script(&home, &kit, "ExceptionInspectState.java");
    assert!(partial.status.success());
    let partial = exception_state(&partial);
    let stale = exception_apply_with(&home, &kit, &kit.identity, "ExceptionSentinel.java");
    let stale_diagnostics = process_diagnostics(&stale);
    assert!(
        stale_diagnostics.contains("ownership registry has a stale or partial size"),
        "partial exception registry was not rejected:\n{stale_diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&stale.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")
                || line == "ExceptionSentinel: RAN"),
        "stale exception replay emitted success or continued"
    );
    let after_stale = exception_run_script(&home, &kit, "ExceptionInspectState.java");
    assert!(after_stale.status.success());
    assert_eq!(exception_state(&after_stale), partial);
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn export_v4_rejects_removed_merged_and_retagged_exception_roots() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    for (mode, expected) in [
        ("removed", "registry function binding is stale"),
        ("merged", "foreign function overlaps exception root"),
        ("retagged", "exception-root instruction"),
    ] {
        let kit = generate_exception_apply_kit(&home, &format!("export_{mode}"), &fixture);
        let imported = exception_import(&home, &kit);
        assert!(
            imported.status.success(),
            "{mode} import failed:\n{}",
            process_diagnostics(&imported)
        );
        let applied = exception_apply(&home, &kit);
        assert!(
            applied.status.success(),
            "{mode} application failed:\n{}",
            process_diagnostics(&applied)
        );

        let rejected = exception_corrupt_and_export(&home, &kit, mode);
        let diagnostics = process_diagnostics(&rejected);
        assert!(
            diagnostics.contains(&format!("ExceptionCorruptTerminal: ready {mode}"))
                && diagnostics.contains("REPORT SCRIPT ERROR")
                && diagnostics.contains(expected),
            "ExportDecomp accepted {mode} root state:\n{diagnostics}"
        );
        assert!(!kit.out.join("export/00_BOOT.complete").exists(), "{mode}");
        for name in ["functions.json", "disasm.lst", "decompiled.c"] {
            assert!(
                !kit.out.join("export/00_BOOT").join(name).exists(),
                "{mode}: {name}"
            );
        }
        let _ = std::fs::remove_dir_all(&kit.dir);
    }
}

#[test]
fn export_rejects_root_byte_drift_after_output_generation_without_publication() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception final-postflight test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "export_final_byte_drift", &fixture);
    let imported = exception_import(&home, &kit);
    assert!(
        imported.status.success(),
        "exception final-byte import failed:\n{}",
        process_diagnostics(&imported)
    );
    let applied = exception_apply(&home, &kit);
    assert!(
        applied.status.success(),
        "exception final-byte application failed:\n{}",
        process_diagnostics(&applied)
    );
    clear_owned_export(&kit.out, "00_BOOT");
    inject_before_final_export_postflight(
        &kit.out,
        concat!(
            "            ghidra.program.model.address.Address driftEntry =\n",
            "                    toAddr(0x40010220L);\n",
            "            currentProgram.getListing().clearCodeUnits(\n",
            "                    driftEntry, driftEntry.add(3), false);\n",
            "            currentProgram.getMemory().setByte(driftEntry, (byte) 0x40);\n",
            "            ghidra.program.model.lang.Register driftTMode =\n",
            "                    currentProgram.getLanguage().getRegister(\"TMode\");\n",
            "            currentProgram.getProgramContext().setValue(\n",
            "                    driftTMode, driftEntry, driftEntry.add(3), java.math.BigInteger.ONE);\n",
            "            ghidra.program.model.address.AddressSet driftRange =\n",
            "                    new ghidra.program.model.address.AddressSet(\n",
            "                            driftEntry, driftEntry.add(3));\n",
            "            ghidra.app.cmd.disassemble.DisassembleCommand drift =\n",
            "                    new ghidra.app.cmd.disassemble.DisassembleCommand(\n",
            "                            driftEntry, driftRange, false);\n",
            "            drift.enableCodeAnalysis(false);\n",
            "            if (!drift.applyTo(currentProgram, monitor)) {\n",
            "                throw new AssertionError(\n",
            "                        \"exception final-byte disassembly failed: \"\n",
            "                        + drift.getStatusMsg());\n",
            "            }\n",
            "            System.out.println(\"ExportFinalExceptionByteDrift: ready\");\n",
        ),
    );

    let rejected = exception_export_only(&home, &kit);
    let diagnostics = process_diagnostics(&rejected);

    assert!(
        diagnostics.contains("ExportFinalExceptionByteDrift: ready")
            && diagnostics.contains("REPORT SCRIPT ERROR")
            && diagnostics.contains("postflight exception-root instruction bytes are stale"),
        "ExportDecomp accepted final exception-byte drift:\n{diagnostics}"
    );
    assert!(
        !kit.out.join("export/00_BOOT.complete").exists(),
        "final exception-byte drift published a v4 marker"
    );
    for name in ["functions.json", "disasm.lst", "decompiled.c"] {
        assert!(
            !kit.out.join("export/00_BOOT").join(name).exists(),
            "final exception-byte drift published {name}"
        );
    }
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn pass1_applies_shared_exception_roles_with_nonlexical_label_order() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_nonlexical_shared_fixture();
    let kit = generate_exception_apply_kit(&home, "nonlexical_shared", &fixture);
    let imported = exception_import(&home, &kit);
    assert!(
        imported.status.success(),
        "shared-role exception fixture import failed:\n{}",
        process_diagnostics(&imported)
    );

    let applied =
        exception_apply_with(&home, &kit, &fixture.identity, "ExceptionInspectState.java");
    let diagnostics = process_diagnostics(&applied);
    assert!(
        applied.status.success(),
        "nonlexical shared-role application failed:\n{diagnostics}"
    );
    let summary = exception_summary(&applied);
    assert_eq!(summary["entries"], 6);
    assert_eq!(summary["shared_entries"], 2);
    assert_eq!(summary["names_not_requested"], 2);
    assert_exception_conservation(&summary);
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn exception_support_guards_pc_spans_and_pal_unicode_policy() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "support_guards", &fixture);
    let imported = exception_import(&home, &kit);
    assert!(
        imported.status.success(),
        "exception support-probe import failed:\n{}",
        process_diagnostics(&imported)
    );

    for mode in ["pc", "spans", "unicode"] {
        let output = exception_run_script_with(&home, &kit, "ExceptionSupportProbe.java", &[mode]);
        let diagnostics = process_diagnostics(&output);
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line == format!("ExceptionSupportProbe: {mode} ok")),
            "exception support probe {mode} failed:\n{diagnostics}"
        );
    }
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn pass1_preserves_meaningful_primary_without_existing_function() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "primary_without_function", &fixture);
    let imported = exception_import(&home, &kit);
    assert!(imported.status.success());
    let seeded = exception_run_script(&home, &kit, "ExceptionSeedPrimaryWithoutFunction.java");
    assert!(
        seeded.status.success()
            && String::from_utf8_lossy(&seeded.stdout)
                .contains("ExceptionSeedPrimaryWithoutFunction: ready"),
        "meaningful-primary seed failed:\n{}",
        process_diagnostics(&seeded)
    );

    let applied = exception_apply_with(
        &home,
        &kit,
        &fixture.identity,
        "ExceptionInspectPreservedPrimary.java",
    );
    let diagnostics = process_diagnostics(&applied);
    assert!(
        applied.status.success()
            && String::from_utf8_lossy(&applied.stdout)
                .lines()
                .any(|line| line == "ExceptionInspectPreservedPrimary: ok"),
        "meaningful no-function primary was not preserved:\n{diagnostics}"
    );
    let summary = exception_summary(&applied);
    assert_eq!(summary["names_preserved"], 2);
    assert_eq!(summary["names_applied"], 4);
    assert_exception_conservation(&summary);
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn pass1_replay_rejects_not_requested_primary_drift() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "not_requested_primary", &fixture);
    assert!(exception_import(&home, &kit).status.success());
    let applied = exception_apply(&home, &kit);
    assert!(
        applied.status.success(),
        "initial exception application failed:\n{}",
        process_diagnostics(&applied)
    );
    let tampered = exception_run_script(&home, &kit, "ExceptionTamperNotRequestedPrimary.java");
    assert!(tampered.status.success());

    let replay = exception_apply_with(&home, &kit, &fixture.identity, "ExceptionSentinel.java");
    let diagnostics = process_diagnostics(&replay);
    assert!(
        diagnostics.contains("not-requested exception primary is stale"),
        "not-requested primary drift was accepted:\n{diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&replay.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")
                || line == "ExceptionSentinel: RAN"),
        "stale replay emitted success or continued to the sentinel:\n{diagnostics}"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn failed_exception_applicator_stops_follow_on_scripts() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "headless_abort", &fixture);
    assert!(exception_import(&home, &kit).status.success());

    let rejected = exception_apply_with(
        &home,
        &kit,
        "v1:0000000000000000000000000000000000000000000000000000000000000000:1:7",
        "ExceptionSentinel.java",
    );
    let diagnostics = process_diagnostics(&rejected);
    assert!(diagnostics.contains("identity does not match"));
    assert!(
        !String::from_utf8_lossy(&rejected.stdout)
            .lines()
            .any(|line| line == "ExceptionSentinel: RAN"),
        "failed exception applicator continued to sentinel:\n{diagnostics}"
    );
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn post_commit_close_failure_is_replayable_without_success_summary() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "close_after_commit", &fixture);
    assert!(exception_import(&home, &kit).status.success());

    let support_path = kit.out.join("scripts/ExceptionRootsSupport.java");
    let source = std::fs::read_to_string(&support_path).unwrap();
    let close_tail = concat!(
        "            if (failure != null) rethrow(failure);\n",
        "        }\n",
        "    }\n",
        "\n",
        "    static final class AppliedState",
    );
    let injected_tail = concat!(
        "            if (failure != null) rethrow(failure);\n",
        "            throw new IOException(\"injected retained-file close failure\");\n",
        "        }\n",
        "    }\n",
        "\n",
        "    static final class AppliedState",
    );
    std::fs::write(
        &support_path,
        replace_once(&source, close_tail, injected_tail),
    )
    .unwrap();

    let failed = exception_apply_with(&home, &kit, &fixture.identity, "ExceptionSentinel.java");
    let diagnostics = process_diagnostics(&failed);
    assert!(
        diagnostics.contains("injected retained-file close failure"),
        "retained-file close injection did not fire:\n{diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&failed.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")
                || line == "ExceptionSentinel: RAN"),
        "post-commit close failure emitted success or continued:\n{diagnostics}"
    );

    std::fs::write(&support_path, source).unwrap();
    let committed = exception_run_script(&home, &kit, "ExceptionInspectApplied.java");
    assert!(
        committed.status.success()
            && String::from_utf8_lossy(&committed.stdout)
                .lines()
                .any(|line| line == "ExceptionInspectApplied: ok"),
        "close failure did not leave committed replayable state:\n{}",
        process_diagnostics(&committed)
    );
    let replay = exception_apply(&home, &kit);
    assert!(
        replay.status.success(),
        "post-close-failure replay failed:\n{}",
        process_diagnostics(&replay)
    );
    let summary = exception_summary(&replay);
    assert_eq!(summary["functions_reapplied"], 5);
    assert_eq!(summary["functions_existing"], 2);
    assert_exception_conservation(&summary);
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn partial_throwable_preflight_closes_retained_handles() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let kit = generate_exception_apply_kit(&home, "partial_throwable_preflight", &fixture);
    assert!(exception_import(&home, &kit).status.success());
    let before = exception_run_script(&home, &kit, "ExceptionInspectState.java");
    assert!(before.status.success());
    let before = exception_state(&before);

    let generic_path = kit.out.join("scripts/PmeScriptSupport.java");
    let generic = std::fs::read_to_string(&generic_path).unwrap();
    let close_site = concat!(
        "                input.close();\n",
        "                closed = true;\n",
    );
    let injected_close = concat!(
        "                input.close();\n",
        "                closed = true;\n",
        "                if (\"00_BOOT\".equals(path.getName())) {\n",
        "                    System.out.println(\"ExceptionRetainedClose: raw\");\n",
        "                    throw new IOException(\"injected partial close failure\");\n",
        "                }\n",
    );
    std::fs::write(
        &generic_path,
        replace_once(&generic, close_site, injected_close),
    )
    .unwrap();

    let support_path = kit.out.join("scripts/ExceptionRootsSupport.java");
    let support = std::fs::read_to_string(&support_path).unwrap();
    let acquisition_site = concat!(
        "            rawFile = PmeScriptSupport.openContainedChild(kitRoot,\n",
        "                    \"images/\" + expectedLabel, \"exception-root raw image\");\n",
        "            if (rawFile.size() != manifest.image.size\n",
    );
    let injected_acquisition = concat!(
        "            rawFile = PmeScriptSupport.openContainedChild(kitRoot,\n",
        "                    \"images/\" + expectedLabel, \"exception-root raw image\");\n",
        "            if (rawFile != null) {\n",
        "                throw new AssertionError(\"injected partial acquisition failure\");\n",
        "            }\n",
        "            if (rawFile.size() != manifest.image.size\n",
    );
    std::fs::write(
        &support_path,
        replace_once(&support, acquisition_site, injected_acquisition),
    )
    .unwrap();

    let failed = exception_apply_with(&home, &kit, &fixture.identity, "ExceptionSentinel.java");
    let diagnostics = process_diagnostics(&failed);
    assert!(
        diagnostics.contains("injected partial acquisition failure"),
        "partial acquisition injection did not fire:\n{diagnostics}"
    );
    assert!(
        String::from_utf8_lossy(&failed.stdout)
            .lines()
            .any(|line| line == "ExceptionRetainedClose: raw"),
        "partially acquired raw handle was not closed:\n{diagnostics}"
    );
    assert!(
        diagnostics.contains("injected partial close failure"),
        "retained-handle close failure was not preserved:\n{diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&failed.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")
                || line == "ExceptionSentinel: RAN"),
        "partial acquisition failure emitted success or continued:\n{diagnostics}"
    );
    let after = exception_run_script(&home, &kit, "ExceptionInspectState.java");
    assert!(after.status.success());
    assert_eq!(exception_state(&after), before);
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn defensive_rollback_precedes_abort_for_partial_commands_and_exact_context() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();

    let context_kit = generate_exception_apply_kit(&home, "partial_disassembly", &fixture);
    assert!(exception_import(&home, &context_kit).status.success());
    let seeded = exception_run_script(
        &home,
        &context_kit,
        "ExceptionSeedHeterogeneousContext.java",
    );
    assert!(seeded.status.success());
    let before = exception_run_script(
        &home,
        &context_kit,
        "ExceptionInspectHeterogeneousContext.java",
    );
    assert!(before.status.success());
    let before = exception_context_state(&before);
    assert_eq!(before, "0,none,1,1:instruction=none:function=none");

    let script_path = context_kit.out.join("scripts/ApplyExceptionRoots.java");
    let source = std::fs::read_to_string(&script_path).unwrap();
    let disassembly_site = concat!(
        "                AddressSetView disassembled = disassemble.getDisassembledAddressSet();\n",
        "                if (!disassembled.contains(instructionRange)\n",
    );
    let injected_disassembly = concat!(
        "                if (entry.equals(toAddr(0x40010220L))) {\n",
        "                    throw new ExceptionRootsSupport.RootError(\n",
        "                            \"injected partial disassembly failure\");\n",
        "                }\n",
        "                AddressSetView disassembled = disassemble.getDisassembledAddressSet();\n",
        "                if (!disassembled.contains(instructionRange)\n",
    );
    let rollback_site = "                rollback(error);\n";
    let verify_context = concat!(
        "                rollback(error);\n",
        "                Address probe = toAddr(0x40010220L);\n",
        "                if (currentProgram.getListing().getInstructionAt(probe) != null) {\n",
        "                    fail(\"defensive disassembly rollback left an instruction\");\n",
        "                }\n",
        "                ProgramContext probeContext = currentProgram.getProgramContext();\n",
        "                StringBuilder actual = new StringBuilder();\n",
        "                for (int offset = 0; offset < 4; offset++) {\n",
        "                    if (offset != 0) actual.append(',');\n",
        "                    RegisterValue value = probeContext.getNonDefaultValue(\n",
        "                            validated.tMode, probe.add(offset));\n",
        "                    actual.append(value == null || !value.hasValue()\n",
        "                            ? \"none\" : value.getUnsignedValue().toString());\n",
        "                }\n",
        "                if (!\"0,none,1,1\".equals(actual.toString())) {\n",
        "                    fail(\"defensive context rollback flattened prior runs: \" + actual);\n",
        "                }\n",
        "                System.out.println(\"ExceptionDefensiveRollback: disassembly/context clean\");\n",
    );
    let injected = replace_once(&source, disassembly_site, injected_disassembly);
    std::fs::write(
        &script_path,
        replace_once(&injected, rollback_site, verify_context),
    )
    .unwrap();
    let failed = exception_apply_with(
        &home,
        &context_kit,
        &fixture.identity,
        "ExceptionSentinel.java",
    );
    let diagnostics = process_diagnostics(&failed);
    assert!(
        diagnostics.contains("injected partial disassembly failure"),
        "partial disassembly injection did not fire:\n{diagnostics}"
    );
    assert!(
        String::from_utf8_lossy(&failed.stdout)
            .lines()
            .any(|line| line == "ExceptionDefensiveRollback: disassembly/context clean"),
        "defensive disassembly/context cleanup did not complete before abort:\n{diagnostics}"
    );
    let after = exception_run_script(
        &home,
        &context_kit,
        "ExceptionInspectHeterogeneousContext.java",
    );
    assert!(after.status.success());
    assert_eq!(exception_context_state(&after), before);
    let _ = std::fs::remove_dir_all(&context_kit.dir);

    let function_kit = generate_exception_apply_kit(&home, "partial_function", &fixture);
    assert!(exception_import(&home, &function_kit).status.success());
    let script_path = function_kit.out.join("scripts/ApplyExceptionRoots.java");
    let source = std::fs::read_to_string(&script_path).unwrap();
    let function_site = concat!(
        "            function = currentProgram.getFunctionManager().getFunctionAt(entry);\n",
        "            if (function == null || !function.getBody().equals(instructionRange)) {\n",
    );
    let injected_function = concat!(
        "            if (entry.equals(toAddr(0x40010220L))) {\n",
        "                throw new ExceptionRootsSupport.RootError(\n",
        "                        \"injected partial function failure\");\n",
        "            }\n",
        "            function = currentProgram.getFunctionManager().getFunctionAt(entry);\n",
        "            if (function == null || !function.getBody().equals(instructionRange)) {\n",
    );
    let verify_function = concat!(
        "                rollback(error);\n",
        "                if (currentProgram.getFunctionManager().getFunctionAt(\n",
        "                        toAddr(0x40010220L)) != null) {\n",
        "                    fail(\"defensive function rollback left a function\");\n",
        "                }\n",
        "                System.out.println(\"ExceptionDefensiveRollback: function clean\");\n",
    );
    let injected = replace_once(&source, function_site, injected_function);
    std::fs::write(
        &script_path,
        replace_once(&injected, rollback_site, verify_function),
    )
    .unwrap();
    let failed = exception_apply_with(
        &home,
        &function_kit,
        &fixture.identity,
        "ExceptionSentinel.java",
    );
    let diagnostics = process_diagnostics(&failed);
    assert!(
        diagnostics.contains("injected partial function failure"),
        "partial function injection did not fire:\n{diagnostics}"
    );
    assert!(
        String::from_utf8_lossy(&failed.stdout)
            .lines()
            .any(|line| line == "ExceptionDefensiveRollback: function clean"),
        "defensive function cleanup did not complete before abort:\n{diagnostics}"
    );
    let _ = std::fs::remove_dir_all(&function_kit.dir);
}

#[test]
fn complete_postflight_rejects_bytes_tmode_and_body_drift() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_fixture();
    let cases = [
        (
            "bytes",
            concat!(
                "            applyAll(validated, counts);\n",
                "                Address driftEntry = toAddr(0x40010220L);\n",
                "                currentProgram.getListing().clearCodeUnits(\n",
                "                        driftEntry, driftEntry.add(3), false);\n",
                "                currentProgram.getMemory().setByte(driftEntry, (byte) 0x40);\n",
                "                currentProgram.getProgramContext().setValue(\n",
                "                        validated.tMode, driftEntry, driftEntry.add(3), BigInteger.ONE);\n",
                "                AddressSet driftRange = new AddressSet(driftEntry, driftEntry.add(3));\n",
                "                DisassembleCommand drift = new DisassembleCommand(\n",
                "                        driftEntry, driftRange, false);\n",
                "                drift.enableCodeAnalysis(false);\n",
                "                if (!drift.applyTo(currentProgram, monitor)) {\n",
                "                    fail(\"injected changed-byte disassembly failed\");\n",
                "                }\n",
            ),
            "postflight exception-root instruction bytes are stale",
        ),
        (
            "tmode",
            concat!(
                "            applyAll(validated, counts);\n",
                "                Address driftEntry = toAddr(0x40010220L);\n",
                "                currentProgram.getListing().clearCodeUnits(\n",
                "                        driftEntry, driftEntry.add(3), false);\n",
                "                currentProgram.getProgramContext().setValue(\n",
                "                        validated.tMode, driftEntry, driftEntry.add(3), BigInteger.ZERO);\n",
                "                AddressSet driftRange = new AddressSet(driftEntry, driftEntry.add(3));\n",
                "                DisassembleCommand drift = new DisassembleCommand(\n",
                "                        driftEntry, driftRange, false);\n",
                "                drift.enableCodeAnalysis(false);\n",
                "                if (!drift.applyTo(currentProgram, monitor)) {\n",
                "                    fail(\"injected wrong-TMode disassembly failed\");\n",
                "                }\n",
            ),
            "postflight exception-root instruction ISA is stale",
        ),
        (
            "body",
            concat!(
                "            applyAll(validated, counts);\n",
                "                Address driftEntry = toAddr(0x40010220L);\n",
                "                currentProgram.getFunctionManager().getFunctionAt(driftEntry)\n",
                "                        .setBody(new AddressSet(driftEntry, driftEntry));\n",
            ),
            "postflight exception-root function body does not contain its instruction",
        ),
    ];

    for (case, injected_site, expected_error) in cases {
        let kit = generate_exception_apply_kit(&home, &format!("postflight_{case}"), &fixture);
        assert!(exception_import(&home, &kit).status.success());
        let before = exception_run_script(&home, &kit, "ExceptionInspectState.java");
        assert!(before.status.success());
        let before = exception_state(&before);
        let script_path = kit.out.join("scripts/ApplyExceptionRoots.java");
        let source = std::fs::read_to_string(&script_path).unwrap();
        std::fs::write(
            &script_path,
            replace_once(
                &source,
                "            applyAll(validated, counts);\n",
                injected_site,
            ),
        )
        .unwrap();

        let rejected =
            exception_apply_with(&home, &kit, &fixture.identity, "ExceptionSentinel.java");
        let diagnostics = process_diagnostics(&rejected);
        assert!(
            diagnostics.contains(expected_error),
            "postflight {case} drift was not rejected:\n{diagnostics}"
        );
        assert!(
            !String::from_utf8_lossy(&rejected.stdout)
                .lines()
                .any(|line| line.starts_with("ApplyExceptionRoots: ")
                    || line == "ExceptionSentinel: RAN"),
            "postflight {case} drift emitted success or continued:\n{diagnostics}"
        );
        let after = exception_run_script(&home, &kit, "ExceptionInspectState.java");
        assert!(after.status.success());
        assert_eq!(exception_state(&after), before);
        let _ = std::fs::remove_dir_all(&kit.dir);
    }
}

#[test]
fn pass1_relocated_same_role_claims_keep_unique_primaries() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let fixture = exception_relocated_same_targets_fixture();
    let kit = generate_exception_apply_kit(&home, "relocated_same_targets", &fixture);
    let imported = exception_import(&home, &kit);
    assert!(
        imported.status.success(),
        "relocated exception fixture import failed:\n{}",
        process_diagnostics(&imported)
    );

    let applied =
        exception_apply_with(&home, &kit, &fixture.identity, "ExceptionInspectState.java");
    let diagnostics = process_diagnostics(&applied);
    assert!(
        applied.status.success(),
        "relocated same-target exception application failed:\n{diagnostics}"
    );
    let summary = exception_summary(&applied);
    assert_eq!(summary["tables"], 2);
    assert_eq!(summary["roles"], 16);
    assert_eq!(summary["entries"], 7);
    assert_eq!(summary["shared_entries"], 1);
    assert_eq!(summary["names_not_requested"], 1);
    assert_exception_conservation(&summary);
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn pass1_applies_scatter_backed_exception_root() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };
    let (kit, fixture) = generate_exception_scatter_apply_kit(&home, "scatter");
    let imported = exception_import(&home, &kit);
    assert!(
        imported.status.success(),
        "scatter exception fixture import failed:\n{}",
        process_diagnostics(&imported)
    );
    let first = exception_apply_with(
        &home,
        &kit,
        &fixture.identity,
        "ExceptionInspectScatterApplied.java",
    );
    let diagnostics = process_diagnostics(&first);
    assert!(
        first.status.success()
            && String::from_utf8_lossy(&first.stdout)
                .lines()
                .any(|line| line == "ExceptionInspectScatterApplied: ok"),
        "scatter-backed exception application failed:\n{diagnostics}"
    );
    let summary = exception_summary(&first);
    assert_eq!(summary["entries"], 7);
    assert_eq!(summary["functions_created"], 6);
    assert_eq!(summary["functions_existing"], 1);
    assert_eq!(summary["names_applied"], 5);
    assert_exception_conservation(&summary);

    let replay = exception_apply_with(
        &home,
        &kit,
        &fixture.identity,
        "ExceptionInspectScatterApplied.java",
    );
    assert!(
        replay.status.success(),
        "scatter-backed exception replay failed:\n{}",
        process_diagnostics(&replay)
    );
    let replay_summary = exception_summary(&replay);
    assert_eq!(replay_summary["functions_reapplied"], 6);
    assert_eq!(replay_summary["functions_existing"], 1);
    assert_exception_conservation(&replay_summary);

    let scatter: serde_json::Value =
        serde_json::from_slice(&std::fs::read(kit.scatter_path.as_ref().unwrap()).unwrap())
            .unwrap();
    let payload_relative = scatter["entries"][3]["materialization"]["path"]
        .as_str()
        .unwrap();
    let payload = kit
        .scatter_path
        .as_ref()
        .unwrap()
        .parent()
        .unwrap()
        .join(payload_relative);
    let original = std::fs::read(&payload).unwrap();
    let mut corrupted = original.clone();
    corrupted[0] ^= 0x80;
    std::fs::write(&payload, corrupted).unwrap();
    let rejected = exception_apply_with(
        &home,
        &kit,
        &fixture.identity,
        "ExceptionInspectScatterApplied.java",
    );
    let rejected_diagnostics = process_diagnostics(&rejected);
    assert!(
        rejected_diagnostics.contains("scatter payload identity does not match"),
        "corrupt scatter payload was accepted:\n{rejected_diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&rejected.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")),
        "corrupt scatter payload emitted a success summary"
    );
    std::fs::write(payload, original).unwrap();
    let _ = std::fs::remove_dir_all(&kit.dir);
}

#[test]
fn pass1_exception_roots_fail_closed_without_residue() {
    let Some(home) = find_ghidra_home() else {
        panic!("configured real-Ghidra exception test requires /opt/ghidra");
    };

    let unknown_base = exception_fixture();
    let mut unknown_manifest = unknown_base.manifest.strip_suffix('}').unwrap().to_string();
    unknown_manifest.push_str(",\n  \"unexpected\": true\n}");
    let unknown_schema = exception_fixture_with_manifest(unknown_base, unknown_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "unknown_schema",
        &unknown_schema,
        &unknown_schema.identity,
        None,
        "malformed exception-root manifest",
    );

    let trailing_base = exception_fixture();
    let trailing_manifest = format!("{}\n", trailing_base.manifest);
    let trailing = exception_fixture_with_manifest(trailing_base, trailing_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "trailing_whitespace",
        &trailing,
        &trailing.identity,
        None,
        "manifest bytes are not in canonical field order or JSON spelling",
    );

    let minified_base = exception_fixture();
    let minified_manifest = minify_json_whitespace(&minified_base.manifest);
    let minified = exception_fixture_with_manifest(minified_base, minified_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "minified_manifest",
        &minified,
        &minified.identity,
        None,
        "manifest bytes are not in canonical field order or JSON spelling",
    );

    let escaped_key_base = exception_fixture();
    let escaped_key_manifest =
        replace_once(&escaped_key_base.manifest, "\"format\"", "\"\\u0066ormat\"");
    let escaped_key = exception_fixture_with_manifest(escaped_key_base, escaped_key_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "escaped_key_manifest",
        &escaped_key,
        &escaped_key.identity,
        None,
        "manifest bytes are not in canonical field order or JSON spelling",
    );

    let scalar_base = exception_fixture();
    let scalar_manifest = replace_once(
        &scalar_base.manifest,
        "\"schema_version\": 1",
        "\"schema_version\": \"1\"",
    );
    let scalar_type = exception_fixture_with_manifest(scalar_base, scalar_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "scalar_type",
        &scalar_type,
        &scalar_type.identity,
        None,
        "schema_version is not a canonical unsigned decimal",
    );

    let numeric_base = exception_fixture();
    let numeric_manifest = replace_once(
        &numeric_base.manifest,
        "\"schema_version\": 1",
        "\"schema_version\": 1e0",
    );
    let numeric_spelling = exception_fixture_with_manifest(numeric_base, numeric_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "numeric_spelling",
        &numeric_spelling,
        &numeric_spelling.identity,
        None,
        "schema_version is not a canonical unsigned decimal",
    );

    let observation_base = exception_fixture();
    let observations = (0..65)
        .map(|index| {
            format!(
                concat!(
                    "      {{\n",
                    "        \"pc\": \"{:#010x}\",\n",
                    "        \"isa\": \"arm\",\n",
                    "        \"source_register\": 0,\n",
                    "        \"conditional\": false,\n",
                    "        \"exact_value\": null,\n",
                    "        \"definitions\": [],\n",
                    "        \"dominates_handoffs\": false\n",
                    "      }}",
                ),
                EXCEPTION_BASE + 0x800 + index * 4
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let observation_manifest = replace_once(
        &observation_base.manifest,
        concat!(
            "  \"relocation\": {\n",
            "    \"status\": \"not_observed\",\n",
            "    \"selected\": null,\n",
            "    \"table_address\": null,\n",
            "    \"observations\": [],\n",
            "    \"handoffs\": [],\n",
            "    \"reason\": null\n",
            "  }",
        ),
        &format!(
            concat!(
                "  \"relocation\": {{\n",
                "    \"status\": \"unresolved\",\n",
                "    \"selected\": null,\n",
                "    \"table_address\": null,\n",
                "    \"observations\": [\n",
                "{observations}\n",
                "    ],\n",
                "    \"handoffs\": [],\n",
                "    \"reason\": null\n",
                "  }}",
            ),
            observations = observations,
        ),
    );
    let too_many_observations =
        exception_fixture_with_manifest(observation_base, observation_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "vbar_limit",
        &too_many_observations,
        &too_many_observations.identity,
        None,
        "relocation.observations exceeds its element ceiling",
    );

    let valid = exception_fixture();
    assert_exception_rejected_unchanged(
        &home,
        "wrong_identity",
        &valid,
        "v1:0000000000000000000000000000000000000000000000000000000000000000:1:7",
        None,
        "identity does not match",
    );

    let vector_base = exception_fixture();
    assert_eq!(
        vector_base
            .manifest
            .matches("\"form\": \"direct_branch\"")
            .count(),
        2
    );
    let vector_manifest = vector_base
        .manifest
        .replace("\"form\": \"direct_branch\"", "\"form\": \"literal_load\"");
    let vector = exception_fixture_with_manifest(vector_base, vector_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "vector_form",
        &vector,
        &vector.identity,
        None,
        "does not decode to its declared root",
    );

    let cross_isa_base = exception_fixture();
    assert_eq!(cross_isa_base.manifest.matches("\"0x40010200\"").count(), 7);
    let cross_isa_manifest = cross_isa_base
        .manifest
        .replace("\"0x40010200\"", "\"0x40010220\"");
    let cross_isa = exception_fixture_with_manifest(cross_isa_base, cross_isa_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "cross_isa",
        &cross_isa,
        &cross_isa.identity,
        None,
        "cross-ISA aliases",
    );

    let duplicate_base = exception_fixture();
    let table_prefix = "  \"tables\": [\n";
    let table_start = duplicate_base.manifest.find(table_prefix).unwrap() + table_prefix.len();
    let table_suffix = "\n  ],\n  \"roots\": [";
    let table_end = duplicate_base.manifest[table_start..]
        .find(table_suffix)
        .unwrap()
        + table_start;
    let initial_table = &duplicate_base.manifest[table_start..table_end];
    let relocated_table = replace_once(
        initial_table,
        "      \"kind\": \"initial\"",
        "      \"kind\": \"relocated\"",
    );
    let duplicate_manifest = format!(
        "{}{},\n{}{}",
        &duplicate_base.manifest[..table_start],
        initial_table,
        relocated_table,
        &duplicate_base.manifest[table_end..]
    );
    let duplicate_table = exception_fixture_with_manifest(duplicate_base, duplicate_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "duplicate_table",
        &duplicate_table,
        &duplicate_table.identity,
        None,
        "duplicate addresses",
    );

    let relocated_base = exception_relocated_same_targets_fixture();
    let canonical_base = exception_fixture();
    let relocation_start = relocated_base.manifest.find("  \"relocation\": {").unwrap();
    let relocation_end = relocated_base.manifest[relocation_start..]
        .find("  \"tables\": [")
        .unwrap()
        + relocation_start;
    let canonical_relocation_start = canonical_base.manifest.find("  \"relocation\": {").unwrap();
    let canonical_relocation_end = canonical_base.manifest[canonical_relocation_start..]
        .find("  \"tables\": [")
        .unwrap()
        + canonical_relocation_start;
    let unbound_manifest = format!(
        "{}{}{}",
        &relocated_base.manifest[..relocation_start],
        &canonical_base.manifest[canonical_relocation_start..canonical_relocation_end],
        &relocated_base.manifest[relocation_end..]
    );
    let unbound_relocated = exception_fixture_with_manifest(relocated_base, unbound_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "unbound_relocated",
        &unbound_relocated,
        &unbound_relocated.identity,
        None,
        "non-relocated evidence published a relocated table",
    );

    let root_bytes_base = exception_fixture();
    let arm_hash = "bb05c128192d9feb3efd889a7572f5283753e943d3dfb9da55d02f2fe9e6dee2";
    assert_eq!(root_bytes_base.manifest.matches(arm_hash).count(), 14);
    let root_bytes_manifest = root_bytes_base.manifest.replace(
        arm_hash,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let root_bytes = exception_fixture_with_manifest(root_bytes_base, root_bytes_manifest);
    assert_exception_rejected_unchanged(
        &home,
        "root_bytes",
        &root_bytes,
        &root_bytes.identity,
        None,
        "root instruction hash does not match runtime bytes",
    );

    assert_exception_rejected_unchanged(
        &home,
        "late_collision",
        &valid,
        &valid.identity,
        Some("ExceptionSeedLateCollision.java"),
        "instruction/data collision exists within exception root 40010220",
    );

    let rollback_kit = generate_exception_apply_kit(&home, "rollback", &valid);
    let imported = exception_import(&home, &rollback_kit);
    assert!(imported.status.success());
    let before = exception_run_script(&home, &rollback_kit, "ExceptionInspectState.java");
    assert!(before.status.success());
    let before = exception_state(&before);
    let script_path = rollback_kit.out.join("scripts/ApplyExceptionRoots.java");
    let source = std::fs::read_to_string(&script_path).unwrap();
    let application_site = "            applyOne(validated, plan, counts);\n";
    let injected = concat!(
        "            applyOne(validated, plan, counts);\n",
        "            if (counts.functionsCreated == 3) {\n",
        "                throw new ExceptionRootsSupport.RootError(\n",
        "                        \"injected exception-root rollback failure\");\n",
        "            }\n",
    );
    std::fs::write(
        &script_path,
        replace_once(&source, application_site, injected),
    )
    .unwrap();
    let rejected = exception_apply_with(
        &home,
        &rollback_kit,
        &rollback_kit.identity,
        "ExceptionSentinel.java",
    );
    let diagnostics = process_diagnostics(&rejected);
    assert!(
        diagnostics.contains("injected exception-root rollback failure"),
        "injected exception rollback did not fire:\n{diagnostics}"
    );
    assert!(
        !String::from_utf8_lossy(&rejected.stdout)
            .lines()
            .any(|line| line.starts_with("ApplyExceptionRoots: ")
                || line == "ExceptionSentinel: RAN"),
        "rolled-back exception run emitted success or continued"
    );
    let after = exception_run_script(&home, &rollback_kit, "ExceptionInspectState.java");
    assert!(after.status.success());
    assert_eq!(exception_state(&after), before);
    let _ = std::fs::remove_dir_all(&rollback_kit.dir);
}
