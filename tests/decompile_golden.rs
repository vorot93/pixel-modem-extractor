//! Self-contained end-to-end test of the `--run` path: craft a tiny ARM blob in a
//! valid TOC, drive real Ghidra headless, and assert the export. Gated on locating
//! Ghidra ($GHIDRA_INSTALL_DIR or /opt/ghidra); skips cleanly otherwise. No
//! proprietary firmware needed.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;

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
    .env("XDG_CONFIG_HOME", config)
    .env("XDG_CACHE_HOME", cache)
    .env("GHIDRA_HEADLESS_JAVA_OPTIONS", java_options)
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
    let mutation_point =
        "        writeFunctionsJson(new File(outDir, \"functions.json\"), fm, listing);\n";
    assert_eq!(script.matches(mutation_point).count(), 1);
    let injected = script.replacen(
        mutation_point,
        concat!(
            "        writeFunctionsJson(new File(outDir, \"functions.json\"), fm, listing);\n",
            "        if (outDir.isDirectory()) {\n",
            "            throw new RuntimeException(\n",
            "                    \"deterministic partial export fault after functions.json\");\n",
            "        }\n"
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
    let mutation_point = "            w.println(\"[\");\n";
    assert_eq!(script.matches(mutation_point).count(), 1);
    let injected = script.replacen(
        mutation_point,
        concat!(
            "            w.close();\n",
            "            w.println(\"[\");\n"
        ),
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
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    // Fixture-only replacement: run_two_pass executes this against the saved
    // temporary project before the shipping ExportDecomp.java post-script.
    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
        r#"//@category PixelModemTest
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.SourceType;

public class ApplySymbols extends GhidraScript {
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
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let map = out.join("mixed-gap-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
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
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
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

public class ApplySymbols extends GhidraScript {
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
    let map = out.join("entry-interior-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
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
fn saved_program_rejects_instruction_free_body_range_outside_u32() {
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
        ghidra_home: Some(home),
        processor: "x86:LE:64:default".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();

    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
        r#"//@category PixelModemTest
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class ApplySymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionManager functions = currentProgram.getFunctionManager();
        while (functions.getFunctionCount() != 0) {
            FunctionIterator iterator = functions.getFunctions(true);
            Function function = iterator.next();
            functions.removeFunction(function.getEntryPoint());
        }
        Address entry = toAddr(0);
        clearListing(entry, entry);
        if (!disassemble(entry)) throw new Exception("failed to disassemble x86 fixture");
        Address high = toAddr(0x1_0000_0000L);
        currentProgram.getMemory().createInitializedBlock(
            "outside_u32", high, 4, (byte) 0, monitor, false);
        AddressSet body = new AddressSet(entry, entry);
        body.addRange(high, high.add(3));
        functions.createFunction(
            "body_outside_u32", entry, body, SourceType.USER_DEFINED);
        println("ApplySymbols: applied 1 names, 0 plate comments, skipped 0");
    }
}
"#,
    )
    .unwrap();
    let map = out.join("body-outside-u32-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert!(
        matches!(
            &pass2.outcomes["00_BOOT"],
            pixel_modem_extractor::decompile::Pass2ProcessOutcome::Failed(reason)
                if reason.contains("incomplete current export")
        ),
        "an instruction-free out-of-domain body range must fail pass 2: {:?}",
        pass2.outcomes["00_BOOT"]
    );
    for path in [
        out.join("export/00_BOOT/functions.json"),
        out.join("export/00_BOOT/disasm.lst"),
        out.join("export/00_BOOT/decompiled.c"),
        out.join("export/00_BOOT.complete"),
    ] {
        assert!(
            !path.exists(),
            "failed pass-2 export survived: {}",
            path.display()
        );
    }
    let application_log = read_ghidra_application_log(&out);
    assert!(
        application_log.contains("unassignable producer address outside u32"),
        "missing producer-integrity failure in application log:\n{application_log}"
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
        ghidra_home: Some(home),
        processor: "ARM:LE:32:v7".to_string(),
        no_thumb_decompile: false,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let pass1 = pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    std::fs::write(
        out.join("scripts/ApplySymbols.java"),
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

public class ApplySymbols extends GhidraScript {
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
    let map = out.join("quarantine-map.json");
    std::fs::write(&map, b"{}").unwrap();
    let inputs = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map, 1)),
            global_map: None,
            global_types_map: None,
        },
    )]);
    let pass2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1, &opts, &out, &inputs).unwrap();
    assert_eq!(
        pass2.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
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
        ghidra_home: Some(home),
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
    "start":"0x0","end":"0x2",
    "attempts":[
      {"producer":"radare2","status":"failed","stdout":null,"error":"radare2 fixture failure"},
      {"producer":"rizin","status":"succeeded","stdout":{"path":"thumb/00000000.rizin.stdout","bytes":1,"blake3":"0000000000000000000000000000000000000000000000000000000000000000"},"error":null}
    ],
    "function_runs":[{"producer":"rizin","first_function":0,"function_count":1,"substantial":0,"accepted":1,"quarantined":0}]
  }],
  "functions": [{
    "name":"retained_thumb_fixture","entry":"0x0","end":"0x2","size":2,
    "decode_ranges":[{"isa":"thumb","start":"0x0","end":"0x2","blake3":"__RANGE_BLAKE3__"}],
    "decode_range_errors":[],"body_kind":"thumb_disassembly","body":"","data_refs":[]
  }]
}"#)
    .unwrap()
    .replace(
        "__RANGE_BLAKE3__",
        blake3::hash(&arm[..2]).to_hex().as_ref(),
    )
    .into_bytes();
    std::fs::write(
        out.join("export/00_BOOT/thumb_functions.json"),
        &retained_thumb,
    )
    .unwrap();

    // One-symbol map: rename entry 0x0 -> boot_reset_handler with one annotation.
    // ApplySymbols.java reads `entry`, `name`, `tier=recovered`, and `annotations[]`.
    let maps_dir = out.join("symbol_maps");
    std::fs::create_dir_all(&maps_dir).unwrap();
    let map_path = maps_dir.join("00_BOOT.json");
    let annotation = "evidence: tier=recovered src=arm-db";
    let symbol_map = serde_json::json!({
        "tool_version": "test",
        "image": "00_BOOT",
        "source_blake3": "0",
        "functions_blake3": "0",
        "symbols": [
            {
                "entry": "0x0",
                "arch": "a32",
                "original_name": "FUN_00000000",
                "name": "boot_reset_handler",
                "tier": "recovered",
                "annotations": [annotation],
            },
        ],
    });
    std::fs::write(
        &map_path,
        serde_json::to_string_pretty(&symbol_map).unwrap(),
    )
    .unwrap();

    let global_map_path = maps_dir.join("00_BOOT-globals.json");

    // Characterize ApplyGlobals' fail-whole-map preflight before 0x20 has
    // been renamed: numerically identical selected addresses in different
    // hexadecimal spellings reject the entire map atomically. The script
    // returns normally, so ExportDecomp still completes in this process.
    let duplicate_global_map = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [
            {
                "address": "0x20",
                "name": "duplicate_first_must_not_apply",
                "tier": "recovered",
            },
            {
                "address": "00000020",
                "name": "duplicate_second_must_not_apply",
                "tier": "recovered",
            },
        ],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&duplicate_global_map).unwrap(),
    )
    .unwrap();
    let duplicate_globals_only = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: Some(prepared_pass2_map(&global_map_path, 2)),
            global_types_map: None,
        },
    )]);
    let duplicate_run = pixel_modem_extractor::decompile::run_two_pass(
        pass1_report,
        &opts,
        &out,
        &duplicate_globals_only,
    )
    .unwrap();
    let duplicate_report = duplicate_run.report;
    let boot = duplicate_report
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .unwrap();
    assert!(boot.pass2_error.is_none());
    assert!(boot.globals_applied.is_none());
    assert!(boot.globals_apply_skipped.is_none());
    assert!(
        boot.globals_apply_error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate selected address")),
        "globals_apply_error: {:?}",
        boot.globals_apply_error
    );
    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(!c.contains("duplicate_first_must_not_apply"));
    assert!(!c.contains("duplicate_second_must_not_apply"));

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
            function_map: Some(prepared_pass2_map(&map_path, 1)),
            global_map: Some(prepared_pass2_map(&global_map_path, 2)),
            global_types_map: None,
        },
    )]);

    // Pass 2: pass pass1_report in (do NOT re-run pass 1).
    let rep2 =
        pixel_modem_extractor::decompile::run_two_pass(duplicate_report, &opts, &out, &inputs)
            .unwrap()
            .report;

    // (c) pass2_applied == Some(1) — ApplySymbols reports 1 rename.
    let boot = rep2
        .images
        .iter()
        .find(|r| r.label == "00_BOOT")
        .expect("00_BOOT in pass-2 report");
    assert_eq!(
        boot.pass2_applied,
        Some(1),
        "pass2_applied should be Some(1): {:?}",
        boot.pass2_error
    );
    assert!(
        boot.pass2_error.is_none(),
        "pass2_error: {:?}",
        boot.pass2_error
    );
    assert_eq!(boot.globals_applied, Some(1));
    assert_eq!(boot.globals_apply_skipped, Some(1));
    assert!(
        boot.globals_apply_error.is_none(),
        "globals_apply_error: {:?}",
        boot.globals_apply_error
    );

    // (a) renamed function appears in the regenerated decompiled.c.
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(
        c.contains("boot_reset_handler"),
        "renamed function missing from decompiled.c:\n{c}"
    );
    assert!(
        c.contains("recovered_global_word"),
        "Recovered global missing at the decompiled reference site:\n{c}"
    );
    assert!(!c.contains("provisional_must_not_apply"));
    assert!(!c.contains("outside_memory_global"));

    // (b) annotation appears as a comment line. Ghidra 12's ExportDecomp
    // renders plate comments as `/* ... */` blocks; accept the line-comment
    // rendering as well so the test remains compatible with either exporter
    // representation while requiring the exact annotation text.
    let block = format!("/* {annotation} */");
    let line = format!("// {annotation}");
    assert!(
        c.lines().any(|l| l.trim() == block || l.trim() == line),
        "annotation plate comment missing from decompiled.c \
         (looked for `{block}` or `{line}`):\n{c}"
    );

    // Second attempt: the exact symbol is now USER_DEFINED, so strict
    // ownership preserves it and classifies the candidate as non-default.
    let second_global_map = serde_json::json!({
        "format": "pixel-modem-extractor-globals-v1",
        "image": "00_BOOT",
        "globals": [{
            "address": "0x20",
            "name": "second_attempt_must_not_replace",
            "tier": "recovered",
        }],
    });
    std::fs::write(
        &global_map_path,
        serde_json::to_string_pretty(&second_global_map).unwrap(),
    )
    .unwrap();
    let globals_only = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: None,
            global_map: Some(prepared_pass2_map(&global_map_path, 1)),
            global_types_map: None,
        },
    )]);
    let rep3 = pixel_modem_extractor::decompile::run_two_pass(rep2, &opts, &out, &globals_only)
        .unwrap()
        .report;
    let boot = rep3.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.globals_applied, Some(0));
    assert_eq!(boot.globals_apply_skipped, Some(1));
    assert!(boot.globals_apply_error.is_none());
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(c.contains("recovered_global_word"));
    assert!(!c.contains("second_attempt_must_not_replace"));

    // A fail-whole-map preflight error returns normally, allowing the
    // independent function rename and final export to complete in this same
    // process while applying zero globals.
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
        &global_map_path,
        serde_json::to_string_pretty(&invalid_global_map).unwrap(),
    )
    .unwrap();
    let third_function_map = serde_json::json!({
        "image": "00_BOOT",
        "symbols": [{
            "entry": "0x0",
            "name": "function_exported_despite_invalid_globals",
            "tier": "recovered",
            "annotations": [],
        }],
    });
    std::fs::write(
        &map_path,
        serde_json::to_string_pretty(&third_function_map).unwrap(),
    )
    .unwrap();
    let invalid_combined = HashMap::from([(
        "00_BOOT".to_string(),
        pixel_modem_extractor::decompile::Pass2Input {
            function_map: Some(prepared_pass2_map(&map_path, 1)),
            global_map: Some(prepared_pass2_map(&global_map_path, 1)),
            global_types_map: None,
        },
    )]);
    let invalid_run =
        pixel_modem_extractor::decompile::run_two_pass(rep3, &opts, &out, &invalid_combined)
            .unwrap();
    assert_eq!(
        invalid_run.outcomes["00_BOOT"],
        pixel_modem_extractor::decompile::Pass2ProcessOutcome::ProcessSucceeded
    );
    let rep4 = invalid_run.report;
    let boot = rep4.images.iter().find(|r| r.label == "00_BOOT").unwrap();
    assert_eq!(boot.pass2_applied, Some(1));
    assert!(boot.pass2_error.is_none());
    assert!(boot.globals_applied.is_none());
    assert!(boot.globals_apply_skipped.is_none());
    assert!(boot.globals_apply_error.is_some());
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(c.contains("function_exported_despite_invalid_globals"));
    assert!(c.contains("recovered_global_word"));
    assert!(!c.contains("invalid_map_must_apply_zero"));
    let final_functions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exp.join("functions.json")).unwrap()).unwrap();
    for function in final_functions.as_array().unwrap() {
        let entry = function["entry"].as_str().unwrap();
        assert_eq!(
            serde_json::json!({
                "decode_ranges": function["decode_ranges"],
                "decode_range_errors": function["decode_range_errors"],
            }),
            pass1_projections[entry],
            "pass 2 changed mandatory execution projection for {entry}"
        );
    }
    assert_eq!(
        std::fs::read(exp.join("thumb_functions.json")).unwrap(),
        retained_thumb,
        "pass 2 must preserve the retained tagged Thumb sidecar byte-for-byte"
    );

    let _ = std::fs::remove_dir_all(&dir);
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

/// Hand-assembled minimal Thumb-2 function: `push {r7, lr}; movs r0, #0; pop {r7, pc}`.
/// Used by the Phase-2 mode-dispatch e2e tests below. Under the `ARM:LE:32:v7`
/// language Ghidra does not auto-switch into Thumb mode for these bytes alone
/// (no `BX` with the LSB set, no `__thumb` symbol), so the assertion the tests
/// make is on TameAnalysis's `mode=` log line rather than on Ghidra's
/// interpretation of the payload — see the per-test notes.
fn thumb_function_bytes() -> Vec<u8> {
    // push {r7, lr}   -> 0xb580 (LE: 80 b5)
    // movs r0, #0     -> 0x2000 (LE: 00 20)
    // pop {r7, pc}    -> 0xbd80 (LE: 80 bd)
    vec![0x80, 0xb5, 0x00, 0x20, 0x80, 0xbd]
}

/// Locate Ghidra's per-run `application.log`, written under
/// `<out>/ghidra_config/user-ghidra/ghidra_<VERSION>_DEV/application.log`. The
/// version-segment path component varies with the Ghidra release, so we walk the
/// directory to find it. Returns the parsed log text.
fn read_ghidra_application_log(out: &std::path::Path) -> String {
    let user_ghidra = out.join("ghidra_config").join("user-ghidra");
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&user_ghidra) {
        for entry in entries.flatten() {
            let candidate = entry.path().join("application.log");
            if candidate.exists() {
                found.push(candidate);
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "expected exactly one application.log under {}, found {found:?}",
        user_ghidra.display()
    );
    std::fs::read_to_string(&found[0]).unwrap()
}

/// Phase-2 e2e: under `--thumb-decompile` (default) `run_report` dispatches
/// `TameAnalysis mode=tighten`, the tightened mode emitted by `headless_args`.
/// With the 6-byte Thumb fixture, Ghidra does not auto-discover a Thumb
/// function under `ARM:LE:32:v7` (no mode-switch instruction), so the assertion
/// verifies (a) the run completed and produced a non-empty `decompiled.c`, and
/// (b) TameAnalysis's startup line in `application.log` records `mode=tighten`.
/// Together with `no_thumb_decompile_flag_falls_back_to_datamark` this locks in
/// the per-mode dispatch on the same fixture.
#[test]
fn tightened_tame_analysis_dispatchs_tighten_mode() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    let payload = thumb_function_bytes();
    let modem = craft_modem_bin(&payload);

    let dir = std::env::temp_dir().join(format!("pme_decompile_t2_{}", std::process::id()));
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
    let report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).expect("run_report");

    assert!(
        report.images.iter().any(|r| r.label == "00_BOOT"
            && matches!(
                r.outcome,
                pixel_modem_extractor::decompile::ImageOutcome::Analyzed(_)
            )),
        "tighten run should have analyzed 00_BOOT: {report:?}"
    );

    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(
        !c.trim().is_empty(),
        "tighten run should produce a non-empty decompiled.c"
    );

    let log = read_ghidra_application_log(&out);
    assert!(
        log.contains("TameAnalysis: mode=tighten"),
        "TameAnalysis should have logged mode=tighten; log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Phase-2 e2e: the `--no-thumb-decompile` escape hatch flips `TameAnalysis` to
/// `mode=datamark`. The 6-byte fixture is far below the 1 MiB `thumb_regions`
/// threshold, so datamark mode marks no regions (Ghidra's analysis matches the
/// tighten run byte-for-byte); the assertion is therefore on the `mode=datamark`
/// dispatch line in `application.log` — proving the Opts flag wires through to
/// `headless_args` and into the spawned script under real Ghidra.
#[test]
fn no_thumb_decompile_flag_falls_back_to_datamark() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    let payload = thumb_function_bytes();
    let modem = craft_modem_bin(&payload);

    let dir = std::env::temp_dir().join(format!("pme_decompile_d2_{}", std::process::id()));
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
        no_thumb_decompile: true,
        rizin_fallback: false,
        tighten_wall_clock_budget_override: None,
        no_skip_opaque: false,
    };
    let _report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).expect("run_report");

    let log = read_ghidra_application_log(&out);
    assert!(
        log.contains("TameAnalysis: mode=datamark"),
        "TameAnalysis should have logged mode=datamark under --no-thumb-decompile; log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
    );
    assert!(
        !log.contains("TameAnalysis: mode=tighten"),
        "datamark run should NOT have logged mode=tighten; log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
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

#[path = "support/pal_fixture.rs"]
mod pal_fixture;

/// Drives `PalTasksSupport` inside real Ghidra against the canonical
/// fixture kit and malformed variants: digest vectors, strict parsing,
/// path containment, raw/scatter byte tampering, storage/task/application
/// partition rejections, the v2 symbol-map reader, and the applied-state
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

    // The strict v2 symbol-map fixtures.
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
        "\"format\": \"pixel-modem-extractor-symbol-map-v2\",",
        "\"format\": \"pixel-modem-extractor-symbol-map-v2\",\n  \"unexpected\": true,",
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
        if (functions.getFunctionAt(toAddr(0x4001_1000L)) == null) {
            throw new AssertionError("the scatter-backed task function is missing");
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
        if (!"stale".equals(mode)) {
            // The stale mode certifies an intact applied state; every other
            // mode must show no task function at any application entry.
            for (long entry : ENTRIES) {
                if (currentProgram.getFunctionManager().getFunctionAt(toAddr(entry)) != null) {
                    throw new AssertionError("a task function survived at 0x"
                            + Long.toHexString(entry));
                }
            }
        }
        if ("pristine".equals(mode)) {
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

struct PalApplyKit {
    dir: PathBuf,
    out: PathBuf,
    identity: String,
    manifest_path: PathBuf,
    scatter_path: PathBuf,
    kit_root: PathBuf,
}

/// Generates the extended seven-task PAL kit (image, scatter map,
/// manifest, staged scripts, helper seeds/inspectors) for one case.
fn generate_pal_apply_kit(home: &std::path::Path, case: &str) -> PalApplyKit {
    let dir = std::env::temp_dir().join(format!("pme_pal_apply_{case}_{}", std::process::id()));
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
    let scatter_hash = pal_fixture::blake3_hex(&std::fs::read(&scatter_path).unwrap());
    let manifest = pal_fixture::extended_manifest(&pal_fixture::craft_main_image(), &scatter_hash);
    let manifest_dir = out.join("pal_tasks/02_MAIN");
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let manifest_path = manifest_dir.join("tasks.json");
    std::fs::write(&manifest_path, &manifest).unwrap();
    let identity = pal_fixture::extended_identity(&manifest);

    for (name, source) in [
        ("PalSeedMeaningful.java", PAL_SEED_MEANINGFUL_JAVA),
        ("PalSeedWrongIsa.java", PAL_SEED_WRONG_ISA_JAVA),
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
            ("PER_ENTRY_BUDGET_MS = 30_000L", "PER_ENTRY_BUDGET_MS = 1L"),
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
/// (mode, identity, regions), optionally followed by one post-script. A
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
        &["datamark", "none", "40010000:40"],
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
    let mut regions_4097: Vec<&str> = vec!["datamark", "none"];
    regions_4097.extend(
        (0..4097).map(|index| {
            Box::leak(format!("{:08x}:1", 0x4001_0000 + index).into_boxed_str()) as &str
        }),
    );
    let over_aggregate = ["00000100:10000001", "10000200:10000001"];
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["explode", "none"], "unknown mode"),
        (vec!["tighten"], "PAL identity"),
        (vec!["datamark"], "PAL identity"),
        (
            vec!["tighten", "none", "40010000:4"],
            "tighten mode accepts no region arguments",
        ),
        (
            vec!["datamark", "bogus"],
            "PAL identity is not the v1 grammar",
        ),
        (
            vec!["datamark", &present_identity, "40010000:4"],
            "stale PAL property",
        ),
        (vec!["datamark", "none", "40010000"], "malformed region"),
        (vec!["datamark", "none", "4001000g:4"], "malformed region"),
        (
            vec!["datamark", "none", "40010000:0"],
            "the region length is zero",
        ),
        (
            vec!["datamark", "none", "ffffffff:2"],
            "wraps the 32-bit address space",
        ),
        (
            vec!["datamark", "none", "40010020:4", "40010010:4"],
            "not sorted",
        ),
        (
            vec!["datamark", "none", "40010000:20", "40010010:8"],
            "overlap",
        ),
        (
            vec!["datamark", "none", "50010000:4"],
            "not fully inside initialized memory",
        ),
        (regions_4097, "region count exceeds"),
        (
            vec!["datamark", "none", over_aggregate[0], over_aggregate[1]],
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
    let failed = tame_datamark(home, &kit, &["datamark", "none", "40010000:40"], None);
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
            ("PHASE_BUDGET_MS = 15 * 60_000L", "PHASE_BUDGET_MS = 1L"),
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
