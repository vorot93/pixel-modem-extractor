//! Self-contained end-to-end test of the `--run` path: craft a tiny ARM blob in a
//! valid TOC, drive real Ghidra headless, and assert the export. Gated on locating
//! Ghidra ($GHIDRA_INSTALL_DIR or /opt/ghidra); skips cleanly otherwise. No
//! proprietary firmware needed.

use std::collections::HashMap;
use std::path::PathBuf;

fn find_ghidra_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        let p = PathBuf::from(dir);
        if p.join("support").join("analyzeHeadless").exists() {
            return Some(p);
        }
    }
    let opt = PathBuf::from("/opt/ghidra");
    if opt.join("support").join("analyzeHeadless").exists() {
        return Some(opt);
    }
    None
}

/// Minimal valid `modem.bin`: TOC + one embedded image (index 1, "BOOT", base 0).
fn craft_modem_bin(payload: &[u8]) -> Vec<u8> {
    let entry_off = 0x20usize;
    let payload_off = entry_off + 0x20; // one 32-byte entry
    let mut buf = vec![0u8; payload_off + payload.len()];
    buf[0..4].copy_from_slice(b"TOC\0");
    buf[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[entry_off..entry_off + 4].copy_from_slice(b"BOOT"); // name
    buf[entry_off + 12..entry_off + 16].copy_from_slice(&(payload_off as u32).to_le_bytes()); // offset
    buf[entry_off + 16..entry_off + 20].copy_from_slice(&0u32.to_le_bytes()); // load_addr
    buf[entry_off + 20..entry_off + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes()); // size
    buf[entry_off + 28..entry_off + 32].copy_from_slice(&1u32.to_le_bytes()); // index
    buf[payload_off..].copy_from_slice(payload);
    buf
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
    let funcs: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exp.join("functions.json")).unwrap()).unwrap();
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

    // generation artifacts exist alongside the export
    assert!(out.join("ghidra_load.json").exists());
    assert!(out.join("run_ghidra.sh").exists());
    assert!(out.join("scripts").join("ExportDecomp.java").exists());
    assert!(out.join("images").join("00_BOOT").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Pass-2 symbolication end-to-end: drive pass 1 via `run_report`, build a
/// one-symbol map with a rename + an annotation, then `run_two_pass` and assert
/// the rename + plate comment are baked into the regenerated `decompiled.c`.
/// Exercises the Phase-1 two-pass path against real Ghidra.
#[test]
fn pass2_renames_function_and_bakes_plate_comment() {
    let Some(home) = find_ghidra_home() else {
        eprintln!("skip: Ghidra not found ($GHIDRA_INSTALL_DIR or /opt/ghidra)");
        return;
    };

    // ARM: `add r0, r0, r1` ; `bx lr`  (little-endian) — yields one tiny FUN_00000000.
    let arm = [0x01u8, 0x00, 0x80, 0xe0, 0x1e, 0xff, 0x2f, 0xe1];
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
    };

    // Pass 1: analyze + initial decompiled.c (with FUN_ placeholder).
    let pass1_report =
        pixel_modem_extractor::decompile::run_report(&modem_path, &opts, &out).unwrap();
    assert!(
        pass1_report.images.iter().any(|r| r.label == "00_BOOT"),
        "pass 1 should have analyzed 00_BOOT"
    );

    // One-symbol map: rename entry 0x0 -> boot_reset_handler with one annotation.
    // ApplySymbols.java reads `entry`, `name`, `tier=recovered`, and `annotations[]`.
    let maps_dir = out.join("symbol_maps");
    std::fs::create_dir_all(&maps_dir).unwrap();
    let map_path = maps_dir.join("00_BOOT.json");
    let annotation = "evidence: tier=recovered src=arm-db";
    let symbol_map = serde_json::json!({
        "tool_version": "test",
        "image": "00_BOOT",
        "source_sha256": "0",
        "functions_sha256": "0",
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

    let mut symbol_maps: HashMap<String, PathBuf> = HashMap::new();
    symbol_maps.insert("00_BOOT".to_string(), map_path);

    // Pass 2: pass pass1_report in (do NOT re-run pass 1).
    let rep2 =
        pixel_modem_extractor::decompile::run_two_pass(pass1_report, &opts, &out, &symbol_maps)
            .unwrap();

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

    // (a) renamed function appears in the regenerated decompiled.c.
    let exp = out.join("export").join("00_BOOT");
    let c = std::fs::read_to_string(exp.join("decompiled.c")).unwrap();
    assert!(
        c.contains("boot_reset_handler"),
        "renamed function missing from decompiled.c:\n{c}"
    );

    // (b) annotation appears as a comment line. Ghidra's ExportDecomp renders
    // plate comments as `/* ... */` block comments in decompiled.c (confirmed
    // against Ghidra 12 — see .superpowers/sdd/applysymbols-fix-report.md).
    let block = format!("/* {annotation} */");
    let line = format!("// {annotation}");
    assert!(
        c.lines().any(|l| l.trim() == block || l.trim() == line),
        "annotation plate comment missing from decompiled.c \
         (looked for `{block}` or `{line}`):\n{c}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
