//! Phase 3.0: env-gated golden tests for globals recovery on a real `02_MAIN`.
//! Skip cleanly when PME_RADIO_IMG / GHIDRA_INSTALL_DIR unset or absent.

use pixel_modem_extractor::{decompile, decompose};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;

fn env_or_skip() -> Option<PathBuf> {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return None;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return None;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available on this host");
        return None;
    }
    Some(img)
}

// Decompose runs ~110 min on the real image. The three tests below share a
// single run via OnceLock so we pay that cost once per test-binary invocation
// instead of three times.
fn shared_decompose_output() -> Option<PathBuf> {
    static OUT: OnceLock<Option<PathBuf>> = OnceLock::new();
    OUT.get_or_init(|| {
        let img = env_or_skip()?;
        let out = std::env::temp_dir().join("pme_globals_golden");
        let _ = std::fs::remove_dir_all(&out);
        let opts = decompose::Opts {
            no_verify: false,
            prune: false,
            ghidra_home: None,
            processor: "ARM:LE:32:v7".to_string(),
            no_symbol_pass: true, // pass 1 only — Phase 3.0 doesn't need pass 2
            no_thumb_decompile: false,
            tighten_wall_clock_budget_override: None,
        };
        // Best-effort: some partitions may fail, but report.json and artifacts
        // are still written. Assert the tree, not the exit status.
        let _ = decompose::run(&img, &opts, &out);
        Some(out)
    })
    .clone()
}

#[test]
fn globals_recovers_nonzero_count_on_real_02_main() {
    let Some(out) = shared_decompose_output() else {
        return;
    };
    let report: Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    let main = report["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["stage"] == "decompile")
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    let count = main
        .get("globals_recovered")
        .and_then(|g| g.as_u64())
        .expect("globals_recovered missing on 02_MAIN");
    assert!(
        count > 0,
        "Phase 3.0 strict algorithm should recover at least one global on real 02_MAIN; got {count}"
    );
}

#[test]
fn globals_json_schema_matches_v1() {
    let Some(out) = shared_decompose_output() else {
        return;
    };
    let path = out.join("images/02_MAIN/decompiled/globals.json");
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(v["format"], "pixel-modem-extractor-globals-v1");
    assert_eq!(v["image"], "02_MAIN");
    let globals = v["globals"].as_array().expect("globals must be an array");
    for g in globals {
        assert!(g.get("address").is_some(), "global missing address: {g}");
        assert!(g.get("name").is_some(), "global missing name: {g}");
        assert_eq!(g["tier"], "recovered", "Phase 3.0 is Recovered-only");
        let arch = g["arch"].as_str().unwrap();
        assert!(
            ["arm", "thumb", "mixed"].contains(&arch),
            "bad arch: {arch}"
        );
        let ev = g["evidence"].as_array().unwrap();
        assert!(!ev.is_empty(), "global with no evidence: {g}");
        assert!(g["size"].is_null(), "Phase 3.0 size must be null");
    }
}

#[test]
fn globals_no_duplicates_by_address() {
    let Some(out) = shared_decompose_output() else {
        return;
    };
    let path = out.join("images/02_MAIN/decompiled/globals.json");
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let globals = v["globals"].as_array().unwrap();
    let mut addrs: Vec<&str> = globals
        .iter()
        .map(|g| g["address"].as_str().unwrap())
        .collect();
    addrs.sort_unstable();
    let before = addrs.len();
    addrs.dedup();
    assert_eq!(addrs.len(), before, "duplicate global addresses present");
}
