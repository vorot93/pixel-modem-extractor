//! End-to-end `decompose` test. Requires a real radio image (`PME_RADIO_IMG`) plus a
//! local Ghidra and radare2; self-skips cleanly when any is absent — matching the
//! other golden tests.

use pixel_modem_extractor::{decompile, decompose};
use std::io::ErrorKind;
use std::path::PathBuf;

#[test]
fn decompose_produces_unified_tree() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available on this host");
        return;
    }

    let out = std::env::temp_dir().join(format!("pme_decompose_golden_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: false,
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
    };

    // Best-effort: some partitions may fail Ghidra analysis, which makes `run` return
    // Err — but `report.json` and every successful leaf are still written. Assert the
    // tree, not the exit status.
    let _ = decompose::run(&img, &opts, &out);

    let report_path = out.join("report.json");
    assert!(report_path.exists(), "report.json written");
    assert!(out.join("manifest.json").exists(), "manifest.json present");
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .exists(),
        "02_MAIN decompiled"
    );
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .join("symbols.json")
            .exists(),
        "02_MAIN symbols.json"
    );
    assert!(
        out.join("images")
            .join("02_MAIN")
            .join("source_tree")
            .exists(),
        "02_MAIN source tree"
    );
    let source_tree = out.join("images").join("02_MAIN").join("source_tree");
    let recovered_index = source_tree.join("recovered_index.json");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    let source_attribution = report["stages"]
        .as_array()
        .and_then(|stages| {
            stages
                .iter()
                .find(|stage| stage["stage"] == "source_attribution")
        })
        .expect("report.json must contain source_attribution stage");
    assert_eq!(
        source_attribution["status"], "ok",
        "source_attribution stage must complete"
    );
    assert_eq!(
        source_attribution["output"], "images/02_MAIN/source_tree/recovered_index.json",
        "source_attribution output must be recovered_index.json"
    );
    assert!(
        recovered_index.exists(),
        "source_attribution reported ok but recovered_index.json was not produced"
    );

    // Phase 1: symbol_map stage ran between source_attribution and decompile pass 2.
    let symbol_map_stage = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|stage| stage["stage"] == "symbol_map"))
        .expect("report.json must contain symbol_map stage");
    assert_eq!(symbol_map_stage["status"], "ok");

    // Phase 1: pass 2 ran on at least one image (02_MAIN on real firmware has
    // token-derived names). pass2_applied is recorded into the decompile stage's
    // per-image report.
    let decompile_stage = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|stage| stage["stage"] == "decompile"))
        .expect("report.json must contain decompile stage");
    let any_pass2 = decompile_stage["images"]
        .as_array()
        .map(|imgs| imgs.iter().any(|i| i.get("pass2_applied").is_some()))
        .unwrap_or(false);
    assert!(
        any_pass2,
        "expected at least one image with pass2_applied set"
    );
    for image in decompile_stage["images"].as_array().unwrap() {
        let Some(functions) = image.get("functions").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let ghidra_accepted = image["ghidra_execution_accepted"]
            .as_u64()
            .expect("analyzed image must report current Ghidra accepted count");
        let ghidra_quarantined = image["ghidra_execution_quarantined"]
            .as_u64()
            .expect("analyzed image must report current Ghidra quarantine count");
        assert_eq!(
            functions,
            ghidra_accepted + ghidra_quarantined,
            "Ghidra raw records must be conserved: {image}"
        );
        match image.get("thumb_functions") {
            Some(_) => {
                let accepted = image["thumb_execution_accepted"]
                    .as_u64()
                    .expect("retained Thumb inventory must report accepted count");
                let quarantined = image["thumb_execution_quarantined"]
                    .as_u64()
                    .expect("retained Thumb inventory must report quarantine count");
                assert!(accepted + quarantined > 0, "{image}");
            }
            None => {
                assert!(image.get("thumb_execution_accepted").is_none(), "{image}");
                assert!(
                    image.get("thumb_execution_quarantined").is_none(),
                    "{image}"
                );
            }
        }
    }

    // Phase 2: thumb_enrich (pass 1) and thumb_enrich_post_pass2 stages are
    // both present in the report. Defaults run both; skip rules covered in
    // Task 10/12.
    let stage_names: Vec<String> = report["stages"]
        .as_array()
        .map(|stages| {
            stages
                .iter()
                .map(|s| s["stage"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        stage_names.iter().any(|s| s == "thumb_enrich"),
        "expected thumb_enrich stage in report: {stage_names:?}"
    );
    assert!(
        stage_names.iter().any(|s| s == "thumb_enrich_post_pass2"),
        "expected thumb_enrich_post_pass2 stage in report: {stage_names:?}"
    );

    // decompiled.c on 02_MAIN contains a plate comment from inline evidence.
    let main_c = std::fs::read_to_string(
        out.join("images")
            .join("02_MAIN")
            .join("decompiled")
            .join("decompiled.c"),
    )
    .unwrap_or_default();
    assert!(
        main_c.contains("// logs:") || main_c.contains("// file:"),
        "expected inline-evidence plate comments in 02_MAIN decompiled.c"
    );

    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&recovered_index).unwrap()).unwrap();
    assert_eq!(index["attribution"], "moderate");
    let sources = index["sources"]
        .as_object()
        .expect("recovered_index.json sources must be an object");
    let attributed_leaves: Vec<_> = sources
        .values()
        .filter_map(|source| {
            let functions = source["functions"].as_array()?;
            if functions.is_empty() {
                None
            } else {
                source["leaf"].as_str()
            }
        })
        .collect();
    assert!(
        !attributed_leaves.is_empty(),
        "recovered_index.json contained no sources with attributed functions"
    );

    let mut saw_recovered = false;
    for leaf in attributed_leaves {
        let path = source_tree.join(leaf);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("// --- recovered function") {
            saw_recovered = true;
            assert!(
                text.starts_with("// Reconstructed node"),
                "source-tree metadata must remain first in {}",
                path.display()
            );
            break;
        }
    }
    assert!(
        saw_recovered,
        "no attributed source-tree leaf contained recovered function evidence"
    );
    // intermediates present without --prune
    assert!(out.join("modem.ext4").exists(), "ext4 kept without --prune");
}

/// Phase 2: on a real `02_MAIN` the per-image entry in `report.json` carries at
/// least one of the Phase-2 Thumb fields — either `thumb_decompiled` (the
/// happy path: tightened Ghidra converged and `thumb_enrich` populated `body_c`)
/// or `thumb_tighten_error` (Surface B fired: the runtime watch killed the
/// tightened run and fell back to datamark). Either is a valid Phase-2 outcome;
/// their absence means the Phase-2 wiring is silently inert.
#[test]
fn report_json_includes_phase2_fields() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available on this host");
        return;
    }

    let out = std::env::temp_dir().join(format!(
        "pme_decompose_golden_phase2_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&out);
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: false,
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
    };
    let _ = decompose::run(&img, &opts, &out);

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    let main = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    assert!(
        main.get("thumb_decompiled").is_some() || main.get("thumb_tighten_error").is_some(),
        "Phase-2 fields absent on 02_MAIN: {main}"
    );
}

/// Phase 3.0: on a real `02_MAIN`, the per-image entry in the `decompile`
/// stage's `images[]` carries either `globals_recovered` (happy path) or
/// `globals_error` (per-image failure). Their absence means the
/// `refresh_decompile_stage_images` call is missing after the globals sweep
/// — the same wiring gap that bit Phase 2.1 on the pass-1 path.
#[test]
fn report_json_includes_globals_field() {
    let Some(img) = std::env::var_os("PME_RADIO_IMG").map(PathBuf::from) else {
        eprintln!("skip: set PME_RADIO_IMG");
        return;
    };
    if !img.exists() {
        eprintln!("skip: PME_RADIO_IMG not found");
        return;
    }
    if decompile::find_headless(None).is_err() || decompile::find_radare2().is_none() {
        eprintln!("skip: Ghidra and/or radare2 not available");
        return;
    }
    let out = std::env::temp_dir().join(format!(
        "pme_decompose_golden_phase3_{}",
        std::process::id()
    ));
    match std::fs::remove_dir_all(&out) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => panic!("failed to remove stale output {}: {e}", out.display()),
    }
    let opts = decompose::Opts {
        no_verify: false,
        prune: false,
        ghidra_home: None,
        processor: "ARM:LE:32:v7".to_string(),
        no_symbol_pass: true,
        no_thumb_decompile: false,
        tighten_wall_clock_budget_override: None,
        globals_provisional: false,
        globals_k_arm: None,
        globals_k_thumb: None,
    };
    let _ = decompose::run(&img, &opts, &out);

    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    let main = report["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    assert!(
        main.get("globals_recovered").is_some() || main.get("globals_error").is_some(),
        "Phase 3.0 fields absent on 02_MAIN: {main}"
    );
    let functions = main["functions"]
        .as_u64()
        .expect("no-symbol-pass must retain current Ghidra raw count");
    assert_eq!(
        functions,
        main["ghidra_execution_accepted"].as_u64().unwrap()
            + main["ghidra_execution_quarantined"].as_u64().unwrap(),
        "no-symbol-pass must use the same terminal validation contract: {main}"
    );
}

/// Phase 3.0.1: on a real `02_MAIN`, the per-image entry in the `decompile`
/// stage's `images[]` carries `globals_provisional` and
/// `globals_provisional_suppressed` (Some, possibly 0). Their absence means
/// the `refresh_decompile_stage_images` call is missing after the Phase 3.0.1
/// globals sweep — the same wiring gap that bit Phase 2.1 on the pass-1 path
/// (and Phase 3.0 on its initial wiring). Reads `$PME_GOLDEN_DIR/report.json`
/// (pre-existing decompose output; never auto-runs decompose — production
/// verification supplies the env); skips cleanly when the env is unset or the
/// file is absent.
#[test]
fn report_json_includes_phase3_0_1_fields() {
    let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let report_path = dir.join("report.json");
    if !report_path.exists() {
        eprintln!("skip: PME_GOLDEN_DIR/report.json not found");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("report.json readable"))
            .expect("report.json valid JSON");
    let main = v["stages"]
        .as_array()
        .and_then(|stages| stages.iter().find(|s| s["stage"] == "decompile"))
        .and_then(|s| s["images"].as_array())
        .and_then(|imgs| imgs.iter().find(|i| i["image"] == "02_MAIN"))
        .expect("02_MAIN entry missing from decompile stage");
    assert!(
        main.get("globals_provisional").is_some(),
        "globals_provisional missing — refresh_decompile_stage_images not called after Phase 3.0.1 sweep: {main}"
    );
    assert!(
        main.get("globals_provisional_suppressed").is_some(),
        "globals_provisional_suppressed missing — refresh_decompile_stage_images not called after Phase 3.0.1 sweep: {main}"
    );
}
