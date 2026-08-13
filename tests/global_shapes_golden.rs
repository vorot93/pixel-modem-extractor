//! Read-only env-gated validation of retained or fresh `global_shapes.json`.
//!
//! Reads `$PME_GOLDEN_DIR` and never launches decompose. Skips cleanly when
//! the env is unset, the directory is absent, or the tree has no shape
//! sidecars (a pre-`global_shapes` corpus). The validator does not hardcode
//! a yield percentage.

use pixel_modem_extractor::global_shapes::FORMAT_V1;
use pixel_modem_extractor::manifest::{sha256_bytes, sha256_file};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn golden_dir() -> Option<PathBuf> {
    let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return None;
    };
    if !dir.exists() {
        eprintln!("skip: PME_GOLDEN_DIR not found on disk: {}", dir.display());
        return None;
    }
    Some(dir)
}

fn load_report(dir: &Path) -> Option<Value> {
    let path = dir.join("report.json");
    if !path.exists() {
        eprintln!("skip: PME_GOLDEN_DIR/report.json not found");
        return None;
    }
    Some(
        serde_json::from_slice(&std::fs::read(&path).expect("report.json readable"))
            .expect("report.json valid JSON"),
    )
}

fn stages(report: &Value) -> &[Value] {
    report["stages"]
        .as_array()
        .expect("report.json stages must be an array")
}

fn stage_names(report: &Value) -> Vec<&str> {
    stages(report)
        .iter()
        .filter_map(|stage| stage["stage"].as_str())
        .collect()
}

fn decompile_images(report: &Value) -> &[Value] {
    stages(report)
        .iter()
        .find(|stage| stage["stage"] == "decompile")
        .and_then(|stage| stage["images"].as_array())
        .expect("decompile stage images must be an array")
}

fn sidecar_path(dir: &Path, label: &str) -> PathBuf {
    dir.join("images")
        .join(label)
        .join("decompiled")
        .join("global_shapes.json")
}

fn present_sidecars(dir: &Path, report: &Value) -> Vec<(String, PathBuf)> {
    decompile_images(report)
        .iter()
        .filter_map(|image| {
            let label = image["image"].as_str()?.to_owned();
            let path = sidecar_path(dir, &label);
            path.is_file().then_some((label, path))
        })
        .collect()
}

struct ShapesTree {
    dir: PathBuf,
    report: Value,
    sidecars: Vec<(String, PathBuf)>,
}

fn shapes_tree() -> Option<ShapesTree> {
    let dir = golden_dir()?;
    let report = load_report(&dir)?;
    let sidecars = present_sidecars(&dir, &report);
    if sidecars.is_empty() {
        eprintln!(
            "skip: no global_shapes.json sidecars under {}",
            dir.display()
        );
        return None;
    }
    Some(ShapesTree {
        dir,
        report,
        sidecars,
    })
}

fn require_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string: {value}"))
}

fn require_u64(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} must be an integer: {value}"))
}

fn require_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array: {value}"))
}

fn parse_canonical_hex(value: &str) -> u32 {
    assert!(
        is_canonical_hex(value),
        "address/PC is not canonical lowercase hex: {value}"
    );
    u32::from_str_radix(&value[2..], 16).expect("canonical hex fits u32")
}

fn is_canonical_hex(value: &str) -> bool {
    let Some(digits) = value.strip_prefix("0x") else {
        return false;
    };
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return false;
    }
    u32::from_str_radix(digits, 16)
        .ok()
        .is_some_and(|parsed| format!("0x{parsed:x}") == value)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn toc_name(label: &str) -> &str {
    label.split_once('_').map(|(_, name)| name).unwrap_or(label)
}

fn load_address(manifest: &Value, label: &str) -> u32 {
    let name = toc_name(label);
    let addr = manifest["toc"]
        .as_array()
        .expect("manifest toc must be an array")
        .iter()
        .find(|entry| entry["name"] == name)
        .and_then(|entry| entry["load_addr"].as_u64())
        .unwrap_or_else(|| panic!("manifest load_addr missing for {label}"));
    u32::try_from(addr).unwrap_or_else(|_| panic!("load_addr for {label} does not fit u32"))
}

fn recovered_globals(globals_json: &Value) -> Vec<&Value> {
    require_array(globals_json, "globals")
        .iter()
        .filter(|global| global["tier"] == "recovered")
        .collect()
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "read" => 0,
        "write" => 1,
        "read_write" => 2,
        other => panic!("unknown access kind {other}"),
    }
}

fn isa_rank(isa: &str) -> u8 {
    match isa {
        "arm" => 0,
        "thumb" => 1,
        other => panic!("unknown observation isa {other}"),
    }
}

fn observation_key(obs: &Value) -> (u8, u32, bool, u8, u8, u32) {
    (
        isa_rank(require_str(obs, "arch")),
        parse_canonical_hex(require_str(obs, "pc")),
        obs["conditional"]
            .as_bool()
            .expect("conditional must be bool"),
        kind_rank(require_str(obs, "kind")),
        u8::try_from(require_u64(obs, "width")).expect("width fits u8"),
        u32::try_from(require_u64(obs, "offset")).expect("offset fits u32"),
    )
}

fn alternative_key(alt: &Value) -> (u32, bool, u8, u8, u32) {
    (
        parse_canonical_hex(require_str(alt, "target_address")),
        alt["conditional"]
            .as_bool()
            .expect("conditional must be bool"),
        kind_rank(require_str(alt, "kind")),
        u8::try_from(require_u64(alt, "width")).expect("width fits u8"),
        u32::try_from(require_u64(alt, "offset")).expect("offset fits u32"),
    )
}

fn function_key(function: &Value) -> (u32, &str) {
    (
        parse_canonical_hex(require_str(function, "entry")),
        require_str(function, "name"),
    )
}

fn assert_sorted_unique<T: Clone + Ord + std::fmt::Debug>(items: &[T], what: &str) {
    let mut sorted = items.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(items, sorted.as_slice(), "{what} must be sorted and unique");
}

fn assert_functions_sorted(functions: &[Value], where_: &str) {
    let keys: Vec<(u32, &str)> = functions.iter().map(function_key).collect();
    assert_sorted_unique(&keys, &format!("{where_} functions"));
}

fn assert_paths_sorted(paths: &[Value], where_: &str) {
    let keys: Vec<Vec<u32>> = paths
        .iter()
        .map(|path| {
            path.as_array()
                .expect("provenance path must be an array")
                .iter()
                .map(|pc| parse_canonical_hex(pc.as_str().expect("path PC must be a string")))
                .collect()
        })
        .collect();
    assert_sorted_unique(&keys, &format!("{where_} provenance_paths"));
}

fn classify_shape(widths: &BTreeSet<u8>, offsets: &BTreeSet<u32>) -> Value {
    let Some(&width) = widths.first().filter(|_| widths.len() == 1) else {
        return serde_json::json!({"kind": "unknown"});
    };
    if offsets.iter().all(|offset| *offset == 0) {
        return serde_json::json!({"kind": "scalar_candidate", "width": width});
    }
    if width == 0
        || !offsets.contains(&0)
        || !offsets.iter().any(|offset| *offset != 0)
        || !offsets.iter().all(|offset| *offset % u32::from(width) == 0)
    {
        return serde_json::json!({"kind": "unknown"});
    }
    let max_index = offsets
        .iter()
        .map(|offset| *offset / u32::from(width))
        .max()
        .expect("array offsets are non-empty");
    serde_json::json!({
        "kind": "array_candidate",
        "element_width": width,
        "minimum_elements": max_index + 1,
    })
}

fn recompute_summary(observations: &[Value]) -> Value {
    let mut minimum_size = 0u32;
    let mut widths = BTreeSet::new();
    let mut offsets = BTreeSet::new();
    let mut reads = 0u64;
    let mut writes = 0u64;
    for observation in observations {
        let width = u8::try_from(require_u64(observation, "width")).expect("width fits u8");
        let offset = u32::try_from(require_u64(observation, "offset")).expect("offset fits u32");
        let end = offset
            .checked_add(u32::from(width))
            .expect("offset + width overflow");
        minimum_size = minimum_size.max(end);
        widths.insert(width);
        offsets.insert(offset);
        match require_str(observation, "kind") {
            "read" => reads += 1,
            "write" => writes += 1,
            "read_write" => {
                reads += 1;
                writes += 1;
            }
            other => panic!("unknown kind {other}"),
        }
    }
    serde_json::json!({
        "minimum_size": minimum_size,
        "observed_widths": widths.iter().copied().collect::<Vec<_>>(),
        "accessed_offsets": offsets.iter().copied().collect::<Vec<_>>(),
        "reads": reads,
        "writes": writes,
        "provisional_shape": classify_shape(&widths, &offsets),
    })
}

fn assert_status_invariants(global: &Value) {
    let observations = require_array(global, "observations");
    let conflicts = require_array(global, "conflicts");
    match require_str(global, "status") {
        "inferred" => {
            assert!(
                !observations.is_empty() && conflicts.is_empty() && !global["summary"].is_null(),
                "inferred status invariant violated: {global}"
            );
        }
        "no_evidence" => {
            assert!(
                observations.is_empty() && conflicts.is_empty() && global["summary"].is_null(),
                "no_evidence status invariant violated: {global}"
            );
        }
        "conflicting" => {
            assert!(
                !conflicts.is_empty() && global["summary"].is_null(),
                "conflicting status invariant violated: {global}"
            );
        }
        other => panic!("unknown status {other}"),
    }
}

fn assert_observation_hex(observation: &Value) {
    parse_canonical_hex(require_str(observation, "pc"));
    for function in require_array(observation, "functions") {
        parse_canonical_hex(require_str(function, "entry"));
    }
    for path in require_array(observation, "provenance_paths") {
        for pc in path.as_array().expect("path must be an array") {
            parse_canonical_hex(pc.as_str().expect("path PC must be a string"));
        }
    }
}

fn assert_nested_collections(global: &Value) {
    let observations = require_array(global, "observations");
    let observation_keys: Vec<_> = observations.iter().map(observation_key).collect();
    assert_sorted_unique(
        &observation_keys,
        &format!("{} observations", global["address"]),
    );
    for (index, observation) in observations.iter().enumerate() {
        assert_observation_hex(observation);
        assert_functions_sorted(
            require_array(observation, "functions"),
            &format!("{} observation {index}", global["address"]),
        );
        assert_paths_sorted(
            require_array(observation, "provenance_paths"),
            &format!("{} observation {index}", global["address"]),
        );
    }

    let conflicts = require_array(global, "conflicts");
    let conflict_keys: Vec<(u8, u32)> = conflicts
        .iter()
        .map(|conflict| {
            (
                isa_rank(require_str(conflict, "arch")),
                parse_canonical_hex(require_str(conflict, "pc")),
            )
        })
        .collect();
    assert_sorted_unique(&conflict_keys, &format!("{} conflicts", global["address"]));
    for (index, conflict) in conflicts.iter().enumerate() {
        parse_canonical_hex(require_str(conflict, "pc"));
        let alternatives = require_array(conflict, "alternatives");
        let alt_keys: Vec<_> = alternatives.iter().map(alternative_key).collect();
        assert_sorted_unique(
            &alt_keys,
            &format!("{} conflict {index} alternatives", global["address"]),
        );
        for (alt_index, alternative) in alternatives.iter().enumerate() {
            parse_canonical_hex(require_str(alternative, "target_address"));
            assert_functions_sorted(
                require_array(alternative, "functions"),
                &format!("{} conflict {index} alt {alt_index}", global["address"]),
            );
            assert_paths_sorted(
                require_array(alternative, "provenance_paths"),
                &format!("{} conflict {index} alt {alt_index}", global["address"]),
            );
        }
    }
}

#[derive(Default)]
struct InventoryCounts {
    raw: usize,
    accepted: usize,
    quarantined: usize,
    quarantine_errors: usize,
}

fn parse_inventory(records: &[Value], image_start: u32, image_len: u32) -> InventoryCounts {
    let image_end = image_start
        .checked_add(image_len)
        .expect("mapped image end overflows u32");
    let mut counts = InventoryCounts {
        raw: records.len(),
        ..InventoryCounts::default()
    };
    for record in records {
        let ranges = require_array(record, "decode_ranges");
        let errors = require_array(record, "decode_range_errors");
        match (ranges.is_empty(), errors.is_empty()) {
            (false, true) => {
                counts.accepted += 1;
                for range in ranges {
                    let start = parse_canonical_hex(require_str(range, "start"));
                    let end = parse_canonical_hex(require_str(range, "end"));
                    assert!(
                        start >= image_start && end <= image_end && end > start,
                        "accepted range [{start:#x}, {end:#x}) is not image-contained in [{image_start:#x}, {image_end:#x})"
                    );
                }
            }
            (true, false) => {
                // Quarantined records have no decode_ranges, so they cannot
                // form an execution identity (entry + ordered range list).
                counts.quarantined += 1;
                counts.quarantine_errors += errors.len();
            }
            _ => panic!("inventory record is not a single tagged state: {record}"),
        }
    }
    assert_eq!(
        counts.raw,
        counts.accepted + counts.quarantined,
        "raw inventory count must equal accepted plus quarantined"
    );
    counts
}

fn ghidra_records(functions_json: &Value) -> &[Value] {
    functions_json
        .as_array()
        .expect("functions.json must be an array")
}

fn thumb_records(thumb_json: &Value) -> &[Value] {
    require_array(thumb_json, "functions")
}

fn validate_artifact(dir: &Path, report_image: &Value, artifact: &Value) {
    let label = require_str(report_image, "image");
    assert_eq!(require_str(artifact, "format"), FORMAT_V1);
    assert_eq!(require_str(artifact, "image"), label);

    let manifest: Value = serde_json::from_slice(
        &std::fs::read(dir.join("manifest.json")).expect("manifest.json readable"),
    )
    .expect("manifest.json valid JSON");
    let load_addr = load_address(&manifest, label);
    assert_eq!(require_str(artifact, "load_address"), hex_addr(load_addr));

    let image_path = dir.join("images").join(label).join(format!("{label}.bin"));
    let decompiled = dir.join("images").join(label).join("decompiled");
    let globals_path = decompiled.join("globals.json");
    let functions_path = decompiled.join("functions.json");
    let thumb_path = decompiled.join("thumb_functions.json");

    let image_len = u32::try_from(std::fs::metadata(&image_path).unwrap().len())
        .expect("image length fits u32");
    let inputs = &artifact["inputs"];
    assert!(is_sha256_hex(require_str(inputs, "image_sha256")));
    assert!(is_sha256_hex(require_str(inputs, "globals_sha256")));
    assert!(is_sha256_hex(require_str(inputs, "functions_sha256")));
    assert_eq!(
        require_str(inputs, "image_sha256"),
        sha256_file(&image_path).unwrap()
    );
    assert_eq!(
        require_str(inputs, "globals_sha256"),
        sha256_file(&globals_path).unwrap()
    );
    assert_eq!(
        require_str(inputs, "functions_sha256"),
        sha256_file(&functions_path).unwrap()
    );

    let report_has_thumb = report_image.get("thumb_functions").is_some();
    match inputs.get("thumb_functions_sha256") {
        Some(Value::Null) | None => {
            assert!(
                !report_has_thumb,
                "{label}: thumb hash is null but report has a Thumb inventory"
            );
            assert!(
                !thumb_path.exists(),
                "{label}: unexpected thumb_functions.json when hash is null"
            );
        }
        Some(Value::String(hash)) => {
            assert!(
                report_has_thumb,
                "{label}: thumb hash is present but report has no Thumb inventory"
            );
            assert!(is_sha256_hex(hash));
            assert_eq!(hash, &sha256_file(&thumb_path).unwrap());
        }
        other => panic!("{label}: thumb_functions_sha256 has unexpected value {other:?}"),
    }

    let globals_json: Value =
        serde_json::from_slice(&std::fs::read(&globals_path).expect("globals.json readable"))
            .expect("globals.json valid JSON");
    let recovered = recovered_globals(&globals_json);
    let shapes = require_array(artifact, "globals");
    assert_eq!(
        shapes.len(),
        recovered.len(),
        "{label}: one shape record per Recovered global"
    );
    for (shape, source) in shapes.iter().zip(&recovered) {
        assert_eq!(
            require_str(shape, "address"),
            hex_addr(parse_global_address(require_str(source, "address"))),
            "{label}: Recovered address order/canonicalization"
        );
        assert_eq!(require_str(shape, "name"), require_str(source, "name"));
        assert_eq!(require_str(shape, "arch"), require_str(source, "arch"));
        parse_canonical_hex(require_str(shape, "address"));
        assert_status_invariants(shape);
        if require_str(shape, "status") == "inferred" {
            assert_eq!(
                shape["summary"],
                recompute_summary(require_array(shape, "observations")),
                "{label}: summary must recompute from observations for {}",
                shape["address"]
            );
        }
        assert_nested_collections(shape);
    }

    let analysis = &artifact["analysis"];
    let observation_count: u64 = shapes
        .iter()
        .map(|global| require_array(global, "observations").len() as u64)
        .sum();
    let conflict_count: u64 = shapes
        .iter()
        .map(|global| require_array(global, "conflicts").len() as u64)
        .sum();
    assert_eq!(require_u64(analysis, "observations"), observation_count);
    assert_eq!(require_u64(analysis, "conflicts"), conflict_count);

    let functions_json: Value =
        serde_json::from_slice(&std::fs::read(&functions_path).expect("functions.json readable"))
            .expect("functions.json valid JSON");
    let ghidra = parse_inventory(ghidra_records(&functions_json), load_addr, image_len);
    assert_eq!(
        ghidra.raw,
        report_image["functions"].as_u64().unwrap() as usize
    );
    assert_eq!(
        ghidra.accepted,
        report_image["ghidra_execution_accepted"].as_u64().unwrap() as usize
    );
    assert_eq!(
        ghidra.quarantined,
        report_image["ghidra_execution_quarantined"]
            .as_u64()
            .unwrap() as usize
    );
    assert_eq!(
        require_u64(analysis, "ghidra_records_quarantined") as usize,
        ghidra.quarantined
    );

    let thumb = if report_has_thumb {
        let thumb_json: Value =
            serde_json::from_slice(&std::fs::read(&thumb_path).expect("thumb_functions readable"))
                .expect("thumb_functions valid JSON");
        let parsed = parse_inventory(thumb_records(&thumb_json), load_addr, image_len);
        assert_eq!(
            parsed.accepted + parsed.quarantined,
            report_image["thumb_execution_accepted"].as_u64().unwrap() as usize
                + report_image["thumb_execution_quarantined"]
                    .as_u64()
                    .unwrap() as usize
        );
        assert_eq!(
            parsed.quarantined,
            report_image["thumb_execution_quarantined"]
                .as_u64()
                .unwrap() as usize
        );
        parsed
    } else {
        InventoryCounts::default()
    };
    assert_eq!(
        require_u64(analysis, "thumb_records_quarantined") as usize,
        thumb.quarantined
    );
    assert_eq!(
        require_u64(analysis, "quarantine_errors") as usize,
        ghidra.quarantine_errors + thumb.quarantine_errors
    );

    if let Some(inferred) = report_image.get("global_shapes_inferred") {
        let inferred_count = shapes
            .iter()
            .filter(|global| global["status"] == "inferred")
            .count() as u64;
        let no_evidence = shapes
            .iter()
            .filter(|global| global["status"] == "no_evidence")
            .count() as u64;
        let conflicting = shapes
            .iter()
            .filter(|global| global["status"] == "conflicting")
            .count() as u64;
        assert_eq!(inferred, inferred_count);
        assert_eq!(report_image["global_shapes_no_evidence"], no_evidence);
        assert_eq!(report_image["global_shapes_conflicting"], conflicting);
        assert_eq!(report_image["global_shape_observations"], observation_count);
        assert_eq!(
            report_image["global_shapes_ghidra_quarantined"],
            require_u64(analysis, "ghidra_records_quarantined")
        );
        assert_eq!(
            report_image["global_shapes_thumb_quarantined"],
            require_u64(analysis, "thumb_records_quarantined")
        );
        assert_eq!(
            report_image["global_shapes_quarantine_errors"],
            require_u64(analysis, "quarantine_errors")
        );
        assert_eq!(
            report_image["global_shapes_decode_failures"],
            require_u64(analysis, "decode_failures")
        );
        assert_eq!(
            report_image["global_shapes_state_barriers"],
            require_u64(analysis, "state_barriers")
        );
    }
}

fn parse_global_address(value: &str) -> u32 {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u32::from_str_radix(digits, 16).expect("global address is hex")
}

fn hex_addr(value: u32) -> String {
    format!("0x{value:x}")
}

fn report_image<'a>(report: &'a Value, label: &str) -> &'a Value {
    decompile_images(report)
        .iter()
        .find(|image| image["image"] == label)
        .unwrap_or_else(|| panic!("{label} missing from decompile stage"))
}

fn assert_stage_order(report: &Value) {
    let names = stage_names(report);
    if !names.contains(&"global_shapes") {
        return;
    }
    let shapes = names
        .iter()
        .position(|name| *name == "global_shapes")
        .unwrap();
    assert_eq!(
        names
            .iter()
            .filter(|name| **name == "global_shapes")
            .count(),
        1,
        "exactly one global_shapes stage: {names:?}"
    );
    let thumb = names
        .iter()
        .position(|name| *name == "thumb_enrich_post_pass2")
        .expect("thumb_enrich_post_pass2 must precede global_shapes");
    assert!(
        thumb < shapes,
        "global_shapes must follow thumb_enrich_post_pass2: {names:?}"
    );
    for decoder in ["decode_rf", "hardware_config"] {
        if let Some(pos) = names.iter().position(|name| *name == decoder) {
            assert!(
                shapes < pos,
                "global_shapes must precede {decoder}: {names:?}"
            );
        }
    }
}

fn parse_stage_totals(output: &str) -> [u64; 9] {
    let mut totals = [0u64; 9];
    for (index, key) in [
        "inferred=",
        "no_evidence=",
        "conflicting=",
        "observations=",
        "ghidra_quarantined=",
        "thumb_quarantined=",
        "quarantine_errors=",
        "decode_failures=",
        "state_barriers=",
    ]
    .into_iter()
    .enumerate()
    {
        let start = output
            .find(key)
            .unwrap_or_else(|| panic!("stage output missing {key}: {output}"));
        let rest = &output[start + key.len()..];
        let end = rest
            .find([',', ')'])
            .unwrap_or_else(|| panic!("unterminated {key} in {output}"));
        totals[index] = rest[..end]
            .parse()
            .unwrap_or_else(|_| panic!("invalid {key} in {output}"));
    }
    totals
}

#[test]
fn artifacts_satisfy_v1_invariants() {
    let Some(tree) = shapes_tree() else {
        return;
    };
    for (label, path) in &tree.sidecars {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            !bytes.ends_with(b"\n"),
            "{} must not have a trailing newline",
            path.display()
        );
        let artifact: Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        validate_artifact(&tree.dir, report_image(&tree.report, label), &artifact);
        assert!(is_sha256_hex(&sha256_bytes(&bytes)));
    }
}

#[test]
fn report_stage_order_and_aggregate_totals() {
    let Some(tree) = shapes_tree() else {
        return;
    };
    assert_stage_order(&tree.report);
    let Some(stage) = stages(&tree.report)
        .iter()
        .find(|stage| stage["stage"] == "global_shapes")
    else {
        return;
    };
    let mut inferred = 0u64;
    let mut no_evidence = 0u64;
    let mut conflicting = 0u64;
    let mut observations = 0u64;
    let mut ghidra_quarantined = 0u64;
    let mut thumb_quarantined = 0u64;
    let mut quarantine_errors = 0u64;
    let mut decode_failures = 0u64;
    let mut state_barriers = 0u64;
    for image in decompile_images(&tree.report) {
        if image.get("global_shapes_error").is_some() {
            continue;
        }
        let Some(value) = image.get("global_shapes_inferred").and_then(Value::as_u64) else {
            continue;
        };
        inferred += value;
        no_evidence += image["global_shapes_no_evidence"].as_u64().unwrap();
        conflicting += image["global_shapes_conflicting"].as_u64().unwrap();
        observations += image["global_shape_observations"].as_u64().unwrap();
        ghidra_quarantined += image["global_shapes_ghidra_quarantined"].as_u64().unwrap();
        thumb_quarantined += image["global_shapes_thumb_quarantined"].as_u64().unwrap();
        quarantine_errors += image["global_shapes_quarantine_errors"].as_u64().unwrap();
        decode_failures += image["global_shapes_decode_failures"].as_u64().unwrap();
        state_barriers += image["global_shapes_state_barriers"].as_u64().unwrap();
    }
    if let Some(output) = stage["output"].as_str() {
        assert_eq!(
            parse_stage_totals(output),
            [
                inferred,
                no_evidence,
                conflicting,
                observations,
                ghidra_quarantined,
                thumb_quarantined,
                quarantine_errors,
                decode_failures,
                state_barriers,
            ]
        );
    }
    assert!(!tree.sidecars.is_empty());
}

#[test]
fn accepted_corpus_has_arm_and_thumb_observations() {
    let Some(tree) = shapes_tree() else {
        return;
    };
    let has_arm_inventory = decompile_images(&tree.report).iter().any(|image| {
        image
            .get("functions")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    });
    let has_thumb_inventory = decompile_images(&tree.report)
        .iter()
        .any(|image| image.get("thumb_functions").is_some());
    let has_recovered = decompile_images(&tree.report).iter().any(|image| {
        image
            .get("globals_recovered")
            .and_then(Value::as_u64)
            .is_some_and(|count| count > 0)
    });
    if !(has_arm_inventory && has_thumb_inventory && has_recovered) {
        eprintln!("skip: tree does not look like the accepted Mustang corpus");
        return;
    }
    let mut saw_arm = false;
    let mut saw_thumb = false;
    for (label, path) in &tree.sidecars {
        let artifact: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for global in require_array(&artifact, "globals") {
            for observation in require_array(global, "observations") {
                match require_str(observation, "arch") {
                    "arm" => saw_arm = true,
                    "thumb" => saw_thumb = true,
                    _ => {}
                }
            }
        }
        let _ = label;
    }
    assert!(
        saw_arm && saw_thumb,
        "accepted Mustang corpus must have at least one ARM and one Thumb observation under {}",
        tree.dir.display()
    );
}
