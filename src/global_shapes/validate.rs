//! Shared v4 artifact checks for env-gated goldens and retained-tree replay.

use super::FORMAT_V4;
use crate::execution_ranges::{
    ExecutionProjection, ValidatedInventory, validate_ghidra_inventory_records,
};
use crate::manifest::blake3_file;
use crate::runtime_image::RuntimeImage;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// Validate a sidecar against the decompose-tree layout
/// (`{root}/manifest.json`, `{root}/images/{label}/...`).
pub fn validate_artifact(tree_root: &Path, report_image: &Value, artifact: &Value) {
    let label = require_str(report_image, "image");
    validate_artifact_files(
        &tree_root.join("images").join(label),
        &tree_root.join("manifest.json"),
        report_image,
        artifact,
    );
}

/// Validate a sidecar against an image directory and manifest path.
pub fn validate_artifact_files(
    image_dir: &Path,
    manifest_path: &Path,
    report_image: &Value,
    artifact: &Value,
) {
    let label = require_str(report_image, "image");
    assert_eq!(require_str(artifact, "format"), FORMAT_V4);
    assert_eq!(require_str(artifact, "image"), label);

    let manifest: Value =
        serde_json::from_slice(&std::fs::read(manifest_path).expect("manifest.json readable"))
            .expect("manifest.json valid JSON");
    let load_addr = load_address(&manifest, label);
    assert_eq!(require_str(artifact, "load_address"), hex_addr(load_addr));

    let image_path = image_dir.join(format!("{label}.bin"));
    let decompiled = image_dir.join("decompiled");
    let globals_path = decompiled.join("globals.json");
    let functions_path = decompiled.join("functions.json");
    let thumb_path = decompiled.join("thumb_functions.json");

    let image = std::fs::read(&image_path).expect("raw image readable");
    let runtime_root = std::fs::canonicalize(image_dir).expect("image directory canonicalizable");
    let runtime_map = runtime_root.join("scatter/load_map.json");
    let runtime = RuntimeImage::from_artifact(
        &image,
        load_addr,
        &runtime_root,
        runtime_map
            .try_exists()
            .expect("scatter map existence query succeeds")
            .then_some(runtime_map.as_path()),
    )
    .expect("runtime image valid");
    let inputs = &artifact["inputs"];
    assert!(is_blake3_hex(require_str(inputs, "image_blake3")));
    assert!(is_blake3_hex(require_str(inputs, "globals_blake3")));
    assert!(is_blake3_hex(require_str(inputs, "functions_blake3")));
    assert_eq!(
        require_str(inputs, "image_blake3"),
        blake3_file(&image_path).unwrap()
    );
    assert_eq!(
        require_str(inputs, "globals_blake3"),
        blake3_file(&globals_path).unwrap()
    );
    assert_eq!(
        require_str(inputs, "functions_blake3"),
        blake3_file(&functions_path).unwrap()
    );

    let report_has_thumb = report_image.get("thumb_functions").is_some();
    match inputs.get("thumb_functions_blake3") {
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
            assert!(is_blake3_hex(hash));
            assert_eq!(hash, &blake3_file(&thumb_path).unwrap());
        }
        other => panic!("{label}: thumb_functions_blake3 has unexpected value {other:?}"),
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

    for key in [
        "cross_block_join_kills",
        "cross_block_join_facts",
        "cross_block_entry_facts",
        "cross_block_propagated_facts",
        "cross_block_functions",
        "cross_block_seeded_functions",
    ] {
        require_u64(analysis, key);
    }

    let functions_json: Value =
        serde_json::from_slice(&std::fs::read(&functions_path).expect("functions.json readable"))
            .expect("functions.json valid JSON");
    let ghidra_records = ghidra_records(&functions_json);
    let ghidra = inventory_counts(
        &validate_ghidra_inventory_records(ghidra_records, ghidra_records.len(), &runtime)
            .expect("Ghidra execution inventory valid"),
    );
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
        let expected_substantial = report_image["thumb_functions"]
            .as_u64()
            .and_then(|count| usize::try_from(count).ok())
            .expect("Thumb substantial count fits usize");
        let parsed = inventory_counts(
            &crate::thumb_analysis::validate_thumb_inventory_streaming(
                &thumb_path,
                &runtime,
                expected_substantial,
            )
            .expect("Thumb execution inventory valid")
            .inventory,
        );
        assert_eq!(
            parsed.accepted,
            report_image["thumb_execution_accepted"].as_u64().unwrap() as usize
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

fn is_blake3_hex(value: &str) -> bool {
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

fn inventory_counts(inventory: &ValidatedInventory) -> InventoryCounts {
    InventoryCounts {
        raw: inventory.raw_count,
        accepted: inventory.accepted,
        quarantined: inventory.quarantined,
        quarantine_errors: inventory
            .records
            .iter()
            .map(|record| match &record.projection {
                ExecutionProjection::Accepted(_) => 0,
                ExecutionProjection::Quarantined(errors) => errors.len(),
            })
            .sum(),
    }
}

fn ghidra_records(functions_json: &Value) -> &[Value] {
    functions_json
        .as_array()
        .expect("functions.json must be an array")
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
