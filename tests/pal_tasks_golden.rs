//! Private-corpus PAL task goldens: the complete production discovery
//! path (scatter generation plus `pal_tasks` manifest generation through
//! `decompile::run_report`) over the two retained Pixel MAIN slices,
//! gated independently on `PME_S5400_MAIN` (Mustang) and `PME_S5300_MAIN`
//! (Cheetah). Every pinned value below is non-proprietary: semantic
//! addresses, geometry, counts, and distributions already recorded in the
//! design baseline. No task names or firmware bytes are committed.
//!
//! The corpus tests authenticate the complete input (exact source
//! BLAKE3, shared with the scatter goldens' identical inputs) before any
//! corpus-specific pin is applied. The two aggregate digest pins -- the
//! canonical manifest BLAKE3 and the sorted per-task metadata BLAKE3 -
//! are corpus-derived values that commit neither names nor bytes; until
//! they are populated from an authenticated corpus run they are empty
//! sentinels that skip loudly with the computed digest printed, so a
//! corpus host can populate them and every later run enforces them.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// The canonical metadata line each task contributes to the sorted
/// metadata digest: interpreted fields only (no names, no firmware
/// bytes, no per-task firmware-byte digests). Lines are sorted
/// lexicographically and joined with `\n` before hashing.
fn metadata_line(task: &Value) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        task["index"].as_u64().unwrap(),
        task["slot"].as_str().unwrap(),
        task["name"].as_str().unwrap().len(),
        task["priority"].as_u64().unwrap(),
        task["stack_size"].as_u64().unwrap(),
        task["entry"].as_str().unwrap(),
        task["isa"].as_str().unwrap(),
        task["instruction_size"].as_u64().unwrap(),
    )
}

struct CorpusPins {
    env_var: &'static str,
    /// TOC label the single-image wrapper must produce (`02_MAIN` /
    /// `01_MAIN`) and the TOC index that derives it.
    label: &'static str,
    toc_index: u32,
    /// Exact source BLAKE3 of the complete corpus input. Identical to
    /// the scatter goldens' pins for the same files.
    source_blake3: &'static str,
    /// Initializer CFG entry, loop start, suffix loop, and count global.
    cfg_entry: &'static str,
    loop_start: &'static str,
    suffix_loop: &'static str,
    count_global: &'static str,
    /// Anchor occurrence and the semantic anchor reference.
    anchor: &'static str,
    reference: &'static str,
    /// Capacity guard: the `LSR` start and the `BHI` branch.
    guard_start: &'static str,
    guard_branch: &'static str,
    /// Derived table geometry: slot base, stride, capacity, terminal.
    slot_base: &'static str,
    stride: u64,
    capacity: u64,
    terminal: &'static str,
    count: usize,
    /// Exact priority span (both endpoints observed).
    priority_min: u64,
    priority_max: u64,
    /// Exact count of priorities above `0x1f` (Cheetah's documented 124).
    priorities_above_threshold: Option<usize>,
    /// Exact count of normalized entries at `2 mod 4` (Cheetah's 57).
    entries_two_mod_four: Option<usize>,
    /// Retained-inventory exact-match counts, non-authoritative context
    /// from the design baseline: proof that semantic discovery exceeds
    /// every retained analyzer inventory, never a gate on validity.
    retained_ghidra_exact: usize,
    retained_radare2_exact: usize,
    /// BLAKE3 of the exact canonical manifest bytes. Empty until
    /// populated from an authenticated corpus run.
    manifest_blake3: &'static str,
    /// BLAKE3 of the sorted metadata lines. Empty until populated from
    /// an authenticated corpus run.
    metadata_blake3: &'static str,
}

const S5400: CorpusPins = CorpusPins {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    toc_index: 3,
    source_blake3: "efdf5ce38548d393b5e473597e0efe61f13e09db8d6e805c927eb76303687dd0",
    cfg_entry: "0x40e28c6c",
    loop_start: "0x40e28cd4",
    suffix_loop: "0x40e28d1a",
    count_global: "0x45dc20d0",
    anchor: "0x40e28d7c",
    reference: "0x40e28cb0",
    guard_start: "0x40e28d00",
    guard_branch: "0x40e28d04",
    slot_base: "0x43d61f60",
    stride: 0x1f8,
    capacity: 1000,
    terminal: "0x43d72538",
    count: 133,
    priority_min: 0x05,
    priority_max: 0x1f,
    priorities_above_threshold: None,
    entries_two_mod_four: None,
    retained_ghidra_exact: 0,
    retained_radare2_exact: 11,
    manifest_blake3: "",
    metadata_blake3: "",
};

const S5300: CorpusPins = CorpusPins {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    toc_index: 2,
    source_blake3: "5b4bc06c800553445ae60471f84afd95b0d2b365a03d481394d8b6e54a0e4d11",
    cfg_entry: "0x41114a68",
    loop_start: "0x41114ad6",
    suffix_loop: "0x41114b1a",
    count_global: "0x46894fe0",
    anchor: "0x41114b8c",
    reference: "0x41114aa8",
    guard_start: "0x41114b02",
    guard_branch: "0x41114b06",
    slot_base: "0x441c8198",
    stride: 0x1d8,
    capacity: 1000,
    terminal: "0x441dac48",
    count: 162,
    priority_min: 0x06,
    priority_max: 0xff,
    priorities_above_threshold: Some(124),
    entries_two_mod_four: Some(57),
    retained_ghidra_exact: 3,
    retained_radare2_exact: 19,
    manifest_blake3: "",
    metadata_blake3: "",
};

#[test]
fn s5400_main_matches_exact_pal_task_corpus() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_main_matches_exact_pal_task_corpus() {
    assert_corpus(&S5300);
}

fn corpus_path(env_var: &str) -> Option<PathBuf> {
    corpus_path_value(env_var, std::env::var_os(env_var)).unwrap_or_else(|error| panic!("{error}"))
}

/// Skip only unset or missing inputs; every other condition is a failure.
fn corpus_path_value(
    env_var: &str,
    value: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>, String> {
    let Some(path) = value.map(PathBuf::from) else {
        eprintln!("skip: set {env_var}");
        return Ok(None);
    };
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(path)),
        Ok(_) => Err(format!(
            "{env_var} input is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skip: {env_var} input not found");
            Ok(None)
        }
        Err(error) => Err(format!(
            "failed to inspect {env_var} input {}: {error}",
            path.display()
        )),
    }
}

/// The corpus gates skip independently: each env var controls only its
/// own leg, a set-but-missing input skips, and a set-but-not-a-file
/// input fails instead of masquerading as absence. Runs identically
/// regardless of the ambient corpus environment.
#[test]
fn no_corpus_environment_skips_independently() {
    assert_eq!(corpus_path_value("PME_S5400_MAIN", None).unwrap(), None);
    assert_eq!(corpus_path_value("PME_S5300_MAIN", None).unwrap(), None);

    let root = tempfile::tempdir().unwrap();
    let s5400 = root.path().join("s5400.bin");
    fs::write(&s5400, b"image").unwrap();

    let resolved = corpus_path_value("PME_S5400_MAIN", Some(s5400.into_os_string())).unwrap();
    assert!(resolved.is_some(), "a set, present, regular input must run");
    assert_eq!(
        corpus_path_value("PME_S5300_MAIN", None).unwrap(),
        None,
        "the other corpus gate must still skip independently"
    );

    let missing = root.path().join("missing.bin");
    assert_eq!(
        corpus_path_value("PME_S5300_MAIN", Some(missing.into_os_string())).unwrap(),
        None,
        "a set-but-missing input skips"
    );
    let error = corpus_path_value(
        "PME_S5300_MAIN",
        Some(root.path().as_os_str().to_os_string()),
    )
    .unwrap_err();
    assert!(error.contains("not a regular file"), "{error}");
}

/// The single-image `modem.bin` TOC wrapper for one corpus MAIN slice
/// (name `MAIN`, base `0x40010000`, index chosen so the derived label is
/// the corpus's split-image label).
fn wrap_corpus_main(image: &[u8], index: u32) -> Vec<u8> {
    let entry_off = 0x20usize;
    let payload_off = entry_off + 0x20;
    let mut buf = vec![0u8; payload_off + image.len()];
    buf[0..4].copy_from_slice(b"TOC\0");
    buf[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes());
    buf[entry_off..entry_off + 4].copy_from_slice(b"MAIN");
    buf[entry_off + 12..entry_off + 16].copy_from_slice(&(payload_off as u32).to_le_bytes());
    buf[entry_off + 16..entry_off + 20].copy_from_slice(&0x4001_0000u32.to_le_bytes());
    buf[entry_off + 20..entry_off + 24].copy_from_slice(&(image.len() as u32).to_le_bytes());
    buf[entry_off + 28..entry_off + 32].copy_from_slice(&index.to_le_bytes());
    buf[payload_off..].copy_from_slice(image);
    buf
}

fn parse_address(value: &Value, what: &str) -> u64 {
    u64::from_str_radix(
        value
            .as_str()
            .unwrap_or_else(|| panic!("{what} must be a string"))
            .trim_start_matches("0x"),
        16,
    )
    .unwrap_or_else(|error| panic!("{what} is not an address: {error}"))
}

fn assert_corpus(pins: &CorpusPins) {
    let Some(path) = corpus_path(pins.env_var) else {
        return;
    };
    let image = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    // Identity first: the complete input is authenticated before any
    // corpus-specific pin is applied.
    let source_blake3 = blake3::hash(&image).to_hex().to_string();
    assert_eq!(
        source_blake3, pins.source_blake3,
        "{} source identity mismatch",
        pins.env_var
    );

    let dir = std::env::temp_dir().join(format!(
        "pme_pal_corpus_{}_{}",
        pins.label,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let modem_path = dir.join("modem.bin");
    fs::write(&modem_path, wrap_corpus_main(&image, pins.toc_index)).unwrap();
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
    .unwrap_or_else(|error| panic!("{} generation failed: {error}", pins.env_var));

    let spec: Value = serde_json::from_slice(&fs::read(out.join("ghidra_load.json")).unwrap())
        .unwrap_or_else(|error| panic!("{} ghidra_load.json invalid: {error}", pins.env_var));
    assert_eq!(
        spec["images"][0]["pal_task_map"],
        format!("pal_tasks/{}/tasks.json", pins.label),
        "{} PAL manifest must be wired into the kit",
        pins.env_var
    );

    let manifest_path = out.join(format!("pal_tasks/{}/tasks.json", pins.label));
    let manifest_bytes = fs::read(&manifest_path)
        .unwrap_or_else(|error| panic!("{} manifest read failed: {error}", pins.env_var));
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| panic!("{} manifest invalid: {error}", pins.env_var));

    assert_pin(&manifest, &["image", "label"], pins.label, "image label");
    assert_eq!(manifest["image"]["base_addr"], "0x40010000");
    assert_eq!(
        manifest["image"]["blake3"].as_str().unwrap(),
        source_blake3,
        "the manifest must authenticate the exact corpus input"
    );
    assert_eq!(
        manifest["image"]["size"].as_u64().unwrap(),
        u64::try_from(image.len()).unwrap(),
        "the manifest must carry the complete image size"
    );

    // Both corpora carry a scatter loader; the PAL manifest must bind it.
    assert!(
        manifest["runtime_view"]["scatter_load_map_blake3"]
            .as_str()
            .is_some(),
        "{} PAL manifest must bind its scatter dependency",
        pins.env_var
    );
    let used = manifest["runtime_view"]["scatter_entries_used"]
        .as_array()
        .unwrap();
    let used_values: Vec<u64> = used.iter().map(|entry| entry.as_u64().unwrap()).collect();
    let mut used_sorted = used_values.clone();
    used_sorted.sort_unstable();
    used_sorted.dedup();
    assert_eq!(
        used_values, used_sorted,
        "scatter entries used must be sorted and unique"
    );

    let initializer = &manifest["initializer"];
    assert_pin(initializer, &["cfg_entry"], pins.cfg_entry, "CFG entry");
    assert_pin(initializer, &["loop_start"], pins.loop_start, "loop start");
    assert_pin(
        initializer,
        &["suffix_loop"],
        pins.suffix_loop,
        "suffix loop",
    );
    assert_pin(
        initializer,
        &["count_global"],
        pins.count_global,
        "count global",
    );
    let anchors = initializer["anchors"].as_array().unwrap();
    assert!(!anchors.is_empty(), "at least one anchor occurrence");
    for anchor in anchors {
        assert_pin(anchor, &["address"], pins.anchor, "anchor occurrence");
    }
    let references = initializer["anchor_references"].as_array().unwrap();
    let wanted = references
        .iter()
        .find(|reference| reference["address"].as_str() == Some(pins.reference))
        .unwrap_or_else(|| {
            panic!(
                "{env} must pin the semantic anchor reference {wanted}",
                env = pins.env_var,
                wanted = pins.reference
            )
        });
    assert_eq!(
        wanted["anchor"].as_str(),
        Some(pins.anchor),
        "the pinned reference must prove the pinned anchor"
    );
    let guard = &initializer["capacity_guard"];
    assert_pin(guard, &["start"], pins.guard_start, "capacity guard start");
    assert_pin(
        guard,
        &["branch"],
        pins.guard_branch,
        "capacity guard branch",
    );
    assert_ne!(
        guard["fallthrough"].as_str(),
        guard["branch"].as_str(),
        "capacity guard fallthrough must differ from its branch"
    );
    assert_pin(
        initializer,
        &["slot_base"],
        pins.slot_base,
        "derived slot base",
    );
    assert_eq!(
        initializer["stride"].as_u64().unwrap(),
        pins.stride,
        "derived stride"
    );
    assert_eq!(
        initializer["capacity"].as_u64().unwrap(),
        pins.capacity,
        "derived capacity"
    );
    assert_eq!(
        initializer["name_offset"].as_u64().unwrap(),
        0x4c,
        "name field offset"
    );
    assert_eq!(
        initializer["index_offset"].as_u64().unwrap(),
        0x0c,
        "index field offset"
    );

    let table = &manifest["table"];
    assert_eq!(
        table["count"].as_u64().unwrap(),
        pins.count as u64,
        "{} task count",
        pins.env_var
    );
    assert_pin(table, &["terminal_slot"], pins.terminal, "terminal slot");
    assert_eq!(
        table["descriptor_projection_offset"].as_u64().unwrap(),
        0x28,
        "descriptor projection offset"
    );
    assert_eq!(table["priority_offset"].as_u64().unwrap(), 0x50);
    assert_eq!(table["stack_size_offset"].as_u64().unwrap(), 0x54);
    assert_eq!(table["entry_offset"].as_u64().unwrap(), 0x58);
    assert_eq!(table["callback_offset"].as_u64().unwrap(), 0x5c);
    assert_eq!(table["unknown_pointer_offset"].as_u64().unwrap(), 0x60);

    let tasks = manifest["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), pins.count);
    let slot_base = parse_address(&initializer["slot_base"], "slot base");
    let mut names = std::collections::BTreeSet::new();
    let mut entries = std::collections::BTreeSet::new();
    let mut arm_total = 0usize;
    let mut thumb_total = 0usize;
    let mut two_mod_four = 0usize;
    let mut priorities_above_threshold = 0usize;
    let mut priority_min = u64::MAX;
    let mut priority_max = 0u64;
    let mut stack_min = u64::MAX;
    let mut stack_max = 0u64;
    let mut non_power_of_two_stacks = 0usize;
    let mut metadata_lines = Vec::with_capacity(tasks.len());
    for (position, task) in tasks.iter().enumerate() {
        assert_eq!(
            task["index"].as_u64().unwrap(),
            position as u64,
            "task indices are dense and in order"
        );
        let slot = parse_address(&task["slot"], "task slot");
        assert_eq!(
            slot,
            slot_base + (position as u64) * pins.stride,
            "task {position} slot geometry"
        );
        let name = task["name"].as_str().unwrap();
        assert!(
            (2..=21).contains(&name.len()),
            "{env} task name length {len} outside the documented 2..=21 span",
            env = pins.env_var,
            len = name.len()
        );
        assert!(
            !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_'),
            "{env} task name must be a valid C identifier",
            env = pins.env_var
        );
        assert!(names.insert(name.to_string()), "task names must be unique");
        let entry_pointer = parse_address(&task["entry_pointer"], "entry pointer");
        let entry = parse_address(&task["entry"], "normalized entry");
        assert_eq!(
            entry_pointer % 2,
            1,
            "stored entries must be odd Thumb pointers"
        );
        assert_eq!(
            entry,
            entry_pointer - 1,
            "normalized entry clears the ISA tag"
        );
        assert!(entries.insert(entry), "normalized entries must be unique");
        match task["isa"].as_str().unwrap() {
            "arm" => arm_total += 1,
            "thumb" => thumb_total += 1,
            other => panic!("unknown ISA {other}"),
        }
        if entry % 4 == 2 {
            two_mod_four += 1;
        }
        let priority = task["priority"].as_u64().unwrap();
        priority_min = priority_min.min(priority);
        priority_max = priority_max.max(priority);
        if priority > 0x1f {
            priorities_above_threshold += 1;
        }
        let stack = task["stack_size"].as_u64().unwrap();
        assert!(stack > 0, "stack sizes are nonzero");
        assert_eq!(stack % 4, 0, "stack sizes are divisible by four");
        stack_min = stack_min.min(stack);
        stack_max = stack_max.max(stack);
        if !stack.is_power_of_two() {
            non_power_of_two_stacks += 1;
        }
        metadata_lines.push(metadata_line(task));
    }
    assert_eq!(arm_total, 0, "every retained entry is Thumb");
    assert_eq!(thumb_total, pins.count, "every retained entry is Thumb");
    assert_eq!(priority_min, pins.priority_min, "priority span minimum");
    assert_eq!(priority_max, pins.priority_max, "priority span maximum");
    if let Some(expected) = pins.priorities_above_threshold {
        assert_eq!(
            priorities_above_threshold, expected,
            "priorities above 0x1f"
        );
    }
    if let Some(expected) = pins.entries_two_mod_four {
        assert_eq!(two_mod_four, expected, "entries at 2 mod 4");
    }
    assert!(
        stack_min >= 0x400 && stack_max <= 0x32000,
        "stack span {stack_min:#x}..{stack_max:#x} outside the documented envelope"
    );
    assert!(
        non_power_of_two_stacks > 0,
        "documented non-power-of-two stack sizes must occur"
    );

    // Semantic discovery must exceed every retained analyzer inventory
    // (non-authoritative context: incomplete coverage was the reason this
    // feature exists, and inventories never gate task validity).
    assert!(
        thumb_total > pins.retained_ghidra_exact && thumb_total > pins.retained_radare2_exact,
        "{env} discovery ({thumb_total} entries) must exceed the retained inventories \
         (Ghidra {ghidra}, radare2 {radare2})",
        env = pins.env_var,
        ghidra = pins.retained_ghidra_exact,
        radare2 = pins.retained_radare2_exact
    );

    let applications = manifest["applications"].as_array().unwrap();
    let mut covered = vec![false; tasks.len()];
    let mut application_entries = std::collections::BTreeSet::new();
    for application in applications {
        let entry = parse_address(&application["entry"], "application entry");
        assert!(
            application_entries.insert(entry),
            "application entries must be unique"
        );
        assert!(
            application["desired_primary"]
                .as_str()
                .is_some_and(|primary| primary.starts_with("pal_TaskEntry_")),
            "application primaries use the reserved prefix"
        );
        for index in application["task_indices"].as_array().unwrap() {
            let index = index.as_u64().unwrap() as usize;
            assert!(
                !std::mem::replace(&mut covered[index], true),
                "applications must partition task indices"
            );
            let task_entry = parse_address(&tasks[index]["entry"], "task entry");
            assert_eq!(
                task_entry, entry,
                "application membership must share the normalized entry"
            );
        }
    }
    assert!(covered.into_iter().all(|seen| seen));

    let manifest_digest = blake3::hash(&manifest_bytes).to_hex().to_string();
    if pins.manifest_blake3.is_empty() {
        eprintln!(
            "PIN UNPOPULATED: {env} manifest BLAKE3 = {manifest_digest} \
             (populate manifest_blake3 in tests/pal_tasks_golden.rs from this authenticated run)",
            env = pins.env_var
        );
    } else {
        assert_eq!(
            manifest_digest, pins.manifest_blake3,
            "{} canonical manifest BLAKE3",
            pins.env_var
        );
    }

    metadata_lines.sort_unstable();
    let metadata_digest = blake3::hash(metadata_lines.join("\n").as_bytes())
        .to_hex()
        .to_string();
    if pins.metadata_blake3.is_empty() {
        eprintln!(
            "PIN UNPOPULATED: {env} sorted metadata BLAKE3 = {metadata_digest} \
             (populate metadata_blake3 in tests/pal_tasks_golden.rs from this authenticated run)",
            env = pins.env_var
        );
    } else {
        assert_eq!(
            metadata_digest, pins.metadata_blake3,
            "{} sorted metadata BLAKE3",
            pins.env_var
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

fn assert_pin(value: &Value, path: &[&str], expected: &'static str, what: &str) {
    let mut cursor = value;
    for key in path {
        cursor = &cursor[*key];
    }
    assert_eq!(
        cursor.as_str(),
        Some(expected),
        "pin mismatch: {what} (expected {expected})"
    );
}
