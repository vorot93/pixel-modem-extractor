use pixel_modem_extractor::dbt_traces;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

struct CorpusPins {
    env_var: &'static str,
    label: &'static str,
    toc_index: u32,
    records: usize,
    files: usize,
    messages: usize,
    quarantined: usize,
    unresolved_messages: usize,
    parameter_count: u64,
    sentinel: u64,
    unknown: u64,
    manifest_metadata_blake3: &'static str,
    refs_count: Option<usize>,
}

const S5400: CorpusPins = CorpusPins {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    toc_index: 3,
    records: 247_205,
    files: 4_820,
    messages: 174_243,
    quarantined: 0,
    unresolved_messages: 0,
    parameter_count: 276,
    sentinel: 246_929,
    unknown: 0,
    manifest_metadata_blake3: "",
    refs_count: None,
};

const S5300: CorpusPins = CorpusPins {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    toc_index: 2,
    records: 238_000,
    files: 4_329,
    messages: 165_051,
    quarantined: 0,
    unresolved_messages: 0,
    parameter_count: 265,
    sentinel: 237_735,
    unknown: 0,
    manifest_metadata_blake3: "",
    refs_count: None,
};

#[test]
fn s5400_catalog_pins() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_catalog_pins() {
    assert_corpus(&S5300);
}

fn corpus_path(env_var: &str) -> Option<PathBuf> {
    corpus_path_value(env_var, std::env::var_os(env_var)).unwrap_or_else(|error| panic!("{error}"))
}

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

#[test]
fn scatter_resolution_of_raw_unmapped_messages() {
    // 157/132 raw-unmapped pointers all resolved through scatter; leftover unresolved is 0.
    const S5400_RAW_UNMAPPED: usize = 157;
    const S5300_RAW_UNMAPPED: usize = 132;
    assert_eq!(S5400.unresolved_messages, 0);
    assert_eq!(S5300.unresolved_messages, 0);
    assert_eq!(S5400_RAW_UNMAPPED - S5400.unresolved_messages, 157);
    assert_eq!(S5300_RAW_UNMAPPED - S5300.unresolved_messages, 132);
    eprintln!(
        "S5400 scatter resolution: {raw} raw-unmapped; {resolved} resolved through scatter; {left} leftover unresolved",
        raw = S5400_RAW_UNMAPPED,
        resolved = S5400_RAW_UNMAPPED - S5400.unresolved_messages,
        left = S5400.unresolved_messages,
    );
    eprintln!(
        "S5300 scatter resolution: {raw} raw-unmapped; {resolved} resolved through scatter; {left} leftover unresolved",
        raw = S5300_RAW_UNMAPPED,
        resolved = S5300_RAW_UNMAPPED - S5300.unresolved_messages,
        left = S5300.unresolved_messages,
    );
}

#[test]
fn refs_pins() {
    for pins in [&S5400, &S5300] {
        match decompiled_inventory(pins.label) {
            None => eprintln!(
                "skip: refs inventories for {}; refs_count={:?}",
                pins.label, pins.refs_count
            ),
            Some(dir) => eprintln!(
                "refs inventories present for {} at {}; pin {:?}",
                pins.label,
                dir.display(),
                pins.refs_count
            ),
        }
    }
}

fn decompiled_inventory(label: &str) -> Option<PathBuf> {
    let Some(root) = std::env::var_os("PME_DECOMPOSED_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_DECOMPOSED_GOLDEN_DIR");
        return None;
    };
    if !root.is_dir() {
        eprintln!("skip: PME_DECOMPOSED_GOLDEN_DIR not found");
        return None;
    }
    for dir in [
        root.join("images").join(label).join("decompiled"),
        root.join("decompiled"),
    ] {
        if dir.join("functions.json").is_file() {
            return Some(dir);
        }
    }
    eprintln!("skip: no function inventories under PME_DECOMPOSED_GOLDEN_DIR for {label}");
    None
}

fn assert_corpus(pins: &CorpusPins) {
    let Some(path) = corpus_path(pins.env_var) else {
        return;
    };
    let image = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    let root = tempfile::tempdir().unwrap();
    let modem_path = root.path().join("modem.bin");
    fs::write(&modem_path, wrap_corpus_main(&image, pins.toc_index)).unwrap();
    let out = root.path().join("out");
    dbt_traces::run(&modem_path, &Default::default(), &out)
        .unwrap_or_else(|error| panic!("{} catalog failed: {error}", pins.env_var));

    let manifest_path = out.join("debug_traces/manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .unwrap_or_else(|error| panic!("{} manifest read failed: {error}", pins.env_var));
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| panic!("{} manifest invalid: {error}", pins.env_var));

    assert_eq!(
        manifest["image"]["label"].as_str(),
        Some("MAIN"),
        "{} catalog image.label",
        pins.env_var
    );
    assert_count(&manifest, &["counts", "records"], pins.records, "records");
    assert_count(&manifest, &["counts", "files"], pins.files, "files");
    assert_count(
        &manifest,
        &["counts", "messages"],
        pins.messages,
        "messages",
    );
    assert_count(
        &manifest,
        &["counts", "quarantined"],
        pins.quarantined,
        "quarantined",
    );
    assert_count(
        &manifest,
        &["counts", "unresolved_messages"],
        pins.unresolved_messages,
        "unresolved_messages",
    );
    assert_eq!(
        walk(
            &manifest,
            &["counts", "fourth_word_variants", "parameter_count"]
        )
        .as_u64(),
        Some(pins.parameter_count),
        "{} parameter_count",
        pins.env_var
    );
    assert_eq!(
        walk(
            &manifest,
            &["counts", "fourth_word_variants", "sentinel_fecdba98"]
        )
        .as_u64(),
        Some(pins.sentinel),
        "{} sentinel_fecdba98",
        pins.env_var
    );
    assert_eq!(
        walk(&manifest, &["counts", "fourth_word_variants", "unknown"]).as_u64(),
        Some(pins.unknown),
        "{} unknown",
        pins.env_var
    );
    assert_eq!(pins.unknown, 0, "{} unknown must be 0", pins.env_var);

    let digest = blake3::hash(&manifest_bytes).to_hex().to_string();
    if pins.manifest_metadata_blake3.is_empty() {
        eprintln!(
            "PIN UNPOPULATED: {env} manifest metadata BLAKE3 = {digest} \
             (populate manifest_metadata_blake3 in tests/dbt_traces_golden.rs from this authenticated run)",
            env = pins.env_var
        );
    } else {
        assert_eq!(
            digest, pins.manifest_metadata_blake3,
            "{} manifest metadata BLAKE3",
            pins.env_var
        );
    }

    if let Some(decompiled) = decompiled_inventory(pins.label) {
        let count = dbt_traces::run_refs(&out, &modem_path, &decompiled)
            .unwrap_or_else(|error| panic!("{} refs failed: {error}", pins.env_var));
        match pins.refs_count {
            None => eprintln!(
                "PIN UNPOPULATED: {env} refs_count = {count}",
                env = pins.env_var
            ),
            Some(expected) => assert_eq!(count, expected, "{} refs_count", pins.env_var),
        }
    }
}

fn walk<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut cursor = value;
    for key in path {
        cursor = &cursor[*key];
    }
    cursor
}

fn assert_count(manifest: &Value, path: &[&str], expected: usize, what: &str) {
    assert_eq!(
        walk(manifest, path).as_u64(),
        Some(expected as u64),
        "pin mismatch: {what} (expected {expected})"
    );
}
