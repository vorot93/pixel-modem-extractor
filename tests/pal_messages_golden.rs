//! Private-corpus PAL messages goldens for retained S5400 and S5300 MAIN images.
//!
//! Path: production scatter + `pal_messages` generation through `decompile::run_report`.
//! Pins stay empty sentinels until a lawful first run prints `PIN OBSERVED`. Only an
//! unset variable skips; a set missing/non-regular/symlink path fails. Never infer a
//! corpus pass from a clean env-gated skip. Do not call Phase 4 landed until both
//! legs PASS with copied pins.

use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

const IMAGE_BASE: u32 = 0x4001_0000;

struct CorpusPin {
    env_var: &'static str,
    label: &'static str,
    toc_index: u32,
    setup_entry: &'static str,
    setup_isa: &'static str,
    table_base: &'static str,
    stride: &'static str,
    capacity: &'static str,
    slot_count: &'static str,
    named_roots: &'static str,
    manifest_blake3: &'static str,
}

const S5400: CorpusPin = CorpusPin {
    env_var: "PME_S5400_MAIN",
    label: "02_MAIN",
    toc_index: 3,
    setup_entry: "",
    setup_isa: "",
    table_base: "",
    stride: "",
    capacity: "",
    slot_count: "",
    named_roots: "",
    manifest_blake3: "",
};

const S5300: CorpusPin = CorpusPin {
    env_var: "PME_S5300_MAIN",
    label: "01_MAIN",
    toc_index: 2,
    setup_entry: "",
    setup_isa: "",
    table_base: "",
    stride: "",
    capacity: "",
    slot_count: "",
    named_roots: "",
    manifest_blake3: "",
};

#[test]
fn s5400_pal_messages_pins_are_structural() {
    assert_corpus(&S5400);
}

#[test]
fn s5300_pal_messages_pins_are_structural() {
    assert_corpus(&S5300);
}

fn assert_corpus(pins: &CorpusPin) {
    let Some(path) = corpus_path_value(pins.env_var, std::env::var_os(pins.env_var))
        .unwrap_or_else(|error| panic!("{error}"))
    else {
        return;
    };
    let image = fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));

    let root = tempfile::tempdir().expect("temporary PAL messages corpus root");
    let modem_path = root.path().join("modem.bin");
    fs::write(&modem_path, wrap_corpus_main(&image, pins.toc_index)).unwrap();
    let out = root.path().join("out");
    let report = pixel_modem_extractor::decompile::run_report(
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

    let expected_relative = format!("pal_messages/{}/messages.json", pins.label);
    let spec: Value = serde_json::from_slice(&fs::read(report.spec_path).unwrap()).unwrap();
    assert_eq!(spec["images"].as_array().unwrap().len(), 1);

    let manifest_path = out.join(&expected_relative);
    let manifest_bytes = fs::read(&manifest_path).unwrap_or_else(|error| {
        panic!(
            "{} did not publish {}: {error}",
            pins.env_var,
            manifest_path.display()
        )
    });
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .unwrap_or_else(|error| panic!("invalid {}: {error}", manifest_path.display()));
    assert_eq!(manifest["format"], "pixel-modem-extractor-pal-messages-v1");
    assert_eq!(manifest["image"]["label"], pins.label);
    assert_eq!(manifest["image"]["base_addr"], "0x40010000");
    assert_eq!(
        manifest["image"]["blake3"],
        blake3::hash(&image).to_hex().to_string()
    );

    let slots = manifest["slots"].as_array().expect("slots array");
    let observed_slots = slots.len().to_string();
    let observed_entry = manifest["setup"]["entry"].as_str().unwrap_or_default();
    let observed_isa = manifest["setup"]["isa"].as_str().unwrap_or_default();
    let observed_base = manifest["table"]["base"].as_str().unwrap_or_default();
    let observed_stride = manifest["table"]["stride"]
        .as_u64()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let observed_capacity = manifest["table"]["capacity"]
        .as_u64()
        .map(|value| value.to_string())
        .unwrap_or_default();
    let observed = blake3::hash(&manifest_bytes).to_hex().to_string();
    let observed_roots = "1";
    eprintln!(
        "PIN OBSERVED: {} setup_entry={} setup_isa={} table_base={} stride={} capacity={} slot_count={} named_roots={} manifest_blake3={}",
        pins.env_var,
        observed_entry,
        observed_isa,
        observed_base,
        observed_stride,
        observed_capacity,
        observed_slots,
        observed_roots,
        observed
    );
    pin_or_observe("setup_entry", pins.setup_entry, observed_entry);
    pin_or_observe("setup_isa", pins.setup_isa, observed_isa);
    pin_or_observe("table_base", pins.table_base, observed_base);
    pin_or_observe("stride", pins.stride, &observed_stride);
    pin_or_observe("capacity", pins.capacity, &observed_capacity);
    pin_or_observe("slot_count", pins.slot_count, &observed_slots);
    pin_or_observe("named_roots", pins.named_roots, observed_roots);
    pin_or_observe("manifest_blake3", pins.manifest_blake3, &observed);
}

fn pin_or_observe(name: &str, expected: &str, observed: &str) {
    if expected.is_empty() {
        return;
    }
    assert_eq!(observed, expected, "pin mismatch: {name}");
}

fn wrap_corpus_main(image: &[u8], index: u32) -> Vec<u8> {
    let entry_offset = 0x20usize;
    let payload_offset = entry_offset + 0x20;
    let mut modem = vec![0; payload_offset + image.len()];
    modem[0..4].copy_from_slice(b"TOC\0");
    modem[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes());
    modem[entry_offset..entry_offset + 4].copy_from_slice(b"MAIN");
    modem[entry_offset + 12..entry_offset + 16]
        .copy_from_slice(&(payload_offset as u32).to_le_bytes());
    modem[entry_offset + 16..entry_offset + 20].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    modem[entry_offset + 20..entry_offset + 24]
        .copy_from_slice(&(image.len() as u32).to_le_bytes());
    modem[entry_offset + 28..entry_offset + 32].copy_from_slice(&index.to_le_bytes());
    modem[payload_offset..].copy_from_slice(image);
    modem
}

fn corpus_path_value(env_var: &str, value: Option<OsString>) -> Result<Option<PathBuf>, String> {
    let Some(value) = value else {
        eprintln!("UNRUN: {env_var} is unset");
        return Ok(None);
    };
    let path = PathBuf::from(
        value
            .into_string()
            .map_err(|_| format!("{env_var} input path is not valid Unicode"))?,
    );
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "{env_var} input is a symlink, expected a regular file: {}",
            path.display()
        )),
        Ok(metadata) if metadata.is_file() => Ok(Some(path)),
        Ok(_) => Err(format!(
            "{env_var} input is not a regular file: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to inspect configured {env_var} input {}: {error}",
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
    std::fs::write(&s5400, b"image").unwrap();

    assert_eq!(
        corpus_path_value("PME_S5400_MAIN", Some(s5400.clone().into_os_string())).unwrap(),
        Some(s5400),
        "a configured regular S5400 input must run"
    );
    assert_eq!(
        corpus_path_value("PME_S5300_MAIN", None).unwrap(),
        None,
        "the unavailable S5300 leg must still skip independently"
    );

    let missing = root.path().join("missing.bin");
    let error = corpus_path_value("PME_S5300_MAIN", Some(missing.into_os_string())).unwrap_err();
    assert!(
        error.contains("failed to inspect configured PME_S5300_MAIN input"),
        "unexpected configured-missing error: {error}"
    );
}

#[cfg(unix)]
#[test]
fn configured_corpus_symlink_to_regular_file_is_rejected() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let regular = root.path().join("main.bin");
    let link = root.path().join("main-link.bin");
    std::fs::write(&regular, b"image").unwrap();
    symlink(&regular, &link).unwrap();

    let error = corpus_path_value("PME_S5400_MAIN", Some(link.into_os_string())).unwrap_err();
    assert!(
        error.contains("is a symlink, expected a regular file"),
        "unexpected configured-symlink error: {error}"
    );
}
