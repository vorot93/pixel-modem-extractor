use std::path::{Path, PathBuf};

pub(crate) mod artifact;
pub(crate) mod discover;
pub(crate) mod exact;
pub(crate) mod reader;
pub(crate) mod refs;
pub(crate) mod wire;

pub(crate) const FORMAT: &str = "pixel-modem-extractor-debug-traces-v1";
pub(crate) const REFS_FORMAT: &str = "pixel-modem-extractor-debug-trace-refs-v1";
pub(crate) const SCHEMA_VERSION: u32 = 1;
pub(crate) const RECORD_BYTES: usize = 28;
pub(crate) const HEADER: &[u8; 4] = b"DBT:";

pub const MAX_OCCURRENCES: usize = 1_048_576;
pub const MAX_RECORDS: usize = 1_048_576;
pub const MAX_UNIQUE_FILES: usize = 65_536;
pub const MAX_UNIQUE_MESSAGES: usize = 2_097_152;
pub const MAX_QUARANTINED: usize = 4_096;
pub const MAX_MESSAGE_BYTES: usize = 4_096;
pub const MAX_LINE: u32 = 1_048_575;
pub const MAX_REFERENCES: usize = 4_194_304;

#[derive(Debug, thiserror::Error)]
pub enum DbtTraceError {
    #[error("dbt traces: io: {0}")]
    Io(#[from] std::io::Error),
    #[error("dbt traces: occurrence cap exceeded ({0})")]
    OccurrenceCap(usize),
    #[error("dbt traces: record cap exceeded ({0})")]
    RecordCap(usize),
    #[error("dbt traces: unique file table cap exceeded ({0})")]
    FileCap(usize),
    #[error("dbt traces: unique message table cap exceeded ({0})")]
    MessageCap(usize),
    #[error("dbt traces: quarantine cap exceeded ({0} quarantined)")]
    QuarantineCap(usize),
    #[error("dbt traces: reference cap exceeded ({0})")]
    ReferenceCap(usize),
    #[error("dbt traces: scatter discovery failed: {0}")]
    Scatter(#[source] crate::scatter::ScatterError),
    #[error("dbt traces: runtime read failed: {0}")]
    Runtime(#[from] crate::error::Error),
    #[error("dbt traces: artifact rejected: {0}")]
    Artifact(String),
}

impl From<DbtTraceError> for crate::error::Error {
    fn from(error: DbtTraceError) -> Self {
        crate::error::Error::BadDbtTraces(error.to_string())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub out: Option<PathBuf>,
}

pub(crate) fn standalone_main(data: &[u8]) -> Result<(&[u8], u32), DbtTraceError> {
    let toc = crate::toc::Toc::parse(data).map_err(DbtTraceError::Runtime)?;
    let main = toc
        .entries
        .iter()
        .find(|image| image.name == "MAIN")
        .ok_or_else(|| DbtTraceError::Artifact("no MAIN image in TOC".into()))?;
    let start = main.offset as usize;
    let end = start
        .checked_add(main.size as usize)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| DbtTraceError::Artifact("MAIN image range escapes the TOC file".into()))?;
    Ok((&data[start..end], main.load_addr))
}

pub(crate) fn bind_standalone<'a>(
    raw: &'a [u8],
    base: u32,
    out: &Path,
) -> crate::error::Result<(
    crate::runtime_image::RuntimeImage<'a>,
    artifact::DbtContext<'static>,
)> {
    let map = out.join("scatter/MAIN/load_map.json");
    let (runtime, scatter_load_map_blake3) = if map.exists() {
        let digest = crate::execution_ranges::parse_blake3(&crate::manifest::blake3_file(&map)?)?;
        let runtime =
            crate::runtime_image::RuntimeImage::from_artifact(raw, base, out, Some(&map))?;
        (runtime, Some(digest))
    } else {
        (
            crate::runtime_image::RuntimeImage::from_plan(raw, base, None)?,
            None,
        )
    };
    let image_blake3 = runtime.hash_range(base, raw.len() as u32)?;
    Ok((
        runtime,
        artifact::DbtContext {
            label: "MAIN",
            image_blake3,
            scatter_load_map_blake3,
        },
    ))
}

pub(crate) fn attribute_published(
    runtime: &crate::runtime_image::RuntimeImage<'_>,
    ctx: &artifact::DbtContext<'_>,
    catalog_dir: &Path,
    decompiled_dir: &Path,
) -> Result<refs::RefsOutcome, DbtTraceError> {
    let functions_path = decompiled_dir.join("functions.json");
    if !functions_path.exists() {
        return Err(DbtTraceError::Artifact("no function inventories".into()));
    }
    let catalog = reader::read(catalog_dir, runtime, ctx)?;
    let mut record_addresses = Vec::with_capacity(catalog.counts.records);
    for record in reader::iter_records(catalog_dir) {
        record_addresses.push(record?.address);
    }
    let mut functions = refs::load_functions(decompiled_dir, runtime)?.unwrap_or_default();
    if let Some(thumb) = refs::load_thumb(decompiled_dir, runtime)? {
        functions.extend(thumb);
    }
    let thumb_path = decompiled_dir.join("thumb_functions.json");
    let inputs = refs::RefsInputs {
        functions_blake3: crate::manifest::blake3_file(&functions_path)?,
        thumb_functions_blake3: if thumb_path.exists() {
            Some(crate::manifest::blake3_file(&thumb_path)?)
        } else {
            None
        },
    };
    refs::attribute(
        runtime,
        &record_addresses,
        &functions,
        &catalog,
        inputs,
        &catalog_dir.join("references.json"),
    )
}

/// Standalone decode of a modem.bin TOC: select the MAIN image
/// structurally, bind any scatter load map, discover the DBT debug-trace
/// records, and publish the catalog under `<out>/debug_traces`.
pub fn run(input: &Path, _opts: &Opts, out: &Path) -> crate::error::Result<PathBuf> {
    let data = std::fs::read(input)?;
    let (raw, base) = standalone_main(&data)?;
    std::fs::create_dir_all(out)?;
    let out = std::fs::canonicalize(out)?;
    match crate::scatter::discover(raw, base) {
        Ok(None) => {}
        Ok(Some(plan)) => {
            crate::scatter::materialize(&plan, raw, "MAIN", &out)?;
        }
        Err(error) => return Err(DbtTraceError::Scatter(error).into()),
    }
    let (runtime, ctx) = bind_standalone(raw, base, &out)?;
    let spill = out.join(format!("dbt_spill+{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&spill);
    let discovery = discover::discover(&runtime, &spill)?;
    let published = artifact::publish(&discovery, &runtime, &ctx, &out, true)?;
    let _ = std::fs::remove_dir_all(&spill);
    if published.is_some() {
        println!("debug traces -> {}", out.join("debug_traces").display());
    } else {
        println!("debug traces -> none (no candidates)");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_match_the_spec() {
        assert_eq!(MAX_OCCURRENCES, 1_048_576);
        assert_eq!(MAX_RECORDS, 1_048_576);
        assert_eq!(MAX_UNIQUE_FILES, 65_536);
        assert_eq!(MAX_UNIQUE_MESSAGES, 2_097_152);
        assert_eq!(MAX_QUARANTINED, 4_096);
        assert_eq!(MAX_MESSAGE_BYTES, 4_096);
        assert_eq!(MAX_LINE, 1_048_575);
        assert_eq!(MAX_REFERENCES, 4_194_304);
        assert_eq!(RECORD_BYTES, 28);
    }

    #[test]
    fn error_converts_into_the_library_error() {
        let error = crate::error::Error::from(DbtTraceError::RecordCap(3));
        assert!(matches!(error, crate::error::Error::BadDbtTraces(_)));
    }

    #[test]
    fn corpus_refs_pins() {
        assert_corpus_refs("PME_S5400_MAIN", "02_MAIN", 3, None);
        assert_corpus_refs("PME_S5300_MAIN", "01_MAIN", 2, None);
    }

    fn decompiled_inventory(label: &str) -> Option<std::path::PathBuf> {
        let Some(root) =
            std::env::var_os("PME_DECOMPOSED_GOLDEN_DIR").map(std::path::PathBuf::from)
        else {
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

    fn assert_corpus_refs(env_var: &str, label: &str, toc_index: u32, refs_count: Option<usize>) {
        let Some(decompiled) = decompiled_inventory(label) else {
            eprintln!("skip: refs inventories for {label}; refs_count={refs_count:?}");
            return;
        };
        let Some(path) = std::env::var_os(env_var).map(std::path::PathBuf::from) else {
            eprintln!("skip: set {env_var}");
            return;
        };
        if !path.is_file() {
            eprintln!("skip: {env_var} input not found");
            return;
        }
        let image = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let root = tempfile::tempdir().unwrap();
        let modem_path = root.path().join("modem.bin");
        std::fs::write(&modem_path, wrap_corpus_main(&image, toc_index)).unwrap();
        let out = run(&modem_path, &Default::default(), &root.path().join("out"))
            .unwrap_or_else(|error| panic!("{env_var} catalog failed: {error}"));
        let data = std::fs::read(&modem_path).unwrap();
        let (raw, base) = standalone_main(&data).unwrap();
        let (runtime, ctx) = bind_standalone(raw, base, &out).unwrap();
        let count = attribute_published(&runtime, &ctx, &out.join("debug_traces"), &decompiled)
            .unwrap_or_else(|error| panic!("{env_var} refs failed: {error}"))
            .count;
        match refs_count {
            None => eprintln!("PIN UNPOPULATED: {env_var} refs_count = {count}"),
            Some(expected) => assert_eq!(count, expected, "{env_var} refs_count"),
        }
    }
}
