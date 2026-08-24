use std::path::{Path, PathBuf};

pub(crate) mod artifact;
pub(crate) mod discover;
pub(crate) mod reader;
#[allow(dead_code)]
pub(crate) mod refs;
pub(crate) mod wire;

pub(crate) const FORMAT: &str = "pixel-modem-extractor-debug-traces-v1";
#[allow(dead_code)]
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

/// Standalone decode of a modem.bin TOC: select the MAIN image
/// structurally, bind any scatter load map, discover the DBT debug-trace
/// records, and publish the catalog under `<out>/debug_traces`.
pub fn run(input: &Path, _opts: &Opts, out: &Path) -> crate::error::Result<PathBuf> {
    let data = std::fs::read(input)?;
    let toc = crate::toc::Toc::parse(&data)?;
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
    let raw = &data[start..end];
    let base = main.load_addr;

    std::fs::create_dir_all(out)?;
    let out = std::fs::canonicalize(out)?;
    let (runtime, scatter_load_map_blake3) = match crate::scatter::discover(raw, base) {
        Ok(None) => (
            crate::runtime_image::RuntimeImage::from_plan(raw, base, None)?,
            None,
        ),
        Ok(Some(plan)) => {
            let materialized = crate::scatter::materialize(&plan, raw, "MAIN", &out)?;
            let digest = crate::execution_ranges::parse_blake3(&materialized.blake3)?;
            let map = out.join(&materialized.relative_path);
            let runtime =
                crate::runtime_image::RuntimeImage::from_artifact(raw, base, &out, Some(&map))?;
            (runtime, Some(digest))
        }
        Err(error) => return Err(DbtTraceError::Scatter(error).into()),
    };
    let image_blake3 = runtime.hash_range(base, raw.len() as u32)?;
    let ctx = artifact::DbtContext {
        label: "MAIN",
        image_blake3,
        scatter_load_map_blake3,
    };
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
}
