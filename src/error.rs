use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const REPORT_REASON_MAX_CHARS: usize = 2_048;
pub(crate) const REPORT_REASON_TRUNCATION_MARKER: &str = " [truncated]";

pub(crate) fn bounded_reason(message: &str) -> String {
    if message.chars().count() <= REPORT_REASON_MAX_CHARS {
        return message.to_owned();
    }
    let marker_chars = REPORT_REASON_TRUNCATION_MARKER.chars().count();
    let mut bounded: String = message
        .chars()
        .take(REPORT_REASON_MAX_CHARS - marker_chars)
        .collect();
    bounded.push_str(REPORT_REASON_TRUNCATION_MARKER);
    bounded
}

pub(crate) fn bounded_labelled_reasons(errors: &[(String, String)], separator: &str) -> String {
    let mut errors = errors.iter().collect::<Vec<_>>();
    errors.sort_unstable();
    let aggregate = errors
        .into_iter()
        .map(|(label, reason)| bounded_reason(&format!("{label}: {}", bounded_reason(reason))))
        .collect::<Vec<_>>()
        .join(separator);
    bounded_reason(&aggregate)
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("bad or missing FBPK magic")]
    BadMagic,
    #[error("unsupported FBPK version {0}")]
    UnsupportedVersion(u32),
    #[error("partition or directory not found: {0}")]
    NotFound(String),
    #[error("unexpected payload (not the expected container)")]
    UnexpectedPayload,
    #[error("bad TOC: {0}")]
    BadToc(String),
    #[error("tree-hash target invalid: {0}")]
    BadTree(String),
    #[error("bad scatter load map: {0}")]
    BadScatter(String),
    #[error("bad token database: {0}")]
    BadTokenDb(String),
    #[error("bad PAL task evidence: {0}")]
    BadPalTasks(String),
    #[error("dbt trace analysis failed: {0}")]
    BadDbtTraces(String),
    #[error("bad exception-root evidence: {0}")]
    BadExceptionRoots(String),
    #[error("bad startup metadata: {0}")]
    BadStartupMetadata(String),
    #[error("size mismatch for {name}: expected {expected}, got {actual}")]
    SizeMismatch {
        name: String,
        expected: u64,
        actual: u64,
    },
    #[error("ext4 error: {0}")]
    Ext4(String),
    #[error("serialize: {0}")]
    Serialize(String),
    #[error("ghidra not found: {0}")]
    GhidraNotFound(String),
    #[error("ghidra failed on {image}: exit code {code}")]
    GhidraFailed { image: String, code: i32 },
    #[error("ghidra state home unusable: {0}")]
    GhidraStateHome(String),
    #[error("required tool not found: {0}")]
    ToolNotFound(String),
    #[error("decompose incomplete: {0}")]
    DecomposeIncomplete(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    #[test]
    fn bounded_reason_counts_unicode_scalars_and_includes_marker() {
        let message = "x".repeat(super::REPORT_REASON_MAX_CHARS - 2) + &"\u{1f642}".repeat(8);

        let bounded = super::bounded_reason(&message);

        assert_eq!(bounded.chars().count(), super::REPORT_REASON_MAX_CHARS);
        assert!(bounded.ends_with(super::REPORT_REASON_TRUNCATION_MARKER));
        assert!(
            message.starts_with(
                bounded
                    .strip_suffix(super::REPORT_REASON_TRUNCATION_MARKER)
                    .unwrap()
            )
        );
    }

    #[test]
    fn bounded_reason_leaves_short_messages_byte_identical() {
        assert_eq!(super::bounded_reason("short \u{1f642}"), "short \u{1f642}");
    }
}
