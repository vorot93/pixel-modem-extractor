//! Stable Thumb-analysis types and subsystem exports.
#[allow(dead_code)]
mod artifact;
mod identity;
mod radare2;
mod rizin;
mod stream;

use crate::analysis_tool::AnalysisTool;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[allow(unused_imports)]
pub(crate) use artifact::{
    AttemptRecord, AttemptStatus, CaptureRecord, FunctionRunRecord, MappedImage, OwnedFunctionRef,
    OwnedThumbFunction, ParsedThumbArtifact, RegionRecord, THUMB_V1_FORMAT, THUMB_V2_FORMAT,
    THUMB_V3_FORMAT, ThumbDecodeRange, ThumbFormat, ThumbFunctionRecord, ThumbTerminalMetadata,
    ValidatedThumbInventory, assemble_v3_atomic, assemble_v3_into, parse_thumb_artifact,
    read_thumb_artifact, read_thumb_functions_streaming, stream_rewrite_json_array,
    stream_rewrite_thumb_functions, validate_thumb_inventory_streaming,
};
pub use radare2::discover_radare2;
pub use rizin::discover_rizin;
pub use stream::run_thumb_analysis;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThumbProducer {
    Radare2,
    Rizin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerIdentity {
    pub producer: ThumbProducer,
    pub executable: PathBuf,
    pub version: String,
    pub command: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThumbTools {
    pub radare2: ProducerIdentity,
    pub rizin: Option<ProducerIdentity>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThumbAnalysisSummary {
    pub regions_requested: usize,
    pub regions_succeeded: usize,
    pub regions_failed: usize,
    pub radare2_runs: usize,
    pub rizin_runs: usize,
    pub raw: usize,
    pub substantial: usize,
    pub accepted: usize,
    pub quarantined: usize,
}

impl ThumbProducer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Radare2 => "radare2",
            Self::Rizin => "rizin",
        }
    }

    pub const fn command(self) -> &'static str {
        match self {
            Self::Radare2 => "aaa;aflj;pdfj @@f",
            Self::Rizin => "aaa;aflj;pdfj @@F;axlj",
        }
    }
}

impl From<ThumbProducer> for AnalysisTool {
    fn from(value: ThumbProducer) -> Self {
        match value {
            ThumbProducer::Radare2 => Self::Radare2,
            ThumbProducer::Rizin => Self::Rizin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ThumbProducer;
    use crate::analysis_tool::AnalysisTool;

    #[test]
    fn thumb_producer_exposes_exact_ids_commands_and_analysis_tools() {
        assert_eq!(ThumbProducer::Radare2.as_str(), "radare2");
        assert_eq!(ThumbProducer::Rizin.as_str(), "rizin");
        assert_eq!(ThumbProducer::Radare2.command(), "aaa;aflj;pdfj @@f");
        assert_eq!(ThumbProducer::Rizin.command(), "aaa;aflj;pdfj @@F;axlj");
        assert_eq!(
            serde_json::to_string(&ThumbProducer::Radare2).unwrap(),
            "\"radare2\""
        );
        assert_eq!(
            serde_json::to_string(&ThumbProducer::Rizin).unwrap(),
            "\"rizin\""
        );
        assert_eq!(
            AnalysisTool::from(ThumbProducer::Radare2),
            AnalysisTool::Radare2
        );
        assert_eq!(
            AnalysisTool::from(ThumbProducer::Rizin),
            AnalysisTool::Rizin
        );
    }
}
