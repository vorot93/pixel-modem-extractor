// PAL task initializer discovery: shared types, named limits, and the
// structured domain error. The bounded anchor sweep and unique-prologue
// root selection live in `discover`; the entry-rooted CFG, its
// definition-aware dataflow, and the graph queries used by the induction
// proofs live in `cfg`. Later stages build loop proofs and table
// validation on the candidates assembled here.

use crate::arm32::Register;
use crate::error::Error;
use crate::runtime_image::{RuntimeImage, StorageSpan};
use serde::{Deserialize, Serialize};
use std::fmt;

mod cfg;
mod discover;

/// Discover every anchor-reference candidate: one entry per semantic
/// reference that survives unique-prologue root selection and bounded
/// CFG closure. Below-threshold misses are skipped; named resource
/// limits and runtime failures are typed errors.
pub(super) fn discover_anchor_cfg(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Vec<AnchorCfgCandidate>, PalTaskError> {
    discover::discover_anchor_cfg(image, label)
}

/// Exact nine-byte runtime materialization searched over byte-backed
/// storage.
pub(crate) const ANCHOR_PATTERN: &[u8; 9] = b"PALTskTm\0";
pub(crate) const MAX_ANCHOR_OCCURRENCES: u64 = 4096;
pub(crate) const MAX_ANCHOR_REFERENCES: u64 = 16384;
/// Maximum absolute distance between a materialization and the anchor
/// occurrence it references.
pub(crate) const MAX_ANCHOR_REFERENCE_DISTANCE: u32 = 4096;
/// Maximum decoded instructions from a `MOVW` through its register
/// consistent `MOVT`, in one basic block.
pub(crate) const MAX_MOVW_MOVT_SPAN_INSTRUCTIONS: usize = 32;
/// Window before a reference that is enumerated for recognized
/// prologues.
pub(crate) const PROLOGUE_WINDOW_BYTES: u32 = 256;
/// Address span the entry-rooted local CFG may decode.
pub(crate) const CFG_WINDOW_BYTES: u32 = 512;
/// Instruction budget the entry-rooted local CFG may decode.
pub(crate) const CFG_MAX_INSTRUCTIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskIsa {
    Arm,
    Thumb,
}

impl TaskIsa {
    #[allow(dead_code)] // entry validation consumes this in the table stage
    pub(crate) const fn decode_isa(self) -> crate::execution_ranges::DecodeIsa {
        match self {
            TaskIsa::Arm => crate::execution_ranges::DecodeIsa::Arm,
            TaskIsa::Thumb => crate::execution_ranges::DecodeIsa::Thumb,
        }
    }
}

impl fmt::Display for TaskIsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TaskIsa::Arm => "arm",
            TaskIsa::Thumb => "thumb",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // later stages construct every variant; Task 4 raises resource and runtime errors
pub(crate) enum PalTaskError {
    Malformed {
        initializer: u32,
        context: String,
    },
    Ambiguous {
        candidates: Vec<(u32, u32)>,
    },
    Decode {
        pc: u32,
        isa: TaskIsa,
        reason: String,
    },
    Runtime {
        address: u32,
        size: u32,
        reason: String,
    },
    ResourceLimit {
        what: &'static str,
        actual: u64,
        limit: u64,
    },
    Artifact(String),
}

impl fmt::Display for PalTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PalTaskError::Malformed {
                initializer,
                context,
            } => {
                write!(
                    f,
                    "malformed PAL candidate at {initializer:#010x}: {context}"
                )
            }
            PalTaskError::Ambiguous { candidates } => {
                write!(f, "ambiguous PAL candidates:")?;
                for (initializer, slot_base) in candidates {
                    write!(
                        f,
                        " initializer {initializer:#010x} slot base {slot_base:#010x}"
                    )?;
                }
                Ok(())
            }
            PalTaskError::Decode { pc, isa, reason } => {
                write!(f, "PAL decode failed at {pc:#010x} ({isa}): {reason}")
            }
            PalTaskError::Runtime {
                address,
                size,
                reason,
            } => {
                write!(
                    f,
                    "PAL runtime range {address:#010x}+{size:#x} is unusable: {reason}"
                )
            }
            PalTaskError::ResourceLimit {
                what,
                actual,
                limit,
            } => {
                write!(f, "PAL {what} count {actual} exceeds the limit {limit}")
            }
            PalTaskError::Artifact(reason) => write!(f, "PAL artifact error: {reason}"),
        }
    }
}

impl std::error::Error for PalTaskError {}

impl From<PalTaskError> for Error {
    fn from(error: PalTaskError) -> Self {
        Error::BadPalTasks(error.to_string())
    }
}

/// How one instruction materializes the anchor address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorReferenceKind {
    /// `ADR`-family PC-relative address materialization.
    Adr,
    /// PC-relative literal load whose pool word equals the anchor.
    Literal,
    /// Register-consistent `MOVW`/`MOVT` construction in one basic block.
    MovwMovt,
}

/// One semantic anchor reference: the instruction that materializes an
/// anchor address into a register. `definitions` is the concrete
/// definition chain (the materialization instruction itself, plus the
/// `MOVT` for a `MOVW`/`MOVT` pair); its first entry is the reaching
/// fact's root definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorReference {
    pub anchor: u32,
    pub kind: AnchorReferenceKind,
    pub pc: u32,
    pub definitions: Vec<u32>,
    pub register: Register,
}

/// One anchor reference that survived unique-prologue root selection and
/// bounded CFG closure, together with its entry-rooted local CFG.
#[derive(Debug, Clone)]
#[allow(dead_code)] // storage provenance is consumed by the artifact stage
pub(crate) struct AnchorCfgCandidate {
    pub anchor: u32,
    pub anchor_storage: Vec<StorageSpan>,
    pub reference: AnchorReference,
    pub initializer: u32,
    pub cfg: cfg::LocalCfg,
}
