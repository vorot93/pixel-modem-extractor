// PAL messaging discovery: unique seed, one initializer proof, and a
// raw hashed descriptor inventory. Evidence-only this increment.
#![allow(dead_code, unused_imports)]

use crate::error::Error;
use crate::execution_ranges::DecodeIsa;
use std::fmt;

mod artifact;
mod discover;
mod table;

pub(crate) use artifact::{
    MaterializedMessages, MessageArtifactContext, clear_materialized, materialize, read_bytes,
};
pub(crate) use discover::discover;

pub(crate) const SEED: &[u8] = b"PAL_MSG_MAX_ENTITY_COUNT";
pub(crate) const MAX_CSTRING_BYTES: usize = 128;
pub(crate) const MAX_TABLE_CAPACITY: u32 = 4096;
pub(crate) const MAX_TABLE_STRIDE: u32 = 64 * 1024;
pub(crate) const MAX_CANDIDATE_VALIDATION_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub(crate) const FORMAT: &str = "pixel-modem-extractor-pal-messages-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PalMessageError {
    Malformed {
        context: String,
    },
    Ambiguous {
        values: Vec<u32>,
    },
    Decode {
        pc: u32,
        isa: DecodeIsa,
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

impl fmt::Display for PalMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PalMessageError::Malformed { context } => {
                write!(f, "malformed PAL messages: {context}")
            }
            PalMessageError::Ambiguous { values } => {
                write!(f, "ambiguous PAL messages values:")?;
                for value in values {
                    write!(f, " {value:#010x}")?;
                }
                Ok(())
            }
            PalMessageError::Decode { pc, isa, reason } => {
                write!(
                    f,
                    "PAL messages decode failed at {pc:#010x} ({isa:?}): {reason}"
                )
            }
            PalMessageError::Runtime {
                address,
                size,
                reason,
            } => write!(
                f,
                "PAL messages runtime range {address:#010x}+{size:#x} is unusable: {reason}"
            ),
            PalMessageError::ResourceLimit {
                what,
                actual,
                limit,
            } => write!(
                f,
                "PAL messages {what} count {actual} exceeds the limit {limit}"
            ),
            PalMessageError::Artifact(reason) => write!(f, "PAL messages artifact error: {reason}"),
        }
    }
}

impl std::error::Error for PalMessageError {}

impl From<PalMessageError> for Error {
    fn from(error: PalMessageError) -> Self {
        Error::BadPalMessages(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessagePlan {
    pub image_label: String,
    pub image_base: u32,
    pub image_size: u32,
    pub setup_entry: u32,
    pub setup_isa: DecodeIsa,
    pub table_base: u32,
    pub table_end: u32,
    pub stride: u32,
    pub capacity: u32,
    pub slots: Vec<RawSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawSlot {
    pub index: u32,
    pub address: u32,
    pub size: u32,
    pub blake3: [u8; 32],
}
