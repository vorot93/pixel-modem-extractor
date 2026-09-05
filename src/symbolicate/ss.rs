#![allow(dead_code)]

use crate::execution_ranges::DecodeIsa;
use crate::pal_messages::PalMessageError;
use std::collections::BTreeMap;
use std::fmt;

pub(crate) const SEED: &[u8] = b"ss_DecodeGmmFacilityMsg";
pub(crate) const MAX_CSTRING_BYTES: usize = 128;
pub(crate) const MAX_SS_CALLSITES: usize = 4096;
pub(crate) const MAX_IDENT_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SsNameError {
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
}

impl fmt::Display for SsNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { context } => write!(f, "ss names malformed: {context}"),
            Self::Ambiguous { values } => write!(f, "ss names ambiguous: {values:?}"),
            Self::Decode { pc, isa, reason } => {
                write!(f, "ss names decode {isa:?} {pc:#010x}: {reason}")
            }
            Self::Runtime {
                address,
                size,
                reason,
            } => write!(f, "ss names runtime {address:#010x}+{size:#x}: {reason}"),
            Self::ResourceLimit {
                what,
                actual,
                limit,
            } => write!(f, "ss names {what} {actual} exceeds {limit}"),
        }
    }
}

pub(crate) fn map_pal_error(error: PalMessageError) -> SsNameError {
    match error {
        PalMessageError::Malformed { context } => SsNameError::Malformed { context },
        PalMessageError::Ambiguous { values } => SsNameError::Ambiguous { values },
        PalMessageError::Decode { pc, isa, reason } => SsNameError::Decode { pc, isa, reason },
        PalMessageError::Runtime {
            address,
            size,
            reason,
        } => SsNameError::Runtime {
            address,
            size,
            reason,
        },
        PalMessageError::ResourceLimit {
            what,
            actual,
            limit,
        } => SsNameError::ResourceLimit {
            what,
            actual,
            limit,
        },
        PalMessageError::Artifact(context) => SsNameError::Malformed { context },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsContainer {
    pub entry: u32,
    pub isa: DecodeIsa,
    pub ranges: Vec<(u32, u32)>,
    pub ghidra: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsPlan {
    pub helper_entry: u32,
    pub helper_isa: DecodeIsa,
    pub callsites: usize,
    pub names: BTreeMap<(u32, DecodeIsa), String>,
    pub conflicts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SsOutcome {
    Absent,
    Present(SsPlan),
    Failed(SsNameError),
}
