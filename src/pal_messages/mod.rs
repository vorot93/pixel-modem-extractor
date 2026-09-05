// PAL messaging discovery: unique seed, one initializer proof, and a
// raw hashed descriptor inventory. Evidence-only this increment.

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
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use discover::{SemanticRef, find_unique_seed, semantic_refs};

pub(crate) const SEED: &[u8] = b"PAL_MSG_MAX_ENTITY_COUNT";
pub(crate) const MAX_CSTRING_BYTES: usize = 128;
pub(crate) const MAX_TABLE_CAPACITY: u32 = 4096;
pub(crate) const MAX_TABLE_STRIDE: u32 = 64 * 1024;
pub(crate) const MAX_CANDIDATE_VALIDATION_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_MOVW_MOVT_SPAN_INSTRUCTIONS: usize = 32;
pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub(crate) const FORMAT: &str = "pixel-modem-extractor-pal-messages-v1";

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) const BASE: u32 = 0x4001_0000;

    pub(crate) fn craft_discoverable_main_image() -> Vec<u8> {
        const A32_ADD_R0_PC_18: [u8; 4] = [0x18, 0x00, 0x8f, 0xe2];
        const A32_MOV_R1_4: [u8; 4] = [0x04, 0x10, 0xa0, 0xe3];
        const A32_MOV_R3_16: [u8; 4] = [0x10, 0x30, 0xa0, 0xe3];
        const A32_STR_R1_R2: [u8; 4] = [0x00, 0x10, 0x82, 0xe5];
        const A32_BX_LR: [u8; 4] = [0x1e, 0xff, 0x2f, 0xe1];
        fn a32_movw(rd: u8, imm16: u16) -> [u8; 4] {
            let imm4 = u32::from(imm16) >> 12;
            let imm12 = u32::from(imm16) & 0xfff;
            (0xe300_0000 | (imm4 << 16) | (u32::from(rd) << 12) | imm12).to_le_bytes()
        }
        fn a32_movt(rd: u8, imm16: u16) -> [u8; 4] {
            let imm4 = u32::from(imm16) >> 12;
            let imm12 = u32::from(imm16) & 0xfff;
            (0xe340_0000 | (imm4 << 16) | (u32::from(rd) << 12) | imm12).to_le_bytes()
        }
        let mut image = vec![0u8; 0x100];
        let table_base = BASE + 0x80;
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_18);
        image[4..8].copy_from_slice(&A32_MOV_R1_4);
        image[8..12].copy_from_slice(&A32_MOV_R3_16);
        image[12..16].copy_from_slice(&a32_movw(2, (table_base & 0xffff) as u16));
        image[16..20].copy_from_slice(&a32_movt(2, (table_base >> 16) as u16));
        image[20..24].copy_from_slice(&A32_STR_R1_R2);
        image[24..28].copy_from_slice(&A32_BX_LR);
        image[0x20..0x20 + super::SEED.len()].copy_from_slice(super::SEED);
        image[0x20 + super::SEED.len()] = 0;
        image
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PalMessageError {
    Malformed {
        context: String,
    },
    Ambiguous {
        values: Vec<u32>,
    },
    #[allow(dead_code)]
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
