// ARM exception-vector discovery: closed domain types, strict limits, and
// the crate boundary. Table classification, reset-side VBAR proof, and one
// global root/application allocation live in `discover`.

use crate::error::Error;
use crate::execution_ranges::DecodeIsa;
use crate::runtime_image::StorageSpan;
use crate::semantic_cfg::Handoff;
use std::fmt;

#[allow(dead_code)]
mod artifact;
mod discover;

#[allow(unused_imports)]
pub(crate) use artifact::{
    ExceptionArtifactContext, MaterializedExceptionRoots, ValidatedExceptionRoots,
    clear_materialized, materialize, read, read_bytes, read_bytes_with_identity,
    read_with_identity,
};
#[allow(unused_imports)]
pub(crate) use discover::discover;

pub(crate) const VECTOR_SLOTS: usize = 8;
pub(crate) const MAX_TABLES: usize = 2;
pub(crate) const MAX_ROOTS: usize = 16;
pub(crate) const MAX_VBAR_WRITES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ExceptionRole {
    Reset,
    UndefinedInstruction,
    SupervisorCall,
    PrefetchAbort,
    DataAbort,
    Reserved,
    Irq,
    Fiq,
}

impl ExceptionRole {
    pub(crate) const ALL: [Self; VECTOR_SLOTS] = [
        Self::Reset,
        Self::UndefinedInstruction,
        Self::SupervisorCall,
        Self::PrefetchAbort,
        Self::DataAbort,
        Self::Reserved,
        Self::Irq,
        Self::Fiq,
    ];

    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::Reset => "reset",
            Self::UndefinedInstruction => "undefined_instruction",
            Self::SupervisorCall => "supervisor_call",
            Self::PrefetchAbort => "prefetch_abort",
            Self::DataAbort => "data_abort",
            Self::Reserved => "reserved",
            Self::Irq => "irq",
            Self::Fiq => "fiq",
        }
    }

    pub(crate) const fn preferred_primary(self) -> &'static str {
        match self {
            Self::Reset => "Reset",
            Self::UndefinedInstruction => "UndefinedInstruction",
            Self::SupervisorCall => "SupervisorCall",
            Self::PrefetchAbort => "PrefetchAbort",
            Self::DataAbort => "DataAbort",
            Self::Reserved => "Reserved",
            Self::Irq => "IRQ",
            Self::Fiq => "FIQ",
        }
    }

    pub(crate) const fn slot_index(self) -> usize {
        match self {
            Self::Reset => 0,
            Self::UndefinedInstruction => 1,
            Self::SupervisorCall => 2,
            Self::PrefetchAbort => 3,
            Self::DataAbort => 4,
            Self::Reserved => 5,
            Self::Irq => 6,
            Self::Fiq => 7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RootIsa {
    Arm,
    Thumb,
}

impl RootIsa {
    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::Arm => "arm",
            Self::Thumb => "thumb",
        }
    }

    pub(crate) const fn decode_isa(self) -> DecodeIsa {
        match self {
            Self::Arm => DecodeIsa::Arm,
            Self::Thumb => DecodeIsa::Thumb,
        }
    }

    pub(crate) const fn from_decode_isa(isa: DecodeIsa) -> Self {
        match isa {
            DecodeIsa::Arm => Self::Arm,
            DecodeIsa::Thumb => Self::Thumb,
        }
    }
}

impl fmt::Display for RootIsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotForm {
    DirectBranch,
    LiteralLoad { literal_address: u32 },
}

impl SlotForm {
    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::DirectBranch => "direct_branch",
            Self::LiteralLoad { .. } => "literal_load",
        }
    }

    pub(crate) const fn is_literal_load(self) -> bool {
        matches!(self, Self::LiteralLoad { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum VectorTableKind {
    Initial,
    Relocated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VectorSlot {
    pub role: ExceptionRole,
    pub address: u32,
    pub form: SlotForm,
    pub slot_blake3: [u8; 32],
    pub literal_blake3: Option<[u8; 32]>,
    pub literal_storage: Vec<StorageSpan>,
    pub entry: u32,
    pub isa: RootIsa,
    pub instruction_size: u8,
    pub instruction_blake3: [u8; 32],
    pub instruction_storage: Vec<StorageSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VectorTable {
    pub kind: VectorTableKind,
    pub address: u32,
    pub blake3: [u8; 32],
    pub storage: Vec<StorageSpan>,
    pub slots: Vec<VectorSlot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExceptionClaim {
    pub table_kind: VectorTableKind,
    pub table_address: u32,
    pub slot_address: u32,
    pub role: ExceptionRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRoot {
    pub entry: u32,
    pub isa: RootIsa,
    pub instruction_size: u8,
    pub instruction_blake3: [u8; 32],
    pub storage: Vec<StorageSpan>,
    pub claims: Vec<ExceptionClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionApplication {
    pub entry: u32,
    pub isa: RootIsa,
    pub desired_primary: Option<String>,
    pub claims: Vec<ExceptionClaim>,
    pub role_labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VbarWriteEvidence {
    pub pc: u32,
    pub isa: RootIsa,
    pub source_register: u8,
    pub conditional: bool,
    pub exact_value: Option<u32>,
    pub definitions: Vec<u32>,
    pub dominates_handoffs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelocationEvidence {
    ConfirmedInitial {
        selected: VbarWriteEvidence,
        observations: Vec<VbarWriteEvidence>,
    },
    Relocated {
        selected: VbarWriteEvidence,
        table_address: u32,
        observations: Vec<VbarWriteEvidence>,
    },
    Unresolved {
        observations: Vec<VbarWriteEvidence>,
    },
    NotObserved,
    AnalysisIncomplete {
        observations: Vec<VbarWriteEvidence>,
        handoffs: Vec<Handoff>,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExceptionRootPlan {
    pub image_label: String,
    pub toc_name: String,
    pub image_base: u32,
    pub image_size: u32,
    pub initial_table: VectorTable,
    pub relocation: RelocationEvidence,
    pub tables: Vec<VectorTable>,
    pub roots: Vec<ExceptionRoot>,
    pub applications: Vec<ExceptionApplication>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExceptionRootError {
    Malformed {
        table: u32,
        context: String,
    },
    Ambiguous {
        values: Vec<u32>,
    },
    Decode {
        pc: u32,
        isa: RootIsa,
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
    #[allow(dead_code)]
    Artifact(String),
}

impl fmt::Display for ExceptionRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { table, context } => {
                write!(f, "malformed exception table at {table:#010x}: {context}")
            }
            Self::Ambiguous { values } => {
                write!(f, "ambiguous exception-root values:")?;
                for value in values {
                    write!(f, " {value:#010x}")?;
                }
                Ok(())
            }
            Self::Decode { pc, isa, reason } => {
                write!(
                    f,
                    "exception-root decode failed at {pc:#010x} ({isa}): {reason}"
                )
            }
            Self::Runtime {
                address,
                size,
                reason,
            } => write!(
                f,
                "exception-root runtime range {address:#010x}+{size:#x} is unusable: {reason}"
            ),
            Self::ResourceLimit {
                what,
                actual,
                limit,
            } => write!(
                f,
                "exception-root {what} count {actual} exceeds the limit {limit}"
            ),
            Self::Artifact(reason) => write!(f, "exception-root artifact error: {reason}"),
        }
    }
}

impl std::error::Error for ExceptionRootError {}

impl From<ExceptionRootError> for Error {
    fn from(error: ExceptionRootError) -> Self {
        Error::BadExceptionRoots(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{ExceptionRole, RootIsa, SlotForm};
    use crate::execution_ranges::DecodeIsa;

    #[test]
    fn closed_domain_wire_names_and_conversions_are_total() {
        assert_eq!(
            ExceptionRole::ALL.map(ExceptionRole::as_wire),
            [
                "reset",
                "undefined_instruction",
                "supervisor_call",
                "prefetch_abort",
                "data_abort",
                "reserved",
                "irq",
                "fiq",
            ]
        );
        assert_eq!(
            ExceptionRole::ALL.map(ExceptionRole::slot_index),
            [0, 1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(RootIsa::Arm.as_wire(), "arm");
        assert_eq!(RootIsa::Thumb.as_wire(), "thumb");
        assert_eq!(RootIsa::from_decode_isa(DecodeIsa::Arm), RootIsa::Arm);
        assert_eq!(RootIsa::from_decode_isa(DecodeIsa::Thumb), RootIsa::Thumb);
        assert_eq!(RootIsa::Arm.decode_isa(), DecodeIsa::Arm);
        assert_eq!(RootIsa::Thumb.decode_isa(), DecodeIsa::Thumb);

        let direct = SlotForm::DirectBranch;
        let literal = SlotForm::LiteralLoad {
            literal_address: 0x4001_0040,
        };
        assert_eq!(direct.as_wire(), "direct_branch");
        assert_eq!(literal.as_wire(), "literal_load");
        assert!(!direct.is_literal_load());
        assert!(literal.is_literal_load());
    }
}
