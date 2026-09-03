// Startup-metadata discovery: closed domain types, named limits, and
// the crate boundary. Seed search and proofs live in `discover`;
// publication lives in `artifact`.

use crate::arm32::SystemDirection;
use crate::error::Error;
use crate::execution_ranges::{
    DecodeIsa, ExecutionProjection, FunctionOwner, TaggedExecutionRecord,
};
use crate::runtime_image::RuntimeImage;
use std::fmt;
use std::path::Path;

mod artifact;
mod discover;

pub(crate) use artifact::{
    StartupArtifactContext, ValidatedStartup, clear_image, clear_materialized, materialize,
    materialize_image, read_bytes,
};
pub(crate) use discover::discover;

pub(crate) const SEED_WARM_BOOT: &[u8] = b"Invalid warm boot";
pub(crate) const SEED_STACK_GUARD: &[u8] = b"Check a function";
pub(crate) const SEED_RVCT: &[u8] = b"ARM RVCT";
pub(crate) const SEED_SHANNON_OS: &[u8] = b"_ShannonOS_";
pub(crate) const MAX_SEED_OCCURRENCES: usize = 1;
pub(crate) const MAX_CSTRING_BYTES: usize = 128;
pub(crate) const MAX_SEED_REFS: usize = 64;
pub(crate) const MAX_APPLICATIONS: usize = 2;
pub(crate) const MAX_PRIVILEGED_OPS: usize = 65_536;
pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_CALLGRAPH_FUNCTIONS: usize = 4096;
pub(crate) const MAX_CALLGRAPH_DEPTH: usize = 64;
pub(crate) const MAX_SYMBOL_LEAF_BYTES: usize = 2000;
pub(crate) const FORMAT: &str = "pixel-modem-extractor-startup-metadata-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRole {
    HardwareInit,
    StackGuard,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Section<T> {
    Absent,
    Present(T),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HardwareInit {
    pub entry: u32,
    pub isa: DecodeIsa,
    pub owner: FunctionOwner,
    pub execution_blake3: [u8; 32],
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StackGuard {
    pub entry: u32,
    pub isa: DecodeIsa,
    pub owner: FunctionOwner,
    pub execution_blake3: [u8; 32],
    pub non_return: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompilerMeta {
    pub format_address: u32,
    pub format_len: u32,
    pub format_blake3: [u8; 32],
    pub callsite_pc: u32,
    pub isa: DecodeIsa,
    pub operands: Vec<u32>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivilegedClass {
    Midr,
    Features,
    Sctlr,
    Ttbr,
    Ttbcr,
    Dacr,
    Fault,
    CacheTlb,
    Pmu,
    Vbar,
    ContextId,
    CpsrSpsr,
    Unclassified,
}

impl PrivilegedClass {
    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::Midr => "midr",
            Self::Features => "features",
            Self::Sctlr => "sctlr",
            Self::Ttbr => "ttbr",
            Self::Ttbcr => "ttbcr",
            Self::Dacr => "dacr",
            Self::Fault => "fault",
            Self::CacheTlb => "cache_tlb",
            Self::Pmu => "pmu",
            Self::Vbar => "vbar",
            Self::ContextId => "context_id",
            Self::CpsrSpsr => "cpsr_spsr",
            Self::Unclassified => "unclassified",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivilegedOp {
    pub pc: u32,
    pub isa: DecodeIsa,
    pub entry: u32,
    pub owner: FunctionOwner,
    pub execution_blake3: [u8; 32],
    pub direction: SystemDirection,
    pub class: PrivilegedClass,
    pub coprocessor: Option<u8>,
    pub opcode1: Option<u8>,
    pub crn: Option<u8>,
    pub crm: Option<u8>,
    pub opcode2: Option<u8>,
    pub register: Option<u8>,
    pub immediate: Option<u32>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupApplication {
    pub role: StartupRole,
    pub entry: u32,
    pub isa: DecodeIsa,
    pub desired_primary: &'static str,
    pub role_label: &'static str,
    pub set_no_return: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartupPlan {
    pub image_label: String,
    pub toc_name: String,
    pub image_base: u32,
    pub image_size: u32,
    pub hardware_init: Section<HardwareInit>,
    pub stack_guard: Section<StackGuard>,
    pub compiler: Section<CompilerMeta>,
    pub privileged_ops: Vec<PrivilegedOp>,
    pub applications: Vec<StartupApplication>,
}

impl StartupRole {
    pub(crate) const fn as_wire(self) -> &'static str {
        match self {
            Self::HardwareInit => "hardware_init",
            Self::StackGuard => "stack_protection_failure",
        }
    }

    pub(crate) const fn desired_primary(self) -> &'static str {
        match self {
            Self::HardwareInit => "hw_Init",
            Self::StackGuard => "StackProtectionFailure",
        }
    }

    pub(crate) const fn role_label(self) -> &'static str {
        match self {
            Self::HardwareInit => "startup_hardware_init",
            Self::StackGuard => "startup_stack_protection_failure",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartupMetadataError {
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

impl fmt::Display for StartupMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { context } => {
                write!(f, "malformed startup metadata: {context}")
            }
            Self::Ambiguous { values } => {
                write!(f, "ambiguous startup-metadata values:")?;
                for value in values {
                    write!(f, " {value:#010x}")?;
                }
                Ok(())
            }
            Self::Decode { pc, isa, reason } => {
                let isa = match isa {
                    DecodeIsa::Arm => "arm",
                    DecodeIsa::Thumb => "thumb",
                };
                write!(
                    f,
                    "startup-metadata decode failed at {pc:#010x} ({isa}): {reason}"
                )
            }
            Self::Runtime {
                address,
                size,
                reason,
            } => write!(
                f,
                "startup-metadata runtime range {address:#010x}+{size:#x} is unusable: {reason}"
            ),
            Self::ResourceLimit {
                what,
                actual,
                limit,
            } => write!(
                f,
                "startup-metadata {what} count {actual} exceeds the limit {limit}"
            ),
            Self::Artifact(reason) => write!(f, "startup-metadata artifact error: {reason}"),
        }
    }
}

impl std::error::Error for StartupMetadataError {}

impl From<StartupMetadataError> for Error {
    fn from(error: StartupMetadataError) -> Self {
        Error::BadStartupMetadata(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCorpusSeeds {
    pub warm_boot: bool,
    pub stack_guard: bool,
    pub rvct: bool,
    pub shannon_os: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCorpusArtifact {
    pub hardware_init_status: &'static str,
    pub stack_guard_status: &'static str,
    pub compiler_status: &'static str,
    pub privileged_ops: usize,
    pub named_roots: usize,
    pub no_return_roots: usize,
    pub identity: String,
    pub manifest_blake3: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupCorpusReport {
    pub seeds: StartupCorpusSeeds,
    pub privileged_ops: usize,
    pub artifact: Option<StartupCorpusArtifact>,
}

pub fn generate_corpus(
    raw: &[u8],
    image_base: u32,
    label: &str,
    toc_name: &str,
    inventories_dir: Option<&Path>,
    out: &Path,
) -> crate::error::Result<StartupCorpusReport> {
    let scatter_plan = crate::scatter::discover(raw, image_base)
        .map_err(|error| Error::BadScatter(error.to_string()))?;
    let scatter_blake3 = if let Some(plan) = scatter_plan.as_ref() {
        let materialized = crate::scatter::materialize(plan, raw, label, out)?;
        let bytes = std::fs::read(out.join(&materialized.relative_path))?;
        Some(*blake3::hash(&bytes).as_bytes())
    } else {
        None
    };
    let runtime = RuntimeImage::from_plan(raw, image_base, scatter_plan.as_ref())?;
    let seeds = StartupCorpusSeeds {
        warm_boot: discover::find_unique_seed(&runtime, SEED_WARM_BOOT)?.is_some(),
        stack_guard: discover::find_unique_seed(&runtime, SEED_STACK_GUARD)?.is_some(),
        rvct: discover::find_unique_seed(&runtime, SEED_RVCT)?.is_some(),
        shannon_os: discover::find_unique_seed(&runtime, SEED_SHANNON_OS)?.is_some(),
    };
    let image_blake3 = *blake3::hash(raw).as_bytes();
    let exception = crate::exception_roots::discover(&runtime, label, toc_name)?;
    let reset = exception.as_ref().and_then(reset_from_plan);
    let exception_identity = if inventories_dir.is_some() {
        match exception.as_ref() {
            Some(plan) => Some(
                crate::exception_roots::materialize(
                    plan,
                    crate::exception_roots::ExceptionArtifactContext {
                        label,
                        toc_name,
                        image_blake3,
                        scatter_load_map_blake3: scatter_blake3,
                    },
                    out,
                )?
                .identity,
            ),
            None => None,
        }
    } else {
        None
    };
    let inventories = match inventories_dir {
        Some(dir) => load_inventories(dir, &runtime)?,
        None => LoadedInventories::empty(),
    };
    let plan = discover(&runtime, label, toc_name, &inventories.records, reset)?;
    let privileged_ops = plan.privileged_ops.len();
    let artifact = if inventories_dir.is_some() {
        let (image_base, image_size) = runtime.image_bounds();
        let context = StartupArtifactContext {
            label,
            toc_name,
            image_base,
            image_size,
            image_blake3,
            scatter_blake3,
            scatter_entries: &[],
            functions_blake3: inventories.functions_blake3,
            thumb_functions_blake3: inventories.thumb_functions_blake3,
            exception_identity: exception_identity.as_deref(),
            tool_version: env!("CARGO_PKG_VERSION"),
        };
        let materialized = materialize(&plan, context, out)?;
        Some(StartupCorpusArtifact {
            hardware_init_status: section_status(&plan.hardware_init),
            stack_guard_status: section_status(&plan.stack_guard),
            compiler_status: section_status(&plan.compiler),
            privileged_ops,
            named_roots: materialized.named_roots,
            no_return_roots: materialized.no_return_roots,
            identity: materialized.identity,
            manifest_blake3: materialized.blake3,
            relative_path: materialized.relative_path,
        })
    } else {
        None
    };
    Ok(StartupCorpusReport {
        seeds,
        privileged_ops,
        artifact,
    })
}

fn reset_from_plan(plan: &crate::exception_roots::ExceptionRootPlan) -> Option<(u32, DecodeIsa)> {
    plan.initial_table
        .slots
        .iter()
        .find(|slot| slot.role == crate::exception_roots::ExceptionRole::Reset)
        .map(|slot| (slot.entry, slot.isa.decode_isa()))
}

struct LoadedInventories {
    records: Vec<TaggedExecutionRecord>,
    functions_blake3: [u8; 32],
    thumb_functions_blake3: Option<[u8; 32]>,
}

impl LoadedInventories {
    fn empty() -> Self {
        Self {
            records: Vec::new(),
            functions_blake3: [0u8; 32],
            thumb_functions_blake3: None,
        }
    }
}

fn load_inventories(
    dir: &Path,
    runtime: &RuntimeImage<'_>,
) -> crate::error::Result<LoadedInventories> {
    let functions_path = dir.join("functions.json");
    let functions_bytes = std::fs::read(&functions_path)?;
    let functions_blake3 = *blake3::hash(&functions_bytes).as_bytes();
    let streamed = crate::execution_ranges::read_ghidra_inventory_bytes(&functions_bytes, runtime)?;
    let mut records = streamed.inventory.records;
    let thumb_path = dir.join("thumb_functions.json");
    let thumb_functions_blake3 = match std::fs::read(&thumb_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
        Ok(thumb_bytes) => {
            let digest = *blake3::hash(&thumb_bytes).as_bytes();
            let owned = crate::thumb_analysis::read_thumb_functions_bytes(
                &thumb_bytes,
                runtime,
                "thumb_functions.json",
            )?;
            for record in owned {
                let Some(identity) = record.execution else {
                    continue;
                };
                records.push(TaggedExecutionRecord {
                    owner: record.owner,
                    entry: identity.entry,
                    projection: ExecutionProjection::Accepted(identity.decode_ranges),
                });
            }
            Some(digest)
        }
    };
    Ok(LoadedInventories {
        records,
        functions_blake3,
        thumb_functions_blake3,
    })
}

fn section_status<T>(section: &Section<T>) -> &'static str {
    match section {
        Section::Absent => "absent",
        Section::Present(_) => "present",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic_cfg::CfgLimits;

    #[test]
    fn closed_domain_wire_names_and_limits_are_total() {
        assert_eq!(StartupRole::HardwareInit.as_wire(), "hardware_init");
        assert_eq!(
            StartupRole::StackGuard.as_wire(),
            "stack_protection_failure"
        );
        assert_eq!(StartupRole::HardwareInit.desired_primary(), "hw_Init");
        assert_eq!(
            StartupRole::StackGuard.desired_primary(),
            "StackProtectionFailure"
        );
        assert_eq!(
            StartupRole::HardwareInit.role_label(),
            "startup_hardware_init"
        );
        assert_eq!(
            StartupRole::StackGuard.role_label(),
            "startup_stack_protection_failure"
        );
        assert_eq!(SEED_WARM_BOOT, b"Invalid warm boot");
        assert_eq!(SEED_STACK_GUARD, b"Check a function");
        assert_eq!(SEED_RVCT, b"ARM RVCT");
        assert_eq!(SEED_SHANNON_OS, b"_ShannonOS_");
        assert_eq!(MAX_SEED_OCCURRENCES, 1);
        assert_eq!(MAX_CSTRING_BYTES, 128);
        assert_eq!(MAX_SEED_REFS, 64);
        assert_eq!(MAX_APPLICATIONS, 2);
        assert_eq!(MAX_PRIVILEGED_OPS, 65_536);
        assert_eq!(MAX_MANIFEST_BYTES, 1024 * 1024);
        assert_eq!(MAX_CALLGRAPH_FUNCTIONS, 4096);
        assert_eq!(MAX_CALLGRAPH_DEPTH, 64);
        let limits = CfgLimits::startup_metadata();
        assert_eq!(limits.max_charged_bytes, 64 * 1024);
        assert_eq!(limits.max_instructions, 32_768);
        assert_eq!(limits.max_blocks, 4_096);
    }
}
