// PAL task initializer discovery: shared types, named limits, and the
// structured domain error. The bounded anchor sweep and unique-prologue
// root selection live in `discover`; shared entry-rooted traversal lives
// in `semantic_cfg`, while PAL's definition/flag facts and the graph queries
// used by the induction proofs live behind the facade in `cfg`. The
// counting-loop, dual-exit, suffix, and
// slot-base proofs assemble the initializer candidates defined here;
// `table` validates their slots and allocates deterministic
// applications, `discover` returns the final plan boundary, and
// `artifact` publishes and strictly revalidates the canonical
// authenticated manifest of one complete plan.

use crate::arm32::Register;
use crate::error::Error;
use crate::runtime_image::{RuntimeImage, StorageSpan};
use crate::semantic_cfg::CfgLimits;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) mod artifact;
mod cfg;
mod discover;
mod table;

// The generation and Ghidra consumers import this surface.
pub(crate) use artifact::{
    MaterializedTaskMap, TaskArtifactContext, ValidatedTaskArtifact, clear_materialized,
    materialize, read_bytes,
};

/// The shared PAL fixture machinery (raw/scatter image construction and
/// the two-pass label-resolving Thumb assembler), reachable crate-wide
/// under test so the decompile generation tests can build discoverable
/// MAIN images.
#[cfg(test)]
pub(crate) use discover::test_support;

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

/// Discover every plausible initializer candidate: the counting-loop,
/// dual-exit, suffix, and slot-base proofs over the anchor CFG
/// candidates. Topology misses are skipped; competing CFG roots stay
/// separate candidates; named resource limits and runtime failures are
/// typed errors.
pub(super) fn discover_initializer_candidates(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Vec<InitializerCandidate>, PalTaskError> {
    let mut budget = CandidateBudget::default();
    discover::discover_initializer_candidates_bounded(image, label, &mut budget)
}

/// The complete discovery boundary: prove initializer candidates,
/// table-validate each against one shared non-refundable budget, and
/// return the single complete plan. `Ok(None)` means no candidate
/// crossed the first-slot plausibility threshold; several complete
/// survivors are the typed ambiguity; a plausible candidate that then
/// fails is the contextual malformed error even when a sibling is
/// valid.
pub(crate) fn discover(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Option<TaskPlan>, PalTaskError> {
    discover::discover(image, label)
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

/// Shared semantic-CFG limits that preserve PAL's established 512-byte / 256
/// instruction local proof. A block always starts at an instruction, so the
/// instruction cap is also a behavior-neutral block ceiling.
pub(super) const fn semantic_cfg_limits() -> CfgLimits {
    CfgLimits {
        max_charged_bytes: CFG_WINDOW_BYTES as u64,
        max_instructions: CFG_MAX_INSTRUCTIONS,
        max_blocks: CFG_MAX_INSTRUCTIONS,
    }
}
/// Unique semantic candidate tuples that may reach table validation.
pub(crate) const MAX_CANDIDATE_TUPLES: usize = 64;
/// One non-refundable budget shared by every slot byte hashed, bounded
/// name byte read, and entry instruction byte decoded across all
/// candidate tuples: charged bytes never return, even when the
/// candidate they were charged for is later rejected.
pub(crate) const MAX_CANDIDATE_VALIDATION_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum decoded instructions in one side-effect-free slot-base leaf.
pub(crate) const MAX_SLOT_LEAF_INSTRUCTIONS: usize = 16;
/// The `pal-task-descriptor-v1` projection subtracts this fixed offset
/// from the discovered name field under checked arithmetic.
pub(crate) const DESCRIPTOR_PROJECTION_OFFSET: u32 = 0x24;
/// Maximum decoded table capacity; parsing never reads more slots.
pub(crate) const MAX_TABLE_CAPACITY: u32 = 4096;
/// Maximum decoded slot stride in bytes.
pub(crate) const MAX_TABLE_STRIDE: u32 = 64 * 1024;
/// Maximum task-name length in bytes (the NUL terminator is extra).
pub(crate) const MAX_TASK_NAME_BYTES: usize = 128;
/// Bytes charged per bounded name read: the printable maximum plus the
/// NUL probe.
pub(crate) const TASK_NAME_READ_BYTES: u64 = MAX_TASK_NAME_BYTES as u64 + 1;
/// Bytes charged per entry instruction decode: the four-byte ISA
/// maximum.
pub(crate) const MAX_ENTRY_INSTRUCTION_BYTES: u64 = 4;
/// Ghidra `SymbolUtilities.MAX_SYMBOL_NAME_LENGTH`: every final leaf is
/// bounded to this many ASCII characters.
pub(crate) const MAX_SYMBOL_LEAF_BYTES: usize = 2000;

/// The shared non-refundable candidate-validation budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CandidateBudget {
    charged: u64,
}

impl CandidateBudget {
    /// Charge `bytes` against the budget before performing the work;
    /// exceeding the limit is a typed resource error and never a
    /// silent miss. Charged bytes are never refunded.
    pub(crate) fn charge(
        &mut self,
        bytes: u64,
        what: &'static str,
    ) -> std::result::Result<(), PalTaskError> {
        let Some(total) = self.charged.checked_add(bytes) else {
            return Err(PalTaskError::ResourceLimit {
                what,
                actual: u64::MAX,
                limit: MAX_CANDIDATE_VALIDATION_BYTES,
            });
        };
        if total > MAX_CANDIDATE_VALIDATION_BYTES {
            return Err(PalTaskError::ResourceLimit {
                what,
                actual: total,
                limit: MAX_CANDIDATE_VALIDATION_BYTES,
            });
        }
        self.charged = total;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TaskIsa {
    Arm,
    Thumb,
}

impl TaskIsa {
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

/// One complete anchor proof path: the anchor occurrence, the
/// materialization whose reaching chain carried it into a call
/// argument, and the dominating direct call itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorProofPath {
    pub anchor: u32,
    pub reference: AnchorReference,
    pub call: u32,
}

/// One anchor occurrence with its byte storage provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorProvenance {
    pub address: u32,
    pub storage: Vec<StorageSpan>,
}

/// The capacity guard: a decoded `count >> shift_amount` compared
/// unsigned with `compare_value`, branching to the join exactly when
/// `count >= capacity`; the branch is proven by
/// `(compare_value + 1) << shift_amount == capacity` under checked
/// arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapacityGuard {
    pub start: u32,
    pub compare: u32,
    pub branch: u32,
    pub fallthrough: u32,
    pub shift_amount: u8,
    pub compare_value: u32,
}

/// The complete root-anchored slot-base definition chain: the direct
/// immediate materialization (MOVW root, its MOVT high-half replacement,
/// and any copies that carry the value onward) or the leaf call and its
/// move, exactly as the dataflow preserved it. `definitions` begins at
/// `root`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotDefinition {
    pub root: u32,
    pub definitions: Vec<u32>,
}

/// The complete initializer proof: canonical proof paths, the loop and
/// induction roots, both exits with the shared count global, the
/// capacity guard, the suffix loop, the join, and the derived table
/// geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitializerEvidence {
    pub cfg_entry: u32,
    pub proof_paths: Vec<AnchorProofPath>,
    pub anchors: Vec<AnchorProvenance>,
    pub code_storage: Vec<StorageSpan>,
    pub loop_start: u32,
    pub count_zero_definition: u32,
    pub slot_definition: SlotDefinition,
    pub normal_exit: u32,
    pub capacity_exit: u32,
    pub capacity_guard: CapacityGuard,
    pub suffix_loop: u32,
    pub join: u32,
    pub count_global: u32,
    pub slot_base: u32,
    pub name_offset: u32,
    pub index_offset: u32,
    pub stride: u32,
    pub capacity: u32,
}

impl InitializerEvidence {
    /// Whether two proofs carry the same semantic tuple: identical CFG
    /// entry, loop start, count/slot roots, geometry, count global,
    /// exits, guard, suffix loop, and join. Proof paths and storage
    /// provenance aggregate instead of distinguishing candidates, and
    /// the slot-definition chain follows from the shared CFG root, so
    /// only its root is compared.
    fn same_semantics(&self, other: &Self) -> bool {
        self.cfg_entry == other.cfg_entry
            && self.loop_start == other.loop_start
            && self.count_zero_definition == other.count_zero_definition
            && self.slot_definition.root == other.slot_definition.root
            && self.slot_base == other.slot_base
            && self.name_offset == other.name_offset
            && self.index_offset == other.index_offset
            && self.stride == other.stride
            && self.capacity == other.capacity
            && self.count_global == other.count_global
            && self.normal_exit == other.normal_exit
            && self.capacity_exit == other.capacity_exit
            && self.capacity_guard == other.capacity_guard
            && self.suffix_loop == other.suffix_loop
            && self.join == other.join
    }
}

/// The table geometry the initializer proof derives for slot parsing:
/// slot base, field offsets, stride, and capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskTableGeometry {
    pub slot_base: u32,
    pub name_offset: u32,
    pub index_offset: u32,
    pub stride: u32,
    pub capacity: u32,
}

/// One plausible initializer candidate: the complete proof plus the
/// geometry its table validation consumes.
#[derive(Debug, Clone)]
pub(crate) struct InitializerCandidate {
    pub evidence: InitializerEvidence,
    pub geometry: TaskTableGeometry,
}

/// One complete validated PAL task table plan. Carries the image
/// identity, the initializer proof, the parsed table, every task
/// record, the deterministic applications, and the terminal evidence;
/// no analyzer inventory appears here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskPlan {
    pub image_base: u32,
    pub image_size: u32,
    pub initializer: InitializerEvidence,
    pub table: TaskTable,
    pub tasks: Vec<TaskRecord>,
    pub applications: Vec<TaskApplication>,
    pub terminal: TerminalRecord,
}

/// The validated descriptor-v1 table: geometry plus the derived field
/// offsets and the observed slot count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskTable {
    pub slot_base: u32,
    pub name_offset: u32,
    pub index_offset: u32,
    pub stride: u32,
    pub capacity: u32,
    pub count: u32,
    pub descriptor_projection_offset: u32,
    pub priority_offset: u32,
    pub stack_size_offset: u32,
    pub entry_offset: u32,
    pub callback_offset: u32,
    pub unknown_pointer_offset: u32,
}

/// One parsed nonterminal slot: the exact firmware name separate from
/// the allocated label, the stored pointer separate from the
/// normalized entry, and the evidence hashes with storage provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskRecord {
    pub index: u32,
    pub slot: u32,
    pub slot_blake3: [u8; 32],
    pub name_pointer: u32,
    pub name: String,
    pub task_label: String,
    pub priority: u8,
    pub stack_size: u32,
    pub entry_pointer: u32,
    pub entry: u32,
    pub isa: TaskIsa,
    pub instruction_size: u8,
    pub instruction_blake3: [u8; 32],
    pub callback: u32,
    pub unknown_pointer: u32,
    pub slot_storage: Vec<StorageSpan>,
    pub name_storage: Vec<StorageSpan>,
    pub entry_storage: Vec<StorageSpan>,
}

/// One application group per normalized `(entry, isa)`: the desired
/// global primary, the complete member task indices, and the complete
/// namespaced-label decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskApplication {
    pub entry: u32,
    pub isa: TaskIsa,
    pub desired_primary: String,
    pub task_indices: Vec<u32>,
    pub labels: Vec<TaskLabelApplication>,
}

/// One allocated task label and the member task indices it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskLabelApplication {
    pub label: String,
    pub task_indices: Vec<u32>,
}

/// The terminal slot evidence: address, complete-slot hash, and
/// storage provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalRecord {
    pub slot: u32,
    pub slot_blake3: [u8; 32],
    pub storage: Vec<StorageSpan>,
}

#[cfg(test)]
mod tests {
    use super::TaskIsa;

    #[test]
    fn task_isa_round_trips_lowercase_wire_names() {
        for (isa, wire) in [(TaskIsa::Arm, "\"arm\""), (TaskIsa::Thumb, "\"thumb\"")] {
            assert_eq!(serde_json::to_string(&isa).unwrap(), wire);
            assert_eq!(serde_json::from_str::<TaskIsa>(wire).unwrap(), isa);
        }
    }
}
