// Shared bounded A32/T32 direct-edge CFG and exact must-value dataflow.
// Consumers choose whether direct calls are also observable handoffs; calls
// never enter their target, and every retained fallthrough applies the shared
// AAPCS/ShannonOS volatile-register boundary first.

use crate::arm32::{
    AddressBase, AddressOffset, ControlFlow, DecodedInstruction, InstructionDecoder, Operand,
    PureRustDecoder, Register, Shift, ValueEffect, ValueExpr, valid_isa_length, visible_pc,
    wrapping_offset,
};
use crate::execution_ranges::DecodeIsa;
use crate::runtime_image::RuntimeImage;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CfgLimits {
    pub max_charged_bytes: u64,
    pub max_instructions: usize,
    pub max_blocks: usize,
}

impl CfgLimits {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn exception_roots() -> Self {
        Self {
            max_charged_bytes: 64 * 1024,
            max_instructions: 32_768,
            max_blocks: 4_096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallPolicy {
    Fallthrough,
    FallthroughAndHandoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactJoin {
    Value,
    ValueDefinitionRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactTransfer {
    Complete,
    ImmediateAndLsr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactPolicy {
    join: ExactJoin,
    transfer: ExactTransfer,
}

impl ExactPolicy {
    pub(crate) const fn new(join: ExactJoin, transfer: ExactTransfer) -> Self {
        Self { join, transfer }
    }

    const fn complete() -> Self {
        Self::new(ExactJoin::Value, ExactTransfer::Complete)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DefinitionLineage {
    definition: u32,
    root: u32,
}

const DEFINITION_CHUNK: usize = 64;

#[derive(Debug, Clone)]
struct DefinitionSet(Arc<DefinitionNode>);

#[derive(Debug)]
enum DefinitionNode {
    Chain {
        chunk: Box<[u32]>,
        previous: Option<DefinitionSet>,
    },
    Union {
        left: DefinitionSet,
        right: DefinitionSet,
    },
}

impl DefinitionSet {
    fn single(pc: u32) -> Self {
        Self(Arc::new(DefinitionNode::Chain {
            chunk: Box::new([pc]),
            previous: None,
        }))
    }

    fn insert(&self, pc: u32) -> Self {
        if let DefinitionNode::Chain { chunk, previous } = self.0.as_ref()
            && chunk.len() < DEFINITION_CHUNK
        {
            let mut next = Vec::with_capacity(chunk.len() + 1);
            next.extend_from_slice(chunk);
            next.push(pc);
            return Self(Arc::new(DefinitionNode::Chain {
                chunk: next.into_boxed_slice(),
                previous: previous.clone(),
            }));
        }
        Self(Arc::new(DefinitionNode::Chain {
            chunk: Box::new([pc]),
            previous: Some(self.clone()),
        }))
    }

    fn union(&self, other: &Self) -> Self {
        if Arc::ptr_eq(&self.0, &other.0) || self == other {
            return self.clone();
        }
        Self(Arc::new(DefinitionNode::Union {
            left: self.clone(),
            right: other.clone(),
        }))
    }

    fn collect(&self) -> BTreeSet<u32> {
        let mut definitions = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut pending = vec![self.clone()];
        while let Some(current) = pending.pop() {
            let identity = Arc::as_ptr(&current.0) as usize;
            if !visited.insert(identity) {
                continue;
            }
            match current.0.as_ref() {
                DefinitionNode::Chain { chunk, previous } => {
                    definitions.extend(chunk.iter().copied());
                    if let Some(previous) = previous {
                        pending.push(previous.clone());
                    }
                }
                DefinitionNode::Union { left, right } => {
                    pending.push(right.clone());
                    pending.push(left.clone());
                }
            }
        }
        definitions
    }
}

impl PartialEq for DefinitionSet {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.collect() == other.collect()
    }
}

impl Eq for DefinitionSet {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactValue {
    pub value: u32,
    definitions: DefinitionSet,
    lineage: Option<DefinitionLineage>,
}

impl ExactValue {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn definitions(&self) -> BTreeSet<u32> {
        self.definitions.collect()
    }

    pub(crate) fn definition(&self) -> Option<u32> {
        self.lineage.map(|lineage| lineage.definition)
    }

    pub(crate) fn root(&self) -> Option<u32> {
        self.lineage.map(|lineage| lineage.root)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RegisterState(BTreeMap<Register, ExactValue>);

impl RegisterState {
    pub(crate) fn get(&self, register: Register) -> Option<&ExactValue> {
        self.0.get(&register)
    }

    pub(crate) fn define(&mut self, register: Register, value: u32, pc: u32) {
        self.0.insert(register, exact_definition(value, pc));
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (Register, &'_ ExactValue)> {
        self.0.iter().map(|(register, value)| (*register, value))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TransferContext<'instruction> {
    pub pc: u32,
    pub instruction: &'instruction DecodedInstruction,
    pub call_boundary: bool,
    pub call_flags_unknown: bool,
    pub predicated: bool,
}

pub(crate) trait DataflowOverlay {
    type State: Clone + Default + PartialEq + Eq;

    fn join(&self, left: &Self::State, right: &Self::State) -> Self::State;

    fn apply(
        &self,
        context: TransferContext<'_>,
        registers: &mut RegisterState,
        state: &mut Self::State,
    );
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct DataflowState<State> {
    registers: RegisterState,
    overlay: State,
}

impl<State> DataflowState<State> {
    pub(crate) const fn registers(&self) -> &RegisterState {
        &self.registers
    }

    pub(crate) const fn overlay(&self) -> &State {
        &self.overlay
    }
}

pub(crate) struct DataflowResult<State> {
    before: BTreeMap<u32, DataflowState<State>>,
    after: BTreeMap<u32, DataflowState<State>>,
}

impl<State> DataflowResult<State> {
    pub(crate) fn before(&self, pc: u32) -> Option<&DataflowState<State>> {
        self.before.get(&pc)
    }

    pub(crate) fn after(&self, pc: u32) -> Option<&DataflowState<State>> {
        self.after.get(&pc)
    }

    fn into_before(self) -> BTreeMap<u32, RegisterState> {
        self.before
            .into_iter()
            .map(|(pc, state)| (pc, state.registers))
            .collect()
    }
}

struct NoOverlay;

impl DataflowOverlay for NoOverlay {
    type State = ();

    fn join(&self, _: &Self::State, _: &Self::State) -> Self::State {}

    fn apply(&self, _: TransferContext<'_>, _: &mut RegisterState, _: &mut Self::State) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BoundaryKind {
    Call,
    Return,
    ExceptionCall,
    Indirect,
    Unmapped,
    DecodeFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Handoff {
    pub pc: u32,
    pub kind: BoundaryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // Runtime is part of the stable Task 3-4 error surface.
pub(crate) enum SemanticCfgError {
    Decode {
        pc: u32,
        reason: String,
    },
    Runtime {
        address: u32,
        size: u32,
        reason: String,
    },
    InvalidFlow {
        pc: u32,
        reason: String,
    },
    ResourceLimit {
        what: &'static str,
        actual: u64,
        limit: u64,
    },
}

impl fmt::Display for SemanticCfgError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { pc, reason } => {
                write!(
                    formatter,
                    "semantic CFG decode failed at {pc:#010x}: {reason}"
                )
            }
            Self::Runtime {
                address,
                size,
                reason,
            } => write!(
                formatter,
                "semantic CFG runtime range {address:#010x}+{size:#x} is unusable: {reason}"
            ),
            Self::InvalidFlow { pc, reason } => {
                write!(
                    formatter,
                    "semantic CFG flow at {pc:#010x} is invalid: {reason}"
                )
            }
            Self::ResourceLimit {
                what,
                actual,
                limit,
            } => write!(
                formatter,
                "semantic CFG {what} count {actual} exceeds the limit {limit}"
            ),
        }
    }
}

impl std::error::Error for SemanticCfgError {}

#[derive(Debug, Clone, Default)]
struct DominatorTree {
    immediate: BTreeMap<u32, u32>,
    intervals: BTreeMap<u32, (usize, usize)>,
}

impl DominatorTree {
    fn dominates(&self, dominator: u32, node: u32) -> bool {
        if !self.immediate.contains_key(&dominator) || !self.immediate.contains_key(&node) {
            return false;
        }
        self.intervals
            .get(&dominator)
            .zip(self.intervals.get(&node))
            .is_some_and(
                |(&(dominator_start, dominator_end), &(node_start, node_end))| {
                    dominator_start <= node_start && node_end <= dominator_end
                },
            )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SemanticCfg {
    entry: u32,
    isa: DecodeIsa,
    instructions: BTreeMap<u32, DecodedInstruction>,
    dominators: DominatorTree,
    handoffs: Vec<Handoff>,
    exact_register_states: BTreeMap<u32, RegisterState>,
    successors: BTreeMap<u32, BTreeSet<u32>>,
    predecessors: BTreeMap<u32, BTreeSet<u32>>,
    external_edges: BTreeSet<(u32, u32)>,
    reachable: BTreeSet<u32>,
}

impl SemanticCfg {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn decode(
        runtime: &RuntimeImage<'_>,
        entry: u32,
        isa: DecodeIsa,
        limits: CfgLimits,
        calls: CallPolicy,
    ) -> Result<Self, SemanticCfgError> {
        Self::decode_with_address_window(runtime, entry, isa, limits, calls, None)
    }

    /// PAL's established local proof has an address window in addition to a
    /// non-refundable work budget. Keeping that consumer policy explicit here
    /// lets the shared exception-prefix walk remain charge-bounded without
    /// treating distant mapped direct targets as local code.
    pub(crate) fn decode_with_address_window(
        runtime: &RuntimeImage<'_>,
        entry: u32,
        isa: DecodeIsa,
        limits: CfgLimits,
        calls: CallPolicy,
        max_address_span: Option<u32>,
    ) -> Result<Self, SemanticCfgError> {
        let mut builder = CfgBuilder::new(runtime, entry, isa, limits, calls, max_address_span)?;
        builder.decode()?;
        let mut cfg = Self::from_graph(
            entry,
            isa,
            builder.instructions,
            builder.successors,
            builder.handoffs.into_iter().collect(),
            BTreeMap::new(),
        );
        cfg.exact_register_states = cfg
            .solve_dataflow(runtime, ExactPolicy::complete(), NoOverlay)
            .into_before();
        Ok(cfg)
    }

    pub(crate) fn dominates(&self, dominator: u32, node: u32) -> bool {
        self.dominators.dominates(dominator, node)
    }

    pub(crate) const fn handoffs(&self) -> &[Handoff] {
        self.handoffs.as_slice()
    }

    pub(crate) const fn instructions(&self) -> &BTreeMap<u32, DecodedInstruction> {
        &self.instructions
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn exact_register_states(&self) -> &BTreeMap<u32, RegisterState> {
        &self.exact_register_states
    }

    pub(crate) const fn entry(&self) -> u32 {
        self.entry
    }

    #[allow(dead_code)] // Stable future-consumer accessor.
    pub(crate) const fn isa(&self) -> DecodeIsa {
        self.isa
    }

    pub(crate) fn successors(&self, pc: u32) -> Option<&BTreeSet<u32>> {
        self.successors.get(&pc)
    }

    pub(crate) fn predecessors(&self, pc: u32) -> &BTreeSet<u32> {
        static EMPTY: BTreeSet<u32> = BTreeSet::new();
        self.predecessors.get(&pc).unwrap_or(&EMPTY)
    }

    pub(crate) const fn external_edges(&self) -> &BTreeSet<(u32, u32)> {
        &self.external_edges
    }

    pub(crate) const fn reachable(&self) -> &BTreeSet<u32> {
        &self.reachable
    }

    pub(crate) fn induced_subgraph(&self, nodes: &BTreeSet<u32>) -> Self {
        let instructions = self
            .instructions
            .iter()
            .filter(|(pc, _)| nodes.contains(pc))
            .map(|(pc, instruction)| (*pc, instruction.clone()))
            .collect::<BTreeMap<_, _>>();
        let successors = self
            .successors
            .iter()
            .filter(|(pc, _)| nodes.contains(pc))
            .map(|(pc, successors)| (*pc, successors.clone()))
            .collect();
        let entry = instructions.keys().next().copied().unwrap_or(self.entry);
        let handoffs = self
            .handoffs
            .iter()
            .copied()
            .filter(|handoff| nodes.contains(&handoff.pc))
            .collect();
        let exact_register_states = self
            .exact_register_states
            .iter()
            .filter(|(pc, _)| nodes.contains(pc))
            .map(|(pc, state)| (*pc, state.clone()))
            .collect();
        Self::from_graph(
            entry,
            self.isa,
            instructions,
            successors,
            handoffs,
            exact_register_states,
        )
    }

    pub(crate) fn solve_dataflow<Overlay: DataflowOverlay>(
        &self,
        runtime: &RuntimeImage<'_>,
        policy: ExactPolicy,
        overlay: Overlay,
    ) -> DataflowResult<Overlay::State> {
        if !self.instructions.contains_key(&self.entry) {
            return DataflowResult {
                before: BTreeMap::new(),
                after: BTreeMap::new(),
            };
        }
        let entry_state = DataflowState::default();
        let mut before = BTreeMap::from([(self.entry, entry_state.clone())]);
        let mut after = BTreeMap::new();
        let mut pending = VecDeque::from([self.entry]);
        let mut queued = BTreeSet::from([self.entry]);
        while let Some(pc) = pending.pop_front() {
            queued.remove(&pc);
            let Some(mut output) = before.get(&pc).cloned() else {
                continue;
            };
            let Some(instruction) = self.instructions.get(&pc) else {
                continue;
            };
            let context =
                apply_exact_effect(runtime, pc, instruction, &mut output.registers, policy);
            overlay.apply(context, &mut output.registers, &mut output.overlay);
            if after.get(&pc) == Some(&output) {
                continue;
            }
            after.insert(pc, output.clone());
            for successor in self.successors.get(&pc).into_iter().flatten() {
                if !self.instructions.contains_key(successor) {
                    continue;
                }
                let Some(mut joined) = join_predecessor_states(
                    *successor,
                    &self.predecessors,
                    &after,
                    policy,
                    &overlay,
                ) else {
                    continue;
                };
                if *successor == self.entry {
                    joined = entry_state.clone();
                }
                if before.get(successor) != Some(&joined) {
                    before.insert(*successor, joined);
                    if queued.insert(*successor) {
                        pending.push_back(*successor);
                    }
                }
            }
        }
        DataflowResult { before, after }
    }

    fn from_graph(
        entry: u32,
        isa: DecodeIsa,
        instructions: BTreeMap<u32, DecodedInstruction>,
        successors: BTreeMap<u32, BTreeSet<u32>>,
        handoffs: Vec<Handoff>,
        exact_register_states: BTreeMap<u32, RegisterState>,
    ) -> Self {
        let reachable = reachable_instructions(entry, &instructions, &successors);
        let mut predecessors: BTreeMap<u32, BTreeSet<u32>> =
            reachable.iter().map(|pc| (*pc, BTreeSet::new())).collect();
        let mut external_edges = BTreeSet::new();
        for source in &reachable {
            for target in successors.get(source).into_iter().flatten() {
                if let Some(incoming) = predecessors.get_mut(target) {
                    incoming.insert(*source);
                } else {
                    external_edges.insert((*source, *target));
                }
            }
        }
        let dominators = compute_dominators(entry, &reachable, &successors, &predecessors);
        Self {
            entry,
            isa,
            instructions,
            dominators,
            handoffs,
            exact_register_states,
            successors,
            predecessors,
            external_edges,
            reachable,
        }
    }
}

struct CfgBuilder<'runtime, 'data> {
    runtime: &'runtime RuntimeImage<'data>,
    entry: u32,
    isa: DecodeIsa,
    limits: CfgLimits,
    calls: CallPolicy,
    max_address_span: Option<u32>,
    charged_bytes: u64,
    instructions_attempted: usize,
    instructions: BTreeMap<u32, DecodedInstruction>,
    extents: BTreeMap<u32, u32>,
    successors: BTreeMap<u32, BTreeSet<u32>>,
    incoming: BTreeMap<u32, BTreeSet<u32>>,
    failed_targets: BTreeMap<u32, BoundaryKind>,
    handoffs: BTreeSet<Handoff>,
    block_starts: BTreeSet<u32>,
    pending: VecDeque<u32>,
    queued: BTreeSet<u32>,
    attempted: BTreeSet<u32>,
}

impl<'runtime, 'data> CfgBuilder<'runtime, 'data> {
    fn new(
        runtime: &'runtime RuntimeImage<'data>,
        entry: u32,
        isa: DecodeIsa,
        limits: CfgLimits,
        calls: CallPolicy,
        max_address_span: Option<u32>,
    ) -> Result<Self, SemanticCfgError> {
        if !is_aligned(entry, isa) {
            return Err(invalid_flow(entry, "entry has invalid ISA alignment"));
        }
        let mut builder = Self {
            runtime,
            entry,
            isa,
            limits,
            calls,
            max_address_span,
            charged_bytes: 0,
            instructions_attempted: 0,
            instructions: BTreeMap::new(),
            extents: BTreeMap::new(),
            successors: BTreeMap::new(),
            incoming: BTreeMap::new(),
            failed_targets: BTreeMap::new(),
            handoffs: BTreeSet::new(),
            block_starts: BTreeSet::new(),
            pending: VecDeque::new(),
            queued: BTreeSet::new(),
            attempted: BTreeSet::new(),
        };
        builder.add_block(entry)?;
        builder.queued.insert(entry);
        builder.pending.push_back(entry);
        Ok(builder)
    }

    fn decode(&mut self) -> Result<(), SemanticCfgError> {
        while let Some(pc) = self.pending.pop_front() {
            self.queued.remove(&pc);
            if self.attempted.contains(&pc) {
                continue;
            }
            self.reject_pc_inside_extent(pc)?;
            self.charge_instruction()?;
            self.attempted.insert(pc);
            let (instruction, it_open) = match self.decode_one(pc)? {
                DecodedAt::Instruction {
                    instruction,
                    it_open,
                } => (instruction, it_open),
                DecodedAt::Boundary(kind) => {
                    self.record_failed_target(pc, kind);
                    continue;
                }
            };
            if it_open {
                return Err(invalid_flow(
                    pc,
                    "IT blocks are not supported by direct-edge traversal",
                ));
            }
            self.validate_instruction(pc, &instruction)?;
            let end = instruction
                .pc
                .checked_add(u32::from(instruction.length))
                .ok_or_else(|| invalid_flow(pc, "instruction extent wraps u32"))?;
            if !self.extent_in_address_window(pc, end) {
                self.record_failed_target(pc, BoundaryKind::Unmapped);
                continue;
            }
            self.reject_extent_overlap(pc, end)?;
            self.extents.insert(pc, end);
            self.instructions.insert(pc, instruction.clone());
            self.follow_instruction(pc, end, &instruction)?;
        }
        Ok(())
    }

    fn decode_one(&mut self, pc: u32) -> Result<DecodedAt, SemanticCfgError> {
        let decoder = PureRustDecoder;
        match self.isa {
            DecodeIsa::Arm => {
                self.charge_bytes(4)?;
                let Some(bytes) = self.executable_bytes(pc, 4) else {
                    return Ok(DecodedAt::Boundary(BoundaryKind::Unmapped));
                };
                let mut state = decoder.begin_range(self.isa);
                match decoder.decode_one(&mut state, self.isa, pc, &bytes) {
                    Ok(instruction) => Ok(DecodedAt::Instruction {
                        instruction,
                        it_open: state.is_open(),
                    }),
                    Err(_) => Ok(DecodedAt::Boundary(BoundaryKind::DecodeFailure)),
                }
            }
            DecodeIsa::Thumb => {
                self.charge_bytes(2)?;
                let Some(first_halfword) = self.executable_bytes(pc, 2) else {
                    return Ok(DecodedAt::Boundary(BoundaryKind::Unmapped));
                };
                let halfword = u16::from_le_bytes([first_halfword[0], first_halfword[1]]);
                let leading_five = halfword >> 11;
                let wide = matches!(leading_five, 0b11101..=0b11111);
                let bytes = if wide {
                    self.charge_bytes(2)?;
                    let Some(bytes) = self.executable_bytes(pc, 4) else {
                        return Ok(DecodedAt::Boundary(BoundaryKind::Unmapped));
                    };
                    bytes
                } else {
                    first_halfword
                };
                let mut state = decoder.begin_range(self.isa);
                match decoder.decode_one(&mut state, self.isa, pc, &bytes) {
                    Ok(instruction) => Ok(DecodedAt::Instruction {
                        instruction,
                        it_open: state.is_open(),
                    }),
                    Err(_) => Ok(DecodedAt::Boundary(BoundaryKind::DecodeFailure)),
                }
            }
        }
    }

    fn executable_bytes(&self, pc: u32, size: usize) -> Option<std::borrow::Cow<'_, [u8]>> {
        let size_u32 = u32::try_from(size).ok()?;
        if self.runtime.is_byte_backed(pc, size_u32).ok()? {
            self.runtime.read_exact(pc, size).ok()
        } else {
            None
        }
    }

    fn validate_instruction(
        &self,
        pc: u32,
        instruction: &DecodedInstruction,
    ) -> Result<(), SemanticCfgError> {
        if instruction.pc != pc {
            return Err(SemanticCfgError::Decode {
                pc,
                reason: "decoder returned a different PC".into(),
            });
        }
        if instruction.isa != self.isa {
            return Err(SemanticCfgError::Decode {
                pc,
                reason: "decoder returned a different ISA".into(),
            });
        }
        if !valid_isa_length(self.isa, instruction.length) {
            return Err(SemanticCfgError::Decode {
                pc,
                reason: "decoder returned an impossible instruction length".into(),
            });
        }
        Ok(())
    }

    fn follow_instruction(
        &mut self,
        pc: u32,
        next: u32,
        instruction: &DecodedInstruction,
    ) -> Result<(), SemanticCfgError> {
        match instruction.flow {
            ControlFlow::Linear => self.schedule(pc, next, false),
            ControlFlow::DirectBranch {
                target,
                fallthrough,
                ..
            } => {
                self.schedule(pc, target, true)?;
                if let Some(fallthrough) = fallthrough {
                    if fallthrough != next {
                        return Err(invalid_flow(
                            pc,
                            "branch fallthrough differs from the instruction end",
                        ));
                    }
                    self.schedule(pc, fallthrough, true)?;
                }
                Ok(())
            }
            ControlFlow::DirectCall { target } => {
                if !is_aligned(target, self.isa) {
                    return Err(invalid_flow(
                        target,
                        "call target has invalid ISA alignment",
                    ));
                }
                if self.calls == CallPolicy::FallthroughAndHandoff {
                    self.handoffs.insert(Handoff {
                        pc,
                        kind: BoundaryKind::Call,
                    });
                }
                self.schedule(pc, next, true)
            }
            ControlFlow::ExceptionCall => {
                self.handoffs.insert(Handoff {
                    pc,
                    kind: BoundaryKind::ExceptionCall,
                });
                if instruction.conditional || self.calls == CallPolicy::Fallthrough {
                    self.schedule(pc, next, true)
                } else {
                    Ok(())
                }
            }
            ControlFlow::Return => {
                self.handoffs.insert(Handoff {
                    pc,
                    kind: BoundaryKind::Return,
                });
                if instruction.conditional {
                    self.schedule(pc, next, true)
                } else {
                    Ok(())
                }
            }
            ControlFlow::Barrier => {
                self.handoffs.insert(Handoff {
                    pc,
                    kind: BoundaryKind::Indirect,
                });
                if instruction.conditional
                    || (instruction.links_lr && self.calls == CallPolicy::Fallthrough)
                {
                    self.schedule(pc, next, true)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn schedule(
        &mut self,
        source: u32,
        target: u32,
        starts_block: bool,
    ) -> Result<(), SemanticCfgError> {
        if !is_aligned(target, self.isa) {
            return Err(invalid_flow(
                target,
                "direct edge has invalid ISA alignment",
            ));
        }
        self.successors.entry(source).or_default().insert(target);
        self.incoming.entry(target).or_default().insert(source);
        if !self.pc_in_address_window(target) {
            self.handoffs.insert(Handoff {
                pc: source,
                kind: BoundaryKind::Unmapped,
            });
            return Ok(());
        }
        if let Some(kind) = self.failed_targets.get(&target).copied() {
            self.handoffs.insert(Handoff { pc: source, kind });
            return Ok(());
        }
        if starts_block {
            self.add_block(target)?;
        }
        if !self.attempted.contains(&target) && self.queued.insert(target) {
            self.pending.push_back(target);
        }
        Ok(())
    }

    fn record_failed_target(&mut self, target: u32, kind: BoundaryKind) {
        self.failed_targets.insert(target, kind);
        let mut recorded = false;
        for source in self.incoming.get(&target).into_iter().flatten() {
            self.handoffs.insert(Handoff { pc: *source, kind });
            recorded = true;
        }
        if !recorded {
            self.handoffs.insert(Handoff { pc: target, kind });
        }
    }

    fn reject_pc_inside_extent(&self, pc: u32) -> Result<(), SemanticCfgError> {
        if let Some((start, end)) = self.extents.range(..=pc).next_back()
            && *start != pc
            && *end > pc
        {
            return Err(invalid_flow(pc, "direct edge enters an instruction extent"));
        }
        Ok(())
    }

    fn reject_extent_overlap(&self, pc: u32, end: u32) -> Result<(), SemanticCfgError> {
        if let Some((prior_pc, prior_end)) = self.extents.range(..=pc).next_back()
            && *prior_pc != pc
            && *prior_end > pc
        {
            return Err(invalid_flow(
                pc,
                "decoded instruction overlaps a prior extent",
            ));
        }
        if let Some((next_pc, _)) = self.extents.range(pc..).next()
            && *next_pc != pc
            && *next_pc < end
        {
            return Err(invalid_flow(
                pc,
                "decoded instruction overlaps a later extent",
            ));
        }
        Ok(())
    }

    fn pc_in_address_window(&self, pc: u32) -> bool {
        let Some(span) = self.max_address_span else {
            return true;
        };
        pc.checked_sub(self.entry)
            .is_some_and(|offset| offset < span)
    }

    fn extent_in_address_window(&self, pc: u32, end: u32) -> bool {
        let Some(span) = self.max_address_span else {
            return true;
        };
        pc.checked_sub(self.entry)
            .zip(end.checked_sub(self.entry))
            .is_some_and(|(start, end)| start < span && end <= span)
    }

    fn add_block(&mut self, pc: u32) -> Result<(), SemanticCfgError> {
        if self.block_starts.contains(&pc) {
            return Ok(());
        }
        let actual = self
            .block_starts
            .len()
            .checked_add(1)
            .ok_or_else(|| resource("blocks", u64::MAX, self.limits.max_blocks as u64))?;
        if actual > self.limits.max_blocks {
            return Err(resource(
                "blocks",
                usize_to_u64(actual),
                usize_to_u64(self.limits.max_blocks),
            ));
        }
        self.block_starts.insert(pc);
        Ok(())
    }

    fn charge_instruction(&mut self) -> Result<(), SemanticCfgError> {
        let actual = self.instructions_attempted.checked_add(1).ok_or_else(|| {
            resource(
                "instructions",
                u64::MAX,
                usize_to_u64(self.limits.max_instructions),
            )
        })?;
        if actual > self.limits.max_instructions {
            return Err(resource(
                "instructions",
                usize_to_u64(actual),
                usize_to_u64(self.limits.max_instructions),
            ));
        }
        self.instructions_attempted = actual;
        Ok(())
    }

    fn charge_bytes(&mut self, bytes: u64) -> Result<(), SemanticCfgError> {
        let actual = self.charged_bytes.saturating_add(bytes);
        if actual > self.limits.max_charged_bytes {
            return Err(resource(
                "charged bytes",
                actual,
                self.limits.max_charged_bytes,
            ));
        }
        self.charged_bytes = actual;
        Ok(())
    }
}

enum DecodedAt {
    Instruction {
        instruction: DecodedInstruction,
        it_open: bool,
    },
    Boundary(BoundaryKind),
}

fn reachable_instructions(
    entry: u32,
    instructions: &BTreeMap<u32, DecodedInstruction>,
    successors: &BTreeMap<u32, BTreeSet<u32>>,
) -> BTreeSet<u32> {
    if !instructions.contains_key(&entry) {
        return BTreeSet::new();
    }
    let mut reachable = BTreeSet::from([entry]);
    let mut pending = VecDeque::from([entry]);
    while let Some(pc) = pending.pop_front() {
        for successor in successors.get(&pc).into_iter().flatten() {
            if instructions.contains_key(successor) && reachable.insert(*successor) {
                pending.push_back(*successor);
            }
        }
    }
    reachable
}

fn compute_dominators(
    entry: u32,
    reachable: &BTreeSet<u32>,
    successors: &BTreeMap<u32, BTreeSet<u32>>,
    predecessors: &BTreeMap<u32, BTreeSet<u32>>,
) -> DominatorTree {
    if !reachable.contains(&entry) {
        return DominatorTree::default();
    }
    let order = reverse_postorder(entry, reachable, successors);
    let positions: BTreeMap<u32, usize> = order
        .iter()
        .enumerate()
        .map(|(position, pc)| (*pc, position))
        .collect();
    let mut immediate = BTreeMap::from([(entry, entry)]);
    loop {
        let mut changed = false;
        for pc in order.iter().copied().filter(|pc| *pc != entry) {
            let mut resolved = predecessors
                .get(&pc)
                .into_iter()
                .flatten()
                .copied()
                .filter(|predecessor| immediate.contains_key(predecessor));
            let Some(mut next) = resolved.next() else {
                continue;
            };
            for predecessor in resolved {
                next = intersect_dominators(next, predecessor, &immediate, &positions);
            }
            if immediate.get(&pc) != Some(&next) {
                immediate.insert(pc, next);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut children: BTreeMap<u32, BTreeSet<u32>> = immediate
        .keys()
        .copied()
        .map(|pc| (pc, BTreeSet::new()))
        .collect();
    for (node, parent) in &immediate {
        if node != parent {
            children.entry(*parent).or_default().insert(*node);
        }
    }
    let mut starts = BTreeMap::new();
    let mut intervals = BTreeMap::new();
    let mut clock = 0usize;
    let mut pending = vec![(entry, false)];
    while let Some((node, exiting)) = pending.pop() {
        if exiting {
            let start = starts[&node];
            intervals.insert(node, (start, clock));
            clock += 1;
            continue;
        }
        starts.insert(node, clock);
        clock += 1;
        pending.push((node, true));
        for child in children.get(&node).into_iter().flatten().rev() {
            pending.push((*child, false));
        }
    }
    DominatorTree {
        immediate,
        intervals,
    }
}

fn reverse_postorder(
    entry: u32,
    reachable: &BTreeSet<u32>,
    successors: &BTreeMap<u32, BTreeSet<u32>>,
) -> Vec<u32> {
    let mut visited = BTreeSet::new();
    let mut postorder = Vec::with_capacity(reachable.len());
    let mut pending = vec![(entry, false)];
    while let Some((node, exiting)) = pending.pop() {
        if exiting {
            postorder.push(node);
            continue;
        }
        if !visited.insert(node) {
            continue;
        }
        pending.push((node, true));
        for successor in successors.get(&node).into_iter().flatten().rev() {
            if reachable.contains(successor) && !visited.contains(successor) {
                pending.push((*successor, false));
            }
        }
    }
    postorder.reverse();
    postorder
}

fn intersect_dominators(
    mut left: u32,
    mut right: u32,
    immediate: &BTreeMap<u32, u32>,
    positions: &BTreeMap<u32, usize>,
) -> u32 {
    while left != right {
        while positions[&left] > positions[&right] {
            left = immediate[&left];
        }
        while positions[&right] > positions[&left] {
            right = immediate[&right];
        }
    }
    left
}

fn join_dataflow_states<Overlay: DataflowOverlay>(
    left: &DataflowState<Overlay::State>,
    right: &DataflowState<Overlay::State>,
    policy: ExactPolicy,
    overlay: &Overlay,
) -> DataflowState<Overlay::State> {
    DataflowState {
        registers: join_register_states(&left.registers, &right.registers, policy),
        overlay: overlay.join(&left.overlay, &right.overlay),
    }
}

fn join_predecessor_states<Overlay: DataflowOverlay>(
    node: u32,
    predecessors: &BTreeMap<u32, BTreeSet<u32>>,
    outputs: &BTreeMap<u32, DataflowState<Overlay::State>>,
    policy: ExactPolicy,
    overlay: &Overlay,
) -> Option<DataflowState<Overlay::State>> {
    let mut incoming = predecessors
        .get(&node)?
        .iter()
        .filter_map(|predecessor| outputs.get(predecessor));
    let mut joined = incoming.next()?.clone();
    for state in incoming {
        joined = join_dataflow_states(&joined, state, policy, overlay);
    }
    Some(joined)
}

fn join_register_states(
    left: &RegisterState,
    right: &RegisterState,
    policy: ExactPolicy,
) -> RegisterState {
    let mut joined = BTreeMap::new();
    for (register, left_value) in &left.0 {
        let Some(right_value) = right.0.get(register) else {
            continue;
        };
        if left_value.value != right_value.value {
            continue;
        }
        if policy.join == ExactJoin::ValueDefinitionRoot
            && (left_value.lineage.is_none() || left_value.lineage != right_value.lineage)
        {
            continue;
        }
        let definitions = left_value.definitions.union(&right_value.definitions);
        joined.insert(
            *register,
            ExactValue {
                value: left_value.value,
                definitions,
                lineage: (left_value.lineage == right_value.lineage)
                    .then_some(left_value.lineage)
                    .flatten(),
            },
        );
    }
    RegisterState(joined)
}

fn apply_exact_effect<'instruction>(
    runtime: &RuntimeImage<'_>,
    pc: u32,
    instruction: &'instruction DecodedInstruction,
    state: &mut RegisterState,
    policy: ExactPolicy,
) -> TransferContext<'instruction> {
    let boundary = instruction.flow.call_boundary(instruction.links_lr);
    let call_boundary = boundary.is_some();
    let call_flags_unknown = boundary
        .as_ref()
        .is_some_and(|boundary| boundary.flags_unknown);
    let predicated = instruction.conditional && matches!(instruction.flow, ControlFlow::Linear);
    if let Some(boundary) = boundary {
        for register in boundary.volatile {
            state.0.remove(&register);
        }
    } else if instruction.conditional {
        for register in &instruction.writes {
            state.0.remove(register);
        }
    } else {
        match &instruction.effect {
            ValueEffect::RegisterWrite { dst, value } => {
                if let Some(value) = evaluate_value_expr(pc, value, state, policy) {
                    state.0.insert(*dst, value);
                } else {
                    state.0.remove(dst);
                }
            }
            ValueEffect::Shift { dst, source, shift } => {
                let supported =
                    policy.transfer == ExactTransfer::Complete || matches!(shift, Shift::Lsr(_));
                if supported
                    && let Some(value) = state.0.get(source).cloned()
                    && let Some(shifted) = shift_value(value.value, *shift)
                {
                    state.0.insert(*dst, derived_value(value, shifted, pc));
                } else {
                    state.0.remove(dst);
                }
            }
            ValueEffect::LiteralWordLoad { dst, address } => {
                if let Some(value) = resolve_literal_word(runtime, pc, address) {
                    state.0.insert(*dst, exact_definition(value, pc));
                } else {
                    state.0.remove(dst);
                }
            }
            ValueEffect::Memory(_) | ValueEffect::Unsupported => {
                for register in &instruction.writes {
                    state.0.remove(register);
                }
            }
            ValueEffect::Compare { .. } | ValueEffect::None => {}
        }
    }
    TransferContext {
        pc,
        instruction,
        call_boundary,
        call_flags_unknown,
        predicated,
    }
}

fn evaluate_value_expr(
    pc: u32,
    expression: &ValueExpr,
    state: &RegisterState,
    policy: ExactPolicy,
) -> Option<ExactValue> {
    match expression {
        ValueExpr::Immediate(value) => Some(exact_definition(*value, pc)),
        ValueExpr::Register(source) => {
            let value = state.get(*source)?.clone();
            let copied = value.value;
            Some(derived_value(value, copied, pc))
        }
        ValueExpr::ReplaceHighHalf { source, high } => {
            let value = state.get(*source)?.clone();
            let replaced = (u32::from(*high) << 16) | (value.value & 0xffff);
            Some(derived_value(value, replaced, pc))
        }
        ValueExpr::Add { left, right } => {
            let register_operand = matches!(right, Operand::Register { .. });
            if policy.transfer == ExactTransfer::ImmediateAndLsr && register_operand {
                return None;
            }
            let mut value = state.get(*left)?.clone();
            let (right_value, definitions) = operand_value(right, state)?;
            value.value = value.value.checked_add(right_value)?;
            if let Some(definitions) = definitions {
                value.definitions = value.definitions.union(&definitions);
            }
            value.definitions = value.definitions.insert(pc);
            if register_operand {
                value.lineage = None;
            } else if let Some(lineage) = &mut value.lineage {
                lineage.definition = pc;
            }
            Some(value)
        }
        ValueExpr::Sub { left, right } => {
            let register_operand = matches!(right, Operand::Register { .. });
            if policy.transfer == ExactTransfer::ImmediateAndLsr && register_operand {
                return None;
            }
            let mut value = state.get(*left)?.clone();
            let (right_value, definitions) = operand_value(right, state)?;
            value.value = value.value.checked_sub(right_value)?;
            if let Some(definitions) = definitions {
                value.definitions = value.definitions.union(&definitions);
            }
            value.definitions = value.definitions.insert(pc);
            if register_operand {
                value.lineage = None;
            } else if let Some(lineage) = &mut value.lineage {
                lineage.definition = pc;
            }
            Some(value)
        }
        ValueExpr::ArchitecturalPc {
            addend,
            align_to_four,
        } => Some(exact_definition(
            wrapping_offset(visible_pc(pc, *align_to_four), *addend),
            pc,
        )),
    }
}

fn operand_value(operand: &Operand, state: &RegisterState) -> Option<(u32, Option<DefinitionSet>)> {
    match operand {
        Operand::Immediate(value) => Some((*value, None)),
        Operand::Register { register, shift } => {
            let value = state.get(*register)?;
            Some((
                shift_value(value.value, *shift)?,
                Some(value.definitions.clone()),
            ))
        }
    }
}

fn shift_value(value: u32, shift: Shift) -> Option<u32> {
    match shift {
        Shift::Lsl(amount) => Some(if amount >= 32 { 0 } else { value << amount }),
        Shift::Lsr(amount) => Some(if amount >= 32 { 0 } else { value >> amount }),
        Shift::Asr(amount) => Some(if amount >= 32 {
            if value & 0x8000_0000 == 0 {
                0
            } else {
                u32::MAX
            }
        } else {
            ((value as i32) >> amount) as u32
        }),
        Shift::Ror(amount) => Some(value.rotate_right(u32::from(amount) % 32)),
        Shift::Rrx => None,
    }
}

fn resolve_literal_word(
    runtime: &RuntimeImage<'_>,
    pc: u32,
    address: &crate::arm32::AddressExpr,
) -> Option<u32> {
    let crate::arm32::AddressExpr {
        base: AddressBase::ArchitecturalPc { align_to_four },
        offset: AddressOffset::Immediate(offset),
    } = address
    else {
        return None;
    };
    let literal = wrapping_offset(visible_pc(pc, *align_to_four), *offset);
    if !runtime.is_byte_backed(literal, 4).ok()? {
        return None;
    }
    runtime.read_u32(literal).ok()
}

fn exact_definition(value: u32, pc: u32) -> ExactValue {
    ExactValue {
        value,
        definitions: DefinitionSet::single(pc),
        lineage: Some(DefinitionLineage {
            definition: pc,
            root: pc,
        }),
    }
}

fn derived_value(mut value: ExactValue, derived: u32, pc: u32) -> ExactValue {
    value.value = derived;
    value.definitions = value.definitions.insert(pc);
    if let Some(lineage) = &mut value.lineage {
        lineage.definition = pc;
    }
    value
}

fn is_aligned(pc: u32, isa: DecodeIsa) -> bool {
    match isa {
        DecodeIsa::Arm => pc.is_multiple_of(4),
        DecodeIsa::Thumb => pc.is_multiple_of(2),
    }
}

fn invalid_flow(pc: u32, reason: &str) -> SemanticCfgError {
    SemanticCfgError::InvalidFlow {
        pc,
        reason: reason.into(),
    }
}

fn resource(what: &'static str, actual: u64, limit: u64) -> SemanticCfgError {
    SemanticCfgError::ResourceLimit {
        what,
        actual,
        limit,
    }
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundaryKind, CallPolicy, CfgLimits, DataflowOverlay, ExactJoin, ExactPolicy,
        ExactTransfer, RegisterState, SemanticCfg, SemanticCfgError, TransferContext,
    };
    use crate::arm32::Register;
    use crate::execution_ranges::DecodeIsa;
    use crate::runtime_image::RuntimeImage;
    use std::collections::BTreeSet;

    fn runtime(bytes: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(bytes, 0, None).expect("raw fixture runtime")
    }

    fn limits(bytes: u64, instructions: usize, blocks: usize) -> CfgLimits {
        CfgLimits {
            max_charged_bytes: bytes,
            max_instructions: instructions,
            max_blocks: blocks,
        }
    }

    // A32 MOV (immediate), derived from cond=AL, I=1, opcode=MOV and an
    // unrotated eight-bit immediate. This fixture does not use the decoder's
    // encoder or any production fixture helper.
    fn arm_mov_immediate(register: u8, value: u8) -> [u8; 4] {
        (0xe3a0_0000 | (u32::from(register) << 12) | u32::from(value)).to_le_bytes()
    }

    fn arm_diamond(left: u8, right: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        // bne 0x0c: target = PC+8 + (1 << 2).
        bytes.extend_from_slice(&0x1a00_0001u32.to_le_bytes());
        bytes.extend_from_slice(&arm_mov_immediate(0, left));
        // b 0x10: target = PC+8 + (0 << 2).
        bytes.extend_from_slice(&0xea00_0000u32.to_le_bytes());
        bytes.extend_from_slice(&arm_mov_immediate(0, right));
        // b 0x10: target = PC+8 + (-2 << 2).
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        bytes
    }

    fn decode_with_policy(bytes: &[u8], isa: DecodeIsa, calls: CallPolicy) -> SemanticCfg {
        SemanticCfg::decode(&runtime(bytes), 0, isa, CfgLimits::exception_roots(), calls)
            .expect("fixture CFG decodes")
    }

    fn decode(bytes: &[u8], isa: DecodeIsa) -> SemanticCfg {
        decode_with_policy(bytes, isa, CallPolicy::FallthroughAndHandoff)
    }

    #[derive(Clone, Default, PartialEq, Eq)]
    struct TestOverlayState {
        calls: usize,
    }

    struct TestOverlay;

    impl DataflowOverlay for TestOverlay {
        type State = TestOverlayState;

        fn join(&self, left: &Self::State, right: &Self::State) -> Self::State {
            if left == right {
                left.clone()
            } else {
                Self::State::default()
            }
        }

        fn apply(
            &self,
            context: TransferContext<'_>,
            registers: &mut RegisterState,
            state: &mut Self::State,
        ) {
            if context.call_boundary {
                state.calls += 1;
                registers.define(Register(0), 0x55, context.pc);
            }
        }
    }

    #[test]
    fn real_a32_direct_edges_compute_dominance() {
        let bytes = arm_diamond(1, 2);
        let cfg = decode(&bytes, DecodeIsa::Arm);

        assert_eq!(
            cfg.instructions().keys().copied().collect::<Vec<_>>(),
            vec![0, 4, 8, 12, 16]
        );
        assert!(cfg.dominates(0, 16));
        assert!(!cfg.dominates(4, 16));
        assert!(!cfg.dominates(12, 16));
    }

    #[test]
    fn real_t32_wide_and_narrow_instructions_are_traversed() {
        let bytes = [
            // movw r0, #0x1234: i:imm4:imm3:imm8 = 0:1:2:0x34.
            0x41, 0xf2, 0x34, 0x20, // b.n 0x4: PC+4 + (-2 << 1).
            0xfe, 0xe7,
        ];
        let cfg = decode(&bytes, DecodeIsa::Thumb);

        assert_eq!(
            cfg.instructions().keys().copied().collect::<Vec<_>>(),
            vec![0, 4]
        );
        let value = cfg.exact_register_states()[&4]
            .get(Register(0))
            .expect("MOVW fact reaches the branch");
        assert_eq!(value.value, 0x1234);
        assert_eq!(value.definitions(), BTreeSet::from([0]));
    }

    #[test]
    fn direct_call_records_handoff_and_clobbers_volatile_fallthrough() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&arm_mov_immediate(0, 0x12));
        bytes.extend_from_slice(&arm_mov_immediate(4, 0x34));
        // bl 0x40 from 0x8: target = PC+8 + (12 << 2).
        bytes.extend_from_slice(&0xeb00_000cu32.to_le_bytes());
        // mcr p15, 0, r0, c12, c0, 0 (VBAR write).
        bytes.extend_from_slice(&[0x10, 0x0f, 0x0c, 0xee]);
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());

        let cfg = decode(&bytes, DecodeIsa::Arm);
        assert!(
            cfg.handoffs()
                .iter()
                .any(|edge| edge.pc == 8 && edge.kind == BoundaryKind::Call)
        );
        assert_eq!(cfg.successors(8), Some(&BTreeSet::from([12])));
        assert!(!cfg.instructions().contains_key(&0x40));
        let before_vbar = &cfg.exact_register_states()[&12];
        assert_eq!(before_vbar.get(Register(0)), None);
        assert_eq!(
            before_vbar.get(Register(4)).map(|value| value.value),
            Some(0x34)
        );

        let cfg = SemanticCfg::decode(
            &runtime(&bytes),
            0,
            DecodeIsa::Arm,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        )
        .expect("fallthrough-only call policy decodes");
        assert!(
            cfg.handoffs()
                .iter()
                .all(|edge| edge.kind != BoundaryKind::Call)
        );
        assert_eq!(
            cfg.exact_register_states()[&12].get(Register(0)),
            None,
            "call clobbers apply even when call handoffs are suppressed"
        );
    }

    #[test]
    fn linked_indirect_stops_exception_prefix_but_pal_policy_retains_fallthrough() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&arm_mov_immediate(0, 0x12));
        bytes.extend_from_slice(&arm_mov_immediate(4, 0x34));
        // blx r1: the target is unresolved, but LR receives the return site.
        bytes.extend_from_slice(&0xe12f_ff31u32.to_le_bytes());
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());

        let cfg = decode(&bytes, DecodeIsa::Arm);

        assert!(
            cfg.handoffs()
                .iter()
                .any(|edge| edge.pc == 8 && edge.kind == BoundaryKind::Indirect)
        );
        assert_eq!(cfg.successors(8), None);
        assert!(!cfg.instructions().contains_key(&12));

        let cfg = SemanticCfg::decode(
            &runtime(&bytes),
            0,
            DecodeIsa::Arm,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        )
        .expect("PAL fallthrough policy decodes");
        assert_eq!(cfg.successors(8), Some(&BTreeSet::from([12])));
        let fallthrough = &cfg.exact_register_states()[&12];
        assert_eq!(fallthrough.get(Register(0)), None);
        assert_eq!(
            fallthrough.get(Register(4)).map(|value| value.value),
            Some(0x34)
        );
    }

    #[test]
    fn conditional_return_retains_taken_handoff_and_not_taken_edge_under_both_policies() {
        let mut bytes = Vec::new();
        // bxne lr: cond=NE and the canonical return register.
        bytes.extend_from_slice(&0x112f_ff1eu32.to_le_bytes());
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());

        for policy in [CallPolicy::Fallthrough, CallPolicy::FallthroughAndHandoff] {
            let cfg = decode_with_policy(&bytes, DecodeIsa::Arm, policy);
            let instruction = &cfg.instructions()[&0];
            assert!(instruction.conditional);
            assert!(matches!(
                instruction.flow,
                crate::arm32::ControlFlow::Return
            ));
            assert!(
                cfg.handoffs()
                    .iter()
                    .any(|edge| edge.pc == 0 && edge.kind == BoundaryKind::Return)
            );
            assert_eq!(cfg.successors(0), Some(&BTreeSet::from([4])));
            assert!(cfg.instructions().contains_key(&4));
        }
    }

    #[test]
    fn conditional_exception_retains_taken_handoff_and_not_taken_edge_under_both_policies() {
        let mut bytes = Vec::new();
        // svcne #0: cond=NE, SVC immediate zero.
        bytes.extend_from_slice(&0x1f00_0000u32.to_le_bytes());
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());

        for policy in [CallPolicy::Fallthrough, CallPolicy::FallthroughAndHandoff] {
            let cfg = decode_with_policy(&bytes, DecodeIsa::Arm, policy);
            let instruction = &cfg.instructions()[&0];
            assert!(instruction.conditional);
            assert!(matches!(
                instruction.flow,
                crate::arm32::ControlFlow::ExceptionCall
            ));
            assert!(
                cfg.handoffs()
                    .iter()
                    .any(|edge| { edge.pc == 0 && edge.kind == BoundaryKind::ExceptionCall })
            );
            assert_eq!(cfg.successors(0), Some(&BTreeSet::from([4])));
            assert!(cfg.instructions().contains_key(&4));
        }
    }

    #[test]
    fn conditional_indirect_retains_taken_handoff_and_not_taken_edge_under_both_policies() {
        let mut bytes = Vec::new();
        // bxne r1: cond=NE and an unresolved, non-linking register target.
        bytes.extend_from_slice(&0x112f_ff11u32.to_le_bytes());
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());

        for policy in [CallPolicy::Fallthrough, CallPolicy::FallthroughAndHandoff] {
            let cfg = decode_with_policy(&bytes, DecodeIsa::Arm, policy);
            let instruction = &cfg.instructions()[&0];
            assert!(instruction.conditional);
            assert!(matches!(
                instruction.flow,
                crate::arm32::ControlFlow::Barrier
            ));
            assert!(!instruction.links_lr);
            assert!(
                cfg.handoffs()
                    .iter()
                    .any(|edge| edge.pc == 0 && edge.kind == BoundaryKind::Indirect)
            );
            assert_eq!(cfg.successors(0), Some(&BTreeSet::from([4])));
            assert!(cfg.instructions().contains_key(&4));
        }
    }

    #[test]
    fn shared_dataflow_overlay_runs_after_call_clobber() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&arm_mov_immediate(0, 0x12));
        // bl 0x40 from 0x4: target = PC+8 + (13 << 2).
        bytes.extend_from_slice(&0xeb00_000du32.to_le_bytes());
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        let runtime = runtime(&bytes);
        let cfg = SemanticCfg::decode(
            &runtime,
            0,
            DecodeIsa::Arm,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        )
        .expect("overlay fixture CFG decodes");

        let states = cfg.solve_dataflow(
            &runtime,
            ExactPolicy::new(ExactJoin::Value, ExactTransfer::Complete),
            TestOverlay,
        );
        let fallthrough = states.before(8).expect("call fallthrough state");

        assert_eq!(fallthrough.overlay().calls, 1);
        assert_eq!(
            fallthrough
                .registers()
                .get(Register(0))
                .map(|value| value.value),
            Some(0x55)
        );
    }

    #[test]
    fn agreeing_predecessors_union_exact_value_definitions() {
        let bytes = arm_diamond(7, 7);
        let cfg = decode(&bytes, DecodeIsa::Arm);
        let value = cfg.exact_register_states()[&16]
            .get(Register(0))
            .expect("equal path values survive");

        assert_eq!(value.value, 7);
        assert_eq!(value.definitions(), BTreeSet::from([4, 12]));
    }

    #[test]
    fn disagreeing_predecessors_kill_an_exact_value() {
        let bytes = arm_diamond(1, 2);
        let cfg = decode(&bytes, DecodeIsa::Arm);

        assert_eq!(cfg.exact_register_states()[&16].get(Register(0)), None);
    }

    #[test]
    fn register_arithmetic_retains_both_operand_definition_sets() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&arm_mov_immediate(1, 1));
        bytes.extend_from_slice(&arm_mov_immediate(2, 2));
        // add r0, r1, r2: cond=AL, opcode=ADD, Rn=1, Rd=0, Rm=2.
        bytes.extend_from_slice(&0xe081_0002u32.to_le_bytes());
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        let cfg = decode(&bytes, DecodeIsa::Arm);
        let value = cfg.exact_register_states()[&12]
            .get(Register(0))
            .expect("ADD result reaches the branch");

        assert_eq!(value.value, 3);
        assert_eq!(value.definitions(), BTreeSet::from([0, 4, 8]));
    }

    #[test]
    fn unconditional_return_stops_under_both_policies() {
        let bytes = 0xe12f_ff1eu32.to_le_bytes();
        for policy in [CallPolicy::Fallthrough, CallPolicy::FallthroughAndHandoff] {
            let returned = decode_with_policy(&bytes, DecodeIsa::Arm, policy);
            assert_eq!(returned.handoffs()[0].kind, BoundaryKind::Return);
            assert_eq!(returned.successors(0), None);
            assert_eq!(
                returned.instructions().keys().copied().collect::<Vec<_>>(),
                [0]
            );
        }
    }

    #[test]
    fn exception_boundary_stops_exception_prefix_but_pal_policy_retains_fallthrough() {
        let mut exception = Vec::new();
        exception.extend_from_slice(&0xef00_0000u32.to_le_bytes());
        exception.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        let cfg = decode(&exception, DecodeIsa::Arm);
        assert!(
            cfg.handoffs()
                .iter()
                .any(|edge| edge.pc == 0 && edge.kind == BoundaryKind::ExceptionCall)
        );
        assert_eq!(cfg.successors(0), None);
        assert!(!cfg.instructions().contains_key(&4));

        let cfg = SemanticCfg::decode(
            &runtime(&exception),
            0,
            DecodeIsa::Arm,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        )
        .expect("PAL fallthrough policy decodes");
        assert!(cfg.instructions().contains_key(&4));
    }

    #[test]
    fn unconditional_non_linking_indirect_stops_under_both_policies() {
        let bytes = 0xe12f_ff10u32.to_le_bytes();
        for policy in [CallPolicy::Fallthrough, CallPolicy::FallthroughAndHandoff] {
            let indirect = decode_with_policy(&bytes, DecodeIsa::Arm, policy);
            assert_eq!(indirect.handoffs()[0].kind, BoundaryKind::Indirect);
            assert_eq!(indirect.successors(0), None);
            assert_eq!(
                indirect.instructions().keys().copied().collect::<Vec<_>>(),
                [0]
            );
        }
    }

    #[test]
    fn unmapped_direct_target_is_a_typed_gap_boundary() {
        // b 0x20 from 0x0: target = PC+8 + (6 << 2).
        let cfg = decode(&0xea00_0006u32.to_le_bytes(), DecodeIsa::Arm);

        assert_eq!(cfg.instructions().len(), 1);
        assert!(
            cfg.handoffs()
                .iter()
                .any(|edge| edge.pc == 0 && edge.kind == BoundaryKind::Unmapped)
        );
    }

    #[test]
    fn missing_wide_t32_continuation_is_an_unmapped_boundary() {
        // The first halfword of movw r0, #0x1234 is a valid wide prefix, but
        // the second halfword is deliberately absent.
        let cfg = decode(&[0x41, 0xf2], DecodeIsa::Thumb);

        assert!(cfg.instructions().is_empty());
        assert_eq!(cfg.handoffs()[0].pc, 0);
        assert_eq!(cfg.handoffs()[0].kind, BoundaryKind::Unmapped);
    }

    #[test]
    fn bad_isa_alignment_is_rejected_before_decode() {
        let bytes = [0; 8];
        let arm = SemanticCfg::decode(
            &runtime(&bytes),
            2,
            DecodeIsa::Arm,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        );
        assert!(matches!(
            arm,
            Err(SemanticCfgError::InvalidFlow { pc: 2, .. })
        ));

        let thumb = SemanticCfg::decode(
            &runtime(&bytes),
            1,
            DecodeIsa::Thumb,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        );
        assert!(matches!(
            thumb,
            Err(SemanticCfgError::InvalidFlow { pc: 1, .. })
        ));
    }

    #[test]
    fn branch_into_a_wide_t32_extent_is_rejected_as_overlap() {
        let bytes = [
            0x41, 0xf2, 0x34, 0x20, // b.n 0x2 from 0x4: target = PC+4 + (-3 << 1).
            0xfd, 0xe7,
        ];
        let result = SemanticCfg::decode(
            &runtime(&bytes),
            0,
            DecodeIsa::Thumb,
            CfgLimits::exception_roots(),
            CallPolicy::Fallthrough,
        );

        assert!(matches!(
            result,
            Err(SemanticCfgError::InvalidFlow { pc: 2, .. })
        ));
    }

    #[test]
    fn charged_byte_limit_is_checked_before_fetch() {
        let result = SemanticCfg::decode(
            &runtime(&arm_mov_immediate(0, 1)),
            0,
            DecodeIsa::Arm,
            limits(3, 8, 8),
            CallPolicy::Fallthrough,
        );

        assert!(matches!(
            result,
            Err(SemanticCfgError::ResourceLimit {
                what: "charged bytes",
                actual: 4,
                limit: 3,
            })
        ));
    }

    #[test]
    fn instruction_limit_is_checked_before_the_next_decode() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&arm_mov_immediate(0, 1));
        bytes.extend_from_slice(&0xeaff_fffeu32.to_le_bytes());
        let result = SemanticCfg::decode(
            &runtime(&bytes),
            0,
            DecodeIsa::Arm,
            limits(64, 1, 8),
            CallPolicy::Fallthrough,
        );

        assert!(matches!(
            result,
            Err(SemanticCfgError::ResourceLimit {
                what: "instructions",
                actual: 2,
                limit: 1,
            })
        ));
    }

    #[test]
    fn basic_block_limit_is_checked_when_direct_edges_split() {
        let bytes = [
            // bne 0x8: target = PC+8 + (0 << 2), fallthrough = 0x4.
            0x00, 0x00, 0x00, 0x1a, 0xfe, 0xff, 0xff, 0xea, 0xfe, 0xff, 0xff, 0xea,
        ];
        let result = SemanticCfg::decode(
            &runtime(&bytes),
            0,
            DecodeIsa::Arm,
            limits(64, 8, 2),
            CallPolicy::Fallthrough,
        );

        assert!(matches!(
            result,
            Err(SemanticCfgError::ResourceLimit {
                what: "blocks",
                actual: 3,
                limit: 2,
            })
        ));
    }

    #[test]
    fn failed_fetch_charge_is_not_refunded_before_another_path() {
        let bytes = [
            // bne 0x8: target is exactly beyond this raw mapping.
            0x00, 0x00, 0x00, 0x1a, // bx lr on the mapped fallthrough path.
            0x1e, 0xff, 0x2f, 0xe1,
        ];
        let result = SemanticCfg::decode(
            &runtime(&bytes),
            0,
            DecodeIsa::Arm,
            limits(10, 8, 8),
            CallPolicy::Fallthrough,
        );

        assert!(matches!(
            result,
            Err(SemanticCfgError::ResourceLimit {
                what: "charged bytes",
                actual: 12,
                limit: 10,
            })
        ));
    }

    #[test]
    fn maximal_thumb_copy_chain_collects_every_definition() {
        const BYTES: usize = 64 * 1024;
        const INSTRUCTIONS: usize = BYTES / 2;
        let mut bytes = Vec::with_capacity(BYTES);
        // movs r0, #1
        bytes.extend_from_slice(&[0x01, 0x20]);
        // mov r0, r0
        for _ in 1..INSTRUCTIONS - 1 {
            bytes.extend_from_slice(&[0x00, 0x46]);
        }
        // bx lr
        bytes.extend_from_slice(&[0x70, 0x47]);
        assert_eq!(bytes.len(), BYTES);

        let cfg = decode(&bytes, DecodeIsa::Thumb);
        let return_pc = u32::try_from(BYTES - 2).unwrap();
        let definitions = cfg.exact_register_states()[&return_pc]
            .get(Register(0))
            .expect("copy chain reaches the return")
            .definitions();

        assert_eq!(cfg.instructions().len(), INSTRUCTIONS);
        assert!(cfg.dominates(0, return_pc));
        assert!(cfg.dominates(return_pc - 2, return_pc));
        assert!(!cfg.dominates(return_pc, return_pc - 2));
        assert_eq!(definitions.len(), INSTRUCTIONS - 1);
        assert_eq!(definitions.first(), Some(&0));
        assert_eq!(definitions.last(), Some(&(return_pc - 2)));
    }
}
