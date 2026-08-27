// PAL-specific proof facade over the shared bounded semantic CFG, plus the
// definition-aware flag/value facts and graph queries the induction proofs
// use. Every node is decoded from the mandatory CFG entry; conditional
// successors must resolve inside the PAL window, and only an explicit
// unconditional direct branch may leave it as a typed external edge.

use crate::arm32::{
    AddressBase, AddressOffset, BranchPredicate, ControlFlow, DecodedInstruction, FlagEffect,
    FlagWriter, InstructionDecoder, ItRangeState, Operand, PureRustDecoder, Shift, ValueEffect,
    ValueExpr,
};
use crate::execution_ranges::DecodeIsa;
use crate::pal_tasks::{CFG_WINDOW_BYTES, semantic_cfg_limits};
use crate::runtime_image::RuntimeImage;
use crate::semantic_cfg::{BoundaryKind, CallPolicy, SemanticCfg};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const THUMB: DecodeIsa = DecodeIsa::Thumb;

/// The visible PC value a PC-relative Thumb expression resolves against.
pub(super) fn visible_pc(pc: u32, align_to_four: bool) -> u32 {
    crate::arm32::visible_pc(pc, align_to_four)
}

/// Wrapping add of an i64 offset onto a u32 address: exact modular
/// arithmetic through the low 32 bits for any offset magnitude.
pub(super) fn wrapping_offset(address: u32, offset: i64) -> u32 {
    crate::arm32::wrapping_offset(address, offset)
}

/// Decode the single Thumb instruction at `pc`, statelessly. Fetch or
/// decode failure yields `None`; callers below the plausibility threshold
/// treat that as a dead position.
pub(super) fn decode_thumb_at(image: &RuntimeImage<'_>, pc: u32) -> Option<DecodedInstruction> {
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(THUMB);
    decode_with(image, &decoder, &mut state, pc)
}

/// Decode one Thumb instruction at `pc`, advancing the caller's IT-range
/// state: a scan over consecutive positions sees predicated flow exactly
/// as the architectural range would.
pub(super) fn decode_with(
    image: &RuntimeImage<'_>,
    decoder: &PureRustDecoder,
    state: &mut ItRangeState,
    pc: u32,
) -> Option<DecodedInstruction> {
    let bytes = match image.read_exact(pc, 4) {
        Ok(bytes) => bytes,
        Err(_) => image.read_exact(pc, 2).ok()?,
    };
    decoder.decode_one(state, THUMB, pc, &bytes).ok()
}

/// Decode the bounded local CFG rooted at `entry`.
///
/// The worklist follows every direct successor under both limits (512
/// address bytes, 256 instructions). Conditional targets and linear
/// fallthroughs must resolve inside the window; an implicit fallthrough
/// at the bound is unresolved. An explicit unconditional direct branch
/// may leave the window as a typed external edge. Barriers (indirect PC
/// writes, table branches, register BLX, IT blocks, and other unresolved
/// flow) reject the candidate, while architectural returns terminate a
/// path. Overlapping instruction extents, unaligned targets, and decode
/// failures also reject. A below-threshold rejection yields `None`.
pub(super) fn decode_entry_rooted_cfg(image: &RuntimeImage<'_>, entry: u32) -> Option<LocalCfg> {
    let end = entry.checked_add(CFG_WINDOW_BYTES)?;
    let semantic = SemanticCfg::decode_with_address_window(
        image,
        entry,
        THUMB,
        semantic_cfg_limits(),
        CallPolicy::Fallthrough,
        Some(CFG_WINDOW_BYTES),
    )
    .ok()?;
    if !semantic.instructions().contains_key(&entry)
        || semantic.handoffs().iter().any(|handoff| {
            matches!(
                handoff.kind,
                BoundaryKind::Call | BoundaryKind::Indirect | BoundaryKind::DecodeFailure
            )
        })
    {
        return None;
    }
    let cfg = LocalCfg { semantic };
    if !cfg.has_only_unconditional_external_exits()
        || cfg.external_edges().iter().any(|(_, target)| {
            // An explicit unconditional branch may leave the local window;
            // an unmapped target inside it remains a failed required decode.
            *target >= entry && *target < end
        })
        || cfg
            .semantic
            .handoffs()
            .iter()
            .filter(|handoff| handoff.kind == BoundaryKind::Unmapped)
            .any(|handoff| {
                !cfg.external_edges()
                    .iter()
                    .any(|(source, _)| *source == handoff.pc)
            })
    {
        return None;
    }
    Some(cfg)
}

/// A local control-flow graph rooted at one unique recognized prologue.
/// Every direct predecessor and successor before the proven join is
/// retained; successors may name external targets that only an explicit
/// unconditional direct branch may reach.
#[derive(Debug, Clone)]
#[allow(dead_code)] // graph queries beyond Task 4's own use are Task 5's proof surface
pub(crate) struct LocalCfg {
    semantic: SemanticCfg,
}

#[allow(dead_code)] // graph queries beyond Task 4's own use are Task 5's proof surface
impl LocalCfg {
    pub(crate) const fn entry(&self) -> u32 {
        self.semantic.entry()
    }

    pub(crate) fn contains_node(&self, pc: u32) -> bool {
        self.semantic.instructions().contains_key(&pc)
    }

    pub(crate) fn instruction(&self, pc: u32) -> Option<&DecodedInstruction> {
        self.semantic.instructions().get(&pc)
    }

    pub(crate) fn instructions(&self) -> impl Iterator<Item = (u32, &'_ DecodedInstruction)> {
        self.semantic
            .instructions()
            .iter()
            .map(|(pc, instruction)| (*pc, instruction))
    }

    pub(crate) fn successors(&self, pc: u32) -> Option<&BTreeSet<u32>> {
        self.semantic.successors(pc)
    }

    pub(crate) fn predecessors(&self, pc: u32) -> &BTreeSet<u32> {
        self.semantic.predecessors(pc)
    }

    pub(crate) fn has_edge(&self, source: u32, target: u32) -> bool {
        self.successors(source)
            .is_some_and(|edges| edges.contains(&target))
    }

    pub(crate) const fn external_edges(&self) -> &BTreeSet<(u32, u32)> {
        self.semantic.external_edges()
    }

    pub(crate) const fn reachable(&self) -> &BTreeSet<u32> {
        self.semantic.reachable()
    }

    pub(crate) fn dominates(&self, dominator: u32, node: u32) -> bool {
        self.semantic.dominates(dominator, node)
    }

    /// Every external edge must originate from an explicit unconditional
    /// direct branch.
    pub(crate) fn has_only_unconditional_external_exits(&self) -> bool {
        self.external_edges().iter().all(|(source, _)| {
            self.instruction(*source).is_some_and(|instruction| {
                matches!(
                    instruction.flow,
                    ControlFlow::DirectBranch {
                        fallthrough: None,
                        predicate: BranchPredicate::Always,
                        ..
                    }
                )
            })
        })
    }

    /// Nodes reachable from `start` without continuing past `stop`.
    pub(crate) fn reachable_until(&self, start: u32, stop: u32) -> BTreeSet<u32> {
        let mut reachable = BTreeSet::from([start]);
        let mut queue = VecDeque::from([start]);
        while let Some(pc) = queue.pop_front() {
            if pc == stop {
                continue;
            }
            for successor in self.successors(pc).into_iter().flatten() {
                if self.contains_node(*successor) && reachable.insert(*successor) {
                    queue.push_back(*successor);
                }
            }
        }
        reachable
    }

    /// Nodes on some path from `start` to `end`.
    pub(crate) fn nodes_on_paths(&self, start: u32, end: u32) -> BTreeSet<u32> {
        self.nodes_on_paths_avoiding(start, end, &BTreeSet::new())
    }

    /// Nodes on some path from `start` to `end` that does not use a
    /// blocked edge.
    pub(crate) fn nodes_on_paths_avoiding(
        &self,
        start: u32,
        end: u32,
        blocked_edges: &BTreeSet<(u32, u32)>,
    ) -> BTreeSet<u32> {
        let mut from_start = BTreeSet::from([start]);
        let mut queue = VecDeque::from([start]);
        while let Some(pc) = queue.pop_front() {
            for successor in self.successors(pc).into_iter().flatten() {
                if blocked_edges.contains(&(pc, *successor)) {
                    continue;
                }
                if from_start.insert(*successor) {
                    queue.push_back(*successor);
                }
            }
        }

        let mut to_end = BTreeSet::from([end]);
        let mut queue = VecDeque::from([end]);
        while let Some(pc) = queue.pop_front() {
            for predecessor in self.predecessors(pc) {
                if blocked_edges.contains(&(*predecessor, pc)) {
                    continue;
                }
                if to_end.insert(*predecessor) {
                    queue.push_back(*predecessor);
                }
            }
        }
        from_start.intersection(&to_end).copied().collect()
    }

    /// Whether the subgraph induced on `nodes` without the blocked edges
    /// is acyclic.
    pub(crate) fn is_acyclic_subgraph(
        &self,
        nodes: &BTreeSet<u32>,
        blocked_edges: &BTreeSet<(u32, u32)>,
    ) -> bool {
        let mut indegrees: BTreeMap<u32, usize> = nodes.iter().map(|pc| (*pc, 0usize)).collect();
        for source in nodes {
            for target in self.successors(*source).into_iter().flatten() {
                if nodes.contains(target) && !blocked_edges.contains(&(*source, *target)) {
                    indegrees.entry(*target).and_modify(|degree| *degree += 1);
                }
            }
        }
        let mut queue: VecDeque<_> = indegrees
            .iter()
            .filter_map(|(pc, degree)| (*degree == 0).then_some(*pc))
            .collect();
        let mut visited = 0usize;
        while let Some(source) = queue.pop_front() {
            visited += 1;
            for target in self.successors(source).into_iter().flatten() {
                if !nodes.contains(target) || blocked_edges.contains(&(source, *target)) {
                    continue;
                }
                let degree = indegrees
                    .get_mut(target)
                    .expect("induced node has a degree");
                *degree -= 1;
                if *degree == 0 {
                    queue.push_back(*target);
                }
            }
        }
        visited == nodes.len()
    }

    /// Whether `end` is reachable from `start` once `blocked_node` is
    /// removed: postdomination by removal.
    pub(crate) fn can_reach_avoiding(&self, start: u32, end: u32, blocked_node: u32) -> bool {
        if start == blocked_node {
            return false;
        }
        let mut visited = BTreeSet::from([start]);
        let mut queue = VecDeque::from([start]);
        while let Some(pc) = queue.pop_front() {
            if pc == end {
                return true;
            }
            for successor in self.successors(pc).into_iter().flatten() {
                if *successor != blocked_node
                    && self.contains_node(*successor)
                    && visited.insert(*successor)
                {
                    queue.push_back(*successor);
                }
            }
        }
        false
    }

    /// The sub-CFG induced on `nodes`: every retained node keeps its
    /// original instruction and successors, with edges to excluded
    /// targets becoming external edges. The entry is the lowest retained
    /// program counter, so the induced theorem is rooted exactly like a
    /// fresh decode of that region.
    pub(crate) fn induced_subgraph(&self, nodes: &BTreeSet<u32>) -> LocalCfg {
        LocalCfg {
            semantic: self.semantic.induced_subgraph(nodes),
        }
    }

    /// Solve the definition-aware dataflow over the graph. Facts merge
    /// only on exact `(value, current definition, root definition)`
    /// triples; NZCV definitions are tracked separately. Direct and
    /// exception call boundaries clobber exactly the volatile contract
    /// the shared decoder reports.
    pub(crate) fn dataflow<'image, 'data>(
        &self,
        image: &'image RuntimeImage<'data>,
        call_results: &'image BTreeMap<u32, u32>,
    ) -> DataflowStates<'_, 'image, 'data> {
        let mut states: BTreeMap<u32, FactState> =
            BTreeMap::from([(self.entry(), FactState::EMPTY)]);
        let mut queue = VecDeque::from([self.entry()]);
        while let Some(pc) = queue.pop_front() {
            let Some(instruction) = self.instruction(pc) else {
                continue;
            };
            let mut output = states[&pc];
            apply_instruction_effect(image, pc, instruction, &mut output, call_results);
            for successor in self.successors(pc).into_iter().flatten() {
                if !self.contains_node(*successor) {
                    continue;
                }
                let merged = match states.get(successor) {
                    None => output,
                    Some(current) => FactState {
                        registers: std::array::from_fn(|register| {
                            (current.registers[register] == output.registers[register])
                                .then_some(current.registers[register])
                                .flatten()
                        }),
                        flags: (current.flags == output.flags)
                            .then_some(current.flags)
                            .flatten(),
                    },
                };
                if states.get(successor) != Some(&merged) {
                    states.insert(*successor, merged);
                    queue.push_back(*successor);
                }
            }
        }
        DataflowStates {
            cfg: self,
            image,
            call_results,
            states,
        }
    }
}

/// One value fact: the concrete value, the instruction that most
/// recently produced it, and the root definition its reaching chain
/// started from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValueFact {
    pub value: u32,
    pub definition: u32,
    pub root: u32,
}

/// One NZCV fact: the instruction whose modeled comparison defined the
/// flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlagFact {
    pub definition: u32,
}

/// Register and flag facts at one program point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FactState {
    pub registers: [Option<ValueFact>; 16],
    pub flags: Option<FlagFact>,
}

impl FactState {
    const EMPTY: FactState = FactState {
        registers: [None; 16],
        flags: None,
    };
}

/// Solved per-instruction fact states for one local CFG.
pub(crate) struct DataflowStates<'cfg, 'image, 'data> {
    cfg: &'cfg LocalCfg,
    image: &'image RuntimeImage<'data>,
    call_results: &'image BTreeMap<u32, u32>,
    states: BTreeMap<u32, FactState>,
}

impl DataflowStates<'_, '_, '_> {
    /// The fact state on entry to the instruction at `pc`.
    pub(crate) fn before(&self, pc: u32) -> Option<&FactState> {
        self.states.get(&pc)
    }

    /// The fact state after the instruction at `pc` executes.
    pub(crate) fn after(&self, pc: u32) -> Option<FactState> {
        let mut state = *self.states.get(&pc)?;
        let instruction = self.cfg.instruction(pc)?;
        apply_instruction_effect(self.image, pc, instruction, &mut state, self.call_results);
        Some(state)
    }
}

fn apply_instruction_effect(
    image: &RuntimeImage<'_>,
    pc: u32,
    instruction: &DecodedInstruction,
    state: &mut FactState,
    call_results: &BTreeMap<u32, u32>,
) {
    if let Some(boundary) = instruction.flow.call_boundary(instruction.links_lr) {
        for register in &boundary.volatile {
            if let Some(fact) = state.registers.get_mut(usize::from(register.0)) {
                *fact = None;
            }
        }
        if boundary.flags_unknown {
            state.flags = None;
        }
        if let ControlFlow::DirectCall { target } = instruction.flow
            && let Some(value) = call_results.get(&target)
        {
            state.registers[0] = Some(ValueFact {
                value: *value,
                definition: pc,
                root: pc,
            });
        }
        return;
    }

    // A predicated instruction may or may not perform its writes; its
    // written registers and flags become unknown.
    let predicated = instruction.conditional && matches!(instruction.flow, ControlFlow::Linear);
    match &instruction.effect {
        ValueEffect::RegisterWrite { dst, value } => {
            state.registers[usize::from(dst.0)] = if predicated {
                None
            } else {
                evaluate_value_expr(pc, value, state)
            };
        }
        ValueEffect::Shift { dst, source, shift } => {
            state.registers[usize::from(dst.0)] = match (predicated, shift) {
                (false, Shift::Lsr(amount)) => state.registers[usize::from(source.0)].map(|fact| {
                    let value = if *amount >= 32 {
                        0
                    } else {
                        fact.value >> *amount
                    };
                    ValueFact {
                        value,
                        definition: pc,
                        root: fact.root,
                    }
                }),
                _ => None,
            };
        }
        ValueEffect::LiteralWordLoad { dst, address } => {
            state.registers[usize::from(dst.0)] = if predicated {
                None
            } else {
                resolve_literal_word(image, pc, address).map(|value| ValueFact {
                    value,
                    definition: pc,
                    root: pc,
                })
            };
        }
        ValueEffect::Memory(_) => {
            // Loaded destinations and address writeback bases become
            // unknown; stores leave register facts untouched.
            for register in &instruction.writes {
                state.registers[usize::from(register.0)] = None;
            }
        }
        ValueEffect::Compare { .. } | ValueEffect::None => {}
        ValueEffect::Unsupported => {
            for register in &instruction.writes {
                state.registers[usize::from(register.0)] = None;
            }
        }
    }

    state.flags = match instruction.flags {
        FlagEffect::Written(FlagWriter::Compare) => {
            (!predicated).then_some(FlagFact { definition: pc })
        }
        FlagEffect::Clobbered => None,
        FlagEffect::Preserved => state.flags,
    };
}

fn evaluate_value_expr(pc: u32, expr: &ValueExpr, state: &FactState) -> Option<ValueFact> {
    match expr {
        ValueExpr::Immediate(value) => Some(ValueFact {
            value: *value,
            definition: pc,
            root: pc,
        }),
        ValueExpr::Register(source) => {
            state.registers[usize::from(source.0)].map(|fact| ValueFact {
                value: fact.value,
                definition: pc,
                root: fact.root,
            })
        }
        ValueExpr::ReplaceHighHalf { source, high } => {
            state.registers[usize::from(source.0)].map(|fact| ValueFact {
                value: (u32::from(*high) << 16) | (fact.value & 0xffff),
                definition: pc,
                root: fact.root,
            })
        }
        ValueExpr::Add {
            left,
            right: Operand::Immediate(addend),
        } => state.registers[usize::from(left.0)].and_then(|fact| {
            fact.value.checked_add(*addend).map(|value| ValueFact {
                value,
                definition: pc,
                root: fact.root,
            })
        }),
        ValueExpr::Sub {
            left,
            right: Operand::Immediate(subtrahend),
        } => state.registers[usize::from(left.0)].and_then(|fact| {
            fact.value.checked_sub(*subtrahend).map(|value| ValueFact {
                value,
                definition: pc,
                root: fact.root,
            })
        }),
        ValueExpr::ArchitecturalPc {
            addend,
            align_to_four,
        } => Some(ValueFact {
            value: wrapping_offset(visible_pc(pc, *align_to_four), *addend),
            definition: pc,
            root: pc,
        }),
        ValueExpr::Add { .. } | ValueExpr::Sub { .. } => None,
    }
}

fn resolve_literal_word(
    image: &RuntimeImage<'_>,
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
    image.read_u32(literal).ok()
}

#[cfg(test)]
mod tests {
    use crate::pal_tasks::cfg::{FactState, FlagFact, ValueFact, decode_entry_rooted_cfg};
    use crate::pal_tasks::discover::unique_prologue_root;
    use crate::runtime_image::RuntimeImage;
    use scaleservers_arm32_assembly::{
        Arm32Condition, Arm32GeneralPurposeRegister as Gpr, Arm32LowGeneralPurposeRegister as Low,
        ArmT32Instruction as T32,
    };
    use std::collections::{BTreeMap, BTreeSet};

    const BASE: u32 = 0x1000;

    fn raw_image(bytes: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(bytes, BASE, None).expect("raw fixture image")
    }

    fn enc(instruction: &T32) -> Vec<u8> {
        instruction.encode().expect("fixture encodes")
    }

    fn put(bytes: &mut [u8], offset: usize, part: &[u8]) {
        bytes[offset..offset + part.len()].copy_from_slice(part);
    }

    fn gpr(number: u8) -> Gpr {
        Gpr::from_operand_bits(number)
    }

    fn low(number: u8) -> Low {
        Low::from_operand_bits(number)
    }

    fn nops(count: usize) -> Vec<Vec<u8>> {
        vec![enc(&T32::Nop_T1); count]
    }

    fn assemble(len: usize, parts: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        for (offset, part) in parts {
            put(&mut bytes, *offset, part);
        }
        bytes
    }

    #[test]
    fn exactly_one_prologue_must_decode_linearly_to_reference() {
        // Exactly one recognized prologue decodes linearly onto the
        // reference at 0x1004.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Nop_T1)),
                (0x04, enc(&T32::Adr_T1(low(1), 0x08))),
            ],
        );
        assert_eq!(
            unique_prologue_root(&raw_image(&bytes), BASE + 0x04),
            Some(BASE)
        );

        // Two prologues reaching the reference leave no unique root.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(14)]))),
                (0x02, enc(&T32::Nop_T1)),
                (0x04, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x06, enc(&T32::Nop_T1)),
                (0x08, enc(&T32::Adr_T1(low(1), 0x04))),
            ],
        );
        assert_eq!(unique_prologue_root(&raw_image(&bytes), BASE + 0x08), None);

        // No prologue at all.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Nop_T1)),
                (0x02, enc(&T32::Nop_T1)),
                (0x04, enc(&T32::Adr_T1(low(1), 0x08))),
            ],
        );
        assert_eq!(unique_prologue_root(&raw_image(&bytes), BASE + 0x04), None);

        // A prologue whose linear decode overruns the reference does not
        // reach it exactly.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Mov_Immediate_T3(gpr(0), 1))),
                (0x06, enc(&T32::Mov_Immediate_T3(gpr(0), 1))),
                (0x08, enc(&T32::Adr_T1(low(1), 0x04))),
            ],
        );
        assert_eq!(unique_prologue_root(&raw_image(&bytes), BASE + 0x08), None);
    }

    #[test]
    fn cfg_follows_both_conditional_successors_and_direct_targets() {
        let bytes = assemble(
            0x28,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                // r1 receives a PC-relative fact on every path.
                (0x02, enc(&T32::Adr_T1(low(1), 0x20))),
                // cbz keeps both the target and the fallthrough.
                (0x04, enc(&T32::Cbz_T1(low(0), 0x10))),
                // The fallthrough path alone defines r2.
                (0x06, enc(&T32::Adr_T1(low(2), 0x10))),
                // A direct branch contributes only its target.
                (0x08, enc(&T32::B_T2(0x0c))),
                (0x0a, enc(&T32::Nop_T1)),
                (0x18, enc(&T32::Bx_T1(gpr(14)))),
            ],
        );
        let cfg = decode_entry_rooted_cfg(&raw_image(&bytes), BASE).expect("fixture cfg decodes");

        let conditional: BTreeSet<u32> = BTreeSet::from([BASE + 0x06, BASE + 0x18]);
        assert_eq!(cfg.successors(BASE + 0x04), Some(&conditional));
        let direct: BTreeSet<u32> = BTreeSet::from([BASE + 0x18]);
        assert_eq!(cfg.successors(BASE + 0x08), Some(&direct));
        let join_predecessors: BTreeSet<u32> = BTreeSet::from([BASE + 0x04, BASE + 0x08]);
        assert_eq!(cfg.predecessors(BASE + 0x18), &join_predecessors);
        assert!(cfg.dominates(BASE, BASE + 0x18));
        assert!(!cfg.dominates(BASE + 0x06, BASE + 0x18));

        // Definition-aware dataflow: r1's fact survives the join while
        // r2's path-local fact merges with absence and is lost.
        let image = raw_image(&bytes);
        let no_call_results = BTreeMap::new();
        let states = cfg.dataflow(&image, &no_call_results);
        let before_join = states.before(BASE + 0x18).expect("join state");
        assert_eq!(
            before_join.registers[1],
            Some(ValueFact {
                value: BASE + 0x24,
                definition: BASE + 0x02,
                root: BASE + 0x02,
            })
        );
        assert_eq!(before_join.registers[2], None);
        let on_fallthrough = states.before(BASE + 0x08).expect("fallthrough state");
        assert_eq!(
            on_fallthrough.registers[2],
            Some(ValueFact {
                value: BASE + 0x18,
                definition: BASE + 0x06,
                root: BASE + 0x06,
            })
        );
    }

    #[test]
    fn missing_target_truncated_fallthrough_overlap_or_pc_write_rejects() {
        // A conditional target outside the window is a missing direct
        // successor.
        let bytes = assemble(
            0x08,
            &[
                (0x00, enc(&T32::B_T1(Arm32Condition::NotEqual, -6))),
                (0x02, enc(&T32::Bx_T1(gpr(14)))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());

        // A wide instruction overrunning the 512-byte window bound is a
        // truncated fallthrough: 255 nops reach 0x11FE and the wide
        // instruction would end past 0x1200.
        let mut parts: Vec<(usize, Vec<u8>)> = nops(255)
            .into_iter()
            .enumerate()
            .map(|(index, nop)| (index * 2, nop))
            .collect();
        parts.push((0x1fe, enc(&T32::Add_Immediate_T3(gpr(4), gpr(4), 1, false))));
        let bytes = assemble(0x220, &parts);
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());

        // A branch into the middle of a wide instruction produces
        // overlapping extents.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Add_Immediate_T3(gpr(4), gpr(4), 1, false))),
                (0x04, enc(&T32::B_T2(-6))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());

        // A PC write is an unresolved barrier on the required path.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Adr_T1(low(1), 0x08))),
                (0x04, enc(&T32::Pop_T1(vec![gpr(4), gpr(15)]))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());

        // A table branch is an unresolved barrier.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Adr_T1(low(1), 0x08))),
                (0x04, enc(&T32::Tbb_T1(gpr(1), gpr(2)))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());

        // An IT block opens predicated flow the bounded proof cannot
        // resolve.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Adr_T1(low(1), 0x08))),
                (0x04, enc(&T32::It_T1(Arm32Condition::Equal, 0b1000))),
                (0x06, enc(&T32::Mov_Immediate_T1(low(0), 1))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());
    }

    #[test]
    fn unaligned_entry_target_rejects_the_cfg() {
        // Unaligned-target rejection: the entry is the first decode
        // target, and a hand-assembled prologue reached at an odd entry
        // is rejected before any byte decodes. Every Thumb branch form
        // the decoder maps scales its displacement in halfwords, so
        // encoded successors are always even; the successor parity
        // check inside the walk is the defensive backstop for that
        // invariant.
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Bx_T1(gpr(14)))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_some());
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE + 1).is_none());
    }

    #[test]
    fn svc_falls_through_but_invalidates_only_volatile_facts() {
        let bytes = assemble(
            0x10,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Adr_T1(low(4), 0x18))),
                (0x04, enc(&T32::Adr_T1(low(1), 0x18))),
                (0x06, enc(&T32::Adr_T1(low(0), 0x18))),
                (0x08, enc(&T32::Cmp_Immediate_T1(low(6), 3))),
                (0x0a, enc(&T32::Svc_T1(0))),
                (0x0c, enc(&T32::Bx_T1(gpr(14)))),
            ],
        );
        let image = raw_image(&bytes);
        let cfg = decode_entry_rooted_cfg(&image, BASE).expect("svc fixture decodes");

        // The exception call keeps its architectural return site.
        let fallthrough: BTreeSet<u32> = BTreeSet::from([BASE + 0x0c]);
        assert_eq!(cfg.successors(BASE + 0x0a), Some(&fallthrough));

        let no_call_results = BTreeMap::new();
        let states = cfg.dataflow(&image, &no_call_results);
        // The compare defines NZCV.
        assert_eq!(
            states.after(BASE + 0x08).unwrap().flags,
            Some(FlagFact {
                definition: BASE + 0x08
            })
        );
        // After the exception call only nonvolatile facts survive.
        let after_svc: FactState = states.after(BASE + 0x0a).unwrap();
        assert_eq!(
            after_svc.registers[4],
            Some(ValueFact {
                value: BASE + 0x1c,
                definition: BASE + 0x02,
                root: BASE + 0x02,
            })
        );
        assert_eq!(after_svc.registers[1], None);
        assert_eq!(after_svc.registers[0], None);
        assert_eq!(after_svc.flags, None);
        // The surviving fact is still available at the return.
        assert_eq!(
            states.before(BASE + 0x0c).unwrap().registers[4],
            Some(ValueFact {
                value: BASE + 0x1c,
                definition: BASE + 0x02,
                root: BASE + 0x02,
            })
        );
    }

    #[test]
    fn explicit_post_join_unconditional_exit_is_the_only_external_edge() {
        let bytes = assemble(
            0x20,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Adr_T1(low(1), 0x10))),
                (0x04, enc(&T32::B_T1(Arm32Condition::Equal, 4))),
                (0x06, enc(&T32::Nop_T1)),
                (0x08, enc(&T32::B_T2(0))),
                (0x0c, enc(&T32::Nop_T1)),
                // Post-join explicit exit far outside the window.
                (0x0e, enc(&T32::B_T4(0x2ee))),
            ],
        );
        let cfg = decode_entry_rooted_cfg(&raw_image(&bytes), BASE)
            .expect("external exit fixture decodes");
        assert_eq!(
            cfg.external_edges(),
            &BTreeSet::from([(BASE + 0x0e, 0x1300)])
        );
        assert!(cfg.has_only_unconditional_external_exits());

        // A conditional target outside the window is not an admissible
        // external edge.
        let bytes = assemble(
            0x20,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x04, enc(&T32::B_T3(Arm32Condition::Equal, 0x2f8))),
            ],
        );
        assert!(decode_entry_rooted_cfg(&raw_image(&bytes), BASE).is_none());
    }

    #[test]
    fn induced_subgraph_keeps_internal_edges_and_externalizes_exits() {
        let bytes = assemble(
            0x20,
            &[
                (0x00, enc(&T32::Push_T1(vec![gpr(4), gpr(14)]))),
                (0x02, enc(&T32::Adr_T1(low(1), 0x10))),
                // A conditional split whose arms rejoin at the return.
                (0x04, enc(&T32::B_T1(Arm32Condition::Equal, 4))),
                (0x06, enc(&T32::Nop_T1)),
                (0x08, enc(&T32::B_T2(0))),
                (0x0c, enc(&T32::Bx_T1(gpr(14)))),
            ],
        );
        let cfg = decode_entry_rooted_cfg(&raw_image(&bytes), BASE).expect("fixture decodes");
        let region = BTreeSet::from([BASE + 0x04, BASE + 0x06, BASE + 0x08]);
        let induced = cfg.induced_subgraph(&region);
        assert_eq!(induced.entry(), BASE + 0x04);
        assert!(induced.contains_node(BASE + 0x08));
        assert!(!induced.contains_node(BASE + 0x0c));
        // Both conditional successors stay edges of the region.
        assert!(induced.has_edge(BASE + 0x04, BASE + 0x0c));
        assert!(induced.has_edge(BASE + 0x04, BASE + 0x06));
        assert!(induced.has_edge(BASE + 0x08, BASE + 0x0c));
        // The excluded join becomes an external edge of the region.
        assert_eq!(
            induced.external_edges(),
            &BTreeSet::from([(BASE + 0x04, BASE + 0x0c), (BASE + 0x08, BASE + 0x0c)])
        );
        // Dominance is proven inside the induced region alone: the
        // region entry dominates, the CFG root does not.
        assert!(induced.dominates(BASE + 0x04, BASE + 0x08));
        assert!(!induced.dominates(BASE, BASE + 0x08));
    }
}
