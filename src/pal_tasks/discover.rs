// Bounded anchor materialization sweep, unique-prologue root selection,
// and initializer proof assembly over the runtime image. One image-wide
// halfword-aligned Thumb sweep resolves every anchor reference for the
// complete anchor set; the counting-loop, dual-exit, suffix, and
// slot-base proofs then run over each entry-rooted local CFG, matching
// decoded operand relationships rather than instruction windows.

use crate::arm32::{
    AccessKind, AddressBase, AddressExpr, AddressOffset, BranchPredicate, CompareOp, ControlFlow,
    DecodedInstruction, FlagEffect, FlagWriter, InstructionDecoder, Operand, PureRustDecoder,
    Register, Shift, ValueEffect, ValueExpr,
};
use crate::execution_ranges::DecodeIsa;
use crate::pal_tasks::cfg::{
    DataflowStates, LocalCfg, ValueFact, decode_entry_rooted_cfg, decode_thumb_at, decode_with,
    visible_pc, wrapping_offset,
};
use crate::pal_tasks::table;
use crate::pal_tasks::{
    ANCHOR_PATTERN, AnchorCfgCandidate, AnchorProofPath, AnchorProvenance, AnchorReference,
    AnchorReferenceKind, CandidateBudget, CapacityGuard, DESCRIPTOR_PROJECTION_OFFSET,
    InitializerCandidate, InitializerEvidence, MAX_ANCHOR_OCCURRENCES,
    MAX_ANCHOR_REFERENCE_DISTANCE, MAX_ANCHOR_REFERENCES, MAX_CANDIDATE_TUPLES,
    MAX_MOVW_MOVT_SPAN_INSTRUCTIONS, MAX_SLOT_LEAF_INSTRUCTIONS, PROLOGUE_WINDOW_BYTES,
    PalTaskError, TaskPlan, TaskTableGeometry,
};
use crate::runtime_image::{MAX_EXACT_READ, RuntimeImage, StorageSpan};
use scaleservers_arm32_assembly::Arm32Condition;
use std::collections::{BTreeMap, BTreeSet};

const THUMB: DecodeIsa = DecodeIsa::Thumb;
const SP: Register = Register(13);
const LR: Register = Register(14);

/// Discover every anchor-reference candidate: one entry per semantic
/// reference that survives unique-prologue root selection and bounded
/// CFG closure. Below-threshold misses are skipped; named resource
/// limits and runtime failures are typed errors.
pub(super) fn discover_anchor_cfg(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Vec<AnchorCfgCandidate>, PalTaskError> {
    let anchors = find_anchor_occurrences(image, label)?;
    if anchors.is_empty() {
        return Ok(Vec::new());
    }
    let references = find_anchor_references(image, label, &anchors)?;
    let mut candidates = Vec::new();
    for reference in references {
        let Some(initializer) = unique_prologue_root(image, reference.pc) else {
            continue;
        };
        let Some(cfg) = decode_entry_rooted_cfg(image, initializer) else {
            continue;
        };
        if !cfg.has_only_unconditional_external_exits() || !cfg.contains_node(reference.pc) {
            continue;
        }
        let anchor_storage = anchors
            .iter()
            .find(|anchor| anchor.address == reference.anchor)
            .map(|anchor| anchor.storage.clone())
            .unwrap_or_default();
        candidates.push(AnchorCfgCandidate {
            anchor: reference.anchor,
            anchor_storage,
            reference,
            initializer,
            cfg,
        });
    }
    Ok(candidates)
}

/// The final discovery boundary: prove every initializer candidate,
/// table-validate each against one shared non-refundable budget, and
/// return the single complete plan. No plausible survivor is
/// `Ok(None)`; a plausible candidate that then fails is the contextual
/// error even when a sibling validates; several complete survivors
/// report every initializer/slot-base pair.
pub(super) fn discover(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Option<TaskPlan>, PalTaskError> {
    let mut budget = CandidateBudget::default();
    let candidates = discover_initializer_candidates_bounded(image, label, &mut budget)?;
    let (image_base, image_size) = image.image_bounds();
    let mut plans = Vec::new();
    for candidate in &candidates {
        if let Some(validated) = table::validate_candidate(image, label, candidate, &mut budget)? {
            plans.push(TaskPlan {
                image_base,
                image_size,
                initializer: candidate.evidence.clone(),
                table: validated.table,
                tasks: validated.tasks,
                applications: validated.applications,
                terminal: validated.terminal,
            });
        }
    }
    match plans.len() {
        0 => Ok(None),
        1 => Ok(plans.pop()),
        _ => Err(PalTaskError::Ambiguous {
            candidates: plans
                .iter()
                .map(|plan| (plan.initializer.cfg_entry, plan.table.slot_base))
                .collect(),
        }),
    }
}

/// One exact `PALTskTm\0` occurrence with its nine-byte storage
/// provenance.
pub(super) struct AnchorOccurrence {
    pub address: u32,
    pub storage: Vec<StorageSpan>,
}

/// Discover every plausible initializer candidate over the anchor CFG
/// candidates, charging table/name/instruction work against one shared
/// non-refundable budget. Topology misses are skipped below the
/// plausibility threshold; competing CFG roots stay separate
/// candidates; named resource limits are typed errors.
pub(super) fn discover_initializer_candidates_bounded(
    image: &RuntimeImage<'_>,
    label: &str,
    budget: &mut CandidateBudget,
) -> std::result::Result<Vec<InitializerCandidate>, PalTaskError> {
    let mut candidates = Vec::new();
    for anchor_cfg in discover_anchor_cfg(image, label)? {
        if let Some(candidate) = prove_initializer(image, label, &anchor_cfg, budget)? {
            merge_initializer_candidate(&mut candidates, candidate)?;
        }
    }
    Ok(candidates)
}

/// One matched counting loop: the load head with its decoded operand
/// relationships.
#[derive(Debug)]
struct CountingLoop {
    loop_start: u32,
    terminal: u32,
    backedge: u32,
    capacity_exit: u32,
    count_zero_definition: u32,
    slot_register: Register,
    count_register: Register,
    name_offset: u32,
    index_offset: u32,
    stride: u32,
    capacity: u32,
}

/// One matched suffix induction loop with its declared join.
#[derive(Debug)]
struct SuffixLoop {
    loop_start: u32,
    join: u32,
}

/// The proven dual exits: the shared count global, the capacity guard,
/// the suffix loop, and the common join.
#[derive(Debug)]
struct ExitProof {
    count_global: u32,
    guard: CapacityGuard,
    suffix_loop: u32,
    join: u32,
}

/// Prove one anchor CFG candidate or skip it below the plausibility
/// threshold. Every rejection here is a miss (`Ok(None)`); malformed
/// evidence is only possible after the first slot becomes readable, in
/// the table stage.
fn prove_initializer(
    image: &RuntimeImage<'_>,
    label: &str,
    anchor_cfg: &AnchorCfgCandidate,
    budget: &mut CandidateBudget,
) -> std::result::Result<Option<InitializerCandidate>, PalTaskError> {
    let cfg = &anchor_cfg.cfg;
    let Some(counting) = match_counting_loop(cfg) else {
        return Ok(None);
    };
    let call_results = evaluate_leaf_calls(image, cfg, budget)?;
    let states = cfg.dataflow(image, &call_results);
    let Some(call) = find_anchor_call(cfg, &anchor_cfg.reference, &states) else {
        return Ok(None);
    };
    if !cfg.dominates(call, counting.loop_start) {
        return Ok(None);
    }
    let Some(preheader) = unique_preheader(cfg, &counting) else {
        return Ok(None);
    };
    let Some(initial) = states.after(preheader) else {
        return Ok(None);
    };
    let Some(count_fact) = initial.registers[usize::from(counting.count_register.0)] else {
        return Ok(None);
    };
    if count_fact.value != 0 || count_fact.root != counting.count_zero_definition {
        return Ok(None);
    }
    let Some(slot_fact) = initial.registers[usize::from(counting.slot_register.0)] else {
        return Ok(None);
    };
    if !slot_base_form_supported(cfg, counting.slot_register, &slot_fact) {
        return Ok(None);
    }
    let Some(exits) = find_exit_evidence(cfg, &counting, &states) else {
        return Ok(None);
    };
    if counting
        .name_offset
        .checked_sub(DESCRIPTOR_PROJECTION_OFFSET)
        .is_none()
    {
        return Ok(None);
    }
    let slot_base = slot_fact.value;
    let evidence = InitializerEvidence {
        cfg_entry: anchor_cfg.initializer,
        proof_paths: vec![AnchorProofPath {
            anchor: anchor_cfg.reference.anchor,
            reference: anchor_cfg.reference.clone(),
            call,
        }],
        anchors: vec![AnchorProvenance {
            address: anchor_cfg.reference.anchor,
            storage: anchor_cfg.anchor_storage.clone(),
        }],
        code_storage: code_storage_spans(image, label, cfg)?,
        loop_start: counting.loop_start,
        count_zero_definition: counting.count_zero_definition,
        slot_definition: slot_fact.root,
        normal_exit: counting.terminal,
        capacity_exit: counting.capacity_exit,
        capacity_guard: exits.guard,
        suffix_loop: exits.suffix_loop,
        join: exits.join,
        count_global: exits.count_global,
        slot_base,
        name_offset: counting.name_offset,
        index_offset: counting.index_offset,
        stride: counting.stride,
        capacity: counting.capacity,
    };
    let geometry = TaskTableGeometry {
        slot_base,
        name_offset: counting.name_offset,
        index_offset: counting.index_offset,
        stride: counting.stride,
        capacity: counting.capacity,
    };
    Ok(Some(InitializerCandidate { evidence, geometry }))
}

/// The single predecessor of the loop head that is not the backedge.
fn unique_preheader(cfg: &LocalCfg, counting: &CountingLoop) -> Option<u32> {
    let mut preheaders = cfg
        .predecessors(counting.loop_start)
        .iter()
        .copied()
        .filter(|predecessor| *predecessor != counting.backedge);
    let preheader = preheaders.next()?;
    preheaders.next().is_none().then_some(preheader)
}

/// Storage provenance of every decoded instruction extent, merging
/// adjacent extents into contiguous runs.
fn code_storage_spans(
    image: &RuntimeImage<'_>,
    label: &str,
    cfg: &LocalCfg,
) -> std::result::Result<Vec<StorageSpan>, PalTaskError> {
    let mut spans = Vec::new();
    let mut run: Option<(u32, u32)> = None;
    for (pc, instruction) in cfg.instructions() {
        let Some(end) = pc.checked_add(u32::from(instruction.length)) else {
            return Err(PalTaskError::Runtime {
                address: pc,
                size: u32::from(instruction.length),
                reason: format!("{label}: decoded instruction extent wraps the address space"),
            });
        };
        match run {
            Some((start, run_end)) if pc == run_end => run = Some((start, end)),
            Some((start, run_end)) => {
                let size = run_end - start;
                spans.extend(
                    image
                        .storage_spans(start, size)
                        .map_err(|error| runtime_error(label, start, size, error))?,
                );
                run = Some((pc, end));
            }
            None => run = Some((pc, end)),
        }
    }
    if let Some((start, run_end)) = run {
        let size = run_end - start;
        spans.extend(
            image
                .storage_spans(start, size)
                .map_err(|error| runtime_error(label, start, size, error))?,
        );
    }
    Ok(spans)
}

/// Whether an instruction provably writes (or provably does not write)
/// one register. Unmodeled effects and predicated writes are unknown.
fn register_write(instruction: &DecodedInstruction, register: Register) -> Option<bool> {
    if instruction.conditional && matches!(instruction.flow, ControlFlow::Linear) {
        return None;
    }
    if let Some(boundary) = instruction.flow.call_boundary(instruction.links_lr) {
        return Some(boundary.volatile.contains(&register));
    }
    match &instruction.effect {
        ValueEffect::RegisterWrite { dst, .. }
        | ValueEffect::Shift { dst, .. }
        | ValueEffect::LiteralWordLoad { dst, .. } => Some(*dst == register),
        ValueEffect::Memory(effect) => Some(
            effect
                .writeback
                .as_ref()
                .is_some_and(|(base, _)| *base == register)
                || effect.transfers.iter().any(|transfer| {
                    transfer.kind != AccessKind::Write && transfer.value == Some(register)
                }),
        ),
        ValueEffect::Compare { .. } | ValueEffect::None => Some(false),
        // An unmodeled effect whose decoded write set is empty (hints
        // such as NOP) provably writes no core register; any other
        // unmodeled effect is unknown.
        ValueEffect::Unsupported if instruction.writes.is_empty() => Some(false),
        ValueEffect::Unsupported => None,
    }
}

/// Whether an instruction provably writes (or provably preserves) NZCV.
fn writes_flags(instruction: &DecodedInstruction) -> Option<bool> {
    if instruction.conditional && matches!(instruction.flow, ControlFlow::Linear) {
        return None;
    }
    match instruction.effect {
        ValueEffect::Unsupported => None,
        _ => match instruction.flags {
            FlagEffect::Written(_) | FlagEffect::Clobbered => Some(true),
            FlagEffect::Preserved => Some(false),
        },
    }
}

/// The decoded `[slot + offset]` word load shape.
fn name_load(instruction: &DecodedInstruction) -> Option<(Register, Register, u32)> {
    let ValueEffect::Memory(effect) = &instruction.effect else {
        return None;
    };
    if effect.writeback.is_some() || effect.transfers.len() != 1 {
        return None;
    }
    let transfer = &effect.transfers[0];
    if transfer.kind != AccessKind::Read || transfer.width != 4 {
        return None;
    }
    let AddressExpr {
        base: AddressBase::Register(base),
        offset: AddressOffset::Immediate(offset),
    } = &transfer.address
    else {
        return None;
    };
    let destination = transfer.value?;
    u32::try_from(*offset)
        .ok()
        .map(|offset| (destination, *base, offset))
}

/// The decoded `store source, [slot + offset]` word shape.
fn index_store(instruction: &DecodedInstruction, slot: Register) -> Option<(Register, u32)> {
    let ValueEffect::Memory(effect) = &instruction.effect else {
        return None;
    };
    if effect.writeback.is_some() || effect.transfers.len() != 1 {
        return None;
    }
    let transfer = &effect.transfers[0];
    if transfer.kind != AccessKind::Write || transfer.width != 4 {
        return None;
    }
    let AddressExpr {
        base: AddressBase::Register(base),
        offset: AddressOffset::Immediate(offset),
    } = &transfer.address
    else {
        return None;
    };
    if *base != slot {
        return None;
    }
    let source = transfer.value?;
    u32::try_from(*offset).ok().map(|offset| (source, offset))
}

/// The decoded `register += immediate` shape, returning the addend.
fn immediate_add(instruction: &DecodedInstruction, register: Register) -> Option<u32> {
    let ValueEffect::RegisterWrite {
        dst,
        value:
            ValueExpr::Add {
                left,
                right: Operand::Immediate(addend),
            },
    } = &instruction.effect
    else {
        return None;
    };
    (*dst == register && *left == register).then_some(*addend)
}

/// The decoded `compare register, immediate` shape with a modeled NZCV
/// definition, returning the compared value.
fn capacity_compare(instruction: &DecodedInstruction, register: Register) -> Option<u32> {
    if instruction.flags != FlagEffect::Written(FlagWriter::Compare) {
        return None;
    }
    let ValueEffect::Compare {
        operation: CompareOp::Subtract,
        left,
        right: Operand::Immediate(value),
    } = &instruction.effect
    else {
        return None;
    };
    (*left == register).then_some(*value)
}

/// Whether a branch keeps taking its backedge while a subtraction is
/// unequal.
fn is_unequal_backedge(flow: ControlFlow) -> bool {
    matches!(
        flow,
        ControlFlow::DirectBranch {
            predicate: BranchPredicate::Condition(Arm32Condition::NotEqual),
            ..
        }
    )
}

/// The decoded `store source, [base]` word shape at offset zero.
fn zero_offset_store(instruction: &DecodedInstruction) -> Option<(Register, Register)> {
    let ValueEffect::Memory(effect) = &instruction.effect else {
        return None;
    };
    if effect.writeback.is_some() || effect.transfers.len() != 1 {
        return None;
    }
    let transfer = &effect.transfers[0];
    if transfer.kind != AccessKind::Write || transfer.width != 4 {
        return None;
    }
    let AddressExpr {
        base: AddressBase::Register(base),
        offset: AddressOffset::Immediate(0),
    } = &transfer.address
    else {
        return None;
    };
    Some((transfer.value?, *base))
}

/// Match the counting loop over decoded relationships: a name load, a
/// zero branch to the terminal, an index store of the count, one count
/// increment, one positive slot stride, a capacity compare, and an
/// unequal backedge to the load. Register identities and immediates are
/// decoded, never fixed.
fn match_counting_loop(cfg: &LocalCfg) -> Option<CountingLoop> {
    for (loop_start, instruction) in cfg.instructions() {
        let Some((name_register, slot_register, name_offset)) = name_load(instruction) else {
            continue;
        };
        let Some(branch_pc) = loop_start.checked_add(u32::from(instruction.length)) else {
            continue;
        };
        let Some(branch) = cfg.instruction(branch_pc) else {
            continue;
        };
        let ControlFlow::DirectBranch {
            target: terminal,
            predicate:
                BranchPredicate::RegisterZero {
                    register,
                    nonzero: false,
                },
            ..
        } = branch.flow
        else {
            continue;
        };
        if register != name_register {
            continue;
        }
        let Some(store_pc) = branch_pc.checked_add(u32::from(branch.length)) else {
            continue;
        };
        let Some(store) = cfg.instruction(store_pc) else {
            continue;
        };
        let Some((count_register, index_offset)) = index_store(store, slot_register) else {
            continue;
        };
        let Some(adder_pc) = store_pc.checked_add(u32::from(store.length)) else {
            continue;
        };
        let Some(adder) = cfg.instruction(adder_pc) else {
            continue;
        };
        let Some(1) = immediate_add(adder, count_register) else {
            continue;
        };
        let Some(stride_pc) = adder_pc.checked_add(u32::from(adder.length)) else {
            continue;
        };
        let Some(strider) = cfg.instruction(stride_pc) else {
            continue;
        };
        let Some(stride) = immediate_add(strider, slot_register) else {
            continue;
        };
        let Some(compare_pc) = stride_pc.checked_add(u32::from(strider.length)) else {
            continue;
        };
        let Some(comparer) = cfg.instruction(compare_pc) else {
            continue;
        };
        let Some(capacity) = capacity_compare(comparer, count_register) else {
            continue;
        };
        let Some(backedge_pc) = compare_pc.checked_add(u32::from(comparer.length)) else {
            continue;
        };
        let Some(backedge) = cfg.instruction(backedge_pc) else {
            continue;
        };
        let ControlFlow::DirectBranch {
            target,
            fallthrough: Some(capacity_exit),
            ..
        } = backedge.flow
        else {
            continue;
        };
        if target != loop_start
            || !is_unequal_backedge(backedge.flow)
            || name_offset == 0
            || stride == 0
            || capacity == 0
        {
            continue;
        }
        let Some(count_zero_definition) =
            count_zero_reaching_loop_head(cfg, loop_start, backedge_pc, count_register)
        else {
            continue;
        };
        return Some(CountingLoop {
            loop_start,
            terminal,
            backedge: backedge_pc,
            capacity_exit,
            count_zero_definition,
            slot_register,
            count_register,
            name_offset,
            index_offset,
            stride,
            capacity,
        });
    }
    None
}

/// The unique dominating count zero root whose value reaches the loop
/// head on every path that avoids the backedge, with no count write in
/// between.
fn count_zero_reaching_loop_head(
    cfg: &LocalCfg,
    loop_start: u32,
    backedge: u32,
    count: Register,
) -> Option<u32> {
    let blocked = BTreeSet::from([(backedge, loop_start)]);
    let mut definitions = Vec::new();
    for (pc, instruction) in cfg.instructions() {
        let ValueEffect::RegisterWrite {
            dst,
            value: ValueExpr::Immediate(0),
        } = &instruction.effect
        else {
            continue;
        };
        if *dst != count || !cfg.dominates(pc, loop_start) {
            continue;
        }
        let clean = cfg
            .nodes_on_paths_avoiding(pc, loop_start, &blocked)
            .iter()
            .filter(|interior| **interior != pc && **interior != loop_start)
            .all(|interior| {
                cfg.instruction(*interior)
                    .is_some_and(|instruction| register_write(instruction, count) == Some(false))
            });
        if clean {
            definitions.push(pc);
        }
    }
    let [definition] = definitions.as_slice() else {
        return None;
    };
    Some(*definition)
}

/// Evaluate every direct call target as a bounded side-effect-free
/// leaf, charging the budget for each decoded instruction byte before
/// decoding. Targets that are not valid leaves simply have no result.
fn evaluate_leaf_calls(
    image: &RuntimeImage<'_>,
    cfg: &LocalCfg,
    budget: &mut CandidateBudget,
) -> std::result::Result<BTreeMap<u32, u32>, PalTaskError> {
    const THUMB_INSTRUCTION_MAX_BYTES: u64 = 4;
    let mut results = BTreeMap::new();
    for instruction in cfg.instructions().map(|(_, instruction)| instruction) {
        let ControlFlow::DirectCall { target } = instruction.flow else {
            continue;
        };
        if results.contains_key(&target) {
            continue;
        }
        let decoder = PureRustDecoder;
        let mut state = decoder.begin_range(THUMB);
        let mut values = [None; 16];
        let mut pc = target;
        for _ in 0..MAX_SLOT_LEAF_INSTRUCTIONS {
            budget.charge(THUMB_INSTRUCTION_MAX_BYTES, "candidate validation bytes")?;
            let Some(instruction) = decode_with(image, &decoder, &mut state, pc) else {
                break;
            };
            if state.is_open() || instruction.conditional {
                break;
            }
            match (&instruction.effect, instruction.flow) {
                (
                    ValueEffect::RegisterWrite {
                        dst,
                        value: ValueExpr::Immediate(value),
                    },
                    ControlFlow::Linear,
                ) => values[usize::from(dst.0)] = Some(*value),
                (
                    ValueEffect::RegisterWrite {
                        dst,
                        value: ValueExpr::ReplaceHighHalf { source, high },
                    },
                    ControlFlow::Linear,
                ) if *source == *dst => {
                    let low = values[usize::from(dst.0)];
                    values[usize::from(dst.0)] =
                        low.map(|low| (u32::from(*high) << 16) | (low & 0xffff));
                }
                (_, ControlFlow::Return) => {
                    if let Some(value) = values[0] {
                        results.insert(target, value);
                    }
                    break;
                }
                _ => break,
            }
            let Some(next) = pc.checked_add(u32::from(instruction.length)) else {
                break;
            };
            pc = next;
        }
    }
    Ok(results)
}

/// The first direct call dominated by the reference whose reaching
/// argument fact carries the anchor value with the reference's root
/// definition.
fn find_anchor_call(
    cfg: &LocalCfg,
    reference: &AnchorReference,
    states: &DataflowStates<'_, '_, '_>,
) -> Option<u32> {
    for (pc, instruction) in cfg.instructions() {
        let ControlFlow::DirectCall { .. } = instruction.flow else {
            continue;
        };
        if !cfg.dominates(reference.pc, pc) {
            continue;
        }
        let carries_anchor = states.before(pc).is_some_and(|state| {
            state.registers[..4].iter().any(|fact| {
                fact.is_some_and(|fact| {
                    fact.value == reference.anchor
                        && reference
                            .definitions
                            .first()
                            .is_some_and(|root| *root == fact.root)
                })
            })
        });
        if carries_anchor {
            return Some(pc);
        }
    }
    None
}

/// Whether the slot fact's root is a supported slot-base form: a direct
/// immediate (MOVW/MOVT-style) construction whose fact chain the
/// dataflow preserved, or one direct leaf call whose constructed R0
/// constant the caller moved into the induction register.
fn slot_base_form_supported(
    cfg: &LocalCfg,
    slot_register: Register,
    slot_fact: &ValueFact,
) -> bool {
    let Some(root) = cfg.instruction(slot_fact.root) else {
        return false;
    };
    match &root.effect {
        ValueEffect::RegisterWrite {
            value: ValueExpr::Immediate(_),
            ..
        } => true,
        _ if matches!(root.flow, ControlFlow::DirectCall { .. }) => {
            let Some(definition) = cfg.instruction(slot_fact.definition) else {
                return false;
            };
            matches!(
                &definition.effect,
                ValueEffect::RegisterWrite {
                    dst,
                    value: ValueExpr::Register(source),
                } if *source == Register(0) && *dst == slot_register
            )
        }
        _ => false,
    }
}

/// Prove the dual exits: exactly one unequal backedge, a linear capacity
/// path and terminal path joining at one node, matching count-global
/// stores, the capacity guard, and the exact suffix induction loop.
fn find_exit_evidence(
    cfg: &LocalCfg,
    counting: &CountingLoop,
    states: &DataflowStates<'_, '_, '_>,
) -> Option<ExitProof> {
    let backedges: Vec<(u32, u32)> = cfg
        .instructions()
        .filter_map(|(pc, instruction)| {
            let ControlFlow::DirectBranch {
                target,
                fallthrough: Some(fallthrough),
                ..
            } = instruction.flow
            else {
                return None;
            };
            (is_unequal_backedge(instruction.flow) && target == counting.loop_start)
                .then_some((pc, fallthrough))
        })
        .collect();
    let [(backedge, capacity_exit)] = backedges.as_slice() else {
        return None;
    };
    let (backedge, capacity_exit) = (*backedge, *capacity_exit);
    if backedge != counting.backedge
        || capacity_exit != counting.capacity_exit
        || !cfg.has_edge(backedge, counting.loop_start)
        || !cfg.has_edge(backedge, capacity_exit)
    {
        return None;
    }
    let capacity_path = linear_path_until(cfg, capacity_exit, |flow| {
        matches!(
            flow,
            ControlFlow::DirectBranch {
                fallthrough: None,
                predicate: BranchPredicate::Always,
                ..
            }
        )
    })?;
    let join = match cfg.instruction(*capacity_path.last()?)?.flow {
        ControlFlow::DirectBranch { target, .. } => target,
        _ => return None,
    };
    let terminal_path = linear_path_until(cfg, counting.terminal, |flow| {
        matches!(
            flow,
            ControlFlow::DirectBranch {
                predicate: BranchPredicate::Condition(Arm32Condition::UnsignedHigher),
                ..
            }
        )
    })?;
    let terminal_join = match cfg.instruction(*terminal_path.last()?)?.flow {
        ControlFlow::DirectBranch { target, .. } => target,
        _ => return None,
    };
    if terminal_join != join || !cfg.contains_node(join) || !is_closed_before(cfg, join) {
        return None;
    }
    let capacity_global = count_global_store(cfg, states, &capacity_path, |_, fact| {
        fact.is_some_and(|fact| fact.value == counting.capacity)
    })?;
    let terminal_global = count_global_store(cfg, states, &terminal_path, |source, _| {
        source == counting.count_register
    })?;
    if capacity_global != terminal_global {
        return None;
    }
    if terminal_path.iter().any(|pc| {
        cfg.instruction(*pc).is_some_and(|instruction| {
            register_write(instruction, counting.count_register) != Some(false)
                || register_write(instruction, counting.slot_register) != Some(false)
        })
    }) {
        return None;
    }
    let terminal_to_join = cfg.nodes_on_paths(counting.terminal, join);
    let suffix_nodes: BTreeSet<u32> = terminal_to_join
        .into_iter()
        .filter(|pc| *pc != join)
        .collect();
    let suffix_cfg = cfg.induced_subgraph(&suffix_nodes);
    let suffix = match_suffix_loop(&suffix_cfg, counting)?;
    if suffix.join != join {
        return None;
    }
    let guard = find_capacity_guard(&suffix_cfg, counting, &suffix)?;
    let reachable_before_join = cfg.reachable_until(guard.fallthrough, join);
    if reachable_before_join != cfg.nodes_on_paths(guard.fallthrough, join)
        || cfg
            .external_edges()
            .iter()
            .any(|(source, _)| reachable_before_join.contains(source) && *source != join)
    {
        return None;
    }
    let suffix_branches: Vec<u32> = cfg
        .instructions()
        .filter_map(|(pc, instruction)| {
            let ControlFlow::DirectBranch {
                target,
                fallthrough: Some(fallthrough),
                ..
            } = instruction.flow
            else {
                return None;
            };
            (is_unequal_backedge(instruction.flow)
                && target == suffix.loop_start
                && fallthrough == join)
                .then_some(pc)
        })
        .collect();
    let [suffix_branch] = suffix_branches.as_slice() else {
        return None;
    };
    if cfg.can_reach_avoiding(guard.fallthrough, join, *suffix_branch) {
        return None;
    }
    let expected_join_predecessors =
        BTreeSet::from([*capacity_path.last()?, guard.branch, *suffix_branch]);
    if cfg.predecessors(join) != &expected_join_predecessors {
        return None;
    }
    Some(ExitProof {
        count_global: capacity_global,
        guard,
        suffix_loop: suffix.loop_start,
        join,
    })
}

/// Walk the single-successor chain from `start` until the first
/// instruction whose flow satisfies `stop`; a revisit or a split ends
/// the proof.
fn linear_path_until(
    cfg: &LocalCfg,
    start: u32,
    stop: impl Fn(&ControlFlow) -> bool,
) -> Option<Vec<u32>> {
    let mut path = Vec::new();
    let mut visited = BTreeSet::new();
    let mut pc = start;
    loop {
        if !visited.insert(pc) {
            return None;
        }
        let instruction = cfg.instruction(pc)?;
        path.push(pc);
        if stop(&instruction.flow) {
            return Some(path);
        }
        let successors = cfg.successors(pc)?;
        if successors.len() != 1 {
            return None;
        }
        pc = *successors.first()?;
    }
}

/// Every external edge before the join rejects the proof region.
fn is_closed_before(cfg: &LocalCfg, join: u32) -> bool {
    let region = cfg.reachable_until(cfg.entry(), join);
    !cfg.external_edges()
        .iter()
        .any(|(source, _)| region.contains(source) && *source != join)
}

/// The single count-global value stored along one exit path. The
/// counted store is selected by its source register and reaching fact;
/// the stored base register must hold one concrete global value.
fn count_global_store(
    cfg: &LocalCfg,
    states: &DataflowStates<'_, '_, '_>,
    path: &[u32],
    counted: impl Fn(Register, Option<&ValueFact>) -> bool,
) -> Option<u32> {
    let mut globals = Vec::new();
    for pc in path {
        let instruction = cfg.instruction(*pc)?;
        let Some((source, base)) = zero_offset_store(instruction) else {
            continue;
        };
        let state = states.before(*pc)?;
        if !counted(source, state.registers[usize::from(source.0)].as_ref()) {
            continue;
        }
        globals.push(state.registers[usize::from(base.0)].map(|fact| fact.value)?);
    }
    let [global] = globals.as_slice() else {
        return None;
    };
    Some(*global)
}

/// Match the suffix induction loop inside the terminal-to-join region:
/// exactly one count store before the increment, one count increment,
/// one slot advance with the same stride, one capacity compare, and one
/// unequal backedge, in dominance order, with the induced
/// loop-to-branch subgraph acyclic once that backedge is removed.
fn match_suffix_loop(suffix_cfg: &LocalCfg, counting: &CountingLoop) -> Option<SuffixLoop> {
    let instructions: Vec<(u32, &DecodedInstruction)> = suffix_cfg.instructions().collect();
    for (store_index, (store_pc, store)) in instructions.iter().enumerate() {
        let Some((source, index_offset)) = index_store(store, counting.slot_register) else {
            continue;
        };
        if source != counting.count_register || index_offset != counting.index_offset {
            continue;
        }
        let store_pc = *store_pc;
        let Some(count_add) = instructions[store_index + 1..]
            .iter()
            .position(|(_, candidate)| immediate_add(candidate, counting.count_register) == Some(1))
            .map(|index| index + store_index + 1)
        else {
            continue;
        };
        let Some(slot_add) = instructions[count_add + 1..]
            .iter()
            .position(|(_, candidate)| {
                immediate_add(candidate, counting.slot_register) == Some(counting.stride)
            })
            .map(|index| index + count_add + 1)
        else {
            continue;
        };
        let Some(compare) = instructions[slot_add + 1..]
            .iter()
            .position(|(_, candidate)| {
                capacity_compare(candidate, counting.count_register) == Some(counting.capacity)
            })
            .map(|index| index + slot_add + 1)
        else {
            continue;
        };
        let mut branch = None;
        for (offset, (_, candidate)) in instructions[compare + 1..].iter().enumerate() {
            if is_unequal_backedge(candidate.flow) {
                branch = Some(compare + 1 + offset);
                break;
            }
            if register_write(candidate, counting.count_register) != Some(false)
                || register_write(candidate, counting.slot_register) != Some(false)
                || writes_flags(candidate) != Some(false)
            {
                break;
            }
        }
        let Some(branch) = branch else {
            continue;
        };
        let ControlFlow::DirectBranch {
            target: loop_start,
            fallthrough: Some(join),
            ..
        } = instructions[branch].1.flow
        else {
            continue;
        };
        let count_add_pc = instructions[count_add].0;
        let slot_add_pc = instructions[slot_add].0;
        let compare_pc = instructions[compare].0;
        let branch_pc = instructions[branch].0;
        if loop_start > store_pc
            || loop_start < suffix_cfg.entry()
            || !suffix_cfg.contains_node(loop_start)
            || !suffix_cfg.dominates(loop_start, store_pc)
            || !suffix_cfg.dominates(store_pc, count_add_pc)
            || !suffix_cfg.dominates(count_add_pc, slot_add_pc)
            || !suffix_cfg.dominates(slot_add_pc, compare_pc)
            || !suffix_cfg.dominates(compare_pc, branch_pc)
            || !suffix_cfg.has_edge(branch_pc, loop_start)
        {
            continue;
        }
        let blocked = BTreeSet::from([(branch_pc, loop_start)]);
        let induction_path = suffix_cfg.nodes_on_paths_avoiding(loop_start, branch_pc, &blocked);
        if !suffix_cfg.is_acyclic_subgraph(&induction_path, &blocked) {
            continue;
        }
        let occurrences = |shape: &dyn Fn(&DecodedInstruction) -> bool| -> Vec<u32> {
            suffix_cfg
                .instructions()
                .filter(|(pc, candidate)| induction_path.contains(pc) && shape(candidate))
                .map(|(pc, _)| pc)
                .collect()
        };
        if occurrences(&|i| {
            index_store(i, counting.slot_register)
                == Some((counting.count_register, counting.index_offset))
        }) != [store_pc]
            || occurrences(&|i| immediate_add(i, counting.count_register) == Some(1))
                != [count_add_pc]
            || occurrences(&|i| immediate_add(i, counting.slot_register) == Some(counting.stride))
                != [slot_add_pc]
            || occurrences(&|i| {
                capacity_compare(i, counting.count_register) == Some(counting.capacity)
            }) != [compare_pc]
        {
            continue;
        }
        let key_pcs = [
            loop_start,
            store_pc,
            count_add_pc,
            slot_add_pc,
            compare_pc,
            branch_pc,
        ];
        if induction_path.iter().any(|pc| {
            !key_pcs.contains(pc) && {
                let Some(instruction) = suffix_cfg.instruction(*pc) else {
                    return true;
                };
                register_write(instruction, counting.count_register) != Some(false)
                    || register_write(instruction, counting.slot_register) != Some(false)
            }
        }) {
            continue;
        }
        let compare_to_branch = suffix_cfg.nodes_on_paths_avoiding(compare_pc, branch_pc, &blocked);
        if compare_to_branch
            .iter()
            .filter(|pc| **pc != compare_pc && **pc != branch_pc)
            .any(|pc| {
                suffix_cfg
                    .instruction(*pc)
                    .is_none_or(|instruction| writes_flags(instruction) != Some(false))
            })
        {
            continue;
        }
        return Some(SuffixLoop { loop_start, join });
    }
    None
}

/// Find the capacity guard: `count >> amount` compared unsigned with
/// `value`, branching to the join exactly when `count >= capacity`
/// because `(value + 1) << amount == capacity` under checked
/// arithmetic.
fn find_capacity_guard(
    suffix_cfg: &LocalCfg,
    counting: &CountingLoop,
    suffix: &SuffixLoop,
) -> Option<CapacityGuard> {
    let suffix_backedges: BTreeSet<(u32, u32)> = suffix_cfg
        .instructions()
        .filter_map(|(pc, instruction)| {
            is_unequal_backedge(instruction.flow)
                .then(|| {
                    let ControlFlow::DirectBranch { target, .. } = instruction.flow else {
                        return None;
                    };
                    (target == suffix.loop_start).then_some((pc, target))
                })
                .flatten()
        })
        .collect();
    let instructions: Vec<(u32, &DecodedInstruction)> = suffix_cfg.instructions().collect();
    instructions.windows(3).find_map(|window| {
        let [
            (shift_pc, shift),
            (compare_pc, compare),
            (branch_pc, branch),
        ] = window
        else {
            return None;
        };
        let ValueEffect::Shift {
            dst,
            source,
            shift: Shift::Lsr(amount),
        } = &shift.effect
        else {
            return None;
        };
        let ValueEffect::Compare {
            operation: CompareOp::Subtract,
            left,
            right: Operand::Immediate(value),
        } = &compare.effect
        else {
            return None;
        };
        let ControlFlow::DirectBranch {
            target,
            fallthrough: Some(fallthrough),
            predicate: BranchPredicate::Condition(Arm32Condition::UnsignedHigher),
        } = branch.flow
        else {
            return None;
        };
        let boundary = value
            .checked_add(1)
            .and_then(|boundary| boundary.checked_shl(u32::from(*amount)))?;
        (*source == counting.count_register
            && dst == left
            && *amount > 0
            && boundary == counting.capacity
            && compare.flags == FlagEffect::Written(FlagWriter::Compare)
            && target == suffix.join
            && suffix_cfg.has_edge(*shift_pc, *compare_pc)
            && suffix_cfg.has_edge(*compare_pc, *branch_pc)
            && suffix_cfg.has_edge(*branch_pc, fallthrough)
            && suffix_cfg.dominates(fallthrough, suffix.loop_start)
            && suffix_cfg
                .nodes_on_paths_avoiding(fallthrough, suffix.loop_start, &suffix_backedges)
                .iter()
                .filter(|pc| **pc != suffix.loop_start)
                .all(|pc| {
                    suffix_cfg.instruction(*pc).is_some_and(|instruction| {
                        register_write(instruction, counting.count_register) == Some(false)
                            && register_write(instruction, counting.slot_register) == Some(false)
                    })
                }))
        .then_some(CapacityGuard {
            start: *shift_pc,
            compare: *compare_pc,
            branch: *branch_pc,
            fallthrough,
            shift_amount: *amount,
            compare_value: *value,
        })
    })
}

/// Canonicalize by the full semantic tuple, aggregate all proof paths,
/// and cap unique tuples at the named limit.
fn merge_initializer_candidate(
    candidates: &mut Vec<InitializerCandidate>,
    mut candidate: InitializerCandidate,
) -> std::result::Result<(), PalTaskError> {
    canonicalize(
        &mut candidate.evidence.proof_paths,
        &mut candidate.evidence.anchors,
    );
    if let Some(existing) = candidates
        .iter_mut()
        .find(|existing| existing.evidence.same_semantics(&candidate.evidence))
    {
        existing
            .evidence
            .proof_paths
            .append(&mut candidate.evidence.proof_paths);
        existing
            .evidence
            .anchors
            .append(&mut candidate.evidence.anchors);
        canonicalize(
            &mut existing.evidence.proof_paths,
            &mut existing.evidence.anchors,
        );
        return Ok(());
    }
    let actual = candidates
        .len()
        .checked_add(1)
        .and_then(|count| u64::try_from(count).ok())
        .unwrap_or(u64::MAX);
    if actual > MAX_CANDIDATE_TUPLES as u64 {
        return Err(PalTaskError::ResourceLimit {
            what: "candidate tuples",
            actual,
            limit: MAX_CANDIDATE_TUPLES as u64,
        });
    }
    candidates.push(candidate);
    Ok(())
}

fn canonicalize(paths: &mut Vec<AnchorProofPath>, anchors: &mut Vec<AnchorProvenance>) {
    paths.sort_unstable_by_key(|path| (path.anchor, path.reference.pc, path.call));
    paths.dedup_by_key(|path| (path.anchor, path.reference.pc, path.call));
    anchors.sort_by_key(|anchor| anchor.address);
    anchors.dedup_by_key(|anchor| anchor.address);
}

fn runtime_error(label: &str, address: u32, size: u32, error: crate::error::Error) -> PalTaskError {
    PalTaskError::Runtime {
        address,
        size,
        reason: format!("{label}: {error}"),
    }
}

/// Scan every byte-backed span once for exact anchor occurrences. A
/// match may cross contiguous provenance spans but never zero-fill or
/// unmapped storage.
pub(super) fn find_anchor_occurrences(
    image: &RuntimeImage<'_>,
    label: &str,
) -> std::result::Result<Vec<AnchorOccurrence>, PalTaskError> {
    let mut occurrences = Vec::new();
    for range in image.byte_backed_ranges() {
        let mut cursor = range.start;
        while cursor < range.end {
            let remaining = range.end - cursor;
            let body = remaining.min(MAX_EXACT_READ as u32 - 8);
            // The chunk tail overlap lets every position in [cursor,
            // cursor + body) complete its nine-byte window inside one
            // read; the final chunk reads exactly to the range end.
            let window = (body + 8).min(remaining);
            let bytes = image
                .read_exact(cursor, window as usize)
                .map_err(|error| runtime_error(label, cursor, window, error))?;
            let scan_limit = window;
            if let Some(last_start) = scan_limit.checked_sub(ANCHOR_PATTERN.len() as u32) {
                for offset in 0..=last_start {
                    let start = offset as usize;
                    let end = start + ANCHOR_PATTERN.len();
                    if bytes[start..end] == ANCHOR_PATTERN[..] {
                        let address = cursor + offset;
                        let storage = image
                            .storage_spans(address, ANCHOR_PATTERN.len() as u32)
                            .map_err(|error| {
                                runtime_error(label, address, ANCHOR_PATTERN.len() as u32, error)
                            })?;
                        occurrences.push(AnchorOccurrence { address, storage });
                        if occurrences.len() as u64 > MAX_ANCHOR_OCCURRENCES {
                            return Err(PalTaskError::ResourceLimit {
                                what: "anchor occurrences",
                                actual: occurrences.len() as u64,
                                limit: MAX_ANCHOR_OCCURRENCES,
                            });
                        }
                    }
                }
            }
            cursor += body;
        }
    }
    Ok(occurrences)
}

/// One image-wide halfword-aligned Thumb sweep over byte-backed storage
/// that resolves every semantic anchor reference for the complete anchor
/// set: `ADR` materializations, literal loads whose pool word equals the
/// anchor, and register-consistent `MOVW`/`MOVT` constructions.
pub(super) fn find_anchor_references(
    image: &RuntimeImage<'_>,
    label: &str,
    anchors: &[AnchorOccurrence],
) -> std::result::Result<Vec<AnchorReference>, PalTaskError> {
    let addresses: Vec<u32> = anchors.iter().map(|anchor| anchor.address).collect();
    let mut references = Vec::new();
    for range in image.byte_backed_ranges() {
        let mut cursor = range.start;
        while cursor < range.end {
            let remaining = range.end - cursor;
            let body = remaining.min(MAX_EXACT_READ as u32 - 4);
            let window = (body + 4).min(remaining);
            let bytes = image
                .read_exact(cursor, window as usize)
                .map_err(|error| runtime_error(label, cursor, window, error))?;
            // Positions in [cursor, cursor + body) belong to this chunk;
            // the last two bytes of the read back a narrow final
            // instruction, and wider decodes fail naturally when the run
            // ends first.
            let limit = (cursor + body).min(cursor + window.saturating_sub(2));
            let mut pc = cursor + (cursor & 1);
            while pc < limit {
                let offset = usize::try_from(pc - cursor).expect("pc stays inside the chunk");
                if let Some(reference) = classify_position(image, pc, &bytes[offset..], &addresses)?
                {
                    references.push(reference);
                    if references.len() as u64 > MAX_ANCHOR_REFERENCES {
                        return Err(PalTaskError::ResourceLimit {
                            what: "anchor references",
                            actual: references.len() as u64,
                            limit: MAX_ANCHOR_REFERENCES,
                        });
                    }
                }
                pc += 2;
            }
            cursor += body;
        }
    }
    Ok(references)
}

fn classify_position(
    image: &RuntimeImage<'_>,
    pc: u32,
    encoding: &[u8],
    anchor_addresses: &[u32],
) -> std::result::Result<Option<AnchorReference>, PalTaskError> {
    let decoder = PureRustDecoder;
    let mut state = decoder.begin_range(THUMB);
    let Ok(instruction) = decoder.decode_one(&mut state, THUMB, pc, encoding) else {
        return Ok(None);
    };
    match &instruction.effect {
        ValueEffect::RegisterWrite { dst, value } => match value {
            ValueExpr::ArchitecturalPc {
                addend,
                align_to_four: true,
            } => {
                let address = wrapping_offset(visible_pc(pc, true), *addend);
                Ok(anchor_reference(
                    anchor_addresses,
                    AnchorReferenceKind::Adr,
                    pc,
                    vec![pc],
                    *dst,
                    address,
                ))
            }
            ValueExpr::Immediate(low) => {
                movw_movt_reference(image, pc, *dst, *low, instruction.length, anchor_addresses)
            }
            _ => Ok(None),
        },
        ValueEffect::LiteralWordLoad { dst, address } => {
            let crate::arm32::AddressExpr {
                base:
                    AddressBase::ArchitecturalPc {
                        align_to_four: true,
                    },
                offset: AddressOffset::Immediate(offset),
            } = address
            else {
                return Ok(None);
            };
            let literal = wrapping_offset(visible_pc(pc, true), *offset);
            match image.read_u32(literal) {
                Ok(value) => Ok(anchor_reference(
                    anchor_addresses,
                    AnchorReferenceKind::Literal,
                    pc,
                    vec![pc],
                    *dst,
                    value,
                )),
                // A pool word outside byte-backed storage is not a
                // materialization of any anchor.
                Err(_) => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// Resolve a `MOVW`-style low-half write through a register-consistent
/// `MOVT` in the same basic block, within the 32-instruction span and
/// with no intervening clobber of the destination.
fn movw_movt_reference(
    image: &RuntimeImage<'_>,
    movw_pc: u32,
    destination: Register,
    low: u32,
    movw_length: u8,
    anchor_addresses: &[u32],
) -> std::result::Result<Option<AnchorReference>, PalTaskError> {
    let Some(start) = movw_pc.checked_add(u32::from(movw_length)) else {
        return Ok(None);
    };
    let mut pc = start;
    let mut remaining = MAX_MOVW_MOVT_SPAN_INSTRUCTIONS - 1;
    while remaining > 0 {
        remaining -= 1;
        let Some(instruction) = decode_thumb_at(image, pc) else {
            return Ok(None);
        };
        if !matches!(instruction.flow, ControlFlow::Linear) {
            // Any non-linear transfer ends the basic block.
            return Ok(None);
        }
        if let ValueEffect::RegisterWrite {
            dst,
            value: ValueExpr::ReplaceHighHalf { source, high },
        } = &instruction.effect
            && *dst == destination
            && *source == destination
        {
            let value = (u32::from(*high) << 16) | (low & 0xffff);
            return Ok(anchor_reference(
                anchor_addresses,
                AnchorReferenceKind::MovwMovt,
                movw_pc,
                vec![movw_pc, pc],
                destination,
                value,
            ));
        }
        if instruction.writes.contains(&destination) {
            // Any other write to the destination breaks register
            // consistency.
            return Ok(None);
        }
        let Some(next) = pc.checked_add(u32::from(instruction.length)) else {
            return Ok(None);
        };
        pc = next;
    }
    Ok(None)
}

fn anchor_reference(
    anchor_addresses: &[u32],
    kind: AnchorReferenceKind,
    pc: u32,
    definitions: Vec<u32>,
    register: Register,
    value: u32,
) -> Option<AnchorReference> {
    let anchor = anchor_addresses
        .binary_search(&value)
        .ok()
        .map(|index| anchor_addresses[index])?;
    (pc.abs_diff(anchor) <= MAX_ANCHOR_REFERENCE_DISTANCE).then_some(AnchorReference {
        anchor,
        kind,
        pc,
        definitions,
        register,
    })
}

/// Enumerate every recognized Thumb prologue in the window before the
/// reference and keep the candidate only when exactly one decodes
/// linearly onto the reference. Selecting the nearest candidate or
/// filtering ambiguous roots by later topology is forbidden.
pub(super) fn unique_prologue_root(image: &RuntimeImage<'_>, reference: u32) -> Option<u32> {
    let window_start = reference.saturating_sub(PROLOGUE_WINDOW_BYTES) & !1;
    let mut candidates = Vec::new();
    let mut pc = window_start;
    while pc < reference {
        if let Some(instruction) = decode_thumb_at(image, pc)
            && is_recognized_prologue(&instruction)
            && linear_decode_reaches(image, pc, reference)
        {
            candidates.push(pc);
        }
        pc = pc.checked_add(2)?;
    }
    match candidates.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn linear_decode_reaches(image: &RuntimeImage<'_>, start: u32, reference: u32) -> bool {
    let mut pc = start;
    while pc < reference {
        let Some(instruction) = decode_thumb_at(image, pc) else {
            return false;
        };
        let Some(next) = pc.checked_add(u32::from(instruction.length)) else {
            return false;
        };
        pc = next;
    }
    pc == reference
}

/// A recognized prologue stores LR through a decrementing SP writeback:
/// `push {..., lr}` or `stmdb sp!, {..., lr}`.
fn is_recognized_prologue(instruction: &DecodedInstruction) -> bool {
    if !matches!(instruction.flow, ControlFlow::Linear) {
        return false;
    }
    let ValueEffect::Memory(effect) = &instruction.effect else {
        return false;
    };
    let Some((base, writeback)) = &effect.writeback else {
        return false;
    };
    if *base != SP {
        return false;
    }
    let AddressOffset::Immediate(delta) = writeback.offset else {
        return false;
    };
    delta < 0
        && effect.transfers.iter().any(|transfer| {
            transfer.kind == AccessKind::Write
                && transfer.width == 4
                && transfer.value == Some(LR)
                && matches!(&transfer.address.base, AddressBase::Register(base) if *base == SP)
        })
}

/// Shared fixture machinery for the PAL test modules: raw/scatter image
/// construction and the two-pass label-resolving Thumb assembler. Both
/// the discovery tests here and the table-validation tests in `table`
/// build their fixtures from these helpers.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::runtime_image::RuntimeImage;
    use crate::scatter::{
        Descriptor, HandlerMap, LoadPlan, Operation, PlannedEntry, PlannedOutput,
    };
    use scaleservers_arm32_assembly::{
        Arm32GeneralPurposeRegister as Gpr, Arm32LowGeneralPurposeRegister as Low,
        ArmT32Instruction as T32,
    };
    use std::collections::BTreeMap;

    pub(crate) const BASE: u32 = 0x1000;

    pub(crate) fn raw_image(bytes: &[u8]) -> RuntimeImage<'_> {
        RuntimeImage::from_plan(bytes, BASE, None).expect("raw fixture image")
    }

    pub(crate) fn bytes_entry(index: usize, destination: u32, bytes: Vec<u8>) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source: destination,
                destination,
                size: u32::try_from(bytes.len()).expect("fixture size fits u32"),
                handler: BASE + 2,
            },
            operation: Operation::Copy,
            compressed_size: None,
            output: PlannedOutput::Bytes(bytes),
        }
    }

    pub(crate) fn zero_entry(index: usize, destination: u32, size: u32) -> PlannedEntry {
        PlannedEntry {
            index,
            descriptor: Descriptor {
                source: destination,
                destination,
                size,
                handler: BASE + 4,
            },
            operation: Operation::Zero,
            compressed_size: None,
            output: PlannedOutput::ZeroFill,
        }
    }

    pub(crate) fn scatter_plan(image_size: u32, entries: Vec<PlannedEntry>) -> LoadPlan {
        let logical = entries
            .iter()
            .map(|entry| u64::from(entry.descriptor.size))
            .sum();
        LoadPlan {
            image_base: BASE,
            image_size,
            loader_address: BASE,
            literal_pair_address: BASE,
            table_start: BASE,
            table_end: BASE + image_size,
            handlers: HandlerMap {
                null: BASE + 1,
                copy: BASE + 2,
                decompress1: BASE + 3,
                zero: BASE + 4,
            },
            entries,
            logical_output_size: logical,
        }
    }

    pub(crate) fn enc(instruction: &T32) -> Vec<u8> {
        instruction.encode().expect("fixture encodes")
    }

    pub(crate) fn put(bytes: &mut [u8], offset: usize, part: &[u8]) {
        bytes[offset..offset + part.len()].copy_from_slice(part);
    }

    pub(crate) fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn gpr(number: u8) -> Gpr {
        Gpr::from_operand_bits(number)
    }

    pub(crate) fn low(number: u8) -> Low {
        Low::from_operand_bits(number)
    }

    pub(crate) type FixtureLabels = BTreeMap<&'static str, u32>;
    pub(crate) type FixtureBuild = Box<dyn Fn(u32, &FixtureLabels) -> T32>;

    pub(crate) enum FixtureItem {
        Insn(&'static str, FixtureBuild),
        Word(&'static str, u32),
        Data(&'static str, usize),
        Anchor(&'static str),
        Align(u32),
    }

    pub(crate) fn insn(
        label: &'static str,
        build: impl Fn(u32, &FixtureLabels) -> T32 + 'static,
    ) -> FixtureItem {
        FixtureItem::Insn(label, Box::new(build))
    }

    /// Assemble a complete fixture image: pass one measures every item
    /// with neutral branch offsets, pass two re-encodes with the
    /// resolved label addresses.
    pub(crate) fn assemble(base: u32, items: &[FixtureItem]) -> (Vec<u8>, FixtureLabels) {
        let unresolved = FixtureLabels::new();
        let mut starts = Vec::with_capacity(items.len());
        let mut pc = base;
        for item in items {
            if let FixtureItem::Align(to) = item {
                pc = pc.div_ceil(*to) * *to;
            }
            starts.push(pc);
            let size = match item {
                FixtureItem::Insn(_, build) => u32::try_from(
                    build(pc, &unresolved)
                        .encode()
                        .expect("fixture instruction encodes")
                        .len(),
                )
                .expect("fixture instruction size fits u32"),
                FixtureItem::Word(_, _) | FixtureItem::Data(_, 4) => 4,
                FixtureItem::Data(_, size) => *size as u32,
                FixtureItem::Anchor(_) => super::ANCHOR_PATTERN.len() as u32,
                FixtureItem::Align(_) => 0,
            };
            pc += size;
        }
        let labels: FixtureLabels = items
            .iter()
            .zip(&starts)
            .filter_map(|(item, start)| match item {
                FixtureItem::Insn(label, _)
                | FixtureItem::Word(label, _)
                | FixtureItem::Data(label, _)
                | FixtureItem::Anchor(label) => (!label.is_empty()).then_some((*label, *start)),
                FixtureItem::Align(_) => None,
            })
            .collect();
        let mut bytes = vec![0u8; (pc - base) as usize];
        for (item, start) in items.iter().zip(&starts) {
            match item {
                FixtureItem::Insn(_, build) => {
                    let part = build(*start, &labels)
                        .encode()
                        .expect("fixture instruction encodes");
                    put(&mut bytes, (*start - base) as usize, &part);
                }
                FixtureItem::Word(_, value) => {
                    put_u32(&mut bytes, (*start - base) as usize, *value)
                }
                FixtureItem::Data(_, _) => {}
                FixtureItem::Anchor(_) => {
                    put(&mut bytes, (*start - base) as usize, super::ANCHOR_PATTERN)
                }
                FixtureItem::Align(_) => {}
            }
        }
        (bytes, labels)
    }

    pub(crate) fn branch_offset(target: u32, pc: u32) -> i32 {
        i32::try_from(i64::from(target) - i64::from(pc) - 4)
            .expect("fixture branch offset fits i32")
    }

    pub(crate) fn branch_i16(target: u32, pc: u32) -> i16 {
        i16::try_from(branch_offset(target, pc)).expect("fixture branch offset fits i16")
    }

    pub(crate) fn cbz_offset(target: u32, pc: u32) -> u8 {
        u8::try_from(branch_offset(target, pc)).expect("fixture cbz offset fits u8")
    }

    pub(crate) fn aligned_offset(target: u32, pc: u32) -> u16 {
        let aligned = (pc.wrapping_add(4)) & !3;
        u16::try_from(target - aligned).expect("fixture aligned offset fits u16")
    }

    // Pass one encodes with unresolved labels, so every lookup falls
    // back to a neutral target that keeps the encoding length fixed.
    pub(crate) fn branch_to(l: &FixtureLabels, name: &str, pc: u32) -> i16 {
        branch_i16(l.get(name).copied().unwrap_or(pc + 4), pc)
    }

    pub(crate) fn branch32_to(l: &FixtureLabels, name: &str, pc: u32) -> i32 {
        branch_offset(l.get(name).copied().unwrap_or(pc + 4), pc)
    }

    pub(crate) fn cbz_to(l: &FixtureLabels, name: &str, pc: u32) -> u8 {
        cbz_offset(l.get(name).copied().unwrap_or(pc + 4), pc)
    }

    pub(crate) fn adr_to(l: &FixtureLabels, name: &str, pc: u32) -> u16 {
        aligned_offset(l.get(name).copied().unwrap_or((pc + 8) & !3), pc)
    }

    pub(crate) fn word_at(l: &FixtureLabels, name: &str) -> u32 {
        l.get(name).copied().unwrap_or(0)
    }

    pub(crate) fn replace_insn(
        mut items: Vec<FixtureItem>,
        label: &'static str,
        build: impl Fn(u32, &FixtureLabels) -> T32 + 'static,
    ) -> Vec<FixtureItem> {
        let position = items
            .iter()
            .position(|item| matches!(item, FixtureItem::Insn(existing, _) if *existing == label))
            .expect("fixture label exists");
        items[position] = insn(label, build);
        items
    }

    pub(crate) fn insert_after(
        mut items: Vec<FixtureItem>,
        label: &'static str,
        new: FixtureItem,
    ) -> Vec<FixtureItem> {
        let position = items
            .iter()
            .position(|item| matches!(item, FixtureItem::Insn(existing, _) if *existing == label))
            .expect("fixture label exists");
        items.insert(position + 1, new);
        items
    }

    pub(crate) fn insert_before(
        mut items: Vec<FixtureItem>,
        label: &'static str,
        new: FixtureItem,
    ) -> Vec<FixtureItem> {
        let position = items
            .iter()
            .position(|item| matches!(item, FixtureItem::Insn(existing, _) if *existing == label))
            .expect("fixture label exists");
        items.insert(position, new);
        items
    }

    pub(crate) fn remove_labeled(
        mut items: Vec<FixtureItem>,
        label: &'static str,
    ) -> Vec<FixtureItem> {
        items.retain(|item| !matches!(item, FixtureItem::Insn(existing, _) if *existing == label));
        items
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        BASE, FixtureItem, adr_to, assemble, branch_to, branch32_to, bytes_entry, cbz_to, enc, gpr,
        insert_after, insert_before, insn, low, put, put_u32, raw_image, remove_labeled,
        replace_insn, scatter_plan, word_at, zero_entry,
    };
    use super::{find_anchor_occurrences, find_anchor_references, merge_initializer_candidate};
    use crate::arm32::Register;
    use crate::pal_tasks::discover_anchor_cfg;
    use crate::pal_tasks::discover_initializer_candidates;
    use crate::pal_tasks::{
        ANCHOR_PATTERN, AnchorProofPath, AnchorProvenance, AnchorReference, AnchorReferenceKind,
        CandidateBudget, CapacityGuard, InitializerCandidate, InitializerEvidence,
        MAX_ANCHOR_REFERENCE_DISTANCE, MAX_CANDIDATE_TUPLES, MAX_CANDIDATE_VALIDATION_BYTES,
        MAX_SLOT_LEAF_INSTRUCTIONS, PalTaskError, TaskTableGeometry,
    };
    use crate::runtime_image::{RuntimeImage, StorageKind, StorageSpan};
    use scaleservers_arm32_assembly::{Arm32Condition, ArmT32Instruction as T32};
    use std::collections::BTreeSet;

    fn addresses(occurrences: &[super::AnchorOccurrence]) -> Vec<u32> {
        occurrences.iter().map(|anchor| anchor.address).collect()
    }

    #[test]
    fn anchor_sweep_finds_raw_scatter_and_cross_span_materializations() {
        // Raw anchor at BASE+0x8, an anchor straddling the raw/scatter
        // boundary at BASE+0x3a, and a fully scatter-backed anchor at
        // 0x3000.
        let mut raw = vec![0u8; 0x40];
        put(&mut raw, 0x08, ANCHOR_PATTERN);
        put(&mut raw, 0x3a, b"PALTsk");
        let cross = b"Tm\0".to_vec();
        let scatter = ANCHOR_PATTERN.to_vec();
        let plan = scatter_plan(
            0x40,
            vec![
                bytes_entry(0, BASE + 0x40, cross),
                bytes_entry(1, 0x3000, scatter),
            ],
        );
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");

        let occurrences = find_anchor_occurrences(&image, "fixture").unwrap();
        assert_eq!(addresses(&occurrences), [BASE + 0x08, BASE + 0x3a, 0x3000]);
        // The cross-span anchor retains the exact nine-byte provenance.
        assert_eq!(
            occurrences[1].storage,
            [
                StorageSpan {
                    kind: StorageKind::Raw,
                    address: BASE + 0x3a,
                    size: 6,
                    scatter_entry: None,
                },
                StorageSpan {
                    kind: StorageKind::ScatterBytes,
                    address: BASE + 0x40,
                    size: 3,
                    scatter_entry: Some(0),
                },
            ]
        );
    }

    #[test]
    fn anchor_references_cover_adr_literal_and_movw_movt_materializations() {
        // ADR: push, adr r1 -> anchor, bx lr.
        let mut bytes = vec![0u8; 0x19];
        put(&mut bytes, 0x00, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        put(&mut bytes, 0x02, &enc(&T32::Adr_T1(low(1), 0x0c)));
        put(&mut bytes, 0x04, &enc(&T32::Bx_T1(gpr(14))));
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].anchor, BASE + 0x10);
        assert_eq!(candidates[0].initializer, BASE);
        assert_eq!(
            candidates[0].reference,
            AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::Adr,
                pc: BASE + 0x02,
                definitions: vec![BASE + 0x02],
                register: Register(1),
            }
        );
        assert!(candidates[0].cfg.contains_node(BASE + 0x02));

        // Literal load: push, ldr r0, [pc, #4] with a pool word equal to
        // the anchor.
        let mut bytes = vec![0u8; 0x19];
        put(&mut bytes, 0x00, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        put(&mut bytes, 0x02, &enc(&T32::Ldr_Literal_T1(low(0), 4)));
        put(&mut bytes, 0x04, &enc(&T32::Bx_T1(gpr(14))));
        put_u32(&mut bytes, 0x08, BASE + 0x10);
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].reference,
            AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::Literal,
                pc: BASE + 0x02,
                definitions: vec![BASE + 0x02],
                register: Register(0),
            }
        );

        // MOVW/MOVT: push, movw r3, movt r3, bx lr, in one basic block.
        let mut bytes = vec![0u8; 0x19];
        put(&mut bytes, 0x00, &enc(&T32::Push_T1(vec![gpr(4), gpr(14)])));
        put(
            &mut bytes,
            0x02,
            &enc(&T32::Mov_Immediate_T3(gpr(3), 0x1010)),
        );
        put(&mut bytes, 0x06, &enc(&T32::Movt_T1(gpr(3), 0)));
        put(&mut bytes, 0x0a, &enc(&T32::Bx_T1(gpr(14))));
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].reference,
            AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::MovwMovt,
                pc: BASE + 0x02,
                definitions: vec![BASE + 0x02, BASE + 0x06],
                register: Register(3),
            }
        );
    }

    #[test]
    fn anchor_reference_beyond_four_kib_is_not_collected() {
        // Anchor at BASE+0x10; a literal load at +0x1000 (exactly the
        // distance limit, collected) and materializations far beyond it
        // (rejected even though they resolve the same anchor).
        let mut bytes = vec![0u8; 0x3020];
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        // Exactly MAX_ANCHOR_REFERENCE_DISTANCE away: collected.
        put(&mut bytes, 0x1010, &enc(&T32::Ldr_Literal_T2(gpr(4), 0)));
        put_u32(&mut bytes, 0x1014, BASE + 0x10);
        // 0x2000 away: not collected.
        put(&mut bytes, 0x2010, &enc(&T32::Ldr_Literal_T2(gpr(0), 0)));
        put_u32(&mut bytes, 0x2014, BASE + 0x10);
        // 0x3000 away: not collected.
        put(
            &mut bytes,
            0x3010,
            &enc(&T32::Mov_Immediate_T3(gpr(2), 0x1010)),
        );
        put(&mut bytes, 0x3014, &enc(&T32::Movt_T1(gpr(2), 0)));

        let anchors = find_anchor_occurrences(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(addresses(&anchors), [BASE + 0x10]);
        let references = find_anchor_references(&raw_image(&bytes), "fixture", &anchors).unwrap();
        assert_eq!(
            references,
            [AnchorReference {
                anchor: BASE + 0x10,
                kind: AnchorReferenceKind::Literal,
                pc: BASE + 0x1010,
                definitions: vec![BASE + 0x1010],
                register: Register(4),
            }]
        );
        assert_eq!(
            MAX_ANCHOR_REFERENCE_DISTANCE, 4096,
            "distance limit fixture depends on the exact bound"
        );
        assert!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn anchor_unrelated_materializations_yield_no_candidates() {
        // An ADR to a nearby non-anchor string is not a reference.
        let mut bytes = vec![0u8; 0x60];
        put(&mut bytes, 0x10, ANCHOR_PATTERN);
        put(&mut bytes, 0x40, b"OTHER\0\0\0");
        put(&mut bytes, 0x02, &enc(&T32::Adr_T1(low(1), 0x40)));
        let candidates = discover_anchor_cfg(&raw_image(&bytes), "fixture").unwrap();
        assert!(candidates.is_empty());

        // An image without the anchor materialization finds nothing.
        let mut bytes = vec![0u8; 0x20];
        put(&mut bytes, 0x02, &enc(&T32::Adr_T1(low(1), 0x08)));
        assert!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn anchor_occurrences_are_capped_at_4096() {
        let mut bytes = vec![0u8; 4097 * 16];
        for index in 0..4097 {
            put(&mut bytes, index * 16, ANCHOR_PATTERN);
        }
        assert!(matches!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture"),
            Err(PalTaskError::ResourceLimit {
                what: "anchor occurrences",
                actual: 4097,
                limit: 4096,
            })
        ));
    }

    #[test]
    fn anchor_references_are_capped_at_16384() {
        // 33 anchors, each preceded by a cluster of 512 ADR references
        // inside the distance limit: 16896 references in total.
        const CLUSTERS: usize = 33;
        const STRIDE: u32 = 0x1100;
        let image_end = 0x400 + STRIDE * (CLUSTERS as u32 - 1) + 0x20;
        let mut bytes = vec![0u8; image_end as usize];
        for cluster in 0..CLUSTERS {
            let anchor_address = BASE + 0x400 + STRIDE * cluster as u32;
            put(
                &mut bytes,
                (0x400 + STRIDE * cluster as u32) as usize,
                ANCHOR_PATTERN,
            );
            let cluster_start = STRIDE * cluster as u32;
            let mut offset = cluster_start;
            while offset < cluster_start + 0x400 {
                let pc = BASE + offset;
                let visible = (pc + 4) & !3;
                let const10 =
                    u16::try_from(anchor_address - visible).expect("fixture const10 fits u16");
                put(
                    &mut bytes,
                    offset as usize,
                    &enc(&T32::Adr_T1(low(1), const10)),
                );
                offset += 2;
            }
        }
        assert!(matches!(
            discover_anchor_cfg(&raw_image(&bytes), "fixture"),
            Err(PalTaskError::ResourceLimit {
                what: "anchor references",
                actual: 16385,
                limit: 16384,
            })
        ));
    }

    #[test]
    fn anchor_movw_movt_pairs_share_one_block_within_32_instructions() {
        // Cluster A: movw + 30 nops + movt is a 32-instruction span.
        let mut bytes = vec![0u8; 0x4060];
        put(
            &mut bytes,
            0x00,
            &enc(&T32::Mov_Immediate_T3(gpr(0), 0x1048)),
        );
        for index in 0..30 {
            put(&mut bytes, 0x04 + index * 2, &enc(&T32::Nop_T1));
        }
        put(&mut bytes, 0x40, &enc(&T32::Movt_T1(gpr(0), 0)));
        put(&mut bytes, 0x48, ANCHOR_PATTERN);

        // Cluster B: one extra nop makes the span 33 instructions.
        put(
            &mut bytes,
            0x1000,
            &enc(&T32::Mov_Immediate_T3(gpr(0), 0x2048)),
        );
        for index in 0..31 {
            put(&mut bytes, 0x1004 + index * 2, &enc(&T32::Nop_T1));
        }
        put(&mut bytes, 0x1042, &enc(&T32::Movt_T1(gpr(0), 0)));
        put(&mut bytes, 0x1048, ANCHOR_PATTERN);

        // Cluster C: an intervening write to the destination register
        // breaks register consistency.
        put(
            &mut bytes,
            0x2000,
            &enc(&T32::Mov_Immediate_T3(gpr(2), 0x3010)),
        );
        put(
            &mut bytes,
            0x2004,
            &enc(&T32::Mov_Register_T1(gpr(2), gpr(3))),
        );
        put(&mut bytes, 0x2006, &enc(&T32::Movt_T1(gpr(2), 0)));
        put(&mut bytes, 0x2010, ANCHOR_PATTERN);

        // Cluster D: an unconditional branch ends the basic block before
        // the movt.
        put(
            &mut bytes,
            0x3000,
            &enc(&T32::Mov_Immediate_T3(gpr(0), 0x4010)),
        );
        put(&mut bytes, 0x3004, &enc(&T32::Nop_T1));
        put(&mut bytes, 0x3006, &enc(&T32::B_T2(0)));
        put(&mut bytes, 0x3008, &enc(&T32::Nop_T1));
        put(&mut bytes, 0x300a, &enc(&T32::Movt_T1(gpr(0), 0)));
        put(&mut bytes, 0x3010, ANCHOR_PATTERN);

        let anchors = find_anchor_occurrences(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(
            addresses(&anchors),
            [BASE + 0x48, BASE + 0x1048, BASE + 0x2010, BASE + 0x3010]
        );
        let references = find_anchor_references(&raw_image(&bytes), "fixture", &anchors).unwrap();
        assert_eq!(
            references,
            [AnchorReference {
                anchor: BASE + 0x48,
                kind: AnchorReferenceKind::MovwMovt,
                pc: BASE,
                definitions: vec![BASE, BASE + 0x40],
                register: Register(0),
            }]
        );
    }

    #[test]
    fn anchor_matches_never_cross_zero_or_gap_storage() {
        // Eight anchor bytes end the raw image and the ninth byte would
        // have to come from zero-fill storage: no match, even though the
        // zero-fill content is a NUL.
        let mut raw = vec![0u8; 0x10];
        put(&mut raw, 0x08, b"PALTskTm");
        let plan = scatter_plan(0x10, vec![zero_entry(0, BASE + 0x10, 8)]);
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");
        assert!(
            find_anchor_occurrences(&image, "fixture")
                .unwrap()
                .is_empty()
        );

        // A pattern split across an unmapped gap never matches.
        let mut raw = vec![0u8; 0x10];
        put(&mut raw, 0x0a, b"PALTsk");
        let plan = scatter_plan(0x10, vec![bytes_entry(0, BASE + 0x18, b"Tm\0".to_vec())]);
        let image = RuntimeImage::from_plan(&raw, BASE, Some(&plan)).expect("fixture image");
        assert!(
            find_anchor_occurrences(&image, "fixture")
                .unwrap()
                .is_empty()
        );
    }

    fn assert_no_initializer(items: Vec<FixtureItem>) {
        let (bytes, _) = assemble(BASE, &items);
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        assert!(
            candidates.is_empty(),
            "unexpected candidates: {candidates:#?}"
        );
    }

    /// The counting loop, dual exits, guard, and suffix shared by the
    /// canonical and leaf-accessor fixtures: slot r4, count r5, name r0.
    fn loop_body_items() -> Vec<FixtureItem> {
        vec![
            insn("load", |_, _| T32::Ldr_Immediate_T1(low(0), low(4), 0x4c)),
            insn("lcbz", |pc, l| T32::Cbz_T1(low(0), cbz_to(l, "term", pc))),
            insn("lstr", |_, _| T32::Str_Immediate_T1(low(5), low(4), 0x0c)),
            insn("ladd", |_, _| T32::Add_Immediate_T2(low(5), 1)),
            insn("lstride", |_, _| {
                T32::Add_Immediate_T3(gpr(4), gpr(4), 0x1f8, false)
            }),
            insn("lcmp", |_, _| T32::Cmp_Immediate_T2(gpr(5), 1000)),
            insn("lbne", |pc, l| {
                T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "load", pc))
            }),
            insn("cap", |_, l| {
                T32::Mov_Immediate_T3(
                    gpr(0),
                    u16::try_from(word_at(l, "globals")).expect("fits u16"),
                )
            }),
            insn("", |_, l| {
                T32::Movt_T1(
                    gpr(0),
                    u16::try_from(word_at(l, "globals") >> 16).expect("fits u16"),
                )
            }),
            insn("cval", |_, _| T32::Mov_Immediate_T3(gpr(1), 1000)),
            insn("cstr", |_, _| T32::Str_Immediate_T1(low(1), low(0), 0)),
            insn("cjmp", |pc, l| T32::B_T2(branch_to(l, "join", pc))),
            insn("term", |pc, l| {
                T32::Adr_T1(low(0), adr_to(l, "globals", pc))
            }),
            insn("tstr", |_, _| T32::Str_Immediate_T1(low(5), low(0), 0)),
            insn("glsr", |_, _| T32::Lsr_Immediate_T1(low(0), low(5), 3)),
            insn("gcmp", |_, _| T32::Cmp_Immediate_T1(low(0), 124)),
            insn("gbhi", |pc, l| {
                T32::B_T1(Arm32Condition::UnsignedHigher, branch_to(l, "join", pc))
            }),
            insn("sstr", |_, _| T32::Str_Immediate_T1(low(5), low(4), 0x0c)),
            insn("sadd", |_, _| T32::Add_Immediate_T2(low(5), 1)),
            insn("sslot", |_, _| {
                T32::Add_Immediate_T3(gpr(4), gpr(4), 0x1f8, false)
            }),
            insn("smov", |_, _| T32::Mov_Register_T1(gpr(6), gpr(0))),
            insn("snop", |_, _| T32::Nop_T1),
            insn("scmp", |_, _| T32::Cmp_Immediate_T2(gpr(5), 1000)),
            insn("sbne", |pc, l| {
                T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "sstr", pc))
            }),
            insn("join", |_, _| T32::Bx_T1(gpr(14))),
        ]
    }

    fn shared_tail_items() -> Vec<FixtureItem> {
        vec![
            FixtureItem::Align(4),
            FixtureItem::Anchor("anchor"),
            FixtureItem::Align(2),
            insn("leaf", |_, _| T32::Mov_Immediate_T3(gpr(0), 0x1234)),
            insn("leaf2", |_, _| T32::Movt_T1(gpr(0), 0)),
            insn("leafret", |_, _| T32::Bx_T1(gpr(14))),
            FixtureItem::Align(4),
            FixtureItem::Data("globals", 8),
        ]
    }

    fn canonical_items() -> Vec<FixtureItem> {
        let mut items = vec![
            insn("init", |_, _| T32::Push_T1(vec![gpr(4), gpr(14)])),
            insn("ref", |pc, l| T32::Adr_T1(low(1), adr_to(l, "anchor", pc))),
            insn("zero", |_, _| T32::Mov_Immediate_T1(low(5), 0)),
            insn("slotlo", |_, _| T32::Mov_Immediate_T3(gpr(4), 0x4000)),
            insn("slothi", |_, _| T32::Movt_T1(gpr(4), 0)),
            insn("call", |pc, l| T32::Bl_T1(branch32_to(l, "leaf", pc))),
        ];
        items.extend(loop_body_items());
        items.extend(shared_tail_items());
        items
    }

    /// A completely different register allocation and encoding mix: slot
    /// r6 seeded through a movw/movt/copy chain, count r2, name r3,
    /// wide load/store, narrow compare, and a direct-shift guard.
    fn varied_items() -> Vec<FixtureItem> {
        vec![
            insn("init", |_, _| T32::Push_T1(vec![gpr(6), gpr(14)])),
            insn("ref", |pc, l| T32::Adr_T1(low(1), adr_to(l, "anchor", pc))),
            insn("call", |pc, l| T32::Bl_T1(branch32_to(l, "leaf", pc))),
            insn("zero", |_, _| T32::Mov_Immediate_T1(low(2), 0)),
            insn("slotlo", |_, _| T32::Mov_Immediate_T3(gpr(10), 0x4800)),
            insn("slothi", |_, _| T32::Movt_T1(gpr(10), 0)),
            insn("scopy", |_, _| T32::Mov_Register_T1(gpr(6), gpr(10))),
            insn("load", |_, _| T32::Ldr_Immediate_T3(gpr(3), gpr(6), 0x24)),
            insn("lcbz", |pc, l| T32::Cbz_T1(low(3), cbz_to(l, "term", pc))),
            insn("lstr", |_, _| T32::Str_Immediate_T3(gpr(2), gpr(6), 4)),
            insn("ladd", |_, _| {
                T32::Add_Immediate_T3(gpr(2), gpr(2), 1, false)
            }),
            insn("lstride", |_, _| {
                T32::Add_Immediate_T3(gpr(6), gpr(6), 0x100, false)
            }),
            insn("lcmp", |_, _| T32::Cmp_Immediate_T1(low(2), 200)),
            insn("lbne", |pc, l| {
                T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "load", pc))
            }),
            insn("cap", |pc, l| T32::Adr_T1(low(0), adr_to(l, "globals", pc))),
            insn("cval", |_, _| T32::Mov_Immediate_T1(low(1), 200)),
            insn("cstr", |_, _| T32::Str_Immediate_T1(low(1), low(0), 0)),
            insn("cjmp", |pc, l| T32::B_T2(branch_to(l, "join", pc))),
            insn("term", |pc, l| {
                T32::Adr_T1(low(0), adr_to(l, "globals", pc))
            }),
            insn("tstr", |_, _| T32::Str_Immediate_T1(low(2), low(0), 0)),
            insn("glsr", |_, _| T32::Lsr_Immediate_T1(low(0), low(2), 2)),
            insn("gcmp", |_, _| T32::Cmp_Immediate_T1(low(0), 49)),
            insn("gbhi", |pc, l| {
                T32::B_T1(Arm32Condition::UnsignedHigher, branch_to(l, "join", pc))
            }),
            insn("sstr", |_, _| T32::Str_Immediate_T3(gpr(2), gpr(6), 4)),
            insn("sadd", |_, _| {
                T32::Add_Immediate_T3(gpr(2), gpr(2), 1, false)
            }),
            insn("sslot", |_, _| {
                T32::Add_Immediate_T3(gpr(6), gpr(6), 0x100, false)
            }),
            insn("scmp", |_, _| T32::Cmp_Immediate_T1(low(2), 200)),
            insn("sbne", |pc, l| {
                T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "sstr", pc))
            }),
            insn("join", |_, _| T32::Bx_T1(gpr(14))),
            FixtureItem::Align(4),
            FixtureItem::Anchor("anchor"),
            FixtureItem::Align(2),
            insn("leaf", |_, _| T32::Mov_Immediate_T3(gpr(0), 0)),
            insn("leaf2", |_, _| T32::Movt_T1(gpr(0), 0)),
            insn("leafret", |_, _| T32::Bx_T1(gpr(14))),
            FixtureItem::Align(4),
            FixtureItem::Data("globals", 8),
        ]
    }

    /// The leaf-accessor slot base: `bl leaf; mov r4, r0`.
    fn leaf_slot_items() -> Vec<FixtureItem> {
        let mut items = vec![
            insn("init", |_, _| T32::Push_T1(vec![gpr(4), gpr(14)])),
            insn("ref", |pc, l| T32::Adr_T1(low(1), adr_to(l, "anchor", pc))),
            insn("zero", |_, _| T32::Mov_Immediate_T1(low(5), 0)),
            insn("call", |pc, l| T32::Bl_T1(branch32_to(l, "leaf", pc))),
            insn("move", |_, _| T32::Mov_Register_T1(gpr(4), gpr(0))),
        ];
        items.extend(loop_body_items());
        items.extend(shared_tail_items());
        items
    }

    fn synthetic_candidate(cfg_entry: u32) -> InitializerCandidate {
        let geometry = TaskTableGeometry {
            slot_base: 0x4000,
            name_offset: 0x4c,
            index_offset: 0x0c,
            stride: 0x1f8,
            capacity: 1000,
        };
        InitializerCandidate {
            evidence: InitializerEvidence {
                cfg_entry,
                proof_paths: vec![AnchorProofPath {
                    anchor: 0x3000,
                    reference: AnchorReference {
                        anchor: 0x3000,
                        kind: AnchorReferenceKind::Adr,
                        pc: 0x1002,
                        definitions: vec![0x1002],
                        register: Register(1),
                    },
                    call: 0x1006,
                }],
                anchors: vec![],
                code_storage: vec![],
                loop_start: 0x1010,
                count_zero_definition: 0x1004,
                slot_definition: 0x1008,
                normal_exit: 0x1020,
                capacity_exit: 0x101c,
                capacity_guard: CapacityGuard {
                    start: 0x1024,
                    compare: 0x1026,
                    branch: 0x1028,
                    fallthrough: 0x102a,
                    shift_amount: 3,
                    compare_value: 124,
                },
                suffix_loop: 0x102a,
                join: 0x1030,
                count_global: 0x5000,
                slot_base: 0x4000,
                name_offset: 0x4c,
                index_offset: 0x0c,
                stride: 0x1f8,
                capacity: 1000,
            },
            geometry,
        }
    }

    #[test]
    fn loop_topology_matches_varied_registers_and_encodings() {
        // Canonical: direct movw/movt slot base, wide stride/compare,
        // count global materialized by value on the capacity path.
        let (bytes, at) = assemble(BASE, &canonical_items());
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        let [candidate] = candidates.as_slice() else {
            panic!("expected exactly one candidate, got {candidates:#?}")
        };
        assert_eq!(
            candidate.evidence,
            InitializerEvidence {
                cfg_entry: BASE,
                proof_paths: vec![AnchorProofPath {
                    anchor: at["anchor"],
                    reference: AnchorReference {
                        anchor: at["anchor"],
                        kind: AnchorReferenceKind::Adr,
                        pc: at["ref"],
                        definitions: vec![at["ref"]],
                        register: Register(1),
                    },
                    call: at["call"],
                }],
                anchors: vec![AnchorProvenance {
                    address: at["anchor"],
                    storage: vec![StorageSpan {
                        kind: StorageKind::Raw,
                        address: at["anchor"],
                        size: 9,
                        scatter_entry: None,
                    }],
                }],
                code_storage: vec![StorageSpan {
                    kind: StorageKind::Raw,
                    address: BASE,
                    size: at["join"] + 2 - BASE,
                    scatter_entry: None,
                }],
                loop_start: at["load"],
                count_zero_definition: at["zero"],
                slot_definition: at["slotlo"],
                normal_exit: at["term"],
                capacity_exit: at["cap"],
                capacity_guard: CapacityGuard {
                    start: at["glsr"],
                    compare: at["gcmp"],
                    branch: at["gbhi"],
                    fallthrough: at["sstr"],
                    shift_amount: 3,
                    compare_value: 124,
                },
                suffix_loop: at["sstr"],
                join: at["join"],
                count_global: at["globals"],
                slot_base: 0x4000,
                name_offset: 0x4c,
                index_offset: 0x0c,
                stride: 0x1f8,
                capacity: 1000,
            }
        );
        assert_eq!(
            candidate.geometry,
            TaskTableGeometry {
                slot_base: 0x4000,
                name_offset: 0x4c,
                index_offset: 0x0c,
                stride: 0x1f8,
                capacity: 1000,
            }
        );

        // Varied allocation and encodings: slot r6 through a copy chain,
        // count r2, name r3, wide load/store, narrow compare, guard
        // shift 2 with value 49.
        let (bytes, at) = assemble(BASE, &varied_items());
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        let [candidate] = candidates.as_slice() else {
            panic!("expected exactly one candidate, got {candidates:#?}")
        };
        assert_eq!(candidate.evidence.cfg_entry, BASE);
        assert_eq!(candidate.evidence.loop_start, at["load"]);
        assert_eq!(candidate.evidence.count_zero_definition, at["zero"]);
        assert_eq!(candidate.evidence.slot_definition, at["slotlo"]);
        assert_eq!(candidate.evidence.slot_base, 0x4800);
        assert_eq!(candidate.evidence.name_offset, 0x24);
        assert_eq!(candidate.evidence.index_offset, 4);
        assert_eq!(candidate.evidence.stride, 0x100);
        assert_eq!(candidate.evidence.capacity, 200);
        assert_eq!(candidate.evidence.capacity_guard.shift_amount, 2);
        assert_eq!(candidate.evidence.capacity_guard.compare_value, 49);
        assert_eq!(candidate.evidence.suffix_loop, at["sstr"]);
        assert_eq!(candidate.evidence.join, at["join"]);
        assert_eq!(candidate.evidence.count_global, at["globals"]);

        // Leaf-accessor slot base: `bl leaf; mov r4, r0`.
        let (bytes, at) = assemble(BASE, &leaf_slot_items());
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        let [candidate] = candidates.as_slice() else {
            panic!("expected exactly one candidate, got {candidates:#?}")
        };
        assert_eq!(candidate.evidence.slot_definition, at["call"]);
        assert_eq!(candidate.evidence.slot_base, 0x1234);
        assert_eq!(candidate.geometry.slot_base, 0x1234);
    }

    #[test]
    fn loop_topology_rejects_wrong_branch_polarity() {
        // cbnz inverts the terminal condition.
        assert_no_initializer(replace_insn(canonical_items(), "lcbz", |pc, l| {
            T32::Cbnz_T1(low(0), cbz_to(l, "term", pc))
        }));
        // An equality backedge exits while the count is unequal.
        assert_no_initializer(replace_insn(canonical_items(), "lbne", |pc, l| {
            T32::B_T1(Arm32Condition::Equal, branch_to(l, "load", pc))
        }));
    }

    #[test]
    fn loop_topology_rejects_stale_or_bypassed_zero() {
        // A count write after the zero root stales the induction fact.
        assert_no_initializer(insert_after(
            canonical_items(),
            "zero",
            insn("", |_, _| T32::Mov_Register_T1(gpr(5), gpr(6))),
        ));
        // A conditional edge into the loop head from before the zero
        // root bypasses it.
        assert_no_initializer(insert_before(
            canonical_items(),
            "zero",
            insn("", |pc, l| T32::Cbz_T1(low(0), cbz_to(l, "load", pc))),
        ));
    }

    #[test]
    fn loop_topology_rejects_mismatched_operands() {
        // The index store sources a different register.
        assert_no_initializer(replace_insn(canonical_items(), "lstr", |_, _| {
            T32::Str_Immediate_T1(low(6), low(4), 0x0c)
        }));
        // The capacity compare reads a different register.
        assert_no_initializer(replace_insn(canonical_items(), "lcmp", |_, _| {
            T32::Cmp_Immediate_T2(gpr(6), 1000)
        }));
        // The stride advances a different register.
        assert_no_initializer(replace_insn(canonical_items(), "lstride", |_, _| {
            T32::Add_Immediate_T3(gpr(6), gpr(6), 0x1f8, false)
        }));
    }

    #[test]
    fn loop_topology_rejects_unknown_effects_and_clobbered_anchor_value() {
        // An unmodeled count write between the zero root and the loop.
        assert_no_initializer(insert_after(
            canonical_items(),
            "zero",
            insn("", |_, _| T32::Mul_T2(gpr(5), gpr(6), gpr(7))),
        ));
        // The anchor value does not reach the call argument.
        assert_no_initializer(insert_before(
            canonical_items(),
            "call",
            insn("", |_, _| T32::Mov_Immediate_T1(low(1), 7)),
        ));
    }

    #[test]
    fn loop_topology_rejects_call_not_dominating_the_preheader() {
        // A conditional edge over the anchor call into the loop head.
        assert_no_initializer(insert_before(
            canonical_items(),
            "call",
            insn("", |pc, l| T32::Cbz_T1(low(0), cbz_to(l, "load", pc))),
        ));
    }

    #[test]
    fn loop_topology_rejects_unequal_backedge() {
        // The backedge targets the index store instead of the load.
        assert_no_initializer(replace_insn(canonical_items(), "lbne", |pc, l| {
            T32::B_T1(Arm32Condition::NotEqual, branch_to(l, "lstr", pc))
        }));
    }

    #[test]
    fn loop_topology_aggregates_proof_paths_and_keeps_competing_roots() {
        // Two references to one anchor, each reaching its own dominating
        // call, aggregate into one candidate with two proof paths.
        let items = canonical_items();
        let items = remove_labeled(items, "call");
        let items = insert_after(
            items,
            "ref",
            insn("callA", |pc, l| T32::Bl_T1(branch32_to(l, "leaf", pc))),
        );
        let items = insert_after(
            items,
            "callA",
            insn("ref2", |pc, l| T32::Adr_T1(low(1), adr_to(l, "anchor", pc))),
        );
        let items = insert_after(
            items,
            "ref2",
            insn("callB", |pc, l| T32::Bl_T1(branch32_to(l, "leaf", pc))),
        );
        let (bytes, at) = assemble(BASE, &items);
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        let [candidate] = candidates.as_slice() else {
            panic!("expected exactly one candidate, got {candidates:#?}")
        };
        assert_eq!(candidate.evidence.anchors.len(), 1);
        assert_eq!(candidate.evidence.proof_paths.len(), 2);
        let calls: BTreeSet<u32> = candidate
            .evidence
            .proof_paths
            .iter()
            .map(|path| path.call)
            .collect();
        assert_eq!(calls, BTreeSet::from([at["callA"], at["callB"]]));
        let references: BTreeSet<u32> = candidate
            .evidence
            .proof_paths
            .iter()
            .map(|path| path.reference.pc)
            .collect();
        assert_eq!(references, BTreeSet::from([at["ref"], at["ref2"]]));

        // Competing CFG roots stay separate candidates.
        let (mut bytes, _) = assemble(BASE, &canonical_items());
        let (second, _) = assemble(BASE + 0x140, &canonical_items());
        bytes.resize(0x140, 0);
        bytes.extend_from_slice(&second);
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        assert_eq!(candidates.len(), 2);
        let roots: BTreeSet<u32> = candidates
            .iter()
            .map(|candidate| candidate.evidence.cfg_entry)
            .collect();
        assert_eq!(roots, BTreeSet::from([BASE, BASE + 0x140]));
    }

    #[test]
    fn loop_topology_caps_unique_tuples_at_64() {
        let mut candidates = Vec::new();
        for index in 0..MAX_CANDIDATE_TUPLES as u32 {
            merge_initializer_candidate(&mut candidates, synthetic_candidate(BASE + index * 0x10))
                .unwrap();
        }
        let overflow = merge_initializer_candidate(&mut candidates, synthetic_candidate(0x2000));
        assert!(matches!(
            overflow,
            Err(PalTaskError::ResourceLimit {
                what: "candidate tuples",
                actual: 65,
                limit: 64,
            })
        ));
        // Merging into an existing tuple aggregates instead of capping.
        let mut duplicate = synthetic_candidate(BASE);
        duplicate.evidence.proof_paths.push(AnchorProofPath {
            anchor: 0x3004,
            reference: AnchorReference {
                anchor: 0x3004,
                kind: AnchorReferenceKind::Adr,
                pc: 0x1012,
                definitions: vec![0x1012],
                register: Register(1),
            },
            call: 0x1016,
        });
        merge_initializer_candidate(&mut candidates, duplicate).unwrap();
        assert_eq!(candidates.len(), MAX_CANDIDATE_TUPLES);
        assert_eq!(candidates[0].evidence.proof_paths.len(), 2);
    }

    #[test]
    fn candidate_budget_charges_are_checked_and_never_refunded() {
        assert_eq!(MAX_CANDIDATE_VALIDATION_BYTES, 512 * 1024 * 1024);
        let mut budget = CandidateBudget::default();
        budget.charge(16, "candidate validation bytes").unwrap();
        budget
            .charge(
                MAX_CANDIDATE_VALIDATION_BYTES - 16,
                "candidate validation bytes",
            )
            .unwrap();
        assert!(matches!(
            budget.charge(1, "candidate validation bytes"),
            Err(PalTaskError::ResourceLimit {
                what: "candidate validation bytes",
                actual,
                limit: MAX_CANDIDATE_VALIDATION_BYTES,
            }) if actual == MAX_CANDIDATE_VALIDATION_BYTES + 1
        ));
        // A rejected charge never refunds prior work, and the counter
        // overflow is the same typed limit.
        assert!(matches!(
            budget.charge(u64::MAX, "candidate validation bytes"),
            Err(PalTaskError::ResourceLimit {
                actual: u64::MAX,
                ..
            })
        ));
        assert!(budget.charge(0, "candidate validation bytes").is_ok());
        assert!(budget.charge(1, "candidate validation bytes").is_err());
    }

    #[test]
    fn loop_topology_suffix_allows_flag_preserving_scheduling() {
        // A side-effect-free instruction directly after the suffix
        // store keeps the induction proof.
        let items = insert_after(canonical_items(), "sstr", insn("", |_, _| T32::Nop_T1));
        let (bytes, at) = assemble(BASE, &items);
        let candidates = discover_initializer_candidates(&raw_image(&bytes), "fixture").unwrap();
        let [candidate] = candidates.as_slice() else {
            panic!("expected exactly one candidate, got {candidates:#?}")
        };
        assert_eq!(candidate.evidence.suffix_loop, at["sstr"]);
        assert_eq!(candidate.evidence.join, at["join"]);
    }

    #[test]
    fn loop_topology_suffix_requires_one_shared_count_global() {
        // The terminal path stores to a different global.
        assert_no_initializer(replace_insn(canonical_items(), "term", |pc, l| {
            T32::Adr_T1(low(0), adr_to(l, "globals", pc) + 4)
        }));
    }

    #[test]
    fn loop_topology_suffix_requires_count_ge_capacity_guard() {
        // (123 + 1) << 3 == 992 != 1000 breaks the guard boundary.
        assert_no_initializer(replace_insn(canonical_items(), "gcmp", |_, _| {
            T32::Cmp_Immediate_T1(low(0), 123)
        }));
    }

    #[test]
    fn loop_topology_suffix_preserves_induction_facts() {
        // A count write on the terminal path.
        assert_no_initializer(insert_after(
            canonical_items(),
            "tstr",
            insn("", |_, _| T32::Mov_Register_T1(gpr(5), gpr(6))),
        ));
        // A slot write between the guard fallthrough and the suffix
        // loop head.
        assert_no_initializer(insert_before(
            canonical_items(),
            "sstr",
            insn("", |_, _| T32::Mov_Register_T1(gpr(4), gpr(6))),
        ));
    }

    #[test]
    fn loop_topology_suffix_requires_store_before_increment() {
        // The suffix increments before storing.
        let items = replace_insn(canonical_items(), "sstr", |_, _| {
            T32::Add_Immediate_T2(low(5), 1)
        });
        let items = replace_insn(items, "sadd", |_, _| {
            T32::Str_Immediate_T1(low(5), low(4), 0x0c)
        });
        assert_no_initializer(items);
    }

    #[test]
    fn loop_topology_suffix_requires_same_stride_and_capacity() {
        assert_no_initializer(replace_insn(canonical_items(), "sslot", |_, _| {
            T32::Add_Immediate_T3(gpr(4), gpr(4), 0x1d8, false)
        }));
        assert_no_initializer(replace_insn(canonical_items(), "scmp", |_, _| {
            T32::Cmp_Immediate_T1(low(5), 250)
        }));
    }

    #[test]
    fn loop_topology_suffix_rejects_wrong_equality_backedge() {
        assert_no_initializer(replace_insn(canonical_items(), "sbne", |pc, l| {
            T32::B_T1(Arm32Condition::Equal, branch_to(l, "sstr", pc))
        }));
    }

    #[test]
    fn loop_topology_suffix_rejects_duplicate_semantic_effects() {
        // A second index store inside the induction path.
        assert_no_initializer(insert_after(
            canonical_items(),
            "sstr",
            insn("", |_, _| T32::Str_Immediate_T1(low(5), low(4), 0x0c)),
        ));
    }

    #[test]
    fn loop_topology_suffix_rejects_any_extra_cycle() {
        // A conditional edge back to the suffix store closes a second
        // cycle inside the induction path.
        assert_no_initializer(insert_after(
            canonical_items(),
            "sadd",
            insn("", |pc, l| {
                T32::B_T1(Arm32Condition::Equal, branch_to(l, "sstr", pc))
            }),
        ));
    }

    #[test]
    fn loop_topology_suffix_rejects_side_return() {
        // A conditional edge out of the suffix region to a return.
        let mut items = insert_after(
            canonical_items(),
            "sstr",
            insn("", |pc, l| {
                T32::B_T1(Arm32Condition::Equal, branch_to(l, "side", pc))
            }),
        );
        items.push(insn("side", |_, _| T32::Bx_T1(gpr(14))));
        assert_no_initializer(items);
    }

    #[test]
    fn loop_topology_suffix_rejects_join_reach_avoiding_suffix_branch() {
        // A conditional edge from the guard fallthrough straight to the
        // join bypasses every required suffix effect.
        assert_no_initializer(insert_before(
            canonical_items(),
            "sstr",
            insn("", |pc, l| {
                T32::B_T1(Arm32Condition::Equal, branch_to(l, "join", pc))
            }),
        ));
    }

    #[test]
    fn loop_topology_requires_supported_slot_base_roots() {
        // A literal-load root is not a supported slot-base form even
        // though its fact reaches the preheader.
        let items = replace_insn(canonical_items(), "slotlo", |pc, l| {
            T32::Ldr_Literal_T1(low(4), adr_to(l, "pool", pc))
        });
        let items = remove_labeled(items, "slothi");
        let mut items = items;
        items.push(FixtureItem::Align(4));
        items.push(FixtureItem::Word("pool", 0x4000));
        assert_no_initializer(items);

        // Equal slot values from competing roots merge to unknown.
        let items = remove_labeled(remove_labeled(canonical_items(), "slotlo"), "slothi");
        let items = insert_before(
            items,
            "call",
            insn("slotcbz", |pc, l| {
                T32::Cbz_T1(low(6), cbz_to(l, "slotB1", pc))
            }),
        );
        let items = insert_after(
            items,
            "slotcbz",
            insn("slotA1", |_, _| T32::Mov_Immediate_T3(gpr(4), 0x4000)),
        );
        let items = insert_after(
            items,
            "slotA1",
            insn("slotA2", |_, _| T32::Movt_T1(gpr(4), 0)),
        );
        let items = insert_after(
            items,
            "slotA2",
            insn("", |pc, l| T32::B_T2(branch_to(l, "call", pc))),
        );
        let items = insert_before(
            items,
            "call",
            insn("slotB1", |_, _| T32::Mov_Immediate_T3(gpr(4), 0x4000)),
        );
        let items = insert_before(
            items,
            "call",
            insn("slotB2", |_, _| T32::Movt_T1(gpr(4), 0)),
        );
        assert_no_initializer(items);

        // A side-effecting leaf cannot seed the slot base.
        assert_no_initializer(replace_insn(leaf_slot_items(), "leaf2", |_, _| {
            T32::Str_Immediate_T1(low(0), low(0), 0)
        }));

        // A leaf longer than the instruction bound cannot seed it.
        let mut long_leaf = leaf_slot_items();
        for index in (0..MAX_SLOT_LEAF_INSTRUCTIONS - 1).rev() {
            let value = u8::try_from(index).expect("fits u8");
            long_leaf = insert_after(
                long_leaf,
                "leaf2",
                insn("", move |_, _| T32::Mov_Immediate_T1(low(1), value)),
            );
        }
        assert_no_initializer(long_leaf);

        // An IT-predicated leaf construction is rejected.
        let items = replace_insn(leaf_slot_items(), "leaf2", |_, _| {
            T32::It_T1(Arm32Condition::Equal, 0b1000)
        });
        let items = insert_after(items, "leaf2", insn("", |_, _| T32::Movt_T1(gpr(0), 0)));
        assert_no_initializer(items);
    }
}
