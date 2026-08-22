// Same-PC agreement, conflicts, and conservative summaries.

use super::artifact::{
    AccessKindWire, AlternativeWire, CallHopWire, ConflictWire, FunctionContextWire, GlobalWire,
    IsaWire, ObservationWire, ProvisionalShape, Status, SummaryWire,
};
use super::tracker::{CallHop, CandidateObservation};
use super::{FunctionContext, RecoveredGlobal};
use crate::arm32::AccessKind;
use crate::error::{Error, Result};
use crate::execution_ranges::DecodeIsa as Isa;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub(crate) struct Aggregation {
    pub globals: Vec<GlobalWire>,
    pub inferred: usize,
    pub no_evidence: usize,
    pub conflicting: usize,
    pub observations: usize,
    pub conflicts: usize,
    pub interprocedural_observations: usize,
    pub interprocedural_dropped: usize,
}

pub(crate) fn aggregate(
    globals: &[RecoveredGlobal],
    intra: Vec<CandidateObservation>,
    inter: Vec<CandidateObservation>,
) -> Result<Aggregation> {
    let recovered = recovered_addresses(globals)?;
    for candidate in intra.iter().chain(inter.iter()) {
        if !recovered.contains(&candidate.target_address) {
            return Err(invalid(&format!(
                "unknown target address {}",
                hex(candidate.target_address)
            )));
        }
    }

    let mut groups: BTreeMap<(Isa, u32), BTreeMap<SemanticKey, Accumulator>> = BTreeMap::new();
    for candidate in intra {
        let key = SemanticKey {
            target_address: candidate.target_address,
            conditional: candidate.conditional,
            kind: candidate.kind,
            width: candidate.width,
            offset: candidate.offset,
        };
        let accumulator = groups
            .entry((candidate.isa, candidate.pc))
            .or_default()
            .entry(key)
            .or_default();
        accumulator.functions.extend(candidate.functions);
        accumulator.paths.insert(candidate.provenance_path);
    }

    let mut per_global = BTreeMap::new();
    for global in globals {
        if per_global
            .insert(global.address, PerGlobal::default())
            .is_some()
        {
            return Err(invalid(&format!(
                "duplicate recovered address {}",
                hex(global.address)
            )));
        }
    }

    // One agreement subgroup at a PC is agreement; two or more is a
    // conflict, and every implicated Recovered target receives the
    // complete alternative group. Support count and function order never
    // choose a winner.
    //
    // A subgroup spans every key sharing (target, conditional, kind,
    // width) at that PC. One instruction's transfers (LDM/STM/LDRD) all
    // evaluate against the same register state and share one base
    // register, so a single instruction can only produce same-target,
    // same-kind, same-width keys differing by offset — honest array
    // evidence, one observation per offset. Cross-target, cross-kind, or
    // cross-width keys at one PC necessarily come from distinct
    // interpretations and stay conflicts.
    //
    // Agreed keys are retained per (target, isa, pc) so the interprocedural
    // merge below can tell whether inter evidence agrees with, or must
    // defer to, intra.
    let mut intra_keys: BTreeMap<(u32, Isa, u32), BTreeSet<SemanticKey>> = BTreeMap::new();
    for ((isa, pc), alternatives) in groups {
        let subgroups: BTreeSet<(u32, bool, AccessKind, u8)> = alternatives
            .keys()
            .map(|key| (key.target_address, key.conditional, key.kind, key.width))
            .collect();
        if subgroups.len() == 1 {
            for (key, accumulator) in alternatives {
                let slot = per_global
                    .get_mut(&key.target_address)
                    .ok_or_else(|| invalid("agreed target is not recovered"))?;
                intra_keys
                    .entry((key.target_address, isa, pc))
                    .or_default()
                    .insert(key);
                slot.observations.push(Observation {
                    isa,
                    pc,
                    conditional: key.conditional,
                    kind: key.kind,
                    width: key.width,
                    offset: key.offset,
                    functions: accumulator.functions,
                    paths: accumulator.paths,
                    via: BTreeSet::new(),
                });
            }
        } else {
            let implicated: BTreeSet<u32> =
                alternatives.keys().map(|key| key.target_address).collect();
            let mut built = Vec::with_capacity(alternatives.len());
            for (key, accumulator) in alternatives {
                // Conflicts are intra-only: every candidate that reaches
                // this branch came from `intra`, which never carries `via`.
                if !accumulator.via.is_empty() {
                    return Err(invalid(
                        "conflict alternative must not carry interprocedural via evidence",
                    ));
                }
                built.push(Alternative {
                    target_address: key.target_address,
                    conditional: key.conditional,
                    kind: key.kind,
                    width: key.width,
                    offset: key.offset,
                    functions: accumulator.functions,
                    paths: accumulator.paths,
                });
            }
            let conflict = Conflict {
                isa,
                pc,
                alternatives: built,
            };
            for address in implicated {
                let slot = per_global
                    .get_mut(&address)
                    .ok_or_else(|| invalid("conflict target is not recovered"))?;
                slot.conflicts.push(conflict.clone());
            }
        }
    }

    let (interprocedural_observations, interprocedural_dropped) =
        merge_interprocedural(inter, &intra_keys, &mut per_global)?;

    let mut inferred = 0usize;
    let mut no_evidence = 0usize;
    let mut conflicting = 0usize;
    let mut observations = 0usize;
    let mut conflicts = 0usize;
    let mut emitted = Vec::with_capacity(globals.len());
    for global in globals {
        let data = per_global
            .remove(&global.address)
            .ok_or_else(|| invalid("missing working state for a recovered global"))?;
        let wire = emit_global(global, data)?;
        match wire.status {
            Status::Inferred => bump(&mut inferred, "inferred")?,
            Status::NoEvidence => bump(&mut no_evidence, "no_evidence")?,
            Status::Conflicting => bump(&mut conflicting, "conflicting")?,
        }
        observations = add_count(observations, wire.observations.len(), "observation")?;
        conflicts = add_count(conflicts, wire.conflicts.len(), "conflict")?;
        emitted.push(wire);
    }
    if !per_global.is_empty() {
        return Err(invalid("working state remains for an unknown global"));
    }

    let aggregation = Aggregation {
        globals: emitted,
        inferred,
        no_evidence,
        conflicting,
        observations,
        conflicts,
        interprocedural_observations,
        interprocedural_dropped,
    };
    validate(&aggregation, globals)?;
    Ok(aggregation)
}

// Per target, per `(isa, pc)`, per semantic key — mirrors the intra `groups`
// shape but scoped under an outer target level, since inter candidates are
// grouped per-target before ever looking at `(isa, pc)`.
type InterGroups = BTreeMap<u32, BTreeMap<(Isa, u32), BTreeMap<SemanticKey, Accumulator>>>;

// Interprocedural candidates are attributed directly to their proven
// `target_address` and never enter the cross-global `(isa, pc)` conflict
// pool: a shared callee instruction seeded with different globals from
// different call sites yields one true observation per global, never a
// conflict. Grouping happens per target first (proven), then per `(isa,
// pc)`, unioning `functions`/`paths`/`via` for identical semantic keys.
//
// Intra is authoritative: an inter observation that lands on an `(isa, pc)`
// where intra already agreed on a *different* semantic key is dropped (and
// counted); one that agrees is merged into the existing intra observation;
// one with no intra observation at that `(isa, pc)` becomes new evidence.
// Inter observations never create conflicts and never touch another
// global's record.
fn merge_interprocedural(
    inter: Vec<CandidateObservation>,
    intra_keys: &BTreeMap<(u32, Isa, u32), BTreeSet<SemanticKey>>,
    per_global: &mut BTreeMap<u32, PerGlobal>,
) -> Result<(usize, usize)> {
    let mut inter_groups: InterGroups = BTreeMap::new();
    for candidate in inter {
        let key = SemanticKey {
            target_address: candidate.target_address,
            conditional: candidate.conditional,
            kind: candidate.kind,
            width: candidate.width,
            offset: candidate.offset,
        };
        let accumulator = inter_groups
            .entry(candidate.target_address)
            .or_default()
            .entry((candidate.isa, candidate.pc))
            .or_default()
            .entry(key)
            .or_default();
        accumulator.functions.extend(candidate.functions);
        accumulator.paths.insert(candidate.provenance_path);
        accumulator.via.extend(candidate.via);
    }

    let mut interprocedural_observations = 0usize;
    let mut interprocedural_dropped = 0usize;
    for (target_address, pcs) in inter_groups {
        let slot = per_global
            .get_mut(&target_address)
            .ok_or_else(|| invalid("interprocedural target is not recovered"))?;
        for ((isa, pc), keys) in pcs {
            for (key, accumulator) in keys {
                match intra_keys.get(&(target_address, isa, pc)) {
                    Some(group) if !group.contains(&key) => {
                        interprocedural_dropped =
                            add_count(interprocedural_dropped, 1, "interprocedural_dropped")?;
                    }
                    Some(_) => {
                        let existing = slot
                            .observations
                            .iter_mut()
                            .find(|observation| {
                                observation.isa == isa
                                    && observation.pc == pc
                                    && observation.conditional == key.conditional
                                    && observation.kind == key.kind
                                    && observation.width == key.width
                                    && observation.offset == key.offset
                            })
                            .ok_or_else(|| {
                                invalid("intra semantic key present without a matching observation")
                            })?;
                        existing.functions.extend(accumulator.functions);
                        existing.paths.extend(accumulator.paths);
                        existing.via.extend(accumulator.via);
                        interprocedural_observations = add_count(
                            interprocedural_observations,
                            1,
                            "interprocedural_observations",
                        )?;
                    }
                    None => {
                        slot.observations.push(Observation {
                            isa,
                            pc,
                            conditional: key.conditional,
                            kind: key.kind,
                            width: key.width,
                            offset: key.offset,
                            functions: accumulator.functions,
                            paths: accumulator.paths,
                            via: accumulator.via,
                        });
                        interprocedural_observations = add_count(
                            interprocedural_observations,
                            1,
                            "interprocedural_observations",
                        )?;
                    }
                }
            }
        }
    }
    Ok((interprocedural_observations, interprocedural_dropped))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SemanticKey {
    target_address: u32,
    conditional: bool,
    kind: AccessKind,
    width: u8,
    offset: u32,
}

#[derive(Default)]
struct Accumulator {
    functions: BTreeSet<FunctionContext>,
    paths: BTreeSet<Vec<u32>>,
    via: BTreeSet<CallHop>,
}

struct Observation {
    isa: Isa,
    pc: u32,
    conditional: bool,
    kind: AccessKind,
    width: u8,
    offset: u32,
    functions: BTreeSet<FunctionContext>,
    paths: BTreeSet<Vec<u32>>,
    via: BTreeSet<CallHop>,
}

#[derive(Clone)]
struct Alternative {
    target_address: u32,
    conditional: bool,
    kind: AccessKind,
    width: u8,
    offset: u32,
    functions: BTreeSet<FunctionContext>,
    paths: BTreeSet<Vec<u32>>,
}

#[derive(Clone)]
struct Conflict {
    isa: Isa,
    pc: u32,
    alternatives: Vec<Alternative>,
}

#[derive(Default)]
struct PerGlobal {
    observations: Vec<Observation>,
    conflicts: Vec<Conflict>,
}

struct SummaryAccess {
    width: u8,
    offset: u32,
    kind: AccessKind,
}

fn recovered_addresses(globals: &[RecoveredGlobal]) -> Result<BTreeSet<u32>> {
    let mut addresses = BTreeSet::new();
    for global in globals {
        if !addresses.insert(global.address) {
            return Err(invalid(&format!(
                "duplicate recovered address {}",
                hex(global.address)
            )));
        }
    }
    Ok(addresses)
}

fn emit_global(source: &RecoveredGlobal, mut data: PerGlobal) -> Result<GlobalWire> {
    data.observations.sort_by(|left, right| {
        left.isa
            .cmp(&right.isa)
            .then(left.pc.cmp(&right.pc))
            .then(left.conditional.cmp(&right.conditional))
            .then(left.kind.cmp(&right.kind))
            .then(left.width.cmp(&right.width))
            .then(left.offset.cmp(&right.offset))
    });
    data.conflicts
        .sort_by(|left, right| left.isa.cmp(&right.isa).then(left.pc.cmp(&right.pc)));
    for conflict in &mut data.conflicts {
        conflict.alternatives.sort_by(|left, right| {
            left.target_address
                .cmp(&right.target_address)
                .then(left.conditional.cmp(&right.conditional))
                .then(left.kind.cmp(&right.kind))
                .then(left.width.cmp(&right.width))
                .then(left.offset.cmp(&right.offset))
        });
    }

    let observations = data
        .observations
        .iter()
        .map(observation_wire)
        .collect::<Vec<_>>();
    let conflicts = data.conflicts.iter().map(conflict_wire).collect::<Vec<_>>();
    let (status, summary) = if !conflicts.is_empty() {
        (Status::Conflicting, None)
    } else if observations.is_empty() {
        (Status::NoEvidence, None)
    } else {
        (Status::Inferred, Some(summarize(&data.observations)?))
    };
    Ok(GlobalWire {
        address: hex(source.address),
        name: source.name.clone(),
        arch: source.arch.clone(),
        status,
        observations,
        conflicts,
        summary,
    })
}

fn observation_wire(observation: &Observation) -> ObservationWire {
    ObservationWire {
        arch: isa_wire(observation.isa),
        pc: hex(observation.pc),
        conditional: observation.conditional,
        kind: kind_wire(observation.kind),
        width: observation.width,
        offset: observation.offset,
        functions: functions_wire(&observation.functions),
        provenance_paths: paths_wire(&observation.paths),
        via: via_wire(&observation.via),
    }
}

fn via_wire(via: &BTreeSet<CallHop>) -> Vec<CallHopWire> {
    let mut hops: Vec<&CallHop> = via.iter().collect();
    hops.sort();
    hops.into_iter()
        .map(|hop| CallHopWire {
            caller_entry: hex(hop.caller_entry),
            caller_name: hop.caller_name.clone(),
            call_pc: hex(hop.call_pc),
            arg_register: format!("r{}", hop.arg_register),
        })
        .collect()
}

fn conflict_wire(conflict: &Conflict) -> ConflictWire {
    ConflictWire {
        arch: isa_wire(conflict.isa),
        pc: hex(conflict.pc),
        alternatives: conflict.alternatives.iter().map(alternative_wire).collect(),
    }
}

fn alternative_wire(alternative: &Alternative) -> AlternativeWire {
    AlternativeWire {
        target_address: hex(alternative.target_address),
        conditional: alternative.conditional,
        kind: kind_wire(alternative.kind),
        width: alternative.width,
        offset: alternative.offset,
        functions: functions_wire(&alternative.functions),
        provenance_paths: paths_wire(&alternative.paths),
    }
}

fn functions_wire(functions: &BTreeSet<FunctionContext>) -> Vec<FunctionContextWire> {
    let mut functions: Vec<_> = functions.iter().collect();
    functions.sort_by(|left, right| {
        left.entry
            .cmp(&right.entry)
            .then(left.name.cmp(&right.name))
    });
    functions
        .into_iter()
        .map(|function| FunctionContextWire {
            entry: hex(function.entry),
            name: function.name.clone(),
        })
        .collect()
}

fn paths_wire(paths: &BTreeSet<Vec<u32>>) -> Vec<Vec<String>> {
    let mut paths: Vec<_> = paths.iter().cloned().collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| path.into_iter().map(hex).collect())
        .collect()
}

fn summarize(observations: &[Observation]) -> Result<SummaryWire> {
    compute_summary(observations.iter().map(|observation| SummaryAccess {
        width: observation.width,
        offset: observation.offset,
        kind: observation.kind,
    }))
}

fn summarize_wire(observations: &[ObservationWire]) -> Result<SummaryWire> {
    compute_summary(observations.iter().map(|observation| SummaryAccess {
        width: observation.width,
        offset: observation.offset,
        kind: kind_from_wire(observation.kind),
    }))
}

fn compute_summary(accesses: impl IntoIterator<Item = SummaryAccess>) -> Result<SummaryWire> {
    let accesses: Vec<SummaryAccess> = accesses.into_iter().collect();
    let mut minimum_size = 0u32;
    let mut widths = BTreeSet::new();
    let mut offsets = BTreeSet::new();
    let mut reads = 0usize;
    let mut writes = 0usize;
    for access in &accesses {
        let end = access
            .offset
            .checked_add(u32::from(access.width))
            .ok_or_else(|| invalid("offset + width overflow"))?;
        if end > minimum_size {
            minimum_size = end;
        }
        widths.insert(access.width);
        offsets.insert(access.offset);
        match access.kind {
            AccessKind::Read => reads = add_count(reads, 1, "read")?,
            AccessKind::Write => writes = add_count(writes, 1, "write")?,
            AccessKind::ReadWrite => {
                reads = add_count(reads, 1, "read")?;
                writes = add_count(writes, 1, "write")?;
            }
        }
    }
    let mut observed_widths: Vec<u8> = widths.iter().copied().collect();
    observed_widths.sort_unstable();
    let mut accessed_offsets: Vec<u32> = offsets.iter().copied().collect();
    accessed_offsets.sort_unstable();
    Ok(SummaryWire {
        minimum_size,
        observed_widths,
        accessed_offsets,
        reads,
        writes,
        provisional_shape: classify_shape(&widths, &offsets)?,
    })
}

fn classify_shape(widths: &BTreeSet<u8>, offsets: &BTreeSet<u32>) -> Result<ProvisionalShape> {
    let Some(&width) = widths.first().filter(|_| widths.len() == 1) else {
        return Ok(ProvisionalShape::Unknown);
    };
    if offsets.iter().all(|offset| *offset == 0) {
        return Ok(ProvisionalShape::ScalarCandidate { width });
    }
    if width == 0
        || !offsets.contains(&0)
        || !offsets.iter().any(|offset| *offset != 0)
        || !offsets.iter().all(|offset| *offset % u32::from(width) == 0)
    {
        return Ok(ProvisionalShape::Unknown);
    }
    let max_index = offsets
        .iter()
        .map(|offset| *offset / u32::from(width))
        .max()
        .ok_or_else(|| invalid("array offsets are empty"))?;
    let minimum_elements = max_index
        .checked_add(1)
        .ok_or_else(|| invalid("minimum_elements overflow"))?;
    Ok(ProvisionalShape::ArrayCandidate {
        element_width: width,
        minimum_elements,
    })
}

fn validate(aggregation: &Aggregation, source: &[RecoveredGlobal]) -> Result<()> {
    if aggregation.globals.len() != source.len() {
        return Err(invalid(
            "output global count does not equal recovered global count",
        ));
    }
    let mut seen = BTreeSet::new();
    let source_addresses = recovered_addresses(source)?;
    let mut observations = 0usize;
    let mut conflicts = 0usize;
    let mut inferred = 0usize;
    let mut no_evidence = 0usize;
    let mut conflicting = 0usize;
    let mut interprocedural_observations = 0usize;
    let mut via_bearing: Vec<(&str, &ObservationWire)> = Vec::new();
    for (wire, recovered) in aggregation.globals.iter().zip(source) {
        if wire.address != hex(recovered.address)
            || wire.name != recovered.name
            || wire.arch != recovered.arch
        {
            return Err(invalid("source order, name, or arch was not preserved"));
        }
        let address = parse_hex(&wire.address)?;
        if !source_addresses.contains(&address) {
            return Err(invalid(&format!(
                "output address {} is not a recovered global",
                wire.address
            )));
        }
        if !seen.insert(address) {
            return Err(invalid(&format!(
                "duplicate output address {}",
                wire.address
            )));
        }
        // `AlternativeWire` has no `via` field: conflicts are intra-only by
        // construction (`aggregate` fails closed if interprocedural `via`
        // evidence ever reached the conflict path), so no alternative can
        // carry one.
        for conflict in &wire.conflicts {
            for alternative in &conflict.alternatives {
                let target = parse_hex(&alternative.target_address)?;
                if !source_addresses.contains(&target) {
                    return Err(invalid(&format!(
                        "conflict target {} is not a recovered global",
                        alternative.target_address
                    )));
                }
            }
        }
        match wire.status {
            Status::Inferred => {
                if wire.observations.is_empty()
                    || !wire.conflicts.is_empty()
                    || wire.summary.is_none()
                {
                    return Err(invalid(&format!(
                        "inferred status invariant violated for {}",
                        wire.address
                    )));
                }
                let expected = summarize_wire(&wire.observations)?;
                if wire.summary.as_ref() != Some(&expected) {
                    return Err(invalid(&format!(
                        "summary does not recompute from observations for {}",
                        wire.address
                    )));
                }
                bump(&mut inferred, "inferred")?;
            }
            Status::NoEvidence => {
                if !wire.observations.is_empty()
                    || !wire.conflicts.is_empty()
                    || wire.summary.is_some()
                {
                    return Err(invalid(&format!(
                        "no_evidence status invariant violated for {}",
                        wire.address
                    )));
                }
                bump(&mut no_evidence, "no_evidence")?;
            }
            Status::Conflicting => {
                if wire.conflicts.is_empty() || wire.summary.is_some() {
                    return Err(invalid(&format!(
                        "conflicting status invariant violated for {}",
                        wire.address
                    )));
                }
                bump(&mut conflicting, "conflicting")?;
            }
        }
        for observation in &wire.observations {
            if !observation.via.is_empty() {
                interprocedural_observations = add_count(
                    interprocedural_observations,
                    1,
                    "interprocedural_observations",
                )?;
                via_bearing.push((wire.address.as_str(), observation));
            }
        }
        observations = add_count(observations, wire.observations.len(), "observation")?;
        conflicts = add_count(conflicts, wire.conflicts.len(), "conflict")?;
    }
    if aggregation.inferred != inferred
        || aggregation.no_evidence != no_evidence
        || aggregation.conflicting != conflicting
    {
        return Err(invalid("status counts do not match serialized entries"));
    }
    if inferred
        .checked_add(no_evidence)
        .and_then(|total| total.checked_add(conflicting))
        != Some(source.len())
    {
        return Err(invalid("status counts do not equal recovered globals"));
    }
    if aggregation.observations != observations || aggregation.conflicts != conflicts {
        return Err(invalid(
            "observation or conflict count does not equal serialized entries",
        ));
    }
    if aggregation.interprocedural_observations != interprocedural_observations {
        return Err(invalid(
            "interprocedural_observations does not equal via-bearing observation count",
        ));
    }
    // Every via-bearing observation lives on exactly one global: no two
    // globals may carry byte-identical via-bearing evidence (a shared
    // callee `(isa, pc)` seeded from two call sites is fine, since each
    // side's `via` hop differs; two globals surfacing the exact same
    // observation, `via` included, would mean attribution leaked).
    for outer in 0..via_bearing.len() {
        for inner in (outer + 1)..via_bearing.len() {
            let (left_address, left) = via_bearing[outer];
            let (right_address, right) = via_bearing[inner];
            if left_address != right_address && left == right {
                return Err(invalid(
                    "via-bearing observation appears on more than one global",
                ));
            }
        }
    }
    // `interprocedural_dropped` counts evidence that never reaches the wire
    // output, so it has no independent trace to recompute here; its only
    // producer is `merge_interprocedural`'s single increment site.
    Ok(())
}

fn isa_wire(isa: Isa) -> IsaWire {
    match isa {
        Isa::Arm => IsaWire::Arm,
        Isa::Thumb => IsaWire::Thumb,
    }
}

fn kind_wire(kind: AccessKind) -> AccessKindWire {
    match kind {
        AccessKind::Read => AccessKindWire::Read,
        AccessKind::Write => AccessKindWire::Write,
        AccessKind::ReadWrite => AccessKindWire::ReadWrite,
    }
}

fn kind_from_wire(kind: AccessKindWire) -> AccessKind {
    match kind {
        AccessKindWire::Read => AccessKind::Read,
        AccessKindWire::Write => AccessKind::Write,
        AccessKindWire::ReadWrite => AccessKind::ReadWrite,
    }
}

fn hex(value: u32) -> String {
    format!("0x{value:x}")
}

fn parse_hex(value: &str) -> Result<u32> {
    if !value.starts_with("0x")
        || value.len() == 2
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("address must be lowercase canonical hexadecimal"));
    }
    let parsed =
        u32::from_str_radix(&value[2..], 16).map_err(|_| invalid("address is outside u32"))?;
    if hex(parsed) != value {
        return Err(invalid("address is not canonical hexadecimal"));
    }
    Ok(parsed)
}

fn bump(count: &mut usize, what: &str) -> Result<()> {
    *count = add_count(*count, 1, what)?;
    Ok(())
}

fn add_count(count: usize, extra: usize, what: &str) -> Result<usize> {
    count
        .checked_add(extra)
        .ok_or_else(|| invalid(&format!("{what} count overflow")))
}

fn invalid(message: &str) -> Error {
    Error::Serialize(format!("global_shapes aggregate: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    const G0: u32 = 0x1000;
    const G1: u32 = 0x2000;
    const G2: u32 = 0x3000;
    const PC0: u32 = 0x4000;
    const PC1: u32 = 0x4010;
    const PC2: u32 = 0x4020;

    fn recovered(address: u32, name: &str, arch: &str) -> RecoveredGlobal {
        RecoveredGlobal {
            source_index: 0,
            address,
            name: name.into(),
            arch: arch.into(),
        }
    }

    fn globals(addresses: &[u32]) -> Vec<RecoveredGlobal> {
        addresses
            .iter()
            .enumerate()
            .map(|(index, address)| RecoveredGlobal {
                source_index: index,
                address: *address,
                name: format!("g{index}"),
                arch: "arm".into(),
            })
            .collect()
    }

    fn ctx(entry: u32, name: &str) -> FunctionContext {
        FunctionContext {
            entry,
            name: name.into(),
        }
    }

    fn cand(
        target: u32,
        isa: Isa,
        pc: u32,
        conditional: bool,
        kind: AccessKind,
        width: u8,
        offset: u32,
    ) -> CandidateObservation {
        CandidateObservation {
            target_address: target,
            isa,
            pc,
            conditional,
            kind,
            width,
            offset,
            functions: BTreeSet::new(),
            provenance_path: Vec::new(),
            via: Vec::new(),
        }
    }

    fn with_support(
        mut candidate: CandidateObservation,
        functions: impl IntoIterator<Item = FunctionContext>,
        path: impl Into<Vec<u32>>,
    ) -> CandidateObservation {
        candidate.functions = functions.into_iter().collect();
        candidate.provenance_path = path.into();
        candidate
    }

    fn run(recovered: &[RecoveredGlobal], candidates: Vec<CandidateObservation>) -> Aggregation {
        aggregate(recovered, candidates, Vec::new()).expect("aggregate")
    }

    fn inter(
        target: u32,
        isa: Isa,
        pc: u32,
        kind: AccessKind,
        width: u8,
        offset: u32,
        hop: CallHop,
    ) -> CandidateObservation {
        let mut c = cand(target, isa, pc, false, kind, width, offset);
        c.via = vec![hop];
        c
    }

    fn hop(caller: u32, call_pc: u32, reg: u8) -> CallHop {
        CallHop {
            caller_entry: caller,
            caller_name: "FUN".into(),
            call_pc,
            arg_register: reg,
        }
    }

    fn hex(value: u32) -> String {
        format!("0x{value:x}")
    }

    fn by_addr(aggregation: &Aggregation, address: u32) -> &GlobalWire {
        aggregation
            .globals
            .iter()
            .find(|global| global.address == hex(address))
            .unwrap_or_else(|| panic!("missing global {}", hex(address)))
    }

    fn functions_of(observation: &ObservationWire) -> Vec<(u32, &str)> {
        observation
            .functions
            .iter()
            .map(|function| {
                let entry = u32::from_str_radix(&function.entry[2..], 16).unwrap();
                (entry, function.name.as_str())
            })
            .collect()
    }

    fn paths_of(observation: &ObservationWire) -> Vec<Vec<u32>> {
        observation
            .provenance_paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|pc| u32::from_str_radix(&pc[2..], 16).unwrap())
                    .collect()
            })
            .collect()
    }

    fn serialize_err(
        recovered: &[RecoveredGlobal],
        candidates: Vec<CandidateObservation>,
    ) -> String {
        match aggregate(recovered, candidates, Vec::new()) {
            Err(Error::Serialize(message)) => message,
            other => panic!("expected serialize error, got {other:?}"),
        }
    }

    #[test]
    fn same_pc_identical_alternatives_union_dedup_and_sort() {
        let recovered = globals(&[G0]);
        let candidates = vec![
            with_support(
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                [ctx(0x2000, "z"), ctx(0x1000, "a")],
                [0x10, 0x20],
            ),
            with_support(
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                [ctx(0x1000, "a"), ctx(0x1000, "b")],
                [0x10],
            ),
            with_support(
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                [ctx(0x1000, "a")],
                [0x10, 0x20],
            ),
            with_support(
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                [],
                [0x8, 0x30],
            ),
        ];
        let aggregation = run(&recovered, candidates);
        let global = by_addr(&aggregation, G0);
        assert_eq!(global.status, Status::Inferred);
        assert_eq!(global.conflicts.len(), 0);
        assert_eq!(global.observations.len(), 1);
        let observation = &global.observations[0];
        assert_eq!(observation.arch, IsaWire::Arm);
        assert_eq!(observation.pc, hex(PC0));
        assert!(!observation.conditional);
        assert_eq!(observation.kind, AccessKindWire::Read);
        assert_eq!(observation.width, 4);
        assert_eq!(observation.offset, 0);
        assert_eq!(
            functions_of(observation),
            vec![(0x1000, "a"), (0x1000, "b"), (0x2000, "z")]
        );
        assert_eq!(
            paths_of(observation),
            vec![vec![0x8, 0x30], vec![0x10], vec![0x10, 0x20]]
        );
    }

    #[test]
    fn same_pc_disagreement_in_target_conditional_kind_or_width_is_a_conflict() {
        struct Case {
            name: &'static str,
            recovered: Vec<RecoveredGlobal>,
            left: CandidateObservation,
            right: CandidateObservation,
            implicated: &'static [u32],
        }
        let cases = [
            Case {
                name: "target",
                recovered: globals(&[G0, G1]),
                left: cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                right: cand(G1, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                implicated: &[G0, G1],
            },
            Case {
                name: "conditional",
                recovered: globals(&[G0]),
                left: cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                right: cand(G0, Isa::Arm, PC0, true, AccessKind::Read, 4, 0),
                implicated: &[G0],
            },
            Case {
                name: "kind",
                recovered: globals(&[G0]),
                left: cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                right: cand(G0, Isa::Arm, PC0, false, AccessKind::Write, 4, 0),
                implicated: &[G0],
            },
            Case {
                name: "width",
                recovered: globals(&[G0]),
                left: cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                right: cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 2, 0),
                implicated: &[G0],
            },
        ];
        for case in cases {
            let aggregation = run(&case.recovered, vec![case.left.clone(), case.right.clone()]);
            for address in case.implicated {
                let global = by_addr(&aggregation, *address);
                assert_eq!(
                    global.status,
                    Status::Conflicting,
                    "{} must conflict",
                    case.name
                );
                assert!(
                    global.summary.is_none(),
                    "{} summary must be null",
                    case.name
                );
                assert_eq!(global.observations.len(), 0, "{} observations", case.name);
                assert_eq!(global.conflicts.len(), 1, "{} conflicts", case.name);
                assert_eq!(global.conflicts[0].alternatives.len(), 2, "{}", case.name);
            }
        }
    }

    #[test]
    fn same_target_multi_offset_one_pc_are_observations_not_conflict() {
        // One LDM at PC0 reading [r0,#0] and [r0,#4] of G0.
        let recovered = globals(&[G0]);
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 4),
            ],
        );
        let global = by_addr(&aggregation, G0);
        assert_eq!(global.status, Status::Inferred);
        assert!(global.conflicts.is_empty());
        assert_eq!(global.observations.len(), 2);
        let summary = global.summary.as_ref().unwrap();
        assert_eq!(summary.minimum_size, 8);
        assert!(matches!(
            summary.provisional_shape,
            ProvisionalShape::ArrayCandidate {
                element_width: 4,
                minimum_elements: 2
            }
        ));
    }

    #[test]
    fn cross_target_one_pc_still_conflicts_even_with_offset_variants() {
        // Two interpretations at PC0: &G0 (+0/+4) and &G1 (+0). The whole
        // PC group must remain a conflict with all three alternatives.
        let recovered = globals(&[G0, G1]);
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 4),
                cand(G1, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
            ],
        );
        for address in [G0, G1] {
            let global = by_addr(&aggregation, address);
            assert_eq!(global.status, Status::Conflicting);
            assert_eq!(global.conflicts[0].alternatives.len(), 3);
        }
    }

    #[test]
    fn differing_kind_or_width_at_one_pc_still_conflicts() {
        let recovered = globals(&[G0]);
        let kind = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC0, false, AccessKind::Write, 4, 0),
            ],
        );
        assert_eq!(by_addr(&kind, G0).status, Status::Conflicting);
        let width = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 2, 0),
            ],
        );
        assert_eq!(by_addr(&width, G0).status, Status::Conflicting);
    }

    #[test]
    fn same_pc_never_selects_by_function_order_or_support_count() {
        let recovered = globals(&[G0]);
        let mut candidates = Vec::new();
        for index in 0..8 {
            candidates.push(with_support(
                cand(G0, Isa::Thumb, PC0, false, AccessKind::Write, 4, 0),
                [ctx(0x5000 + index, "popular")],
                [0x40],
            ));
        }
        candidates.push(with_support(
            cand(G0, Isa::Thumb, PC0, false, AccessKind::Read, 1, 8),
            [ctx(0x9, "rare")],
            [0x41],
        ));
        let aggregation = run(&recovered, candidates);
        let global = by_addr(&aggregation, G0);
        assert_eq!(global.status, Status::Conflicting);
        assert_eq!(global.observations.len(), 0);
        assert_eq!(global.conflicts.len(), 1);
        let alternatives = &global.conflicts[0].alternatives;
        assert_eq!(alternatives.len(), 2);
        assert_eq!(alternatives[0].kind, AccessKindWire::Read);
        assert_eq!(alternatives[0].width, 1);
        assert_eq!(alternatives[0].offset, 8);
        assert_eq!(alternatives[0].functions[0].name, "rare");
        assert_eq!(alternatives[1].kind, AccessKindWire::Write);
        assert_eq!(alternatives[1].width, 4);
        assert_eq!(alternatives[1].functions.len(), 8);
    }

    #[test]
    fn same_pc_implicated_targets_receive_full_conflict_group() {
        let recovered = globals(&[G0, G1]);
        let candidates = vec![
            with_support(
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                [ctx(0x100, "left")],
                [0x10],
            ),
            with_support(
                cand(G1, Isa::Arm, PC0, true, AccessKind::Write, 2, 8),
                [ctx(0x200, "right")],
                [0x11],
            ),
        ];
        let aggregation = run(&recovered, candidates);
        for address in [G0, G1] {
            let global = by_addr(&aggregation, address);
            assert_eq!(global.status, Status::Conflicting);
            assert_eq!(global.observations.len(), 0);
            assert_eq!(global.conflicts.len(), 1);
            let alternatives = &global.conflicts[0].alternatives;
            assert_eq!(alternatives.len(), 2);
            assert_eq!(alternatives[0].target_address, hex(G0));
            assert_eq!(alternatives[0].kind, AccessKindWire::Read);
            assert_eq!(alternatives[0].functions[0].name, "left");
            assert_eq!(alternatives[1].target_address, hex(G1));
            assert_eq!(alternatives[1].kind, AccessKindWire::Write);
            assert_eq!(alternatives[1].functions[0].name, "right");
            assert!(alternatives[1].conditional);
            assert_eq!(alternatives[1].width, 2);
            assert_eq!(alternatives[1].offset, 8);
        }
        assert_eq!(
            by_addr(&aggregation, G0).conflicts,
            by_addr(&aggregation, G1).conflicts
        );
        assert_eq!(aggregation.conflicts, 2);
    }

    #[test]
    fn same_pc_unrelated_pcs_remain_ordinary_evidence() {
        let recovered = globals(&[G0]);
        let candidates = vec![
            cand(G0, Isa::Thumb, 0x1000, true, AccessKind::Write, 1, 3),
            cand(G0, Isa::Arm, 0x2000, false, AccessKind::Read, 4, 0),
            cand(G0, Isa::Arm, 0x1000, true, AccessKind::ReadWrite, 2, 8),
        ];
        let aggregation = run(&recovered, candidates);
        let global = by_addr(&aggregation, G0);
        assert_eq!(global.status, Status::Inferred);
        assert!(global.conflicts.is_empty());
        assert_eq!(global.observations.len(), 3);
        assert_eq!(global.observations[0].arch, IsaWire::Arm);
        assert_eq!(global.observations[0].pc, hex(0x1000));
        assert_eq!(global.observations[0].kind, AccessKindWire::ReadWrite);
        assert_eq!(global.observations[0].width, 2);
        assert_eq!(global.observations[0].offset, 8);
        assert_eq!(global.observations[1].arch, IsaWire::Arm);
        assert_eq!(global.observations[1].pc, hex(0x2000));
        assert_eq!(global.observations[2].arch, IsaWire::Thumb);
        assert_eq!(global.observations[2].pc, hex(0x1000));
        assert!(global.observations[2].conditional);
        assert_eq!(global.observations[2].kind, AccessKindWire::Write);
        assert_eq!(global.observations[2].width, 1);
        assert_eq!(global.observations[2].offset, 3);
    }

    #[test]
    fn same_pc_retains_nonconflicting_observations_when_conflicting() {
        let recovered = globals(&[G0, G1]);
        let candidates = vec![
            cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
            cand(G0, Isa::Arm, PC1, false, AccessKind::Read, 4, 0),
            cand(G1, Isa::Arm, PC1, false, AccessKind::Write, 2, 4),
        ];
        let aggregation = run(&recovered, candidates);
        let left = by_addr(&aggregation, G0);
        assert_eq!(left.status, Status::Conflicting);
        assert!(left.summary.is_none());
        assert_eq!(left.observations.len(), 1);
        assert_eq!(left.observations[0].pc, hex(PC0));
        assert_eq!(left.conflicts.len(), 1);
        assert_eq!(left.conflicts[0].pc, hex(PC1));
        assert_eq!(left.conflicts[0].alternatives.len(), 2);
        let right = by_addr(&aggregation, G1);
        assert_eq!(right.status, Status::Conflicting);
        assert!(right.observations.is_empty());
        assert_eq!(right.conflicts.len(), 1);
        assert_eq!(right.conflicts[0].alternatives.len(), 2);
    }

    #[test]
    fn same_pc_unknown_target_cannot_enter_aggregation() {
        let recovered = globals(&[G0]);
        let message = serialize_err(
            &recovered,
            vec![cand(0x9999, Isa::Arm, PC0, false, AccessKind::Read, 4, 0)],
        );
        assert!(message.starts_with("global_shapes aggregate:"), "{message}");
        assert!(message.contains("0x9999"), "{message}");

        let mixed = serialize_err(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(0x1234, Isa::Arm, PC1, false, AccessKind::Write, 4, 0),
            ],
        );
        assert!(mixed.starts_with("global_shapes aggregate:"), "{mixed}");
        assert!(mixed.contains("0x1234"), "{mixed}");
    }

    #[test]
    fn summary_minimum_size_is_checked_max_offset_plus_width() {
        let recovered = globals(&[G0]);
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC1, false, AccessKind::Write, 2, 4),
                cand(G0, Isa::Arm, PC2, false, AccessKind::Read, 1, 8),
            ],
        );
        let summary = by_addr(&aggregation, G0).summary.as_ref().unwrap();
        assert_eq!(summary.minimum_size, 9);

        let overflow = serialize_err(
            &recovered,
            vec![cand(
                G0,
                Isa::Arm,
                PC0,
                false,
                AccessKind::Read,
                1,
                u32::MAX,
            )],
        );
        assert!(
            overflow.starts_with("global_shapes aggregate:"),
            "{overflow}"
        );
        assert!(overflow.contains("overflow"), "{overflow}");
    }

    #[test]
    fn summary_widths_and_offsets_are_sorted_unique() {
        let recovered = globals(&[G0]);
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, 0x4018, false, AccessKind::Read, 4, 8),
                cand(G0, Isa::Arm, 0x4004, false, AccessKind::Write, 1, 2),
                cand(G0, Isa::Arm, 0x4008, false, AccessKind::Read, 4, 2),
                cand(G0, Isa::Arm, 0x400c, false, AccessKind::Read, 2, 0),
                cand(G0, Isa::Arm, 0x4014, false, AccessKind::Write, 1, 8),
            ],
        );
        let summary = by_addr(&aggregation, G0).summary.as_ref().unwrap();
        assert_eq!(summary.observed_widths, vec![1, 2, 4]);
        assert_eq!(summary.accessed_offsets, vec![0, 2, 8]);
    }

    #[test]
    fn summary_counts_unique_instruction_observations() {
        let recovered = globals(&[G0]);
        let aggregation = run(
            &recovered,
            vec![
                with_support(
                    cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                    [ctx(0x10, "a")],
                    [0x1],
                ),
                with_support(
                    cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                    [ctx(0x20, "b")],
                    [0x2],
                ),
                cand(G0, Isa::Arm, PC1, false, AccessKind::Write, 4, 0),
                cand(G0, Isa::Arm, PC2, false, AccessKind::ReadWrite, 4, 0),
            ],
        );
        let summary = by_addr(&aggregation, G0).summary.as_ref().unwrap();
        assert_eq!(summary.reads, 2);
        assert_eq!(summary.writes, 2);
        assert_eq!(by_addr(&aggregation, G0).observations.len(), 3);
    }

    #[test]
    fn summary_scalar_only_for_common_width_and_offset_zero() {
        let recovered = globals(&[G0, G1]);
        let scalar = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Thumb, PC1, true, AccessKind::Write, 4, 0),
            ],
        );
        assert_eq!(
            by_addr(&scalar, G0)
                .summary
                .as_ref()
                .unwrap()
                .provisional_shape,
            ProvisionalShape::ScalarCandidate { width: 4 }
        );

        let mixed_width = run(
            &recovered,
            vec![
                cand(G1, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G1, Isa::Arm, PC1, false, AccessKind::Read, 2, 0),
            ],
        );
        assert_eq!(
            by_addr(&mixed_width, G1)
                .summary
                .as_ref()
                .unwrap()
                .provisional_shape,
            ProvisionalShape::Unknown
        );
    }

    #[test]
    fn summary_array_only_for_aligned_zero_and_nonzero() {
        let recovered = globals(&[G0, G1, G2]);
        let array = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC1, false, AccessKind::Write, 4, 8),
            ],
        );
        assert_eq!(
            by_addr(&array, G0)
                .summary
                .as_ref()
                .unwrap()
                .provisional_shape,
            ProvisionalShape::ArrayCandidate {
                element_width: 4,
                minimum_elements: 3,
            }
        );

        let missing_zero = run(
            &recovered,
            vec![
                cand(G1, Isa::Arm, PC0, false, AccessKind::Read, 4, 4),
                cand(G1, Isa::Arm, PC1, false, AccessKind::Read, 4, 8),
            ],
        );
        assert_eq!(
            by_addr(&missing_zero, G1)
                .summary
                .as_ref()
                .unwrap()
                .provisional_shape,
            ProvisionalShape::Unknown
        );

        let mixed_width = run(
            &recovered,
            vec![
                cand(G2, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G2, Isa::Arm, PC1, false, AccessKind::Read, 2, 4),
            ],
        );
        assert_eq!(
            by_addr(&mixed_width, G2)
                .summary
                .as_ref()
                .unwrap()
                .provisional_shape,
            ProvisionalShape::Unknown
        );
    }

    #[test]
    fn summary_array_allows_holes_and_computes_minimum_elements() {
        let recovered = globals(&[G0]);
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC1, false, AccessKind::Read, 4, 8),
                cand(G0, Isa::Arm, PC2, false, AccessKind::Write, 4, 16),
            ],
        );
        let summary = by_addr(&aggregation, G0).summary.as_ref().unwrap();
        assert_eq!(summary.accessed_offsets, vec![0, 8, 16]);
        assert_eq!(
            summary.provisional_shape,
            ProvisionalShape::ArrayCandidate {
                element_width: 4,
                minimum_elements: 5,
            }
        );
    }

    #[test]
    fn summary_mixed_width_misaligned_or_no_zero_is_unknown() {
        let recovered = globals(&[G0, G1, G2]);
        let mixed = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC1, false, AccessKind::Read, 1, 4),
            ],
        );
        let misaligned = run(
            &recovered,
            vec![
                cand(G1, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G1, Isa::Arm, PC1, false, AccessKind::Read, 4, 2),
            ],
        );
        let no_zero = run(
            &recovered,
            vec![cand(G2, Isa::Arm, PC0, false, AccessKind::Read, 2, 4)],
        );
        for (aggregation, address) in [(&mixed, G0), (&misaligned, G1), (&no_zero, G2)] {
            assert_eq!(
                by_addr(aggregation, address)
                    .summary
                    .as_ref()
                    .unwrap()
                    .provisional_shape,
                ProvisionalShape::Unknown
            );
        }
    }

    #[test]
    fn summary_non_null_only_for_inferred() {
        let recovered = vec![
            recovered(G0, "inferred", "arm"),
            recovered(G1, "none", "thumb"),
            recovered(G2, "conflict", "mixed"),
        ];
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G2, Isa::Arm, PC1, false, AccessKind::Read, 4, 0),
                cand(G2, Isa::Arm, PC1, false, AccessKind::Write, 4, 0),
            ],
        );
        assert!(by_addr(&aggregation, G0).summary.is_some());
        assert!(by_addr(&aggregation, G1).summary.is_none());
        assert!(by_addr(&aggregation, G2).summary.is_none());
    }

    #[test]
    fn status_inferred_iff_observations_nonempty_and_conflicts_empty() {
        let recovered = globals(&[G0]);
        let aggregation = run(
            &recovered,
            vec![cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0)],
        );
        let global = by_addr(&aggregation, G0);
        assert_eq!(global.status, Status::Inferred);
        assert!(!global.observations.is_empty());
        assert!(global.conflicts.is_empty());
        assert!(global.summary.is_some());
        assert_eq!(aggregation.inferred, 1);
    }

    #[test]
    fn status_no_evidence_iff_both_empty() {
        let recovered = globals(&[G0]);
        let aggregation = run(&recovered, Vec::new());
        let global = by_addr(&aggregation, G0);
        assert_eq!(global.status, Status::NoEvidence);
        assert!(global.observations.is_empty());
        assert!(global.conflicts.is_empty());
        assert!(global.summary.is_none());
        assert_eq!(aggregation.no_evidence, 1);
    }

    #[test]
    fn status_conflicting_iff_conflicts_nonempty() {
        let recovered = globals(&[G0, G1]);
        let empty_obs = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC0, false, AccessKind::Write, 4, 0),
            ],
        );
        assert_eq!(by_addr(&empty_obs, G0).status, Status::Conflicting);
        assert!(by_addr(&empty_obs, G0).observations.is_empty());
        assert!(!by_addr(&empty_obs, G0).conflicts.is_empty());
        assert!(by_addr(&empty_obs, G0).summary.is_none());

        let with_obs = run(
            &recovered,
            vec![
                cand(G1, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G1, Isa::Arm, PC1, false, AccessKind::Read, 4, 0),
                cand(G1, Isa::Arm, PC1, false, AccessKind::Write, 2, 0),
            ],
        );
        assert_eq!(by_addr(&with_obs, G1).status, Status::Conflicting);
        assert_eq!(by_addr(&with_obs, G1).observations.len(), 1);
        assert!(!by_addr(&with_obs, G1).conflicts.is_empty());
        assert!(by_addr(&with_obs, G1).summary.is_none());
    }

    #[test]
    fn status_counts_sum_to_globals_len() {
        let recovered = vec![
            recovered(G0, "keep-name", "mixed"),
            recovered(G2, "middle", "thumb"),
            recovered(G1, "last", "arm"),
        ];
        let aggregation = run(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G1, Isa::Thumb, PC1, false, AccessKind::Read, 4, 0),
                cand(G1, Isa::Thumb, PC1, true, AccessKind::Read, 4, 0),
            ],
        );
        assert_eq!(aggregation.inferred, 1);
        assert_eq!(aggregation.no_evidence, 1);
        assert_eq!(aggregation.conflicting, 1);
        assert_eq!(
            aggregation.inferred + aggregation.no_evidence + aggregation.conflicting,
            aggregation.globals.len()
        );
        assert_eq!(
            aggregation
                .globals
                .iter()
                .map(|g| g.address.as_str())
                .collect::<Vec<_>>(),
            vec![hex(G0), hex(G2), hex(G1)]
        );
        assert_eq!(aggregation.globals[0].name, "keep-name");
        assert_eq!(aggregation.globals[0].arch, "mixed");
        assert_eq!(aggregation.globals[1].name, "middle");
        assert_eq!(aggregation.globals[2].name, "last");
    }

    #[test]
    fn interprocedural_shared_callee_pc_is_not_a_conflict() {
        // Same callee PC seeded with two different globals from two call
        // sites => two independent observations, NOT a conflict.
        let recovered = globals(&[G0, G1]);
        let agg = aggregate(
            &recovered,
            Vec::new(),
            vec![
                inter(
                    G0,
                    Isa::Thumb,
                    PC0,
                    AccessKind::Read,
                    4,
                    0,
                    hop(0xA00, 0xA10, 0),
                ),
                inter(
                    G1,
                    Isa::Thumb,
                    PC0,
                    AccessKind::Read,
                    4,
                    0,
                    hop(0xB00, 0xB10, 0),
                ),
            ],
        )
        .unwrap();
        assert_eq!(by_addr(&agg, G0).status, Status::Inferred);
        assert_eq!(by_addr(&agg, G1).status, Status::Inferred);
        assert!(by_addr(&agg, G0).conflicts.is_empty());
        // the observation carries its via hop
        assert_eq!(by_addr(&agg, G0).observations[0].via.len(), 1);
    }

    #[test]
    fn interprocedural_matches_intra_key_across_multi_offset_group() {
        // Intra LDM at PC0 observes offsets 0 and 4; an inter candidate at
        // the same PC whose key equals the offset-4 intra key merges into
        // the offset-4 observation, and one matching no intra key is
        // dropped.
        let recovered = globals(&[G0]);
        let agg = aggregate(
            &recovered,
            vec![
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0),
                cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 4),
            ],
            vec![
                inter(
                    G0,
                    Isa::Arm,
                    PC0,
                    AccessKind::Read,
                    4,
                    4,
                    hop(0xA00, 0xA10, 0),
                ),
                inter(
                    G0,
                    Isa::Arm,
                    PC0,
                    AccessKind::Read,
                    4,
                    8,
                    hop(0xB00, 0xB10, 0),
                ),
            ],
        )
        .unwrap();
        let g = by_addr(&agg, G0);
        assert_eq!(g.status, Status::Inferred);
        assert_eq!(g.observations.len(), 2);
        let off0 = g
            .observations
            .iter()
            .find(|observation| observation.offset == 0)
            .unwrap();
        let off4 = g
            .observations
            .iter()
            .find(|observation| observation.offset == 4)
            .unwrap();
        assert!(off0.via.is_empty());
        assert_eq!(off4.via.len(), 1);
        assert_eq!(agg.interprocedural_observations, 1);
        assert_eq!(agg.interprocedural_dropped, 1);
    }

    #[test]
    fn interprocedural_never_demotes_an_intra_inferred() {
        // G0 is intra-inferred at PC0; an interprocedural obs at the SAME
        // pc with a different semantic key is dropped (intra wins), G0
        // stays inferred.
        let recovered = globals(&[G0]);
        let agg = aggregate(
            &recovered,
            vec![cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0)],
            vec![inter(
                G0,
                Isa::Arm,
                PC0,
                AccessKind::Write,
                2,
                0,
                hop(0xA00, 0xA10, 1),
            )],
        )
        .unwrap();
        assert_eq!(by_addr(&agg, G0).status, Status::Inferred);
        assert_eq!(by_addr(&agg, G0).observations.len(), 1);
        assert_eq!(by_addr(&agg, G0).observations[0].kind, AccessKindWire::Read);
        assert_eq!(agg.interprocedural_dropped, 1);
    }

    #[test]
    fn interprocedural_enriches_summary_of_existing_inferred() {
        // intra obs at offset 0 width 4; inter obs at offset 8 width 4
        // grows minimum_size.
        let recovered = globals(&[G0]);
        let agg = aggregate(
            &recovered,
            vec![cand(G0, Isa::Arm, PC0, false, AccessKind::Read, 4, 0)],
            vec![inter(
                G0,
                Isa::Arm,
                PC1,
                AccessKind::Read,
                4,
                8,
                hop(0xA00, 0xA10, 0),
            )],
        )
        .unwrap();
        let g = by_addr(&agg, G0);
        assert_eq!(g.status, Status::Inferred);
        assert_eq!(g.summary.as_ref().unwrap().minimum_size, 12);
        assert_eq!(agg.interprocedural_observations, 1);
    }
}
