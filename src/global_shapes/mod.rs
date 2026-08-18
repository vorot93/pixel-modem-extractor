// Per-image coordinator: decode, track, aggregate, and atomically commit
// one `global_shapes.json` sidecar.

mod aggregate;
mod artifact;
mod decoder;
mod tracker;
mod validate;

use crate::error::{Error, Result};
use crate::execution_ranges::{DecodeIsa as Isa, ExecutionIdentity};
use aggregate::{Aggregation, aggregate};
use artifact::{
    AnalysisWire, DecoderWire, GlobalShapesFile, InputHashesWire, LoadedInputs, Status, serialize,
    write_atomic,
};
use decoder::{InstructionDecoder, Register, decode_function, reachable_blocks};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use tracker::{CallFact, CallHop, CandidateObservation};

pub const FORMAT_V3: &str = "pixel-modem-extractor-global-shapes-v3";
pub use validate::{validate_artifact, validate_artifact_files};

#[derive(Debug)]
pub(crate) struct RunRequest<'a> {
    pub image_dir: &'a Path,
    pub image_label: &'a str,
    pub manifest_path: &'a Path,
    pub expected_ghidra_records: usize,
    pub expected_ghidra_accepted: usize,
    pub expected_ghidra_quarantined: usize,
    pub expected_thumb_substantial: Option<usize>,
    pub expected_thumb_accepted: Option<usize>,
    pub expected_thumb_quarantined: Option<usize>,
    pub expected_recovered_globals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalShapesReport {
    pub inferred: usize,
    pub no_evidence: usize,
    pub conflicting: usize,
    pub observations: usize,
    pub ghidra_quarantined: usize,
    pub thumb_quarantined: usize,
    pub quarantine_errors: usize,
    pub decode_failures: usize,
    pub state_barriers: usize,
    pub interprocedural_dropped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FunctionContext {
    pub entry: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FunctionExecution {
    pub identity: ExecutionIdentity,
    pub contexts: BTreeSet<FunctionContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceProjectionCounts {
    pub ghidra_accepted: usize,
    pub ghidra_quarantined: usize,
    pub thumb_accepted: usize,
    pub thumb_quarantined: usize,
    pub quarantine_errors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredGlobal {
    pub source_index: usize,
    pub address: u32,
    pub name: String,
    pub arch: String,
}

const PANIC_REASON_MAX_CHARS: usize = 2_048;

struct ImageAnalysis {
    file: GlobalShapesFile,
    report: GlobalShapesReport,
}

pub(crate) fn run_image(request: &RunRequest<'_>) -> Result<GlobalShapesReport> {
    run_image_with_decoder(request, &decoder::PureRustDecoder)
}

fn run_image_with_decoder(
    request: &RunRequest<'_>,
    decoder: &impl InstructionDecoder,
) -> Result<GlobalShapesReport> {
    run_image_with(request, decoder, aggregate, serialize, write_atomic)
}

fn run_image_with(
    request: &RunRequest<'_>,
    decoder: &impl InstructionDecoder,
    aggregate_fn: impl FnOnce(
        &[RecoveredGlobal],
        Vec<CandidateObservation>,
        Vec<CandidateObservation>,
    ) -> Result<Aggregation>,
    serialize_fn: impl FnOnce(&GlobalShapesFile) -> Result<Vec<u8>>,
    write_fn: impl FnOnce(&Path, &[u8]) -> Result<()>,
) -> Result<GlobalShapesReport> {
    let inputs = artifact::load_inputs(request)?;
    let analysis = match catch_unwind(AssertUnwindSafe(|| {
        analyze_loaded_inputs(request.image_label, &inputs, decoder, aggregate_fn)
    })) {
        Ok(result) => result?,
        Err(payload) => return Err(decoder_panic_error(payload)),
    };
    revalidate(&analysis.file, &inputs, &analysis.report)?;
    let path = request
        .image_dir
        .join("decompiled")
        .join("global_shapes.json");
    commit_artifact_with(&analysis.file, &path, serialize_fn, write_fn)?;
    Ok(analysis.report)
}

/// Pass-2 bookkeeping for one distinct (callee identity, seed vector) replay:
/// every resolved `CallFact` that harvested this exact seed for this exact
/// callee contributes to `hops_by_address`, keyed by the recovered global
/// address each seed entry carried (never by register), since a candidate's
/// `via` is stamped purely from which address it proves, not from how the
/// callee's own register flow happened to reach it.
struct SeedGroup<'a> {
    callee: &'a FunctionExecution,
    seed: BTreeMap<Register, u32>,
    hops_by_address: BTreeMap<u32, BTreeSet<CallHop>>,
}

/// Strict depth-1 callee resolution: an accepted identity's entry must equal
/// `target` exactly, and its first decode range's ISA (the ISA the entry is
/// actually invoked in) must equal `isa`. Zero or more than one surviving
/// match is unresolved, never a guess.
fn resolve_callee<'a>(
    entry_index: &BTreeMap<u32, Vec<&'a FunctionExecution>>,
    target: u32,
    isa: Isa,
) -> Option<&'a FunctionExecution> {
    let mut matches = entry_index
        .get(&target)
        .into_iter()
        .flatten()
        .copied()
        .filter(|candidate| {
            candidate
                .identity
                .decode_ranges
                .first()
                .map(|range| range.isa)
                == Some(isa)
        });
    let callee = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(callee)
}

fn analyze_loaded_inputs(
    image_label: &str,
    inputs: &LoadedInputs,
    decoder: &impl InstructionDecoder,
    aggregate_fn: impl FnOnce(
        &[RecoveredGlobal],
        Vec<CandidateObservation>,
        Vec<CandidateObservation>,
    ) -> Result<Aggregation>,
) -> Result<ImageAnalysis> {
    let identity = decoder.identity();
    // Pass 1 tracks every accepted identity cold (no interprocedural seed),
    // collecting both its intra-procedural candidates and any call-facts it
    // harvests. Pass 2 (below) resolves those call-facts strictly against
    // the accepted-identity index, groups them by (callee identity, seed
    // vector), and re-tracks each distinct group once with its seed; only
    // evidence that traces back to a seeded global is kept as `inter`.
    let mut intra = Vec::new();
    let mut inter_candidates = Vec::new();
    let mut instructions_decoded = 0usize;
    let mut decode_failures = 0usize;
    let mut state_barriers = 0usize;
    let mut arm_functions = 0usize;
    let mut thumb_functions = 0usize;
    let mut direct_calls_resolved = 0usize;
    let mut call_facts_unresolved = 0usize;
    let mut seeded_callees = 0usize;
    let mut seed_vectors = 0usize;
    let mut cross_block_join_kills = 0usize;
    let mut cross_block_join_facts = 0usize;
    let mut cross_block_entry_facts = 0usize;
    let mut cross_block_propagated_facts = 0usize;
    let mut cross_block_functions: BTreeSet<u32> = BTreeSet::new();
    let mut cross_block_seeded_functions: BTreeSet<u32> = BTreeSet::new();

    if !inputs.globals.is_empty() {
        let recovered: BTreeSet<u32> = inputs.globals.iter().map(|global| global.address).collect();
        let mut functions: Vec<&FunctionExecution> = inputs.functions.iter().collect();
        functions.sort_by(|left, right| left.identity.cmp(&right.identity));
        (arm_functions, thumb_functions) = count_isa_identities(functions.iter().copied())?;

        let mut entry_index: BTreeMap<u32, Vec<&FunctionExecution>> = BTreeMap::new();
        for function in &functions {
            entry_index
                .entry(function.identity.entry)
                .or_default()
                .push(*function);
        }

        let mut call_facts: Vec<CallFact> = Vec::new();
        for function in functions {
            let decoded = decode_function(decoder, function, &inputs.image, inputs.load_address)?;
            for range in &decoded.ranges {
                instructions_decoded = add_count(
                    instructions_decoded,
                    range.instructions.len(),
                    "instructions_decoded",
                )?;
                if range.decode_failure.is_some() {
                    bump(&mut decode_failures, "decode_failures")?;
                }
            }
            let blocks = reachable_blocks(function, &decoded)?;
            if blocks.is_empty()
                && decoded
                    .ranges
                    .iter()
                    .all(|range| range.decode_failure.is_none())
            {
                bump(&mut decode_failures, "decode_failures")?;
            }
            let tracked = tracker::track_function(
                function,
                &decoded,
                &blocks,
                &inputs.image,
                inputs.load_address,
                &recovered,
                &BTreeMap::new(),
            )?;
            state_barriers = add_count(state_barriers, tracked.state_barriers, "state_barriers")?;
            cross_block_join_kills = add_count(
                cross_block_join_kills,
                tracked.join_kills,
                "cross_block_join_kills",
            )?;
            cross_block_join_facts = add_count(
                cross_block_join_facts,
                tracked.join_facts,
                "cross_block_join_facts",
            )?;
            cross_block_entry_facts = add_count(
                cross_block_entry_facts,
                tracked.entry_facts,
                "cross_block_entry_facts",
            )?;
            cross_block_propagated_facts = add_count(
                cross_block_propagated_facts,
                tracked.propagated_facts,
                "cross_block_propagated_facts",
            )?;
            if tracked.join_survivor {
                cross_block_functions.insert(function.identity.entry);
            }
            intra.extend(tracked.candidates);
            call_facts.extend(tracked.call_facts);
        }

        // Resolve, then group resolved facts by (callee identity, seed
        // vector) so identical seeds harvested from different call sites
        // replay the callee exactly once; union their CallHop provenance.
        let mut groups: BTreeMap<(ExecutionIdentity, Vec<(u8, u32)>), SeedGroup<'_>> =
            BTreeMap::new();
        for fact in &call_facts {
            let Some(callee) = resolve_callee(&entry_index, fact.callee_target, fact.callee_isa)
            else {
                bump(&mut call_facts_unresolved, "call_facts_unresolved")?;
                continue;
            };
            bump(&mut direct_calls_resolved, "direct_calls_resolved")?;
            let seed_key: Vec<(u8, u32)> = fact
                .seed
                .iter()
                .map(|(register, address)| (register.0, *address))
                .collect();
            let group = groups
                .entry((callee.identity.clone(), seed_key))
                .or_insert_with(|| SeedGroup {
                    callee,
                    seed: fact.seed.clone(),
                    hops_by_address: BTreeMap::new(),
                });
            for (register, address) in &fact.seed {
                for context in &fact.caller_contexts {
                    group
                        .hops_by_address
                        .entry(*address)
                        .or_default()
                        .insert(CallHop {
                            caller_entry: fact.caller_entry,
                            caller_name: context.name.clone(),
                            call_pc: fact.call_pc,
                            arg_register: register.0,
                        });
                }
            }
        }

        // Pass 2: re-track each distinct group once with its seed. Its own
        // harvested call-facts are discarded (depth-1: no seed originates
        // from a seeded run). A resulting candidate is kept only when its
        // target address is one this group actually seeded — anything else
        // is evidence this same callee would produce on its own and is
        // already covered by its own Pass-1 cold run.
        seed_vectors = groups.len();
        let mut seeded_callee_identities: BTreeSet<ExecutionIdentity> = BTreeSet::new();
        for group in groups.values() {
            seeded_callee_identities.insert(group.callee.identity.clone());
            let decoded =
                decode_function(decoder, group.callee, &inputs.image, inputs.load_address)?;
            let blocks = reachable_blocks(group.callee, &decoded)?;
            let tracked = tracker::track_function(
                group.callee,
                &decoded,
                &blocks,
                &inputs.image,
                inputs.load_address,
                &recovered,
                &group.seed,
            )?;
            cross_block_join_kills = add_count(
                cross_block_join_kills,
                tracked.join_kills,
                "cross_block_join_kills",
            )?;
            cross_block_join_facts = add_count(
                cross_block_join_facts,
                tracked.join_facts,
                "cross_block_join_facts",
            )?;
            cross_block_entry_facts = add_count(
                cross_block_entry_facts,
                tracked.entry_facts,
                "cross_block_entry_facts",
            )?;
            cross_block_propagated_facts = add_count(
                cross_block_propagated_facts,
                tracked.propagated_facts,
                "cross_block_propagated_facts",
            )?;
            if tracked.join_survivor {
                cross_block_functions.insert(group.callee.identity.entry);
                if !group.seed.is_empty() {
                    cross_block_seeded_functions.insert(group.callee.identity.entry);
                }
            }
            for mut candidate in tracked.candidates {
                let Some(hops) = group.hops_by_address.get(&candidate.target_address) else {
                    continue;
                };
                candidate.via = hops.iter().cloned().collect();
                inter_candidates.push(candidate);
            }
        }
        seeded_callees = seeded_callee_identities.len();
    }

    let aggregation = aggregate_fn(&inputs.globals, intra, inter_candidates)?;
    let file = GlobalShapesFile {
        format: FORMAT_V3,
        image: image_label.to_owned(),
        load_address: hex(inputs.load_address),
        inputs: InputHashesWire {
            image_sha256: inputs.hashes.image_sha256.clone(),
            globals_sha256: inputs.hashes.globals_sha256.clone(),
            functions_sha256: inputs.hashes.functions_sha256.clone(),
            thumb_functions_sha256: inputs.hashes.thumb_functions_sha256.clone(),
        },
        decoder: DecoderWire {
            crate_name: identity.crate_name.to_owned(),
            version: identity.version.to_owned(),
        },
        analysis: AnalysisWire {
            arm_functions,
            thumb_functions,
            ghidra_records_quarantined: inputs.source_counts.ghidra_quarantined,
            thumb_records_quarantined: inputs.source_counts.thumb_quarantined,
            quarantine_errors: inputs.source_counts.quarantine_errors,
            instructions_decoded,
            decode_failures,
            state_barriers,
            observations: aggregation.observations,
            conflicts: aggregation.conflicts,
            direct_calls_resolved,
            call_facts_unresolved,
            seeded_callees,
            seed_vectors,
            interprocedural_observations: aggregation.interprocedural_observations,
            interprocedural_dropped: aggregation.interprocedural_dropped,
            cross_block_join_kills,
            cross_block_join_facts,
            cross_block_entry_facts,
            cross_block_propagated_facts,
            cross_block_functions: cross_block_functions.len(),
            cross_block_seeded_functions: cross_block_seeded_functions.len(),
        },
        globals: aggregation.globals,
    };
    Ok(ImageAnalysis {
        report: GlobalShapesReport {
            inferred: aggregation.inferred,
            no_evidence: aggregation.no_evidence,
            conflicting: aggregation.conflicting,
            observations: aggregation.observations,
            ghidra_quarantined: inputs.source_counts.ghidra_quarantined,
            thumb_quarantined: inputs.source_counts.thumb_quarantined,
            quarantine_errors: inputs.source_counts.quarantine_errors,
            decode_failures,
            state_barriers,
            interprocedural_dropped: aggregation.interprocedural_dropped,
        },
        file,
    })
}

fn commit_artifact_with(
    file: &GlobalShapesFile,
    path: &Path,
    serialize_fn: impl FnOnce(&GlobalShapesFile) -> Result<Vec<u8>>,
    write_fn: impl FnOnce(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    let bytes = serialize_fn(file)?;
    write_fn(path, &bytes)
}

fn revalidate(
    file: &GlobalShapesFile,
    inputs: &LoadedInputs,
    report: &GlobalShapesReport,
) -> Result<()> {
    if file.format != FORMAT_V3 {
        return Err(invalid("artifact format is not v3"));
    }
    if file.globals.len() != inputs.globals.len() {
        return Err(invalid(
            "output global count does not equal recovered global count",
        ));
    }

    let mut inferred = 0usize;
    let mut no_evidence = 0usize;
    let mut conflicting = 0usize;
    let mut observations = 0usize;
    let mut conflicts = 0usize;
    // Depth-1 interprocedural evidence has no marker of its own beyond a
    // non-empty `via`; the status invariants and summary-recompute below
    // already run over each global's complete (intra + surviving
    // interprocedural) observation set, since `wire.observations` is the
    // merged list `aggregate` produced.
    let mut interprocedural_observations = 0usize;
    for (wire, recovered) in file.globals.iter().zip(&inputs.globals) {
        if wire.address != hex(recovered.address)
            || wire.name != recovered.name
            || wire.arch != recovered.arch
        {
            return Err(invalid("source order, name, or arch was not preserved"));
        }
        for observation in &wire.observations {
            if !observation.via.is_empty() {
                interprocedural_observations = add_count(
                    interprocedural_observations,
                    1,
                    "interprocedural_observations",
                )?;
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
        observations = add_count(observations, wire.observations.len(), "observation")?;
        conflicts = add_count(conflicts, wire.conflicts.len(), "conflict")?;
    }
    if inferred != report.inferred
        || no_evidence != report.no_evidence
        || conflicting != report.conflicting
    {
        return Err(invalid("status counts do not match serialized entries"));
    }
    if inferred
        .checked_add(no_evidence)
        .and_then(|total| total.checked_add(conflicting))
        != Some(inputs.globals.len())
    {
        return Err(invalid("status counts do not equal recovered globals"));
    }
    if file.analysis.observations != observations
        || file.analysis.conflicts != conflicts
        || report.observations != observations
        || file.analysis.observations != report.observations
    {
        return Err(invalid(
            "observation or conflict count does not equal serialized entries",
        ));
    }
    if file.analysis.interprocedural_observations != interprocedural_observations {
        return Err(invalid(
            "interprocedural_observations does not equal via-bearing observation count",
        ));
    }
    if file.analysis.interprocedural_dropped != report.interprocedural_dropped {
        return Err(invalid("interprocedural_dropped does not match the report"));
    }
    if file.analysis.ghidra_records_quarantined != inputs.source_counts.ghidra_quarantined
        || file.analysis.thumb_records_quarantined != inputs.source_counts.thumb_quarantined
        || file.analysis.quarantine_errors != inputs.source_counts.quarantine_errors
        || report.ghidra_quarantined != inputs.source_counts.ghidra_quarantined
        || report.thumb_quarantined != inputs.source_counts.thumb_quarantined
        || report.quarantine_errors != inputs.source_counts.quarantine_errors
    {
        return Err(invalid(
            "quarantine counts do not match validated source records",
        ));
    }
    if file.analysis.decode_failures != report.decode_failures
        || file.analysis.state_barriers != report.state_barriers
    {
        return Err(invalid("decoder counters do not match the report"));
    }
    if inputs.globals.is_empty()
        && (file.analysis.arm_functions != 0
            || file.analysis.thumb_functions != 0
            || file.analysis.instructions_decoded != 0
            || file.analysis.decode_failures != 0
            || file.analysis.state_barriers != 0
            || file.analysis.observations != 0
            || file.analysis.conflicts != 0
            || file.analysis.direct_calls_resolved != 0
            || file.analysis.call_facts_unresolved != 0
            || file.analysis.seeded_callees != 0
            || file.analysis.seed_vectors != 0
            || file.analysis.interprocedural_observations != 0
            || file.analysis.interprocedural_dropped != 0
            || file.analysis.cross_block_join_kills != 0
            || file.analysis.cross_block_join_facts != 0
            || file.analysis.cross_block_entry_facts != 0
            || file.analysis.cross_block_propagated_facts != 0
            || file.analysis.cross_block_functions != 0
            || file.analysis.cross_block_seeded_functions != 0)
    {
        return Err(invalid("empty recovered set must not analyze identities"));
    }
    if !inputs.globals.is_empty() {
        let (arm, thumb) = count_isa_identities(inputs.functions.iter())?;
        if file.analysis.arm_functions != arm || file.analysis.thumb_functions != thumb {
            return Err(invalid(
                "analyzed identity ISA counts do not match unique accepted identities",
            ));
        }
    }
    Ok(())
}

fn count_isa_identities<'a>(
    functions: impl IntoIterator<Item = &'a FunctionExecution>,
) -> Result<(usize, usize)> {
    let mut arm = 0usize;
    let mut thumb = 0usize;
    for function in functions {
        if identity_has_isa(function, Isa::Arm) {
            bump(&mut arm, "arm_functions")?;
        }
        if identity_has_isa(function, Isa::Thumb) {
            bump(&mut thumb, "thumb_functions")?;
        }
    }
    Ok((arm, thumb))
}

fn identity_has_isa(function: &FunctionExecution, isa: Isa) -> bool {
    function
        .identity
        .decode_ranges
        .iter()
        .any(|range| range.isa == isa)
}

fn decoder_panic_error(payload: Box<dyn Any + Send>) -> Error {
    let raw = if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic payload".to_owned()
    };
    let bounded: String = raw.chars().take(PANIC_REASON_MAX_CHARS).collect();
    Error::Serialize(format!("global_shapes decoder panic: {bounded}"))
}

fn hex(value: u32) -> String {
    format!("0x{value:x}")
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
    Error::Serialize(format!("global_shapes: {message}"))
}

/// Test-only seam: analyze an image to the exact sidecar bytes without
/// opening or replacing `decompiled/global_shapes.json`.
#[cfg(test)]
fn analyze_to_bytes_without_commit(
    request: &RunRequest<'_>,
) -> Result<(Vec<u8>, GlobalShapesReport)> {
    let inputs = artifact::load_inputs(request)?;
    let analysis = match catch_unwind(AssertUnwindSafe(|| {
        analyze_loaded_inputs(
            request.image_label,
            &inputs,
            &decoder::PureRustDecoder,
            aggregate,
        )
    })) {
        Ok(result) => result?,
        Err(payload) => return Err(decoder_panic_error(payload)),
    };
    revalidate(&analysis.file, &inputs, &analysis.report)?;
    Ok((serialize(&analysis.file)?, analysis.report))
}

#[cfg(test)]
mod tests {
    use super::{
        GlobalShapesReport, RunRequest, aggregate, analyze_to_bytes_without_commit,
        commit_artifact_with, decoder_panic_error, run_image, run_image_with,
        run_image_with_decoder, validate_artifact, validate_artifact_files,
    };
    use crate::error::Error;
    use crate::execution_ranges::DecodeIsa as Isa;
    use crate::global_shapes::artifact::{
        AccessKindWire, AnalysisWire, DecoderWire, FunctionContextWire, GlobalShapesFile,
        GlobalWire, InputHashesWire, IsaWire, ObservationWire, ProvisionalShape, Status,
        SummaryWire, serialize, write_atomic, write_atomic_with_before_commit,
    };
    use crate::global_shapes::decoder::{
        AccessKind, AddressBase, AddressExpr, AddressOffset, CallTarget, ControlFlow, DecodeError,
        DecodedInstruction, DecoderIdentity, InstructionDecoder, MemoryEffect, MemoryTransfer,
        PureRustDecoder, Register, SemanticEffect, ValueExpr, decode_function,
    };
    use crate::global_shapes::{FORMAT_V3, FunctionContext, FunctionExecution};
    use crate::manifest::sha256_bytes;
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};

    const LABEL: &str = "02_MAIN";
    const LOAD_ADDR: u32 = 0x4000;
    const R0: Register = Register(0);
    const R1: Register = Register(1);
    const SCALAR: u32 = 0x5000;
    const ARRAY: u32 = 0x5100;
    const NONE: u32 = 0x5200;
    const OLD_SIDECAR: &[u8] = b"older global_shapes.json";
    const INTERPROC_CALLER_ENTRY: u32 = 0x4000;
    const INTERPROC_CALL_PC: u32 = 0x4004;
    const INTERPROC_CALLEE_ENTRY: u32 = 0x4100;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "pme_global_shapes_run_{name}_{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join(LABEL).join("decompiled")).unwrap();
            Self { root }
        }

        fn image_dir(&self) -> PathBuf {
            self.root.join(LABEL)
        }

        fn decompiled(&self) -> PathBuf {
            self.image_dir().join("decompiled")
        }

        fn sidecar(&self) -> PathBuf {
            self.decompiled().join("global_shapes.json")
        }

        fn manifest_path(&self) -> PathBuf {
            self.root.join("manifest.json")
        }

        fn write_manifest(&self) {
            fs::write(
                self.manifest_path(),
                format!(r#"{{"toc":[{{"name":"MAIN","load_addr":{}}}]}}"#, LOAD_ADDR),
            )
            .unwrap();
        }

        fn write_image(&self, bytes: &[u8]) {
            fs::write(self.image_dir().join(format!("{LABEL}.bin")), bytes).unwrap();
        }

        fn write_globals(&self, value: &Value) {
            fs::write(self.decompiled().join("globals.json"), value.to_string()).unwrap();
        }

        fn write_functions(&self, value: &Value) {
            fs::write(self.decompiled().join("functions.json"), value.to_string()).unwrap();
        }

        fn write_thumb(&self, value: &Value) {
            fs::write(
                self.decompiled().join("thumb_functions.json"),
                value.to_string(),
            )
            .unwrap();
        }

        fn seed_old_sidecar(&self) {
            fs::write(self.sidecar(), OLD_SIDECAR).unwrap();
        }

        fn assert_old_sidecar(&self) {
            assert_eq!(fs::read(self.sidecar()).unwrap(), OLD_SIDECAR);
        }

        fn hash_sources(&self) -> (String, String, String, String) {
            (
                sha256_bytes(&fs::read(self.image_dir().join(format!("{LABEL}.bin"))).unwrap()),
                sha256_bytes(&fs::read(self.decompiled().join("globals.json")).unwrap()),
                sha256_bytes(&fs::read(self.decompiled().join("functions.json")).unwrap()),
                sha256_bytes(&fs::read(self.decompiled().join("thumb_functions.json")).unwrap()),
            )
        }
    }

    struct BoundRequest {
        image_dir: PathBuf,
        manifest: PathBuf,
        ghidra_records: usize,
        ghidra_accepted: usize,
        ghidra_quarantined: usize,
        thumb_substantial: Option<usize>,
        thumb_accepted: Option<usize>,
        thumb_quarantined: Option<usize>,
        recovered: usize,
    }

    impl BoundRequest {
        #[allow(clippy::too_many_arguments)]
        fn from_fixture(
            fixture: &Fixture,
            ghidra_records: usize,
            ghidra_accepted: usize,
            ghidra_quarantined: usize,
            thumb_substantial: Option<usize>,
            thumb_accepted: Option<usize>,
            thumb_quarantined: Option<usize>,
            recovered: usize,
        ) -> Self {
            Self {
                image_dir: fixture.image_dir(),
                manifest: fixture.manifest_path(),
                ghidra_records,
                ghidra_accepted,
                ghidra_quarantined,
                thumb_substantial,
                thumb_accepted,
                thumb_quarantined,
                recovered,
            }
        }

        fn get(&self) -> RunRequest<'_> {
            RunRequest {
                image_dir: &self.image_dir,
                image_label: LABEL,
                manifest_path: &self.manifest,
                expected_ghidra_records: self.ghidra_records,
                expected_ghidra_accepted: self.ghidra_accepted,
                expected_ghidra_quarantined: self.ghidra_quarantined,
                expected_thumb_substantial: self.thumb_substantial,
                expected_thumb_accepted: self.thumb_accepted,
                expected_thumb_quarantined: self.thumb_quarantined,
                expected_recovered_globals: self.recovered,
            }
        }
    }

    fn recovered_global(address: &str, name: &str, arch: &str) -> Value {
        json!({
            "address": address,
            "arch": arch,
            "name": name,
            "tier": "recovered",
            "size": null,
            "evidence": [],
            "annotations": [],
        })
    }

    fn provisional_global(address: &str, name: &str) -> Value {
        json!({
            "address": address,
            "arch": "arm",
            "name": name,
            "tier": "provisional",
            "size": null,
            "evidence": [],
            "annotations": [],
        })
    }

    fn globals_file(globals: &[Value]) -> Value {
        json!({
            "format": "pixel-modem-extractor-globals-v1",
            "image": LABEL,
            "globals": globals,
            "phase3_0_1_error": null,
            "provisional_suppressed": 0,
        })
    }

    fn arm_range(start: &str, end: &str) -> Value {
        json!({"isa": "arm", "start": start, "end": end})
    }

    fn thumb_range(start: &str, end: &str) -> Value {
        json!({"isa": "thumb", "start": start, "end": end})
    }

    fn ghidra_accepted(name: &str, entry: &str, end: &str, size: u64, ranges: Vec<Value>) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "end": end,
            "size": size,
            "decode_ranges": ranges,
            "decode_range_errors": [],
            "data_refs": [],
        })
    }

    fn ghidra_quarantined(
        name: &str,
        entry: &str,
        end: &str,
        size: u64,
        errors: Vec<Value>,
    ) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "end": end,
            "size": size,
            "decode_ranges": [],
            "decode_range_errors": errors,
            "data_refs": [],
        })
    }

    fn thumb_accepted(name: &str, entry: &str, size: u64, ranges: Vec<Value>) -> Value {
        json!({
            "name": name,
            "entry": entry,
            "size": size,
            "decode_ranges": ranges,
            "decode_range_errors": [],
        })
    }

    fn thumb_file(functions: &[Value]) -> Value {
        json!({
            "format": "pixel-modem-extractor-thumb-functions-v2",
            "functions": functions,
        })
    }

    fn quarantine_error(kind: &str, address: &str) -> Value {
        json!({"kind": kind, "address": address, "end": null})
    }

    fn synthetic_image_bytes() -> Vec<u8> {
        let mut image = vec![0u8; 0x100];
        image[0x00..0x04].copy_from_slice(&[0x00, 0x00, 0x05, 0xe3]);
        image[0x04..0x08].copy_from_slice(&[0x00, 0x10, 0x90, 0xe5]);
        image[0x40..0x44].copy_from_slice(&[0x45, 0xf2, 0x00, 0x10]);
        image[0x44..0x46].copy_from_slice(&[0x01, 0x80]);
        image[0x46..0x48].copy_from_slice(&[0x01, 0x82]);
        image[0x80..0x84].copy_from_slice(&[0x00, 0x00, 0x00, 0xea]);
        image[0x88..0x8a].copy_from_slice(&[0x00, 0xbf]);
        image[0xc0..0xc4].copy_from_slice(&[0x00, 0x00, 0xa0, 0xe1]);
        image[0xc4..0xc8].copy_from_slice(&[0x00, 0x00, 0xa0, 0xe1]);
        image
    }

    fn write_synthetic_sources(fixture: &Fixture, recovered: &[Value]) {
        fixture.write_manifest();
        fixture.write_image(&synthetic_image_bytes());
        fixture.write_globals(&globals_file(recovered));
        fixture.write_functions(&json!([
            ghidra_accepted(
                "FUN_arm",
                "0x4000",
                "0x4008",
                8,
                vec![arm_range("0x4000", "0x4008")],
            ),
            ghidra_accepted(
                "FUN_mixed",
                "0x4080",
                "0x408c",
                12,
                vec![
                    arm_range("0x4080", "0x4084"),
                    thumb_range("0x4088", "0x408c"),
                ],
            ),
            ghidra_accepted(
                "FUN_overlap_arm",
                "0x40c0",
                "0x40c8",
                8,
                vec![arm_range("0x40c0", "0x40c8")],
            ),
            ghidra_accepted(
                "FUN_overlap_thumb",
                "0x40c0",
                "0x40c8",
                8,
                vec![thumb_range("0x40c0", "0x40c8")],
            ),
            ghidra_quarantined(
                "FUN_quarantined",
                "0x4100",
                "0x4104",
                4,
                vec![quarantine_error("empty_projection", "0x4100")],
            ),
        ]));
        fixture.write_thumb(&thumb_file(&[thumb_accepted(
            "thumb_4040",
            "0x4040",
            32,
            vec![thumb_range("0x4040", "0x4048")],
        )]));
    }

    fn synthetic_recovered() -> Vec<Value> {
        vec![
            recovered_global("0x5000", "g_scalar", "arm"),
            recovered_global("0x5100", "g_array", "thumb"),
            recovered_global("0x5200", "g_none", "mixed"),
        ]
    }

    fn synthetic_bound(fixture: &Fixture, recovered: usize) -> BoundRequest {
        let globals = if recovered == 0 {
            vec![provisional_global("0x5000", "skip")]
        } else {
            synthetic_recovered()
        };
        write_synthetic_sources(fixture, &globals);
        BoundRequest::from_fixture(fixture, 5, 4, 1, Some(1), Some(1), Some(0), recovered)
    }

    // A separate, dedicated fixture for the depth-1 interprocedural
    // coordinator test (below). It deliberately does not extend
    // `synthetic_image_bytes`/`write_synthetic_sources`: those are shared by
    // every test above via `synthetic_bound`, and several pin exact byte
    // counts (`instructions_decoded`, `arm_functions`/`thumb_functions`,
    // ghidra/thumb accepted counts) against the golden
    // `synthetic_image_writes_complete_v2_sidecar` sidecar. A single accepted
    // ARM caller and Thumb callee keep this fixture minimal and independent.
    fn interproc_image_bytes() -> Vec<u8> {
        vec![0u8; 0x200]
    }

    fn write_interproc_sources(fixture: &Fixture) {
        fixture.write_manifest();
        fixture.write_image(&interproc_image_bytes());
        fixture.write_globals(&globals_file(&[recovered_global(
            &hex(SCALAR),
            "g_scalar",
            "arm",
        )]));
        fixture.write_functions(&json!([ghidra_accepted(
            "FUN_caller",
            &hex(INTERPROC_CALLER_ENTRY),
            &hex(INTERPROC_CALLER_ENTRY + 8),
            8,
            vec![arm_range(
                &hex(INTERPROC_CALLER_ENTRY),
                &hex(INTERPROC_CALLER_ENTRY + 8),
            )],
        )]));
        fixture.write_thumb(&thumb_file(&[thumb_accepted(
            "thumb_callee",
            &hex(INTERPROC_CALLEE_ENTRY),
            32,
            vec![thumb_range(
                &hex(INTERPROC_CALLEE_ENTRY),
                &hex(INTERPROC_CALLEE_ENTRY + 4),
            )],
        )]));
    }

    fn interproc_bound(fixture: &Fixture) -> BoundRequest {
        write_interproc_sources(fixture);
        BoundRequest::from_fixture(fixture, 1, 1, 0, Some(1), Some(1), Some(0), 1)
    }

    fn hex(value: u32) -> String {
        format!("0x{value:x}")
    }

    fn insn(
        isa: Isa,
        pc: u32,
        length: u8,
        writes: impl IntoIterator<Item = Register>,
        effect: SemanticEffect,
        flow: ControlFlow,
    ) -> DecodedInstruction {
        DecodedInstruction {
            isa,
            pc,
            length,
            conditional: false,
            reads: BTreeSet::new(),
            writes: writes.into_iter().collect(),
            effect,
            flow,
        }
    }

    fn mov_imm(isa: Isa, pc: u32, length: u8, dst: Register, value: u32) -> DecodedInstruction {
        insn(
            isa,
            pc,
            length,
            [dst],
            SemanticEffect::RegisterWrite {
                dst,
                value: ValueExpr::Immediate(value),
            },
            ControlFlow::Linear,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mem(
        isa: Isa,
        pc: u32,
        length: u8,
        base: Register,
        offset: i64,
        kind: AccessKind,
        width: u8,
        dests: impl IntoIterator<Item = Register>,
    ) -> DecodedInstruction {
        insn(
            isa,
            pc,
            length,
            dests,
            SemanticEffect::Memory(MemoryEffect {
                transfers: vec![MemoryTransfer {
                    address: AddressExpr {
                        base: AddressBase::Register(base),
                        offset: AddressOffset::Immediate(offset),
                    },
                    kind,
                    width,
                }],
                writeback: None,
            }),
            ControlFlow::Linear,
        )
    }

    fn branch(isa: Isa, pc: u32, length: u8, target: u32) -> DecodedInstruction {
        insn(
            isa,
            pc,
            length,
            [],
            SemanticEffect::None,
            ControlFlow::DirectBranch {
                target,
                has_fallthrough: false,
            },
        )
    }

    fn wrong_pc(isa: Isa, pc: u32) -> DecodedInstruction {
        insn(
            isa,
            pc.wrapping_add(4),
            4,
            [],
            SemanticEffect::None,
            ControlFlow::Linear,
        )
    }

    struct MapDecoder {
        crate_name: &'static str,
        version: &'static str,
        insns: BTreeMap<(Isa, u32), DecodedInstruction>,
        errors: BTreeMap<(Isa, u32), &'static str>,
        panic_at: Option<(Isa, u32)>,
    }

    impl MapDecoder {
        fn fixture() -> Self {
            let mut decoder = Self {
                crate_name: "test-decoder",
                version: "fixture",
                insns: BTreeMap::new(),
                errors: BTreeMap::new(),
                panic_at: None,
            };
            decoder
                .insns
                .insert((Isa::Arm, 0x4000), mov_imm(Isa::Arm, 0x4000, 4, R0, SCALAR));
            decoder.insns.insert(
                (Isa::Arm, 0x4004),
                mem(Isa::Arm, 0x4004, 4, R0, 0, AccessKind::Read, 4, [R1]),
            );
            decoder.insns.insert(
                (Isa::Thumb, 0x4040),
                mov_imm(Isa::Thumb, 0x4040, 4, R0, ARRAY),
            );
            decoder.insns.insert(
                (Isa::Thumb, 0x4044),
                mem(Isa::Thumb, 0x4044, 2, R0, 0, AccessKind::Write, 2, []),
            );
            decoder.insns.insert(
                (Isa::Thumb, 0x4046),
                mem(Isa::Thumb, 0x4046, 2, R0, 8, AccessKind::Write, 2, []),
            );
            decoder
                .insns
                .insert((Isa::Arm, 0x4080), branch(Isa::Arm, 0x4080, 4, 0x4088));
            decoder
        }

        fn panicking() -> Self {
            let mut decoder = Self::fixture();
            decoder.panic_at = Some((Isa::Arm, 0x4000));
            decoder
        }

        fn invariant_failure() -> Self {
            let mut decoder = Self::fixture();
            decoder
                .insns
                .insert((Isa::Arm, 0x4000), wrong_pc(Isa::Arm, 0x4000));
            decoder
        }

        /// A dedicated (non-`fixture`-derived) decoder for the depth-1
        /// interprocedural coordinator test: an ARM caller does
        /// `mov r0, &g_scalar` then a direct `bl` into a Thumb callee. The
        /// callee's entry block holds only an unconditional branch; the
        /// seeded `str [r0, #0]` sits in the successor block (mirroring
        /// `seeded_fact_flows_beyond_the_entry_block`), so the seeded fact
        /// must cross a block edge to reach its dereference.
        fn with_interproc_call() -> Self {
            let mut decoder = Self {
                crate_name: "test-decoder",
                version: "fixture",
                insns: BTreeMap::new(),
                errors: BTreeMap::new(),
                panic_at: None,
            };
            decoder.insns.insert(
                (Isa::Arm, INTERPROC_CALLER_ENTRY),
                mov_imm(Isa::Arm, INTERPROC_CALLER_ENTRY, 4, R0, SCALAR),
            );
            decoder.insns.insert(
                (Isa::Arm, INTERPROC_CALL_PC),
                insn(
                    Isa::Arm,
                    INTERPROC_CALL_PC,
                    4,
                    [],
                    SemanticEffect::None,
                    ControlFlow::Call {
                        target: Some(CallTarget {
                            entry: INTERPROC_CALLEE_ENTRY,
                            isa: Isa::Thumb,
                        }),
                    },
                ),
            );
            decoder.insns.insert(
                (Isa::Thumb, INTERPROC_CALLEE_ENTRY),
                branch(
                    Isa::Thumb,
                    INTERPROC_CALLEE_ENTRY,
                    2,
                    INTERPROC_CALLEE_ENTRY + 2,
                ),
            );
            decoder.insns.insert(
                (Isa::Thumb, INTERPROC_CALLEE_ENTRY + 2),
                mem(
                    Isa::Thumb,
                    INTERPROC_CALLEE_ENTRY + 2,
                    2,
                    R0,
                    0,
                    AccessKind::Write,
                    4,
                    [],
                ),
            );
            decoder
        }
    }

    impl InstructionDecoder for MapDecoder {
        type RangeState = ();

        fn identity(&self) -> DecoderIdentity {
            DecoderIdentity {
                crate_name: self.crate_name,
                version: self.version,
            }
        }

        fn begin_range(&self, _isa: Isa) {}

        fn decode_one(
            &self,
            _state: &mut Self::RangeState,
            isa: Isa,
            pc: u32,
            _bytes: &[u8],
        ) -> std::result::Result<DecodedInstruction, DecodeError> {
            if self.panic_at == Some((isa, pc)) {
                panic!("deliberate decoder panic");
            }
            if let Some(message) = self.errors.get(&(isa, pc)) {
                return Err(DecodeError {
                    message: (*message).to_owned(),
                });
            }
            if let Some(instruction) = self.insns.get(&(isa, pc)) {
                return Ok(instruction.clone());
            }
            Ok(insn(
                isa,
                pc,
                match isa {
                    Isa::Arm => 4,
                    Isa::Thumb => 2,
                },
                [],
                SemanticEffect::None,
                ControlFlow::Linear,
            ))
        }
    }

    fn serialize_err(result: crate::error::Result<GlobalShapesReport>) -> String {
        match result {
            Err(Error::Serialize(message)) => message,
            other => panic!("expected serialize error, got {other:?}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observation(
        isa: IsaWire,
        pc: u32,
        kind: AccessKindWire,
        width: u8,
        offset: u32,
        entry: u32,
        name: &str,
        provenance: &[u32],
    ) -> ObservationWire {
        ObservationWire {
            arch: isa,
            pc: hex(pc),
            conditional: false,
            kind,
            width,
            offset,
            functions: vec![FunctionContextWire {
                entry: hex(entry),
                name: name.to_owned(),
            }],
            provenance_paths: vec![provenance.iter().copied().map(hex).collect()],
            via: Vec::new(),
        }
    }

    fn expected_synthetic_file(fixture: &Fixture) -> GlobalShapesFile {
        let (image_sha256, globals_sha256, functions_sha256, thumb_sha256) = fixture.hash_sources();
        GlobalShapesFile {
            format: FORMAT_V3,
            image: LABEL.into(),
            load_address: hex(LOAD_ADDR),
            inputs: InputHashesWire {
                image_sha256,
                globals_sha256,
                functions_sha256,
                thumb_functions_sha256: Some(thumb_sha256),
            },
            decoder: DecoderWire {
                crate_name: "test-decoder".into(),
                version: "fixture".into(),
            },
            analysis: AnalysisWire {
                arm_functions: 3,
                thumb_functions: 3,
                ghidra_records_quarantined: 1,
                thumb_records_quarantined: 0,
                quarantine_errors: 1,
                instructions_decoded: 14,
                decode_failures: 0,
                state_barriers: 0,
                observations: 3,
                conflicts: 0,
                direct_calls_resolved: 0,
                call_facts_unresolved: 0,
                seeded_callees: 0,
                seed_vectors: 0,
                interprocedural_observations: 0,
                interprocedural_dropped: 0,
                cross_block_join_kills: 0,
                cross_block_join_facts: 0,
                cross_block_entry_facts: 0,
                cross_block_propagated_facts: 0,
                cross_block_functions: 0,
                cross_block_seeded_functions: 0,
            },
            globals: vec![
                GlobalWire {
                    address: hex(SCALAR),
                    name: "g_scalar".into(),
                    arch: "arm".into(),
                    status: Status::Inferred,
                    observations: vec![observation(
                        IsaWire::Arm,
                        0x4004,
                        AccessKindWire::Read,
                        4,
                        0,
                        0x4000,
                        "FUN_arm",
                        &[0x4000],
                    )],
                    conflicts: vec![],
                    summary: Some(SummaryWire {
                        minimum_size: 4,
                        observed_widths: vec![4],
                        accessed_offsets: vec![0],
                        reads: 1,
                        writes: 0,
                        provisional_shape: ProvisionalShape::ScalarCandidate { width: 4 },
                    }),
                },
                GlobalWire {
                    address: hex(ARRAY),
                    name: "g_array".into(),
                    arch: "thumb".into(),
                    status: Status::Inferred,
                    observations: vec![
                        observation(
                            IsaWire::Thumb,
                            0x4044,
                            AccessKindWire::Write,
                            2,
                            0,
                            0x4040,
                            "thumb_4040",
                            &[0x4040],
                        ),
                        observation(
                            IsaWire::Thumb,
                            0x4046,
                            AccessKindWire::Write,
                            2,
                            8,
                            0x4040,
                            "thumb_4040",
                            &[0x4040],
                        ),
                    ],
                    conflicts: vec![],
                    summary: Some(SummaryWire {
                        minimum_size: 10,
                        observed_widths: vec![2],
                        accessed_offsets: vec![0, 8],
                        reads: 0,
                        writes: 2,
                        provisional_shape: ProvisionalShape::ArrayCandidate {
                            element_width: 2,
                            minimum_elements: 5,
                        },
                    }),
                },
                GlobalWire {
                    address: hex(NONE),
                    name: "g_none".into(),
                    arch: "mixed".into(),
                    status: Status::NoEvidence,
                    observations: vec![],
                    conflicts: vec![],
                    summary: None,
                },
            ],
        }
    }

    #[test]
    fn synthetic_image_writes_complete_v3_sidecar() {
        let fixture = Fixture::new("synthetic");
        let bound = synthetic_bound(&fixture, 3);
        let report = run_image_with_decoder(&bound.get(), &MapDecoder::fixture())
            .expect("synthetic image analysis");
        assert_eq!(
            report,
            GlobalShapesReport {
                inferred: 2,
                no_evidence: 1,
                conflicting: 0,
                observations: 3,
                ghidra_quarantined: 1,
                thumb_quarantined: 0,
                quarantine_errors: 1,
                decode_failures: 0,
                state_barriers: 0,
                interprocedural_dropped: 0,
            }
        );
        let expected = serialize(&expected_synthetic_file(&fixture)).unwrap();
        assert_eq!(fs::read(fixture.sidecar()).unwrap(), expected);
        assert!(!expected.ends_with(b"\n"));
    }

    #[test]
    fn interprocedural_pass_recovers_shape_through_a_direct_call() {
        let fixture = Fixture::new("interproc");
        let bound = interproc_bound(&fixture);
        let report = run_image_with_decoder(&bound.get(), &MapDecoder::with_interproc_call())
            .expect("interprocedural synthetic run");
        let file: Value = serde_json::from_slice(&fs::read(fixture.sidecar()).unwrap()).unwrap();
        let g = file["globals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["name"] == "g_scalar")
            .unwrap();
        assert_eq!(g["status"], "inferred");
        let via = g["observations"][0]["via"].as_array().unwrap();
        assert_eq!(via.len(), 1);
        assert_eq!(via[0]["arg_register"], "r0");
        assert_eq!(file["analysis"]["direct_calls_resolved"], 1);
        assert_eq!(file["analysis"]["call_facts_unresolved"], 0);
        assert_eq!(file["analysis"]["seeded_callees"], 1);
        assert_eq!(file["analysis"]["seed_vectors"], 1);
        assert!(
            file["analysis"]["interprocedural_observations"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert_eq!(file["analysis"]["interprocedural_dropped"], 0);
        // Cross-block counters, derived from the fixture's CFG (see
        // `with_interproc_call`): the only (block, register) arrival is the
        // seeded r0 joining the callee's second block (join_facts 1, and it
        // survives the single-edge join so join_kills 0); that same non-entry
        // block's final in-state holds the one fact (entry_facts 1,
        // join_survivor → cross_block_functions 1, seed non-empty →
        // cross_block_seeded_functions 1); the store's provenance is the
        // empty seed path, so nothing propagates (propagated_facts 0).
        assert_eq!(file["analysis"]["cross_block_join_kills"], 0);
        assert_eq!(file["analysis"]["cross_block_join_facts"], 1);
        assert_eq!(file["analysis"]["cross_block_entry_facts"], 1);
        assert_eq!(file["analysis"]["cross_block_propagated_facts"], 0);
        assert_eq!(file["analysis"]["cross_block_functions"], 1);
        assert_eq!(file["analysis"]["cross_block_seeded_functions"], 1);
        assert!(report.inferred >= 1);
    }

    #[test]
    fn undecoded_entry_is_recoverable_and_later_identities_still_run() {
        let fixture = Fixture::new("undecoded_entry");
        let bound = synthetic_bound(&fixture, 3);
        let mut decoder = MapDecoder::fixture();
        decoder
            .errors
            .insert((Isa::Arm, 0x4000), "unrecognized encoding");
        let report = run_image_with_decoder(&bound.get(), &decoder)
            .expect("undecoded entry must not fail the image");
        assert!(
            report.decode_failures >= 1,
            "failed entry must count as a decode failure: {report:?}"
        );
        assert!(
            report.observations >= 1,
            "later identities must still produce evidence: {report:?}"
        );
        assert!(
            fixture.sidecar().exists(),
            "recoverable entry loss must still commit the sidecar"
        );
        let file: Value = serde_json::from_slice(&fs::read(fixture.sidecar()).unwrap()).unwrap();
        let globals = file["globals"].as_array().expect("globals array");
        let scalar = globals
            .iter()
            .find(|global| global["address"] == hex(SCALAR))
            .expect("scalar global");
        assert_eq!(scalar["status"], "no_evidence");
        assert_eq!(scalar["observations"], json!([]));
        let array = globals
            .iter()
            .find(|global| global["address"] == hex(ARRAY))
            .expect("array global");
        assert_eq!(array["status"], "inferred");
        assert!(
            !array["observations"].as_array().unwrap().is_empty(),
            "second identity must still emit observations"
        );
    }

    #[test]
    fn empty_recovered_writes_zero_analysis_without_decoding() {
        let fixture = Fixture::new("empty_recovered");
        let bound = synthetic_bound(&fixture, 0);
        let report = run_image_with_decoder(&bound.get(), &MapDecoder::panicking())
            .expect("empty recovered must not decode");
        assert_eq!(
            report,
            GlobalShapesReport {
                inferred: 0,
                no_evidence: 0,
                conflicting: 0,
                observations: 0,
                ghidra_quarantined: 1,
                thumb_quarantined: 0,
                quarantine_errors: 1,
                decode_failures: 0,
                state_barriers: 0,
                interprocedural_dropped: 0,
            }
        );
        let file: Value = serde_json::from_slice(&fs::read(fixture.sidecar()).unwrap()).unwrap();
        assert_eq!(file["analysis"]["arm_functions"], 0);
        assert_eq!(file["analysis"]["thumb_functions"], 0);
        assert_eq!(file["analysis"]["instructions_decoded"], 0);
        assert_eq!(file["analysis"]["ghidra_records_quarantined"], 1);
        assert_eq!(file["analysis"]["quarantine_errors"], 1);
        assert_eq!(file["globals"], json!([]));
    }

    #[test]
    fn malformed_and_currentness_failures_preserve_old_sidecar() {
        let fixture = Fixture::new("malformed");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        fs::write(fixture.decompiled().join("functions.json"), b"{not json").unwrap();
        assert!(run_image(&bound.get()).is_err());
        fixture.assert_old_sidecar();

        let fixture = Fixture::new("currentness");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        let mut stale = bound.get();
        stale.expected_ghidra_accepted = 3;
        assert!(run_image(&stale).is_err());
        fixture.assert_old_sidecar();
    }

    #[test]
    fn selected_adapter_invariant_failure_preserves_old_sidecar() {
        let fixture = Fixture::new("adapter_invariant");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        assert!(run_image_with_decoder(&bound.get(), &MapDecoder::invariant_failure()).is_err());
        fixture.assert_old_sidecar();
    }

    #[test]
    fn aggregate_invariant_failure_preserves_old_sidecar() {
        let fixture = Fixture::new("aggregate_invariant");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        let message = serialize_err(run_image_with(
            &bound.get(),
            &MapDecoder::fixture(),
            |globals, intra, inter| {
                let mut aggregation = aggregate(globals, intra, inter)?;
                aggregation.observations = aggregation
                    .observations
                    .checked_add(1)
                    .expect("observation bump");
                Ok(aggregation)
            },
            serialize,
            write_atomic,
        ));
        assert!(
            message.contains("observation or conflict count"),
            "{message}"
        );
        fixture.assert_old_sidecar();
    }

    #[test]
    fn injected_serialization_failure_preserves_old_sidecar() {
        let fixture = Fixture::new("serialize_fail");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        let message = serialize_err(run_image_with(
            &bound.get(),
            &MapDecoder::fixture(),
            aggregate,
            |_| Err(Error::Serialize("injected serialize failure".into())),
            write_atomic,
        ));
        assert_eq!(message, "injected serialize failure");
        fixture.assert_old_sidecar();
    }

    #[test]
    fn atomic_pre_commit_failure_preserves_old_sidecar() {
        let fixture = Fixture::new("precommit");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        let message = serialize_err(run_image_with(
            &bound.get(),
            &MapDecoder::fixture(),
            aggregate,
            serialize,
            |path, bytes| {
                write_atomic_with_before_commit(path, bytes, || {
                    Err(Error::Serialize(
                        "injected failure immediately before commit".into(),
                    ))
                })
            },
        ));
        assert_eq!(message, "injected failure immediately before commit");
        fixture.assert_old_sidecar();
    }

    #[test]
    fn decoder_panic_returns_error_without_commit() {
        let fixture = Fixture::new("panic_absent");
        let bound = synthetic_bound(&fixture, 3);
        let message = serialize_err(run_image_with_decoder(
            &bound.get(),
            &MapDecoder::panicking(),
        ));
        assert!(
            message.starts_with("global_shapes decoder panic:"),
            "{message}"
        );
        assert!(message.contains("deliberate decoder panic"), "{message}");
        assert!(!fixture.sidecar().exists());
    }

    #[test]
    fn decoder_panic_preserves_old_sidecar() {
        let fixture = Fixture::new("panic_old");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        assert!(run_image_with_decoder(&bound.get(), &MapDecoder::panicking()).is_err());
        fixture.assert_old_sidecar();
    }

    #[test]
    fn decoder_panic_allows_later_image() {
        let first = Fixture::new("panic_first");
        let first_bound = synthetic_bound(&first, 3);
        assert!(run_image_with_decoder(&first_bound.get(), &MapDecoder::panicking()).is_err());
        assert!(!first.sidecar().exists());

        let second = Fixture::new("panic_second");
        let second_bound = synthetic_bound(&second, 3);
        let report = run_image_with_decoder(&second_bound.get(), &MapDecoder::fixture())
            .expect("later image must still run");
        assert_eq!(report.inferred, 2);
        assert!(second.sidecar().exists());
    }

    #[test]
    fn decoder_panic_unwind_profile_remains_enabled() {
        let manifest = fs::read_to_string("Cargo.toml").unwrap();
        assert!(
            !manifest.contains("panic = \"abort\"") && !manifest.contains("panic='abort'"),
            "run_image must keep the repository unwind profile"
        );
        if Path::new(".cargo/config.toml").exists() {
            let config = fs::read_to_string(".cargo/config.toml").unwrap();
            assert!(
                !config.contains("panic = \"abort\"") && !config.contains("panic='abort'"),
                "do not add panic = abort cargo config"
            );
        }
        let payload: Box<dyn std::any::Any + Send> = Box::new("deliberate decoder panic");
        let message = match decoder_panic_error(payload) {
            Error::Serialize(message) => message,
            other => panic!("expected serialize panic error, got {other:?}"),
        };
        assert_eq!(
            message,
            "global_shapes decoder panic: deliberate decoder panic"
        );
    }

    #[test]
    fn selected_decoder_arbitrary_bytes_never_panic() {
        let decoder = PureRustDecoder;
        for (index, fill) in [0x00u8, 0xff, 0xa5, 0x5a].into_iter().enumerate() {
            for length in [
                1usize, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 64, 127, 128, 255, 256,
            ] {
                let bytes = vec![fill.wrapping_add(index as u8); length];
                for isa in [Isa::Arm, Isa::Thumb] {
                    let end = 0x4000 + u32::try_from(length.max(4)).unwrap();
                    let function = FunctionExecution {
                        identity: crate::execution_ranges::ExecutionIdentity {
                            entry: 0x4000,
                            decode_ranges: vec![crate::execution_ranges::DecodeRange {
                                start: 0x4000,
                                end,
                                isa,
                            }],
                        },
                        contexts: BTreeSet::from([FunctionContext {
                            entry: 0x4000,
                            name: "arbitrary".into(),
                        }]),
                    };
                    let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        decode_function(&decoder, &function, &bytes, 0x4000)
                    }))
                    .unwrap_or_else(|_| panic!("decoder panicked on {isa:?} fill={fill:#x}"));
                    let decoded = match decoded {
                        Ok(decoded) => decoded,
                        Err(_) => continue,
                    };
                    let mut cursor = 0x4000u32;
                    for (pc, instruction) in &decoded.ranges[0].instructions {
                        assert_eq!(*pc, cursor);
                        assert!(instruction.length > 0, "zero-length instruction at {pc:#x}");
                        let next = pc
                            .checked_add(u32::from(instruction.length))
                            .expect("forward progress");
                        assert!(next > *pc, "decoded PC did not advance at {pc:#x}");
                        cursor = next;
                    }
                }
            }
        }
    }

    #[test]
    fn rerun_is_deterministic_and_non_mutating() {
        let fixture = Fixture::new("rerun");
        let bound = synthetic_bound(&fixture, 3);
        let before = fixture.hash_sources();
        let first = run_image(&bound.get()).expect("first production run");
        let first_bytes = fs::read(fixture.sidecar()).unwrap();
        let after_first = fixture.hash_sources();
        let second = run_image(&bound.get()).expect("second production run");
        let second_bytes = fs::read(fixture.sidecar()).unwrap();
        let after_second = fixture.hash_sources();
        assert_eq!(first, second);
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(before, after_first);
        assert_eq!(before, after_second);
        assert!(!first_bytes.ends_with(b"\n"));
    }

    #[test]
    fn commit_artifact_with_does_not_write_when_serialize_fails() {
        let root =
            std::env::temp_dir().join(format!("pme_global_shapes_commit_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("global_shapes.json");
        fs::write(&path, OLD_SIDECAR).unwrap();
        let file = GlobalShapesFile {
            format: FORMAT_V3,
            image: LABEL.into(),
            load_address: hex(LOAD_ADDR),
            inputs: InputHashesWire {
                image_sha256: "aa".into(),
                globals_sha256: "bb".into(),
                functions_sha256: "cc".into(),
                thumb_functions_sha256: None,
            },
            decoder: DecoderWire {
                crate_name: "test".into(),
                version: "0".into(),
            },
            analysis: AnalysisWire {
                arm_functions: 0,
                thumb_functions: 0,
                ghidra_records_quarantined: 0,
                thumb_records_quarantined: 0,
                quarantine_errors: 0,
                instructions_decoded: 0,
                decode_failures: 0,
                state_barriers: 0,
                observations: 0,
                conflicts: 0,
                direct_calls_resolved: 0,
                call_facts_unresolved: 0,
                seeded_callees: 0,
                seed_vectors: 0,
                interprocedural_observations: 0,
                interprocedural_dropped: 0,
                cross_block_join_kills: 0,
                cross_block_join_facts: 0,
                cross_block_entry_facts: 0,
                cross_block_propagated_facts: 0,
                cross_block_functions: 0,
                cross_block_seeded_functions: 0,
            },
            globals: vec![],
        };
        let error = commit_artifact_with(
            &file,
            &path,
            |_| Err(Error::Serialize("injected serialize failure".into())),
            |_, _| panic!("write must not run after serialize failure"),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Serialize(ref reason) if reason == "injected serialize failure"
        ));
        assert_eq!(fs::read(&path).unwrap(), OLD_SIDECAR);
    }

    #[test]
    fn analyze_to_bytes_without_commit_is_deterministic_and_does_not_write() {
        let fixture = Fixture::new("no_commit");
        let bound = synthetic_bound(&fixture, 3);
        fixture.seed_old_sidecar();
        let before = fixture.hash_sources();
        let old = fs::read(fixture.sidecar()).unwrap();
        let (first, first_report) =
            analyze_to_bytes_without_commit(&bound.get()).expect("first analyze");
        let (second, second_report) =
            analyze_to_bytes_without_commit(&bound.get()).expect("second analyze");
        assert_eq!(first, second);
        assert_eq!(sha256_bytes(&first), sha256_bytes(&second));
        assert_eq!(first_report, second_report);
        assert_eq!(fs::read(fixture.sidecar()).unwrap(), old);
        assert_eq!(fixture.hash_sources(), before);
        assert!(!first.ends_with(b"\n"));
        let file: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(file["format"], FORMAT_V3);
        assert_eq!(file["globals"].as_array().unwrap().len(), 3);
        let mut report_image = json!({
            "image": LABEL,
            "functions": bound.ghidra_records,
            "ghidra_execution_accepted": bound.ghidra_accepted,
            "ghidra_execution_quarantined": bound.ghidra_quarantined,
            "globals_recovered": bound.recovered,
        });
        if let (Some(substantial), Some(accepted), Some(quarantined)) = (
            bound.thumb_substantial,
            bound.thumb_accepted,
            bound.thumb_quarantined,
        ) {
            report_image["thumb_functions"] = json!(substantial);
            report_image["thumb_execution_accepted"] = json!(accepted);
            report_image["thumb_execution_quarantined"] = json!(quarantined);
        }
        validate_artifact_files(
            &fixture.image_dir(),
            &fixture.manifest_path(),
            &report_image,
            &file,
        );
    }

    #[test]
    fn shape_sidecar_snapshot_detects_write_that_content_hash_ignores() {
        let root = std::env::temp_dir().join(format!(
            "pme_global_shapes_sidecar_snap_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("decompiled")).unwrap();
        fs::write(root.join("keep.bin"), b"terminal").unwrap();
        let before_hash = hash_tree_except_shapes(&root);
        let before_sidecars = shape_sidecar_states(&root);
        assert!(before_sidecars.is_empty(), "no sidecar present yet");

        fs::write(root.join("decompiled/global_shapes.json"), b"committed").unwrap();
        assert_eq!(
            hash_tree_except_shapes(&root),
            before_hash,
            "content hash still ignores sidecar writes"
        );
        let after_create = shape_sidecar_states(&root);
        assert_ne!(
            after_create, before_sidecars,
            "sidecar snapshot must see a newly written global_shapes.json"
        );

        fs::write(root.join("decompiled/global_shapes.json"), b"changed").unwrap();
        assert_ne!(
            shape_sidecar_states(&root),
            after_create,
            "sidecar snapshot must see byte changes"
        );

        fs::remove_file(root.join("decompiled/global_shapes.json")).unwrap();
        assert_eq!(
            shape_sidecar_states(&root),
            before_sidecars,
            "absent after delete must match the original absent snapshot"
        );
        let _ = fs::remove_dir_all(&root);
    }

    fn walk_files(dir: &Path, visit: &mut impl FnMut(&Path, &fs::DirEntry)) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                walk_files(&path, visit);
            } else if file_type.is_file() {
                visit(&path, &entry);
            }
        }
    }

    fn hash_tree_except_shapes(root: &Path) -> BTreeMap<PathBuf, String> {
        let mut hashes = BTreeMap::new();
        walk_files(root, &mut |path, entry| {
            if entry.file_name() != "global_shapes.json" {
                hashes.insert(path.to_path_buf(), sha256_bytes(&fs::read(path).unwrap()));
            }
        });
        hashes
    }

    fn shape_sidecar_states(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut states = BTreeMap::new();
        walk_files(root, &mut |path, entry| {
            if entry.file_name() == "global_shapes.json" {
                states.insert(path.to_path_buf(), fs::read(path).unwrap());
            }
        });
        states
    }

    fn replay_eligible(image: &Value) -> Option<BoundReplay> {
        let label = image.get("image")?.as_str()?.to_owned();
        let ghidra_records = image.get("functions")?.as_u64()? as usize;
        let ghidra_accepted = image.get("ghidra_execution_accepted")?.as_u64()? as usize;
        let ghidra_quarantined = image.get("ghidra_execution_quarantined")?.as_u64()? as usize;
        if ghidra_accepted.checked_add(ghidra_quarantined) != Some(ghidra_records) {
            return None;
        }
        if image.get("thumb_error").is_some() || image.get("globals_error").is_some() {
            return None;
        }
        let thumb = match (
            image.get("thumb_functions").and_then(Value::as_u64),
            image
                .get("thumb_execution_accepted")
                .and_then(Value::as_u64),
            image
                .get("thumb_execution_quarantined")
                .and_then(Value::as_u64),
        ) {
            (None, None, None) => (None, None, None),
            (Some(substantial), Some(accepted), Some(quarantined)) => (
                Some(substantial as usize),
                Some(accepted as usize),
                Some(quarantined as usize),
            ),
            _ => return None,
        };
        let recovered = image.get("globals_recovered")?.as_u64()? as usize;
        Some(BoundReplay {
            label,
            ghidra_records,
            ghidra_accepted,
            ghidra_quarantined,
            thumb_substantial: thumb.0,
            thumb_accepted: thumb.1,
            thumb_quarantined: thumb.2,
            recovered,
        })
    }

    struct BoundReplay {
        label: String,
        ghidra_records: usize,
        ghidra_accepted: usize,
        ghidra_quarantined: usize,
        thumb_substantial: Option<usize>,
        thumb_accepted: Option<usize>,
        thumb_quarantined: Option<usize>,
        recovered: usize,
    }

    impl BoundReplay {
        fn request<'a>(&'a self, image_dir: &'a Path, manifest: &'a Path) -> RunRequest<'a> {
            RunRequest {
                image_dir,
                image_label: &self.label,
                manifest_path: manifest,
                expected_ghidra_records: self.ghidra_records,
                expected_ghidra_accepted: self.ghidra_accepted,
                expected_ghidra_quarantined: self.ghidra_quarantined,
                expected_thumb_substantial: self.thumb_substantial,
                expected_thumb_accepted: self.thumb_accepted,
                expected_thumb_quarantined: self.thumb_quarantined,
                expected_recovered_globals: self.recovered,
            }
        }
    }

    #[test]
    #[ignore = "requires retained production tree and is intentionally expensive"]
    fn retained_tree_replay_is_deterministic_and_non_mutating() {
        if std::env::var("PME_GLOBAL_SHAPES_REPLAY").ok().as_deref() != Some("1") {
            eprintln!("skip: set PME_GLOBAL_SHAPES_REPLAY=1");
            return;
        }
        let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        if !dir.exists() {
            eprintln!("skip: PME_GOLDEN_DIR not found: {}", dir.display());
            return;
        }
        // Recorded v2-era status split on mustang 02_MAIN (CONTRIBUTING
        // "Phase 3.2 production baselines"). The v3 engine is monotone vs
        // v2: `inferred` may only grow out of `no_evidence`; `conflicting`
        // must not increase.
        const MUSTANG_MAIN: &str = "02_MAIN";
        const V2_INFERRED: usize = 125;
        const V2_NO_EVIDENCE: usize = 787;
        const V2_CONFLICTING: usize = 3;
        let report: Value = serde_json::from_slice(
            &fs::read(dir.join("report.json")).expect("report.json readable"),
        )
        .expect("report.json valid JSON");
        let images = report["stages"]
            .as_array()
            .and_then(|stages| {
                stages
                    .iter()
                    .find(|stage| stage["stage"] == "decompile")
                    .and_then(|stage| stage["images"].as_array())
            })
            .expect("decompile images");
        let before = hash_tree_except_shapes(&dir);
        let before_sidecars = shape_sidecar_states(&dir);
        let manifest = dir.join("manifest.json");
        for image in images {
            let Some(bound) = replay_eligible(image) else {
                continue;
            };
            let image_dir = dir.join("images").join(&bound.label);
            if !image_dir.join(format!("{}.bin", bound.label)).is_file() {
                eprintln!("skip {}: missing raw image", bound.label);
                continue;
            }
            let request = bound.request(&image_dir, &manifest);
            let started = std::time::Instant::now();
            let (first, first_report) = analyze_to_bytes_without_commit(&request)
                .unwrap_or_else(|e| panic!("{} first analyze: {e}", bound.label));
            let first_elapsed = started.elapsed();
            let (second, second_report) = analyze_to_bytes_without_commit(&request)
                .unwrap_or_else(|e| panic!("{} second analyze: {e}", bound.label));
            assert_eq!(first, second, "{} artifact bytes drifted", bound.label);
            assert_eq!(
                sha256_bytes(&first),
                sha256_bytes(&second),
                "{} artifact hash drifted",
                bound.label
            );
            assert_eq!(
                first_report, second_report,
                "{} report drifted",
                bound.label
            );
            if bound.label == MUSTANG_MAIN {
                assert!(
                    first_report.inferred >= V2_INFERRED,
                    "{}: monotonicity violated: inferred {} < v2's {}",
                    bound.label,
                    first_report.inferred,
                    V2_INFERRED
                );
                assert!(
                    first_report.no_evidence <= V2_NO_EVIDENCE,
                    "{}: monotonicity violated: no_evidence {} > v2's {}",
                    bound.label,
                    first_report.no_evidence,
                    V2_NO_EVIDENCE
                );
                assert!(
                    first_report.conflicting <= V2_CONFLICTING,
                    "{}: conflicting must not increase: {} > v2's {}",
                    bound.label,
                    first_report.conflicting,
                    V2_CONFLICTING
                );
            }
            let artifact: Value = serde_json::from_slice(&first).expect("artifact JSON");
            validate_artifact(&dir, image, &artifact);
            let file = artifact;
            println!(
                "global_shapes replay {}: wall={:?} sha256={} accepted_identities={}/{} ghidra_quarantined={} thumb_quarantined={} quarantine_errors={} instructions_decoded={} decode_failures={} state_barriers={} cross_block_join_kills={} cross_block_join_facts={} cross_block_entry_facts={} cross_block_propagated_facts={} cross_block_functions={} cross_block_seeded_functions={}",
                bound.label,
                first_elapsed,
                sha256_bytes(&first),
                file["analysis"]["arm_functions"],
                file["analysis"]["thumb_functions"],
                first_report.ghidra_quarantined,
                first_report.thumb_quarantined,
                first_report.quarantine_errors,
                file["analysis"]["instructions_decoded"],
                first_report.decode_failures,
                first_report.state_barriers,
                file["analysis"]["cross_block_join_kills"],
                file["analysis"]["cross_block_join_facts"],
                file["analysis"]["cross_block_entry_facts"],
                file["analysis"]["cross_block_propagated_facts"],
                file["analysis"]["cross_block_functions"],
                file["analysis"]["cross_block_seeded_functions"],
            );
        }
        assert_eq!(
            hash_tree_except_shapes(&dir),
            before,
            "retained tree must not be mutated"
        );
        assert_eq!(
            shape_sidecar_states(&dir),
            before_sidecars,
            "global_shapes.json must not appear or change"
        );
    }

    #[test]
    #[ignore = "measurement: PME_GLOBAL_SHAPES_MEASURE=1 PME_GOLDEN_DIR=<tree> PME_GLOBAL_SHAPES_MEASURE_LABEL=<image>"]
    fn interprocedural_yield_on_retained_tree() {
        if std::env::var("PME_GLOBAL_SHAPES_MEASURE").ok().as_deref() != Some("1") {
            eprintln!("skip: set PME_GLOBAL_SHAPES_MEASURE=1");
            return;
        }
        let Some(dir) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        if !dir.exists() {
            eprintln!("skip: PME_GOLDEN_DIR not found: {}", dir.display());
            return;
        }
        let label =
            std::env::var("PME_GLOBAL_SHAPES_MEASURE_LABEL").unwrap_or_else(|_| LABEL.to_owned());
        let report: Value = serde_json::from_slice(
            &fs::read(dir.join("report.json")).expect("report.json readable"),
        )
        .expect("report.json valid JSON");
        let images = report["stages"]
            .as_array()
            .and_then(|stages| {
                stages
                    .iter()
                    .find(|stage| stage["stage"] == "decompile")
                    .and_then(|stage| stage["images"].as_array())
            })
            .expect("decompile images");
        let Some(image) = images.iter().find(|image| image["image"] == label.as_str()) else {
            eprintln!("skip: {label} not present in report.json decompile images");
            return;
        };
        let Some(bound) = replay_eligible(image) else {
            eprintln!("skip: {label} not replay-eligible");
            return;
        };
        let image_dir = dir.join("images").join(&bound.label);
        if !image_dir.join(format!("{}.bin", bound.label)).is_file() {
            eprintln!("skip: {LABEL} missing raw image");
            return;
        }
        let manifest = dir.join("manifest.json");
        let request = bound.request(&image_dir, &manifest);

        let before = hash_tree_except_shapes(&dir);
        let before_sidecars = shape_sidecar_states(&dir);

        let started = std::time::Instant::now();
        let (first, first_report) = analyze_to_bytes_without_commit(&request)
            .unwrap_or_else(|e| panic!("{label} first analyze: {e}"));
        let first_elapsed = started.elapsed();
        let (second, second_report) = analyze_to_bytes_without_commit(&request)
            .unwrap_or_else(|e| panic!("{label} second analyze: {e}"));

        assert_eq!(first, second, "{label} artifact bytes drifted between runs");
        assert_eq!(
            sha256_bytes(&first),
            sha256_bytes(&second),
            "{label} artifact hash drifted between runs"
        );
        assert_eq!(
            first_report, second_report,
            "{label} report drifted between runs"
        );

        // Non-mutation: analyze_to_bytes_without_commit writes nothing, so the
        // retained tree (including any global_shapes.json sidecars) must be
        // byte-identical before and after both analyze passes.
        assert_eq!(
            hash_tree_except_shapes(&dir),
            before,
            "retained tree must not be mutated"
        );
        assert_eq!(
            shape_sidecar_states(&dir),
            before_sidecars,
            "global_shapes.json must not appear or change"
        );

        let artifact: Value = serde_json::from_slice(&first).expect("artifact JSON");
        let analysis = &artifact["analysis"];
        println!(
            "global_shapes interprocedural yield {label}: wall={:?} sha256={} inferred={} no_evidence={} conflicting={} direct_calls_resolved={} call_facts_unresolved={} seeded_callees={} seed_vectors={} interprocedural_observations={} interprocedural_dropped={} cross_block_join_kills={} cross_block_join_facts={} cross_block_entry_facts={} cross_block_propagated_facts={} cross_block_functions={} cross_block_seeded_functions={}",
            first_elapsed,
            sha256_bytes(&first),
            first_report.inferred,
            first_report.no_evidence,
            first_report.conflicting,
            analysis["direct_calls_resolved"],
            analysis["call_facts_unresolved"],
            analysis["seeded_callees"],
            analysis["seed_vectors"],
            analysis["interprocedural_observations"],
            analysis["interprocedural_dropped"],
            analysis["cross_block_join_kills"],
            analysis["cross_block_join_facts"],
            analysis["cross_block_entry_facts"],
            analysis["cross_block_propagated_facts"],
            analysis["cross_block_functions"],
            analysis["cross_block_seeded_functions"],
        );
    }
}
