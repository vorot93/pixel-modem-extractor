// Semantic reference attribution: walk every authenticated execution
// range of every loaded function inventory, materialize the record
// addresses each instruction computes (MOVW+MOVT pairs, literal-pool
// loads, PC-relative forms), and publish the deduplicated, sorted row
// set as the canonical references artifact.
use crate::analysis_tool::AnalysisTool;
use crate::arm32::{
    AddressBase, AddressExpr, AddressOffset, ControlFlow, DecodedInstruction, InstructionDecoder,
    ItRangeState, PureRustDecoder, Register, ValueEffect, ValueExpr, visible_pc, wrapping_offset,
};
use crate::dbt_traces::reader::ValidatedCatalog;
use crate::dbt_traces::wire::JsonWriter;
use crate::dbt_traces::{DbtTraceError, MAX_REFERENCES, REFS_FORMAT, SCHEMA_VERSION};
use crate::execution_ranges::{
    AuthenticatedDecodeRange, DecodeIsa, ExecutionIdentity, FunctionOwner, execution_identity,
    validate_ghidra_inventory_records,
};
use crate::runtime_image::RuntimeImage;
use crate::thumb_analysis::read_thumb_functions_streaming;
use atomic_write_file::AtomicWriteFile;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

const MAX_MOVW_MOVT_SPAN_INSTRUCTIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceKind {
    MovwMovt,
    LiteralLoad,
    PcRelative,
}

impl EvidenceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::MovwMovt => "movw_movt",
            EvidenceKind::LiteralLoad => "literal_load",
            EvidenceKind::PcRelative => "pc_relative",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceRow {
    pub(crate) record_address: u32,
    pub(crate) pc: u32,
    pub(crate) isa: DecodeIsa,
    pub(crate) function_entry: u32,
    pub(crate) function_name: String,
    pub(crate) producer: AnalysisTool,
    pub(crate) evidence_kind: EvidenceKind,
}

impl ReferenceRow {
    fn producer_wire_order(&self) -> u8 {
        match self.producer {
            AnalysisTool::Ghidra => 0,
            AnalysisTool::Radare2 => 1,
            AnalysisTool::Rizin => 2,
        }
    }

    fn evidence_kind_wire_order(&self) -> u8 {
        match self.evidence_kind {
            EvidenceKind::LiteralLoad => 0,
            EvidenceKind::MovwMovt => 1,
            EvidenceKind::PcRelative => 2,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RefFunction {
    pub(crate) owner: FunctionOwner,
    pub(crate) identity: ExecutionIdentity,
    pub(crate) name: String,
}

#[derive(Debug)]
pub(crate) struct RefsOutcome {
    pub(crate) count: usize,
    pub(crate) producers: Vec<AnalysisTool>,
}

#[derive(Debug)]
pub(crate) struct RefsInputs {
    pub(crate) functions_blake3: String,
    pub(crate) thumb_functions_blake3: Option<String>,
}

pub(crate) fn attribute(
    runtime: &RuntimeImage<'_>,
    record_addresses: &[u32],
    functions: &[RefFunction],
    catalog: &ValidatedCatalog,
    inputs: RefsInputs,
    out_path: &Path,
) -> Result<RefsOutcome, DbtTraceError> {
    attribute_capped(
        runtime,
        record_addresses,
        functions,
        catalog,
        inputs,
        out_path,
        MAX_REFERENCES,
    )
}

pub(crate) fn attribute_capped(
    runtime: &RuntimeImage<'_>,
    record_addresses: &[u32],
    functions: &[RefFunction],
    catalog: &ValidatedCatalog,
    inputs: RefsInputs,
    out_path: &Path,
    cap: usize,
) -> Result<RefsOutcome, DbtTraceError> {
    let outcome = collect_rows(runtime, record_addresses, functions, cap).and_then(|rows| {
        write_references(&rows, catalog, &inputs, out_path)?;
        Ok(RefsOutcome {
            count: rows.len(),
            producers: distinct_producers(functions),
        })
    });
    match outcome {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let _ = std::fs::remove_file(out_path);
            Err(error)
        }
    }
}

fn distinct_producers(functions: &[RefFunction]) -> Vec<AnalysisTool> {
    functions
        .iter()
        .map(|function| function.owner.analysis_tool())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collect_rows(
    runtime: &RuntimeImage<'_>,
    record_addresses: &[u32],
    functions: &[RefFunction],
    cap: usize,
) -> Result<Vec<ReferenceRow>, DbtTraceError> {
    let addresses: BTreeSet<u32> = record_addresses.iter().copied().collect();
    let mut rows: Vec<ReferenceRow> = Vec::new();
    for function in functions {
        for range in &function.identity.decode_ranges {
            walk_range(runtime, range, function, &addresses, cap, &mut rows)?;
        }
    }
    rows.sort_by_key(|row| {
        (
            row.record_address,
            row.pc,
            row.producer_wire_order(),
            row.evidence_kind_wire_order(),
        )
    });
    rows.dedup_by_key(|row| (row.pc, row.record_address, row.producer, row.evidence_kind));
    Ok(rows)
}

fn walk_range(
    runtime: &RuntimeImage<'_>,
    range: &AuthenticatedDecodeRange,
    function: &RefFunction,
    addresses: &BTreeSet<u32>,
    cap: usize,
    rows: &mut Vec<ReferenceRow>,
) -> Result<(), DbtTraceError> {
    let mut walk = RangeWalk::new(runtime, range.isa);
    let mut pc = range.start;
    while pc < range.end {
        let Some(instruction) = walk.decode_at(pc) else {
            return Ok(());
        };
        if let Some((value, kind)) = walk.classify(pc, &instruction)
            && addresses.contains(&value)
        {
            if rows.len() >= cap {
                return Err(DbtTraceError::ReferenceCap(rows.len() + 1));
            }
            rows.push(ReferenceRow {
                record_address: value,
                pc,
                isa: range.isa,
                function_entry: function.identity.entry,
                function_name: function.name.clone(),
                producer: function.owner.analysis_tool(),
                evidence_kind: kind,
            });
        }
        let Some(next) = pc.checked_add(u32::from(instruction.length)) else {
            return Ok(());
        };
        pc = next;
    }
    Ok(())
}

struct RangeWalk<'a, 'img> {
    runtime: &'a RuntimeImage<'img>,
    decoder: PureRustDecoder,
    state: ItRangeState,
    isa: DecodeIsa,
}

impl<'a, 'img> RangeWalk<'a, 'img> {
    fn new(runtime: &'a RuntimeImage<'img>, isa: DecodeIsa) -> Self {
        let decoder = PureRustDecoder;
        let state = decoder.begin_range(isa);
        RangeWalk {
            runtime,
            decoder,
            state,
            isa,
        }
    }

    /// Decode one instruction at `pc`: a four-byte fetch with a two-byte
    /// fallback at range tails, sharing the range's IT-block state.
    fn decode_at(&mut self, pc: u32) -> Option<DecodedInstruction> {
        let bytes = match self.runtime.read_exact(pc, 4) {
            Ok(bytes) => bytes,
            Err(_) => self.runtime.read_exact(pc, 2).ok()?,
        };
        self.decoder
            .decode_one(&mut self.state, self.isa, pc, &bytes)
            .ok()
    }

    fn classify(
        &mut self,
        pc: u32,
        instruction: &DecodedInstruction,
    ) -> Option<(u32, EvidenceKind)> {
        match &instruction.effect {
            ValueEffect::RegisterWrite {
                value:
                    ValueExpr::ArchitecturalPc {
                        addend,
                        align_to_four,
                    },
                ..
            } => Some((
                wrapping_offset(visible_pc(pc, *align_to_four), *addend),
                EvidenceKind::PcRelative,
            )),
            ValueEffect::RegisterWrite {
                dst,
                value: ValueExpr::Immediate(low),
            } => self
                .movw_movt_value(pc, instruction.length, *dst, *low)
                .map(|value| (value, EvidenceKind::MovwMovt)),
            ValueEffect::LiteralWordLoad { address, .. } => {
                let AddressExpr {
                    base: AddressBase::ArchitecturalPc { align_to_four },
                    offset: AddressOffset::Immediate(offset),
                } = address
                else {
                    return None;
                };
                let literal = wrapping_offset(visible_pc(pc, *align_to_four), *offset);
                self.runtime
                    .read_u32(literal)
                    .ok()
                    .map(|value| (value, EvidenceKind::LiteralLoad))
            }
            _ => None,
        }
    }

    /// Resolve a MOVW low-half write through a register-consistent MOVT in
    /// the same linear span: at most 32 instructions, killed by any other
    /// write to the destination or any non-linear transfer. The inner walk
    /// decodes through the IT-state shared with the outer range walk, which
    /// then re-decodes the same span — fixture-equivalent today; revisit if
    /// IT-block fixtures appear.
    fn movw_movt_value(
        &mut self,
        movw_pc: u32,
        movw_length: u8,
        destination: Register,
        low: u32,
    ) -> Option<u32> {
        let mut pc = movw_pc.checked_add(u32::from(movw_length))?;
        let mut remaining = MAX_MOVW_MOVT_SPAN_INSTRUCTIONS - 1;
        while remaining > 0 {
            remaining -= 1;
            let instruction = self.decode_at(pc)?;
            if !matches!(instruction.flow, ControlFlow::Linear) {
                return None;
            }
            if let ValueEffect::RegisterWrite {
                dst,
                value: ValueExpr::ReplaceHighHalf { source, high },
            } = &instruction.effect
                && *dst == destination
                && *source == destination
            {
                return Some((u32::from(*high) << 16) | (low & 0xffff));
            }
            if instruction.writes.contains(&destination) {
                return None;
            }
            pc = pc.checked_add(u32::from(instruction.length))?;
        }
        None
    }
}

pub(crate) fn load_functions(
    decompiled_dir: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<Option<Vec<RefFunction>>, DbtTraceError> {
    let path = decompiled_dir.join("functions.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)?;
    let raw: Vec<serde_json::Value> = serde_json::from_slice(&bytes)
        .map_err(|error| artifact(format!("functions inventory parsing failed: {error}")))?;
    let inventory = validate_ghidra_inventory_records(&raw, raw.len(), runtime)
        .map_err(DbtTraceError::Runtime)?;
    let mut functions = Vec::with_capacity(inventory.records.len());
    for (value, tagged) in raw.iter().zip(&inventory.records) {
        let Some(identity) =
            execution_identity(tagged.entry, &tagged.projection).map_err(DbtTraceError::Runtime)?
        else {
            continue;
        };
        functions.push(RefFunction {
            owner: tagged.owner,
            identity,
            name: inventory_name(value)?,
        });
    }
    Ok(Some(functions))
}

pub(crate) fn load_thumb(
    decompiled_dir: &Path,
    runtime: &RuntimeImage<'_>,
) -> Result<Option<Vec<RefFunction>>, DbtTraceError> {
    let path = decompiled_dir.join("thumb_functions.json");
    if !path.exists() {
        return Ok(None);
    }
    let owned = read_thumb_functions_streaming(&path, runtime).map_err(DbtTraceError::Runtime)?;
    let functions = owned
        .into_iter()
        .filter_map(|record| {
            let identity = record.execution?;
            Some(RefFunction {
                owner: record.owner,
                identity,
                name: record
                    .function
                    .original_name
                    .unwrap_or(record.function.name),
            })
        })
        .collect();
    Ok(Some(functions))
}

fn inventory_name(value: &serde_json::Value) -> Result<String, DbtTraceError> {
    let object = value
        .as_object()
        .ok_or_else(|| artifact("inventory record must be an object"))?;
    let original = object.get("original_name").and_then(|name| name.as_str());
    let name = object
        .get("name")
        .and_then(|name| name.as_str())
        .ok_or_else(|| artifact("inventory record lacks a name"))?;
    Ok(original.unwrap_or(name).to_string())
}

fn artifact(message: impl Into<String>) -> DbtTraceError {
    DbtTraceError::Artifact(message.into())
}

fn write_references(
    rows: &[ReferenceRow],
    catalog: &ValidatedCatalog,
    inputs: &RefsInputs,
    out_path: &Path,
) -> Result<(), DbtTraceError> {
    let mut file = AtomicWriteFile::open(out_path)?;
    {
        let mut json = JsonWriter::new(&mut file);
        json.open_object()?;
        json.key(true, "format")?;
        json.string_value(REFS_FORMAT)?;
        json.key(false, "schema_version")?;
        json.u64_value(u64::from(SCHEMA_VERSION))?;
        json.key(false, "tool_version")?;
        json.string_value(env!("CARGO_PKG_VERSION"))?;
        json.key(false, "image")?;
        json.open_object()?;
        json.key(true, "blake3")?;
        json.hex_value(&catalog.image_blake3)?;
        json.close_object()?;
        json.key(false, "catalog")?;
        json.open_object()?;
        json.key(true, "manifest_blake3")?;
        json.hex_value(&catalog.manifest_blake3)?;
        json.key(false, "identity")?;
        json.string_value(&catalog.identity)?;
        json.close_object()?;
        json.key(false, "inputs")?;
        json.open_object()?;
        json.key(true, "functions_blake3")?;
        json.string_value(&inputs.functions_blake3)?;
        if let Some(thumb) = &inputs.thumb_functions_blake3 {
            json.key(false, "thumb_functions_blake3")?;
            json.string_value(thumb)?;
        }
        json.close_object()?;
        json.key(false, "count")?;
        json.u64_value(rows.len() as u64)?;
        json.key(false, "references")?;
        json.open_array()?;
        for (index, row) in rows.iter().enumerate() {
            json.element(index == 0)?;
            write_row(&mut json, row)?;
        }
        json.close_array()?;
        json.close_object()?;
    }
    file.write_all(b"\n")?;
    file.flush()?;
    file.commit()?;
    Ok(())
}

fn write_row(json: &mut JsonWriter<impl Write>, row: &ReferenceRow) -> Result<(), DbtTraceError> {
    json.open_object()?;
    json.key(true, "record_address")?;
    json.u32_hex_value(row.record_address)?;
    json.key(false, "pc")?;
    json.u32_hex_value(row.pc)?;
    json.key(false, "isa")?;
    json.string_value(isa_name(row.isa))?;
    json.key(false, "function_entry")?;
    json.u32_hex_value(row.function_entry)?;
    json.key(false, "function_name")?;
    json.string_value(&row.function_name)?;
    json.key(false, "producer")?;
    json.string_value(producer_name(row.producer))?;
    json.key(false, "evidence_kind")?;
    json.string_value(row.evidence_kind.as_str())?;
    json.close_object()?;
    Ok(())
}

fn isa_name(isa: DecodeIsa) -> &'static str {
    match isa {
        DecodeIsa::Arm => "arm",
        DecodeIsa::Thumb => "thumb",
    }
}

pub(crate) fn producer_name(producer: AnalysisTool) -> &'static str {
    match producer {
        AnalysisTool::Ghidra => "ghidra",
        AnalysisTool::Radare2 => "radare2",
        AnalysisTool::Rizin => "rizin",
    }
}

/// Inverse of `producer_name` for wire parsing; `None` on an unknown name.
pub(crate) fn producer_from_name(name: &str) -> Option<AnalysisTool> {
    match name {
        "ghidra" => Some(AnalysisTool::Ghidra),
        "radare2" => Some(AnalysisTool::Radare2),
        "rizin" => Some(AnalysisTool::Rizin),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EvidenceKind, RefFunction, RefsInputs, attribute, attribute_capped, load_functions,
        load_thumb,
    };
    use crate::analysis_tool::AnalysisTool;
    use crate::dbt_traces::DbtTraceError;
    use crate::dbt_traces::artifact::CatalogCounts;
    use crate::dbt_traces::discover::testkit::{BASE, unique_dir};
    use crate::dbt_traces::reader::ValidatedCatalog;
    use crate::execution_ranges::{
        AuthenticatedDecodeRange, DecodeIsa, ExecutionIdentity, FunctionOwner,
    };
    use crate::runtime_image::RuntimeImage;
    use crate::thumb_analysis::THUMB_V2_FORMAT;

    const RECORD: u32 = 0x4000_0200;

    // T32 encodings re-derived from the arm32 decoder fixtures in
    // src/arm32/mod.rs tests (t32_movw, t32_movt, t32_mov_reg, t32_adr,
    // t32_literal_load) and the unconditional B T2 family.
    const MOVW_R0_0200: [u8; 4] = [0x40, 0xf2, 0x00, 0x20];
    const MOVT_R0_4000: [u8; 4] = [0xc4, 0xf2, 0x00, 0x00];
    const MOV_R0_R1: [u8; 2] = [0x08, 0x46];
    const ADR_PLUS_8: [u8; 2] = [0x02, 0xa0];
    const ADR_PLUS_4: [u8; 2] = [0x01, 0xa0];
    const LDR_R0_PC4: [u8; 2] = [0x01, 0x48];
    const B_FWD_2: [u8; 2] = [0x01, 0xe0];
    // A32 encodings re-derived from the arm32 decoder fixtures
    // (a32_movw, a32_movt, a32_literal_load, a32_pc_address).
    const A32_MOVW_R0_0200: [u8; 4] = [0x00, 0x02, 0x00, 0xe3];
    const A32_MOVT_R0_4000: [u8; 4] = [0x00, 0x00, 0x44, 0xe3];
    const A32_LDR_R0_PC0: [u8; 4] = [0x00, 0x00, 0x9f, 0xe5];
    const A32_ADD_R0_PC_8: [u8; 4] = [0x08, 0x00, 0x8f, 0xe2];

    fn thumb_range(runtime: &RuntimeImage<'_>, start: u32, end: u32) -> AuthenticatedDecodeRange {
        AuthenticatedDecodeRange {
            isa: DecodeIsa::Thumb,
            start,
            end,
            blake3: runtime.hash_range(start, end - start).unwrap(),
        }
    }

    fn arm_range(runtime: &RuntimeImage<'_>, start: u32, end: u32) -> AuthenticatedDecodeRange {
        AuthenticatedDecodeRange {
            isa: DecodeIsa::Arm,
            start,
            end,
            blake3: runtime.hash_range(start, end - start).unwrap(),
        }
    }

    fn function(
        owner: FunctionOwner,
        name: &str,
        ranges: Vec<AuthenticatedDecodeRange>,
    ) -> RefFunction {
        RefFunction {
            owner,
            identity: ExecutionIdentity {
                entry: ranges.first().map(|range| range.start).unwrap_or(BASE),
                decode_ranges: ranges,
                execution_blake3: [0u8; 32],
            },
            name: name.to_string(),
        }
    }

    fn catalog_for(runtime: &RuntimeImage<'_>) -> ValidatedCatalog {
        let (base, size) = runtime.image_bounds();
        ValidatedCatalog {
            counts: CatalogCounts {
                records: 1,
                files: 1,
                messages: 1,
                quarantined: 0,
                unresolved_messages: 0,
                occurrences: 1,
            },
            identity: "v1:refs-fixture".to_string(),
            manifest_blake3: [1u8; 32],
            image_blake3: runtime.hash_range(base, size).unwrap(),
            scatter_entries_used: Vec::new(),
        }
    }

    fn inputs() -> RefsInputs {
        RefsInputs {
            functions_blake3: "0f".repeat(32),
            thumb_functions_blake3: None,
        }
    }

    fn run_attribute(
        tag: &str,
        image: &[u8],
        functions: &[RefFunction],
    ) -> (super::RefsOutcome, serde_json::Value) {
        let runtime = RuntimeImage::from_plan(image, BASE, None).unwrap();
        let tmp = unique_dir(tag);
        let out_path = tmp.path().join("references.json");
        let outcome = attribute(
            &runtime,
            &[RECORD],
            functions,
            &catalog_for(&runtime),
            inputs(),
            &out_path,
        )
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        (outcome, parsed)
    }

    fn rows_of(refs: &serde_json::Value) -> Vec<(String, String, String, String)> {
        refs["references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["pc"].as_str().unwrap().to_string(),
                    row["function_name"].as_str().unwrap().to_string(),
                    row["producer"].as_str().unwrap().to_string(),
                    row["evidence_kind"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    fn movw_movt_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x04].copy_from_slice(&MOVW_R0_0200);
        image[0x04..0x08].copy_from_slice(&MOVT_R0_4000);
        image
    }

    #[test]
    fn movw_movt_materialization_attributes_the_record() {
        let image = movw_movt_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "materializer",
            vec![thumb_range(&runtime, BASE, BASE + 8)],
        )];
        let (outcome, refs) = run_attribute("refs-movw", &image, &functions);
        assert_eq!(outcome.count, 1);
        assert_eq!(outcome.producers, vec![AnalysisTool::Ghidra]);
        assert_eq!(refs["format"], crate::dbt_traces::REFS_FORMAT);
        assert_eq!(refs["schema_version"], 1);
        assert_eq!(refs["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(refs["count"], 1);
        assert_eq!(
            refs["image"]["blake3"],
            crate::manifest::blake3_fixed(catalog_for(&runtime).image_blake3)
        );
        assert_eq!(
            refs["catalog"]["manifest_blake3"],
            crate::manifest::blake3_fixed([1u8; 32])
        );
        assert_eq!(refs["catalog"]["identity"], "v1:refs-fixture");
        assert_eq!(refs["inputs"]["functions_blake3"], "0f".repeat(32));
        assert!(refs["inputs"].get("thumb_functions_blake3").is_none());
        let row = &refs["references"][0];
        assert_eq!(row["record_address"], "0x40000200");
        assert_eq!(row["pc"], "0x40000000");
        assert_eq!(row["isa"], "thumb");
        assert_eq!(row["function_entry"], "0x40000000");
        assert_eq!(row["function_name"], "materializer");
        assert_eq!(row["producer"], "ghidra");
        assert_eq!(row["evidence_kind"], "movw_movt");
    }

    #[test]
    fn literal_load_resolves_through_the_pool() {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x02].copy_from_slice(&LDR_R0_PC4);
        image[0x08..0x0c].copy_from_slice(&RECORD.to_le_bytes());
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "loader",
            vec![thumb_range(&runtime, BASE, BASE + 2)],
        )];
        let (outcome, refs) = run_attribute("refs-literal", &image, &functions);
        assert_eq!(outcome.count, 1);
        let row = &refs["references"][0];
        assert_eq!(row["record_address"], "0x40000200");
        assert_eq!(row["pc"], "0x40000000");
        assert_eq!(row["evidence_kind"], "literal_load");
    }

    #[test]
    fn pc_relative_form_attributes() {
        let mut image = vec![0u8; 0x200];
        image[0x1f4..0x1f6].copy_from_slice(&ADR_PLUS_8);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "adr_fn",
            vec![thumb_range(&runtime, BASE + 0x1f4, BASE + 0x1f6)],
        )];
        let (outcome, refs) = run_attribute("refs-adr", &image, &functions);
        assert_eq!(outcome.count, 1);
        let row = &refs["references"][0];
        assert_eq!(row["record_address"], "0x40000200");
        assert_eq!(row["pc"], "0x400001f4");
        assert_eq!(row["evidence_kind"], "pc_relative");
    }

    #[test]
    fn a32_movw_movt_materialization_attributes_the_record() {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x04].copy_from_slice(&A32_MOVW_R0_0200);
        image[0x04..0x08].copy_from_slice(&A32_MOVT_R0_4000);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "a32_materializer",
            vec![arm_range(&runtime, BASE, BASE + 8)],
        )];
        let (outcome, refs) = run_attribute("refs-a32-movw", &image, &functions);
        assert_eq!(outcome.count, 1);
        let row = &refs["references"][0];
        assert_eq!(row["record_address"], "0x40000200");
        assert_eq!(row["pc"], "0x40000000");
        assert_eq!(row["isa"], "arm");
        assert_eq!(row["evidence_kind"], "movw_movt");
    }

    #[test]
    fn a32_literal_load_resolves_through_the_pool() {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x04].copy_from_slice(&A32_LDR_R0_PC0);
        image[0x08..0x0c].copy_from_slice(&RECORD.to_le_bytes());
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "a32_loader",
            vec![arm_range(&runtime, BASE, BASE + 4)],
        )];
        let (outcome, refs) = run_attribute("refs-a32-literal", &image, &functions);
        assert_eq!(outcome.count, 1);
        let row = &refs["references"][0];
        assert_eq!(row["record_address"], "0x40000200");
        assert_eq!(row["pc"], "0x40000000");
        assert_eq!(row["isa"], "arm");
        assert_eq!(row["evidence_kind"], "literal_load");
    }

    #[test]
    fn a32_pc_relative_form_attributes_with_unaligned_visible_pc() {
        let mut image = vec![0u8; 0x200];
        image[0x1f0..0x1f4].copy_from_slice(&A32_ADD_R0_PC_8);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "a32_adr_fn",
            vec![arm_range(&runtime, BASE + 0x1f0, BASE + 0x1f4)],
        )];
        let (outcome, refs) = run_attribute("refs-a32-adr", &image, &functions);
        assert_eq!(outcome.count, 1);
        let row = &refs["references"][0];
        assert_eq!(row["record_address"], "0x40000200");
        assert_eq!(row["pc"], "0x400001f0");
        assert_eq!(row["isa"], "arm");
        assert_eq!(row["evidence_kind"], "pc_relative");
    }

    #[test]
    fn clobbered_movw_never_pairs() {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x04].copy_from_slice(&MOVW_R0_0200);
        image[0x04..0x06].copy_from_slice(&MOV_R0_R1);
        image[0x06..0x0a].copy_from_slice(&MOVT_R0_4000);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "clobbered",
            vec![thumb_range(&runtime, BASE, BASE + 0x0a)],
        )];
        let (outcome, refs) = run_attribute("refs-clobber", &image, &functions);
        assert_eq!(outcome.count, 0);
        assert_eq!(refs["count"], 0);
        assert_eq!(refs["references"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn branch_breaks_the_pair_walk() {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x04].copy_from_slice(&MOVW_R0_0200);
        image[0x04..0x06].copy_from_slice(&B_FWD_2);
        image[0x06..0x0a].copy_from_slice(&MOVT_R0_4000);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "branched",
            vec![thumb_range(&runtime, BASE, BASE + 0x0a)],
        )];
        let (outcome, refs) = run_attribute("refs-branch", &image, &functions);
        assert_eq!(outcome.count, 0);
        assert_eq!(refs["count"], 0);
    }

    #[test]
    fn rows_are_deduplicated_and_sorted() {
        let mut image = vec![0u8; 0x200];
        image[0x00..0x04].copy_from_slice(&MOVW_R0_0200);
        image[0x04..0x08].copy_from_slice(&MOVT_R0_4000);
        image[0x1f4..0x1f6].copy_from_slice(&ADR_PLUS_8);
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![
            function(
                FunctionOwner::Ghidra,
                "alpha",
                vec![thumb_range(&runtime, BASE, BASE + 8)],
            ),
            function(
                FunctionOwner::Ghidra,
                "alpha_dup",
                vec![thumb_range(&runtime, BASE, BASE + 8)],
            ),
            function(
                FunctionOwner::Legacy {
                    producer: AnalysisTool::Radare2,
                },
                "radar",
                vec![thumb_range(&runtime, BASE, BASE + 8)],
            ),
            function(
                FunctionOwner::Ghidra,
                "beta",
                vec![thumb_range(&runtime, BASE + 0x1f4, BASE + 0x1f6)],
            ),
        ];
        let (outcome, refs) = run_attribute("refs-dedup", &image, &functions);
        assert_eq!(outcome.count, 3);
        assert_eq!(
            outcome.producers,
            vec![AnalysisTool::Ghidra, AnalysisTool::Radare2]
        );
        assert_eq!(
            rows_of(&refs),
            vec![
                (
                    "0x40000000".into(),
                    "alpha".into(),
                    "ghidra".into(),
                    "movw_movt".into()
                ),
                (
                    "0x40000000".into(),
                    "radar".into(),
                    "radare2".into(),
                    "movw_movt".into()
                ),
                (
                    "0x400001f4".into(),
                    "beta".into(),
                    "ghidra".into(),
                    "pc_relative".into()
                ),
            ]
        );
    }

    fn four_adr_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x200];
        image[0x1f4..0x1f6].copy_from_slice(&ADR_PLUS_8);
        image[0x1f6..0x1f8].copy_from_slice(&ADR_PLUS_8);
        image[0x1f8..0x1fa].copy_from_slice(&ADR_PLUS_4);
        image[0x1fa..0x1fc].copy_from_slice(&ADR_PLUS_4);
        image
    }

    #[test]
    fn reference_cap_fails_closed() {
        let image = four_adr_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "adr_fn",
            vec![thumb_range(&runtime, BASE + 0x1f4, BASE + 0x1fc)],
        )];
        let tmp = unique_dir("refs-cap");
        let out_path = tmp.path().join("references.json");
        let error = attribute_capped(
            &runtime,
            &[RECORD],
            &functions,
            &catalog_for(&runtime),
            inputs(),
            &out_path,
            2,
        )
        .unwrap_err();
        assert!(matches!(error, DbtTraceError::ReferenceCap(3)));
    }

    #[test]
    fn refs_failure_leaves_catalog_and_removes_refs_file() {
        let image = movw_movt_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "materializer",
            vec![thumb_range(&runtime, BASE, BASE + 8)],
        )];
        let tmp = unique_dir("refs-absent");
        std::fs::write(tmp.path().join("manifest.json"), b"catalog-intact").unwrap();
        let out_path = tmp.path().join("references.json");
        std::fs::write(&out_path, b"stale").unwrap();
        let error = attribute_capped(
            &runtime,
            &[RECORD],
            &functions,
            &catalog_for(&runtime),
            inputs(),
            &out_path,
            0,
        )
        .unwrap_err();
        assert!(matches!(error, DbtTraceError::ReferenceCap(1)));
        assert!(!out_path.exists());
        assert_eq!(
            std::fs::read(tmp.path().join("manifest.json")).unwrap(),
            b"catalog-intact"
        );
    }

    #[test]
    fn loaders_are_none_when_inventories_are_absent() {
        let image = movw_movt_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let tmp = unique_dir("refs-absent-inv");
        assert!(load_functions(tmp.path(), &runtime).unwrap().is_none());
        assert!(load_thumb(tmp.path(), &runtime).unwrap().is_none());
    }

    #[test]
    fn load_functions_reads_and_filters_ghidra_records() {
        let image = movw_movt_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let range_hash = crate::manifest::blake3_fixed(runtime.hash_range(BASE, 8).unwrap());
        let json = format!(
            "[{{\
                \"name\": \"renamed_out\", \"original_name\": \"renamed_in\", \
                \"primary_source\": \"default\", \"entry\": \"0x40000000\", \
                \"end\": \"0x40000008\", \"size\": 8, \
                \"decode_ranges\": [{{\"isa\": \"thumb\", \"start\": \"0x40000000\", \
                \"end\": \"0x40000008\", \"blake3\": \"{range_hash}\"}}], \
                \"decode_range_errors\": [], \"data_refs\": []}}, \
               {{\"name\": \"quarantined\", \"primary_source\": \"analysis\", \
                \"entry\": \"0x40000010\", \"end\": \"0x40000018\", \"size\": 8, \
                \"decode_ranges\": [], \"decode_range_errors\": [{{\"kind\": \
                \"empty_projection\", \"address\": \"0x40000010\", \"end\": null}}], \
                \"data_refs\": []}}]"
        );
        let tmp = unique_dir("refs-ghidra");
        std::fs::write(tmp.path().join("functions.json"), json).unwrap();
        let functions = load_functions(tmp.path(), &runtime).unwrap().unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "renamed_in");
        assert!(matches!(functions[0].owner, FunctionOwner::Ghidra));
        assert_eq!(functions[0].identity.entry, BASE);
        assert_eq!(functions[0].identity.decode_ranges.len(), 1);
        assert_eq!(functions[0].identity.decode_ranges[0].start, BASE);
    }

    #[test]
    fn load_thumb_reads_legacy_records_and_skips_quarantined() {
        let image = movw_movt_image();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let json = format!(
            "{{\"format\": \"{THUMB_V2_FORMAT}\", \"functions\": [\
                {{\"name\": \"thumb_fn\", \"entry\": \"0x40000000\", \
                \"decode_ranges\": [{{\"isa\": \"thumb\", \"start\": \"0x40000000\", \
                \"end\": \"0x40000008\"}}]}}, \
                {{\"name\": \"empty_fn\", \"entry\": \"0x40000010\"}}]}}"
        );
        let tmp = unique_dir("refs-thumb");
        std::fs::write(tmp.path().join("thumb_functions.json"), json).unwrap();
        let functions = load_thumb(tmp.path(), &runtime).unwrap().unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "thumb_fn");
        assert!(matches!(
            functions[0].owner,
            FunctionOwner::Legacy {
                producer: AnalysisTool::Radare2
            }
        ));
        assert_eq!(functions[0].identity.decode_ranges.len(), 1);
        assert_eq!(functions[0].identity.decode_ranges[0].end, BASE + 8);
    }

    #[test]
    fn evidence_kind_wire_names_are_exact() {
        assert_eq!(EvidenceKind::MovwMovt.as_str(), "movw_movt");
        assert_eq!(EvidenceKind::LiteralLoad.as_str(), "literal_load");
        assert_eq!(EvidenceKind::PcRelative.as_str(), "pc_relative");
    }

    #[test]
    fn rows_outside_the_record_set_and_unreadable_pools_are_ignored() {
        let mut image = vec![0u8; 0x10];
        image[0x00..0x02].copy_from_slice(&LDR_R0_PC4);
        image[0x08..0x0c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let functions = vec![function(
            FunctionOwner::Ghidra,
            "loader",
            vec![thumb_range(&runtime, BASE, BASE + 2)],
        )];
        let (outcome, refs) = run_attribute("refs-nonrecord", &image, &functions);
        assert_eq!(outcome.count, 0);
        assert_eq!(refs["count"], 0);
    }
}
