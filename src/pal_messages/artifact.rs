use super::{FORMAT, MAX_MANIFEST_BYTES, MessagePlan, PalMessageError, RawSlot};
use crate::execution_ranges::DecodeIsa;
use crate::runtime_image::RuntimeImage;
use atomic_write_file::AtomicWriteFile;
use serde_json::{Map, Value};
use std::fs;
use std::io::Write as _;
use std::path::Path;

const ARTIFACT_DIR_NAME: &str = "pal_messages";
const ARTIFACT_FILE_NAME: &str = "messages.json";

#[derive(Clone, Copy)]
pub(crate) struct MessageArtifactContext<'a> {
    pub label: &'a str,
    pub image_blake3: [u8; 32],
    pub scatter_load_map_blake3: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedMessages {
    pub relative_path: String,
    pub blake3: String,
    pub identity: String,
    pub slots: usize,
}

pub(crate) fn materialize(
    plan: &MessagePlan,
    context: MessageArtifactContext<'_>,
    root: &Path,
) -> Result<MaterializedMessages, PalMessageError> {
    let bytes = serialize(plan, &context)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(artifact(format!(
            "serialized manifest is {} bytes, above the {MAX_MANIFEST_BYTES}-byte ceiling",
            bytes.len()
        )));
    }
    let dir = root.join(ARTIFACT_DIR_NAME).join(context.label);
    fs::create_dir_all(&dir).map_err(|error| artifact(error.to_string()))?;
    let target = dir.join(ARTIFACT_FILE_NAME);
    let digest = *blake3::hash(&bytes).as_bytes();
    let mut file = AtomicWriteFile::open(&target)
        .map_err(|error| artifact(format!("atomic publication failed: {error}")))?;
    file.write_all(&bytes)
        .map_err(|error| artifact(format!("atomic write failed: {error}")))?;
    file.commit()
        .map_err(|error| artifact(format!("atomic commit failed: {error}")))?;
    Ok(MaterializedMessages {
        relative_path: format!(
            "{ARTIFACT_DIR_NAME}/{}/{}",
            context.label, ARTIFACT_FILE_NAME
        ),
        blake3: hex_digest(digest),
        identity: identity(digest, 1, plan.slots.len()),
        slots: plan.slots.len(),
    })
}

pub(crate) fn read_bytes(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    context: MessageArtifactContext<'_>,
) -> Result<MessagePlan, PalMessageError> {
    let canonical = serialize(&parse_plan(bytes, runtime, &context)?, &context)?;
    if canonical.as_slice() != bytes {
        return Err(artifact("manifest bytes are not canonical"));
    }
    parse_plan(bytes, runtime, &context)
}

pub(crate) fn clear_materialized(root: &Path, label: &str) -> Result<(), PalMessageError> {
    let target = root
        .join(ARTIFACT_DIR_NAME)
        .join(label)
        .join(ARTIFACT_FILE_NAME);
    match fs::remove_file(&target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(artifact(error.to_string())),
    }
}

fn serialize(
    plan: &MessagePlan,
    context: &MessageArtifactContext<'_>,
) -> Result<Vec<u8>, PalMessageError> {
    let mut slots = Vec::new();
    for slot in &plan.slots {
        slots.push(Value::Object(slot_object(slot)));
    }
    let mut image = Map::new();
    image.insert("label".into(), Value::String(plan.image_label.clone()));
    image.insert(
        "base_addr".into(),
        Value::String(format!("{:#010x}", plan.image_base)),
    );
    image.insert(
        "blake3".into(),
        Value::String(hex_digest(context.image_blake3)),
    );
    let mut setup = Map::new();
    setup.insert(
        "entry".into(),
        Value::String(format!("{:#010x}", plan.setup_entry)),
    );
    setup.insert(
        "isa".into(),
        Value::String(isa_label(plan.setup_isa).into()),
    );
    let mut table = Map::new();
    table.insert(
        "base".into(),
        Value::String(format!("{:#010x}", plan.table_base)),
    );
    table.insert(
        "end".into(),
        Value::String(format!("{:#010x}", plan.table_end)),
    );
    table.insert("stride".into(), Value::from(plan.stride));
    table.insert("capacity".into(), Value::from(plan.capacity));
    let mut root = Map::new();
    root.insert("format".into(), Value::String(FORMAT.into()));
    root.insert("image".into(), Value::Object(image));
    if let Some(scatter) = context.scatter_load_map_blake3 {
        root.insert(
            "scatter_load_map_blake3".into(),
            Value::String(hex_digest(scatter)),
        );
    }
    root.insert("setup".into(), Value::Object(setup));
    root.insert("table".into(), Value::Object(table));
    root.insert("slots".into(), Value::Array(slots));
    let mut bytes = serde_json::to_vec_pretty(&Value::Object(root))
        .map_err(|error| artifact(error.to_string()))?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(bytes)
}

fn parse_plan(
    bytes: &[u8],
    runtime: &RuntimeImage<'_>,
    context: &MessageArtifactContext<'_>,
) -> Result<MessagePlan, PalMessageError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| artifact(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| artifact("manifest is not an object"))?;
    if object.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(artifact("unexpected format"));
    }
    let image = object
        .get("image")
        .and_then(Value::as_object)
        .ok_or_else(|| artifact("missing image"))?;
    let label = image
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| artifact("missing label"))?
        .to_owned();
    if label != context.label {
        return Err(artifact("image label mismatch"));
    }
    let setup = object
        .get("setup")
        .and_then(Value::as_object)
        .ok_or_else(|| artifact("missing setup"))?;
    let table = object
        .get("table")
        .and_then(Value::as_object)
        .ok_or_else(|| artifact("missing table"))?;
    let slots = object
        .get("slots")
        .and_then(Value::as_array)
        .ok_or_else(|| artifact("missing slots"))?;
    let mut parsed_slots = Vec::new();
    for slot in slots {
        parsed_slots.push(parse_slot(slot, runtime)?);
    }
    let (image_base, image_size) = runtime.image_bounds();
    Ok(MessagePlan {
        image_label: label,
        image_base,
        image_size,
        setup_entry: parse_addr(setup.get("entry"))?,
        setup_isa: parse_isa(setup.get("isa"))?,
        table_base: parse_addr(table.get("base"))?,
        table_end: parse_addr(table.get("end"))?,
        stride: table
            .get("stride")
            .and_then(Value::as_u64)
            .ok_or_else(|| artifact("missing stride"))? as u32,
        capacity: table
            .get("capacity")
            .and_then(Value::as_u64)
            .ok_or_else(|| artifact("missing capacity"))? as u32,
        slots: parsed_slots,
    })
}

fn parse_slot(value: &Value, runtime: &RuntimeImage<'_>) -> Result<RawSlot, PalMessageError> {
    let object = value
        .as_object()
        .ok_or_else(|| artifact("slot is not an object"))?;
    let index = object
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| artifact("missing slot index"))? as u32;
    let address = parse_addr(object.get("address"))?;
    let size = object
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| artifact("missing slot size"))? as u32;
    let expected = object
        .get("blake3")
        .and_then(Value::as_str)
        .ok_or_else(|| artifact("missing slot blake3"))?;
    let digest = runtime
        .hash_range(address, size)
        .map_err(|error| PalMessageError::Runtime {
            address,
            size,
            reason: error.to_string(),
        })?;
    if hex_digest(digest) != expected {
        return Err(artifact("slot blake3 mismatch"));
    }
    Ok(RawSlot {
        index,
        address,
        size,
        blake3: digest,
    })
}

fn parse_addr(value: Option<&Value>) -> Result<u32, PalMessageError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| artifact("missing address"))?;
    let stripped = text
        .strip_prefix("0x")
        .ok_or_else(|| artifact("address is not lowercase hex"))?;
    u32::from_str_radix(stripped, 16).map_err(|error| artifact(error.to_string()))
}

fn parse_isa(value: Option<&Value>) -> Result<DecodeIsa, PalMessageError> {
    match value.and_then(Value::as_str) {
        Some("arm") => Ok(DecodeIsa::Arm),
        Some("thumb") => Ok(DecodeIsa::Thumb),
        _ => Err(artifact("invalid isa")),
    }
}

fn slot_object(slot: &RawSlot) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("index".into(), Value::from(slot.index));
    object.insert(
        "address".into(),
        Value::String(format!("{:#010x}", slot.address)),
    );
    object.insert("size".into(), Value::from(slot.size));
    object.insert("blake3".into(), Value::String(hex_digest(slot.blake3)));
    object
}

fn identity(digest: [u8; 32], named_roots: usize, slots: usize) -> String {
    format!("v1:{}:{named_roots}:{slots}", hex_digest(digest))
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn isa_label(isa: DecodeIsa) -> &'static str {
    match isa {
        DecodeIsa::Arm => "arm",
        DecodeIsa::Thumb => "thumb",
    }
}

fn artifact(reason: impl Into<String>) -> PalMessageError {
    PalMessageError::Artifact(reason.into())
}

#[cfg(test)]
mod tests {
    use super::{MessageArtifactContext, clear_materialized, materialize, read_bytes};
    use crate::pal_messages::discover::discover;
    use crate::runtime_image::RuntimeImage;

    const BASE: u32 = 0x4001_0000;
    const SEED: &[u8] = crate::pal_messages::SEED;
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

    fn plant() -> Vec<u8> {
        let mut image = vec![0u8; 0x100];
        let table_base = BASE + 0x80;
        image[0..4].copy_from_slice(&A32_ADD_R0_PC_18);
        image[4..8].copy_from_slice(&A32_MOV_R1_4);
        image[8..12].copy_from_slice(&A32_MOV_R3_16);
        image[12..16].copy_from_slice(&a32_movw(2, (table_base & 0xffff) as u16));
        image[16..20].copy_from_slice(&a32_movt(2, (table_base >> 16) as u16));
        image[20..24].copy_from_slice(&A32_STR_R1_R2);
        image[24..28].copy_from_slice(&A32_BX_LR);
        image[0x20..0x20 + SEED.len()].copy_from_slice(SEED);
        image[0x20 + SEED.len()] = 0;
        image
    }

    #[test]
    fn materialize_then_read_round_trips() {
        let image = plant();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let plan = discover(&runtime, "02_MAIN").unwrap().unwrap();
        let root = tempfile::tempdir().unwrap();
        let context = MessageArtifactContext {
            label: "02_MAIN",
            image_blake3: *blake3::hash(&image).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let bytes = std::fs::read(root.path().join(&materialized.relative_path)).unwrap();
        assert_ne!(bytes.last().copied(), Some(b'\n'));
        let read = read_bytes(&bytes, &runtime, context).unwrap();
        assert_eq!(read.setup_entry, plan.setup_entry);
        assert_eq!(read.slots, plan.slots);
        assert!(materialized.identity.starts_with("v1:"));
    }

    #[test]
    fn reader_rejects_one_byte_slot_mutation() {
        let image = plant();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let plan = discover(&runtime, "02_MAIN").unwrap().unwrap();
        let root = tempfile::tempdir().unwrap();
        let context = MessageArtifactContext {
            label: "02_MAIN",
            image_blake3: *blake3::hash(&image).as_bytes(),
            scatter_load_map_blake3: None,
        };
        let materialized = materialize(&plan, context, root.path()).unwrap();
        let path = root.path().join(&materialized.relative_path);
        let bytes = std::fs::read(&path).unwrap();
        let mut mutated = image.clone();
        mutated[0x80] ^= 1;
        let mutated_runtime = RuntimeImage::from_plan(&mutated, BASE, None).unwrap();
        assert!(read_bytes(&bytes, &mutated_runtime, context).is_err());
    }

    #[test]
    fn clear_removes_owned_leaf_only() {
        let image = plant();
        let runtime = RuntimeImage::from_plan(&image, BASE, None).unwrap();
        let plan = discover(&runtime, "02_MAIN").unwrap().unwrap();
        let root = tempfile::tempdir().unwrap();
        let context = MessageArtifactContext {
            label: "02_MAIN",
            image_blake3: *blake3::hash(&image).as_bytes(),
            scatter_load_map_blake3: None,
        };
        materialize(&plan, context, root.path()).unwrap();
        let sibling = root.path().join("foreign.txt");
        std::fs::write(&sibling, b"keep").unwrap();
        clear_materialized(root.path(), "02_MAIN").unwrap();
        assert!(
            !root
                .path()
                .join("pal_messages/02_MAIN/messages.json")
                .exists()
        );
        assert_eq!(std::fs::read(&sibling).unwrap(), b"keep");
    }
}
