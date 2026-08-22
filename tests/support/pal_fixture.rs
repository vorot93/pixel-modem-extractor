//! Non-proprietary MAIN/scatter/PAL fixture builder for the real-Ghidra
//! integration tests. Everything here is synthesized: no proprietary
//! names, bytes, or derived payloads. The MAIN image carries a valid
//! scatter loader/table (so kit generation materializes a real
//! `scatter/02_MAIN/load_map.json` whose digest pins the PAL manifest's
//! scatter dependency), two disassemblable ARM task entries, two anchor
//! occurrences, and the task slot/name storage the canonical manifest
//! references. The canonical manifest bytes follow the exact
//! `pal_tasks::artifact` wire layout (two-space indent, exact key order,
//! lowercase `0x` addresses, canonical decimals).

pub(super) const BASE: u32 = 0x4001_0000;
pub(super) const IMAGE_LEN: usize = 0x1000;
pub(super) const LABEL: &str = "02_MAIN";

const SLOT_BASE_OFF: usize = 0x100;
const STRIDE: usize = 0x40;
const SLOT_A_OFF: usize = SLOT_BASE_OFF;
const SLOT_B_OFF: usize = SLOT_BASE_OFF + STRIDE;
const TERMINAL_OFF: usize = SLOT_BASE_OFF + 2 * STRIDE;
const ENTRY_A_OFF: usize = 0x400;
const ENTRY_B_OFF: usize = 0x410;
const ANCHOR_A_OFF: usize = 0x440;
const ANCHOR_B_OFF: usize = 0x450;
const CFG_ENTRY_OFF: usize = 0x460;
const NAME_ALPHA_OFF: usize = 0x500;
const NAME_BETA_OFF: usize = 0x508;
const NAME_OFFSET: u32 = 40;
const ANCHOR_PATTERN: &[u8; 9] = b"PALTskTm\0";

pub(super) fn entry_a() -> u32 {
    BASE + ENTRY_A_OFF as u32
}

pub(super) fn entry_b() -> u32 {
    BASE + ENTRY_B_OFF as u32
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// The MAIN slice: scatter loader/table/sources copied from the
/// scatter-kit fixture, plus PAL task content (entries, anchors, names)
/// and the zeroed slot region.
pub(super) fn craft_main_image() -> Vec<u8> {
    const LOADER_OFFSET: usize = 0x40;
    const LOADER_IMMEDIATE: u32 = 0x38;
    const LITERAL_OFFSET: usize = LOADER_OFFSET + 8 + LOADER_IMMEDIATE as usize;
    const TABLE_OFFSET: usize = 0x200;
    const TABLE_LEN: u32 = 6 * 16;
    const NULL_HANDLER: u32 = BASE + 0x600;
    const COPY_HANDLER: u32 = BASE + 0x601;
    const DECOMPRESS1_HANDLER: u32 = BASE + 0x604;
    const ZERO_HANDLER: u32 = BASE + 0x609;
    const SENTINEL_SOURCE: u32 = BASE + 0x680;
    const SELF_COPY_SOURCE: u32 = BASE + 0x700;
    const COPY_SOURCE: u32 = BASE + 0x710;
    const DECOMPRESS1_SOURCE: u32 = BASE + 0x720;
    const ZERO_SOURCE: u32 = BASE + 0x730;

    let mut image = vec![0u8; IMAGE_LEN];
    // add r0, pc, #0x38; ldmia r0, {r10, r11}; add r10, r10, r0; add r11, r11, r0
    for (offset, instruction) in [0xe28f_0038, 0xe890_0c00, 0xe08a_a000, 0xe08b_b000]
        .into_iter()
        .enumerate()
    {
        put_u32(&mut image, LOADER_OFFSET + offset * 4, instruction);
    }
    let literal_address = BASE + LITERAL_OFFSET as u32;
    let table_address = BASE + TABLE_OFFSET as u32;
    put_u32(
        &mut image,
        LITERAL_OFFSET,
        table_address.wrapping_sub(literal_address),
    );
    put_u32(
        &mut image,
        LITERAL_OFFSET + 4,
        (table_address + TABLE_LEN).wrapping_sub(literal_address),
    );

    image[0x700..0x704].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    image[0x710..0x714].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    image[0x720..0x722].copy_from_slice(&[0x22, 0xaa]);
    for (index, source, destination, size, handler) in [
        (0, SENTINEL_SOURCE, 0, 0, NULL_HANDLER),
        (1, 0, SENTINEL_SOURCE, 0, NULL_HANDLER),
        (2, SELF_COPY_SOURCE, SELF_COPY_SOURCE, 4, COPY_HANDLER),
        (3, COPY_SOURCE, BASE + IMAGE_LEN as u32, 4, COPY_HANDLER),
        (
            4,
            DECOMPRESS1_SOURCE,
            BASE + IMAGE_LEN as u32 + 0x10,
            3,
            DECOMPRESS1_HANDLER,
        ),
        (
            5,
            ZERO_SOURCE,
            BASE + IMAGE_LEN as u32 + 0x20,
            5,
            ZERO_HANDLER,
        ),
    ] {
        let offset = TABLE_OFFSET + index * 16;
        for (field, value) in [source, destination, size, handler].into_iter().enumerate() {
            put_u32(&mut image, offset + field * 4, value);
        }
    }

    // PAL task content: two ARM functions (add r0,r0,r1 / add r1,r1,r2 /
    // bx lr and add r0,r0,r1 / bx lr), two anchor occurrences, names.
    image[ENTRY_A_OFF..ENTRY_A_OFF + 12].copy_from_slice(&[
        0x01, 0x00, 0x80, 0xe0, 0x02, 0x10, 0x81, 0xe0, 0x1e, 0xff, 0x2f, 0xe1,
    ]);
    image[ENTRY_B_OFF..ENTRY_B_OFF + 8]
        .copy_from_slice(&[0x01, 0x00, 0x80, 0xe0, 0x1e, 0xff, 0x2f, 0xe1]);
    image[ANCHOR_A_OFF..ANCHOR_A_OFF + 9].copy_from_slice(ANCHOR_PATTERN);
    image[ANCHOR_B_OFF..ANCHOR_B_OFF + 9].copy_from_slice(ANCHOR_PATTERN);
    image[NAME_ALPHA_OFF..NAME_ALPHA_OFF + 6].copy_from_slice(b"alpha\0");
    image[NAME_BETA_OFF..NAME_BETA_OFF + 5].copy_from_slice(b"beta\0");
    image
}

/// The modem.bin wrapping the MAIN slice (TOC label `02_MAIN`).
pub(super) fn craft_pal_main_modem_bin() -> Vec<u8> {
    let image = craft_main_image();
    let entry_off = 0x20usize;
    let payload_off = entry_off + 0x20;
    let mut buf = vec![0u8; payload_off + image.len()];
    buf[0..4].copy_from_slice(b"TOC\0");
    buf[0x1c..0x20].copy_from_slice(&1u32.to_le_bytes());
    buf[entry_off..entry_off + 4].copy_from_slice(b"MAIN");
    buf[entry_off + 12..entry_off + 16].copy_from_slice(&(payload_off as u32).to_le_bytes());
    buf[entry_off + 16..entry_off + 20].copy_from_slice(&BASE.to_le_bytes());
    buf[entry_off + 20..entry_off + 24].copy_from_slice(&(image.len() as u32).to_le_bytes());
    buf[entry_off + 28..entry_off + 32].copy_from_slice(&3u32.to_le_bytes());
    buf[payload_off..].copy_from_slice(&image);
    buf
}

pub(super) fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_string()
}

/// The PAL identity grammar: `v1:<manifest-blake3>:<task-records>:<distinct-entries>`.
pub(super) fn identity(manifest: &str) -> String {
    format!("v1:{}:2:0", blake3_hex(manifest.as_bytes()))
}

// A minimal pretty-JSON writer pinned to the canonical two-space layout
// `pal_tasks::artifact` emits (same shapes as the pinned Rust fixture).
struct Json {
    out: String,
    depth: usize,
}

impl Json {
    fn new() -> Self {
        Json {
            out: String::new(),
            depth: 0,
        }
    }

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }

    fn key(&mut self, first: bool, name: &str) {
        if !first {
            self.out.push(',');
        }
        self.out.push('\n');
        self.indent();
        self.out.push('"');
        self.out.push_str(name);
        self.out.push_str("\": ");
    }

    fn string_value(&mut self, value: &str) {
        self.out.push('"');
        for character in value.chars() {
            match character {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                other => self.out.push(other),
            }
        }
        self.out.push('"');
    }

    fn string_field(&mut self, first: bool, name: &str, value: &str) {
        self.key(first, name);
        self.string_value(value);
    }

    fn number_field(&mut self, first: bool, name: &str, value: u64) {
        self.key(first, name);
        self.out.push_str(&value.to_string());
    }

    fn open_object(&mut self) {
        self.out.push('{');
        self.depth += 1;
    }

    fn close_object(&mut self) {
        self.depth -= 1;
        if self.out.ends_with('{') {
            self.out.push('}');
            return;
        }
        self.out.push('\n');
        self.indent();
        self.out.push('}');
    }

    fn open_array(&mut self) {
        self.out.push('[');
        self.depth += 1;
    }

    fn close_array(&mut self) {
        self.depth -= 1;
        if self.out.ends_with('[') {
            self.out.push(']');
            return;
        }
        self.out.push('\n');
        self.indent();
        self.out.push(']');
    }

    fn element(&mut self, first: bool) {
        if !first {
            self.out.push(',');
        }
        self.out.push('\n');
        self.indent();
    }

    fn span(&mut self, address: u32, size: u64) {
        self.open_object();
        self.string_field(true, "kind", "raw");
        self.string_field(false, "address", &format!("{address:#010x}"));
        self.number_field(false, "size", size);
        self.close_object();
    }

    fn spans_field(&mut self, first: bool, name: &str, spans: &[(u32, u64)]) {
        self.key(first, name);
        self.open_array();
        for (index, (address, size)) in spans.iter().enumerate() {
            self.element(index == 0);
            self.span(*address, *size);
        }
        self.close_array();
    }
}

fn hash_region(image: &[u8], offset: usize, len: usize) -> String {
    blake3_hex(&image[offset..offset + len])
}

fn address(value: u32) -> String {
    format!("{value:#010x}")
}

/// The canonical PAL task manifest for the fixture image, pinned against
/// the generated scatter load map's digest. Layout mirrors the Rust
/// serializer byte for byte.
pub(super) fn canonical_manifest(image: &[u8], scatter_blake3_hex: &str) -> String {
    let image_hash = blake3_hex(image);
    let mut json = Json::new();
    json.open_object();
    json.string_field(true, "format", "pixel-modem-extractor-pal-tasks-v1");
    json.number_field(false, "schema_version", 1);
    json.string_field(false, "tool_version", env!("CARGO_PKG_VERSION"));

    json.key(false, "image");
    json.open_object();
    json.string_field(true, "label", LABEL);
    json.string_field(false, "base_addr", &address(BASE));
    json.number_field(false, "size", IMAGE_LEN as u64);
    json.string_field(false, "blake3", &image_hash);
    json.close_object();

    json.key(false, "runtime_view");
    json.open_object();
    json.string_field(true, "scatter_load_map_blake3", scatter_blake3_hex);
    json.key(false, "scatter_entries_used");
    json.open_array();
    json.close_array();
    json.close_object();

    json.key(false, "decoder");
    json.open_object();
    json.string_field(true, "semantic_adapter", "pixel-modem-extractor-arm32-v1");
    json.string_field(false, "backend_crate", "scaleservers-arm32-assembly");
    json.string_field(false, "backend_version", env!("CARGO_PKG_VERSION"));
    json.close_object();

    json.key(false, "initializer");
    json.open_object();
    json.string_field(true, "cfg_entry", &address(BASE + CFG_ENTRY_OFF as u32));
    json.key(false, "anchors");
    json.open_array();
    for (index, offset) in [ANCHOR_A_OFF, ANCHOR_B_OFF].into_iter().enumerate() {
        json.element(index == 0);
        json.open_object();
        json.string_field(true, "address", &address(BASE + offset as u32));
        json.spans_field(false, "storage", &[(BASE + offset as u32, 9)]);
        json.close_object();
    }
    json.close_array();
    json.key(false, "anchor_references");
    json.open_array();
    json.element(true);
    json.open_object();
    json.string_field(true, "anchor", &address(BASE + ANCHOR_A_OFF as u32));
    json.string_field(false, "address", &address(BASE + ENTRY_A_OFF as u32));
    json.string_field(false, "kind", "adr");
    json.key(false, "definitions");
    json.open_array();
    json.element(true);
    json.string_value(&address(BASE + ENTRY_A_OFF as u32));
    json.close_array();
    json.string_field(false, "call", &address(BASE + ENTRY_A_OFF as u32 + 4));
    json.close_object();
    json.element(false);
    json.open_object();
    json.string_field(true, "anchor", &address(BASE + ANCHOR_B_OFF as u32));
    json.string_field(false, "address", &address(BASE + ENTRY_B_OFF as u32));
    json.string_field(false, "kind", "movw_movt");
    json.key(false, "definitions");
    json.open_array();
    json.element(true);
    json.string_value(&address(BASE + ENTRY_B_OFF as u32));
    json.element(false);
    json.string_value(&address(BASE + ENTRY_B_OFF as u32 + 2));
    json.close_array();
    json.string_field(false, "call", &address(BASE + ENTRY_B_OFF as u32 + 4));
    json.close_object();
    json.close_array();
    json.spans_field(false, "code_storage", &[(BASE + ENTRY_A_OFF as u32, 0x90)]);
    json.string_field(
        false,
        "loop_start",
        &address(BASE + CFG_ENTRY_OFF as u32 + 4),
    );
    json.string_field(
        false,
        "count_zero_definition",
        &address(BASE + CFG_ENTRY_OFF as u32 + 8),
    );
    json.key(false, "slot_definition");
    json.open_object();
    json.string_field(true, "root", &address(BASE + CFG_ENTRY_OFF as u32 + 0xc));
    json.key(false, "definitions");
    json.open_array();
    json.element(true);
    json.string_value(&address(BASE + CFG_ENTRY_OFF as u32 + 0xc));
    json.close_array();
    json.close_object();
    json.string_field(
        false,
        "normal_exit",
        &address(BASE + CFG_ENTRY_OFF as u32 + 0x10),
    );
    json.string_field(
        false,
        "capacity_exit",
        &address(BASE + CFG_ENTRY_OFF as u32 + 0x14),
    );
    json.key(false, "capacity_guard");
    json.open_object();
    json.string_field(true, "start", &address(BASE + CFG_ENTRY_OFF as u32 + 0x18));
    json.string_field(
        false,
        "branch",
        &address(BASE + CFG_ENTRY_OFF as u32 + 0x1c),
    );
    json.string_field(
        false,
        "fallthrough",
        &address(BASE + CFG_ENTRY_OFF as u32 + 0x1e),
    );
    json.string_field(false, "relation", "count_ge_capacity");
    json.close_object();
    json.string_field(
        false,
        "suffix_loop",
        &address(BASE + CFG_ENTRY_OFF as u32 + 0x20),
    );
    json.string_field(false, "join", &address(BASE + CFG_ENTRY_OFF as u32 + 0x24));
    json.string_field(
        false,
        "count_global",
        &address(BASE + CFG_ENTRY_OFF as u32 + 0x28),
    );
    json.string_field(false, "slot_base", &address(BASE + SLOT_BASE_OFF as u32));
    json.number_field(false, "name_offset", NAME_OFFSET as u64);
    json.number_field(false, "index_offset", 12);
    json.number_field(false, "stride", STRIDE as u64);
    json.number_field(false, "capacity", 8);
    json.close_object();

    json.key(false, "table");
    json.open_object();
    json.number_field(true, "count", 2);
    json.string_field(false, "terminal_slot", &address(BASE + TERMINAL_OFF as u32));
    json.string_field(
        false,
        "terminal_blake3",
        &hash_region(image, TERMINAL_OFF, STRIDE),
    );
    json.spans_field(
        false,
        "terminal_storage",
        &[(BASE + TERMINAL_OFF as u32, STRIDE as u64)],
    );
    json.number_field(
        false,
        "descriptor_projection_offset",
        (NAME_OFFSET - 0x24) as u64,
    );
    json.number_field(false, "priority_offset", NAME_OFFSET as u64 + 4);
    json.number_field(false, "stack_size_offset", NAME_OFFSET as u64 + 8);
    json.number_field(false, "entry_offset", NAME_OFFSET as u64 + 12);
    json.number_field(false, "callback_offset", NAME_OFFSET as u64 + 16);
    json.number_field(false, "unknown_pointer_offset", NAME_OFFSET as u64 + 20);
    json.close_object();

    json.key(false, "tasks");
    json.open_array();
    let tasks = [
        (
            0,
            SLOT_A_OFF,
            NAME_ALPHA_OFF,
            6,
            "alpha",
            100,
            512,
            ENTRY_A_OFF,
            "0x00000000",
            "0x00000000",
        ),
        (
            1,
            SLOT_B_OFF,
            NAME_BETA_OFF,
            5,
            "beta",
            255,
            33000,
            ENTRY_B_OFF,
            "0x6789abcd",
            "0x00001234",
        ),
    ];
    for (index, slot, name_at, name_len, name, priority, stack, entry, callback, unknown) in tasks {
        json.element(index == 0);
        json.open_object();
        json.number_field(true, "index", index as u64);
        json.string_field(false, "slot", &address(BASE + slot as u32));
        json.string_field(false, "slot_blake3", &hash_region(image, slot, STRIDE));
        json.string_field(false, "name_pointer", &address(BASE + name_at as u32));
        json.string_field(false, "name", name);
        json.string_field(false, "task_label", &format!("pal_TaskEntry_{name}"));
        json.number_field(false, "priority", priority);
        json.number_field(false, "stack_size", stack);
        json.string_field(false, "entry_pointer", &address(BASE + entry as u32));
        json.string_field(false, "entry", &address(BASE + entry as u32));
        json.string_field(false, "isa", "arm");
        json.number_field(false, "instruction_size", 4);
        json.string_field(false, "instruction_blake3", &hash_region(image, entry, 4));
        json.string_field(false, "callback", callback);
        json.string_field(false, "unknown_pointer", unknown);
        json.spans_field(
            false,
            "slot_storage",
            &[(BASE + slot as u32, STRIDE as u64)],
        );
        json.spans_field(false, "name_storage", &[(BASE + name_at as u32, name_len)]);
        json.spans_field(false, "entry_storage", &[(BASE + entry as u32, 4)]);
        json.close_object();
    }
    json.close_array();

    json.key(false, "applications");
    json.open_array();
    for (index, (name, entry)) in [("alpha", ENTRY_A_OFF), ("beta", ENTRY_B_OFF)]
        .into_iter()
        .enumerate()
    {
        json.element(index == 0);
        json.open_object();
        json.string_field(true, "entry", &address(BASE + entry as u32));
        json.string_field(false, "isa", "arm");
        json.string_field(false, "desired_primary", &format!("pal_TaskEntry_{name}"));
        json.key(false, "task_indices");
        json.open_array();
        json.element(true);
        json.out.push_str(&index.to_string());
        json.close_array();
        json.key(false, "labels");
        json.open_array();
        json.element(true);
        json.open_object();
        json.string_field(true, "label", &format!("pal_TaskEntry_{name}"));
        json.key(false, "task_indices");
        json.open_array();
        json.element(true);
        json.out.push_str(&index.to_string());
        json.close_array();
        json.close_object();
        json.close_array();
        json.close_object();
    }
    json.close_array();

    json.close_object();
    json.out.push('\n');
    json.out
}

fn le_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// The execution digest grammar shared with Task 2 and the Java support:
/// domain, little-endian u32 entry, little-endian u32 range count, then
/// per range the ISA byte (0=arm), little-endian u32 start/end, and the
/// 32 range-digest bytes.
pub(super) fn execution_digest(entry: u32, ranges: &[(u32, u32, &str, &str)]) -> String {
    let mut framed = Vec::new();
    framed.extend_from_slice(b"pixel-modem-extractor-execution-v1\0");
    framed.extend_from_slice(&entry.to_le_bytes());
    le_u32(u32::try_from(ranges.len()).unwrap(), &mut framed);
    for &(start, end, _isa, blake3_hex) in ranges {
        framed.push(0);
        le_u32(start, &mut framed);
        le_u32(end, &mut framed);
        framed.extend_from_slice(
            &hex_decode(blake3_hex).expect("fixture range digests are canonical hex"),
        );
    }
    blake3_hex(&framed)
}

pub(super) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
    }
    Some(out)
}

/// A minimal canonical `pixel-modem-extractor-symbol-map-v2` covering the
/// two fixture executions (one PAL rename decision, one preserve), with
/// the exact ordered fields the strict reader enforces.
pub(super) fn canonical_symbol_map(
    image: &[u8],
    pal_identity: &str,
    manifest_blake3_hex: &str,
    scatter_blake3_hex: &str,
    functions_blake3_hex: &str,
) -> String {
    let range_a_blake3 = hash_region(image, ENTRY_A_OFF, 12);
    let range_b_blake3 = hash_region(image, ENTRY_B_OFF, 8);
    let execution_a = execution_digest(
        BASE + ENTRY_A_OFF as u32,
        &[(entry_a(), entry_a() + 12, "arm", &range_a_blake3)],
    );
    let execution_b = execution_digest(
        BASE + ENTRY_B_OFF as u32,
        &[(entry_b(), entry_b() + 8, "arm", &range_b_blake3)],
    );

    let mut json = Json::new();
    json.open_object();
    json.string_field(true, "format", "pixel-modem-extractor-symbol-map-v2");
    json.key(false, "image");
    json.open_object();
    json.string_field(true, "label", LABEL);
    json.string_field(false, "base_addr", &address(BASE));
    json.number_field(false, "size", IMAGE_LEN as u64);
    json.string_field(false, "blake3", &blake3_hex(image));
    json.close_object();
    json.key(false, "pal");
    json.open_object();
    json.string_field(true, "identity", pal_identity);
    json.string_field(false, "manifest_blake3", manifest_blake3_hex);
    json.string_field(false, "scatter_load_map_blake3", scatter_blake3_hex);
    json.close_object();
    json.string_field(false, "functions_blake3", functions_blake3_hex);
    json.key(false, "executions");
    json.open_array();
    for (first, entry, execution, start, end, blake3) in [
        (
            true,
            entry_a(),
            execution_a,
            entry_a(),
            entry_a() + 12,
            range_a_blake3,
        ),
        (
            false,
            entry_b(),
            execution_b,
            entry_b(),
            entry_b() + 8,
            range_b_blake3,
        ),
    ] {
        json.element(first);
        json.open_object();
        json.string_field(true, "producer", "ghidra");
        json.string_field(false, "entry", &address(entry));
        json.string_field(false, "execution_blake3", &execution);
        json.key(false, "decode_ranges");
        json.open_array();
        json.element(true);
        json.open_object();
        json.string_field(true, "isa", "arm");
        json.string_field(false, "start", &address(start));
        json.string_field(false, "end", &address(end));
        json.string_field(false, "blake3", &blake3);
        json.close_object();
        json.close_array();
        json.close_object();
    }
    json.close_array();
    json.key(false, "symbols");
    json.open_array();
    json.element(true);
    json.open_object();
    json.number_field(true, "execution", 0);
    json.string_field(false, "original_primary", "FUN_40010400");
    json.string_field(false, "original_source", "default");
    json.string_field(false, "final_primary", "pal_TaskEntry_alpha");
    json.string_field(false, "final_source", "analysis");
    json.string_field(false, "action", "rename");
    json.key(false, "annotations");
    json.open_array();
    json.element(true);
    json.string_value("pal task alpha");
    json.close_array();
    json.key(false, "pal_transition");
    json.open_object();
    json.string_field(true, "from", "pal_owned");
    json.string_field(false, "to", "pass2_owned");
    json.close_object();
    json.close_object();
    json.element(false);
    json.open_object();
    json.number_field(true, "execution", 1);
    json.string_field(false, "original_primary", "FUN_40010410");
    json.string_field(false, "original_source", "default");
    json.string_field(false, "final_primary", "FUN_40010410");
    json.string_field(false, "final_source", "default");
    json.string_field(false, "action", "preserve");
    json.key(false, "annotations");
    json.open_array();
    json.close_array();
    json.key(false, "pal_transition");
    json.out.push_str("null");
    json.close_object();
    json.close_array();
    json.close_object();
    json.out.push('\n');
    json.out
}
