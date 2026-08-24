use std::path::PathBuf;

const BASE: u32 = 0x4001_0000;
const RECORD_BYTES: usize = 28;

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ptr(offset: usize) -> u32 {
    BASE + offset as u32
}

fn record(words: [u32; 7]) -> [u8; RECORD_BYTES] {
    let mut bytes = [0u8; RECORD_BYTES];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn main_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x220];
    image[0x100..0x109].copy_from_slice(b"main.c\0\0\0");
    image[0x140..0x149].copy_from_slice(b"hello %d\0");
    let words = [
        u32::from_le_bytes(*b"DBT:"),
        4,
        2,
        0xfecdba98,
        ptr(0x140),
        214,
        ptr(0x100),
    ];
    image[0x200..0x200 + RECORD_BYTES].copy_from_slice(&record(words));
    image
}

fn wrap_main(image: &[u8]) -> Vec<u8> {
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
    buf[payload_off..].copy_from_slice(image);
    buf
}

#[test]
fn decode_traces_on_synthetic_toc_produces_catalog() {
    let tmp = std::env::temp_dir().join(format!("pme-dbt-it-{}", std::process::id()));
    let _cleanup = Cleanup(tmp.clone());
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let toc_path = tmp.join("modem.bin");
    std::fs::write(&toc_path, wrap_main(&main_image())).unwrap();

    let out = tmp.join("decoded_traces");
    pixel_modem_extractor::dbt_traces::run(&toc_path, &Default::default(), &out).expect("run");

    let manifest = std::fs::read_to_string(out.join("debug_traces/manifest.json")).unwrap();
    assert!(manifest.contains("pixel-modem-extractor-debug-traces-v1"));
    assert!(manifest.contains("\"records\": 1"));
}
