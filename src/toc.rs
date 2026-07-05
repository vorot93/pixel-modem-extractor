use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

const ENTRY_OFF: usize = 0x20;
const ENTRY_STRIDE: usize = 0x20;

#[derive(Debug, Clone)]
pub struct TocEntry {
    pub name: String,
    pub offset: u32,
    pub load_addr: u32,
    pub size: u32,
    pub crc: u32,
    pub index: u32,
}

impl TocEntry {
    /// Canonical split-image label, e.g. index 3 / "MAIN" -> "02_MAIN".
    ///
    /// The TOC `name` comes from (untrusted) firmware. The label flows into
    /// filesystem paths and the generated `run_ghidra.sh`, so every name char
    /// outside `[A-Za-z0-9_.-]` collapses to `_` — neutralizing path traversal
    /// (`/`, `..`) and shell metacharacters (`"`, `$`, …). The numeric `NN_`
    /// prefix means the label is always a single component, never `.`/`..`. For
    /// real images (BOOT/PSP/MAIN/APM/VSS/DBGCORE) this is a no-op.
    pub fn label(&self) -> String {
        let safe: String = self
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{:02}_{}", self.index - 1, safe)
    }
}

#[derive(Debug, Clone)]
pub struct Toc {
    pub entries: Vec<TocEntry>,
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl Toc {
    pub fn parse(data: &[u8]) -> Result<Toc> {
        if data.len() < 0x20 || &data[0..4] != b"TOC\0" {
            return Err(Error::BadToc("missing TOC magic".into()));
        }
        let count = rd_u32(data, 0x1c) as usize;
        let max_by_data = data.len().saturating_sub(ENTRY_OFF) / ENTRY_STRIDE;
        let mut entries = Vec::with_capacity(count.min(max_by_data));
        for i in 0..count {
            let p = ENTRY_OFF + i * ENTRY_STRIDE;
            if p + ENTRY_STRIDE > data.len() {
                return Err(Error::BadToc(format!("entry {i} out of range")));
            }
            let name_bytes = &data[p..p + 12];
            let nend = name_bytes.iter().position(|&c| c == 0).unwrap_or(12);
            entries.push(TocEntry {
                name: String::from_utf8_lossy(&name_bytes[..nend]).into_owned(),
                offset: rd_u32(data, p + 12),
                load_addr: rd_u32(data, p + 16),
                size: rd_u32(data, p + 20),
                crc: rd_u32(data, p + 24),
                index: rd_u32(data, p + 28),
            });
        }
        Ok(Toc { entries })
    }

    pub fn embedded(&self) -> Vec<&TocEntry> {
        let mut v: Vec<&TocEntry> = self
            .entries
            .iter()
            .filter(|e| (1..=6).contains(&e.index) && e.offset > 0)
            .collect();
        v.sort_by_key(|e| e.index);
        v
    }

    pub fn split_to_dir(&self, data: &[u8], out_dir: &Path, verify: bool) -> Result<Vec<PathBuf>> {
        std::fs::create_dir_all(out_dir)?;
        let mut written = Vec::new();
        for e in self.embedded() {
            let start = e.offset as usize;
            let end = start + e.size as usize;
            if end > data.len() {
                return Err(Error::SizeMismatch {
                    name: e.name.clone(),
                    expected: e.size as u64,
                    actual: data.len().saturating_sub(start) as u64,
                });
            }
            let slice = &data[start..end];
            if verify {
                let crc = crc32fast::hash(slice);
                if crc != e.crc {
                    tracing::warn!(
                        "crc advisory mismatch for {}: toc={:#x} crc32={:#x}",
                        e.name,
                        e.crc,
                        crc
                    );
                }
            }
            let fname = e.label();
            let path = out_dir.join(&fname);
            std::fs::write(&path, slice)?;
            written.push(path);
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FW: &str = "PIXELMODEM_rootfs/images/g5400i-260317-260429-B-15308590";

    #[test]
    fn parses_real_toc() {
        // Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root); unset/absent → skip.
        let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        let modem_bin = root.join(FW).join("modem.bin");
        if !modem_bin.exists() {
            eprintln!("skip: golden modem.bin absent");
            return;
        }
        let data = std::fs::read(&modem_bin).unwrap();
        let toc = Toc::parse(&data).unwrap();
        assert_eq!(toc.entries.len(), 10);
        let emb = toc.embedded();
        assert_eq!(emb.len(), 6);
        let main = emb.iter().find(|e| e.name == "MAIN").unwrap();
        assert_eq!(main.offset, 0x5f220);
        assert_eq!(main.size, 0x534e694);
        assert_eq!(main.load_addr, 0x4001_0000);
        // contiguity
        for w in emb.windows(2) {
            assert_eq!(
                w[0].offset + w[0].size,
                w[1].offset,
                "gap before {}",
                w[1].name
            );
        }
    }

    #[test]
    fn label_formats_index_minus_one_and_name() {
        let main = TocEntry {
            name: "MAIN".into(),
            offset: 1,
            load_addr: 0,
            size: 1,
            crc: 0,
            index: 3,
        };
        assert_eq!(main.label(), "02_MAIN");
        let boot = TocEntry {
            name: "BOOT".into(),
            offset: 1,
            load_addr: 0,
            size: 1,
            crc: 0,
            index: 1,
        };
        assert_eq!(boot.label(), "00_BOOT");
    }

    #[test]
    fn label_sanitizes_unsafe_name_chars() {
        // path separators, parent refs, and shell-active chars all collapse to '_'.
        let e = TocEntry {
            name: "a/../b\"$x".into(),
            offset: 1,
            load_addr: 0,
            size: 1,
            crc: 0,
            index: 1,
        };
        let label = e.label();
        assert_eq!(label, "00_a_.._b__x");
        assert!(!label.contains('/'), "no path separators in {label}");
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')),
            "only safe chars remain: {label}"
        );
    }

    #[test]
    fn splits_to_files() {
        // Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root); unset/absent → skip.
        let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        let modem_bin = root.join(FW).join("modem.bin");
        if !modem_bin.exists() {
            eprintln!("skip: golden modem.bin absent");
            return;
        }
        let data = std::fs::read(&modem_bin).unwrap();
        let toc = Toc::parse(&data).unwrap();
        let dir = std::env::temp_dir().join("pme_toc_test");
        let _ = std::fs::remove_dir_all(&dir);
        let paths = toc.split_to_dir(&data, &dir, true).unwrap();
        assert_eq!(paths.len(), 6);
        let boot = dir.join("00_BOOT");
        assert!(boot.exists());
        assert_eq!(std::fs::metadata(&boot).unwrap().len(), 138240);
        assert_eq!(
            std::fs::metadata(dir.join("05_DBGCORE")).unwrap().len(),
            5520
        );
    }
}
