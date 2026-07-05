use crate::error::{Error, Result};
use ext4_view::{Ext4, Ext4Read};
use std::path::Path;

pub struct Ext4Fs {
    fs: Ext4,
}

/// A reader that prepends a virtual 1024-byte boot sector (all zeros) to the
/// underlying file. Some ext4 images (e.g. Android firmware partitions) omit
/// the boot-sector area, placing the superblock at byte 0 instead of byte 1024.
/// ext4-view always reads the superblock from byte 1024, so we shift reads by
/// +1024: when ext4-view asks for byte N we serve file byte N-1024.
struct BootSectorPrependReader {
    file: std::fs::File,
}

impl Ext4Read for BootSectorPrependReader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        use std::io::{Read, Seek, SeekFrom};

        const BOOT: u64 = 1024;

        if dst.is_empty() {
            return Ok(());
        }

        if start_byte < BOOT {
            // Part of the read falls in the virtual boot sector.
            let zeros_count =
                (BOOT.min(start_byte.saturating_add(dst.len() as u64)) - start_byte) as usize;
            dst[..zeros_count].fill(0);
            if zeros_count < dst.len() {
                // Rest of the read starts at file offset 0.
                self.file.seek(SeekFrom::Start(0)).map_err(Box::new)?;
                self.file
                    .read_exact(&mut dst[zeros_count..])
                    .map_err(Box::new)?;
            }
        } else {
            // Shift the read back by BOOT bytes.
            let file_offset = start_byte - BOOT;
            self.file
                .seek(SeekFrom::Start(file_offset))
                .map_err(Box::new)?;
            self.file.read_exact(dst).map_err(Box::new)?;
        }
        Ok(())
    }
}

/// Detect whether the file's superblock starts at byte 0 (no boot sector).
/// Returns true when the ext4 magic 0xEF53 is at file offset 56.
fn has_superblock_at_zero(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut header = [0u8; 64];
    f.read_exact(&mut header)?;
    Ok(u16::from_le_bytes([header[0x38], header[0x39]]) == 0xEF53)
}

impl Ext4Fs {
    pub fn open(path: &Path) -> Result<Ext4Fs> {
        // Standard layout: superblock at byte 1024.
        if !has_superblock_at_zero(path).unwrap_or(false) {
            let fs = Ext4::load_from_path(path).map_err(|e| Error::Ext4(e.to_string()))?;
            return Ok(Ext4Fs { fs });
        }

        // Non-standard layout (boot sector omitted): superblock at byte 0.
        // Use a reader that transparently inserts a virtual 1024-byte zero prefix.
        let file = std::fs::File::open(path)?;
        let fs = Ext4::load(Box::new(BootSectorPrependReader { file }))
            .map_err(|e| Error::Ext4(e.to_string()))?;
        Ok(Ext4Fs { fs })
    }

    pub fn read_file(&self, abs: &str) -> Result<Vec<u8>> {
        self.fs.read(abs).map_err(|e| Error::Ext4(e.to_string()))
    }

    pub fn list_dir(&self, abs: &str) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in self
            .fs
            .read_dir(abs)
            .map_err(|e| Error::Ext4(e.to_string()))?
        {
            let entry = entry.map_err(|e| Error::Ext4(e.to_string()))?;
            // file_name() -> DirEntryName; as_str() -> Result<&str, Utf8Error>
            let file_name = entry.file_name();
            let leaf = file_name
                .as_str()
                .map_err(|e| Error::Ext4(e.to_string()))?
                .to_string();
            if leaf != "." && leaf != ".." && !leaf.is_empty() {
                names.push(leaf);
            }
        }
        Ok(names)
    }

    pub fn images_subdir(&self) -> Result<String> {
        for name in self.list_dir("/images")? {
            if name.starts_with("g5400i") {
                return Ok(name);
            }
        }
        Err(Error::NotFound("/images/g5400i-*".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_modem_bin_from_ext4() {
        // Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root); unset/absent → skip.
        let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_GOLDEN_DIR");
            return;
        };
        let gold_ext4 = root.join("g5400i-260317-260429-B-15308590.ext4");
        if !gold_ext4.exists() {
            eprintln!("skip: golden ext4 absent");
            return;
        }
        let fs = Ext4Fs::open(&gold_ext4).unwrap();
        let sub = fs.images_subdir().unwrap();
        assert!(sub.starts_with("g5400i"), "subdir was {}", sub);
        let modem = fs.read_file(&format!("/images/{}/modem.bin", sub)).unwrap();
        assert_eq!(modem.len(), 93_170_136);
        assert_eq!(&modem[0..4], b"TOC\0");
    }
}
