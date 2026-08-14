use crate::error::{Error, Result};

const FBPK_MAGIC: u32 = 0x4b50_4246; // "FBPK" little-endian
const HEADER_SIZE: usize = 0x54;
const PART_ENTRY_SIZE: usize = 0x38;

#[derive(Debug, Clone)]
pub struct Partition {
    pub label: String,
    pub data_offset: u64,
    pub size: u64,
    pub checksum: u32,
}

#[derive(Debug, Clone)]
pub struct Fbpk {
    pub name: String,
    pub partitions: Vec<Partition>,
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn rd_cstr(b: &[u8], off: usize, len: usize) -> String {
    let slice = &b[off..off + len];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(len);
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

impl Fbpk {
    pub fn parse(data: &[u8]) -> Result<Fbpk> {
        if data.len() < HEADER_SIZE || rd_u32(data, 0) != FBPK_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = rd_u32(data, 4);
        if version != 1 {
            return Err(Error::UnsupportedVersion(version));
        }
        let name = rd_cstr(data, 8, 0x4c - 8);
        let num_parts = rd_u32(data, 0x4c) as usize;
        let mut partitions = Vec::new();
        let mut pos = HEADER_SIZE;
        for _ in 0..num_parts {
            if pos + PART_ENTRY_SIZE > data.len() {
                return Err(Error::UnexpectedPayload);
            }
            let label = rd_cstr(data, pos + 4, 32);
            let payload_size = rd_u32(data, pos + 0x28) as u64;
            let next = rd_u32(data, pos + 0x30) as u64;
            let checksum = rd_u32(data, pos + 0x34);
            partitions.push(Partition {
                label,
                data_offset: (pos + PART_ENTRY_SIZE) as u64,
                size: payload_size,
                checksum,
            });
            // treat next == 0 (or out-of-range or non-advancing) as end-of-list sentinel
            if next == 0 || next as usize >= data.len() || next as usize <= pos {
                break;
            }
            pos = next as usize;
        }
        Ok(Fbpk { name, partitions })
    }

    pub fn partition(&self, label: &str) -> Option<&Partition> {
        self.partitions.iter().find(|p| p.label == label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_image() {
        // Set PME_RADIO_IMG to the radio FBPK `.img`; unset/absent → skip.
        let Some(img) = std::env::var_os("PME_RADIO_IMG").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_RADIO_IMG");
            return;
        };
        if !img.exists() {
            eprintln!("skip: PME_RADIO_IMG not found");
            return;
        }
        let data = std::fs::read(&img).unwrap();
        let fb = Fbpk::parse(&data).unwrap();
        assert!(
            crate::model::firmware_prefix(&fb.name).is_some(),
            "name was {}",
            fb.name
        );
        let modem = fb.partition("modem").expect("modem partition");
        assert_eq!(modem.data_offset, 0x8C);
        assert!(modem.size > 0, "modem.size was {}", modem.size);
    }

    #[test]
    fn rejects_bad_magic() {
        let bad = vec![0u8; 0x54];
        assert!(matches!(
            Fbpk::parse(&bad),
            Err(crate::error::Error::BadMagic)
        ));
    }
}
