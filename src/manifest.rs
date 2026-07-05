use crate::error::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let result = h.finalize();
    let mut s = String::with_capacity(64);
    for byte in result.iter() {
        use std::fmt::Write;
        write!(s, "{:02x}", byte).unwrap();
    }
    s
}

pub fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_bytes(&std::fs::read(path)?))
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TocImageInfo {
    pub name: String,
    pub index: u32,
    pub offset: u32,
    pub size: u32,
    pub load_addr: u32,
    pub toc_crc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_crc32: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crc_match: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Manifest {
    pub source_image: String,
    pub source_sha256: String,
    pub fbpk_name: String,
    pub tool_version: String,
    pub verified: bool,
    pub toc: Vec<TocImageInfo>,
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn add(&mut self, root: &Path, file: &Path) -> Result<()> {
        let rel = file.strip_prefix(root).unwrap_or(file);
        let meta = std::fs::metadata(file)?;
        self.entries.push(ManifestEntry {
            path: rel.to_string_lossy().replace('\\', "/"),
            size: meta.len(),
            sha256: sha256_file(file)?,
        });
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let mut view = Manifest {
            source_image: self.source_image.clone(),
            source_sha256: self.source_sha256.clone(),
            fbpk_name: self.fbpk_name.clone(),
            tool_version: self.tool_version.clone(),
            verified: self.verified,
            toc: self.toc.clone(),
            entries: self.entries.clone(),
        };
        view.entries.sort_by(|a, b| a.path.cmp(&b.path));
        let json = serde_json::to_string_pretty(&view)
            .map_err(|e| crate::error::Error::Serialize(e.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_writes() {
        let dir = std::env::temp_dir().join("pme_manifest_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.bin"), b"bbb").unwrap();
        std::fs::write(dir.join("a.bin"), b"a").unwrap();
        let mut m = Manifest {
            source_image: "x.img".into(),
            source_sha256: "deadbeef".into(),
            fbpk_name: "g5400i".into(),
            tool_version: "0".into(),
            verified: false,
            toc: vec![],
            entries: vec![],
        };
        m.add(&dir, &dir.join("b.bin")).unwrap();
        m.add(&dir, &dir.join("a.bin")).unwrap();
        let out = dir.join("manifest.json");
        m.write(&out).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["entries"][0]["path"], "a.bin"); // sorted
        assert_eq!(v["entries"][0]["size"], 1);
        assert_eq!(v["entries"].as_array().unwrap().len(), 2);
    }
}
