use crate::error::{Error, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

pub fn blake3_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Stream a reader into a blake3 hex digest. Handles short reads (any
/// `read` returning 0..=buf.len()) without requiring a full-buffer fill.
fn blake3_reader(mut reader: impl Read) -> Result<String> {
    let mut h = Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}

pub fn blake3_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)?;
    blake3_reader(file)
}

/// Best-effort read of `fbpk_name` from a written `manifest.json`.
/// `None` if the file is absent/unreadable or lacks the field.
pub fn read_fbpk_name(manifest_path: &Path) -> Option<String> {
    let bytes = std::fs::read(manifest_path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("fbpk_name")?.as_str().map(|s| s.to_owned())
}

/// TOC image name for a decompose label, e.g. `"02_MAIN"` → `"MAIN"`.
pub(crate) fn toc_name(image_label: &str) -> &str {
    image_label
        .split_once('_')
        .map(|(_, name)| name)
        .unwrap_or(image_label)
}

/// Minimal deserialize view of the extract/decompose manifest — only the
/// fields needed for load-address lookup. Missing-manifest is `Ok(None)`;
/// parse failures are `Error::Serialize`.
#[derive(Deserialize)]
struct ExtractManifest {
    #[serde(default)]
    toc: Vec<ManifestTocEntry>,
}

#[derive(Deserialize)]
struct ManifestTocEntry {
    name: String,
    load_addr: u64,
}

/// Resolve `toc[].load_addr` for a decompose image label (e.g. `"02_MAIN"`).
/// Returns `Ok(None)` when the manifest file is absent or has no matching
/// `toc[].name` entry (after `toc_name` mapping).
pub(crate) fn load_addr_for_image(manifest_path: &Path, image_label: &str) -> Result<Option<u64>> {
    if !manifest_path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(manifest_path)?;
    let m: ExtractManifest =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let name = toc_name(image_label);
    Ok(m.toc
        .into_iter()
        .find(|t| t.name == name)
        .map(|t| t.load_addr))
}

#[derive(Debug, Clone, Serialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub blake3: String,
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
    pub source_blake3: String,
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
            blake3: blake3_file(file)?,
        });
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let mut view = Manifest {
            source_image: self.source_image.clone(),
            source_blake3: self.source_blake3.clone(),
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
    use crate::error::Error;
    use std::io::Read;

    #[test]
    fn records_and_writes() {
        let dir = std::env::temp_dir().join("pme_manifest_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.bin"), b"bbb").unwrap();
        std::fs::write(dir.join("a.bin"), b"a").unwrap();
        let mut m = Manifest {
            source_image: "x.img".into(),
            source_blake3: "deadbeef".into(),
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
        assert_eq!(v["source_blake3"], "deadbeef");
        assert_eq!(v["entries"][0]["path"], "a.bin"); // sorted
        assert_eq!(v["entries"][0]["size"], 1);
        assert_eq!(v["entries"][0]["blake3"], blake3_bytes(b"a"));
        assert_eq!(v["entries"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn reads_fbpk_name_from_manifest_json() {
        let tmp = std::env::temp_dir().join("pme_manifest_read.json");
        std::fs::write(
            &tmp,
            br#"{"fbpk_name":"g5300q-260317-260505-M-15346003","tool_version":"x"}"#,
        )
        .unwrap();
        assert_eq!(
            read_fbpk_name(&tmp).as_deref(),
            Some("g5300q-260317-260505-M-15346003")
        );
        let missing = std::env::temp_dir().join("pme_manifest_absent.json");
        let _ = std::fs::remove_file(&missing);
        assert_eq!(read_fbpk_name(&missing), None);
    }

    #[test]
    fn load_addr_for_image_maps_decompose_label_to_toc_name() {
        let dir = std::env::temp_dir().join("pme_manifest_load_addr_map");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"toc":[{"name":"MAIN","load_addr":1073807360}]}"#,
        )
        .unwrap();
        let addr = load_addr_for_image(&manifest, "02_MAIN").unwrap();
        assert_eq!(addr, Some(1073807360));
        assert_eq!(toc_name("02_MAIN"), "MAIN");
        assert_eq!(toc_name("MAIN"), "MAIN");
    }

    #[test]
    fn load_addr_for_image_returns_none_for_missing_manifest_or_toc_entry() {
        let dir = std::env::temp_dir().join("pme_manifest_load_addr_none");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("does-not-exist.json");
        assert_eq!(load_addr_for_image(&missing, "02_MAIN").unwrap(), None);

        let manifest = dir.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":[{"name":"APM","load_addr":4096}]}"#).unwrap();
        assert_eq!(load_addr_for_image(&manifest, "02_MAIN").unwrap(), None);
    }

    #[test]
    fn load_addr_for_image_rejects_malformed_manifest() {
        let dir = std::env::temp_dir().join("pme_manifest_load_addr_bad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = dir.join("manifest.json");
        std::fs::write(&manifest, r#"{"toc":"not-an-array"}"#).unwrap();
        let err = load_addr_for_image(&manifest, "02_MAIN").unwrap_err();
        assert!(matches!(err, Error::Serialize(_)));
    }

    /// In-memory `Read` that returns 1–3 bytes per call so hashing cannot
    /// assume a single full read fills the buffer.
    struct ShortRead<'a> {
        data: &'a [u8],
        pos: usize,
        next_n: usize,
    }

    impl Read for ShortRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            let n = self
                .next_n
                .clamp(1, 3)
                .min(buf.len())
                .min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            self.next_n = if self.next_n >= 3 { 1 } else { self.next_n + 1 };
            Ok(n)
        }
    }

    #[test]
    fn blake3_bytes_pins_empty_input_vector_and_lowercase_hex() {
        let h = blake3_bytes(b"");
        assert_eq!(
            h,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(h.len(), 64);
        assert!(
            h.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn blake3_file_matches_blake3_bytes_via_streaming() {
        let dir = std::env::temp_dir().join(format!("pme_blake3_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("input.bin");
        let payload = vec![0xA5u8; 200_000]; // > one 64 KiB buffer to exercise short-read streaming
        std::fs::write(&path, &payload).unwrap();
        assert_eq!(blake3_file(&path).unwrap(), blake3_bytes(&payload));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hash_reader_handles_short_reads_across_chunk_boundaries() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(10_000).collect();
        let expected = blake3_bytes(&payload);
        let short = ShortRead {
            data: &payload,
            pos: 0,
            next_n: 1,
        };
        let got = blake3_reader(short).unwrap();
        assert_eq!(got, expected);
    }
}
