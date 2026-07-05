use crate::error::{Error, Result};
use std::{io::Cursor, path::Path};

/// Extract the first non-empty regular-file member from `tar_bytes` to `out_path`,
/// returning the member's name. Zero-byte entries are skipped.
pub fn extract_single_member_to(tar_bytes: &[u8], out_path: &Path) -> Result<String> {
    let mut ar = tar::Archive::new(Cursor::new(tar_bytes));
    for entry in ar.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_file() && entry.size() > 0 {
            let name = entry.path()?.to_string_lossy().into_owned();
            let mut out = std::fs::File::create(out_path)?;
            std::io::copy(&mut entry, &mut out)?;
            return Ok(name);
        }
    }
    Err(Error::UnexpectedPayload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tar(name: &str, body: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path(name).unwrap();
        h.set_size(body.len() as u64);
        h.set_cksum();
        b.append(&h, body).unwrap();
        b.into_inner().unwrap()
    }

    #[test]
    fn extracts_single_member() {
        let tar = make_tar("the-ext4", b"hello ext4 bytes");
        let dir = std::env::temp_dir().join("pme_tar_test");
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.bin");
        let name = extract_single_member_to(&tar, &out).unwrap();
        assert_eq!(name, "the-ext4");
        assert_eq!(std::fs::read(&out).unwrap(), b"hello ext4 bytes");
    }

    #[test]
    fn skips_leading_empty_member() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h0 = tar::Header::new_ustar();
        h0.set_path("dummy").unwrap();
        h0.set_size(0);
        h0.set_cksum();
        b.append(&h0, std::io::empty()).unwrap();
        let body = b"the real ext4 bytes";
        let mut h1 = tar::Header::new_ustar();
        h1.set_path("real.ext4").unwrap();
        h1.set_size(body.len() as u64);
        h1.set_cksum();
        b.append(&h1, &body[..]).unwrap();
        let tar = b.into_inner().unwrap();
        let dir = std::env::temp_dir().join("pme_tar_skip_empty");
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.bin");
        let name = extract_single_member_to(&tar, &out).unwrap();
        assert_eq!(name, "real.ext4");
        assert_eq!(std::fs::read(&out).unwrap(), body);
    }
}
