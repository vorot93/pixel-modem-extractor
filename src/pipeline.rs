use crate::{
    classify::classify,
    error::Result,
    ext4::Ext4Fs,
    fbpk::Fbpk,
    gzip,
    manifest::{BatteryInfo, Manifest, TocImageInfo, blake3_bytes},
    toc::Toc,
};
use std::path::{Path, PathBuf};

pub fn extract(img_path: &Path, out_dir: &Path, verify: bool) -> Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let img = std::fs::read(img_path)?;

    // Stage 1: FBPK -> modem partition payload (the tar)
    let fb = Fbpk::parse(&img)?;
    let modem = fb
        .partition("modem")
        .ok_or_else(|| crate::error::Error::NotFound("modem".into()))?;
    let start = modem.data_offset as usize;
    let end = modem
        .data_offset
        .checked_add(modem.size)
        .filter(|&e| (e as usize) <= img.len())
        .ok_or(crate::error::Error::UnexpectedPayload)? as usize;
    let payload = &img[start..end];

    // Stage 2: untar -> ext4 image on disk
    // The modem tar has a 0-byte dummy entry first; archive::extract_single_member_to skips empties.
    let ext4_path = out_dir.join("modem.ext4");
    crate::archive::extract_single_member_to(payload, &ext4_path)?;

    // Stage 3: read ext4 -> rootfs files
    let fs = Ext4Fs::open(&ext4_path)?;
    let sub = fs.images_subdir()?;
    let rootfs = out_dir.join("rootfs").join("images").join(&sub);
    std::fs::create_dir_all(&rootfs)?;
    let modem_bytes = fs.read_file(&format!("/images/{sub}/modem.bin"))?;
    std::fs::write(rootfs.join("modem.bin"), &modem_bytes)?;
    for f in ["hardware_config.json", "pw_token_db"] {
        if let Ok(bytes) = fs.read_file(&format!("/images/{sub}/{f}")) {
            std::fs::write(rootfs.join(f), bytes)?;
        }
    }
    // RF_CFG_*.gz
    let mut rf_gz = Vec::new();
    for name in fs.list_dir(&format!("/images/{sub}"))? {
        if name.starts_with("RF_CFG_") && name.ends_with(".gz") {
            let bytes = fs.read_file(&format!("/images/{sub}/{name}"))?;
            std::fs::write(rootfs.join(&name), &bytes)?;
            rf_gz.push((name, bytes));
        }
    }

    // Stage 4: gunzip RF_CFG_*
    let rf_out = out_dir.join("rf_cfg_decompressed");
    std::fs::create_dir_all(&rf_out)?;
    for (name, bytes) in &rf_gz {
        let plain = gzip::gunzip(bytes)?;
        let stem = name.strip_suffix(".gz").unwrap_or(name);
        std::fs::write(rf_out.join(stem), plain)?;
    }

    // Stage 5: TOC split modem.bin
    let modem_bin = std::fs::read(rootfs.join("modem.bin"))?;
    let toc = Toc::parse(&modem_bin)?;
    let split_dir = out_dir.join("modem.bin.split");
    toc.split_to_dir(&modem_bin, &split_dir, verify)?;

    // Manifest
    let toc_images: Vec<TocImageInfo> = toc
        .embedded()
        .iter()
        .map(|e| {
            let s = e.offset as usize;
            let en = s + e.size as usize;
            let in_range = en <= modem_bin.len();
            let (computed_crc32, crc_match) = if verify && in_range {
                let c = crc32fast::hash(&modem_bin[s..en]);
                (Some(c), Some(c == e.crc))
            } else {
                (None, None)
            };
            // The battery is a record, not a check: computed for every embedded
            // image regardless of `verify` (`verified` semantics untouched).
            let battery = if in_range {
                Some(BatteryInfo::from_stats(&classify(&modem_bin[s..en])))
            } else {
                None
            };
            TocImageInfo {
                name: e.name.clone(),
                index: e.index,
                offset: e.offset,
                size: e.size,
                load_addr: e.load_addr,
                toc_crc: e.crc,
                computed_crc32,
                crc_match,
                battery,
            }
        })
        .collect();
    let mut m = Manifest {
        source_image: img_path.display().to_string(),
        source_blake3: blake3_bytes(&img),
        fbpk_name: fb.name.clone(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        verified: verify,
        toc: toc_images,
        entries: vec![],
    };
    for entry in walk_files(out_dir)? {
        if entry
            .file_name()
            .map(|n| n == "manifest.json")
            .unwrap_or(false)
        {
            continue;
        }
        m.add(out_dir, &entry)?;
    }
    let manifest_path = out_dir.join("manifest.json");
    m.write(&manifest_path)?;
    Ok(manifest_path)
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let e = e?;
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_produces_split_images() {
        // Set PME_RADIO_IMG to the radio FBPK `.img`; unset/absent → skip.
        let Some(img) = std::env::var_os("PME_RADIO_IMG").map(std::path::PathBuf::from) else {
            eprintln!("skip: set PME_RADIO_IMG");
            return;
        };
        if !img.exists() {
            eprintln!("skip: PME_RADIO_IMG not found");
            return;
        }
        let out = std::env::temp_dir().join("pme_pipeline_test");
        let _ = std::fs::remove_dir_all(&out);
        let manifest = extract(&img, &out, true).unwrap();
        assert!(manifest.exists());
        let split = out.join("modem.bin.split");
        let has_main = std::fs::read_dir(&split)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.ends_with("_MAIN"))
                    .unwrap_or(false)
            });
        assert!(has_main, "no *_MAIN split image found");
        assert!(out.join("modem.ext4").exists());
    }
}
