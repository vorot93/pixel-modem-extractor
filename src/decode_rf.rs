//! Decode the RF_CFG calibration databases (reverse-engineered).
//! Structural + numeric decode (container/framing/cal curves), not field-named.
use crate::error::{Error, Result};
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
};

const HDR: usize = 0x90;

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub version: u32,
    pub variant_rev: u8,
    pub data_offset: u32,
    pub f0x0c: u32,
}

fn parse_header(b: &[u8]) -> Header {
    Header {
        version: rd_u32(b, 0),
        variant_rev: b[4],
        data_offset: rd_u32(b, 8),
        f0x0c: rd_u32(b, 0x0c),
    }
}

fn data_end(b: &[u8]) -> usize {
    let mut e = b.len();
    while e > 0 && b[e - 1] == 0 {
        e -= 1;
    }
    e
}

#[derive(Debug, Serialize)]
pub struct Table {
    pub offset: String,
    pub count: usize,
    pub min: i64,
    pub max: i64,
    pub monotonic: bool,
    pub step_set: Vec<i64>,
    pub values_u16: Vec<serde_json::Value>,
}

fn extract_tables(b: &[u8], start: usize, end: usize) -> Vec<Table> {
    let n = end.saturating_sub(start) / 2; // == (end-start)/2 for real inputs; guards usize underflow if end<=start
    let v = |k: usize| -> u16 { u16::from_le_bytes([b[start + 2 * k], b[start + 2 * k + 1]]) };
    let mut tables = Vec::new();
    let mut i = 0usize;
    while i < n.saturating_sub(6) {
        if !(1..=4095).contains(&v(i)) {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < n
            && (1..=4095).contains(&v(j))
            && (j == i || (v(j) as i64 - v(j - 1) as i64).abs() <= 256)
        {
            j += 1;
        }
        let run = j - i;
        let seg: Vec<i64> = (i..j).map(|k| v(k) as i64).collect();
        let distinct = seg.iter().collect::<HashSet<_>>().len();
        if run >= 6 && distinct >= 3 {
            let d: Vec<i64> = seg.windows(2).map(|w| w[1] - w[0]).collect();
            let mut step_set: Vec<i64> = d
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            step_set.truncate(6);
            let monotonic = d.iter().all(|&x| x <= 0) || d.iter().all(|&x| x >= 0);
            let mut values_u16: Vec<serde_json::Value> =
                seg.iter().take(24).map(|&x| serde_json::json!(x)).collect();
            if run > 24 {
                values_u16.push(serde_json::json!("..."));
            }
            tables.push(Table {
                offset: format!("0x{:x}", start + i * 2),
                count: run,
                min: *seg.iter().min().unwrap(),
                max: *seg.iter().max().unwrap(),
                monotonic,
                step_set,
                values_u16,
            });
            i = j;
        } else {
            i += 1;
        }
    }
    tables
}

fn segment_records(b: &[u8], start: usize, end: usize) -> Vec<(usize, usize)> {
    const ZG: usize = 4;
    let mut recs = Vec::new();
    let mut i = start;
    while i < end {
        if b[i] == 0 {
            i += 1;
            continue;
        }
        let s = i;
        let mut zr = 0usize;
        while i < end && zr < ZG {
            if b[i] == 0 {
                zr += 1;
            } else {
                zr = 0;
            }
            i += 1;
        }
        let e = i - zr;
        recs.push((s, e - s));
    }
    recs
}

#[derive(Debug, Clone, Serialize)]
pub struct Variant {
    pub platform: i64,
    pub product: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rf_sub: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rf_sku: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rfid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwinfo: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modem_hw: Option<i64>,
}

fn build_sha2var(hwcfg: &serde_json::Value) -> HashMap<String, Vec<Variant>> {
    let mut map: HashMap<String, Vec<Variant>> = HashMap::new();
    let empty: Vec<serde_json::Value> = Vec::new();
    for cfg in hwcfg["configurations"].as_array().unwrap_or(&empty) {
        let platform = cfg["platform"].as_i64().unwrap_or(0);
        let product = cfg["product"].as_i64().unwrap_or(0);
        for ct in cfg["config_table"].as_array().unwrap_or(&empty) {
            let cf = ct["config_file"].as_str().unwrap_or("");
            let sha = cf
                .rsplit_once("RF_CFG_")
                .map(|(_, s)| s.to_string())
                .unwrap_or_default();
            let g = |k: &str| ct.get(k).and_then(|x| x.as_i64());
            map.entry(sha).or_default().push(Variant {
                platform,
                product,
                stage: g("stage"),
                major: g("major"),
                minor: g("minor"),
                rf_sub: g("rf_sub"),
                rf_sku: g("rf_sku"),
                rfid: g("rfid"),
                hwinfo: g("hwinfo"),
                modem_hw: g("modem_hw"),
            });
        }
    }
    map
}

#[derive(Debug, Serialize)]
pub struct DecodedFile {
    pub sha1: String,
    pub size: usize,
    pub data_end: String,
    pub header: Header,
    pub variants: Vec<Variant>,
    pub num_records: usize,
    pub num_cal_tables: usize,
    pub cal_table_value_count: usize,
    pub tables: Vec<Table>,
    pub records_offsets: Vec<(String, usize)>,
}

#[derive(Debug, Serialize)]
struct SummaryEntry {
    sha1: String,
    header: Header,
    variants: Vec<Variant>,
    num_records: usize,
    num_cal_tables: usize,
    cal_table_value_count: usize,
    data_end: String,
}

/// Serializable `summary.json` view that *borrows* the entries, so the console
/// report below can still read `summary` after the file is written.
#[derive(Serialize)]
struct Summary<'a> {
    format: &'static str,
    files: &'a [SummaryEntry],
}

/// Group digits into thousands with `,` — mirrors the reference's `{:,}` console
/// formatting. `rchunks` groups from the right — no `% == 0`/`is_multiple_of` check needed.
fn commafy(n: usize) -> String {
    let s = n.to_string();
    let mut groups: Vec<String> = s
        .as_bytes()
        .rchunks(3)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    groups.reverse();
    groups.join(",")
}

fn decode_file(path: &Path, sha2var: &HashMap<String, Vec<Variant>>) -> Result<DecodedFile> {
    let b = std::fs::read(path)?;
    // `parse_header` reads u32 fields at offsets up to 0x0c and `extract_tables`/`segment_records`
    // slice from `HDR` (0x90) onward — a truncated or corrupt RF_CFG (e.g. a 0-byte file from a
    // partial download) would otherwise index out of bounds and abort the whole batch. Fail closed.
    if b.len() < HDR {
        return Err(Error::SizeMismatch {
            name: path.display().to_string(),
            expected: HDR as u64,
            actual: b.len() as u64,
        });
    }
    let de = data_end(&b);
    let header = parse_header(&b);
    let tables = extract_tables(&b, HDR, de);
    let recs = segment_records(&b, HDR, de);
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let sha = fname.replace("RF_CFG_", ""); // mirrors reference `.replace("RF_CFG_","")`; sha1 hex never contains the marker, so == build_sha2var's rsplit key
    let variants = sha2var.get(&sha).cloned().unwrap_or_default();
    let cal_table_value_count = tables.iter().map(|t| t.count).sum();
    Ok(DecodedFile {
        sha1: sha,
        size: b.len(),
        data_end: format!("0x{:x}", de),
        header,
        variants,
        num_records: recs.len(),
        num_cal_tables: tables.len(),
        cal_table_value_count,
        records_offsets: recs
            .iter()
            .map(|&(s, l)| (format!("0x{:x}", s), l))
            .collect(),
        tables,
    })
}

pub fn run(rf_dir: &Path, hwcfg_path: &Path, out: &Path) -> Result<PathBuf> {
    let hwcfg: serde_json::Value = serde_json::from_slice(&std::fs::read(hwcfg_path)?)
        .map_err(|e| Error::Serialize(e.to_string()))?;
    let sha2var = build_sha2var(&hwcfg);
    std::fs::create_dir_all(out)?;

    let mut files: Vec<PathBuf> = std::fs::read_dir(rf_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("RF_CFG_"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    let mut summary: Vec<SummaryEntry> = Vec::new();
    for path in &files {
        let d = decode_file(path, &sha2var)?;
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let detail = out.join(format!("{fname}.decoded.json"));
        std::fs::write(
            &detail,
            serde_json::to_string_pretty(&d).map_err(|e| Error::Serialize(e.to_string()))?,
        )?;
        summary.push(SummaryEntry {
            sha1: d.sha1.clone(),
            header: d.header.clone(),
            variants: d.variants.clone(),
            num_records: d.num_records,
            num_cal_tables: d.num_cal_tables,
            cal_table_value_count: d.cal_table_value_count,
            data_end: d.data_end.clone(),
        });
    }

    let summary_obj = Summary {
        format: "Pixel modem RF_CFG (reverse-engineered)",
        files: &summary, // borrow — `summary` is read again by the report below
    };
    let summary_path = out.join("summary.json");
    std::fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary_obj).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;

    // Console report (totals + first-12 table).
    let total_tables: usize = summary.iter().map(|s| s.num_cal_tables).sum();
    let total_vals: usize = summary.iter().map(|s| s.cal_table_value_count).sum();
    println!("decoded {} RF_CFG files -> {}/", files.len(), out.display());
    println!(
        "total candidate calibration tables extracted: {}  ({} values)\n",
        commafy(total_tables),
        commafy(total_vals)
    );
    println!(
        "{:<14}{:>4}{:>4}{:>7}{:>8}{:>9}  variants(platform/product:sku)",
        "sha1[:12]", "ver", "rev", "#recs", "#calTbl", "#vals"
    );
    for s in summary.iter().take(12) {
        let vs = s
            .variants
            .iter()
            .take(3)
            .map(|v| {
                let sku = v
                    .rf_sku
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "?".to_string());
                format!("{}/{}:{}", v.platform, v.product, sku)
            })
            .collect::<Vec<_>>()
            .join(",");
        let sha12: String = s.sha1.chars().take(12).collect();
        println!(
            "{:<14}{:>4}{:>4}{:>7}{:>8}{:>9}  {}",
            sha12,
            s.header.version,
            s.header.variant_rev,
            s.num_records,
            s.num_cal_tables,
            s.cal_table_value_count,
            vs
        );
    }
    // v1 dumps every file (not the reference's 3 representatives).
    println!(
        "... ({} files; full table dumps for all {} in {}/)",
        files.len(),
        files.len(),
        out.display()
    );
    Ok(summary_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_reads_fields() {
        let mut b = vec![0u8; HDR];
        b[0..4].copy_from_slice(&11u32.to_le_bytes()); // version
        b[4] = 8; // variant_rev
        b[8..12].copy_from_slice(&144u32.to_le_bytes()); // data_offset
        b[0x0c..0x10].copy_from_slice(&20992u32.to_le_bytes()); // f0x0c
        let h = parse_header(&b);
        assert_eq!(h.version, 11);
        assert_eq!(h.variant_rev, 8);
        assert_eq!(h.data_offset, 144);
        assert_eq!(h.f0x0c, 20992);
    }

    #[test]
    fn data_end_trims_trailing_zeros() {
        assert_eq!(data_end(&[1, 2, 3, 0, 0, 0]), 3);
        assert_eq!(data_end(&[0, 0, 0]), 0);
        assert_eq!(data_end(&[9]), 1);
    }

    #[test]
    fn extract_tables_finds_monotonic_run() {
        // 26 values stepping +10 from 100 (monotonic, distinct, run>=6, >24 so "..." appended)
        let mut buf = Vec::new();
        for k in 0..26u16 {
            buf.extend_from_slice(&(100 + k * 10).to_le_bytes());
        }
        let tables = extract_tables(&buf, 0, buf.len());
        assert_eq!(tables.len(), 1);
        let t = &tables[0];
        assert_eq!(t.count, 26);
        assert_eq!(t.min, 100);
        assert_eq!(t.max, 350); // 100 + 25*10
        assert!(t.monotonic);
        assert_eq!(t.step_set, vec![10]);
        assert_eq!(t.values_u16.len(), 25); // first 24 + "..."
        assert_eq!(t.values_u16[0], serde_json::json!(100));
        assert_eq!(t.values_u16[24], serde_json::json!("..."));
        assert_eq!(t.offset, "0x0");
    }

    #[test]
    fn extract_tables_skips_short_run() {
        // 5 values (< 6) => no table
        let mut buf = Vec::new();
        for k in 0..5u16 {
            buf.extend_from_slice(&(100 + k * 10).to_le_bytes());
        }
        assert!(extract_tables(&buf, 0, buf.len()).is_empty());
    }

    #[test]
    fn segment_records_splits_on_zero_gaps() {
        // record A = [1,2,3] then 4 zeros (gap) then record B = [7,8]
        let b = [1u8, 2, 3, 0, 0, 0, 0, 7, 8];
        let recs = segment_records(&b, 0, b.len());
        // A starts at 0, length 3 (the 4 trailing zeros excluded); B starts at 7, length 2
        assert_eq!(recs[0], (0, 3));
        assert_eq!(recs.last().copied().unwrap(), (7, 2));
    }

    #[test]
    fn build_sha2var_maps_sha_to_variants() {
        let hw = serde_json::json!({
            "configurations": [{
                "platform": 7, "product": 4,
                "config_table": [{
                    "config_file": "/mnt/vendor/modem_img/images/default/RF_CFG_deadbeef",
                    "stage": 3, "major": 1, "minor": 1, "rf_sub": 0, "rf_sku": 0,
                    "rfid": 711, "hwinfo": 1057, "modem_hw": 0
                }]
            }]
        });
        let map = build_sha2var(&hw);
        let vs = &map["deadbeef"];
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].platform, 7);
        assert_eq!(vs[0].product, 4);
        assert_eq!(vs[0].rfid, Some(711));
        assert_eq!(vs[0].modem_hw, Some(0));
    }

    #[test]
    fn commafy_groups_thousands() {
        assert_eq!(commafy(0), "0");
        assert_eq!(commafy(42), "42");
        assert_eq!(commafy(1234), "1,234");
        assert_eq!(commafy(1234567), "1,234,567");
    }

    #[test]
    fn decode_file_rejects_truncated_input() {
        // A sub-header file used to index OOB in `rd_u32` (offset 0x0c) and panic.
        // Now it must fail closed with SizeMismatch instead.
        let dir = std::env::temp_dir().join(format!("pme_decode_rf_short_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("RF_CFG_deadbeef");
        std::fs::write(&path, b"\x00\x00\x00").unwrap();
        let err = decode_file(&path, &HashMap::new());
        assert!(
            matches!(err, Err(Error::SizeMismatch { .. })),
            "expected SizeMismatch, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
