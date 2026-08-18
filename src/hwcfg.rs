//! Summarize `hardware_config.json`: structural stats + per-config RF_CFG sha
//! sets + (with `--rf-dir`) coverage/orphan analysis. hwcfg-only — it never
//! decodes the RF_CFG databases. The legacy "pretty-print" is a no-op (the input
//! is already pretty), so this delivers a summary instead.

use crate::error::{Error, Result};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub stage: i64,
    pub major: i64,
    pub minor: i64,
    pub rf_sub: i64,
    pub rf_sku: i64,
    pub rfid: i64,
    pub hwinfo: i64,
    pub modem_hw: i64,
    pub sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub index: usize,
    pub platform: i64,
    pub product: i64,
    pub entries: Vec<Entry>,
}

pub fn parse(hwcfg: &serde_json::Value) -> Vec<Config> {
    let empty: Vec<serde_json::Value> = Vec::new();
    let mut configs = Vec::new();
    for (index, cfg) in hwcfg["configurations"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .enumerate()
    {
        let platform = cfg["platform"].as_i64().unwrap_or(0);
        let product = cfg["product"].as_i64().unwrap_or(0);
        let mut entries = Vec::new();
        for ct in cfg["config_table"].as_array().unwrap_or(&empty) {
            let g = |k: &str| ct[k].as_i64().unwrap_or(0);
            let sha = ct["config_file"]
                .as_str()
                .unwrap_or("")
                .rsplit_once("RF_CFG_")
                .map(|(_, s)| s.to_string())
                .unwrap_or_default();
            entries.push(Entry {
                stage: g("stage"),
                major: g("major"),
                minor: g("minor"),
                rf_sub: g("rf_sub"),
                rf_sku: g("rf_sku"),
                rfid: g("rfid"),
                hwinfo: g("hwinfo"),
                modem_hw: g("modem_hw"),
                sha,
            });
        }
        configs.push(Config {
            index,
            platform,
            product,
            entries,
        });
    }
    configs
}

pub fn present_shas(rf_dir: &Path) -> Result<BTreeSet<String>> {
    let mut set = BTreeSet::new();
    for entry in std::fs::read_dir(rf_dir)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name.strip_prefix("RF_CFG_") else {
            continue;
        };
        set.insert(rest.strip_suffix(".gz").unwrap_or(rest).to_string());
    }
    Ok(set)
}

#[derive(Debug, Serialize)]
pub struct Coverage {
    pub rf_dir: String,
    pub referenced: usize,
    pub present: usize,
    pub orphans: Vec<String>,
    pub unused: Vec<String>,
}

/// Distinct, non-empty RF_CFG shas referenced across all configs.
fn referenced_shas(configs: &[Config]) -> BTreeSet<String> {
    configs
        .iter()
        .flat_map(|c| c.entries.iter().map(|e| e.sha.clone()))
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn compute_coverage(configs: &[Config], present: &BTreeSet<String>, rf_dir: &str) -> Coverage {
    let referenced = referenced_shas(configs);
    let orphans: Vec<String> = referenced.difference(present).cloned().collect();
    let unused: Vec<String> = present.difference(&referenced).cloned().collect();
    Coverage {
        rf_dir: rf_dir.to_string(),
        referenced: referenced.len(),
        present: present.len(),
        orphans,
        unused,
    }
}

#[derive(Debug, Serialize)]
pub struct ConfigSummary {
    pub index: usize,
    pub platform: i64,
    pub product: i64,
    pub num_entries: usize,
    pub rf_cfg_shas: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub format: &'static str,
    pub input: String,
    pub input_blake3: String,
    pub num_configurations: usize,
    pub num_config_entries: usize,
    pub distinct_platform_product: usize,
    pub distinct_rf_cfg_referenced: usize,
    pub configurations: Vec<ConfigSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
}

pub fn build_summary(
    configs: &[Config],
    input_name: &str,
    input_bytes: &[u8],
    coverage: Option<Coverage>,
) -> Summary {
    let num_config_entries: usize = configs.iter().map(|c| c.entries.len()).sum();
    let distinct_platform_product = configs
        .iter()
        .map(|c| (c.platform, c.product))
        .collect::<BTreeSet<_>>()
        .len();
    let distinct_rf_cfg_referenced = referenced_shas(configs).len();
    let configurations = configs
        .iter()
        .map(|c| {
            let shas: BTreeSet<String> = c
                .entries
                .iter()
                .map(|e| e.sha.clone())
                .filter(|s| !s.is_empty())
                .collect();
            ConfigSummary {
                index: c.index,
                platform: c.platform,
                product: c.product,
                num_entries: c.entries.len(),
                rf_cfg_shas: shas.into_iter().collect(),
            }
        })
        .collect();
    Summary {
        format: "Pixel modem hardware_config summary",
        input: input_name.to_string(),
        input_blake3: crate::manifest::blake3_bytes(input_bytes),
        num_configurations: configs.len(),
        num_config_entries,
        distinct_platform_product,
        distinct_rf_cfg_referenced,
        configurations,
        coverage,
    }
}

/// Summarize `hardware_config.json` into `out/summary.json`. `rf_dir` is the
/// RF directory to compute blob coverage against, as a `(read_path, label)`
/// pair: the label is what `coverage.rf_dir` records. Decompose passes a
/// location-independent label (`"rf_cfg_decompressed"`, relative to its tree
/// root) so its output tree carries no absolute build-machine paths; the
/// standalone subcommand passes the user's path spelling verbatim.
pub fn run(input: &Path, rf_dir: Option<(&Path, &str)>, out: &Path) -> Result<PathBuf> {
    let bytes = std::fs::read(input)?;
    let hwcfg: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| Error::Serialize(e.to_string()))?;
    let configs = parse(&hwcfg);
    let coverage = match rf_dir {
        Some((dir, label)) => {
            let present = present_shas(dir)?;
            Some(compute_coverage(&configs, &present, label))
        }
        None => None,
    };
    std::fs::create_dir_all(out)?;
    let input_name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("hardware_config.json")
        .to_string();
    let summary = build_summary(&configs, &input_name, &bytes, coverage);
    let summary_path = out.join("summary.json");
    std::fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).map_err(|e| Error::Serialize(e.to_string()))?,
    )?;

    println!(
        "hardware_config: {} configurations, {} entries, {} distinct platform/product, {} distinct RF_CFG referenced",
        summary.num_configurations,
        summary.num_config_entries,
        summary.distinct_platform_product,
        summary.distinct_rf_cfg_referenced
    );
    println!(
        "  {:>3}  {:>8}  {:>7}  {:>8}  {:>5}",
        "idx", "platform", "product", "#entries", "#shas"
    );
    for c in &summary.configurations {
        println!(
            "  {:>3}  {:>8}  {:>7}  {:>8}  {:>5}",
            c.index,
            c.platform,
            c.product,
            c.num_entries,
            c.rf_cfg_shas.len()
        );
    }
    if let Some(cov) = &summary.coverage {
        println!(
            "coverage ({}): {} referenced, {} present, {} orphans, {} unused",
            cov.rf_dir,
            cov.referenced,
            cov.present,
            cov.orphans.len(),
            cov.unused.len()
        );
    }
    println!("summary -> {}", summary_path.display());
    Ok(summary_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2 configs that BOTH use (platform 4, product 7) — exercising the repeated
    /// pair — where config 0 has a 3-entry config_table with "aaa" appearing twice
    /// (distinct -> {aaa, bbb}) and config 1 has one entry "ccc".
    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "configurations": [
                { "platform": 4, "product": 7, "config_table": [
                    { "config_file": "/x/RF_CFG_aaa", "stage":1,"major":1,"minor":0,"rf_sub":0,"rf_sku":0,"rfid":0,"hwinfo":0,"modem_hw":0 },
                    { "config_file": "/x/RF_CFG_bbb", "stage":1,"major":1,"minor":0,"rf_sub":1,"rf_sku":0,"rfid":1,"hwinfo":0,"modem_hw":0 },
                    { "config_file": "/x/RF_CFG_aaa", "stage":2,"major":1,"minor":0,"rf_sub":2,"rf_sku":0,"rfid":2,"hwinfo":0,"modem_hw":0 }
                ]},
                { "platform": 4, "product": 7, "config_table": [
                    { "config_file": "/x/RF_CFG_ccc", "stage":1,"major":0,"minor":0,"rf_sub":0,"rf_sku":0,"rfid":0,"hwinfo":0,"modem_hw":0 }
                ]}
            ]
        })
    }

    #[test]
    fn present_shas_strips_prefix_and_gz() {
        let dir = std::env::temp_dir().join("pme_hwcfg_present_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("RF_CFG_aaa"), b"x").unwrap();
        std::fs::write(dir.join("RF_CFG_bbb.gz"), b"x").unwrap();
        std::fs::write(dir.join("not_rf.txt"), b"x").unwrap();
        let set = present_shas(&dir).unwrap();
        assert_eq!(set, BTreeSet::from(["aaa".to_string(), "bbb".to_string()]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_computes_orphans_and_unused() {
        let configs = parse(&fixture()); // referenced shas: aaa, bbb, ccc
        let present = BTreeSet::from(["aaa".to_string(), "ddd".to_string()]);
        let cov = compute_coverage(&configs, &present, "/rf");
        assert_eq!(cov.rf_dir, "/rf");
        assert_eq!(cov.referenced, 3);
        assert_eq!(cov.present, 2);
        assert_eq!(cov.orphans, vec!["bbb".to_string(), "ccc".to_string()]); // referenced - present, sorted
        assert_eq!(cov.unused, vec!["ddd".to_string()]); // present - referenced
    }

    /// The coverage `rf_dir` records the *label* the caller passed, not the
    /// read path — decompose pins its output tree by content and must not
    /// embed the absolute output location.
    #[test]
    fn run_records_coverage_label_verbatim() {
        let base = std::env::temp_dir().join("pme_hwcfg_label_test");
        let _ = std::fs::remove_dir_all(&base);
        let rf = base.join("deep/nested/rf_cfg_decompressed");
        std::fs::create_dir_all(&rf).unwrap();
        std::fs::write(rf.join("RF_CFG_aaa"), b"x").unwrap();
        let hw = base.join("hardware_config.json");
        std::fs::write(&hw, fixture().to_string().as_bytes()).unwrap();
        let out = base.join("summary_out");
        let path = run(&hw, Some((&rf, "rf_cfg_decompressed")), &out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["coverage"]["rf_dir"], "rf_cfg_decompressed");
        assert_eq!(v["coverage"]["present"], 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn build_summary_has_correct_stats() {
        let configs = parse(&fixture());
        let bytes = b"{}";
        let s = build_summary(&configs, "hardware_config.json", bytes, None);
        assert_eq!(s.num_configurations, 2);
        assert_eq!(s.num_config_entries, 4); // 3 + 1
        assert_eq!(s.distinct_platform_product, 1); // both (4,7)
        assert_eq!(s.distinct_rf_cfg_referenced, 3); // aaa, bbb, ccc
        assert_eq!(s.configurations[0].num_entries, 3);
        assert_eq!(
            s.configurations[0].rf_cfg_shas,
            vec!["aaa".to_string(), "bbb".to_string()]
        ); // distinct, sorted
        assert_eq!(s.configurations[1].rf_cfg_shas, vec!["ccc".to_string()]);
        assert_eq!(s.input_blake3.len(), 64);
        assert!(s.coverage.is_none());

        let present = BTreeSet::from(["aaa".to_string()]);
        let s2 = build_summary(
            &configs,
            "hardware_config.json",
            bytes,
            Some(compute_coverage(&configs, &present, "/rf")),
        );
        assert_eq!(
            s2.coverage.as_ref().unwrap().orphans,
            vec!["bbb".to_string(), "ccc".to_string()]
        );
    }

    #[test]
    fn parse_reads_configs_and_entries() {
        let configs = parse(&fixture());
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].index, 0);
        assert_eq!((configs[0].platform, configs[0].product), (4, 7));
        assert_eq!(configs[0].entries.len(), 3);
        assert_eq!(configs[0].entries[0].sha, "aaa");
        assert_eq!(configs[0].entries[1].sha, "bbb");
        assert_eq!(configs[0].entries[1].rfid, 1);
        assert_eq!(configs[0].entries[2].stage, 2);
        // a repeated (platform,product) across configs is preserved, not deduped
        assert_eq!(configs[1].index, 1);
        assert_eq!((configs[1].platform, configs[1].product), (4, 7));
        assert_eq!(configs[1].entries[0].sha, "ccc");
    }
}
