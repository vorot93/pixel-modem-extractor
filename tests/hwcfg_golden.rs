use std::path::PathBuf;

// Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root).
const FW: &str = "PIXELMODEM_rootfs/images/g5400i-260317-260429-B-15308590";

#[test]
fn hwcfg_matches_golden() {
    let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let base = root.join(FW);
    let hw = base.join("hardware_config.json");
    let rf_dir = base.join("RF_CFG_decompressed");
    if !hw.exists() || !rf_dir.exists() {
        eprintln!("skip: golden hardware_config inputs absent");
        return;
    }
    let bytes = std::fs::read(&hw).unwrap();
    let hwcfg: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let configs = pixel_modem_extractor::hwcfg::parse(&hwcfg);
    assert_eq!(configs.len(), 20, "num_configurations");
    let total: usize = configs.iter().map(|c| c.entries.len()).sum();
    assert_eq!(total, 298, "num_config_entries");

    let present = pixel_modem_extractor::hwcfg::present_shas(&rf_dir).unwrap();
    assert_eq!(present.len(), 64, "present");
    let cov = pixel_modem_extractor::hwcfg::compute_coverage(
        &configs,
        &present,
        rf_dir.to_str().unwrap(),
    );
    assert_eq!(cov.referenced, 93, "referenced");
    assert_eq!(cov.orphans.len(), 29, "orphans");
    assert!(cov.unused.is_empty(), "unused");

    // run() writes summary.json with matching stats
    let out = std::env::temp_dir().join(format!("pme_hwcfg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    pixel_modem_extractor::hwcfg::run(&hw, Some(rf_dir.as_path()), &out).unwrap();
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("summary.json")).unwrap()).unwrap();
    assert_eq!(summary["num_configurations"], 20);
    assert_eq!(summary["num_config_entries"], 298);
    assert_eq!(summary["distinct_platform_product"], 17);
    assert_eq!(summary["distinct_rf_cfg_referenced"], 93);
    assert_eq!(summary["coverage"]["orphans"].as_array().unwrap().len(), 29);
}
