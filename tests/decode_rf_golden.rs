use std::path::{Path, PathBuf};

// Set PME_GOLDEN_DIR to the extracted golden tree (the `modem_extracted` root).
const FW: &str = "PIXELMODEM_rootfs/images/g5400i-260317-260429-B-15308590";
const DETAIL: [&str; 3] = [
    "01894958812b12db474fdd03f0a326a317873a50",
    "4e9beac525041f5a3d24894697e8e1b751a218ef",
    "d46164cea841235b2f96d23216778d258ca108da",
];

fn load(p: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn decode_rf_matches_golden() {
    let Some(root) = std::env::var_os("PME_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("skip: set PME_GOLDEN_DIR");
        return;
    };
    let base = root.join(FW);
    let rf_dir = base.join("RF_CFG_decompressed");
    let hwcfg = base.join("hardware_config.json");
    let gold = base.join("decoded_rf");
    if !rf_dir.exists() || !gold.join("summary.json").exists() {
        eprintln!("skip: golden inputs absent");
        return;
    }
    let out = std::env::temp_dir().join("pme_decode_rf");
    let _ = std::fs::remove_dir_all(&out);
    pixel_modem_extractor::decode_rf::run(&rf_dir, &hwcfg, &out).unwrap();

    // summary.json structural match (objects compare key-order-independent; files arrays both sorted)
    let ours = load(&out.join("summary.json"));
    let gold_summary = load(&gold.join("summary.json"));
    assert_eq!(ours["format"], gold_summary["format"]);
    assert_eq!(ours["files"].as_array().unwrap().len(), 64);
    assert_eq!(ours["files"], gold_summary["files"], "summary files differ");

    // the 3 golden detail files structurally match ours
    for sha in DETAIL {
        let o = load(&out.join(format!("RF_CFG_{sha}.decoded.json")));
        let g = load(&gold.join(format!("RF_CFG_{sha}.decoded.json")));
        assert_eq!(o, g, "detail {sha} differs");
    }
}
