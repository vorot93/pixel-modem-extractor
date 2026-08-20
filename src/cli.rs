use crate::pipeline;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "pixel-modem-extractor",
    about = "Extract Pixel modem artifacts from a radio FBPK .img"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Full pipeline: .img -> ext4 -> rootfs -> rf decompress -> TOC split
    Extract {
        img: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        no_verify: bool,
    },
    /// Stage 1-2: .img -> modem.ext4
    UnpackFbpk {
        img: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Stage 5: modem.bin -> split images
    SplitToc {
        modem_bin: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Reconstruct the 02_MAIN source tree from embedded __FILE__ strings
    SourceTree {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        no_attribution: bool,
        #[arg(long, default_value_t = 4)]
        gap: usize,
        #[arg(long, default_value_t = 0.05)]
        shared_pct: f64,
        #[arg(long, default_value_t = 3)]
        min_run: usize,
        #[arg(long)]
        modem: Option<String>,
    },
    /// Decode the RF_CFG calibration databases (structural + numeric)
    DecodeRf {
        rf_dir: PathBuf,
        #[arg(long)]
        hwcfg: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Decode the pw_token_db Pigweed token database (TOKENS) -> CSV + summary
    DecodeTokens {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Summarize hardware_config.json (structural stats + RF_CFG coverage)
    HardwareConfig {
        input: PathBuf,
        #[arg(long)]
        rf_dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Decompile modem TOC images; --run drives Ghidra headless and radare2 for dense Thumb regions
    Decompile {
        modem_bin: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        run: bool,
        #[arg(long)]
        ghidra_home: Option<PathBuf>,
        #[arg(long, default_value = "ARM:LE:32:v7")]
        processor: String,
        /// Skip Phase-2 Thumb decompilation: dense Thumb regions stay marked as data
        /// (today's Phase-1 behavior). `thumb_functions.json` is emitted at v2
        /// asm-only (no `body_c`). Use when the tightened TameAnalysis regresses on
        /// your firmware version.
        #[arg(long)]
        no_thumb_decompile: bool,
        /// Enable failure-only Rizin fallback for dense Thumb regions. radare2
        /// remains the primary backend; Rizin runs only after a radare2 attempt
        /// fails.
        #[arg(long, requires = "run")]
        rizin_fallback: bool,
        /// Test-only override: supply an absolute wall-clock budget (seconds) for the
        /// tighten-watch kill decision, bypassing the default `baseline * multiplier`
        /// heuristic. Hidden from `--help` — production users should reach for
        /// `--no-thumb-decompile` instead.
        #[arg(long, hide = true)]
        tighten_wall_clock_budget_sec: Option<u64>,
        /// Run Ghidra + radare2 even for unanimously-opaque images (the statistical
        /// battery that e.g. Pixel `01_PSP` fails on every test). Research escape
        /// hatch; by default such images are skipped — nothing is recoverable from
        /// them under the standard import.
        #[arg(long)]
        no_skip_opaque: bool,
    },
    /// Exhaustive pipeline: extract, Ghidra/radare2 decompile, recovered attribution, and decoders
    Decompose {
        img: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        no_verify: bool,
        #[arg(long)]
        prune: bool,
        /// Skip the symbolication pass 2 (Phase 1). Today's single-pass decompile behavior.
        #[arg(long)]
        no_symbol_pass: bool,
        #[arg(long)]
        ghidra_home: Option<PathBuf>,
        #[arg(long, default_value = "ARM:LE:32:v7")]
        processor: String,
        /// Skip Phase-2 Thumb decompilation: dense Thumb regions stay marked as data
        /// (today's Phase-1 behavior). `thumb_functions.json` is emitted at v2
        /// asm-only (no `body_c`).
        #[arg(long)]
        no_thumb_decompile: bool,
        /// Enable failure-only Rizin fallback for dense Thumb regions. radare2
        /// remains the primary backend; Rizin runs only after a radare2 attempt
        /// fails.
        #[arg(long)]
        rizin_fallback: bool,
        /// Test-only override: supply an absolute wall-clock budget (seconds) for the
        /// tighten-watch kill decision, bypassing the default `baseline * multiplier`
        /// heuristic. Hidden from `--help` — production users should reach for
        /// `--no-thumb-decompile` instead.
        #[arg(long, hide = true)]
        tighten_wall_clock_budget_sec: Option<u64>,
        /// Phase 3.0.1: emit tier:"provisional" globals (name-prior tiebreakers).
        /// Off by default. Recovered-tier globals always emitted.
        #[arg(long)]
        globals_provisional: bool,
        /// Phase 3.0.1 test-only: override K (proximity window) for ARM.
        /// Hidden from `--help`.
        #[arg(long, hide = true)]
        globals_k_arm: Option<usize>,
        /// Phase 3.0.1 test-only: override K (proximity window) for Thumb.
        /// Hidden from `--help`.
        #[arg(long, hide = true)]
        globals_k_thumb: Option<usize>,
        /// Do not apply recovered global shapes as undefinedN types to decompiled.c.
        #[arg(long)]
        no_apply_global_types: bool,
        /// Run Ghidra + radare2 even for unanimously-opaque images (the statistical
        /// battery that e.g. Pixel `01_PSP` fails on every test). Research escape
        /// hatch; by default such images are skipped — nothing is recoverable from
        /// them under the standard import.
        #[arg(long)]
        no_skip_opaque: bool,
    },
    /// Symbolicate a decompose output tree: recover names + log annotations in place, emit symbols.json
    Symbolicate {
        path: PathBuf,
        #[arg(long)]
        token_db: Option<PathBuf>,
    },
    /// Print the whole-tree pme-paq-v1 hash of <dir> (one 64-hex value); writes nothing
    TreeHash { dir: PathBuf },
}

fn default_out(img: &Path) -> PathBuf {
    let stem = img
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".into());
    PathBuf::from(format!("./{stem}.extracted"))
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Extract {
            img,
            out,
            no_verify,
        } => {
            let out = out.unwrap_or_else(|| default_out(&img));
            let manifest = pipeline::extract(&img, &out, !no_verify)?;
            println!("extracted -> {}", out.display());
            println!("manifest  -> {}", manifest.display());
        }
        Commands::UnpackFbpk { img, out } => {
            let out = out.unwrap_or_else(|| default_out(&img));
            // v1: no partial-pipeline API yet — runs the full pipeline and reports the ext4 path
            let _ = pipeline::extract(&img, &out, false)?;
            println!("ext4 -> {}", out.join("modem.ext4").display());
        }
        Commands::SplitToc { modem_bin, out } => {
            let out = out.unwrap_or_else(|| default_out(&modem_bin));
            let data = std::fs::read(&modem_bin)?;
            let toc = crate::toc::Toc::parse(&data)?;
            toc.split_to_dir(&data, &out.join("modem.bin.split"), true)?;
            println!("split -> {}", out.join("modem.bin.split").display());
        }
        Commands::SourceTree {
            input,
            out,
            no_attribution,
            gap,
            shared_pct,
            min_run,
            modem,
        } => {
            let out = out.unwrap_or_else(|| {
                let stem = input
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "out".into());
                PathBuf::from(format!("./{stem}.source_tree"))
            });
            let opts = crate::source_tree::Opts {
                no_attribution,
                gap,
                shared_pct,
                min_run,
                modem_label: modem,
            };
            let manifest = crate::source_tree::run(&input, &out, &opts)?;
            println!("source tree -> {}", out.display());
            println!("manifest    -> {}", manifest.display());
        }
        Commands::DecodeRf { rf_dir, hwcfg, out } => {
            let out = out.unwrap_or_else(|| PathBuf::from("./decoded_rf"));
            crate::decode_rf::run(&rf_dir, &hwcfg, &out)?; // run() prints the console report
        }
        Commands::DecodeTokens { input, out } => {
            let out = out.unwrap_or_else(|| PathBuf::from("./decoded_tokens"));
            crate::tokens::run(&input, &out)?; // run() prints the console report
        }
        Commands::HardwareConfig { input, rf_dir, out } => {
            let out = out.unwrap_or_else(|| PathBuf::from("./hwcfg_summary"));
            // Standalone: record the user's path spelling verbatim as coverage provenance.
            let summary = if let Some(rf_path) = rf_dir.as_deref() {
                let label = rf_path.display().to_string();
                crate::hwcfg::run(&input, Some((rf_path, &label)), &out)
            } else {
                crate::hwcfg::run(&input, None, &out)
            };
            summary?; // run() prints the console report
        }
        Commands::Decompile {
            modem_bin,
            out,
            image,
            run,
            ghidra_home,
            processor,
            no_thumb_decompile,
            rizin_fallback,
            tighten_wall_clock_budget_sec,
            no_skip_opaque,
        } => {
            let out = out.unwrap_or_else(|| {
                let stem = modem_bin
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "modem".into());
                PathBuf::from(format!("./{stem}.decompiled"))
            });
            let opts = crate::decompile::Opts {
                run,
                image,
                ghidra_home,
                processor,
                no_thumb_decompile,
                rizin_fallback,
                tighten_wall_clock_budget_override: tighten_wall_clock_budget_sec
                    .map(std::time::Duration::from_secs),
                no_skip_opaque,
            };
            crate::decompile::run(&modem_bin, &opts, &out)?; // run() prints the console report
        }
        Commands::Decompose {
            img,
            out,
            no_verify,
            prune,
            no_symbol_pass,
            ghidra_home,
            processor,
            no_thumb_decompile,
            rizin_fallback,
            tighten_wall_clock_budget_sec,
            globals_provisional,
            globals_k_arm,
            globals_k_thumb,
            no_apply_global_types,
            no_skip_opaque,
        } => {
            let out = out.unwrap_or_else(|| {
                let stem = img
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "out".into());
                PathBuf::from(format!("./{stem}.decomposed"))
            });
            let opts = crate::decompose::Opts {
                no_verify,
                prune,
                ghidra_home,
                processor,
                no_symbol_pass,
                no_thumb_decompile,
                rizin_fallback,
                tighten_wall_clock_budget_override: tighten_wall_clock_budget_sec
                    .map(std::time::Duration::from_secs),
                globals_provisional,
                globals_k_arm,
                globals_k_thumb,
                no_apply_global_types,
                no_skip_opaque,
            };
            let report = crate::decompose::run(&img, &opts, &out)?;
            println!("decomposed -> {}", out.display());
            println!("report     -> {}", report.display());
        }
        Commands::Symbolicate { path, token_db } => {
            let opts = crate::symbolicate::Opts {
                token_db,
                rewrite_decompiled_c: true,
            };
            let root = crate::symbolicate::run(&path, &opts)?;
            println!("symbolicated -> {}", root.display());
        }
        Commands::TreeHash { dir } => {
            let hash = crate::tree_hash::pme_paq_v1(&dir)?;
            println!("{hash}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_extract() {
        let cli = Cli::try_parse_from(["pme", "extract", "/tmp/x.img", "--out", "/tmp/o"]).unwrap();
        match cli.command {
            Commands::Extract {
                img,
                out,
                no_verify,
            } => {
                assert_eq!(img, PathBuf::from("/tmp/x.img"));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
                assert!(!no_verify);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parses_decode_tokens() {
        let cli = Cli::try_parse_from([
            "pme",
            "decode-tokens",
            "/tmp/pw_token_db",
            "--out",
            "/tmp/o",
        ])
        .unwrap();
        match cli.command {
            Commands::DecodeTokens { input, out } => {
                assert_eq!(input, PathBuf::from("/tmp/pw_token_db"));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parses_decompile() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompile",
            "/tmp/modem.bin",
            "--out",
            "/tmp/o",
            "--image",
            "05_DBGCORE",
            "--run",
            "--ghidra-home",
            "/opt/ghidra",
            "--processor",
            "ARM:LE:32:v8",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompile {
                modem_bin,
                out,
                image,
                run,
                ghidra_home,
                processor,
                ..
            } => {
                assert_eq!(modem_bin, PathBuf::from("/tmp/modem.bin"));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
                assert_eq!(image, Some("05_DBGCORE".to_string()));
                assert!(run);
                assert_eq!(ghidra_home, Some(PathBuf::from("/opt/ghidra")));
                assert_eq!(processor, "ARM:LE:32:v8");
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompile_rizin_fallback_requires_run() {
        assert!(
            Cli::try_parse_from([
                "pixel-modem-extractor",
                "decompile",
                "modem.bin",
                "--rizin-fallback",
            ])
            .is_err()
        );

        let cli = Cli::try_parse_from([
            "pixel-modem-extractor",
            "decompile",
            "modem.bin",
            "--run",
            "--rizin-fallback",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Decompile {
                rizin_fallback: true,
                ..
            }
        ));
    }

    #[test]
    fn decompose_accepts_rizin_fallback() {
        let default =
            Cli::try_parse_from(["pixel-modem-extractor", "decompose", "radio.img"]).unwrap();
        assert!(matches!(
            default.command,
            Commands::Decompose {
                rizin_fallback: false,
                ..
            }
        ));

        let enabled = Cli::try_parse_from([
            "pixel-modem-extractor",
            "decompose",
            "radio.img",
            "--rizin-fallback",
        ])
        .unwrap();
        assert!(matches!(
            enabled.command,
            Commands::Decompose {
                rizin_fallback: true,
                ..
            }
        ));
    }

    #[test]
    fn decompile_help_mentions_radare2_thumb_regions() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompile")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("radare2"), "help:\n{help}");
        assert!(help.contains("Thumb"), "help:\n{help}");
        assert!(
            help.contains("radare2 remains the primary"),
            "help:\n{help}"
        );
        assert!(
            help.contains("Rizin runs only after a radare2 attempt fails"),
            "help:\n{help}"
        );
    }

    #[test]
    fn decompose_help_mentions_recovered_attribution_and_tool_requirements() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompose")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("recovered"), "help:\n{help}");
        assert!(help.contains("Ghidra"), "help:\n{help}");
        assert!(help.contains("radare2"), "help:\n{help}");
        assert!(
            help.contains("radare2 remains the primary"),
            "help:\n{help}"
        );
        assert!(
            help.contains("Rizin runs only after a radare2 attempt fails"),
            "help:\n{help}"
        );
    }

    #[test]
    fn parses_hardware_config() {
        let cli = Cli::try_parse_from([
            "pme",
            "hardware-config",
            "/tmp/hardware_config.json",
            "--rf-dir",
            "/tmp/rf",
            "--out",
            "/tmp/o",
        ])
        .unwrap();
        match cli.command {
            Commands::HardwareConfig { input, rf_dir, out } => {
                assert_eq!(input, PathBuf::from("/tmp/hardware_config.json"));
                assert_eq!(rf_dir, Some(PathBuf::from("/tmp/rf")));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parses_decompose() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompose",
            "/tmp/radio.img",
            "--out",
            "/tmp/o",
            "--prune",
            "--no-verify",
            "--no-symbol-pass",
            "--ghidra-home",
            "/opt/ghidra",
            "--processor",
            "ARM:LE:32:v8",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompose {
                img,
                out,
                no_verify,
                prune,
                no_symbol_pass,
                ghidra_home,
                processor,
                ..
            } => {
                assert_eq!(img, PathBuf::from("/tmp/radio.img"));
                assert_eq!(out, Some(PathBuf::from("/tmp/o")));
                assert!(no_verify);
                assert!(prune);
                assert!(no_symbol_pass);
                assert_eq!(ghidra_home, Some(PathBuf::from("/opt/ghidra")));
                assert_eq!(processor, "ARM:LE:32:v8");
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parses_symbolicate() {
        let cli = Cli::try_parse_from([
            "pme",
            "symbolicate",
            "/tmp/dec",
            "--token-db",
            "/tmp/pw_token_db",
        ])
        .unwrap();
        match cli.command {
            Commands::Symbolicate { path, token_db } => {
                assert_eq!(path, PathBuf::from("/tmp/dec"));
                assert_eq!(token_db, Some(PathBuf::from("/tmp/pw_token_db")));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_help_lists_no_thumb_decompile_flag() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompose")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("--no-thumb-decompile"), "help:\n{help}");
    }

    #[test]
    fn decompose_help_lists_no_skip_opaque_flag() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompose")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("--no-skip-opaque"), "help:\n{help}");
    }

    #[test]
    fn decompile_help_lists_no_skip_opaque_flag() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompile")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("--no-skip-opaque"), "help:\n{help}");
    }

    #[test]
    fn decompose_no_skip_opaque_flag_defaults_false() {
        let cli = Cli::try_parse_from(["pme", "decompose", "/tmp/radio.img"]).unwrap();
        match cli.command {
            Commands::Decompose { no_skip_opaque, .. } => {
                assert!(!no_skip_opaque, "default --no-skip-opaque should be false");
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_no_skip_opaque_flag_parses_true() {
        let cli = Cli::try_parse_from(["pme", "decompose", "--no-skip-opaque", "/tmp/radio.img"])
            .unwrap();
        match cli.command {
            Commands::Decompose { no_skip_opaque, .. } => {
                assert!(
                    no_skip_opaque,
                    "--no-skip-opaque should parse to true when passed"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompile_no_skip_opaque_flag_defaults_false() {
        let cli = Cli::try_parse_from(["pme", "decompile", "/tmp/modem.bin"]).unwrap();
        match cli.command {
            Commands::Decompile { no_skip_opaque, .. } => {
                assert!(!no_skip_opaque, "default --no-skip-opaque should be false");
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompile_no_skip_opaque_flag_parses_true() {
        let cli = Cli::try_parse_from(["pme", "decompile", "--no-skip-opaque", "/tmp/modem.bin"])
            .unwrap();
        match cli.command {
            Commands::Decompile { no_skip_opaque, .. } => {
                assert!(
                    no_skip_opaque,
                    "--no-skip-opaque should parse to true when passed"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompile_help_lists_no_thumb_decompile_flag() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompile")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("--no-thumb-decompile"), "help:\n{help}");
    }

    #[test]
    fn decompose_no_thumb_decompile_flag_defaults_false() {
        let cli = Cli::try_parse_from(["pme", "decompose", "/tmp/radio.img"]).unwrap();
        match cli.command {
            Commands::Decompose {
                no_thumb_decompile, ..
            } => {
                assert!(
                    !no_thumb_decompile,
                    "default --no-thumb-decompile should be false"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_no_thumb_decompile_flag_parses_true() {
        let cli =
            Cli::try_parse_from(["pme", "decompose", "--no-thumb-decompile", "/tmp/radio.img"])
                .unwrap();
        match cli.command {
            Commands::Decompose {
                no_thumb_decompile, ..
            } => {
                assert!(
                    no_thumb_decompile,
                    "--no-thumb-decompile should parse to true when passed"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_help_lists_no_apply_global_types_flag() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompose")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(help.contains("--no-apply-global-types"), "help:\n{help}");
    }

    #[test]
    fn decompose_no_apply_global_types_flag_defaults_false() {
        let cli = Cli::try_parse_from(["pme", "decompose", "/tmp/radio.img"]).unwrap();
        match cli.command {
            Commands::Decompose {
                no_apply_global_types,
                ..
            } => {
                assert!(
                    !no_apply_global_types,
                    "default --no-apply-global-types should be false"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_no_apply_global_types_flag_parses_true() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompose",
            "--no-apply-global-types",
            "/tmp/radio.img",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompose {
                no_apply_global_types,
                ..
            } => {
                assert!(
                    no_apply_global_types,
                    "--no-apply-global-types should parse to true when passed"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_tighten_wall_clock_budget_sec_is_hidden_from_help() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompose")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(
            !help.contains("--tighten-wall-clock-budget-sec"),
            "hidden test-only flag should not appear in help:\n{help}"
        );
    }

    #[test]
    fn decompose_tighten_wall_clock_budget_sec_parses_u64_seconds() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompose",
            "--tighten-wall-clock-budget-sec",
            "42",
            "/tmp/radio.img",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompose {
                tighten_wall_clock_budget_sec,
                ..
            } => {
                assert_eq!(
                    tighten_wall_clock_budget_sec,
                    Some(42),
                    "--tighten-wall-clock-budget-sec 42 should parse as Some(42)"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompile_tighten_wall_clock_budget_sec_is_hidden_from_help() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompile")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(
            !help.contains("--tighten-wall-clock-budget-sec"),
            "hidden test-only flag should not appear in help:\n{help}"
        );
    }

    #[test]
    fn decompile_tighten_wall_clock_budget_sec_parses_u64_seconds() {
        let cli = Cli::try_parse_from([
            "pme",
            "decompile",
            "--tighten-wall-clock-budget-sec",
            "42",
            "/tmp/radio.img",
        ])
        .unwrap();
        match cli.command {
            Commands::Decompile {
                tighten_wall_clock_budget_sec,
                ..
            } => {
                assert_eq!(
                    tighten_wall_clock_budget_sec,
                    Some(42),
                    "--tighten-wall-clock-budget-sec 42 should parse as Some(42)"
                );
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn decompose_globals_provisional_flag_parses() {
        let cli = Cli::try_parse_from(["pme", "decompose", "radio.img", "--globals-provisional"])
            .unwrap();
        match cli.command {
            Commands::Decompose {
                globals_provisional,
                ..
            } => assert!(globals_provisional),
            _ => panic!("not decompose"),
        }
    }

    #[test]
    fn decompose_globals_provisional_defaults_off() {
        let cli = Cli::try_parse_from(["pme", "decompose", "radio.img"]).unwrap();
        match cli.command {
            Commands::Decompose {
                globals_provisional,
                ..
            } => assert!(!globals_provisional),
            _ => panic!("not decompose"),
        }
    }

    #[test]
    fn decompose_globals_k_arm_hidden_flag_parses() {
        let cli = Cli::try_parse_from(["pme", "decompose", "radio.img", "--globals-k-arm", "12"])
            .unwrap();
        match cli.command {
            Commands::Decompose { globals_k_arm, .. } => {
                assert_eq!(globals_k_arm, Some(12));
            }
            _ => panic!("not decompose"),
        }
    }

    #[test]
    fn decompose_globals_k_thumb_hidden_flag_parses() {
        let cli = Cli::try_parse_from(["pme", "decompose", "radio.img", "--globals-k-thumb", "8"])
            .unwrap();
        match cli.command {
            Commands::Decompose {
                globals_k_thumb, ..
            } => {
                assert_eq!(globals_k_thumb, Some(8));
            }
            _ => panic!("not decompose"),
        }
    }

    #[test]
    fn decompose_globals_k_flags_are_hidden_from_help() {
        use clap::CommandFactory;

        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("decompose")
            .unwrap()
            .render_long_help()
            .to_string();

        assert!(
            !help.contains("--globals-k-arm"),
            "hidden test-only flag should not appear in help:\n{help}"
        );
        assert!(
            !help.contains("--globals-k-thumb"),
            "hidden test-only flag should not appear in help:\n{help}"
        );
    }

    #[test]
    fn parses_tree_hash() {
        let cli = Cli::try_parse_from(["pme", "tree-hash", "/tmp/some_tree"]).unwrap();
        match cli.command {
            Commands::TreeHash { dir } => {
                assert_eq!(dir, PathBuf::from("/tmp/some_tree"));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn tree_hash_help_mentions_the_scheme() {
        use clap::CommandFactory;
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("tree-hash")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("pme-paq-v1"), "help:\n{help}");
    }
}
