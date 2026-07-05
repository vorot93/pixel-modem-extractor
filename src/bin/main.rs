fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = pixel_modem_extractor::cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
