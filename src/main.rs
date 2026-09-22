use std::path::PathBuf;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config_path = PathBuf::from("config.yaml");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                config_path = PathBuf::from(path);
            }
        }
    }

    let text = std::fs::read_to_string(&config_path)?;
    let cfg = pii_guard::config::Config::from_yaml(&text)?;
    cfg.validate()?;
    if !std::path::Path::new(&cfg.pii_types_file).exists() {
        anyhow::bail!("pii_types_file not found: {}", cfg.pii_types_file);
    }
    if !std::path::Path::new(&cfg.allowlist_file).exists() {
        anyhow::bail!("allowlist_file not found: {}", cfg.allowlist_file);
    }

    pii_guard::server::run(config_path).await
}