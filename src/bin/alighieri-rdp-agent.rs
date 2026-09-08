#[cfg(windows)]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init()
        .map_err(|error| std::io::Error::other(format!("initialize logging: {error}")))?;
    alighieri::rdp::windows::wts::run_agent().await
}

#[cfg(not(windows))]
fn main() {
    eprintln!("alighieri-rdp-agent is available only on Windows");
    std::process::exit(1);
}
