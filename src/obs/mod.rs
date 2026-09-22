use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Installs the Prometheus recorder with latency buckets from 0.0005s to 5s.
pub fn install_metrics() -> anyhow::Result<PrometheusHandle> {
    let buckets = [
        0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
    ];
    let handle = PrometheusBuilder::new()
        .set_buckets(&buckets)?
        .install_recorder()?;
    Ok(handle)
}

/// Initializes JSON tracing to stdout.
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .with_writer(std::io::stdout)
        .init();
}