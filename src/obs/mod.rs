use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Installs the Prometheus recorder with latency buckets from 0.0005s to 5s, plus custom buckets
/// for the payload-size and entities-per-request histograms.
pub fn install_metrics() -> anyhow::Result<PrometheusHandle> {
    let buckets = [
        0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
    ];
    let payload_buckets = [
        64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0,
    ];
    let entity_buckets = [0.0, 1.0, 2.0, 3.0, 5.0, 8.0, 13.0, 21.0, 50.0, 100.0];
    let handle = PrometheusBuilder::new()
        .set_buckets(&buckets)?
        .set_buckets_for_metric(Matcher::Full("pii_payload_bytes".to_owned()), &payload_buckets)?
        .set_buckets_for_metric(Matcher::Full("pii_entities_per_request".to_owned()), &entity_buckets)?
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