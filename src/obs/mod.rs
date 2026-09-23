use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Rough LLM token estimate used by metrics and logs: one token per 4 characters, rounded up.
pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4)
}

/// Installs the Prometheus recorder with latency buckets from 0.0005s to 5s, plus custom buckets
/// for the payload-size, entities-per-request and LLM tokens-per-second histograms.
pub fn install_metrics() -> anyhow::Result<PrometheusHandle> {
    let buckets = [
        0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0,
    ];
    let payload_buckets = [
        64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0,
    ];
    let entity_buckets = [0.0, 1.0, 2.0, 3.0, 5.0, 8.0, 13.0, 21.0, 50.0, 100.0];
    let llm_tps_buckets = [1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 5000.0];
    let handle = PrometheusBuilder::new()
        .set_buckets(&buckets)?
        .set_buckets_for_metric(Matcher::Full("pii_payload_bytes".to_owned()), &payload_buckets)?
        .set_buckets_for_metric(Matcher::Full("pii_entities_per_request".to_owned()), &entity_buckets)?
        .set_buckets_for_metric(Matcher::Full("pii_llm_tokens_per_second".to_owned()), &llm_tps_buckets)?
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