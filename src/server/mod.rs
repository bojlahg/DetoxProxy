use std::sync::Arc;

use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;

use crate::config::ConfigStore;
use crate::detect::Detector;
use crate::registry::Registry;
use crate::store::MappingStore;

pub struct AppState {
    pub config: ConfigStore,
    pub registry: Arc<Registry>,
    pub detector: Detector,
    pub store: MappingStore,
    pub metrics: PrometheusHandle,
    pub inflight: tokio::sync::Semaphore,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    todo!()
}

pub async fn run(config_path: std::path::PathBuf) -> anyhow::Result<()> {
    todo!()
}