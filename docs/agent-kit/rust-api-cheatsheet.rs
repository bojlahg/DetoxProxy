// API cheat sheet: every call below is verified by the compiler against the pinned crate versions (see Cargo.deps.toml).
// Reference only, not part of the solution. Use these exact forms instead of recalling APIs from memory.
use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use axum::{
    body::Body,
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    serve::ListenerExt,
    Router,
};
use futures_util::StreamExt;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Deserialize;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Clone, Deserialize)]
struct Config {
    upstream: String,
}

#[derive(Deserialize)]
struct ChatProbe {
    model: String,
    #[serde(default)]
    stream: bool,
}

struct AppState {
    config: ArcSwap<Config>,
    client: reqwest::Client,
    metrics: PrometheusHandle,
}

async fn count_requests(State(_state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    metrics::counter!("proxy_requests_total", "route" => "chat").increment(1);
    next.run(req).await
}

async fn chat(State(state): State<Arc<AppState>>, body: bytes::Bytes) -> Result<Response, axum::http::StatusCode> {
    let cfg = state.config.load_full();
    let probe: ChatProbe = serde_json::from_slice(&body).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    tracing::debug!(model = %probe.model, stream = probe.stream, "request parsed");
    let resp = state
        .client
        .post(format!("{}/v1/chat/completions", cfg.upstream))
        .body(body)
        .send()
        .await
        .map_err(|_| axum::http::StatusCode::BAD_GATEWAY)?;
    let mut stream = resp.bytes_stream();
    let first = tokio::time::timeout(Duration::from_millis(500), stream.next())
        .await
        .map_err(|_| axum::http::StatusCode::GATEWAY_TIMEOUT)?;
    let first = first.and_then(Result::ok).ok_or(axum::http::StatusCode::BAD_GATEWAY)?;
    let rest = futures_util::stream::once(async move { Ok::<_, reqwest::Error>(first) }).chain(stream);
    Response::builder()
        .header("content-type", "text/event-stream")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(rest))
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn render_metrics(State(state): State<Arc<AppState>>) -> String {
    state.metrics.render()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").json().init();
    let metrics = PrometheusBuilder::new().install_recorder()?;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(512)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_nodelay(true)
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    let cfg: Config = serde_yaml_ng::from_str("upstream: http://127.0.0.1:9000")?;
    let state = Arc::new(AppState { config: ArcSwap::from_pointee(cfg), client, metrics });

    let app = Router::new()
        .route("/v1/chat/completions", post(chat))
        .route("/metrics", get(render_metrics))
        .route("/v1/models/{id}", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(state.clone(), count_requests))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?.tap_io(|tcp| {
        let _ = tcp.set_nodelay(true);
    });
    axum::serve(listener, app).await?;
    Ok(())
}
