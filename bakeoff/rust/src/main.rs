use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
struct AppState {
    upstreams: Vec<String>,
    ttft: Duration,
    client: reqwest::Client,
    requests_total: Arc<AtomicU64>,
}

#[tokio::main]
async fn main() {
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:18080".into());
    let upstreams: Vec<String> = std::env::var("UPSTREAMS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let ttft_ms: u64 = std::env::var("TTFT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);

    let client = reqwest::Client::builder()
        .build()
        .expect("failed to build client");

    let state = AppState {
        upstreams,
        ttft: Duration::from_millis(ttft_ms),
        client,
        requests_total: Arc::new(AtomicU64::new(0)),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/chat/completions", post(proxy))
        .with_state(state);

    let addr: SocketAddr = listen.parse().expect("invalid LISTEN_ADDR");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind failed");
    axum::serve(listener, app).await.expect("server error");
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn metrics(State(state): State<AppState>) -> String {
    format!(
        "proxy_requests_total {}\n",
        state.requests_total.load(Ordering::Relaxed)
    )
}

async fn proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    state.requests_total.fetch_add(1, Ordering::Relaxed);

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "bad request body"),
    };

    let is_stream = serde_json::from_slice::<Value>(&body_bytes)
        .ok()
        .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
        .unwrap_or(false);

    let mut last_status = StatusCode::BAD_GATEWAY;
    for upstream in &state.upstreams {
        match try_upstream(&state, upstream, &headers, &body_bytes, is_stream).await {
            Ok(resp) => return resp,
            Err(status) => last_status = status,
        }
    }
    error_response(last_status, "all upstreams failed")
}

async fn try_upstream(
    state: &AppState,
    upstream: &str,
    headers: &HeaderMap,
    body: &Bytes,
    is_stream: bool,
) -> Result<Response, StatusCode> {
    let url = format!("{}/v1/chat/completions", upstream.trim_end_matches('/'));
    let mut req = state.client.post(&url);
    for (k, v) in headers {
        if k == header::HOST || k == header::CONTENT_LENGTH || k == header::TRANSFER_ENCODING {
            continue;
        }
        req = req.header(k, v);
    }
    req = req.body(body.clone());

    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => return Err(StatusCode::BAD_GATEWAY),
    };

    let status = resp.status();
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        return Err(status);
    }

    let mut builder = Response::builder().status(status);
    for (k, v) in resp.headers() {
        if k == header::CONTENT_LENGTH || k == header::TRANSFER_ENCODING {
            continue;
        }
        builder = builder.header(k, v);
    }

    if is_stream {
        let mut stream = resp.bytes_stream();
        let first = tokio::time::timeout(state.ttft, stream.next()).await;
        let first_chunk = match first {
            Err(_) => return Err(StatusCode::GATEWAY_TIMEOUT),
            Ok(None) => return Err(StatusCode::BAD_GATEWAY),
            Ok(Some(Err(_))) => return Err(StatusCode::BAD_GATEWAY),
            Ok(Some(Ok(chunk))) => chunk,
        };

        let rest = stream.map(|item| item.map_err(|e| -> BoxError { Box::new(e) }));
        let first_stream = stream::once(async move { Ok::<Bytes, BoxError>(first_chunk) });
        let combined = first_stream.chain(rest);

        let body = Body::from_stream(combined);
        return builder
            .body(body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::BAD_GATEWAY),
    };
    builder
        .body(Body::from(body_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    let body = serde_json::json!({
        "error": {"message": msg, "type": "proxy_error"}
    });
    let body = Body::from(body.to_string());
    match Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
    {
        Ok(r) => r,
        Err(_) => Response::new(Body::empty()),
    }
}