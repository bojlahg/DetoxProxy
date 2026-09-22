use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::serve::ListenerExt;
use detox_proxy::config::{Config, ConfigStore};
use detox_proxy::detect::{Detector, Dictionaries};
use detox_proxy::registry::Registry;
use detox_proxy::server::{build_router, AppState};
use detox_proxy::store::MappingStore;

static METRICS: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> = std::sync::OnceLock::new();

fn metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    METRICS
        .get_or_init(|| detox_proxy::obs::install_metrics().expect("install metrics"))
        .clone()
}

fn build_state(cfg: Config) -> Arc<AppState> {
    let pii_types = std::fs::read_to_string(&cfg.pii_types_file).expect("read pii_types.yaml");
    let registry = Arc::new(Registry::from_yaml(&pii_types).expect("parse registry"));
    let dicts = match &cfg.dictionaries_dir {
        Some(dir) if std::path::Path::new(dir).exists() => {
            Arc::new(Dictionaries::load_dir(std::path::Path::new(dir)).expect("load dicts"))
        }
        _ => Arc::new(Dictionaries::empty()),
    };
    let detector = Detector::new(registry.clone(), dicts);
    let store = Arc::new(MappingStore::new(
        Duration::from_secs(cfg.server.mapping_ttl_sec),
        cfg.server.mapping_max_entries,
    ));
    Arc::new(AppState {
        config: ConfigStore::new(cfg.clone()),
        registry: ArcSwap::from(registry),
        detector: ArcSwap::from_pointee(detector),
        store,
        metrics: metrics_handle(),
        inflight: Arc::new(tokio::sync::Semaphore::new(cfg.server.max_inflight)),
        heavy: Arc::new(tokio::sync::Semaphore::new(cfg.server.heavy_max_concurrency)),
        config_path: std::path::PathBuf::from("config.yaml"),
    })
}

fn base_cfg() -> Config {
    let text = std::fs::read_to_string("config.yaml").expect("read config.yaml");
    let cfg = Config::from_yaml(&text).expect("parse config");
    cfg.validate().expect("validate config");
    cfg
}

async fn spawn_app(state: Arc<AppState>) -> String {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let listener = listener.tap_io(|tcp| {
        let _ = tcp.set_nodelay(true);
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{}", addr)
}

async fn post_chat(
    base: &str,
    body: &serde_json::Value,
    headers: &[(&str, &str)],
) -> (u16, String, reqwest::header::HeaderMap) {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{}/v1/chat/completions", base)).json(body);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.expect("send");
    let status = resp.status().as_u16();
    let hdrs = resp.headers().clone();
    let text = resp.text().await.expect("text");
    (status, text, hdrs)
}

fn chat_body(stream: bool) -> serde_json::Value {
    serde_json::json!({
        "model": "test-model",
        "messages": [
            {"role": "user", "content": "Клиент Иванов Иван Иванович, ИНН 7707083893"}
        ],
        "stream": stream,
        "temperature": 0.7
    })
}

#[tokio::test]
async fn demo_mode_restores_values_and_header() {
    let cfg = base_cfg();
    let base = spawn_app(build_state(cfg)).await;

    let (st, text, hdrs) = post_chat(&base, &chat_body(false), &[]).await;
    assert_eq!(st, 200, "body: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let content = json["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(content.contains("Иванов Иван Иванович"), "content: {content}");
    let n = hdrs
        .get("x-detox-masked-entities")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(n >= 2, "header x-detox-masked-entities = {n}");
}

#[tokio::test]
async fn fake_upstream_echoes_tokens_and_restores() {
    let upstream = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(|body: axum::body::Bytes| async move {
            let json: serde_json::Value = serde_json::from_slice(&body).expect("upstream json");
            let body_str = serde_json::to_string(&json).unwrap();
            assert!(!body_str.contains("7707083893"), "upstream got PII: {body_str}");
            assert!(!body_str.contains("Иванов"), "upstream got PII: {body_str}");
            assert_eq!(json["stream"], true, "upstream must receive stream:true");

            let content = json["messages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["role"] == "user")
                .and_then(|m| m["content"].as_str())
                .unwrap();
            let tokens: Vec<String> = regex::Regex::new(r"<<[A-Za-z_]+_\d+>>")
                .unwrap()
                .find_iter(content)
                .map(|m| m.as_str().to_string())
                .collect();
            let mut sse = String::new();
            for (i, t) in tokens.iter().enumerate() {
                let chunk = serde_json::json!({
                    "id": "x",
                    "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"content": t}, "finish_reason": null}]
                });
                if i % 2 == 0 {
                    sse.push_str(&format!("data: {}\n\n", chunk));
                } else {
                    sse.push_str(&format!("data:{}\n\n", chunk));
                }
            }
            sse.push_str("data: [DONE]\n\n");
            (
                axum::http::StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                sse,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.expect("serve upstream");
    });

    let mut cfg = base_cfg();
    cfg.llm = Some(detox_proxy::config::LlmConfig {
        upstream_url: Some(format!("http://{}/v1/chat/completions", addr)),
        api_key_env: None,
        timeout_ms: 5000,
        case_hints: true,
    });
    let base = spawn_app(build_state(cfg)).await;

    let (st, text, _) = post_chat(&base, &chat_body(false), &[]).await;
    assert_eq!(st, 200, "body: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let content = json["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(content.contains("Иванов Иван Иванович"), "content: {content}");
    assert!(content.contains("7707083893"), "content: {content}");
}

#[tokio::test]
async fn upstream_500_returns_502_without_body() {
    let upstream = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "internal secret detail",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.expect("serve upstream");
    });

    let mut cfg = base_cfg();
    cfg.llm = Some(detox_proxy::config::LlmConfig {
        upstream_url: Some(format!("http://{}/v1/chat/completions", addr)),
        api_key_env: None,
        timeout_ms: 5000,
        case_hints: true,
    });
    let base = spawn_app(build_state(cfg)).await;

    let (st, text, _) = post_chat(&base, &chat_body(false), &[]).await;
    assert_eq!(st, 502, "body: {text}");
    assert!(!text.contains("internal secret detail"), "upstream body leaked: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert_eq!(json["error"]["type"], "upstream");
}

#[tokio::test]
async fn client_stream_true_returns_sse_with_done() {
    let cfg = base_cfg();
    let base = spawn_app(build_state(cfg)).await;

    let (st, text, hdrs) = post_chat(&base, &chat_body(true), &[]).await;
    assert_eq!(st, 200, "body: {text}");
    assert_eq!(
        hdrs.get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    assert!(text.contains("data: [DONE]"), "body: {text}");
    assert!(text.contains("Иванов Иван Иванович"), "body: {text}");
}

/// Spawns a fake upstream that records whether it received the case-hints system message and
/// replies with a token carrying a nominative case suffix.
async fn spawn_case_upstream(got_hint: Arc<AtomicBool>) -> String {
    let upstream = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |body: axum::body::Bytes| {
            let got_hint = got_hint.clone();
            async move {
                let json: serde_json::Value = serde_json::from_slice(&body).expect("upstream json");
                let msgs = json["messages"].as_array().unwrap();
                let has_system = msgs.iter().any(|m| {
                    m["role"] == "system"
                        && m["content"]
                            .as_str()
                            .map(|c| c.contains("Placeholders like"))
                            .unwrap_or(false)
                });
                got_hint.store(has_system, Ordering::SeqCst);
                let sse = "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Дорогой <<FIO_1:nom>>, с прискорбием сообщаем…\"},\"finish_reason\":null}]}\n\ndata: [DONE]\n\n";
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    sse,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, upstream).await.expect("serve upstream");
    });
    format!("http://{}/v1/chat/completions", addr)
}

#[tokio::test]
async fn case_hints_system_message_and_inflected_unmask() {
    let got_hint = Arc::new(AtomicBool::new(false));
    let url = spawn_case_upstream(got_hint.clone()).await;

    let mut cfg = base_cfg();
    cfg.llm = Some(detox_proxy::config::LlmConfig {
        upstream_url: Some(url),
        api_key_env: None,
        timeout_ms: 5000,
        case_hints: true,
    });
    let base = spawn_app(build_state(cfg)).await;

    let body = serde_json::json!({
        "model": "test-model",
        "messages": [
            {"role": "user", "content": "Напиши письмо с отказом Иванову Ивану Ивановичу"}
        ],
        "stream": false
    });
    let (st, text, _) = post_chat(&base, &body, &[]).await;
    assert_eq!(st, 200, "body: {text}");
    assert!(got_hint.load(Ordering::SeqCst), "upstream must receive the case-hints system message");
    let json: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let content = json["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(
        content.contains("Дорогой Иванов Иван Иванович, с прискорбием сообщаем…"),
        "content: {content}"
    );
}

#[tokio::test]
async fn case_hints_disabled_no_system_message() {
    let got_hint = Arc::new(AtomicBool::new(false));
    let url = spawn_case_upstream(got_hint.clone()).await;

    let mut cfg = base_cfg();
    cfg.llm = Some(detox_proxy::config::LlmConfig {
        upstream_url: Some(url),
        api_key_env: None,
        timeout_ms: 5000,
        case_hints: false,
    });
    let base = spawn_app(build_state(cfg)).await;

    let body = serde_json::json!({
        "model": "test-model",
        "messages": [
            {"role": "user", "content": "Напиши письмо с отказом Иванову Ивану Ивановичу"}
        ],
        "stream": false
    });
    let (st, text, _) = post_chat(&base, &body, &[]).await;
    assert_eq!(st, 200, "body: {text}");
    assert!(
        !got_hint.load(Ordering::SeqCst),
        "upstream must NOT receive the case-hints system message"
    );
}