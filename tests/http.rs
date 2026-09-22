use std::sync::Arc;
use std::time::Duration;

use axum::serve::ListenerExt;
use pii_guard::config::{Config, ConfigStore};
use pii_guard::detect::{Detector, Dictionaries};
use pii_guard::registry::Registry;
use pii_guard::server::{build_router, AppState};
use pii_guard::store::MappingStore;

static METRICS: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> = std::sync::OnceLock::new();

fn metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    METRICS
        .get_or_init(|| pii_guard::obs::install_metrics().expect("install metrics"))
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
    let store = MappingStore::new(
        Duration::from_secs(cfg.server.mapping_ttl_sec),
        cfg.server.mapping_max_entries,
    );
    Arc::new(AppState {
        config: ConfigStore::new(cfg.clone()),
        registry,
        detector,
        store,
        metrics: metrics_handle(),
        inflight: Arc::new(tokio::sync::Semaphore::new(cfg.server.max_inflight)),
    })
}

fn load_root_config() -> Config {
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

async fn post_json(base: &str, path: &str, body: &serde_json::Value, headers: &[(&str, &str)]) -> (u16, serde_json::Value, reqwest::header::HeaderMap) {
    let client = reqwest::Client::new();
    let mut req = client.post(format!("{}{}", base, path)).json(body);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.send().await.expect("send");
    let status = resp.status().as_u16();
    let hdrs = resp.headers().clone();
    let text = resp.text().await.expect("text");
    let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, json, hdrs)
}

async fn get(base: &str, path: &str) -> (u16, String) {
    let client = reqwest::Client::new();
    let resp = client.get(format!("{}{}", base, path)).send().await.expect("send");
    let status = resp.status().as_u16();
    let text = resp.text().await.expect("text");
    (status, text)
}

#[tokio::test]
async fn process_mask_unmask_retry_distorted() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;

    let payload = "Клиент ИНН 7707083893, тел. +7 912 345-67-89, email ivan@mail.ru";
    let id = "A";
    let body = serde_json::json!({"payload": payload, "payload_id": id});

    let (st, json, _) = post_json(&base, "/process", &body, &[]).await;
    assert_eq!(st, 200);
    let masked = json["result"].as_str().unwrap().to_string();
    assert!(masked.contains("<<INN_1>>"), "masked: {masked}");
    assert!(masked.contains("<<PHONE_1>>"), "masked: {masked}");
    assert!(masked.contains("<<EMAIL_1>>"), "masked: {masked}");
    assert!(!masked.contains("7707083893"));
    assert!(!masked.contains("ivan@mail.ru"));

    let (st, json, _) = post_json(&base, "/process", &serde_json::json!({"payload": masked, "payload_id": id}), &[]).await;
    assert_eq!(st, 200);
    assert_eq!(json["result"].as_str().unwrap(), payload);

    let (st, json, _) = post_json(&base, "/process", &body, &[]).await;
    assert_eq!(st, 200);
    assert_eq!(json["result"].as_str().unwrap(), masked);

    let distorted = masked.replace("<<INN_1>>", "<< inn_1 >>");
    let (st, json, _) = post_json(&base, "/process", &serde_json::json!({"payload": distorted, "payload_id": id}), &[]).await;
    assert_eq!(st, 200);
    assert!(json["result"].as_str().unwrap().contains("7707083893"));
}

#[tokio::test]
async fn process_unknown_id_is_new_mask() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let payload = "ИНН 7707083893";
    let (st, json, _) = post_json(&base, "/process", &serde_json::json!({"payload": payload, "payload_id": "unknown-id"}), &[]).await;
    assert_eq!(st, 200);
    assert!(json["result"].as_str().unwrap().contains("<<INN_1>>"));
}

#[tokio::test]
async fn process_system_unknown_403_and_chatbot_hash() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;

    let (st, json, _) = post_json(
        &base,
        "/process",
        &serde_json::json!({"payload": "ИНН 7707083893", "payload_id": "x1"}),
        &[("X-System-Id", "unknown")],
    )
    .await;
    assert_eq!(st, 403);
    assert_eq!(json["error"]["type"], "forbidden");

    let (st, json, _) = post_json(
        &base,
        "/process",
        &serde_json::json!({"payload": "ИНН 7707083893", "payload_id": "c1"}),
        &[("X-System-Id", "chatbot")],
    )
    .await;
    assert_eq!(st, 200);
    let m1 = json["result"].as_str().unwrap().to_string();
    assert!(regex::Regex::new(r"<<INN_[0-9a-f]{6}>>").unwrap().is_match(&m1), "m1: {m1}");

    let (st, json, _) = post_json(
        &base,
        "/process",
        &serde_json::json!({"payload": "ИНН 7707083893", "payload_id": "c2"}),
        &[("X-System-Id", "chatbot")],
    )
    .await;
    assert_eq!(st, 200);
    let m2 = json["result"].as_str().unwrap().to_string();
    assert_eq!(m1, m2, "same INN must give same hash token across payload_ids");
}

#[tokio::test]
async fn v1_mask_unmask_roundtrip_and_not_found() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;

    let (st, json, _) = post_json(&base, "/v1/mask", &serde_json::json!({"text": "ИНН 7707083893"}), &[]).await;
    assert_eq!(st, 200);
    let session = json["session_id"].as_str().unwrap().to_string();
    let masked = json["text"].as_str().unwrap().to_string();
    assert!(masked.contains("<<INN_1>>"));
    assert_eq!(json["entities"][0]["type"], "inn");

    let (st, json, _) = post_json(&base, "/v1/unmask", &serde_json::json!({"text": masked, "session_id": session}), &[]).await;
    assert_eq!(st, 200);
    assert_eq!(json["text"].as_str().unwrap(), "ИНН 7707083893");

    let (st, json, hdrs) = post_json(&base, "/v1/unmask", &serde_json::json!({"text": "что-то", "session_id": "nope"}), &[]).await;
    assert_eq!(st, 200);
    assert_eq!(json["text"].as_str().unwrap(), "что-то");
    assert_eq!(hdrs.get("x-unmask").and_then(|v| v.to_str().ok()), Some("not-found"));
}

#[tokio::test]
async fn v1_detect_no_values() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    let (st, json, _) = post_json(&base, "/v1/detect", &serde_json::json!({"text": "ИНН 7707083893"}), &[]).await;
    assert_eq!(st, 200);
    let s = serde_json::to_string(&json).unwrap();
    assert!(json["entities"][0]["type"] == "inn");
    assert!(!s.contains("7707083893"), "detect must not return values: {s}");
}

#[tokio::test]
async fn process_bad_requests() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;

    let (st, _json, _) = post_json(&base, "/process", &serde_json::json!({"payload": "x"}), &[]).await;
    assert_eq!(st, 400);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/process", base))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn body_too_large_413() {
    let cfg_text = r#"
version: 1
server:
  listen: "127.0.0.1:0"
  max_body_bytes: 100
  max_inflight: 2048
  mapping_ttl_sec: 900
  mapping_max_entries: 200000
  request_deadline_ms: 5000
default_system: autotest
systems:
  - id: autotest
    enabled: true
    mask_mode: token
    unmask_enabled: true
    types: all
    overrides: {}
    combination_rule: false
    min_confidence: 0.3
    allow_substrings: []
    session_mode: stateless
    token_numbering: sequential
pii_types_file: data/pii_types.yaml
allowlist_file: data/allowlist.yaml
"#;
    let cfg = Config::from_yaml(cfg_text).expect("parse");
    cfg.validate().expect("validate");
    let base = spawn_app(build_state(cfg)).await;

    let client = reqwest::Client::new();
    let big = "x".repeat(500);
    let resp = client
        .post(format!("{}/process", base))
        .json(&serde_json::json!({"payload": big, "payload_id": "big"}))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 413);
}

#[tokio::test]
async fn overload_429() {
    let cfg_text = r#"
version: 1
server:
  listen: "127.0.0.1:0"
  max_body_bytes: 4194304
  max_inflight: 1
  mapping_ttl_sec: 900
  mapping_max_entries: 200000
  request_deadline_ms: 5000
default_system: autotest
systems:
  - id: autotest
    enabled: true
    mask_mode: token
    unmask_enabled: true
    types: all
    overrides: {}
    combination_rule: false
    min_confidence: 0.3
    allow_substrings: []
    session_mode: stateless
    token_numbering: sequential
pii_types_file: data/pii_types.yaml
allowlist_file: data/allowlist.yaml
"#;
    let cfg = Config::from_yaml(cfg_text).expect("parse");
    cfg.validate().expect("validate");
    let state = build_state(cfg);
    let base = spawn_app(state.clone()).await;

    let permit = state.inflight.clone().try_acquire_owned().expect("acquire permit");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/process", base))
        .json(&serde_json::json!({"payload": "ИНН 7707083893", "payload_id": "o1"}))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status().as_u16(), 429);
    assert_eq!(resp.headers().get("retry-after").and_then(|v| v.to_str().ok()), Some("1"));

    drop(permit);
}

#[tokio::test]
async fn metrics_and_health() {
    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;

    let (st, _) = get(&base, "/healthz").await;
    assert_eq!(st, 200);

    let (st, _) = get(&base, "/readyz").await;
    assert_eq!(st, 200);

    post_json(&base, "/process", &serde_json::json!({"payload": "ИНН 7707083893", "payload_id": "m1"}), &[]).await;

    let (st, body) = get(&base, "/metrics").await;
    assert_eq!(st, 200);
    assert!(body.contains("pii_requests_total"), "metrics: {body}");
    assert!(body.contains("pii_latency_seconds"), "metrics: {body}");
}

#[tokio::test]
async fn logs_do_not_contain_pii() {
    let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = buf.clone();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(move || {
                let w = writer.clone();
                std::io::BufWriter::new(TestWriter(w))
            })
            .json()
            .finish(),
    );

    let cfg = load_root_config();
    let base = spawn_app(build_state(cfg)).await;
    post_json(&base, "/process", &serde_json::json!({"payload": "ИНН 7707083893", "payload_id": "log1"}), &[]).await;

    std::thread::sleep(Duration::from_millis(100));
    let data = buf.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&data).to_string();
    assert!(!text.contains("7707083893"), "log leaked PII: {text}");
}

struct TestWriter(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}