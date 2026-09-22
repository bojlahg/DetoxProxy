use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::ListenerExt,
    Json, Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};

use crate::config::{ConfigStore, SystemConfig, TokenNumbering};
use crate::detect::{DetectOptions, Detector};
use crate::mask::{mask_with, mask_with_seed, unmask, MaskOptions, Numbering};
use crate::registry::Registry;
use crate::store::MappingStore;
use crate::types::Direction;

pub struct AppState {
    pub config: ConfigStore,
    pub registry: Arc<Registry>,
    pub detector: Detector,
    pub store: MappingStore,
    pub metrics: PrometheusHandle,
    pub inflight: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug, Deserialize)]
struct ProcessRequest {
    payload: String,
    payload_id: String,
}

#[derive(Debug, Serialize)]
struct ProcessResponse {
    result: String,
}

#[derive(Debug, Deserialize)]
struct MaskRequest {
    text: String,
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct MaskResponse {
    text: String,
    session_id: String,
    entities: Vec<MaskEntity>,
    mappings: Vec<crate::types::Mapping>,
}

#[derive(Debug, Serialize)]
struct MaskEntity {
    #[serde(rename = "type")]
    type_id: String,
    start: usize,
    end: usize,
    token: String,
}

#[derive(Debug, Deserialize)]
struct UnmaskRequest {
    text: String,
    session_id: String,
}

#[derive(Debug, Serialize)]
struct UnmaskResponse {
    text: String,
}

#[derive(Debug, Deserialize)]
struct DetectRequest {
    text: String,
}

#[derive(Debug, Serialize)]
struct DetectResponse {
    entities: Vec<DetectEntity>,
}

#[derive(Debug, Serialize)]
struct DetectEntity {
    #[serde(rename = "type")]
    type_id: String,
    start: usize,
    end: usize,
    confidence: f32,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: ApiErrorBody,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    message: String,
    #[serde(rename = "type")]
    kind: String,
}

fn error_response(status: StatusCode, message: &str, kind: &str) -> Response {
    let body = ApiError {
        error: ApiErrorBody {
            message: message.to_string(),
            kind: kind.to_string(),
        },
    };
    (status, Json(body)).into_response()
}

fn hash_id(id: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn request_id(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get("x-request-id") {
        if let Ok(s) = v.to_str() {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    format!("{:016x}", n)
}

fn system_for(headers: &HeaderMap, cfg: &crate::config::Config) -> Result<Arc<SystemConfig>, Box<Response>> {
    let id = headers
        .get("x-system-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| cfg.default_system.clone());
    match cfg.system(&id) {
        Some(sys) if sys.enabled => Ok(Arc::new(sys.clone())),
        _ => Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "system not allowed",
            "forbidden",
        ))),
    }
}

fn detect_options<'a>(sys: &'a SystemConfig) -> DetectOptions<'a> {
    let enabled_types = match &sys.types {
        crate::config::TypeSelection::All(_) => None,
        crate::config::TypeSelection::List(ids) => Some(ids.as_slice()),
    };
    DetectOptions {
        enabled_types,
        min_confidence: sys.min_confidence,
        allow_substrings: &sys.allow_substrings,
        trap_policy: sys.trap_policy,
    }
}

fn mask_options<'a>(sys: &'a SystemConfig) -> MaskOptions<'a> {
    MaskOptions {
        default_mode: sys.mask_mode,
        overrides: &sys.overrides,
        combination_rule: sys.combination_rule,
    }
}

fn numbering(sys: &SystemConfig) -> Numbering {
    match sys.token_numbering {
        TokenNumbering::Sequential => Numbering::Sequential,
        TokenNumbering::Hash => Numbering::Hash(sys.hash_salt.clone().unwrap_or_default()),
    }
}

fn log_request(
    request_id: &str,
    system: &str,
    direction: Direction,
    payload_id: &str,
    entity_types: &HashMap<String, usize>,
    latency_ms: u64,
    status: u16,
) {
    let pid = if payload_id.len() > 64 {
        hash_id(payload_id)
    } else {
        payload_id.to_string()
    };
    tracing::info!(
        request_id = %request_id,
        system = %system,
        direction = ?direction,
        payload_id = %pid,
        entities = ?entity_types,
        latency_ms = latency_ms,
        status = status,
        "request"
    );
}

fn record_metrics(system: &str, direction: Direction, status: u16, latency_ms: u64, entity_types: &HashMap<String, usize>) {
    metrics::counter!(
        "pii_requests_total",
        "system" => system.to_string(),
        "direction" => format!("{:?}", direction).to_lowercase(),
        "status" => status.to_string(),
    )
    .increment(1);
    metrics::histogram!(
        "pii_latency_seconds",
        "direction" => format!("{:?}", direction).to_lowercase(),
    )
    .record(latency_ms as f64 / 1000.0);
    for (t, c) in entity_types {
        metrics::counter!("pii_entities_total", "type" => t.clone()).increment(*c as u64);
    }
}

async fn process_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let started = Instant::now();
    let rid = request_id(&headers);
    let cfg = state.config.load();
    let sys = match system_for(&headers, &cfg) {
        Ok(s) => s,
        Err(resp) => {
            record_metrics("unknown", Direction::Mask, 403, started.elapsed().as_millis() as u64, &HashMap::new());
            return *resp;
        }
    };

    let deadline = Duration::from_millis(cfg.server.request_deadline_ms);
    let result = tokio::time::timeout(deadline, async {
        let req: ProcessRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "invalid json".to_string())),
        };
        let payload = req.payload;
        let payload_id = req.payload_id;

        if payload.is_empty() {
            return Ok((ProcessResponse { result: String::new() }, HashMap::new()));
        }

        let existing = state.store.get(&payload_id);
        let entry = match existing {
            Some(e) => e,
            None => {
                let entities = state.detector.detect(&payload, &detect_options(&sys));
                let res = mask_with(&payload, &entities, &state.registry, &mask_options(&sys), numbering(&sys));
                let original_hash = hash_id(&payload);
                state.store.insert_with_hash(
                    &payload_id,
                    res.text.clone(),
                    res.mappings.clone(),
                    original_hash,
                );
                let mut et = HashMap::new();
                for e in &entities {
                    *et.entry(e.type_id.clone()).or_insert(0) += 1;
                }
                return Ok((ProcessResponse { result: res.text }, et));
            }
        };

        if payload == entry.masked_text {
            if !sys.unmask_enabled {
                return Ok((ProcessResponse { result: payload }, HashMap::new()));
            }
            let restored = unmask(&payload, &entry.mappings);
            return Ok((ProcessResponse { result: restored }, HashMap::new()));
        }

        if hash_id(&payload) == entry.original_hash {
            return Ok((ProcessResponse { result: entry.masked_text }, HashMap::new()));
        }

        let restored = unmask(&payload, &entry.mappings);
        Ok((ProcessResponse { result: restored }, HashMap::new()))
    })
    .await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok((resp, entity_types))) => {
            record_metrics(&sys.id, Direction::Mask, 200, latency, &entity_types);
            log_request(&rid, &sys.id, Direction::Mask, "", &entity_types, latency, 200);
            let mut resp = Json(resp).into_response();
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Ok(Err((status, msg))) => {
            let entity_types = HashMap::new();
            record_metrics(&sys.id, Direction::Mask, status.as_u16(), latency, &entity_types);
            log_request(&rid, &sys.id, Direction::Mask, "", &entity_types, latency, status.as_u16());
            let mut resp = error_response(status, &msg, "bad_request");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Err(_) => {
            let entity_types = HashMap::new();
            record_metrics(&sys.id, Direction::Mask, 503, latency, &entity_types);
            log_request(&rid, &sys.id, Direction::Mask, "", &entity_types, latency, 503);
            let mut resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "request deadline exceeded", "timeout");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
    }
}

async fn mask_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let started = Instant::now();
    let rid = request_id(&headers);
    let cfg = state.config.load();
    let sys = match system_for(&headers, &cfg) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let deadline = Duration::from_millis(cfg.server.request_deadline_ms);
    let result = tokio::time::timeout(deadline, async {
        let req: MaskRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "invalid json".to_string())),
        };
        let session_id = match req.session_id {
            Some(s) if !s.is_empty() => s,
            _ => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut bytes = [0u8; 16];
                rng.fill(&mut bytes);
                bytes.iter().map(|b| format!("{:02x}", b)).collect()
            }
        };
        let entities = state.detector.detect(&req.text, &detect_options(&sys));
        let existing = if sys.session_mode == crate::config::SessionMode::Stateful {
            state.store.get(&session_id)
        } else {
            None
        };
        let seed: Vec<crate::types::Mapping> = existing
            .as_ref()
            .map(|e| e.mappings.clone())
            .unwrap_or_default();
        let res = mask_with_seed(
            &req.text,
            &entities,
            &state.registry,
            &mask_options(&sys),
            numbering(&sys),
            &seed,
        );
        let mut merged = seed;
        for m in &res.mappings {
            if !merged.iter().any(|x| x.masked == m.masked) {
                merged.push(m.clone());
            }
        }
        state.store.insert_with_hash(&session_id, res.text.clone(), merged, hash_id(&req.text));
        let out_entities = res
            .entities
            .iter()
            .map(|e| MaskEntity {
                type_id: e.type_id.clone(),
                start: e.start,
                end: e.end,
                token: res
                    .mappings
                    .iter()
                    .find(|m| m.type_id == e.type_id)
                    .map(|m| m.masked.clone())
                    .unwrap_or_default(),
            })
            .collect();
        Ok(MaskResponse {
            text: res.text,
            session_id,
            entities: out_entities,
            mappings: res.mappings,
        })
    })
    .await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(resp)) => {
            record_metrics(&sys.id, Direction::Mask, 200, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, 200);
            let mut resp = Json(resp).into_response();
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Ok(Err((status, msg))) => {
            record_metrics(&sys.id, Direction::Mask, status.as_u16(), latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, status.as_u16());
            let mut resp = error_response(status, &msg, "bad_request");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Err(_) => {
            record_metrics(&sys.id, Direction::Mask, 503, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, 503);
            let mut resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "request deadline exceeded", "timeout");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
    }
}

async fn unmask_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let started = Instant::now();
    let rid = request_id(&headers);
    let cfg = state.config.load();
    let sys = match system_for(&headers, &cfg) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let deadline = Duration::from_millis(cfg.server.request_deadline_ms);
    let result = tokio::time::timeout(deadline, async {
        let req: UnmaskRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "invalid json".to_string())),
        };
        match state.store.get(&req.session_id) {
            Some(entry) => {
                let restored = unmask(&req.text, &entry.mappings);
                Ok((false, UnmaskResponse { text: restored }))
            }
            None => Ok((true, UnmaskResponse { text: req.text })),
        }
    })
    .await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok((not_found, resp))) => {
            record_metrics(&sys.id, Direction::Unmask, 200, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Unmask, "", &HashMap::new(), latency, 200);
            let mut resp = Json(resp).into_response();
            if not_found {
                resp.headers_mut().insert("x-unmask", "not-found".parse().unwrap());
            }
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Ok(Err((status, msg))) => {
            record_metrics(&sys.id, Direction::Unmask, status.as_u16(), latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Unmask, "", &HashMap::new(), latency, status.as_u16());
            let mut resp = error_response(status, &msg, "bad_request");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Err(_) => {
            record_metrics(&sys.id, Direction::Unmask, 503, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Unmask, "", &HashMap::new(), latency, 503);
            let mut resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "request deadline exceeded", "timeout");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
    }
}

async fn detect_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let started = Instant::now();
    let rid = request_id(&headers);
    let cfg = state.config.load();
    let sys = match system_for(&headers, &cfg) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let deadline = Duration::from_millis(cfg.server.request_deadline_ms);
    let result = tokio::time::timeout(deadline, async {
        let req: DetectRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return Err((StatusCode::BAD_REQUEST, "invalid json".to_string())),
        };
        let entities = state.detector.detect(&req.text, &detect_options(&sys));
        let out: Vec<DetectEntity> = entities
            .iter()
            .map(|e| DetectEntity {
                type_id: e.type_id.clone(),
                start: e.start,
                end: e.end,
                confidence: e.confidence,
            })
            .collect();
        Ok(DetectResponse { entities: out })
    })
    .await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(resp)) => {
            record_metrics(&sys.id, Direction::Mask, 200, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, 200);
            let mut resp = Json(resp).into_response();
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Ok(Err((status, msg))) => {
            record_metrics(&sys.id, Direction::Mask, status.as_u16(), latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, status.as_u16());
            let mut resp = error_response(status, &msg, "bad_request");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Err(_) => {
            record_metrics(&sys.id, Direction::Mask, 503, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, 503);
            let mut resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "request deadline exceeded", "timeout");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<Arc<AppState>>) -> StatusCode {
    let cfg = state.config.load();
    if cfg.systems.is_empty() || state.registry.types().is_empty() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> String {
    state.metrics.render()
}

async fn inflight_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let permit = match state.inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            metrics::counter!("pii_rejected_total", "reason" => "overload").increment(1);
            let mut resp = error_response(StatusCode::TOO_MANY_REQUESTS, "too many requests", "overload");
            resp.headers_mut().insert("retry-after", "1".parse().unwrap());
            return resp;
        }
    };
    metrics::gauge!("pii_inflight").set(state.inflight.available_permits() as f64);
    let resp = next.run(req).await;
    drop(permit);
    metrics::gauge!("pii_inflight").set(state.inflight.available_permits() as f64);
    resp
}

async fn body_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let cfg = state.config.load();
    let limit = cfg.server.max_body_bytes;
    let content_length = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    if let Some(len) = content_length {
        if len > limit {
            metrics::counter!("pii_rejected_total", "reason" => "body_too_large").increment(1);
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body too large", "payload_too_large");
        }
    }
    next.run(req).await
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/process", post(process_handler))
        .route("/v1/mask", post(mask_handler))
        .route("/v1/unmask", post(unmask_handler))
        .route("/v1/detect", post(detect_handler))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .layer(middleware::from_fn_with_state(state.clone(), body_limit_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), inflight_middleware))
        .with_state(state)
}

pub async fn run(config_path: std::path::PathBuf) -> anyhow::Result<()> {
    crate::obs::init_tracing();
    let metrics = crate::obs::install_metrics()?;

    let text = std::fs::read_to_string(&config_path)?;
    let cfg = crate::config::Config::from_yaml(&text)?;
    cfg.validate()?;

    let pii_types = std::fs::read_to_string(&cfg.pii_types_file)?;
    let registry = Arc::new(crate::registry::Registry::from_yaml(&pii_types)?);

    let dicts = match &cfg.dictionaries_dir {
        Some(dir) if std::path::Path::new(dir).exists() => {
            Arc::new(crate::detect::Dictionaries::load_dir(std::path::Path::new(dir))?)
        }
        _ => Arc::new(crate::detect::Dictionaries::empty()),
    };
    let allowlist_text = std::fs::read_to_string(&cfg.allowlist_file)?;
    let allowlist = crate::detect::Allowlist::from_yaml(&allowlist_text)?;
    let detector = crate::detect::Detector::with_allowlist(registry.clone(), dicts, allowlist)
        .with_historical_date_years(cfg.server.historical_date_years);

    let store = crate::store::MappingStore::new(
        Duration::from_secs(cfg.server.mapping_ttl_sec),
        cfg.server.mapping_max_entries,
    );

    let state = Arc::new(AppState {
        config: crate::config::ConfigStore::new(cfg.clone()),
        registry,
        detector,
        store,
        metrics,
        inflight: Arc::new(tokio::sync::Semaphore::new(cfg.server.max_inflight)),
    });

    let sweep_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let removed = sweep_state.store.sweep();
            metrics::gauge!("pii_mappings_stored").set(sweep_state.store.len() as f64);
            if removed > 0 {
                tracing::debug!(removed = removed, "store sweep");
            }
        }
    });

    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind(&cfg.server.listen)
        .await?
        .tap_io(|tcp| {
            let _ = tcp.set_nodelay(true);
        });
    tracing::info!(listen = %cfg.server.listen, "server started");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}