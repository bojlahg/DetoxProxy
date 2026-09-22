use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use axum::{
    body::Body,
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
use serde_json::Value;

use crate::config::{ConfigStore, SystemConfig, TokenNumbering};
use crate::detect::{DetectOptions, Detector};
use crate::mask::{count_unresolved_tokens, mask_with, mask_with_seed, unmask, MaskOptions, Numbering};
use crate::registry::Registry;
use crate::store::MappingStore;
use crate::types::Direction;

pub struct AppState {
    pub config: ConfigStore,
    pub registry: ArcSwap<Registry>,
    pub detector: ArcSwap<Detector>,
    pub store: MappingStore,
    pub metrics: PrometheusHandle,
    pub inflight: Arc<tokio::sync::Semaphore>,
    pub heavy: Arc<tokio::sync::Semaphore>,
    pub config_path: PathBuf,
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

/// 503 response when the request deadline expires while waiting for a heavy permit or a
/// blocking detection task. Carries `Retry-After: 1` and the `pii_rejected_total{reason="deadline"}` metric.
fn deadline_response() -> Response {
    metrics::counter!("pii_rejected_total", "reason" => "deadline").increment(1);
    let mut resp = error_response(StatusCode::SERVICE_UNAVAILABLE, "request deadline exceeded", "timeout");
    resp.headers_mut().insert("retry-after", "1".parse().unwrap());
    resp
}

/// Runs detection+masking. Short texts run inline on the async worker; long texts run on the
/// blocking thread pool, bounded by the `heavy` semaphore. The whole operation (permit wait +
/// execution) shares a single deadline; on expiry a 503 with `Retry-After: 1` is returned.
async fn run_detection<T, F>(
    state: &Arc<AppState>,
    text_len: usize,
    inline_max_bytes: usize,
    deadline: Duration,
    f: F,
) -> Result<T, Box<Response>>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let heavy = state.heavy.clone();
    let result = tokio::time::timeout(deadline, async move {
        if text_len <= inline_max_bytes {
            Ok::<T, ()>(f())
        } else {
            let _permit = heavy.acquire_owned().await.map_err(|_| ())?;
            Ok(tokio::task::spawn_blocking(f).await.map_err(|_| ())?)
        }
    })
    .await;
    match result {
        Ok(Ok(v)) => Ok(v),
        _ => Err(Box::new(deadline_response())),
    }
}

fn store_key(system: &str, id: &str) -> String {
    format!("{}\u{1f}{}", system, id)
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

/// Records the payload-size histogram for a request.
fn record_payload_bytes(system: &str, direction: Direction, bytes: usize) {
    metrics::histogram!(
        "pii_payload_bytes",
        "system" => system.to_string(),
        "direction" => format!("{:?}", direction).to_lowercase(),
    )
    .record(bytes as f64);
}

/// Records the entities-per-request histogram for a masking request.
fn record_entities_per_request(count: usize) {
    metrics::histogram!("pii_entities_per_request").record(count as f64);
}

/// Records unresolved-token metrics for a restore request.
fn record_unresolved(system: &str, unresolved: usize) {
    if unresolved > 0 {
        metrics::counter!("pii_unmask_unresolved_tokens_total", "system" => system.to_string())
            .increment(unresolved as u64);
        metrics::counter!("pii_unmask_requests_with_unresolved_total", "system" => system.to_string())
            .increment(1);
    }
}

/// Records metrics and the request log line, then attaches the `x-request-id` header.
fn finish_response(
    rid: &str,
    sys: &SystemConfig,
    direction: Direction,
    latency: u64,
    status: u16,
    entity_types: &HashMap<String, usize>,
    resp: Response,
) -> Response {
    record_metrics(&sys.id, direction, status, latency, entity_types);
    log_request(rid, &sys.id, direction, "", entity_types, latency, status);
    let mut resp = resp;
    resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
    resp
}

/// Generates a random 32-hex-char session id.
fn new_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Outcome of a /process request, carrying the data needed to emit per-branch metrics.
struct ProcessOutcome {
    resp: ProcessResponse,
    entity_types: HashMap<String, usize>,
    entity_count: usize,
    is_fresh_mask: bool,
    is_retry: bool,
    unresolved_tokens: usize,
    payload_bytes: usize,
    direction: Direction,
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
    let inline_max = cfg.server.inline_max_bytes;
    let result = process_inner(&state, &sys, &body, deadline, inline_max).await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(outcome) => {
            if outcome.payload_bytes > 0 {
                record_payload_bytes(&sys.id, outcome.direction, outcome.payload_bytes);
            }
            if outcome.direction == Direction::Mask {
                if outcome.is_fresh_mask {
                    record_entities_per_request(outcome.entity_count);
                    if outcome.entity_count == 0 {
                        metrics::counter!("pii_requests_without_entities_total", "system" => sys.id.clone())
                            .increment(1);
                    }
                }
                if outcome.is_retry {
                    metrics::counter!("pii_process_retry_total", "system" => sys.id.clone()).increment(1);
                }
            } else {
                record_unresolved(&sys.id, outcome.unresolved_tokens);
            }
            finish_response(
                &rid,
                &sys,
                outcome.direction,
                latency,
                200,
                &outcome.entity_types,
                Json(outcome.resp).into_response(),
            )
        }
        Err(resp) => {
            let status = resp.status();
            finish_response(&rid, &sys, Direction::Mask, latency, status.as_u16(), &HashMap::new(), *resp)
        }
    }
}

/// Parses the /process body and runs the mask/unmask/retry decision tree.
async fn process_inner(
    state: &Arc<AppState>,
    sys: &SystemConfig,
    body: &axum::body::Bytes,
    deadline: Duration,
    inline_max: usize,
) -> Result<ProcessOutcome, Box<Response>> {
    let req: ProcessRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Err(Box::new(error_response(StatusCode::BAD_REQUEST, "invalid json", "bad_request"))),
    };
    let payload = req.payload;
    let payload_id = req.payload_id;

    if payload.is_empty() {
        return Ok(empty_outcome());
    }

    let key = store_key(&sys.id, &payload_id);
    let entry = match state.store.get(&key) {
        Some(e) => e,
        None => return process_fresh_mask(state, sys, &key, &payload, deadline, inline_max).await,
    };

    if payload == entry.masked_text {
        if !sys.unmask_enabled {
            return Ok(ProcessOutcome {
                resp: ProcessResponse { result: payload.clone() },
                entity_types: HashMap::new(),
                entity_count: 0,
                is_fresh_mask: false,
                is_retry: false,
                unresolved_tokens: 0,
                payload_bytes: payload.len(),
                direction: Direction::Mask,
            });
        }
        return Ok(unmask_outcome(&payload, &entry, Direction::Unmask));
    }

    if hash_id(&payload) == entry.original_hash {
        return Ok(ProcessOutcome {
            resp: ProcessResponse { result: entry.masked_text.clone() },
            entity_types: HashMap::new(),
            entity_count: 0,
            is_fresh_mask: false,
            is_retry: true,
            unresolved_tokens: 0,
            payload_bytes: payload.len(),
            direction: Direction::Mask,
        });
    }

    Ok(unmask_outcome(&payload, &entry, Direction::Unmask))
}

/// Outcome for an empty payload: an empty result with no metrics side effects.
fn empty_outcome() -> ProcessOutcome {
    ProcessOutcome {
        resp: ProcessResponse { result: String::new() },
        entity_types: HashMap::new(),
        entity_count: 0,
        is_fresh_mask: false,
        is_retry: false,
        unresolved_tokens: 0,
        payload_bytes: 0,
        direction: Direction::Mask,
    }
}

/// Outcome for a payload that must be unmasked against an existing store entry.
fn unmask_outcome(payload: &str, entry: &crate::store::StoredEntry, direction: Direction) -> ProcessOutcome {
    let restored = unmask(payload, &entry.mappings);
    let unresolved = count_unresolved_tokens(payload, &entry.mappings);
    ProcessOutcome {
        resp: ProcessResponse { result: restored },
        entity_types: HashMap::new(),
        entity_count: 0,
        is_fresh_mask: false,
        is_retry: false,
        unresolved_tokens: unresolved,
        payload_bytes: payload.len(),
        direction,
    }
}

/// Runs detection+masking for a payload with no existing store entry and persists the result.
async fn process_fresh_mask(
    state: &Arc<AppState>,
    sys: &SystemConfig,
    key: &str,
    payload: &str,
    deadline: Duration,
    inline_max: usize,
) -> Result<ProcessOutcome, Box<Response>> {
    let st = state.clone();
    let sys2 = sys.clone();
    let key2 = key.to_string();
    let payload2 = payload.to_string();
    let (text, et) = run_detection(state, payload.len(), inline_max, deadline, move || {
        let cfg = st.config.load();
        let registry = st.registry.load();
        let detector = st.detector.load();
        let entities = detector.detect(&payload2, &detect_options(&sys2));
        let res = mask_with(&payload2, &entities, &registry, &mask_options(&sys2), numbering(&sys2));
        let original_hash = hash_id(&payload2);
        st.store.insert_with_hash(&key2, res.text.clone(), res.mappings.clone(), original_hash);
        let mut et = HashMap::new();
        for e in &entities {
            *et.entry(e.type_id.clone()).or_insert(0) += 1;
        }
        (res.text, et)
    })
    .await?;
    let entity_count: usize = et.values().sum();
    Ok(ProcessOutcome {
        resp: ProcessResponse { result: text },
        entity_types: et,
        entity_count,
        is_fresh_mask: true,
        is_retry: false,
        unresolved_tokens: 0,
        payload_bytes: payload.len(),
        direction: Direction::Mask,
    })
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
    let inline_max = cfg.server.inline_max_bytes;
    let result = mask_inner(&state, &sys, &body, deadline, inline_max).await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(resp) => finish_response(&rid, &sys, Direction::Mask, latency, 200, &HashMap::new(), Json(resp).into_response()),
        Err(resp) => {
            let status = resp.status();
            finish_response(&rid, &sys, Direction::Mask, latency, status.as_u16(), &HashMap::new(), *resp)
        }
    }
}

/// Parses the /v1/mask body, runs detection+masking (stateful or stateless) and persists mappings.
async fn mask_inner(
    state: &Arc<AppState>,
    sys: &SystemConfig,
    body: &axum::body::Bytes,
    deadline: Duration,
    inline_max: usize,
) -> Result<MaskResponse, Box<Response>> {
    let req: MaskRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return Err(Box::new(error_response(StatusCode::BAD_REQUEST, "invalid json", "bad_request"))),
    };
    let session_id = match req.session_id {
        Some(s) if !s.is_empty() => s,
        _ => new_session_id(),
    };
    let existing = if sys.session_mode == crate::config::SessionMode::Stateful {
        state.store.get(&store_key(&sys.id, &session_id))
    } else {
        None
    };
    let seed: Vec<crate::types::Mapping> = existing
        .as_ref()
        .map(|e| e.mappings.clone())
        .unwrap_or_default();
    let st = state.clone();
    let sys2 = sys.clone();
    let session_id2 = session_id.clone();
    let text2 = req.text.clone();
    let seed2 = seed.clone();
    let res = run_detection(state, req.text.len(), inline_max, deadline, move || {
        let cfg = st.config.load();
        let registry = st.registry.load();
        let detector = st.detector.load();
        mask_with_seed(
            &text2,
            &detector.detect(&text2, &detect_options(&sys2)),
            &registry,
            &mask_options(&sys2),
            numbering(&sys2),
            &seed2,
        )
    })
    .await?;
    let mut merged = seed;
    for m in &res.mappings {
        if !merged.iter().any(|x| x.masked == m.masked) {
            merged.push(m.clone());
        }
    }
    state.store.insert_with_hash(&store_key(&sys.id, &session_id), res.text.clone(), merged, hash_id(&req.text));
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
        let text_len = req.text.len();
        match state.store.get(&store_key(&sys.id, &req.session_id)) {
            Some(entry) => {
                let restored = unmask(&req.text, &entry.mappings);
                let unresolved = count_unresolved_tokens(&req.text, &entry.mappings);
                Ok((false, unresolved, text_len, UnmaskResponse { text: restored }))
            }
            None => Ok((true, 0, text_len, UnmaskResponse { text: req.text })),
        }
    })
    .await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok((not_found, unresolved, text_len, resp))) => {
            record_metrics(&sys.id, Direction::Unmask, 200, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Unmask, "", &HashMap::new(), latency, 200);
            record_payload_bytes(&sys.id, Direction::Unmask, text_len);
            record_unresolved(&sys.id, unresolved);
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
    let inline_max = cfg.server.inline_max_bytes;
    let result = async {
        let req: DetectRequest = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(_) => return Err(Box::new(error_response(StatusCode::BAD_REQUEST, "invalid json", "bad_request"))),
        };
        let st = state.clone();
        let sys2 = sys.clone();
        let text2 = req.text.clone();
        let entities = run_detection(&state, req.text.len(), inline_max, deadline, move || {
            let cfg = st.config.load();
            let detector = st.detector.load();
            detector.detect(&text2, &detect_options(&sys2))
        })
        .await?;
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
    }
    .await;

    let latency = started.elapsed().as_millis() as u64;
    match result {
        Ok(resp) => {
            record_metrics(&sys.id, Direction::Mask, 200, latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, 200);
            let mut resp = Json(resp).into_response();
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
        Err(resp) => {
            let status = resp.status();
            record_metrics(&sys.id, Direction::Mask, status.as_u16(), latency, &HashMap::new());
            log_request(&rid, &sys.id, Direction::Mask, "", &HashMap::new(), latency, status.as_u16());
            let mut resp = *resp;
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp
        }
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// OpenAI-compatible chat completions proxy: masks request messages, forwards to the upstream LLM
/// (or demo mode), unmasks the model reply and returns it as JSON or SSE.
async fn chat_completions_handler(
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
    let llm_cfg = cfg.llm.clone().unwrap_or_default();

    let req: crate::llm::ChatRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid json", "bad_request"),
    };
    let want_stream = req.stream.unwrap_or(false);

    let masked = mask_chat_request(&state, &sys, &req, &rid);
    let upstream_body = build_upstream_body(&body, &masked, &req);

    let api_key = llm_cfg
        .api_key_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok())
        .filter(|k| !k.is_empty());

    let upstream_result = match &llm_cfg.upstream_url {
        Some(url) => {
            crate::llm::call_upstream(
                url,
                api_key.as_deref(),
                upstream_body,
                Duration::from_millis(llm_cfg.timeout_ms),
            )
            .await
        }
        None => Ok(crate::llm::demo_response(&masked.mappings)),
    };

    let (status, model_text) = match upstream_result {
        Ok(text) => (200, text),
        Err(_) => {
            let latency = started.elapsed().as_millis() as u64;
            log_request(&rid, &sys.id, Direction::Mask, "", &masked.entity_types, latency, 502);
            let mut resp = error_response(StatusCode::BAD_GATEWAY, "upstream error", "upstream");
            resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
            resp.headers_mut()
                .insert("x-detox-masked-entities", masked.entity_count.to_string().parse().unwrap());
            return resp;
        }
    };

    let restored = unmask(&model_text, &masked.mappings);
    let model = req.model.clone().unwrap_or_default();

    let mut resp = build_chat_response(want_stream, &rid, model, restored);
    resp.headers_mut().insert("x-request-id", rid.parse().unwrap());
    resp.headers_mut()
        .insert("x-detox-masked-entities", masked.entity_count.to_string().parse().unwrap());

    let latency = started.elapsed().as_millis() as u64;
    log_request(&rid, &sys.id, Direction::Mask, "", &masked.entity_types, latency, status);
    resp
}

/// Masks all chat messages, persists the shared mapping table and returns the masked result.
fn mask_chat_request(
    state: &Arc<AppState>,
    sys: &SystemConfig,
    req: &crate::llm::ChatRequest,
    rid: &str,
) -> crate::llm::MaskedMessages {
    let registry = state.registry.load();
    let detector = state.detector.load();
    let masked = crate::llm::mask_messages(
        &req.messages,
        &detector,
        &registry,
        &detect_options(sys),
        &mask_options(sys),
        &numbering(sys),
    );
    let store_key = store_key(&sys.id, &format!("chat:{}", rid));
    state.store.insert(&store_key, String::new(), masked.mappings.clone());
    masked
}

/// Replaces `messages` and forces `stream: true` in the upstream body.
fn build_upstream_body(
    body: &axum::body::Bytes,
    masked: &crate::llm::MaskedMessages,
    req: &crate::llm::ChatRequest,
) -> Value {
    let mut upstream_body = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut upstream_body {
        let msgs: Vec<Value> = masked
            .texts
            .iter()
            .zip(req.messages.iter())
            .map(|(t, m)| serde_json::json!({ "role": m.role, "content": t }))
            .collect();
        map.insert("messages".to_string(), Value::Array(msgs));
        map.insert("stream".to_string(), Value::Bool(true));
    }
    upstream_body
}

/// Builds the client response as SSE (streaming) or JSON (non-streaming).
fn build_chat_response(want_stream: bool, rid: &str, model: String, restored: String) -> Response {
    if want_stream {
        let chunk = serde_json::json!({
            "id": rid,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{
                "index": 0,
                "delta": { "role": "assistant", "content": restored },
                "finish_reason": null
            }]
        });
        let sse = format!("data: {}\n\ndata: [DONE]\n\n", chunk);
        let mut r = Response::new(Body::from(sse));
        r.headers_mut().insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
        r.headers_mut().insert("cache-control", "no-cache".parse().unwrap());
        r.headers_mut().insert("x-accel-buffering", "no".parse().unwrap());
        r
    } else {
        let json = crate::llm::ChatCompletionResponse {
            id: rid.to_string(),
            object: "chat.completion",
            model,
            choices: vec![crate::llm::Choice {
                index: 0,
                message: crate::llm::Message {
                    role: "assistant",
                    content: restored,
                },
                finish_reason: "stop",
            }],
        };
        Json(json).into_response()
    }
}

async fn readyz(State(state): State<Arc<AppState>>) -> StatusCode {
    let cfg = state.config.load();
    if cfg.systems.is_empty() || state.registry.load().types().is_empty() {
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

/// Re-reads config.yaml, pii_types.yaml, allowlist.yaml and dictionaries; validates and swaps
/// the config, registry and detector snapshots. On any error the previous state is kept.
fn reload_config(state: &Arc<AppState>) -> Result<u64, String> {
    let text = std::fs::read_to_string(&state.config_path).map_err(|e| format!("read config: {e}"))?;
    let cfg = crate::config::Config::from_yaml(&text).map_err(|e| format!("parse config: {e}"))?;
    cfg.validate().map_err(|e| format!("validate config: {e}"))?;

    let pii_types = std::fs::read_to_string(&cfg.pii_types_file).map_err(|e| format!("read pii_types: {e}"))?;
    let registry = Arc::new(crate::registry::Registry::from_yaml(&pii_types).map_err(|e| format!("parse registry: {e}"))?);

    let dicts = match &cfg.dictionaries_dir {
        Some(dir) if std::path::Path::new(dir).exists() => {
            Arc::new(crate::detect::Dictionaries::load_dir(std::path::Path::new(dir)).map_err(|e| format!("load dicts: {e}"))?)
        }
        _ => Arc::new(crate::detect::Dictionaries::empty()),
    };
    let allowlist_text = std::fs::read_to_string(&cfg.allowlist_file).map_err(|e| format!("read allowlist: {e}"))?;
    let allowlist = crate::detect::Allowlist::from_yaml(&allowlist_text).map_err(|e| format!("parse allowlist: {e}"))?;
    let detector = crate::detect::Detector::with_allowlist(registry.clone(), dicts, allowlist)
        .with_historical_date_years(cfg.server.historical_date_years);

    let version = cfg.version;
    state.config.replace(cfg).map_err(|e| format!("replace config: {e}"))?;
    state.registry.store(registry);
    state.detector.store(Arc::new(detector));
    Ok(version)
}

async fn reload_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let token = match std::env::var("DETOX_ADMIN_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let provided = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != token {
        return StatusCode::FORBIDDEN.into_response();
    }
    match reload_config(&state) {
        Ok(version) => {
            metrics::counter!("pii_config_reloads_total", "result" => "ok").increment(1);
            Json(serde_json::json!({ "version": version })).into_response()
        }
        Err(e) => {
            metrics::counter!("pii_config_reloads_total", "result" => "error").increment(1);
            error_response(StatusCode::BAD_REQUEST, &e, "reload_error")
        }
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/process", post(process_handler))
        .route("/v1/mask", post(mask_handler))
        .route("/v1/unmask", post(unmask_handler))
        .route("/v1/detect", post(detect_handler))
        .route("/v1/chat/completions", post(chat_completions_handler))
        .route("/admin/reload", post(reload_handler))
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

    let cfg = load_config(&config_path)?;
    let store = crate::store::MappingStore::new(
        Duration::from_secs(cfg.server.mapping_ttl_sec),
        cfg.server.mapping_max_entries,
    );

    let state = Arc::new(AppState {
        config: crate::config::ConfigStore::new(cfg.clone()),
        registry: ArcSwap::from(load_registry(&cfg)?),
        detector: ArcSwap::from_pointee(load_detector(&cfg)?),
        store,
        metrics,
        inflight: Arc::new(tokio::sync::Semaphore::new(cfg.server.max_inflight)),
        heavy: Arc::new(tokio::sync::Semaphore::new(cfg.server.heavy_max_concurrency)),
        config_path: config_path.clone(),
    });

    spawn_background_tasks(&state);

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

/// Reads and validates the config file.
fn load_config(config_path: &std::path::Path) -> anyhow::Result<crate::config::Config> {
    let text = std::fs::read_to_string(config_path)?;
    let cfg = crate::config::Config::from_yaml(&text)?;
    cfg.validate()?;
    Ok(cfg)
}

/// Loads the PII registry from the configured types file.
fn load_registry(cfg: &crate::config::Config) -> anyhow::Result<Arc<Registry>> {
    let pii_types = std::fs::read_to_string(&cfg.pii_types_file)?;
    Ok(Arc::new(crate::registry::Registry::from_yaml(&pii_types)?))
}

/// Loads dictionaries, allowlist and builds the detector.
fn load_detector(cfg: &crate::config::Config) -> anyhow::Result<crate::detect::Detector> {
    let registry = load_registry(cfg)?;
    let dicts = match &cfg.dictionaries_dir {
        Some(dir) if std::path::Path::new(dir).exists() => {
            Arc::new(crate::detect::Dictionaries::load_dir(std::path::Path::new(dir))?)
        }
        _ => Arc::new(crate::detect::Dictionaries::empty()),
    };
    let allowlist_text = std::fs::read_to_string(&cfg.allowlist_file)?;
    let allowlist = crate::detect::Allowlist::from_yaml(&allowlist_text)?;
    Ok(crate::detect::Detector::with_allowlist(registry, dicts, allowlist)
        .with_historical_date_years(cfg.server.historical_date_years))
}

/// Spawns the SIGHUP reload loop and the periodic store sweep.
fn spawn_background_tasks(state: &Arc<AppState>) {
    #[cfg(unix)]
    {
        let reload_state = state.clone();
        tokio::spawn(async move {
            let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGHUP handler");
                    return;
                }
            };
            loop {
                sig.recv().await;
                match reload_config(&reload_state) {
                    Ok(version) => {
                        metrics::counter!("pii_config_reloads_total", "result" => "ok").increment(1);
                        tracing::info!(version = version, "config reloaded via SIGHUP");
                    }
                    Err(e) => {
                        metrics::counter!("pii_config_reloads_total", "result" => "error").increment(1);
                        tracing::error!(error = %e, "config reload via SIGHUP failed");
                    }
                }
            }
        });
    }

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