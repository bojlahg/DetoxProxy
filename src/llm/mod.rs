use std::collections::HashMap;
use std::time::Duration;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detect::{DetectOptions, Detector};
use crate::mask::{mask_with_seed, MaskOptions, Numbering};
use crate::registry::Registry;
use crate::types::Mapping;

/// One chat message as sent by the client. `content` is a plain string.
#[derive(Debug, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Minimal OpenAI-compatible chat request. Unknown fields are ignored; the original body is
/// forwarded upstream with only `messages` and `stream` replaced.
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub stream: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: &'static str,
    pub model: String,
    pub choices: Vec<Choice>,
}

#[derive(Debug, Serialize)]
pub struct Choice {
    pub index: u32,
    pub message: Message,
    pub finish_reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub role: &'static str,
    pub content: String,
}

/// Result of masking all messages of one request with a single shared mapping table.
pub struct MaskedMessages {
    /// Masked content of each message, in order.
    pub texts: Vec<String>,
    /// Shared mapping table across all messages.
    pub mappings: Vec<Mapping>,
    /// Entity counts by type (only masked entities).
    pub entity_types: HashMap<String, usize>,
    /// Total number of masked entities.
    pub entity_count: usize,
}

/// Masks every message's content, reusing one mapping table so identical values across messages
/// share a single token. Sequential numbering continues across messages.
pub fn mask_messages(
    messages: &[ChatMessage],
    detector: &Detector,
    registry: &Registry,
    detect_opts: &DetectOptions<'_>,
    mask_opts: &MaskOptions<'_>,
    numbering: &Numbering,
) -> MaskedMessages {
    let mut seed: Vec<Mapping> = Vec::new();
    let mut texts = Vec::with_capacity(messages.len());
    let mut entity_types: HashMap<String, usize> = HashMap::new();
    for msg in messages {
        let entities = detector.detect(&msg.content, detect_opts);
        let res = mask_with_seed(&msg.content, &entities, registry, mask_opts, numbering.clone(), &seed);
        for m in &res.mappings {
            if !seed.iter().any(|x| x.masked == m.masked) {
                seed.push(m.clone());
            }
        }
        for e in &res.entities {
            *entity_types.entry(e.type_id.clone()).or_insert(0) += 1;
        }
        texts.push(res.text);
    }
    let entity_count: usize = entity_types.values().sum();
    MaskedMessages {
        texts,
        mappings: seed,
        entity_types,
        entity_count,
    }
}

/// Collects the assistant text from an SSE body: concatenates `choices[0].delta.content` from
/// every `data: {...}` / `data:{...}` event, skipping `data: [DONE]`.
pub fn collect_sse_text(body: &str) -> String {
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("data:") {
            Some(r) => r.trim(),
            None => continue,
        };
        if rest == "[DONE]" {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(rest) {
            if let Some(content) = v["choices"][0]["delta"]["content"].as_str() {
                out.push_str(content);
            }
        }
    }
    out
}

/// Builds the demo-mode model text: a fixed prefix followed by every token from the request.
pub fn demo_response(mappings: &[Mapping]) -> String {
    let mut tokens: Vec<String> = mappings.iter().map(|m| m.masked.clone()).collect();
    tokens.sort();
    tokens.dedup();
    format!("Принято. Запрос по клиенту обработан: {}", tokens.join(", "))
}

/// Classification of an upstream failure. Never carries upstream body text.
#[derive(Debug)]
pub enum UpstreamError {
    Timeout,
    Status(u16),
    Transport,
}

/// Shared HTTP client for upstream LLM calls. One per process.
static CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .pool_max_idle_per_host(512)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("build reqwest client")
});

/// Sends the masked body to the upstream endpoint and returns the raw SSE body text.
/// The API key is read from the environment and never logged.
pub async fn call_upstream(
    url: &str,
    api_key: Option<&str>,
    body: Value,
    timeout: Duration,
) -> Result<String, UpstreamError> {
    let mut req = CLIENT.post(url).json(&body);
    if let Some(key) = api_key {
        req = req.header("authorization", format!("Bearer {}", key));
    }
    let resp = tokio::time::timeout(timeout, req.send())
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(|_| UpstreamError::Transport)?;
    let status = resp.status();
    if !status.is_success() {
        return Err(UpstreamError::Status(status.as_u16()));
    }
    let text = tokio::time::timeout(timeout, resp.text())
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(|_| UpstreamError::Transport)?;
    Ok(text)
}