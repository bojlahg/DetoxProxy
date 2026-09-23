use std::collections::HashMap;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detox: Option<DetoxDebug>,
}

/// Debug view of the masking chain, returned only when the client sends `X-Detox-Debug: 1`.
/// Contains only masked texts and the raw model output — never original PII values.
#[derive(Debug, Serialize)]
pub struct DetoxDebug {
    pub masked_messages: Vec<MaskedMessage>,
    pub upstream_messages: Vec<MaskedMessage>,
    pub model_output: String,
}

#[derive(Debug, Serialize)]
pub struct MaskedMessage {
    pub role: String,
    pub content: String,
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

/// Matches a token mapping value of the form `<<LABEL_N>>` where N is a sequential number or a
/// hex hash suffix (hash numbering).
static TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^<<([A-Za-z_]+)_([0-9a-f]+)>>$").expect("valid token regex"));

/// Appends a grammatical-case suffix to a token, producing `<<LABEL_N:case>>`.
fn token_with_case(token: &str, case: &str) -> String {
    let trimmed = token.trim_end_matches('>');
    format!("{}:{}>>", trimmed, case)
}

/// Short Russian display names for PII types, used in the demo response. Unknown types fall back
/// to the bare token.
fn type_display_name(type_id: &str) -> Option<&'static str> {
    Some(match type_id {
        "fio" => "ФИО",
        "birth_date" => "дата рождения",
        "birth_place" => "место рождения",
        "citizenship" => "гражданство",
        "passport" => "паспорт",
        "passport_issuer" => "кем выдан",
        "passport_issue_date" => "дата выдачи",
        "subdivision_code" => "код подразделения",
        "driver_license" => "водительское удостоверение",
        "snils" => "СНИЛС",
        "inn" => "ИНН",
        "phone" => "телефон",
        "email" => "email",
        "address" => "адрес",
        "card_number" => "карта",
        "cvv" => "CVV",
        "card_pin" => "PIN",
        "card_holder" => "держатель карты",
        _ => return None,
    })
}

/// Builds the demo-mode model text from the token mappings so that restoration is visible on
/// every masked type. Only token entries (`<<LABEL_N>>`) are referenced; the type display name
/// comes from `type_display_name`, otherwise the bare token is used.
pub fn demo_response(mappings: &[Mapping]) -> String {
    let mut fio: Option<String> = None;
    let mut others: Vec<(String, String)> = Vec::new();
    for m in mappings {
        let Some(caps) = TOKEN_RE.captures(&m.masked) else { continue };
        let token = format!("<<{}_{}>>", &caps[1], &caps[2]);
        if m.type_id == "fio" {
            if fio.is_none() {
                fio = Some(token);
            }
        } else {
            let name = type_display_name(&m.type_id).unwrap_or("").to_string();
            others.push((name, token));
        }
    }

    let mut out = String::new();
    match &fio {
        Some(t) => out.push_str(&format!("Уважаемый {}!", token_with_case(t, "им"))),
        None => out.push_str("Здравствуйте!"),
    }
    out.push_str(" Ваше обращение рассмотрено.");
    if !others.is_empty() {
        out.push_str(" Проверены данные: ");
        let parts: Vec<String> = others
            .iter()
            .map(|(n, t)| {
                if n.is_empty() {
                    t.clone()
                } else {
                    format!("{} {}", n, t)
                }
            })
            .collect();
        out.push_str(&parts.join(", "));
        out.push('.');
    }
    if let Some(t) = &fio {
        out.push_str(&format!(" Копия письма направлена {}.", token_with_case(t, "дат")));
    }
    out
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