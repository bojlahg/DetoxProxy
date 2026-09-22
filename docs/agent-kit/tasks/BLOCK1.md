# Блок 1 — ядро PII-модуля (Rust)

Порядок: T01 (каркас + типы) → T02 (реестр типов и структурные детекторы) → T03 (маскирование/демаскирование + хранилище) → T04 (`/process` + HTTP) → T05 (даты, ФИО, адреса) → T06 (ловушки, комбинации, конфиг систем) → T07 (датасет + отчёт качества) → T08 (метрики, логи, 429) → T09 (LLM-прокси `/v1/chat/completions`).
Одна задача — одна сессия. Извлечь: `python docs/agent-kit/tasks/task.py T01`.

Общее: правила — `AGENTS.md`; спецификация — `docs/agent-kit/SPEC.md`; зависимости — `docs/agent-kit/Cargo.deps.toml` (добавлены `regex`, `once_cell`, `unicode-segmentation`, `rand`); образцы API — `docs/agent-kit/rust-api-cheatsheet.rs`. Бинарник `pii-guard`, запуск `pii-guard --config config.yaml`. Полная проверка: `cargo clippy --all-targets -- -D warnings && cargo test`.

<task id="T01">
  <goal>Каркас проекта pii-guard: модули, публичные типы и сигнатуры ядра с телами todo!(), проект собирается и проходит clippy.</goal>
  <context>docs/agent-kit/SPEC.md §1, §4–§7; docs/agent-kit/Cargo.deps.toml; AGENTS.md (layout). Ниже — точные типы. Копируй имена, поля, derive и сигнатуры дословно; тела — todo!().</context>
  <files_allowed>Cargo.toml, .gitignore, src/main.rs, src/lib.rs, src/types.rs, src/registry/mod.rs, src/detect/mod.rs, src/mask/mod.rs, src/store/mod.rs, src/config/mod.rs, src/server/mod.rs, src/obs/mod.rs</files_allowed>
  <requirements>
    1. Cargo.toml: package `pii-guard`, edition 2021, `[lib]` + `[[bin]]` (main.rs использует крейт как библиотеку — так интеграционные тесты видят типы). Зависимости и профиль release — из Cargo.deps.toml дословно, плюс `regex = "1"`, `once_cell = "1"`, `unicode-segmentation = "1"`, `rand = "0.8"`.
    2. src/lib.rs объявляет модули: types, registry, detect, mask, store, config, server, obs. src/main.rs: mimalloc, #[tokio::main], разбор `--config <path>` через std::env::args, вызов `server::run(config_path).await`.
    3. src/types.rs — дословно:
```rust
use serde::{Deserialize, Serialize};

/// Identifier of a PII type from the registry, e.g. "fio", "card_number".
pub type TypeId = String;

/// A detected span of personal data. Offsets are byte offsets into the original text (UTF-8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub type_id: TypeId,
    pub start: usize,
    pub end: usize,
    /// 0.0..=1.0; validator passed => >= 0.9, pattern only => ~0.6, context only => ~0.4
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaskMode { Token, Stars, Synthetic, Remove, Off }

/// One replacement performed during masking; kept in the store for unmasking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    pub type_id: TypeId,
    pub original: String,
    pub masked: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaskResult {
    pub text: String,
    pub entities: Vec<Entity>,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction { Mask, Unmask }
```
    4. src/registry/mod.rs — дословно:
```rust
use crate::types::{MaskMode, TypeId};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validator { None, Luhn, Inn, Snils, Date, Phone, Email }

/// Declarative description of one PII type. Loaded from YAML; adding a type needs no code.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeSpec {
    pub id: TypeId,
    pub name: String,
    /// Regex patterns (case-insensitive, unicode). Any match is a candidate.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Words that, when found within `context_window` chars before the candidate, raise confidence.
    #[serde(default)]
    pub context_words: Vec<String>,
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    /// If true, a match is accepted only when a context word is present.
    #[serde(default)]
    pub context_required: bool,
    #[serde(default = "default_validator")]
    pub validator: Validator,
    /// Named dictionary this type consults (e.g. "surnames"); resolved by the detector.
    #[serde(default)]
    pub dictionary: Option<String>,
    #[serde(default = "default_mask_mode")]
    pub mask: MaskMode,
    /// Token label used in `{LABEL_N}`, e.g. "FIO".
    pub token_label: String,
    /// For stars mode: how many leading/trailing chars stay visible.
    #[serde(default)]
    pub stars_keep_prefix: usize,
    #[serde(default)]
    pub stars_keep_suffix: usize,
    /// Masked only when another confidently detected type is present in the same text (cvv, pin).
    #[serde(default)]
    pub requires_companion: bool,
}
fn default_context_window() -> usize { 40 }
fn default_validator() -> Validator { Validator::None }
fn default_mask_mode() -> MaskMode { MaskMode::Token }

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("invalid regex in type {type_id}: {source}")]
    Regex { type_id: TypeId, source: regex::Error },
    #[error("duplicate type id {0}")]
    Duplicate(TypeId),
}

/// Compiled registry: specs plus compiled regexes. Immutable after build; shared via Arc.
pub struct Registry {
    specs: Vec<TypeSpec>,
    compiled: Vec<Vec<regex::Regex>>,
}

impl Registry {
    pub fn from_yaml(text: &str) -> Result<Self, RegistryError> { todo!() }
    pub fn from_specs(specs: Vec<TypeSpec>) -> Result<Self, RegistryError> { todo!() }
    pub fn types(&self) -> &[TypeSpec] { todo!() }
    pub fn get(&self, id: &str) -> Option<&TypeSpec> { todo!() }
    pub fn patterns(&self, id: &str) -> &[regex::Regex] { todo!() }
}
```
    5. src/detect/mod.rs — дословно:
```rust
use crate::{registry::Registry, types::Entity};
use std::collections::HashSet;

/// Named word lists (surnames, first names, patronymics, cities, public persons...). Lowercased.
pub struct Dictionaries {
    pub lists: std::collections::HashMap<String, HashSet<String>>,
}
impl Dictionaries {
    pub fn empty() -> Self { todo!() }
    pub fn load_dir(dir: &std::path::Path) -> std::io::Result<Self> { todo!() }
    pub fn contains(&self, list: &str, word_lower: &str) -> bool { todo!() }
}

pub struct DetectOptions<'a> {
    /// Only these type ids are detected; None = all registry types.
    pub enabled_types: Option<&'a [String]>,
    pub min_confidence: f32,
    /// Substrings that must never be reported (bank office addresses, service phones).
    pub allow_substrings: &'a [String],
}

pub struct Detector {
    registry: std::sync::Arc<Registry>,
    dicts: std::sync::Arc<Dictionaries>,
}

impl Detector {
    pub fn new(registry: std::sync::Arc<Registry>, dicts: std::sync::Arc<Dictionaries>) -> Self { todo!() }
    /// Runs all enabled types, validates, scores, drops allow-listed and overlapping spans
    /// (longer / more confident wins). Result sorted by start. Case-insensitive.
    pub fn detect(&self, text: &str, opts: &DetectOptions<'_>) -> Vec<Entity> { todo!() }
}

/// Validators are a fixed set selected by name from the registry.
pub mod validators {
    pub fn luhn(digits: &str) -> bool { todo!() }
    pub fn inn(digits: &str) -> bool { todo!() }
    pub fn snils(digits: &str) -> bool { todo!() }
    /// Accepts dd.mm.yyyy, dd/mm/yyyy, yyyy-mm-dd, mm.dd.yyyy (ambiguous both ways), and textual Russian months.
    pub fn date(s: &str) -> bool { todo!() }
    pub fn phone(s: &str) -> bool { todo!() }
    pub fn email(s: &str) -> bool { todo!() }
}
```
    6. src/mask/mod.rs — дословно:
```rust
use crate::{registry::Registry, types::{Entity, Mapping, MaskMode, MaskResult}};

pub struct MaskOptions<'a> {
    pub default_mode: MaskMode,
    /// Per-type overrides (type_id -> mode).
    pub overrides: &'a std::collections::HashMap<String, MaskMode>,
    /// Enforce `requires_companion` from the registry.
    pub combination_rule: bool,
}

/// Replaces entity spans right-to-left; identical originals of the same type share one token.
/// Deterministic for the same (text, entities, options).
pub fn mask(text: &str, entities: &[Entity], registry: &Registry, opts: &MaskOptions<'_>) -> MaskResult { todo!() }

/// Restores originals using mappings. Tokens `{LABEL_N}` are located by regex anywhere in the text
/// (any order, any surrounding); stars/synthetic masks are located as substrings, longest first.
/// Unknown tokens are left untouched.
pub fn unmask(text: &str, mappings: &[Mapping]) -> String { todo!() }

/// Renders the stars mask for a value: keeps prefix/suffix chars, keeps separators (space, '-', '.', '(', ')', '+', '@'),
/// replaces the rest with '*'. For FIO renders initials "И. И. И.".
pub fn stars(value: &str, type_id: &str, keep_prefix: usize, keep_suffix: usize) -> String { todo!() }
```
    7. src/store/mod.rs — дословно:
```rust
use crate::types::Mapping;
use std::time::Duration;

/// In-memory mapping store keyed by payload_id / session_id. TTL + max entries. Values never leave the process.
pub struct MappingStore {
    inner: dashmap::DashMap<String, StoredEntry>,
    ttl: Duration,
    max_entries: usize,
}
pub struct StoredEntry {
    pub mappings: Vec<Mapping>,
    /// First masked result for this id; returned again on identical repeat (idempotency).
    pub masked_text: String,
    pub created_at: std::time::Instant,
}
impl MappingStore {
    pub fn new(ttl: Duration, max_entries: usize) -> Self { todo!() }
    pub fn insert(&self, id: &str, masked_text: String, mappings: Vec<Mapping>) { todo!() }
    pub fn get(&self, id: &str) -> Option<StoredEntry> { todo!() }
    pub fn len(&self) -> usize { todo!() }
    pub fn is_empty(&self) -> bool { todo!() }
    /// Removes expired entries; called periodically.
    pub fn sweep(&self) -> usize { todo!() }
}
```
    8. src/config/mod.rs — типы конфигурации по SPEC §8 (Config, ServerConfig, SystemConfig, UpstreamConfig; `#[serde(deny_unknown_fields)]`, длительности в `_ms`/`_sec` как целые), `ConfigStore` на `ArcSwap` с `load()` и `replace()` (валидация), `Config::from_yaml`, `Config::validate`, `Config::system(&self, id) -> Option<&SystemConfig>`. Поля `pii_types` и `allowlist` — пути к файлам (String), не `!include`.
    9. src/server/mod.rs: `pub async fn run(config_path: std::path::PathBuf) -> anyhow::Result<()>` и `pub fn build_router(state: std::sync::Arc<AppState>) -> axum::Router`, `pub struct AppState { config: ConfigStore, registry: Arc<Registry>, detector: Detector, store: MappingStore, metrics: PrometheusHandle, inflight: tokio::sync::Semaphore }`. Обработчики только объявлены (todo!()). src/obs/mod.rs: `install_metrics()`, `init_tracing()`.
    10. `#![allow(dead_code, unused_variables)]` допустим в lib.rs на этой задаче. .gitignore: target/, *.exe, *.log, __pycache__/, check-result.json.
  </requirements>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo build</acceptance>
  <out_of_scope>Реализация любой логики. Изменение сигнатур. Новые крейты сверх перечисленных.</out_of_scope>
</task>
