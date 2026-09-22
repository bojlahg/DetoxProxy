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
<task id="T02">
  <goal>Реестр типов ПДн из YAML и детекторы структурированных типов с валидацией: карта, ИНН, СНИЛС, телефон, email, паспорт, код подразделения, водительское удостоверение, CVV, ПИН. Детектор возвращает корректные байтовые спаны, не учитывает регистр, разрешает пересечения.</goal>
  <context>docs/agent-kit/SPEC.md §4, §5 (пункт про confidence), §10. Сигнатуры в src/registry/mod.rs и src/detect/mod.rs уже заданы — реализуй тела, не меняя их. AGENTS.md, блок pii_rules.</context>
  <files_allowed>src/registry/mod.rs, src/detect/mod.rs, data/pii_types.yaml, tests/registry.rs, tests/detect_structured.rs</files_allowed>
  <requirements>
    1. Registry::from_yaml разбирает YAML вида `types: [TypeSpec, ...]`, проверяет уникальность id, компилирует каждый pattern через `regex::RegexBuilder::new(p).case_insensitive(true).unicode(true).build()`; ошибка компиляции — RegistryError::Regex с id типа. Registry::patterns возвращает пустой срез для неизвестного id.
    2. data/pii_types.yaml — реестр со всеми 17 типами из SPEC §4 плюс snils. Рабочие patterns в этой задаче нужны для: card_number, inn, snils, phone, email, passport, subdivision_code, driver_license, cvv, card_pin. Для fio, birth_date, birth_place, citizenship, passport_issuer, passport_issue_date, address, card_holder — запись с id, name, token_label, context_words и пустым patterns (детекция — T05). Комментарии в YAML на английском.
    3. Шаблоны (регистронезависимые, unicode) и обязательные вариации:
       - card_number: 13–19 цифр группами по 4 через пробел, дефис или слитно; validator luhn; stars_keep_prefix 4, stars_keep_suffix 4; token_label CARD.
       - inn: 10 или 12 цифр как отдельное слово (с обеих сторон не цифра); validator inn (контрольные разряды ФНС для 10 и 12 знаков); context_words [инн]; token_label INN.
       - snils: `NNN-NNN-NNN NN` и 11 цифр слитно; validator snils; token_label SNILS.
       - phone: `+7`, `8` или `7` и 10 цифр с любыми разделителями (пробел, дефис, скобки, точка), а также 10 цифр с кодом в скобках без префикса; validator phone (после удаления нецифр: 11 цифр с первой 7 или 8, либо 10 цифр с первой 9, 4 или 8); token_label PHONE; stars_keep_prefix 2, stars_keep_suffix 2.
       - email: локальная часть из букв, цифр, точек, плюсов, дефисов, подчёркиваний; `@`; домен с хотя бы одной точкой; validator email; token_label EMAIL.
       - passport: `NNNN NNNNNN`, `NN NN NNNNNN`, `NNNNNNNNNN`, а также с разделяющими словами: «серия NNNN номер NNNNNN», «серия: NNNN, номер: NNNNNN», «паспорт NNNN NNNNNN». Спан начинается на первой цифре серии и заканчивается на последней цифре номера; слово «номер» между ними входит в спан, слова «серия» и «паспорт» перед серией — нет. context_words [паспорт, серия, номер, паспортные данные]; token_label PASSPORT; stars_keep_prefix 2, stars_keep_suffix 2.
       - subdivision_code: `NNN-NNN`; context_required true; context_words [код подразделения, к/п, подразделения]; token_label SUBDIV.
       - driver_license: `NN NN NNNNNN`, `NNNN NNNNNN`, `NN AA NNNNNN` (AA — две кириллические буквы) с разделителями; context_required true; context_words [в/у, ву, водительское, удостоверение, права]; token_label DRIVER_LICENSE.
       - cvv: 3–4 цифры как отдельное слово; context_required true; context_words [cvv, cvc, cvv2, cvc2, код безопасности, защитный код]; requires_companion true; token_label CVV.
       - card_pin: 4 цифры как отдельное слово; context_required true; context_words [пин, pin, пин-код, pin-код]; requires_companion true; token_label PIN.
    4. Detector::detect:
       - для каждого включённого типа прогоняет все patterns; кандидат получает confidence 0.6; если validator не None и прошёл — плюс 0.3, если validator задан и не прошёл — кандидат отбрасывается; если в окне context_window символов (считать по char, не по байтам) перед началом спана есть context_word (в нижнем регистре) — плюс 0.1; если context_required и контекстного слова нет — отбрасывается; итог не больше 1.0;
       - отбрасывает кандидатов с confidence меньше opts.min_confidence и кандидатов, чей текст спана входит как подстрока в любую строку из opts.allow_substrings (без учёта регистра);
       - убирает пересечения: сортировка по start, при пересечении побеждает более длинный, при равной длине — более уверенный;
       - start и end — байтовые смещения в исходной строке; гарантируется, что оба — границы символов;
       - регистр не влияет: «ИНН 7707083893» и «инн 7707083893» дают одинаковый спан.
    5. validators: luhn (стандарт, вход — только цифры); inn (10 знаков: коэффициенты 2,4,10,3,5,9,4,6,8; 12 знаков: первый контрольный с 7,2,4,10,3,5,9,4,6,8 и второй с 3,7,2,4,10,3,5,9,4,6,8; сумма mod 11 mod 10); snils (сумма первых 9 цифр с весами 9..1; если сумма меньше 100 — контроль равен сумме; 100 или 101 — контроль 00; больше 101 — сумма mod 101, и 100 даёт 00); phone; email. date в этой задаче остаётся todo!() и не вызывается.
    6. Dictionaries::empty, load_dir (каждый файл `*.txt` в каталоге — список слов по строкам, имя списка равно имени файла без расширения, слова в нижний регистр, пустые строки и строки с # пропускаются), contains. В этой задаче детектор словари не использует.
    7. Производительность: регулярки компилируются в Registry один раз; detect не создаёт Regex. Тест: 1000 вызовов detect на предложении из 200 символов со всеми типами укладываются в 2 с в debug-сборке.
  </requirements>
  <tests>
    tests/registry.rs: from_yaml на data/pii_types.yaml даёт не меньше 18 типов; дубль id даёт Duplicate; битая регулярка даёт Regex с нужным id; patterns("unknown") пуст.
    tests/detect_structured.rs — табличные; каждый случай задаёт текст, ожидаемый type_id и ожидаемый точный текст спана, извлечённый по байтовым смещениям:
      - карта: валидный по Luhn номер в трёх написаниях (с пробелами, с дефисами, слитно), например 4276 3800 1234 5674 если проходит Luhn — иначе подобрать; невалидный по Luhn номер не находится;
      - ИНН: валидные 10- и 12-значные (например 7707083893 — проверить), невалидный не находится; «ИНН 7707083893» и «инн 7707083893» дают одинаковый спан;
      - СНИЛС: с разделителями и слитно, контрольная сумма проверена;
      - телефон: «+7 (912) 345-67-89», «8-912-345-67-89», «89123456789», «+7 912 345 67 89», «(912) 345-67-89»; «12345» не находится;
      - email: «ivan.petrov@mail.ru», «IVAN@EXAMPLE.COM», «a+b@sub.domain.org»;
      - паспорт: «паспорт 4509 123456» даёт спан «4509 123456»; «серия 4509 номер 123456» даёт спан «4509 номер 123456»; «серия: 45 09, номер: 123456»; «4509123456» с контекстом «паспорт»;
      - код подразделения: «код подразделения 770-001» даёт «770-001»; «770-001» без контекста не находится;
      - ВУ: «в/у 77 12 345678», «водительское удостоверение 7712 345678»; без контекста не находится;
      - CVV и PIN: «CVV 123» даёт cvv; «пин-код 1234» даёт card_pin; «123» без контекста не находится;
      - пересечение: «карта 4276380012345678» не даёт inn или phone на подстроках номера;
      - UTF-8: «Клиент Иванов, тел. +7 912 345-67-89, email ivan@mail.ru» — все спаны на границах символов, извлечённые подстроки точны;
      - allow_substrings: при «8 800 555-35-35» в allow-списке этот телефон не находится;
      - min_confidence 0.95 отсекает кандидатов без валидатора.
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test --test registry --test detect_structured</acceptance>
  <out_of_scope>ФИО, даты, адреса, гражданство, орган выдачи (T05). Маскирование (T03). HTTP (T04).</out_of_scope>
</task>
<task id="T03">
  <goal>Маскирование и демаскирование: режимы token/stars/synthetic/remove, стабильные токены <<LABEL_N>>, точное восстановление в любом окружении, хранилище соответствий с TTL. Плюс привести метки токенов в data/pii_types.yaml к SPEC.</goal>
  <context>docs/agent-kit/SPEC.md §1, §4 (таблица меток), §6, §7, §3. Сигнатуры в src/mask/mod.rs и src/store/mod.rs заданы в T01 — реализуй тела, не меняя их. AGENTS.md, блок pii_rules.</context>
  <files_allowed>src/mask/mod.rs, src/store/mod.rs, data/pii_types.yaml, tests/mask.rs, tests/store.rs</files_allowed>
  <requirements>
    1. data/pii_types.yaml: token_label по таблице SPEC §4 — FIO, BDATE, BPLACE, PASSPORT, CITIZEN, PASSISS, SUBDIV, ISSDATE, DRIVLIC, ADDR, EMAIL, PHONE, INN, CARD, CVV, PIN, CARDHLD, SNILS. Ничего другого в YAML не менять.
    2. mask(): формат токена `<<LABEL_N>>` (два символа «меньше», метка, подчёркивание, номер, два символа «больше»). Нумерация с 1 отдельно по каждому типу в пределах одного вызова, в порядке первого появления в тексте. Одинаковый исходный текст спана одного типа (сравнение без учёта регистра и после схлопывания пробелов) получает один и тот же токен. Замены применяются справа налево по байтовым позициям сущностей, чтобы смещения оставались верными. Результат детерминирован.
    3. Режим для сущности: opts.overrides[type_id], иначе режим из TypeSpec.mask если он не Token, иначе opts.default_mode. Off — сущность не маскируется и в mappings не попадает. Remove — замена на «[removed]».
    4. combination_rule: если true, сущности типов с requires_companion маскируются только когда среди сущностей есть хотя бы одна другого типа с confidence не ниже 0.9; иначе пропускаются. Если false — маскируются всегда.
    5. stars(): сохраняет длину и разделители (пробел, дефис, точка, скобки, плюс, @, слэш), заменяет остальные символы на «*», кроме первых keep_prefix и последних keep_suffix значащих символов (считать по char). Для type_id == "fio": инициалы каждого слова с точкой через пробел («Иванов Иван Иванович» → «И. И. И.»). Для email: keep_prefix символов локальной части, домен целиком («ivan.petrov@mail.ru» при keep_prefix 1 → «i**********@mail.ru»). Примеры: паспорт «4509 123456» keep 2/2 → «45** ****56»; телефон «+7 (912) 345-67-89» keep 2/2 → «+7 (***) ***-**-89».
    6. synthetic: замена того же типа и похожей формы — для fio случайное ФИО из фиксированного встроенного списка из 20 русских ФИО, для card валидный по Luhn 16-значный номер с тем же форматом разделителей, для phone случайный номер с тем же форматом, для email случайная локальная часть с тем же доменом, для остальных — цифры заменяются случайными той же длины с сохранением разделителей. Одинаковые исходные значения получают одну и ту же замену в пределах вызова.
    7. Каждая замена пишется в MaskResult.mappings как Mapping { type_id, original (точный исходный спан), masked (что подставлено) }; для повторов одного значения — одна запись. MaskResult.entities — входные сущности (без Off и без отсеянных правилом комбинаций).
    8. unmask(): токены ищутся регуляркой без учёта регистра с допуском пробелов внутри скобок (`<< fio_1 >>` тоже находится); каждый найденный токен заменяется original из mappings по точному совпадению masked (сравнение без регистра и пробелов). Токены без соответствия остаются как есть. Для нетокенных масок (stars/synthetic/remove) — поиск masked как подстроки, сначала более длинные, чтобы короткая маска не заменила часть длинной. Работает на любом тексте: другой порядок, часть токенов, токены внутри кавычек, SQL, JSON.
    9. MappingStore: DashMap; insert перезаписывает; get возвращает клон и не продлевает TTL; get на просроченной записи возвращает None; sweep удаляет просроченные и возвращает число удалённых; при превышении max_entries insert сначала вызывает sweep, если всё ещё переполнено — удаляет самые старые записи (по created_at) до max_entries - 1. len/is_empty.
  </requirements>
  <tests>
    tests/mask.rs (Registry из data/pii_types.yaml, сущности задавать вручную по байтовым смещениям, проверять точные строки):
      - «Клиент Иванов Иван Иванович, ИНН 7707083893, тел. +7 912 345-67-89. Иванов Иван Иванович просил перезвонить.» → «Клиент <<FIO_1>>, ИНН <<INN_1>>, тел. <<PHONE_1>>. <<FIO_1>> просил перезвонить.» (одно ФИО дважды — один токен); mappings ровно 3 записи;
      - два разных ИНН → <<INN_1>> и <<INN_2>> в порядке появления;
      - round-trip: для 10 разных текстов (включая кириллицу, эмодзи, переводы строк, JSON с ПДн внутри строк) unmask(mask(x).text, mappings) == x побайтово;
      - демаскирование в другом окружении: маска «Клиент <<FIO_1>>, ИНН <<INN_1>>», ответ LLM «SELECT * FROM users WHERE inn = '<<INN_1>>' AND name = "<<fio_1>>"; -- <<INN_1>>» → все три токена заменены, регистр токена не мешает;
      - неизвестный токен <<CARD_9>> остаётся как есть;
      - stars: паспорт, телефон, email, ФИО по примерам из требования 5; unmask по stars восстанавливает исходное;
      - synthetic: карта проходит Luhn и не равна исходной; формат разделителей сохранён; одинаковые входы дают одинаковую замену; unmask восстанавливает;
      - overrides: default token, override cvv → stars — CVV замаскирован звёздочками, остальное токенами;
      - Off: тип не изменён и не в mappings;
      - combination_rule true: текст с одним card_pin без карты — не маскируется; с card_pin и валидной картой — маскируются оба; при false — pin маскируется всегда;
      - смещения: сущность с не-ASCII текстом до и после — результат точен, паника отсутствует.
    tests/store.rs: insert/get; get после TTL (ttl 50 ms, sleep 80 ms) → None; sweep возвращает число удалённых; max_entries 3 и 5 insert → len не больше 3, самые новые сохранены; is_empty.
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test --test mask --test store --test detect_structured --test registry</acceptance>
  <out_of_scope>HTTP и /process (T04). Детекция ФИО/дат/адресов (T05). Изменение сигнатур.</out_of_scope>
</task>
