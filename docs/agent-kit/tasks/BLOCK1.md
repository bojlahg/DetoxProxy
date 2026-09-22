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
<task id="T04">
  <goal>HTTP-сервис pii-guard: конфигурация систем-потребителей, эндпоинт POST /process строго по контракту автопрогона (идемпотентный, маскирование по первому запросу с payload_id и демаскирование по второму), /v1/mask, /v1/unmask, /v1/detect, /healthz, /readyz, /metrics; 429 при перегрузке; ничего из ПДн в логах.</goal>
  <context>docs/agent-kit/SPEC.md §2, §3, §8, §9, §10; docs/brief/BRIEF.md раздел «Приложение A» и «Приложение B» (контракт и правила прогона). Сигнатуры config/server/obs из T01 — реализовать; AppState можно дополнить полями. docs/agent-kit/rust-api-cheatsheet.rs — образцы axum 0.8. AGENTS.md, блоки pii_rules и ownership_rules.</context>
  <files_allowed>src/config/mod.rs, src/server/mod.rs, src/obs/mod.rs, src/main.rs, src/lib.rs, src/mask/mod.rs (только замена списка синтетических ФИО), config.yaml, data/allowlist.yaml, tests/http.rs</files_allowed>
  <requirements>
    1. Конфигурация (src/config/mod.rs), YAML, `deny_unknown_fields`, длительности целыми в `_ms`/`_sec`:
```rust
pub struct Config { pub version: u64, pub server: ServerConfig, pub default_system: String, pub systems: Vec<SystemConfig>, pub pii_types_file: String, pub allowlist_file: String, pub dictionaries_dir: Option<String> }
pub struct ServerConfig { pub listen: String, pub max_body_bytes: usize /*4 MiB*/, pub max_inflight: usize /*2048*/, pub mapping_ttl_sec: u64 /*900*/, pub mapping_max_entries: usize /*200000*/, pub request_deadline_ms: u64 /*5000*/ }
pub struct SystemConfig { pub id: String, pub enabled: bool, pub mask_mode: MaskMode, pub unmask_enabled: bool, pub types: TypeSelection /* enum: All | List(Vec<String>) через untagged serde: "all" или список */, pub overrides: HashMap<String, MaskMode>, pub combination_rule: bool, pub min_confidence: f32, pub allow_substrings: Vec<String>, pub session_mode: SessionMode /* Stateless | Stateful */, pub token_numbering: TokenNumbering /* Sequential | Hash */, pub hash_salt: Option<String> }
```
       Config::from_yaml + validate: listen непустой; default_system существует в systems и enabled; id систем уникальны; min_confidence в 0..=1; при token_numbering hash — hash_salt задан; файлы pii_types_file и allowlist_file существуют (проверка при загрузке в main, не в validate). ConfigStore на ArcSwap: load(), replace() с валидацией и сохранением прежнего снимка при ошибке. Config::system(id).
    2. config.yaml в корне — рабочий пример: системы `autotest` (default, token, sequential, все типы, combination_rule false, min_confidence 0.3) и `chatbot` (token, hash, соль, unmask_enabled false, types список из 6 типов, allow_substrings с адресом отделения). data/allowlist.yaml: `public_persons: [...]` (не меньше 30 известных имён: писатели, композиторы, учёные, исторические деятели), `organizations: [...]` (10 примеров вроде «Альфа-Банк», «Сбербанк», «отделение банка»). В этой задаче allowlist только загружается и валидируется, применение — T06.
    3. Сервер (axum 0.8). AppState: config ConfigStore, registry Arc<Registry>, detector Detector, store MappingStore, metrics PrometheusHandle, inflight Arc<tokio::sync::Semaphore>. run(): читает конфиг, реестр из pii_types_file, словари из dictionaries_dir (если задан и существует; иначе Dictionaries::empty), устанавливает метрики и tracing (JSON в stdout), слушает listen с TCP_NODELAY, запускает фоновую задачу sweep хранилища раз в 30 с, graceful shutdown по Ctrl+C.
    4. Идентификация потребителя: заголовок `X-System-Id`; если отсутствует — default_system. Неизвестный или enabled=false → 403 `{"error":{"message":"system not allowed","type":"forbidden"}}`.
    5. POST /process — контракт: тело `{"payload": string, "payload_id": string}`; ответ 200 `{"result": string}`. Логика:
       - если в хранилище нет записи с payload_id → маскирование: detect с опциями системы → mask (режимы/overrides/combination_rule системы) → сохранить StoredEntry { masked_text, mappings, original_hash: u64 (FxHash/DefaultHasher от payload) } → вернуть маску;
       - если запись есть и payload равен сохранённому masked_text → демаскирование: unmask(payload, mappings) → вернуть;
       - если запись есть и hash(payload) равен original_hash (ретрай маскирования) → вернуть сохранённый masked_text;
       - иначе (запись есть, payload ни маска, ни исходник) → выполнить unmask по карте и вернуть результат (терпимость к искажениям);
       - для системы с unmask_enabled false на втором шаге возвращать payload как есть.
       Пустой payload → 200 с пустым result. Отсутствие поля или невалидный JSON → 400 с JSON-ошибкой.
    6. POST /v1/mask `{text, session_id?}` → `{text, session_id, entities:[{type, start, end, token}]}`: session_id генерируется (uuid v4 через rand, hex 32 символа), если не передан; при session_mode stateful и переданном session_id существующая карта дополняется (одинаковые значения получают прежние токены, нумерация продолжается). POST /v1/unmask `{text, session_id}` → `{text}`; неизвестный session_id → 200 с текстом как есть и заголовком `X-Unmask: not-found`. POST /v1/detect `{text}` → `{entities:[{type, start, end, confidence}]}` — без значений.
    7. token_numbering hash: токен `<<LABEL_xxxxxx>>`, где xxxxxx — первые 6 hex SHA-256(hash_salt + "\0" + нормализованное значение). Реализовать через отдельную функцию в src/mask/mod.rs не меняя существующих сигнатур (например `pub fn mask_with(text, entities, registry, opts, numbering: Numbering) -> MaskResult`; существующая mask() вызывает её с Sequential). SHA-256 — крейт `sha2 = "0.10"` (разрешается добавить в Cargo.toml).
    8. Перегрузка: семафор на max_inflight; если разрешение получить сразу не удалось (try_acquire) → 429 с заголовком `Retry-After: 1` и JSON-ошибкой. Дедлайн запроса request_deadline_ms через tokio::time::timeout → 503 при превышении. Лимит тела max_body_bytes → 413.
    9. GET /healthz → 200 "ok". GET /readyz → 200, если конфиг и реестр загружены. GET /metrics — Prometheus: pii_requests_total{system,direction,status}, pii_latency_seconds{direction} (гистограмма, бакеты 0.0005…5), pii_entities_total{type}, pii_inflight (gauge), pii_mappings_stored (gauge), pii_rejected_total{reason}.
    10. Логи: tracing JSON, одна запись на запрос: request_id, system, direction, payload_id (хеш от него, не сам id, если длиннее 64 символов), entity types с count, latency_ms, status. **Никаких значений текста, спанов или масок в логах и в сообщениях об ошибках.**
    11. src/mask/mod.rs: список синтетических ФИО заменить на 20 вымышленных нейтральных (например «Смирнов Алексей Петрович», «Кузнецова Мария Ивановна»), без реальных известных людей.
    12. Заголовки ответа: `X-Request-Id` (принимается от клиента или генерируется), `Content-Type: application/json`.
  </requirements>
  <tests>
    tests/http.rs — поднимает приложение в процессе (build_router + axum::serve на порту 0 или tower::ServiceExt::oneshot), использует config.yaml из корня:
      - /process маска: «Клиент ИНН 7707083893, тел. +7 912 345-67-89, email ivan@mail.ru» с id A → result содержит <<INN_1>>, <<PHONE_1>>, <<EMAIL_1>> и не содержит исходных значений;
      - /process демаска: тот же id A, payload = полученная маска → result равен исходной строке побайтово;
      - ретрай маскирования: id A и исходный payload повторно → тот же masked, что в первый раз;
      - искажённая маска: id A, payload = маска с «<< inn_1 >>» и другим порядком → исходные значения восстановлены;
      - неизвестный id при демаске = новая маска (первый запрос);
      - X-System-Id: unknown → 403; chatbot → токены в hash-формате `<<INN_[0-9a-f]{6}>>`, одинаковы для двух разных payload_id с одним ИНН;
      - /v1/mask + /v1/unmask round-trip; /v1/unmask с неизвестным session_id → 200 и X-Unmask: not-found; /v1/detect не возвращает текст значений;
      - 400 на невалидный JSON и на отсутствие payload_id; 413 на тело больше лимита (в тесте задать max_body_bytes маленьким через отдельный конфиг-строку);
      - 429: max_inflight 1, один запрос удерживает разрешение (через тестовый маршрут или sleep в payload недоступен — допускается тест на уровне функции проверки семафора);
      - /metrics после запросов содержит pii_requests_total и pii_latency_seconds; /healthz 200;
      - логи: захватить вывод tracing в буфер (tracing_subscriber с writer в Arc<Mutex<Vec<u8>>>) и проверить, что после запроса с ИНН 7707083893 буфер не содержит «7707083893».
  </tests>
  <acceptance>cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml</acceptance>
  <out_of_scope>LLM-прокси /v1/chat/completions (T09). Hot reload по файлу и /admin (T08). Детекция ФИО/дат/адресов (T05). Применение allowlist (T06).</out_of_scope>
</task>
<task id="T05">
Привет. Следующая задача — ФИО, даты и адреса. Это самая заметная часть для жюри, они будут слать «Иванов Иван Иванович, родился 12.05.1985, живёт на Ленина 5».

Что нужно.

**Словари.** Сделай `data/dict/surnames.txt`, `first_names.txt`, `patronymics.txt`, `cities.txt` — по слову на строку, нижний регистр. Фамилий минимум 2000 самых частых русских, имён 500 (муж+жен), отчеств 300, городов 300 крупнейших РФ + Пушкин, Королёв, Чехов, Толстой (города-омонимы фамилий). Генерируй сам, но реальные, не выдуманные. Загрузка через уже готовый `Dictionaries::load_dir`.

**ФИО** (`fio`). Кандидат — 2–3 слова подряд с заглавной буквы (или инициалы «И. И.» / «И.И.»), между ними пробел. Считай ФИО если: хотя бы одно слово в словаре фамилий/имён/отчеств, ИЛИ отчество по окончанию (-ович/-евич/-ич/-овна/-евна/-ична/-инична), ИЛИ фамилия по окончанию (-ов/-ев/-ин/-ын/-ский/-цкий/-ова/-ева/-ина/-ская/-цкая/-ко/-ук/-юк/-ян/-дзе) плюс рядом имя из словаря. Порядок любой: «Иванов Иван Иванович», «Иван Иванович Иванов», «Иванов И. И.», «И. И. Иванов». Одно слово из словаря фамилий без ничего — тоже кандидат, но только при ПДн-контексте (клиент, гражданин, заявитель, ФИО, паспорт, тел). Confidence: 3 компонента 0.9, 2 — 0.7, 1 с контекстом 0.5. Не бери слово после «ул./улица/пл./пр./пер./наб.» (это адрес) и первое слово предложения, если оно единственный кандидат и не в словаре. Регистр: «ИВАНОВ ИВАН ИВАНОВИЧ» и «иванов иван иванович» с контекстом тоже ловим.

**Даты** (`birth_date`, `passport_issue_date`). Реализуй `validators::date` и детекцию: `дд.мм.гггг`, `дд/мм/гггг`, `дд-мм-гггг`, `гггг-мм-дд`, `мм.дд.гггг` (если день > 12 — однозначно), текстом «5 мая 1985», «05 мая 1985 г.», «5 мая 1985 года», «пятого мая 1985», двузначный год «12.05.85». Дата — сущность только при маркере в 40 символах до: birth_date — «родился», «родилась», «дата рождения», «д.р.», «г.р.», «др:», «day of birth»; passport_issue_date — «выдан», «дата выдачи», «выдано». Голая дата без маркера — не сущность. Дата в будущем — не сущность. Если возраст от даты рождения больше `historical_date_years` из конфига (добавь поле в ServerConfig, default 120) — минус 0.3.

**Место рождения** (`birth_place`): после «место рождения», «родился в», «родилась в», «уроженец», «уроженка» — берём до конца предложения или до запятой/точки: «г. Москва», «город Москва», «с. Ивановка Тульской обл.». Confidence 0.7.

**Гражданство** (`citizenship`): после «гражданство», «гражданин», «гражданка», «гражданство:» — слово из списка стран/прилагательных (сделай `data/dict/countries.txt`: Россия, РФ, Российская Федерация, российское, Беларусь, Казахстан, Узбекистан, Таджикистан, Киргизия, Армения, Азербайджан, Украина, Молдова, Грузия + 30 популярных). Без маркера — не сущность.

**Орган выдачи** (`passport_issuer`): после «выдан», «кем выдан», «выдано» — фраза до даты, до «код подразделения», до «к/п» или до точки: «ОУФМС России по г. Москве», «Отделом УФМС», «ГУ МВД России по Московской области». Confidence 0.7. Паттерн — начинается с ОУФМС/УФМС/ОВД/ГУ МВД/МВД/ТП/ОВМ/Отделом/Отделением/Управлением.

**Адрес** (`address`). Компоненты: индекс (6 цифр, 1xxxxx–6xxxxx), страна, регион («обл.», «область», «край», «респ.»), город («г.», «город» + словарь городов или заглавное слово), улица («ул.», «улица», «пр-т», «проспект», «пер.», «переулок», «наб.», «ш.», «шоссе», «б-р», «бульвар» + название), дом («д.», «дом» + число, «к.», «корп.», «стр.»), квартира («кв.», «квартира», «оф.», «пом.»). Адрес — минимум 2 компонента подряд (через запятые/пробелы). Спан от первого до последнего компонента. Также голый «ул. Ленина, д. 5» без города — адрес. Confidence: 3+ компонента 0.9, 2 — 0.7. Маркер «проживает», «адрес», «зарегистрирован», «прописан» +0.1. Компоненты отдельно (только индекс «101000», только «г. Москва») — не сущность, если не рядом с маркером «адрес»/«проживает»/«индекс».

**Держатель карты** (`card_holder`): латиница `[A-Z]+ [A-Z]+` (2–3 слова капсом) при маркере «держатель», «cardholder», «holder», «на имя», или в 60 символах после номера карты. Confidence 0.8.

**Приоритеты при пересечении**: адрес > ФИО (чтобы «ул. Пушкина» не стало ФИО). В `detect()` это уже есть по длине; проверь, что адресный спан длиннее и побеждает.

**Убери** из `detect()` эвристику «карта без Luhn при CVV рядом» — невалидный по Luhn номер маскировать не нужно, это ложные срабатывания.

Валидаторы и словари — как данные: паттерны в `data/pii_types.yaml`, окончания и маркеры тоже туда (добавь полям TypeSpec что нужно, например `suffixes`, `pii_context`, `non_pii_context` с `#[serde(default)]` — это твоё, сигнатуры функций не трогай).

**Тесты** — `tests/detect_names_dates_addresses.rs`, табличные, точный спан:
- ФИО: «Иванов Иван Иванович», «Иван Иванович Иванов», «Иванов И. И.», «И.И. Иванов», «клиент Петров» (с контекстом — да; «Петров» без контекста — нет), «ИВАНОВ ИВАН ИВАНОВИЧ», «Смирнова Анна Сергеевна», «Ким Чен Ир» (нет в словаре, но 3 слова с заглавной + маркер «клиент» → да).
- Ловушки: «поэт Александр Пушкин» → ФИО НЕ найдено (маркер «поэт» — сделай `non_pii_context` для fio, −0.3); «ул. Пушкина, д. 5» → address, не fio; «г. Пушкин, ул. Ленина, 1» → address с городом; «г. Пушкин И. С.» → fio.
- Даты: все форматы выше с маркером «родился» → birth_date со спаном ровно на дате; та же дата без маркера → нет; «выдан 12.05.2010» → passport_issue_date; «родился 6 июня 1799» → confidence ниже 0.6; «12.05.2099» → нет.
- Место рождения, гражданство, орган выдачи — по 2 примера каждый.
- Адрес: «101000, г. Москва, ул. Ленина, д. 5, кв. 12», «Москва, Ленина 5», «ул. Тверская, д. 1», «проживает: Санкт-Петербург, Невский пр-т, 28»; «отделение банка: ул. Тверская, 1» — находится как address (allowlist применим в T06, тут просто спан); голый «101000» → нет.
- Держатель: «держатель IVAN PETROV», «4276 3800 1234 5674 IVAN PETROV».
- Сложное предложение из ТЗ-примера: «Клиент Иванов Иван Иванович, паспорт 4509 123456 выдан ОУФМС России по г. Москве 12.05.2010, код подразделения 770-001, родился 12.05.1985 в г. Москва, проживает: г. Москва, ул. Ленина, д. 5, кв. 12, тел. +7 912 345-67-89» → ровно 8 сущностей нужных типов, без пересечений.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test` — все тесты, включая старые. Старые тесты не ломать, сигнатуры не менять. Файлы: `src/detect/mod.rs`, `src/registry/mod.rs` (только новые поля TypeSpec), `src/config/mod.rs` (поле historical_date_years), `data/pii_types.yaml`, `data/dict/*.txt`, новый тест-файл.
</task>
<task id="T06">
Привет. Следующая задача — ловушки и контекст. Жюри будет специально проверять: «поэт Александр Пушкин» не маскируем, «клиент Пушкин Иван» маскируем, «адрес отделения банка» не маскируем, «пин-код 1234» без карты — не маскируем (если правило включено). Плюс мелкие баги.

Прочитай docs/agent-kit/SPEC.md §5 целиком — там логика с числами. Кратко:

**1. Три списка маркеров в data/pii_types.yaml (глобально, секция `context:` на верхнем уровне YAML, плюс возможность переопределить на тип):**
- `non_pii_markers` — поэт, писатель, писательница, композитор, художник, учёный, режиссёр, актёр, актриса, президент, император, царь, князь, памятник, музей, улица имени, площадь имени, роман, стихотворение, произведение, автор, книга, герой, персонаж, фильм; для адресов — отделение, офис, филиал, головной офис, адрес банка, юридический адрес, горячая линия, приёмная; для чисел — пример, тест, тестовый, образец, шаблон.
- `pii_markers` — клиент, клиентка, гражданин, гражданка, заявитель, заёмщик, держатель, пользователь, сотрудник, сотрудница, абонент, пациент, ФИО, паспорт, родился, родилась, проживает, зарегистрирован, прописан, телефон, тел, прошу, мой, моя, мне, я.
- Ищутся в окне ±40 символов (по char) вокруг спана, без регистра. Найден non_pii — минус 0.3 к confidence; найден pii — плюс 0.3. Оба — по `trap_policy` из конфига системы: `prefer_mask` (default) → считать как pii, `prefer_skip` → как non_pii.

**2. Публичные персоны** — `data/allowlist.yaml` уже есть (`public_persons`, `organizations`). Загружай в Detector (добавь поле, конструктор `Detector::with_allowlist(registry, dicts, allowlist)` — новый, старый `new` оставь). Совпадение ФИО **целиком** с записью (без регистра, пробелы схлопнуты, точки после инициалов необязательны, порядок слов любой из перестановок 3 слов) — минус 0.3. Частичное совпадение (только фамилия) — ничего. `organizations` — если название организации найдено в окне ±60 символов от адреса — минус 0.3 к адресу.

**3. Уверенность ФИО — соседство:** если в том же предложении (до ближайшей точки/переноса) есть другая сущность с confidence ≥ 0.9 (паспорт, ИНН, телефон, карта) — плюс 0.2 к ФИО. Так «Александр Сергеевич Пушкин, паспорт 4509 123456» маскируется даже как полный тёзка.

**4. Даты:** плюс поле `historical_date_years` уже есть в конфиге — проверь, что оно применяется (минус 0.3, не отсечка); дата в будущем — минус 0.5.

**5. Правило комбинаций** — `combination_rule` в конфиге системы уже пробрасывается в mask(); проверь, что `/process` с системой, у которой `combination_rule: true`, действительно не маскирует одинокий «пин-код 1234», а с картой рядом — маскирует. В config.yaml добавь третью систему `strict` (combination_rule true, trap_policy prefer_skip) для демо.

**6. Мелкие баги:**
- `/v1/detect` на тексте без сущностей возвращает JSON без поля `entities` (KeyError у клиента). Должно быть `{"entities": []}`. Проверь `/v1/mask` тоже — `entities: []` и `mappings` пустые, но поля есть.
- Карта: если 16 цифр в формате карты (4×4) стоят после маркера «карта», «card», «номер карты», «№ карты» — маскировать даже при невалидном Luhn, confidence 0.6. В датасете жюри могут быть синтетические номера. Без маркера и без Luhn — не маскировать.
- Маркеры дат («г.», «года», «место рождения», «уроженец» и т.п.), которые сейчас захардкожены в src/detect/mod.rs строками, вынеси в YAML (поле типа `suffixes` / `markers` у соответствующих типов). В коде кириллических литералов быть не должно, кроме тестов.

**Тесты** — `tests/traps.rs`, табличные, через Detector с allowlist и через `/process` где сказано:
- «Поэт Александр Пушкин написал Евгения Онегина» → fio НЕ найдено.
- «Клиент Пушкин Иван Сергеевич, паспорт 4509 123456» → fio найдено, паспорт найден.
- «Александр Сергеевич Пушкин, паспорт 4509 123456, тел. +7 912 345-67-89» → fio найдено (тёзка с ПДн-контекстом).
- «Александр Сергеевич Пушкин» голой строкой: с trap_policy prefer_mask → найдено; prefer_skip → нет.
- «Памятник Пушкину на площади Пушкина» → ничего.
- «Отделение банка: г. Москва, ул. Тверская, д. 1» → address НЕ найден (маркер «отделение»). «Проживает: г. Москва, ул. Тверская, д. 1» → найден.
- «Альфа-Банк, ул. Каланчёвская, д. 27» (организация из allowlist рядом) → address не найден.
- «Пример телефона: +7 900 000-00-00» → phone не найден (маркер «пример»); «мой телефон +7 912 345-67-89» → найден.
- «Пушкин родился 6 июня 1799 года» → birth_date confidence ниже 0.6 и fio не найдено.
- «пин-код 1234» через /process с системой strict → без изменений; «карта 4276 3800 1234 5679, пин-код 1234» → оба замаскированы; с системой autotest — пин маскируется всегда.
- «карта 1234 5678 9012 3456» (невалидный Luhn, есть маркер) → card_number найден с confidence ≈ 0.6; «1234 5678 9012 3456» без маркера → нет.
- `/v1/detect` с «Погода хорошая» → `{"entities": []}`.
- Старые 68 тестов не ломать.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml`. Файлы: src/detect/mod.rs, src/server/mod.rs, src/config/mod.rs (поле trap_policy у SystemConfig, default prefer_mask), src/registry/mod.rs (новые поля TypeSpec с default), data/pii_types.yaml, data/allowlist.yaml (можно дополнить), config.yaml, tests/traps.rs. Сначала прочитай существующий detect/mod.rs — там уже есть контекстные окна и confidence, встраивайся, не переписывай. После плана сразу пиши код.
</task>

<task id="T07">
Привет. Прогнали 25 ручных кейсов (docs/brief/manual-test-cases.md) — round-trip везде ок, но точность хромает. Эта задача — числа, маркеры, адреса организаций. Имена и биографии — следующей задачей, их не трогай.

Как проверять: `bash tools/manual_accept.sh --only 1,4,5,6,7,8,9,13,16,17,18,19,24` — поднимает release-бинарник, гоняет кейсы, пишет FAIL с причиной. Ожидания лежат в tests/manual_expect.json (не меняй). Сейчас падают 4, 6, 7, 16, 17, 18.

Что поправить:

**1. Порог.** В config.yaml у системы autotest `min_confidence: 0.3` — слишком низко, ловушки с −0.3 всё равно проходят. Поставь 0.5 у autotest и chatbot. Откалибруй confidence так, чтобы:
- значение со своим маркером рядом («паспорт 4512 345678», «CVV 317») — ≥ 0.7;
- паттерн с валидатором без маркера (ИНН с контрольной суммой, карта по Luhn, email, телефон +7/8 в обычном формате) — ≥ 0.8;
- голый паттерн без валидатора и без маркера (10 цифр подряд, «4512 345679» без слова паспорт) — 0.4, то есть не проходит.

**2. Ближайшая метка решает (кейсы 7, 18).** «Паспорт клиента: 4512 345678. Код заявки: 4512 345679» — второй номер сейчас паспорт, потому что «Паспорт» в окне. Правило: маркер типа засчитывается, только если между концом маркера и началом значения нет другой метки поля. Метка поля — слово/фраза, за которой стоит «:», или маркер другого типа. То же для «CVV 317 и PIN 4821»: 4821 ближе к PIN, значит PIN, а не CVV. Если значение подходит под несколько маркерных типов (cvv, pin, passport, inn, snils, subdivision_code, driver_license) — выигрывает тип с ближайшим маркером слева.

**3. Склеенные маркеры (кейсы 16, 25).** «CVV317», «PIN4821», «CVV:317», «пин-код:4821» — маскировать только цифры, маркер оставить. Разреши ноль пробелов между маркером и значением для cvv/cvc/cvv2/pin/пин/пин-код.

**4. Ложный телефон (кейс 17).** «Версия сборки 8.900.123.45.67» — не телефон. Формат с точками как разделителями — телефон только при маркере телефона в окне. Добавь в non_pii_markers телефона: версия, сборка, build, version, релиз, ver.

**5. Дата рождения с маркером после (кейсы 15, 25).** «10.02.1982 года рождения», «06.06.1988 г.р.», «1982 г. р.» — маркер рождения справа от даты (в пределах 20 символов) тоже засчитывается. Маркеры в YAML.

**6. Адрес организации (кейс 4).** «Адрес отделения Альфа-Банка: г. Москва, ул. Каланчёвская, д. 27» сейчас маскируется. То же правило ближайшей метки: если ближайший слева маркер адреса — non_pii (отделение, отделении, офис, офисе, филиал, банк, банка, адрес банка), а не pii (проживает, живёт, адрес регистрации, зарегистрирован, прописан) — адрес не маскировать. Кейс 24 («Встреча назначена в офисе на ул. Кремлёвской, д. 18») сейчас проходит — не сломай.

**7. Долг с T06.** В src/detect/mod.rs остались кириллические литералы в коде (`looks_like_place` и рядом: "г.", "город", "обл." и т.п.). Вынеси в YAML. Проверка: `LC_ALL=C.UTF-8 grep -nP "[А-Яа-яЁё]" src/**/*.rs | grep -v "//"` — пусто.

**Тесты** — допиши в tests/traps.rs (Detector, как там уже сделано):
- «Паспорт клиента: 4512 345678. Код заявки: 4512 345679.» → один passport, первый.
- «Для карты клиента CVV 317 и PIN 4821.» → cvv «317», card_pin «4821».
- «Карта 4276-5500-1122-3347,CVV317,PIN4821.» → card_number, cvv, card_pin; спаны cvv/pin — только цифры.
- «Версия сборки 8.900.123.45.67» → нет phone; «телефон 8.900.123.45.67» → phone.
- «Иванов, 10.02.1982 года рождения» и «06.06.1988 г.р.» → birth_date.
- «Адрес отделения банка: г. Москва, ул. Тверская, д. 1» → нет address; «Клиент проживает по адресу: г. Москва, ул. Лесная, д. 17, кв. 42» → address.
- «внутренний идентификатор 4512345678» → нет passport.
Старые тесты не ломать. Если старый тест противоречит пунктам выше — не правь его сам, остановись и напиши в REPORT.md, какой и почему.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh --only 1,4,5,6,7,8,9,13,16,17,18,19,24`.

Файлы: src/detect/mod.rs, src/registry/mod.rs (новые поля с default), data/pii_types.yaml, config.yaml, tests/traps.rs. Больше ничего. Сначала прочитай detect/mod.rs — встраивайся в существующие окна контекста, не переписывай. После плана сразу пиши код.
</task>

<task id="T08">
Привет. Числа сделали, теперь имена. Проверка: `bash tools/manual_accept.sh --only 1,3,4,5,6,7,8,9,10,11,12,13,14,16,17,18,19,20,21,22,23,24,25` (soft можно). Сейчас по именам падают 3, 10, 12, 21, 23, 25.

**1. Границы спана ФИО (кейсы 21, 23).**
- «Клиент Иван Иванов» → в спан попадает «Клиент». Слово из любого списка маркеров (pii_markers, non_pii_markers, context_words любого типа) никогда не входит в ФИО.
- «Клиент: Смирнов Андрей Игоревич. Сегодня команда» → сейчас маскируется «Андрей Игоревич. Сегодня», а «Смирнов» остаётся открытым. Слова ФИО должны идти подряд, между ними только пробелы; точка допустима только после однобуквенного инициала («И. И. Иванов»). Предложение не пересекать.

**2. Падежи (кейс 10).** «Иван Петров позвонил Ивану Петрову» — второе вхождение не найдено. Имя в косвенном падеже: отрежь окончание (у, ю, а, я, е, ом, ем, ой, ей, ым, им, ого, ему) и проверь по словарю имён; фамилии — суффиксы в косвенных падежах (-ову, -еву, -ину, -ым, -ой, -овой, -евой, -иной, -ского, -скому, -ской) в YAML. Два соседних слова с заглавной, одно — имя (любой падеж), другое — фамилия (словарь или суффикс, любой падеж) → fio 0.7.
Если успеешь (не обязательно): одно лицо в разных падежах → один токен. Ключ для нумерации — нормализованные основы, а не исходная строка.

**3. Биография (кейсы 3, 25).** Сейчас «Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года» маскируется целиком: −0.3 от маркера и −0.3 от allowlist дают 0.3, а порог стоял 0.3. Правила:
- историческая дата (год старше `historical_date_years`) привязывается к ближайшему ФИО слева в пределах 80 символов; такое ФИО и сама дата не маскируются;
- сильные non_pii маркеры (поэт, писатель, композитор, «в биографии», памятник, музей, император) непосредственно перед ФИО (до 3 слов) — ФИО не маскируется вообще, без арифметики;
- в кейсе 3 после «, а клиент Петров Алексей Иванович родился 03.11.1990» Петров и его дата должны маскироваться — правило ближайшего маркера, клиент ближе.
- «Наш клиент ПУШКИН АЛЕКСАНДР СЕРГЕЕВИЧ, 06.06.1988 г.р.» — маскируется (pii маркер «клиент» и соседние сущности важнее allowlist).
- Полное совпадение с public_persons из allowlist **без** pii-маркера и без уверенной соседней сущности в предложении → не маскировать (сейчас 0.9−0.3=0.6 проходит). Датасет tests/data/hard_negatives.jsonl: «Лев Николаевич Толстой родился в 1828 году», «Фильм о Юрий Алексеевич Гагарин вышел в прокат», «Лекция о Сергей Павлович Королёв состоится…» — всё это не ПДн. Добавь в non_pii_markers: лекция о, фильм о, книга о, биография, умер, скончался.
- Название улицы без «ул.» («Филиал в г. Омск: Маршала Жукова, д. 15») — не ФИО: слово после звания (маршала, генерала, адмирала, академика) и перед «, д.» — адрес.

**4. Гражданство (кейс 12).** «гражданство Российская Федерация» → спан «Российская Федерация» целиком. Многословные страны в словаре countries (Российская Федерация, Республика Беларусь, Республика Казахстан, Соединённые Штаты Америки, Кыргызская Республика), длиннейшее совпадение.

**5. Адрес отделения, остаток от T07 (кейс 25).** «Встреча состоится в отделении банка по адресу Москва, ул. Каланчёвская, дом 27» всё ещё маскируется. Ближайший маркер слева — «в отделении банка» (non_pii), «по адресу» нейтральный — адрес не маскировать. Домашний адрес в том же тексте («проживает: Москва, ул. Лесная, дом 17, квартира 42») — маскировать.

Кем выдан (кейсы 2, 15) — не трогай, это следующая задача.

**Тесты** — tests/traps.rs и tests/detect_names_dates_addresses.rs (дописывать можно, старое не менять), по одному тесту на каждый пункт, тексты из кейсов.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh --only 1,3,4,5,6,7,8,9,10,11,12,13,14,16,17,18,19,20,21,22,23,24,25`.

Файлы: src/detect/mod.rs, src/registry/mod.rs, data/pii_types.yaml, data/allowlist.yaml, data/dict/countries.txt, data/dict/*.txt (дописывать), tests/traps.rs, tests/detect_names_dates_addresses.rs. После плана сразу пиши код.
</task>

<task id="T09">
Привет. Скорость на больших текстах. Сейчас ~2 мс на КБ линейно: 184 КБ — 375 мс, 923 КБ — 1.9 с (VPS, 4 ядра). Нужно: 1 МБ текста ≤ 250 мс на /process, без потери точности.

**1. Замер.** Добавь `tests/perf.rs` с `#[ignore]` тестом: собирает текст ~1 МБ (нейтральная фраза × N + 20 разных ПДн вразброс), гоняет `Detector::detect` 5 раз, печатает лучшее время, assert ≤ 250 мс в release. Запуск: `cargo test --release --test perf -- --ignored --nocapture`.

**2. Где искать.** Сначала замерь по типам (временный eprintln с Instant, потом убрать), потом правь самое дорогое. Типичные причины:
- поиск маркеров контекста по окну для каждого кандидата через `to_lowercase()` окна и `contains` по списку — лучше один проход `aho_corasick` (крейт aho-corasick, уже транзитивно есть через regex) по всему тексту в lowercase, один раз на запрос, потом бинарный поиск по позициям;
- `name_tokens` / словари: аллокация `String` на каждое слово — использовать `&str` и lowercase только для слов с заглавной;
- отдельный проход regex на каждый тип — объединить в `RegexSet` для префильтра, дальше только сработавшие;
- `to_lowercase()` всего текста несколько раз на запрос — один раз.

**3. Не ломать.** Все тесты, check_process, manual_accept должны остаться зелёными.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && cargo test --release --test perf -- --ignored --nocapture && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh`.

Файлы: src/detect/mod.rs, src/registry/mod.rs, Cargo.toml (aho-corasick), tests/perf.rs. После плана сразу пиши код.
</task>

<task id="T10">
Привет. Реквизиты документов и карты — по датасету tests/data/synthetic_missing_categories.jsonl сильные провалы. Проверка: `python tools/eval_dataset.py --url http://127.0.0.1:<порт> --files tests/data/synthetic_missing_categories.jsonl,tests/data/synthetic_alfa.jsonl,tests/data/multi_entity.jsonl` (сервис подними сам на свободном порту, как в tools/manual_accept.sh). Сейчас: passport_issuer 12/120, card_holder 0/120, birth_date 91/120, birth_place 88/120, subdivision_code 97/120.

**1. Держатель карты (0/120).** Сейчас требуется номер карты рядом — убрать требование. Маркеры: держатель, держатель карты, владелец карты, cardholder, card holder, имя на карте. После маркера (и необязательного «:») два-три слова с заглавной или целиком заглавными, латиница или кириллица, любой порядок имя/фамилия → card_holder 0.8. NEG из датасета: «Режиссёр фильма — Сергей Петров», «Герой романа — Иван Васильевич» — без маркера держателя не трогать.

**2. Кем выдан (12/120).** Маркеры: выдан, выдано, кем выдан, «кем выдан (N):», орган выдачи, «орган выдачи —». После маркера фраза до точки/запятой/даты/«код подразделения». Фраза начинается с органа: ОМВД, УМВД, ГУ МВД, МВД, УФМС, ОУФМС, ТП, ОВД, ГУВМ, отдел, отделом, отделение, отделением, паспортный стол, управа, отдел полиции. NEG: «Справка выдана архивом», «Документ выдан системой», «Отделение банка выдаёт кредиты» — не маскировать (нет органа из списка / «банк»).

**3. Дата рождения (91/120).** Маркеры добавить: «год рождения», «д/р», «д.р.», «г.р.», «дата рожд.». Форматы: dd.mm.yyyy, dd-mm-yyyy, dd/mm/yyyy, yyyy-mm-dd, «5 апреля 1979». Примеры пропусков: «Анкета: год рождения 1998-05-07», «д/р 21-01-1986», «год рождения: 20/05/1960».

**4. Место рождения (88/120).** «Место рождения Комарова Григорий: г. Ясенево» — сейчас birth_place захватывает ФИО. Спан места — только город/село: слово из словаря cities (с падежами: Хабаровске → Хабаровск) или после г./с./пос./дер./город. Маркеры: место рождения, родился в, родилась в, уроженец, уроженка. ФИО между маркером и местом — отдельная сущность fio. NEG: «Экспорт в ЮАР растёт», «Город Торжок упоминается в учебнике» — без маркера не трогать.

**5. Код подразделения (97/120).** Маркеры добавить: «код подр.», «к/п», «к.п.». NEG: «Рейс 770-001», «Артикул 455-210», «Версия прошивки 100-200» — без маркера не трогать.

**Тесты** — tests/detect_documents.rs, по 3 позитива и 2 негатива на пункт, тексты из датасета.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh`.
Цель по eval: каждый из пяти типов ≥ 110/120 на synthetic_missing_categories, лишних масок не больше, чем сейчас.

Файлы: src/detect/mod.rs, src/registry/mod.rs, data/pii_types.yaml, data/dict/*.txt, tests/detect_documents.rs. После плана сразу пиши код.
</task>

<task id="T11">
Привет. Внешний датасет tests/data/rmr_benchmark_alfa.jsonl (живые тексты, не синтетика) — у нас там recall 33%. Проверка: `python tools/eval_dataset.py --url http://127.0.0.1:<порт> --files tests/data/rmr_benchmark_alfa.jsonl --errors 40`. Сейчас: snils 1/223, driver_license 22/371, passport 116/494, fio 300/669, email 109/221, card_number 82/203.

Главная особенность датасета — токенизированные пробелы: «123 - 456 - 789 01», «tkut @ uraltrd . ru», «+7 ( 812 ) 987 6543», «5555 - 1111 - 2222 - 3333». Везде, где в регексах разделитель `[-.\s]`, разреши `\s*[-./]\s*` и пробелы вокруг скобок/@/точки.

**1. СНИЛС (1/223).** Маркеры: снилс, снилс:, страховой номер, СНИЛС (любой регистр, опечатки «снил», «снылс»). Форматы: 123-456-789 01, 123.456.789.01, 12345678901, «123 - 456 - 789 01». Контрольная сумма: если сходится — 0.9 даже без маркера; не сходится, но маркер есть — 0.7 (в датасете синтетические номера 555.666.777.88).

**2. Паспорт (116/494).** Маркеры: паспорт, паспорта, паспортные данные, серия, серии, серию, номер паспорта, «№». Форматы: «45 03 123456», «4503 123456», «серия 43 21, а номер паспорта 987654», «Серия: 5555, № 667788», «92 01 - 987654». Серия и номер могут стоять раздельно, между ними до 30 символов — маскировать обе части (два спана или один).

**3. Водительское удостоверение (22/371).** Маркеры: права, водительское удостоверение, вод. удостоверение, ВУ, в/у. В тексте с таким маркером «серия 5019, номер 004512», «серия 78 16 и номер 112233», «44 / 33 987654», «9911 223344» → driver_license, а не passport. Правило ближайшего маркера из T07.

**4. Email (109/221).** «ugray@gmail . com», «tkut @ uraltrd . ru» — пробелы вокруг @ и точки. Спан — от первого символа локальной части до конца домена.

**5. Карта (82/203).** «5555 - 1111 - 2222 - 3333» — дефисы с пробелами; с маркером карты — без Luhn (как в T06).

**6. ФИО (300/669).** Фамилия + инициалы: «Лукин П. П.», «Дорохова И. И.», «П.П. Лукин» → fio 0.8. Латиница рядом с маркером (держатель, автор, клиент, заявитель, пациент): «Theodore Weaver», «Dorothy LANGFOrd» → fio 0.7. Одиночное имя в косвенном падеже без фамилии («согласовать с Тимуром») — не трогаем.

**Не ломать точность:** hard_negatives.jsonl и overlap_conflicts.jsonl не должны ухудшиться — проверь до и после.

**Тесты** — tests/detect_rmr.rs, по 3 примера на пункт из датасета.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh`. Цель по eval rmr: snils ≥ 180/223, passport ≥ 380/494, driver_license ≥ 250/371, email ≥ 200/221.

Файлы: src/detect/mod.rs, src/registry/mod.rs, data/pii_types.yaml, tests/detect_rmr.rs. После плана сразу пиши код.
</task>

<task id="T12">
Привет. После T07 на датасетах регрессии — чиним, ничего нового не добавляем. Проверка: `bash tools/eval_accept.sh` — поднимает бинарник, гоняет tests/data/*.jsonl и сверяет с порогами из tests/eval_floors.txt (не меняй его). Сейчас падает.

**1. Адрес без маркера (overlap_conflicts address 12 → 0, rmr address 80 → 38).** После подъёма порога до 0.5 полный адрес без маркера перестал проходить: «Доставить: г. Белгород, ул. Садовая, д. 41». Полный адрес по структуре (город + улица + дом, или улица + дом + квартира) — 0.7 сам по себе, без маркера. Минус только от non_pii маркера адреса (отделение, офис…), как сделано в T07.

**2. CVV далеко от маркера (лишних cvv 40 → 120).** «CVV находится на обороте карты (заметка № 001/cvv)» — «001» стал CVV. Маркер cvv/pin засчитывается только слева от значения, и между ними только пробелы, «:», «-», «=», «код» — не больше 12 символов. Склейка «CVV317» из T07 остаётся.

**3. Паспорт в rmr (116 → 95).** Правило ближайшей метки режет «серия 43 21, а номер паспорта 987654» и «Серия: 5555, № 667788»: «номер», «№», «серия» — это части паспортного маркера, а не чужие метки. Чужой меткой считается только маркер другого типа или «Слово:» не из списка маркеров паспорта.

Тесты — в tests/traps.rs, по одному на пункт, тексты выше.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh --only 1,3,4,5,6,7,8,9,10,11,12,13,14,16,17,18,19,20,21,22,23,24,25 && bash tools/eval_accept.sh`.

Файлы: src/detect/mod.rs, data/pii_types.yaml, tests/traps.rs. После плана сразу пиши код.
</task>

<task id="T13">
Привет. Мелкая механическая задача: проект называется DetoxProxy, а крейт у нас pii-guard. Переименуй.

1. Cargo.toml: `[package] name = "detox-proxy"`, библиотека `detox_proxy`, бинарник `detox-proxy` (если секции [lib]/[[bin]] есть — поправь name, если нет — хватит имени пакета). Описание пакета: "DetoxProxy: PII detection, masking and unmasking for LLM traffic".
2. Все `use pii_guard::` и `pii_guard::` в src/ и tests/ → `detox_proxy::`.
3. Строки в коде с "pii-guard" / "pii_guard" (сообщения логов, user-agent, описание CLI) → "detox-proxy". Имена метрик `pii_*` НЕ трогай.
4. `cargo build` обновит Cargo.lock сам — не редактируй его руками.

Больше ничего не меняй. Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && test -f target/release/detox-proxy.exe && ! grep -rn "pii_guard\|pii-guard" src tests Cargo.toml`.

Файлы: Cargo.toml, Cargo.lock, src/**/*.rs, tests/*.rs.
</task>

<task id="T14">
Привет. Адреса и пара форматов, которые мы теряем. Проверка: `bash tools/eval_accept.sh` (пороги в tests/eval_floors.txt — не меняй). Сейчас падают cvv (83 < 115) и driver_license в synthetic_alfa (12 < 16) — это регрессия T12, её надо вернуть.

**1. Адрес без «д.» (главное).** Самая частая живая форма — улица и номер дома без «д.»: «на ул. Гагарина 28», «ул. Строителей 17к3», «пр. Победы 45 кв 89», «ул. 8 Марта 102 подъезд 4», «ул. Космонавтов 15 корпус 3», «проспекте Сахарова 22». Правило: маркер улицы (ул., улица, пр., пр-т, проспект, пер., переулок, ш., шоссе, б-р, бульвар, наб., набережная, пл., площадь, мкр., микрорайон — в любом падеже: «улице», «проспекте») + название (1–3 слова, может начинаться с цифры: «8 Марта», «1-я Парковая») + номер дома (`\d+[а-яА-Я]?(/\d+)?`, «17к3», «28/4») + необязательно корпус/к./стр./кв./квартира/подъезд с номером → address 0.8 без всякого контекста. Если перед этим стоит город («г. Москва, », «Москва, ») — включить в спан. Также «Хабаровск, Маршала Жукова, 188» и «Вольск, Рокоссовского, 131»: город из словаря + слово с заглавной + номер → address 0.7. Non_pii маркеры адреса (отделение, офис, банк…) из T07 продолжают работать.

**2. CVV-код (регрессия T12).** «CVV-код 317 введён», «CVC-код: 123», «код CVV 317» — это маркер и значение, маскировать цифры. «CVV-код находится на обратной стороне карты» — цифр после маркера нет, ничего не маскировать (ручной кейс 5 должен остаться зелёным).

**3. Паспорт «NN NN NNNNNN».** «Паспорт 48 90 234004 выдан …» не маскируется. Формат серии двумя парами через пробел + номер 6 цифр рядом с маркером паспорта → passport 0.9.

**4. Водительское удостоверение (регрессия T12).** В tests/data/synthetic_alfa.jsonl было 16/16, стало 12/16 — найди по eval (`--errors 40 --files tests/data/synthetic_alfa.jsonl`), что пропало, и верни.

**Тесты** в tests/traps.rs, по одному на пункт; примеры бери из текста выше.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh --only 1,3,4,5,6,7,8,9,10,11,12,13,14,16,17,18,19,20,21,22,23,24,25 && bash tools/eval_accept.sh`.

Файлы: src/detect/mod.rs, data/pii_types.yaml, tests/traps.rs. После плана сразу пиши код.
</task>

<task id="T16">
Привет. Небольшая дыра в изоляции. Хранилище соответствий (src/store) ключуется только по `payload_id` / `session_id`. Если две разные системы-потребителя (заголовок X-System-Id) пришлют одинаковый payload_id, система B отправит маску системы A и получит исходные данные A.

Сделать: во всех местах src/server/mod.rs, где вызывается `state.store.get` / `insert` / `insert_with_hash`, ключ — `format!("{}\u{1f}{}", system_id, payload_id)` (разделитель \u{1f}, чтобы нельзя было подобрать коллизию через сам payload_id). Для /v1/mask и /v1/unmask так же с session_id. В лог по-прежнему пишется только payload_id (не составной ключ). Вынеси построение ключа в одну функцию `fn store_key(system: &str, id: &str) -> String`.

Тесты — в tests/http.rs:
- система autotest маскирует «ИНН 7707083893» с payload_id X → «ИНН <<INN_1>>»; система strict (X-System-Id: strict) шлёт «ИНН <<INN_1>>» с тем же X → в ответе НЕТ 7707083893;
- та же проверка для /v1/mask + /v1/unmask с одинаковым session_id и разными системами;
- в рамках одной системы round-trip по-прежнему работает (старые тесты не менять).

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,13,20,21`.

Файлы: src/server/mod.rs, tests/http.rs. Больше ничего. После плана сразу пиши код.
</task>

<task id="T17">
Привет. Две вещи в src/server/mod.rs.

**1. Детекция не должна блокировать async-потоки.** Сейчас `state.detector.detect(...)` и `mask_with(...)` вызываются синхронно внутри async-обработчика. На больших текстах это сотни миллисекунд CPU: рабочий поток tokio занят, маленькие запросы ждут, а `tokio::time::timeout` не может прервать синхронный код — дедлайн не срабатывает.
Сделать: для текстов длиннее `server.inline_max_bytes` (новое поле ServerConfig, default 16384) выполнять детекцию+маскирование в `tokio::task::spawn_blocking`, короткие — как сейчас, inline (spawn_blocking на коротких дороже самой работы). Число одновременных тяжёлых задач ограничить семафором `server.heavy_max_concurrency` (default = число ядер, `std::thread::available_parallelism`), при исчерпании — ждать permit внутри того же дедлайна; дедлайн истёк → 503 с `Retry-After: 1` и метрикой `pii_rejected_total{reason="deadline"}`. Для spawn_blocking нужны `Arc` на detector/registry — AppState уже в Arc, передавай его клон. То же для /v1/mask и /v1/detect.

**2. Горячая перезагрузка конфигурации.** `ConfigStore::replace` есть, но ничто его не вызывает. Добавить:
- `POST /admin/reload` — перечитывает config.yaml, data/pii_types.yaml, data/allowlist.yaml, словари; валидирует; при ошибке оставляет старое и отвечает 400 с текстом ошибки (без ПД), при успехе 200 `{"version": N}`. Доступ: только с заголовком `X-Admin-Token`, равным переменной окружения `DETOX_ADMIN_TOKEN`; если переменная не задана — эндпоинт отвечает 404.
- на Unix — то же по сигналу SIGHUP (`tokio::signal::unix`), под `#[cfg(unix)]`.
- registry и detector тоже должны перезагружаться: держи их в `ArcSwap` так же, как конфиг, запросы берут снапшот один раз в начале.
- метрика `pii_config_reloads_total{result="ok|error"}`.

**Тесты** в tests/http.rs: текст 50 КБ и параллельно 20 коротких запросов — короткие отвечают < 100 мс каждый; /admin/reload без токена → 404 (переменная не задана) и с неверным токеном → 403 (переменная задана); reload с битым YAML → 400, старая конфигурация продолжает работать.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,13,20,21,22,23`.

Файлы: src/server/mod.rs, src/config/mod.rs (новые поля с default), src/main.rs, tests/http.rs. После плана сразу пиши код.
</task>

<task id="T18">
Привет. Метрики для разбора автопрогона — без единого значения ПД. Всё в src/server/mod.rs (или src/obs/mod.rs, если там удобнее), существующие метрики не переименовывать.

1. `pii_payload_bytes` — гистограмма размера входного текста в байтах, метки `system`, `direction`; бакеты 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304.
2. `pii_requests_without_entities_total{system}` — маскирование, где не найдено ни одной сущности (payload непустой).
3. `pii_unmask_unresolved_tokens_total{system}` — при восстановлении: сколько в тексте нашлось подстрок формата наших токенов (`<<LABEL_...>>`, с учётом регистра/пробелов, как в unmask), для которых нет соответствия. Плюс `pii_unmask_requests_with_unresolved_total{system}` — число таких запросов.
4. `pii_process_retry_total{system}` — /process пришёл с тем же payload_id и исходным текстом (повтор маскирования, отдали сохранённую маску).
5. `pii_entities_per_request` — гистограмма числа сущностей на запрос маскирования, бакеты 0,1,2,3,5,8,13,21,50,100.

Тесты в tests/http.rs: после одного маскирования без ПДн, одного с ПДн, одного повтора и одного восстановления с чужим токеном `<<INN_99>>` в /metrics есть все пять метрик с ожидаемыми значениями; в /metrics нет ни одного значения ПД из тестовых текстов.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,13,20,21,22,23`.

Файлы: src/server/mod.rs, src/obs/mod.rs, tests/http.rs. Каталог logs/ не удалять и не чистить — там логи запуска. После плана сразу пиши код.
</task>

<task id="T19">
Привет. Два пункта в src/detect/mod.rs.

**1. Та же паника, что починили в HF1, вернулась в T14.** Около строки 1068 (город перед запятой в адресе): `.map(|(i, _)| i + 1)` после `char_indices().rev().find(...)`. Замени на `.map(|(i, c)| i + c.len_utf8())`. Во всём src/ не должно остаться ни одного `.map(|(i, _)| i + 1)` — приёмка это проверяет grep'ом.

**2. CVV в разговорной речи.** Сейчас ловится только значение вплотную к маркеру. Живые формы: «нужен cvc, вот 123», «cvc был 123», «цвс правильный 123», «код на обороте карты 123», «cvc, хотя код 123», «вот мой cvc 123». Правило:
- маркеры: cvv, cvc, cvv2, cvc2, цвв, цвс, свв, свс, «код безопасности», «код на обороте», «на обороте карты», «с обратной стороны карты» — в YAML;
- значение: отдельное число из 3 цифр (4 — только для cvv/cvc с явным «4-значный»/amex не нужно, делай 3), в том же предложении, справа от маркера не дальше 30 символов; между ними не больше 3 слов и нет другого числа;
- НЕ считать CVV: число сразу после «№», «номер», «заметка», «шаг», «ошибка», «код ошибки», «версия»; число, которое само часть большего числа или даты;
- порог по лишним cvv в tests/eval_floors.txt (`fp.cvv<=10`) должен выполняться, ручные кейсы 5 и 18 — зелёные.

Тесты — в tests/traps.rs: по одному на каждую форму выше (позитив) и 3 негатива («заметка № 001/cvv», «CVV находится на обороте карты», «ошибка 317 при вводе cvv»).

Приёмка: `! grep -rn 'map(|(i, _)| i + 1)' src/ && cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml && bash tools/manual_accept.sh --only 1,3,4,5,6,7,8,9,10,11,12,13,14,16,17,18,19,20,21,22,23,24,25 && bash tools/eval_accept.sh`.

Файлы: src/detect/mod.rs, data/pii_types.yaml, tests/traps.rs. Каталог logs/ не трогай. После плана сразу пиши код.
</task>

<task id="T20">
Привет. Постоянный тест против паник на Unicode. Прод падал на неразрывном пробеле (U+202F) — такой текст не должен ронять ни детектор, ни маскирование.

Создай tests/unicode_safety.rs:
- детектор как в tests/traps.rs (с allowlist), `min_confidence: 0.0`;
- для каждого файла tests/data/*.jsonl и tests/data/holdout/*.jsonl — первые 40 строк; каждый текст прогнать в трёх вариантах: исходный, все пробелы → '\u{00a0}', все пробелы → '\u{202f}'. Для каждого варианта: `detect`, затем маскирование и восстановление (как в tests/mask.rs). Проверить: нет паники; все спаны на границах символов (`is_char_boundary`); восстановление даёт исходный текст;
- ручные строки: «ул.\u{202f}Лесная, д.\u{00a0}17», «г.\u{2009}Москва, ул.\u{202f}Тверская», «Клиент\u{00a0}Иванов\u{00a0}Иван», «CVV\u{00a0}317», ««Иванов Иван» — клиент 😀», «тел.\u{202f}+7\u{202f}912\u{202f}345-67-89», «Москва,\u{00a0}ул. Лесная 5», текст из одних '\u{202f}', пустая строка;
- неразрывный пробел работает как обычный: «ул.\u{00a0}Лесная, д.\u{00a0}17, кв.\u{00a0}42» → address; «ИНН\u{00a0}7707083893» → inn.
- Весь файл тестов должен проходить в debug-сборке быстрее 20 секунд (`cargo test --test unicode_safety`) — если медленно, уменьши число строк, но не варианты.

Приёмка: `cargo clippy --all-targets -- -D warnings && timeout 60 cargo test --test unicode_safety && cargo test`.

Файлы: только tests/unicode_safety.rs. Код продукта не менять: если тест находит панику — остановись и опиши её в REPORT.md (текст-пример и строку паники), не чини. Каталог logs/ не трогай.
</task>

<task id="T21">
Привет. Сквозной сценарий для жюри: OpenAI-совместимый прокси к LLM. Новый модуль src/llm/mod.rs + маршрут в src/server/mod.rs.

`POST /v1/chat/completions`, тело — как у OpenAI (`model`, `messages: [{role, content}]`, `stream` опционально, остальные поля пробрасываются как есть через `serde_json::Value`).

1. Маскирование: `content` каждого сообщения маскируется детектором системы (X-System-Id, как в /process); все сообщения одного запроса — одна таблица соответствий (одинаковое значение → один токен во всех сообщениях). Хранить в store под ключом `store_key(system, "chat:" + request_id)`, TTL обычный.
2. Upstream задаётся в config.yaml новым блоком (все поля опциональны):
   ```yaml
   llm:
     upstream_url: "https://.../v1/chat/completions"   # нет → демо-режим
     api_key_env: "DETOX_LLM_API_KEY"                  # имя переменной окружения с ключом
     timeout_ms: 60000
   ```
   Ключ читается из переменной окружения, никогда не логируется и не попадает в ответы/ошибки.
3. Запрос в upstream: reqwest, тело с замаскированными messages, `stream: true` всегда (некоторые upstream принимают только stream). Ответ SSE (`data: {...}` и `data:{...}` — оба варианта, `data: [DONE]`) собрать в текст из `choices[0].delta.content`.
4. Демо-режим (upstream не задан): ответ LLM имитируется — «Принято. Запрос по клиенту обработан: » + все токены из запроса через запятую. Так видно, что токены доходят и восстанавливаются.
5. Ответ клиенту: текст модели демаскируется (`unmask` с таблицей этого запроса). Если клиент просил `stream: true` — отдать SSE с одним чанком `delta.content` и `[DONE]`; иначе обычный JSON `{"id","object":"chat.completion","model","choices":[{"index":0,"message":{"role":"assistant","content":...},"finish_reason":"stop"}]}`.
6. В ответ добавить заголовок `X-Detox-Masked-Entities: <число>`. В лог — только число сущностей по типам, длины, статус upstream; никаких текстов.
7. Ошибка upstream (таймаут, не-200) → 502 `{"error":{"message":"upstream error","type":"upstream"}}` без деталей тела upstream.

Тесты в tests/llm.rs:
- демо-режим: messages с «Клиент Иванов Иван Иванович, ИНН 7707083893» → в ответе исходные значения восстановлены, заголовок X-Detox-Masked-Entities ≥ 2;
- фейковый upstream: поднять в тесте свой axum-сервер на 127.0.0.1:0, который проверяет, что в полученном теле НЕТ «7707083893» и «Иванов», и отвечает SSE с чанками, содержащими токены из запроса (эхо) → клиент получает исходные значения; проверить оба формата `data:{` и `data: {`;
- upstream отвечает 500 → клиент получает 502 без текста upstream;
- stream: true у клиента → ответ SSE с `[DONE]`.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,13,20,21`.

Файлы: src/llm/mod.rs (новый), src/lib.rs, src/server/mod.rs, src/config/mod.rs (блок llm, default — демо), tests/llm.rs, Cargo.toml (только если нужна фича зависимости). Каталог logs/ не трогай. После плана сразу пиши код.
</task>

<task id="T22">
Привет. Рефакторинг без изменения поведения — автопроверка кода жюри (Sonar) снимает баллы за сложные и длинные функции. Только src/server/mod.rs и src/mask/mod.rs.

Цели (clippy): когнитивная сложность каждой функции ≤ 10, длина ≤ 80 строк. Сейчас выше:
- src/mask/mod.rs:75 `mask_with_seed` — сложность 12, 108 строк;
- src/server/mod.rs:314 (158 строк), :484 (102 строки), :720 (108 строк), :967 (сложность 12).

Как: выносить шаги в отдельные функции с понятными именами (разбор запроса, выбор системы, поиск в store, маскирование, запись метрик, ответ); повторяющиеся блоки обработчиков /process, /v1/mask, /v1/detect — в общую функцию (DRY); глубокую вложенность `match`/`if` — ранними `return` / `?`. Публичные сигнатуры (`pub fn` в lib) не менять. Поведение не менять ни на байт: все существующие тесты — без правок.

Добавь в корень clippy.toml:
```
cognitive-complexity-threshold = 10
too-many-lines-threshold = 80
```

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo clippy --lib -- -W clippy::cognitive_complexity -W clippy::too_many_lines 2>&1 | (! grep -E "src.(server|mask).mod.rs") && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,13,20,21,22,23`.

Файлы: src/server/mod.rs, src/mask/mod.rs, clippy.toml (новый). Тесты не трогать. Каталог logs/ не трогай. После плана сразу пиши код.
</task>

<task id="T24">
Привет. Мелочь в src/server/mod.rs: `log_request(...)` везде вызывается с пустой строкой вместо идентификатора запроса — в логе `"payload_id":""`. Передавай настоящий: для /process — `payload_id` из тела, для /v1/mask и /v1/unmask — `session_id`, для /v1/detect и /v1/chat/completions — пустую строку (там нет идентификатора). Длинный (> 64 символов) уже хешируется внутри log_request — это оставить. Сам идентификатор ПД не является, но проверь, что в лог по-прежнему не попадает ни payload, ни result.

Тест в tests/http.rs: поднять сервис с логами в буфер (или файл), сделать /process с payload_id "log-check-123" и текстом «ИНН 7707083893» → в логе есть "log-check-123", нет "7707083893".

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190`.

Файлы: src/server/mod.rs, tests/http.rs. Каталог logs/ не трогай.
</task>

<task id="T23a">
Привет. Новый модуль склонения — для прокси к LLM (см. T23b), чтобы модель могла попросить нужный падеж у токена. Только правила, без внешних библиотек и словарей из сети. Модуль src/morph/mod.rs, подключить в src/lib.rs.

API:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case { Nom, Gen, Dat, Acc, Ins, Prep }
impl Case { pub fn parse(s: &str) -> Option<Case> } // "им"|"nom", "род"|"gen", "дат"|"dat", "вин"|"acc", "твор"|"тв"|"ins", "пр"|"предл"|"prep"; регистр не важен
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gender { Male, Female, Unknown }
pub enum Kind { Person, Place, Country, Street }
/// Приводит значение (в любом падеже) к именительному и склоняет в нужный падеж.
/// None — если форма не распознана уверенно: вызывающий вернёт исходное значение.
pub fn inflect(value: &str, kind: Kind, case: Case) -> Option<String>
```
Регистр результата повторяет регистр исходного значения (ИВАНОВ → ИВАНОВУ; Иванов → Иванову). Точки инициалов и разделители сохраняются.

**Person (ФИО, 1–3 слова, любой порядок, инициалы «И. И.» не склоняются).**
- Пол: по отчеству (-ович/-евич/-ич → м, -овна/-евна/-ична/-инична → ж), иначе по имени (словарь data/dict/first_names.txt + окончание -а/-я у имени → ж, кроме Илья, Никита, Кузьма, Фома, Лука, Савва — м), иначе по фамилии (-ова/-ева/-ина/-ская/-цкая → ж).
- Нормализация к им. п.: снять падежное окончание по таблицам ниже в обратную сторону (Иванову → Иванов, Ивановой → Иванова, Ивану → Иван, Ивановичу → Иванович, Марии → Мария).
- Фамилии м.: -ов/-ев/-ёв/-ин/-ын: род -а, дат -у, вин -а, твор -ым, пр -е. -ский/-цкий/-ой/-ый: род -ого, дат -ому, вин -ого, твор -им/-ым, пр -ом. Согласный в конце (Шмидт, Гусак) — как существительное м. р.: -а, -у, -а, -ом, -е. 
- Фамилии ж.: -ова/-ева/-ина/-ына: род/дат/твор/пр -ой, вин -у. -ская/-цкая/-ая: -ой, -ой, -ую, -ой, -ой. Женские на согласный (Шмидт у женщины) — не склоняются.
- Несклоняемые фамилии: на -о, -е, -и, -у, -ю, -ых, -их (Шевченко, Дурново, Черных) и на гласную + -а (Гарсиа) — возвращаются как есть; всё, что не подходит под правила, — None.
- Имена: м. на согласный — как существительные (Иван → Ивана, Ивану, Ивана, Иваном, Иване); на -й (Андрей, Сергей) → -я, -ю, -я, -ем, -е; на -ь (Игорь) → -я, -ю, -я, -ем, -е; Лев → Льва, Павел → Павла, Пётр → Петра (исключения таблицей). Ж. и м. на -а → -ы/-и, -е, -у, -ой/-ей, -е; на -я → -и, -е, -ю, -ей, -е; на -ия (Мария) → -ии, -ии, -ию, -ией, -ии; Любовь → Любови, Любови, Любовь, Любовью, Любови.
- Отчества: -ович → -овича, -овичу, -овича, -овичем, -овиче; -овна → -овны, -овне, -овну, -овной, -овне (так же -евич/-евна, -ич/-ична).

**Place (город, село; 1–3 слова).** Москва → Москвы, Москве, Москву, Москвой, Москве; Казань → Казани, Казани, Казань, Казанью, Казани; Омск/Екатеринбург (согласный) → -а, -у, как им., -ом, -е; Тверь → Твери…; Нижний Новгород → Нижнего Новгорода… (прилагательное + существительное); Пушкин (город) → Пушкина, Пушкину, Пушкин, Пушкином, Пушкине (вин = им для неодушевлённых!). Несклоняемые (на -о, -е, -и, -у: Сочи, Тбилиси, Осло) — все падежи равны им. п. Всё непонятное → None. Префиксы «г.», «город», «с.», «пос.», «дер.» сохраняются без изменений, склоняется только название после них: «г. Москва» → «г. Москве» (пр.).

**Country.** Словарь стран (data/dict/countries.txt) + многословные: Российская Федерация → Российской Федерации, …, Российскую Федерацию, Российской Федерацией, Российской Федерации; Россия → России…; Беларусь → Беларуси…; Казахстан → Казахстана…; Республика Беларусь → Республики Беларусь (склоняется только «Республика»).

**Street.** «ул. Лесная» → склоняется только прилагательное: Лесной, Лесной, Лесную, Лесной, Лесной; «ул. Пушкина», «ул. 8 Марта», «проспект Мира» — родительный падеж имени, не склоняются → вернуть как есть (Some(value)). «Ленинский проспект» → Ленинского проспекта…

**Тесты** — tests/morph.rs, табличные: для каждого значения ниже — все 6 падежей, и обратно: `inflect(форма_в_падеже_X, kind, Nom) == им. п.` для каждой формы.
- Person: «Иванов Иван Иванович», «Иванова Мария Петровна», «Петров Илья Сергеевич», «Кузнецова Любовь Андреевна», «Смирнов Андрей Игоревич», «Толстой Лев Николаевич», «Достоевский Фёдор Михайлович», «Шевченко Тарас Григорьевич» (фамилия не склоняется), «Сидорова Анна» (без отчества), «ИВАНОВ ИВАН» (регистр).
- Place: Москва, Казань, Омск, Тверь, Нижний Новгород, Пушкин, Сочи (все падежи = Сочи).
- Country: Россия, Российская Федерация, Беларусь, Казахстан, Республика Беларусь.
- Street: «ул. Лесная», «ул. Пушкина» (как есть), «Ленинский проспект».
- Непонятное → None: «Xyz Абв», «12345».

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test --test morph && cargo test`.

Файлы: src/morph/mod.rs (новый), src/lib.rs, tests/morph.rs (новый). Больше ничего. Каталог logs/ не трогай. Кириллица допустима только в таблицах окончаний/исключений — вынеси их в `const` массивы в начале модуля. После плана сразу пиши код.
</task>

<task id="T23b">
Привет. Встраиваем склонение (src/morph из T23a) в восстановление и в прокси к LLM.

1. Токен с падежом: `<<FIO_1:дат>>`, `<<fio_1 : dat>>`, `<<BPLACE_1:пр>>` — регистр и пробелы как у обычных токенов. В src/mask/mod.rs `unmask`: если у токена есть суффикс падежа и `morph::Case::parse` его понимает — восстановить `morph::inflect(original, kind, case).unwrap_or(original)`; kind по типу: fio/card_holder → Person, birth_place → Place, citizenship → Country, address → Street если значение начинается с маркера улицы, иначе Place. Прочие типы — суффикс игнорируется, возвращается оригинал. Токены без суффикса — ровно как раньше (round-trip /process не меняется ни на байт).
2. `count_unresolved_tokens` и метрика — учитывают токены с суффиксом.
3. Прокси /v1/chat/completions: новый флаг `llm.case_hints: bool` (default true). Если true — первым сообщением в upstream добавить system: "Placeholders like <<FIO_1>> stand for hidden personal data. Keep them unchanged. If a Russian grammatical case is needed, append it inside the brackets: <<FIO_1:gen>>, <<FIO_1:dat>>, <<FIO_1:acc>>, <<FIO_1:ins>>, <<FIO_1:prep>>; nominative is <<FIO_1:nom>>." В демо-режиме (без upstream) имитировать ответ: «Уважаемый <<FIO_1:им>>, сообщаем…» — чтобы склонение было видно.

Тесты:
- tests/mask.rs (дописать, старое не менять): маска «Иванову Ивану Ивановичу» → `<<FIO_1>>`; unmask «Дорогой <<FIO_1:им>>» → «Дорогой Иванов Иван Иванович»; «<<FIO_1:дат>>» → «Иванову Ивану Ивановичу»; «<<FIO_1>>» → исходное; «<<INN_1:дат>>» → исходный ИНН; «родился в <<BPLACE_1:пр>>» при оригинале «Москва» → «родился в Москве».
- tests/llm.rs: фейковый upstream отвечает «Дорогой <<FIO_1:nom>>, с прискорбием сообщаем…» на запрос «Напиши письмо с отказом Иванову Ивану Ивановичу» → клиент получает «Дорогой Иванов Иван Иванович, с прискорбием сообщаем…»; проверить, что upstream получил system-подсказку, а с `case_hints: false` — не получил.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,10,11,13,20,21`.

Файлы: src/mask/mod.rs, src/llm/mod.rs, src/server/mod.rs, src/config/mod.rs, tests/mask.rs, tests/llm.rs. Каталог logs/ не трогай.
</task>

<task id="T25">
Привет. Срочная производительность хранилища (src/store/mod.rs). Нашли на нагрузке: когда записей становится `max_entries`, каждый `insert_with_hash` делает `sweep()` (обход всей таблицы) и `evict_oldest()` (ещё один полный обход). При 200 тыс. записей пропускная способность падает с 6400 до 700 запросов/с, задержка — до 1 с.

Сделать:
1. `sweep()` больше не вызывается из insert. Вместо этого фоновая задача в src/server/mod.rs: `tokio::time::interval(Duration::from_secs(5))` → `store.sweep()`, запускается в `run()`. Сделай у MappingStore метод `pub fn spawn_sweeper(self: &Arc<Self>, every: Duration)` или аналог — как удобнее, но без блокировки async-потоков на большой таблице (sweep в `spawn_blocking`).
2. Вытеснение при переполнении — O(1) амортизированно: храни порядок вставки в `Mutex<VecDeque<(String, Instant)>>` (или `crossbeam`-очередь, если уже есть в зависимостях; новых зависимостей не добавлять). При `len >= max_entries` вынимай из головы очереди ключи и удаляй их из DashMap, пока не освободится место (запись могла уже удалиться sweep'ом — просто пропусти). Sweep тоже чистит голову очереди от просроченных.
3. config.yaml: `mapping_max_entries: 2000000` (≈1,1 КБ на запись → ~2,3 ГБ на пределе, у сервера 8 ГБ).
4. Метрика `pii_store_evictions_total` (вытеснено по переполнению) и `pii_store_expired_total` (убрано по TTL).

Тесты в tests/store.rs (старые не менять): 
- max_entries=1000, вставить 5000 → len ≤ 1000, самые старые вытеснены, последние 1000 на месте;
- производительность: max_entries=10_000, вставить 200_000 записей — должно уложиться в 2 с в debug (сейчас это минуты);
- просроченные убираются sweep'ом, get просроченной → None.

Приёмка: `cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release && python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml --port 18190 && MANUAL_PORT=18197 bash tools/manual_accept.sh --only 1,5,13,20,21,22,23`.

Файлы: src/store/mod.rs, src/server/mod.rs, config.yaml, tests/store.rs. Каталог logs/ не трогай.
</task>
