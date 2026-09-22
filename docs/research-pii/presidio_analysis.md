# Presidio: архитектурный разбор для переноса в Rust

Источник: github.com/microsoft/presidio (Apache 2.0), docs microsoft.github.io/presidio, код `presidio-analyzer` (AnalyzerEngine, PatternRecognizer, EntityRecognizer, ContextAwareEnhancer). Дата доступа 2026-09-22.

## 1. Компоненты

```
text
  → NlpEngine (spaCy/Transformers/Stanza: tokens, lemmas, NER)
  → RecognizerRegistry (все EntityRecognizer)
       → PatternRecognizer (regex + deny-list + validate + context)
       → EntityRecognizer (NER/ML/remote)
  → candidate RecognizerResult[] (entity_type, start, end, score)
  → ContextAwareEnhancer (LemmaContextAwareEnhancer)
  → conflict resolution (overlap removal) + score threshold
  → final spans
  → AnonymizerEngine (mask/hash/encrypt/replace) + DeanonymizerEngine (decrypt/resolve)
```

- **AnalyzerEngine** (`analyzer_engine.py`): оркестратор. Принимает `text, language, entities, correlation_id`. Вызывает `nlp_engine.process_text`, затем каждый recognizer из registry, затем `enhance_using_context`, затем фильтрует по `score_threshold` и разруливает пересечения. Поддерживает `REGEX_TIMEOUT_SECONDS` (default 60) против catastrophic backtracking.
- **PatternRecognizer** (`pattern_recognizer.py`): regex или deny-list + `patterns: Pattern(name, regex, score)` + `context: list[str]` + `validate_result()` / `invalidate_result()` хуки + `deny_list_score`. Именно сюда встраиваются checksum (пример: `CreditCardRecognizer` с Luhn).
- **EntityRecognizer**: абстрактный базовый класс. `analyze(text, entities, nlp_artifacts)`. Переопределяемый `enhance_using_context`.
- **RecognizerRegistry + RecognizerRegistryProvider**: YAML-конфиг `default_recognizers.yaml` (какие recognizers включены per language). `add/remove_recognizer`, `load_predefined_recognizers`.
- **ContextAwareEnhancer**: лемматизирует контекст вокруг спана (±N слов, default window ~10), считает схожесть с `context` списком recognizer'а, добавляет `CONTEXT_SIMILARITY_FACTOR` (0.35 в тестах) к score. Реализация — `LemmaContextAwareEnhancer`.
- **Anonymizer**: операторы `mask`, `redact`, `replace`, `hash`, `encrypt` (AES), `custom`. Применяет замены справа налево, чтобы не ломать offsets. **Deanonymizer**: `decrypt` + `Encrypt/Decrypt` key management; для stateful tokenization нужен внешний store.
- **Conflict resolution**: в `AnalyzerEngine.analyze` — удаление дубликатов и пересечений: приоритет higher score; при равном — longer span. Тест `test_when_analyze_two_entities_embedded_then_return_results` это покрывает.

## 2. Формула `pattern + validation + context = PII span`

```python
candidates = regex_match(text, pattern.regex)          # score = pattern.score (0.01 weak … 0.6 medium … 1.0 strong)
if recognizer.validate_result(match): score → 1.0      # напр. Luhn/ИНН-КС
else: score stays low / dropped
score += context_boost if context_word nearby          # +0.35 в дефолте
if score >= threshold and not invalidated: emit span
```

Это ровно то, что нужно для DetoxProxy: каждый recognizer = `{regex, validator, context, base_score}`.

## 3. Confidence scoring (как перенести)

- Weak pattern (только формат): 0.01–0.4 (пример: zip `0.01`, паспорт без КС `0.4` в ru-recognizers).
- Medium (формат + сепараторы): 0.4–0.6.
- Validated (прошёл checksum): 1.0.
- Context boost: +0.15…0.35 с затуханием по расстоянию.
- NER: score от модели (softmax), обычно 0.5–0.9.

## 4. Что разумно перенести в Rust (рекомендации архитектору, не решение)

1. Трейт `Recognizer { fn analyze(&str) -> Vec<Candidate> }` + `PatternRecognizer { patterns: Vec<CompiledRegex>, validator: fn(&str)->bool, context: Vec<&str> }`.
2. `Registry` с per-language списками + YAML-конфиг включения.
3. `ContextEnhancer`: Aho-Corasick по леммам/нижним формам ключевых слов в окне ±64–128 символов, boost с decay `1/(1+dist/k)`.
4. Overlap resolution: `validated > context-aware > longer > higher-base-score`.
5. Anonymizer справа-налево по `end_byte` desc, byte offsets (Rust strings — bytes).
6. `REGEX_TIMEOUT` аналог: `regex-automata` без backtracking + лимит haystack chunk (100k tokens → чанкинг с overlap).

## 5. Ограничения Presidio (не скрываем)

- Тяжёлый: spaCy модель 500MB+, startup >2s. Для 1000–2000 RPS и ≤0.5s не годится без серьёзной переделки.
- Нет русской локали из коробки (только en + частично es/it/pl/ko). Русские recognizers — только сторонние (см. `docs/russian_recognizers.md` — brikkoAI).
- NER — spaCy/Transformers, на CPU медленный; для 100k tokens неприменим без чанкинга/GPU.
- Лицензия Apache 2.0 — перенос идей разрешён, копирование кода в Rust всё равно требует переписывания.

Лицензия: Apache 2.0 (microsoft/presidio). Совместима с закрытым кодом при сохранении NOTICE.
