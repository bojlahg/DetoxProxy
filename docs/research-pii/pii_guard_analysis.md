# pii-guard: разбор официального кода redmadrobot-rnd/pii-guard

Источник: клон `github.com/redmadrobot-rnd/pii-guard` в `references/pii_guard/upstream/` (commit на 2026-09-22, глубина 1).
Лицензия репозитория: **Apache-2.0** (`upstream/LICENSE`, бейдж `README.md:9`, `pyproject.toml:11`).
Веса NER: `redmadrobot-rnd/rubert-base-pii-ner`, Apache-2.0, в git не лежат (`.gitignore`, `models/README.md`), качаются один раз с HF Hub, дальше офлайн (`docs/architecture.md:58-59`).
Зависимости по `NOTICE`: presidio-analyzer/anonymizer MIT, spaCy MIT, pymorphy3 MIT, thefuzz MIT, lingua Apache-2.0, torch BSD-3, transformers Apache-2.0, базовый `ai-forever/ruBert-base` Apache-2.0. Исключение: `latin-gender/gender-guesser` GPLv3 — только opt-in, иначе деградация в `unknown` (`NOTICE:66-82`, `pseudonymize.py:101-115`).
Код НЕ копируем в DetoxProxy (требование ТЗ) — ниже только факты для переноса идей.

## 1. Сущности: что ловит regex, что — ML

Всего 20 типов (`README.md:40-63`, `config.py:32-37 DEFAULT_ENTITIES`):

- **ML-only** (`config.py:42-44 NER_ONLY_ENTITIES`): `PERSON`, `LOCATION`, `PHONE_NUMBER`, `URL`. Отдельных regex-классификаторов для них нет — только NER.
- **Deterministic numeric** (`src/pii_guard/entities/*.py` через `@register_entity`, 12 файлов, в `docs/architecture.md:128` заявлено как 16 framework-типов = 12 + 4 regex): `INN`, `SNILS`, `PASSPORT`, `DRIVER_LICENSE`, `MILITARY_ID`, `BIRTH_CERTIFICATE`, `CREDIT_CARD`, `OMS`, `BANK_ACCOUNT`, `BIK`, `POSTAL_CODE`, `TELEGRAM`.
- **Deterministic regex** (через `@register_regex_entity`): `DATE_TIME` (8 PatternRecognizer, `date_time.py:183-259`), `EMAIL_ADDRESS`, `IP_ADDRESS`, `IP_PORT`.
- Двойное покрытие: NER также эмитит шумные/OCR-варианты `EMAIL/PHONE/URL/IP + PASSPORT/CREDIT_CARD/DRIVER_LICENSE/INN/SNILS/MILITARY_ID/BIRTH_CERT/OMS` как fallback (`engine.py:14-18,59-81 NER_ENTITY_MAPPING`), но в конфликте они проигрывают правилам.

Правило проекта (`README.md:37`): правила ловят то, что проверяется контрольной суммой, модель — то, что суммой не проверить.

## 2. Конвейер (реальный, не реконструкция)

`README.md:15-35` (mermaid), `engine.py`, `docs/architecture.md:120-159`:

```
Текст → Нормализация → (EN-числительные) → (Base64-сканирование) → (Транслит+lang-guard)
  → Ветка A: правила (NumericPIIRecognizer + regex-recognizers, detect.py:51-61)
  → Ветка B: NER (ленивый импорт torch, engine.py:205-229; без torch — только правила + warn NER_ONLY)
  → слияние: resolve_ml_vs_rules_conflicts → resolve_conflicts → allowlist → AnonymizerEngine
  → mask / tag / pseudonymize (+ deanonymize с падежами)
```

1. **Нормализация** (`engine.py:283`, `framework/normalize.py:158-222`): 1:1 замена пробелов/тире, чистка soft/zero-width, схлопывание пробелов, числительные словами (≥4 букв) и количественные до 1000 в цифры.
2. **EN-числительные** (`engine.py:285-286`, `config.py:101 enable_en_numbers`).
3. **Base64** (`engine.py:288-317`): бюджет `MAX_B64_BLOBS=32`, `MAX_B64_DECODED_CHARS=20000` (`engine.py:103-104`); превышение — отказ, а не пропуск (`Base64BudgetExceeded`); декодированное пере-анализируется и схлопывается к границам блоба.
4. **Транслит + lang-guard** (`engine.py:320-339`): блобы маскируются (`_mask_spans`), при `looks_like_translit + is_confident_foreign(0.90)` текст транслитерируется в кириллицу (`SpanMap`), анализируется, спаны ремаппятся (`_remap_results`); результат аддитивный (`orig + non_overlapping(orig,cyr)`), чтобы не потерять `II` серии.
5. **Правила + NER параллельно** (`_analyze_raw`, `framework/recognizer.py:102-154`): `normalize_safe → iter_candidates → get_context/get_wide_context → registry.classify → data_spans` (разбиение `серия 7518, номер 492137` на два спана — `framework/spans.py:37-70`, `docs/usage.md:30-37`).
6. **Фасад** (`anonymizer.py:107-160`): `mask` напрямую, `tag` через `build_tagged_text` справа-налево, `pseudonymize` через batch; глобальный lock (spaCy/torch не thread-safe); offsets индексируют **нормализованный** текст (`anonymizer.py:39-44`, `docs/usage.md:23-28`) — для подсветки исходника нужен собственный ремап.

## 3. Deterministic recognizers (факты из entities/)

Конвенция (`framework/base.py:52-109`): `entity_type, priority, candidate_patterns, conflict_wins_over, classify(...) -> (type, score)|None`; побеждает max score (`base.py:273-296`).

- **INN** (`inn.py`): строгие `\d{10}`, `\d{12}` с анти-склейкой; КС10 `[2,4,10,3,5,9,4,6,8] %11%10`, КС12 два каскада; keywords `инн|налогов...`; INN12→0.95, INN10 с ближним контекстом 80/160→0.90, без серии/паспорта/прав→0.85; `priority 40`, бьёт PHONE.
- **SNILS** (`snils.py`): 11 цифр, `Σd*(9-i)`, `<100 / =100,101 / %101==100→0` → 0.95; `priority 30`, бьёт PHONE.
- **PASSPORT** (`passport.py`): 10 цифр любой группировкой, КС нет; keyword рядом→0.80, оба+resolver→0.75; `priority 60`.
- **DRIVER_LICENSE** (`driver_license.py`): зеркально паспорту; `priority 70`.
- **BIRTH_CERTIFICATE** (`birth_certificate.py`): римские `I..D` 1–4 + кириллица/латиница 2 + 6 цифр; strict 0.95/0.85, loose 0.90/0.80; `priority 10`.
- **MILITARY_ID** (`military_id.py`): 2 буквы + 7 цифр, strict/ambig (`РФ,RF,ИИ,II`); бюджеты 60/140/40; до 0.95; `priority 20`.
- **CREDIT_CARD** (`credit_card.py`, `_card_common.py`): Luhn; 13/15/18/19+Luhn→0.90; 16+Luhn против OMS-паттернов на дистанции 100/220: card-only 0.90, ближе 0.85, ничья 0.60; `priority 50`.
- **OMS** (`oms.py`): 16 цифр+Luhn, зеркальные дистанции; `priority 51`.
- **BANK_ACCOUNT + BIK** (`bank_account.py`, `_bik_common.py`, `bik.py`): счёт 20 цифр, КС ЦБ `веса [7,1,3]*7+[7,1]`, префикс от БИК; БИК 9 цифр `04 + 050-999`, окно 40; BIK+valid→0.97, без БИК с контекстом→0.90; `priority 45/50`.
- **POSTAL_CODE** (`postal_code.py`): 6 цифр, префиксы `101-499|600-699`; keywords + veto (`биржев`) + negatives; 0.92; `priority 60`.
- **TELEGRAM** (`telegram.py`): только `@[A-Za-z]\w{4,31}`, veto INSTAGRAM ≤40 → 0.90; `t.me`-ссылки сознательно отданы URL.
- **DATE_TIME** (`date_time.py`): 8 PatternRecognizer 0.75–0.85 (русские полные, точки/тире, время, слэши, ISO, год, аббревиатуры, английские).
- **EMAIL/IP/IP_PORT**: email с пробелами 0.85; IPv4/IPv6 полный/частичный/сжатый 0.85–0.90; `IP_PORT` 0.6 (чтобы внутренний IP выигрывал без правила).

## 4. Как объединяются результаты и разрешаются пересечения

`framework/conflict_resolver.py:63-195`, `engine.py:20-25`:

0. **ML vs rules** (`resolve_ml_vs_rules_conflicts`): все правила сохраняются, NER — только без пересечений. Правила важнее модели даже при ошибке (`docs/architecture.md:163-168`).
1. **`conflict_wins_over`**: почти все numeric бьют `PHONE_NUMBER`.
2. **Pairwise**: `EMAIL>URL`, `IP_PORT>IP_ADDRESS`, `URL>IP_ADDRESS`, `IP_ADDRESS>PHONE`, `IP_PORT/ADDRESS/URL > DATE_TIME`; ацикличность охраняется тестом-треугольником (`test_conflict_resolution.py:162-185`).
3. **Кастомные хендлеры**: URL в email, DATE_TIME в IP/нормативных кодах, дроп IP без цифр.
4. **Same-type dedup**: более длинный выигрывает.
5. **Score**: жадный по `(-score, -len, start)`; NER фиксированно 0.70 ниже правил (≥0.75, `config.py:80-85`) — score решает только среди правил.
6. **Паспорт vs права**: отдельный `resolve_passport_dl_conflict` (`resolvers.py:84-128`): ближний контекст 80/160, иначе центр, хвост 200.

## 5. Контекст, дистанция, confidence

`framework/context.py:59-103`: `get_context(80)` в пределах предложения (`./!?;\n`, затем ±80) + `get_wide_context(260)`; `nearest_distance` по центрам, `nearest_before_distance` с лимитом. Принцип (`docs/architecture.md:170-178`): важна **дистанция, а не наличие**. Измеренные бюджеты: документы 80/160/after200, БИК 40, счёт 120, военник 60/140/40, индекс 60/45, ИНН 80/160, карта/ОМС 100/220. Confidence = базовый score паттерна + классификатор (КС/дистанция), NER = 0.70 фикс.

## 6. Masking / tokenization / pseudonymization

`operators.py`, `engine.py:362-381`, `pseudonymize.py`:

- **mask**: Presidio AnonymizerEngine, `mask_char=*`, маскировать всё (иначе хвост 99 символов на блобах/адресах).
- **tag**: `[TYPE]` справа-налево.
- **pseudonymize**: `<PII type gender id/>`; склейка соседних PERSON через пробел (`MAX_NAME_PARTS=3`); дедуп `TYPE::norm` + fuzzy (PERSON 85 на именительном через pymorphy3, LOCATION 90, только без цифр); счётчики в `PseudonymizationState`, стабильны в batch/сессии; PERSON хранится в именительном, LOCATION как в тексте.
- **deanonymize**: PERSON/LOCATION склоняются обратно (spaCy `ru_core_news_sm` + pymorphy3, окно 150, заморозка `Мира/Ленина`), остальные дословно; fuzzy-поиск тега, бюджет `len(<PII)` против chain-DoS; остатки → `****`. Таблица у вызывающего (stateless), утечка — только если caller отправит её наружу.

## 7. Hard negatives и ограничения (из кода и тестов)

- Явные тесты: `test_classifiers_conflicts.py`, `test_conflict_resolution.py`, `postal_code` veto/negatives, `IP-no-digits` дроп, base64-бюджеты, translit-аддитивность.
- Задокументированные ограничения (`docs/architecture.md:163-194`, `docs/usage.md`): правила прячут правильный NER на пересечении; composite-документы = два спана/маски; offsets — по нормализованному тексту; `MAX_NAME_PARTS=3` режет длинные ФИО без запятой; `mps` не auto; сервер без auth по умолчанию, лимиты после парсинга body (нужен proxy `client_max_body_size`), семафор 503.

## 8. Что берём в DetoxProxy (идеи, не код)

1. Двухветочную схему `правила (16 типов) + ruBERT (PERSON/LOCATION/PHONE/URL)` с приоритетом правил.
2. Дистанционные бюджеты контекста вместо бинарного наличия.
3. Exact pairwise-таблицу конфликтов и greedy `(-score,-len,start)`.
4. Разбиение `серия/номер` на data-only спаны + склейку PERSON до 3 частей.
5. Base64/транслит-препроцессинг с бюджетами и аддитивностью.
6. Benchmark-протокол из `tests/quality/` (strict + type-overlap, 1:1, regression-gate `micro_f1`, `require_same_dataset`).
