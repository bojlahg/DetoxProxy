# Spans, конфликты, производительность

## 1. Span representation (байты vs символы)

- Rust `String` индексируется **байтами** (UTF-8). Кириллица — 2 байта/буква. Резать `&s[a..b]` можно только по `is_char_boundary`.
- Хранить: `{start_byte, end_byte, entity_type, confidence, source}` (+ опционально `start_char` для отладки/совместимости с Python).
- В corpus: фиксируем **Unicode character offsets** (Python `str` индексы — как в ТЗ-примере), а в `corpus/README.md` документируем конвертацию `char → byte` (`len(text[:char].encode('utf-8'))`).
- Замены применять **справа налево** по `end_byte desc` — тогда ранние offsets не съезжают. Альтернатива — строить новый String за один проход по отсортированным спанам (предпочтительно для 100k tokens — меньше меммувов).
- Graphemes (ё+диакритика, эмодзи ZWJ) для ПД нерелевантны; нормализация NFC один раз на входе, дальше — байты.

## 2. Span conflicts

Случаи: вложенность (`+7 999...` внутри `ADDRESS`?), частичное пересечение, одинаковый span разных типов (ИНН-10 vs паспорт 4+6).

Стратегии (порядок приоритета):
1. `validated > regex-only` (КС 1.0 бьёт 0.4).
2. `context-aware > context-free` (есть keyword рядом).
3. `longest span` при равном score (адресная склейка бьёт отдельный CITY).
4. `priority` per-type (CARD > PHONE > INN > PASSPORT для числовых коллизий — настраивается).
5. `confidence` как tie-breaker последнего уровня.

Реализация: сортировка по `(start, -end, -score)`, sweep-line с подавлением пересекающихся, либо per-span-group `max_by(score, length)`.

## 3. Производительность detection pipeline (оценки, не benchmark DetoxProxy)

| Стадия | Сложность | Заметки под 100k tokens / 1000–2000 RPS / ≤0.5–1.0s |
|---|---|---|
| regex scan | O(n·m) naive → O(n) с `RegexSet`/автоматом | Один проход `RegexSet`, предкомпилированные, без backtracking; чанкинг с overlap 256 символов |
| Aho-Corasick (keywords/словари) | O(n + k) | Один проход по всем литералам; SIMD-prefilter |
| Dictionary lookup (FST/PHF) | O(token) | Только на кандидатах, не на весь текст |
| Checksum (ИНН/СНИЛС/ОГРН/Luhn) | O(L) цифр | Дешёвая арифметика, режет FP до NER |
| NER inference | O(n·d) | Единственный риск: BERT/GLiNER не уложатся в 0.5s на 100k tokens CPU; slovnet-CNN — погранично; запускать только на окнах-кандидатах или отдельным tier |

Ловушки: многократное сканирование (N recognizers × N проходов — заменить на 1–2 прохода), catastrophic regex (`(a+)+` — невозможен в `regex` crate, но следить за `.*` с Unicode), аллокации на каждый матч (использовать `find_iter` + reuse буферов), копирование 100k-строк (работать по `&str`/срезам), Unicode normalization per match (нормализовать один раз), ML inference в hot path (вынести за скоуп p50).

Архитектору: pipeline `prefilter (AC+RegexSet) → validators (КС) → context boost → (optional) NER на окна → resolve → anonymize` укладывается в бюджет без GPU, если NER — только slovnet-уровень и только на кандидатах.
