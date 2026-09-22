# Rust ecosystem для DetoxProxy

Источники: docs.rs, crates.io, github rust-lang/regex. Дата 2026-09-22. Лицензии проверены по crates.io.

| Crate | Назначение | Актуальность | Лицензия | Overhead / заметки | Вердикт |
|---|---|---|---|---|---|
| `regex` (+ `regex-automata`, `regex-syntax`) | основной regex-движок | активно (rust-lang) | MIT/Apache-2.0 | предкомпиляция `Regex::new` once (lazy_static/OnceLock), thread-safe (`Send+Sync`), Unicode по умолчанию (UTS#18 Level1), byte offsets `find_iter`, без backtracking (нет catastrophic) | **брать** |
| `aho-corasick` | bulk multi-pattern (контекстные слова, словари) | активно (BurntSushi) | MIT/Unlicense | линейное время, `MatchKind::LeftmostLongest`, byte offsets, SIMD-prefilter, `find_overlapping_iter` | **брать** для keywords/словарей |
| `fst` | компактные словари (фамилии/города) | стабилен | MIT/Apache | memory-mapped, но сборка медленная; альтернатива — `phf`/sorted Vec | рассмотреть для больших словарей |
| `phonenumber` | парсинг телефонов | средняя (порт libphonenumber) | MIT/Apache | тяжёлый, медленный; для RU достаточно своего regex+длина | **не брать**, свой валидатор |
| `luhn` | Luhn для карт | мал, стабилен | MIT/Apache | тривиально, можно inline 10 строк | брать или inline |
| `unicode-normalization` | NFC/NFKC | стабилен | MIT/Apache | нужен только если нормализуем `ё`/латиницу; аллокации | опционально, по необходимости |
| `serde` (+ `serde_json`) | corpus/config сериализация | стандарт | MIT/Apache | — | брать для tools/config |
| `dashmap` | concurrent map (кэш/состояние токенов) | популярен | MIT | sharded locks; для read-heavy — `papaya`/`parking_lot+HashMap` | рассмотреть, не обязательно |
| `tokio` | async runtime | стандарт | MIT | нужен для 1000–2000 RPS HTTP | брать |
| `axum` | HTTP server | стандарт (tokio-team) | MIT/Apache | лёгкий, быстрый | брать |

Ключевые ответы:
- Предкомпиляция regex: да (`Regex::new` → `Arc/OnceLock`, `RegexSet` для bulk).
- Thread safety: `regex::Regex: Send+Sync`, можно шарить между потоками.
- Unicode: `(?i)` Unicode-aware, `\p{Cyrillic}`, `\b` Unicode word boundary (с оговорками по perf на не-ASCII — см. UNICODE.md).
- Без аллокаций: `find_iter`/`captures_read_at` возвращают offsets без копирования haystack; замены — справа-налево в `String::replace_range`.
- Byte offsets: все матчи — bytes; для русских строк резать только по `is_char_boundary`.
- Bulk: `RegexSet` (много regex за проход) + `AhoCorasick` (литералы) — избегать N проходов по 100k tokens.
