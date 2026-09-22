# SOURCES.md

Дата доступа: 2026-09-22 (обновлено: клон pii-guard, карточки pii_train/rubert-base-pii-ner, метаданные HF Hub через API).

## Официальный pii-guard + модель + данные (redmadrobot-rnd)

1. redmadrobot-rnd/pii-guard — https://github.com/redmadrobot-rnd/pii-guard — **Apache-2.0** — клон `research/references/pii_guard/upstream/` (depth 1, 2026-09-22). Использовано: `README.md` (20 типов, pipeline), `docs/architecture.md` (C4, бюджеты, offsets), `docs/quality.md` + `tests/quality/` (протокол strict/overlap, gate micro_f1 0.974513), `docs/usage.md`, `models/README.md` (678MB, 43 BIO, env `PII_GUARD_NER_MODEL/REVISION`), `src/pii_guard/engine.py|config.py|detect.py`, `framework/*` (conflict_resolver, resolvers, context 80/260, normalize, spans), `entities/*` (КС/приоритеты/scores), `ner/*` (512/stride-128/0.70), `anonymizer.py|operators.py|pseudonymize.py`, `NOTICE` (сторонние лицензии, GPL-исключение gender-guesser opt-in).
2. redmadrobot-rnd/rubert-base-pii-ner — https://huggingface.co/redmadrobot-rnd/rubert-base-pii-ner — **Apache-2.0** — base `ai-forever/ruBert-base`, 178M/F32, 21 тип/43 BIO, train 17,137/39,687, eval `pii_benchmark` 2,841. Метрики (self-reported, exact 14 кат.): P81.9/R85.5/F1 83.6; пайплайн 90.4/87.5/88.9; PERSON+LOCATION overlap 94.7/95.0. Гиперпараметры: 10 эпох, lr 3e-5, batch 16, AdamW 0.01, seed 42. Веса не скачивались.
3. redmadrobot-rnd/pii_benchmark — https://huggingface.co/datasets/redmadrobot-rnd/pii_benchmark — **MIT** — sha `f77ea83`, 2841 rows, `test.csv` ~3.2MB. Скачан целиком в `datasets/redmadrobot/pii_benchmark/`.
4. redmadrobot-rnd/pii_train — https://huggingface.co/datasets/redmadrobot-rnd/pii_train — **MIT** — sha `1a74b9f`, 17137 rows, `train.csv` ~12.7MB. Скачан целиком в `datasets/redmadrobot/pii_train/`.

## Код / архитектура (прочее)

5. microsoft/presidio — https://github.com/microsoft/presidio — Apache 2.0.
6. brikkoAI/presidio-ru-recognizers — https://github.com/brikkoAI/presidio-ru-recognizers — MIT (сверка КС).
7. Natasha/slovnet/naeval — https://github.com/natasha/* — MIT.
8. gantz-ai/pii.engineer — https://github.com/gantz-ai/pii.engineer — Apache 2.0 (Rust+ONNX прецедент).

## Checksum / форматы

9. ФНС-методика ИНН — https://htmlweb.ru/php/example/test_inn_bik_kpp_ogrn.php; https://pro-chislo.ru/validator/inn.
10. СНИЛС/ОГРН — https://habr.com/ru/articles/1046397; https://pro-chislo.ru/validator/snils; https://focus.kontur.ru/site/poisk/ogrn-po-inn.
11. Госуслуги валидация — https://info.gosuslugi.ru/articles/Валидация.

## Rust

12. rust-lang/regex — https://github.com/rust-lang/regex — MIT/Apache-2.0.
13. aho-corasick — https://docs.rs/aho-corasick — MIT/Unlicense.

## Право

14. 152-ФЗ ст.3 — https://base.garant.ru/12148567/5ac206a89ea76855804609cd950fcaf7; https://www.consultant.ru/cons/cgi/online.cgi?base=LAW&n=61801.
15. Обезличивание/ГИС — https://www.law.ru/article/28041-obezlichivanie-personalnyh-dannyh-novye-pravila-s-1-sentyabrya-2025-goda.
