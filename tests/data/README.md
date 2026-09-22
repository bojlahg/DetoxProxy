# Corpus DetoxProxy (research)

`external_rmr` — только реальный маппинг benchmark. `synthetic`, `hard_negatives`, `conflicts` — только выдуманные данные. Реальных ПД нет нигде.

Offsets — **Unicode character offsets** (Python `str` индексы, `start` inclusive, `end` exclusive): `text[start:end] == entity.text`.
Байтовые offsets для Rust: `len(text[:start].encode('utf-8'))`.

## Файлы

- `external_rmr/rmr_benchmark_alfa.jsonl` — 2841 строк из `pii_benchmark/test.csv` (MIT). Поля: `id=rmr-NNNNN`, `entities=[{type,start,end,text,rmr_label}]`, `source=redmadrobot-pii_benchmark`. FIO/ADDRESS склеены из частей (gap ≤2). Сборка: `dataset_convert.py` (весь файл, без лимита).
- `synthetic/synthetic_alfa.jsonl` — 302 разнообразных позитива по 17 Alfa-категориям (варианты регистра, разделителей, контекста).
- `synthetic/synthetic_missing_categories.jsonl` — 2156: 9 категорий × ~120 pos + ~120 neg (дедуплицировано по тексту).
- `synthetic/multi_entity.jsonl` — 80 сложных (multi-2/3/5/10).
- `hard_negatives/hard_negatives.jsonl` — 219 уникальных (famous, org-address, historic-date, bad-checksum, format-talk, fiction, meta-numbers, fiction-person-or-infra).
- `conflicts/overlap_conflicts.jsonl` — 105 кейсов: `entities` (gold), `candidates` (пересекающиеся альтернативы со `score`+`rule`), `conflict` (тип), `expected` (кто должен выиграть и почему). Типы: INN-vs-PASSPORT, PASSPORT-vs-DRIVER_LICENSE, CARD-vs-OMS, PHONE-fragment, ADDRESS-merge-vs-single, ADDRESS-suppressor, EMAIL-vs-URL, IP_PORT-vs-IP_ADDRESS, DIVISION_CODE/CVV-gate, FIO-merge-vs-parts.

## Пересборка

```
python research/tools/generate_corpora.py --seed 20260922
python research/tools/corpus_stats.py --corpus research/corpus
python research/tools/dataset_inspect.py --file research/corpus/conflicts/overlap_conflicts.jsonl --limit 5
```

Генератор детерминирован (seed), тексты уникальны в пределах файла (счётчик `dups skipped` в выводе).
