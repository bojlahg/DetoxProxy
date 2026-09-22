# Сторонние данные и их лицензии

| Данные | Источник | Лицензия | Использование |
|---|---|---|---|
| Фамилии (муж. форма, с частотой), имена м/ж, отчества | ulzr/realistic-russian-names — https://github.com/ulzr/realistic-russian-names | Unlicense | `data/dict/raw/*.yaml` → словари детектора |
| Имена (7,6k) | natasha/natasha — https://github.com/natasha/natasha | MIT | `data/dict/raw/first.txt` |
| Размеченный корпус PII (2841 текстов) | redmadrobot-rnd/pii_benchmark — https://huggingface.co/datasets/redmadrobot-rnd/pii_benchmark | MIT | `tests/data/rmr_benchmark_alfa.jsonl` — оценка точности |
| Отложенные наборы (только измерение, правила по ним не настраивались) | hivetrace/pii-bench (Apache-2.0), just-ai/jayguard-ner-benchmark (MIT), alrosait/pii-synthetic-ru (MIT), scanpatch/pii-ner-corpus-synthetic-controlled (MIT) — Hugging Face | Apache-2.0 / MIT | `tests/data/holdout/*.jsonl`, конвертер `tools/convert_holdout.py` |
| Синтетические тексты, негативы, конфликты | собственная генерация (seed 20260922), реальных ПДн нет | — | `tests/data/*.jsonl` |
| Таблица сокращений адресных элементов | приказ Минфина № 171н; ФИАС SOCRBASE (hflabs/socrbase) | НПА / открытые данные | правила детектора адресов |
| Контрольные суммы ИНН/СНИЛС/Luhn | публичные алгоритмы регуляторов | не охраняются | валидаторы |

Архитектурные идеи: redmadrobot-rnd/pii-guard (Apache-2.0), microsoft/presidio (Apache-2.0) — код не копировался.
