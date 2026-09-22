# Лицензии внешних проектов и датасетов

| Проект/данные | URL | Лицензия | Можно ли тащить код/данные |
|---|---|---|---|
| redmadrobot-rnd/pii-guard (код) | github.com/redmadrobot-rnd/pii-guard | **Apache-2.0** | Идеи — да; код не копируем по ТЗ; клон только для чтения |
| redmadrobot-rnd/rubert-base-pii-ner (веса) | huggingface.co/redmadrobot-rnd/rubert-base-pii-ner | **Apache-2.0** | Веса не качаем в research; использование — по Apache-2.0 с NOTICE |
| microsoft/presidio | github.com/microsoft/presidio | Apache 2.0 | Идеи — да; код — только с сохранением NOTICE, в Rust всё равно переписывать |
| brikkoAI/presidio-ru-recognizers | github.com/brikkoAI/presidio-ru-recognizers | **MIT** | Идеи/веса-КС (математика регуляторов — не объект АП) — да; код — только по MIT с атрибуцией, но ТЗ запрещает автокопирование |
| redmadrobot-rnd/pii_benchmark | huggingface.co/datasets/redmadrobot-rnd/pii_benchmark | **MIT** | Данные — да (benchmark/corpus), с указанием источника |
| redmadrobot-rnd/pii_train | huggingface.co/datasets/redmadrobot-rnd/pii_train | MIT (по фильтру HF) | Да, аналогично |
| Natasha (natasha/slovnet/razdel/navec/naeval) | github.com/natasha/* | MIT | Да, с атрибуцией |
| GLiNER / gliner_multi | huggingface (zero-shot) | Apache 2.0 | Да |
| pii.engineer (Rust+ONNX прецедент) | github.com/gantz-ai/pii.engineer | Apache 2.0 | Идеи архитектуры — да |
| rust regex/aho-corasick/serde/tokio/axum | crates.io | MIT/Apache-2.0 dual (aho-corasick: MIT/Unlicense) | Да |
| ФИАС (адреса) | nalog.ru (ФИАС) | открытая лицензия ФНС | Топонимы — да |
| OSM (гео) | openstreetmap.org | **ODbL (share-alike!)** | Осторожно, только с юристом |
| OpenCorpora (морфология/имена) | opencorpora.org | CC-BY-SA | С атрибуцией, производные — проверить |
| 152-ФЗ тексты (Консультант/Гарант) | consultant.ru, garant.ru | официальные НПА — не объект АП | Цитировать — да |

Правило ТЗ: checksum-формулы ФНС/ПФР/ЦБ — публичные математические процедуры регуляторов, не охраняются; собственные реализации пишем с нуля под MIT/Apache-2.0 проекта.
