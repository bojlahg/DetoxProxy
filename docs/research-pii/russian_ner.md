# Русский NER: нужен ли ML и что брать (обновлено)

Вывод: ML нужен для ФИО / адреса / контактов, а ядро документ-сущностей закрывают правила с КС. **Основной кандидат — специализированный RMR ruBERT + deterministic rules** (см. `docs/rubert_pii_ner.md`): модель одна 83.6 exact / 94.7 overlap (PERSON+LOCATION), пайплайн 88.9/95.0. Generic-модели ниже — fallback/контекст.

| Модель/библиотека | Размер / RAM | CPU latency | GPU | Лицензия | Классы | PII-метрика (рус) | Вердикт |
|---|---|---|---|---|---|---|---|
| **RMR rubert-base-pii-ner** (finetune ai-forever/ruBert-base) | 178M / ~678MB safetensors, ctx 512 | 10–100ms/запрос CPU (данные upstream; своих замеров нет) | опц. | Apache-2.0 | 21 тип/43 BIO (PERSON/LOCATION/контакты/документы) | **83.6 exact / 94.7 overlap; пайплайн 88.9/95.0** | **primary**: единственный с измеренным качеством на русских документах |
| Natasha slovnet NER news | ~27MB / ~205MB | ~40ms/1KB CPU numpy | нет | MIT | PER/LOC/ORG | нет PII-замеров | fallback до latency-тестов |
| natasha-spacy ru | 135–138MB | ~8 статей/сек | нет | MIT | PER/LOC/ORG | нет | только для прототипа |
| DeepPavlov BERT NER | ~500MB–2GB | секунды CPU | да | Apache 2.0 | PER/LOC/ORG | нет PII-замеров | не брать без GPU-пула |
| GLiNER zero-shot | ~200–400MB | 100–300ms CPU | жел. | Apache 2.0 | произвольные | ~70 F1 (RMR leaderboard, PERSON+LOCATION) | ниже цели, не покрывает доки |
| GLiNER2 guard / pii.engineer | ~280M INT8 | ~180ms p50 CPU | нет | Apache 2.0 | 9 типов | нет рус. PII-замеров | прецедент Rust+ONNX |
| Yargy/Tomita | KB–MB | µs–ms | нет | MIT | даты/адреса по правилам | н/п | дополнение к regex |

Рекомендация архитектору:
1. Primary: RMR ruBERT (512/stride-128/порог; merge фрагментов обязателен) + 16 rule-типов; правила побеждают модель на пересечении.
2. Rules-first отсекает FP (КС/дистанции) до NER; слабые места модели (IP 36.0, INN 68.3) закрыты regex.
3. BERT под 1000–2000 RPS/0.5s — только по замерам (батчинг/квантование/отдельный tier, реплики); иначе fallback Slovnet на окнах.
4. Веса в Git не кладём (см. `.gitignore`); карточка модели + `models/README.md` upstream — достаточны.
