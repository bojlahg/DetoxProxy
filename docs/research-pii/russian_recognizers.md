# Российские recognizers (Presidio-RU и аналоги)

## 1. brikkoAI / presidio-ru-recognizers (основной)

- Репозиторий: github.com/brikkoAI/presidio-ru-recognizers, PyPI `presidio-ru-recognizers 0.1.0`, лицензия **MIT** (проверено: README + LICENSE в репо, libraries.io).
- Зависимости: `presidio-analyzer >= 2.2`, stdlib-only checksums. Тесты: 61 тест (pytest), lint ruff+mypy.
- Статус PyPI: релиз 0.1.0 есть на PyPI/piwheels (ранее — только GitHub). Установка: `pip install presidio-ru-recognizers`.

| Entity | Формат (regex-идея) | Checksum | Context keywords | FP-защита | Score |
|---|---|---|---|---|---|
| `INN_RU` 10/12 | `\b\d{10}\b` / `\b\d{12}\b` с допусками сепараторов | да, per-length (веса ФНС) | `инн`, `налогоплательщик` | КС отсекает ~90% мусора | 1.0 если КС ✓ |
| `SNILS` | `XXX-XXX-XXX YY` + bare 11 цифр | да (+ special-case ≤001-001-998 → `00`) | `снилс`, `страховой` | bare-формат — низкий score | 1.0 / 0.3 |
| `OGRN` 13 | `\b\d{13}\b` | `%11%10` | `огрн` | КС | 1.0 |
| `OGRNIP` 15 | `\b\d{15}\b` | `%13%10` | `огрнип` | КС | 1.0 |
| `PASSPORT_RF` | `\d{4}[\s\-]?\d{6}` + word-boundary | нет | `паспорт`, `серия`, `номер`, `выдан` | только контекст, base 0.4 | 0.4 + boost |
| `PHONE_RF` | `+7`/`8` + 10 цифр, `-(). ` | длина 11 после strip | `телефон`, `тел`, `моб` | strip+длина | 0.6 + boost |
| `BANK_ACCOUNT_RF` | `\b\d{20}\b` | нет (нужен БИК ЦБ, out of scope) | `р/с`, `расчётный счёт`, `счёт` | низкий score + контекст | 0.3 + boost |

- Overlap-проблема (документирована авторами): 10-цифровой ИНН также матчится `PASSPORT_RF` (4+6). Решение: highest-score-wins (КС 1.0 бьёт 0.4).
- Код НЕ переносим автоматически (требование ТЗ). Берём: веса, ветвления SNILS, идею score-уровней, список контекстных слов.

## 2. Другие источники русских паттернов

- `microsoft/presidio` — русских recognizers нет (только en/es/it/pl/ko/nigeria/india/singapore). Подтверждено `default_recognizers.yaml` и `supported_entities.md`.
- Natasha/Yargy (см. `russian_ner.md`) — не Presidio-recognizers, но грамматики дат/адресов/ФИО можно переиспользовать как идеи regex.
- ai4privacy/pii-masking-200k (англ., 1500 примеров для валидации) — для русской части нерелевантен, упомянут как методология измерения recall/precision.

## 3. Рекомендация для DetoxProxy

Взять таблицу выше как стартовый набор deterministic recognizers. Недостающие Alfa-категории (дата рождения, место рождения, гражданство, орган выдачи, код подразделения, дата выдачи, CVV, PIN, держатель карты) — делать по той же схеме `regex + context`, без checksum (см. `pii_categories.md`).
