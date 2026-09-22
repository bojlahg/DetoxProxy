# Маскирование данных карт: PCI DSS v4.0.1 и российская нормативка (исследование 22.09.2026)

Все цитаты — из официального PDF PCI DSS v4.0.1 (June 2024), проверены построчно.

| Требование | Цитата | Что это значит для нас |
|---|---|---|
| **3.4.1** | "PAN is masked when displayed (the BIN and last four digits are the maximum number of digits to be displayed)" | Наш режим stars для карты: открыты первые 4–6 и последние 4, остальное `*`. Формат `4276 **** **** 5674` соответствует. |
| 3.4.1 Purpose | "if only the last four digits are needed to perform a business function, PAN should be masked to only show the last four digits." | По умолчанию для LLM можно оставлять только последние 4 (настройка `stars_keep_prefix: 0`). |
| **3.3.1.2** | "The card verification code is not stored upon completion of the authorization process." | CVV в хранилище соответствий — только на TTL запроса, никогда на диск. |
| **3.3.1.3** | "The personal identification number (PIN) and the PIN block are not stored upon completion of the authorization process." | То же для PIN. |
| **3.5.1** | "PAN is rendered unreadable anywhere it is stored… as well as non-primary storage (backup, audit logs, exception, or troubleshooting logs)." | Обоснование правила «ни одного значения ПДн в логах и метриках». |
| 3.5.1 | "Index tokens." (как допустимый метод) | Наши токены `<<CARD_1>>` — index tokens по терминологии PCI. |
| FAQ #1091 | 16-значный PAN: "At least 4 digits removed. Maximum digits which may be retained: 'First 8, any other 4'" | Верхняя граница открытых цифр. |

Российская цепочка: 161-ФЗ ст. 27 → Положение ЦБ 821-П (с 01.04.2024, преемник 719-П) → уровни защиты по ГОСТ Р 57580.1-2017. **Явного требования маскировать PAN в них нет**; ближайшие меры — РД.8 (сокрытие вводимых аутентификационных данных), РД.17 (запрет хранения аутентификационных данных в открытом виде), ПУИ.1 (контроль передачи конфиденциальной информации вовне). Требование о PAN приходит через PCI DSS как правило платёжных систем (включая «Мир»/НСПК).

Источники: https://www.middlebury.edu/sites/default/files/2025-01/PCI-DSS-v4_0_1.pdf ; https://www.pcisecuritystandards.org/faqs/1091 ; https://www.pcisecuritystandards.org/faqs/1492 ; 821-П: https://www.garant.ru/products/ipo/prime/doc/408082189/ ; ГОСТ Р 57580.1: https://itglobal.com/wp-content/uploads/2021/05/gost-57580.1-1.pdf
