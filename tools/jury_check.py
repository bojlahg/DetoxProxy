#!/usr/bin/env python3
"""Examples the jury will type: every example from README, docs/JURY.md and the /demo presets.

  python tools/jury_check.py --bin target/release/detox-proxy.exe
  python tools/jury_check.py --url http://93.183.93.44:8080

Traps must come back unchanged. PII examples must hide every listed secret (digits, names) and
restore exactly. Exit 0 only when all pass. Only stdlib.
"""
import argparse, json, os, re, subprocess, sys, time, urllib.request, uuid

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TRAPS = [
    "Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года в Москве.",
    "Адрес отделения банка: г. Казань, ул. Баумана, д. 3.",
    "Заполните форму: ФИО, дата рождения, ИНН, PIN и CVV.",
    "Версия сборки 8.900.123.45.67 опубликована вчера.",
    "Номер заказа 500100732258 передан в доставку.",
    "IMEI 356938035643809, горячая линия 8 800 200-00-00, накладная 9876 543210.",
    "В свое время Пушкин А.С. написал немало рассказов и сказок.",
    "Стихи А. С. Пушкина мы учили в школе.",
    "Пин 4821 от домофона.",
    "Код от домофона 4821, подъезд 3.",
    "Комментарий: Юридический адрес компании: г. Омск, пр. Мира, д. 1.",
    "Общая площадь 42 кв.м., третий этаж.",
]

# (text, secrets that must not appear in the mask)
PII = [
    ("Клиент Иванов Иван Иванович, паспорт 4509 123456, ИНН 500100732259, тел. +7 912 345-67-89",
     ["Иванов", "4509", "123456", "500100732259", "345-67-89"]),
    ("Наш клиент ПУШКИН АЛЕКСАНДР СЕРГЕЕВИЧ, 06.06.1988 г.р., проживает: Москва, ул. Лесная, дом 17, квартира 42",
     ["ПУШКИН", "АЛЕКСАНДР", "06.06", "1988", "Лесная", "17"]),
    ("Клиентка Иванова Мария Петровна, дата рождения 03.12.1985, родилась в г. Самара, гражданка РФ, паспорт серия 3604 номер 123456, "
     "выдан 12.01.2006 ГУ МВД России по Самарской области, код подразделения 630-001, в/у 63 12 345678, адрес: 443001, г. Самара, "
     "ул. Ленинградская, д. 5, кв. 12, e-mail ivanova@mail.ru, тел. 8 (927) 123-45-67, ИНН 500100732259, карта 4276 3800 1234 5678, "
     "CVV 123, PIN 4321, держатель MARIA IVANOVA",
     ["Иванова", "Мария", "03.12.1985", "3604", "123456", "12.01.2006", "Самарской", "630-001", "345678", "443001", "Ленинградская",
      "ivanova@mail.ru", "123-45-67", "500100732259", "4276", "5678", "CVV 123", "4321", "MARIA"]),
    ("иванов иван иванович, тел 89123456789. ПЕТРОВ ПЁТР ПЕТРОВИЧ, дата рождения 03.12.1985. Родился двенадцатого марта 1985 г. "
     "Паспорт серия 4509, номер 123456. Клиент Иванoв Сергей",
     ["иванов", "89123456789", "ПЕТРОВ", "03.12.1985", "двенадцатого", "4509", "123456", "Иванoв"]),
    ("Клиентка ИВАНОВА мария петровна обратилась", ["ИВАНОВА", "мария", "петровна"]),
    ("клиент: сидоров ПЁТР иванович, тел 89123456789", ["сидоров", "ПЁТР", "иванович", "89123456789"]),
    ("email petr . sidorov @ mail . ru", ["petr", "sidorov"]),
    ("Карта 4276 5500 1122 3347, код 4821.", ["4276", "3347", "4821"]),
    ("Карта 4276 5500 1122 3347, цифры на обороте 4821.", ["3347", "4821"]),
    ("Клиент гражданин России, паспорт 4509 123456", ["России", "4509"]),
    ("Адрес: улица Пушкина, 23, корпус 1. Позвоню на 89161234567", ["Пушкина, 23", "корпус 1", "89161234567"]),
    ("Абонент Орехова-Беляева Ульяна подала жалобу", ["Орехова", "Беляева", "Ульяна"]),
    ("Дата рождения клиента: 12.31.1985", ["12.31.1985"]),
    ("Дата рождения клиента: 1985.31.12", ["1985.31.12"]),
    ("Передай Петровой Анне Сергеевне и Сидорову Петру Ивановичу приглашение на встречу", ["Петровой", "Сидорову"]),
    ("Клиент Кузнецов Олег Викторович родился в Нижнем Новгороде, гражданство: Россия", ["Кузнецов", "Нижнем", "Россия"]),
    ("Доставьте документы Кузнецову Олегу Викторовичу: г. Казань, ул. Баумана, д. 14, кв. 8", ["Кузнецову", "Баумана, д. 14"]),
]


def call(base, payload, pid):
    body = json.dumps({"payload": payload, "payload_id": pid}).encode()
    req = urllib.request.Request(base + "/process", body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())["result"]


def start(binary, port):
    cfg = open("config.yaml", encoding="utf-8").read()
    cfg = re.sub(r'listen:\s*"[^"]*"', f'listen: "127.0.0.1:{port}"', cfg, count=1)
    path = os.path.abspath("jury-check-config.yaml")
    open(path, "w", encoding="utf-8").write(cfg)
    proc = subprocess.Popen([os.path.abspath(binary), "--config", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if urllib.request.urlopen(base + "/healthz", timeout=1).status == 200:
                return proc, base, path
        except OSError:
            time.sleep(0.1)
    proc.kill()
    sys.exit("binary did not start")


def run_checks(base):
    failed = 0
    for t in TRAPS:
        m = call(base, t, uuid.uuid4().hex)
        ok = m == t
        failed += not ok
        print(("ok   " if ok else "FAIL ") + "trap: " + (t if ok else f"{t}\n       -> {m}"))
    for t, secrets in PII:
        pid = uuid.uuid4().hex
        m = call(base, t, pid)
        leaked = [s for s in secrets if s in m]
        restored = call(base, m, pid) == t
        ok = not leaked and restored
        failed += not ok
        note = "" if ok else f"\n       -> {m}\n       leaked: {leaked} restored: {restored}"
        print(("ok   " if ok else "FAIL ") + "pii:  " + t[:70] + note)
    return failed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin")
    ap.add_argument("--url")
    ap.add_argument("--port", type=int, default=18181)
    a = ap.parse_args()
    if not (a.bin or a.url):
        sys.exit("--bin or --url is required")
    proc = path = None
    if a.bin:
        proc, base, path = start(a.bin, a.port)
    else:
        base = a.url.rstrip("/")
    try:
        failed = run_checks(base)
    finally:
        if proc:
            proc.kill()
            proc.wait()
        if path and os.path.exists(path):
            os.remove(path)
    print("JURY CHECK:", "FAIL" if failed else "PASS", f"({len(TRAPS) + len(PII)} examples, {failed} failed)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
