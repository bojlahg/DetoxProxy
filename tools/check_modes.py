#!/usr/bin/env python3
"""Black-box check of every mask mode against a spawned detox-proxy.

  python tools/check_modes.py --bin target/release/detox-proxy.exe [--port 18131]

Adds one system per mode (token, stars, synthetic, pseudonym, remove) to config.yaml,
sends the same text through each, then sends the mask back with the same payload_id.
Exit 0 when every check passes. Only stdlib.
"""
import argparse, json, os, re, subprocess, sys, time, uuid, urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TEXT = ("Клиент Сидоров Пётр Иванович, паспорт 4509 123456, ИНН 500100732259, тел. +7 912 345-67-89, "
        "проживает: г. Казань, ул. Баумана, д. 14, кв. 8. Карта 4276 5500 1122 3347, "
        "email petr.sidorov@mail.ru. Второй телефон +7 903 111-22-33.")
ORIGINALS = ["Сидоров", "4509 123456", "500100732259", "345-67-89", "Баумана", "4276 5500 1122 3347",
             "petr.sidorov", "111-22-33", "Казань"]
MODES = ["token", "stars", "synthetic", "pseudonym", "remove"]
SYSTEM = """  - id: m_{m}
    enabled: true
    mask_mode: {m}
    unmask_enabled: true
    types: all
    overrides: {{}}
    min_confidence: 0.5
    session_mode: stateless
    token_numbering: sequential
"""


def post(base, system, payload, pid):
    body = json.dumps({"payload": payload, "payload_id": pid}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(base + "/process", body,
                                 {"Content-Type": "application/json", "X-System-Id": system})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())["result"]


def write_config(port):
    cfg = open("config.yaml", encoding="utf-8").read()
    cfg = re.sub(r'listen:\s*"[^"]*"', f'listen: "127.0.0.1:{port}"', cfg, count=1)
    extra = "".join(SYSTEM.format(m=m) for m in MODES)
    cfg = cfg.replace("pii_types_file:", extra + "pii_types_file:", 1)
    path = os.path.abspath("check-modes-config.yaml")
    open(path, "w", encoding="utf-8").write(cfg)
    return path


def start(bin_path, port):
    cfg = write_config(port)
    log = open("check-modes.log", "wb")
    proc = subprocess.Popen([os.path.abspath(bin_path), "--config", cfg], stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if urllib.request.urlopen(base + "/healthz", timeout=1).status == 200:
                return proc, log, base
        except OSError:
            time.sleep(0.1)
    proc.kill()
    sys.exit("service did not start")


class Checks:
    def __init__(self):
        self.ok = 0
        self.total = 0

    def __call__(self, name, cond, detail=""):
        self.total += 1
        self.ok += bool(cond)
        print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))


def check_mode(base, check, mode):
    pid = uuid.uuid4().hex
    masked = post(base, f"m_{mode}", TEXT, pid)
    back = post(base, f"m_{mode}", masked, pid)
    leaked = [v for v in ORIGINALS if v in masked]
    check(f"{mode}: no original in mask", not leaked, f"leaked={leaked}" if leaked else "")
    if mode == "remove":
        check("remove: unmask restores nothing", back == masked, back[:160])
        return
    check(f"{mode}: round-trip", back == TEXT, "" if back == TEXT else back[:160])
    if mode == "pseudonym":
        check_pseudonym_address(check, masked)


def check_pseudonym_address(check, masked):
    m = re.search(r"проживает: (.*?)\. Карта", masked)
    addr = m.group(1) if m else ""
    has_parts = all(p in addr for p in ("г. ", "ул. ", "д. ", "кв. "))
    check("pseudonym: address keeps city, street, house, flat", has_parts, addr)
    check("pseudonym: street replaced", "Баумана" not in addr and "ул. " in addr, addr)
    check("pseudonym: city replaced", "Казань" not in addr and "г. " in addr, addr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="target/release/detox-proxy.exe")
    ap.add_argument("--port", type=int, default=18131)
    a = ap.parse_args()
    proc, log, base = start(a.bin, a.port)
    check = Checks()
    try:
        for mode in MODES:
            check_mode(base, check, mode)
    finally:
        proc.terminate()
        proc.wait(5)
        log.close()
    print(f"\nRESULT: {check.ok}/{check.total}")
    return 0 if check.ok == check.total else 1


if __name__ == "__main__":
    sys.exit(main())
