#!/usr/bin/env python3
"""Black-box check of the /process contract (Appendix A/B) against a running or spawned detox-proxy.

  python tools/check_process.py --bin target/release/detox-proxy.exe --config config.yaml [--port 18090]
  python tools/check_process.py --url http://host:port            # already running service

Exit 0 when every check passes. Prints one line per check. Only stdlib.
"""
import argparse, json, os, subprocess, sys, time, uuid, urllib.request, urllib.error, re

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROCESS = "/process"

CASES = [
    ("inn+phone+email", "Клиент ИНН 7707083893, тел. +7 912 345-67-89, email ivan.petrov@mail.ru", ["7707083893", "912", "ivan.petrov@mail.ru"]),
    ("passport", "Паспорт 4509 123456 выдан 12.05.2010", ["4509 123456"]),
    ("passport words", "серия 4509 номер 123456", ["4509", "123456"]),
    ("card+cvv", "Карта 4276 3800 1234 5679, CVV 123", ["4276 3800 1234 5679"]),
    ("snils", "СНИЛС 112-233-445 95", ["112-233-445 95"]),
    ("subdiv", "код подразделения 770-001", ["770-001"]),
    ("driver", "в/у 77 12 345678", ["345678"]),
    ("case", "ИНН 7707083893 и инн 7707083893", ["7707083893"]),
    ("repeat-token", "тел. +7 912 345-67-89, повторно +7 912 345-67-89", ["912"]),
    ("json", '{"user": {"phone": "+7 912 345-67-89", "inn": "7707083893"}}', ["7707083893"]),
    ("multiline", "Строка 1: email a@b.ru\nСтрока 2: тел. 8-912-345-67-89\nСтрока 3: без данных", ["a@b.ru"]),
    ("emoji", "Привет 😀 мой ИНН 7707083893 🎉", ["7707083893"]),
    ("no-pii", "Погода сегодня хорошая, идём гулять в парк.", []),
    ("empty", "", []),
    ("long", ("Клиент ИНН 7707083893. " * 400), ["7707083893"]),
]

def post(url, body, headers=None, timeout=10):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data, {"Content-Type": "application/json", **(headers or {})})
    t = time.perf_counter()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8"), (time.perf_counter() - t) * 1000, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), (time.perf_counter() - t) * 1000, dict(e.headers)

class Checks:
    """Counts checks and prints one line per check."""

    def __init__(self):
        self.ok = 0
        self.total = 0

    def __call__(self, name, cond, detail=""):
        self.total += 1
        self.ok += bool(cond)
        suffix = (": " + detail) if detail else ""
        print(f"[{'PASS' if cond else 'FAIL'}] {name}{suffix}")


def start_service(bin_path, config_path, port):
    """Starts the binary on a spare port. Returns (process, log file, base url) or (None, None, None)."""
    cfg = open(config_path, encoding="utf-8").read()
    cfg = re.sub(r'listen:\s*"[^"]*"', f'listen: "127.0.0.1:{port}"', cfg, count=1)
    tmp = os.path.abspath("check-process-config.yaml")
    open(tmp, "w", encoding="utf-8").write(cfg)
    log = open("check-process.log", "wb")
    proc = subprocess.Popen([os.path.abspath(bin_path), "--config", tmp], stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if urllib.request.urlopen(base + "/healthz", timeout=1).status == 200:
                return proc, log, base
        except OSError:
            time.sleep(0.1)
        if proc.poll() is not None:
            break
    print("[FAIL] start: no 200 on /healthz in 10 s")
    return None, None, None


def mask_detail(leaked, leaks, masked, text, ms):
    if leaked:
        return f"leak={leaked}"
    if leaks and masked == text:
        return "no entity masked"
    return f"{ms:.1f} ms"


def run_case(base, check, lat, name, text, leaks):
    """mask -> unmask -> idempotent retry for one case."""
    pid = uuid.uuid4().hex
    st, body, ms, _ = post(base + PROCESS, {"payload": text, "payload_id": pid})
    lat.append(ms)
    if st != 200:
        check(f"{name} mask", False, f"status {st} {body[:80]}")
        return
    masked = json.loads(body)["result"]
    leaked = [v for v in leaks if v in masked]
    check(f"{name} mask", not leaked and (masked != text or not leaks),
          mask_detail(leaked, leaks, masked, text, ms))
    st2, body2, ms2, _ = post(base + PROCESS, {"payload": masked, "payload_id": pid})
    lat.append(ms2)
    un = json.loads(body2)["result"] if st2 == 200 else None
    check(f"{name} unmask", un == text, "" if un == text else f"status {st2}, mismatch")
    st3, body3, _, _ = post(base + PROCESS, {"payload": text, "payload_id": pid})
    check(f"{name} retry-mask", st3 == 200 and json.loads(body3)["result"] == masked)


def run_token_checks(base, check):
    """Token numbering and tolerance to a mask distorted by the model."""
    pid = uuid.uuid4().hex
    _, body, _, _ = post(base + PROCESS, {"payload": "ИНН 7707083893 и снова ИНН 7707083893", "payload_id": pid})
    m = json.loads(body)["result"]
    check("token format <<INN_1>>", "<<INN_1>>" in m and "<<INN_2>>" not in m, m)
    distorted = m.replace("<<INN_1>>", "<< inn_1 >>", 1)
    _, body, _, _ = post(base + PROCESS, {"payload": distorted, "payload_id": pid})
    check("distorted token unmask", "7707083893" in json.loads(body)["result"])


def run_error_checks(base, check):
    st, _, _, _ = post(base + PROCESS, {"payload": "x"})
    check("400 missing payload_id", st == 400, str(st))
    req = urllib.request.Request(base + PROCESS, b"{not json", {"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
        st = 200
    except urllib.error.HTTPError as e:
        st = e.code
    check("400 invalid json", st == 400, str(st))
    st, _, _, _ = post(base + PROCESS, {"payload": "ИНН 7707083893", "payload_id": uuid.uuid4().hex},
                       {"X-System-Id": "nope"})
    check("403 unknown system", st == 403, str(st))
    st, body, _, _ = post(base + PROCESS, {"payload": "ИНН 7707083893", "payload_id": uuid.uuid4().hex},
                          {"X-System-Id": "chatbot"})
    check("hash tokens for chatbot",
          st == 200 and re.search(r"<<INN_[0-9a-f]{6}>>", json.loads(body)["result"]) is not None, body[:80])


def run_metrics_checks(base, check, lat):
    mt = urllib.request.urlopen(base + "/metrics", timeout=5).read().decode()
    check("metrics present", "pii_requests_total" in mt and "pii_latency_seconds" in mt)
    check("no PII in metrics", "7707083893" not in mt and "ivan.petrov" not in mt)
    lat.sort()
    p50 = lat[len(lat) // 2]
    p99 = lat[int(len(lat) * 0.99)]
    check("latency p99 < 100 ms (sequential)", p99 < 100, f"p50={p50:.1f} p99={p99:.1f} ms")


def stop_service(proc, log, check):
    proc.terminate()
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()
    txt = open("check-process.log", encoding="utf-8", errors="replace").read()
    check("no PII in service log",
          "7707083893" not in txt and "ivan.petrov" not in txt and "4509 123456" not in txt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--url")
    a = ap.parse_args()
    proc = log = None
    base = a.url
    if not base:
        proc, log, base = start_service(a.bin, a.config, a.port)
        if base is None:
            return 1
    check = Checks()
    lat = []
    try:
        for name, text, leaks in CASES:
            run_case(base, check, lat, name, text, leaks)
        run_token_checks(base, check)
        run_error_checks(base, check)
        run_metrics_checks(base, check, lat)
    finally:
        if proc:
            stop_service(proc, log, check)
    print("")
    print(f"RESULT: {check.ok}/{check.total}")
    return 0 if check.ok == check.total else 1


if __name__ == "__main__":
    sys.exit(main())
