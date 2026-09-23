#!/usr/bin/env python3
"""Large-text check: ~100 000 tokens in one /process request must be masked and restored.

  python tools/big_text_check.py --bin target/release/detox-proxy.exe [--chars 400000] [--limit-ms 1500]
  python tools/big_text_check.py --url http://93.183.93.44:8080 [--limit-ms 3000]

Builds texts of --chars characters (400 000 chars of Russian is about 100 000 LLM tokens) from one
kind of sentence each (client data, card, famous person, plain legal text, delivery address) and a
mix of all, sends each to /process, restores it with the same payload_id and checks: HTTP 200,
the restored text equals the original, no original passport/card/phone digits in the mask, and the
masking time is under --limit-ms. With --bin it starts the binary on a spare port with config.yaml.
Exit 0 only when every text passes. Only stdlib.
"""
import argparse, itertools, json, os, re, subprocess, sys, time, urllib.error, urllib.request, uuid

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SENTENCES = {
    "client": "Клиент Иванов Иван Иванович, паспорт 4509 123456, тел. +7 912 345-67-89, обратился в отделение.",
    "card": "Просим проверить операции по карте 4276 3800 1234 5678 за прошлый месяц и сообщить результат.",
    "famous": "Поэт Александр Сергеевич Пушкин родился 6 июня 1799 года в Москве, это известный факт.",
    "plain": "Договор составлен в двух экземплярах, имеющих одинаковую юридическую силу, по одному для каждой стороны.",
    "address": "Адрес доставки: г. Казань, ул. Баумана, д. 3, кв. 15, получатель Петрова Анна Сергеевна.",
}
SECRETS = ["4509 123456", "4276 3800 1234 5678", "345-67-89"]


def build(kind, chars):
    pool = list(SENTENCES.values()) if kind == "mix" else [SENTENCES[kind]]
    parts, n = [], 0
    for s in itertools.cycle(pool):
        if n >= chars:
            break
        parts.append(s)
        n += len(s) + 1
    return " ".join(parts)


def post(base, payload, pid):
    body = json.dumps({"payload": payload, "payload_id": pid}).encode()
    req = urllib.request.Request(base + "/process", body, {"Content-Type": "application/json"})
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return 200, json.loads(r.read())["result"], (time.time() - t) * 1000
    except urllib.error.HTTPError as e:
        return e.code, "", (time.time() - t) * 1000


def start(binary, port):
    cfg = open("config.yaml", encoding="utf-8").read()
    cfg = re.sub(r'listen:\s*"[^"]*"', f'listen: "127.0.0.1:{port}"', cfg, count=1)
    path = os.path.abspath("big-text-config.yaml")
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


def check_one(base, kind, chars, limit_ms):
    """Masks and restores one text; returns (masked_ms, list of problems)."""
    text = build(kind, chars)
    pid = f"big-{kind}-{uuid.uuid4().hex}"
    code, masked, mask_ms = post(base, text, pid)
    if code != 200:
        return len(text), mask_ms, [f"mask HTTP {code}"]
    problems = []
    if mask_ms > limit_ms:
        problems.append(f"mask {mask_ms:.0f} ms > {limit_ms:.0f} ms")
    leaked = [s for s in SECRETS if s in text and s in masked]
    if leaked:
        problems.append("leak " + ", ".join(leaked))
    code2, restored, _ = post(base, masked, pid)
    if code2 != 200:
        problems.append(f"unmask HTTP {code2}")
    elif restored != text:
        problems.append("restored text differs")
    return len(text), mask_ms, problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin")
    ap.add_argument("--url")
    ap.add_argument("--port", type=int, default=18171)
    ap.add_argument("--chars", type=int, default=400_000)
    ap.add_argument("--limit-ms", type=float, default=1500)
    a = ap.parse_args()
    if not (a.bin or a.url):
        sys.exit("--bin or --url is required")
    proc = path = None
    if a.bin:
        proc, base, path = start(a.bin, a.port)
    else:
        base = a.url.rstrip("/")
    failed = 0
    try:
        for kind in list(SENTENCES) + ["mix"]:
            n, mask_ms, problems = check_one(base, kind, a.chars, a.limit_ms)
            failed += bool(problems)
            status = "FAIL " + "; ".join(problems) if problems else "ok"
            print(f"{kind:8} {n:>8} chars  mask {mask_ms:7.0f} ms  {status}", flush=True)
    finally:
        if proc:
            proc.kill()
            proc.wait()
        if path and os.path.exists(path):
            os.remove(path)
    print("BIG TEXT CHECK:", "FAIL" if failed else "PASS")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
