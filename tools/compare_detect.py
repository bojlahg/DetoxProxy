#!/usr/bin/env python3
"""Behaviour check for pure refactors and optimizations of the detector.

  python tools/compare_detect.py --baseline <old-binary> --candidate target/release/detox-proxy.exe
      [--files tests/data/a.jsonl,...] [--show 10]

Starts both binaries on spare ports with config.yaml, sends every text of the given datasets
(default: every tests/data/*.jsonl and tests/data/holdout/*.jsonl; only the texts are read, never
the labels) to /v1/detect of both and compares the entity lists (type, start, end). Exit 0 only
when every text gives exactly the same entities.
Only stdlib.
"""
import argparse, glob, http.client, json, os, re, subprocess, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def start(binary, port, tag):
    cfg = open("config.yaml", encoding="utf-8").read()
    cfg = re.sub(r'listen:\s*"[^"]*"', f'listen: "127.0.0.1:{port}"', cfg, count=1)
    path = os.path.abspath(f"compare-{tag}.yaml")
    open(path, "w", encoding="utf-8").write(cfg)
    proc = subprocess.Popen([os.path.abspath(binary), "--config", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if urllib.request.urlopen(base + "/healthz", timeout=1).status == 200:
                return proc, base, path
        except OSError:
            time.sleep(0.1)
    proc.kill()
    sys.exit(f"{tag} binary did not start")


_local = threading.local()


def detect(base, text):
    """One keep-alive connection per thread and server: thousands of short connections exhaust
    the ephemeral ports on Windows."""
    port = int(base.rsplit(":", 1)[1])
    conns = getattr(_local, "conns", None)
    if conns is None:
        conns = _local.conns = {}
    body = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
    for attempt in range(3):
        conn = conns.get(port) or http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        conns[port] = conn
        try:
            conn.request("POST", "/v1/detect", body, {"Content-Type": "application/json"})
            ents = json.loads(conn.getresponse().read()).get("entities", [])
            return sorted((e["type"], e["start"], e["end"]) for e in ents)
        except (OSError, http.client.HTTPException):
            conn.close()
            conns.pop(port, None)
            time.sleep(0.2 * (attempt + 1))
    raise RuntimeError("detect failed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--candidate", default="target/release/detox-proxy.exe")
    ap.add_argument("--files", default="")
    ap.add_argument("--show", type=int, default=10)
    a = ap.parse_args()
    files = a.files.split(",") if a.files else sorted(glob.glob("tests/data/*.jsonl") + glob.glob("tests/data/holdout/*.jsonl"))
    texts = [json.loads(l)["text"] for f in files for l in open(f, encoding="utf-8") if l.strip()]
    old, old_base, old_cfg = start(a.baseline, 18171, "baseline")
    new, new_base, new_cfg = start(a.candidate, 18172, "candidate")
    try:
        with ThreadPoolExecutor(8) as ex:
            olds = list(ex.map(lambda t: detect(old_base, t), texts))
            news = list(ex.map(lambda t: detect(new_base, t), texts))
    finally:
        for p in (old, new):
            p.terminate()
            p.wait(5)
        for c in (old_cfg, new_cfg):
            os.remove(c)
    diffs = [(t, o, n) for t, o, n in zip(texts, olds, news) if o != n]
    print(f"texts: {len(texts)}, differing: {len(diffs)}")
    for t, o, n in diffs[:a.show]:
        raw = t.encode("utf-8")
        span = lambda e: f"{e[0]}:{raw[e[1]:e[2]].decode('utf-8', 'replace')!r}"
        print(f"- {t[:120]!r}")
        print(f"    only baseline:  {[span(e) for e in o if e not in n]}")
        print(f"    only candidate: {[span(e) for e in n if e not in o]}")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
