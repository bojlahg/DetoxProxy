#!/usr/bin/env python3
"""Runs the manual test cases from docs/brief/manual-test-cases.md against a running pii-guard.

  python tools/run_manual_cases.py --url http://127.0.0.1:8080 [--detect] [--only 3,5,25]

For every case: mask -> unmask -> retry-mask via /process (autotest system), plus /v1/detect for entity types.
Prints masked text, detected types, round-trip result and latency. Writes docs/loadtest/manual-cases-report.md.
Only stdlib.
"""
import argparse, json, re, sys, time, uuid, urllib.request, urllib.error, os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def post(url, body, timeout=15):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8"), (time.perf_counter() - t) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), (time.perf_counter() - t) * 1000


def parse_cases(md):
    """Returns [(num, title, [texts])]. Texts are '> ' quoted blocks under the case; multi-step cases yield several."""
    cases = []
    parts = re.split(r"^# (\d+)\. (.+)$", md, flags=re.M)
    for i in range(1, len(parts), 3):
        num, title, body = int(parts[i]), parts[i + 1].strip(), parts[i + 2]
        texts = []
        for block in re.findall(r"((?:^> .*\n?)+)", body, flags=re.M):
            t = "\n".join(line[2:] for line in block.strip().splitlines() if line.startswith("> "))
            if t.strip():
                texts.append(t)
        expect = re.search(r"## Ожидается\s*\n(.*?)(?=\n## |\n# |\Z)", body, flags=re.S)
        cases.append((num, title, texts, (expect.group(1).strip() if expect else "")))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--file", default="docs/brief/manual-test-cases.md")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    only = {int(x) for x in a.only.split(",") if x.strip()}
    md = open(a.file, encoding="utf-8").read()
    cases = parse_cases(md)
    out = ["# Прогон ручных тест-кейсов", f"Сервис: `{a.url}`, время: {time.strftime('%Y-%m-%d %H:%M')}", ""]
    ok_rt = 0; total_rt = 0; lat = []
    for num, title, texts, expect in cases:
        if only and num not in only:
            continue
        print(f"\n=== {num}. {title} ===")
        out.append(f"## {num}. {title}\n")
        if expect:
            out.append("Ожидается:\n```\n" + expect + "\n```")
        for k, text in enumerate(texts, 1):
            pid = uuid.uuid4().hex
            st, body, ms = post(a.url + "/process", {"payload": text, "payload_id": pid}); lat.append(ms)
            masked = json.loads(body)["result"] if st == 200 else f"<HTTP {st}>"
            st_d, body_d, _ = post(a.url + "/v1/detect", {"text": text})
            types = []
            if st_d == 200:
                ents = json.loads(body_d).get("entities", [])
                types = [f"{e['type']}({e.get('confidence', 0):.1f}:{text[e['start']:e['end']]!r})" for e in ents]
            st2, body2, ms2 = post(a.url + "/process", {"payload": masked, "payload_id": pid}); lat.append(ms2)
            unmasked = json.loads(body2)["result"] if st2 == 200 else None
            st3, body3, _ = post(a.url + "/process", {"payload": text, "payload_id": pid})
            retry_same = st3 == 200 and json.loads(body3)["result"] == masked
            rt = unmasked == text
            total_rt += 1; ok_rt += rt
            label = f"[{k}] " if len(texts) > 1 else ""
            print(f"{label}IN  : {text[:300]}")
            print(f"{label}MASK: {masked[:300]}")
            print(f"{label}TYPES: {', '.join(types) if types else '(none)'}")
            print(f"{label}round-trip: {'OK' if rt else 'MISMATCH'} | retry idempotent: {'OK' if retry_same else 'DIFF'} | {ms:.1f} ms / {ms2:.1f} ms")
            out.append(f"{label}**Вход:** `{text}`\n\n{label}**Маска:** `{masked}`\n\n{label}**Типы:** {', '.join(types) if types else '(нет)'}\n\n{label}**Round-trip:** {'OK' if rt else 'MISMATCH'}; retry: {'OK' if retry_same else 'DIFF'}; latency {ms:.1f} / {ms2:.1f} ms\n")
    lat.sort()
    summary = f"\n**Итого:** round-trip {ok_rt}/{total_rt}; latency p50 {lat[len(lat)//2]:.1f} ms, p99 {lat[int(len(lat)*0.99)]:.1f} ms"
    print(summary)
    out.append(summary)
    os.makedirs("docs/loadtest", exist_ok=True)
    open("docs/loadtest/manual-cases-report.md", "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
