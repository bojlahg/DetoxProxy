#!/usr/bin/env python3
"""Runs the manual test cases from docs/brief/manual-test-cases.md against a running detox-proxy.

  python tools/run_manual_cases.py --url http://127.0.0.1:8080 [--only 3,5,25]
      [--expect tests/manual_expect.json] [--report docs/loadtest/manual-cases-report.md]

For every case: mask -> unmask -> retry-mask via /process (default system), plus /v1/detect for entity types.
Case 20 (retry) and 21 (isolation) are run as scripted steps, cases 22/23 are embedded into a ~100 KB neutral text.
With --expect, checks every case against the expectations and exits 1 on any hard failure. Only stdlib.
"""
import argparse, json, re, sys, time, uuid, urllib.request, urllib.error, os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FILLER = "Сегодня команда обсуждала планы на квартал, сроки проекта и порядок согласования документов. " * 1100


def post(url, body, timeout=15):
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    t = time.perf_counter()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8"), (time.perf_counter() - t) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), (time.perf_counter() - t) * 1000


def process(base, payload, pid):
    st, body, ms = post(base + "/process", {"payload": payload, "payload_id": pid})
    return (json.loads(body)["result"] if st == 200 else f"<HTTP {st}>"), ms


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
        if not texts:
            texts = re.findall(r'"payload":\s*"([^"]+)"', body)
        cases.append((num, title, texts))
    return cases


def entity_types(base, text):
    st, body, _ = post(base + "/v1/detect", {"text": text})
    if st != 200:
        return []
    raw = text.encode("utf-8")
    out = []
    for e in json.loads(body).get("entities", []):
        span = raw[e["start"]:e["end"]].decode("utf-8", "replace")
        out.append(f"{e['type']}({e.get('confidence', 0):.2f}:{span!r})")
    return out


def check(exp, text, masked):
    """Returns list of failure strings for one expectation block."""
    fails = []
    if exp.get("unchanged") and masked != text:
        fails.append("text changed")
    fails += [f"not masked: {s!r}" for s in exp.get("mask", []) if s in masked]
    fails += [f"lost: {s!r}" for s in exp.get("keep", []) if s not in masked]
    fails += [f"no match: {r!r}" for r in exp.get("regex", []) if not re.search(r, masked)]
    return fails


def short(s, n=400):
    return s if len(s) <= n else s[:n // 2] + f" …[{len(s)} chars]… " + s[-n // 2:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--file", default="docs/brief/manual-test-cases.md")
    ap.add_argument("--expect", default="")
    ap.add_argument("--report", default="docs/loadtest/manual-cases-report.md")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    only = {int(x) for x in a.only.split(",") if x.strip()}
    expect = json.load(open(a.expect, encoding="utf-8")) if a.expect else {}
    cases = parse_cases(open(a.file, encoding="utf-8").read())
    base = a.url.rstrip("/")
    out = ["# Прогон ручных тест-кейсов", f"Сервис: `{base}`, время: {time.strftime('%Y-%m-%d %H:%M')}", ""]
    hard_fail, soft_fail, rt_ok, rt_total, lat = [], [], 0, 0, []

    def log(line):
        print(line)
        out.append(line + "  ")

    for num, title, texts in cases:
        if only and num not in only:
            continue
        log(f"\n## {num}. {title}")
        fails = []
        if num == 21:
            a_text, b_text = "Клиент Иван Иванов, тел. +7 900 111-22-33.", "Клиент Пётр Петров, тел. +7 900 444-55-66."
            pa, pb = uuid.uuid4().hex, uuid.uuid4().hex
            ma, _ = process(base, a_text, pa)
            process(base, b_text, pb)
            leak, _ = process(base, ma, pb)
            log(f"A mask: {ma}")
            log(f"A mask sent with payload_id B -> {leak}")
            if "Иван Иванов" in leak or "111-22-33" in leak:
                fails.append("A data disclosed through B")
            if "21" in expect:
                fails += check(expect["21"], a_text, ma)
        else:
            if num == 22:
                texts = [FILLER + texts[0]]
            elif num == 23 and len(texts) == 2:
                texts = [texts[0] + " " + FILLER + texts[1]]
            for text in texts:
                pid = "manual-retry-001-" + uuid.uuid4().hex[:8] if num == 20 else uuid.uuid4().hex
                masked, ms = process(base, text, pid); lat.append(ms)
                unmasked, ms2 = process(base, masked, pid); lat.append(ms2)
                retry, _ = process(base, text, pid)
                rt = unmasked == text
                rt_total += 1; rt_ok += rt
                log(f"IN   : {short(text)}")
                log(f"MASK : {short(masked)}")
                if len(text) < 2000:
                    types = entity_types(base, text)
                    log(f"TYPES: {', '.join(types) if types else '(none)'}")
                log(f"round-trip {'OK' if rt else 'MISMATCH'}, retry {'OK' if retry == masked else 'DIFF'}, {ms:.1f} / {ms2:.1f} ms")
                if not rt:
                    fails.append("round-trip mismatch")
                if retry != masked:
                    fails.append("retry returned a different mask")
                for key in (str(num), f"{num}s"):
                    if key in expect:
                        f = check(expect[key], text, masked)
                        if expect[key].get("soft"):
                            soft_fail += [f"{num}: {x}" for x in f]
                            if f:
                                log(f"SOFT : {'; '.join(f)}")
                        else:
                            fails += f
        if fails:
            hard_fail += [f"{num}: {x}" for x in fails]
            log(f"FAIL : {'; '.join(fails)}")
        elif expect:
            log("PASS")
    lat.sort()
    summary = (f"\nИтого: round-trip {rt_ok}/{rt_total}; latency p50 {lat[len(lat)//2]:.1f} ms, "
               f"max {lat[-1]:.1f} ms" if lat else "\nИтого: нет запросов")
    log(summary)
    if expect:
        failed_cases = sorted({int(x.split(':')[0]) for x in hard_fail})
        log(f"Кейсы с ошибками: {len(failed_cases)} {failed_cases}; soft: {len(soft_fail)}")
        for x in hard_fail:
            log(f"- {x}")
    if a.report:
        os.makedirs(os.path.dirname(a.report), exist_ok=True)
        open(a.report, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    return 1 if hard_fail else 0


if __name__ == "__main__":
    sys.exit(main())
