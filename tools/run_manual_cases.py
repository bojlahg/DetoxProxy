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

ISOLATION_CASE = 21
RETRY_CASE = 20
BIG_TEXT_TAIL_CASE = 22
BIG_TEXT_BOTH_ENDS_CASE = 23


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


class Runner:
    """State of one run: service URL, expectations, collected report lines and counters."""

    def __init__(self, base, expect):
        self.base = base
        self.expect = expect
        self.out = ["# Прогон ручных тест-кейсов", f"Сервис: `{base}`, время: {time.strftime('%Y-%m-%d %H:%M')}", ""]
        self.hard_fail = []
        self.soft_fail = []
        self.lat = []
        self.rt_ok = 0
        self.rt_total = 0

    def log(self, line):
        print(line)
        self.out.append(line + "  ")

    @staticmethod
    def case_texts(num, texts):
        """Cases 22 and 23 embed their text into a ~100 KB neutral document."""
        if num == BIG_TEXT_TAIL_CASE:
            return [FILLER + texts[0]]
        if num == BIG_TEXT_BOTH_ENDS_CASE and len(texts) == 2:
            return [texts[0] + " " + FILLER + texts[1]]
        return texts

    def check_expectations(self, num, text, masked):
        fails = []
        for key in (str(num), f"{num}s"):
            exp = self.expect.get(key)
            if not exp:
                continue
            found = check(exp, text, masked)
            if exp.get("soft"):
                self.soft_fail += [f"{num}: {x}" for x in found]
                if found:
                    self.log("SOFT : " + "; ".join(found))
            else:
                fails += found
        return fails

    def run_text(self, num, text):
        pid = "manual-retry-001-" + uuid.uuid4().hex[:8] if num == RETRY_CASE else uuid.uuid4().hex
        masked, ms = process(self.base, text, pid)
        unmasked, ms2 = process(self.base, masked, pid)
        retry, _ = process(self.base, text, pid)
        self.lat += [ms, ms2]
        round_trip = unmasked == text
        self.rt_total += 1
        self.rt_ok += round_trip
        self.log("IN   : " + short(text))
        self.log("MASK : " + short(masked))
        if len(text) < 2000:
            types = entity_types(self.base, text)
            self.log("TYPES: " + (", ".join(types) if types else "(none)"))
        self.log("round-trip {}, retry {}, {:.1f} / {:.1f} ms".format(
            "OK" if round_trip else "MISMATCH", "OK" if retry == masked else "DIFF", ms, ms2))
        fails = []
        if not round_trip:
            fails.append("round-trip mismatch")
        if retry != masked:
            fails.append("retry returned a different mask")
        return fails + self.check_expectations(num, text, masked)

    def run_isolation(self):
        """Case 21: a mask made under one payload_id must not be unmasked under another."""
        a_text = "Клиент Иван Иванов, тел. +7 900 111-22-33."
        b_text = "Клиент Пётр Петров, тел. +7 900 444-55-66."
        mask_a, _ = process(self.base, a_text, uuid.uuid4().hex)
        pid_b = uuid.uuid4().hex
        process(self.base, b_text, pid_b)
        leak, _ = process(self.base, mask_a, pid_b)
        self.log("A mask: " + mask_a)
        self.log("A mask sent with payload_id B -> " + leak)
        fails = []
        if "Иван Иванов" in leak or "111-22-33" in leak:
            fails.append("A data disclosed through B")
        if str(ISOLATION_CASE) in self.expect:
            fails += check(self.expect[str(ISOLATION_CASE)], a_text, mask_a)
        return fails

    def run_case(self, num, title, texts):
        self.log("")
        self.log(f"## {num}. {title}")
        if num == ISOLATION_CASE:
            fails = self.run_isolation()
        else:
            fails = [f for text in self.case_texts(num, texts) for f in self.run_text(num, text)]
        if fails:
            self.hard_fail += [f"{num}: {x}" for x in fails]
            self.log("FAIL : " + "; ".join(fails))
        elif self.expect:
            self.log("PASS")

    def summarize(self):
        self.lat.sort()
        self.log("")
        if self.lat:
            self.log("Итого: round-trip {}/{}; latency p50 {:.1f} ms, max {:.1f} ms".format(
                self.rt_ok, self.rt_total, self.lat[len(self.lat) // 2], self.lat[-1]))
        else:
            self.log("Итого: нет запросов")
        if not self.expect:
            return
        failed_cases = sorted({int(x.split(":")[0]) for x in self.hard_fail})
        self.log(f"Кейсы с ошибками: {len(failed_cases)} {failed_cases}; soft: {len(self.soft_fail)}")
        for x in self.hard_fail:
            self.log("- " + x)

    def write_report(self, path):
        if not path:
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w", encoding="utf-8", newline="\n").write("\n".join(self.out) + "\n")


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
    runner = Runner(a.url.rstrip("/"), expect)
    for num, title, texts in parse_cases(open(a.file, encoding="utf-8").read()):
        if not only or num in only:
            runner.run_case(num, title, texts)
    runner.summarize()
    runner.write_report(a.report)
    return 1 if runner.hard_fail else 0


if __name__ == "__main__":
    sys.exit(main())
