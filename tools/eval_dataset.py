#!/usr/bin/env python3
"""Detection quality on tests/data/*.jsonl against a running pii-guard (/v1/detect).

  python tools/eval_dataset.py --url http://127.0.0.1:8080 [--files tests/data/a.jsonl,...] [--limit N]
      [--report docs/QUALITY-raw.md] [--errors 20] [--require "overlap_conflicts:address>=12,synthetic_missing_categories:fp.cvv<=40,hard_negatives:clean>=190"]

Gold offsets are char offsets, service offsets are UTF-8 byte offsets (converted here).
Metrics:
  entity: a gold entity is found when a predicted span of the same type overlaps it (typed) / any type (untyped);
          a prediction is correct when it overlaps a gold entity (untyped) - extra masks lower precision.
  char:   share of gold PII characters covered by any prediction (recall) and share of predicted characters
          inside gold PII (precision) - closest to "span quality vs original".
Gold types outside the 17 required ones are ignored: they are neither misses nor false positives.
Only stdlib.
"""
import argparse, collections, glob, json, re, sys, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# dataset type -> service type
TYPE_MAP = {
    "FIO": "fio", "BIRTH_DATE": "birth_date", "BIRTH_PLACE": "birth_place", "PASSPORT": "passport",
    "CITIZENSHIP": "citizenship", "ISSUE_AUTHORITY": "passport_issuer", "DIVISION_CODE": "subdivision_code",
    "ISSUE_DATE": "passport_issue_date", "DRIVER_LICENSE": "driver_license", "ADDRESS": "address",
    "EMAIL": "email", "PHONE": "phone", "INN": "inn", "CARD": "card_number", "CVV": "cvv", "PIN": "card_pin",
    "CARDHOLDER": "card_holder", "SNILS": "snils",
}


def detect(base, text):
    data = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(base + "/v1/detect", data, {"Content-Type": "application/json"})
    for attempt in range(3):
        try:
            body = json.loads(urllib.request.urlopen(req, timeout=20).read())
            break
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.5 * (attempt + 1))
    else:
        raise RuntimeError("detect failed")
    raw = text.encode("utf-8")
    out = []
    for e in body.get("entities", []):
        s = len(raw[:e["start"]].decode("utf-8", "replace"))
        t = len(raw[:e["end"]].decode("utf-8", "replace"))
        out.append((e["type"], s, t))
    return out


def overlap(a0, a1, b0, b1):
    return max(0, min(a1, b1) - max(a0, b0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--files", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--errors", type=int, default=15)
    ap.add_argument("--report", default="")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--require", default="", help="comma list of file:metric>=N / file:metric<=N; metric = <type> (typed found), fp.<type>, clean")
    a = ap.parse_args()
    files = a.files.split(",") if a.files else sorted(glob.glob("tests/data/*.jsonl"))
    base = a.url.rstrip("/")
    lines = []

    def log(s=""):
        print(s)
        lines.append(s)

    total = collections.Counter()
    stats = {}
    for f in files:
        rows = [json.loads(l) for l in open(f, encoding="utf-8")]
        if a.limit:
            rows = rows[:a.limit]
        with ThreadPoolExecutor(a.workers) as ex:
            preds = list(ex.map(lambda r: detect(base, r["text"]), rows))
        c = collections.Counter()
        per_type = collections.defaultdict(collections.Counter)
        fp_types = collections.Counter()
        misses, extras = [], []
        for r, pred in zip(rows, preds):
            gold = [(TYPE_MAP[e["type"]], e["start"], e["end"]) for e in r["entities"] if e["type"] in TYPE_MAP]
            ignored = [(e["start"], e["end"]) for e in r["entities"] if e["type"] not in TYPE_MAP]
            pred = [p for p in pred if not any(overlap(p[1], p[2], s, t) for s, t in ignored)]
            for g in gold:
                typed = any(p[0] == g[0] and overlap(p[1], p[2], g[1], g[2]) for p in pred)
                untyped = any(overlap(p[1], p[2], g[1], g[2]) for p in pred)
                c["gold"] += 1; c["found_typed"] += typed; c["found_any"] += untyped
                per_type[g[0]]["gold"] += 1; per_type[g[0]]["found"] += typed
                if not untyped:
                    misses.append((r["id"], g[0], r["text"][g[1]:g[2]], r["text"]))
            for p in pred:
                ok = any(overlap(p[1], p[2], g[1], g[2]) for g in gold)
                c["pred"] += 1; c["pred_ok"] += ok
                if not ok:
                    fp_types[p[0]] += 1
                    extras.append((r["id"], p[0], r["text"][p[1]:p[2]], r["text"]))
            gold_chars = set(i for _, s, t in gold for i in range(s, t))
            pred_chars = set(i for _, s, t in pred for i in range(s, t))
            c["gchars"] += len(gold_chars); c["pchars"] += len(pred_chars); c["both"] += len(gold_chars & pred_chars)
            c["rows"] += 1
            c["neg_rows"] += not gold
            c["neg_rows_clean"] += (not gold and not pred)
        total.update(c)
        name = f.replace("\\", "/").split("/")[-1]
        st = {t: v["found"] for t, v in per_type.items()}
        st.update({f"fp.{t}": n for t, n in fp_types.items()})
        st["clean"] = c["neg_rows_clean"]
        stats[name.replace(".jsonl", "")] = st
        log(f"\n## {name} — {c['rows']} строк")
        log(report_line(c))
        if c["neg_rows"]:
            log(f"строк без ПДн: {c['neg_rows']}, из них без единой маски: {c['neg_rows_clean']}")
        log("по типам (recall typed): " + ", ".join(
            f"{t} {v['found']}/{v['gold']}" for t, v in sorted(per_type.items(), key=lambda x: -x[1]["gold"])))
        if fp_types:
            log("лишние маски по типам: " + ", ".join(f"{t} {n}" for t, n in fp_types.most_common()))
        for title, items in (("пропуски", misses), ("лишние", extras)):
            if items and a.errors:
                log(f"{title} (первые {a.errors}):")
                for id_, t, span, text in items[:a.errors]:
                    log(f"  {id_} {t} {span!r} | {text[:160]}")
    log("\n## Итого")
    log(report_line(total))
    failed = []
    for req in filter(None, (x.strip() for x in a.require.split(","))):
        m = re.fullmatch(r"([\w-]+):([\w.]+)(>=|<=)(\d+)", req)
        if not m:
            sys.exit(f"bad --require item: {req}")
        fname, metric, op, n = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if fname not in stats:
            sys.exit(f"--require names a file that was not evaluated: {fname}")
        v = stats[fname].get(metric, 0)
        if not (v >= n if op == ">=" else v <= n):
            failed.append(f"{req} (actual {v})")
    if a.require:
        log("\n## Требования")
        log("все выполнены" if not failed else "НЕ выполнены: " + "; ".join(failed))
    if a.report:
        open(a.report, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    sys.exit(1 if failed else 0)


def report_line(c):
    def pct(x, y):
        return f"{100 * x / y:.1f}%" if y else "n/a"
    return (f"entity recall {pct(c['found_any'], c['gold'])} (typed {pct(c['found_typed'], c['gold'])}), "
            f"entity precision {pct(c['pred_ok'], c['pred'])}; "
            f"char recall {pct(c['both'], c['gchars'])}, char precision {pct(c['both'], c['pchars'])}")


if __name__ == "__main__":
    main()
