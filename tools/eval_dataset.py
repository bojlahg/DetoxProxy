#!/usr/bin/env python3
"""Detection quality on tests/data/*.jsonl against a running detox-proxy (/v1/detect).

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
        except OSError:  # URLError and TimeoutError both derive from OSError
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


def score_row(row, pred, counters, per_type, fp_types, misses, extras):
    """Compares one row's gold entities with the predictions and updates the counters."""
    gold = [(TYPE_MAP[e["type"]], e["start"], e["end"]) for e in row["entities"] if e["type"] in TYPE_MAP]
    ignored = [(e["start"], e["end"]) for e in row["entities"] if e["type"] not in TYPE_MAP]
    pred = [p for p in pred if not any(overlap(p[1], p[2], s, t) for s, t in ignored)]
    for g in gold:
        typed = any(p[0] == g[0] and overlap(p[1], p[2], g[1], g[2]) for p in pred)
        untyped = any(overlap(p[1], p[2], g[1], g[2]) for p in pred)
        counters["gold"] += 1
        counters["found_typed"] += typed
        counters["found_any"] += untyped
        per_type[g[0]]["gold"] += 1
        per_type[g[0]]["found"] += typed
        if not untyped:
            misses.append((row["id"], g[0], row["text"][g[1]:g[2]], row["text"]))
    for p in pred:
        ok = any(overlap(p[1], p[2], g[1], g[2]) for g in gold)
        counters["pred"] += 1
        counters["pred_ok"] += ok
        if not ok:
            fp_types[p[0]] += 1
            extras.append((row["id"], p[0], row["text"][p[1]:p[2]], row["text"]))
    gold_chars = {i for _, s, t in gold for i in range(s, t)}
    pred_chars = {i for _, s, t in pred for i in range(s, t)}
    counters["gchars"] += len(gold_chars)
    counters["pchars"] += len(pred_chars)
    counters["both"] += len(gold_chars & pred_chars)
    counters["rows"] += 1
    counters["neg_rows"] += not gold
    counters["neg_rows_clean"] += (not gold and not pred)


def evaluate_file(path, base, workers, limit):
    """Runs the detector over one dataset file. Returns (counters, per_type, fp_types, misses, extras)."""
    rows = [json.loads(l) for l in open(path, encoding="utf-8")]
    if limit:
        rows = rows[:limit]
    with ThreadPoolExecutor(workers) as ex:
        preds = list(ex.map(lambda r: detect(base, r["text"]), rows))
    counters = collections.Counter()
    per_type = collections.defaultdict(collections.Counter)
    fp_types = collections.Counter()
    misses, extras = [], []
    for row, pred in zip(rows, preds):
        score_row(row, pred, counters, per_type, fp_types, misses, extras)
    return counters, per_type, fp_types, misses, extras


def file_stats(counters, per_type, fp_types):
    """Metrics addressable from --require: <type>, fp.<type>, clean."""
    st = {t: v["found"] for t, v in per_type.items()}
    st.update({f"fp.{t}": n for t, n in fp_types.items()})
    st["clean"] = counters["neg_rows_clean"]
    return st


def report_file(log, name, counters, per_type, fp_types, misses, extras, errors):
    log("")
    log(f"## {name} — {counters['rows']} строк")
    log(report_line(counters))
    if counters["neg_rows"]:
        log(f"строк без ПДн: {counters['neg_rows']}, из них без единой маски: {counters['neg_rows_clean']}")
    log("по типам (recall typed): " + ", ".join(
        f"{t} {v['found']}/{v['gold']}" for t, v in sorted(per_type.items(), key=lambda x: -x[1]["gold"])))
    if fp_types:
        log("лишние маски по типам: " + ", ".join(f"{t} {n}" for t, n in fp_types.most_common()))
    if not errors:
        return
    for title, items in (("пропуски", misses), ("лишние", extras)):
        if items:
            log(f"{title} (первые {errors}):")
            for id_, t, span, text in items[:errors]:
                log(f"  {id_} {t} {span!r} | {text[:160]}")


def check_requirements(require, stats):
    """Returns the list of unmet requirements from the --require string."""
    failed = []
    for req in filter(None, (x.strip() for x in require.split(","))):
        m = re.fullmatch(r"([\w-]+):([\w.]+)(>=|<=)(\d+)", req)
        if not m:
            sys.exit(f"bad --require item: {req}")
        fname, metric, op, n = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if fname not in stats:
            sys.exit(f"--require names a file that was not evaluated: {fname}")
        value = stats[fname].get(metric, 0)
        if not (value >= n if op == ">=" else value <= n):
            failed.append(f"{req} (actual {value})")
    return failed


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
        counters, per_type, fp_types, misses, extras = evaluate_file(f, base, a.workers, a.limit)
        total.update(counters)
        name = f.replace("\\", "/").split("/")[-1]
        stats[name.replace(".jsonl", "")] = file_stats(counters, per_type, fp_types)
        report_file(log, name, counters, per_type, fp_types, misses, extras, a.errors)
    log("")
    log("## Итого")
    log(report_line(total))
    failed = check_requirements(a.require, stats)
    if a.require:
        log("")
        log("## Требования")
        log("все выполнены" if not failed else "НЕ выполнены: " + "; ".join(failed))
    if a.report:
        open(a.report, "w", encoding="utf-8", newline=chr(10)).write(chr(10).join(lines) + chr(10))
    sys.exit(1 if failed else 0)


def report_line(c):
    def pct(x, y):
        return f"{100 * x / y:.1f}%" if y else "n/a"
    return (f"entity recall {pct(c['found_any'], c['gold'])} (typed {pct(c['found_typed'], c['gold'])}), "
            f"entity precision {pct(c['pred_ok'], c['pred'])}; "
            f"char recall {pct(c['both'], c['gchars'])}, char precision {pct(c['both'], c['pchars'])}")


if __name__ == "__main__":
    main()
