#!/usr/bin/env python3
"""Сводка времени по задачам из logs/runs.jsonl: python timing.py [путь к runs.jsonl]"""
import json, os, sys
from collections import OrderedDict
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "runs.jsonl")
rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
tasks = OrderedDict()
for r in rows:
    key = r.get("task") or r.get("dir") or r.get("stack") or "?"
    t = tasks.setdefault(key, {"rounds": 0, "seconds": 0, "steps": 0, "verdicts": []})
    t["rounds"] += 1; t["seconds"] += r.get("seconds", 0); t["steps"] += r.get("steps", 0)
    t["verdicts"].append(r.get("verdict") or ("PASS" if r.get("exit") == 0 else "FAIL"))
LIMITS = {"block1": 20, "block2": 40}
print(f"{'задача':<14}{'раундов':>8}{'минут':>8}{'шагов':>7}  вердикты (последний — текущий)")
total = 0
for k, t in tasks.items():
    m = t["seconds"] / 60; total += m
    flag = ""
    if t["rounds"] > 2 or m > LIMITS["block1"]:
        flag = "  <-- выше порога блока 1"
    print(f"{k:<14}{t['rounds']:>8}{m:>8.1f}{t['steps']:>7}  {' → '.join(t['verdicts'])}{flag}")
print(f"{'итого':<14}{sum(t['rounds'] for t in tasks.values()):>8}{total:>8.1f}")
