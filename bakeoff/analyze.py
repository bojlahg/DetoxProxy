import json, sys, re, collections, glob, hashlib
def analyze(stack, f):
    out = {"stack": stack, "log": f.replace("\\", "/").split("/")[-1]}
    tools = collections.Counter(); tok_in = tok_out = steps = 0; checks = []; builds = 0; build_fail = 0; t0 = t1 = None
    for f in [f]:
        for ln in open(f, encoding="utf-8", errors="replace"):
            try: e = json.loads(ln)
            except ValueError: continue
            ts = e.get("timestamp"); t0 = t0 or ts; t1 = ts or t1
            p = e.get("part", {})
            if e["type"] == "step_finish":
                steps += 1; tk = p.get("tokens", {}); tok_in += tk.get("input", 0) + tk.get("cache", {}).get("read", 0); tok_out += tk.get("output", 0)
            if e["type"] == "tool_use":
                tools[p["tool"]] += 1
                st = p.get("state", {}); cmd = str(st.get("input", {}).get("command", "")); o = str(st.get("output", ""))
                if "check.py" in cmd and "--cmd" in cmd:
                    m = re.search(r"(\d+)/(\d+)", o[o.rfind("ИТОГ"):] if "ИТОГ" in o else "")
                    checks.append(m.group(0) if m else "no-result")
                elif re.search(r"go build|cargo (build|check|clippy)|\bmake\b", cmd):
                    builds += 1
                    if re.search(r"error(\[E\d+\])?:|\berror\b.*:|undefined:|cannot ", o): build_fail += 1
    out.update(minutes=round((t1 - t0) / 60000, 1) if t0 else None, steps=steps, tokens_in=tok_in, tokens_out=tok_out,
               tools=dict(tools), builds=builds, builds_with_errors=build_fail, check_runs=checks)
    return out
import os
base = os.path.dirname(os.path.abspath(__file__))
for s in sys.argv[1:] or ["go", "rust", "c"]:
    for f in sorted(glob.glob(os.path.join(base, "logs", f"{s}-[0-9]*.jsonl"))):
        print(json.dumps(analyze(s, f), ensure_ascii=False))
