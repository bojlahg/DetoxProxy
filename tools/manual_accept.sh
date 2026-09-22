#!/usr/bin/env bash
# Starts the release binary on a spare port, runs the manual cases with expectations, stops the binary.
#   tools/manual_accept.sh [--only 1,4,5] [bin]
# Exit code = exit code of run_manual_cases.py (0 = every selected case passes).
set -u
only=""
if [ "${1:-}" = "--only" ]; then only="$2"; shift 2; fi
bin="${1:-target/release/detox-proxy.exe}"
[ -x "$bin" ] || bin="target/release/detox-proxy"
port="${MANUAL_PORT:-18097}"
cfg="$(mktemp -t manual-cfg.XXXX.yaml)"
sed -E "s#listen: \"[^\"]*\"#listen: \"127.0.0.1:$port\"#" config.yaml > "$cfg"
"$bin" --config "$cfg" > manual-accept.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -f "$cfg"' EXIT
for _ in $(seq 1 100); do
  curl -s -o /dev/null "http://127.0.0.1:$port/healthz" && break
  kill -0 $pid 2>/dev/null || { echo "service failed to start:"; tail -5 manual-accept.log; exit 2; }
  sleep 0.1
done
args=(--url "http://127.0.0.1:$port" --expect tests/manual_expect.json --report "")
[ -n "$only" ] && args+=(--only "$only")
timeout 300 python tools/run_manual_cases.py "${args[@]}" | grep -E "^## |FAIL|SOFT|Итого|Кейсы|^- "
exit "${PIPESTATUS[0]}"
