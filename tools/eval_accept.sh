#!/usr/bin/env bash
# Starts the release binary on a spare port, runs the dataset evaluation with quality floors, stops the binary.
#   tools/eval_accept.sh ["file:metric>=N,..."] [bin]
# Without arguments uses the floors in docs/agent-kit/tasks/eval_floors.txt (one requirement per line).
# Exit code = exit code of eval_dataset.py (0 = every floor holds).
set -u
req="${1:-}"
bin="${2:-target/release/pii-guard.exe}"
[ -x "$bin" ] || bin="target/release/pii-guard"
if [ -z "$req" ]; then
  req="$(grep -v '^\s*#' docs/agent-kit/tasks/eval_floors.txt | grep -v '^\s*$' | paste -sd, -)"
fi
port=18098
cfg="$(mktemp -t eval-cfg.XXXX.yaml)"
sed -E "s#listen: \"[^\"]*\"#listen: \"127.0.0.1:$port\"#" config.yaml > "$cfg"
"$bin" --config "$cfg" > eval-accept.log 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -f "$cfg" eval-accept.log' EXIT
for _ in $(seq 1 100); do
  curl -s -o /dev/null "http://127.0.0.1:$port/healthz" && break
  kill -0 $pid 2>/dev/null || { echo "service failed to start:"; tail -5 eval-accept.log; exit 2; }
  sleep 0.1
done
timeout 900 python tools/eval_dataset.py --url "http://127.0.0.1:$port" --errors 0 --workers 8 --require "$req" \
  | grep -E "^## |entity recall|строк без|по типам|лишние|НЕ выполнены|все выполнены"
exit "${PIPESTATUS[0]}"
