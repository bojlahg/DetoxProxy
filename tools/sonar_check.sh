#!/usr/bin/env bash
# Scans the WORKING TREE (the same paths make_zip.sh ships) with the local SonarQube and
# fails when any issue is found. For acceptance while changes are not committed yet.
#
#   tools/sonar_check.sh [project-key] [path-regex]
#   project-key defaults to detox-<worktree dir name>; with path-regex only issues in matching
#   files fail the check (e.g. 'src/(mask|server)|static/'), all issues are still printed.
#
# Needs the SonarQube container from tools/sonar_scan.sh (port 19000) and its token file.
set -uo pipefail
key="${1:-detox-$(basename "$PWD" | tr 'A-Z' 'a-z')}"
filter="${2:-.}"
token_file="$HOME/.detox-sonar-token"
pass_file="$HOME/.detox-sonar-pass"
if ! curl -s -m 3 http://localhost:19000/api/system/status | grep -q '"status":"UP"'; then
  echo "SonarQube is not running on :19000 (start it with tools/sonar_scan.sh)"; exit 2
fi
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
for p in README.md Dockerfile Cargo.toml Cargo.lock config.yaml src data static tests tools/check_process.py \
         tools/check_modes.py tools/big_text_check.py tools/run_manual_cases.py tools/manual_accept.sh tools/eval_dataset.py; do
  [ -e "$p" ] && cp -r --parents "$p" "$stage/"
done
rm -rf "$stage/tests/data" "$stage/data/dict/raw"

MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -w "$stage"):/usr/src" \
  -e SONAR_HOST_URL=http://host.docker.internal:19000 -e SONAR_TOKEN="$(cat "$token_file")" \
  sonarsource/sonar-scanner-cli -Dsonar.projectKey="$key" -Dsonar.projectName="$key" \
  -Dsonar.qualitygate.wait=false 2>&1 | grep -E "ANALYSIS SUCCESSFUL|ERROR" | grep -v "Clippy prerequisites" || true

# wait until the server has processed this project's report (reports are processed one at a time)
auth="admin:$(cat "$pass_file")"
sleep 3
for _ in $(seq 1 60); do
  q="$(curl -s -u "$auth" "http://localhost:19000/api/ce/component?component=$key")"
  echo "$q" | grep -q '"queue":\[\]' && ! echo "$q" | grep -q '"status":"IN_PROGRESS"' && break
  sleep 3
done
PASS="$(cat "$pass_file")" KEY="$key" FILTER="$filter" python - <<'EOF'
import base64, collections, json, os, re, sys, urllib.request
auth = base64.b64encode(("admin:" + os.environ["PASS"]).encode()).decode()
url = f"http://localhost:19000/api/issues/search?componentKeys={os.environ['KEY']}&ps=200&resolved=false"
d = json.loads(urllib.request.urlopen(urllib.request.Request(url, headers={"Authorization": "Basic " + auth}), timeout=30).read())
order = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
by_sev = collections.Counter(i.get("severity", "?") for i in d["issues"])
print(f"sonar issues {d['total']}: " + ", ".join(f"{s} {by_sev.get(s, 0)}" for s in order))
for i in sorted(d["issues"], key=lambda x: (order.index(x.get("severity", "INFO")), x["component"])):
    print(f"[{i.get('severity')}] {i['component'].split(':')[-1]}:{i.get('line', '-')} {i['message'][:110]}")
own = [i for i in d["issues"] if re.search(os.environ["FILTER"], i["component"].split(":")[-1])]
print(f"issues in files matching {os.environ['FILTER']!r}: {len(own)}")
sys.exit(1 if own else 0)
EOF
