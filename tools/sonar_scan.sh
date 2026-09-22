#!/usr/bin/env bash
# Runs SonarQube (the analyzer the organizers appear to use: same severities and report shape)
# over the contents of the submission zip and prints the issues grouped by severity.
#
#   tools/sonar_scan.sh [path/to/DetoxProxy-xxxx.zip]
#
# First run starts a local SonarQube container (community, port 19000) and stores the admin
# password and token under the scratch dir; later runs reuse them. Docker required.
set -euo pipefail
zip="${1:-$(ls -t ../submission/DetoxProxy-*.zip | head -1)}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
unzip -q "$zip" -d "$work"
src="$work/DetoxProxy"
pass_file="$HOME/.detox-sonar-pass"
token_file="$HOME/.detox-sonar-token"

if ! curl -s -m 3 http://localhost:19000/api/system/status | grep -q '"status":"UP"'; then
  docker start sonarqube >/dev/null 2>&1 || \
    docker run -d --name sonarqube -p 19000:9000 -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true sonarqube:community >/dev/null
  echo "waiting for SonarQube..."
  for _ in $(seq 1 90); do
    curl -s -m 3 http://localhost:19000/api/system/status | grep -q '"status":"UP"' && break
    sleep 5
  done
fi

if [ ! -f "$pass_file" ]; then
  echo 'DetoxProxy2026!hack' > "$pass_file"
  curl -s -u admin:admin -X POST http://localhost:19000/api/users/change_password \
    --data-urlencode login=admin --data-urlencode previousPassword=admin \
    --data-urlencode "password=$(cat "$pass_file")" >/dev/null || true
fi
pass="$(cat "$pass_file")"
if [ ! -s "$token_file" ]; then
  curl -s -u "admin:$pass" -X POST http://localhost:19000/api/user_tokens/generate -d "name=scan$RANDOM" \
    | python -c "import sys,json;print(json.load(sys.stdin)['token'])" > "$token_file"
fi

MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -w "$src"):/usr/src" \
  -e SONAR_HOST_URL=http://host.docker.internal:19000 -e SONAR_TOKEN="$(cat "$token_file")" \
  sonarsource/sonar-scanner-cli -Dsonar.projectKey=detoxproxy -Dsonar.projectName=DetoxProxy 2>&1 \
  | grep -E "ANALYSIS SUCCESSFUL|ERROR" || true

sleep 12
PASS="$pass" python - <<'EOF'
import base64, collections, json, os, urllib.request
auth = base64.b64encode(("admin:" + os.environ["PASS"]).encode()).decode()
req = urllib.request.Request(
    "http://localhost:19000/api/issues/search?componentKeys=detoxproxy&ps=200&resolved=false",
    headers={"Authorization": "Basic " + auth})
d = json.loads(urllib.request.urlopen(req, timeout=30).read())
by_sev = collections.Counter(i.get("severity", "?") for i in d["issues"])
order = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
print(f"total {d['total']}: " + ", ".join(f"{s} {by_sev.get(s, 0)}" for s in order))
for i in sorted(d["issues"], key=lambda x: (order.index(x.get("severity", "INFO")), x["component"])):
    print(f"[{i.get('severity')}] {i['component'].split(':')[-1]}:{i.get('line', '-')} {i['message'][:100]}")
EOF
