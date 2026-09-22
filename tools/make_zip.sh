#!/usr/bin/env bash
# Builds the submission zip from the committed HEAD using an explicit allow-list of paths.
#   tools/make_zip.sh [out.zip]
# Only committed files go in: uncommitted edits are never shipped by accident.
set -euo pipefail
out="${1:-../submission/pii-guard-$(git rev-parse --short HEAD).zip}"
mkdir -p "$(dirname "$out")"
paths=(
  README.md AGENTS.md opencode.json Cargo.toml Cargo.lock config.yaml
  src data tests/*.rs
  tools/check_process.py tools/run_manual_cases.py tools/manual_accept.sh tools/eval_dataset.py
  docs/LICENSES.md docs/brief/manual-test-cases.md docs/agent-kit/tasks/manual_expect.json
)
for extra in docs/ARCHITECTURE.md docs/JURY.md docs/MASKS.md docs/QUALITY.md docs/LOAD.md docs/LIMITATIONS.md; do
  git cat-file -e "HEAD:$extra" 2>/dev/null && paths+=("$extra")
done
git archive --format=zip --prefix=pii-guard/ -o "$out" HEAD -- "${paths[@]}" ':(exclude)data/dict/raw'
echo "$out"
python - "$out" <<'EOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = [n for n in z.namelist() if not n.endswith("/")]
size = sum(i.file_size for i in z.infolist())
print(f"{len(names)} files, {size/1024:.0f} KB uncompressed")
bad = [n for n in names if any(s in n.lower() for s in ("claude", "logs/", "bakeoff", "research", "00-prep", "loop.md", ".env", "target/"))]
print("suspicious:", bad or "none")
EOF
