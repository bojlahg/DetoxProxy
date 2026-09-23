#!/usr/bin/env bash
# Builds the submission zip from the committed HEAD using an explicit allow-list of paths.
#   tools/make_zip.sh [out.zip]
# Only committed files go in: uncommitted edits are never shipped by accident.
# Before zipping, the whole exported folder is scanned (file names and contents of every file,
# case-insensitive) for "claude" and other orchestrator traces; any hit aborts and no zip is created.
set -euo pipefail
out="${1:-.work/submission/DetoxProxy-$(git rev-parse --short HEAD).zip}"
paths=(
  README.md opencode.json Cargo.toml Cargo.lock config.yaml
  src data static ':(glob)tests/*.rs'
  tools/check_process.py tools/check_modes.py tools/big_text_check.py tools/jury_check.py tools/run_manual_cases.py tools/manual_accept.sh tools/eval_dataset.py
  docs/LICENSES.md docs/brief/manual-test-cases.md tests/manual_expect.json
)
for extra in AGENTS.md docs/PROCESS.md Dockerfile .dockerignore docs/ARCHITECTURE.md docs/JURY.md docs/MASKS.md docs/QUALITY.md docs/LOAD.md docs/LIMITATIONS.md docs/DEMO.md; do
  git cat-file -e "HEAD:$extra" 2>/dev/null && paths+=("$extra")
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
git archive --format=tar --prefix=DetoxProxy/ HEAD -- "${paths[@]}" ':(exclude)data/dict/raw' | tar -x -C "$stage"

echo "scanning $(find "$stage" -type f | wc -l) files in the folder to be zipped..."
fail=0
name_hits="$(cd "$stage" && find . -iname '*claude*' -o -iname '*.env')"
if [ -n "$name_hits" ]; then echo "FORBIDDEN FILE NAMES:"; echo "$name_hits"; fail=1; fi
# Roles (including the assistant used as architect) are disclosed only in these files.
disclosure='^\./DetoxProxy/(README\.md|AGENTS\.md|docs/PROCESS\.md):'
if (cd "$stage" && grep -rnia "claude" . | grep -vE "$disclosure"); then echo "FOUND 'claude' outside the disclosure files"; fail=1; fi
if (cd "$stage" && grep -rnaiE "anthropic|оркестр|orchestrat|chatgpt|codex|\bopus\b|\bsonnet\b" . | grep -v "/Cargo.lock:" | grep -vE "$disclosure"); then
  echo "FOUND other orchestrator traces"; fail=1
fi
if [ "$fail" != 0 ]; then echo "zip NOT created"; exit 1; fi
echo "scan clean: mentions only in README.md, AGENTS.md and docs/PROCESS.md"

mkdir -p "$(dirname "$out")"
out_abs="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
rm -f "$out_abs"
(cd "$stage" && python -c "import shutil,sys; shutil.make_archive(sys.argv[1][:-4], 'zip', '.', 'DetoxProxy')" "$out_abs")
python - "$out_abs" <<'EOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = [n for n in z.namelist() if not n.endswith("/")]
print(f"{sys.argv[1]}: {len(names)} files, {sum(i.file_size for i in z.infolist())/1024:.0f} KB uncompressed")
EOF
