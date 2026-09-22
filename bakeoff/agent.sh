#!/usr/bin/env bash
# Запуск DeepSeek-агента через OpenCode с защитой от зависаний и независимой приёмкой.
#
#   agent.sh <рабочая_папка> <файл_с_промптом | "текст промпта"> [--accept "<команда приёмки>"]
#            [--protect "<файл1> <файл2>"] [--timeout-min 45] [--stall-min 8] [--session <id>] [--task T04]
#   task для сводки времени (timing.py) берётся из --task, иначе из имени файла ТЗ, иначе из имени папки.
#
# Итог печатается одной строкой VERDICT=... и дописывается в logs/runs.jsonl.
# Код возврата: 0 — приёмка зелёная; 1 — приёмка красная; 2 — агент завис или упал; 3 — изменён защищённый файл или агент сделал коммит.
set -u
MODEL="alfagen/deepseek-ai/DeepSeek-V4-Flash-0731"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$ROOT/logs"; mkdir -p "$LOGS"
export PATH="/c/Users/bojla/scoop/apps/rustup/current/.cargo/bin:$PATH"

dir="$1"; prompt="$2"; shift 2
accept=""; protect=""; tmo=45; stall=8; session=""; task=""
while [ $# -gt 0 ]; do
  case "$1" in
    --accept) accept="$2"; shift 2;;
    --protect) protect="$2"; shift 2;;
    --timeout-min) tmo="$2"; shift 2;;
    --stall-min) stall="$2"; shift 2;;
    --session) session="$2"; shift 2;;
    --task) task="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 64;;
  esac
done
cd "$dir" || { echo "VERDICT=NO_DIR dir=$dir"; exit 2; }
[ -f "$prompt" ] && { [ -z "$task" ] && task="$(basename "$prompt" | sed -E 's/\.[^.]*$//')"; prompt="$(cat "$prompt")"; }
[ -z "$task" ] && task="$(basename "$PWD")"
name="$(basename "$PWD")"
n=$(( $(ls "$LOGS"/"$name"-*.jsonl 2>/dev/null | wc -l) + 1 ))
log="$LOGS/$name-$n.jsonl"; err="$LOGS/$name-$n.err"

# контрольные суммы защищённых файлов до запуска
sums_before=""; for f in $protect; do sums_before="$sums_before$(md5sum "$f" 2>/dev/null)"$'\n'; done

head_before=$(git rev-parse HEAD 2>/dev/null || echo none)
start=$(date +%s)
args=(run --auto --format json -m "$MODEL"); [ -n "$session" ] && args+=(-s "$session")
# stdin обязательно закрыт: с открытым stdin opencode run ждёт ввод и зависает молча
opencode "${args[@]}" "$prompt" > "$log" 2> "$err" < /dev/null &
pid=$!

# сторожок: общий таймаут и отсутствие роста лога
reason="exit"; last_size=-1; last_change=$start
while kill -0 "$pid" 2>/dev/null; do
  sleep 5
  now=$(date +%s); size=$(stat -c %s "$log" 2>/dev/null || echo 0)
  if [ "$size" != "$last_size" ]; then last_size=$size; last_change=$now; fi
  if [ $(( now - start )) -ge $(( tmo * 60 )) ]; then reason="timeout_${tmo}m"; break; fi
  if [ $(( now - last_change )) -ge $(( stall * 60 )) ]; then reason="stalled_${stall}m"; break; fi
done
if [ "$reason" != "exit" ]; then
  winpid=$(cat "/proc/$pid/winpid" 2>/dev/null)   # у taskkill свой PID, не тот, что в bash
  [ -n "$winpid" ] && taskkill //PID "$winpid" //T //F >/dev/null 2>&1
  kill -9 "$pid" 2>/dev/null
  agent_exit=-1
else
  wait "$pid"; agent_exit=$?
fi
secs=$(( $(date +%s) - start ))

# проверка, что агент реально работал в нужном провайдере и что-то сделал
steps=$(grep -c '"type":"step_finish"' "$log" 2>/dev/null || echo 0)
sid=$(grep -o '"sessionID":"[^"]*"' "$log" 2>/dev/null | head -1 | cut -d'"' -f4)

# защищённые файлы
sums_after=""; for f in $protect; do sums_after="$sums_after$(md5sum "$f" 2>/dev/null)"$'\n'; done
tampered=0; [ "$sums_before" != "$sums_after" ] && tampered=1
# агенту коммитить запрещено: HEAD не должен сдвинуться
head_after=$(git rev-parse HEAD 2>/dev/null || echo none)
committed=0; [ "$head_before" != "$head_after" ] && committed=1

# независимая приёмка: запускаем сами, словам агента не верим
accept_exit="skipped"
if [ -n "$accept" ]; then
  bash -c "$accept" > "$LOGS/$name-$n.accept.log" 2>&1 < /dev/null; accept_exit=$?
fi

verdict="PASS"; code=0
if [ "$reason" != "exit" ] || [ "$agent_exit" != "0" ] || [ "$steps" = "0" ]; then verdict="AGENT_FAILED"; code=2; fi
if [ "$accept_exit" != "skipped" ] && [ "$accept_exit" != "0" ]; then verdict="ACCEPT_FAILED"; code=1; fi
if [ "$accept_exit" = "0" ] && [ "$code" = "2" ] && [ "$steps" != "0" ]; then verdict="PASS_AGENT_INTERRUPTED"; code=0; fi
if [ "$tampered" = "1" ]; then verdict="PROTECTED_FILE_CHANGED"; code=3; fi
[ "$accept_exit" = "skipped" ] && [ "$code" = "0" ] && verdict="DONE_UNVERIFIED"
if [ "$committed" = "1" ]; then verdict="AGENT_COMMITTED"; code=3; fi

line="{\"task\":\"$task\",\"dir\":\"$name\",\"round\":$n,\"verdict\":\"$verdict\",\"stop\":\"$reason\",\"agent_exit\":$agent_exit,\"steps\":$steps,\"accept_exit\":\"$accept_exit\",\"tampered\":$tampered,\"agent_committed\":$committed,\"seconds\":$secs,\"session\":\"$sid\"}"
echo "$line" >> "$LOGS/runs.jsonl"
echo "VERDICT=$verdict task=$task stop=$reason steps=$steps accept_exit=$accept_exit tampered=$tampered agent_committed=$committed ${secs}s session=$sid log=$log"
[ "$accept_exit" != "skipped" ] && [ "$accept_exit" != "0" ] && { echo "--- хвост приёмки ---"; tail -12 "$LOGS/$name-$n.accept.log"; }
exit $code
