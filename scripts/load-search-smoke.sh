#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/redtrace-load.XXXXXX")
token=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
server_pid=""
source_dir=${REDTRACE_SMOKE_SOURCE_DIR:-}

if [ -z "$source_dir" ] && [ -n "${HOME:-}" ] && [ -d "$HOME/Library/Application Support/REDTRACE" ]; then
  source_dir="$HOME/Library/Application Support/REDTRACE"
fi
mkdir -p "$test_dir/data"
if [ -n "$source_dir" ] && [ -d "$source_dir" ]; then
  cp -R "$source_dir/." "$test_dir/data/"
fi

cleanup() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf -- "$test_dir"
}
trap cleanup EXIT INT TERM

REDTRACE_DATA_DIR="$test_dir/data" REDTRACE_API_TOKEN="$token" REDTRACE_LOOKBACK=15m \
  "$project_dir/target/release/redtrace" >"$test_dir/server.log" 2>&1 &
server_pid=$!
attempts=0
until curl -fsS -H "x-redtrace-token: $token" http://127.0.0.1:9710/api/health >/dev/null 2>&1; do
  attempts=$((attempts + 1))
  [ "$attempts" -lt 50 ] || { echo "server did not become healthy" >&2; exit 1; }
  sleep 0.1
done

export REDTRACE_LOAD_TOKEN="$token"
export REDTRACE_LOAD_OUTPUT="$test_dir/times.txt"
: >"$REDTRACE_LOAD_OUTPUT"
seq 1 500 | xargs -P 20 -I '{}' sh -c '
  code=$(curl -sS -o /dev/null -w "%{http_code} %{time_total}" -H "x-redtrace-token: $REDTRACE_LOAD_TOKEN" "http://127.0.0.1:9710/api/search?q=*&limit=100")
  case "$code" in 200\ *) printf "%s\n" "${code#200 }" >>"$REDTRACE_LOAD_OUTPUT";; *) exit 1;; esac
'

count=$(wc -l <"$test_dir/times.txt" | tr -d ' ')
[ "$count" -eq 500 ]
sort -n "$test_dir/times.txt" >"$test_dir/times.sorted"
p95_line=$((count * 95 / 100))
[ "$p95_line" -gt 0 ] || p95_line=1
p95=$(sed -n "${p95_line}p" "$test_dir/times.sorted")
rss_kb=$(ps -o rss= -p "$server_pid" | tr -d ' ')

echo "search load smoke passed: requests=$count concurrency=20 p95=${p95}s rss=${rss_kb}KB"
