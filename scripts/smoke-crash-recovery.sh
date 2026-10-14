#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/redtrace-smoke.XXXXXX")
token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
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

start_server() {
  REDTRACE_DATA_DIR="$test_dir/data" \
  REDTRACE_API_TOKEN="$token" \
  REDTRACE_LOOKBACK=15m \
  "$project_dir/target/release/redtrace" >"$test_dir/server.log" 2>&1 &
  server_pid=$!
  attempts=0
  until curl -fsS -H "x-redtrace-token: $token" http://127.0.0.1:9710/api/health >"$test_dir/health.json" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 50 ]; then
      echo "server did not become healthy" >&2
      return 1
    fi
    sleep 0.1
  done
}

event_count() {
  node -e 'const fs=require("fs");const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));process.stdout.write(String(value.events_indexed));' "$test_dir/health.json"
}

start_server
curl -sS -X POST -H "x-redtrace-token: $token" http://127.0.0.1:9710/api/collect >/dev/null || true
sleep 1
curl -fsS -H "x-redtrace-token: $token" http://127.0.0.1:9710/api/health >"$test_dir/health.json"
before=$(event_count)
if [ -n "$source_dir" ] && [ "$before" -eq 0 ]; then
  echo "real source data was found but no events were recovered" >&2
  exit 1
fi

kill -9 "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""

start_server
curl -fsS -H "x-redtrace-token: $token" http://127.0.0.1:9710/api/health >"$test_dir/health.json"
after=$(event_count)
if [ "$after" -lt "$before" ]; then
  echo "event count regressed after crash: $before -> $after" >&2
  exit 1
fi

unauthorized=$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:9710/api/health)
[ "$unauthorized" = "401" ]
complex=$(curl -sS -o /dev/null -w '%{http_code}' -H "x-redtrace-token: $token" "http://127.0.0.1:9710/api/search?q=$(node -e 'process.stdout.write(encodeURIComponent(Array(70).fill("a").join(" OR ")))')")
[ "$complex" = "400" ]
curl -fsS -H "x-redtrace-token: $token" http://127.0.0.1:9710/api/diagnostics >"$test_dir/diagnostics.json"
node -e 'const fs=require("fs");const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(value.privacy.contains_event_content||value.privacy.contains_file_paths||value.privacy.contains_user_names)process.exit(1);' "$test_dir/diagnostics.json"

echo "crash recovery smoke passed: events $before -> $after"
