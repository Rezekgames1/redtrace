#!/bin/sh
set -eu

if [ ! -f Cargo.toml ] || ! grep -q '^name = "redtrace"$' Cargo.toml; then
    echo "run from the redtrace repository root" >&2
    exit 2
fi

TMP=$(mktemp -d /tmp/redtrace-agent-smoke.XXXXXX)
FIXTURE="$TMP/bin"
mkdir -p "$FIXTURE" "$TMP/server-data" "$TMP/agent-state"

cat > "$FIXTURE/journalctl" <<'SHIM'
#!/bin/sh
now=$(date +%s)
pid=$$
printf '%s\n' \
  "{\"MESSAGE\":\"Failed password for root from 10.99.0.7 port 50222 ssh2\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"__REALTIME_TIMESTAMP\":\"${now}000000\",\"_PID\":\"111\",\"__CURSOR\":\"smoke=${pid}-1\"}" \
  "{\"MESSAGE\":\"Failed password for invalid user oracle from 10.99.0.8 port 50223 ssh2\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"__REALTIME_TIMESTAMP\":\"${now}000001\",\"_PID\":\"111\",\"__CURSOR\":\"smoke=${pid}-2\"}" \
  "{\"MESSAGE\":\"Accepted password for deploy from 10.99.0.9 port 50224 ssh2\",\"SYSLOG_IDENTIFIER\":\"sshd\",\"__REALTIME_TIMESTAMP\":\"${now}000002\",\"_PID\":\"112\",\"__CURSOR\":\"smoke=${pid}-3\"}"
SHIM
chmod +x "$FIXTURE/journalctl"

echo "[smoke] building release binaries"
cargo build --release --bin redtrace --bin redtrace-agent

SERVER_PID=""
AGENT_PID=""
cleanup() {
    [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

echo "[smoke] starting core with isolated data dir and ingest port"
REDTRACE_DATA_DIR="$TMP/server-data" \
REDTRACE_ALLOW_UNAUTHENTICATED=1 \
REDTRACE_INGEST_BIND="127.0.0.1:9711" \
REDTRACE_SEGMENT_MB=1 \
    ./target/release/redtrace > "$TMP/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
    if curl -sf http://127.0.0.1:9710/api/health > "$TMP/health.json" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
curl -sf http://127.0.0.1:9710/api/health > /dev/null

echo "[smoke] registering agent token"
curl -sf -X POST http://127.0.0.1:9710/api/agents \
    -H 'Content-Type: application/json' \
    -d '{"name":"smoke-host"}' > "$TMP/agent.json"

AGENT_ID=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/agent.json"))["id"])')
AGENT_TOKEN=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/agent.json"))["token"])')
echo "[smoke] agent id: $AGENT_ID"

echo "[smoke] starting agent with fixture journalctl on PATH"
PATH="$FIXTURE:$PATH" \
    ./target/release/redtrace-agent \
    --server http://127.0.0.1:9711 \
    --token "$AGENT_TOKEN" \
    --name smoke-host \
    --state-dir "$TMP/agent-state" \
    --poll 1 > "$TMP/agent.log" 2>&1 &
AGENT_PID=$!

sleep 6

echo "[smoke] verifying search, sources and health"
curl -sf "http://127.0.0.1:9710/api/search?q=agent.id:$AGENT_ID&limit=50" > "$TMP/search.json"
FOUND=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/search.json"))["total"])')
echo "[smoke] events from agent: $FOUND"

curl -sf http://127.0.0.1:9710/api/sources > "$TMP/sources.json"
AGENT_SOURCE=$(python3 -c 'import json;print(sum(1 for s in json.load(open("'"$TMP"'/sources.json")) if s["name"]=="agent.smoke-host"))')

curl -sf http://127.0.0.1:9710/api/health > "$TMP/health.json"
REMOTE_TOTAL=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/health.json"))["remote_ingest"]["remote_events_total"])')
ENABLED=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/health.json"))["remote_ingest"]["enabled"])')
AGENTS_ACTIVE=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/health.json"))["remote_ingest"]["agents_active"])')
echo "[smoke] remote_ingest: enabled=$ENABLED agents_active=$AGENTS_ACTIVE remote_events_total=$REMOTE_TOTAL"

sleep 3
curl -sf "http://127.0.0.1:9710/api/search?q=agent.id:$AGENT_ID&limit=50" > "$TMP/search2.json"
FOUND_AFTER=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/search2.json"))["total"])')
echo "[smoke] events after continued polling (dedup expected): $FOUND_AFTER"

FAILED=0
[ "$FOUND" -ge 3 ] || { echo "FAIL: expected at least 3 agent events, got $FOUND"; FAILED=1; }
[ "$AGENT_SOURCE" -eq 1 ] || { echo "FAIL: agent source missing in /api/sources"; FAILED=1; }
[ "$ENABLED" = "True" ] || { echo "FAIL: remote ingest is not enabled"; FAILED=1; }
[ "$AGENTS_ACTIVE" -ge 1 ] || { echo "FAIL: agent is not active"; FAILED=1; }
[ "$REMOTE_TOTAL" -ge 3 ] || { echo "FAIL: remote_events_total too low"; FAILED=1; }
[ "$FOUND_AFTER" -eq "$FOUND" ] || { echo "FAIL: duplicate events were re-indexed ($FOUND -> $FOUND_AFTER)"; FAILED=1; }

kill "$AGENT_PID" 2>/dev/null || true
AGENT_PID=""

curl -sf -X DELETE "http://127.0.0.1:9710/api/agents/$AGENT_ID" > "$TMP/revoke.json"
REVOKED=$(python3 -c 'import json;print(json.load(open("'"$TMP"'/revoke.json"))["revoked"])')

PATH="$FIXTURE:$PATH" \
    ./target/release/redtrace-agent \
    --server http://127.0.0.1:9711 \
    --token "$AGENT_TOKEN" \
    --name smoke-host \
    --state-dir "$TMP/agent-state-2" \
    --poll 1 > "$TMP/agent2.log" 2>&1 &
AGENT_PID=$!
sleep 4
if grep -q "token" "$TMP/agent2.log" && grep -qi "401\|rejected" "$TMP/agent2.log"; then
    echo "[smoke] revoked token correctly rejected"
else
    echo "FAIL: revoked agent was not rejected"
    cat "$TMP/agent2.log" || true
    FAILED=1
fi

if [ "$REVOKED" = "True" ] && [ "$FAILED" -eq 0 ]; then
    echo "PASS: agent ingest smoke"
    exit 0
fi
echo "FAIL: agent ingest smoke"
exit 1
