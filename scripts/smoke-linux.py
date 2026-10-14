import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def request(path, token, method="GET", body=None):
    headers = {"x-redtrace-token": token, "Content-Type": "application/json"}
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:9710{path}", headers=headers, method=method, data=data)
    with urllib.request.urlopen(req, timeout=3) as response:
        return json.load(response)


def wait_for(check, seconds=40):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            result = check()
            if result:
                return result
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(0.25)
    raise AssertionError("Timed out waiting for Linux collector/API")


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def main():
    if not Path("/proc").exists():
        raise RuntimeError("Run this smoke test on Linux")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 9710))
    root = Path(__file__).resolve().parent.parent
    subprocess.run(["cargo", "build", "--bins", "--locked"], cwd=root, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
    core_binary = target / "debug" / "redtrace"
    agent_binary = target / "debug" / "redtrace-agent"
    token = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="redtrace-linux-smoke-") as directory:
        directory = Path(directory)
        environment = dict(os.environ, REDTRACE_DATA_DIR=str(directory / "core"), REDTRACE_API_TOKEN=token, REDTRACE_LOOKBACK="15m", REDTRACE_INGEST_BIND="127.0.0.1:9711")
        for variable in ("REDTRACE_INGEST_CERT", "REDTRACE_INGEST_KEY"):
            environment.pop(variable, None)
        processes = []
        with (directory / "core.log").open("w") as core_log, (directory / "agent.log").open("w") as agent_log:
            def start_core():
                process = subprocess.Popen([str(core_binary)], env=environment, stdout=core_log, stderr=core_log, start_new_session=True)
                processes.append(process)
                wait_for(lambda: request("/api/health", token))
                return process

            def search(query):
                return request("/api/search?" + urllib.parse.urlencode({"q": query, "limit": 1000}), token)

            try:
                core = start_core()
                for route in ("/api/health", "/api/live"):
                    try:
                        request(route, "")
                        raise AssertionError("API accepted missing session token")
                    except urllib.error.HTTPError as error:
                        assert error.code == 401
                baseline = wait_for(lambda: (result := search("source~linux."))["events"] and result)
                first = baseline["events"][0]
                assert first["fields"].get("collector.cursor")
                live_request = urllib.request.Request("http://127.0.0.1:9710/api/live", headers={"x-redtrace-token": token})
                live_stream = urllib.request.urlopen(live_request, timeout=10)
                assert live_stream.headers["content-type"].startswith("text/event-stream")
                def read_revision():
                    while line := live_stream.readline():
                        if line.startswith(b"data:"):
                            return int(line.split(b":", 1)[1])
                    raise AssertionError("Live stream ended before notification")
                initial_revision = read_revision()
                marker = "redtrace-validation-" + secrets.token_hex(8)
                subprocess.run(["logger", "--tag", "redtrace-validation", marker], check=True)
                live = wait_for(lambda: (result := search(f'"{marker}"'))["total"] and result)
                assert live["total"] == 1
                event = live["events"][0]
                assert read_revision() > initial_revision
                live_stream.close()
                assert event["fields"]["process.pid"]
                assert search('source="linux.redtrace-validation"')["total"] >= 1
                assert search(f'message~"{marker[5:]}"')["total"] == 1
                assert search(f'message="{marker}"')["total"] == 1
                assert search(f'NOT message="{marker}"')["total"] >= baseline["total"]
                agent = request("/api/agents", token, "POST", {"name": "linux-validation"})
                agent_env = dict(environment, REDTRACE_AGENT_TOKEN=agent["token"], REDTRACE_AGENT_STATE=str(directory / "agent"))
                process = subprocess.Popen([str(agent_binary), "--server", "http://127.0.0.1:9711", "--name", "linux-validation", "--poll", "1"], env=agent_env, stdout=agent_log, stderr=agent_log, start_new_session=True)
                processes.append(process)
                remote = wait_for(lambda: (result := search(f'agent.id="{agent["id"]}"'))["total"] and result)
                agents = request("/api/agents", token)["agents"]
                assert next(item for item in agents if item["id"] == agent["id"])["platform"] == "linux"
                stop(core)
                processes.remove(core)
                start_core()
                recovered = search(f'uid="{event["uid"]}"')
                assert recovered["total"] == 1
                assert search(f'message="{marker}" AND NOT agent.id:*')["total"] == 1
                assert request(f'/api/agents/{agent["id"]}', token, "DELETE")["revoked"]
                health = request("/api/health", token)
                assert health["storage"]["checkpoint_sources"] > 0
                assert health["ingestion"]["wal_errors"] == 0
                print(json.dumps({"result": "PASS", "real_backfill_events": baseline["total"], "remote_events": remote["total"], "events_indexed": health["events_indexed"], "source": health["source"], "checks": ["authenticated API", "real journald backfill", "live diagnostic record", "exact/contains/exclusion", "Linux remote agent", "crash recovery/dedup", "revocation"]}, ensure_ascii=False))
            finally:
                for process in reversed(processes):
                    stop(process)


if __name__ == "__main__":
    main()
