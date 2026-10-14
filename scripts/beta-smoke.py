import json
import os
import pathlib
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main():
    root = pathlib.Path(os.environ["LOCALAPPDATA"]) / "Temp/opencode" / ("redtrace-beta-smoke-" + secrets.token_hex(8))
    root.mkdir()
    api_port, ingest_port = port(), port()
    token = secrets.token_hex(32)
    env = {key: value for key, value in os.environ.items() if not key.startswith("REDTRACE_")}
    env.update(REDTRACE_API_TOKEN=token, REDTRACE_API_BIND=f"127.0.0.1:{api_port}", REDTRACE_DATA_DIR=str(root / "data"), REDTRACE_COLLECT_LOCAL="0", REDTRACE_INGEST_BIND=f"127.0.0.1:{ingest_port}")
    base = f"http://127.0.0.1:{api_port}"

    def request(url, credential=token, body=None, ingest=False):
        req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers={"x-redtrace-ingest-token" if ingest else "x-redtrace-token": credential, "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)

    with (root / "core.log").open("wb") as log:
        core = subprocess.Popen(["outputs/beta-20261013/windows-x64/redtrace.exe"], env=env, stdout=log, stderr=log)
        try:
            for _ in range(60):
                try:
                    request(base + "/api/health")
                    break
                except Exception:
                    if core.poll() is not None:
                        raise RuntimeError("Packaged core exited")
                    time.sleep(0.2)
            agent = request(base + "/api/agents", body={"name": "beta-smoke-fixture"})
            events = [{"timestamp": f"2026-10-13T06:00:0{index}Z", "source": "beta.fixture", "level": "low", "message": f"isolated time fixture {index}", "fields": {"event.record_id": str(index)}} for index in range(4)]
            ack = request(f"http://127.0.0.1:{ingest_port}/ingest/v1/events", agent["token"], {"events": events}, ingest=True)
            assert ack["accepted"] == 4
            bounds = {"q": "*", "from": "2026-10-13T09:00:01+03:00", "to": "2026-10-13T06:00:03Z"}
            search = request(base + "/api/search?" + urllib.parse.urlencode({**bounds, "limit": 1}))
            assert search["total"] == 2 and len(search["events"]) == 1
            page = request(base + "/api/search?" + urllib.parse.urlencode({**bounds, "cursor": search["next_cursor"]}))
            assert page["total"] == 2 and len(page["events"]) == 1
            aggregate = request(base + "/api/aggregations?" + urllib.parse.urlencode(bounds))
            assert aggregate["total"] == aggregate["sampled"] == 2
            export = request(base + "/api/export?" + urllib.parse.urlencode({**bounds, "format": "json"}))
            assert len(export) == 2
            try:
                request(base + "/api/search?from=invalid")
                raise RuntimeError("Invalid date accepted")
            except urllib.error.HTTPError as error:
                assert error.code == 400
            print(json.dumps({"packaged_windows_core": "PASS", "isolated_events": 4, "filtered_events": 2, "paging": "PASS", "aggregation": "PASS", "export": "PASS", "invalid_date": "400", "fixture_directory": str(root)}, indent=2))
        finally:
            if core.poll() is None:
                try:
                    identity = request(base + "/api/session")
                    req = urllib.request.Request(base + "/api/session/stop", data=b"", headers={"x-redtrace-token": token, "x-redtrace-instance": identity["instance"]})
                    urllib.request.urlopen(req, timeout=5).close()
                    core.wait(timeout=15)
                except Exception:
                    core.terminate()
                    core.wait(timeout=5)


if __name__ == "__main__":
    main()
