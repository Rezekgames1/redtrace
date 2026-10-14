import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-empty-native-logs", action="store_true")
    arguments = parser.parse_args()
    app = arguments.app.resolve()
    output = arguments.output.resolve()
    output.mkdir(mode=0o700, exist_ok=True)
    os.umask(0o077)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 9710))
    swift = output / "windows.swift"
    swift.write_text('import Foundation\nimport CoreGraphics\nlet pid = Int(CommandLine.arguments[1])!\nlet all = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []\nlet own = all.filter { ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0 }\nlet result: [String: Any] = ["count": own.count, "onscreen": own.contains { ($0[kCGWindowIsOnscreen as String] as? Bool) == true }]\nlet data = try JSONSerialization.data(withJSONObject: result)\nprint(String(data: data, encoding: .utf8)!)\n')
    executable = app / "Contents/MacOS/redtrace-desktop"
    expected_core = app / "Contents/MacOS/redtrace"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("REDTRACE_")}
    environment.update(REDTRACE_DATA_DIR=str(output / "data"), REDTRACE_LOOKBACK="2m", RUST_LOG="redtrace=info,tower_http=debug")
    token = None
    core_pid = None
    report = {"platform": "macOS arm64", "result": "FAIL"}

    def api(path, authorized=True):
        headers = {"x-redtrace-token": token} if authorized else {}
        with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:9710" + path, headers=headers), timeout=5) as response:
            return json.load(response)

    with (output / "desktop.log").open("w") as log:
        desktop = subprocess.Popen([str(executable)], env=environment, stdout=log, stderr=log, start_new_session=True)
        try:
            for _ in range(100):
                if desktop.poll() is not None:
                    raise RuntimeError("macOS desktop exited; inspect protected desktop.log")
                processes = subprocess.check_output(["/bin/ps", "-axww", "-o", "pid=,ppid=,comm="], text=True)
                for row in processes.splitlines():
                    parts = row.split(None, 2)
                    if len(parts) == 3 and int(parts[1]) == desktop.pid and parts[2] == str(expected_core):
                        core_pid = int(parts[0])
                        variables = subprocess.check_output(["/bin/ps", "-E", "-ww", "-p", str(core_pid), "-o", "command="], text=True)
                        match = re.search(r"(?:^|\s)REDTRACE_API_TOKEN=([0-9a-f]{64})(?:\s|$)", variables)
                        if match:
                            token = match.group(1)
                if token:
                    try:
                        health = api("/api/health")
                        text = (output / "desktop.log").read_text()
                        if "/api/search" in text and "/api/live" in text and (health["events_indexed"] > 0 or arguments.allow_empty_native_logs and health["source"]["state"] in {"streaming", "ready", "degraded"}):
                            break
                    except (OSError, urllib.error.URLError):
                        pass
                time.sleep(0.5)
            else:
                raise RuntimeError("PID-bound authenticated core and frontend traffic were not established")
            window = json.loads(subprocess.check_output(["/usr/bin/swift", str(swift), str(desktop.pid)], text=True, timeout=60))
            if window["count"] < 1:
                raise RuntimeError("Native macOS window missing")
            results = api("/api/search?q=*&limit=100")
            if not results["events"] and not arguments.allow_empty_native_logs:
                raise RuntimeError("Native collector has no events")
            try:
                api("/api/health", authorized=False)
                raise RuntimeError("Missing token accepted")
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    raise
            first = results["events"][0]["timestamp"] if results["events"] else "2026-01-01T00:00:00Z"
            query = urllib.parse.urlencode({"q": "*", "from": first, "limit": 100})
            ranged = api("/api/search?" + query)
            if not ranged["events"] and results["events"]:
                raise RuntimeError("Date/time API rejected valid native timestamp")
            report.update(result="PASS", native_window=window, indexed=results["total"], api_events=len(results["events"]), sources=sorted({event["source"] for event in results["events"]}), date_time_filter="PASS", frontend_requests=["/api/health", "/api/search", "/api/live"], unauthenticated="401")
            report["native_event_delivery"] = "PASS" if results["events"] else "not exercised: no accessible native events in the configured lookback"
            report["source_status"] = health["source"]
            quit_result = subprocess.run(["/usr/bin/osascript", "-e", f'tell application "{app}" to quit'], capture_output=True, text=True, timeout=15)
            if quit_result.returncode == 0:
                desktop.wait(timeout=35)
                report["gui_quit"] = "PASS"
            else:
                report["gui_quit"] = "Apple Events permission unavailable; explicit owned cleanup used"
        finally:
            if token:
                try:
                    identity = api("/api/session")
                    request = urllib.request.Request("http://127.0.0.1:9710/api/session/stop", data=b"", headers={"x-redtrace-token": token, "x-redtrace-instance": identity["instance"]})
                    urllib.request.urlopen(request, timeout=5).close()
                except (OSError, urllib.error.URLError):
                    pass
            if desktop.poll() is None:
                desktop.terminate()
                try:
                    desktop.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    desktop.kill()
                    desktop.wait()
            if core_pid:
                for _ in range(60):
                    try:
                        os.kill(core_pid, 0)
                    except ProcessLookupError:
                        report["core_cleanup"] = "PASS"
                        break
                    time.sleep(0.25)
                else:
                    os.kill(core_pid, signal.SIGTERM)
                    report["core_cleanup"] = "Explicit owned core stop required"
            (output / "report.json").write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
