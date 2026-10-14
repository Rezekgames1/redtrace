import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import gi

gi.require_version("Atspi", "2.0")
from gi.repository import Atspi


def accessible_names():
    names = []
    stack = [Atspi.get_desktop(0)]
    while stack and len(names) < 20000:
        node = stack.pop()
        if node is None:
            continue
        try:
            name = node.get_name()
            if name:
                names.append(name)
            stack.extend(node.get_child_at_index(index) for index in range(node.get_child_count()))
        except Exception:
            continue
    return names


def close_window(window):
    class Data(ctypes.Union):
        _fields_ = [("longs", ctypes.c_long * 5)]

    class ClientMessage(ctypes.Structure):
        _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong), ("send_event", ctypes.c_int), ("display", ctypes.c_void_p), ("window", ctypes.c_ulong), ("message_type", ctypes.c_ulong), ("format", ctypes.c_int), ("data", Data)]

    class Event(ctypes.Union):
        _fields_ = [("client", ClientMessage), ("padding", ctypes.c_long * 24)]

    x11 = ctypes.CDLL("libX11.so.6")
    x11.XOpenDisplay.restype = ctypes.c_void_p
    x11.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    x11.XInternAtom.restype = ctypes.c_ulong
    x11.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_long, ctypes.POINTER(Event)]
    x11.XFlush.argtypes = [ctypes.c_void_p]
    x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
    display = x11.XOpenDisplay(None)
    if not display:
        raise RuntimeError("X11 display unavailable")
    event = Event()
    event.client.type = 33
    event.client.display = display
    event.client.window = window
    event.client.message_type = x11.XInternAtom(display, b"WM_PROTOCOLS", 0)
    event.client.format = 32
    event.client.data.longs[0] = x11.XInternAtom(display, b"WM_DELETE_WINDOW", 0)
    x11.XSendEvent(display, window, 0, 0, ctypes.byref(event))
    x11.XFlush(display)
    x11.XCloseDisplay(display)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not arguments.output.parent.is_dir():
        raise RuntimeError("Output parent must exist")
    arguments.output.mkdir(exist_ok=True)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 9710))
    with tempfile.TemporaryDirectory(prefix="redtrace-linux-desktop-") as directory:
        directory = Path(directory)
        subprocess.run(["dpkg-deb", "--extract", str(arguments.package), str(directory / "package")], check=True)
        environment = dict(os.environ, REDTRACE_DATA_DIR=str(directory / "data"), REDTRACE_LOOKBACK="15m", GDK_BACKEND="x11", GTK_MODULES="atk-bridge", NO_AT_BRIDGE="0")
        with (arguments.output / "desktop.log").open("w") as log:
            desktop = subprocess.Popen([str(directory / "package/usr/bin/redtrace-desktop")], env=environment, stdout=log, stderr=log, start_new_session=True)
            try:
                token = None
                core_pid = None
                window = None
                for _ in range(120):
                    assert desktop.poll() is None, "Linux desktop exited unexpectedly; inspect desktop.log"
                    for entry in Path("/proc").iterdir():
                        if not entry.name.isdigit():
                            continue
                        try:
                            status = (entry / "status").read_text()
                            if re.search(rf"PPid:\s+{desktop.pid}\n", status) and Path(os.readlink(entry / "exe")).name == "redtrace":
                                core_pid = int(entry.name)
                                variables = (entry / "environ").read_bytes().split(b"\0")
                                token = next(value.split(b"=", 1)[1].decode() for value in variables if value.startswith(b"REDTRACE_API_TOKEN="))
                        except (OSError, StopIteration):
                            pass
                    windows = subprocess.run(["xwininfo", "-root", "-tree"], capture_output=True, text=True, check=True).stdout
                    match = re.search(r'(0x[0-9a-f]+) "RED//TRACE', windows)
                    if match:
                        window = int(match.group(1), 16)
                    names = accessible_names()
                    if token and window and any("Журнал событий" in name for name in names) and any("linux." in name for name in names):
                        break
                    time.sleep(0.5)
                assert token and core_pid and window, "Window or PID-checked core/token missing"
                assert any("Журнал событий" in name for name in names), "WebView UI not visible in accessibility tree"
                assert any("linux." in name for name in names), "No actual Linux event rows in WebView"
                def api(path, authorized=True):
                    headers = {"x-redtrace-token": token} if authorized else {}
                    with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:9710" + path, headers=headers), timeout=3) as response:
                        return json.load(response)

                health = api("/api/health")
                results = api("/api/search?q=*&limit=100")
                assert results["total"] > 0 and results["events"]
                marker = "REDTRACE-GUI-LIVE-" + secrets.token_hex(8)
                started = time.monotonic()
                subprocess.run(["logger", "--tag", "redtrace-ui-validation", marker], check=True)
                for _ in range(100):
                    names = accessible_names()
                    if any(marker in name for name in names):
                        break
                    time.sleep(0.1)
                assert any(marker in name for name in names), "Live journal record did not appear in actual WebView without manual refresh"
                live_latency_ms = round((time.monotonic() - started) * 1000)
                health = api("/api/health")
                process_rows = subprocess.run(["ps", "-eo", "pid,ppid,rss,comm", "--no-headers"], capture_output=True, text=True, check=True).stdout.splitlines()
                tree = {desktop.pid}
                rows = [line.split(None, 3) for line in process_rows]
                for _ in range(10):
                    tree.update(int(pid) for pid, parent, _, _ in rows if int(parent) in tree)
                resources = [{"pid": int(pid), "name": name, "rss_kib": int(rss)} for pid, _, rss, name in rows if int(pid) in tree]
                try:
                    api("/api/health", False)
                    raise AssertionError("Desktop API accepted missing token")
                except urllib.error.HTTPError as error:
                    assert error.code == 401
                second = subprocess.Popen([str(directory / "package/usr/bin/redtrace-desktop")], env=environment, stdout=log, stderr=log)
                assert second.wait(timeout=10) == 0
                close_window(window)
                desktop.wait(timeout=15)
                for _ in range(40):
                    if not Path(f"/proc/{core_pid}").exists():
                        break
                    time.sleep(0.25)
                assert not Path(f"/proc/{core_pid}").exists(), "Core sidecar left alive after window close"
                report = {"result": "PASS", "events_indexed": health["events_indexed"], "api_events": len(results["events"]), "accessible_event_labels": sum("linux." in name for name in names), "live_latency_ms": live_latency_ms, "source": health["source"], "process_rss_snapshot": resources, "rss_method": "ps rss KiB for desktop descendants; shared pages may be counted more than once", "checks": ["extracted deb", "actual Linux WebView event rows", "automatic journald → SSE → WebView", "PID-checked sidecar", "authenticated API", "single instance", "window close/sidecar cleanup"]}
                (arguments.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
                print(json.dumps(report, ensure_ascii=False))
            finally:
                try:
                    os.killpg(desktop.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if desktop.poll() is None:
                    desktop.wait(timeout=10)


if __name__ == "__main__":
    main()
