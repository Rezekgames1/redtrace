import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


ROOT = Path.home() / ".local" / "share" / "redtrace-wsl-pilot"
CONFIG = ROOT / "config.json"
BINARY = ROOT / "redtrace-agent"
PID_FILE = ROOT / "pid.json"


def write_private(path, value):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def identity(pid):
    try:
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        return {"executable": str(executable), "start": start}
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def running():
    if not PID_FILE.exists():
        return None
    saved = json.loads(PID_FILE.read_text())
    current = identity(saved["pid"])
    if current == saved["identity"] and current["executable"] == str(BINARY):
        return saved["pid"]
    return None


def stop():
    pid = running()
    if pid:
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            if not running():
                break
            time.sleep(0.1)
        if running():
            os.kill(pid, signal.SIGKILL)
    PID_FILE.unlink(missing_ok=True)
    return {"stopped": bool(pid)}


def network():
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route", "show", "default"]))
    route = next(item for item in routes if item.get("gateway"))
    addresses = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", route["dev"]]))
    address = next(item["local"] for item in addresses[0]["addr_info"] if item["family"] == "inet")
    return {"gateway": route["gateway"], "address": address, "hostname": socket.gethostname()}


def pki(payload):
    directory = ROOT / "pki"
    directory.mkdir(mode=0o700, exist_ok=True)
    ca_key = directory / "ca.key"
    ca = directory / "ca.pem"
    key = directory / "server.key"
    certificate = directory / "server.pem"
    csr = directory / "server.csr"
    extensions = directory / "server.ext"
    if not ca.exists() and not ca_key.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "30", "-keyout", str(ca_key), "-out", str(ca), "-subj", "/CN=REDTRACE WSL Pilot CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, capture_output=True)
    if not ca.exists() or not ca_key.exists():
        raise RuntimeError("Incomplete pilot CA; preserve the files and repair explicitly")
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=REDTRACE Windows WSL collector"], check=True, capture_output=True)
    write_private(extensions, f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:{payload['gateway']},IP:127.0.0.1,DNS:localhost\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(certificate), "-days", "14", "-sha256", "-extfile", str(extensions)], check=True, capture_output=True)
    result = {"ca": ca.read_text(), "certificate": certificate.read_text(), "key": key.read_text()}
    for path in (key, csr, extensions, certificate):
        path.unlink()
    return result


def configure(payload):
    if running():
        raise RuntimeError("Stop the pilot agent before changing its configuration")
    config = json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    if payload.get("token"):
        config["token"] = payload["token"]
    if not config.get("token"):
        raise RuntimeError("Agent enrollment token is required")
    config.update({"server": f"https://{payload['gateway']}:9711", "name": "kali-wsl", "agent_id": payload["agent_id"]})
    source = Path(payload["binary"])
    temporary = ROOT / (".agent-" + secrets.token_hex(8))
    shutil.copyfile(source, temporary)
    temporary.chmod(0o700)
    temporary.replace(BINARY)
    write_private(CONFIG, json.dumps(config))
    return {"configured": True, "agent_id": config["agent_id"], "root": str(ROOT)}


def start():
    pid = running()
    if pid:
        return {"pid": pid, "already_running": True}
    config = json.loads(CONFIG.read_text())
    environment = dict(os.environ)
    for key in list(environment):
        if key.startswith("REDTRACE_"):
            del environment[key]
    environment.update({"REDTRACE_AGENT_TOKEN": config["token"], "REDTRACE_AGENT_CA": str(ROOT / "pki" / "ca.pem"), "REDTRACE_AGENT_STATE": str(ROOT / "state")})
    with (ROOT / "agent.log").open("a") as log:
        process = subprocess.Popen([str(BINARY), "--server", config["server"], "--name", config["name"], "--poll", "2", "--heartbeat", "10", "--lookback", "15m"], env=environment, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
    for _ in range(30):
        current = identity(process.pid)
        if current and current["executable"] == str(BINARY):
            write_private(PID_FILE, json.dumps({"pid": process.pid, "identity": current}))
            return {"pid": process.pid, "server": config["server"]}
        if process.poll() is not None:
            raise RuntimeError("Agent exited during startup; inspect the protected agent.log")
        time.sleep(0.1)
    raise RuntimeError("Agent startup identity check timed out")


def health(payload):
    ca = ROOT / "pki" / "ca.pem"
    url = f"https://{payload['gateway']}:9711/ingest/v1/health"
    context = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(url, timeout=5) as response:
        result = json.load(response)
    if payload.get("negative_checks"):
        config = json.loads(CONFIG.read_text())
        for label, target, trust in [
            ("untrusted_ca", url, ssl.create_default_context()),
            ("wrong_san", url, context),
        ]:
            if label == "wrong_san":
                connection = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                connection.load_verify_locations(cafile=str(ca))
                try:
                    with socket.create_connection((payload["gateway"], 9711), timeout=5) as raw:
                        connection.wrap_socket(raw, server_hostname="wrong.redtrace.invalid")
                    raise RuntimeError("Wrong SAN accepted")
                except ssl.SSLCertVerificationError:
                    result[label] = "rejected"
            else:
                try:
                    rejected = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
                    rejected.open(target, timeout=5)
                    raise RuntimeError("Untrusted CA accepted")
                except urllib.error.URLError as error:
                    if not isinstance(error.reason, ssl.SSLCertVerificationError):
                        raise
                    result[label] = "rejected"
        request = urllib.request.Request(url.replace("/health", "/heartbeat"), data=b"{}", headers={"Content-Type": "application/json", "x-redtrace-ingest-token": secrets.token_hex(32)})
        try:
            opener.open(request, timeout=5)
            raise RuntimeError("Invalid token accepted")
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            result["invalid_token"] = "rejected"
        request.add_header("x-redtrace-ingest-token", config["token"])
        with opener.open(request, timeout=5) as response:
            result["authenticated_heartbeat"] = response.status
    return result


def status():
    config = json.loads(CONFIG.read_text()) if CONFIG.exists() else {}
    checkpoints = ROOT / "state" / "checkpoints.json"
    return {"pid": running(), "configured": bool(config), "server": config.get("server"), "agent_id": config.get("agent_id"), "checkpoint_exists": checkpoints.exists(), "credential_mode": oct(CONFIG.stat().st_mode & 0o777) if CONFIG.exists() else None, "root": str(ROOT)}


def main():
    os.umask(0o077)
    action = sys.argv[1]
    payload = {} if action == "hold" else json.loads(sys.stdin.read() or "{}")
    if action in ("pki", "configure", "start"):
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        if ROOT.stat().st_uid != os.getuid() or ROOT.stat().st_mode & 0o077:
            raise RuntimeError("Pilot directory must be owned by the current user with mode 700")
    if action == "network":
        result = network()
    elif action == "pki":
        result = pki(payload)
    elif action == "configure":
        result = configure(payload)
    elif action == "start":
        result = start()
    elif action == "hold":
        start()
        while running():
            time.sleep(1)
        return
    elif action == "stop":
        result = stop()
    elif action == "status":
        result = status()
    elif action == "health":
        result = health(payload)
    elif action == "marker":
        marker = "REDTRACE-WSL-" + secrets.token_hex(8)
        subprocess.run(["logger", "--tag", "redtrace-wsl-check", marker], check=True)
        result = {"marker": marker}
    else:
        raise ValueError("Unknown pilot action")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
