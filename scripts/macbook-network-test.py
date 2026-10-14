import argparse
import datetime
import ipaddress
import json
import os
import pathlib
import secrets
import socket
import subprocess
import time
import urllib.request
import urllib.parse

import paramiko
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def request(base, token, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, headers={"x-redtrace-token": token, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def execute(client, command):
    _, stdout, stderr = client.exec_command(command, timeout=120)
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    if stdout.channel.recv_exit_status():
        raise RuntimeError(f"Remote command failed: {err[:1000]}")
    return out


def stop_core(base, token, core):
    identity = request(base, token, "/api/session")
    req = urllib.request.Request(base + "/api/session/stop", data=b"", headers={"x-redtrace-token": token, "x-redtrace-instance": identity["instance"]})
    urllib.request.urlopen(req, timeout=5).close()
    core.wait(timeout=15)


def ssh_client(args):
    client = paramiko.SSHClient()
    client.load_host_keys(str(pathlib.Path.home() / ".ssh/known_hosts"))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(args.host, username=args.user, key_filename=args.key, allow_agent=False, look_for_keys=False, timeout=10)
    return client


def remote_pending(client, state):
    with client.open_sftp() as sftp:
        return len([name for name in sftp.listdir(state + "/pending") if name.endswith(".json")])


def certificates(directory, address):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "REDTRACE temporary network test CA")])
    ca = x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, address)])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]), critical=False).sign(ca_key, hashes.SHA256())
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "server.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--collector", required=True)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--ingest-port", type=int, default=19711)
    args = parser.parse_args()
    directory = args.root / ("redtrace-network-" + secrets.token_hex(8))
    directory.mkdir()
    sid = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"], text=True).strip()
    subprocess.run(["icacls.exe", str(directory), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=True, capture_output=True)
    certificates(directory, args.collector)
    api_probe = socket.socket()
    api_probe.bind(("127.0.0.1", 0))
    api_port = api_probe.getsockname()[1]
    api_probe.close()
    ingest_probe = socket.socket()
    ingest_probe.bind((args.collector, args.ingest_port))
    ingest_port = ingest_probe.getsockname()[1]
    ingest_probe.close()
    token = secrets.token_hex(32)
    env = {key: value for key, value in os.environ.items() if not key.startswith("REDTRACE_")}
    env.update(REDTRACE_API_TOKEN=token, REDTRACE_API_BIND=f"127.0.0.1:{api_port}", REDTRACE_DATA_DIR=str(directory / "data"), REDTRACE_COLLECT_LOCAL="0", REDTRACE_INGEST_BIND=f"{args.collector}:{ingest_port}", REDTRACE_INGEST_CERT=str(directory / "server.pem"), REDTRACE_INGEST_KEY=str(directory / "server.key"))
    log = (directory / "core.log").open("wb")
    core = subprocess.Popen([str(pathlib.Path("target/debug/redtrace.exe").resolve())], env=env, stdout=log, stderr=log)
    client = paramiko.SSHClient()
    client.load_host_keys(str(pathlib.Path.home() / ".ssh/known_hosts"))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    remote = f"/Users/{args.user}/.local/share/redtrace-network-validation-20261013"
    remote_state = remote + "/agent-state-" + directory.name
    remote_pid = None
    base = f"http://127.0.0.1:{api_port}"
    report = {"directory": str(directory), "transport": "direct LAN HTTPS", "mac_host": args.host, "collector": args.collector}
    try:
        for _ in range(80):
            if core.poll() is not None:
                raise RuntimeError("Isolated collector exited; inspect protected core.log")
            try:
                request(base, token, "/api/health")
                break
            except Exception:
                time.sleep(0.25)
        issued = request(base, token, "/api/agents", {"name": "macbook-network-test"})
        client.connect(args.host, username=args.user, key_filename=args.key, allow_agent=False, look_for_keys=False, timeout=10)
        with client.open_sftp() as sftp:
            sftp.put(str(directory / "ca.pem"), remote + "/ca.pem")
            with sftp.open(remote + "/agent.token", "w") as output:
                output.write(issued["token"] + "\n")
            sftp.chmod(remote + "/agent.token", 0o600)
        probe = execute(client, f"/usr/bin/curl --silent --show-error --connect-timeout 5 --cacert {remote}/ca.pem https://{args.collector}:{ingest_port}/ingest/v1/health")
        report["tls_health"] = json.loads(probe)
        denied = execute(client, f"/usr/bin/curl --silent --show-error --connect-timeout 5 --cacert {remote}/ca.pem -o /dev/null -w '%{{http_code}}' -H 'x-redtrace-ingest-token: {'0' * 64}' -H 'content-type: application/json' -d '{{}}' https://{args.collector}:{ingest_port}/ingest/v1/heartbeat")
        if denied != "401":
            raise RuntimeError("Invalid credential was not rejected")
        report["invalid_token_rejected"] = True
        no_ca = execute(client, f"/usr/bin/curl --silent --connect-timeout 5 -o /dev/null https://{args.collector}:{ingest_port}/ingest/v1/health; result=$?; test $result -eq 60 && echo rejected")
        if no_ca.strip() != "rejected":
            raise RuntimeError("Untrusted CA was not rejected")
        report["untrusted_ca_rejected"] = True
        remote_pid = int(execute(client, f"cd {remote}; REDTRACE_AGENT_SERVER=https://{args.collector}:{ingest_port} REDTRACE_AGENT_TOKEN_FILE={remote}/agent.token REDTRACE_AGENT_CA={remote}/ca.pem REDTRACE_AGENT_NAME=macbook-network-test REDTRACE_AGENT_STATE={remote_state} REDTRACE_LOOKBACK=2m nohup source/target/debug/redtrace-agent > agent.log 2>&1 < /dev/null & echo $!").strip())
        deadline = time.monotonic() + 45
        agent_query = urllib.parse.quote('agent.id="' + issued["id"] + '"')
        results = None
        while time.monotonic() < deadline:
            results = request(base, token, "/api/search?q=" + agent_query + "&limit=100")
            if results["total"]:
                break
            time.sleep(0.5)
        if not results or not results["total"]:
            raise RuntimeError("MacBook telemetry did not arrive; inspect protected remote agent.log")
        report["events"] = results["total"]
        report["sources"] = sorted({event["source"] for event in results["events"]})
        original_uids = {event["uid"] for event in results["events"]}
        trigger = time.monotonic()
        with ssh_client(args) as extra:
            execute(extra, "/usr/bin/true")
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            live = request(base, token, "/api/search?q=" + agent_query + "&limit=1000")
            if any(event["uid"] not in original_uids for event in live["events"]):
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("Fresh SSH telemetry did not arrive")
        report["fresh_ssh_delivery_ms"] = round((time.monotonic() - trigger) * 1000)
        before_restart = {event["uid"] for event in live["events"]}
        stop_core(base, token, core)
        with ssh_client(args) as extra:
            execute(extra, "/usr/bin/true")
        deadline = time.monotonic() + 15
        pending = 0
        while time.monotonic() < deadline:
            pending = remote_pending(client, remote_state)
            if pending:
                break
            time.sleep(0.5)
        if not pending:
            raise RuntimeError("Offline agent did not preserve new telemetry in spool")
        report["offline_spooled_events"] = pending
        execute(client, f"kill -KILL {remote_pid}")
        remote_pid = None
        core = subprocess.Popen([str(pathlib.Path("target/debug/redtrace.exe").resolve())], env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                request(base, token, "/api/health")
                break
            except Exception:
                time.sleep(0.25)
        remote_pid = int(execute(client, f"cd {remote}; REDTRACE_AGENT_SERVER=https://{args.collector}:{ingest_port} REDTRACE_AGENT_TOKEN_FILE={remote}/agent.token REDTRACE_AGENT_CA={remote}/ca.pem REDTRACE_AGENT_NAME=macbook-network-test REDTRACE_AGENT_STATE={remote_state} REDTRACE_LOOKBACK=2m nohup source/target/debug/redtrace-agent >> agent.log 2>&1 < /dev/null & echo $!").strip())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            recovered = request(base, token, "/api/search?q=" + agent_query + "&limit=1000")
            if before_restart.issubset({event["uid"] for event in recovered["events"]}) and remote_pending(client, remote_state) == 0 and recovered["total"] > live["total"]:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("Collector/force-killed agent restart did not recover all observed UIDs and spool")
        report["restart_original_uids_preserved"] = len(before_restart)
        report["offline_forcekill_recovery"] = True
        report["events_after_restart"] = recovered["total"]
        report["pending_after_recovery"] = remote_pending(client, remote_state)
        report["health"] = request(base, token, "/api/health")
        report["mac_agent_process"] = execute(client, f"/bin/ps -p {remote_pid} -o pid=,rss=,%cpu=,etime=").strip()
        print(json.dumps(report, indent=2))
    except Exception as error:
        report["error"] = str(error)
        print(json.dumps(report, indent=2))
        raise
    finally:
        if remote_pid and client.get_transport() and client.get_transport().is_active():
            execute(client, f"kill -TERM {remote_pid} 2>/dev/null || true")
        client.close()
        if core.poll() is None:
            try:
                stop_core(base, token, core)
            except Exception:
                core.terminate()
                core.wait(timeout=5)
        log.close()
        (directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
