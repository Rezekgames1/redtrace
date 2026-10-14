import argparse
import io
import os
import pathlib
import shlex
import subprocess
import sys
import tkinter
from tkinter import simpledialog

import paramiko


def connect(host, user, key_path, bootstrap):
    client = paramiko.SSHClient()
    known_hosts = pathlib.Path.home() / ".ssh" / "known_hosts"
    client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    if bootstrap:
        root = tkinter.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        password = simpledialog.askstring("REDTRACE MacBook SSH", f"SSH password for {user}@{host}", show="*", parent=root)
        root.destroy()
        if not password:
            raise RuntimeError("SSH password input cancelled")
        client.connect(host, username=user, password=password, look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=20)
        password = None
        key = paramiko.RSAKey.generate(3072)
        stream = io.StringIO()
        key.write_private_key(stream)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            sid = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"], text=True).strip()
            subprocess.run(["icacls.exe", str(key_path.parent), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=True, capture_output=True)
        with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            output.write(stream.getvalue())
        public = f"{key.get_name()} {key.get_base64()} redtrace-macbook-temporary"
        command = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; printf '%s\\n' " + shlex.quote(public) + " >> ~/.ssh/authorized_keys"
        run(client, command)
        print("Temporary SSH access ready; credentials were not printed")
    else:
        client.connect(host, username=user, key_filename=str(key_path), look_for_keys=False, allow_agent=False, timeout=10, auth_timeout=10)
    return client


def run(client, command):
    _, stdout, stderr = client.exec_command(command, timeout=120)
    text = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    if text:
        print(text, end="")
    if error:
        print(error, end="", file=sys.stderr)
    status = stdout.channel.recv_exit_status()
    if status:
        raise RuntimeError(f"Remote command exited {status}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["bootstrap", "exec", "upload", "download", "cleanup"])
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--key", type=pathlib.Path, required=True)
    parser.add_argument("--command")
    parser.add_argument("--command-file", type=pathlib.Path)
    parser.add_argument("--local", type=pathlib.Path)
    parser.add_argument("--remote")
    args = parser.parse_args()
    client = connect(args.host, args.user, args.key, args.action == "bootstrap")
    try:
        if args.action == "bootstrap":
            run(client, "sw_vers; uname -m; id; command -v cargo || true; command -v rustc || true; command -v brew || true; launchctl list com.apple.auditd || true")
        elif args.action == "exec":
            command = args.command_file.read_text(encoding="utf-8") if args.command_file else args.command
            if not command:
                raise RuntimeError("Remote command is required")
            run(client, command)
        elif args.action in ("upload", "download"):
            if not args.local or not args.remote:
                raise RuntimeError("Local and remote paths required")
            with client.open_sftp() as sftp:
                if args.action == "upload":
                    sftp.put(str(args.local), args.remote)
                else:
                    sftp.get(args.remote, str(args.local))
        elif args.action == "cleanup":
            key = paramiko.RSAKey.from_private_key_file(str(args.key))
            public = f"{key.get_name()} {key.get_base64()} redtrace-macbook-temporary"
            with client.open_sftp() as sftp:
                home = sftp.normalize(".")
                path = home + "/.ssh/authorized_keys"
                with sftp.open(path, "r") as source:
                    original = source.read().decode()
                lines = [line for line in original.splitlines() if line != public]
                temporary = path + ".redtrace-cleanup"
                with sftp.open(temporary, "w") as output:
                    output.write("\n".join(lines) + "\n")
                sftp.chmod(temporary, 0o600)
                sftp.posix_rename(temporary, path)
            args.key.unlink()
            print("Temporary SSH key removed locally and remotely")
    finally:
        client.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"MacBook SSH failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
