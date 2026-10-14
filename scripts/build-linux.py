import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--collect-only", action="store_true")
    arguments = parser.parse_args()
    source = Path(__file__).resolve().parent.parent
    workspace = arguments.workspace.resolve()
    if not workspace.parent.is_dir() or workspace == source or source in workspace.parents:
        raise RuntimeError("Use an existing external parent for the isolated Linux build workspace")
    workspace.mkdir(exist_ok=True)
    environment = dict(os.environ)
    environment["PATH"] = str(Path.home() / ".cargo" / "bin") + ":/usr/local/bin:/usr/bin:/bin"
    environment.setdefault("CARGO_TARGET_DIR", str(workspace.parent / "redtrace-linux-target"))
    if not arguments.collect_only:
        previous_lock = (workspace / "package-lock.json").read_bytes() if (workspace / "package-lock.json").exists() else None
        incoming_lock = (source / "package-lock.json").read_bytes()
        package = json.loads((source / "package.json").read_text())
        locked = json.loads(incoming_lock)["packages"][""]
        if any(package.get(name, {}) != locked.get(name, {}) for name in ("dependencies", "devDependencies")):
            raise RuntimeError("package.json dependencies do not match package-lock.json")
        for name in ("app", "desktop", "src", "src-tauri", "scripts", "public"):
            shutil.copytree(source / name, workspace / name, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target", "binaries", "__pycache__", ".DS_Store"))
        for name in ("Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "tsconfig.json", "vite.desktop.config.ts", "eslint.config.mjs", "next-env.d.ts", "postcss.config.mjs"):
            shutil.copy2(source / name, workspace / name)
        if previous_lock != incoming_lock or not (workspace / "node_modules" / "@tauri-apps" / "cli-linux-x64-gnu").is_dir():
            subprocess.run(["npm", "ci", "--no-audit", "--no-fund"], cwd=workspace, env=environment, check=True)
        subprocess.run(["npm", "run", "desktop:build", "--", "--bundles", "deb", "--ci", "--no-sign"], cwd=workspace, env=environment, check=True)
    destination = source / "outputs" / "linux"
    destination.mkdir(parents=True, exist_ok=True)
    target = Path(environment["CARGO_TARGET_DIR"])
    packages = list((target / "release" / "bundle" / "deb").glob("*.deb"))
    if not packages:
        raise RuntimeError("No Linux .deb found after build")
    for package in packages:
        shutil.copy2(package, destination / package.name)
        print(f"Linux package: {destination / package.name}")


if __name__ == "__main__":
    main()
