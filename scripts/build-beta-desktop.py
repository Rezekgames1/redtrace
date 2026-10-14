import argparse
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys


def execute(arguments, directory, environment):
    subprocess.run(arguments, cwd=directory, env=environment, check=True)


def prepare(source, workspace, core, triple):
    if not workspace.parent.is_dir() or not core.is_file():
        raise RuntimeError("Existing workspace parent and built core are required")
    if source != workspace:
        workspace.mkdir(exist_ok=True)
        for name in ("src", "src-tauri", "desktop-dist"):
            shutil.copytree(source / name, workspace / name, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target", "binaries", "__pycache__", ".DS_Store"))
        for name in ("Cargo.toml", "Cargo.lock", "package.json"):
            shutil.copy2(source / name, workspace / name)
    if not (workspace / "desktop-dist/index.html").is_file():
        raise RuntimeError("Embedded frontend has not been built")
    binaries = workspace / "src-tauri/binaries"
    binaries.mkdir(exist_ok=True)
    sidecar = binaries / f"redtrace-{triple}"
    shutil.copy2(core, sidecar)
    sidecar.chmod(0o755)


def linux(arguments, environment):
    prepare(arguments.source, arguments.workspace, arguments.core, "x86_64-unknown-linux-gnu")
    cli = arguments.workspace / "node_modules/@tauri-apps/cli/tauri.js"
    if not cli.is_file():
        raise RuntimeError("Native Linux Tauri CLI missing; use npm ci in the isolated workspace")
    environment["CARGO_TARGET_DIR"] = str(arguments.target)
    execute(["node", str(cli), "build", "--bundles", "deb", "--ci", "--no-sign", "--config", "src-tauri/tauri.beta-bundle.conf.json"], arguments.workspace, environment)
    print("Linux GUI packages: " + str(arguments.target / "release/bundle/deb"))


def macos(arguments, environment):
    prepare(arguments.source, arguments.workspace, arguments.core, "aarch64-apple-darwin")
    environment["CARGO_TARGET_DIR"] = str(arguments.target)
    environment["TAURI_CONFIG"] = (arguments.workspace / "src-tauri/tauri.beta-bundle.conf.json").read_text()
    execute(["cargo", "build", "--release", "--manifest-path", "src-tauri/Cargo.toml", "--features", "tauri/custom-protocol"], arguments.workspace, environment)
    output = arguments.workspace / "beta-desktop-output"
    output.mkdir(exist_ok=True)
    stage = output / "dmg-stage"
    stage.mkdir(exist_ok=True)
    app = stage / "REDTRACE.app"
    mac = app / "Contents/MacOS"
    resources = app / "Contents/Resources"
    mac.mkdir(parents=True, exist_ok=True)
    resources.mkdir(parents=True, exist_ok=True)
    for name, source in (("redtrace-desktop", arguments.target / "release/redtrace-desktop"), ("redtrace", arguments.core)):
        shutil.copy2(source, mac / name)
        (mac / name).chmod(0o755)
    shutil.copy2(arguments.workspace / "src-tauri/icons/icon.icns", resources / "icon.icns")
    info = {
        "CFBundleDevelopmentRegion": "en", "CFBundleDisplayName": "REDTRACE", "CFBundleExecutable": "redtrace-desktop",
        "CFBundleIconFile": "icon.icns", "CFBundleIdentifier": "com.redlabs.redtrace", "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "REDTRACE", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "20261013",
        "LSApplicationCategoryType": "public.app-category.developer-tools", "LSMinimumSystemVersion": "13.0",
        "NSHighResolutionCapable": True, "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True, "NSAllowsArbitraryLoads": True},
    }
    with (app / "Contents/Info.plist").open("wb") as file:
        plistlib.dump(info, file)
    execute(["codesign", "--force", "--sign", "-", str(mac / "redtrace")], output, environment)
    execute(["codesign", "--force", "--deep", "--sign", "-", str(app)], output, environment)
    execute(["codesign", "--verify", "--deep", "--strict", str(app)], output, environment)
    applications = stage / "Applications"
    if not applications.exists() and not applications.is_symlink():
        applications.symlink_to("/Applications")
    dmg = output / "REDTRACE-macos-arm64-beta-20261013.dmg"
    execute(["hdiutil", "create", "-volname", "REDTRACE Early Beta", "-srcfolder", str(stage), "-ov", "-format", "UDZO", str(dmg)], output, environment)
    print("macOS GUI DMG: " + str(dmg))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", choices=["linux", "macos"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    arguments = parser.parse_args()
    for name in ("source", "workspace", "core", "target"):
        setattr(arguments, name, getattr(arguments, name).resolve())
    environment = dict(os.environ)
    environment["PATH"] = str(Path.home() / ".cargo/bin") + ":/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    environment.pop("TAURI_CONFIG", None)
    (linux if arguments.platform == "linux" else macos)(arguments, environment)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Desktop package build failed: {error}", file=sys.stderr)
        sys.exit(1)
