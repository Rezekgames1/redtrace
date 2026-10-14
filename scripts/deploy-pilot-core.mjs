import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants, copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

assert.equal(process.platform, "win32");
const root = fileURLToPath(new URL("../", import.meta.url));
const source = join(root, "target", "release", "redtrace.exe");
const destination = join(root, "src-tauri", "target", "release", "redtrace.exe");
const pilot = join(process.env.LOCALAPPDATA, "REDTRACE", "wsl-pilot");
assert.ok(existsSync(source) && existsSync(destination) && existsSync(pilot), "Build and configure the pilot first");
const quoted = destination.replaceAll("'", "''");
const running = execFileSync("powershell.exe", ["-NoProfile", "-Command", `@(Get-CimInstance Win32_Process -Filter "Name='redtrace.exe'" | Where-Object { $_.ExecutablePath -eq '${quoted}' }).Count`], { encoding: "utf8", windowsHide: true }).trim();
assert.equal(Number(running), 0, "Close the pilot before replacing its core");
const id = randomBytes(8).toString("hex");
const backup = join(pilot, `core-before-wal-fix-${id}`);
mkdirSync(backup);
copyFileSync(destination, join(backup, "redtrace.exe"), constants.COPYFILE_EXCL);
const temporary = join(dirname(destination), `.redtrace-update-${id}.exe`);
const digest = path => createHash("sha256").update(readFileSync(path)).digest("hex");
let copied = false;
try {
  copyFileSync(source, temporary, constants.COPYFILE_EXCL);
  copied = true;
  assert.equal(digest(source), digest(temporary));
  renameSync(temporary, destination);
  console.log(JSON.stringify({ result: "PASS", core_sha256: digest(destination), backup }));
} finally {
  if (copied) rmSync(temporary, { force: true });
}
