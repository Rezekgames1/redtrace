import assert from "node:assert/strict";
import { copyFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const source = join(root, "target", "x86_64-pc-windows-msvc", "release", "redtrace.exe");
const staged = join(root, "src-tauri", "binaries", "redtrace-x86_64-pc-windows-msvc.exe");
const runtime = join(root, "src-tauri", "target", "release", "redtrace.exe");
assert.equal(process.platform, "win32");
assert.ok(existsSync(source) && existsSync(staged) && existsSync(runtime));
copyFileSync(source, staged);
copyFileSync(source, runtime);
console.log("Staged validated core for Windows bundle");
