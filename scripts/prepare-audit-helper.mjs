import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const target = execFileSync("rustc", ["-vV"], { encoding: "utf8" }).split("\n").find((line) => line.startsWith("host: "))?.slice(6).trim();
if (!target?.includes("windows")) throw new Error("Windows helper build requires a Windows host");
const runtime = join(root, "src-tauri", "target", "release");
if (!existsSync(runtime)) throw new Error("Build the desktop application first");
execFileSync("cargo", ["build", "--release", "--target", target, "--bin", "redtrace-audit-helper"], { cwd: root, stdio: "inherit" });
const source = join(root, "target", target, "release", "redtrace-audit-helper.exe");
copyFileSync(source, join(root, "src-tauri", "binaries", `redtrace-audit-helper-${target}.exe`));
copyFileSync(source, join(runtime, "redtrace-audit-helper.exe"));
writeFileSync(join(root, "src-tauri", "binaries", "audit-helper.sha256"), createHash("sha256").update(readFileSync(source)).digest("hex"));
console.log("Prepared audit helper and build digest");
