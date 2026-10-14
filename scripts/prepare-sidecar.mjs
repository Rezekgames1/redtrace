import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const host = execFileSync("rustc", ["-vV"], { encoding: "utf8" })
  .split("\n")
  .find((line) => line.startsWith("host: "))
  ?.slice(6);
const target = process.env.TAURI_ENV_TARGET_TRIPLE ?? process.argv[2] ?? host;
if (!target) throw new Error("could not determine Rust target triple");

const isWindows = target.includes("windows");
execFileSync("cargo", ["build", "--release", "--target", target], {
  cwd: projectRoot,
  stdio: "inherit",
});
const executable = `redtrace${isWindows ? ".exe" : ""}`;
const targetDirectory = resolve(projectRoot, process.env.CARGO_TARGET_DIR ?? "target");
const source = join(targetDirectory, target, "release", executable);
const destination = join(
  projectRoot,
  "src-tauri",
  "binaries",
  `redtrace-${target}${isWindows ? ".exe" : ""}`,
);
mkdirSync(dirname(destination), { recursive: true });
copyFileSync(source, destination);
for (const name of ["redtrace-agent", "redtrace-admin", "redtrace-service", "redtrace-service-agent"]) {
  copyFileSync(join(targetDirectory, target, "release", `${name}${isWindows ? ".exe" : ""}`), join(projectRoot, "src-tauri", "binaries", `${name}-${target}${isWindows ? ".exe" : ""}`));
}
if (target.includes("apple-darwin")) {
  execFileSync("node", ["scripts/build-es-helper.mjs", join(projectRoot, "src-tauri", "binaries", `redtrace-es-helper-${target}`)], { cwd: projectRoot, stdio: "inherit", env: { ...process.env, REDTRACE_ES_ARCH: target.startsWith("x86_64") ? "x86_64" : "arm64" } });
}
if (isWindows) {
  copyFileSync(
    join(targetDirectory, target, "release", "redtrace-audit-helper.exe"),
    join(projectRoot, "src-tauri", "binaries", `redtrace-audit-helper-${target}.exe`),
  );
  const helper = join(targetDirectory, target, "release", "redtrace-audit-helper.exe");
  writeFileSync(join(projectRoot, "src-tauri", "binaries", "audit-helper.sha256"), createHash("sha256").update(readFileSync(helper)).digest("hex"));
}
console.log(`Prepared RED//TRACE sidecar for ${target}`);
