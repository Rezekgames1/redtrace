import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, resolve } from "node:path";

const project = process.cwd();
const output = join(project, "outputs", "beta-20261013");
mkdirSync(output, { recursive: true });
copyFileSync(join(project, "docs", "BETA_INSTALL.md"), join(output, "INSTALL.md"));
copyFileSync(join(project, "docs", "SERVICE_MODE.md"), join(output, "SERVICE_MODE.md"));
const installer = join(project, "src-tauri", "target", "release", "bundle", "nsis", "REDTRACE_0.1.0_x64-setup.exe");
if (existsSync(installer)) copyFileSync(installer, join(output, "REDTRACE-windows-beta-20261013-setup.exe"));
const linuxInstaller = resolve(process.env.LOCALAPPDATA, "Temp", "opencode", "redtrace-linux-target", "release", "bundle", "deb", "REDTRACE_0.1.0_amd64.deb");
if (existsSync(linuxInstaller)) copyFileSync(linuxInstaller, join(output, "REDTRACE-linux-x64-beta-20261013.deb"));
const platforms = [
  { name: "windows-x64", root: join(project, "target", "x86_64-pc-windows-msvc", "release"), suffix: ".exe", archive: "zip" },
  { name: "linux-x64", root: resolve(process.env.LOCALAPPDATA, "Temp", "opencode", "redtrace-linux-target", "release"), suffix: "", archive: "tar.gz" },
  { name: "macos-arm64", root: resolve(process.env.LOCALAPPDATA, "Temp", "opencode", "redtrace-macos-release"), suffix: "", archive: "tar.gz" },
];
for (const platform of platforms) {
  const names = ["redtrace", "redtrace-agent", "redtrace-service", "redtrace-service-agent"];
  if (!names.every((name) => existsSync(join(platform.root, name + platform.suffix)))) continue;
  const directory = join(output, platform.name);
  mkdirSync(directory, { recursive: true });
  for (const name of names) copyFileSync(join(platform.root, name + platform.suffix), join(directory, name + platform.suffix));
  copyFileSync(join(output, "INSTALL.md"), join(directory, "INSTALL.md"));
  copyFileSync(join(output, "SERVICE_MODE.md"), join(directory, "SERVICE_MODE.md"));
  const archive = join(output, `REDTRACE-${platform.name}-beta-20261013.${platform.archive}`);
  execFileSync("tar.exe", platform.archive === "zip" ? ["-a", "-cf", archive, "-C", directory, "."] : ["-czf", archive, "-C", directory, "."], { stdio: "inherit" });
}
const artifacts = readdirSync(output).filter((name) => /\.(exe|zip|gz|deb|dmg)$/.test(name)).map((name) => {
  const path = join(output, name);
  return { name, bytes: statSync(path).size, sha256: createHash("sha256").update(readFileSync(path)).digest("hex") };
});
const manifest = { release: "REDTRACE 0.1.0 early beta", build: "2026-10-13", artifacts };
writeFileSync(join(output, "manifest.json"), JSON.stringify(manifest, null, 2));
console.log(JSON.stringify(manifest, null, 2));
