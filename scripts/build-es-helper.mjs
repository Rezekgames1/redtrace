import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
if (process.platform !== "darwin") throw new Error("Endpoint Security helper builds on macOS only");
const output = resolve(process.argv[2] ?? "target/debug/redtrace-es-helper");
mkdirSync(dirname(output), { recursive: true });
const result = spawnSync("xcrun", ["clang", ...(process.env.REDTRACE_ES_ARCH ? ["-arch", process.env.REDTRACE_ES_ARCH] : []), "-O2", "-Wall", "-Wextra", "-Werror", "-fblocks", "-mmacosx-version-min=13.0", "native/macos/es-helper.c", "-lEndpointSecurity", "-lbsm", "-o", output], { stdio: "inherit" });
if (result.status !== 0) process.exit(result.status ?? 1);
if (process.env.REDTRACE_ES_SIGN_IDENTITY) {
  const signed = spawnSync("codesign", ["--force", "--options", "runtime", "--entitlements", "native/macos/endpoint-security.entitlements.plist", "--sign", process.env.REDTRACE_ES_SIGN_IDENTITY, output], { stdio: "inherit" });
  if (signed.status !== 0) process.exit(signed.status ?? 1);
}
console.log(output);
