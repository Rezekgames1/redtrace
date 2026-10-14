import { spawnSync } from "node:child_process";

const binary = process.argv[2];
if (!binary) throw new Error("Sysmon64.exe path required");
const result = spawnSync(binary, ["-accepteula", "-s", ...process.argv.slice(3)], { encoding: "buffer", maxBuffer: 1024 * 1024 });
const buffers = [result.stdout, result.stderr].filter(Boolean);
for (const buffer of buffers) {
  const text = buffer.toString("utf8").replaceAll("\0", "");
  for (const line of text.split(/\r?\n/)) {
    if (/schemaversion|Sysmon|HashAlgorithms|CheckRevocation|DnsLookup|Root|RuleGroup|IMPHASH/i.test(line)) console.log(line);
  }
}
if (result.error) throw result.error;
process.exit(result.status ?? 1);
