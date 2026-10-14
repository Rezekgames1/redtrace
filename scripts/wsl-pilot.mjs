import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import net from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const project = fileURLToPath(new URL("../", import.meta.url));
const root = join(process.env.LOCALAPPDATA ?? "", "REDTRACE", "wsl-pilot");
const statePath = join(root, "deployment.json");
const desktop = state().desktop_path ?? join(project, "src-tauri", "target", "release", "redtrace-desktop.exe");
const sidecar = join(dirname(desktop), "redtrace.exe");
const distribution = "kali-linux";
const helper = linuxPath(join(project, "scripts", "wsl-pilot-agent.py"));
const binary = linuxPath(resolve(process.env.REDTRACE_WSL_AGENT_BINARY ?? join(process.env.LOCALAPPDATA ?? "", "Temp", "opencode", "redtrace-linux-target", "release", "redtrace-agent")));
const wait = milliseconds => new Promise(resolvePromise => setTimeout(resolvePromise, milliseconds));

function linuxPath(path) {
  return execFileSync("wsl.exe", ["-d", distribution, "--exec", "wslpath", "-u", path], { encoding: "utf8", windowsHide: true }).trim();
}

function wsl(action, payload = {}) {
  return JSON.parse(execFileSync("wsl.exe", ["-d", distribution, "--exec", "python3", helper, action], {
    input: JSON.stringify(payload), encoding: "utf8", windowsHide: true, timeout: 45000, maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"],
  }));
}

function state() {
  return existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : {};
}

function save(value) {
  const temporary = `${statePath}.tmp`;
  writeFileSync(temporary, JSON.stringify(value, null, 2), { mode: 0o600 });
  renameSync(temporary, statePath);
}

function powershell(expression, args = []) {
  return execFileSync("powershell.exe", ["-NoProfile", "-Command", expression, ...args], { encoding: "utf8", windowsHide: true, timeout: 20000 }).trim();
}

function processInfo(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  const result = powershell(`$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${pid}'; if($p){ @{pid=$p.ProcessId; parent=$p.ParentProcessId; path=$p.ExecutablePath; created=$p.CreationDate.ToString('o')} | ConvertTo-Json -Compress }`);
  return result ? JSON.parse(result) : null;
}

async function freePort(port, host) {
  await new Promise((resolvePromise, reject) => {
    const probe = net.createServer();
    probe.once("error", () => reject(new Error(`${host}:${port} is occupied; preserve the existing listener`)));
    probe.listen(port, host, () => probe.close(resolvePromise));
  });
}

async function retry(operation, attempts = 80) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const value = await operation();
      if (value) return value;
    } catch {
      if (attempt === attempts - 1) throw new Error("Pilot readiness check timed out; inspect the local pilot logs");
    }
    await wait(250);
  }
  throw new Error("Pilot readiness check timed out; inspect the local pilot logs");
}

function initialize() {
  if (!existsSync(root)) {
    mkdirSync(root);
    const sid = powershell("[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value");
    execFileSync("icacls.exe", [root, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`, "*S-1-5-18:(OI)(CI)F"], { stdio: "pipe", windowsHide: true });
  }
}

async function startDesktop(gateway, debug = false) {
  if (state().ui_mode === "vite-dev") await frontend();
  await freePort(9710, "127.0.0.1");
  await freePort(9711, gateway);
  if (debug) await freePort(9225, "127.0.0.1");
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.startsWith("REDTRACE_") || key === "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") delete environment[key];
  }
  Object.assign(environment, {
    REDTRACE_DATA_DIR: join(process.env.LOCALAPPDATA, "REDTRACE"),
    REDTRACE_INGEST_BIND: `${gateway}:9711`,
    REDTRACE_INGEST_CERT: join(root, "server.pem"),
    REDTRACE_INGEST_KEY: join(root, "server.key"),
    REDTRACE_LOOKBACK: "15m",
  });
  if (debug) environment.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9225";
  const output = openSync(join(root, "desktop.log"), "a");
  const child = spawn(desktop, [], { env: environment, detached: true, stdio: ["ignore", output, output], windowsHide: false });
  closeSync(output);
  await new Promise((resolvePromise, reject) => { child.once("spawn", resolvePromise); child.once("error", reject); });
  child.unref();
  const identity = await retry(() => processInfo(child.pid));
  save({ ...state(), desktop: identity, gateway, debug });
  await retry(async () => (await fetch("http://127.0.0.1:9710/api/health", { signal: AbortSignal.timeout(2000) })).status === 401, 1200);
  const owner = Number(powershell("(Get-NetTCPConnection -LocalPort 9710 -State Listen -ErrorAction Stop).OwningProcess"));
  const core = processInfo(owner);
  assert.equal(core?.parent, child.pid, "API listener is not the desktop-owned sidecar");
  assert.equal(core?.path?.toLowerCase(), sidecar.toLowerCase(), "Unexpected core executable");
  await retry(() => wsl("health", { gateway }).status === "ok");
  return identity;
}

async function stopDesktop() {
  const saved = state().desktop;
  if (!saved) return;
  const current = processInfo(saved.pid);
  if (!current) return;
  assert.equal(current.path?.toLowerCase(), desktop.toLowerCase(), "Refusing to close an unknown process");
  assert.equal(current.created, saved.created, "Refusing to close a reused PID");
  powershell(`$p=Get-Process -Id ${saved.pid} -ErrorAction Stop; if(-not $p.CloseMainWindow()){throw 'No application window to close'}; if(-not $p.WaitForExit(10000)){throw 'Application shutdown timed out'}`);
  await retry(async () => {
    try { await freePort(9710, "127.0.0.1"); return true; } catch { return false; }
  });
  save({ ...state(), desktop: null, debug: false });
}

async function connectGui() {
  const target = await retry(async () => {
    const targets = await (await fetch("http://127.0.0.1:9225/json", { signal: AbortSignal.timeout(2000) })).json();
    return targets.find(candidate => candidate.type === "page" && (candidate.url.includes("tauri") || candidate.url.startsWith("http://127.0.0.1:1420")));
  });
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolvePromise, reject) => { socket.onopen = resolvePromise; socket.onerror = reject; });
  let sequence = 0;
  const pending = new Map();
  socket.onmessage = ({ data }) => {
    const response = JSON.parse(data);
    if (!response.id) return;
    const entry = pending.get(response.id);
    if (!entry) return;
    pending.delete(response.id);
    clearTimeout(entry.timeout);
    if (response.error) entry.reject(new Error(response.error.message));
    else entry.resolve(response.result);
  };
  const command = (method, params = {}) => new Promise((resolvePromise, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error("GUI command timed out")); }, 10000);
    pending.set(id, { resolve: resolvePromise, reject, timeout });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async expression => {
    const response = await command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    assert.ok(!response.exceptionDetails, "GUI evaluation failed");
    return response.result.value;
  };
  await retry(() => evaluate("Boolean(window.__TAURI_INTERNALS__)"));
  const token = await evaluate("window.__TAURI_INTERNALS__.invoke('api_token')");
  const api = async (path, method = "GET", body = undefined) => {
    const response = await fetch(`http://127.0.0.1:9710${path}`, {
      method, headers: { "x-redtrace-token": token, "Content-Type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000),
    });
    assert.ok(response.ok, `API ${path.split("?")[0]} returned ${response.status}`);
    return response.json();
  };
  return { command, evaluate, api, close: () => socket.close() };
}

async function startAgent() {
  const previous = state().keeper;
  const current = processInfo(previous?.pid);
  if (current && current.created === previous.created && current.path?.toLowerCase().endsWith("\\wsl.exe")) {
    return wsl("start");
  }
  const output = openSync(join(root, "keeper.log"), "a");
  const child = spawn("wsl.exe", ["-d", distribution, "--exec", "python3", helper, "hold"], {
    detached: true, stdio: ["ignore", output, output], windowsHide: true,
  });
  closeSync(output);
  await new Promise((resolvePromise, reject) => { child.once("spawn", resolvePromise); child.once("error", reject); });
  child.unref();
  const identity = await retry(() => processInfo(child.pid));
  save({ ...state(), keeper: identity });
  return retry(() => { const agent = wsl("status"); return agent.pid && agent; });
}

async function showKali(gui, agentId) {
  await gui.evaluate("document.querySelector('button[title=\"События\"]')?.click()");
  await retry(() => gui.evaluate("Boolean(document.querySelector('.runButton'))"));
  await gui.evaluate("Array.from(document.querySelectorAll('.filterRow button')).find(button=>button.textContent.includes('Добавить фильтр')).click()");
  for (const [selector, text] of [["input[aria-label='Поле фильтра']", "agent.id"], ["input[aria-label='Значение фильтра']", agentId]]) {
    await gui.evaluate(`document.querySelector(${JSON.stringify(selector)}).focus(); document.querySelector(${JSON.stringify(selector)}).select()`);
    await gui.command("Input.insertText", { text });
  }
  await gui.evaluate("document.querySelector('.filterBuilder button[type=submit]').click()");
  await retry(() => gui.evaluate(`document.querySelector('input[aria-label="Поисковый запрос"]')?.value.includes('agent.id')`), 160);
  await retry(() => gui.evaluate(`(() => { const cells = Array.from(document.querySelectorAll('.eventRow .sourceCell')); return cells.length > 0 && cells.every(element => element.textContent.startsWith("linux.")); })()`), 160);
  const rows = await gui.evaluate("Array.from(document.querySelectorAll('.eventRow .sourceCell')).map(element=>element.textContent)");
  assert.ok(rows.every(source => source.startsWith("linux.")), "Non-Linux events in the agent-filtered GUI");
  return rows.length;
}

async function verify(gui, gateway, agentId) {
  const query = `agent.id="${agentId}"`;
  const search = value => gui.api(`/api/search?${new URLSearchParams({ q: value, limit: "100" })}`);
  await retry(async () => {
    const agents = (await gui.api("/api/agents")).agents;
    return agents.some(agent => agent.id === agentId && agent.platform === "linux" && agent.events_received > 0);
  }, 240);
  const remote = await retry(async () => { const result = await search(query); return result.total > 0 && result; }, 120);
  const first = remote.events[0];
  assert.equal(first.fields["agent.id"], agentId);
  assert.equal(first.fields["host.name"], "kali-wsl");
  assert.ok(first.source.startsWith("linux."));
  assert.ok(first.fields["event.record_id"]);
  const rows = await showKali(gui, agentId);
  const { marker } = wsl("marker");
  const started = Date.now();
  const live = await retry(async () => { const result = await search(`${query} AND message="${marker}"`); return result.total === 1 && result; }, 120);
  await retry(() => gui.evaluate(`Array.from(document.querySelectorAll('.eventRow')).some(row=>row.textContent.includes(${JSON.stringify(marker)}))`), 120);
  const latency = Date.now() - started;
  const health = await gui.api("/api/health");
  assert.equal(health.ingestion.wal_errors, 0);
  assert.equal(health.ingestion.checkpoint_errors, 0);
  const tls = wsl("health", { gateway, negative_checks: true });
  assert.equal(tls.untrusted_ca, "rejected");
  assert.equal(tls.wrong_san, "rejected");
  assert.equal(tls.invalid_token, "rejected");
  assert.equal(tls.authenticated_heartbeat, 200);
  const agent = wsl("status");
  assert.equal(agent.checkpoint_exists, true);
  assert.equal(agent.credential_mode, "0o600");
  return { agent_id: agentId, remote_events: remote.total, linux_ui_rows: rows, marker_uid: live.events[0].uid, live_latency_ms: latency, total_indexed: health.events_indexed, wal_errors: health.ingestion.wal_errors, agent, tls };
}

async function setup(resume = false) {
  assert.ok(resume || !processInfo(state().desktop?.pid), "Close the running pilot with the stop command before setup");
  initialize();
  const network = wsl("network");
  if (!resume) {
    const credentials = wsl("pki", network);
    writeFileSync(join(root, "server.pem"), credentials.certificate, { mode: 0o600 });
    writeFileSync(join(root, "server.key"), credentials.key, { mode: 0o600 });
    writeFileSync(join(root, "ca.pem"), credentials.ca, { mode: 0o600 });
  } else {
    const current = processInfo(state().desktop?.pid);
    assert.equal(current?.path?.toLowerCase(), desktop.toLowerCase());
    assert.equal(current?.created, state().desktop.created);
    assert.equal(state().debug, true);
  }
  wsl("stop");
  if (!resume) await startDesktop(network.gateway, true);
  const gui = await connectGui();
  try {
    let agentId = state().agent_id;
    const existing = (await gui.api("/api/agents")).agents.find(agent => agent.id === agentId && !agent.revoked);
    let enrollment;
    if (!existing) {
      enrollment = await gui.api("/api/agents", "POST", { name: "kali-wsl" });
      agentId = enrollment.id;
    }
    wsl("configure", { ...network, agent_id: agentId, binary, ...(enrollment ? { token: enrollment.token } : {}) });
    save({ ...state(), agent_id: agentId, distribution, project });
    await startAgent();
    const report = await verify(gui, network.gateway, agentId);
    const snapshot = await gui.command("Page.captureScreenshot", { format: "png" });
    const outputs = join(project, "outputs", "wsl-pilot");
    mkdirSync(outputs, { recursive: true });
    writeFileSync(join(outputs, "kali-on-windows.png"), Buffer.from(snapshot.data, "base64"));
    report.final_remote_events = (await gui.api(`/api/search?${new URLSearchParams({ q: `agent.id="${agentId}"`, limit: "1" })}`)).total;
    report.created_at = new Date().toISOString();
    gui.close();
    await stopDesktop();
    await startDesktop(network.gateway, false);
    await retry(() => wsl("health", network).status === "ok");
    report.final_desktop = state().desktop;
    writeFileSync(join(outputs, "report.json"), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
  } catch (error) {
    try {
      const health = await gui.api("/api/health");
      console.error(JSON.stringify({ ingestion: health.ingestion, remote_ingest: health.remote_ingest, source: health.source }));
    } catch {
      console.error("Authenticated health diagnostics unavailable");
    }
    throw error;
  } finally {
    gui.close();
    if (state().debug) await stopDesktop();
  }
}

async function start() {
  assert.ok(state().agent_id, "Run setup first");
  const network = wsl("network");
  assert.equal(network.gateway, state().gateway, "WSL gateway changed; run setup to renew the SAN/config");
  const current = processInfo(state().desktop?.pid);
  if (current) {
    assert.equal(current.path?.toLowerCase(), desktop.toLowerCase());
    assert.equal(current.created, state().desktop.created);
  } else {
    await startDesktop(network.gateway, false);
  }
  await startAgent();
  await status();
}

async function frontend() {
  const previous = state().frontend;
  const current = processInfo(previous?.pid);
  if (current && current.created === previous.created && current.path?.toLowerCase().endsWith("\\node.exe")) {
    save({ ...state(), ui_mode: "vite-dev" });
    console.log("GUI dev server is already running at http://127.0.0.1:1420");
    return;
  }
  await freePort(1420, "127.0.0.1");
  const output = openSync(join(root, "frontend.log"), "a");
  const child = spawn(process.execPath, [join(project, "node_modules", "vite", "bin", "vite.js"), "--config", join(project, "vite.desktop.config.ts"), "--host", "127.0.0.1", "--port", "1420", "--strictPort"], {
    cwd: project, detached: true, stdio: ["ignore", output, output], windowsHide: true,
  });
  closeSync(output);
  await new Promise((resolvePromise, reject) => { child.once("spawn", resolvePromise); child.once("error", reject); });
  child.unref();
  save({ ...state(), ui_mode: "vite-dev", frontend: await retry(() => processInfo(child.pid)) });
  await retry(async () => (await fetch("http://127.0.0.1:1420", { signal: AbortSignal.timeout(2000) })).ok);
  console.log("GUI dev server is running at http://127.0.0.1:1420");
}

async function status() {
  const saved = state();
  const current = processInfo(saved.desktop?.pid);
  const agent = wsl("status");
  let tls = null;
  if (saved.gateway && current) tls = wsl("health", { gateway: saved.gateway });
  const registryPath = join(process.env.LOCALAPPDATA, "REDTRACE", "agents.json");
  const registry = existsSync(registryPath) ? JSON.parse(readFileSync(registryPath, "utf8")) : { agents: [] };
  const record = registry.agents.find(candidate => candidate.id === saved.agent_id);
  console.log(JSON.stringify({ desktop: current, keeper: processInfo(saved.keeper?.pid), debugging_enabled: saved.debug ?? false, agent, ingest: tls, server_agent: record ? { id: record.id, name: record.name, platform: record.platform, events_received: record.events_received, last_seen_unix: record.last_seen_unix, revoked: record.revoked } : null }, null, 2));
}

assert.equal(process.platform, "win32", "Run this launcher on Windows");
assert.ok(process.env.LOCALAPPDATA, "LOCALAPPDATA is required");
const action = process.argv[2] ?? "status";
try {
  if (action === "setup") await setup();
  else if (action === "resume") await setup(true);
  else if (action === "start") await start();
  else if (action === "frontend") await frontend();
  else if (action === "stop") { console.log(JSON.stringify(wsl("stop"))); await stopDesktop(); }
  else if (action === "close-window") await stopDesktop();
  else if (action === "use-installed") {
    assert.ok(!processInfo(state().desktop?.pid), "Close the pilot window first");
    const installed = join(process.env.ProgramW6432 ?? process.env.ProgramFiles, "REDTRACE", "redtrace-desktop.exe");
    assert.ok(existsSync(installed), "Administrative installation is missing");
    save({ ...state(), desktop_path: installed, desktop: null, ui_mode: "embedded" });
    console.log("Pilot now uses the installed desktop");
  }
  else if (action === "status") await status();
  else throw new Error("Use setup, resume, start, frontend, status, stop, close-window or use-installed");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
