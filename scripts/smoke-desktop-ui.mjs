import assert from "node:assert/strict";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { closeSync, mkdirSync, mkdtempSync, openSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const binaryIndex = process.argv.indexOf("--binary");
const desktopBinary = binaryIndex >= 0 ? process.argv[binaryIndex + 1] : join(root, "src-tauri/target/release/redtrace-desktop.exe");
const recoverLatest = process.argv.includes("--recover-latest");
const auditAll = process.argv.includes("--audit-all");
const auditUi = process.argv.includes("--audit-ui");
const sysmonArgument = process.argv.indexOf("--sysmon-leave");
const sysmonPath = sysmonArgument >= 0 ? process.argv[sysmonArgument + 1] : null;
const grantLogRead = process.argv.includes("--grant-log-read");
const testReadRollback = process.argv.includes("--test-read-rollback");
const inspectLive = process.argv.includes("--inspect-live");
const keepOpen = process.argv.includes("--keep-open");
const screenshotIndex = process.argv.indexOf("--screenshot");
const screenshotPath = screenshotIndex >= 0 ? process.argv[screenshotIndex + 1] : null;
const soakIndex = process.argv.indexOf("--soak-seconds");
const soakSeconds = soakIndex >= 0 ? Number(process.argv[soakIndex + 1]) : 0;
const auditTest = process.argv.includes("--audit") || auditAll || auditUi || recoverLatest || Boolean(sysmonPath) || grantLogRead || testReadRollback;
const portCheck = spawnSync("powershell.exe", ["-NoProfile", "-Command", `if (Get-NetTCPConnection -LocalPort 9710,9225${soakSeconds ? ",9711" : ""} -State Listen -ErrorAction SilentlyContinue) { exit 7 }`], { stdio: "ignore", windowsHide: true });
assert.equal(portCheck.status, 0, "required ports are occupied; close the existing application before testing");
const directory = mkdtempSync(join(tmpdir(), "redtrace-ui-"));
const desktopEnvironment = { ...process.env, ...(inspectLive ? {} : { REDTRACE_DATA_DIR: directory }), ...((process.argv.includes("--live-ui") || soakSeconds) ? { REDTRACE_LOOKBACK: "1m" } : {}), WEBVIEW2_USER_DATA_FOLDER: join(directory, "webview-profile"), WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: "--remote-debugging-port=9225" };
delete desktopEnvironment.REDTRACE_AUDIT_DEV;
if (auditTest) {
  desktopEnvironment.REDTRACE_LOOKBACK = "1m";
  delete desktopEnvironment.REDTRACE_INGEST_BIND;
  delete desktopEnvironment.REDTRACE_INGEST_CERT;
  delete desktopEnvironment.REDTRACE_INGEST_KEY;
}
if (soakSeconds) { Object.assign(desktopEnvironment, { REDTRACE_INGEST_BIND: "127.0.0.1:9711", REDTRACE_SEGMENT_MB: "1", REDTRACE_MAX_STORAGE_MB: "128" }); delete desktopEnvironment.REDTRACE_INGEST_CERT; delete desktopEnvironment.REDTRACE_INGEST_KEY; }
let desktopLog;
if (auditTest) {
  mkdirSync(join(root, "outputs", "windows-admin"), { recursive: true });
  desktopLog = openSync(join(root, "outputs", "windows-admin", "desktop.log"), "a");
}
const processHandle = spawn(desktopBinary, [], {
  env: desktopEnvironment,
  stdio: desktopLog === undefined ? "ignore" : ["ignore", desktopLog, desktopLog],
});
if (desktopLog !== undefined) closeSync(desktopLog);
let socket;
let auditRecovery;
const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
try {
  let target;
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      const response = await fetch("http://127.0.0.1:9225/json");
      const targets = await response.json();
      target = targets.find((candidate) => candidate.type === "page" && candidate.url.includes("tauri"));
      if (target) break;
    } catch { await wait(250); }
    await wait(250);
  }
  assert.ok(target, "WebView debug target unavailable");
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let sequence = 0;
  let searchRequests = 0;
  const pending = new Map();
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === "Network.requestWillBeSent" && message.params?.request?.url?.startsWith("http://127.0.0.1:9710/api/search?")) searchRequests += 1;
    if (!message.id) return;
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
  };
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (expression) => {
    const result = await command("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) throw new Error(String(result.exceptionDetails.exception?.value ?? result.exceptionDetails.exception?.description ?? result.exceptionDetails.text));
    return result.result.value;
  };
  if (soakSeconds) {
    await wait(2000);
    const { runDesktopSoak } = await import("./soak-desktop.mjs");
    await runDesktopSoak({ command, evaluate, wait, pid: processHandle.pid, duration: soakSeconds, output: join(root, "outputs", soakSeconds <= 600 ? "soak-short" : "soak") });
  } else if (screenshotPath) {
    const viewport = process.argv.indexOf("--viewport");
    if (viewport >= 0) await command("Emulation.setDeviceMetricsOverride", { width: Number(process.argv[viewport + 1]), height: 850, deviceScaleFactor: 1, mobile: false });
    const workspaceIndex = process.argv.indexOf("--workspace");
    if (workspaceIndex >= 0) {
      const selector = `button[title="${process.argv[workspaceIndex + 1]}"]`;
      for (let attempt = 0; attempt < 50; attempt++) {
        if (await evaluate(`Boolean(document.querySelector(${JSON.stringify(selector)}))`)) break;
        await wait(100);
      }
      await evaluate(`document.querySelector(${JSON.stringify(selector)}).click()`);
    }
    await wait(3000);
    const layout = await evaluate("({viewport:innerWidth, documentWidth:document.documentElement.scrollWidth, rows:document.querySelectorAll('.eventRow').length, fieldsVisible:getComputedStyle(document.querySelector('.fieldsPane') ?? document.body).display !== 'none', horizontalScroll:document.querySelector('.eventStream') ? document.querySelector('.eventStream').scrollWidth > document.querySelector('.eventStream').clientWidth : false})");
    assert.ok(layout.documentWidth <= layout.viewport, "GUI overflows viewport horizontally");
    if (workspaceIndex < 0) assert.equal(layout.horizontalScroll, false, "event list requires horizontal scroll in default layout");
    const screenshot = await command("Page.captureScreenshot", { format: "png" });
    writeFileSync(screenshotPath, Buffer.from(screenshot.data, "base64"));
    writeFileSync(`${screenshotPath}.json`, JSON.stringify(layout, null, 2));
    console.log(`Screenshot: ${screenshotPath}; real event rows=${await evaluate("document.querySelectorAll('.eventRow').length")}`);
  } else if (inspectLive) {
    await wait(1500);
    const details = await evaluate("(async () => { const token = await window.__TAURI_INTERNALS__.invoke('api_token'); const headers = {'x-redtrace-token':token}; const health = await (await fetch('http://127.0.0.1:9710/api/health',{headers})).json(); const result = await (await fetch('http://127.0.0.1:9710/api/search?q=*&limit=100',{headers})).json(); return {health, search:{total:result.total,events:result.events?.length,error:result.error}, ui:{body:document.body.innerText.slice(0,2400), rows:document.querySelectorAll('.eventRow').length, empty:document.querySelector('.emptyState')?.innerText ?? ''}}; })()");
    console.log(JSON.stringify(details, null, 2));
  } else {
  await wait(1500);
  if (process.argv.includes("--preferences")) {
    const { checkPreferences } = await import("./preferences-desktop.mjs");
    await checkPreferences({ command, evaluate, wait });
    await evaluate("document.querySelector('.queryInput input').focus(); document.querySelector('.queryInput input').select()");
    await command("Input.insertText", { text: "*" });
    await evaluate("document.querySelector('.runButton').click()");
    await wait(500);
  }
  if (process.argv.includes("--live-ui")) {
    assert.equal(await evaluate("(async () => { const response = await fetch('http://127.0.0.1:9710/api/live'); const status = response.status; await response.body?.cancel(); return status; })()"), 401);
    assert.equal(await evaluate("getComputedStyle(document.querySelector('.fieldsPane')).display"), "none");
    assert.equal(await evaluate("getComputedStyle(document.querySelector('.detailsPane')).display"), "none");
    assert.equal(await evaluate("document.querySelector('.histogramPanel') === null"), true);
    assert.equal(await evaluate("document.body.innerText.includes('Обновить логи')"), false);
    for (let attempt = 0; attempt < 160; attempt++) {
      if (await evaluate("document.querySelector('.liveStatus')?.textContent === 'LIVE'")) break;
      await wait(250);
    }
    assert.equal(await evaluate("document.querySelector('.liveStatus')?.textContent"), "LIVE");
    const marker = `REDTRACE-LIVE-${process.pid}-${Date.now()}`;
    await evaluate("document.querySelector('input[aria-label=\"Поисковый запрос\"]').focus(); document.querySelector('input[aria-label=\"Поисковый запрос\"]').select()");
    await command("Input.insertText", { text: marker });
    await evaluate("document.querySelector('.runButton').click()");
    await wait(750);
    assert.equal(await evaluate("document.querySelectorAll('.eventRow').length"), 0);
    const probe = () => new Promise((resolve, reject) => {
      const child = spawn("cmd.exe", ["/c", "echo", marker], { stdio: "ignore" });
      child.on("error", reject);
      child.on("exit", resolve);
    });
    const started = Date.now();
    await probe();
    let captured = false;
    for (let attempt = 0; attempt < 80; attempt++) {
      captured = await evaluate(`Array.from(document.querySelectorAll('.eventRow')).some(row => row.textContent.includes(${JSON.stringify(marker)}))`);
      if (captured) break;
      await wait(100);
    }
    if (!captured) console.log(await evaluate(`(async () => { const token = await window.__TAURI_INTERNALS__.invoke('api_token'); const headers={'x-redtrace-token':token}; const result = await (await fetch('http://127.0.0.1:9710/api/search?q=' + encodeURIComponent(${JSON.stringify(JSON.stringify(marker))}), {headers})).json(); const health = await (await fetch('http://127.0.0.1:9710/api/health',{headers})).json(); return {matches:result.total, rows:document.querySelectorAll('.eventRow').length, live:document.querySelector('.liveStatus')?.textContent, source:health.source, ingestion:health.ingestion, banner:document.querySelector('.liveNotice')?.textContent, query:document.querySelector('.queryInput input')?.value}; })()`));
    assert.ok(captured, "native live event did not appear automatically");
    const latency = Date.now() - started;
    await evaluate("document.querySelector('.eventRow').click()");
    const selectedUid = await evaluate("document.querySelector('.detailsPane .paneHeader small').textContent");
    await evaluate("document.querySelector('.liveToggle').click()");
    const before = await evaluate("document.querySelectorAll('.eventRow').length");
    await probe();
    await wait(3000);
    assert.equal(await evaluate("document.querySelectorAll('.eventRow').length"), before, "paused list changed");
    assert.equal(await evaluate("document.querySelector('.detailsPane .paneHeader small').textContent"), selectedUid);
    await evaluate("document.querySelector('.liveToggle').click()");
    for (let attempt = 0; attempt < 60; attempt++) {
      if (await evaluate(`document.querySelectorAll('.eventRow').length > ${before}`)) break;
      await wait(100);
    }
    const resumed = await evaluate(`document.querySelectorAll('.eventRow').length > ${before}`);
    if (!resumed) console.log(await evaluate(`(async () => { const token = await window.__TAURI_INTERNALS__.invoke('api_token'); const result = await (await fetch('http://127.0.0.1:9710/api/search?q=' + encodeURIComponent(${JSON.stringify(JSON.stringify(marker))}), {headers:{'x-redtrace-token':token}})).json(); return {matches:result.total, rows:document.querySelectorAll('.eventRow').length, before:${before}, live:document.querySelector('.liveStatus')?.textContent, banner:document.querySelector('.liveNotice')?.textContent, query:document.querySelector('.queryInput input')?.value}; })()`));
    assert.ok(resumed, "resume did not catch up");
    assert.equal(await evaluate("document.querySelector('.detailsPane .paneHeader small').textContent"), selectedUid, "live updates replaced inspected event");
    const beforeOffline = await evaluate("document.querySelectorAll('.eventRow').length");
    await command("Network.enable");
    await command("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    await probe();
    await wait(2000);
    await command("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    for (let attempt = 0; attempt < 100; attempt++) {
      if (await evaluate(`document.querySelectorAll('.eventRow').length > ${beforeOffline}`)) break;
      await wait(100);
    }
    assert.ok(await evaluate(`document.querySelectorAll('.eventRow').length > ${beforeOffline}`), "network recovery did not catch up automatically");
    await evaluate("document.querySelector('.detailsPane .paneHeader button').click()");
    await evaluate("document.querySelector('input[aria-label=\"Поисковый запрос\"]').focus(); document.querySelector('input[aria-label=\"Поисковый запрос\"]').select()");
    await command("Input.insertText", { text: "*" });
    await evaluate("document.querySelector('.runButton').click()");
    await wait(750);
    console.log(`PASS: automatic native Sysmon → SSE → actual WebView; first-event latency=${latency}ms; pause/resume, pinned details, network recovery`);
  }
  if (process.argv.includes("--filters")) {
    for (let attempt = 0; attempt < 60; attempt++) {
      if (await evaluate("document.querySelectorAll('.eventRow').length > 0")) break;
      await wait(250);
    }
    assert.ok(await evaluate("document.querySelectorAll('.eventRow').length > 0"), "no real events displayed");
    const source = await evaluate("document.querySelector('.eventRow .sourceCell').textContent");
    await evaluate("document.querySelector('input[aria-label=\"Поисковый запрос\"]').focus(); document.querySelector('input[aria-label=\"Поисковый запрос\"]').select()");
    await command("Input.insertText", { text: source.slice(3) });
    await evaluate("document.querySelector('.runButton').click()");
    await wait(1000);
    assert.ok(await evaluate("document.querySelectorAll('.eventRow').length > 0"), "global source substring search failed");
    await evaluate("Array.from(document.querySelectorAll('.filterRow button')).find(button => button.textContent.includes('Добавить фильтр')).click()");
    await evaluate("document.querySelector('input[aria-label=\"Поле фильтра\"]').focus(); document.querySelector('input[aria-label=\"Поле фильтра\"]').select()");
    await command("Input.insertText", { text: "source" });
    await evaluate("document.querySelector('input[aria-label=\"Значение фильтра\"]').focus()");
    await command("Input.insertText", { text: source });
    await evaluate("document.querySelector('.filterBuilder button[type=submit]').click()");
    await wait(1000);
    assert.equal(await evaluate("document.querySelector('select[aria-label=\"Режим поиска\"]').value"), "dsl");
    assert.ok(await evaluate("document.querySelector('input[aria-label=\"Поисковый запрос\"]').value.includes('source=')"));
    assert.equal(await evaluate(`Array.from(document.querySelectorAll('.eventRow .sourceCell')).every(element => element.textContent === ${JSON.stringify(source)})`), true);
    assert.ok(await evaluate("document.querySelectorAll('.eventRow').length > 0"), "exact source filter failed");
    assert.equal(await evaluate("document.querySelector('.queryInput.invalid') === null"), true);
    console.log(`PASS: real WebView global contains and exact filter builder; rows=${await evaluate("document.querySelectorAll('.eventRow').length")}; source=${source}`);
  }
  assert.equal(await evaluate("document.querySelector('button[title=\"Источники\"]') !== null"), true);
  await evaluate("document.querySelector('button[title=\"Источники\"]').click()");
  await wait(1000);
  await evaluate("document.querySelector('input[aria-label=\"Имя нового агента\"]').focus()");
  await command("Input.insertText", { text: "desktop-ui-test" });
  await wait(200);
  await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'ВЫПУСТИТЬ ТОКЕН').click()");
  await wait(1000);
  assert.equal(await evaluate("document.querySelector('.remoteAgentsPanel .privacyNotice code')?.textContent.length"), 64);
  assert.equal(await evaluate("document.querySelector('.remoteAgentsPanel').textContent.includes('desktop-ui-test')"), true);
  await evaluate("Array.from(document.querySelectorAll('.remoteAgentsPanel button')).find(button => button.textContent === 'ОТОЗВАТЬ ТОКЕН').click()");
  await wait(1000);
  assert.equal(await evaluate("document.querySelector('.remoteAgentsPanel').textContent.includes('Токен отозван')"), true);
  await evaluate("Array.from(document.querySelectorAll('.remoteAgentsPanel button')).find(button => button.textContent === 'СКРЫТЬ').click()");
  assert.equal(await evaluate("document.querySelector('.remoteAgentsPanel .privacyNotice code') === null"), true);
  if (process.argv.includes("--live-ui")) {
    const beforeSources = searchRequests;
    const marker = `REDTRACE-RETURN-${process.pid}-${Date.now()}`;
    const child = spawn("cmd.exe", ["/c", "echo", marker], { stdio: "ignore" });
    await new Promise((resolve, reject) => { child.on("exit", resolve); child.on("error", reject); });
    await wait(2000);
    assert.equal(searchRequests, beforeSources, "event searches continued in Sources workspace");
    await evaluate("document.querySelector('button[title=\"События\"]').click()");
    let resumed = false;
    for (let attempt = 0; attempt < 80; attempt++) {
      resumed = await evaluate(`Array.from(document.querySelectorAll('.eventRow')).some(row => row.textContent.includes(${JSON.stringify(marker)}))`);
      if (resumed) break;
      await wait(100);
    }
    assert.ok(resumed, "workspace return did not synchronize new events");
    console.log("PASS: no hidden event searches in Sources; return to Events automatically catches up");
  }
  if (testReadRollback) {
    const prior = await evaluate("localStorage.getItem('redtrace.log_read.snapshot')");
    assert.ok(prior, "original read ACL snapshot unavailable");
    console.log("Read ACL test: approve restore, then re-grant; final state retains user-authorized read access.");
    const restored = await evaluate(`window.__TAURI_INTERNALS__.invoke('audit_execute', {request:{operation:'restore_log_read',snapshot_id:${JSON.stringify(prior)},confirmation:'RESTORE REDTRACE LOG READ'}})`);
    assert.ok(restored.success, restored.error ?? "read ACL restore failed");
    const probe = spawnSync("powershell.exe", ["-NoProfile", "-Command", "try { Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1 -ErrorAction Stop | Out-Null; exit 0 } catch { exit 5 }"], { stdio: "ignore" });
    assert.equal(probe.status, 5, "original Sysmon read restriction did not return");
    await wait(1000);
    const granted = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'grant_log_read',confirmation:'GRANT REDTRACE LOG READ'}})");
    assert.ok(granted.success, granted.error ?? "read ACL re-grant failed");
    await evaluate(`localStorage.setItem('redtrace.log_read.snapshot', ${JSON.stringify(granted.snapshot_id)})`);
    await wait(1000);
    const noop = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'grant_log_read',confirmation:'GRANT REDTRACE LOG READ'}})");
    assert.ok(noop.success);
    assert.equal(noop.snapshot_id, null, "no-op grant replaced original rollback reference");
    const readable = spawnSync("powershell.exe", ["-NoProfile", "-Command", "try { Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1 -ErrorAction Stop | Out-Null; Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null; exit 0 } catch { exit 5 }"], { stdio: "ignore" });
    assert.equal(readable.status, 0, "normal-user channel read failed after re-grant");
    console.log("PASS: ACL restore, original restriction verified, re-grant, no-op snapshot preservation, Security+Sysmon readable as normal user; read access retained");
  } else if (grantLogRead) {
    console.log("Read ACL UI test: approve UAC; add only current-user read rights on Security/Sysmon and preserve prior ACLs.");
    await evaluate("document.querySelector('button[title=\"Аудит\"]').click()");
    await wait(1500);
    await evaluate("document.querySelector('input[aria-label=\"Подтверждение чтения журналов\"]').focus()");
    await command("Input.insertText", { text: "GRANT REDTRACE LOG READ" });
    await wait(200);
    await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'РАЗРЕШИТЬ READ-ONLY').click()");
    let granted = false;
    for (let attempt = 0; attempt < 150; attempt++) {
      const error = await evaluate("document.querySelector('.logReadWorkspace .operationError')?.textContent ?? ''");
      assert.equal(error, "", error);
      if (await evaluate("document.querySelector('.logReadWorkspace').textContent.includes('Текущему пользователю разрешено чтение Security и Sysmon')")) { granted = true; break; }
      await wait(1000);
    }
    assert.ok(granted, "read ACL grant timed out");
    console.log(`Read ACL snapshot ID: ${await evaluate("localStorage.getItem('redtrace.log_read.snapshot')")}`);
    await wait(6000);
    const probe = spawn("cmd.exe", ["/c", "echo", "REDTRACE-SYSMON-PROBE"], { stdio: "ignore" });
    const pid = probe.pid;
    await new Promise((resolve) => probe.on("exit", resolve));
    const query = `source:windows.sysmon AND event.id:1 AND process.pid:${pid}`;
    let captured = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      captured = await evaluate(`(async () => { const token = await window.__TAURI_INTERNALS__.invoke('api_token'); const result = await (await fetch('http://127.0.0.1:9710/api/search?q=' + encodeURIComponent(${JSON.stringify(query)}), {headers: {'x-redtrace-token':token}})).json(); return result.events.some(event => event.fields['process.command_line']?.includes('REDTRACE-SYSMON-PROBE') && event.fields['process.parent.pid'] && event.fields['collector.mode'] === 'native'); })()`);
      if (captured) break;
      await wait(500);
    }
    assert.ok(captured, "live native Sysmon event unavailable after read grant");
    console.log("PASS: user read-only ACL grant, protected ACL snapshot, live native Sysmon event in non-elevated desktop");
  } else if (sysmonPath) {
    console.log("Sysmon UI test: verify official binary, approve UAC install, leave service/driver installed.");
    await evaluate("document.querySelector('button[title=\"Аудит\"]').click()");
    await wait(1500);
    await evaluate("document.querySelector('input[aria-label=\"Путь к Sysmon64.exe\"]').focus()");
    await command("Input.insertText", { text: sysmonPath });
    await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'ПРОВЕРИТЬ SYSMON').click()");
    for (let attempt = 0; attempt < 90; attempt++) {
      const error = await evaluate("document.querySelector('.sysmonWorkspace .operationError')?.textContent ?? ''");
      assert.equal(error, "", error);
      if (await evaluate("document.querySelector('.sysmonWorkspace').textContent.includes('Authenticode: Valid')")) break;
      await wait(1000);
    }
    assert.equal(await evaluate("document.querySelector('.sysmonWorkspace').textContent.includes('83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352')"), true);
    await evaluate("document.querySelector('input[aria-label=\"Подтверждение Sysmon\"]').focus()");
    await command("Input.insertText", { text: "INSTALL REDTRACE SYSMON" });
    await wait(200);
    await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'УСТАНОВИТЬ SYSMON').click()");
    let installed = false;
    for (let attempt = 0; attempt < 150; attempt++) {
      const error = await evaluate("document.querySelector('.sysmonWorkspace .operationError')?.textContent ?? ''");
      assert.equal(error, "", error);
      if (await evaluate("document.querySelector('.sysmonWorkspace').textContent.includes('Sysmon установлен; служба работает')")) { installed = true; break; }
      await wait(1000);
    }
    assert.ok(installed, "Sysmon install response timed out; inspect service and preserved snapshot");
    console.log(`Sysmon snapshot ID: ${await evaluate("localStorage.getItem('redtrace.sysmon.snapshot')")}`);
    const probe = spawn("cmd.exe", ["/c", "echo", "REDTRACE-SYSMON-PROBE"], { stdio: "ignore" });
    const pid = probe.pid;
    await new Promise((resolve) => probe.on("exit", resolve));
    const query = `source:windows.sysmon AND event.id:1 AND process.pid:${pid}`;
    let captured = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      captured = await evaluate(`(async () => { const token = await window.__TAURI_INTERNALS__.invoke('api_token'); const result = await (await fetch('http://127.0.0.1:9710/api/search?q=' + encodeURIComponent(${JSON.stringify(query)}), {headers: {'x-redtrace-token':token}})).json(); return result.events.some(event => event.fields['process.command_line']?.includes('REDTRACE-SYSMON-PROBE') && event.fields['process.parent.pid'] && event.fields['collector.mode'] === 'native'); })()`);
      if (captured) break;
      await wait(500);
    }
    assert.ok(captured, "live Sysmon process event did not reach native subscription");
    console.log("PASS: Sysmon signature/hash/config preview, explicit UI/UAC install, running service, live native process event with PID/PPID/command line; Sysmon retained");
  } else if (recoverLatest) {
    console.log("Recovery: approve UAC to restore the latest complete protected snapshot.");
    const recovered = await evaluate(`window.__TAURI_INTERNALS__.invoke('audit_execute', { request: { operation: 'rollback', snapshot_id: '${"0".repeat(32)}', confirmation: 'ROLLBACK REDTRACE AUDIT' } })`);
    console.log(`Recovery snapshot ID: ${recovered.snapshot_id ?? "unavailable"}`);
    assert.ok(recovered.success, recovered.error ?? "recovery failed");
    assert.ok(recovered.verified);
    console.log("PASS: original logon policy restored and verified");
  } else if (auditUi) {
    console.log("Audit UI test: approve UAC for apply and rollback of the four selected audit settings.");
    await evaluate("document.querySelector('button[title=\"Аудит\"]').click()");
    await wait(1500);
    assert.equal(await evaluate("document.querySelector('.auditMode').textContent.includes('ГОТОВ К ПРИМЕНЕНИЮ')"), true);
    const baseline = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'status'}})");
    assert.ok(baseline.success && baseline.state, baseline.error ?? "effective baseline unavailable");
    assert.equal(await evaluate("document.querySelectorAll('.auditActions input:not(:disabled)').length"), 4);
    await evaluate("document.querySelectorAll('.auditActions input:not(:disabled)').forEach(input => input.click())");
    await evaluate("document.querySelector('input[aria-label=\"Подтверждение изменения аудита\"]').focus()");
    await command("Input.insertText", { text: "APPLY REDTRACE AUDIT" });
    await wait(200);
    await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'ПРИМЕНИТЬ ВЫБРАННОЕ').click()");
    const waitAudit = async (message) => {
      for (let attempt = 0; attempt < 150; attempt++) {
        const error = await evaluate("document.querySelector('.auditWorkspace .operationError')?.textContent ?? ''");
        assert.equal(error, "", error);
        if (await evaluate(`document.querySelector('.auditWorkspace').textContent.includes(${JSON.stringify(message)})`)) return;
        await wait(1000);
      }
      throw new Error("Audit UI operation timed out; inspect the retained snapshot before retrying");
    };
    await waitAudit("Выбранные политики применены и проверены");
    const auditSnapshot = await evaluate("localStorage.getItem('redtrace.audit.snapshot')");
    console.log(`Applied snapshot: ${auditSnapshot}`);
    auditRecovery = async () => {
      const report = await evaluate(`window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'rollback',snapshot_id:${JSON.stringify(auditSnapshot)},confirmation:'ROLLBACK REDTRACE AUDIT'}})`);
      assert.ok(report.success && report.verified, report.error ?? "failure rollback did not verify");
      console.log(`Failure cleanup: snapshot ${auditSnapshot} restored and verified`);
    };
    const appliedState = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'status'}})");
    assert.ok(appliedState.success && appliedState.state, appliedState.error);
    assert.deepEqual(appliedState.state.policy, {logon:3,"account-lockout":1,"process-creation":1});
    assert.equal(appliedState.state.process_command_line.dword, 1);
    assert.equal(appliedState.state.powershell_script_block.dword, 1);
    const processMarker = `REDTRACE-AUDIT-PROCESS-${process.pid}-${Date.now()}`;
    const scriptMarker = `REDTRACE-AUDIT-SCRIPT-${process.pid}-${Date.now()}`;
    spawnSync("cmd.exe", ["/c", "echo", processMarker], { stdio: "ignore", windowsHide: true });
    spawnSync("powershell.exe", ["-NoProfile", "-Command", `$value='${scriptMarker}'; $value | Out-Null`], { stdio: "ignore", windowsHide: true });
    const observed = async (query) => {
      for (let attempt = 0; attempt < 60; attempt++) {
        const result = await evaluate(`(async()=>{const token=await window.__TAURI_INTERNALS__.invoke('api_token'); const response=await fetch('http://127.0.0.1:9710/api/search?q='+encodeURIComponent(${JSON.stringify(query)}),{headers:{'x-redtrace-token':token}}); return response.json();})()`);
        if (result.total > 0) return;
        await wait(250);
      }
      const diagnostic = await evaluate("(async()=>{const token=await window.__TAURI_INTERNALS__.invoke('api_token');const headers={'x-redtrace-token':token};const health=await(await fetch('http://127.0.0.1:9710/api/health',{headers})).json();const sample=await(await fetch('http://127.0.0.1:9710/api/search?q=event.id%3D4104',{headers})).json();return {source:health.source,ingestion:health.ingestion,powershell_count:sample.total};})()");
      console.log(JSON.stringify({ failed_query: query, diagnostic }));
      throw new Error("Configured audit event did not reach the SIEM");
    };
    await observed(`event.id=4688 AND process.command_line~"${processMarker}"`);
    await observed(`event.id=4104 AND *~"${scriptMarker}"`);
    console.log("PASS: actual 4688 command line and 4104 ScriptBlock events reached the collector");
    console.log(`Audit UI snapshot ID: ${await evaluate("localStorage.getItem('redtrace.audit.snapshot')")}`);
    await evaluate("document.querySelector('input[aria-label=\"Подтверждение изменения аудита\"]').focus()");
    await command("Input.insertText", { text: "ROLLBACK REDTRACE AUDIT" });
    await wait(200);
    await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'ОТКАТИТЬ SNAPSHOT').click()");
    await waitAudit("Исходные политики восстановлены и проверены");
    auditRecovery = undefined;
    const restoredState = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'status'}})");
    assert.ok(restoredState.success && restoredState.state, restoredState.error);
    assert.deepEqual(restoredState.state.policy, baseline.state.policy);
    assert.deepEqual(restoredState.state.process_command_line, baseline.state.process_command_line);
    assert.deepEqual(restoredState.state.powershell_script_block, baseline.state.powershell_script_block);
    assert.equal(restoredState.state.sysmon_installed, baseline.state.sysmon_installed);
    const readGrant = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'grant_log_read',confirmation:'GRANT REDTRACE LOG READ'}})");
    assert.ok(readGrant.success && readGrant.verified, readGrant.error);
    let finalState = restoredState.state;
    if (process.argv.includes("--leave-audit-enabled")) {
      await evaluate("document.querySelector('input[aria-label=\"Подтверждение изменения аудита\"]').focus(); document.querySelector('input[aria-label=\"Подтверждение изменения аудита\"]').select()");
      await command("Input.insertText", { text: "APPLY REDTRACE AUDIT" });
      await wait(200);
      await evaluate("Array.from(document.querySelectorAll('button')).find(button => button.textContent === 'ПРИМЕНИТЬ ВЫБРАННОЕ').click()");
      await waitAudit("Выбранные политики применены и проверены");
      const enabled = await evaluate("window.__TAURI_INTERNALS__.invoke('audit_execute',{request:{operation:'status'}})");
      assert.ok(enabled.success && enabled.state, enabled.error);
      assert.deepEqual(enabled.state.policy, appliedState.state.policy);
      assert.equal(enabled.state.process_command_line.dword, 1);
      assert.equal(enabled.state.powershell_script_block.dword, 1);
      finalState = enabled.state;
      console.log("Recommended audit settings remain enabled; protected rollback snapshot preserved");
    }
    const auditOutput = join(root, "outputs", "windows-admin");
    mkdirSync(auditOutput, { recursive: true });
    writeFileSync(join(auditOutput, "audit-report.json"), JSON.stringify({result:"PASS",desktop_binary:desktopBinary,baseline:baseline.state,applied:appliedState.state,rollback:restoredState.state,final:finalState,read_grant_verified:readGrant.verified,security_4688:true,powershell_4104:true}, null, 2));
    console.log("PASS: installed Audit UI ready without dev-env, effective baseline/apply/rollback equality, four-settings, Sysmon retained, read grant");
  } else if (auditTest) {
    console.log("Audit test: approve UAC for the dev helper; apply selected policies, then restore the verified snapshot.");
    const actions = auditAll ? ["logon", "account-lockout", "process-creation", "powershell-script-block"] : ["logon"];
    const applied = await evaluate(`window.__TAURI_INTERNALS__.invoke('audit_execute', { request: { operation: 'apply', profile: 'recommended-workstation', action_ids: ${JSON.stringify(actions)}, confirmation: 'APPLY REDTRACE AUDIT' } })`);
    console.log(`Audit snapshot ID: ${applied.snapshot_id ?? "unavailable"}`);
    assert.ok(applied.success, applied.error ?? "audit apply failed");
    assert.deepEqual(applied.applied_actions, actions);
    assert.ok(applied.verified);
    await wait(1000);
    const rolledBack = await evaluate(`window.__TAURI_INTERNALS__.invoke('audit_execute', { request: { operation: 'rollback', snapshot_id: ${JSON.stringify(applied.snapshot_id)}, confirmation: 'ROLLBACK REDTRACE AUDIT' } })`);
    assert.ok(rolledBack.success, rolledBack.error ?? "audit rollback failed");
    assert.ok(rolledBack.verified);
    console.log(`PASS: UAC helper IPC, protected snapshot, apply/verify/rollback for ${actions.join(", ")}`);
  }
  console.log("PASS: desktop UI, Tauri session token, agent registration, token display/hide, browser DELETE revocation");
  }
} catch (error) {
  if (auditRecovery) await auditRecovery();
  throw error;
} finally {
  socket?.close();
  if (processHandle.pid && !keepOpen) {
    try { execFileSync("taskkill.exe", ["/PID", String(processHandle.pid), "/T", "/F"], { stdio: "ignore" }); } catch { processHandle.kill(); }
  }
  await wait(1000);
  rmSync(directory, { recursive: true, force: true });
}
