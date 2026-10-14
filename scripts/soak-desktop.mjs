import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export async function runDesktopSoak({ command, evaluate, wait, pid, duration, output }) {
  assert.ok(Number.isInteger(duration) && duration >= 60 && duration <= 259200, "duration must be 60–259200 seconds");
  const token = await evaluate("window.__TAURI_INTERNALS__.invoke('api_token')");
  const api = async (path, init = {}) => {
    const response = await fetch(`http://127.0.0.1:9710${path}`, { ...init, headers: { "x-redtrace-token": token, "content-type": "application/json" }, signal: AbortSignal.timeout(20000) });
    assert.ok(response.ok, `API status ${response.status}`);
    return response.json();
  };
  for (let attempt = 0; attempt < 120; attempt++) {
    const health = await api("/api/health");
    if (health.source.state !== "backfilling" && health.ingestion.queue_depth === 0) break;
    await wait(500);
  }
  const agent = await api("/api/agents", { method: "POST", body: JSON.stringify({ name: "isolated-soak-validation" }) });
  const query = `agent.id="${agent.id}"`;
  await evaluate("document.querySelector('select[aria-label=\"Режим поиска\"]').focus()");
  await command("Input.dispatchKeyEvent", { type: "keyDown", key: "End", code: "End", windowsVirtualKeyCode: 35 });
  await command("Input.dispatchKeyEvent", { type: "keyUp", key: "End", code: "End", windowsVirtualKeyCode: 35 });
  await command("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  await command("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 });
  assert.equal(await evaluate("document.querySelector('select[aria-label=\"Режим поиска\"]').value"), "dsl");
  await evaluate("document.querySelector('.queryInput input').focus(); document.querySelector('.queryInput input').select()");
  await command("Input.insertText", { text: query });
  await evaluate("document.querySelector('.runButton').click()");
  await wait(750);
  let sent = 0;
  let retries = 0;
  let duplicates = 0;
  let lastBatch;
  const samples = [];
  const latencies = [];
  const searchTimes = [];
  const started = Date.now();
  let nextSample = 0;
  let midBurst = false;
  const makeBatch = (count) => ({ host: { name: "isolated-validation", os: "validation" }, events: Array.from({ length: count }, (_, index) => ({ timestamp: new Date().toISOString(), source: "validation.load", level: "low", message: `Isolated soak fixture ${sent + index}`, fields: { "event.id": "validation.load", "event.record_id": `${agent.id}-${sent + index}`, "validation.sequence": String(sent + index) } })) });
  const deliver = async (batch) => {
    for (let attempt = 0; attempt < 6; attempt++) {
      const response = await fetch("http://127.0.0.1:9711/ingest/v1/events", { method: "POST", headers: { "x-redtrace-ingest-token": agent.token, "content-type": "application/json" }, body: JSON.stringify(batch), signal: AbortSignal.timeout(20000) });
      if (response.ok) {
        const result = await response.json();
        assert.equal(result.accepted + result.duplicates, batch.events.length);
        duplicates += result.duplicates;
        return;
      }
      assert.equal(response.status, 503, `ingest status ${response.status}`);
      retries += 1;
      await wait(250 * (attempt + 1));
    }
    throw new Error("ingest retries exhausted");
  };
  const burst = async () => {
    for (let batch = 0; batch < 8; batch++) { lastBatch = makeBatch(250); await deliver(lastBatch); sent += lastBatch.events.length; }
  };
  const resources = () => JSON.parse(execFileSync("powershell.exe", ["-NoProfile", "-Command", `$rootPid=${pid}; $all=Get-CimInstance Win32_Process; $ids=@($rootPid); for($i=0;$i -lt 8;$i++){ $ids=@($ids + @($all | Where-Object { $_.ParentProcessId -in $ids } | ForEach-Object { [int]$_.ProcessId }) | Sort-Object -Unique) }; @($ids | ForEach-Object { $p=Get-Process -Id $_ -ErrorAction SilentlyContinue; if($p){ [pscustomobject]@{pid=$p.Id;name=$p.ProcessName;working_set_bytes=$p.WorkingSet64;private_bytes=$p.PrivateMemorySize64;cpu_seconds=$p.CPU} } }) | ConvertTo-Json -Compress`], { encoding: "utf8", windowsHide: true }).trim());
  try {
    await burst();
    while (Date.now() - started < duration * 1000) {
      const tick = Date.now();
      lastBatch = makeBatch(25);
      await deliver(lastBatch);
      sent += lastBatch.events.length;
      if (!midBurst && Date.now() - started >= duration * 500) { await burst(); midBurst = true; }
      if (Date.now() - started >= nextSample) {
        const search = await api(`/api/search?q=${encodeURIComponent(query)}&limit=100`);
        searchTimes.push(search.took_micros / 1000);
        const newest = search.events[0]?.uid;
        const expectedSequence = Math.max(...search.events.map((event) => Number(event.fields["validation.sequence"])));
        assert.ok(newest, "search produced no load fixtures");
        const uiStarted = Date.now();
        let visible = false;
        for (let attempt = 0; attempt < 100; attempt++) {
          visible = await evaluate(`(() => { const rows=Array.from(document.querySelectorAll('.eventRow')); return rows.some(row => row.dataset.uid === ${JSON.stringify(newest)}) || Math.max(-1,...rows.map(row => Number(row.querySelector('.messageCell b')?.textContent.match(/^Isolated soak fixture (\\d+)$/)?.[1] ?? -1))) >= ${expectedSequence}; })()`);
          if (visible) break;
          await wait(50);
        }
        if (!visible) samples.push({ elapsed_seconds: Math.round((Date.now() - started) / 1000), sent, catchup_failure: await evaluate("({rows:document.querySelectorAll('.eventRow').length, live:document.querySelector('.liveStatus')?.textContent, scroll_top:document.querySelector('.eventStream')?.scrollTop, max_sequence:Math.max(-1,...Array.from(document.querySelectorAll('.eventRow .messageCell b')).map(element => Number(element.textContent.match(/^Isolated soak fixture (\\d+)$/)?.[1] ?? -1)))})"), expected_sequence: expectedSequence });
        assert.ok(visible, "GUI failed to catch up during load");
        latencies.push(Date.now() - uiStarted);
        const health = await api("/api/health");
        assert.equal(health.ingestion.dropped_events + health.ingestion.wal_errors + health.ingestion.segment_errors + health.ingestion.checkpoint_errors, 0);
        const ui = await evaluate("({rows:document.querySelectorAll('.eventRow').length, live:document.querySelector('.liveStatus')?.textContent})");
        assert.ok(ui.rows <= 100 && ui.rows > 0);
        assert.equal(ui.live, "LIVE");
        samples.push({ elapsed_seconds: Math.round((Date.now() - started) / 1000), sent, queue_depth: health.ingestion.queue_depth, events_indexed: health.events_indexed, wal_bytes: health.storage.wal_bytes, segment_bytes: health.storage.segment_bytes, segment_count: health.storage.segment_count, ui_rows: ui.rows, resources: resources() });
        nextSample = Date.now() - started + 10000;
        if (samples.length % 6 === 0) console.log(`Soak: ${samples.at(-1).elapsed_seconds}s, fixtures=${sent}, UI=${ui.rows}, queue=${health.ingestion.queue_depth}`);
      }
      await wait(Math.max(0, 1000 - (Date.now() - tick)));
    }
    await deliver(lastBatch);
    await wait(3000);
    const result = await api(`/api/search?q=${encodeURIComponent(query)}&limit=1000`);
    assert.equal(result.total, sent, "acknowledged fixtures missing or duplicated");
    assert.equal(new Set(result.events.map((event) => event.uid)).size, result.events.length);
    const health = await api("/api/health");
    assert.ok(health.storage.segment_count > 0, "segment rotation was not exercised");
    const percentile = (values, fraction) => [...values].sort((left, right) => left - right)[Math.min(values.length - 1, Math.ceil(values.length * fraction) - 1)];
    const report = { result: "PASS", scope: "synthetic fixtures in isolated temporary desktop database; native collector also active", duration_seconds: Math.round((Date.now() - started) / 1000), fixtures_sent: sent, fixtures_searchable: result.total, retries, duplicates_acknowledged: duplicates, bursts: 2, steady_target_events_per_second: 25, ui_catchup_p95_ms: percentile(latencies, 0.95), search_p95_ms: percentile(searchTimes, 0.95), final_queue_depth: health.ingestion.queue_depth, final_segment_count: health.storage.segment_count, samples, memory_method: "per-process Get-Process WorkingSet64/private bytes; CPU cumulative seconds; includes WebView2 child tree" };
    mkdirSync(output, { recursive: true });
    writeFileSync(join(output, "report.json"), JSON.stringify(report, null, 2));
    console.log(`PASS: soak ${report.duration_seconds}s, ${sent} fixtures, UI p95 catch-up=${report.ui_catchup_p95_ms}ms, search p95=${report.search_p95_ms}ms`);
  } catch (error) {
    mkdirSync(output, { recursive: true });
    writeFileSync(join(output, "report.json"), JSON.stringify({ result: "FAIL", duration_seconds: Math.round((Date.now() - started) / 1000), fixtures_sent: sent, retries, samples, error: error.message }, null, 2));
    throw error;
  } finally { await api(`/api/agents/${agent.id}`, { method: "DELETE" }).catch(() => undefined); }
}
