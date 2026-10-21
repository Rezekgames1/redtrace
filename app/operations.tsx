"use client";

import { useEffect, useState } from "react";
import { createRemoteAgent, executeWindowsAudit, getDiagnostics, getRemoteAgents, getWindowsAudit, previewSysmon, revokeRemoteAgent, controlRequest } from "./events/api";
import { OnboardingPanel, initialAgentConfig } from "./control-workspaces";
import type { RuntimeConfig } from "./control-workspaces";
import type { AuditEffectiveState, Diagnostics, RemoteAgent, SensorHealth, SysmonPreview, WindowsAuditPlan, WindowsAuditStatus } from "./events/api";

export function SourcesWorkspace({ health, onRefresh, refreshing, onExplore }: { health: SensorHealth | null; onRefresh: () => void; refreshing: boolean; onExplore?: (query: string) => void }) {
  const source = health?.source;
  const errorCount = health ? health.ingestion.wal_errors + health.ingestion.segment_errors + health.ingestion.checkpoint_errors + health.ingestion.detection_errors : 0;
  const quarantine = health?.storage.wal_quarantine;
  return <section className="operationsWorkspace">
    <div className="operationsHeader"><div><span>ИСТОЧНИКИ ДАННЫХ</span><h2>Состояние сенсоров</h2><p>{health?.remote_ingest?.enabled ? `Приём событий от агентов: ${health.remote_ingest.bind}` : "Локальный сбор активен. Приём от агентов включается ниже, в «Подключении устройств»."}</p></div><button onClick={onRefresh} disabled={refreshing}>{refreshing ? "ПРОВЕРКА…" : "↻ ПРОВЕРИТЬ СЕЙЧАС"}</button></div>
    <div className="metricGrid">
      <article><small>СОБЫТИЙ В БАЗЕ</small><b>{health?.events_indexed ?? 0}</b><span>WAL + неизменяемые сегменты</span></article>
      <article><small>ОЧЕРЕДЬ</small><b>{health ? `${health.ingestion.queue_depth}/${health.ingestion.queue_bound}` : "—"}</b><span>bounded ingestion channel</span></article>
      <article><small>АЛЕРТОВ</small><b>{health?.storage.alert_records ?? 0}</b><span>сохранено с checksum</span></article>
      <article className={errorCount ? "metricWarn" : ""}><small>ОШИБОК</small><b>{errorCount}</b><span>с момента запуска</span></article>
    </div>
    <article className="sourceCard"><div className="sourceIcon">▦</div><div className="sourceIdentity"><small>{source?.name ?? "локальный источник"}</small><b>{source?.name ?? "Сенсор недоступен"}</b><span>Режим: read-only · окно {source?.lookback ?? "—"}</span></div><div className={`sourceState ${source?.state ?? "error"}`}><i/><b>{source?.state ?? "offline"}</b><span>{source?.last_error || "ошибок источника нет"}</span></div><dl><div><dt>Собрано за сеанс</dt><dd>{source?.events_collected ?? 0}</dd></div><div><dt>Сегментов</dt><dd>{health?.storage.segment_count ?? 0}</dd></div><div><dt>Checkpoints</dt><dd>{health?.storage.checkpoint_sources ?? 0}</dd></div><div><dt>Последнее событие</dt><dd>{health?.ingestion.last_event_at ?? "нет новых"}</dd></div></dl></article>
    {source?.name === "macos.unified_log" && <article className="controlPanel"><h3>Что собирается с Mac</h3><p>События sudo, SSH и выдачи прав через authd. Для запусков всех процессов, их аргументов и файловых операций нужен отдельный источник macOS Endpoint Security. Его состояние и права доступны в настройках SIEM.</p></article>}
    <OnboardingPanel />
    <RemoteAgentsPanel health={health} onExplore={onExplore} />
    <details className="integrityDetails"><summary>Целостность хранилища{!health ? " · ожидание данных" : health.storage.corrupted_records + health.storage.corrupted_segments + health.storage.corrupted_segment_indexes + health.storage.corrupted_alert_records > 0 ? " · обнаружены повреждения" : quarantine?.archives ? " · есть архив восстановления WAL" : " · повреждений нет"}</summary><div className="integrityPanel"><div><span>Повреждённые данные изолируются и не подмешиваются в поиск.</span>{quarantine && quarantine.archives > 0 && <p>Сохранено архивов WAL: {quarantine.archives}. Повреждённых строк в архивах: {quarantine.corrupted_records}; найдено проверенных записей: {quarantine.salvageable_records}. Исходные байты сохранены для анализа.</p>}</div><ul><li><b>{health?.storage.corrupted_records ?? 0}</b> WAL records</li><li><b>{health?.storage.corrupted_segments ?? 0}</b> segments</li><li><b>{health?.storage.corrupted_segment_indexes ?? 0}</b> indexes</li><li><b>{health?.storage.corrupted_alert_records ?? 0}</b> alerts</li></ul></div></details>
  </section>;
}

function RemoteAgentsPanel({ health, onExplore }: { health: SensorHealth | null; onExplore?: (query: string) => void }) {
  const [agents, setAgents] = useState<RemoteAgent[]>([]);
  const [name, setName] = useState("");
  const [issuedToken, setIssuedToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const refreshEpoch = Math.floor((health?.uptime_seconds ?? 0) / 15);
  useEffect(() => {
    let active = true;
    void getRemoteAgents().then((result) => { if (active) { setAgents(result); setError(""); } }).catch(() => { if (active) setError("Список агентов недоступен"); });
    return () => { active = false; };
  }, [refreshEpoch]);
  const create = async () => {
    setBusy(true);
    setError("");
    try {
      const created = await createRemoteAgent(name.trim());
      setIssuedToken(created.token);
      setName("");
      setAgents(await getRemoteAgents());
    } catch { setError("Не удалось зарегистрировать агента"); }
    finally { setBusy(false); }
  };
  const revoke = async (id: string) => {
    setBusy(true);
    setError("");
    try { await revokeRemoteAgent(id); setAgents(await getRemoteAgents()); }
    catch { setError("Не удалось отозвать токен"); }
    finally { setBusy(false); }
  };
  return <section className="remoteAgentsPanel">
    <div className="operationsHeader"><div><span>УДАЛЁННЫЕ АГЕНТЫ</span><h2>Подключённые машины</h2><p>Активных: {health?.remote_ingest?.agents_active ?? 0} · принято событий: {health?.remote_ingest?.remote_events_total ?? 0}</p></div></div>
    <details className="controlPanel"><summary>Ручной выпуск токена</summary><p>Для обычного подключения используйте одноразовый пакет выше. Ручной токен требует отдельной передачи доверенного CA и параметров соединения.</p><div className="operationButtons"><input aria-label="Имя нового агента" placeholder="Имя машины" maxLength={64} value={name} onChange={(event) => setName(event.target.value)} /><button disabled={busy || !name.trim()} onClick={() => void create()}>ВЫПУСТИТЬ ТОКЕН</button></div>
    {error && <div className="operationError">{error}</div>}
    {issuedToken && <div className="privacyNotice"><b>Токен показан один раз</b><code>{issuedToken}</code><button onClick={() => setIssuedToken("")}>СКРЫТЬ</button></div>}</details>
    {agents.map((agent) => <AgentCard key={agent.id} agent={agent} busy={busy} onRevoke={() => void revoke(agent.id)} onExplore={onExplore} />)}
    {!agents.length && <p>Агенты ещё не зарегистрированы.</p>}
  </section>;
}

function AgentCard({ agent, busy, onRevoke, onExplore }: { agent: RemoteAgent; busy: boolean; onRevoke: () => void; onExplore?: (query: string) => void }) {
  const [policy, setPolicy] = useState(""); const [message, setMessage] = useState(""); const [saving, setSaving] = useState(false);
  const telemetry = agent.telemetry;
  const states: Record<string, string> = { online: "В сети · события поступают", idle: "В сети · новых событий нет", stale: "Контакт задерживается", offline: "Не в сети", degraded: "Требуется внимание", registered: "Ожидает подключения", revoked: "Токен отозван", expired: "Токен истёк" };
  async function loadPolicy() { setSaving(true); setMessage(""); try { const result = await controlRequest<{ config: RuntimeConfig | null; generation: number }>(`/api/agents/${encodeURIComponent(agent.id)}/config`); setPolicy(JSON.stringify(result.config ?? initialAgentConfig(), null, 2)); setMessage(result.config ? `Настройки коллектора для этого агента, версия ${result.generation}` : "Для агента ещё не назначены настройки. В редакторе базовый профиль."); } catch (reason) { setMessage(reason instanceof Error ? reason.message : String(reason)); } finally { setSaving(false); } }
  async function savePolicy() { setSaving(true); setMessage(""); try { await controlRequest(`/api/agents/${encodeURIComponent(agent.id)}/config`, "PUT", JSON.parse(policy)); setMessage("Настройки будут применены на следующем heartbeat"); } catch (reason) { setMessage(reason instanceof Error ? reason.message : String(reason)); } finally { setSaving(false); } }
  return <article className="controlPanel agentHealth"><div className="operationsHeader"><div><b>{agent.name}</b><small> {agent.id} · {agent.platform ?? "ОС неизвестна"}</small><p className={`fleetState ${agent.state ?? "registered"}`}>{states[agent.state ?? "registered"] ?? agent.state}</p></div><div className="operationButtons"><button disabled={!onExplore} onClick={() => onExplore?.(`agent.id="${agent.id}"`)}>События</button><button disabled={busy || agent.revoked} onClick={onRevoke}>Отозвать токен</button></div></div><dl className="fleetMetrics"><div><dt>Контакт</dt><dd>{agent.last_seen_unix ? new Date(agent.last_seen_unix * 1000).toLocaleString() : "—"}</dd></div><div><dt>Последнее событие</dt><dd>{agent.last_event_at ? new Date(agent.last_event_at).toLocaleString() : "—"}</dd></div><div><dt>Доставка события</dt><dd>{agent.delivery_lag_seconds == null ? "—" : agent.delivery_lag_seconds < 0 ? "Часы хоста опережают коллектор" : `${agent.delivery_lag_seconds} с`}</dd></div><div><dt>Принято</dt><dd>{agent.events_received}</dd></div><div><dt>Pending / spool</dt><dd>{telemetry ? `${telemetry.pending_events} / ${(telemetry.spool_bytes / 1048576).toFixed(1)} из ${(telemetry.spool_limit_bytes / 1048576).toFixed(1)} MiB` : "Агент не сообщил"}</dd></div><div><dt>Самое старое pending</dt><dd>{telemetry?.oldest_pending_at ? new Date(telemetry.oldest_pending_at).toLocaleString() : "—"}</dd></div><div><dt>Retry / quarantine / refused</dt><dd>{telemetry ? `${telemetry.retry_total} / ${telemetry.quarantine_events} / ${telemetry.enqueue_refused_total}` : "—"}</dd></div><div><dt>Конфигурация</dt><dd>{telemetry ? `${telemetry.config_generation} / ${agent.config_generation ?? 0}` : "—"}</dd></div></dl>{telemetry?.modules.map(module => <p key={module.id}><code>{module.id}</code> · {module.state} · {module.permissions}{module.error && <span className="operationError"> {module.error}</span>}</p>)}<details><summary>Настройки этого агента</summary><button disabled={saving || busy} onClick={() => void loadPolicy()}>Загрузить настройки агента</button><textarea aria-label={`Настройки агента ${agent.name}`} className="controlEditor" disabled={saving || busy} value={policy} onChange={event => setPolicy(event.target.value)} spellCheck={false} /><button disabled={saving || busy || !policy || agent.revoked} onClick={() => void savePolicy()}>Отправить настройки</button>{message && <p role="status">{message}</p>}</details></article>;
}

export function AuditWorkspace() {
  const [plan, setPlan] = useState<WindowsAuditPlan | null>(null);
  const [status, setStatus] = useState<WindowsAuditStatus | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [confirmation, setConfirmation] = useState("");
  const [snapshot, setSnapshot] = useState(() => typeof window === "undefined" ? "" : localStorage.getItem("redtrace.audit.snapshot") ?? "");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [effective, setEffective] = useState<AuditEffectiveState | null>(null);
  const checkState = async () => {
    setBusy(true); setError("");
    try {
      const report = await executeWindowsAudit({ operation: "status" });
      if (!report.success || !report.state) throw new Error(report.error ?? "Состояние Windows недоступно");
      setEffective(report.state);
      if (!snapshot && report.state.audit_snapshot) setSnapshot(report.state.audit_snapshot);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Проверка состояния не выполнена"); }
    finally { setBusy(false); }
  };
  const execute = async (rollback: boolean) => {
    if (!plan) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const report = await executeWindowsAudit(rollback ? { operation: "rollback", snapshot_id: snapshot || "0".repeat(32), confirmation } : { operation: "apply", profile: plan.profile, action_ids: selected, confirmation });
      if (report.snapshot_id) { setSnapshot(report.snapshot_id); localStorage.setItem("redtrace.audit.snapshot", report.snapshot_id); }
      if (!report.success) throw new Error(report.error ?? "Helper вернул ошибку");
      if (report.state) setEffective(report.state);
      setMessage(rollback ? "Исходные политики восстановлены и проверены" : "Выбранные политики применены и проверены");
      setConfirmation("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Операция аудита не выполнена"); }
    finally { setBusy(false); }
  };
  useEffect(() => { void getWindowsAudit().then(({ plan, status }) => { setPlan(plan); setStatus(status); }).catch((reason) => setError(reason instanceof Error ? reason.message : "Профиль недоступен")); }, []);
  if (status && !status.platform_supported) return <section className="operationsWorkspace auditWorkspace"><div className="operationsHeader"><div><h2>Аудит системных журналов</h2><p>Сенсор читает доступные журналы автоматически. Состояние и разрешения отображаются в разделе «Источники».</p></div></div><div className="privacyNotice"><b>Сбор read-only</b><span>Мастер Windows Audit и Sysmon доступен только на Windows. Настройка auditd/eBPF на Linux и дополнительных источников macOS выполняется отдельно.</span></div></section>;
  return <section className="operationsWorkspace auditWorkspace">
    <div className="operationsHeader"><div><span>БЫСТРАЯ НАСТРОЙКА</span><h2>Windows Audit и Sysmon</h2><p>Локальный Windows-хост: входы, командная строка, PowerShell и системная телеметрия.</p></div><div className={`auditMode ${status?.executor_available ? "ready" : "preview"}`}><i/><span><small>РЕЖИМ</small><b>{status?.executor_available ? "ГОТОВ К ПРИМЕНЕНИЮ" : "ТОЛЬКО ПРЕДПРОСМОТР"}</b></span></div></div>
    <div className="operationButtons"><button disabled={!status?.executor_available || busy} onClick={() => void checkState()}>{busy ? "ОПЕРАЦИЯ…" : "ПРОВЕРИТЬ СОСТОЯНИЕ WINDOWS"}</button></div>
    {effective && <div className="metricGrid"><article><small>АУДИТ ВХОДОВ</small><b>{effective.policy.logon === 3 ? "Success + Failure" : `Flags ${effective.policy.logon}`}</b></article><article><small>УПРАВЛЕНИЕ УЧЁТНЫМИ ЗАПИСЯМИ</small><b>{effective.policy["account-lockout"] & 1 ? "Включён" : "Выключен"}</b></article><article><small>4688 / COMMAND LINE</small><b>{(effective.policy["process-creation"] & 1) && effective.process_command_line.dword === 1 ? "Включён" : "Неполный"}</b></article><article><small>POWERSHELL SCRIPT BLOCK</small><b>{effective.powershell_script_block.dword === 1 ? "Включён" : "Выключен"}</b></article></div>}
    {error && <div className="operationError">{error}</div>}
    {plan && <><div className="privacyNotice"><b>ПРИВАТНОСТЬ</b><span>{plan.privacy_warning}</span></div><div className="auditActions">{plan.actions.map((action, index) => <article key={action.id}><header><span>{String(index + 1).padStart(2, "0")}</span><div><b>{action.title}</b><small>{action.source_events.map((event) => `Event ${event}`).join(" · ")}</small></div>{action.id === "sysmon" ? <button onClick={() => document.querySelector(".sysmonWorkspace")?.scrollIntoView({ block: "start" })}>Настроить Sysmon</button> : <label><input type="checkbox" aria-label={action.title} checked={selected.includes(action.id)} disabled={!status?.executor_available || busy} onChange={(event) => setSelected((values) => event.target.checked ? [...values, action.id] : values.filter((value) => value !== action.id))} /> Выбрать</label>}</header><p>{action.description}</p><details className="auditCommands"><summary>Команды и параметры</summary><div className="commandPreview">{action.apply.map((command, commandIndex) => <code key={commandIndex}>{command.program} {command.args.join(" ")}</code>)}</div></details><footer><span>Откат: {action.rollback.kind.replaceAll("_", " ")}</span><b>✓ allowlist</b></footer></article>)}</div></>}
    {message && <div className="privacyNotice">{message}</div>}
    <div className="auditFooter"><div><b>{status?.executor_available ? "Административный helper с UAC" : "Применение отключено"}</b><span>{status?.reason ?? "Проверка платформы…"}</span></div></div>
    {status?.executor_available && <><p>Для применения введите APPLY REDTRACE AUDIT. Для отката — ROLLBACK REDTRACE AUDIT. Если ID отсутствует, откатывается последний защищённый snapshot этого хоста.</p><div className="operationButtons"><input aria-label="Подтверждение изменения аудита" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /><button disabled={busy || selected.length === 0 || confirmation !== "APPLY REDTRACE AUDIT"} onClick={() => void execute(false)}>ПРИМЕНИТЬ ВЫБРАННОЕ</button><button disabled={busy || confirmation !== "ROLLBACK REDTRACE AUDIT"} onClick={() => void execute(true)}>{snapshot ? "ОТКАТИТЬ SNAPSHOT" : "ОТКАТИТЬ ПОСЛЕДНИЙ SNAPSHOT"}</button></div>{snapshot && <p>Snapshot ID: <code>{snapshot}</code></p>}</>}
    {status?.platform_supported && <SysmonWorkspace enabled={Boolean(status.executor_available) && !busy} effective={effective} />}
    {status?.platform_supported && <LogReadWorkspace enabled={Boolean(status.executor_available) && !busy} effective={effective} />}
  </section>;
}

function LogReadWorkspace({ enabled, effective }: { enabled: boolean; effective: AuditEffectiveState | null }) {
  const [confirmation, setConfirmation] = useState("");
  const [snapshot, setSnapshot] = useState(() => typeof window === "undefined" ? "" : localStorage.getItem("redtrace.log_read.snapshot") ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const restoreSnapshot = snapshot || effective?.read_access_snapshot || "";
  const execute = async (restore: boolean) => {
    setBusy(true); setError(""); setMessage("");
    try {
      const report = await executeWindowsAudit(restore ? { operation: "restore_log_read", snapshot_id: restoreSnapshot, confirmation } : { operation: "grant_log_read", confirmation });
      if (report.snapshot_id) { setSnapshot(report.snapshot_id); localStorage.setItem("redtrace.log_read.snapshot", report.snapshot_id); }
      if (!report.success) throw new Error(report.error ?? "Channel access operation failed");
      setMessage(restore ? "Исходные ACL журналов восстановлены" : "Текущему пользователю разрешено чтение Security и Sysmon");
      setConfirmation("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  return <section className="logReadWorkspace"><div className="operationsHeader"><div><span>ПРАВА СЕНСОРА</span><h2>Read-only доступ к Security и Sysmon</h2><p>Право read выдаётся только пользователю desktop-процесса. Write/clear не выдаются. Исходные ACL сохраняются; restore проверяет конфликт с последующими изменениями.</p></div></div>
    {error && <div className="operationError">{error}</div>}{message && <div className="privacyNotice">{message}</div>}
    <p>GRANT REDTRACE LOG READ — выдать чтение. RESTORE REDTRACE LOG READ — восстановить ACL.</p><div className="operationButtons"><input aria-label="Подтверждение чтения журналов" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /><button disabled={!enabled || busy || confirmation !== "GRANT REDTRACE LOG READ"} onClick={() => void execute(false)}>РАЗРЕШИТЬ READ-ONLY</button><button disabled={!enabled || busy || !restoreSnapshot || confirmation !== "RESTORE REDTRACE LOG READ"} onClick={() => void execute(true)}>ВОССТАНОВИТЬ ACL</button></div>
    {restoreSnapshot && <p>ACL snapshot ID: <code>{restoreSnapshot}</code></p>}
  </section>;
}

function SysmonWorkspace({ enabled, effective }: { enabled: boolean; effective: AuditEffectiveState | null }) {
  const [path, setPath] = useState("");
  const [preview, setPreview] = useState<SysmonPreview | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [snapshot, setSnapshot] = useState(() => typeof window === "undefined" ? "" : localStorage.getItem("redtrace.sysmon.snapshot") ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const removeSnapshot = snapshot || effective?.sysmon_snapshot || "";
  const check = async () => {
    setBusy(true); setError(""); setPreview(null);
    try { setPreview(await previewSysmon(path)); }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const execute = async (remove: boolean) => {
    if (!remove && !preview) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const request = remove ? { operation: "remove_sysmon", snapshot_id: removeSnapshot, confirmation } : { operation: "install_sysmon", binary_sha256: preview!.sha256, binary_length: preview!.binary_length, confirmation };
      const report = await executeWindowsAudit(request);
      if (report.snapshot_id) { setSnapshot(report.snapshot_id); localStorage.setItem("redtrace.sysmon.snapshot", report.snapshot_id); }
      if (!report.success) throw new Error(report.error ?? "Sysmon operation failed");
      setMessage(remove ? "Sysmon удалён; отсутствие службы проверено" : "Sysmon установлен; служба работает");
      if (preview) setPreview({ ...preview, installed: !remove });
      setConfirmation("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  return <section className="sysmonWorkspace">
    <div className="operationsHeader"><div><span>MICROSOFT SYSMON</span><h2>Проверенный бинарник и профиль</h2><p>Windows 11 / Server 2019+. Поддерживается одобренный Microsoft Sysmon 15.22. Существующая установка не заменяется.</p></div></div>
    <div className="operationButtons"><input aria-label="Путь к Sysmon64.exe" placeholder="C:\...\Sysmon64.exe" value={path} onChange={(event) => { setPath(event.target.value); setPreview(null); }} /><button disabled={busy || !path} onClick={() => void check()}>ПРОВЕРИТЬ SYSMON</button></div>
    {error && <div className="operationError">{error}</div>}
    {preview && <><div className="privacyNotice"><b>Authenticode: {preview.signature} · {preview.publisher}</b><code>SHA-256: {preview.sha256}</code><span>Версия {preview.version} · Config SHA-256: {preview.configuration_sha256}</span></div><pre className="commandPreview">{preview.configuration}</pre><p>Создаются служба и boot-start драйвер. Process command line и DNS могут содержать чувствительные данные. INSTALL REDTRACE SYSMON подтверждает установку и принятие EULA Microsoft Sysinternals.</p></>}
    {message && <div className="privacyNotice">{message}</div>}
    {effective?.sysmon_installed && <p>Sysmon уже установлен. Существующая служба не заменяется.</p>}
    <div className="operationButtons"><input aria-label="Подтверждение Sysmon" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /><button disabled={!enabled || busy || !preview || preview.installed || effective?.sysmon_installed || confirmation !== "INSTALL REDTRACE SYSMON"} onClick={() => void execute(false)}>УСТАНОВИТЬ SYSMON</button><button disabled={!enabled || busy || !removeSnapshot || confirmation !== "REMOVE REDTRACE SYSMON"} onClick={() => void execute(true)}>УДАЛИТЬ ЭКЗЕМПЛЯР REDTRACE</button></div>
    {removeSnapshot && <p>Sysmon snapshot ID: <code>{removeSnapshot}</code></p>}
  </section>;
}

export function DiagnosticsWorkspace() {
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  const [error, setError] = useState("");
  const refresh = () => void getDiagnostics().then(setDiagnostics).catch((reason) => setError(reason instanceof Error ? reason.message : "Диагностика недоступна"));
  useEffect(refresh, []);
  const download = () => {
    if (!diagnostics) return;
    const blob = new Blob([JSON.stringify(diagnostics, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `redtrace-diagnostics-${new Date().toISOString().replaceAll(":", "-")}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  return <section className="operationsWorkspace diagnosticsWorkspace">
    <div className="operationsHeader"><div><span>ПОДДЕРЖКА</span><h2>Локальная диагностика</h2><p>Техническое состояние без содержимого событий, пользовательских имён и путей.</p></div><div className="operationButtons"><button onClick={refresh}>↻ ОБНОВИТЬ</button><button onClick={download} disabled={!diagnostics}>⇩ СОХРАНИТЬ ОТЧЁТ</button></div></div>
    {diagnostics && <p className="diagnosticTimestamp">Снимок состояния: {diagnostics.generated_at}. Кнопка «Обновить» создаёт новый снимок.</p>}
    {error && <div className="operationError">{error}</div>}
    {diagnostics && <><div className="privacyProof"><i>✓</i><div><b>Отчёт безопасен для предварительной передачи в поддержку</b><span>События: нет · пути: нет · пользователи: нет</span></div></div><div className="diagnosticGrid"><article><h3>ПРИЛОЖЕНИЕ</h3><dl><div><dt>Версия</dt><dd>{diagnostics.application.version}</dd></div><div><dt>ОС</dt><dd>{diagnostics.application.target_os}</dd></div><div><dt>Архитектура</dt><dd>{diagnostics.application.target_arch}</dd></div><div><dt>Данные</dt><dd>{diagnostics.application.data_mode}</dd></div></dl></article><article><h3>ХРАНИЛИЩЕ</h3><dl>{Object.entries(diagnostics.storage).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl></article><article><h3>INGESTION</h3><dl>{Object.entries(diagnostics.ingestion).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value ?? "—"}</dd></div>)}</dl></article></div></>}
  </section>;
}
