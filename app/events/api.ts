import type { DetectionAlert, EventLevel, SearchResult, UiEvent } from "./types";
import { RevisionDecoder } from "./stream";
import { ALL_TIME, timeQuery } from "./time";
import type { TimeFilter } from "./time";

const API_ROOT = "http://127.0.0.1:9710";
let tokenPromise: Promise<string> | null = null;

async function localSessionToken(): Promise<string> {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) return "";
  tokenPromise ??= import("@tauri-apps/api/core")
    .then(({ invoke }) => invoke<string>("api_token"))
    .catch(() => "");
  return tokenPromise;
}

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const token = await localSessionToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("x-redtrace-token", token);
  let response = await fetch(`${API_ROOT}${path}`, { ...init, headers });
  if (response.status === 401 && typeof window !== "undefined" && "__TAURI_INTERNALS__" in window) { tokenPromise = null; headers.set("x-redtrace-token", await localSessionToken()); response = await fetch(`${API_ROOT}${path}`, { ...init, headers }); }
  return response;
}

export type SensorHealth = {
  data_mode: "real";
  events_indexed: number;
  uptime_seconds: number;
  source: {
    name: string;
    state: string;
    events_collected: number;
    lookback: string;
    last_error?: string | null;
  };
  storage: {
    wal_quarantine?: { archives: number; bytes: number; corrupted_records: number; salvageable_records: number };
    wal_bytes: number;
    segment_bytes: number;
    segment_count: number;
    corrupted_records: number;
    corrupted_segments: number;
    corrupted_segment_indexes: number;
    checkpoint_sources: number;
    alert_records: number;
    corrupted_alert_records: number;
  };
  ingestion: {
    queue_depth: number;
    queue_bound: number;
    ingested_total: number;
    dropped_events: number;
    wal_errors: number;
    segment_errors: number;
    checkpoint_errors: number;
    detection_errors: number;
    alerts_created: number;
    last_event_at: string | null;
  };
  remote_ingest?: {
    enabled: boolean;
    bind: string | null;
    agents_total: number;
    agents_active: number;
    remote_events_total: number;
  };
};

export type RemoteAgent = {
  id: string;
  name: string;
  platform: string | null;
  last_seen_unix: number;
  events_received: number;
  revoked: boolean;
  state?: string;
  last_event_at?: string | null;
  delivery_lag_seconds?: number | null;
  token_expires_unix?: number | null;
  config_generation?: number;
  telemetry?: { pending_events: number; spool_bytes: number; spool_limit_bytes: number; oldest_pending_at: string | null; retry_total: number; quarantine_events: number; quarantine_bytes: number; enqueue_refused_total: number; config_generation: number; modules: { id: string; state: string; permissions: string; error: string | null }[] } | null;
};

export async function controlRequest<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const response = await apiFetch(path, { method, ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }) });
  const result = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(result.error ?? `HTTP ${response.status}`);
  return result;
}

export async function downloadBackup(): Promise<Blob> {
  const response = await apiFetch("/api/backup", { method: "POST" });
  if (!response.ok) { const value = await response.json() as { error?: string }; throw new Error(value.error ?? "Резервное копирование не выполнено"); }
  return response.blob();
}

export async function getRemoteAgents(): Promise<RemoteAgent[]> {
  const response = await apiFetch("/api/agents");
  if (!response.ok) throw new Error("Не удалось получить список агентов");
  const data = await response.json() as { agents: RemoteAgent[] };
  return data.agents;
}

export async function createRemoteAgent(name: string): Promise<{ id: string; name: string; token: string }> {
  const response = await apiFetch("/api/agents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!response.ok) throw new Error("Не удалось зарегистрировать агента");
  return response.json();
}

export async function revokeRemoteAgent(id: string): Promise<void> {
  const response = await apiFetch(`/api/agents/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!response.ok) throw new Error("Не удалось отозвать токен агента");
}

export type Diagnostics = {
  generated_at: string;
  application: { name: string; version: string; target_os: string; target_arch: string; data_mode: string };
  source: SensorHealth["source"] & { platform?: string };
  storage: Record<string, number>;
  ingestion: SensorHealth["ingestion"];
  privacy: { contains_event_content: boolean; contains_file_paths: boolean; contains_user_names: boolean };
};

export type WindowsAuditPlan = {
  profile: string;
  requires_administrator: boolean;
  apply_requires_confirmation: boolean;
  privacy_warning: string;
  actions: Array<{
    id: string;
    title: string;
    description: string;
    source_events: string[];
    apply: Array<{ program: string; args: string[] }>;
    rollback: { kind: string };
  }>;
};

export type WindowsAuditStatus = {
  platform_supported: boolean;
  executor_available: boolean;
  mode: string;
  confirmation_text: string;
  reason: string;
};

const COLLECTING_STATES = new Set(["ready", "streaming", "backfilling", "degraded"]);

type ApiEvent = {
  id: number;
  uid: string;
  timestamp: string;
  level: EventLevel;
  source: string;
  message: string;
  fields: Record<string, string>;
};

type ApiSearchResponse = {
  events: ApiEvent[];
  total: number;
  took_micros: number;
  error?: string;
  offset?: number;
  next_cursor?: string | null;
};

type ApiAggregationResponse = {
  hours?: Record<string, number>;
};

export async function isSensorAvailable(): Promise<boolean> {
  try {
    const data = await getSensorHealth();
    return data.data_mode === "real" && COLLECTING_STATES.has(data.source.state);
  } catch {
    return false;
  }
}

export async function getSensorHealth(): Promise<SensorHealth> {
  const response = await apiFetch("/api/health");
  if (!response.ok) throw new Error("Локальный сенсор недоступен");
  return response.json() as Promise<SensorHealth>;
}

export async function subscribeToUpdates(onUpdate: () => void, onConnection: (connected: boolean) => void, signal: AbortSignal): Promise<void> {
  let retry = 500;
  while (!signal.aborted) {
    try {
      const response = await apiFetch("/api/live", { signal, headers: { Accept: "text/event-stream" }, cache: "no-store" });
      if (!response.ok || !response.body || !response.headers.get("content-type")?.startsWith("text/event-stream")) throw new Error("Live stream unavailable");
      onConnection(true);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const frames = new RevisionDecoder();
      try {
        while (!signal.aborted) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const revision of frames.push(decoder.decode(value, { stream: true }))) {
            if (revision >= 0) { retry = 500; onUpdate(); }
          }
        }
      } finally {
        await reader.cancel().catch(() => undefined);
        reader.releaseLock();
      }
    } catch {
      if (signal.aborted) return;
    }
    if (signal.aborted) return;
    onConnection(false);
    await new Promise<void>((resolve) => {
      const finish = () => { window.clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
      const timer = window.setTimeout(finish, retry);
      signal.addEventListener("abort", finish, { once: true });
      if (signal.aborted) finish();
    });
    retry = Math.min(retry * 2, 10000);
  }
}

export async function collectLocalEvents(): Promise<void> {
  const response = await apiFetch("/api/collect", { method: "POST" });
  if (!response.ok) {
    const data = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(data.error ?? "Не удалось обновить локальные журналы");
  }
}

export async function getLocalAlerts(): Promise<{ alerts: DetectionAlert[]; total: number }> {
  const response = await apiFetch("/api/alerts?limit=500");
  if (!response.ok) throw new Error("Не удалось получить локальные алерты");
  return response.json() as Promise<{ alerts: DetectionAlert[]; total: number }>;
}

export async function exportLocalEvents(query: string, format: "json" | "jsonl" | "csv" = "json", time: TimeFilter = ALL_TIME): Promise<Blob> {
  const response = await apiFetch(`/api/export?q=${encodeURIComponent(query)}&format=${format}&limit=10000${timeQuery(time)}`);
  if (!response.ok) {
    const data = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(data.error ?? "Не удалось экспортировать события");
  }
  return response.blob();
}

export async function getDiagnostics(): Promise<Diagnostics> {
  const response = await apiFetch("/api/diagnostics");
  if (!response.ok) throw new Error("Диагностика недоступна");
  return response.json() as Promise<Diagnostics>;
}

export async function getWindowsAudit(): Promise<{ plan: WindowsAuditPlan; status: WindowsAuditStatus }> {
  const [planResponse, statusResponse] = await Promise.all([
    apiFetch("/api/audit/windows/plan"),
    apiFetch("/api/audit/windows/status"),
  ]);
  if (!planResponse.ok || !statusResponse.ok) throw new Error("Профиль аудита недоступен");
  const result = {
    plan: await planResponse.json() as WindowsAuditPlan,
    status: await statusResponse.json() as WindowsAuditStatus,
  };
  if (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window && result.status.platform_supported) {
    const { invoke } = await import("@tauri-apps/api/core");
    const helper = await invoke<Pick<WindowsAuditStatus, "executor_available" | "mode" | "reason">>("audit_helper_status");
    result.status = { ...result.status, ...helper };
  }
  return result;
}

export type AuditHelperResponse = {
  success: boolean;
  snapshot_id: string | null;
  verified: boolean;
  error: string | null;
  state?: AuditEffectiveState | null;
};

export type AuditEffectiveState = {
  policy: Record<string, number>;
  process_command_line: { present: boolean; kind: number | null; dword: number | null };
  powershell_script_block: { present: boolean; kind: number | null; dword: number | null };
  sysmon_installed: boolean;
  audit_snapshot: string | null;
  read_access_snapshot: string | null;
  sysmon_snapshot: string | null;
};

export type SysmonPreview = {
  version: string;
  publisher: string;
  signature: string;
  sha256: string;
  binary_length: number;
  configuration: string;
  configuration_sha256: string;
  installed: boolean;
};

export async function previewSysmon(binaryPath: string): Promise<SysmonPreview> {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) throw new Error("Sysmon preview доступен в Windows desktop");
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<SysmonPreview>("sysmon_preview", { binaryPath });
}

export async function executeWindowsAudit(request: Record<string, unknown>): Promise<AuditHelperResponse> {
  if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) throw new Error("Применение аудита доступно только в desktop-оболочке");
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<AuditHelperResponse>("audit_execute", { request });
}

export async function searchLocalEvents(query: string, cursor?: string | null, includeAggregations = false, time: TimeFilter = ALL_TIME): Promise<SearchResult> {
  const timeParams = timeQuery(time);
  const cursorQuery = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
  const response = await apiFetch(`/api/search?q=${encodeURIComponent(query)}&limit=100${cursorQuery}${timeParams}`);
  const data = (await response.json()) as ApiSearchResponse;

  if (!response.ok) {
    const position = typeof data.offset === "number" ? ` · позиция ${data.offset}` : "";
    throw new Error(`${data.error ?? "Ошибка запроса"}${position}`);
  }

  const events: UiEvent[] = data.events.map((item) => ({
    uid: item.uid,
    time: item.timestamp.slice(11, 23),
    level: item.level,
    source: item.source,
    title: item.message,
    fields: {
      "@timestamp": item.timestamp,
      "source": item.source,
      "uid": item.uid,
      "event.description": item.message,
      "process.command_line": item.fields["process.command_line"] ?? "н/д",
      "process.pid": item.fields["process.pid"] ?? "н/д",
      "process.parent.pid": item.fields["process.parent.pid"] ?? "н/д",
      ...item.fields,
    },
    get raw() { return JSON.stringify(item, null, 2); },
  }));

  let hours: number[] = [];
  if (!cursor && includeAggregations) {
    const aggregation = await apiFetch(`/api/aggregations?q=${encodeURIComponent(query)}${timeParams}`);
    if (aggregation.ok) {
      const payload = await aggregation.json() as ApiAggregationResponse;
      hours = Array.from({ length: 24 }, () => 0);
      for (const [hour, count] of Object.entries(payload.hours ?? {})) {
        const index = Number(hour.slice(-2));
        if (Number.isInteger(index) && index >= 0 && index < 24) hours[index] += count;
      }
    }
  }

  return {
    events,
    total: data.total,
    took: `${data.took_micros} мкс`,
    nextCursor: data.next_cursor ?? null,
    hours,
  };
}
