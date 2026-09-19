import type { EventLevel, SearchResult, UiEvent } from "./types";

const API_ROOT = "http://127.0.0.1:9710";

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
    wal_bytes: number;
    corrupted_records: number;
  };
};

type ApiEvent = {
  id: number;
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
};

export async function isSensorAvailable(): Promise<boolean> {
  try {
    const data = await getSensorHealth();
    return data.data_mode === "real" && data.source.state === "ready";
  } catch {
    return false;
  }
}

export async function getSensorHealth(): Promise<SensorHealth> {
  const response = await fetch(`${API_ROOT}/api/health`);
  if (!response.ok) throw new Error("Локальный сенсор недоступен");
  return response.json() as Promise<SensorHealth>;
}

export async function collectLocalEvents(): Promise<void> {
  const response = await fetch(`${API_ROOT}/api/collect`, { method: "POST" });
  if (!response.ok) {
    const data = await response.json().catch(() => ({})) as { error?: string };
    throw new Error(data.error ?? "Не удалось обновить локальные журналы");
  }
}

export async function searchLocalEvents(query: string): Promise<SearchResult> {
  const response = await fetch(`${API_ROOT}/api/search?q=${encodeURIComponent(query)}&limit=100`);
  const data = (await response.json()) as ApiSearchResponse;

  if (!response.ok) {
    const position = typeof data.offset === "number" ? ` · позиция ${data.offset}` : "";
    throw new Error(`${data.error ?? "Ошибка запроса"}${position}`);
  }

  const events: UiEvent[] = data.events.map((item) => ({
    uid: item.id,
    time: item.timestamp.slice(11, 23),
    level: item.level,
    source: item.source,
    title: item.message,
    fields: {
      "event.description": item.message,
      "process.command_line": item.fields["process.command_line"] ?? "н/д",
      "process.pid": item.fields["process.pid"] ?? "н/д",
      "process.parent.pid": item.fields["process.parent.pid"] ?? "н/д",
      ...item.fields,
    },
    raw: JSON.stringify(item, null, 2),
  }));

  return { events, total: data.total, took: `${data.took_micros} мкс` };
}
