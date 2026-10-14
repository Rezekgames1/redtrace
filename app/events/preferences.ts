import { DEFAULT_COLUMNS, normalizeColumns } from "./columns.ts";

export const PREFERENCES_KEY = "redtrace.event-preferences.v1";
export const MAX_VIEWS = 32;
export type SearchMode = "contains" | "dsl";
export type SavedView = { id: string; name: string; query: string; mode: SearchMode; columns: string[] };
export type EventPreferences = { version: 1; columns: string[]; views: SavedView[] };
export const DEFAULT_PREFERENCES: EventPreferences = { version: 1, columns: DEFAULT_COLUMNS, views: [] };

function validView(value: unknown): value is SavedView {
  if (!value || typeof value !== "object") return false;
  const view = value as Record<string, unknown>;
  return typeof view.id === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(view.id)
    && typeof view.name === "string" && view.name.trim().length > 0 && view.name.length <= 64
    && typeof view.query === "string" && view.query.length <= 4096
    && (view.mode === "contains" || view.mode === "dsl") && Array.isArray(view.columns);
}

export function parsePreferences(raw: string | null): EventPreferences {
  if (!raw || raw.length > 262144) return DEFAULT_PREFERENCES;
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== "object") return DEFAULT_PREFERENCES;
    const prefs = value as Record<string, unknown>;
    if (prefs.version !== 1) return DEFAULT_PREFERENCES;
    const seen = new Set<string>();
    const views = Array.isArray(prefs.views) ? prefs.views.filter(validView).filter((view) => {
      if (seen.has(view.id)) return false;
      seen.add(view.id);
      return true;
    }).slice(0, MAX_VIEWS).map((view) => ({ id: view.id, name: view.name.trim(), query: view.query, mode: view.mode, columns: normalizeColumns(view.columns) })) : [];
    return { version: 1, columns: normalizeColumns(prefs.columns), views };
  } catch {
    return DEFAULT_PREFERENCES;
  }
}

export function saveView(prefs: EventPreferences, view: SavedView): EventPreferences {
  if (!validView(view)) throw new Error("Имя представления — 1–64 символа, запрос — до 4096 символов");
  if (prefs.views.some((existing) => existing.id !== view.id && existing.name.toLocaleLowerCase() === view.name.trim().toLocaleLowerCase())) throw new Error("Представление с таким именем уже существует");
  const exists = prefs.views.some((existing) => existing.id === view.id);
  if (!exists && prefs.views.length >= MAX_VIEWS) throw new Error("Можно сохранить не более 32 представлений");
  const saved = { ...view, name: view.name.trim(), columns: normalizeColumns(view.columns) };
  return { ...prefs, views: exists ? prefs.views.map((existing) => existing.id === saved.id ? saved : existing) : [...prefs.views, saved] };
}

let cachedRaw: string | null | undefined;
let cachedPreferences = DEFAULT_PREFERENCES;
const listeners = new Set<() => void>();

export function getPreferences(): EventPreferences {
  if (typeof window === "undefined") return DEFAULT_PREFERENCES;
  let raw: string | null;
  try { raw = window.localStorage.getItem(PREFERENCES_KEY); } catch { return DEFAULT_PREFERENCES; }
  if (raw !== cachedRaw) { cachedRaw = raw; cachedPreferences = parsePreferences(raw); }
  return cachedPreferences;
}

export function serverPreferences(): EventPreferences {
  return DEFAULT_PREFERENCES;
}

export function subscribePreferences(listener: () => void): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => { if (event.key === PREFERENCES_KEY || event.key === null) listener(); };
  window.addEventListener("storage", onStorage);
  return () => { listeners.delete(listener); window.removeEventListener("storage", onStorage); };
}

export function writePreferences(preferences: EventPreferences): void {
  const raw = JSON.stringify(preferences);
  if (raw.length > 262144) throw new Error("Превышен размер настроек представлений");
  try { window.localStorage.setItem(PREFERENCES_KEY, raw); } catch { throw new Error("Не удалось сохранить настройки в локальном хранилище"); }
  cachedRaw = undefined;
  for (const listener of listeners) listener();
}
