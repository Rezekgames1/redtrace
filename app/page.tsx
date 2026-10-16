"use client";

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from "react";
import { exportLocalEvents, getLocalAlerts, getSensorHealth, searchLocalEvents, subscribeToUpdates, controlRequest } from "./events/api";
import type { SensorHealth } from "./events/api";
import type { DetectionAlert, EventLevel, UiEvent } from "./events/types";
import { AuditWorkspace, DiagnosticsWorkspace, SourcesWorkspace } from "./operations";
import { SettingsWorkspace, RulesWorkspace, CasesWorkspace } from "./control-workspaces";
import { appendFilter, quoteValue, valueFilter } from "./events/query";
import { EventRow } from "./events/row";
import { columnInfo, columnLayout, normalizeColumns } from "./events/columns";
import { getPreferences, serverPreferences, subscribePreferences, writePreferences, saveView } from "./events/preferences";
import type { SearchMode, SavedView } from "./events/preferences";
import { PreferencesPanel } from "./events/preferences-panel";
import { AutocompleteInput } from "./events/autocomplete-input";
import { buildSuggestionCatalog, containsSuggestions, fieldSuggestions, querySuggestions, valueSuggestions } from "./events/suggestions";
import type { TimeFilter } from "./events/time";

const selectedFields = ["@timestamp", "event.id", "event.description", "source", "process.command_line", "process.pid", "process.parent.pid"];
const initialTimeFilter: TimeFilter = { preset: "15m", from: "", to: "" };
type Workspace = "events" | "alerts" | "sources" | "audit" | "diagnostics" | "settings" | "rules" | "cases";

function workspaceTitle(workspace: Workspace): string {
  return { events: "Журнал событий", alerts: "Алерты", sources: "Источники", audit: "Настройка аудита", diagnostics: "Диагностика", settings: "Настройки SIEM", rules: "Правила", cases: "Расследования" }[workspace];
}

function streamLabel(health: SensorHealth | null): string {
  if (!health) return "ЛОКАЛЬНЫЙ СБОР АКТИВЕН";
  if (health.source.state === "backfilling") return "ЗАГРУЗКА ЖУРНАЛОВ";
  if (health.source.state === "streaming") return "ПОТОК СОБЫТИЙ АКТИВЕН";
  if (health.source.state === "degraded") return "СБОР АКТИВЕН · ЧАСТЬ КАНАЛОВ НЕДОСТУПНА";
  if (health.source.state === "disabled") return "ЛОКАЛЬНЫЙ ИСТОЧНИК ОТКЛЮЧЁН";
  if (health.source.state === "error") return "ОШИБКА ЛОКАЛЬНОГО ИСТОЧНИКА";
  return "ЛОКАЛЬНЫЙ СБОР АКТИВЕН";
}

function lookbackLabel(value?: string): string {
  const compact = value?.replace(" + stream", "") ?? "15m";
  if (compact.endsWith("m")) return `${compact.slice(0, -1)} минут`;
  if (compact.endsWith("h")) return `${compact.slice(0, -1)} часов`;
  if (compact.endsWith("d")) return `${compact.slice(0, -1)} дней`;
  return compact;
}

export default function Home() {
  const [query, setQuery] = useState("");
  const [timeFilter, setTimeFilter] = useState<TimeFilter>(initialTimeFilter);
  const timeRef = useRef<TimeFilter>(initialTimeFilter);
  const [queryCaret, setQueryCaret] = useState(0);
  const [appliedQuery, setAppliedQuery] = useState("*");
  const [searchMode, setSearchMode] = useState<"contains" | "dsl">("contains");
  const [appliedSearch, setAppliedSearch] = useState<{ query: string; mode: SearchMode }>({ query: "", mode: "contains" });
  const [preferencesSection, setPreferencesSection] = useState<"views" | "columns" | null>(null);
  const [preferencesMessage, setPreferencesMessage] = useState("");
  const preferences = useSyncExternalStore(subscribePreferences, getPreferences, serverPreferences);
  const [filterOpen, setFilterOpen] = useState(false);
  const [filterField, setFilterField] = useState("event.id");
  const [filterValue, setFilterValue] = useState("");
  const [filterOperator, setFilterOperator] = useState<"exact" | "contains" | "exists">("exact");
  const [filterExclude, setFilterExclude] = useState(false);
  const [events, setEvents] = useState<UiEvent[]>([]);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [alertTotal, setAlertTotal] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const [workspace, setWorkspace] = useState<Workspace>("events");
  const [alertSeverity, setAlertSeverity] = useState<"all" | EventLevel>("all");
  const [selectedId, setSelectedId] = useState("0");
  const [fieldSearch, setFieldSearch] = useState("");
  const [total, setTotal] = useState(0);
  const [took, setTook] = useState("—");
  const [online, setOnline] = useState(false);
  const [health, setHealth] = useState<SensorHealth | null>(null);
  const [searching, setSearching] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [queryError, setQueryError] = useState("");
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hourCounts, setHourCounts] = useState<number[]>([]);
  const [detailTab, setDetailTab] = useState<"summary" | "fields" | "raw">("summary");
  const [fieldsOpen, setFieldsOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [fieldsWidth, setFieldsWidth] = useState(260);
  const [detailsWidth, setDetailsWidth] = useState(400);
  const [histogramOpen, setHistogramOpen] = useState(false);
  const [alertOverviewOpen, setAlertOverviewOpen] = useState(false);
  const [liveEnabled, setLiveEnabled] = useState(true);
  const [liveConnected, setLiveConnected] = useState(false);
  const [hasUpdates, setHasUpdates] = useState(false);
  const [inspectedEvent, setInspectedEvent] = useState<UiEvent | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);
  const [investigating, setInvestigating] = useState(false);
  const investigationRef = useRef(false);
  const queryRef = useRef("*");
  const indexedRef = useRef(-1);
  const observedCountRef = useRef(-1);
  const alertsRef = useRef(-1);
  const liveRef = useRef(true);
  const eventsVisibleRef = useRef(true);
  const histogramRef = useRef(false);
  const needsSearchRef = useRef(true);
  const revisionRef = useRef(0);
  const generationRef = useRef(0);
  const manualBusyRef = useRef(false);
  const requestSyncRef = useRef<() => void>(() => undefined);
  const streamRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const selected = inspectedEvent ?? events.find((event) => event.uid === selectedId) ?? events[0];
  const selectedAlert = alerts.find((alert) => alert.id === selectedAlertId) ?? alerts[0];
  const visibleAlerts = useMemo(() => alertSeverity === "all" ? alerts : alerts.filter((alert) => alert.severity === alertSeverity), [alerts, alertSeverity]);
  const fieldCatalog = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of events) for (const field of Object.keys(event.fields)) counts.set(field, (counts.get(field) ?? 0) + 1);
    return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [events]);
  const visibleFields = useMemo(() => fieldCatalog.filter(([name]) => name.includes(fieldSearch.toLowerCase())), [fieldCatalog, fieldSearch]);
  const suggestionCatalog = useMemo(() => buildSuggestionCatalog(events), [events]);
  const queryOptions = useMemo(() => searchMode === "dsl" ? querySuggestions(query, queryCaret, suggestionCatalog) : containsSuggestions(query, suggestionCatalog), [searchMode, query, queryCaret, suggestionCatalog]);
  const filterFieldOptions = useMemo(() => fieldSuggestions(filterField, suggestionCatalog), [filterField, suggestionCatalog]);
  const filterValueOptions = useMemo(() => valueSuggestions(filterField, filterValue, suggestionCatalog), [filterField, filterValue, suggestionCatalog]);
  const histogram = useMemo(() => {
    const buckets = Array.from({ length: 24 }, (_, index) => hourCounts[index] ?? 0);
    const peak = Math.max(...buckets, 1);
    return buckets.map((value) => value === 0 ? 0 : Math.max(3, Math.round((value / peak) * 92)));
  }, [hourCounts]);
  const detailFields = useMemo<Record<string, string>>(() => selected ? {
    "event.description": selected.title,
    "process.command_line": selected.fields["process.command_line"] ?? "н/д",
    "process.pid": selected.fields["process.pid"] ?? "н/д",
    "process.parent.pid": selected.fields["process.parent.pid"] ?? "н/д",
    ...selected.fields,
  } : {}, [selected]);
  const summaryFields = Object.entries(detailFields).filter(([name, value]) => ["@timestamp", "source", "event.id", "event.outcome", "user.name", "source.ip", "process.command_line", "process.executable"].includes(name) && value !== "н/д");
  const explorerStyle = {
    "--fields-width": `${fieldsWidth}px`,
    "--details-width": `${detailsWidth}px`,
  } as CSSProperties;

  useEffect(() => {
    let active = true;
    let busy = false;
    let again = false;
    let connected = false;
    let timer: number | undefined;
    let lastHealth = 0;
    const controller = new AbortController();
    const schedule = () => {
      again = true;
      if (timer !== undefined || !active) return;
      timer = window.setTimeout(() => { timer = undefined; void synchronize(); }, 250);
    };
    requestSyncRef.current = schedule;
    const synchronize = async () => {
      if (!active || (document.hidden && Date.now() - lastHealth < 15000)) return;
      if (busy || manualBusyRef.current) { again = true; return; }
      busy = true;
      again = false;
      try {
        const nextHealth = await getSensorHealth();
        if (!active) return;
        lastHealth = Date.now();
        observedCountRef.current = nextHealth.events_indexed;
        setHealth(nextHealth);
        setOnline(true);
        if (alertsRef.current !== nextHealth.storage.alert_records) {
          const result = await getLocalAlerts();
          if (!active) return;
          alertsRef.current = nextHealth.storage.alert_records;
          setAlerts(result.alerts);
          setAlertTotal(result.total);
          setSelectedAlertId((current) => result.alerts.some((alert) => alert.id === current) ? current : (result.alerts[0]?.id ?? ""));
        }
        if (!eventsVisibleRef.current) return;
        if (manualBusyRef.current) { again = true; return; }
        if (needsSearchRef.current || indexedRef.current !== nextHealth.events_indexed) {
          if (!liveRef.current) { setHasUpdates(true); return; }
          const generation = generationRef.current;
          const revision = revisionRef.current;
          const result = await searchLocalEvents(queryRef.current, null, histogramRef.current, timeRef.current);
          if (!active || manualBusyRef.current || generation !== generationRef.current) return;
          indexedRef.current = nextHealth.events_indexed;
          needsSearchRef.current = revision !== revisionRef.current;
          setHasUpdates(false);
          setEvents((current) => {
            const known = new Map(current.map((event) => [event.uid, event]));
            if (current.length === result.events.length && current.every((event, index) => event.uid === result.events[index].uid)) return current;
            return result.events.map((event) => known.get(event.uid) ?? event);
          });
          setTotal(result.total);
          setTook(result.took);
          setNextCursor(result.nextCursor);
          if (result.hours.length) setHourCounts(result.hours);
          setSelectedId((current) => result.events.some((event) => event.uid === current) ? current : (result.events[0]?.uid ?? "0"));
        }
      } catch {
        if (active) setOnline(false);
      } finally {
        busy = false;
        if (again && active) schedule();
      }
    };
    void synchronize();
    void subscribeToUpdates(() => {
      if (!active) return;
      revisionRef.current += 1;
      needsSearchRef.current = true;
      schedule();
    }, (value) => { connected = value; if (active) setLiveConnected(value); }, controller.signal);
    const fallback = window.setInterval(() => {
      if (!connected || Date.now() - lastHealth >= 15000) schedule();
    }, 2500);
    const visible = () => { if (!document.hidden) schedule(); };
    document.addEventListener("visibilitychange", visible);
    window.addEventListener("online", schedule);
    return () => { active = false; controller.abort(); window.clearTimeout(timer); window.clearInterval(fallback); document.removeEventListener("visibilitychange", visible); window.removeEventListener("online", schedule); requestSyncRef.current = () => undefined; };
  }, []);

  useEffect(() => {
    eventsVisibleRef.current = workspace === "events";
    if (workspace === "events") requestSyncRef.current();
  }, [workspace]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); searchInputRef.current?.focus(); }
      if (event.key === "Escape") { setFilterOpen(false); setFieldsOpen(false); setDetailsOpen(false); setPreferencesSection(null); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  function compiledQuery() {
    return searchMode === "contains" && query.trim() && query.trim() !== "*" ? quoteValue(query) : query.trim() || "*";
  }

  async function runSearch(nextQuery = compiledQuery(), search = nextQuery === compiledQuery() ? { query, mode: searchMode } : { query: nextQuery === "*" ? "" : nextQuery, mode: "dsl" as SearchMode }) {
    const generation = ++generationRef.current;
    const revision = revisionRef.current;
    manualBusyRef.current = true;
    setSearching(true);
    setQueryError("");
    try {
      const result = await searchLocalEvents(nextQuery, null, histogramRef.current, timeFilter);
      if (generation !== generationRef.current) return;
      queryRef.current = nextQuery;
      timeRef.current = timeFilter;
      setAppliedQuery(nextQuery);
      setAppliedSearch(search);
      needsSearchRef.current = revision !== revisionRef.current;
      if (!needsSearchRef.current) indexedRef.current = observedCountRef.current;
      setEvents(result.events);
      setTotal(result.total);
      setTook(result.took);
      setNextCursor(result.nextCursor);
      if (result.hours.length) setHourCounts(result.hours);
      setSelectedId(result.events[0]?.uid ?? "0");
      setInspectedEvent(null);
      setDetailsOpen(false);
      setHasUpdates(false);
      if (streamRef.current) streamRef.current.scrollTop = 0;
      setOnline(true);
    } catch (error) {
      if (generation === generationRef.current) setQueryError(error instanceof Error ? error.message : "Поиск недоступен");
    } finally {
      if (generation === generationRef.current) { manualBusyRef.current = false; setSearching(false); requestSyncRef.current(); }
    }
  }

  async function openAlerts() {
    setWorkspace("alerts");
    setQueryError("");
    try {
      const result = await getLocalAlerts();
      setAlerts(result.alerts);
      setAlertTotal(result.total);
      setSelectedAlertId((current) => result.alerts.some((alert) => alert.id === current) ? current : (result.alerts[0]?.id ?? ""));
    } catch (error) {
      setQueryError(error instanceof Error ? error.message : "Алерты недоступны");
    }
  }

  async function loadMoreEvents() {
    if (!nextCursor || searching || events.length >= 1000) return;
    const generation = ++generationRef.current;
    manualBusyRef.current = true;
    liveRef.current = false;
    setLiveEnabled(false);
    setSearching(true);
    try {
      const result = await searchLocalEvents(queryRef.current, nextCursor, false, timeRef.current);
      if (generation !== generationRef.current) return;
      setEvents((current) => {
        const known = new Set(current.map((event) => event.uid));
        return [...current, ...result.events.filter((event) => !known.has(event.uid))];
      });
      setNextCursor(result.nextCursor);
      setTook(result.took);
    } catch (error) {
      if (generation === generationRef.current) setQueryError(error instanceof Error ? error.message : "Пагинация недоступна");
    } finally {
      if (generation === generationRef.current) { setSearching(false); manualBusyRef.current = false; requestSyncRef.current(); }
    }
  }

  function toggleLive() {
    liveRef.current = !liveRef.current;
    setLiveEnabled(liveRef.current);
    if (liveRef.current) { needsSearchRef.current = true; if (streamRef.current) streamRef.current.scrollTop = 0; requestSyncRef.current(); }
  }

  function toggleHistogram() {
    histogramRef.current = !histogramRef.current;
    setHistogramOpen(histogramRef.current);
    if (histogramRef.current) {
      const generation = generationRef.current;
      void searchLocalEvents(queryRef.current, null, true, timeRef.current).then((result) => {
        if (generation === generationRef.current) setHourCounts(result.hours);
      }).catch((error) => setQueryError(error instanceof Error ? error.message : "График недоступен"));
    }
  }

  const inspectEvent = useCallback((event: UiEvent) => {
    setSelectedId(event.uid);
    setInspectedEvent(event);
    setDetailTab("summary");
    setDetailsOpen(true);
  }, []);

  function updateColumns(columns: string[]) {
    try { writePreferences({ ...getPreferences(), columns: normalizeColumns(columns) }); setPreferencesMessage(""); }
    catch (error) { setPreferencesMessage(error instanceof Error ? error.message : "Не удалось сохранить колонки"); }
  }

  function storeView(name: string, id?: string) {
    try {
      const current = getPreferences();
      writePreferences(saveView(current, { id: id ?? crypto.randomUUID(), name, ...appliedSearch, columns: current.columns }));
      setPreferencesMessage("Представление сохранено");
    } catch (error) { setPreferencesMessage(error instanceof Error ? error.message : "Не удалось сохранить представление"); }
  }

  function applyView(view: SavedView) {
    setQuery(view.query);
    setSearchMode(view.mode);
    updateColumns(view.columns);
    setPreferencesSection(null);
    const next = view.mode === "contains" && view.query.trim() && view.query.trim() !== "*" ? quoteValue(view.query) : view.query.trim() || "*";
    void runSearch(next, { query: view.query, mode: view.mode });
  }

  function deleteView(id: string) {
    try { const current = getPreferences(); writePreferences({ ...current, views: current.views.filter((view) => view.id !== id) }); setPreferencesMessage("Представление удалено"); }
    catch (error) { setPreferencesMessage(error instanceof Error ? error.message : "Не удалось удалить представление"); }
  }

  async function exportEvents() {
    setQueryError("");
    let blob: Blob;
    try {
      blob = await exportLocalEvents(queryRef.current, "json", timeRef.current);
    } catch (error) {
      setQueryError(error instanceof Error ? error.message : "Экспорт недоступен");
      return;
    }
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `redtrace-events-${new Date().toISOString().replaceAll(":", "-")}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function copySelectedJson() {
    if (!selected) return;
    try {
      await navigator.clipboard.writeText(selected.raw);
      setCopiedJson(true);
      window.setTimeout(() => setCopiedJson(false), 1500);
    } catch {
      setQueryError("Копирование в буфер недоступно");
    }
  }

  async function investigateAlert() {
    if (!selectedAlert || investigationRef.current) return;
    investigationRef.current = true; setInvestigating(true); setQueryError("");
    try {
      const cases = await controlRequest<{ alert_ids: string[] }[]>("/api/cases");
      if (!cases.some(item => item.alert_ids.includes(selectedAlert.id))) {
        await controlRequest("/api/cases", "PUT", [...cases, { id: crypto.randomUUID(), title: selectedAlert.title.slice(0, 256), status: "open", alert_ids: [selectedAlert.id], evidence: selectedAlert.evidence, notes: "" }]);
      }
      setWorkspace("cases");
    } catch (error) { setQueryError(error instanceof Error ? error.message : "Расследование не создано"); }
    finally { investigationRef.current = false; setInvestigating(false); }
  }

  function filterBy(field: string, value?: string, exclude = false) {
    if (value === undefined) {
      setFilterField(field);
      setFilterOpen(true);
      return;
    }
    const next = appendFilter(compiledQuery(), valueFilter(field, value, "exact", exclude));
    setSearchMode("dsl");
    setQuery(next);
    void runSearch(next);
  }

  function addFilter() {
    if (!/^[a-zA-Z_@][a-zA-Z0-9_.@-]*$/.test(filterField)) {
      setQueryError("Укажите корректное имя поля");
      return;
    }
    const next = appendFilter(compiledQuery(), valueFilter(filterField, filterValue, filterOperator, filterExclude));
    setSearchMode("dsl");
    setQuery(next);
    setFilterOpen(false);
    void runSearch(next);
  }

  async function refreshSourceStatus() {
    setCollecting(true);
    setQueryError("");
    try {
      setHealth(await getSensorHealth());
      requestSyncRef.current();
    } catch (error) {
      setQueryError(error instanceof Error ? error.message : "Сборщик недоступен");
      setOnline(false);
    } finally {
      setCollecting(false);
    }
  }

  function beginPaneResize(side: "fields" | "details", event: ReactPointerEvent<HTMLElement>) {
    if (window.innerWidth <= 820) return;
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = side === "fields" ? fieldsWidth : detailsWidth;
    const update = side === "fields" ? setFieldsWidth : setDetailsWidth;
    const min = side === "fields" ? 190 : 300;
    const max = side === "fields" ? 420 : 560;
    document.body.classList.add("isResizing");
    const onMove = (moveEvent: PointerEvent) => {
      const delta = side === "fields" ? moveEvent.clientX - startX : startX - moveEvent.clientX;
      update(Math.min(max, Math.max(min, startWidth + delta)));
    };
    const onUp = () => {
      document.body.classList.remove("isResizing");
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp, { once: true });
  }

  function resizePaneWithKeyboard(side: "fields" | "details", event: ReactKeyboardEvent<HTMLElement>) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const direction = event.key === "ArrowRight" ? 1 : -1;
    if (side === "fields") setFieldsWidth((width) => Math.min(420, Math.max(190, width + direction * 12)));
    else setDetailsWidth((width) => Math.min(560, Math.max(300, width - direction * 12)));
  }

  return (
    <main className="appShell">
      <aside className="rail" aria-label="Основная навигация">
        <div className="railBrand">R<span>{"//"}</span></div>
        <button className={`railItem ${workspace === "events" ? "active" : ""}`} title="События" onClick={() => setWorkspace("events")}>⌁<small>События</small></button>
        <button className={`railItem ${workspace === "alerts" ? "active" : ""}`} title="Обнаружения" onClick={() => void openAlerts()}>◇{alertTotal > 0 && <i>{Math.min(alertTotal, 99)}</i>}<small>Детекты</small></button>
        <button className={`railItem ${workspace === "sources" ? "active" : ""}`} title="Источники" onClick={() => setWorkspace("sources")}>▦<small>Источники</small></button>
        <button className={`railItem ${workspace === "audit" ? "active" : ""}`} title="Аудит" onClick={() => setWorkspace("audit")}>⚙<small>Аудит</small></button>
        <button className={`railItem ${workspace === "rules" ? "active" : ""}`} title="Правила" onClick={() => setWorkspace("rules")}>≡<small>Правила</small></button>
        <button className={`railItem ${workspace === "cases" ? "active" : ""}`} title="Расследования" onClick={() => setWorkspace("cases")}>▤<small>Кейсы</small></button>
        <button className={`railItem ${workspace === "settings" ? "active" : ""}`} title="Настройки SIEM" onClick={() => setWorkspace("settings")}>⚒<small>Настройки</small></button>
        <span className="railSpacer" />
        <button className={`railItem ${workspace === "diagnostics" ? "active" : ""}`} title="Диагностика" onClick={() => setWorkspace("diagnostics")}>⋮<small>Диагн.</small></button>
      </aside>

      <section className="application">
        <header className="topbar">
          <div className="product"><b>RED<span>{"//"}</span>TRACE</b><em>LOCAL SIEM</em></div>
          <div className={`sensor ${online ? "" : "demo"}`}><i/><span><b>{online ? streamLabel(health) : "ИСТОЧНИК НЕДОСТУПЕН"}</b><small>{health?.source.name ?? "Этот компьютер · системные журналы"}</small></span></div>
          <div className="topActions"><button onClick={() => void exportEvents()} disabled={!events.length && !total}>Экспорт JSON</button></div>
        </header>

        <section className="searchWorkspace">
          <div className="workspaceTitle"><div><h1>{workspaceTitle(workspace)}</h1>{(workspace === "events" || workspace === "alerts") && <em><b>{(workspace === "events" ? total : alertTotal).toLocaleString("ru-RU")}</b> {workspace === "events" ? "событий" : "алертов"}</em>}</div>{(workspace === "events" || workspace === "alerts") && <div className="paneActions"><button aria-expanded={fieldsOpen} onClick={() => setFieldsOpen((open) => !open)}>{workspace === "events" ? "Поля" : "Фильтры"}</button><button aria-expanded={detailsOpen} onClick={() => { if (workspace === "events" && selected) setInspectedEvent(selected); setDetailsOpen((open) => !open); }} disabled={workspace === "events" ? !selected : !selectedAlert}>Детали</button></div>}</div>

          {workspace === "events" ? <><div className="queryRow">
            <select aria-label="Режим поиска" value={searchMode} onChange={(event) => setSearchMode(event.target.value as "contains" | "dsl")}><option value="contains">Все поля · contains</option><option value="dsl">Поля · DSL</option></select>
            <div className={`queryInput ${queryError ? "invalid" : ""}`}><span>⌕</span><AutocompleteInput inputRef={searchInputRef} value={query} suggestions={queryOptions} onCaretChange={setQueryCaret} placeholder={searchMode === "contains" ? "Найти текст в любом поле события…" : 'event.id=4625 AND user.name~"admin"'} onChange={setQuery} onKeyDown={(event) => { if (event.key === "Enter") void runSearch(); }} aria-label="Поисковый запрос"/><kbd>Ctrl K</kbd></div>
            <button className="runButton" onClick={() => void runSearch()} disabled={searching}>{searching ? "ПОИСК…" : "ВЫПОЛНИТЬ"}</button>
          </div>
          <div className="filterRow"><button aria-expanded={filterOpen} onClick={() => setFilterOpen((open) => !open)}>＋ Добавить фильтр</button><details className="searchHelp"><summary>Синтаксис</summary><div><b>Поиск без учёта регистра</b><p><code>event.id=4625</code> — точное значение</p><p><code>{'process.command_line~"ssh"'}</code> — содержит</p><p><code>process.pid:*</code> — поле существует</p><p><code>{'NOT user.name="root"'}</code> — исключить</p><p>AND / OR / NOT, скобки. Пустой запрос — все события.</p></div></details>{compiledQuery() !== appliedQuery && <span className="queryDraft">Нажмите Enter, чтобы применить запрос</span>}<em>{took}</em></div>
          <div className="timeFilterRow">
            <label>Период <select aria-label="Период событий" value={timeFilter.preset} onChange={(event) => setTimeFilter((current) => ({ ...current, preset: event.target.value as TimeFilter["preset"] }))}><option value="all">За всё время</option><option value="15m">Последние 15 минут</option><option value="1h">Последний час</option><option value="24h">Последние 24 часа</option><option value="7d">Последние 7 дней</option><option value="custom">Дата и время…</option></select></label>
            {timeFilter.preset === "custom" && <><label>С <input type="datetime-local" step="1" aria-label="Начало периода" value={timeFilter.from} onChange={(event) => setTimeFilter((current) => ({ ...current, from: event.target.value }))} /></label><label>До <input type="datetime-local" step="1" aria-label="Окончание периода" value={timeFilter.to} onChange={(event) => setTimeFilter((current) => ({ ...current, to: event.target.value }))} /></label></>}
            <span>Локальное время · нажмите «Выполнить»</span>
          </div>
          {queryError && <div className="searchError" role="alert">{queryError}</div>}
          <div className="preferencesActions"><button aria-expanded={preferencesSection === "views"} onClick={() => { setPreferencesSection((section) => section === "views" ? null : "views"); setPreferencesMessage(""); }}>Представления{preferences.views.length ? ` (${preferences.views.length})` : ""}</button><button aria-expanded={preferencesSection === "columns"} onClick={() => { setPreferencesSection((section) => section === "columns" ? null : "columns"); setPreferencesMessage(""); }}>Колонки</button>{preferencesMessage && <span role="status">{preferencesMessage}</span>}</div>
          {preferencesSection && <PreferencesPanel section={preferencesSection} preferences={preferences} fields={fieldCatalog.map(([field]) => field)} onColumns={updateColumns} onSave={storeView} onApply={applyView} onDelete={deleteView} />}
          {filterOpen && <form className="filterBuilder" onSubmit={(event) => { event.preventDefault(); addFilter(); }}>
            <AutocompleteInput aria-label="Поле фильтра" value={filterField} suggestions={filterFieldOptions} onChange={(value) => { setFilterField(value); setFilterValue(""); }} placeholder="Поле" />
            <select aria-label="Оператор фильтра" value={filterOperator} onChange={(event) => setFilterOperator(event.target.value as typeof filterOperator)}><option value="exact">Равно</option><option value="contains">Содержит</option><option value="exists">Существует</option></select>
            <AutocompleteInput aria-label="Значение фильтра" value={filterValue} suggestions={filterValueOptions} onChange={setFilterValue} disabled={filterOperator === "exists"} placeholder="Значение" required={filterOperator !== "exists"} />
            <label><input type="checkbox" checked={filterExclude} onChange={(event) => setFilterExclude(event.target.checked)} /> Исключить</label>
            <button type="submit">Применить</button><button type="button" onClick={() => setFilterOpen(false)}>Отмена</button><small className="filterSuggestionNote">Значения из показанных событий</small>
          </form>}</> : workspace === "alerts" ? <div className="alertSummary"><span>Встроенные и пользовательские правила</span><span><b>{alertTotal}</b> срабатываний</span><span><b>{health?.ingestion.detection_errors ?? 0}</b> ошибок движка</span><em>{queryError || "Только реальные события этого хоста"}</em></div> : null}

          {(workspace === "events" || workspace === "alerts") ? <>
          {(fieldsOpen || detailsOpen) && <button className="drawerScrim" aria-label="Закрыть боковую панель" onClick={() => { setFieldsOpen(false); setDetailsOpen(false); }} />}
          <div className={`explorer cleanExplorer ${fieldsOpen ? "withFields" : ""} ${detailsOpen ? "withDetails" : ""}`} style={explorerStyle}>
            <aside className={`fieldsPane ${fieldsOpen ? "drawerOpen" : ""}`}>
              <div className="paneHeader"><b>{workspace === "events" ? "ПОЛЯ СОБЫТИЙ" : "ФИЛЬТРЫ АЛЕРТОВ"}</b><button title="Свернуть" onClick={() => setFieldsOpen(false)}>×</button></div>
              {workspace === "events" ? <>
              <div className="fieldSearch"><span>⌕</span><input value={fieldSearch} onChange={(event) => setFieldSearch(event.target.value)} placeholder="Найти поле" aria-label="Найти поле"/></div>
              <div className="fieldSection">
                <div className="sectionTitle"><span>ОСНОВНЫЕ ПОЛЯ</span><em>{selectedFields.length}</em></div>
                {selectedFields.map((field) => <button className="field selected" key={field} onClick={() => filterBy(field)}><span>≡</span><b>{field}</b><i>＋</i></button>)}
              </div>
              <div className="fieldSection available">
                <div className="sectionTitle"><span>ДОСТУПНЫЕ ПОЛЯ</span><em>{visibleFields.length}</em></div>
                {visibleFields.map(([field, count]) => <button className="field" key={field} onClick={() => filterBy(field)}><span>Ab</span><b>{field}</b><small>{count}</small><i>＋</i></button>)}
              </div>
              <div className="fieldStats"><b>СОБРАННЫЕ ПОЛЯ</b><small>{fieldCatalog.length} полей из {events.length} локальных событий</small></div>
              </> : <>
                <div className="alertFilterGroup"><div className="sectionTitle"><span>ВАЖНОСТЬ</span><em>{visibleAlerts.length}</em></div>
                  {(["all", "critical", "high", "medium", "low"] as const).map((level) => <button className={`alertFilter ${alertSeverity === level ? "active" : ""}`} key={level} onClick={() => setAlertSeverity(level)}><span>{level === "all" ? "Все уровни" : level}</span><b>{level === "all" ? alerts.length : alerts.filter((alert) => alert.severity === level).length}</b></button>)}
                </div>
                <div className="alertRules"><div className="sectionTitle"><span>ВСТРОЕННЫЕ ДЕТЕКТЫ</span></div><span>T1110 · Brute Force</span><span>T1059 · Command Shell</span><span>T1059.001 · PowerShell</span><span>T1548.003 · Sudo</span></div>
                <div className="fieldStats"><b>ЛОКАЛЬНЫЙ ДВИЖОК</b><small>Анализ после надёжной записи события. Демо-данные отключены.</small></div>
              </>}
              <button type="button" className="paneResizeHandle right" aria-label="Изменить ширину панели полей" onPointerDown={(event) => beginPaneResize("fields", event)} onKeyDown={(event) => resizePaneWithKeyboard("fields", event)}><span /></button>
            </aside>

            <section className="centerPane">
              {workspace === "events" ? <>
              {histogramOpen && <article className="histogramPanel">
                <div className="chartHeader"><div><b>События по выбранному запросу</b><span>По часам UTC</span></div><button aria-label="Скрыть график" onClick={toggleHistogram}>×</button></div>
                <div className="chartArea"><div className="yAxis"><span>{Math.max(...hourCounts, 0)}</span><span>0</span></div><div className="bars">{histogram.map((height, index) => <i style={{height:`${height}%`}} title={`${index}:00 UTC: ${hourCounts[index] ?? 0}`} key={index}/>)}</div><div className="xAxis"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:59</span></div></div>
              </article>}

              <div className="eventsToolbar"><div><b>ПОТОК СОБЫТИЙ</b><span className={`liveStatus ${liveEnabled ? "active" : "paused"}`}><i/>{liveEnabled ? health?.source.state === "backfilling" ? "ЗАГРУЗКА ИСТОРИИ" : liveConnected ? "LIVE" : "ПОДКЛЮЧЕНИЕ…" : "ПАУЗА"}</span></div><div><button aria-pressed={histogramOpen} onClick={toggleHistogram}>График</button><button className="liveToggle" aria-label={liveEnabled ? "Приостановить ленту" : "Продолжить live-поток"} aria-pressed={liveEnabled} onClick={toggleLive}>{liveEnabled ? "Ⅱ Пауза" : "▶ В прямой эфир"}</button></div></div>
              {!liveEnabled && <div className="liveNotice"><span>{hasUpdates ? "Есть новые события. Сбор продолжается." : "Лента приостановлена для просмотра. Сбор продолжается."}</span><button onClick={toggleLive}>Показать актуальные</button></div>}
              <div className="eventStream configurableEvents" ref={streamRef} onScroll={(event) => { if (liveRef.current && event.currentTarget.scrollTop > 80) { liveRef.current = false; setLiveEnabled(false); } }}>
                <div className="eventHead" style={columnLayout(preferences.columns)}><span/>{preferences.columns.map((field) => <span key={field} data-field={field} className="columnHeading" title={field}>{columnInfo(field).label}</span>)}</div>
                {events.map((event) => <EventRow key={event.uid} event={event} columns={preferences.columns} active={detailsOpen && selected?.uid === event.uid} onSelect={inspectEvent} />)}
                {!events.length && <div className="emptyState"><i>⌁</i><b>{online ? "Событий не найдено" : "Ожидание сенсора"}</b><span>{online ? "Новые подходящие события появятся автоматически. Можно изменить или сбросить поиск." : "Соединение восстанавливается автоматически. Проверьте источник, если ожидание затянулось."}</span><button onClick={() => { setQuery(""); setSearchMode("contains"); void runSearch("*", { query: "", mode: "contains" }); }}>Сбросить поиск</button></div>}
              </div>
              <footer className="streamFooter"><span>Новые сверху · окно сбора {lookbackLabel(health?.source.lookback)}</span><span>Показано {events.length} из {total.toLocaleString("ru-RU")}</span>{events.length >= 1000 ? <span>Уточните поиск для более старых событий</span> : nextCursor && <button onClick={() => void loadMoreEvents()} disabled={searching}>Загрузить ещё</button>}</footer>
              </> : <>
                {alertOverviewOpen && <article className="alertOverview">
                  <div><small>КРИТИЧЕСКИЕ</small><b>{alerts.filter((alert) => alert.severity === "critical").length}</b><span>требуют первичной проверки</span></div>
                  <div><small>ВЫСОКИЕ</small><b>{alerts.filter((alert) => alert.severity === "high").length}</b><span>значимый риск</span></div>
                  <div><small>СРЕДНИЕ</small><b>{alerts.filter((alert) => alert.severity === "medium").length}</b><span>контекст для анализа</span></div>
                  <div><small>ПОСЛЕДНЕЕ СРАБАТЫВАНИЕ</small><b className="alertLastSeen">{alerts[0]?.timestamp.slice(0, 19).replace("T", " ") ?? "—"}</b><span>локальное время источника</span></div>
                </article>}
                <div className="eventsToolbar"><div><b>ЛЕНТА АЛЕРТОВ</b><span>Автоматическое обновление</span></div><div><button aria-pressed={alertOverviewOpen} onClick={() => setAlertOverviewOpen((open) => !open)}>Сводка</button></div></div>
                <div className="alertHead"><span>ВРЕМЯ</span><span>РИСК</span><span>ПРАВИЛО</span><span>ОПИСАНИЕ</span><span>ГРУППА</span><span>MITRE</span></div>
                <div className="eventStream alertStream">
                  {visibleAlerts.map((alert) => <button className={`alertRow ${selectedAlert?.id === alert.id ? "active" : ""}`} key={alert.id} onClick={() => { setSelectedAlertId(alert.id); setDetailsOpen(true); }}>
                    <span className="mono time">{alert.timestamp.slice(11, 19)}</span><span className="alertRisk"><i className={`severity ${alert.severity}`}/><b>{alert.risk_score}</b><small>{alert.severity}</small></span><span><b>{alert.title}</b><small className="mono">{alert.rule_id}</small></span><span>{alert.description}</span><span className="mono">{alert.group_key}</span><b className="mono">{alert.mitre_technique}</b>
                  </button>)}
                  {!visibleAlerts.length && <div className="emptyState"><i>◇</i><b>{alerts.length ? "Нет алертов этого уровня" : "Алертов пока нет"}</b><span>{alerts.length ? "Выберите другой уровень важности." : "Новые срабатывания по реальным событиям появятся автоматически."}</span>{alerts.length > 0 && <button onClick={() => setAlertSeverity("all")}>Сбросить фильтр</button>}</div>}
                </div>
                <footer className="streamFooter"><span>Сортировка: <b>@timestamp ↓</b></span><span>Сохранено {alertTotal.toLocaleString("ru-RU")}</span><span className="footerStatus">контрольные суммы включены</span></footer>
              </>}
            </section>

            <aside className={`detailsPane ${detailsOpen ? "drawerOpen" : ""}`}>
              <div className="paneHeader"><div><b>{workspace === "events" ? "СВОДКА СОБЫТИЯ" : "СВОДКА АЛЕРТА"}</b><small>#{workspace === "events" ? (selected?.uid ?? "—") : (selectedAlert?.id ?? "—")}</small></div><button title="Закрыть" onClick={() => setDetailsOpen(false)}>×</button></div>
              {workspace === "events" ? <>{selected && <>
                <div className="detailHero"><div><i className={`severity ${selected.level}`}/><span><small>{selected.source} · {selected.fields["event.id"]}</small><b>{selected.title}</b></span></div><time>{selected.time}</time></div>
                <div className="detailTabs"><button className={detailTab === "summary" ? "active" : ""} onClick={() => setDetailTab("summary")}>Сводка</button><button className={detailTab === "fields" ? "active" : ""} onClick={() => setDetailTab("fields")}>Все поля</button><button className={detailTab === "raw" ? "active" : ""} onClick={() => setDetailTab("raw")}>JSON</button></div>
                {detailTab === "summary" && <div className="detailBody">
                  <section><h3>ОСНОВНЫЕ ПОЛЯ</h3>{summaryFields.map(([field, value]) => <div className="detailField" key={field}><span><b>{field}</b><em>{value}</em></span><div><button title="Фильтровать по значению" onClick={() => filterBy(field, value)}>＋</button><button title="Исключить значение" onClick={() => filterBy(field, value, true)}>−</button></div></div>)}</section>
                  {detailFields["process.pid"] !== "н/д" && <section><h3>КОНТЕКСТ ПРОЦЕССА</h3><div className="processMeta"><span><b>PID</b>{detailFields["process.pid"]}</span><span><b>PPID</b>{detailFields["process.parent.pid"]}</span></div>{selected.fields["process.name"] && <p className="processName">{selected.fields["process.name"]}</p>}</section>}
                  <section><div className="quickActions"><button onClick={() => void copySelectedJson()} aria-live="polite">{copiedJson ? "Скопировано ✓" : "Скопировать JSON"}</button></div></section>
                </div>}
                {detailTab === "fields" && <div className="allFields">{Object.entries(detailFields).map(([field,value]) => <div key={field}><b>{field}</b><span>{value}</span><button onClick={() => filterBy(field,value)}>＋</button></div>)}</div>}
                {detailTab === "raw" && <pre className="rawEvent">{selected.raw}</pre>}
              </>}</> : <>{selectedAlert && <>
                <div className="detailHero alertDetailHero"><div><i className={`severity ${selectedAlert.severity}`}/><span><small>{selectedAlert.rule_id} · риск {selectedAlert.risk_score}/100</small><b>{selectedAlert.title}</b></span></div><time>{selectedAlert.timestamp}</time></div><button disabled={investigating} onClick={() => void investigateAlert()}>{investigating ? "Сохранение…" : "Открыть расследование"}</button>
                <div className="alertDetailBody">
                  <section><h3>ОЦЕНКА</h3><div className="alertScore"><strong>{selectedAlert.risk_score}</strong><span><b>Риск</b><small>Уверенность {selectedAlert.confidence}%</small></span></div></section>
                  <section><h3>ОПИСАНИЕ</h3><p>{selectedAlert.description}</p></section>
                  <section><h3>КОНТЕКСТ</h3><dl><div><dt>MITRE ATT&amp;CK</dt><dd>{selectedAlert.mitre_technique}</dd></div><div><dt>Группа</dt><dd>{selectedAlert.group_key}</dd></div><div><dt>Важность</dt><dd>{selectedAlert.severity}</dd></div></dl></section>
                  <section><h3>ДОКАЗАТЕЛЬСТВА <span>{selectedAlert.evidence.length}</span></h3><div className="evidenceList">{selectedAlert.evidence.map((uid) => <button key={uid} onClick={() => { setWorkspace("events"); setSearchMode("dsl"); const next = valueFilter("uid", uid, "exact"); setQuery(next); void runSearch(next); }}>{uid}<span>Открыть событие →</span></button>)}</div></section>
                </div>
              </>}</>}
              <button type="button" className="paneResizeHandle left" aria-label="Изменить ширину панели подробностей" onPointerDown={(event) => beginPaneResize("details", event)} onKeyDown={(event) => resizePaneWithKeyboard("details", event)}><span /></button>
            </aside>
          </div>
          </> : workspace === "sources" ? <SourcesWorkspace health={health} onRefresh={() => void refreshSourceStatus()} refreshing={collecting} onExplore={(query) => { setWorkspace("events"); setSearchMode("dsl"); setQuery(query); void runSearch(query); }} /> : workspace === "audit" ? <AuditWorkspace /> : workspace === "settings" ? <SettingsWorkspace /> : workspace === "rules" ? <RulesWorkspace /> : workspace === "cases" ? <CasesWorkspace /> : <DiagnosticsWorkspace />}
        </section>
      </section>
    </main>
  );
}
