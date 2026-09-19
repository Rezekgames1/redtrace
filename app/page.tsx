"use client";

import { useEffect, useMemo, useState } from "react";
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent } from "react";
import { collectLocalEvents, getSensorHealth, searchLocalEvents } from "./events/api";
import type { SensorHealth } from "./events/api";
import type { UiEvent } from "./events/types";

const selectedFields = ["@timestamp", "event.id", "event.description", "source", "process.command_line", "process.pid", "process.parent.pid"];

export default function Home() {
  const [query, setQuery] = useState("*");
  const [events, setEvents] = useState<UiEvent[]>([]);
  const [selectedId, setSelectedId] = useState(0);
  const [fieldSearch, setFieldSearch] = useState("");
  const [total, setTotal] = useState(0);
  const [took, setTook] = useState("—");
  const [online, setOnline] = useState(false);
  const [health, setHealth] = useState<SensorHealth | null>(null);
  const [searching, setSearching] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const [queryError, setQueryError] = useState("");
  const [detailTab, setDetailTab] = useState<"summary" | "fields" | "raw">("summary");
  const [fieldsOpen, setFieldsOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [fieldsWidth, setFieldsWidth] = useState(236);
  const [detailsWidth, setDetailsWidth] = useState(348);

  const selected = events.find((event) => event.uid === selectedId) ?? events[0];
  const fieldCatalog = useMemo(() => {
    const counts = new Map<string, number>();
    for (const event of events) for (const field of Object.keys(event.fields)) counts.set(field, (counts.get(field) ?? 0) + 1);
    return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [events]);
  const visibleFields = useMemo(() => fieldCatalog.filter(([name]) => name.includes(fieldSearch.toLowerCase())), [fieldCatalog, fieldSearch]);
  const histogram = useMemo(() => {
    const buckets = Array.from({ length: 24 }, () => 0);
    for (const event of events) {
      const hour = Number(event.time.slice(0, 2));
      if (Number.isInteger(hour) && hour >= 0 && hour < 24) buckets[hour] += 1;
    }
    const peak = Math.max(...buckets, 1);
    return buckets.map((value) => value === 0 ? 2 : Math.max(8, Math.round((value / peak) * 92)));
  }, [events]);
  const detailFields = useMemo(() => selected ? {
    "event.description": selected.title,
    "process.command_line": selected.fields["process.command_line"] ?? "н/д",
    "process.pid": selected.fields["process.pid"] ?? "н/д",
    "process.parent.pid": selected.fields["process.parent.pid"] ?? "н/д",
    ...selected.fields,
  } : {}, [selected]);
  const explorerStyle = {
    "--fields-width": `${fieldsWidth}px`,
    "--details-width": `${detailsWidth}px`,
  } as CSSProperties;

  useEffect(() => {
    void getSensorHealth()
      .then((nextHealth) => {
        setHealth(nextHealth);
        setOnline(nextHealth.source.state === "ready");
        void runSearch("*");
      })
      .catch(() => setOnline(false));
    // Initial collection is requested only from the local Rust sensor.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runSearch(nextQuery = query) {
    setSearching(true);
    setQueryError("");
    try {
      const result = await searchLocalEvents(nextQuery);
      setEvents(result.events);
      setTotal(result.total);
      setTook(result.took);
      setSelectedId(result.events[0]?.uid ?? 0);
      setOnline(true);
    } catch (error) {
      setQueryError(error instanceof Error ? error.message : "Поиск недоступен");
      setOnline(false);
    } finally { setSearching(false); }
  }

  function filterBy(field: string, value?: string) {
    const token = value ? `${field}:"${value}"` : `${field}:`;
    const next = query === "*" ? token : `${query} AND ${token}`;
    setQuery(next);
    if (value) void runSearch(next);
  }

  async function refreshLocalLogs() {
    setCollecting(true);
    setQueryError("");
    try {
      await collectLocalEvents();
      await runSearch(query);
      setHealth(await getSensorHealth());
    } catch (error) {
      setQueryError(error instanceof Error ? error.message : "Сборщик недоступен");
      setOnline(false);
    } finally {
      setCollecting(false);
    }
  }

  function beginPaneResize(side: "fields" | "details", event: ReactPointerEvent<HTMLDivElement>) {
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

  function resizePaneWithKeyboard(side: "fields" | "details", event: ReactKeyboardEvent<HTMLDivElement>) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const direction = event.key === "ArrowRight" ? 1 : -1;
    if (side === "fields") setFieldsWidth((width) => Math.min(420, Math.max(190, width + direction * 12)));
    else setDetailsWidth((width) => Math.min(560, Math.max(300, width - direction * 12)));
  }

  return (
    <main className="appShell">
      <aside className="rail" aria-label="Основная навигация">
        <div className="railBrand">R<span>//</span></div>
        <button className="railItem active" title="События">⌁<small>События</small></button>
        <button className="railItem" title="Обнаружения">◇<small>Детекты</small><i>3</i></button>
        <button className="railItem" title="Источники">▦<small>Источники</small></button>
        <button className="railItem" title="Аудит">⚙<small>Аудит</small></button>
        <span className="railSpacer" />
        <button className="railItem" title="Настройки">⋮<small>Ещё</small></button>
      </aside>

      <section className="application">
        <header className="topbar">
          <div className="product"><b>RED<span>//</span>TRACE</b><em>LOCAL SIEM</em></div>
          <div className={`sensor ${online ? "" : "demo"}`}><i/><span><b>{online ? "ЛОКАЛЬНЫЙ СБОР АКТИВЕН" : "ИСТОЧНИК НЕДОСТУПЕН"}</b><small>{health ? `${health.source.name} · WAL ${Math.max(1, Math.ceil(health.storage.wal_bytes / 1024))} КБ` : "Этот компьютер · системные журналы"}</small></span></div>
          <div className="topActions"><button>Сохранить представление</button><button>Экспорт</button><button className="iconButton">?</button></div>
        </header>

        <section className="searchWorkspace">
          <div className="workspaceTitle"><div><span className="crumb">РАССЛЕДОВАНИЕ /</span><h1>Журнал событий</h1><em><b>{total.toLocaleString("ru-RU")}</b> событий</em></div><div className="streamControl"><button className="active"><i/> События</button><button>Алерты</button><button>Аналитика</button></div><div className="mobilePaneButtons"><button onClick={() => setFieldsOpen(true)}>Поля</button><button onClick={() => setDetailsOpen(true)} disabled={!selected}>Детали</button></div></div>

          <div className="queryRow">
            <button className="historyButton" title="История запросов">↶</button>
            <div className={`queryInput ${queryError ? "invalid" : ""}`}><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void runSearch(); }} aria-label="Поисковый запрос"/><kbd>CTRL K</kbd></div>
            <button className="timeRange"><span>◷</span><div><small>ОКНО СБОРЩИКА</small><b>Последние 15 минут</b></div><em>⌄</em></button>
            <button className="runButton" onClick={() => void runSearch()} disabled={searching}>{searching ? "ПОИСК…" : "ВЫПОЛНИТЬ"}</button>
          </div>
          <div className="filterRow"><button>＋ Добавить фильтр</button><span><b>Источник</b> реальные локальные журналы <i>✓</i></span><em>{queryError || `Запрос: ${took}`}</em></div>

          {(fieldsOpen || detailsOpen) && <button className="drawerScrim" aria-label="Закрыть боковую панель" onClick={() => { setFieldsOpen(false); setDetailsOpen(false); }} />}
          <div className="explorer" style={explorerStyle}>
            <aside className={`fieldsPane ${fieldsOpen ? "drawerOpen" : ""}`}>
              <div className="paneHeader"><b>ПОЛЯ СОБЫТИЙ</b><button title="Свернуть" onClick={() => setFieldsOpen(false)}>×</button></div>
              <div className="fieldSearch"><span>⌕</span><input value={fieldSearch} onChange={(event) => setFieldSearch(event.target.value)} placeholder="Найти поле" aria-label="Найти поле"/></div>
              <div className="fieldSection">
                <div className="sectionTitle"><span>ВЫБРАННЫЕ ПОЛЯ</span><em>{selectedFields.length}</em></div>
                {selectedFields.map((field) => <button className="field selected" key={field} onClick={() => filterBy(field)}><span>≡</span><b>{field}</b><i>−</i></button>)}
              </div>
              <div className="fieldSection available">
                <div className="sectionTitle"><span>ДОСТУПНЫЕ ПОЛЯ</span><em>{visibleFields.length}</em></div>
                {visibleFields.map(([field, count]) => <button className="field" key={field} onClick={() => filterBy(field)}><span>Ab</span><b>{field}</b><small>{count}</small><i>＋</i></button>)}
              </div>
              <div className="fieldStats"><b>СОБРАННЫЕ ПОЛЯ</b><div><span style={{width: events.length ? "100%" : "0%"}}/></div><small>{fieldCatalog.length} полей из локальных событий</small></div>
              <div className="paneResizeHandle right" role="separator" aria-label="Изменить ширину панели полей" aria-orientation="vertical" tabIndex={0} onPointerDown={(event) => beginPaneResize("fields", event)} onKeyDown={(event) => resizePaneWithKeyboard("fields", event)}><span /></div>
            </aside>

            <section className="centerPane">
              <article className="histogramPanel">
                <div className="chartHeader"><div><b>Активность за окно сбора</b><span>Распределение по часам</span></div><div className="legend"><span><i className="normal"/>Все события</span><span><i className="alert"/>Высокий риск</span><button>⌃</button></div></div>
                <div className="chartArea"><div className="yAxis"><span>{Math.max(...histogram)}</span><span>0</span></div><div className="bars">{histogram.map((height, index) => <i style={{height:`${height}%`}} key={index}/>)}</div><div className="xAxis"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:59</span></div></div>
                <div className="brush"><span style={{left:"62%",width:"29%"}}><i/><i/></span></div>
              </article>

              <div className="eventsToolbar"><div><b>ПОТОК СОБЫТИЙ</b><span>{events.length} показано</span><i className="liveDot"/>LOCAL</div><div><button onClick={() => void refreshLocalLogs()} disabled={collecting}>{collecting ? "СБОР…" : "↻ Обновить логи"}</button><button>Плотность⌄</button><button>Столбцы</button><button>⇩</button></div></div>
              <div className="eventHead"><span/><span>ВРЕМЯ</span><span>ВАЖН.</span><span>ИСТОЧНИК</span><span>ID</span><span>СОБЫТИЕ</span><span>ПОЛЬЗОВАТЕЛЬ</span></div>
              <div className="eventStream">
                {events.map((event) => <button className={`eventRow ${selected?.uid === event.uid ? "active" : ""}`} key={event.uid} onClick={() => { setSelectedId(event.uid); setDetailTab("summary"); setDetailsOpen(true); }}>
                  <span className="expand">›</span><span className="mono time">{event.time}</span><span><i className={`severity ${event.level}`}/><small>{event.level === "critical" ? "Крит." : event.level === "high" ? "Выс." : event.level === "medium" ? "Сред." : "Низ."}</small></span><span className="sourceCell">{event.source}</span><b className="mono idCell">{event.fields["event.id"] ?? "—"}</b><span className="messageCell"><b>{event.title}</b><small>{event.fields["process.command_line"] ?? event.fields["source.ip"] ?? event.fields["file.path"] ?? event.raw}</small></span><span className="mono userCell">{event.fields["user.name"] ?? "—"}</span>
                </button>)}
                {!events.length && <div className="emptyState"><i>⌁</i><b>Событий не найдено</b><span>{online ? "Измените запрос или обновите локальные журналы." : "Запустите локальный сенсор и проверьте разрешения на чтение журналов."}</span><button onClick={() => void refreshLocalLogs()} disabled={collecting}>{collecting ? "Сбор…" : "Обновить журналы"}</button></div>}
              </div>
              <footer className="streamFooter"><span>Сортировка: <b>@timestamp ↓</b></span><span>Загружено {events.length} из {total.toLocaleString("ru-RU")}</span><button>Загрузить ещё</button></footer>
            </section>

            <aside className={`detailsPane ${detailsOpen ? "drawerOpen" : ""}`}>
              <div className="paneHeader"><div><b>СВОДКА СОБЫТИЯ</b><small>#{selected?.uid ?? "—"}</small></div><button title="Закрыть" onClick={() => setDetailsOpen(false)}>×</button></div>
              {selected && <>
                <div className="detailHero"><div><i className={`severity ${selected.level}`}/><span><small>{selected.source} · {selected.fields["event.id"]}</small><b>{selected.title}</b></span></div><time>{selected.time}</time></div>
                <div className="detailTabs"><button className={detailTab === "summary" ? "active" : ""} onClick={() => setDetailTab("summary")}>Сводка</button><button className={detailTab === "fields" ? "active" : ""} onClick={() => setDetailTab("fields")}>Все поля</button><button className={detailTab === "raw" ? "active" : ""} onClick={() => setDetailTab("raw")}>JSON</button></div>
                {detailTab === "summary" && <div className="detailBody">
                  <section><h3>ОСНОВНЫЕ ПОЛЯ <span>{Object.keys(detailFields).length}</span></h3>{Object.entries(detailFields).slice(0, 9).map(([field, value]) => <div className="detailField" key={field}><span><b>{field}</b><em>{value}</em></span><div><button title="Фильтровать по значению" onClick={() => filterBy(field, value)}>＋</button><button title="Исключить значение">−</button></div></div>)}</section>
                  <section><h3>КОНТЕКСТ ПРОЦЕССА</h3><div className="processMeta"><span><b>PID</b>{detailFields["process.pid"]}</span><span><b>PPID</b>{detailFields["process.parent.pid"]}</span></div><div className="processTree"><span><i/>{selected.fields["parent.name"] ?? "parent process"} <em>PID {detailFields["process.parent.pid"]}</em></span><span><i/>{selected.fields["process.name"] ?? selected.source} <em>PID {detailFields["process.pid"]}</em></span></div></section>
                  <section><h3>БЫСТРЫЕ ДЕЙСТВИЯ</h3><div className="quickActions"><button>Показать похожие</button><button>События до и после</button><button>Скопировать JSON</button></div></section>
                </div>}
                {detailTab === "fields" && <div className="allFields">{Object.entries(detailFields).map(([field,value]) => <div key={field}><b>{field}</b><span>{value}</span><button onClick={() => filterBy(field,value)}>＋</button></div>)}</div>}
                {detailTab === "raw" && <pre className="rawEvent">{selected.raw}</pre>}
              </>}
              <div className="paneResizeHandle left" role="separator" aria-label="Изменить ширину панели подробностей" aria-orientation="vertical" tabIndex={0} onPointerDown={(event) => beginPaneResize("details", event)} onKeyDown={(event) => resizePaneWithKeyboard("details", event)}><span /></div>
            </aside>
          </div>
        </section>
      </section>
    </main>
  );
}
