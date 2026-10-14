import { useState } from "react";
import { columnChoices, columnInfo, DEFAULT_COLUMNS, MAX_COLUMNS } from "./columns";
import type { EventPreferences, SavedView } from "./preferences";

export function PreferencesPanel({ section, preferences, fields, onColumns, onSave, onApply, onDelete }: {
  section: "views" | "columns";
  preferences: EventPreferences;
  fields: string[];
  onColumns: (columns: string[]) => void;
  onSave: (name: string, id?: string) => void;
  onApply: (view: SavedView) => void;
  onDelete: (id: string) => void;
}) {
  const [name, setName] = useState("");
  const [editingId, setEditingId] = useState<string | undefined>();
  const [fieldSearch, setFieldSearch] = useState("");
  const moveColumn = (index: number, offset: number) => {
    const columns = [...preferences.columns];
    [columns[index], columns[index + offset]] = [columns[index + offset], columns[index]];
    onColumns(columns);
  };
  return <section className="eventPreferences" aria-label={section === "views" ? "Сохранённые представления" : "Настройка колонок"}>
    {section === "views" ? <>
      <div className="preferencesIntro"><b>Представления</b><span>Выполненный запрос, режим поиска и колонки. Хранятся локально.</span></div>
      <form className="viewSave" onSubmit={(event) => { event.preventDefault(); onSave(name, editingId); }}>
        <input aria-label="Название представления" value={name} onChange={(event) => setName(event.target.value)} maxLength={64} placeholder="Например, ошибки входа" required />
        <button type="submit" disabled={!name.trim()}>{editingId ? "Обновить представление" : "Сохранить представление"}</button>
        {editingId && <button type="button" onClick={() => { setEditingId(undefined); setName(""); }}>Новое</button>}
      </form>
      <div className="savedViewList">{preferences.views.map((view) => <div className="savedView" key={view.id} data-view-id={view.id}>
        <span><b>{view.name}</b><small>{view.query || "Все события"}</small></span>
        <button onClick={() => onApply(view)}>Открыть</button>
        <button onClick={() => { setEditingId(view.id); setName(view.name); }} aria-label={`Изменить ${view.name}`}>Изменить</button>
        <button onClick={() => { onDelete(view.id); if (editingId === view.id) { setEditingId(undefined); setName(""); } }} aria-label={`Удалить ${view.name}`}>Удалить</button>
      </div>)}</div>
      {!preferences.views.length && <p>Сохранённых представлений пока нет.</p>}
    </> : <>
      <div className="preferencesIntro"><b>Колонки · {preferences.columns.length}/{MAX_COLUMNS}</b><span>Порядок слева направо. «Событие» остаётся обязательным.</span><button onClick={() => onColumns([...DEFAULT_COLUMNS])}>Стандартные колонки</button></div>
      <div className="selectedColumns">{preferences.columns.map((field, index) => <div key={field} data-column={field}>
        <span>{columnInfo(field).label}<small>{field}</small></span>
        <button disabled={index === 0} aria-label={`Сдвинуть ${field} влево`} onClick={() => moveColumn(index, -1)}>←</button>
        <button disabled={index === preferences.columns.length - 1} aria-label={`Сдвинуть ${field} вправо`} onClick={() => moveColumn(index, 1)}>→</button>
        <button disabled={field === "event.description"} aria-label={`Убрать ${field}`} onClick={() => onColumns(preferences.columns.filter((column) => column !== field))}>×</button>
      </div>)}</div>
      <input aria-label="Найти колонку" placeholder="Найти поле для колонки" value={fieldSearch} onChange={(event) => setFieldSearch(event.target.value)} />
      <div className="columnChoices">{columnChoices(fields).filter((field) => !preferences.columns.includes(field) && `${field} ${columnInfo(field).label}`.toLowerCase().includes(fieldSearch.toLowerCase())).map((field) => <button key={field} data-add-column={field} disabled={preferences.columns.length >= MAX_COLUMNS} onClick={() => onColumns([...preferences.columns, field])}>＋ {columnInfo(field).label}<small>{field}</small></button>)}</div>
    </>}
  </section>;
}
