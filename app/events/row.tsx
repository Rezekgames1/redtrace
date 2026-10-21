import { memo } from "react";
import type { UiEvent } from "./types";
import { columnInfo, columnLayout } from "./columns";
import { eventContext } from "./summary";

export const EventRow = memo(function EventRow({ event, columns, active, onSelect }: { event: UiEvent; columns: string[]; active: boolean; onSelect: (event: UiEvent) => void }) {
  const context = eventContext(event);
  return <button className={`eventRow ${active ? "active" : ""}`} data-uid={event.uid} style={columnLayout(columns)} onClick={() => onSelect(event)}>
    <span className="expand">›</span>
    {columns.map((field) => {
      const value = field === "level" ? event.level : Object.hasOwn(event.fields, field) && event.fields[field] !== "н/д" ? event.fields[field] : "—";
      return <span key={field} data-field={field} className={`eventCell ${columnInfo(field).className}`} title={field === "@timestamp" ? event.fields[field] : value}>
        {field === "@timestamp" ? event.time : field === "level" ? <><i className={`severity ${event.level}`}/><small>{event.level === "critical" ? "Крит." : event.level === "high" ? "Выс." : event.level === "medium" ? "Сред." : "Низ."}</small></> : field === "event.description" ? <><b title={event.title}>{event.title}</b>{context && <small title={context}>{context}</small>}</> : field === "source" ? event.source : value}
      </span>;
    })}
  </button>;
});
