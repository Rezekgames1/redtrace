export const DEFAULT_COLUMNS = ["@timestamp", "level", "source", "event.id", "event.description", "user.name"];
export const MAX_COLUMNS = 8;

const catalog: Record<string, { label: string; width: number; className: string }> = {
  "@timestamp": { label: "Время UTC", width: 105, className: "mono time" },
  "level": { label: "Уровень", width: 80, className: "severityCell" },
  "source": { label: "Источник", width: 140, className: "sourceCell" },
  "event.id": { label: "ID", width: 70, className: "mono idCell" },
  "event.description": { label: "Событие", width: 200, className: "messageCell" },
  "user.name": { label: "Пользователь", width: 110, className: "mono userCell" },
  "process.pid": { label: "PID", width: 90, className: "mono" },
  "process.parent.pid": { label: "PPID", width: 90, className: "mono" },
  "process.name": { label: "Процесс", width: 150, className: "customCell" },
  "process.command_line": { label: "Командная строка", width: 300, className: "customCell" },
  "process.executable": { label: "Исполняемый файл", width: 240, className: "customCell" },
  "source.ip": { label: "IP источника", width: 140, className: "mono" },
  "host.name": { label: "Хост", width: 150, className: "customCell" },
  "event.outcome": { label: "Результат", width: 130, className: "customCell" },
  "sudo.command": { label: "Запрошенная команда sudo", width: 300, className: "customCell" },
  "user.target.name": { label: "Целевой пользователь", width: 150, className: "customCell" },
  "authorization.right": { label: "Запрошенное право", width: 260, className: "customCell" },
  "client.process.executable": { label: "Приложение-заявитель", width: 260, className: "customCell" },
  "client.process.pid": { label: "PID заявителя", width: 110, className: "mono" },
};

export function validColumn(field: unknown): field is string {
  return typeof field === "string" && field.length <= 128 && /^[a-zA-Z_@][a-zA-Z0-9_.@-]*$/.test(field);
}

export function normalizeColumns(value: unknown): string[] {
  if (!Array.isArray(value)) return [...DEFAULT_COLUMNS];
  const columns = [...new Set(value.filter(validColumn))].slice(0, MAX_COLUMNS);
  if (!columns.includes("event.description")) {
    if (columns.length === MAX_COLUMNS) columns.pop();
    columns.push("event.description");
  }
  return columns;
}

export function columnInfo(field: string) {
  return Object.hasOwn(catalog, field) ? catalog[field] : { label: field, width: 160, className: "customCell" };
}

export function columnChoices(fields: string[]): string[] {
  return [...new Set([...DEFAULT_COLUMNS, ...Object.keys(catalog), ...fields.filter(validColumn)])];
}

export function columnLayout(columns: string[]) {
  return {
    gridTemplateColumns: ["20px", ...columns.map((field) => field === "event.description" ? "minmax(200px, 1fr)" : `${columnInfo(field).width}px`)].join(" "),
    minWidth: `${20 + columns.reduce((sum, field) => sum + columnInfo(field).width, 0) + columns.length * 8 + 28}px`,
  };
}
