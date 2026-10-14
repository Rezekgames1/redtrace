export function quoteValue(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function valueFilter(field: string, value: string, operator: "exact" | "contains" | "exists", exclude = false): string {
  const term = operator === "exists" ? `${field}:*` : `${field}${operator === "exact" ? "=" : "~"}${quoteValue(value)}`;
  return exclude ? `NOT (${term})` : term;
}

export function appendFilter(query: string, filter: string): string {
  return !query.trim() || query.trim() === "*" ? filter : `(${query}) AND (${filter})`;
}
