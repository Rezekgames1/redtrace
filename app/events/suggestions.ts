import { columnChoices, validColumn } from "./columns.ts";
import { quoteValue } from "./query.ts";

export type Suggestion = { value: string; label: string; detail: string; caret?: number };
export type SuggestionCatalog = { fields: string[]; values: ReadonlyMap<string, string[]> };
const MAX_OPTIONS = 12;
const MAX_FIELDS = 256;
const MAX_EVENTS = 200;
const MAX_VALUES = 100;
const MAX_VALUE_LENGTH = 512;
const commonFields = ["agent.id", "agent.name", "host.name", "host.os", "uid", "event.record_id", "service.name", "log.transport"];

export function buildSuggestionCatalog(events: readonly { fields: Record<string, string> }[]): SuggestionCatalog {
  const values = new Map<string, Set<string>>();
  for (const event of events.slice(0, MAX_EVENTS)) {
    for (const [field, value] of Object.entries(event.fields)) {
      if (!validColumn(field) || typeof value !== "string" || !value.trim() || value === "н/д" || value.length > MAX_VALUE_LENGTH) continue;
      if (!values.has(field) && values.size < MAX_FIELDS) values.set(field, new Set());
      const choices = values.get(field);
      if (choices && choices.size < MAX_VALUES) choices.add(value);
    }
  }
  return {
    fields: columnChoices([...commonFields, ...values.keys()]).slice(0, MAX_FIELDS),
    values: new Map([...values].map(([field, choices]) => [field, [...choices]])),
  };
}

function matches(values: string[], input: string): string[] {
  const needle = input.toLowerCase();
  return values.filter(value => value.toLowerCase().includes(needle))
    .sort((left, right) => Number(right.toLowerCase().startsWith(needle)) - Number(left.toLowerCase().startsWith(needle)) || left.localeCompare(right))
    .slice(0, MAX_OPTIONS);
}

export function fieldSuggestions(input: string, catalog: SuggestionCatalog): Suggestion[] {
  return matches(catalog.fields, input).map(field => ({ value: field, label: field, detail: "Поле" }));
}

export function valueSuggestions(field: string, input: string, catalog: SuggestionCatalog): Suggestion[] {
  return matches(catalog.values.get(field) ?? catalog.values.get(field.toLowerCase()) ?? [], input).map(value => ({ value, label: value, detail: field }));
}

export function containsSuggestions(input: string, catalog: SuggestionCatalog): Suggestion[] {
  if (!input.trim()) return [];
  const choices = new Map<string, string>();
  for (const [field, values] of catalog.values) {
    for (const value of values) if (value.trim() !== "*" && !choices.has(value)) choices.set(value, field);
  }
  return matches([...choices.keys()], input).map(value => ({ value, label: value, detail: choices.get(value)! }));
}

function tokenBoundary(query: string, end: number): { start: number; quoted: boolean } {
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < end; index++) {
    const character = query[index];
    if (escaped) { escaped = false; continue; }
    if (quoted && character === "\\") { escaped = true; continue; }
    if (character === '"') { quoted = !quoted; continue; }
    if (!quoted && (/[\s]/.test(character) || character === "(" || character === ")")) start = index + 1;
  }
  return { start, quoted };
}

function tokenEnd(query: string, start: number): number {
  let quoted = false;
  let escaped = false;
  for (let index = start; index < query.length; index++) {
    const character = query[index];
    if (escaped) { escaped = false; continue; }
    if (quoted && character === "\\") { escaped = true; continue; }
    if (character === '"') { quoted = !quoted; continue; }
    if (!quoted && (/[\s]/.test(character) || character === "(" || character === ")")) return index;
  }
  return query.length;
}

function partialValue(value: string): string {
  if (!value.startsWith('"')) return value;
  let result = "";
  for (let index = 1; index < value.length; index++) {
    if (value[index] === "\\" && index + 1 < value.length) index++;
    result += value[index];
  }
  return result;
}

export function querySuggestions(query: string, position: number, catalog: SuggestionCatalog): Suggestion[] {
  if (query.length > 8192) return [];
  const caret = Math.min(Math.max(position, 0), query.length);
  const { start, quoted } = tokenBoundary(query, caret);
  const fragment = query.slice(start, caret);
  const previous = query.slice(0, start);
  const predicate = fragment.match(/^([a-zA-Z_@][a-zA-Z0-9_.@-]*)([=:~])([\s\S]*)$/);
  if (predicate) {
    const [, field, operator, value] = predicate;
    if ((value.startsWith('"') && !quoted) || (operator === ":" && value === "*")) return [];
    const suffix = query.slice(tokenEnd(query, start));
    return valueSuggestions(field, partialValue(value), catalog).map(choice => {
      const completed = `${previous}${field}${operator}${quoteValue(choice.value)}`;
      return { ...choice, value: completed + suffix, caret: completed.length };
    });
  }
  if (quoted || !/^[a-zA-Z0-9_.@-]*$/.test(fragment)) return [];
  const expectsTerm = !previous.trim() || /(?:^|[\s(])(?:AND|OR|NOT)\s*$|\(\s*$/i.test(previous);
  if (!expectsTerm) {
    return matches(["AND", "OR"], fragment).map(operator => {
      const completed = `${previous}${operator} `;
      return { value: completed + query.slice(tokenEnd(query, start)), label: operator, detail: "Оператор", caret: completed.length };
    });
  }
  const fieldEnd = caret + (query.slice(caret).match(/^[a-zA-Z0-9_.@-]*/)?.[0].length ?? 0);
  const operatorExists = /^[=:~]/.test(query.slice(fieldEnd));
  return fieldSuggestions(fragment, catalog).map(choice => {
    const completed = previous + choice.value;
    return { ...choice, value: completed + (operatorExists ? "" : "=") + query.slice(fieldEnd), caret: completed.length + 1 };
  });
}
