import assert from "node:assert/strict";
import test from "node:test";
import { columnInfo, columnLayout, DEFAULT_COLUMNS, normalizeColumns } from "../app/events/columns.ts";
import { DEFAULT_PREFERENCES, getPreferences, parsePreferences, saveView, writePreferences } from "../app/events/preferences.ts";

test("corrupt, unknown and oversized preferences fall back without breaking the UI", () => {
  for (const raw of [null, "broken", "[]", '{"version":2}', "a".repeat(262145)]) assert.equal(parsePreferences(raw), DEFAULT_PREFERENCES);
  const parsed = parsePreferences(JSON.stringify({ version: 1, columns: ["source", "source", "bad:field"], views: [{ id: "bad", name: "", query: "*", mode: "dsl", columns: [] }] }));
  assert.deepEqual(parsed.columns, ["source", "event.description"]);
  assert.deepEqual(parsed.views, []);
});

test("saved views preserve mode, query and ordered columns, and update by identity", () => {
  const first = { id: "test-view", name: "  SSH  ", query: 'source~"linux"', mode: "dsl", columns: ["source", "event.description", "process.pid"] };
  const prefs = saveView(DEFAULT_PREFERENCES, first);
  assert.equal(prefs.views[0].name, "SSH");
  assert.deepEqual(parsePreferences(JSON.stringify(prefs)), prefs);
  const updated = saveView(prefs, { ...first, name: "SSH errors", query: "failed", mode: "contains" });
  assert.equal(updated.views.length, 1);
  assert.equal(updated.views[0].mode, "contains");
  assert.throws(() => saveView(prefs, { ...first, id: "another", name: "ssh" }), /уже существует/);
  assert.throws(() => saveView(prefs, { ...first, name: " ".repeat(65) }), /Имя/);
});

test("columns are bounded, preserve the event description and handle prototype-like field names", () => {
  assert.deepEqual(normalizeColumns(undefined), DEFAULT_COLUMNS);
  const columns = normalizeColumns(Array.from({ length: 20 }, (_, index) => `field.${index}`));
  assert.equal(columns.length, 8);
  assert.ok(columns.includes("event.description"));
  assert.equal(columnInfo("constructor").width, 160);
  assert.ok(!columnLayout(normalizeColumns(["constructor"])).minWidth.includes("NaN"));
});

test("storage failures leave previously persisted settings available", () => {
  const previous = globalThis.window;
  let value = JSON.stringify(DEFAULT_PREFERENCES);
  globalThis.window = { localStorage: { getItem: () => value, setItem: (_, raw) => { value = raw; } } };
  try {
    writePreferences({ ...DEFAULT_PREFERENCES, columns: ["source", "event.description"] });
    assert.deepEqual(getPreferences().columns, ["source", "event.description"]);
    globalThis.window.localStorage.setItem = () => { throw new Error("quota"); };
    assert.throws(() => writePreferences(DEFAULT_PREFERENCES), /локальном хранилище/);
    assert.deepEqual(getPreferences().columns, ["source", "event.description"]);
  } finally { globalThis.window = previous; }
});
