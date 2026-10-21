import assert from "node:assert/strict";
import test from "node:test";
import { buildSuggestionCatalog, containsSuggestions, fieldSuggestions, querySuggestions, valueSuggestions } from "../app/events/suggestions.ts";

const catalog = buildSuggestionCatalog([
  { fields: { source: "linux.sshd", "agent.name": "kali-wsl", "process.name": "sshd", "process.command_line": String.raw`C:\Program Files\app.exe "x"`, "event.id": "ssh.login.failure", "user.name": "root", "process.parent.pid": "н/д" } },
  { fields: { source: "windows.sysmon", "agent.name": "kali-wsl", "process.name": "powershell.exe", "user.name": "ROOT", "message": "foo AND bar" } },
]);

test("field suggestions include common and observed fields, ignore case and prefer prefixes", () => {
  assert.deepEqual(fieldSuggestions("AGENT.N", catalog).map(choice => choice.value), ["agent.name"]);
  assert.ok(fieldSuggestions("process.", catalog).some(choice => choice.value === "process.command_line"));
  assert.ok(fieldSuggestions("", catalog).length <= 12);
  assert.equal(fieldSuggestions("bad:field", catalog).length, 0);
});

test("value suggestions use real selected-field values and exclude synthetic missing markers", () => {
  assert.deepEqual(valueSuggestions("agent.name", "KA", catalog).map(choice => choice.value), ["kali-wsl"]);
  assert.deepEqual(valueSuggestions("AGENT.NAME", "KA", catalog).map(choice => choice.value), ["kali-wsl"]);
  assert.deepEqual(valueSuggestions("source", "sysmon", catalog).map(choice => choice.value), ["windows.sysmon"]);
  assert.equal(valueSuggestions("process.parent.pid", "", catalog).length, 0);
  assert.equal(valueSuggestions("absent", "", catalog).length, 0);
  const unusual = buildSuggestionCatalog([{ fields: Object.fromEntries([["__proto__", "literal"], ["constructor", "value"], ["invalid:key", "ignore"]]) }]);
  assert.equal(valueSuggestions("__proto__", "", unusual)[0].value, "literal");
  assert.equal(valueSuggestions("constructor", "", unusual)[0].value, "value");
  assert.ok(!unusual.fields.includes("invalid:key"));
});

test("contains suggestions insert literal values without DSL operators or duplicate values", () => {
  assert.equal(containsSuggestions("", catalog).length, 0);
  assert.deepEqual(containsSuggestions("kali", catalog).map(choice => choice.value), ["kali-wsl"]);
  assert.equal(containsSuggestions("AND", catalog)[0].value, "foo AND bar");
  const html = buildSuggestionCatalog([{ fields: { message: "<img src=x onerror=alert(1)>" } }]);
  assert.equal(containsSuggestions("img", html)[0].label, "<img src=x onerror=alert(1)>");
  const wildcards = buildSuggestionCatalog([{ fields: { message: "*", spaced: " * ", other: "star * argument" } }]);
  assert.deepEqual(containsSuggestions("*", wildcards).map(choice => choice.value), ["star * argument"]);
});

test("DSL field completion handles nested predicates and replaces the field at the caret", () => {
  const input = 'source="linux.sshd" AND (agent.n';
  assert.equal(querySuggestions(input, input.length, catalog)[0].value, 'source="linux.sshd" AND (agent.name=');
  const middle = "agent.na=old OR source=other";
  const choice = querySuggestions(middle, 7, catalog).find(item => item.label === "agent.name");
  assert.equal(choice.value, "agent.name=old OR source=other");
  assert.equal(choice.caret, "agent.name=".length);
  const negated = querySuggestions("NOT pro", 7, catalog);
  assert.ok(negated[0].label.startsWith("process."));
  assert.ok(negated.every(item => item.label.includes("pro") && item.value === `NOT ${item.label}=`));
  assert.equal(querySuggestions("NOT client.process.p", 20, catalog)[0].value, "NOT client.process.pid=");
});

test("DSL value completion preserves escaping, operators and the remaining query", () => {
  const prefix = 'agent.name="ka';
  assert.equal(querySuggestions(prefix, prefix.length, catalog)[0].value, 'agent.name="kali-wsl"');
  const middle = 'agent.name="kaOLD" AND source="linux.sshd"';
  assert.equal(querySuggestions(middle, prefix.length, catalog)[0].value, 'agent.name="kali-wsl" AND source="linux.sshd"');
  const windows = 'process.command_line~"C:\\\\Pro';
  assert.equal(querySuggestions(windows, windows.length, catalog)[0].value, 'process.command_line~"C:\\\\Program Files\\\\app.exe \\"x\\""');
  assert.equal(querySuggestions("source:win", 10, catalog)[0].value, 'source:"windows.sysmon"');
  assert.equal(querySuggestions('agent.name="kali-wsl"', 21, catalog).length, 0);
});

test("DSL operator completion does not interpret boolean-looking literals as operators", () => {
  const input = 'agent.name="kali-wsl" A';
  assert.equal(querySuggestions(input, input.length, catalog)[0].value, 'agent.name="kali-wsl" AND ');
  assert.deepEqual(querySuggestions("source=foo.AND ", 15, catalog).map(choice => choice.label), ["AND", "OR"]);
  assert.equal(querySuggestions('"process.na', 11, catalog).length, 0);
  assert.equal(querySuggestions("source:*", 8, catalog).length, 0);
  const literal = buildSuggestionCatalog([{ fields: { message: "*" } }]);
  assert.equal(querySuggestions("message=*", 9, literal)[0].value, 'message="*"');
});

test("suggestion catalogs and outputs remain bounded with many unique or oversized values", () => {
  const many = buildSuggestionCatalog(Array.from({ length: 500 }, (_, index) => ({ fields: { source: `source-${index}`, message: "x".repeat(513) } })));
  assert.equal(many.values.get("source").length, 100);
  assert.equal(many.values.has("message"), false);
  assert.equal(valueSuggestions("source", "", many).length, 12);
  assert.equal(querySuggestions("x".repeat(8193), 8193, many).length, 0);
});
