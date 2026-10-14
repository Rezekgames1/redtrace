import assert from "node:assert/strict";
import test from "node:test";
import { appendFilter, quoteValue, valueFilter } from "../app/events/query.ts";

test("filter values preserve quotes, Windows paths and boolean-looking content", () => {
  assert.equal(quoteValue('C:\\Program Files\\app.exe "x"'), '"C:\\\\Program Files\\\\app.exe \\"x\\""');
  assert.equal(valueFilter("message", "a OR b", "contains"), 'message~"a OR b"');
  assert.equal(valueFilter("user.name", "admin", "exact", true), 'NOT (user.name="admin")');
  assert.equal(valueFilter("process.pid", "", "exists"), "process.pid:*");
});

test("adding a filter preserves existing OR precedence", () => {
  assert.equal(appendFilter("a OR b", "event.id=4625"), "(a OR b) AND (event.id=4625)");
  assert.equal(appendFilter("*", "event.id=4625"), "event.id=4625");
});
