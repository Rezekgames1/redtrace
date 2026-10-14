import assert from "node:assert/strict";
import test from "node:test";
import { ALL_TIME, timeQuery } from "../app/events/time.ts";

test("rolling presets and timezone-aware custom ranges produce shared API bounds", () => {
  const now = Date.parse("2026-10-13T07:00:00Z");
  assert.equal(timeQuery(ALL_TIME, now), "");
  const rolling = new URLSearchParams(timeQuery({ ...ALL_TIME, preset: "1h" }, now).slice(1));
  assert.equal(rolling.get("from"), "2026-10-13T06:00:00.000Z");
  const custom = new URLSearchParams(timeQuery({ preset: "custom", from: "2026-10-13T09:00:00+03:00", to: "2026-10-13T07:00:00Z" }).slice(1));
  assert.equal(custom.get("from"), "2026-10-13T06:00:00.000Z");
  assert.equal(custom.get("to"), "2026-10-13T07:00:00.000Z");
  assert.throws(() => timeQuery({ preset: "custom", from: "invalid", to: "" }));
  assert.throws(() => timeQuery({ preset: "custom", from: "2026-10-13T07:00:00Z", to: "2026-10-13T06:00:00Z" }));
});
