import assert from "node:assert/strict";
import test from "node:test";
import { RevisionDecoder } from "../app/events/stream.ts";

test("decodes revisions across chunk boundaries and heartbeat frames", () => {
  const decoder = new RevisionDecoder();
  assert.deepEqual(decoder.push(": keep-alive\n\nevent: upd"), []);
  assert.deepEqual(decoder.push("ate\nid: 12\ndata: 12\n"), []);
  assert.deepEqual(decoder.push("\nevent: update\r\ndata: 13\r\n\r\n"), [12, 13]);
  assert.deepEqual(decoder.push("event: other\ndata: 14\n\nevent: update\ndata: invalid\n\n"), []);
});

test("bounds incomplete frames instead of accumulating an unbounded response", () => {
  const decoder = new RevisionDecoder();
  assert.throws(() => decoder.push("a".repeat(65537)), /limit/);
});
