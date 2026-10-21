import assert from "node:assert/strict";
import test from "node:test";
import { eventContext, eventTitle } from "../app/events/summary.ts";

test("authd explains the right and requesting app instead of repeating authd's own command line", () => {
  const fields = {
    "authorization.right": "com.apple.ServiceManagement.daemons.modify", "event.outcome": "success",
    "client.process.name": "fixture-client", "client.process.executable": "/usr/libexec/fixture-client", "client.process.pid": "123",
    "process.command_line": "/usr/libexec/authd", "process.pid": "42",
  };
  const title = eventTitle("macos.authd", "Original evidence", fields);
  assert.equal(title, "Разрешено право com.apple.ServiceManagement.daemons.modify · fixture-client");
  assert.equal(eventContext({ source: "macos.authd", title, fields }), "/usr/libexec/fixture-client · PID 123");
  assert.equal(eventTitle("macos.authd", "Original evidence", { ...fields, "event.outcome": "failure" }), "Отказ в праве com.apple.ServiceManagement.daemons.modify · fixture-client");
  assert.equal(fields["process.pid"], "42");
});

test("sudo summarizes the request and preserves the requested command separately from the sudo process", () => {
  const fields = { "event.id": "sudo.command.failure", "user.name": "fixture", "user.target.name": "root", "sudo.command": "/usr/bin/id -u", "process.command_line": "sudo -n /usr/bin/id -u" };
  const title = eventTitle("macos.sudo", "Original evidence", fields);
  assert.equal(title, "sudo: отказ в запуске · fixture → root");
  assert.equal(eventContext({ source: "macos.sudo", title, fields }), "/usr/bin/id -u");
  assert.match(eventTitle("macos.sudo", "Original evidence", { ...fields, "event.id": "sudo.command.allowed" }), /разрешён запуск/);
  assert.match(eventTitle("macos.sudo", "Original evidence", { ...fields, "event.id": "sudo.event" }), /запрос запуска/);
});

test("unsupported, historical and incomplete records keep their original message", () => {
  for (const source of ["macos.authd", "macos.sudo", "windows.security", "linux.journald"]) {
    assert.equal(eventTitle(source, "Original <private> evidence", {}), "Original <private> evidence");
  }
  assert.equal(eventContext({ source: "macos.sudo", title: "Original", fields: { "process.command_line": "н/д" } }), undefined);
  const fields = { "event.id": "ssh.login.failure", "user.name": "fixture", "source.ip": "192.0.2.5", "source.port": "43210" };
  assert.equal(eventTitle("macos.sshd-session", "Original", fields), "SSH: отказ во входе · fixture · 192.0.2.5:43210");
});
