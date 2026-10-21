import type { UiEvent } from "./types";

// Summaries explain recorded facts; the original message remains searchable and
// available in event.description and raw JSON. Missing facts stay missing.
export function eventTitle(source: string, message: string, fields: Record<string, string>): string {
  if (source === "macos.authd" && fields["authorization.right"]) {
    const outcome = fields["event.outcome"];
    const action = outcome === "success" ? "Разрешено право" : outcome === "failure" ? "Отказ в праве" : "Запрос права";
    const client = fields["client.process.name"];
    return `${action} ${fields["authorization.right"]}${client ? ` · ${client}` : ""}`;
  }
  if (source === "macos.sudo" && fields["sudo.command"]) {
    const id = fields["event.id"];
    const action = id === "sudo.command.failure" ? "отказ в запуске" : id === "sudo.command.allowed" ? "разрешён запуск" : "запрос запуска";
    const user = fields["user.name"];
    const target = fields["user.target.name"];
    return `sudo: ${action}${user ? ` · ${user}` : ""}${target ? ` → ${target}` : ""}`;
  }
  if ((source === "macos.sshd" || source === "macos.sshd-session") && fields["source.ip"]) {
    const id = fields["event.id"];
    if (id === "ssh.login.success" || id === "ssh.login.failure") {
      return `SSH: ${id === "ssh.login.success" ? "вход разрешён" : "отказ во входе"}${fields["user.name"] ? ` · ${fields["user.name"]}` : ""} · ${fields["source.ip"]}${fields["source.port"] ? `:${fields["source.port"]}` : ""}`;
    }
  }
  return message;
}

export function eventContext(event: Pick<UiEvent, "source" | "title" | "fields">): string | undefined {
  const fields = event.fields;
  if (event.source === "macos.authd" && fields["client.process.executable"]) {
    return `${fields["client.process.executable"]}${fields["client.process.pid"] ? ` · PID ${fields["client.process.pid"]}` : ""}`;
  }
  const candidates = [fields["sudo.command"], fields["process.command_line"], fields["source.ip"], fields["file.path"]];
  return candidates.find(value => value && value !== "н/д" && !event.title.toLowerCase().includes(value.toLowerCase()));
}
