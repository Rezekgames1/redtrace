export type TimeFilter = { preset: "all" | "15m" | "1h" | "24h" | "7d" | "custom"; from: string; to: string };

export const ALL_TIME: TimeFilter = { preset: "all", from: "", to: "" };

export function timeQuery(filter: TimeFilter, now = Date.now()): string {
  const params = new URLSearchParams();
  if (filter.preset === "all") return "";
  if (filter.preset !== "custom") {
    const milliseconds = { "15m": 900000, "1h": 3600000, "24h": 86400000, "7d": 604800000 }[filter.preset];
    params.set("from", new Date(now - milliseconds).toISOString());
  } else {
    const dates = [filter.from, filter.to].map((value) => value ? new Date(value) : null);
    if (dates.some((date) => date !== null && !Number.isFinite(date.getTime()))) throw new Error("Введите корректную дату и время");
    if (dates[0] && dates[1] && dates[0] >= dates[1]) throw new Error("Начало периода должно быть раньше окончания");
    if (dates[0]) params.set("from", dates[0].toISOString());
    if (dates[1]) params.set("to", dates[1].toISOString());
  }
  return params.size ? `&${params.toString()}` : "";
}
