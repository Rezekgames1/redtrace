export type EventLevel = "critical" | "high" | "medium" | "low";

export type UiEvent = {
  uid: number;
  time: string;
  level: EventLevel;
  source: string;
  title: string;
  fields: Record<string, string>;
  raw: string;
};

export type SearchResult = {
  events: UiEvent[];
  total: number;
  took: string;
};
