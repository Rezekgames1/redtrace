export type EventLevel = "critical" | "high" | "medium" | "low";

export type UiEvent = {
  uid: string;
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
  nextCursor: string | null;
  hours: number[];
};

export type DetectionAlert = {
  id: string;
  rule_id: string;
  title: string;
  severity: EventLevel;
  confidence: number;
  risk_score: number;
  mitre_technique: string;
  timestamp: string;
  group_key: string;
  evidence: string[];
  description: string;
};
