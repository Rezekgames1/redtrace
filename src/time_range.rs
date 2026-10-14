use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Default, Deserialize)]
pub struct TimeRangeParams {
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Default)]
pub struct TimeRange {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

impl TimeRange {
    pub fn parse(params: &TimeRangeParams) -> Result<Self, &'static str> {
        let parse = |value: &Option<String>| -> Result<Option<DateTime<Utc>>, &'static str> {
            value
                .as_ref()
                .map(|value| {
                    if value.len() > 64 {
                        return Err("time bounds must be RFC3339 timestamps with a timezone");
                    }
                    DateTime::parse_from_rfc3339(value)
                        .map(|at| at.to_utc())
                        .map_err(|_| "time bounds must be RFC3339 timestamps with a timezone")
                })
                .transpose()
        };
        let range = Self {
            from: parse(&params.from)?,
            to: parse(&params.to)?,
        };
        if range
            .from
            .zip(range.to)
            .is_some_and(|(from, to)| from >= to)
        {
            return Err("time range start must precede its end");
        }
        Ok(range)
    }

    pub fn contains(&self, timestamp: &str) -> bool {
        if self.from.is_none() && self.to.is_none() {
            return true;
        }
        DateTime::parse_from_rfc3339(timestamp).is_ok_and(|at| {
            let at = at.to_utc();
            self.from.is_none_or(|from| at >= from) && self.to.is_none_or(|to| at < to)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timezone_offsets_and_subseconds_use_inclusive_start_exclusive_end() {
        let range = TimeRange::parse(&TimeRangeParams {
            from: Some("2026-10-13T09:00:00+03:00".into()),
            to: Some("2026-10-13T07:00:00Z".into()),
        })
        .unwrap();
        assert!(!range.contains("2026-10-13T05:59:59.999999Z"));
        assert!(range.contains("2026-10-13T06:00:00Z"));
        assert!(range.contains("2026-10-13T06:59:59.999999Z"));
        assert!(!range.contains("2026-10-13T07:00:00Z"));
        assert!(!range.contains("invalid"));
    }

    #[test]
    fn open_bounds_and_invalid_or_reversed_ranges_are_explicit() {
        assert!(TimeRange::default().contains("legacy"));
        assert!(
            TimeRange::parse(&TimeRangeParams {
                from: Some("2026-10-13".into()),
                to: None
            })
            .is_err()
        );
        assert!(
            TimeRange::parse(&TimeRangeParams {
                from: Some("2026-10-13T07:00:00Z".into()),
                to: Some("2026-10-13T06:00:00Z".into())
            })
            .is_err()
        );
        let range = TimeRange::parse(&TimeRangeParams {
            from: None,
            to: Some("2026-10-13T06:00:00Z".into()),
        })
        .unwrap();
        assert!(range.contains("2026-01-01T00:00:00Z"));
    }
}
