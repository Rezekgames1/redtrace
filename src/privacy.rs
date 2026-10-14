use crate::model::Event;

const REDACTED: &str = "[REDACTED]";

pub fn redact_event(event: &Event) -> Event {
    let mut event = event.clone();
    for (field, value) in &mut event.fields {
        if sensitive_name(field) {
            *value = REDACTED.into();
        } else if field == "process.command_line" {
            *value = redact_command_line(value);
        }
    }
    event
}

pub fn csv_cell(value: &str) -> String {
    let protected = if value.trim_start().starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", protected.replace('"', "\"\""))
}

fn sensitive_name(name: &str) -> bool {
    let compact = name.to_ascii_lowercase().replace(['.', '-', '_'], "");
    [
        "password",
        "passwd",
        "accesstoken",
        "refreshtoken",
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn redact_command_line(command: &str) -> String {
    let parts: Vec<_> = command.split_whitespace().collect();
    let mut output = Vec::with_capacity(parts.len());
    let mut hide_next = false;
    for part in parts {
        if hide_next {
            output.push(REDACTED.to_owned());
            hide_next = false;
            continue;
        }
        let lower = part.to_ascii_lowercase();
        if let Some((name, _)) = lower.split_once('=')
            && sensitive_name(name.trim_start_matches('-'))
        {
            let original_name = part.split_once('=').map(|(name, _)| name).unwrap_or(part);
            output.push(format!("{original_name}={REDACTED}"));
            continue;
        }
        output.push(part.to_owned());
        hide_next = lower.starts_with('-') && sensitive_name(lower.trim_start_matches('-'));
    }
    output.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn redacts_sensitive_fields_and_command_arguments() {
        let event = Event::normalized(
            1,
            "2026-01-01T00:00:00Z".into(),
            "test".into(),
            "low".into(),
            "test".into(),
            BTreeMap::from([
                (
                    "http.request.header.authorization".into(),
                    "Bearer abc".into(),
                ),
                (
                    "process.command_line".into(),
                    "tool --password hunter2 --api-key=value safe".into(),
                ),
            ]),
        );
        let redacted = redact_event(&event);
        assert_eq!(
            redacted.fields["http.request.header.authorization"],
            REDACTED
        );
        assert_eq!(
            redacted.fields["process.command_line"],
            "tool --password [REDACTED] --api-key=[REDACTED] safe"
        );
    }

    #[test]
    fn prevents_csv_formula_execution() {
        assert_eq!(csv_cell("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
        assert_eq!(csv_cell("normal"), "\"normal\"");
    }
}
