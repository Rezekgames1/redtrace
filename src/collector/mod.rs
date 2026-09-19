#[cfg(target_os = "macos")]
mod macos;

use crate::model::Event;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub platform: String,
    pub state: String,
    pub events_collected: usize,
    pub lookback: String,
    pub last_error: Option<String>,
}

#[derive(Debug)]
pub struct CollectionBatch {
    pub events: Vec<Event>,
    pub status: SourceStatus,
}

pub fn collect_platform_events() -> CollectionBatch {
    #[cfg(target_os = "macos")]
    {
        return macos::collect();
    }

    #[allow(unreachable_code)]
    CollectionBatch {
        events: Vec::new(),
        status: SourceStatus {
            name: "unsupported".into(),
            platform: std::env::consts::OS.into(),
            state: "unsupported".into(),
            events_collected: 0,
            lookback: "none".into(),
            last_error: Some("native collector is not implemented for this platform".into()),
        },
    }
}
