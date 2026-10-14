use futures_util::{Stream, stream};
use tokio::sync::watch;

#[derive(Clone)]
pub struct LiveUpdates(watch::Sender<u64>);

impl Default for LiveUpdates {
    fn default() -> Self {
        Self(watch::channel(0).0)
    }
}

impl LiveUpdates {
    pub fn notify(&self) {
        self.0
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    pub fn subscribe(&self) -> impl Stream<Item = u64> + Send + 'static + use<> {
        stream::unfold(
            (self.0.subscribe(), true),
            |(mut receiver, initial)| async move {
                if !initial && receiver.changed().await.is_err() {
                    return None;
                }
                let revision = *receiver.borrow_and_update();
                Some((revision, (receiver, false)))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{StreamExt, pin_mut};

    #[tokio::test]
    async fn delivers_initial_revision_and_coalesces_slow_consumers() {
        let updates = LiveUpdates::default();
        let stream = updates.subscribe();
        pin_mut!(stream);
        assert_eq!(stream.next().await, Some(0));
        updates.notify();
        updates.notify();
        assert_eq!(stream.next().await, Some(2));
        updates.notify();
        assert_eq!(stream.next().await, Some(3));
    }
}
