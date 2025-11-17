use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::watch::{Receiver as WatchReceiver, Sender as WatchSender, Watch};
use embassy_time::{Duration, Instant};

/// Mutex used by the time broadcast channel.
pub type TimeMutex = CriticalSectionRawMutex;

/// Maximum number of concurrent time subscribers.
const TIME_SUBSCRIBERS: usize = 8;

static TIME_UPDATES: Watch<TimeMutex, u64, TIME_SUBSCRIBERS> = Watch::new_with(0);

/// Sender used to push wall-clock updates to other tasks.
pub type TimeSender = WatchSender<'static, TimeMutex, u64, TIME_SUBSCRIBERS>;
/// Receiver used to observe wall-clock updates.
pub type TimeReceiver = WatchReceiver<'static, TimeMutex, u64, TIME_SUBSCRIBERS>;

/// Obtain a sender for the global time broadcast channel.
pub fn time_sender() -> TimeSender {
    TIME_UPDATES.sender()
}

/// Obtain a receiver for the global time broadcast channel.
pub fn time_receiver() -> TimeReceiver {
    TIME_UPDATES
        .receiver()
        .expect("time watch should always have capacity for subscribers")
}

/// Publish the current wall-clock timestamp in milliseconds since the Unix epoch.
pub fn publish_time(now_ms: u64) {
    time_sender().send(now_ms);
}

/// Monotonic clock calibrated against an epoch offset.
#[derive(Clone, Debug)]
pub struct CalibratedClock {
    anchor: Instant,
    offset_ms: i128,
}

impl CalibratedClock {
    /// Create a new clock anchored to the current instant.
    pub fn new() -> Self {
        Self {
            anchor: Instant::now(),
            offset_ms: 0,
        }
    }

    /// Current time in milliseconds since the Unix epoch.
    pub fn current_time_ms(&self) -> u64 {
        let elapsed_ms = self.elapsed_ms();
        let adjusted = elapsed_ms + self.offset_ms;

        if adjusted.is_negative() {
            0
        } else {
            adjusted.min(u64::MAX as i128) as u64
        }
    }

    /// Recalibrate the epoch offset using the provided timestamp.
    pub fn set_time_ms(&mut self, epoch_ms: u64) -> u64 {
        let elapsed_ms = self.elapsed_ms();
        self.offset_ms = epoch_ms as i128 - elapsed_ms;
        self.current_time_ms()
    }

    fn elapsed_ms(&self) -> i128 {
        let now = Instant::now();
        let elapsed = now
            .checked_duration_since(self.anchor)
            .unwrap_or_else(|| Duration::from_millis(0));
        elapsed.as_millis() as i128
    }
}

impl Default for CalibratedClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_offset_when_setting_time() {
        let mut clock = CalibratedClock::new();
        let now_ms = clock.current_time_ms();
        let updated = clock.set_time_ms(now_ms + 5_000);

        assert!(updated >= now_ms + 5_000);
    }

    #[test]
    fn saturates_before_underflow() {
        let mut clock = CalibratedClock::new();
        let _ = clock.set_time_ms(1_000);
        clock.offset_ms = -10_000;

        assert_eq!(clock.current_time_ms(), 0);
    }
}
