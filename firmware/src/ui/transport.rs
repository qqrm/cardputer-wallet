use alloc::{format, string::String};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::watch::{Receiver, Sender, Watch};

/// High-level transport channels surfaced in the UI status row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    Usb,
    Ble,
}

impl TransportKind {
    fn label(self) -> &'static str {
        match self {
            TransportKind::Usb => "USB",
            TransportKind::Ble => "BLE",
        }
    }

    fn icon_for(self, state: TransportState) -> &'static str {
        match (self, state) {
            (TransportKind::Usb, TransportState::Offline) => "usb-off",
            (TransportKind::Usb, TransportState::Waiting) => "usb-wait",
            (TransportKind::Usb, TransportState::Connecting) => "usb-connect",
            (TransportKind::Usb, TransportState::Connected) => "usb-on",
            (TransportKind::Usb, TransportState::Error) => "usb-error",
            (TransportKind::Ble, TransportState::Offline) => "ble-off",
            (TransportKind::Ble, TransportState::Waiting) => "ble-wait",
            (TransportKind::Ble, TransportState::Connecting) => "ble-connect",
            (TransportKind::Ble, TransportState::Connected) => "ble-on",
            (TransportKind::Ble, TransportState::Error) => "ble-error",
        }
    }
}

/// Transport connectivity states rendered in the UI.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    Offline = 0,
    Waiting = 1,
    Connecting = 2,
    Connected = 3,
    Error = 4,
}

impl TransportState {
    fn description(self) -> &'static str {
        match self {
            TransportState::Offline => "offline",
            TransportState::Waiting => "waiting",
            TransportState::Connecting => "connecting",
            TransportState::Connected => "connected",
            TransportState::Error => "error",
        }
    }
}

/// Transport status metadata exposed by the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportStatus {
    pub kind: TransportKind,
    pub state: TransportState,
    pub icon: &'static str,
    pub text: String,
}

impl TransportStatus {
    pub fn new(kind: TransportKind, state: TransportState) -> Self {
        let text = format!("{} {}", kind.label(), state.description());
        Self {
            kind,
            state,
            icon: kind.icon_for(state),
            text,
        }
    }
}

/// Snapshot of both transport channels rendered in the frame header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportIndicators {
    pub usb: TransportStatus,
    pub ble: TransportStatus,
}

impl TransportIndicators {
    pub fn new(usb: TransportState, ble: TransportState) -> Self {
        Self {
            usb: TransportStatus::new(TransportKind::Usb, usb),
            ble: TransportStatus::new(TransportKind::Ble, ble),
        }
    }
}

type WatchMutex = CriticalSectionRawMutex;

const TRANSPORT_RECEIVER_LIMIT: usize = 4;

static TRANSPORT_WATCH: Watch<WatchMutex, TransportIndicators, TRANSPORT_RECEIVER_LIMIT> =
    Watch::new();

pub type TransportReceiver =
    Receiver<'static, WatchMutex, TransportIndicators, TRANSPORT_RECEIVER_LIMIT>;
pub type TransportSender =
    Sender<'static, WatchMutex, TransportIndicators, TRANSPORT_RECEIVER_LIMIT>;

/// Update the cached USB status indicator.
pub fn set_usb_state(state: TransportState) {
    modify_transport(|indicators| indicators.usb = TransportStatus::new(TransportKind::Usb, state));
}

/// Update the cached BLE status indicator.
pub fn set_ble_state(state: TransportState) {
    modify_transport(|indicators| indicators.ble = TransportStatus::new(TransportKind::Ble, state));
}

/// Snapshot the current transport status for rendering.
pub fn snapshot() -> TransportIndicators {
    TRANSPORT_WATCH.try_get().unwrap_or_else(default_transport)
}

/// Subscribe to transport updates.
pub fn receiver() -> Option<TransportReceiver> {
    TRANSPORT_WATCH.receiver()
}

fn sender() -> TransportSender {
    TRANSPORT_WATCH.sender()
}

fn modify_transport(update: impl Fn(&mut TransportIndicators)) {
    sender().send_if_modified(|state| {
        let mut indicators = state.clone().unwrap_or_else(default_transport);
        let before = indicators.clone();
        update(&mut indicators);
        let changed = indicators != before;
        *state = Some(indicators);
        changed
    });
}

fn default_transport() -> TransportIndicators {
    TransportIndicators::new(TransportState::Offline, TransportState::Offline)
}

#[cfg(test)]
pub fn reset() {
    sender().send(default_transport());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_renders_transport_metadata() {
        reset();
        set_usb_state(TransportState::Waiting);
        set_ble_state(TransportState::Connecting);

        let indicators = snapshot();
        assert_eq!(indicators.usb.text, "USB waiting");
        assert_eq!(indicators.usb.icon, "usb-wait");
        assert_eq!(indicators.ble.state, TransportState::Connecting);
        assert_eq!(indicators.ble.icon, "ble-connect");
    }
}
