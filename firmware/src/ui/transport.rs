use alloc::{format, string::String};
use core::sync::atomic::{AtomicU8, Ordering};

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
    fn from_u8(value: u8) -> Self {
        match value {
            1 => TransportState::Waiting,
            2 => TransportState::Connecting,
            3 => TransportState::Connected,
            4 => TransportState::Error,
            _ => TransportState::Offline,
        }
    }

    const fn as_u8(self) -> u8 {
        self as u8
    }

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

static USB_STATE: AtomicU8 = AtomicU8::new(TransportState::Offline.as_u8());
static BLE_STATE: AtomicU8 = AtomicU8::new(TransportState::Offline.as_u8());

/// Update the cached USB status indicator.
pub fn set_usb_state(state: TransportState) {
    USB_STATE.store(state.as_u8(), Ordering::Relaxed);
}

/// Update the cached BLE status indicator.
pub fn set_ble_state(state: TransportState) {
    BLE_STATE.store(state.as_u8(), Ordering::Relaxed);
}

fn load_state(atom: &AtomicU8) -> TransportState {
    TransportState::from_u8(atom.load(Ordering::Relaxed))
}

/// Snapshot the current transport status for rendering.
pub fn snapshot() -> TransportIndicators {
    TransportIndicators::new(load_state(&USB_STATE), load_state(&BLE_STATE))
}

#[cfg(test)]
pub fn reset() {
    set_usb_state(TransportState::Offline);
    set_ble_state(TransportState::Offline);
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
