use core::sync::atomic::{AtomicBool, Ordering};

use super::render::TransportIndicators;
use crate::transport::{HidBackend, LinkKind};

static USB_CONNECTED: AtomicBool = AtomicBool::new(false);
static BLE_CONNECTED: AtomicBool = AtomicBool::new(false);

struct UiBackend;

static UI_BACKEND: UiBackend = UiBackend;

/// Access the singleton HID backend used by the UI layer.
pub fn hid_backend() -> &'static dyn HidBackend {
    &UI_BACKEND
}

/// Update the cached USB status indicator.
pub fn set_usb_connected(connected: bool) {
    USB_CONNECTED.store(connected, Ordering::Relaxed);
}

/// Update the cached BLE status indicator.
pub fn set_ble_connected(connected: bool) {
    BLE_CONNECTED.store(connected, Ordering::Relaxed);
}

/// Snapshot the current transport status for rendering.
pub fn snapshot() -> TransportIndicators {
    TransportIndicators::new(
        USB_CONNECTED.load(Ordering::Relaxed),
        BLE_CONNECTED.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
pub fn reset() {
    set_usb_connected(false);
    set_ble_connected(false);
}

impl HidBackend for UiBackend {
    fn set_connected(&self, kind: LinkKind, connected: bool) {
        match kind {
            LinkKind::Usb => set_usb_connected(connected),
            LinkKind::Ble => set_ble_connected(connected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_updates_indicators() {
        reset();
        let backend = hid_backend();
        backend.set_connected(LinkKind::Usb, true);
        backend.set_connected(LinkKind::Ble, true);
        assert!(snapshot().usb_connected);
        assert!(snapshot().ble_connected);
    }
}
