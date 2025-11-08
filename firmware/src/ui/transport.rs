use core::sync::atomic::{AtomicBool, Ordering};

use super::render::TransportIndicators;

static USB_CONNECTED: AtomicBool = AtomicBool::new(false);
static BLE_CONNECTED: AtomicBool = AtomicBool::new(false);

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
