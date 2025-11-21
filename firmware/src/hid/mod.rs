//! Human-interface side of the firmware runtime, including session action queues and the Xtensa
//! runtime entry point.

pub mod core;
pub use core::actions;

#[cfg(any(test, target_arch = "xtensa", feature = "ui-tests"))]
pub mod ble;

#[cfg(target_arch = "xtensa")]
pub mod usb;

#[cfg(target_arch = "xtensa")]
pub use usb::runtime;
