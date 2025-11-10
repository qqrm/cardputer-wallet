#![cfg_attr(all(feature = "firmware-bin", target_arch = "xtensa"), no_std)]
#![cfg_attr(all(feature = "firmware-bin", target_arch = "xtensa"), no_main)]

#[cfg(all(feature = "firmware-bin", target_arch = "xtensa"))]
use esp_backtrace as _;

#[cfg(all(feature = "firmware-bin", target_arch = "xtensa"))]
// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(feature = "firmware-bin", target_arch = "xtensa"))]
#[esp_hal::entry]
fn main() -> ! {
    firmware::runtime::main()
}

#[cfg(all(feature = "firmware-bin", not(target_arch = "xtensa")))]
fn main() {
    panic!("`firmware-bin` requires the xtensa target");
}

#[cfg(not(feature = "firmware-bin"))]
fn main() {}
