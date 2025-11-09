#![cfg(all(feature = "firmware-bin", target_arch = "xtensa"))]
#![no_std]
#![no_main]

use esp_backtrace as _;

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal::entry]
fn main() -> ! {
    firmware::runtime::main()
}
