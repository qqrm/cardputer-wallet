# Firmware crate

This crate hosts the embedded firmware for the Cardputer wallet prototype. The target microcontroller for the initial bring-up is the **ESP32-S3**.

The crate integrates the `embassy` async embedded framework together with `esp-hal` support packages to manage the ESP32-S3 peripherals. The actual firmware logic will live in `src/` as the project evolves.
