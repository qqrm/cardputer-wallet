//! Human-interface side of the firmware runtime, including session action queues and the Xtensa
//! runtime entry point.
#[cfg(any(test, target_arch = "xtensa"))]
pub mod actions {
    use alloc::vec::Vec;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::{Channel, Receiver, Sender};

    type QueueMutex = CriticalSectionRawMutex;

    const ACTION_QUEUE_DEPTH: usize = 8;

    static ACTION_CHANNEL: Channel<QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH> = Channel::new();

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DeviceAction {
        StartSession { session_id: u32 },
        EndSession,
    }

    pub type ActionSender = Sender<'static, QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH>;
    pub type ActionReceiver = Receiver<'static, QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH>;

    pub fn action_sender() -> ActionSender {
        ACTION_CHANNEL.sender()
    }

    pub fn action_receiver() -> ActionReceiver {
        ACTION_CHANNEL.receiver()
    }

    pub fn publish(action: DeviceAction) {
        let sender = action_sender();
        let _ = sender.try_send(action);
    }

    #[cfg(test)]
    pub fn clear() {
        action_sender().clear();
        let receiver = action_receiver();
        while receiver.try_receive().is_ok() {}
    }

    #[cfg(test)]
    pub fn drain() -> Vec<DeviceAction> {
        let receiver = action_receiver();
        let mut collected = Vec::new();
        while let Ok(action) = receiver.try_receive() {
            collected.push(action);
        }
        collected
    }
}

#[cfg(target_arch = "xtensa")]
pub mod runtime {
    use super::actions;
    use crate::storage::{self, BootFlash, StorageError};
    use crate::sync::{self, SyncContext};
    use embassy_executor::Executor;
    use esp_alloc::EspHeap;
    use esp_hal::{
        Blocking, Config, clock::CpuClock, timer::timg::TimerGroup, usb_serial_jtag::UsbSerialJtag,
    };
    use esp_storage::FlashStorage;
    use static_cell::StaticCell;

    #[global_allocator]
    static ALLOCATOR: EspHeap = EspHeap::empty();

    fn init_allocator() {
        const HEAP_SIZE: usize = 96 * 1024;
        static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        unsafe { ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP.len()) };
    }

    static EXECUTOR: StaticCell<Executor> = StaticCell::new();

    pub fn main() -> ! {
        init_allocator();

        let mut peripherals = esp_hal::init(Config::default().with_cpu_clock(CpuClock::max()));
        let mut timg0 = TimerGroup::new(peripherals.TIMG0);
        timg0.wdt.disable();

        let timer0 = timg0.timer0;
        esp_hal_embassy::init(timer0);

        let mut flash = BootFlash::new(FlashStorage::new(peripherals.FLASH));
        let boot_context = flash
            .sequential_storage_range()
            .ok_or_else(|| StorageError::Decode("sync flash partition not found".to_string()))
            .and_then(|range| {
                storage::block_on(storage::initialize_context_from_flash(&mut flash, range))
            });

        let usb = UsbSerialJtag::new(peripherals.USB_DEVICE);

        let executor = EXECUTOR.init(Executor::new());
        executor.run(move |spawner| {
            let ble_actions = actions::action_receiver();
            spawner
                .spawn(super::tasks::ble_profile(ble_actions))
                .expect("spawn BLE task");
            spawner
                .spawn(super::tasks::cdc_server(usb, boot_context))
                .expect("spawn CDC task");
        });
    }
}

#[cfg(target_arch = "xtensa")]
mod tasks {
    use super::actions::{self, DeviceAction};
    use crate::storage::{self, StorageError};
    use crate::sync::{self, FRAME_MAX_SIZE, SyncContext, process_host_frame};
    use crate::ui::transport;
    use alloc::{format, vec::Vec};
    use embassy_executor::task;
    use embassy_time::{Duration, Timer};
    use esp_hal::{Blocking, usb_serial_jtag::UsbSerialJtag};
    use nb::Error as NbError;
    use trouble_host::types::capabilities::IoCapabilities;

    use esp_storage::FlashStorageError;

    #[cfg(target_arch = "xtensa")]
    extern "C" {
        fn ets_printf(format: *const core::ffi::c_char, ...) -> i32;
    }

    type BootContext = Result<SyncContext, StorageError<FlashStorageError>>;

    #[task]
    pub async fn cdc_server(mut serial: UsbSerialJtag<'static, Blocking>, ctx: BootContext) {
        let (mut context, mut boot_error) = ctx
            .map(|ctx| (ctx, None))
            .unwrap_or_else(|error| (SyncContext::new(), Some(error)));

        if let Some(error) = &boot_error {
            log_boot_failure(error);
        }

        transport::set_usb_connected(true);
        loop {
            match read_frame(&mut serial).await {
                Ok((command, frame)) => {
                    transport::set_usb_connected(true);
                    if let Some(error) = boot_error.take() {
                        let payload = boot_failure_payload(&error);
                        if let Err(err) =
                            write_frame(&mut serial, shared::cdc::CdcCommand::Nack, &payload)
                        {
                            if matches!(err, sync::ProtocolError::Transport) {
                                transport::set_usb_connected(false);
                            }
                        }
                        continue;
                    }

                    match process_host_frame(command, &frame, &mut context) {
                        Ok((response_command, response)) => {
                            if let Err(err) = write_frame(&mut serial, response_command, &response)
                            {
                                if matches!(err, sync::ProtocolError::Transport) {
                                    transport::set_usb_connected(false);
                                }
                            }
                        }
                        Err(err) => {
                            let payload = match sync::encode_response(
                                &shared::schema::DeviceResponse::Nack(err.as_nack()),
                            ) {
                                Ok(encoded) => encoded,
                                Err(encode_err) => {
                                    let fatal = encode_err.as_nack();
                                    sync::encode_response(&shared::schema::DeviceResponse::Nack(
                                        fatal,
                                    ))
                                    .unwrap_or_default()
                                }
                            };
                            if let Err(err) =
                                write_frame(&mut serial, shared::cdc::CdcCommand::Nack, &payload)
                            {
                                if matches!(err, sync::ProtocolError::Transport) {
                                    transport::set_usb_connected(false);
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    let payload = match sync::encode_response(
                        &shared::schema::DeviceResponse::Nack(err.as_nack()),
                    ) {
                        Ok(encoded) => encoded,
                        Err(encode_err) => {
                            let fatal = encode_err.as_nack();
                            sync::encode_response(&shared::schema::DeviceResponse::Nack(fatal))
                                .unwrap_or_default()
                        }
                    };
                    if matches!(err, sync::ProtocolError::Transport) {
                        transport::set_usb_connected(false);
                    }
                    if let Err(err) =
                        write_frame(&mut serial, shared::cdc::CdcCommand::Nack, &payload)
                    {
                        if matches!(err, sync::ProtocolError::Transport) {
                            transport::set_usb_connected(false);
                        }
                    }
                }
            }
        }
    }

    fn boot_failure_payload(error: &StorageError<FlashStorageError>) -> alloc::vec::Vec<u8> {
        let response = shared::schema::DeviceResponse::Nack(shared::schema::NackResponse {
            protocol_version: shared::schema::PROTOCOL_VERSION,
            code: shared::schema::DeviceErrorCode::InternalFailure,
            message: format!("failed to load flash state: {error}"),
        });

        match sync::encode_response(&response) {
            Ok(encoded) => encoded,
            Err(encode_err) => {
                let fatal = encode_err.as_nack();
                sync::encode_response(&shared::schema::DeviceResponse::Nack(fatal))
                    .unwrap_or_default()
            }
        }
    }

    fn log_boot_failure(error: &StorageError<FlashStorageError>) {
        let mut message = format!("[cdc] failed to restore state: {error}\n").into_bytes();
        message.push(0);

        unsafe {
            let _ = ets_printf(
                b"%s\0".as_ptr() as *const core::ffi::c_char,
                message.as_ptr() as *const core::ffi::c_char,
            );
        }
    }

    async fn read_frame(
        serial: &mut UsbSerialJtag<'static, Blocking>,
    ) -> Result<(shared::cdc::CdcCommand, alloc::vec::Vec<u8>), sync::ProtocolError> {
        use shared::cdc::{FRAME_HEADER_SIZE, decode_frame, decode_frame_header};

        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        for byte in header_bytes.iter_mut() {
            *byte = read_byte(serial).await?;
        }

        let header = decode_frame_header(
            shared::schema::PROTOCOL_VERSION,
            FRAME_MAX_SIZE,
            header_bytes,
        )?;

        let mut buffer = alloc::vec::Vec::with_capacity(header.length as usize);
        for _ in 0..header.length {
            buffer.push(read_byte(serial).await?);
        }

        decode_frame(&header, &buffer)?;

        Ok((header.command, buffer))
    }

    async fn read_byte(
        serial: &mut UsbSerialJtag<'static, Blocking>,
    ) -> Result<u8, sync::ProtocolError> {
        loop {
            match serial.read_byte() {
                Ok(byte) => return Ok(byte),
                Err(NbError::WouldBlock) => Timer::after(Duration::from_micros(250)).await,
                Err(NbError::Other(_)) => return Err(sync::ProtocolError::Transport),
            }
        }
    }

    fn write_frame(
        serial: &mut UsbSerialJtag<'static, Blocking>,
        command: shared::cdc::CdcCommand,
        payload: &[u8],
    ) -> Result<(), sync::ProtocolError> {
        use shared::cdc::encode_frame;

        let header = encode_frame(
            shared::schema::PROTOCOL_VERSION,
            command,
            payload,
            FRAME_MAX_SIZE,
        )?;

        serial
            .write(&header)
            .map_err(|_| sync::ProtocolError::Transport)?;
        if !payload.is_empty() {
            serial
                .write(payload)
                .map_err(|_| sync::ProtocolError::Transport)?;
        }
        serial
            .flush_tx()
            .map_err(|_| sync::ProtocolError::Transport)
    }

    #[task]
    pub async fn ble_profile(mut receiver: actions::ActionReceiver) {
        let _capabilities = IoCapabilities::KeyboardDisplay;
        while let Ok(action) = receiver.recv().await {
            match action {
                DeviceAction::StartSession { session_id } => {
                    let _ = session_id;
                }
                DeviceAction::EndSession => {}
            }
        }
    }
}
