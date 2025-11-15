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
    use crate::transport::usb::UsbCdcLink;
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
            let backend = crate::ui::transport::hid_backend();
            spawner
                .spawn(super::tasks::ble_profile(ble_actions, backend))
                .expect("spawn BLE task");
            let usb_link = UsbCdcLink::new(usb, backend);
            spawner
                .spawn(super::tasks::cdc_server(usb_link, boot_context))
                .expect("spawn CDC task");
        });
    }
}

#[cfg(target_arch = "xtensa")]
mod tasks {
    use super::actions::{self, DeviceAction};
    use crate::storage::{self, StorageError};
    use crate::sync::{self, SyncContext, process_host_frame};
    use crate::transport::{HidBackend, LinkKind, TransportLink};
    use alloc::{format, vec::Vec};
    use embassy_executor::task;
    use trouble_host::types::capabilities::IoCapabilities;

    use esp_storage::FlashStorageError;

    #[cfg(target_arch = "xtensa")]
    extern "C" {
        fn ets_printf(format: *const core::ffi::c_char, ...) -> i32;
    }

    type BootContext = Result<SyncContext, StorageError<FlashStorageError>>;

    #[task]
    pub async fn cdc_server<L>(mut link: L, ctx: BootContext)
    where
        L: TransportLink + 'static,
    {
        let (mut context, mut boot_error) = ctx
            .map(|ctx| (ctx, None))
            .unwrap_or_else(|error| (SyncContext::new(), Some(error)));

        if let Some(error) = &boot_error {
            log_boot_failure(error);
        }

        link.mark_connected();
        loop {
            match link.read_frame().await {
                Ok((command, frame)) => {
                    link.mark_connected();
                    if let Some(error) = boot_error.take() {
                        let payload = boot_failure_payload(&error);
                        if let Err(err) = link
                            .write_frame(shared::cdc::CdcCommand::Nack, &payload)
                            .await
                        {
                            if matches!(err, sync::ProtocolError::Transport) {
                                link.mark_disconnected();
                            }
                        }
                        continue;
                    }

                    match process_host_frame(command, &frame, &mut context) {
                        Ok((response_command, response)) => {
                            if let Err(err) = link.write_frame(response_command, &response).await {
                                if matches!(err, sync::ProtocolError::Transport) {
                                    link.mark_disconnected();
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
                            if let Err(err) = link
                                .write_frame(shared::cdc::CdcCommand::Nack, &payload)
                                .await
                            {
                                if matches!(err, sync::ProtocolError::Transport) {
                                    link.mark_disconnected();
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
                        link.mark_disconnected();
                    }
                    if let Err(err) = link
                        .write_frame(shared::cdc::CdcCommand::Nack, &payload)
                        .await
                    {
                        if matches!(err, sync::ProtocolError::Transport) {
                            link.mark_disconnected();
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

    #[task]
    pub async fn ble_profile(
        mut receiver: actions::ActionReceiver,
        backend: &'static dyn HidBackend,
    ) {
        let _capabilities = IoCapabilities::KeyboardDisplay;
        backend.mark_disconnected(LinkKind::Ble);
        while let Ok(action) = receiver.recv().await {
            match action {
                DeviceAction::StartSession { session_id } => {
                    let _ = session_id;
                    backend.mark_connected(LinkKind::Ble);
                }
                DeviceAction::EndSession => backend.mark_disconnected(LinkKind::Ble),
            }
        }
    }
}
