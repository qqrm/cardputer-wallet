#![cfg(target_arch = "xtensa")]

type BootContext =
    Result<crate::sync::SyncContext, crate::storage::StorageError<esp_storage::FlashStorageError>>;

const USB_MAX_PACKET_SIZE: u16 = 64;

mod tasks {
    use super::BootContext;
    use super::USB_MAX_PACKET_SIZE;
    use crate::hid::ble::{BleHid, HidError, profile};
    use crate::hid::core::actions;
    use crate::hid::usb::usb::{UsbEventReceiver, UsbTransportEvent};
    use crate::storage::{self, BootFlash, StorageError};
    use crate::sync::{self, FRAME_MAX_SIZE, process_host_frame};
    use crate::time::{self, CalibratedClock};
    use crate::ui::transport::{self, TransportState};
    use alloc::{format, vec, vec::Vec};
    use embassy_executor::task;
    use embassy_futures::select::{Either, select};
    use embassy_sync::{
        blocking_mutex::raw::CriticalSectionRawMutex,
        channel::{Channel, Receiver, Sender},
        signal::Signal,
    };
    use embassy_time::{Duration, Ticker, Timer};
    use embassy_usb::{
        UsbDevice,
        class::cdc_acm::{BufferedReceiver, Sender as CdcSender},
        driver::EndpointError,
    };
    use embedded_io_async::Read;
    use shared::cdc::FRAME_HEADER_SIZE;
    use shared::cdc::transport::{decode_frame, decode_frame_header};
    use shared::schema::PROTOCOL_VERSION;
    use trouble_host::IoCapabilities;

    use esp_storage::FlashStorageError;

    #[cfg(any(test, feature = "ui-tests"))]
    use core::sync::atomic::{AtomicU64, Ordering};

    unsafe extern "C" {
        fn ets_printf(format: *const core::ffi::c_char, ...) -> i32;
    }

    const HOST_FRAME_QUEUE_DEPTH: usize = 4;

    type HostFrameResult = Result<(shared::cdc::CdcCommand, Vec<u8>), HostFrameError>;
    type HostFrameSender =
        Sender<'static, CriticalSectionRawMutex, HostFrameJob, HOST_FRAME_QUEUE_DEPTH>;
    type HostFrameReceiver =
        Receiver<'static, CriticalSectionRawMutex, HostFrameJob, HOST_FRAME_QUEUE_DEPTH>;
    type HostFrameResponseSender =
        Sender<'static, CriticalSectionRawMutex, HostFrameResult, HOST_FRAME_QUEUE_DEPTH>;
    type HostFrameResponseReceiver =
        Receiver<'static, CriticalSectionRawMutex, HostFrameResult, HOST_FRAME_QUEUE_DEPTH>;

    static HOST_FRAME_CHANNEL: Channel<
        CriticalSectionRawMutex,
        HostFrameJob,
        HOST_FRAME_QUEUE_DEPTH,
    > = Channel::new();

    static HOST_FRAME_RESPONSE_CHANNEL: Channel<
        CriticalSectionRawMutex,
        HostFrameResult,
        HOST_FRAME_QUEUE_DEPTH,
    > = Channel::new();

    #[derive(Debug)]
    struct HostFrameJob {
        command: shared::cdc::CdcCommand,
        frame: Vec<u8>,
    }

    #[derive(Debug)]
    enum HostFrameError {
        Boot(Vec<u8>),
        Protocol(sync::ProtocolError),
    }

    #[cfg(any(test, feature = "ui-tests"))]
    static SLOW_FLASH_DELAY_MS: AtomicU64 = AtomicU64::new(0);

    pub fn host_frame_sender() -> HostFrameSender {
        HOST_FRAME_CHANNEL.sender()
    }

    pub fn host_frame_receiver() -> HostFrameReceiver {
        HOST_FRAME_CHANNEL.receiver()
    }

    pub fn host_frame_response_sender() -> HostFrameResponseSender {
        HOST_FRAME_RESPONSE_CHANNEL.sender()
    }

    pub fn host_frame_response_receiver() -> HostFrameResponseReceiver {
        HOST_FRAME_RESPONSE_CHANNEL.receiver()
    }

    #[cfg(any(test, feature = "ui-tests"))]
    pub fn set_flash_delay_ms(delay_ms: u64) {
        SLOW_FLASH_DELAY_MS.store(delay_ms, Ordering::Relaxed);
    }

    async fn maybe_simulate_flash_delay() {
        #[cfg(any(test, feature = "ui-tests"))]
        {
            let delay_ms = SLOW_FLASH_DELAY_MS.load(Ordering::Relaxed);
            if delay_ms > 0 {
                Timer::after_millis(delay_ms).await;
            }
        }
    }

    #[task]
    pub async fn usb_device(
        mut device: UsbDevice<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
    ) {
        device.run().await;
    }

    #[task]
    pub async fn flash_restore_task(
        flash: &'static mut BootFlash<'static>,
        signal: &'static Signal<CriticalSectionRawMutex, BootContext>,
        retry_delay_ms: u64,
    ) {
        loop {
            let boot_result = async {
                let range = flash.sequential_storage_range().await.ok_or_else(|| {
                    StorageError::Decode("sync flash partition not found".to_string())
                })?;

                storage::initialize_context_from_flash(flash, range).await
            }
            .await;

            let restore_ok = boot_result.is_ok();
            signal.signal(boot_result);

            if restore_ok {
                break;
            }

            if retry_delay_ms > 0 {
                Timer::after_millis(retry_delay_ms).await;
            }
        }
    }

    #[task]
    pub async fn frame_worker(
        jobs: HostFrameReceiver,
        responses: HostFrameResponseSender,
        boot_signal: &'static Signal<CriticalSectionRawMutex, BootContext>,
    ) {
        let mut boot_state = boot_signal.wait().await;
        if let Err(error) = &boot_state {
            log_boot_failure(error);
        }

        loop {
            if let Some(updated) = boot_signal.try_take() {
                if let Err(error) = &updated {
                    log_boot_failure(error);
                }
                boot_state = updated;
            }

            let job = jobs.receive().await;
            maybe_simulate_flash_delay().await;

            let response = match boot_state.as_mut() {
                Ok(ctx) => process_host_frame(job.command, &job.frame, ctx)
                    .map_err(HostFrameError::Protocol),
                Err(error) => Err(HostFrameError::Boot(boot_failure_payload(error))),
            };

            let _ = responses.send(response).await;
        }
    }

    #[task]
    pub async fn time_broadcast() {
        let mut receiver = time::time_receiver();
        let mut clock = CalibratedClock::new();

        if let Some(current_time) = receiver.try_get() {
            clock.set_time_ms(current_time);
        }

        loop {
            let next_time = receiver.changed().await;
            clock.set_time_ms(next_time);
        }
    }

    #[task]
    pub async fn ble_profile(mut receiver: actions::ActionReceiver) {
        transport::set_ble_state(TransportState::Waiting);

        let mut ticker = Ticker::every(Duration::from_millis(5));

        let profile = match profile::TroubleProfile::new("Cardputer") {
            Ok(profile) => profile,
            Err(error) => {
                transport::set_ble_state(TransportState::Error);
                log::error!("Failed to initialize BLE HID profile: {error:?}");
                return;
            }
        };

        let mut hid = BleHid::new(profile, IoCapabilities::KeyboardDisplay);

        loop {
            match select(ticker.next(), receiver.receive()).await {
                Either::First(_) => {}
                Either::Second(action) => {
                    if process_action(&mut hid, action).is_err() {
                        transport::set_ble_state(TransportState::Error);
                        break;
                    }
                }
            }
        }
    }

    fn process_action(hid: &mut BleHid, action: actions::DeviceAction) -> Result<(), HidError> {
        match action {
            actions::DeviceAction::StartSession { session_id } => {
                hid.start_session(session_id).map(|_| ())
            }
            actions::DeviceAction::EndSession => hid.end_session().map(|_| ()),
            actions::DeviceAction::SendReport { session_id, report } => {
                hid.send_report(session_id, &report).map(|_| ())
            }
            actions::DeviceAction::HoldKeys { session_id, hold } => {
                hid.send_hold(session_id, &hold).map(|_| ())
            }
            actions::DeviceAction::StreamMacro { session_id, buffer } => {
                hid.stream_macro(session_id, &buffer).map(|_| ())
            }
        }
    }

    #[task]
    pub async fn cdc_server(
        mut receiver: BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        mut sender: CdcSender<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        mut events: UsbEventReceiver,
        frame_jobs: HostFrameSender,
        frame_responses: HostFrameResponseReceiver,
    ) {
        let max_packet_size = USB_MAX_PACKET_SIZE as usize;
        loop {
            match select(
                select(
                    receive_frame(&mut receiver, max_packet_size),
                    frame_responses.receive(),
                ),
                events.receive(),
            )
            .await
            {
                Either::First(Either::First(Ok(job))) => {
                    frame_jobs.send(job).await;
                }
                Either::First(Either::First(Err(FrameIoError::UsbError(error)))) => {
                    log::error!("Failed to read from CDC endpoint: {error:?}");
                }
                Either::First(Either::First(Err(FrameIoError::Protocol(error)))) => {
                    log::warn!("Failed to parse CDC frame: {error:?}");
                    let nack = sync::encode_response(&shared::schema::DeviceResponse::Nack(
                        error.as_nack(),
                    ));

                    if let Ok(response) = nack {
                        let _ = send(&mut sender, response).await;
                    }
                }
                Either::First(Either::Second(Ok((_, payload)))) => {
                    if send(&mut sender, payload).await.is_err() {
                        log::warn!("CDC disconnected while sending response");
                    }
                }
                Either::First(Either::Second(Err(HostFrameError::Boot(bytes)))) => {
                    if send(&mut sender, bytes).await.is_err() {
                        log::warn!("CDC disconnected while sending boot error");
                    }
                }
                Either::First(Either::Second(Err(HostFrameError::Protocol(error)))) => {
                    let response = sync::encode_response(&shared::schema::DeviceResponse::Nack(
                        error.as_nack(),
                    ));

                    if let Ok(response) = response {
                        let _ = send(&mut sender, response).await;
                    }
                }
                Either::Second(event) => match event {
                    UsbTransportEvent::Enabled => log::info!("usb enabled"),
                    UsbTransportEvent::Disabled => log::info!("usb disabled"),
                    UsbTransportEvent::Suspended => log::info!("usb suspended"),
                    UsbTransportEvent::Resumed => log::info!("usb resumed"),
                },
            }
        }
    }

    fn log_boot_failure(error: &StorageError<FlashStorageError>) {
        log::error!("[cdc] failed to restore state: {error:?}");
    }

    fn storage_protocol_error(error: &StorageError<FlashStorageError>) -> sync::ProtocolError {
        sync::ProtocolError::Decode(format!("{error:?}"))
    }

    fn boot_failure_payload(error: &StorageError<FlashStorageError>) -> Vec<u8> {
        match sync::encode_response(&shared::schema::DeviceResponse::Nack(
            storage_protocol_error(error).as_nack(),
        )) {
            Ok(encoded) => encoded,
            Err(encode_err) => {
                let fatal = encode_err.as_nack();
                let mut bytes =
                    format!("[cdc] failed to serialize response: {fatal:?}\n").into_bytes();
                bytes.truncate(USB_MAX_PACKET_SIZE as usize);
                bytes
            }
        }
    }

    enum FrameIoError {
        UsbError(EndpointError),
        Protocol(sync::ProtocolError),
    }

    async fn receive_frame(
        receiver: &mut BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        packet_size: usize,
    ) -> Result<HostFrameResult, FrameIoError> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        let mut offset = 0usize;

        loop {
            let chunk = receiver
                .read(&mut header[offset..])
                .await
                .map_err(FrameIoError::UsbError)?;

            offset += chunk;

            if offset == header.len() {
                break;
            }
        }

        let decoded_header = decode_frame_header(PROTOCOL_VERSION, FRAME_MAX_SIZE, header)
            .map_err(|error| FrameIoError::Protocol(error.into()))?;
        let mut payload = vec![0u8; decoded_header.length as usize];
        offset = 0;
        loop {
            let to_read = core::cmp::min(packet_size, payload.len() - offset);
            let chunk = receiver
                .read(&mut payload[offset..offset + to_read])
                .await
                .map_err(FrameIoError::UsbError)?;
            offset += chunk;
            if offset == payload.len() {
                break;
            }
        }

        decode_frame(&decoded_header, &payload)
            .map_err(|error| FrameIoError::Protocol(error.into()))?;

        Ok(Ok((decoded_header.command, payload)))
    }

    async fn send(
        sender: &mut CdcSender<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        data: Vec<u8>,
    ) -> Result<(), EndpointError> {
        let mut offset = 0usize;

        while offset < data.len() {
            let end = core::cmp::min(offset + USB_MAX_PACKET_SIZE as usize, data.len());
            sender.write_packet(&data[offset..end]).await?;
            offset = end;
        }

        Ok(())
    }
}

pub mod runtime {
    use super::BootContext;
    use super::USB_MAX_PACKET_SIZE;
    use super::tasks;
    use super::usb;
    use crate::hid::core::actions;
    use crate::storage::BootFlash;
    use crate::system;
    use core::future::pending;
    use embassy_executor::{SpawnError, Spawner};
    use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal};
    use embassy_usb::{Builder as UsbBuilder, class::cdc_acm};
    use esp_alloc::{EspHeap, HeapRegion, MemoryCapability};
    use esp_hal::{
        Config,
        clock::CpuClock,
        otg_fs::{
            Usb,
            asynch::{Config as UsbDriverConfig, Driver as UsbDriver},
        },
        timer::timg::TimerGroup,
    };
    use esp_storage::FlashStorage;
    use static_cell::StaticCell;

    #[global_allocator]
    static ALLOCATOR: EspHeap = EspHeap::empty();

    fn init_allocator() {
        const HEAP_SIZE: usize = 96 * 1024;
        static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        unsafe {
            ALLOCATOR.add_region(HeapRegion::new(
                HEAP.as_mut_ptr(),
                HEAP.len(),
                MemoryCapability::Internal.into(),
            ));
        };
    }

    static USB_CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static USB_BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static USB_MSOS_DESCRIPTOR: StaticCell<[u8; 0]> = StaticCell::new();
    static USB_CONTROL_BUF: StaticCell<[u8; 256]> = StaticCell::new();
    static USB_CDC_STATE: StaticCell<cdc_acm::State<'static>> = StaticCell::new();
    static USB_EVENT_HANDLER: StaticCell<usb::UsbEventHandler> = StaticCell::new();
    static USB_RX_BUFFER: StaticCell<[u8; USB_MAX_PACKET_SIZE as usize]> = StaticCell::new();
    static FLASH_RESTORE_SIGNAL: Signal<CriticalSectionRawMutex, BootContext> = Signal::new();
    static FLASH_STORAGE: StaticCell<BootFlash<'static>> = StaticCell::new();

    const USB_VID: u16 = 0x303A;
    const USB_PID: u16 = 0x4001;
    const FLASH_RESTORE_DELAY_MS: u64 = 2_000;

    static mut USB_EP_OUT_BUFFER: [u8; 1024] = [0; 1024];

    fn spawn_or_log(name: &str, result: Result<(), SpawnError>) {
        if let Err(error) = result {
            log::error!("Failed to spawn {name}: {error:?}");
            panic!("failed to spawn {name}: {error:?}");
        }
    }

    #[esp_rtos::main]
    pub async fn main(spawner: Spawner) {
        init_allocator();

        let mut peripherals = esp_hal::init(Config::default().with_cpu_clock(CpuClock::max()));
        let mut timg0 = TimerGroup::new(peripherals.TIMG0);
        timg0.wdt.disable();

        let flash = FLASH_STORAGE.init(BootFlash::new(FlashStorage::new(peripherals.FLASH)));

        let usb = Usb::new(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);

        let driver = UsbDriver::new(
            usb,
            unsafe { &mut USB_EP_OUT_BUFFER },
            UsbDriverConfig::default(),
        );

        let mut config = embassy_usb::Config::new(USB_VID, USB_PID);
        config.manufacturer = Some("Cardputer");
        config.product = Some("Cardputer Wallet");
        config.serial_number = Some("0001");
        config.device_class = 0xEF;
        config.device_sub_class = 0x02;
        config.device_protocol = 0x01;
        config.composite_with_iads = true;

        let mut builder = UsbBuilder::new(
            driver,
            config,
            USB_CONFIG_DESCRIPTOR.init([0; 256]),
            USB_BOS_DESCRIPTOR.init([0; 256]),
            USB_MSOS_DESCRIPTOR.init([]),
            USB_CONTROL_BUF.init([0; 256]),
        );

        let handler = USB_EVENT_HANDLER.init(usb::UsbEventHandler::new());
        builder.handler(handler);

        let cdc_state = USB_CDC_STATE.init(cdc_acm::State::new());
        let cdc = cdc_acm::CdcAcmClass::new(&mut builder, cdc_state, USB_MAX_PACKET_SIZE);
        let usb_device = builder.build();

        let (cdc_sender, cdc_receiver) = cdc.split();
        let buffered_receiver =
            cdc_receiver.into_buffered(USB_RX_BUFFER.init([0u8; USB_MAX_PACKET_SIZE as usize]));
        let usb_events = usb::event_receiver();

        let ble_actions = actions::action_receiver();
        spawn_or_log("BLE task", spawner.spawn(tasks::ble_profile(ble_actions)));
        spawn_or_log(
            "USB device task",
            spawner.spawn(tasks::usb_device(usb_device)),
        );
        spawn_or_log(
            "time broadcast task",
            spawner.spawn(tasks::time_broadcast()),
        );
        spawn_or_log("UI task", spawner.spawn(system::ui_task()));
        spawn_or_log(
            "flash restore task",
            spawner.spawn(tasks::flash_restore_task(
                flash,
                &FLASH_RESTORE_SIGNAL,
                FLASH_RESTORE_DELAY_MS,
            )),
        );
        let frame_jobs = tasks::host_frame_receiver();
        let frame_jobs_sender = tasks::host_frame_sender();
        let frame_responses = tasks::host_frame_response_sender();
        let frame_responses_receiver = tasks::host_frame_response_receiver();
        spawn_or_log(
            "frame worker task",
            spawner.spawn(tasks::frame_worker(
                frame_jobs,
                frame_responses,
                &FLASH_RESTORE_SIGNAL,
            )),
        );
        spawn_or_log(
            "CDC task",
            spawner.spawn(tasks::cdc_server(
                buffered_receiver,
                cdc_sender,
                usb_events,
                frame_jobs_sender,
                frame_responses_receiver,
            )),
        );

        pending::<()>().await;
    }
}

mod usb {
    use embassy_sync::{
        blocking_mutex::raw::CriticalSectionRawMutex,
        channel::{Channel, Receiver, Sender},
    };
    use embassy_usb::Handler;

    const USB_EVENT_QUEUE_DEPTH: usize = 4;

    static USB_EVENTS: Channel<CriticalSectionRawMutex, UsbTransportEvent, USB_EVENT_QUEUE_DEPTH> =
        Channel::new();

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum UsbTransportEvent {
        Enabled,
        Disabled,
        Suspended,
        Resumed,
    }

    pub type UsbEventReceiver =
        Receiver<'static, CriticalSectionRawMutex, UsbTransportEvent, USB_EVENT_QUEUE_DEPTH>;

    pub struct UsbEventHandler {
        sender: Sender<'static, CriticalSectionRawMutex, UsbTransportEvent, USB_EVENT_QUEUE_DEPTH>,
    }

    impl UsbEventHandler {
        pub fn new() -> Self {
            Self {
                sender: USB_EVENTS.sender(),
            }
        }

        fn publish(&mut self, event: UsbTransportEvent) {
            let _ = self.sender.try_send(event);
        }
    }

    impl Handler for UsbEventHandler {
        fn enabled(&mut self, enabled: bool) {
            self.publish(if enabled {
                UsbTransportEvent::Enabled
            } else {
                UsbTransportEvent::Disabled
            });
        }

        fn configured(&mut self, configured: bool) {
            if configured {
                self.publish(UsbTransportEvent::Enabled);
            } else {
                self.publish(UsbTransportEvent::Disabled);
            }
        }

        fn suspended(&mut self, suspended: bool) {
            self.publish(if suspended {
                UsbTransportEvent::Suspended
            } else {
                UsbTransportEvent::Resumed
            });
        }
    }

    pub fn event_receiver() -> UsbEventReceiver {
        USB_EVENTS.receiver()
    }
}
