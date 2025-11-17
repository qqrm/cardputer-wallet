//! Human-interface side of the firmware runtime, including session action queues and the Xtensa
//! runtime entry point.
#[cfg(target_arch = "xtensa")]
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal};

use crate::ui::transport::TransportState;

#[cfg(any(test, target_arch = "xtensa"))]
pub mod ble;
#[cfg(any(test, target_arch = "xtensa"))]
pub mod actions {
    use crate::ui::transport::{self, TransportState};
    use alloc::{boxed::Box, vec::Vec};
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::channel::{Channel, Receiver, Sender};
    use heapless::Vec as HeaplessVec;

    type QueueMutex = CriticalSectionRawMutex;

    const ACTION_QUEUE_DEPTH: usize = 8;
    pub const KEYBOARD_ROLLOVER: usize = 6;
    pub const HID_REPORT_SIZE: usize = KEYBOARD_ROLLOVER + 2;
    pub const MACRO_BUFFER_CAPACITY: usize = 32;

    static ACTION_CHANNEL: Channel<QueueMutex, DeviceAction, ACTION_QUEUE_DEPTH> = Channel::new();

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum DeviceAction {
        StartSession {
            session_id: u32,
        },
        EndSession,
        SendReport {
            session_id: u32,
            report: KeyboardReport,
        },
        HoldKeys {
            session_id: u32,
            hold: KeyHold,
        },
        StreamMacro {
            session_id: u32,
            buffer: Box<MacroBuffer>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct KeyboardReport {
        pub modifiers: u8,
        pub keys: [u8; KEYBOARD_ROLLOVER],
    }

    impl KeyboardReport {
        pub const fn empty() -> Self {
            Self {
                modifiers: 0,
                keys: [0; KEYBOARD_ROLLOVER],
            }
        }

        pub fn to_bytes(&self) -> [u8; HID_REPORT_SIZE] {
            let mut data = [0u8; HID_REPORT_SIZE];
            data[0] = self.modifiers;
            data[2..].copy_from_slice(&self.keys);
            data
        }

        pub fn from_keys(modifiers: u8, pressed: &[u8]) -> Self {
            let mut report = Self::empty();
            report.modifiers = modifiers;
            for (idx, key) in pressed.iter().copied().enumerate() {
                if idx >= KEYBOARD_ROLLOVER {
                    break;
                }
                report.keys[idx] = key;
            }
            report
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct KeyHold {
        pub report: KeyboardReport,
        pub duration_ms: u16,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum MacroStep {
        Delay(u16),
        Report(KeyboardReport),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MacroBuffer {
        steps: HeaplessVec<MacroStep, MACRO_BUFFER_CAPACITY>,
    }

    impl MacroBuffer {
        pub const fn new() -> Self {
            Self {
                steps: HeaplessVec::new(),
            }
        }

        pub fn push(&mut self, step: MacroStep) -> Result<(), MacroStep> {
            self.steps.push(step)
        }

        pub fn len(&self) -> usize {
            self.steps.len()
        }

        pub fn is_empty(&self) -> bool {
            self.steps.is_empty()
        }

        pub fn iter(&self) -> impl Iterator<Item = &MacroStep> {
            self.steps.iter()
        }

        pub fn clear(&mut self) {
            self.steps.clear();
        }
    }

    impl Default for MacroBuffer {
        fn default() -> Self {
            Self::new()
        }
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
        if let DeviceAction::StartSession { .. } = &action {
            super::publish_ble_state(TransportState::Connecting);
        }
        if let DeviceAction::EndSession = &action {
            super::publish_ble_state(TransportState::Waiting);
        }
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
type TransportSignal = Signal<CriticalSectionRawMutex, TransportState>;

#[cfg(target_arch = "xtensa")]
static USB_TRANSPORT_SIGNAL: TransportSignal = Signal::new();
#[cfg(target_arch = "xtensa")]
static BLE_TRANSPORT_SIGNAL: TransportSignal = Signal::new();

#[cfg(target_arch = "xtensa")]
fn publish_usb_state(state: TransportState) {
    USB_TRANSPORT_SIGNAL.signal(state);
}

#[cfg(not(target_arch = "xtensa"))]
fn publish_usb_state(state: TransportState) {
    crate::ui::transport::set_usb_state(state);
}

#[cfg(target_arch = "xtensa")]
fn publish_ble_state(state: TransportState) {
    BLE_TRANSPORT_SIGNAL.signal(state);
}

#[cfg(not(target_arch = "xtensa"))]
fn publish_ble_state(state: TransportState) {
    crate::ui::transport::set_ble_state(state);
}

#[cfg(target_arch = "xtensa")]
fn usb_state_signal() -> &'static TransportSignal {
    &USB_TRANSPORT_SIGNAL
}

#[cfg(target_arch = "xtensa")]
fn ble_state_signal() -> &'static TransportSignal {
    &BLE_TRANSPORT_SIGNAL
}

#[cfg(target_arch = "xtensa")]
pub mod runtime {
    use super::actions;
    use super::usb;
    use crate::storage::{self, BootFlash, StorageError};
    use crate::sync::{self, SyncContext};
    use crate::system;
    use embassy_executor::Executor;
    use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal};
    use embassy_usb::{Builder as UsbBuilder, class::cdc_acm};
    use esp_alloc::EspHeap;
    use esp_hal::{
        Config,
        clock::CpuClock,
        otg_fs::{
            Usb,
            asynch::{Config as UsbDriverConfig, Driver as UsbDriver},
        },
        timer::timg::TimerGroup,
    };
    use esp_storage::{FlashStorage, FlashStorageError};
    use static_cell::StaticCell;

    #[global_allocator]
    static ALLOCATOR: EspHeap = EspHeap::empty();

    fn init_allocator() {
        const HEAP_SIZE: usize = 96 * 1024;
        static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
        unsafe { ALLOCATOR.init(HEAP.as_ptr() as usize, HEAP.len()) };
    }

    static EXECUTOR: StaticCell<Executor> = StaticCell::new();
    static USB_DRIVER: StaticCell<UsbDriver<'static>> = StaticCell::new();
    static USB_CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static USB_BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static USB_MSOS_DESCRIPTOR: StaticCell<[u8; 0]> = StaticCell::new();
    static USB_CONTROL_BUF: StaticCell<[u8; 256]> = StaticCell::new();
    static USB_CDC_STATE: StaticCell<cdc_acm::State<'static>> = StaticCell::new();
    static USB_EVENT_HANDLER: StaticCell<usb::UsbEventHandler> = StaticCell::new();
    static USB_RX_BUFFER: StaticCell<[u8; USB_MAX_PACKET_SIZE as usize]> = StaticCell::new();
    static FLASH_RESTORE_SIGNAL: Signal<CriticalSectionRawMutex, BootContext> = Signal::new();
    static FLASH_STORAGE: StaticCell<BootFlash<'static>> = StaticCell::new();

    const USB_MAX_PACKET_SIZE: u16 = 64;
    const USB_VID: u16 = 0x303A;
    const USB_PID: u16 = 0x4001;
    const FLASH_RESTORE_DELAY_MS: u64 = 2_000;

    type BootContext = Result<SyncContext, StorageError<FlashStorageError>>;

    static mut USB_EP_OUT_BUFFER: [u8; 1024] = [0; 1024];

    pub fn main() -> ! {
        init_allocator();

        let mut peripherals = esp_hal::init(Config::default().with_cpu_clock(CpuClock::max()));
        let mut timg0 = TimerGroup::new(peripherals.TIMG0);
        timg0.wdt.disable();

        let timer0 = timg0.timer0;
        esp_hal_embassy::init(timer0);

        let flash = FLASH_STORAGE.init(BootFlash::new(FlashStorage::new(peripherals.FLASH)));

        let usb = Usb::new(peripherals.USB0, peripherals.GPIO20, peripherals.GPIO19);

        let driver = USB_DRIVER.init(UsbDriver::new(
            usb,
            unsafe { &mut USB_EP_OUT_BUFFER },
            UsbDriverConfig::default(),
        ));

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

        let (cdc_sender, cdc_receiver, cdc_control) = cdc.split_with_control();
        let buffered_receiver =
            cdc_receiver.into_buffered(USB_RX_BUFFER.init([0u8; USB_MAX_PACKET_SIZE as usize]));
        let usb_events = usb::event_receiver();

        let usb_states = super::usb_state_signal();
        let ble_states = super::ble_state_signal();
        let ui_commands = system::ui_command_sender();
        let executor = EXECUTOR.init(Executor::new());
        executor.run(move |spawner| {
            let ble_actions = actions::action_receiver();
            spawner
                .spawn(super::tasks::ble_profile(ble_actions))
                .expect("spawn BLE task");
            spawner
                .spawn(super::tasks::usb_device(usb_device))
                .expect("spawn USB device task");
            spawner
                .spawn(super::tasks::transport_coordinator(
                    usb_states,
                    ble_states,
                    ui_commands,
                ))
                .expect("spawn transport coordinator");
            spawner
                .spawn(super::tasks::flash_restore_task(
                    flash,
                    &FLASH_RESTORE_SIGNAL,
                    FLASH_RESTORE_DELAY_MS,
                ))
                .expect("spawn flash restore task");
            spawner
                .spawn(super::tasks::cdc_server(
                    buffered_receiver,
                    cdc_sender,
                    cdc_control,
                    usb_events,
                    &FLASH_RESTORE_SIGNAL,
                ))
                .expect("spawn CDC task");
        });
    }
}

#[cfg(target_arch = "xtensa")]
mod tasks {
    use super::actions;
    use super::ble::{
        BleHid, HID_COMMAND_QUEUE_DEPTH, HidCommandQueue, HidError, HidResponse, profile,
    };
    use super::usb::{UsbEventReceiver, UsbTransportEvent};
    use crate::storage::{self, BootFlash, StorageError};
    use crate::sync::{self, FRAME_MAX_SIZE, SyncContext, process_host_frame};
    use crate::system::{UiCommandSender, UiTaskMessage};
    use crate::time;
    use crate::ui::transport::{self, TransportState};
    use alloc::{format, vec::Vec};
    use embassy_executor::task;
    use embassy_futures::select::{Either, Either3, select, select3};
    use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal};
    use embassy_time::Timer;
    use embassy_usb::{
        UsbDevice,
        class::cdc_acm::{BufferedReceiver, ControlChanged, Sender},
        driver::EndpointError,
    };
    use trouble_host::types::capabilities::IoCapabilities;

    use esp_storage::FlashStorageError;

    #[cfg(target_arch = "xtensa")]
    extern "C" {
        fn ets_printf(format: *const core::ffi::c_char, ...) -> i32;
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

            signal.signal(boot_result);

            if matches!(boot_result, BootContext::Ok(_)) {
                break;
            }

            if retry_delay_ms > 0 {
                Timer::after_millis(retry_delay_ms).await;
            }
        }
    }

    #[task]
    #[allow(clippy::too_many_arguments)]
    pub async fn cdc_server(
        mut receiver: BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        mut sender: Sender<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        mut control: ControlChanged<'static>,
        mut events: UsbEventReceiver,
        boot_signal: &'static Signal<CriticalSectionRawMutex, BootContext>,
    ) {
        let mut boot_state = boot_signal.wait().await;
        if let Err(error) = &boot_state {
            log_boot_failure(error);
        }

        let callbacks = TransportCallbacks::new();
        let packet_size = receiver.max_packet_size() as usize;
        callbacks.waiting().await;
        loop {
            if let Some(updated) = boot_signal.try_take() {
                if let Err(error) = &updated {
                    log_boot_failure(error);
                }
                boot_state = updated;
            }

            if matches!(
                wait_for_session(
                    &mut receiver,
                    &mut sender,
                    &mut control,
                    &mut events,
                    &callbacks,
                )
                .await,
                SessionControl::Drop
            ) {
                continue;
            }

            loop {
                if let Some(updated) = boot_signal.try_take() {
                    if let Err(error) = &updated {
                        log_boot_failure(error);
                    }
                    boot_state = updated;
                }

                let read_future = read_frame(&mut receiver);
                let event_future = events.receive();
                let combined = select(read_future, event_future);
                let control_future = control.control_changed();

                match select(combined, control_future).await {
                    Either::First(Either::First(Ok((command, frame)))) => {
                        callbacks.connected().await;
                        if let Err(error) = &boot_state {
                            let payload = boot_failure_payload(error);
                            if let Err(err) = write_frame(
                                &mut sender,
                                packet_size,
                                shared::cdc::CdcCommand::Nack,
                                &payload,
                            )
                            .await
                            {
                                if handle_frame_error(err, &callbacks).await {
                                    break;
                                }
                            }
                            continue;
                        }

                        let context = match boot_state.as_mut() {
                            Ok(ctx) => ctx,
                            Err(_) => unreachable!(),
                        };

                        match process_host_frame(command, &frame, context) {
                            Ok((response_command, response)) => {
                                if let Err(err) = write_frame(
                                    &mut sender,
                                    packet_size,
                                    response_command,
                                    &response,
                                )
                                .await
                                {
                                    if handle_frame_error(err, &callbacks).await {
                                        break;
                                    }
                                }
                            }
                            Err(err) => {
                                let payload = encode_nack_payload(err);
                                if let Err(err) = write_frame(
                                    &mut sender,
                                    packet_size,
                                    shared::cdc::CdcCommand::Nack,
                                    &payload,
                                )
                                .await
                                {
                                    if handle_frame_error(err, &callbacks).await {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Either::First(Either::First(Err(FrameIoError::Protocol(err)))) => {
                        let payload = encode_nack_payload(err);
                        if let Err(write_err) = write_frame(
                            &mut sender,
                            packet_size,
                            shared::cdc::CdcCommand::Nack,
                            &payload,
                        )
                        .await
                        {
                            if handle_frame_error(write_err, &callbacks).await {
                                break;
                            }
                        }
                    }
                    Either::First(Either::First(Err(FrameIoError::Endpoint(err)))) => {
                        if handle_endpoint_error(err, &callbacks).await {
                            break;
                        }
                    }
                    Either::First(Either::Second(event)) => {
                        if matches!(
                            handle_usb_event(event, &callbacks, &receiver).await,
                            SessionControl::Drop
                        ) {
                            break;
                        }
                    }
                    Either::Second(()) => {
                        if !receiver.dtr() {
                            callbacks.waiting().await;
                            break;
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SessionControl {
        Continue,
        Drop,
    }

    enum FrameIoError {
        Protocol(sync::ProtocolError),
        Endpoint(EndpointError),
    }

    struct TransportCallbacks;

    impl TransportCallbacks {
        const fn new() -> Self {
            Self
        }

        async fn set(&self, state: TransportState) {
            super::publish_usb_state(state);
        }

        async fn waiting(&self) {
            self.set(TransportState::Waiting).await;
        }

        async fn connecting(&self) {
            self.set(TransportState::Connecting).await;
        }

        async fn connected(&self) {
            self.set(TransportState::Connected).await;
        }

        async fn offline(&self) {
            self.set(TransportState::Offline).await;
        }

        async fn error(&self) {
            self.set(TransportState::Error).await;
        }
    }

    const TRANSPORT_DEBOUNCE_MS: u64 = 25;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum CoordinatorEvent {
        Usb(TransportState),
        Ble(TransportState),
        Time(u64),
    }

    #[task]
    pub async fn transport_coordinator(
        usb_states: &'static super::TransportSignal,
        ble_states: &'static super::TransportSignal,
        ui_commands: UiCommandSender,
    ) {
        let mut usb_state = TransportState::Offline;
        let mut ble_state = TransportState::Offline;
        let mut pending_time: Option<u64> = None;
        let mut time_rx = time::time_receiver();

        transport::set_usb_state(usb_state);
        transport::set_ble_state(ble_state);

        loop {
            apply_update(
                next_transport_event(usb_states, ble_states, &mut time_rx).await,
                &mut usb_state,
                &mut ble_state,
                &mut pending_time,
            );

            let mut debounce = Timer::after_millis(TRANSPORT_DEBOUNCE_MS);
            loop {
                match select(
                    next_transport_event(usb_states, ble_states, &mut time_rx),
                    &mut debounce,
                )
                .await
                {
                    Either::First(update) => {
                        apply_update(update, &mut usb_state, &mut ble_state, &mut pending_time);
                        debounce = Timer::after_millis(TRANSPORT_DEBOUNCE_MS);
                    }
                    Either::Second(()) => break,
                }
            }

            transport::set_usb_state(usb_state);
            transport::set_ble_state(ble_state);

            if let Some(now_ms) = pending_time.take() {
                let _ = ui_commands.try_send(UiTaskMessage::SyncTime(now_ms));
            }
        }
    }

    async fn next_transport_event(
        usb_states: &'static super::TransportSignal,
        ble_states: &'static super::TransportSignal,
        time_rx: &mut time::TimeReceiver,
    ) -> CoordinatorEvent {
        match select3(usb_states.wait(), ble_states.wait(), time_rx.changed()).await {
            Either3::First(state) => CoordinatorEvent::Usb(state),
            Either3::Second(state) => CoordinatorEvent::Ble(state),
            Either3::Third(now_ms) => CoordinatorEvent::Time(now_ms),
        }
    }

    fn apply_update(
        event: CoordinatorEvent,
        usb_state: &mut TransportState,
        ble_state: &mut TransportState,
        pending_time: &mut Option<u64>,
    ) {
        match event {
            CoordinatorEvent::Usb(state) => *usb_state = state,
            CoordinatorEvent::Ble(state) => *ble_state = state,
            CoordinatorEvent::Time(now_ms) => *pending_time = Some(now_ms),
        }
    }

    async fn wait_for_session(
        receiver: &mut BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        sender: &mut Sender<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        control: &mut ControlChanged<'static>,
        events: &mut UsbEventReceiver,
        callbacks: &TransportCallbacks,
    ) -> SessionControl {
        callbacks.waiting().await;
        receiver.wait_connection().await;
        sender.wait_connection().await;
        callbacks.connecting().await;

        loop {
            if receiver.dtr() {
                callbacks.connected().await;
                return SessionControl::Continue;
            }

            let control_future = control.control_changed();
            let event_future = events.receive();
            match select(control_future, event_future).await {
                Either::First(()) => continue,
                Either::Second(event) => {
                    if matches!(
                        handle_usb_event(event, callbacks, receiver).await,
                        SessionControl::Drop
                    ) {
                        return SessionControl::Drop;
                    }
                }
            }
        }
    }

    async fn handle_usb_event(
        event: UsbTransportEvent,
        callbacks: &TransportCallbacks,
        receiver: &BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
    ) -> SessionControl {
        match event {
            UsbTransportEvent::Enabled => {
                callbacks.waiting().await;
                SessionControl::Continue
            }
            UsbTransportEvent::Disabled => {
                callbacks.offline().await;
                SessionControl::Drop
            }
            UsbTransportEvent::Suspended => {
                callbacks.waiting().await;
                SessionControl::Continue
            }
            UsbTransportEvent::Resumed => {
                if receiver.dtr() {
                    callbacks.connected().await;
                } else {
                    callbacks.waiting().await;
                }
                SessionControl::Continue
            }
        }
    }

    async fn read_frame(
        reader: &mut BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
    ) -> Result<(shared::cdc::CdcCommand, Vec<u8>), FrameIoError> {
        use shared::cdc::{FRAME_HEADER_SIZE, decode_frame, decode_frame_header};

        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        read_exact(reader, &mut header_bytes).await?;

        let header = decode_frame_header(
            shared::schema::PROTOCOL_VERSION,
            FRAME_MAX_SIZE,
            header_bytes,
        )
        .map_err(FrameIoError::Protocol)?;

        let mut buffer = vec![0u8; header.length as usize];
        read_exact(reader, &mut buffer).await?;

        decode_frame(&header, &buffer).map_err(FrameIoError::Protocol)?;

        Ok((header.command, buffer))
    }

    async fn read_exact(
        reader: &mut BufferedReceiver<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        buf: &mut [u8],
    ) -> Result<(), FrameIoError> {
        let mut offset = 0;
        while offset < buf.len() {
            match reader.read(&mut buf[offset..]).await {
                Ok(0) => continue,
                Ok(count) => offset += count,
                Err(err) => return Err(FrameIoError::Endpoint(err)),
            }
        }
        Ok(())
    }

    async fn write_frame(
        sender: &mut Sender<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        packet_size: usize,
        command: shared::cdc::CdcCommand,
        payload: &[u8],
    ) -> Result<(), FrameIoError> {
        use shared::cdc::encode_frame;

        let header = encode_frame(
            shared::schema::PROTOCOL_VERSION,
            command,
            payload,
            FRAME_MAX_SIZE,
        )
        .map_err(FrameIoError::Protocol)?;

        write_all(sender, packet_size, &header).await?;
        if !payload.is_empty() {
            write_all(sender, packet_size, payload).await?;
            if payload.len() % packet_size == 0 {
                sender
                    .write_packet(&[])
                    .await
                    .map_err(FrameIoError::Endpoint)?;
            }
        }
        Ok(())
    }

    async fn write_all(
        sender: &mut Sender<'static, esp_hal::otg_fs::asynch::Driver<'static>>,
        packet_size: usize,
        mut data: &[u8],
    ) -> Result<(), FrameIoError> {
        while !data.is_empty() {
            let chunk_len = packet_size.min(data.len());
            match sender.write(&data[..chunk_len]).await {
                Ok(0) => continue,
                Ok(written) => data = &data[written..],
                Err(err) => return Err(FrameIoError::Endpoint(err)),
            }
        }
        Ok(())
    }

    async fn handle_endpoint_error(error: EndpointError, callbacks: &TransportCallbacks) -> bool {
        match error {
            EndpointError::Disabled => {
                callbacks.waiting().await;
                true
            }
            EndpointError::BufferOverflow => {
                callbacks.error().await;
                true
            }
        }
    }

    async fn handle_frame_error(error: FrameIoError, callbacks: &TransportCallbacks) -> bool {
        match error {
            FrameIoError::Endpoint(endpoint) => handle_endpoint_error(endpoint, callbacks).await,
            FrameIoError::Protocol(_) => {
                callbacks.error().await;
                true
            }
        }
    }

    fn encode_nack_payload(err: sync::ProtocolError) -> Vec<u8> {
        match sync::encode_response(&shared::schema::DeviceResponse::Nack(err.as_nack())) {
            Ok(encoded) => encoded,
            Err(encode_err) => {
                let fatal = encode_err.as_nack();
                sync::encode_response(&shared::schema::DeviceResponse::Nack(fatal))
                    .unwrap_or_default()
            }
        }
    }

    #[task]
    pub async fn ble_profile(mut receiver: actions::ActionReceiver) {
        let profile = profile::TroubleProfile::new("Cardputer HID").expect("init BLE profile");
        let mut backend = BleHid::new(profile, IoCapabilities::KeyboardDisplay);
        let mut queue = HidCommandQueue::<HID_COMMAND_QUEUE_DEPTH>::new();
        super::publish_ble_state(TransportState::Waiting);

        loop {
            let action = receiver.receive().await;
            if let Err(returned) = queue.enqueue(action) {
                handle_error(HidError::CommandQueueFull(returned));
                continue;
            }

            queue.process(&mut backend, handle_response, handle_error);
        }
    }

    fn handle_response(response: HidResponse) {
        match response {
            HidResponse::Connected { .. }
            | HidResponse::ReportSent { .. }
            | HidResponse::MacroAccepted { .. } => {
                super::publish_ble_state(TransportState::Connected)
            }
            HidResponse::Acknowledged { .. } | HidResponse::Disconnected => {
                super::publish_ble_state(TransportState::Waiting);
            }
        }
    }

    fn handle_error(error: HidError) {
        match error {
            HidError::AlreadyConnected { .. } => {
                super::publish_ble_state(TransportState::Connected);
            }
            HidError::NoActiveSession => super::publish_ble_state(TransportState::Waiting),
            HidError::SessionMismatch { .. }
            | HidError::CommandQueueFull(_)
            | HidError::MacroQueueFull
            | HidError::Profile(_) => super::publish_ble_state(TransportState::Error),
        }
    }
}

#[cfg(target_arch = "xtensa")]
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
