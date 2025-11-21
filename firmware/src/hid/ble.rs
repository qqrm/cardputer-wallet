use heapless::Deque;
use trouble_host::IoCapabilities;

use super::actions::{
    DeviceAction, HID_REPORT_SIZE, KeyHold, KeyboardReport, MacroBuffer, MacroStep,
};

/// Maximum number of queued HID commands waiting for the BLE backend.
pub const HID_COMMAND_QUEUE_DEPTH: usize = 8;

/// Resulting state transition emitted by the HID backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidResponse {
    /// BLE link moved into an active session.
    Connected { session_id: u32 },
    /// Host confirmed receipt of the last command batch.
    Acknowledged { session_id: u32 },
    /// A keyboard report was delivered to the BLE transport.
    ReportSent { session_id: u32 },
    /// A macro payload has been accepted and emitted.
    MacroAccepted {
        session_id: u32,
        emitted_reports: usize,
    },
    /// BLE link returned to the idle state because of a transport event.
    Disconnected,
}

/// Errors returned while attempting to act on a `DeviceAction`.
#[derive(Debug, Clone, PartialEq)]
pub enum HidError {
    /// A new session was requested while another one is still active.
    AlreadyConnected { active_session: u32 },
    /// A command that requires an active session was triggered while idle.
    NoActiveSession,
    /// The provided session identifier does not match the active connection.
    SessionMismatch { active_session: u32, provided: u32 },
    /// The action queue is full and the newest command had to be dropped.
    CommandQueueFull(DeviceAction),
    /// The macro backlog exceeded the configured limit.
    MacroQueueFull,
    /// The Trouble HID profile rejected the request.
    Profile(profile::ProfileError),
}

impl From<profile::ProfileError> for HidError {
    fn from(value: profile::ProfileError) -> Self {
        match value {
            profile::ProfileError::MacroOverflow => HidError::MacroQueueFull,
            other => HidError::Profile(other),
        }
    }
}

/// Minimal abstraction around a HID backend so BLE and USB implementations can
/// share the same queue handling logic.
pub trait HidBackend {
    /// Return the IO capabilities exposed to the peer during pairing.
    fn capabilities(&self) -> IoCapabilities;

    /// Handle the next `DeviceAction` pulled from the queue.
    fn process_action(&mut self, action: DeviceAction) -> Result<HidResponse, HidError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BleSessionState {
    #[default]
    Idle,
    Connected(u32),
}

/// Lightweight BLE HID implementation built on top of `trouble-host`.
#[derive(Debug)]
pub struct BleHid {
    state: BleSessionState,
    io_capabilities: IoCapabilities,
    profile: profile::TroubleProfile,
}

impl BleHid {
    /// Construct a new backend with the provided IO capabilities.
    pub fn new(profile: profile::TroubleProfile, io_capabilities: IoCapabilities) -> Self {
        Self {
            state: BleSessionState::Idle,
            io_capabilities,
            profile,
        }
    }

    pub(crate) fn start_session(&mut self, session_id: u32) -> Result<HidResponse, HidError> {
        match self.state {
            BleSessionState::Idle => {
                self.state = BleSessionState::Connected(session_id);
                self.profile.reset();
                Ok(HidResponse::Connected { session_id })
            }
            BleSessionState::Connected(active) => Err(HidError::AlreadyConnected {
                active_session: active,
            }),
        }
    }

    fn ensure_session(&self, session_id: u32) -> Result<(), HidError> {
        match self.state {
            BleSessionState::Idle => Err(HidError::NoActiveSession),
            BleSessionState::Connected(active) if active == session_id => Ok(()),
            BleSessionState::Connected(active) => Err(HidError::SessionMismatch {
                active_session: active,
                provided: session_id,
            }),
        }
    }

    pub(crate) fn end_session(&mut self) -> Result<HidResponse, HidError> {
        match self.state {
            BleSessionState::Idle => Err(HidError::NoActiveSession),
            BleSessionState::Connected(session) => {
                self.state = BleSessionState::Idle;
                self.profile.reset();
                Ok(HidResponse::Acknowledged {
                    session_id: session,
                })
            }
        }
    }

    pub(crate) fn send_report(
        &mut self,
        session_id: u32,
        report: &KeyboardReport,
    ) -> Result<HidResponse, HidError> {
        self.ensure_session(session_id)?;
        self.profile.send_keyboard_report(report)?;
        Ok(HidResponse::ReportSent { session_id })
    }

    pub(crate) fn send_hold(
        &mut self,
        session_id: u32,
        hold: &KeyHold,
    ) -> Result<HidResponse, HidError> {
        self.send_report(session_id, &hold.report)
    }

    pub(crate) fn stream_macro(
        &mut self,
        session_id: u32,
        buffer: &MacroBuffer,
    ) -> Result<HidResponse, HidError> {
        self.ensure_session(session_id)?;
        let emitted = self.profile.stream_macro(buffer)?;
        Ok(HidResponse::MacroAccepted {
            session_id,
            emitted_reports: emitted,
        })
    }
}

impl HidBackend for BleHid {
    fn capabilities(&self) -> IoCapabilities {
        self.io_capabilities
    }

    fn process_action(&mut self, action: DeviceAction) -> Result<HidResponse, HidError> {
        match action {
            DeviceAction::StartSession { session_id } => self.start_session(session_id),
            DeviceAction::EndSession => self.end_session(),
            DeviceAction::SendReport { session_id, report } => {
                self.send_report(session_id, &report)
            }
            DeviceAction::HoldKeys { session_id, hold } => self.send_hold(session_id, &hold),
            DeviceAction::StreamMacro { session_id, buffer } => {
                self.stream_macro(session_id, &buffer)
            }
        }
    }
}

/// Lock-free queue that decouples UI generated actions from the BLE runtime.
#[derive(Debug)]
pub struct HidCommandQueue<const N: usize = HID_COMMAND_QUEUE_DEPTH> {
    buffer: Deque<DeviceAction, N>,
}

impl<const N: usize> HidCommandQueue<N> {
    /// Create a new empty queue.
    pub const fn new() -> Self {
        Self {
            buffer: Deque::new(),
        }
    }

    /// Enqueue a `DeviceAction`, returning the original action if the queue is full.
    pub fn enqueue(&mut self, action: DeviceAction) -> Result<(), DeviceAction> {
        self.buffer.push_back(action)
    }

    /// Pop the next pending action if any.
    pub fn dequeue(&mut self) -> Option<DeviceAction> {
        self.buffer.pop_front()
    }

    /// Number of pending actions.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Drain the queue by invoking the backend and forwarding responses or errors.
    pub fn process<B, R, E>(&mut self, backend: &mut B, mut on_response: R, mut on_error: E)
    where
        B: HidBackend,
        R: FnMut(HidResponse),
        E: FnMut(HidError),
    {
        while let Some(action) = self.dequeue() {
            match backend.process_action(action) {
                Ok(response) => on_response(response),
                Err(error) => on_error(error),
            }
        }
    }
}

impl<const N: usize> Default for HidCommandQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub mod profile {
    use super::*;
    use core::{
        fmt,
        hint::spin_loop,
        sync::atomic::{AtomicBool, Ordering},
    };
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
    use heapless::Deque;
    use trouble_host::Error as TroubleError;
    use trouble_host::advertise::{AdStructure, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
    use trouble_host::prelude::{
        FromGatt, GapConfig, PeripheralConfig, appearance, characteristic, descriptors,
        gatt_server, gatt_service, service,
    };

    const REPORT_DESCRIPTOR_LEN: usize = 63;
    const REPORT_DESCRIPTOR: [u8; REPORT_DESCRIPTOR_LEN] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
        0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
        0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
        0x81, 0x00, 0xC0,
    ];
    const HID_INFORMATION: [u8; 4] = [0x11, 0x01, 0x00, 0x02];
    const REPORT_REFERENCE: [u8; 2] = [0x01, 0x01];
    const MACRO_REPORT_BACKLOG: usize = 64;
    const ADV_BUFFER_LEN: usize = 31;
    const ATTRIBUTE_TABLE_SIZE: usize = 96;
    const CCCD_TABLE_SIZE: usize = 4;
    const CONNECTIONS_MAX: usize = 1;
    static SERVER_POOL: Mutex<CriticalSectionRawMutex, Option<HidServer<'static>>> =
        Mutex::new(None);
    static SERVER_INITIALIZED: AtomicBool = AtomicBool::new(false);

    #[gatt_service(uuid = service::HUMAN_INTERFACE_DEVICE)]
    struct HidService {
        #[characteristic(uuid = characteristic::HID_INFORMATION, read, value = HID_INFORMATION)]
        information: [u8; 4],
        #[characteristic(uuid = characteristic::REPORT_MAP, read, value = REPORT_DESCRIPTOR)]
        report_map: [u8; REPORT_DESCRIPTOR_LEN],
        #[descriptor(uuid = descriptors::REPORT_REFERENCE, read, value = REPORT_REFERENCE)]
        #[characteristic(uuid = characteristic::REPORT, read, notify, value = [0u8; HID_REPORT_SIZE])]
        input_report: [u8; HID_REPORT_SIZE],
        #[characteristic(uuid = characteristic::HID_CONTROL_POINT, write_without_response, value = 0u8)]
        control_point: u8,
        #[characteristic(uuid = characteristic::PROTOCOL_MODE, read, write_without_response, value = 1u8)]
        protocol_mode: u8,
    }

    #[gatt_server(
        connections_max = CONNECTIONS_MAX,
        mutex_type = NoopRawMutex,
        attribute_table_size = ATTRIBUTE_TABLE_SIZE,
        cccd_table_size = CCCD_TABLE_SIZE
    )]
    struct HidServer {
        hid: HidService,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum ProfileError {
        InvalidConfig(&'static str),
        AdvertisementTooLong,
        MacroOverflow,
        Attribute(TroubleError),
    }

    impl From<TroubleError> for ProfileError {
        fn from(value: TroubleError) -> Self {
            ProfileError::Attribute(value)
        }
    }

    pub struct TroubleProfile {
        pub name: &'static str,
        server: Option<HidServer<'static>>,
        macro_backlog: Deque<[u8; HID_REPORT_SIZE], MACRO_REPORT_BACKLOG>,
        last_report: Option<[u8; HID_REPORT_SIZE]>,
        adv_data: [u8; ADV_BUFFER_LEN],
        adv_len: usize,
        scan_data: [u8; ADV_BUFFER_LEN],
        scan_len: usize,
    }

    impl TroubleProfile {
        pub fn new(name: &'static str) -> Result<Self, ProfileError> {
            let server = acquire_server(name)?;
            let (adv_data, adv_len) = encode_name_advertisement(name)?;
            let (scan_data, scan_len) = encode_scan_response(name)?;
            Ok(Self {
                name,
                server: Some(server),
                macro_backlog: Deque::new(),
                last_report: None,
                adv_data,
                adv_len,
                scan_data,
                scan_len,
            })
        }

        pub fn reset(&mut self) {
            self.macro_backlog.clear();
            self.last_report = None;
        }

        pub fn descriptor(&self) -> &[u8; REPORT_DESCRIPTOR_LEN] {
            &REPORT_DESCRIPTOR
        }

        pub fn advertisement(&self) -> (&[u8], &[u8]) {
            (
                &self.adv_data[..self.adv_len],
                &self.scan_data[..self.scan_len],
            )
        }

        pub fn send_keyboard_report(
            &mut self,
            report: &KeyboardReport,
        ) -> Result<(), ProfileError> {
            let bytes = report.to_bytes();
            {
                let server = self.server();
                let input = &server.hid.input_report;
                server.set(input, &bytes)?;
            }
            self.last_report = Some(bytes);
            Ok(())
        }

        pub fn stream_macro(&mut self, buffer: &MacroBuffer) -> Result<usize, ProfileError> {
            for step in buffer.iter() {
                if let MacroStep::Report(report) = step {
                    self.macro_backlog
                        .push_back(report.to_bytes())
                        .map_err(|_| ProfileError::MacroOverflow)?;
                }
            }

            let mut emitted = 0;
            while let Some(report) = self.macro_backlog.pop_front() {
                let server = self.server();
                let input = &server.hid.input_report;
                server.set(input, &report)?;
                self.last_report = Some(report);
                emitted += 1;
            }
            Ok(emitted)
        }

        pub fn last_report(&self) -> Option<[u8; HID_REPORT_SIZE]> {
            self.last_report
        }
    }

    impl fmt::Debug for TroubleProfile {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TroubleProfile")
                .field("name", &self.name)
                .field("macro_backlog", &self.macro_backlog.len())
                .finish()
        }
    }

    impl TroubleProfile {
        fn server(&mut self) -> &mut HidServer<'static> {
            self.server.as_mut().expect("server acquired")
        }
    }

    impl Drop for TroubleProfile {
        fn drop(&mut self) {
            if let Some(server) = self.server.take() {
                unsafe {
                    SERVER_POOL.lock_mut(|pool| {
                        if pool.is_none() {
                            *pool = Some(server);
                        }
                    });
                }
            }
        }
    }

    fn encode_name_advertisement(
        name: &'static str,
    ) -> Result<([u8; ADV_BUFFER_LEN], usize), ProfileError> {
        let mut buffer = [0u8; ADV_BUFFER_LEN];
        let len = AdStructure::encode_slice(
            &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::CompleteLocalName(name.as_bytes()),
            ],
            &mut buffer,
        )
        .map_err(|_| ProfileError::AdvertisementTooLong)?;
        Ok((buffer, len))
    }

    fn encode_scan_response(
        name: &'static str,
    ) -> Result<([u8; ADV_BUFFER_LEN], usize), ProfileError> {
        let mut buffer = [0u8; ADV_BUFFER_LEN];
        let len = AdStructure::encode_slice(
            &[AdStructure::ShortenedLocalName(name.as_bytes())],
            &mut buffer,
        )
        .map_err(|_| ProfileError::AdvertisementTooLong)?;
        Ok((buffer, len))
    }

    fn acquire_server(name: &'static str) -> Result<HidServer<'static>, ProfileError> {
        loop {
            if let Some(server) = unsafe { SERVER_POOL.lock_mut(|pool| pool.take()) } {
                return Ok(server);
            }

            if SERVER_INITIALIZED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let gap_config = GapConfig::Peripheral(PeripheralConfig {
                    name,
                    appearance: &appearance::human_interface_device::KEYBOARD,
                });
                let server =
                    HidServer::new_with_config(gap_config).map_err(ProfileError::InvalidConfig)?;
                return Ok(server);
            }

            spin_loop();
        }
    }
}
