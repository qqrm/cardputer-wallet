use heapless::Deque;
use trouble_host::IoCapabilities;

use super::actions::DeviceAction;

/// Maximum number of queued HID commands waiting for the BLE backend.
pub const HID_COMMAND_QUEUE_DEPTH: usize = 8;

/// Resulting state transition emitted by the HID backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidResponse {
    /// BLE link moved into an active session.
    Connected { session_id: u32 },
    /// Host confirmed receipt of the last command batch.
    Acknowledged { session_id: u32 },
    /// BLE link returned to the idle state because of a transport event.
    Disconnected,
}

/// Errors returned while attempting to act on a `DeviceAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidError {
    /// A new session was requested while another one is still active.
    AlreadyConnected { active_session: u32 },
    /// A command that requires an active session was triggered while idle.
    NoActiveSession,
    /// The action queue is full and the newest command had to be dropped.
    CommandQueueFull(DeviceAction),
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
}

impl BleHid {
    /// Construct a new backend with the provided IO capabilities.
    pub const fn new(io_capabilities: IoCapabilities) -> Self {
        Self {
            state: BleSessionState::Idle,
            io_capabilities,
        }
    }

    fn start_session(&mut self, session_id: u32) -> Result<HidResponse, HidError> {
        match self.state {
            BleSessionState::Idle => {
                self.state = BleSessionState::Connected(session_id);
                Ok(HidResponse::Connected { session_id })
            }
            BleSessionState::Connected(active) => Err(HidError::AlreadyConnected {
                active_session: active,
            }),
        }
    }

    fn end_session(&mut self) -> Result<HidResponse, HidError> {
        match self.state {
            BleSessionState::Idle => Err(HidError::NoActiveSession),
            BleSessionState::Connected(session) => {
                self.state = BleSessionState::Idle;
                Ok(HidResponse::Acknowledged {
                    session_id: session,
                })
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::Vec;

    #[test]
    fn queue_preserves_fifo_order() {
        let mut queue = HidCommandQueue::<4>::new();
        queue
            .enqueue(DeviceAction::StartSession { session_id: 1 })
            .unwrap();
        queue.enqueue(DeviceAction::EndSession).unwrap();
        assert_eq!(queue.len(), 2);
        assert_eq!(
            queue.dequeue(),
            Some(DeviceAction::StartSession { session_id: 1 })
        );
        assert_eq!(queue.dequeue(), Some(DeviceAction::EndSession));
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_reports_overflow() {
        let mut queue = HidCommandQueue::<1>::new();
        queue
            .enqueue(DeviceAction::StartSession { session_id: 7 })
            .unwrap();
        let overflow = queue.enqueue(DeviceAction::EndSession).err();
        assert_eq!(overflow, Some(DeviceAction::EndSession));
    }

    #[test]
    fn backend_emits_connected_and_acknowledged_events() {
        let mut queue = HidCommandQueue::<4>::new();
        let mut backend = BleHid::new(IoCapabilities::KeyboardDisplay);
        queue
            .enqueue(DeviceAction::StartSession { session_id: 42 })
            .unwrap();
        queue.enqueue(DeviceAction::EndSession).unwrap();

        let mut responses: Vec<HidResponse, 2> = Vec::new();
        queue.process(
            &mut backend,
            |resp| {
                responses.push(resp).ok();
            },
            |_| unreachable!("no backend errors expected"),
        );

        assert_eq!(
            responses.as_slice(),
            &[
                HidResponse::Connected { session_id: 42 },
                HidResponse::Acknowledged { session_id: 42 },
            ]
        );
    }

    #[test]
    fn backend_rejects_duplicate_session() {
        let mut backend = BleHid::new(IoCapabilities::KeyboardDisplay);
        assert!(
            backend
                .process_action(DeviceAction::StartSession { session_id: 1 })
                .is_ok()
        );
        let err = backend
            .process_action(DeviceAction::StartSession { session_id: 2 })
            .unwrap_err();
        assert_eq!(err, HidError::AlreadyConnected { active_session: 1 });
    }
}
