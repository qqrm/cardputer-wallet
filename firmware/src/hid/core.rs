//! Shared HID primitives used by both BLE and USB transports.

pub mod actions {
    use crate::ui::transport::{self, TransportState};
    use alloc::boxed::Box;
    #[cfg(test)]
    use alloc::vec::Vec;
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
            transport::set_ble_state(TransportState::Connecting);
        }
        if let DeviceAction::EndSession = &action {
            transport::set_ble_state(TransportState::Waiting);
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
