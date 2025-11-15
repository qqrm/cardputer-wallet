//! Transport abstractions shared by the sync and HID layers.
use alloc::{boxed::Box, vec::Vec};

use async_trait::async_trait;
use shared::cdc::CdcCommand;

use crate::sync::ProtocolError;

/// Logical transport channels available on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// USB CDC connection riding on the HID stack.
    Usb,
    /// BLE CDC connection riding on the HID stack.
    Ble,
}

/// Observer notified whenever a HID transport link changes connectivity state.
pub trait HidBackend: Sync {
    /// Update the connectivity status for the provided link kind.
    fn set_connected(&self, kind: LinkKind, connected: bool);

    /// Helper for marking a link as connected.
    fn mark_connected(&self, kind: LinkKind) {
        self.set_connected(kind, true);
    }

    /// Helper for marking a link as disconnected.
    fn mark_disconnected(&self, kind: LinkKind) {
        self.set_connected(kind, false);
    }
}

/// Contract implemented by transport links capable of exchanging CDC frames.
#[async_trait(?Send)]
pub trait TransportLink {
    /// Resolve the kind of link represented by this instance.
    fn kind(&self) -> LinkKind;

    /// Access the HID backend that should receive state changes for this link.
    fn backend(&self) -> &dyn HidBackend;

    /// Receive a single CDC frame from the host.
    async fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), ProtocolError>;

    /// Send a CDC frame to the host.
    async fn write_frame(
        &mut self,
        command: CdcCommand,
        payload: &[u8],
    ) -> Result<(), ProtocolError>;

    /// Notify the backend that the link is currently connected.
    fn mark_connected(&self) {
        self.backend().mark_connected(self.kind());
    }

    /// Notify the backend that the link lost connectivity.
    fn mark_disconnected(&self) {
        self.backend().mark_disconnected(self.kind());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::sync::Mutex;

    struct RecordingBackend {
        events: Mutex<Vec<(LinkKind, bool)>>,
    }

    impl RecordingBackend {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }
    }

    impl HidBackend for RecordingBackend {
        fn set_connected(&self, kind: LinkKind, connected: bool) {
            self.events.lock().unwrap().push((kind, connected));
        }
    }

    struct DummyLink<'a> {
        backend: &'a RecordingBackend,
    }

    #[async_trait(?Send)]
    impl<'a> TransportLink for DummyLink<'a> {
        fn kind(&self) -> LinkKind {
            LinkKind::Ble
        }

        fn backend(&self) -> &dyn HidBackend {
            self.backend
        }

        async fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), ProtocolError> {
            let payload = vec![0xAA];
            Ok((CdcCommand::Hello, payload))
        }

        async fn write_frame(
            &mut self,
            _command: CdcCommand,
            _payload: &[u8],
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    #[test]
    fn link_notifies_backend() {
        let backend = RecordingBackend::new();
        let link = DummyLink { backend: &backend };
        link.mark_connected();
        link.mark_disconnected();

        let events = backend.events.lock().unwrap();
        assert_eq!(
            events.as_slice(),
            &[(LinkKind::Ble, true), (LinkKind::Ble, false)]
        );
    }
}

#[cfg(target_arch = "xtensa")]
pub mod usb;
