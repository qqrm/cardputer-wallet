//! USB CDC transport link backed by the ESP32-S3 USB serial peripheral.
use alloc::{boxed::Box, vec::Vec};

use async_trait::async_trait;
use embassy_time::{Duration, Timer};
use esp_hal::{Blocking, usb_serial_jtag::UsbSerialJtag};
use nb::Error as NbError;
use shared::cdc::CdcCommand;

use crate::sync::{FRAME_MAX_SIZE, ProtocolError};
use crate::transport::{HidBackend, LinkKind, TransportLink};

/// USB CDC transport implementation.
pub struct UsbCdcLink<'a> {
    serial: UsbSerialJtag<'static, Blocking>,
    backend: &'a dyn HidBackend,
}

impl<'a> UsbCdcLink<'a> {
    /// Create a new USB CDC link backed by the provided serial peripheral.
    pub fn new(serial: UsbSerialJtag<'static, Blocking>, backend: &'a dyn HidBackend) -> Self {
        Self { serial, backend }
    }

    async fn read_byte(&mut self) -> Result<u8, ProtocolError> {
        loop {
            match self.serial.read_byte() {
                Ok(byte) => return Ok(byte),
                Err(NbError::WouldBlock) => Timer::after(Duration::from_micros(250)).await,
                Err(NbError::Other(_)) => {
                    self.mark_disconnected();
                    return Err(ProtocolError::Transport);
                }
            }
        }
    }
}

#[async_trait(?Send)]
impl<'a> TransportLink for UsbCdcLink<'a> {
    fn kind(&self) -> LinkKind {
        LinkKind::Usb
    }

    fn backend(&self) -> &dyn HidBackend {
        self.backend
    }

    async fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), ProtocolError> {
        use shared::cdc::{FRAME_HEADER_SIZE, decode_frame, decode_frame_header};

        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        for byte in header_bytes.iter_mut() {
            *byte = self.read_byte().await?;
        }

        let header = decode_frame_header(
            shared::schema::PROTOCOL_VERSION,
            FRAME_MAX_SIZE,
            header_bytes,
        )?;

        let mut buffer = Vec::with_capacity(header.length as usize);
        for _ in 0..header.length {
            buffer.push(self.read_byte().await?);
        }

        decode_frame(&header, &buffer)?;

        Ok((header.command, buffer))
    }

    async fn write_frame(
        &mut self,
        command: CdcCommand,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        use shared::cdc::encode_frame;

        let header = encode_frame(
            shared::schema::PROTOCOL_VERSION,
            command,
            payload,
            FRAME_MAX_SIZE,
        )?;

        self.serial
            .write(&header)
            .map_err(|_| ProtocolError::Transport)
            .map_err(|err| {
                self.mark_disconnected();
                err
            })?;
        if !payload.is_empty() {
            self.serial
                .write(payload)
                .map_err(|_| ProtocolError::Transport)
                .map_err(|err| {
                    self.mark_disconnected();
                    err
                })?;
        }
        if let Err(err) = self.serial.flush_tx().map_err(|_| ProtocolError::Transport) {
            self.mark_disconnected();
            return Err(err);
        }

        Ok(())
    }
}
