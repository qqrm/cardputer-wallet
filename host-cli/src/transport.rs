pub mod adapters;
pub mod helpers;
#[cfg(test)]
pub mod memory;

pub use adapters::{
    CliResponseAdapter, DeviceResponseAdapter, RecordingResponseAdapter, handle_device_response,
    print_ack, print_head,
};
pub use helpers::{read_device_response, send_host_request};

use std::io::{self, Read, Write};
use std::time::Duration;

use crate::constants::{
    CARDPUTER_IDENTITY_KEYWORDS, CARDPUTER_USB_PID, CARDPUTER_USB_VID, DEFAULT_TIMEOUT_SECS,
    HOST_BUFFER_SIZE, SERIAL_BAUD_RATE,
};
use serialport::{SerialPort, SerialPortType};
use shared::cdc::transport::{
    FrameTransportError, command_for_request, command_for_response, decode_frame,
    decode_frame_header, encode_frame,
};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE};
use shared::error::SharedError;
use shared::schema::{DeviceResponse, HostRequest};

/// Abstraction over bidirectional device transports capable of exchanging CDC frames.
pub trait FrameTransport {
    /// Write a CDC frame to the transport.
    fn write_frame(&mut self, command: CdcCommand, payload: &[u8]) -> Result<(), SharedError>;

    /// Read the next CDC frame from the transport.
    fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), SharedError>;
}

/// High-level transport that can encode host requests and decode device responses.
pub trait DeviceTransport: FrameTransport {
    /// Serialize and dispatch a host request.
    fn send_request(&mut self, request: &HostRequest) -> Result<(), SharedError> {
        let payload = postcard::to_allocvec(request).map_err(SharedError::from)?;
        let command = command_for_request(request);
        self.write_frame(command, &payload)
    }

    /// Receive and decode a device response.
    fn read_response(&mut self) -> Result<DeviceResponse, SharedError> {
        let (command, payload) = self.read_frame()?;
        let response = postcard::from_bytes(&payload).map_err(SharedError::from)?;
        validate_response_command(command, &response)?;
        Ok(response)
    }
}

impl<T> FrameTransport for T
where
    T: Read + Write + ?Sized,
{
    fn write_frame(&mut self, command: CdcCommand, payload: &[u8]) -> Result<(), SharedError> {
        write_framed_message(self, command, payload)
    }

    fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), SharedError> {
        read_framed_message(self)
    }
}

impl<T> DeviceTransport for T where T: FrameTransport + ?Sized {}

pub fn open_serial_port(path: &str) -> Result<Box<dyn SerialPort>, SharedError> {
    let mut port = serialport::new(path, SERIAL_BAUD_RATE)
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .open()
        .map_err(|err| {
            SharedError::Transport(format!("failed to open serial port {path}: {err}"))
        })?;

    port.set_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .map_err(|err| {
            SharedError::Transport(format!("failed to configure timeout on {path}: {err}"))
        })?;

    Ok(port)
}

pub fn detect_first_serial_port(allow_any_port: bool) -> Result<String, SharedError> {
    let ports = serialport::available_ports().map_err(|err| {
        SharedError::Transport(format!("failed to enumerate serial ports: {err}"))
    })?;

    select_serial_port(&ports, allow_any_port)
        .map(|info| info.port_name.clone())
        .ok_or_else(|| missing_cardputer_error(allow_any_port))
}

pub fn select_serial_port(
    ports: &[serialport::SerialPortInfo],
    allow_any_port: bool,
) -> Option<&serialport::SerialPortInfo> {
    if allow_any_port {
        return ports
            .iter()
            .find(|info| matches!(info.port_type, SerialPortType::UsbPort(_)));
    }

    let mut matches = ports
        .iter()
        .filter(|info| matches_cardputer_vid_pid(info))
        .peekable();

    let first = matches.next()?;
    if matches.peek().is_none() {
        return Some(first);
    }

    std::iter::once(first)
        .chain(matches)
        .find(|info| matches_cardputer_identity(info))
        .or(Some(first))
}

pub fn matches_cardputer_vid_pid(info: &serialport::SerialPortInfo) -> bool {
    matches!(
        &info.port_type,
        SerialPortType::UsbPort(usb)
            if usb.vid == CARDPUTER_USB_VID && usb.pid == CARDPUTER_USB_PID
    )
}

pub fn matches_cardputer_identity(info: &serialport::SerialPortInfo) -> bool {
    match &info.port_type {
        SerialPortType::UsbPort(usb) => {
            field_matches_keyword(usb.product.as_deref())
                || field_matches_keyword(usb.serial_number.as_deref())
                || field_matches_keyword(usb.manufacturer.as_deref())
        }
        _ => false,
    }
}

fn field_matches_keyword(field: Option<&str>) -> bool {
    field.is_some_and(contains_keyword)
}

fn contains_keyword(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    CARDPUTER_IDENTITY_KEYWORDS
        .iter()
        .any(|keyword| lower.contains(keyword))
}

pub fn missing_cardputer_error(allow_any_port: bool) -> SharedError {
    let mut message = format!(
        "Cardputer USB CDC device not found (expected VID 0x{CARDPUTER_USB_VID:04X}, PID 0x{CARDPUTER_USB_PID:04X})."
    );

    if !allow_any_port {
        message.push_str(" Pass --any-port to connect to the first available USB serial device.");
    }

    SharedError::Transport(message)
}

fn write_framed_message<W>(
    writer: &mut W,
    command: CdcCommand,
    payload: &[u8],
) -> Result<(), SharedError>
where
    W: Write + ?Sized,
{
    let header = encode_frame(
        shared::schema::PROTOCOL_VERSION,
        command,
        payload,
        usize::MAX,
    )
    .map_err(|err| map_transport_error("encode frame", err))?;
    writer
        .write_all(&header)
        .map_err(map_io_error("write frame header"))?;
    writer
        .write_all(payload)
        .map_err(map_io_error("write frame payload"))?;

    writer.flush().map_err(map_io_error("flush frame"))?;
    Ok(())
}

fn read_framed_message<R>(reader: &mut R) -> Result<(CdcCommand, Vec<u8>), SharedError>
where
    R: Read + ?Sized,
{
    let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
    reader
        .read_exact(&mut header_bytes)
        .map_err(map_io_error("read frame header"))?;
    let header = decode_frame_header(
        shared::schema::PROTOCOL_VERSION,
        HOST_BUFFER_SIZE as usize,
        header_bytes,
    )
    .map_err(|err| map_transport_error("decode frame header", err))?;

    let mut payload = vec![0u8; header.length as usize];
    reader
        .read_exact(&mut payload)
        .map_err(map_io_error("read frame payload"))?;

    decode_frame(&header, &payload)
        .map_err(|err| map_transport_error("validate frame payload", err))?;

    Ok((header.command, payload))
}

fn validate_response_command(
    command: CdcCommand,
    response: &DeviceResponse,
) -> Result<(), SharedError> {
    let expected = command_for_response(response);
    if command == expected {
        Ok(())
    } else {
        Err(SharedError::Transport(format!(
            "unexpected command {:?} for response {:?} (expected {:?})",
            command, response, expected
        )))
    }
}

fn map_io_error(context: &'static str) -> impl Fn(io::Error) -> SharedError {
    move |err| {
        let mut message = format!("{context} failed: {err}");
        if err.kind() == io::ErrorKind::TimedOut {
            message.push_str(" (operation timed out)");
        }
        SharedError::Transport(message)
    }
}

fn map_transport_error(context: &'static str, error: FrameTransportError) -> SharedError {
    SharedError::Transport(format!("{context} failed: {error}"))
}

#[cfg(test)]
pub fn read_framed_message_for_tests<R>(
    reader: &mut R,
) -> Result<(CdcCommand, Vec<u8>), SharedError>
where
    R: Read + ?Sized,
{
    read_framed_message(reader)
}

#[cfg(test)]
pub fn write_framed_message_for_tests<W>(
    writer: &mut W,
    command: CdcCommand,
    payload: &[u8],
) -> Result<(), SharedError>
where
    W: Write + ?Sized,
{
    write_framed_message(writer, command, payload)
}
