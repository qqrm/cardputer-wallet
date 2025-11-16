use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use std::time::Duration;

use serialport::{SerialPort, SerialPortType};
use shared::cdc::transport::{
    FrameTransportError, command_for_request, command_for_response, decode_frame,
    decode_frame_header, encode_frame,
};
use shared::cdc::{CdcCommand, FRAME_HEADER_SIZE};
use shared::error::SharedError;
use shared::journal::FrameTracker;
use shared::schema::{
    AckResponse, DeviceResponse, HelloResponse, HostRequest, JournalFrame, PullHeadResponse,
    StatusResponse, TimeResponse, VaultArtifact, VaultChunk,
};

use crate::artifacts::TransferArtifactStore;
use crate::constants::{
    CARDPUTER_IDENTITY_KEYWORDS, CARDPUTER_USB_PID, CARDPUTER_USB_VID, DEFAULT_TIMEOUT_SECS,
    HOST_BUFFER_SIZE, SERIAL_BAUD_RATE,
};

#[cfg(test)]
pub mod memory;

/// Abstraction over bidirectional device transports capable of exchanging CDC frames.
pub trait DeviceTransport {
    /// Write a CDC frame to the transport.
    fn write_frame(&mut self, command: CdcCommand, payload: &[u8]) -> Result<(), SharedError>;

    /// Read the next CDC frame from the transport.
    fn read_frame(&mut self) -> Result<(CdcCommand, Vec<u8>), SharedError>;

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

impl<T> DeviceTransport for T
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

pub fn send_host_request<T>(transport: &mut T, request: &HostRequest) -> Result<(), SharedError>
where
    T: DeviceTransport + ?Sized,
{
    transport.send_request(request)
}

pub fn read_device_response<T>(transport: &mut T) -> Result<DeviceResponse, SharedError>
where
    T: DeviceTransport + ?Sized,
{
    transport.read_response()
}

pub fn handle_device_response(
    response: DeviceResponse,
    tracker: Option<&mut FrameTracker>,
    artifacts: Option<&mut dyn TransferArtifactStore>,
) -> Result<bool, SharedError> {
    match response {
        DeviceResponse::Hello(info) => {
            print_hello(&info);
            if let Some(storage) = artifacts {
                storage.record_log("hello response");
            }
            Ok(false)
        }
        DeviceResponse::Status(status) => {
            print_status(&status);
            if let Some(storage) = artifacts {
                storage.record_log("status response");
            }
            Ok(false)
        }
        DeviceResponse::Time(time) => {
            print_time(&time);
            if let Some(storage) = artifacts {
                storage.record_log("time response");
            }
            Ok(false)
        }
        DeviceResponse::Head(head) => {
            print_head(&head);
            if let Some(storage) = artifacts {
                storage.record_log("head response");
            }
            Ok(false)
        }
        DeviceResponse::JournalFrame(frame) => {
            print_journal_frame(&frame);
            if let Some(state) = tracker {
                state.record(frame.sequence, frame.checksum);
            }
            if let Some(storage) = artifacts {
                storage.record_journal_frame(&frame);
            }
            Ok(frame.remaining_operations > 0)
        }
        DeviceResponse::VaultChunk(chunk) => {
            print_vault_chunk(&chunk);
            if let Some(state) = tracker {
                state.record(chunk.sequence, chunk.checksum);
            }
            let should_continue = if let Some(storage) = artifacts {
                storage.record_vault_chunk(&chunk)?
            } else {
                !chunk.is_last
            };
            Ok(should_continue)
        }
        DeviceResponse::Ack(message) => {
            print_ack(&message);
            if let Some(storage) = artifacts {
                storage.record_log("ack response");
            }
            Ok(false)
        }
        DeviceResponse::Nack(err) => Err(SharedError::Transport(format!(
            "device reported {code:?}: {message}",
            code = err.code,
            message = err.message
        ))),
    }
}

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

fn print_journal_frame(frame: &JournalFrame) {
    println!(
        "Received journal frame #{sequence} with {remaining} operations pending.",
        sequence = frame.sequence,
        remaining = frame.remaining_operations,
    );
    if frame.operations.is_empty() {
        println!("  No operations in this frame.");
    } else {
        println!("  Operations: {}", frame.operations.len());
        for op in &frame.operations {
            println!("    - {op:?}");
        }
    }
}

fn print_vault_chunk(chunk: &VaultChunk) {
    let artifact = match chunk.artifact {
        VaultArtifact::Vault => "vault image",
        VaultArtifact::Recipients => "recipients manifest",
        VaultArtifact::Signature => "vault signature",
    };
    println!(
        "Received {artifact} chunk #{sequence} ({size} bytes, {remaining} bytes remaining).",
        sequence = chunk.sequence,
        size = chunk.data.len(),
        remaining = chunk.remaining_bytes,
    );
    if chunk.is_last {
        println!("  This was the final chunk of the transfer.");
    }
}

pub fn print_hello(info: &HelloResponse) {
    println!(
        "HELLO response from '{name}' running firmware v{firmware} (session {session}).",
        name = info.device_name,
        firmware = info.firmware_version,
        session = info.session_id,
    );
}

pub fn print_status(status: &StatusResponse) {
    println!(
        "Status: generation {generation}, pending ops {pending}, device time {time} ms.",
        generation = status.vault_generation,
        pending = status.pending_operations,
        time = status.current_time_ms,
    );
}

pub fn print_time(time: &TimeResponse) {
    println!("Device time: {} ms since Unix epoch", time.epoch_millis);
}

pub fn print_head(head: &PullHeadResponse) {
    println!(
        "Vault head generation {generation}.",
        generation = head.vault_generation,
    );
    println!("  Vault hash   : {}", hex_encode(&head.vault_hash));
    println!("  Recipients hash: {}", hex_encode(&head.recipients_hash));
    println!("  Signature hash : {}", hex_encode(&head.signature_hash));
}

pub fn print_ack(message: &AckResponse) {
    println!("Acknowledgement: {}", message.message);
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = FmtWrite::write_fmt(&mut output, format_args!("{:02X}", byte));
    }
    output
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
