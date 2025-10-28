use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serialport::{SerialPort, SerialPortType};

use shared::cdc::{FrameCommand, FrameHeader};
use shared::error::SharedError;
use shared::schema::{
    AbortReason, AbortRequest, DeviceResponse, HostRequest, JournalFrame, PullVaultRequest,
    PushAck, SyncCompletion, VaultChunk, PROTOCOL_VERSION,
};

const SERIAL_BAUD_RATE: u32 = 115_200;
const DEFAULT_TIMEOUT_SECS: u64 = 2;
const HOST_BUFFER_SIZE: u32 = 64 * 1024;
const MAX_CHUNK_SIZE: u32 = 4 * 1024;
const CARDPUTER_USB_VID: u16 = 0x303A;
const CARDPUTER_USB_PID: u16 = 0x4001;
const CARDPUTER_IDENTITY_KEYWORDS: &[&str] = &["cardputer", "m5stack"];

#[derive(Parser, Debug)]
#[command(author, version, about = "Cardputer host command line interface")]
struct Cli {
    /// Optional path to the serial device. Falls back to auto-detection when omitted.
    #[arg(short, long)]
    port: Option<String>,

    /// Skip Cardputer VID/PID filtering and accept the first USB serial device.
    #[arg(long)]
    any_port: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fetch the latest vault data from the device.
    Pull(RepoArgs),
    /// Confirm that pushed journal frames were persisted locally.
    Push(RepoArgs),
    /// Query the device for its current sync status.
    Status(RepoArgs),
}

#[derive(Args, Debug, Clone)]
struct RepoArgs {
    /// Path to the repository that should receive or provide data.
    #[arg(long, value_name = "PATH")]
    repo: PathBuf,
    /// Path to the credentials file used during the operation.
    #[arg(long, value_name = "PATH")]
    credentials: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        match &err {
            SharedError::Transport(_) => {
                eprintln!("Transport failure: {err}");
            }
            SharedError::Serialization(_) => {
                eprintln!("CBOR decoding error: {err}");
            }
        }
        return Err(anyhow::Error::from(err));
    }

    Ok(())
}

fn run(cli: Cli) -> Result<(), SharedError> {
    let port_path = match cli.port {
        Some(port) => port,
        None => detect_first_serial_port(cli.any_port)?,
    };

    println!("Connecting to Cardputer on {port_path}…");
    let mut port = open_serial_port(&port_path)?;

    match cli.command {
        Command::Pull(args) => execute_pull(&mut *port, &args),
        Command::Push(args) => execute_push(&mut *port, &args),
        Command::Status(args) => execute_status(&mut *port, &args),
    }
}

fn execute_pull<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!(
        "Preparing pull for repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );

    let request = HostRequest::PullVault(PullVaultRequest {
        protocol_version: PROTOCOL_VERSION,
        host_buffer_size: HOST_BUFFER_SIZE,
        max_chunk_size: MAX_CHUNK_SIZE,
        known_generation: None,
    });

    send_host_request(port, &request)?;
    println!("Request sent. Waiting for device responses…");

    loop {
        let response = read_device_response(port)?;
        if !handle_device_response(response)? {
            break;
        }
    }

    Ok(())
}

fn execute_push<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!(
        "Confirming push for repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );

    let request = HostRequest::AckPush(PushAck {
        protocol_version: PROTOCOL_VERSION,
        last_frame_sequence: 0,
        journal_checksum: 0,
    });

    send_host_request(port, &request)?;
    println!("Acknowledgement sent. Awaiting confirmation…");

    loop {
        let response = read_device_response(port)?;
        if !handle_device_response(response)? {
            break;
        }
    }

    Ok(())
}

fn execute_status<P>(port: &mut P, args: &RepoArgs) -> Result<(), SharedError>
where
    P: Read + Write + ?Sized,
{
    println!(
        "Checking device status for repository '{}' using credentials '{}'",
        args.repo.display(),
        args.credentials.display()
    );

    let probe = HostRequest::Abort(AbortRequest {
        protocol_version: PROTOCOL_VERSION,
        reason: AbortReason::UserCancelled,
    });
    send_host_request(port, &probe)?;
    println!("Status probe sent. Awaiting device reply…");

    let response = read_device_response(port)?;
    handle_device_response(response)?;
    Ok(())
}

fn handle_device_response(response: DeviceResponse) -> Result<bool, SharedError> {
    match response {
        DeviceResponse::JournalFrame(frame) => {
            print_journal_frame(&frame);
            Ok(true)
        }
        DeviceResponse::VaultChunk(chunk) => {
            print_vault_chunk(&chunk);
            Ok(true)
        }
        DeviceResponse::Completed(summary) => {
            print_completion(&summary);
            Ok(false)
        }
        DeviceResponse::Error(err) => Err(SharedError::Transport(format!(
            "device reported {code:?}: {message}",
            code = err.code,
            message = err.message
        ))),
    }
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
    println!(
        "Received vault chunk #{sequence} ({size} bytes, {remaining} bytes remaining).",
        sequence = chunk.sequence,
        size = chunk.data.len(),
        remaining = chunk.remaining_bytes,
    );
    if chunk.is_last {
        println!("  This was the final chunk of the transfer.");
    }
}

fn print_completion(summary: &SyncCompletion) {
    println!(
        "Device completed the sync phase using protocol v{version} after {frames} frames.",
        version = summary.protocol_version,
        frames = summary.frames_sent,
    );
    println!(
        "  Stream checksum: 0x{checksum:08X}",
        checksum = summary.stream_checksum
    );
}

fn send_host_request<W>(writer: &mut W, request: &HostRequest) -> Result<(), SharedError>
where
    W: Write + ?Sized,
{
    let (command, payload) = encode_host_request(request)?;
    write_framed_message(writer, command, &payload)
}

fn encode_host_request(request: &HostRequest) -> Result<(FrameCommand, Vec<u8>), SharedError> {
    match request {
        HostRequest::PullVault(pull) => {
            let payload = serde_cbor::to_vec(pull)?;
            Ok((FrameCommand::HostPullVault, payload))
        }
        HostRequest::AckPush(ack) => {
            let payload = serde_cbor::to_vec(ack)?;
            Ok((FrameCommand::HostAckPush, payload))
        }
        HostRequest::Abort(abort) => {
            let payload = serde_cbor::to_vec(abort)?;
            Ok((FrameCommand::HostAbort, payload))
        }
    }
}

fn read_device_response<R>(reader: &mut R) -> Result<DeviceResponse, SharedError>
where
    R: Read + ?Sized,
{
    let (command, payload) = read_framed_message(reader)?;
    decode_device_response(command, &payload)
}

fn decode_device_response(
    command: FrameCommand,
    payload: &[u8],
) -> Result<DeviceResponse, SharedError> {
    match command {
        FrameCommand::DeviceJournalFrame => {
            let frame = serde_cbor::from_slice(payload)?;
            Ok(DeviceResponse::JournalFrame(frame))
        }
        FrameCommand::DeviceVaultChunk => {
            let chunk = serde_cbor::from_slice(payload)?;
            Ok(DeviceResponse::VaultChunk(chunk))
        }
        FrameCommand::DeviceCompleted => {
            let summary = serde_cbor::from_slice(payload)?;
            Ok(DeviceResponse::Completed(summary))
        }
        FrameCommand::DeviceError => {
            let error = serde_cbor::from_slice(payload)?;
            Ok(DeviceResponse::Error(error))
        }
        other => Err(SharedError::Transport(format!(
            "unexpected frame command {other:?} from device"
        ))),
    }
}

fn write_framed_message<W>(
    writer: &mut W,
    command: FrameCommand,
    payload: &[u8],
) -> Result<(), SharedError>
where
    W: Write + ?Sized,
{
    let length = payload.len();
    if length > u32::MAX as usize {
        return Err(SharedError::Transport(format!(
            "payload too large: {length} bytes"
        )));
    }

    let header = FrameHeader::new(command, length as u32);
    let header_bytes = header.encode();
    writer
        .write_all(&header_bytes)
        .map_err(map_io_error("write frame header"))?;
    writer
        .write_all(payload)
        .map_err(map_io_error("write frame payload"))?;

    let checksum = header.checksum(payload);
    writer
        .write_all(&checksum.to_le_bytes())
        .map_err(map_io_error("write frame checksum"))?;
    writer.flush().map_err(map_io_error("flush frame"))?;
    Ok(())
}

fn read_framed_message<R>(reader: &mut R) -> Result<(FrameCommand, Vec<u8>), SharedError>
where
    R: Read + ?Sized,
{
    let mut header_bytes = [0u8; FrameHeader::ENCODED_LEN];
    reader
        .read_exact(&mut header_bytes)
        .map_err(map_io_error("read frame header"))?;
    let header = FrameHeader::decode(header_bytes)
        .map_err(|err| SharedError::Transport(format!("invalid frame header: {err}")))?;
    let length = header.payload_length as usize;
    let mut payload = vec![0u8; length];
    if !payload.is_empty() {
        reader
            .read_exact(&mut payload)
            .map_err(map_io_error("read frame payload"))?;
    }

    let mut checksum_bytes = [0u8; 4];
    reader
        .read_exact(&mut checksum_bytes)
        .map_err(map_io_error("read frame checksum"))?;
    let expected = u32::from_le_bytes(checksum_bytes);
    let actual = header.checksum(&payload);
    if expected != actual {
        return Err(SharedError::Transport(format!(
            "checksum mismatch (expected 0x{expected:08X}, calculated 0x{actual:08X})"
        )));
    }

    Ok((header.command, payload))
}

fn open_serial_port(path: &str) -> Result<Box<dyn SerialPort>, SharedError> {
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

fn detect_first_serial_port(allow_any_port: bool) -> Result<String, SharedError> {
    let ports = serialport::available_ports().map_err(|err| {
        SharedError::Transport(format!("failed to enumerate serial ports: {err}"))
    })?;

    select_serial_port(&ports, allow_any_port)
        .map(|info| info.port_name.clone())
        .ok_or_else(|| missing_cardputer_error(allow_any_port))
}

fn select_serial_port(
    ports: &[serialport::SerialPortInfo],
    allow_any_port: bool,
) -> Option<&serialport::SerialPortInfo> {
    if allow_any_port {
        return ports
            .iter()
            .find(|info| matches!(info.port_type, SerialPortType::UsbPort(_)));
    }

    let matches: Vec<&serialport::SerialPortInfo> = ports
        .iter()
        .filter(|info| matches_cardputer_vid_pid(info))
        .collect();

    if matches.is_empty() {
        return None;
    }

    if matches.len() == 1 {
        return matches.into_iter().next();
    }

    if let Some(preferred) = matches
        .iter()
        .copied()
        .find(|info| matches_cardputer_identity(info))
    {
        return Some(preferred);
    }

    matches.into_iter().next()
}

fn matches_cardputer_vid_pid(info: &serialport::SerialPortInfo) -> bool {
    matches!(&info.port_type, SerialPortType::UsbPort(usb) if usb.vid == CARDPUTER_USB_VID && usb.pid == CARDPUTER_USB_PID)
}

fn matches_cardputer_identity(info: &serialport::SerialPortInfo) -> bool {
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

fn missing_cardputer_error(allow_any_port: bool) -> SharedError {
    let mut message = format!(
        "Cardputer USB CDC device not found (expected VID 0x{CARDPUTER_USB_VID:04X}, PID 0x{CARDPUTER_USB_PID:04X})."
    );

    if !allow_any_port {
        message.push_str(" Pass --any-port to connect to the first available USB serial device.");
    }

    SharedError::Transport(message)
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

#[cfg(test)]
mod tests {
    use super::*;
    use shared::cdc::FRAME_VERSION;
    use std::io::Cursor;

    fn usb_port(
        name: &str,
        vid: u16,
        pid: u16,
        serial: Option<&str>,
        manufacturer: Option<&str>,
        product: Option<&str>,
    ) -> serialport::SerialPortInfo {
        serialport::SerialPortInfo {
            port_name: name.to_string(),
            port_type: SerialPortType::UsbPort(serialport::UsbPortInfo {
                vid,
                pid,
                serial_number: serial.map(|value| value.to_string()),
                manufacturer: manufacturer.map(|value| value.to_string()),
                product: product.map(|value| value.to_string()),
                interface: None,
            }),
        }
    }

    fn non_usb_port(name: &str) -> serialport::SerialPortInfo {
        serialport::SerialPortInfo {
            port_name: name.to_string(),
            port_type: SerialPortType::PciPort,
        }
    }

    fn encode_response(response: DeviceResponse) -> Vec<u8> {
        let (command, payload) = match response {
            DeviceResponse::JournalFrame(frame) => (
                FrameCommand::DeviceJournalFrame,
                serde_cbor::to_vec(&frame).expect("encode journal"),
            ),
            DeviceResponse::VaultChunk(chunk) => (
                FrameCommand::DeviceVaultChunk,
                serde_cbor::to_vec(&chunk).expect("encode chunk"),
            ),
            DeviceResponse::Completed(summary) => (
                FrameCommand::DeviceCompleted,
                serde_cbor::to_vec(&summary).expect("encode summary"),
            ),
            DeviceResponse::Error(error) => (
                FrameCommand::DeviceError,
                serde_cbor::to_vec(&error).expect("encode error"),
            ),
        };

        let header = FrameHeader::new(command, payload.len() as u32);
        let mut frame = Vec::new();
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&header.checksum(&payload).to_le_bytes());
        frame
    }

    #[test]
    fn detect_cardputer_by_vid_pid() {
        let ports = vec![
            non_usb_port("/dev/ttyS0"),
            usb_port(
                "/dev/ttyUSB0",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                Some("M5Stack"),
                None,
            ),
        ];

        let detected = select_serial_port(&ports, false).expect("cardputer port");
        assert_eq!(detected.port_name, "/dev/ttyUSB0");
    }

    #[test]
    fn detect_cardputer_prefers_identity_keywords() {
        let ports = vec![
            usb_port(
                "/dev/ttyUSB0",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                None,
                Some("Generic CDC"),
            ),
            usb_port(
                "/dev/ttyUSB1",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                Some("M5Stack"),
                Some("Cardputer CDC"),
            ),
        ];

        let detected = select_serial_port(&ports, false).expect("cardputer port");
        assert_eq!(detected.port_name, "/dev/ttyUSB1");
    }

    #[test]
    fn detect_cardputer_none_without_match() {
        let ports = vec![
            non_usb_port("/dev/ttyS0"),
            usb_port(
                "/dev/ttyUSB0",
                0x10C4,
                0xEA60,
                None,
                Some("Silicon Labs"),
                Some("CP210x"),
            ),
        ];

        assert!(select_serial_port(&ports, false).is_none());
    }

    #[test]
    fn detect_cardputer_allows_any_port_override() {
        let ports = vec![
            usb_port(
                "/dev/ttyUSB0",
                0x10C4,
                0xEA60,
                None,
                Some("Silicon Labs"),
                Some("CP210x"),
            ),
            usb_port(
                "/dev/ttyUSB1",
                CARDPUTER_USB_VID,
                CARDPUTER_USB_PID,
                None,
                Some("M5Stack"),
                Some("Cardputer CDC"),
            ),
        ];

        let detected = select_serial_port(&ports, true).expect("usb port");
        assert_eq!(detected.port_name, "/dev/ttyUSB0");
    }

    #[test]
    fn framing_roundtrip() {
        let request = HostRequest::PullVault(PullVaultRequest {
            protocol_version: PROTOCOL_VERSION,
            host_buffer_size: HOST_BUFFER_SIZE,
            max_chunk_size: MAX_CHUNK_SIZE,
            known_generation: Some(7),
        });

        let (command, payload) = encode_host_request(&request).expect("encode request");
        let mut writer = Cursor::new(Vec::new());
        write_framed_message(&mut writer, command, &payload).expect("write frame");

        let data = writer.into_inner();
        let mut reader = Cursor::new(data);
        let (decoded_command, decoded_payload) =
            read_framed_message(&mut reader).expect("read frame");

        assert_eq!(decoded_command, command);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn framing_detects_checksum_mismatch() {
        let payload = vec![1u8, 2, 3, 4];
        let header = FrameHeader::new(FrameCommand::DeviceCompleted, payload.len() as u32);
        let mut frame = Vec::new();
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());

        let mut reader = Cursor::new(frame);
        let err = read_framed_message(&mut reader).expect_err("expected checksum error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("checksum mismatch"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn framing_detects_magic_mismatch() {
        let payload = vec![0u8; 2];
        let mut header = FrameHeader::new(FrameCommand::DeviceCompleted, payload.len() as u32);
        header.magic = 0xDEAD_BEEFu32;
        let header_bytes = header.encode();
        let checksum = header.checksum(&payload);

        let mut frame = Vec::new();
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&checksum.to_le_bytes());

        let mut reader = Cursor::new(frame);
        let err = read_framed_message(&mut reader).expect_err("expected magic error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("invalid frame header"));
                assert!(message.contains("magic"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn framing_detects_version_mismatch() {
        let payload = vec![0u8; 1];
        let mut header = FrameHeader::new(FrameCommand::DeviceCompleted, payload.len() as u32);
        header.version = FRAME_VERSION + 1;
        let header_bytes = header.encode();
        let checksum = header.checksum(&payload);

        let mut frame = Vec::new();
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&checksum.to_le_bytes());

        let mut reader = Cursor::new(frame);
        let err = read_framed_message(&mut reader).expect_err("expected version error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("invalid frame header"));
                assert!(message.contains("version"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn pull_sends_request_and_stops_on_completion() {
        let responses = [
            encode_response(DeviceResponse::VaultChunk(VaultChunk {
                protocol_version: PROTOCOL_VERSION,
                sequence: 1,
                total_size: 1024,
                remaining_bytes: 512,
                device_chunk_size: MAX_CHUNK_SIZE,
                data: vec![0; 8],
                checksum: 0x1234ABCD,
                is_last: false,
            })),
            encode_response(DeviceResponse::Completed(SyncCompletion {
                protocol_version: PROTOCOL_VERSION,
                frames_sent: 2,
                stream_checksum: 0xCAFEBABE,
            })),
        ]
        .concat();

        let mut port = MockPort::new(responses);
        let args = RepoArgs {
            repo: PathBuf::from("/tmp/repo"),
            credentials: PathBuf::from("/tmp/creds"),
        };

        execute_pull(&mut port, &args).expect("pull succeeds");

        let mut reader = Cursor::new(port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, FrameCommand::HostPullVault);
        let decoded: PullVaultRequest = serde_cbor::from_slice(&payload).expect("decode request");
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn status_sends_abort_probe() {
        let responses = encode_response(DeviceResponse::Completed(SyncCompletion {
            protocol_version: PROTOCOL_VERSION,
            frames_sent: 0,
            stream_checksum: 0,
        }));

        let mut port = MockPort::new(responses);
        let args = RepoArgs {
            repo: PathBuf::from("/tmp/repo"),
            credentials: PathBuf::from("/tmp/creds"),
        };

        execute_status(&mut port, &args).expect("status succeeds");

        let mut reader = Cursor::new(port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, FrameCommand::HostAbort);
        let decoded: AbortRequest = serde_cbor::from_slice(&payload).expect("decode request");
        assert_eq!(decoded.protocol_version, PROTOCOL_VERSION);
    }

    struct MockPort {
        read_cursor: Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    impl MockPort {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_cursor: Cursor::new(read_data),
                writes: Vec::new(),
            }
        }
    }

    impl Read for MockPort {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_cursor.read(buf)
        }
    }

    impl Write for MockPort {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
