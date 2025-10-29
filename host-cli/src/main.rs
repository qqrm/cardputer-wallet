use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use serialport::{SerialPort, SerialPortType};

use shared::cdc::{compute_crc32, CdcCommand, FrameHeader, FRAME_HEADER_SIZE};
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
const SYNC_STATE_FILE: &str = ".cardputer-sync-state";

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

    let mut state_tracker = SyncStateTracker::default();

    loop {
        let response = read_device_response(port)?;
        if !handle_device_response(response, Some(&mut state_tracker))? {
            break;
        }
    }

    persist_sync_state(&args.repo, state_tracker.last_pair())
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

    let (sequence, checksum) = match load_sync_state(&args.repo)? {
        Some(pair) => pair,
        None => {
            eprintln!(
                "Missing journal state in '{}'. Run pull before confirming a push.",
                args.repo.display()
            );
            return Err(SharedError::Transport(
                "journal state not found for push acknowledgement".into(),
            ));
        }
    };

    let request = HostRequest::AckPush(PushAck {
        protocol_version: PROTOCOL_VERSION,
        last_frame_sequence: sequence,
        journal_checksum: checksum,
    });

    send_host_request(port, &request)?;
    println!("Acknowledgement sent. Awaiting confirmation…");

    loop {
        let response = read_device_response(port)?;
        if !handle_device_response(response, None)? {
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
    handle_device_response(response, None)?;
    Ok(())
}

fn handle_device_response(
    response: DeviceResponse,
    tracker: Option<&mut SyncStateTracker>,
) -> Result<bool, SharedError> {
    match response {
        DeviceResponse::JournalFrame(frame) => {
            print_journal_frame(&frame);
            if let Some(state) = tracker {
                state.record(frame.sequence, frame.checksum);
            }
            Ok(true)
        }
        DeviceResponse::VaultChunk(chunk) => {
            print_vault_chunk(&chunk);
            if let Some(state) = tracker {
                state.record(chunk.sequence, chunk.checksum);
            }
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

#[derive(Default)]
struct SyncStateTracker {
    last_pair: Option<(u32, u32)>,
}

impl SyncStateTracker {
    fn record(&mut self, sequence: u32, checksum: u32) {
        self.last_pair = Some((sequence, checksum));
    }

    fn last_pair(&self) -> Option<(u32, u32)> {
        self.last_pair
    }
}

fn persist_sync_state(repo_path: &Path, state: Option<(u32, u32)>) -> Result<(), SharedError> {
    let path = sync_state_path(repo_path);
    match state {
        Some((sequence, checksum)) => {
            let content = format!("{sequence}:{checksum}\n");
            fs::write(&path, content).map_err(|err| {
                SharedError::Transport(format!(
                    "failed to write sync state to '{}': {err}",
                    path.display()
                ))
            })?
        }
        None => match fs::remove_file(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(SharedError::Transport(format!(
                    "failed to clear sync state at '{}': {err}",
                    path.display()
                )))
            }
        },
    }

    Ok(())
}

fn load_sync_state(repo_path: &Path) -> Result<Option<(u32, u32)>, SharedError> {
    let path = sync_state_path(repo_path);
    let content = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SharedError::Transport(format!(
                "failed to read sync state from '{}': {err}",
                path.display()
            )))
        }
    };

    let trimmed = content.trim();
    let (sequence_str, checksum_str) = trimmed.split_once(':').ok_or_else(|| {
        SharedError::Transport(format!(
            "invalid sync state format in '{}': expected 'sequence:checksum'",
            path.display()
        ))
    })?;

    let sequence = sequence_str.trim().parse::<u32>().map_err(|err| {
        SharedError::Transport(format!(
            "invalid sequence in sync state '{}': {err}",
            path.display()
        ))
    })?;
    let checksum = checksum_str.trim().parse::<u32>().map_err(|err| {
        SharedError::Transport(format!(
            "invalid checksum in sync state '{}': {err}",
            path.display()
        ))
    })?;

    Ok(Some((sequence, checksum)))
}

fn sync_state_path(repo_path: &Path) -> PathBuf {
    repo_path.join(SYNC_STATE_FILE)
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
    let payload = serde_cbor::to_vec(request)?;
    let command = command_for_request(request);
    write_framed_message(writer, command, &payload)
}

fn read_device_response<R>(reader: &mut R) -> Result<DeviceResponse, SharedError>
where
    R: Read + ?Sized,
{
    let (command, payload) = read_framed_message(reader)?;
    let response = serde_cbor::from_slice(&payload)?;
    validate_response_command(command, &response)?;
    Ok(response)
}

fn write_framed_message<W>(
    writer: &mut W,
    command: CdcCommand,
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

    let checksum = compute_crc32(payload);
    let header = FrameHeader::new(PROTOCOL_VERSION, command, length as u32, checksum);
    writer
        .write_all(&header.to_bytes())
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
    let header = FrameHeader::from_bytes(header_bytes)
        .map_err(|err| SharedError::Transport(format!("failed to decode header: {err}")))?;

    if header.version != PROTOCOL_VERSION {
        return Err(SharedError::Transport(format!(
            "unsupported protocol version: {}",
            header.version
        )));
    }

    let length = header.length as usize;
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(map_io_error("read frame payload"))?;

    let expected = header.checksum;
    let actual = compute_crc32(&payload);
    if expected != actual {
        return Err(SharedError::Transport(format!(
            "checksum mismatch (expected 0x{expected:08X}, calculated 0x{actual:08X})"
        )));
    }

    Ok((header.command, payload))
}

fn command_for_request(request: &HostRequest) -> CdcCommand {
    match request {
        HostRequest::PullVault(_) => CdcCommand::PullVault,
        HostRequest::AckPush(_) => CdcCommand::Ack,
        HostRequest::Abort(_) => CdcCommand::Nack,
    }
}

fn command_for_response(response: &DeviceResponse) -> CdcCommand {
    match response {
        DeviceResponse::JournalFrame(_) => CdcCommand::PushOps,
        DeviceResponse::VaultChunk(_) => CdcCommand::PullVault,
        DeviceResponse::Completed(_) => CdcCommand::Status,
        DeviceResponse::Error(_) => CdcCommand::Nack,
    }
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
    use shared::schema::{DeviceError, DeviceErrorCode};
    use std::io::Cursor;
    use tempfile::tempdir;

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
        let payload = serde_cbor::to_vec(&response).expect("encode response");
        let mut cursor = Cursor::new(Vec::new());
        let command = command_for_response(&response);
        write_framed_message(&mut cursor, command, &payload).expect("write frame");
        cursor.into_inner()
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

        let payload = serde_cbor::to_vec(&request).expect("encode request");
        let mut writer = Cursor::new(Vec::new());
        let command = command_for_request(&request);
        write_framed_message(&mut writer, command, &payload).expect("write frame");

        let data = writer.into_inner();
        let mut reader = Cursor::new(data);
        let (decoded_command, decoded) = read_framed_message(&mut reader).expect("read frame");

        assert_eq!(decoded_command, command);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn framing_detects_checksum_mismatch() {
        let payload = vec![1u8, 2, 3, 4];
        let mut frame = Vec::new();
        let header = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            payload.len() as u32,
            0xDEADBEEFu32,
        );
        frame.extend_from_slice(&header.to_bytes());
        frame.extend_from_slice(&payload);

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
    fn response_command_mismatch_is_reported() {
        let response = DeviceResponse::Error(DeviceError {
            protocol_version: PROTOCOL_VERSION,
            code: DeviceErrorCode::InternalFailure,
            message: "failure".into(),
        });
        let payload = serde_cbor::to_vec(&response).expect("encode response");
        let mut frame = Vec::new();
        let checksum = compute_crc32(&payload);
        let wrong_command = FrameHeader::new(
            PROTOCOL_VERSION,
            CdcCommand::PullVault,
            payload.len() as u32,
            checksum,
        );
        frame.extend_from_slice(&wrong_command.to_bytes());
        frame.extend_from_slice(&payload);

        let mut reader = Cursor::new(frame);
        let err = read_device_response(&mut reader).expect_err("expected command error");
        match err {
            SharedError::Transport(message) => {
                assert!(message.contains("unexpected command"));
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
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().to_path_buf(),
            credentials: temp.path().join("creds"),
        };

        execute_pull(&mut port, &args).expect("pull succeeds");

        let mut reader = Cursor::new(port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, CdcCommand::PullVault);
        let decoded: HostRequest = serde_cbor::from_slice(&payload).expect("decode request");
        assert!(matches!(decoded, HostRequest::PullVault(_)));
    }

    #[test]
    fn status_sends_abort_probe() {
        let responses = encode_response(DeviceResponse::Completed(SyncCompletion {
            protocol_version: PROTOCOL_VERSION,
            frames_sent: 0,
            stream_checksum: 0,
        }));

        let mut port = MockPort::new(responses);
        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().to_path_buf(),
            credentials: temp.path().join("creds"),
        };

        execute_status(&mut port, &args).expect("status succeeds");

        let mut reader = Cursor::new(port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, CdcCommand::Nack);
        let decoded: HostRequest = serde_cbor::from_slice(&payload).expect("decode request");
        assert!(matches!(decoded, HostRequest::Abort(_)));
    }

    #[test]
    fn push_ack_uses_saved_journal_state() {
        let sequence = 7;
        let checksum = 0xAABBCCDD;
        let pull_responses = [
            encode_response(DeviceResponse::JournalFrame(JournalFrame {
                protocol_version: PROTOCOL_VERSION,
                sequence,
                remaining_operations: 0,
                operations: Vec::new(),
                checksum,
            })),
            encode_response(DeviceResponse::Completed(SyncCompletion {
                protocol_version: PROTOCOL_VERSION,
                frames_sent: 1,
                stream_checksum: checksum,
            })),
        ]
        .concat();

        let temp = tempdir().expect("tempdir");
        let args = RepoArgs {
            repo: temp.path().to_path_buf(),
            credentials: temp.path().join("creds"),
        };

        {
            let mut port = MockPort::new(pull_responses);
            execute_pull(&mut port, &args).expect("pull succeeds");
        }

        let push_responses = encode_response(DeviceResponse::Completed(SyncCompletion {
            protocol_version: PROTOCOL_VERSION,
            frames_sent: 0,
            stream_checksum: 0,
        }));

        let mut push_port = MockPort::new(push_responses);
        execute_push(&mut push_port, &args).expect("push succeeds");

        let mut reader = Cursor::new(push_port.writes);
        let (command, payload) = read_framed_message(&mut reader).expect("decode written frame");
        assert_eq!(command, CdcCommand::Ack);
        let decoded: HostRequest = serde_cbor::from_slice(&payload).expect("decode request");

        match decoded {
            HostRequest::AckPush(ack) => {
                assert_eq!(ack.last_frame_sequence, sequence);
                assert_eq!(ack.journal_checksum, checksum);
            }
            other => panic!("unexpected request written: {:?}", other),
        }
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
