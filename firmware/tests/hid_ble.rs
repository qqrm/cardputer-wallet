#![cfg(feature = "ui-tests")]

use firmware::hid::ble::profile::TroubleProfile;
use firmware::hid::ble::{BleHid, HidBackend, HidCommandQueue, HidError, HidResponse, profile};
use firmware::hid::core::actions::{DeviceAction, KeyboardReport, MacroBuffer, MacroStep};
use heapless::Vec;
use std::boxed::Box;
use trouble_host::IoCapabilities;

fn test_backend() -> BleHid {
    let profile = profile::TroubleProfile::new("Test HID").expect("profile");
    BleHid::new(profile, IoCapabilities::KeyboardDisplay)
}

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
    let mut backend = test_backend();
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
    let mut backend = test_backend();
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

#[test]
fn backend_requires_session_before_reports() {
    let mut backend = test_backend();
    let err = backend
        .process_action(DeviceAction::SendReport {
            session_id: 99,
            report: KeyboardReport::empty(),
        })
        .unwrap_err();
    assert_eq!(err, HidError::NoActiveSession);
}

#[test]
fn profile_streams_macro_reports() {
    let profile = profile::TroubleProfile::new("Test HID").unwrap();
    let mut backend = BleHid::new(profile, IoCapabilities::KeyboardDisplay);
    backend
        .process_action(DeviceAction::StartSession { session_id: 5 })
        .unwrap();
    let mut buffer = MacroBuffer::new();
    buffer
        .push(MacroStep::Report(KeyboardReport::from_keys(0, &[4, 5])))
        .unwrap();
    buffer.push(MacroStep::Delay(20)).unwrap();
    buffer
        .push(MacroStep::Report(KeyboardReport::from_keys(1, &[6])))
        .unwrap();
    let resp = backend
        .process_action(DeviceAction::StreamMacro {
            session_id: 5,
            buffer: Box::new(buffer),
        })
        .unwrap();
    assert_eq!(
        resp,
        HidResponse::MacroAccepted {
            session_id: 5,
            emitted_reports: 2,
        }
    );
}

#[test]
fn profile_encodes_reports() {
    let mut profile = TroubleProfile::new("Test").unwrap();
    profile
        .send_keyboard_report(&KeyboardReport::from_keys(1, &[4, 5]))
        .unwrap();
    let last = profile.last_report().unwrap();
    assert_eq!(last[0], 1);
    assert_eq!(&last[2..4], &[4, 5]);
}

#[test]
fn macro_queue_drains_in_order() {
    let mut profile = TroubleProfile::new("Test").unwrap();
    let mut buffer = MacroBuffer::new();
    buffer
        .push(MacroStep::Report(KeyboardReport::from_keys(0, &[30])))
        .unwrap();
    buffer
        .push(MacroStep::Report(KeyboardReport::from_keys(0, &[40])))
        .unwrap();
    let emitted = profile.stream_macro(&buffer).unwrap();
    assert_eq!(emitted, 2);
    let last = profile.last_report().unwrap();
    assert_eq!(last[2], 40);
}

#[test]
fn advertisement_fits_into_payload() {
    let profile = TroubleProfile::new("Cardputer").unwrap();
    let (adv, scan) = profile.advertisement();
    assert!(!adv.is_empty());
    assert!(!scan.is_empty());
}
