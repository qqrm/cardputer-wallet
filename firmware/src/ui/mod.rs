//! Firmware user interface runtime.
//!
//! The UI module owns the on-device navigation state machine, translates
//! keyboard input into high level actions, and produces renderable frames for
//! the display pipeline. It deliberately separates transport status tracking
//! and view rendering so the code can be exercised in tests without hardware
//! dependencies.

mod data;
mod input;
pub mod journal;
mod render;
mod state;
pub mod transport;

pub use data::{JournalAction, JournalEntryView, TotpProvider, TotpSnapshot, VaultViewModel};
pub use input::{KeyEvent, KeyModifiers, Keymap, PhysicalKey, UiCommand};
pub use journal::JournalOperationViewExt;
pub use render::{
    EditView, EntryView, Frame, HintBar, HintItem, HomeView, LockView, RecentList, SearchWidget,
    SettingsView, SyncView, TotpWidget, ViewContent,
};
#[cfg(any(test, feature = "ui-tests"))]
pub use state::fixtures;
pub use state::{EntrySummary, UiEffect, UiRuntime, UiScreen};
pub use transport::{TransportIndicators, TransportKind, TransportState, TransportStatus};
