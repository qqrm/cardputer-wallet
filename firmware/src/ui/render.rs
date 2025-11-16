use alloc::{string::String, vec::Vec};

use super::transport::TransportIndicators;

/// Aggregated render output for the active UI frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub transport: TransportIndicators,
    pub content: ViewContent,
    pub hint_bar: HintBar,
}

/// Footer with per-screen keyboard hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HintBar {
    pub hints: Vec<HintItem>,
}

impl HintBar {
    pub fn new(hints: Vec<HintItem>) -> Self {
        Self { hints }
    }
}

/// Key-action pairing presented in the hint bar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HintItem {
    pub key: String,
    pub action: String,
}

impl HintItem {
    pub fn new<K: Into<String>, A: Into<String>>(key: K, action: A) -> Self {
        Self {
            key: key.into(),
            action: action.into(),
        }
    }
}

/// Content rendered for each screen variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewContent {
    Lock(LockView),
    Home(HomeView),
    Entry(EntryView),
    Edit(EditView),
    Settings(SettingsView),
    Sync(SyncView),
}

/// Lock screen prompt state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockView {
    pub prompt: String,
    pub remaining_attempts: Option<u8>,
    pub entered_digits: usize,
    pub max_digits: usize,
    pub backoff_remaining_ms: Option<u64>,
    pub wipe_required: bool,
}

/// Search bar state for the home screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchWidget {
    pub query: String,
    pub has_focus: bool,
}

/// Recent entry list widget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentList {
    pub entries: Vec<RecentListItem>,
    pub selected: Option<usize>,
}

/// Entry summary shown in the recent list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentListItem {
    pub title: String,
    pub subtitle: Option<String>,
}

/// Time-based OTP indicator widget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpWidget {
    pub code: Option<String>,
    pub seconds_remaining: u8,
    pub period: u8,
}

/// Composite home screen view model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeView {
    pub search: SearchWidget,
    pub recent: RecentList,
    pub totp: TotpWidget,
}

/// Detailed entry view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryView {
    pub entry: EntryDetails,
    pub hint: Option<String>,
}

/// Entry metadata displayed on the entry screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryDetails {
    pub title: String,
    pub username: String,
    pub note: Option<String>,
    pub totp: Option<TotpWidget>,
}

/// Edit form layout for entry modification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditView {
    pub form: FormWidget,
    pub toolbar_hint: Option<String>,
}

/// Form widget for editing entry fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormWidget {
    pub fields: Vec<FormField>,
    pub active_index: usize,
}

/// Individual editable field descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormField {
    pub label: String,
    pub value: String,
    pub secure: bool,
}

/// Settings list view model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsView {
    pub options: Vec<SettingsItem>,
    pub selected: usize,
}

/// Individual settings option descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsItem {
    pub label: String,
    pub value: String,
}

/// Sync progress overlay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncView {
    pub stage: String,
    pub progress_percent: u8,
    pub hint: Option<String>,
}
