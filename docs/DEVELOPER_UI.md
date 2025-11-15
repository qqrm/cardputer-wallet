# Firmware UI State Machine

This document maps the firmware user interface module, outlines the runtime
state machine, and captures the developer-facing key binding catalogue.

## Screen Structure

The UI runtime (`firmware::ui`) manages six primary screens:

| Screen   | Purpose                                                       | Key Widgets                                                       |
|----------|----------------------------------------------------------------|-------------------------------------------------------------------|
| Lock     | Unlock prompt and failure counter                             | Hint bar, lock prompt                                             |
| Home     | Default landing view with quick access to entries             | Search field, recent entries list, TOTP timer, status indicators  |
| Entry    | Single entry detail and quick actions                         | Entry metadata, optional TOTP timer, hint bar                     |
| Edit     | Inline form editor for the active entry                       | Form fields with focus, contextual toolbar hint                   |
| Settings | Device configuration browser                                  | Settings list, hint bar                                           |
| Sync     | Status overlay for host synchronization                       | Progress indicator, stage hint, transport indicators              |

Each screen renders through the `ViewContent` enum produced by
`UiRuntime::render()`. The `Frame` struct returned by that method also
includes BLE/USB transport indicators and the context-sensitive hint bar.

## State Machine Overview

`UiRuntime` owns the navigation state. The high-level transitions are:

* `Lock → Home` when the user confirms the unlock prompt (`Enter`).
* `Home → Entry` when the highlighted recent entry is activated (`Enter`).
* `Home → Edit` via the dedicated edit shortcut.
* `Home → Settings` via the settings shortcut.
* `Home → Sync` via the sync shortcut or external trigger.
* `Entry → Edit` when the edit shortcut is pressed.
* `Entry → Home` using `Esc`/`Fn+Home`.
* `Edit → Entry` when the form is saved (`Enter`) or cancelled (`Esc`).
* `Settings → Home` using `Esc`.
* Any screen → `Lock` via the lock shortcut (`Fn+L`).
* Any screen → `Sync` via the sync shortcut (`Fn+S`).

The state machine persists the recent list selection, search query, edit form
buffer, and sync progress between transitions so the UI can seamlessly resume
where the user left off.

## Rendering Pipeline

The rendering code converts state into lightweight widget structs. These
structs are platform-agnostic and suitable for either direct drawing code on
hardware or host-driven UI simulation:

* `SearchWidget` – Captures the search query text and focus state.
* `RecentList` – Highlights the currently selected entry and provides the data
  needed for list rendering.
* `TotpWidget` – Exposes the active code (if any) and the seconds remaining in
  the TOTP window; the countdown is advanced via `UiRuntime::tick()`.
* `EntryView` – Provides entry metadata for the detail view, including the note
  field and TOTP indicator if the entry has an OTP secret.
* `EditView` – Represents the editable fields and which field currently has
  focus.
* `SettingsView` – Lists user-configurable options alongside the selected row.
* `SyncView` – Carries the sync stage description and progress percentage.

Transport status comes from `ui::transport::snapshot()` which surfaces BLE/USB
status metadata (icon name plus textual label) across the Offline/Waiting/
Connecting/Connected/Error states. The USB CDC loop and BLE profile tasks push
state transitions directly into this cache so the UI can reflect live link
health without blocking on hardware APIs.

## Default Key Bindings

The default `Keymap` translates keyboard events into high level commands. The
bindings follow the v0.1 specification and are summarised below:

| Command            | Keys              | Notes                                   |
|--------------------|-------------------|-----------------------------------------|
| Activate           | `Enter`           | Unlock, open entry, save edit           |
| Back               | `Esc`             | Return to previous screen               |
| Lock               | `Fn+L`            | Force lock from any screen              |
| Go home            | `Fn+Home`         | (also triggered via `Esc` in Entry)     |
| Open settings      | `Fn+Settings`     |                                          |
| Start sync         | `Fn+S`            | Displays the sync overlay               |
| Edit entry         | `E` or `Fn+E`     | Opens the editor for the highlighted entry |
| Focus search       | `Fn+Search`       | Places the caret in the search field    |
| Next/Prev widget   | `Tab` / `Shift+Tab` | Cycle focus between search and lists  |
| Move selection     | Arrow keys        | Navigate recent entries and settings    |
| Delete character   | `Backspace`/`Del` | Remove characters from focused field    |

Character keys without modifiers append to the active text field (search or
form field).

## Hint Bar

The hint bar conveys the most relevant shortcuts for the current screen. It is
toggleable via the `ToggleHints` command (mapped in software) and recomputes on
state changes. Tests verify that the hint bar updates when transitioning across
screens.

## Testing Harness

`UiRuntime` ships with unit tests (`firmware/src/ui/state.rs`) that simulate key
flows:

* Unlocking, navigating through entry/edit/sync states, and relocking.
* Hint bar updates across screen transitions.
* Recent entry navigation using arrow keys.

These tests operate without hardware dependencies and provide a foundation for
future UI integration or snapshot testing.
