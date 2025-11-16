use alloc::vec::Vec;

/// Physical key identifiers emitted by the keyboard matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalKey {
    Enter,
    Escape,
    Home,
    Lock,
    Sync,
    Settings,
    Edit,
    Search,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Tab,
    Backspace,
    Delete,
    Space,
    Char(char),
    Unknown(u8),
}

/// Modifier flags accompanying a key event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyModifiers {
    pub shift: bool,
    pub alt: bool,
    pub control: bool,
    pub function: bool,
}

/// Raw keyboard event prior to command mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub key: PhysicalKey,
    pub modifiers: KeyModifiers,
    pub pressed: bool,
}

impl KeyEvent {
    /// Convenience constructor for a key press without modifiers.
    pub fn pressed(key: PhysicalKey) -> Self {
        Self {
            key,
            modifiers: KeyModifiers::default(),
            pressed: true,
        }
    }
}

/// High level user intention extracted from the keyboard layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiCommand {
    Activate,
    Back,
    Lock,
    GoHome,
    OpenSettings,
    StartSync,
    EditEntry,
    FocusSearch,
    ClearSearch,
    MoveSelectionUp,
    MoveSelectionDown,
    MoveSelectionLeft,
    MoveSelectionRight,
    NextWidget,
    PreviousWidget,
    InsertChar(char),
    DeleteChar,
    ConfirmEdit,
    CancelEdit,
    ToggleHints,
    SendUsername,
    SendPassword,
    SendTotp { fallback: Option<char> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Binding {
    key: PhysicalKey,
    modifiers: KeyModifiers,
    command: UiCommand,
}

/// Keyboard map describing how raw key events translate into UI commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keymap {
    bindings: Vec<Binding>,
}

impl Default for Keymap {
    fn default() -> Self {
        let mut map = Self {
            bindings: Vec::new(),
        };
        map.add_binding(
            PhysicalKey::Enter,
            KeyModifiers::default(),
            UiCommand::SendUsername,
        );
        map.add_binding(
            PhysicalKey::Enter,
            KeyModifiers {
                function: true,
                ..KeyModifiers::default()
            },
            UiCommand::SendPassword,
        );
        map.add_binding(
            PhysicalKey::Enter,
            KeyModifiers {
                shift: true,
                ..KeyModifiers::default()
            },
            UiCommand::Activate,
        );
        map.add_binding(
            PhysicalKey::Char('t'),
            KeyModifiers::default(),
            UiCommand::SendTotp {
                fallback: Some('t'),
            },
        );
        map.add_binding(
            PhysicalKey::Char('T'),
            KeyModifiers {
                shift: true,
                ..KeyModifiers::default()
            },
            UiCommand::SendTotp {
                fallback: Some('T'),
            },
        );
        map.add_binding(
            PhysicalKey::Escape,
            KeyModifiers::default(),
            UiCommand::Back,
        );
        map.add_binding(
            PhysicalKey::Home,
            KeyModifiers::default(),
            UiCommand::GoHome,
        );
        map.add_binding(PhysicalKey::Lock, KeyModifiers::default(), UiCommand::Lock);
        map.add_binding(
            PhysicalKey::Settings,
            KeyModifiers::default(),
            UiCommand::OpenSettings,
        );
        map.add_binding(
            PhysicalKey::Sync,
            KeyModifiers::default(),
            UiCommand::StartSync,
        );
        map.add_binding(
            PhysicalKey::Edit,
            KeyModifiers::default(),
            UiCommand::EditEntry,
        );
        map.add_binding(
            PhysicalKey::Search,
            KeyModifiers::default(),
            UiCommand::FocusSearch,
        );
        map.add_binding(
            PhysicalKey::Tab,
            KeyModifiers::default(),
            UiCommand::NextWidget,
        );
        map.add_binding(
            PhysicalKey::Tab,
            KeyModifiers {
                shift: true,
                ..KeyModifiers::default()
            },
            UiCommand::PreviousWidget,
        );
        map.add_binding(
            PhysicalKey::ArrowUp,
            KeyModifiers::default(),
            UiCommand::MoveSelectionUp,
        );
        map.add_binding(
            PhysicalKey::ArrowDown,
            KeyModifiers::default(),
            UiCommand::MoveSelectionDown,
        );
        map.add_binding(
            PhysicalKey::ArrowLeft,
            KeyModifiers::default(),
            UiCommand::MoveSelectionLeft,
        );
        map.add_binding(
            PhysicalKey::ArrowRight,
            KeyModifiers::default(),
            UiCommand::MoveSelectionRight,
        );
        map.add_binding(
            PhysicalKey::Backspace,
            KeyModifiers::default(),
            UiCommand::DeleteChar,
        );
        map.add_binding(
            PhysicalKey::Delete,
            KeyModifiers::default(),
            UiCommand::DeleteChar,
        );
        map
    }
}

impl Keymap {
    /// Default key layout derived from the v0.1 specification.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or override a custom binding.
    pub fn add_binding(&mut self, key: PhysicalKey, modifiers: KeyModifiers, command: UiCommand) {
        if let Some(existing) = self
            .bindings
            .iter_mut()
            .find(|binding| binding.key == key && binding.modifiers == modifiers)
        {
            existing.command = command;
        } else {
            self.bindings.push(Binding {
                key,
                modifiers,
                command,
            });
        }
    }

    /// Resolve a command for the provided key event.
    pub fn resolve(&self, event: &KeyEvent) -> Option<UiCommand> {
        if !event.pressed {
            return None;
        }

        if let Some(binding) = self
            .bindings
            .iter()
            .find(|binding| binding.key == event.key && binding.modifiers == event.modifiers)
        {
            return Some(binding.command);
        }

        if let PhysicalKey::Char(c) = event.key
            && !event.modifiers.control
            && !event.modifiers.alt
            && !event.modifiers.function
        {
            return Some(UiCommand::InsertChar(c));
        }

        if let PhysicalKey::Space = event.key
            && !event.modifiers.control
            && !event.modifiers.alt
            && !event.modifiers.function
        {
            return Some(UiCommand::InsertChar(' '));
        }

        None
    }
}
