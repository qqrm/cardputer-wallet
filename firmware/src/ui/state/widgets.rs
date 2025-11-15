use alloc::{string::String, vec, vec::Vec};

use super::{UiRuntime, UiScreen};
use crate::ui::render::{HintBar, HintItem, SettingsItem};

pub(super) fn default_settings_options() -> Vec<SettingsItem> {
    vec![
        SettingsItem {
            label: String::from("Auto-lock"),
            value: String::from("90s"),
        },
        SettingsItem {
            label: String::from("Theme"),
            value: String::from("Contrast"),
        },
        SettingsItem {
            label: String::from("Sync target"),
            value: String::from("Repo"),
        },
    ]
}

impl UiRuntime {
    pub(super) fn hint_bar(&self) -> HintBar {
        if !self.show_hints {
            return HintBar::new(vec![]);
        }

        let hints = match self.screen {
            UiScreen::Lock => vec![
                HintItem::new("Enter", "Unlock"),
                HintItem::new("Fn+L", "Lock"),
            ],
            UiScreen::Home => vec![
                HintItem::new("Enter", "Open"),
                HintItem::new("E", "Edit"),
                HintItem::new("Fn+S", "Sync"),
                HintItem::new("Fn+L", "Lock"),
            ],
            UiScreen::Entry => vec![
                HintItem::new("Esc", "Back"),
                HintItem::new("E", "Edit"),
                HintItem::new("Fn+S", "Sync"),
            ],
            UiScreen::Edit => vec![
                HintItem::new("Enter", "Save"),
                HintItem::new("Esc", "Cancel"),
                HintItem::new("Tab", "Next field"),
            ],
            UiScreen::Settings => vec![
                HintItem::new("Esc", "Home"),
                HintItem::new("Enter", "Select"),
                HintItem::new("Fn+L", "Lock"),
            ],
            UiScreen::Sync => vec![HintItem::new("Esc", "Home"), HintItem::new("Fn+L", "Lock")],
        };

        HintBar::new(hints)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::input::PhysicalKey;

    #[test]
    fn hint_bar_reflects_active_screen() {
        let vault =
            super::super::fixtures::MemoryVault::new(super::super::fixtures::sample_entries());
        let mut ui = super::super::fixtures::build_runtime(vault);

        fn assert_hint(ui: &UiRuntime, expected: &str) {
            let frame = ui.render();
            assert!(
                frame
                    .hint_bar
                    .hints
                    .iter()
                    .any(|hint| hint.action.contains(expected)),
                "missing {expected} hint"
            );
        }

        assert_hint(&ui, "Unlock");
        super::super::fixtures::press(&mut ui, PhysicalKey::Enter);
        assert_hint(&ui, "Open");
        super::super::fixtures::press(&mut ui, PhysicalKey::Enter);
        assert_hint(&ui, "Edit");
        super::super::fixtures::press(&mut ui, PhysicalKey::Edit);
        assert_hint(&ui, "Save");
        super::super::fixtures::press(&mut ui, PhysicalKey::Settings);
        assert_hint(&ui, "Select");
        super::super::fixtures::press(&mut ui, PhysicalKey::Sync);
        assert_hint(&ui, "Lock");
    }
}
