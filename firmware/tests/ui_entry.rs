#![cfg(feature = "ui-tests")]

use firmware::ui::{UiCommand, ViewContent, fixtures};

#[test]
fn recent_selection_moves_with_arrows() {
    let vault = fixtures::MemoryVault::new(fixtures::sample_entries());
    let mut ui = fixtures::build_runtime(vault);
    let adapter = fixtures::SystemAdapter::default();

    fixtures::submit_pin(&mut ui, &adapter, fixtures::TEST_PIN);
    fixtures::apply(&mut ui, &adapter, UiCommand::MoveSelectionDown);
    let frame = ui.render();
    match frame.content {
        ViewContent::Home(home) => {
            assert_eq!(home.recent.selected, Some(1));
        }
        _ => panic!("expected home view"),
    }
}

#[test]
fn search_results_follow_spec_sorting() {
    let mut entries =
        fixtures::generate_entries(fixtures::EntryFixtureConfig::newest_first(4, false));
    entries[1].id = String::from("alpine");
    entries[1].title = String::from("Alpine");
    entries[1].username = String::from("ops");
    entries[2].username = String::from("alx");
    entries[2].last_used = String::from("2024-01-10");
    let vault = fixtures::MemoryVault::new(entries);
    let mut ui = fixtures::build_runtime(vault);
    let adapter = fixtures::SystemAdapter::default();

    fixtures::submit_pin(&mut ui, &adapter, fixtures::TEST_PIN);
    fixtures::apply(&mut ui, &adapter, UiCommand::InsertChar('a'));
    fixtures::apply(&mut ui, &adapter, UiCommand::InsertChar('l'));
    let frame = ui.render();
    match frame.content {
        ViewContent::Home(home) => {
            let titles: Vec<_> = home
                .recent
                .entries
                .iter()
                .map(|item| item.title.clone())
                .collect();
            assert_eq!(titles[0], "Alpha");
            assert_eq!(titles[1], "Alpine");
            assert_eq!(titles[2], "Gamma");
        }
        _ => panic!("expected home view"),
    }
}
