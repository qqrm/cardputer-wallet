use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};
use core::cmp;

use crate::ui::{TotpProvider, TotpSnapshot};
use shared::totp::{TotpCode, generate};
use shared::vault::TotpConfig;

const FALLBACK_PERIOD: u8 = 30;

/// Shared TOTP engine that keeps UI and HID outputs aligned.
pub struct SharedTotp {
    configs: BTreeMap<String, TotpConfig>,
    active_entry: Option<String>,
    snapshot: TotpSnapshot,
    now_ms: u64,
}

impl SharedTotp {
    pub fn new() -> Self {
        Self {
            configs: BTreeMap::new(),
            active_entry: None,
            snapshot: TotpSnapshot::empty(FALLBACK_PERIOD),
            now_ms: 0,
        }
    }

    pub fn upsert_config(&mut self, entry_id: impl Into<String>, config: TotpConfig) {
        self.configs.insert(entry_id.into(), config);
        self.refresh_snapshot();
    }

    pub fn remove_config(&mut self, entry_id: &str) {
        self.configs.remove(entry_id);
        if self
            .active_entry
            .as_ref()
            .is_some_and(|active| active == entry_id)
        {
            self.active_entry = None;
        }
        self.refresh_snapshot();
    }

    pub fn sync_time(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.refresh_snapshot();
    }

    pub fn code_for_hid(&self) -> Option<String> {
        self.snapshot.code.clone()
    }

    fn refresh_snapshot(&mut self) {
        if let Some(active) = self.active_entry.clone()
            && let Some(config) = self.configs.get(&active)
            && let Ok(code) = generate(config, self.now_ms)
        {
            self.snapshot = to_snapshot(config, &code);
            return;
        }

        self.snapshot = TotpSnapshot::empty(FALLBACK_PERIOD);
    }
}

impl Default for SharedTotp {
    fn default() -> Self {
        Self::new()
    }
}

impl TotpProvider for SharedTotp {
    fn select_entry(&mut self, entry_id: Option<&str>) {
        self.active_entry = entry_id.map(|id| id.to_string());
        self.refresh_snapshot();
    }

    fn snapshot(&self) -> TotpSnapshot {
        self.snapshot.clone()
    }

    fn tick(&mut self, elapsed_ms: u32) {
        if elapsed_ms == 0 {
            return;
        }

        if self.now_ms > 0 {
            self.now_ms = self.now_ms.saturating_add(elapsed_ms as u64);
        }

        if self.snapshot.remaining_ms <= elapsed_ms {
            self.refresh_snapshot();
        } else {
            self.snapshot.remaining_ms -= elapsed_ms;
        }
    }
}

fn to_snapshot(config: &TotpConfig, code: &TotpCode) -> TotpSnapshot {
    let period = cmp::min(config.period, u8::MAX as u16) as u8;
    TotpSnapshot {
        code: Some(code.code.clone()),
        period,
        remaining_ms: cmp::min(code.remaining_ms, period as u32 * 1_000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::vault::{SecretString, TotpAlgorithm};

    fn sample_config() -> TotpConfig {
        TotpConfig {
            secret: SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        }
    }

    #[test]
    fn hid_and_ui_share_codes() {
        let mut totp = SharedTotp::new();
        totp.upsert_config("alpha", sample_config());
        totp.sync_time(59_000);
        totp.select_entry(Some("alpha"));

        let ui_code = totp.snapshot().code;
        let hid_code = totp.code_for_hid();
        assert_eq!(ui_code, hid_code);
    }

    #[test]
    fn tick_refreshes_after_window() {
        let mut totp = SharedTotp::new();
        totp.upsert_config("alpha", sample_config());
        totp.sync_time(59_000);
        totp.select_entry(Some("alpha"));
        let remaining = totp.snapshot().remaining_ms;
        totp.tick(remaining);
        assert!(totp.snapshot().code.is_some());
    }
}
