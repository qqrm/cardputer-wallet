#![cfg(test)]

use super::SyncContext;

pub(super) fn fresh_context() -> SyncContext {
    crate::hid::actions::clear();
    SyncContext::new()
}
