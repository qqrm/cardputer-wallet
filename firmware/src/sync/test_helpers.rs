use super::SyncContext;

pub(super) fn fresh_context() -> SyncContext {
    crate::hid::core::actions::clear();
    SyncContext::new()
}
