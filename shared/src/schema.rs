use serde::{Deserialize, Serialize};

/// Placeholder request message definition shared between firmware and host CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub command: String,
}

/// Placeholder response message definition shared between firmware and host CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: String,
}
