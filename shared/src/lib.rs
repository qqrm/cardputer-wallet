#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod cdc;
#[cfg(feature = "std")]
pub mod error;
pub mod schema;
pub mod vault;
