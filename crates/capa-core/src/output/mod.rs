//! Output formatting
//!
//! Formats match results for various output formats.

mod json;
pub mod pipeline;

pub use json::{CapaOutput, Capability, SampleInfo, TimingInfo};
