//! Output formatting
//!
//! Formats match results for various output formats.

mod json;
pub mod pipeline;
pub mod result_document;
pub mod verbose;

pub use json::{CapaOutput, Capability, SampleInfo, TimingInfo};
pub use result_document::ResultDocument;
