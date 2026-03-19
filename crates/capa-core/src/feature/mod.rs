//! Feature extraction and representation
//!
//! Defines the feature types and extraction trait.

mod extractor;
mod types;
pub mod com;
pub mod freeze;

pub use extractor::FeatureExtractor;
pub use types::*;
