//! ONNX-runtime-backed scanners for [`llm-guard`].
//!
//! This crate exists so the base `llm-guard` crate stays pure-Rust,
//! sub-millisecond, and free of ML runtime deps. If you need to catch
//! paraphrased / novel prompt-injection attacks that the rules tier
//! can't, add `llm-guard-ml` and compose its [`OnnxScanner`] into
//! your existing [`llm_guard::Pipeline`].
//!
//! ## What it does
//!
//! Loads an ONNX classifier (typically a distilled prompt-injection
//! model exported from Hugging Face) and runs inference on input
//! text. Outputs are mapped to the same [`llm_guard::Match`] /
//! [`llm_guard::ScanResult`] types the rules-tier scanners use, so
//! downstream code branches identically.
//!
//! ## What it deliberately doesn't do
//!
//! - **No model download.** Loading is the caller's job - pass a
//!   path to [`OnnxScanner::from_file`]. This keeps the crate free
//!   of `reqwest` / `sha2` / cache-dir code, makes air-gapped
//!   deployments straightforward, and forces the operator to own
//!   the model-update story.
//! - **No model bundling.** Cargo crates are capped at 10 MB and the
//!   smallest useful classifier is ~50 MB int8. Operators download
//!   weights once during deployment; runtime is mmap.
//! - **No vendor lock-in.** Any ONNX classifier with a `logits` or
//!   `output_0` two-class output works. We ship reference loaders
//!   for the popular options ([`models`]) but the core loader takes
//!   any compatible model.
//!
//! ## Quickstart
//!
//! ```ignore
//! use llm_guard::{Pipeline, PipelineMode, RoleOverride, Scanner};
//! use llm_guard_ml::OnnxScanner;
//!
//! // Load once at startup (mmaps the weights).
//! let ml = OnnxScanner::from_file(
//!     "/var/lib/models/deberta-v3-prompt-injection-int8.onnx",
//!     "/var/lib/models/tokenizer.json",
//! )?;
//!
//! let pipeline = Pipeline::new(PipelineMode::All)
//!     .with(RoleOverride::new())
//!     .with(ml); // OnnxScanner implements Scanner
//! # Ok::<(), llm_guard_ml::FromFileError>(())
//! ```
//!
//! ## Execution providers
//!
//! - CPU is always built in (no feature flag).
//! - `--features cuda` enables CUDA on Linux/Windows (requires CUDA
//!   toolkit on the build/runtime host).
//! - `--features coreml` enables `CoreML` on macOS (Apple Silicon
//!   acceleration via the Apple Neural Engine where the model
//!   supports it).
//! - `--features directml` enables `DirectML` on Windows.

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![deny(unsafe_code)]

pub mod models;
mod scanner;

pub use scanner::{ExecutionProvider, FromFileError, OnnxScanner, OnnxScannerBuilder};

// Re-export the base-crate types callers will need to configure the
// scanner. Saves them an extra `use llm_guard::{Confidence, ...}`
// import when they're already pulling from `llm_guard_ml`.
pub use llm_guard::{Confidence, Severity};
