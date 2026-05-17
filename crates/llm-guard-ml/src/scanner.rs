//! [`OnnxScanner`]: the core ML scanner.
//!
//! Loads a tokenizer + ONNX classifier from disk, runs inference per
//! [`llm_guard::Scanner::scan`] call, and emits the same
//! [`llm_guard::Match`] shape the rules-tier scanners use - so the
//! Pipeline doesn't know it's talking to an ML model.
//!
//! # Threading
//!
//! The wrapped `ort::Session` keeps an internal thread pool. We hold
//! it inside a [`std::sync::Mutex`] so `OnnxScanner` is `Send + Sync`
//! (the [`llm_guard::Scanner`] trait bound), at the cost of
//! serialising calls on a single instance. If you need parallel
//! inference, hold one `OnnxScanner` per worker - the model file is
//! mmaped, so the per-instance memory cost is just session state
//! plus the input/output buffers (a few MB).

use std::path::Path;
use std::sync::Mutex;

use ort::session::Session;
use ort::value::Tensor;
use thiserror::Error;
use tokenizers::Tokenizer;
use tracing::warn;

use llm_guard::{Confidence, Match, ScanResult, Scanner, Severity};

/// Errors surfaced from [`OnnxScanner::from_file`]. The variants are
/// boxed string messages rather than nested error types so we don't
/// leak the `ort` / `tokenizers` crate identities into our public
/// API - if we swap the runtime in 0.2 we won't break callers.
#[derive(Debug, Error)]
pub enum FromFileError {
    /// The ONNX model file failed to load - missing file, corrupt,
    /// unsupported opset, or a missing execution provider for the
    /// build that opened it.
    #[error("model load failed: {0}")]
    Model(String),
    /// The tokenizer.json file failed to parse - missing file or
    /// schema mismatch.
    #[error("tokenizer load failed: {0}")]
    Tokenizer(String),
}

/// Which ONNX Runtime execution provider to ask for. The CPU
/// provider is always built in; GPU providers require the matching
/// cargo feature (`cuda`, `coreml`, `directml`) at compile time AND
/// the corresponding native libraries on the runtime host.
///
/// If the requested provider isn't available at runtime, the session
/// silently falls back to CPU - log the choice if you care to
/// distinguish those cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutionProvider {
    /// Always available. Default.
    #[default]
    Cpu,
    /// NVIDIA CUDA. Requires `--features cuda` and CUDA toolkit
    /// installed at runtime.
    #[cfg(feature = "cuda")]
    Cuda,
    /// Apple CoreML. Requires `--features coreml` and macOS.
    #[cfg(feature = "coreml")]
    CoreML,
    /// Microsoft DirectML. Requires `--features directml` and Windows.
    #[cfg(feature = "directml")]
    DirectML,
}

/// Builder for [`OnnxScanner`]. Use this when the defaults don't fit:
/// custom execution provider, threshold, or severity / confidence
/// overrides.
///
/// ```ignore
/// use llm_guard::Severity;
/// use llm_guard_ml::{ExecutionProvider, OnnxScannerBuilder};
///
/// let scanner = OnnxScannerBuilder::new()
///     .execution_provider(ExecutionProvider::Cpu)
///     .threshold(0.7)
///     .severity(Severity::Block)
///     .build("model.onnx", "tokenizer.json")?;
/// # Ok::<(), llm_guard_ml::FromFileError>(())
/// ```
pub struct OnnxScannerBuilder {
    execution_provider: ExecutionProvider,
    threshold: f32,
    severity: Severity,
    confidence: Confidence,
    name: &'static str,
    pattern: &'static str,
    max_seq_len: usize,
}

impl Default for OnnxScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OnnxScannerBuilder {
    /// Start a builder with conservative defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            execution_provider: ExecutionProvider::Cpu,
            // Most prompt-injection classifiers output a probability;
            // 0.5 is the natural decision boundary. We err on the
            // recall side - 0.5 is the default; tune per your FP
            // tolerance.
            threshold: 0.5,
            // Defaults match the FuzzyMatch scanner: Warn-only by
            // default so the rules tier owns refusal decisions. A
            // caller who trusts the model raises this to Block.
            severity: Severity::Warn,
            confidence: Confidence::Medium,
            name: "onnx_scanner",
            pattern: "prompt_injection",
            // 512 covers BERT/DeBERTa-base. Inputs are truncated to
            // fit so we don't blow up on long documents.
            max_seq_len: 512,
        }
    }

    /// Choose an execution provider (default CPU).
    #[must_use]
    pub fn execution_provider(mut self, ep: ExecutionProvider) -> Self {
        self.execution_provider = ep;
        self
    }

    /// Probability threshold for emitting a match (default 0.5).
    /// Clamped to `[0.0, 1.0]`.
    #[must_use]
    pub fn threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Severity attached to every emitted match (default
    /// [`Severity::Warn`]).
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Confidence attached to every emitted match (default
    /// [`Confidence::Medium`]).
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Override the scanner name (default `"onnx_scanner"`). Used
    /// when multiple `OnnxScanner` instances coexist in one pipeline and the
    /// audit log needs to disambiguate them.
    #[must_use]
    pub fn name(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }

    /// Override the match pattern id (default `"prompt_injection"`).
    /// Useful when the model is classifying something other than
    /// prompt-injection (e.g. toxicity).
    #[must_use]
    pub fn pattern(mut self, pattern: &'static str) -> Self {
        self.pattern = pattern;
        self
    }

    /// Maximum tokenised sequence length. Inputs longer than this
    /// are truncated before being fed to the model. Default 512,
    /// which matches BERT / DeBERTa-base.
    #[must_use]
    pub fn max_seq_len(mut self, n: usize) -> Self {
        self.max_seq_len = n;
        self
    }

    /// Build the scanner. Loads the tokenizer and model from disk;
    /// the heavy work happens here, not on the scan hot path.
    ///
    /// # Errors
    ///
    /// Returns [`FromFileError::Model`] if the ONNX model fails to
    /// load (missing file, unsupported opset, EP not built in).
    /// Returns [`FromFileError::Tokenizer`] if the tokenizer.json
    /// fails to parse.
    pub fn build<P: AsRef<Path>, Q: AsRef<Path>>(
        self,
        model: P,
        tokenizer: Q,
    ) -> Result<OnnxScanner, FromFileError> {
        let tokenizer =
            Tokenizer::from_file(tokenizer).map_err(|e| FromFileError::Tokenizer(e.to_string()))?;

        let mut builder = Session::builder().map_err(|e| FromFileError::Model(e.to_string()))?;
        // Execution-provider registration. Each EP is registered as
        // a *preferred* provider; ort falls back to CPU if the EP
        // isn't available at runtime. The feature-gating ensures
        // the registration call only compiles when the matching
        // `ort/cuda` / `ort/coreml` / `ort/directml` feature is on.
        match self.execution_provider {
            ExecutionProvider::Cpu => {}
            #[cfg(feature = "cuda")]
            ExecutionProvider::Cuda => {
                builder = builder
                    .with_execution_providers([
                        ort::execution_providers::CUDAExecutionProvider::default().build(),
                    ])
                    .map_err(|e| FromFileError::Model(e.to_string()))?;
            }
            #[cfg(feature = "coreml")]
            ExecutionProvider::CoreML => {
                builder = builder
                    .with_execution_providers([
                        ort::execution_providers::CoreMLExecutionProvider::default().build(),
                    ])
                    .map_err(|e| FromFileError::Model(e.to_string()))?;
            }
            #[cfg(feature = "directml")]
            ExecutionProvider::DirectML => {
                builder = builder
                    .with_execution_providers([
                        ort::execution_providers::DirectMLExecutionProvider::default().build(),
                    ])
                    .map_err(|e| FromFileError::Model(e.to_string()))?;
            }
        }
        let session = builder
            .commit_from_file(model)
            .map_err(|e| FromFileError::Model(e.to_string()))?;

        Ok(OnnxScanner {
            session: Mutex::new(session),
            tokenizer,
            threshold: self.threshold,
            severity: self.severity,
            confidence: self.confidence,
            name: self.name,
            pattern: self.pattern,
            max_seq_len: self.max_seq_len,
        })
    }
}

/// ML scanner wrapping a tokenizer + ONNX classifier session.
///
/// Construct via [`Self::from_file`] for the common case or
/// [`OnnxScannerBuilder`] when you need to customise.
///
/// Implements [`llm_guard::Scanner`] so it composes into any
/// [`llm_guard::Pipeline`] alongside the rules-tier scanners.
pub struct OnnxScanner {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    threshold: f32,
    severity: Severity,
    confidence: Confidence,
    name: &'static str,
    pattern: &'static str,
    max_seq_len: usize,
}

impl OnnxScanner {
    /// Load a scanner from `model` (path to `.onnx`) and `tokenizer`
    /// (path to `tokenizer.json`). Uses default settings - CPU
    /// execution, threshold 0.5, [`Severity::Warn`], 512 max tokens.
    ///
    /// For non-default settings use [`OnnxScannerBuilder`].
    ///
    /// # Errors
    ///
    /// See [`OnnxScannerBuilder::build`].
    pub fn from_file<P: AsRef<Path>, Q: AsRef<Path>>(
        model: P,
        tokenizer: Q,
    ) -> Result<Self, FromFileError> {
        OnnxScannerBuilder::new().build(model, tokenizer)
    }

    /// Returns the configured probability threshold.
    #[must_use]
    pub fn threshold(&self) -> f32 {
        self.threshold
    }
}

impl Scanner for OnnxScanner {
    fn name(&self) -> &'static str {
        self.name
    }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        // EVERY early return below logs a `warn!` event. This is the
        // L1 fix from the security review: silent failures of a
        // security-critical scanner are themselves an attack surface
        // (a tokenizer hiccup could mute the entire ML tier). With
        // tracing in place, operators see the failure mode in their
        // logs and can route on it.
        let scanner_name = self.name;

        // Tokenize. The tokenizers crate handles its own truncation
        // / padding configuration; here we just take what it gives
        // us and truncate manually to `max_seq_len`.
        let enc = match self.tokenizer.encode(input, true) {
            Ok(enc) => enc,
            Err(e) => {
                warn!(scanner = scanner_name, error = %e, "tokenizer.encode failed; treating as no-match");
                return ScanResult::default();
            }
        };
        let ids = enc.get_ids();
        let mask = enc.get_attention_mask();
        let len = ids.len().min(self.max_seq_len);
        if len == 0 {
            // Empty tokenisation - usually means empty input. Not a
            // failure; nothing to log.
            return ScanResult::default();
        }
        // Convert to i64 (ONNX models from HF expect i64 input ids).
        let input_ids: Vec<i64> = ids[..len].iter().map(|&u| i64::from(u)).collect();
        let attention_mask: Vec<i64> = mask[..len].iter().map(|&u| i64::from(u)).collect();
        // `len` is bounded by `max_seq_len` (default 512) so the
        // cast can't overflow i64 in practice, but be explicit.
        let Ok(len_i64) = i64::try_from(len) else {
            warn!(
                scanner = scanner_name,
                len, "max_seq_len exceeds i64::MAX; treating as no-match"
            );
            return ScanResult::default();
        };
        let shape = [1_i64, len_i64];

        // Build input tensors. `Tensor::from_array((shape, vec))`
        // gives us a tensor that owns its data - no ndarray dance.
        let ids_tensor = match Tensor::from_array((shape, input_ids)) {
            Ok(t) => t,
            Err(e) => {
                warn!(scanner = scanner_name, error = %e, "input_ids tensor build failed; treating as no-match");
                return ScanResult::default();
            }
        };
        let mask_tensor = match Tensor::from_array((shape, attention_mask)) {
            Ok(t) => t,
            Err(e) => {
                warn!(scanner = scanner_name, error = %e, "attention_mask tensor build failed; treating as no-match");
                return ScanResult::default();
            }
        };

        // L2 fix: previously a poisoned mutex (panic in another scan
        // thread) silently disabled this scanner forever. Now we
        // recover the inner session via `into_inner()` on
        // `PoisonError` - the session's own state is independent of
        // the panic, and continuing to use it is preferable to
        // permanent fail-clean.
        let mut session = match self.session.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                warn!(
                    scanner = scanner_name,
                    "session mutex was poisoned by a prior panic; recovering and continuing"
                );
                poison.into_inner()
            }
        };
        let outputs = match session.run(ort::inputs![
            "input_ids" => ids_tensor,
            "attention_mask" => mask_tensor,
        ]) {
            Ok(o) => o,
            Err(e) => {
                warn!(scanner = scanner_name, error = %e, "ort session.run failed; treating as no-match");
                return ScanResult::default();
            }
        };

        // Pull the first output (usually "logits"). Some models name
        // it "output_0" - we don't depend on the name.
        let Some((_, first)) = outputs.iter().next() else {
            warn!(
                scanner = scanner_name,
                "ort returned no outputs; treating as no-match"
            );
            return ScanResult::default();
        };
        let (out_shape, logits) = match first.try_extract_tensor::<f32>() {
            Ok(t) => t,
            Err(e) => {
                warn!(scanner = scanner_name, error = %e, "could not extract f32 logits tensor; treating as no-match");
                return ScanResult::default();
            }
        };

        // L3 fix: previously we silently returned clean on
        // unexpected output shapes - a misconfigured model (e.g.
        // a multi-class toxicity classifier with `[1, 3]` output
        // wired to an OnnxScanner) would look like a clean scan
        // forever. Now we log the actual shape so the operator
        // can spot the mismatch on first call.
        let dims = out_shape.as_ref();
        let last_dim = dims.last().copied();
        if dims.len() < 2 || last_dim != Some(2) || logits.len() < 2 {
            warn!(
                scanner = scanner_name,
                shape = ?dims,
                logits_len = logits.len(),
                "OnnxScanner expects 2-class output (shape [..., 2]); got something else - treating as no-match. Use OnnxScannerBuilder with a custom inference path if your model has a different head."
            );
            return ScanResult::default();
        }
        let prob_injection = softmax_binary(logits[0], logits[1]);
        if prob_injection < self.threshold {
            return ScanResult::default();
        }

        // Zero-copy: report the FULL input slice as the match span.
        // We can't localise the hit to a sub-region because the
        // classifier scored the whole sequence; callers wanting a
        // literal span use the rules-tier scanners.
        ScanResult {
            matches: vec![Match::new(
                self.name,
                self.pattern,
                0..input.len(),
                input,
                self.confidence,
                self.severity,
            )],
        }
    }
}

/// Two-class softmax. Numerically stable: subtract the max before
/// `exp()` to avoid overflow on large positive logits.
fn softmax_binary(benign: f32, injection: f32) -> f32 {
    let m = benign.max(injection);
    let eb = (benign - m).exp();
    let ei = (injection - m).exp();
    ei / (eb + ei)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_clean_logits() {
        // Strongly negative injection logit → near zero.
        let p = softmax_binary(5.0, -5.0);
        assert!(p < 0.001, "got {p}");
    }

    #[test]
    fn softmax_attack_logits() {
        // Strongly positive injection logit → near one.
        let p = softmax_binary(-5.0, 5.0);
        assert!(p > 0.999, "got {p}");
    }

    #[test]
    fn softmax_neutral_logits() {
        // Equal logits → 0.5.
        let p = softmax_binary(0.0, 0.0);
        assert!((p - 0.5).abs() < 1e-6);
    }

    #[test]
    fn softmax_numerical_stability() {
        // Very large logits would overflow without the max-subtract.
        let p = softmax_binary(1000.0, 1001.0);
        // Should not be NaN/Inf; e^1 / (e^0 + e^1) ≈ 0.731.
        assert!(p.is_finite());
        assert!((p - 0.731_058_6).abs() < 1e-4, "got {p}");
    }

    #[test]
    fn builder_clamps_threshold() {
        let s = OnnxScannerBuilder::new().threshold(1.5);
        assert!((s.threshold - 1.0).abs() < f32::EPSILON);
        let s = OnnxScannerBuilder::new().threshold(-0.5);
        assert!(s.threshold.abs() < f32::EPSILON);
    }

    #[test]
    fn from_file_returns_error_on_missing_files() {
        let r = OnnxScanner::from_file("/nonexistent/model.onnx", "/nonexistent/tok.json");
        // Either tokenizer or model failure is fine - we want an Err.
        assert!(r.is_err());
    }
}
