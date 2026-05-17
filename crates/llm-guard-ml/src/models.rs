//! Pointers to recommended models. This module **does not** download
//! or bundle weights - it documents where to get them and the exact
//! files the [`crate::OnnxScanner`] expects to find.
//!
//! Why documentation instead of code: the crate's design contract is
//! that loading is the caller's responsibility. That keeps us free
//! of `reqwest` / `sha2` / cache-dir code, makes air-gapped builds
//! straightforward, and forces the operator to own the model-update
//! story (which they need to do anyway for compliance reasons).
//!
//! ## Recommended: `ProtectAI` `DeBERTa-v3` prompt-injection v2
//!
//! - **Source:** <https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2>
//! - **License:** Apache-2.0
//! - **Files needed:**
//!   - `onnx/model.onnx` (fp32, ~735 MB) **or**
//!     `onnx/model_quantized.onnx` (int8, ~184 MB) - we recommend
//!     the int8 export for production deployments.
//!   - `tokenizer.json`
//! - **Output shape:** `[batch, 2]` logits, index 0 = `SAFE`,
//!   index 1 = `INJECTION`. Matches [`crate::OnnxScanner`]'s
//!   expected shape - no custom builder needed.
//!
//! ### One-time download (Linux / macOS)
//!
//! ```bash
//! mkdir -p /var/lib/llm-guard-ml/protectai-deberta-v3
//! cd /var/lib/llm-guard-ml/protectai-deberta-v3
//! curl -L -o model.onnx \
//!     https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model_quantized.onnx
//! curl -L -o tokenizer.json \
//!     https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/tokenizer.json
//! ```
//!
//! Then in your code:
//!
//! ```ignore
//! use llm_guard_ml::OnnxScanner;
//! let scanner = OnnxScanner::from_file(
//!     "/var/lib/llm-guard-ml/protectai-deberta-v3/model.onnx",
//!     "/var/lib/llm-guard-ml/protectai-deberta-v3/tokenizer.json",
//! )?;
//! # Ok::<(), llm_guard_ml::FromFileError>(())
//! ```
//!
//! ## Other compatible models
//!
//! Any HuggingFace-style ONNX classifier with:
//!   - `input_ids` (`int64`, `[batch, seq]`) and `attention_mask`
//!     (`int64`, `[batch, seq]`) inputs;
//!   - `[batch, 2]` two-class logits output;
//!
//! works out of the box. For other output shapes (e.g. multi-label
//! toxicity classifiers) write a thin wrapper around the
//! [`crate::OnnxScanner`]-derived custom loader.
//!
//! ## Why no auto-download
//!
//! See the [crate-level docs][crate] for the full reasoning. In
//! short: ML model deployment is an operational concern (caching,
//! mirroring, signing, compliance review) that we'd do badly if we
//! shipped one default workflow.
