# llm-guard-ml

[![Crates.io](https://img.shields.io/crates/v/llm-guard-ml.svg)](https://crates.io/crates/llm-guard-ml)
[![Docs.rs](https://docs.rs/llm-guard-ml/badge.svg)](https://docs.rs/llm-guard-ml)
[![License](https://img.shields.io/crates/l/llm-guard-ml.svg)](#license)

ONNX-runtime-backed scanners for [`llm-guard`](../llm-guard). Adds an
ML tier on top of the rules tier — catches paraphrased / novel
prompt-injection attacks the rules can't.

## When you need this

You don't, by default. The base `llm-guard` crate covers:

- Literal-substring injections, role-override markers, secret leakage.
- Deobfuscation pre-pass (base64 / leet / spacing / confusables).
- IDN homograph, markdown link smuggling, PII shapes with checksums.
- Optional fuzzy paraphrase matching via `--features fuzzy`.

All of that runs in microseconds and ships with zero ML dependencies.
Add `llm-guard-ml` when you need:

- Recall against attacks no curated corpus has seen yet.
- A model-based second opinion alongside the rules tier.
- Domain-specific classifiers (toxicity, policy, etc.) running on the
  same `Scanner` trait so they compose into your existing
  `Pipeline`.

The cost: per-scan latency goes from microseconds to a few
milliseconds on CPU. See the speed matrix in the base crate's
[README](../llm-guard/README.md#speed-matrix).

## Design contract

- **No model download at runtime.** Loading is the caller's job:
  pass a path to `OnnxScanner::from_file(...)`. Keeps the crate free
  of network code, air-gap-friendly, and forces the operator to own
  the model-update story.
- **No model bundling.** Cargo crates are capped at 10 MB; the
  smallest useful classifier is ~50 MB int8. Operators download
  weights once during deployment; runtime is mmap.
- **No vendor lock-in.** Any ONNX classifier with `input_ids` +
  `attention_mask` inputs and a `[batch, 2]` logits output works.
- **Same `Scanner` trait as the rules tier.** Drop into any
  `llm_guard::Pipeline`.

## Installation

```toml
[dependencies]
llm-guard-ml = "0.1"
```

The build pulls down the prebuilt ONNX Runtime shared library
(~30 MB) so consumers don't need to install `libonnxruntime` via
their OS package manager. This is a **build-time** network fetch,
not a runtime one — runtime is fully offline.

## Quickstart

Download a model once (see [src/models.rs](src/models.rs) for the
recommended one):

```bash
mkdir -p /var/lib/llm-guard-ml/protectai-deberta-v3
cd /var/lib/llm-guard-ml/protectai-deberta-v3
curl -L -o model.onnx \
    https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model_quantized.onnx
curl -L -o tokenizer.json \
    https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/tokenizer.json
```

Then in your code:

```rust,ignore
use llm_guard::{Pipeline, PipelineMode, RoleOverride};
use llm_guard_ml::OnnxScanner;

let ml = OnnxScanner::from_file(
    "/var/lib/llm-guard-ml/protectai-deberta-v3/model.onnx",
    "/var/lib/llm-guard-ml/protectai-deberta-v3/tokenizer.json",
)?;

let pipeline = Pipeline::new(PipelineMode::All)
    .with(RoleOverride::new())   // cheap rules-tier first
    .with(ml);                   // ML as the backstop

let r = pipeline.scan(user_input);
if r.should_refuse() { /* refuse */ }
# Ok::<(), llm_guard_ml::FromFileError>(())
```

For customisation (threshold, severity, custom scanner name, GPU
execution provider) use `OnnxScannerBuilder`:

```rust,ignore
use llm_guard_ml::{ExecutionProvider, OnnxScannerBuilder, Severity};

let scanner = OnnxScannerBuilder::new()
    .threshold(0.7)
    .severity(Severity::Block)              // upgrade from Warn → Block
    .execution_provider(ExecutionProvider::Cpu)
    .build("model.onnx", "tokenizer.json")?;
# Ok::<(), llm_guard_ml::FromFileError>(())
```

## Execution providers

| Feature           | Platform        | Notes                                                              |
| ----------------- | --------------- | ------------------------------------------------------------------ |
| (default)         | All             | CPU. Always built in.                                              |
| `cuda`            | Linux / Windows | Requires CUDA toolkit installed on build/runtime host.             |
| `coreml`          | macOS           | Apple Neural Engine acceleration where the model supports it.      |
| `directml`        | Windows         | DirectX 12 GPU acceleration.                                       |

```toml
llm-guard-ml = { version = "0.1", features = ["cuda"] }
```

If the requested provider isn't available at runtime, the session
silently falls back to CPU.

## FP discipline

Defaults are the same as the rules-tier `FuzzyMatch`: **Warn /
Medium**, threshold 0.5. ML is a heuristic; the operator should know
that when reading the audit log. Upgrade to `Severity::Block` via
the builder when you trust the model's precision in your deployment.

## Status

- 0.1.0 — initial release. Pinned to `ort = 2.0.0-rc.12`. The pin
  will move when `ort` 2.0 final ships.
- Tested via `cargo test -p llm-guard-ml`. The end-to-end smoke
  test in `tests/smoke.rs` requires you to point env vars at a real
  model; otherwise it skips silently.

## License

MIT OR Apache-2.0
