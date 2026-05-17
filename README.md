# llm-guard-rs

[![CI](https://github.com/marirs/llm-guard-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/llm-guard-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/marirs/llm-guard-rs)

Zero-copy, sub-millisecond guardrails for LLM input/output. Pure-Rust
scanners by default; opt-in ML tier when you need it.

## Crates in this workspace

| Crate                                          | What it gives you                                                              | When to use                                                  |
| ---------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| [`llm-guard`](crates/llm-guard)                | Rules-tier scanners: substring, regex, structural. Pure Rust, no ML, no network. Sub-millisecond per scan. | Always — this is the base layer. Covers the textbook attacks (prompt-injection, role-override, secret leakage, PII, IDN homograph, markdown smuggling). |
| [`llm-guard-ml`](crates/llm-guard-ml)          | ONNX-runtime-backed scanner. Drop-in implementation of the same `Scanner` trait. | Add when you need to catch paraphrased / novel attacks the rules tier can't. Caller supplies the model file (no auto-download, no bundling). |

## Defence-in-depth tiers

1. **Base** — the `llm-guard` crate, default features. Microsecond
   per-scan, no dependencies beyond `aho-corasick` / `regex` /
   `base64` / `unicode-security`. This is what almost everyone
   actually needs.
2. **Fuzzy** — `llm-guard` with `--features fuzzy`. Adds the
   `FuzzyMatch` scanner: trigram-containment paraphrase detection
   against a curated corpus. Still microsecond range.
3. **ML** — the `llm-guard-ml` crate. ONNX classifier (~3–10 ms p99
   on CPU, much less on GPU). Caller supplies the model.

## Quickstart — base crate

```toml
[dependencies]
llm-guard = "0.2"
```

```rust
use llm_guard::{
    Pipeline, PipelineMode, BanSubstrings, InvisibleText, RoleOverride, TokenLimit,
    patterns::COMMON_INJECTION_PATTERNS,
};

let guard = Pipeline::new(PipelineMode::FirstHit)
    .with(TokenLimit::new(8_000))
    .with(InvisibleText::new())
    .with(RoleOverride::new())
    .with(BanSubstrings::new("injection", COMMON_INJECTION_PATTERNS));

let result = guard.scan(user_input);
if result.should_refuse() {
    // refuse the request
}
```

## Quickstart — ML tier

```toml
[dependencies]
llm-guard    = "0.2"
llm-guard-ml = "0.1"
```

Download a model once during deployment (see
[crates/llm-guard-ml/README.md](crates/llm-guard-ml/README.md) for
the curl recipe and recommended classifiers):

```bash
mkdir -p /var/lib/llm-guard-ml/protectai-deberta-v3
curl -L -o /var/lib/llm-guard-ml/protectai-deberta-v3/model.onnx \
    https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/onnx/model_quantized.onnx
curl -L -o /var/lib/llm-guard-ml/protectai-deberta-v3/tokenizer.json \
    https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2/resolve/main/tokenizer.json
```

```rust,ignore
use llm_guard::{Pipeline, PipelineMode, RoleOverride};
use llm_guard_ml::OnnxScanner;

let ml = OnnxScanner::from_file(
    "/var/lib/llm-guard-ml/protectai-deberta-v3/model.onnx",
    "/var/lib/llm-guard-ml/protectai-deberta-v3/tokenizer.json",
)?;

let pipeline = Pipeline::new(PipelineMode::All)
    .with(RoleOverride::new())  // cheap rules-tier first
    .with(ml);                  // ML as the backstop
# Ok::<(), llm_guard_ml::FromFileError>(())
```

## Building and testing

```bash
# Build everything in the workspace.
cargo build --workspace

# Test the base crate (default features).
cargo test -p llm-guard

# Test the base crate with the fuzzy paraphrase matcher.
cargo test -p llm-guard --features fuzzy

# Test the ML crate (unit tests only; smoke test needs a real model).
cargo test -p llm-guard-ml

# Run the strict zero-copy / bounded-allocation contract test.
# Release mode only - debug builds add capacity tracking that
# disappears under opt-level >= 1.
cargo test --release -p llm-guard --features fuzzy \
    --test zero_alloc -- --test-threads=1

# Run the ML smoke test against a real model.
LLM_GUARD_ML_MODEL=/path/to/model.onnx \
LLM_GUARD_ML_TOKENIZER=/path/to/tokenizer.json \
cargo test --release -p llm-guard-ml --test smoke -- --nocapture

# Clippy across the whole workspace.
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features llm-guard/fuzzy -- -D warnings
```

## Comparison with other guardrail projects

| Property                                    | NeMo Guardrails | Guardrails AI | ZenGuard | AI-Infra-Guard | **this workspace**          |
| ------------------------------------------- | --------------- | ------------- | -------- | -------------- | --------------------------- |
| Language                                    | Python          | Python        | cloud    | Go             | **Rust**                    |
| Default latency                             | 10s–100s ms     | 10s–100s ms   | RTT      | n/a            | **µs (rules), ms (ML)**     |
| ML required by default                      | yes             | yes           | yes      | yes            | **no, opt-in via separate crate** |
| Network at scan time                        | sometimes       | sometimes     | always   | no             | **never**                   |
| Zero-copy borrowed match spans              | no              | no            | no       | no             | **yes (rules tier)**        |
| IDN-homograph defence                       | no              | no            | no       | no             | **built in**                |
| Layered deobfuscation pre-pass              | no              | no            | no       | no             | **built in**                |
| Confidence + severity per hit               | partial         | partial       | no       | no             | **every match**             |

See [crates/llm-guard/README.md](crates/llm-guard/README.md) for the
full per-scanner table, FP discipline notes, and measured speed
matrix.

## Repository layout

```text
.
├── crates/
│   ├── llm-guard/       # base crate (no ML deps)
│   │   ├── src/
│   │   ├── examples/
│   │   ├── tests/
│   │   └── README.md
│   └── llm-guard-ml/    # ONNX scanner
│       ├── src/
│       ├── examples/
│       ├── tests/
│       └── README.md
├── Cargo.toml           # workspace root
└── README.md            # this file
```

## License

MIT OR Apache-2.0
