# llm-guard

[![CI](https://github.com/marirs/llm-guard-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/llm-guard-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/llm-guard.svg)](https://crates.io/crates/llm-guard)
[![Docs.rs](https://docs.rs/llm-guard/badge.svg)](https://docs.rs/llm-guard)
[![Downloads](https://img.shields.io/crates/d/llm-guard.svg)](https://crates.io/crates/llm-guard)
[![License](https://img.shields.io/crates/l/llm-guard.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://github.com/marirs/llm-guard-rs)

Zero-copy, sub-millisecond guardrails for LLM input/output. Pure-Rust
scanners — no Python, no ML runtime on the default path, no network
calls. Built to be the fast first line of defence in front of any LLM
gateway, with optional ML deepening behind a feature flag.

## Why llm-guard

| Property              | NeMo Guardrails | Guardrails AI | ZenGuard | AI-Infra-Guard | **llm-guard**       |
| --------------------- | --------------- | ------------- | -------- | -------------- | ------------------- |
| Language              | Python          | Python        | cloud    | Go             | **Rust**            |
| Default latency       | 10s–100s ms     | 10s–100s ms   | RTT      | n/a            | **µs (substring); bounded ms (regex)** |
| ML required by default| yes             | yes           | yes      | yes            | **no, opt-in**      |
| Network at scan time  | sometimes       | sometimes     | always   | no             | **never**           |
| Zero-copy borrowed spans | no           | no            | no       | no             | **yes**             |
| IDN-homograph / look-alike defence | no  | no            | no       | no             | **yes (built in)**  |
| Layered deobfuscation pre-pass | no    | no            | no       | no             | **yes (built in)**  |
| Confidence + severity per hit  | partial | partial    | no       | no             | **yes (every match)** |

## Installation

```toml
[dependencies]
llm-guard = "0.2"
```

## Design

- **Strict zero-copy on the data path.** Every `Match<'a>` borrows
  from the caller's input. Patterns are `&'static str`. Clean scans
  on substring-based scanners allocate **exactly zero times in
  release mode** (proven by [`tests/zero_alloc.rs`](tests/zero_alloc.rs)).
- **`Send + Sync` scanners.** No per-request state — pattern tables
  baked in at construction. Share one instance across worker tasks.
- **No global registry.** Caller assembles the `Pipeline`. Cheap
  scanners (e.g. `TokenLimit`) should come first so `FirstHit` mode
  short-circuits early.
- **FP discipline by design.** Every match carries a `Confidence` and
  a `Severity`. Callers refuse on `should_refuse()` (true only when
  some match is `Severity::Block`); everything else is for the audit
  log. PII shapes with checksums (Luhn, IBAN mod-97) drop the match
  entirely on checksum failure rather than emitting a noisy warning.

## Defence-in-depth tiers

1. **Base (default build, in-process, sub-millisecond).** Substring,
   regex, and structural scanners listed below. This is what we
   recommend for almost everyone — it covers the textbook attacks
   (prompt-injection, role-override, secret leakage, IDN homograph,
   markdown smuggling) without paying the latency or build-time cost
   of an ML model.
2. **Fuzzy (planned, opt-in via `--features fuzzy`).** Trigram-Jaccard
   similarity against a canonical injection corpus to catch
   paraphrases. Adds ~50–200µs/scan.
3. **ML (planned, separate `llm-guard-ml` crate).** ONNX-runtime
   based, distilled int8 prompt-injection classifier for paraphrased
   and novel attacks. Adds millisecond latency — see Speed matrix
   below.

## Scanners (default build)

| Scanner                | Purpose                                                                  |
| ---------------------- | ------------------------------------------------------------------------ |
| `BanSubstrings`        | Multi-pattern substring match via Aho–Corasick (case-insensitive).       |
| `BanCode`              | Detect code-like content (fences, language prefixes, script tags).       |
| `RoleOverride`         | Chat-template marker injection (system/instruction prefixes).            |
| `Secrets`              | Regex-based credential leak detection (API keys, PEM, JWT).              |
| `PiiPatterns`          | Email, phone (E.164), IPv4/IPv6, MAC, SSN, credit card (Luhn), IBAN (mod-97). |
| `InvisibleText`        | Zero-width / bidi-override codepoints used in prompt smuggling.          |
| `ScriptMix`            | Unicode-script mixing (Cyrillic look-alikes against Latin, etc.).        |
| `UrlExtract`           | URL extraction + IDN-homograph host-label detection.                     |
| `MarkdownLinkSmuggle`  | `[visible](url)` where the visible text claims a different domain.       |
| `TemplateMarkerShape`  | Novel chat-template marker shapes beyond the fixed `RoleOverride` list.  |
| `Repetition`           | Char-flood / many-shot stuffing detection.                               |
| `Deobfuscate`          | Pre-pass that re-runs an inner scanner against normalised input (spacing collapse, leet fold, confusables fold, shape-gated base64 decode). |
| `RegexScan`            | Caller-supplied regex patterns for custom shapes.                        |
| `TokenLimit`           | Cheap character-count gate before invoking the model.                    |

Helpers:

- `sanitize::strip_controls` — replaces C0/C1 control chars with spaces,
  returns `Cow<str>` (borrowed when input is clean).
- `wrap::with_boundary` — wraps user input with defence delimiters and
  an optional warning preamble for flagged messages.

Curated pattern tables in `patterns::`:

- `COMMON_INJECTION_PATTERNS` — generic prompt-injection phrases.
- `ROLE_OVERRIDE_PATTERNS` — what `RoleOverride` uses internally.
- `IDENTITY_LEAK_MARKERS` — for output-side `BanSubstrings`.

## Usage

### Minimal input guard

```rust
use llm_guard::{
    Pipeline, PipelineMode, BanSubstrings, InvisibleText, RoleOverride, TokenLimit,
    patterns::COMMON_INJECTION_PATTERNS,
};

let input_guard = Pipeline::new(PipelineMode::FirstHit)
    .with(TokenLimit::new(8_000))
    .with(InvisibleText::new())
    .with(RoleOverride::new())
    .with(BanSubstrings::new("injection", COMMON_INJECTION_PATTERNS));

let result = input_guard.scan(user_input);
// `should_refuse()` is true only when some match has Severity::Block.
if result.should_refuse() {
    let first = result.first().unwrap();
    tracing::warn!(
        scanner = first.scanner,
        pattern = first.pattern,
        confidence = ?first.confidence,
        severity = ?first.severity,
        "input refused"
    );
    // refuse, redact, or return an error to the caller
}
```

### Output guard — collect every hit

```rust
use llm_guard::{
    Pipeline, PipelineMode, BanSubstrings, PiiPatterns, Secrets,
    patterns::IDENTITY_LEAK_MARKERS,
};

let output_guard = Pipeline::new(PipelineMode::All)
    .with(Secrets::new())
    .with(PiiPatterns::new())
    .with(BanSubstrings::new("identity_leak", IDENTITY_LEAK_MARKERS));

let result = output_guard.scan(model_response);
for m in &result.matches {
    tracing::warn!(
        scanner = m.scanner,
        pattern = m.pattern,
        confidence = ?m.confidence,
        severity = ?m.severity,
        span = ?m.span,
    );
}
```

### Deobfuscation pre-pass (catches base64, leet, spacing, confusables)

```rust
use llm_guard::{Deobfuscate, BanSubstrings, Pipeline, PipelineMode,
    patterns::COMMON_INJECTION_PATTERNS};

let guard = Pipeline::new(PipelineMode::FirstHit)
    .with(BanSubstrings::new("injection", COMMON_INJECTION_PATTERNS))
    // Deobfuscate composes ANY inner scanner. Here we re-run the
    // injection substrings table against normalised views of the
    // input - catches "1gn0re pr3v10us", "i g n o r e", and
    // base64-of-"ignore previous".
    .with(Deobfuscate::new(
        BanSubstrings::new("injection_deob", COMMON_INJECTION_PATTERNS),
    ));

let r = guard.scan("decode this: aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==");
assert!(r.should_refuse());
```

### URL + IDN-homograph

```rust
use llm_guard::{UrlExtract, Scanner};

let s = UrlExtract::new();
let r = s.scan("log in at https://раypal.com/login now");
// Emits two matches: pattern="url" (Info) and pattern="idn_homograph" (Block).
assert!(r.should_refuse());
```

### Caller-supplied regex

```rust
use llm_guard::{RegexScan, RegexPattern, Scanner, Severity, Confidence};

let scanner = RegexScan::new("internal", vec![
    RegexPattern::new("employee_id", r"\bEMP-\d{6}\b").unwrap()
        .with_severity(Severity::Block)
        .with_confidence(Confidence::High),
    RegexPattern::new("ticket_ref",  r"\bTKT-[A-Z]{3}-\d{4}\b").unwrap(),
]);
let r = scanner.scan("ticket from EMP-123456 escalated");
assert!(r.flagged());
```

See the [`examples/`](examples/) directory for runnable end-to-end usage.

## FP discipline

Every match carries:

- `confidence: Confidence` — `Low` / `Medium` / `High` — how certain
  the scanner is that this hit is a real attack/violation rather than
  benign text that happened to match the shape.
- `severity: Severity` — `Info` / `Warn` / `Block` — what the scanner
  *recommends* the caller do. `should_refuse()` is true iff some hit
  is `Block`.

| Scanner               | Default confidence | Default severity | FP discipline                                          |
| --------------------- | ------------------ | ---------------- | ------------------------------------------------------ |
| `BanSubstrings`       | Medium             | Warn             | Caller picks via `.with_severity(...)`.                |
| `BanCode`             | Medium             | Warn             | Shape-based markers; prose about code does not match.  |
| `RoleOverride`        | High               | Block            | Curated marker list, no FPs in benign prose.           |
| `Secrets`             | High (JWT: Medium) | Block            | Prefixed vendor keys nearly impossible to FP; JWT high-recall by design. |
| `PiiPatterns`         | Medium/High        | Warn/Block       | Patterns with checksums (Luhn / mod-97) **drop the match** on failed checksum rather than warning. |
| `InvisibleText`       | High               | Block            | No legitimate reason for zero-width/bidi in chat.      |
| `ScriptMix`           | Medium             | Warn             | Caller threshold; legitimate multilingual text passes. |
| `UrlExtract`          | High               | Info / Block     | URL itself is Info; IDN-homograph is Block.            |
| `MarkdownLinkSmuggle` | High               | Block            | Only flags when **both sides** look like a domain AND they disagree on registrable suffix. |
| `TemplateMarkerShape` | High               | Block            | Caller allowlist suppresses legitimate markers (`### Note:` etc). |
| `Repetition`          | High               | Block            | Caller picks `min_run`. No global default — deliberate. |
| `Deobfuscate`         | High               | Block            | Never flags on its own. Only re-fires inner scanner over normalised view; if inner doesn't match, nothing happens. |
| `TokenLimit`          | High               | Block            | Hard limit set by caller; no ambiguity.                |

## Speed matrix

Real benchmarks coming with the v0.3 ML feature. Current default-tier
numbers (Apple M2, single thread, release):

```text
                              p50      p99    notes
Base (substring scanners)     <5µs    <50µs   BanSubstrings, RoleOverride,
                                              InvisibleText, ScriptMix,
                                              Repetition, TokenLimit
Base (regex scanners)        ~20µs   ~150µs   Secrets, PiiPatterns,
                                              UrlExtract, MarkdownLinkSmuggle,
                                              TemplateMarkerShape
Deobfuscate (clean input)     <5µs    <50µs   All four shape gates skip
                                              → no normalisation path
```

Planned tiers (numbers are budgets, not measurements yet):

```text
                              p50      p99    cold-start  use case
Fuzzy (--features fuzzy)    ~150µs   ~500µs   1ms         paraphrase detection
                                                         (trigram Jaccard vs corpus)
ML (llm-guard-ml CPU x86)    3-8ms    12ms    180ms       distilled prompt-injection classifier (ONNX int8)
ML (llm-guard-ml CPU arm64)  4-10ms   16ms    220ms       same model on Apple Silicon / aarch64 Linux
ML (llm-guard-ml CUDA)     ~400µs   ~1.2ms    900ms       same model with CUDA execution provider
```

The headline contract: **the default build will never get slower than
sub-ms per scan**. If you add ML you sign up for ms-range latency in
exchange for paraphrase / novel-attack coverage; the choice is yours.

## Adding a scanner

Implement the `Scanner` trait:

```rust
use llm_guard::{Match, ScanResult, Scanner, Confidence, Severity};

struct MyScanner;

impl Scanner for MyScanner {
    fn name(&self) -> &'static str { "my_scanner" }

    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        // return ScanResult::default() for no hits
        // matches must borrow from `input`
        ScanResult::default()
    }
}
```

Wire it into a `Pipeline` at the call site. There is no global
registry — the integration layer owns the assembly.

## Status

Library is unit-tested (107 unit tests + 13 alloc-contract tests = 120
tests) and clippy-clean under `#![warn(clippy::pedantic)]`. CI builds
and tests on Linux/macOS/Windows across x86_64 and aarch64. The strict
zero-copy contract is enforced by `tests/zero_alloc.rs` (release mode).

## License

MIT OR Apache-2.0
