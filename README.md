# llm-guard

Zero-copy guardrails for LLM input/output. Pure-Rust port of selected
scanners from the upstream Python [llm-guard](https://github.com/protectai/llm-guard)
— no Python, no ML runtime, no network calls.

## Why

Upstream `llm-guard` is Python + pandas + transformers — too heavy
to depend on from a Rust web server. This crate keeps the scanner
*names* and *intent* familiar so the integration call site reads like
the upstream docs, but the implementations are minimal, deterministic,
and pure-regex / pure-substring.

## Design

- **Zero-copy.** Every `Match<'a>` borrows from the caller's input.
  Patterns are `&'static str`. The only allocation on a hit is the
  `Vec<Match>` itself; a clean scan is allocation-free end-to-end.
- **`Send + Sync` scanners.** Scanners hold no per-request state —
  pattern tables are baked in at construction. Share one instance
  across worker tasks.
- **No global registry.** The caller assembles the `Pipeline` it
  wants. Cheap scanners (e.g. `TokenLimit`) should come first so
  `FirstHit` mode short-circuits early.

## Scanners

| Scanner         | Purpose                                                              |
| --------------- | -------------------------------------------------------------------- |
| `BanSubstrings` | Multi-pattern substring match via Aho–Corasick (case-insensitive).   |
| `RoleOverride`  | Chat-template marker injection (system/instruction prefixes).        |
| `Secrets`       | Regex-based credential leak detection (API keys, PEM, JWT).          |
| `InvisibleText` | Zero-width / bidi-override codepoints used in prompt smuggling.      |
| `TokenLimit`    | Cheap character-count gate before invoking the model.                |

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

```rust
use llm_guard::{Pipeline, PipelineMode, BanSubstrings, Secrets, InvisibleText, TokenLimit};

const INJECTION_PATTERNS: &[&str] = &[
    "ignore previous instructions",
    "developer mode",
    "system:",
];

let pipeline = Pipeline::new(PipelineMode::FirstHit)
    .with(TokenLimit::new(8_000))
    .with(InvisibleText::new())
    .with(BanSubstrings::new("injection", INJECTION_PATTERNS))
    .with(Secrets::new());

let result = pipeline.scan(user_input);
if result.flagged() {
    let first = result.first().unwrap();
    tracing::warn!(
        scanner = first.scanner,
        pattern = first.pattern,
        "input refused"
    );
    // refuse, redact, or return an error to the caller
}
```

`PipelineMode::All` collects every match across every scanner —
useful for output filtering where you want the full audit picture.
`PipelineMode::FirstHit` stops at the first scanner that flags.

## Adding a scanner

Implement the `Scanner` trait:

```rust
use llm_guard::{Match, ScanResult, Scanner};

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

Library is unit-tested (25 tests) and clippy-clean under
`#![warn(clippy::pedantic)]`. Not yet wired into a host crate.

## License

MIT OR Apache-2.0
