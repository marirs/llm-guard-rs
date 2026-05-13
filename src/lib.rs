//! llm-guard - zero-copy scanners for LLM input/output.
//!
//! Pure-Rust port of the scanners we actually use from upstream's
//! Python llm-guard. Every scanner takes a `&str` and returns
//! [`ScanResult<'a>`] whose [`Match`] entries are *borrowed* slices
//! of the original input - no allocation, no lower-casing,
//! no copying. Patterns themselves are `&'static str`, so a clean
//! scan is allocation-free end-to-end.
//!
//! ## Layout
//!
//! - [`Scanner`] - the trait every scanner implements.
//! - [`Pipeline`] - runs a list of scanners in order, short-circuits
//!   on the first hit (or collects all, depending on mode).
//! - [`sanitize`] - control-char stripping, returns `Cow<str>`
//!   (borrowed when input is already clean).
//! - [`scanners`] - concrete scanner impls (`BanSubstrings`,
//!   `Secrets`, `InvisibleText`, `TokenLimit`, `RoleOverride`,
//!   `RegexScan`, `BanCode`, `ScriptMix`).
//! - [`patterns`] - curated `&'static [&'static str]` lists for the
//!   common prompt-injection / identity-leak cases, ready to plug
//!   into a `BanSubstrings`.
//! - [`wrap`] - defence-boundary helper for splicing user input into
//!   a chat-template turn.
//!
//! ## Why this exists
//!
//! Upstream llm-guard is Python + pandas + transformers - too heavy
//! to depend on from a Rust web server, and pulls in an ML stack we
//! don't have a runtime for. This crate keeps the scanner *names* and
//! *intent* familiar so the integration in `crates/safety` reads
//! like the upstream docs, but the implementations are minimal,
//! deterministic, and pure-regex / pure-substring. No ML, no calls
//! out.
//!
//! Adding a new scanner: implement [`Scanner`], wire it into
//! [`Pipeline`] at the call site. There is no global registry - the
//! integration layer is responsible for assembling the pipeline it
//! wants.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::ops::Range;

pub mod patterns;
pub mod sanitize;
pub mod scanners;
pub mod wrap;

/// A single scanner hit. Spans are byte offsets into the original
/// input; `text` is `&input[span]` so callers can render it directly
/// without re-slicing.
#[derive(Debug, Clone)]
pub struct Match<'a> {
    /// Identifier of the scanner that produced the match
    /// (e.g. `"ban_substrings"`, `"secrets"`).
    pub scanner: &'static str,
    /// Identifier of the specific pattern within the scanner that
    /// matched. For `BanSubstrings` this is the substring itself.
    /// For `Secrets` it's the credential class (e.g. `"openai_key"`).
    pub pattern: &'static str,
    /// Byte range within the original input. Always valid UTF-8
    /// boundaries (we match on char boundaries throughout).
    pub span: Range<usize>,
    /// `&input[span]` - borrowed from the caller's input.
    pub text: &'a str,
}

/// Outcome of a single scanner run. Matches borrow from the original
/// input; the result struct itself is the only allocation, and only
/// when there's at least one hit.
#[derive(Debug, Clone, Default)]
pub struct ScanResult<'a> {
    pub matches: Vec<Match<'a>>,
}

impl<'a> ScanResult<'a> {
    /// True iff at least one match was recorded.
    #[must_use]
    pub fn flagged(&self) -> bool {
        !self.matches.is_empty()
    }

    /// First match, if any - convenient for callers that only care
    /// about *whether* something hit and which pattern was the
    /// trigger (audit logging).
    #[must_use]
    pub fn first(&self) -> Option<&Match<'a>> {
        self.matches.first()
    }

    /// Merge another result's matches into this one. Used by
    /// [`Pipeline`] to accumulate across scanners.
    pub fn extend(&mut self, other: ScanResult<'a>) {
        self.matches.extend(other.matches);
    }
}

/// Implemented by every scanner. Scanners must be `Send + Sync` so a
/// single instance can be shared across worker tasks; they hold no
/// per-request state (the pattern tables are baked in at
/// construction time).
pub trait Scanner: Send + Sync {
    /// Stable identifier, used as `Match::scanner`.
    fn name(&self) -> &'static str;

    /// Scan `input` and return any matches. Returned `Match` entries
    /// borrow from `input`; the result lives no longer than the
    /// caller's borrow of the input string.
    fn scan<'a>(&self, input: &'a str) -> ScanResult<'a>;
}

/// How a [`Pipeline`] handles its scanner list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineMode {
    /// Run every scanner and collect all matches. Useful when the
    /// caller wants the full audit picture (e.g. output filtering
    /// where we want to log every leak marker the model produced).
    All,
    /// Stop at the first scanner that flags. Useful when one hit is
    /// enough to refuse the request - saves work on long input
    /// strings that already failed the first cheap scanner.
    FirstHit,
}

/// Ordered list of scanners. Cheap scanners (e.g. `TokenLimit`)
/// should come first; expensive ones (regex with many patterns)
/// later, so `FirstHit` short-circuits well.
pub struct Pipeline {
    scanners: Vec<Box<dyn Scanner>>,
    mode: PipelineMode,
}

impl Pipeline {
    #[must_use]
    pub fn new(mode: PipelineMode) -> Self {
        Self {
            scanners: Vec::new(),
            mode,
        }
    }

    #[must_use]
    pub fn with(mut self, scanner: impl Scanner + 'static) -> Self {
        self.scanners.push(Box::new(scanner));
        self
    }

    /// Run the pipeline over `input`. Matches borrow from `input`.
    #[must_use]
    pub fn scan<'a>(&self, input: &'a str) -> ScanResult<'a> {
        let mut out = ScanResult::default();
        for s in &self.scanners {
            let r = s.scan(input);
            let was_empty = r.matches.is_empty();
            out.extend(r);
            if !was_empty && self.mode == PipelineMode::FirstHit {
                break;
            }
        }
        out
    }
}

pub use sanitize::strip_controls;
pub use scanners::{
    BanCode, BanSubstrings, InvisibleText, RegexPattern, RegexScan, RoleOverride, ScriptMix,
    Secrets, TokenLimit,
};
