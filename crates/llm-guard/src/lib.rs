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

/// How confident the scanner is that this hit represents a real attack
/// or violation rather than benign text that happened to match the
/// scanner's shape. Used by callers to set a refusal threshold without
/// having to know each scanner's individual false-positive profile.
///
/// - `High`: shape is structural and rarely appears in benign text
///   (chat-template markers, valid Luhn-checked card numbers, PEM
///   private-key headers).
/// - `Medium`: shape is distinctive but can occur in legitimate text
///   (e.g. a phone-number-shaped string, a known injection phrase that
///   could also appear in a security blog post).
/// - `Low`: heuristic / fuzzy match - prefer to log rather than refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Confidence {
    Low = 0,
    Medium = 1,
    High = 2,
}

/// What action the scanner *recommends* on this hit. The library never
/// enforces - the caller decides - but having the recommendation on
/// every `Match` means callers can configure a single policy
/// ("refuse on Block, otherwise log") instead of per-scanner branching.
///
/// - `Info`: noteworthy but harmless on its own (e.g. a URL was
///   extracted; the caller may want to log or annotate).
/// - `Warn`: suspicious - log loudly, consider wrapping the input with
///   a defensive preamble via [`wrap::with_boundary`].
/// - `Block`: high-confidence attack signal - refuse the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Warn = 1,
    Block = 2,
}

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
    /// Scanner's confidence in this hit. See [`Confidence`].
    pub confidence: Confidence,
    /// Scanner's recommended action. See [`Severity`].
    pub severity: Severity,
    /// True iff the scanner fired on a *decoded* / *normalised* view
    /// of `text` rather than the literal byte content (e.g. a
    /// base64-decoded inner payload matched an injection phrase, or
    /// the input was deobfuscated to ASCII before matching). The
    /// `span` still points at the **encoded** bytes in the original
    /// input - this is the zero-copy contract.
    pub decoded: bool,
}

impl<'a> Match<'a> {
    /// Convenience constructor used by every built-in scanner.
    /// `decoded` defaults to `false`; the Deobfuscate scanner flips it
    /// via [`Self::with_decoded`].
    #[must_use]
    pub fn new(
        scanner: &'static str,
        pattern: &'static str,
        span: Range<usize>,
        text: &'a str,
        confidence: Confidence,
        severity: Severity,
    ) -> Self {
        Self {
            scanner,
            pattern,
            span,
            text,
            confidence,
            severity,
            decoded: false,
        }
    }

    /// Set the `decoded` flag (used by [`crate::scanners::Deobfuscate`]).
    #[must_use]
    pub fn with_decoded(mut self, decoded: bool) -> Self {
        self.decoded = decoded;
        self
    }
}

/// Outcome of a single scanner run. Matches borrow from the original
/// input; the result struct itself is the only allocation, and only
/// when there's at least one hit.
#[derive(Debug, Clone, Default)]
pub struct ScanResult<'a> {
    pub matches: Vec<Match<'a>>,
}

impl<'a> ScanResult<'a> {
    /// True iff at least one match was recorded. Matches
    /// pre-0.2 behavior - any scanner hit, regardless of severity.
    /// For severity-aware refusal logic prefer [`Self::should_refuse`].
    #[must_use]
    pub fn flagged(&self) -> bool {
        !self.matches.is_empty()
    }

    /// True iff at least one match has [`Severity::Block`]. This is
    /// the recommended refusal predicate - it lets callers wire a
    /// single policy ("refuse on Block, otherwise log and proceed")
    /// instead of branching per scanner.
    #[must_use]
    pub fn should_refuse(&self) -> bool {
        self.matches.iter().any(|m| m.severity == Severity::Block)
    }

    /// Highest severity across all matches, or `None` if clean.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.matches.iter().map(|m| m.severity).max()
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

// Ordering for `max_severity()` - `Info < Warn < Block`.
impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}
impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
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
// New 0.2.0 scanners - re-exported as each module lands.
pub use scanners::{
    Deobfuscate, MarkdownLinkSmuggle, PiiPatterns, Repetition, TemplateMarkerShape, UrlExtract,
};
// Opt-in fuzzy paraphrase matcher (--features fuzzy).
#[cfg(feature = "fuzzy")]
pub use scanners::FuzzyMatch;
