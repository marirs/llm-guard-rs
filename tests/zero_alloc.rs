// The library itself is `#![forbid(unsafe_code)]`. The counting
// allocator below needs `unsafe` because `GlobalAlloc` requires it -
// `#![allow(unsafe_code)]` opts this single test file out. Production
// code paths still have the harder guarantee.
#![allow(unsafe_code)]

//! Strict zero-copy / bounded-allocation contract test.
//!
//! Wraps the global allocator in a counter and asserts each scanner's
//! actual allocation behaviour on a clean (no-hit) input.
//!
//! ## Why two tiers (Strict vs Bounded)
//!
//! - **Strict zero**: scanners that don't depend on the `regex` crate
//!   for the hot path - they do one byte-level pass over the input
//!   and emit a `Vec<Match>` (which is `Vec::new()` and so does not
//!   allocate when empty). These MUST allocate exactly 0 times in
//!   steady state. A regression here is a bug in our code.
//!
//! - **Bounded**: scanners that use `regex::Regex::find_iter` /
//!   `captures_iter`. The `regex` crate maintains a per-thread
//!   pool of matcher state; each `find_iter` call acquires a `Pool`
//!   guard, which is a small constant-size allocation. We can't
//!   avoid that without forking the regex crate. The contract for
//!   these scanners is: **per-call alloc is bounded and does not
//!   grow with input length or call count** - which is what real-
//!   world latency depends on.
//!
//! ## Why release-only
//!
//! Debug builds add capacity-tracking and panic strings on slice
//! indexing that disappear under `opt-level >= 1`. The tests are
//! gated to release-mode runs - in debug they no-op so `cargo test`
//! stays green for fast iteration.
//!
//! Run with: `cargo test --release --test zero_alloc -- --test-threads=1`
//! (single-threaded because the per-thread regex pool gets fresh
//!  state per test thread and pollutes the warm-up).
//!
//! ## What this catches
//!
//! - A future refactor adding a hidden `String::new()` / `format!()`
//!   on a clean-scan path.
//! - A new scanner that allocates per-input-byte (linear-in-input
//!   alloc - the bounded test would catch the growth).
//!
//! ## What this doesn't catch
//!
//! - Allocation on hits (intended - the `Vec<Match>` push is unavoidable
//!   and not in scope of "zero copy on clean scan").
//! - `Scanner::new` construction cost (one-shot, fine to allocate).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(feature = "fuzzy")]
use llm_guard::FuzzyMatch;
use llm_guard::{
    BanCode, BanSubstrings, Deobfuscate, InvisibleText, MarkdownLinkSmuggle, PiiPatterns,
    Repetition, RoleOverride, Scanner, ScriptMix, Secrets, TemplateMarkerShape, TokenLimit,
    UrlExtract, patterns::COMMON_INJECTION_PATTERNS,
};

struct CountingAllocator {
    counting: AtomicBool,
    allocs: AtomicUsize,
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if self.counting.load(Ordering::Relaxed) {
            self.allocs.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAllocator = CountingAllocator {
    counting: AtomicBool::new(false),
    allocs: AtomicUsize::new(0),
};

fn count_allocs<F: FnOnce()>(f: F) -> usize {
    A.allocs.store(0, Ordering::Relaxed);
    A.counting.store(true, Ordering::Relaxed);
    f();
    A.counting.store(false, Ordering::Relaxed);
    A.allocs.load(Ordering::Relaxed)
}

/// Plain text that should not trigger ANY scanner.
const CLEAN: &str = "Help me draft a status update for the engineering review next Thursday.";

/// Long but still no-hit input - used to verify the bounded
/// scanners' alloc count does NOT grow linearly with input size.
fn long_clean() -> String {
    "ordinary words and prose without any flagged shapes inside it. ".repeat(50)
}

const WARMUP: usize = 5;
const STEADY: usize = 10;

/// STRICT contract: every steady-state clean scan must allocate
/// exactly zero times. Use only for scanners that don't depend on
/// `regex` for the hot path.
fn assert_strict_zero<S: Scanner>(scanner: &S, input: &str, label: &str) {
    if !cfg!(debug_assertions) {
        // Release mode: enforce the real contract.
        for _ in 0..WARMUP {
            let _ = scanner.scan(input);
        }
        let allocs = count_allocs(|| {
            for _ in 0..STEADY {
                let _ = scanner.scan(input);
            }
        });
        assert_eq!(
            allocs, 0,
            "{label}: {STEADY} steady clean scans allocated {allocs} times (want 0)"
        );
    }
    // Debug mode: the contract is for release only - debug builds add
    // capacity-tracking that we don't care about.
}

/// Allowance per call for bounded scanners - upstream regex pool
/// overhead. If a future refactor pushed us above this we'd want
/// to know.
const MAX_PER_CALL: usize = 20;

/// BOUNDED contract: alloc per call must be bounded by [`MAX_PER_CALL`]
/// regardless of input length. This rules out any "per byte" or
/// "per pattern" allocation pattern in our code - what's left is
/// just the upstream regex pool overhead.
fn assert_bounded<S: Scanner>(scanner: &S, label: &str) {
    if !cfg!(debug_assertions) {
        let short = CLEAN;
        let long = long_clean();
        // Warm up on both lengths so any cache stabilises.
        for _ in 0..WARMUP {
            let _ = scanner.scan(short);
            let _ = scanner.scan(&long);
        }
        let short_allocs = count_allocs(|| {
            for _ in 0..STEADY {
                let _ = scanner.scan(short);
            }
        });
        let long_allocs = count_allocs(|| {
            for _ in 0..STEADY {
                let _ = scanner.scan(&long);
            }
        });
        let short_per_call = short_allocs / STEADY;
        let long_per_call = long_allocs / STEADY;
        assert!(
            short_per_call <= MAX_PER_CALL,
            "{label}: short input allocated {short_per_call}/call (cap {MAX_PER_CALL})"
        );
        assert!(
            long_per_call <= MAX_PER_CALL,
            "{label}: long input allocated {long_per_call}/call (cap {MAX_PER_CALL})"
        );
        // Per-call allocation must not grow with input size. We
        // allow long inputs to allocate at most 2x the short input
        // path (different code branches can take slightly different
        // pool paths) - but NOT linearly with input length.
        assert!(
            long_per_call <= short_per_call.saturating_mul(2).max(2),
            "{label}: long input ({long_per_call}/call) allocates more than 2x short ({short_per_call}/call) - possible linear-in-input alloc"
        );
    }
}

// ---- Strict-zero scanners (no `regex` on hot path) -----------------

#[test]
fn ban_substrings_clean_strict_zero() {
    let s = BanSubstrings::new("inj", COMMON_INJECTION_PATTERNS);
    assert_strict_zero(&s, CLEAN, "BanSubstrings");
}

#[test]
fn ban_code_clean_strict_zero() {
    let s = BanCode::new();
    assert_strict_zero(&s, CLEAN, "BanCode");
}

#[test]
fn role_override_clean_strict_zero() {
    let s = RoleOverride::new();
    assert_strict_zero(&s, CLEAN, "RoleOverride");
}

#[test]
fn invisible_text_clean_strict_zero() {
    let s = InvisibleText::new();
    assert_strict_zero(&s, CLEAN, "InvisibleText");
}

#[test]
fn script_mix_clean_strict_zero() {
    let s = ScriptMix::new(0);
    assert_strict_zero(&s, CLEAN, "ScriptMix");
}

#[test]
fn token_limit_clean_strict_zero() {
    let s = TokenLimit::new(10_000);
    assert_strict_zero(&s, CLEAN, "TokenLimit");
}

#[test]
fn repetition_clean_strict_zero() {
    let s = Repetition::new(200);
    assert_strict_zero(&s, CLEAN, "Repetition");
}

#[test]
fn deobfuscate_clean_strict_zero() {
    // Clean input has no leet, no spacing trick, no non-ASCII, no
    // base64-shaped run - all 4 shape gates reject and we never
    // enter a normalisation path. The wrapped BanSubstrings inner
    // scanner is never invoked.
    let s = Deobfuscate::new(BanSubstrings::new("inj", COMMON_INJECTION_PATTERNS));
    assert_strict_zero(&s, CLEAN, "Deobfuscate");
}

// ---- Bounded-alloc scanners (regex on hot path) --------------------

#[test]
fn secrets_clean_bounded() {
    let s = Secrets::new();
    assert_bounded(&s, "Secrets");
}

#[test]
fn pii_patterns_clean_bounded() {
    let s = PiiPatterns::new();
    assert_bounded(&s, "PiiPatterns");
}

#[test]
fn url_extract_clean_bounded() {
    let s = UrlExtract::new();
    assert_bounded(&s, "UrlExtract");
}

#[test]
fn markdown_link_smuggle_clean_bounded() {
    let s = MarkdownLinkSmuggle::new();
    assert_bounded(&s, "MarkdownLinkSmuggle");
}

#[test]
fn template_marker_shape_clean_bounded() {
    let s = TemplateMarkerShape::new();
    assert_bounded(&s, "TemplateMarkerShape");
}

// ---- Fuzzy scanner alloc contract (--features fuzzy) --------------

/// `FuzzyMatch` allocates the normalised input `String` + the trigram
/// `HashSet` (which may rehash once or twice as it grows). Cap at
/// [`FUZZY_MAX_PER_CALL`] - well above the expected ~3-5, well below
/// any pathological per-pattern alloc.
#[cfg(feature = "fuzzy")]
const FUZZY_MAX_PER_CALL: usize = 10;

/// `FuzzyMatch` builds an input-side trigram `HashSet` per call;
/// that's unavoidable. The contract we enforce is: per-call alloc
/// count is bounded by a small multiple and does not grow
/// worse-than-linearly with input length. A naive implementation
/// that allocated per canonical phrase would fail this; a naive
/// implementation that rebuilt the corpus trigrams per scan would
/// also fail this.
#[cfg(feature = "fuzzy")]
#[test]
fn fuzzy_match_clean_bounded() {
    let s = FuzzyMatch::new();
    if !cfg!(debug_assertions) {
        let short = CLEAN;
        let long = long_clean();
        for _ in 0..WARMUP {
            let _ = s.scan(short);
            let _ = s.scan(&long);
        }
        let short_allocs = count_allocs(|| {
            for _ in 0..STEADY {
                let _ = s.scan(short);
            }
        });
        let long_allocs = count_allocs(|| {
            for _ in 0..STEADY {
                let _ = s.scan(&long);
            }
        });
        let short_per_call = short_allocs / STEADY;
        let long_per_call = long_allocs / STEADY;
        assert!(
            short_per_call <= FUZZY_MAX_PER_CALL,
            "FuzzyMatch short: {short_per_call}/call (cap {FUZZY_MAX_PER_CALL})"
        );
        assert!(
            long_per_call <= FUZZY_MAX_PER_CALL,
            "FuzzyMatch long: {long_per_call}/call (cap {FUZZY_MAX_PER_CALL})"
        );
    }
}
