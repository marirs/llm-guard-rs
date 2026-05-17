//! Input normalisation helpers. All return [`Cow<'_, str>`]: when the
//! input is already clean, the caller gets the original `&str` back
//! with no allocation. Only when a mutation is actually needed do we
//! materialise a `String`.

use std::borrow::Cow;

/// Replace C0 / C1 control characters with a single ASCII space.
/// `\n`, `\r`, `\t` are preserved - whitespace is meaningful to both
/// the LLM and the rendering layer.
///
/// Returns [`Cow::Borrowed`] (no allocation) when the input has no
/// stray control characters. The common case in a chat surface is
/// clean text, so most calls pay only the scan cost.
#[must_use]
pub fn strip_controls(input: &str) -> Cow<'_, str> {
    // Fast path: scan once. If we don't find anything to replace,
    // hand back the original slice unchanged. The byte-level scan
    // is cheaper than allocating a `String` and char-by-char copying
    // for the typical "clean input" case.
    let first_bad = input.char_indices().find(|(_, c)| is_strippable(*c));
    let Some((start, _)) = first_bad else {
        return Cow::Borrowed(input);
    };

    // Slow path: copy the prefix that was already clean, then walk
    // the rest replacing as we go. Pre-allocates the worst-case
    // capacity so the build doesn't repeatedly grow.
    let mut out = String::with_capacity(input.len());
    out.push_str(&input[..start]);
    for c in input[start..].chars() {
        if is_strippable(c) {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn is_strippable(c: char) -> bool {
    c.is_control() && c != '\n' && c != '\r' && c != '\t'
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn clean_input_returns_borrowed() {
        let s = "I want to explore what came up.";
        let out = strip_controls(s);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, s);
    }

    #[test]
    fn whitespace_is_preserved() {
        let s = "hello\nworld\ttab\rreturn";
        let out = strip_controls(s);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, s);
    }

    #[test]
    fn control_chars_replaced_with_space() {
        let s = "hello\x00world\x07!";
        let out = strip_controls(s);
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(&*out, "hello world !");
    }

    #[test]
    fn preserves_unicode_outside_controls() {
        let s = "naïve résumé - emoji 🌱";
        let out = strip_controls(s);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, s);
    }

    #[test]
    fn does_not_corrupt_multibyte_at_strip_boundary() {
        // U+0007 (BEL, one byte) directly adjacent to a 3-byte char.
        let s = "ok\x07é";
        let out = strip_controls(s);
        assert_eq!(&*out, "ok é");
    }
}
