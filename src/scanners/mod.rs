//! Concrete scanner implementations. Each module is independent and
//! optional - the integration layer picks which scanners go into its
//! [`crate::Pipeline`].

pub mod ban_code;
pub mod ban_substrings;
pub mod deobfuscate;
pub mod invisible_text;
pub mod markdown_link_smuggle;
pub mod pii_patterns;
pub mod regex;
pub mod repetition;
pub mod role_override;
pub mod script_mix;
pub mod secrets;
pub mod template_marker_shape;
pub mod token_limit;
pub mod url_extract;

pub use ban_code::BanCode;
pub use ban_substrings::BanSubstrings;
pub use deobfuscate::Deobfuscate;
pub use invisible_text::InvisibleText;
pub use markdown_link_smuggle::MarkdownLinkSmuggle;
pub use pii_patterns::PiiPatterns;
pub use regex::{RegexPattern, RegexScan};
pub use repetition::Repetition;
pub use role_override::RoleOverride;
pub use script_mix::ScriptMix;
pub use secrets::Secrets;
pub use template_marker_shape::TemplateMarkerShape;
pub use token_limit::TokenLimit;
pub use url_extract::UrlExtract;
