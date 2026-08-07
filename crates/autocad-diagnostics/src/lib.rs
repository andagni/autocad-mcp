//! Shared coded-error primitive for AutoCAD-MCP's diagnostic surface.
//!
//! `autocad-reader`, `autocad-writer`, and `autocad-mcp` each define their own
//! domain-specific failure codes (xref failures, layer failures, write
//! failures, ...), but every one of them wants the exact same *shape*: a
//! short machine-matchable `code`, a human-readable `message`, and a
//! `Display` impl that renders `code=<code> <message>` for the MCP tool
//! output the client actually sees.
//!
//! Before this crate existed, that shape was hand-copied into ~19 separate
//! structs across the workspace, and the copies had already drifted: some
//! exposed a `message()` accessor for safe re-wrapping into another coded
//! error, some didn't (which reproduces the double `code=` prefix bug fixed
//! in `e4ee102` for `XrefError`, just for a different struct); some stored
//! `code` as `&'static str`, some as `String` because a couple of call sites
//! (layer mutation errors parsed back out of an embedded AutoLISP script's
//! own `RESULT:ERROR:<code>:<message>` output) generate the code at runtime
//! rather than knowing it at compile time.
//!
//! [`DomainError`] is the one shape now: `code` is `Cow<'static, str>` so
//! both the compile-time-literal case and the parsed-at-runtime case use the
//! same type without allocating in the common case, and `message()` is
//! always available so wrapping one `DomainError` inside another can never
//! silently double the prefix again.
//!
//! Domains that need extra fields beyond code+message (e.g. a `kind` enum
//! for programmatic dispatch, or a `installation_may_have_occurred` flag)
//! compose a `DomainError` in rather than duplicating this shape.

use std::borrow::Cow;
use std::fmt;

/// A coded, human-readable domain error shared by every AutoCAD-MCP crate's
/// diagnostic surface.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainError {
    code: Cow<'static, str>,
    message: String,
}

impl DomainError {
    pub fn new(code: impl Into<Cow<'static, str>>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// The machine-matchable failure code, e.g. `"xref_source_not_found"`.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The raw message, without the `code=<code> ` prefix `Display` adds.
    ///
    /// Callers that re-wrap a `DomainError` into another error type carrying
    /// its own `code` (whether that's another `DomainError` or a struct that
    /// composes one) should use this rather than `to_string()`/`Display`,
    /// which would otherwise bake a second, redundant `code=<code>` into the
    /// new error's detail text.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code={} {}", self.code, self.message)
    }
}

impl std::error::Error for DomainError {}

/// Declares a domain-specific newtype over [`DomainError`].
///
/// A newtype (not a `type` alias) so each domain keeps its own nominal type —
/// callers can't accidentally mix a `LayerError` where an `XrefError` is
/// expected, trait impls elsewhere targeting the domain type stay legal
/// under the orphan rule, and constructor visibility (`new_vis`) can be
/// restricted independently of the struct's own visibility, exactly as the
/// hand-written versions of these types did before consolidation.
///
/// Generates `new`, `code()`, `message()`, `Display` (`"code=<code>
/// <message>"`), and `std::error::Error`. `message()` is the raw text
/// without the `code=<code> ` prefix `Display` adds — always use it, never
/// `to_string()`, when folding one of these errors into another's message;
/// otherwise the prefix doubles up.
#[macro_export]
macro_rules! domain_error {
    ($(#[$meta:meta])* $vis:vis struct $name:ident, new = $new_vis:vis) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        $vis struct $name($crate::DomainError);

        impl $name {
            $new_vis fn new(
                code: impl Into<::std::borrow::Cow<'static, str>>,
                message: impl Into<String>,
            ) -> Self {
                Self($crate::DomainError::new(code, message))
            }

            #[allow(dead_code)]
            pub fn code(&self) -> &str {
                self.0.code()
            }

            #[allow(dead_code)]
            pub fn message(&self) -> &str {
                self.0.message()
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::std::error::Error for $name {}
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_matches_the_shared_code_equals_message_shape() {
        let error = DomainError::new("xref_not_found", "no XREF matched the given selector");
        assert_eq!(
            error.to_string(),
            "code=xref_not_found no XREF matched the given selector"
        );
    }

    #[test]
    fn message_omits_the_code_prefix_so_rewrapping_cannot_double_it() {
        let error = DomainError::new("xref_not_found", "no XREF matched the given selector");
        assert_eq!(error.message(), "no XREF matched the given selector");

        let wrapped = DomainError::new("mutation_failed", error.message());
        assert_eq!(
            wrapped.to_string(),
            "code=mutation_failed no XREF matched the given selector"
        );
    }

    #[test]
    fn accepts_both_static_and_runtime_codes() {
        let static_code = DomainError::new("layer_not_found", "layer not found");
        assert_eq!(static_code.code(), "layer_not_found");

        let runtime_code: String = "layer_has_content".to_string();
        let dynamic_code = DomainError::new(runtime_code, "layer has content");
        assert_eq!(dynamic_code.code(), "layer_has_content");
    }

    domain_error!(
        /// A stand-in domain error, exercised only by this crate's own tests.
        pub struct ExampleError, new = pub(crate)
    );

    #[test]
    fn generated_newtype_matches_domain_error_shape_and_serializes_transparently() {
        let error = ExampleError::new("example_failed", "something went wrong");
        assert_eq!(error.code(), "example_failed");
        assert_eq!(error.message(), "something went wrong");
        assert_eq!(
            error.to_string(),
            "code=example_failed something went wrong"
        );

        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(
            json,
            r#"{"code":"example_failed","message":"something went wrong"}"#
        );
    }
}
