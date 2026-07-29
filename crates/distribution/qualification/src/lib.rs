//! Closed, mode-neutral primitives for authenticated JSON statements.
//!
//! This crate intentionally knows nothing about product versions, package
//! modes, evidence classes, or activation policy. Domain crates define those
//! statement contracts and use this crate only for strict parsing,
//! canonicalization, key admission, signing, and verification.

mod canonical;
mod envelope;
mod finite;
mod keyring;
mod strict_json;

pub use envelope::{
    parse_and_verify, SignatureAlgorithm, StatementContract, VerifiedStatement,
    SIGNED_ENVELOPE_SCHEMA_VERSION,
};
#[cfg(feature = "signing")]
pub use envelope::{sign_canonical, SigningKey};
pub use keyring::{KeyRing, KeyState, PinnedKey};
pub use strict_json::parse_strict_json;

use std::fmt;

/// Stable failure categories for fail-closed callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    JsonInvalid,
    JsonTrailingData,
    JsonNotIJson,
    JsonNotCanonical,
    CanonicalizationFailed,
    EnvelopeSchemaInvalid,
    EnvelopeVersionUnsupported,
    EnvelopeKindMismatch,
    ContractInvalid,
    StatementNotObject,
    StatementInvalid,
    IdentifierInvalid,
    SignatureEncodingInvalid,
    SignatureInvalid,
    KeyRingEmpty,
    KeyRingNotSorted,
    KeyDuplicate,
    KeyMaterialDuplicate,
    PublicKeyInvalid,
    PublicKeyWeak,
    KeyUnknown,
    KeyKindMismatch,
    KeyRevoked,
    SigningKeyNotActive,
    SigningKeyMismatch,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonInvalid => "json_invalid",
            Self::JsonTrailingData => "json_trailing_data",
            Self::JsonNotIJson => "json_not_i_json",
            Self::JsonNotCanonical => "json_not_canonical",
            Self::CanonicalizationFailed => "canonicalization_failed",
            Self::EnvelopeSchemaInvalid => "envelope_schema_invalid",
            Self::EnvelopeVersionUnsupported => "envelope_version_unsupported",
            Self::EnvelopeKindMismatch => "envelope_kind_mismatch",
            Self::ContractInvalid => "contract_invalid",
            Self::StatementNotObject => "statement_not_object",
            Self::StatementInvalid => "statement_invalid",
            Self::IdentifierInvalid => "identifier_invalid",
            Self::SignatureEncodingInvalid => "signature_encoding_invalid",
            Self::SignatureInvalid => "signature_invalid",
            Self::KeyRingEmpty => "key_ring_empty",
            Self::KeyRingNotSorted => "key_ring_not_sorted",
            Self::KeyDuplicate => "key_duplicate",
            Self::KeyMaterialDuplicate => "key_material_duplicate",
            Self::PublicKeyInvalid => "public_key_invalid",
            Self::PublicKeyWeak => "public_key_weak",
            Self::KeyUnknown => "key_unknown",
            Self::KeyKindMismatch => "key_kind_mismatch",
            Self::KeyRevoked => "key_revoked",
            Self::SigningKeyNotActive => "signing_key_not_active",
            Self::SigningKeyMismatch => "signing_key_mismatch",
        }
    }
}

/// One bounded, non-secret validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustError {
    code: ErrorCode,
    detail: &'static str,
}

impl TrustError {
    pub(crate) const fn new(code: ErrorCode, detail: &'static str) -> Self {
        Self { code, detail }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for TrustError {}
