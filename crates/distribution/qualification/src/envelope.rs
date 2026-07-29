#[cfg(any(test, feature = "signing"))]
use crate::canonical::to_i_json_value;
use crate::canonical::{canonicalize, require_canonical_json};
use crate::keyring::require_identifier;
#[cfg(any(test, feature = "signing"))]
use crate::PinnedKey;
use crate::{ErrorCode, KeyRing, KeyState, TrustError};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(feature = "signing")]
use ed25519_dalek::Signer;
#[cfg(feature = "signing")]
pub use ed25519_dalek::SigningKey;

pub const SIGNED_ENVELOPE_SCHEMA_VERSION: u32 = 1;

const MESSAGE_PREFIX: &[u8] = b"autocad-mcp.canonical-signed-json-envelope.v1\0";
const MAX_DOMAIN_BYTES: usize = 255;

/// The only signature algorithm accepted by schema version 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

/// A domain-owned closed statement contract.
///
/// `KIND` appears inside the signed envelope. `SIGNING_DOMAIN` is not
/// serialized; it prevents a valid envelope for one protocol from being
/// accepted by another protocol with an accidentally compatible schema.
pub trait StatementContract: Serialize + DeserializeOwned {
    const KIND: &'static str;
    const SIGNING_DOMAIN: &'static str;

    /// Enforce semantic constraints which Serde's closed structural schema
    /// cannot express. The static error code must not contain private input.
    fn validate(&self) -> Result<(), &'static str>;
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope {
    schema_version: u32,
    kind: String,
    algorithm: SignatureAlgorithm,
    key_id: String,
    statement: serde_json::Value,
    signature: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedEnvelope<'a> {
    schema_version: u32,
    kind: &'a str,
    algorithm: SignatureAlgorithm,
    key_id: &'a str,
    statement: &'a serde_json::Value,
}

/// A statement which passed strict parsing, canonical-byte checking, its
/// domain contract, key admission, and strict Ed25519 verification.
///
/// All fields are private and this crate exposes no unchecked constructor.
#[derive(Debug)]
pub struct VerifiedStatement<T> {
    statement: T,
    key_id: String,
    key_state: KeyState,
    canonical_envelope: Vec<u8>,
}

impl<T> VerifiedStatement<T> {
    pub fn statement(&self) -> &T {
        &self.statement
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub const fn key_state(&self) -> KeyState {
        self.key_state
    }

    pub fn canonical_envelope(&self) -> &[u8] {
        &self.canonical_envelope
    }

    pub fn into_statement(self) -> T {
        self.statement
    }
}

/// Strictly parse and authenticate one exact canonical signed envelope.
pub fn parse_and_verify<T>(
    bytes: &[u8],
    key_ring: &KeyRing,
) -> Result<VerifiedStatement<T>, TrustError>
where
    T: StatementContract,
{
    validate_contract::<T>()?;
    let value = require_canonical_json(bytes)?;
    let envelope: SignedEnvelope = serde_json::from_value(value).map_err(|_| {
        TrustError::new(
            ErrorCode::EnvelopeSchemaInvalid,
            "signed envelope does not match its closed schema",
        )
    })?;

    if envelope.schema_version != SIGNED_ENVELOPE_SCHEMA_VERSION {
        return Err(TrustError::new(
            ErrorCode::EnvelopeVersionUnsupported,
            "signed envelope schema_version is unsupported",
        ));
    }
    if envelope.kind != T::KIND {
        return Err(TrustError::new(
            ErrorCode::EnvelopeKindMismatch,
            "signed envelope kind does not match the requested statement contract",
        ));
    }
    require_identifier(&envelope.key_id)?;
    if !envelope.statement.is_object() {
        return Err(TrustError::new(
            ErrorCode::StatementNotObject,
            "signed envelope statement must be a JSON object",
        ));
    }

    let signature_bytes = decode_lower_hex::<64>(&envelope.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let pinned_key = key_ring.find(&envelope.key_id)?;
    if pinned_key.permitted_kind() != T::KIND {
        return Err(TrustError::new(
            ErrorCode::KeyKindMismatch,
            "pinned key is not admitted for the requested statement kind",
        ));
    }
    if pinned_key.state() == KeyState::Revoked {
        return Err(TrustError::new(
            ErrorCode::KeyRevoked,
            "signed envelope names a revoked key",
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(pinned_key.public_key()).map_err(|_| {
        TrustError::new(
            ErrorCode::PublicKeyInvalid,
            "pinned Ed25519 public key became invalid after key-ring construction",
        )
    })?;
    let unsigned = UnsignedEnvelope {
        schema_version: envelope.schema_version,
        kind: &envelope.kind,
        algorithm: envelope.algorithm,
        key_id: &envelope.key_id,
        statement: &envelope.statement,
    };
    let message = signing_message(T::SIGNING_DOMAIN, &unsigned)?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| {
            TrustError::new(
                ErrorCode::SignatureInvalid,
                "Ed25519 signature verification failed",
            )
        })?;

    let statement: T = serde_json::from_value(envelope.statement).map_err(|_| {
        TrustError::new(
            ErrorCode::EnvelopeSchemaInvalid,
            "authenticated statement does not match its closed schema",
        )
    })?;
    statement.validate().map_err(|_| {
        TrustError::new(
            ErrorCode::StatementInvalid,
            "statement contract rejected the authenticated value",
        )
    })?;

    Ok(VerifiedStatement {
        statement,
        key_id: envelope.key_id,
        key_state: pinned_key.state(),
        canonical_envelope: bytes.to_vec(),
    })
}

/// Canonically encode and sign one statement with an already-custodied key.
///
/// This function performs no key generation and accepts only an active pinned
/// key whose public half exactly matches `signing_key`.
#[cfg(feature = "signing")]
pub fn sign_canonical<T>(
    statement: &T,
    pinned_key: &PinnedKey,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, TrustError>
where
    T: StatementContract,
{
    validate_contract::<T>()?;
    if pinned_key.state() != KeyState::Active {
        return Err(TrustError::new(
            ErrorCode::SigningKeyNotActive,
            "new statements may be signed only by an active pinned key",
        ));
    }
    if signing_key.verifying_key().as_bytes() != pinned_key.public_key() {
        return Err(TrustError::new(
            ErrorCode::SigningKeyMismatch,
            "signing key does not match the selected pinned public key",
        ));
    }
    if pinned_key.permitted_kind() != T::KIND {
        return Err(TrustError::new(
            ErrorCode::KeyKindMismatch,
            "pinned key is not admitted for the requested statement kind",
        ));
    }
    let statement_value = to_i_json_value(statement)?;
    if !statement_value.is_object() {
        return Err(TrustError::new(
            ErrorCode::StatementNotObject,
            "signed envelope statement must be a JSON object",
        ));
    }
    let rehydrated: T = serde_json::from_value(statement_value.clone()).map_err(|_| {
        TrustError::new(
            ErrorCode::ContractInvalid,
            "statement contract cannot deserialize its serialized representation",
        )
    })?;
    rehydrated.validate().map_err(|_| {
        TrustError::new(
            ErrorCode::StatementInvalid,
            "statement contract rejected the serialized value",
        )
    })?;
    if to_i_json_value(&rehydrated)? != statement_value {
        return Err(TrustError::new(
            ErrorCode::ContractInvalid,
            "statement contract serialization is not round-trip stable",
        ));
    }

    let unsigned = UnsignedEnvelope {
        schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
        kind: T::KIND,
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: pinned_key.key_id(),
        statement: &statement_value,
    };
    let message = signing_message(T::SIGNING_DOMAIN, &unsigned)?;
    let signature = signing_key.sign(&message);
    let envelope = SignedEnvelope {
        schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
        kind: T::KIND.to_owned(),
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: pinned_key.key_id().to_owned(),
        statement: statement_value,
        signature: encode_lower_hex(&signature.to_bytes()),
    };
    canonicalize(&envelope)
}

fn validate_contract<T: StatementContract>() -> Result<(), TrustError> {
    require_identifier(T::KIND).map_err(|_| {
        TrustError::new(
            ErrorCode::ContractInvalid,
            "statement contract kind is not a canonical identifier",
        )
    })?;
    let domain = T::SIGNING_DOMAIN.as_bytes();
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_BYTES
        || !domain
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'\\')
    {
        return Err(TrustError::new(
            ErrorCode::ContractInvalid,
            "signing domain must be 1 to 255 visible ASCII bytes without backslashes",
        ));
    }
    Ok(())
}

fn signing_message(domain: &str, unsigned: &UnsignedEnvelope<'_>) -> Result<Vec<u8>, TrustError> {
    let canonical = canonicalize(unsigned)?;
    let domain = domain.as_bytes();
    let mut message = Vec::with_capacity(MESSAGE_PREFIX.len() + domain.len() + 1 + canonical.len());
    message.extend_from_slice(MESSAGE_PREFIX);
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(message)
}

fn decode_lower_hex<const N: usize>(value: &str) -> Result<[u8; N], TrustError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TrustError::new(
            ErrorCode::SignatureEncodingInvalid,
            "Ed25519 signature is not the exact lowercase hexadecimal encoding",
        ));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("caller validates lowercase hexadecimal"),
    }
}

#[cfg(any(test, feature = "signing"))]
fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    const SECRET: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const OTHER_SECRET: [u8; 32] = [7; 32];

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestStatement {
        counter: u32,
        subject: String,
    }

    impl StatementContract for TestStatement {
        const KIND: &'static str = "release_only_test_statement";
        const SIGNING_DOMAIN: &'static str = "autocad-mcp.test/release-only-statement/v1";

        fn validate(&self) -> Result<(), &'static str> {
            if self.counter == 0 {
                Err("counter_zero")
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct OtherDomainStatement {
        counter: u32,
        subject: String,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct RepresentationStatement {
        counter: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        optional: Option<String>,
    }

    impl StatementContract for RepresentationStatement {
        const KIND: &'static str = "release_only_representation_statement";
        const SIGNING_DOMAIN: &'static str = "autocad-mcp.test/release-only-representation/v1";

        fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct ScalarStatement(u32);

    impl StatementContract for ScalarStatement {
        const KIND: &'static str = "release_only_scalar_statement";
        const SIGNING_DOMAIN: &'static str = "autocad-mcp.test/release-only-scalar/v1";

        fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[cfg(feature = "signing")]
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct FloatingStatement {
        value: Option<f64>,
    }

    #[cfg(feature = "signing")]
    impl StatementContract for FloatingStatement {
        const KIND: &'static str = "release_only_floating_statement";
        const SIGNING_DOMAIN: &'static str = "autocad-mcp.test/release-only-floating/v1";

        fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[cfg(feature = "signing")]
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct AsymmetricStatement {
        #[serde(deserialize_with = "increment_on_deserialize")]
        value: u32,
    }

    #[cfg(feature = "signing")]
    fn increment_on_deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(u32::deserialize(deserializer)?.saturating_add(1))
    }

    #[cfg(feature = "signing")]
    impl StatementContract for AsymmetricStatement {
        const KIND: &'static str = "release_only_asymmetric_statement";
        const SIGNING_DOMAIN: &'static str = "autocad-mcp.test/release-only-asymmetric/v1";

        fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    impl StatementContract for OtherDomainStatement {
        const KIND: &'static str = "release_only_test_statement";
        const SIGNING_DOMAIN: &'static str = "autocad-mcp.test/release-only-other/v1";

        fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SECRET)
    }

    fn pinned(state: KeyState) -> PinnedKey {
        PinnedKey::new(
            "test-key-1",
            "release_only_test_statement",
            signing_key().verifying_key().to_bytes(),
            state,
        )
        .unwrap()
    }

    fn ring(state: KeyState) -> KeyRing {
        KeyRing::new(vec![pinned(state)]).unwrap()
    }

    fn statement() -> TestStatement {
        TestStatement {
            counter: 7,
            subject: "neutral".to_owned(),
        }
    }

    fn signed_bytes_for<T: StatementContract + Serialize>(
        statement: &T,
        key_id: &str,
        key: &SigningKey,
    ) -> Vec<u8> {
        let statement_value = to_i_json_value(statement).unwrap();
        let unsigned = UnsignedEnvelope {
            schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
            kind: T::KIND,
            algorithm: SignatureAlgorithm::Ed25519,
            key_id,
            statement: &statement_value,
        };
        let message = signing_message(T::SIGNING_DOMAIN, &unsigned).unwrap();
        let envelope = SignedEnvelope {
            schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
            kind: T::KIND.to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_owned(),
            statement: statement_value,
            signature: encode_lower_hex(&key.sign(&message).to_bytes()),
        };
        canonicalize(&envelope).unwrap()
    }

    fn signed_value_bytes(
        kind: &str,
        domain: &str,
        statement: Value,
        key_id: &str,
        key: &SigningKey,
    ) -> Vec<u8> {
        let unsigned = UnsignedEnvelope {
            schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
            kind,
            algorithm: SignatureAlgorithm::Ed25519,
            key_id,
            statement: &statement,
        };
        let message = signing_message(domain, &unsigned).unwrap();
        let envelope = SignedEnvelope {
            schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
            kind: kind.to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_owned(),
            statement,
            signature: encode_lower_hex(&key.sign(&message).to_bytes()),
        };
        canonicalize(&envelope).unwrap()
    }

    fn signed_bytes() -> Vec<u8> {
        signed_bytes_for(&statement(), "test-key-1", &signing_key())
    }

    #[test]
    fn canonical_protocol_vector_is_frozen() {
        // Independently assembled and signed with Python cryptography's
        // Ed25519 implementation, not generated by this crate.
        assert_eq!(
            signed_bytes(),
            concat!(
                "{\"algorithm\":\"ed25519\",\"key_id\":\"test-key-1\",",
                "\"kind\":\"release_only_test_statement\",\"schema_version\":1,",
                "\"signature\":\"bef6973e22e53df674ab989ccf1d4db2e",
                "94b88c3a0862ff294671638b595674e197cfce3a824d4a67bf5e0b",
                "94e1105e0b0d087640d4ddaa3bf24d6b22f9f6307\",",
                "\"statement\":{\"counter\":7,\"subject\":\"neutral\"}}"
            )
            .as_bytes()
        );
    }

    fn mutate_canonical(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(bytes).unwrap();
        mutate(&mut value);
        canonicalize(&value).unwrap()
    }

    #[test]
    fn active_and_verification_only_keys_authenticate() {
        let bytes = signed_bytes();
        for state in [KeyState::Active, KeyState::VerificationOnly] {
            let verified = parse_and_verify::<TestStatement>(&bytes, &ring(state)).unwrap();
            assert_eq!(verified.statement(), &statement());
            assert_eq!(verified.key_id(), "test-key-1");
            assert_eq!(verified.key_state(), state);
            assert_eq!(verified.canonical_envelope(), bytes);
            assert_eq!(verified.into_statement(), statement());
        }
    }

    #[test]
    fn revoked_and_unknown_keys_fail_closed() {
        let error = parse_and_verify::<TestStatement>(&signed_bytes(), &ring(KeyState::Revoked))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::KeyRevoked);

        let other = PinnedKey::new(
            "another-key",
            "release_only_test_statement",
            SigningKey::from_bytes(&OTHER_SECRET)
                .verifying_key()
                .to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        let error =
            parse_and_verify::<TestStatement>(&signed_bytes(), &KeyRing::new(vec![other]).unwrap())
                .unwrap_err();
        assert_eq!(error.code(), ErrorCode::KeyUnknown);
    }

    #[test]
    fn tampering_any_signed_field_invalidates_the_signature() {
        let original = signed_bytes();
        let counter_tamper = mutate_canonical(&original, |value| {
            value["statement"]["counter"] = Value::from(8);
        });
        let key_id_tamper = mutate_canonical(&original, |value| {
            value["key_id"] = Value::from("test-key-2");
        });
        for tampered in [counter_tamper, key_id_tamper] {
            let error =
                parse_and_verify::<TestStatement>(&tampered, &ring(KeyState::Active)).unwrap_err();
            assert!(
                matches!(
                    error.code(),
                    ErrorCode::KeyUnknown | ErrorCode::SignatureInvalid
                ),
                "{error}"
            );
        }

        let tampered = mutate_canonical(&original, |value| {
            let signature = value["signature"].as_str().unwrap();
            let replacement = format!(
                "{}{}",
                if &signature[..1] == "0" { "1" } else { "0" },
                &signature[1..]
            );
            value["signature"] = Value::from(replacement);
        });
        assert_eq!(
            parse_and_verify::<TestStatement>(&tampered, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::SignatureInvalid
        );
    }

    #[test]
    fn semantic_validation_runs_only_after_authentication() {
        let tampered = mutate_canonical(&signed_bytes(), |value| {
            value["statement"]["counter"] = Value::from(0);
        });
        assert_eq!(
            parse_and_verify::<TestStatement>(&tampered, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::SignatureInvalid
        );

        let invalid = TestStatement {
            counter: 0,
            subject: "neutral".to_owned(),
        };
        let authenticated = signed_bytes_for(&invalid, "test-key-1", &signing_key());
        assert_eq!(
            parse_and_verify::<TestStatement>(&authenticated, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::StatementInvalid
        );
    }

    #[test]
    fn verification_uses_the_exact_parsed_statement_representation() {
        let statement = serde_json::json!({
            "counter": 7,
            "optional": null
        });
        let bytes = signed_value_bytes(
            RepresentationStatement::KIND,
            RepresentationStatement::SIGNING_DOMAIN,
            statement,
            "representation-key",
            &signing_key(),
        );
        let pinned = PinnedKey::new(
            "representation-key",
            RepresentationStatement::KIND,
            signing_key().verifying_key().to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        let verified = parse_and_verify::<RepresentationStatement>(
            &bytes,
            &KeyRing::new(vec![pinned]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            verified.statement(),
            &RepresentationStatement {
                counter: 7,
                optional: None,
            }
        );
    }

    #[test]
    fn domain_separation_prevents_cross_contract_replay() {
        let bytes = signed_bytes();
        assert_eq!(
            parse_and_verify::<OtherDomainStatement>(&bytes, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::SignatureInvalid
        );
    }

    #[test]
    fn noncanonical_duplicate_trailing_and_unknown_fields_are_rejected() {
        let canonical = signed_bytes();
        let spaced = format!(" {}", String::from_utf8(canonical.clone()).unwrap());
        assert_eq!(
            parse_and_verify::<TestStatement>(spaced.as_bytes(), &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::JsonNotCanonical
        );

        let duplicate = String::from_utf8(canonical.clone()).unwrap().replacen(
            "{",
            "{\"kind\":\"release_only_test_statement\",",
            1,
        );
        assert_eq!(
            parse_and_verify::<TestStatement>(duplicate.as_bytes(), &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::JsonInvalid
        );

        let mut trailing = canonical.clone();
        trailing.extend_from_slice(b"{}");
        assert_eq!(
            parse_and_verify::<TestStatement>(&trailing, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::JsonTrailingData
        );

        let extra = mutate_canonical(&canonical, |value| {
            value["extra"] = Value::Bool(true);
        });
        assert_eq!(
            parse_and_verify::<TestStatement>(&extra, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::EnvelopeSchemaInvalid
        );
    }

    #[test]
    fn malformed_envelope_and_statement_contracts_are_rejected() {
        let canonical = signed_bytes();
        for (mutated, expected) in [
            (
                mutate_canonical(&canonical, |value| value["schema_version"] = Value::from(2)),
                ErrorCode::EnvelopeVersionUnsupported,
            ),
            (
                mutate_canonical(&canonical, |value| {
                    value["kind"] = Value::from("other_kind")
                }),
                ErrorCode::EnvelopeKindMismatch,
            ),
            (
                mutate_canonical(&canonical, |value| value["signature"] = Value::from("00")),
                ErrorCode::SignatureEncodingInvalid,
            ),
            (
                mutate_canonical(&canonical, |value| {
                    value["signature"] = Value::from("A".repeat(128))
                }),
                ErrorCode::SignatureEncodingInvalid,
            ),
        ] {
            assert_eq!(
                parse_and_verify::<TestStatement>(&mutated, &ring(KeyState::Active))
                    .unwrap_err()
                    .code(),
                expected
            );
        }

        let unknown_algorithm =
            mutate_canonical(&canonical, |value| value["algorithm"] = Value::from("rsa"));
        assert_eq!(
            parse_and_verify::<TestStatement>(&unknown_algorithm, &ring(KeyState::Active))
                .unwrap_err()
                .code(),
            ErrorCode::EnvelopeSchemaInvalid
        );
    }

    #[test]
    fn public_verification_errors_do_not_echo_authenticated_payloads() {
        const SENTINEL: &str = "private-payload-sentinel";
        let bytes = signed_value_bytes(
            TestStatement::KIND,
            TestStatement::SIGNING_DOMAIN,
            serde_json::json!({
                "counter": 7,
                "subject": "neutral",
                "private-payload-sentinel": SENTINEL
            }),
            "test-key-1",
            &signing_key(),
        );
        let error = parse_and_verify::<TestStatement>(&bytes, &ring(KeyState::Active)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::EnvelopeSchemaInvalid);
        assert!(!error.detail().contains(SENTINEL));
        assert!(!error.to_string().contains(SENTINEL));
    }

    #[test]
    fn statement_must_be_a_json_object() {
        let statement = Value::from(7);
        let bytes = signed_value_bytes(
            ScalarStatement::KIND,
            ScalarStatement::SIGNING_DOMAIN,
            statement,
            "scalar-key",
            &signing_key(),
        );
        let pinned = PinnedKey::new(
            "scalar-key",
            ScalarStatement::KIND,
            signing_key().verifying_key().to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        assert_eq!(
            parse_and_verify::<ScalarStatement>(&bytes, &KeyRing::new(vec![pinned]).unwrap())
                .unwrap_err()
                .code(),
            ErrorCode::StatementNotObject
        );

        #[cfg(feature = "signing")]
        {
            let pinned = PinnedKey::new(
                "scalar-key",
                ScalarStatement::KIND,
                signing_key().verifying_key().to_bytes(),
                KeyState::Active,
            )
            .unwrap();
            assert_eq!(
                sign_canonical(&ScalarStatement(7), &pinned, &signing_key())
                    .unwrap_err()
                    .code(),
                ErrorCode::StatementNotObject
            );
        }
    }

    #[test]
    fn key_scope_is_enforced_independently_of_key_material() {
        let wrong_scope = PinnedKey::new(
            "test-key-1",
            "another_release_kind",
            signing_key().verifying_key().to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        assert_eq!(
            parse_and_verify::<TestStatement>(
                &signed_bytes(),
                &KeyRing::new(vec![wrong_scope]).unwrap()
            )
            .unwrap_err()
            .code(),
            ErrorCode::KeyKindMismatch
        );
    }

    #[cfg(feature = "signing")]
    #[test]
    fn feature_gated_signer_round_trips_and_enforces_key_state() {
        let key = signing_key();
        let active = pinned(KeyState::Active);
        let bytes = sign_canonical(&statement(), &active, &key).unwrap();
        parse_and_verify::<TestStatement>(&bytes, &ring(KeyState::Active)).unwrap();

        for state in [KeyState::VerificationOnly, KeyState::Revoked] {
            assert_eq!(
                sign_canonical(&statement(), &pinned(state), &key)
                    .unwrap_err()
                    .code(),
                ErrorCode::SigningKeyNotActive
            );
        }
        let other = SigningKey::from_bytes(&OTHER_SECRET);
        assert_eq!(
            sign_canonical(&statement(), &active, &other)
                .unwrap_err()
                .code(),
            ErrorCode::SigningKeyMismatch
        );
    }

    #[cfg(feature = "signing")]
    #[test]
    fn signer_rejects_non_finite_and_asymmetric_statement_representations() {
        let signing_key = signing_key();
        let floating_key = PinnedKey::new(
            "floating-key",
            FloatingStatement::KIND,
            signing_key.verifying_key().to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = sign_canonical(
                &FloatingStatement { value: Some(value) },
                &floating_key,
                &signing_key,
            )
            .unwrap_err();
            assert_eq!(error.code(), ErrorCode::CanonicalizationFailed);
        }

        let asymmetric_key = PinnedKey::new(
            "asymmetric-key",
            AsymmetricStatement::KIND,
            signing_key.verifying_key().to_bytes(),
            KeyState::Active,
        )
        .unwrap();
        let error = sign_canonical(
            &AsymmetricStatement { value: 7 },
            &asymmetric_key,
            &signing_key,
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ContractInvalid);
    }
}
