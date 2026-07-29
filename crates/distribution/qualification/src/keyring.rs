use crate::{ErrorCode, TrustError};
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, BTreeSet};

const MAX_KEY_ID_BYTES: usize = 64;

/// Lifecycle state for one pinned verification key.
///
/// This is offline, binary-local policy. A later revocation reaches a
/// consumer only when that consumer receives a build containing the updated
/// pinned key ring; it cannot retroactively alter an older installed binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyState {
    /// Accepted for verification and for new signatures.
    Active,
    /// Accepted for verification but not by this crate's signing helper.
    ///
    /// This is an operational rotation state, not a cryptographic issuance
    /// cutoff: without trusted signed time or sequence data, verification
    /// cannot distinguish an old signature from a new signature made by
    /// someone who still holds the private key. Use `Revoked` when compromise
    /// is suspected.
    VerificationOnly,
    /// Rejected even when the cryptographic signature is otherwise valid.
    Revoked,
}

/// One exact key admitted by a caller-owned trust policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedKey {
    key_id: String,
    permitted_kind: String,
    public_key: [u8; 32],
    state: KeyState,
}

impl PinnedKey {
    pub fn new(
        key_id: impl Into<String>,
        permitted_kind: impl Into<String>,
        public_key: [u8; 32],
        state: KeyState,
    ) -> Result<Self, TrustError> {
        let key_id = key_id.into();
        let permitted_kind = permitted_kind.into();
        require_identifier(&key_id)?;
        require_identifier(&permitted_kind)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
            TrustError::new(
                ErrorCode::PublicKeyInvalid,
                "pinned Ed25519 public key is not a valid compressed point",
            )
        })?;
        if verifying_key.is_weak() {
            return Err(TrustError::new(
                ErrorCode::PublicKeyWeak,
                "pinned Ed25519 public key is weak",
            ));
        }
        Ok(Self {
            key_id,
            permitted_kind,
            public_key,
            state,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn permitted_kind(&self) -> &str {
        &self.permitted_kind
    }

    pub const fn state(&self) -> KeyState {
        self.state
    }
}

/// A closed, caller-owned set of exact pinned keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRing {
    keys: BTreeMap<String, PinnedKey>,
}

impl KeyRing {
    /// Construct a key ring from keys already in strict ascending key-ID order.
    ///
    /// Requiring canonical input order prevents silent normalization from
    /// concealing drift in a compiled or generated trust registry.
    pub fn new(keys: Vec<PinnedKey>) -> Result<Self, TrustError> {
        if keys.is_empty() {
            return Err(TrustError::new(
                ErrorCode::KeyRingEmpty,
                "pinned key ring must not be empty",
            ));
        }
        for pair in keys.windows(2) {
            if pair[0].key_id == pair[1].key_id {
                return Err(TrustError::new(
                    ErrorCode::KeyDuplicate,
                    "one pinned key ID appears more than once",
                ));
            }
            if pair[0].key_id > pair[1].key_id {
                return Err(TrustError::new(
                    ErrorCode::KeyRingNotSorted,
                    "pinned keys must be in strict ascending key-ID order",
                ));
            }
        }
        let mut public_keys = BTreeSet::new();
        for key in &keys {
            if !public_keys.insert(key.public_key) {
                return Err(TrustError::new(
                    ErrorCode::KeyMaterialDuplicate,
                    "one Ed25519 public key is assigned to more than one key ID",
                ));
            }
        }
        Ok(Self {
            keys: keys
                .into_iter()
                .map(|key| (key.key_id.clone(), key))
                .collect(),
        })
    }

    pub fn keys(&self) -> impl ExactSizeIterator<Item = &PinnedKey> {
        self.keys.values()
    }

    pub(crate) fn find(&self, key_id: &str) -> Result<&PinnedKey, TrustError> {
        self.keys.get(key_id).ok_or_else(|| {
            TrustError::new(
                ErrorCode::KeyUnknown,
                "signed envelope names a key absent from the pinned key ring",
            )
        })
    }
}

pub(crate) fn require_identifier(value: &str) -> Result<(), TrustError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_KEY_ID_BYTES
        || !bytes[0].is_ascii_lowercase()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
    {
        return Err(identifier_error());
    }
    let mut previous_separator = false;
    for byte in bytes {
        let separator = matches!(byte, b'-' | b'_');
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || separator)
            || (separator && previous_separator)
        {
            return Err(identifier_error());
        }
        previous_separator = separator;
    }
    Ok(())
}

fn identifier_error() -> TrustError {
    TrustError::new(
        ErrorCode::IdentifierInvalid,
        "identifier must be 1 to 64 bytes of canonical lowercase ASCII segments",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NON_WEAK_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn key(id: &str, seed: u8) -> PinnedKey {
        PinnedKey::new(
            id,
            "release_only_test_statement",
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
            KeyState::Active,
        )
        .unwrap()
    }

    #[test]
    fn key_ids_are_closed_and_canonical() {
        for accepted in ["a", "key-1", "key_1", "a1-b2_c3"] {
            assert!(PinnedKey::new(
                accepted,
                "release_only_test_statement",
                NON_WEAK_KEY,
                KeyState::Active
            )
            .is_ok());
        }
        for rejected in [
            "", "1key", "-key", "key-", "Key", "key--one", "key__one", "key.one",
        ] {
            assert_eq!(
                PinnedKey::new(
                    rejected,
                    "release_only_test_statement",
                    NON_WEAK_KEY,
                    KeyState::Active
                )
                .unwrap_err()
                .code(),
                ErrorCode::IdentifierInvalid
            );
        }
    }

    #[test]
    fn weak_keys_are_rejected() {
        let error = PinnedKey::new(
            "weak-key",
            "release_only_test_statement",
            [0; 32],
            KeyState::Active,
        )
        .unwrap_err();
        assert!(
            matches!(
                error.code(),
                ErrorCode::PublicKeyInvalid | ErrorCode::PublicKeyWeak
            ),
            "{error}"
        );
    }

    #[test]
    fn permitted_kind_is_part_of_the_closed_key_scope() {
        let key = PinnedKey::new(
            "key-1",
            "release_only_test_statement",
            NON_WEAK_KEY,
            KeyState::VerificationOnly,
        )
        .unwrap();
        assert_eq!(key.permitted_kind(), "release_only_test_statement");
        assert_eq!(key.state(), KeyState::VerificationOnly);

        assert_eq!(
            PinnedKey::new("key-1", "Invalid Kind", NON_WEAK_KEY, KeyState::Active)
                .unwrap_err()
                .code(),
            ErrorCode::IdentifierInvalid
        );
    }

    #[test]
    fn key_ring_requires_a_nonempty_sorted_unique_inventory() {
        assert_eq!(
            KeyRing::new(Vec::new()).unwrap_err().code(),
            ErrorCode::KeyRingEmpty
        );
        assert_eq!(
            KeyRing::new(vec![key("b", 2), key("a", 1)])
                .unwrap_err()
                .code(),
            ErrorCode::KeyRingNotSorted
        );
        assert_eq!(
            KeyRing::new(vec![key("a", 1), key("a", 2)])
                .unwrap_err()
                .code(),
            ErrorCode::KeyDuplicate
        );
        assert_eq!(
            KeyRing::new(vec![key("a", 1), key("b", 2)])
                .unwrap()
                .keys()
                .count(),
            2
        );
        assert_eq!(
            KeyRing::new(vec![key("a", 1), key("b", 1)])
                .unwrap_err()
                .code(),
            ErrorCode::KeyMaterialDuplicate
        );
    }
}
