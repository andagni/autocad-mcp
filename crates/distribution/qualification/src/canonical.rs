use crate::finite::require_finite_numbers;
use crate::{parse_strict_json, ErrorCode, TrustError};
use serde::Serialize;
use serde_json::Value;

pub(crate) fn canonicalize<T>(value: &T) -> Result<Vec<u8>, TrustError>
where
    T: Serialize + ?Sized,
{
    let value = to_i_json_value(value)?;
    canonicalize_value(&value)
}

pub(crate) fn to_i_json_value<T>(source: &T) -> Result<Value, TrustError>
where
    T: Serialize + ?Sized,
{
    // serde_json and serde_jcs normalize nested non-finite floats to null.
    // Inspect the original Serde event stream first so values such as
    // `Some(NaN)` cannot silently become `None`.
    require_finite_numbers(source)?;
    let value = serde_json::to_value(source).map_err(|_| {
        TrustError::new(
            ErrorCode::CanonicalizationFailed,
            "value could not be serialized for RFC 8785 canonicalization",
        )
    })?;
    require_i_json(&value)?;
    let canonical_value = canonicalize_value(&value)?;
    let canonical_source = serde_jcs::to_vec(source).map_err(|_| {
        TrustError::new(
            ErrorCode::CanonicalizationFailed,
            "value could not be serialized for RFC 8785 canonicalization",
        )
    })?;
    if canonical_source != canonical_value {
        return Err(TrustError::new(
            ErrorCode::CanonicalizationFailed,
            "value serialization is not stable across canonical JSON serializers",
        ));
    }
    Ok(value)
}

fn canonicalize_value(value: &Value) -> Result<Vec<u8>, TrustError> {
    let canonical = serde_jcs::to_vec(value).map_err(|_| {
        TrustError::new(
            ErrorCode::CanonicalizationFailed,
            "value could not be encoded as RFC 8785 canonical JSON",
        )
    })?;

    // Close the serializer/parser representation boundary. In particular,
    // ryu-js can render an exactly integral f64 as an integer token; reparsing
    // must not turn a value admitted as binary64 into an unsafe JSON integer
    // which the verifier would reject.
    let reparsed = parse_strict_json(&canonical)?;
    require_safe_integer_tokens(&canonical)?;
    require_i_json(&reparsed)?;
    Ok(canonical)
}

pub(crate) fn require_canonical_json(bytes: &[u8]) -> Result<Value, TrustError> {
    let value = parse_strict_json(bytes)?;
    require_safe_integer_tokens(bytes)?;
    require_i_json(&value)?;
    let canonical = canonicalize_value(&value)?;
    if canonical != bytes {
        return Err(TrustError::new(
            ErrorCode::JsonNotCanonical,
            "JSON bytes are not the exact RFC 8785 canonical encoding",
        ));
    }
    Ok(value)
}

fn require_i_json(value: &Value) -> Result<(), TrustError> {
    const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
    const MIN_SAFE_INTEGER: i64 = -((1_i64 << 53) - 1);

    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value < MIN_SAFE_INTEGER || value > MAX_SAFE_INTEGER as i64 {
                    return Err(i_json_integer_error());
                }
            } else if let Some(value) = number.as_u64() {
                if value > MAX_SAFE_INTEGER {
                    return Err(i_json_integer_error());
                }
            } else if number.as_f64().is_none() {
                return Err(TrustError::new(
                    ErrorCode::JsonNotIJson,
                    "JSON number is not representable as a finite IEEE 754 binary64 value",
                ));
            }
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                require_i_json(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                require_i_json(value)?;
            }
            Ok(())
        }
    }
}

fn i_json_integer_error() -> TrustError {
    TrustError::new(
        ErrorCode::JsonNotIJson,
        "JSON integer token is outside the interoperable range -(2^53-1) through 2^53-1",
    )
}

fn require_safe_integer_tokens(bytes: &[u8]) -> Result<(), TrustError> {
    const MAX_SAFE_INTEGER_DECIMAL: &[u8] = b"9007199254740991";

    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte != b'-' && !byte.is_ascii_digit() {
            index += 1;
            continue;
        }

        let start = index;
        if byte == b'-' {
            index += 1;
        }
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let integer_end = index;
        let has_fraction = index < bytes.len() && bytes[index] == b'.';
        if has_fraction {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
        let has_exponent = index < bytes.len() && matches!(bytes[index], b'e' | b'E');
        if has_exponent {
            index += 1;
            if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
                index += 1;
            }
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }

        if !has_fraction && !has_exponent {
            let magnitude_start = start + usize::from(bytes[start] == b'-');
            let magnitude = &bytes[magnitude_start..integer_end];
            if magnitude.len() > MAX_SAFE_INTEGER_DECIMAL.len()
                || (magnitude.len() == MAX_SAFE_INTEGER_DECIMAL.len()
                    && magnitude > MAX_SAFE_INTEGER_DECIMAL)
            {
                return Err(i_json_integer_error());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn jcs_uses_utf16_property_order() {
        let value = json!({
            "\u{e000}": 2,
            "\u{1f600}": 1
        });
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\"😀\":1,\"\":2}".as_bytes()
        );
    }

    #[test]
    fn jcs_normalizes_ecmascript_numbers() {
        let value: Value = serde_json::from_str(
            "[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]",
        )
        .unwrap();
        assert_eq!(
            canonicalize(&value).unwrap(),
            b"[333333333.3333333,1e+30,4.5,0.002,1e-27]"
        );
    }

    #[test]
    fn canonical_input_must_match_byte_for_byte() {
        assert!(require_canonical_json(br#"{"a":1,"b":2}"#).is_ok());
        for bytes in [
            br#"{ "a":1,"b":2}"#.as_slice(),
            br#"{"b":2,"a":1}"#.as_slice(),
            b"{\"a\":1,\"b\":2}\n".as_slice(),
        ] {
            assert_eq!(
                require_canonical_json(bytes).unwrap_err().code(),
                ErrorCode::JsonNotCanonical
            );
        }
    }

    #[test]
    fn i_json_integer_boundaries_are_enforced_before_canonicalization() {
        for accepted in [
            b"9007199254740991".as_slice(),
            b"-9007199254740991".as_slice(),
            br#"{"nested":[9007199254740991,-9007199254740991]}"#.as_slice(),
        ] {
            assert!(require_canonical_json(accepted).is_ok(), "{accepted:?}");
        }
        for rejected in [
            b"9007199254740992".as_slice(),
            b"-9007199254740992".as_slice(),
            b"18446744073709551616".as_slice(),
            b"-18446744073709551616".as_slice(),
            br#"{"nested":[9007199254740992]}"#.as_slice(),
        ] {
            assert_eq!(
                require_canonical_json(rejected).unwrap_err().code(),
                ErrorCode::JsonNotIJson
            );
        }

        assert_eq!(
            canonicalize(&u64::MAX).unwrap_err().code(),
            ErrorCode::JsonNotIJson
        );
    }

    #[test]
    fn canonicalization_outputs_are_closed_under_strict_reparsing() {
        let safe_integer_float = canonicalize(&9_007_199_254_740_991_f64).unwrap();
        assert!(require_canonical_json(&safe_integer_float).is_ok());

        let exponent_float = canonicalize(&1e30_f64).unwrap();
        assert_eq!(exponent_float, b"1e+30");
        assert!(require_canonical_json(&exponent_float).is_ok());

        assert_eq!(
            canonicalize(&9_007_199_254_740_992_f64).unwrap_err().code(),
            ErrorCode::JsonNotIJson
        );
    }

    #[test]
    fn non_finite_numbers_cannot_be_canonicalized_as_null() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                canonicalize(&value).unwrap_err().code(),
                ErrorCode::CanonicalizationFailed
            );
            assert_eq!(
                canonicalize(&Some(value)).unwrap_err().code(),
                ErrorCode::CanonicalizationFailed
            );
        }
    }

    #[derive(Serialize)]
    struct NestedNumbers {
        optional: Option<f64>,
        sequence: Vec<f32>,
        map: BTreeMap<String, f64>,
    }

    #[test]
    fn non_finite_numbers_are_rejected_in_every_compound_shape() {
        let finite = NestedNumbers {
            optional: Some(1.5),
            sequence: vec![2.5],
            map: BTreeMap::from([("finite".to_owned(), 3.5)]),
        };
        assert!(canonicalize(&finite).is_ok());

        for value in [
            NestedNumbers {
                optional: Some(f64::NAN),
                sequence: Vec::new(),
                map: BTreeMap::new(),
            },
            NestedNumbers {
                optional: None,
                sequence: vec![f32::INFINITY],
                map: BTreeMap::new(),
            },
            NestedNumbers {
                optional: None,
                sequence: Vec::new(),
                map: BTreeMap::from([("bad".to_owned(), f64::NEG_INFINITY)]),
            },
        ] {
            let error = canonicalize(&value).unwrap_err();
            assert_eq!(error.code(), ErrorCode::CanonicalizationFailed);
            assert_eq!(
                error.detail(),
                "value contains a non-finite floating-point number or cannot be serialized"
            );
        }
    }

    #[test]
    fn wide_integers_do_not_bypass_value_integer_safety() {
        for error in [
            canonicalize(&i128::MIN).unwrap_err(),
            canonicalize(&i128::MAX).unwrap_err(),
            canonicalize(&u128::MAX).unwrap_err(),
        ] {
            assert_eq!(error.code(), ErrorCode::CanonicalizationFailed);
        }
        assert_eq!(
            canonicalize(&9_007_199_254_740_992_i128)
                .unwrap_err()
                .code(),
            ErrorCode::JsonNotIJson
        );
        assert_eq!(
            canonicalize(&9_007_199_254_740_992_u128)
                .unwrap_err()
                .code(),
            ErrorCode::JsonNotIJson
        );
    }
}
