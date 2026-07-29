use crate::{ErrorCode, TrustError};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Parse exactly one JSON value while rejecting duplicate object keys at every
/// nesting level.
pub fn parse_strict_json(bytes: &[u8]) -> Result<Value, TrustError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictJsonValue::deserialize(&mut deserializer).map_err(|_| {
        TrustError::new(
            ErrorCode::JsonInvalid,
            "input is not one strict JSON value without duplicate object keys",
        )
    })?;
    deserializer.end().map_err(|_| {
        TrustError::new(
            ErrorCode::JsonTrailingData,
            "strict JSON value is followed by trailing data",
        )
    })?;
    Ok(strict.0)
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<StrictJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"outer":{"a":1,"a":2}}"#.as_slice(),
            br#"[{"a":1,"a":2}]"#.as_slice(),
        ] {
            let error = parse_strict_json(bytes).unwrap_err();
            assert_eq!(error.code(), ErrorCode::JsonInvalid);
            assert_eq!(
                error.detail(),
                "input is not one strict JSON value without duplicate object keys"
            );
        }
    }

    #[test]
    fn rejects_trailing_values_and_non_json_data() {
        let error = parse_strict_json(br#"{"a":1} {"b":2}"#).unwrap_err();
        assert_eq!(error.code(), ErrorCode::JsonTrailingData);

        let error = parse_strict_json(b"{").unwrap_err();
        assert_eq!(error.code(), ErrorCode::JsonInvalid);
    }

    #[test]
    fn preserves_one_complete_nested_value() {
        let value = parse_strict_json(br#"{"a":[null,true,1,-2,3.5,"x"]}"#).unwrap();
        assert_eq!(value["a"][5], "x");
    }

    #[test]
    fn public_parse_errors_do_not_echo_untrusted_input() {
        const SENTINEL: &str = "private-payload-sentinel";
        for bytes in [
            br#"{"private-payload-sentinel":1,"private-payload-sentinel":2}"#.as_slice(),
            br#"{"private-payload-sentinel":"#.as_slice(),
            br#"{} private-payload-sentinel"#.as_slice(),
        ] {
            let error = parse_strict_json(bytes).unwrap_err();
            assert!(!error.detail().contains(SENTINEL));
            assert!(!error.to_string().contains(SENTINEL));
        }
    }
}
