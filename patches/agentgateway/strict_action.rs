//! AgentGuard's strict v1.5.0 webhook action boundary.
//!
//! Deserialization never guesses an action by trying enum variants in order.
//! Unknown/duplicate fields, invalid types and noncanonical masks are errors.
//! The original public action types and their serialization remain unchanged.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;

use super::{
    GuardrailsPromptResponse, GuardrailsResponseResponse, MaskAction, MaskActionBody,
    PassAction, PromptMessages, RejectAction, RequestAction, ResponseAction, ResponseChoices,
};

/// Preserve duplicate-key detection before converting any object to Value.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Number::from_f64(v).map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<UniqueValue>()? { values.push(v.0); }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        // Do not echo attacker-supplied keys or content into error logs.
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    values.insert(key, map.next_value::<UniqueValue>()?.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

enum CanonicalAction { Pass(PassAction), Reject(RejectAction), Mask(MaskAction) }

fn action(value: Value, request: bool) -> Result<CanonicalAction, &'static str> {
    let obj = value.as_object().ok_or("action must be an object")?;
    let reason = obj.get("reason").and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty()).ok_or("nonempty reason required")?;
    if obj.contains_key("status_code") {
        if obj.len() != 3 || !obj.contains_key("body") {
            return Err("reject requires only reason, body and status_code");
        }
        let status = obj["status_code"].as_u64().filter(|v| (400..=599).contains(v))
            .ok_or("reject status_code must be an integer from 400 through 599")?;
        let body = obj["body"].as_str().ok_or("reject body must be a string")?;
        return Ok(CanonicalAction::Reject(RejectAction {
            status_code: status as u16, body: body.to_owned(), reason: Some(reason.to_owned()),
        }));
    }
    if let Some(body) = obj.get("body") {
        if obj.len() != 2 { return Err("mask requires only reason and body"); }
        let fields = body.as_object().ok_or("mask body must be an object")?;
        let key = if request { "messages" } else { "choices" };
        if fields.len() != 1 || !fields.get(key).is_some_and(|v| v.as_array().is_some_and(|a| !a.is_empty())) {
            return Err("mask requires a nonempty array in the correct phase");
        }
        // Use the actual upstream schema, not a second approximate Message type.
        // Lossy deserialization (including ignored fields and sequence-as-struct)
        // is rejected rather than silently discarded during mutation.
        let parsed = if request {
            let parsed: PromptMessages = serde_json::from_value(body.clone()).map_err(|_| "invalid request mask schema")?;
            if serde_json::to_value(&parsed).map_err(|_| "mask serialization failed")? != *body {
                return Err("noncanonical or lossy request mask");
            }
            MaskActionBody::PromptMessages(parsed)
        } else {
            let parsed: ResponseChoices = serde_json::from_value(body.clone()).map_err(|_| "invalid response mask schema")?;
            if serde_json::to_value(&parsed).map_err(|_| "mask serialization failed")? != *body {
                return Err("noncanonical or lossy response mask");
            }
            MaskActionBody::ResponseChoices(parsed)
        };
        return Ok(CanonicalAction::Mask(MaskAction { body: parsed, reason: Some(reason.to_owned()) }));
    }
    if obj.len() != 1 { return Err("pass requires only reason"); }
    Ok(CanonicalAction::Pass(PassAction { reason: Some(reason.to_owned()) }))
}

fn envelope(value: Value, request: bool) -> Result<CanonicalAction, &'static str> {
    let mut obj = match value { Value::Object(v) => v, _ => return Err("envelope must be an object") };
    if obj.len() != 1 { return Err("envelope requires only action"); }
    action(obj.remove("action").ok_or("action required")?, request)
}

impl CanonicalAction {
    fn request(self) -> RequestAction {
        match self { Self::Pass(v) => RequestAction::Pass(v), Self::Reject(v) => RequestAction::Reject(v), Self::Mask(v) => RequestAction::Mask(v) }
    }
    fn response(self) -> ResponseAction {
        match self { Self::Pass(v) => ResponseAction::Pass(v), Self::Reject(v) => ResponseAction::Reject(v), Self::Mask(v) => ResponseAction::Mask(v) }
    }
}

impl<'de> Deserialize<'de> for GuardrailsPromptResponse {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let parsed = envelope(UniqueValue::deserialize(d)?.0, true).map_err(de::Error::custom)?;
        Ok(Self { action: parsed.request() })
    }
}
impl<'de> Deserialize<'de> for GuardrailsResponseResponse {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let parsed = envelope(UniqueValue::deserialize(d)?.0, false).map_err(de::Error::custom)?;
        Ok(Self { action: parsed.response() })
    }
}
impl<'de> Deserialize<'de> for RequestAction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        action(UniqueValue::deserialize(d)?.0, true).map(CanonicalAction::request).map_err(de::Error::custom)
    }
}
impl<'de> Deserialize<'de> for ResponseAction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        action(UniqueValue::deserialize(d)?.0, false).map(CanonicalAction::response).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agentguard_strict_shared_negative_fixtures() {
        let fixtures: Value = serde_json::from_str(include_str!("agentguard-webhook-negative.json")).unwrap();
        let mut count = 0;
        for case in fixtures["cases"].as_array().unwrap() {
            for phase in case["phases"].as_array().unwrap() {
                let raw = case["raw"].as_str().unwrap();
                let rejected = if phase == "request" { serde_json::from_str::<GuardrailsPromptResponse>(raw).is_err() }
                    else { serde_json::from_str::<GuardrailsResponseResponse>(raw).is_err() };
                assert!(rejected, "{} / {} must reject", case["id"], phase);
                count += 1;
            }
        }
        assert_eq!(count, 42);
    }

    #[test]
    fn agentguard_strict_controls_roundtrip() {
        for raw in [r#"{"action":{"reason":"ALLOW"}}"#,
                    r#"{"action":{"reason":"DENY","status_code":403,"body":"blocked"}}"#] {
            let request: GuardrailsPromptResponse = serde_json::from_str(raw).unwrap();
            let response: GuardrailsResponseResponse = serde_json::from_str(raw).unwrap();
            let original: Value = serde_json::from_str(raw).unwrap();
            assert_eq!(serde_json::to_value(request).unwrap(), original);
            assert_eq!(serde_json::to_value(response).unwrap(), original);
        }
    }

    #[test]
    fn agentguard_strict_masks_use_real_upstream_schema() {
        // Produce canonical masks using the same upstream types used by Gateway.
        let messages: PromptMessages = serde_json::from_value(serde_json::json!({"messages":[{"role":"user","content":"masked"}]})).unwrap();
        let choices: ResponseChoices = serde_json::from_value(serde_json::json!({"choices":[{"message":{"role":"assistant","content":"masked"}}]})).unwrap();
        let request = serde_json::json!({"action":{"reason":"MASK","body":messages}});
        let response = serde_json::json!({"action":{"reason":"MASK","body":choices}});
        assert!(matches!(serde_json::from_value::<GuardrailsPromptResponse>(request.clone()).unwrap().action, RequestAction::Mask(_)));
        assert!(matches!(serde_json::from_value::<GuardrailsResponseResponse>(response.clone()).unwrap().action, ResponseAction::Mask(_)));
        assert!(serde_json::from_value::<GuardrailsPromptResponse>(response).is_err());
        assert!(serde_json::from_value::<GuardrailsResponseResponse>(request).is_err());
    }

    #[test]
    fn agentguard_strict_rejects_sequence_and_nested_duplicates() {
        for raw in [r#"[{"reason":"ALLOW"}]"#,
                    r#"{"action":{"reason":"ALLOW"},"action":{"reason":"ALLOW"}}"#,
                    r#"{"action":{"reason":"MASK","body":{"messages":[{"role":"user","content":"x","content":"y"}]}}}"#,
                    r#"{"action":{"reason":" "}}"#,
                    r#"{"action":{"reason":"DENY","status_code":403.0,"body":"x"}}"#] {
            assert!(serde_json::from_str::<GuardrailsPromptResponse>(raw).is_err());
            assert!(serde_json::from_str::<GuardrailsResponseResponse>(raw).is_err());
        }
    }

    #[test]
    fn agentguard_strict_direct_actions_do_not_fall_through() {
        assert!(serde_json::from_str::<RequestAction>(r#"{"body":{},"reason":"MASK"}"#).is_err());
        assert!(serde_json::from_str::<ResponseAction>(r#"{"status":403,"reason":"DENY","body":"x"}"#).is_err());
        assert!(matches!(serde_json::from_str::<RequestAction>(r#"{"reason":"ALLOW"}"#).unwrap(), RequestAction::Pass(_)));
    }
}
