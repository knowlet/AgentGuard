//! AgentGuard strict webhook action decoder for AgentGateway v1.5.0.
//! Only the normalized role/content messages and message choices are supported.
//! This is wire validation, NOT prompt inspection, authorization, or coverage evidence.
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub message: Message,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Messages {
    pub messages: Vec<Message>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Choices {
    pub choices: Vec<Choice>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MaskBody {
    Request(Messages),
    Response(Choices),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Body {
    Rejection(String),
    Mask(MaskBody),
}

#[derive(Debug)]
pub enum Action {
    Pass { reason: String },
    Reject { reason: String, body: String, status_code: u16 },
    Mask { reason: String, body: MaskBody },
}

#[derive(Clone, Copy)]
pub enum Phase { Request, Response }

/// Check direction BEFORE converting to the upstream mutation types.
/// No fallback action is tried when validation or conversion fails.
pub fn decode<'de, D: Deserializer<'de>>(d: D, phase: Phase) -> Result<Action, D::Error> {
    let action = Action::deserialize(d)?;
    let direction_ok = match (&action, phase) {
        (Action::Mask { body: MaskBody::Request(_), .. }, Phase::Response)
        | (Action::Mask { body: MaskBody::Response(_), .. }, Phase::Request) => false,
        _ => true,
    };
    if !direction_ok { return Err(de::Error::custom("AG_WIRE_WRONG_PHASE")); }
    Ok(action)
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ActionVisitor;
        impl<'de> Visitor<'de> for ActionVisitor {
            type Value = Action;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("one canonical AgentGuard action")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Action, M::Error> {
                let (mut reason, mut body, mut status) = (None::<String>, None::<Body>, None::<u16>);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "reason" => {
                            if reason.is_some() { return Err(de::Error::custom("AG_WIRE_DUPLICATE_KEY")); }
                            reason = Some(map.next_value::<String>()?);
                        }
                        "body" => {
                            if body.is_some() { return Err(de::Error::custom("AG_WIRE_DUPLICATE_KEY")); }
                            body = Some(map.next_value::<Body>()?);
                        }
                        "status_code" => {
                            if status.is_some() { return Err(de::Error::custom("AG_WIRE_DUPLICATE_KEY")); }
                            status = Some(map.next_value::<u16>()?);
                        }
                        // Do not echo unknown field names (which may contain secrets) into logs.
                        _ => return Err(de::Error::custom("AG_WIRE_UNKNOWN_KEY")),
                    }
                }
                let reason = reason.ok_or_else(|| de::Error::custom("AG_WIRE_REASON_REQUIRED"))?;
                if reason.trim().is_empty() || reason.len() > 512 {
                    return Err(de::Error::custom("AG_WIRE_INVALID_REASON"));
                }
                match (body, status) {
                    (None, None) => Ok(Action::Pass { reason }),
                    (Some(Body::Rejection(body)), Some(status_code)) if (400..=599).contains(&status_code) => {
                        Ok(Action::Reject { reason, body, status_code })
                    }
                    (Some(Body::Mask(body)), None) => {
                        let len = match &body {
                            MaskBody::Request(x) => x.messages.len(),
                            MaskBody::Response(x) => x.choices.len(),
                        };
                        if len == 0 || len > 1024 {
                            return Err(de::Error::custom("AG_WIRE_INVALID_MASK_LENGTH"));
                        }
                        Ok(Action::Mask { reason, body })
                    }
                    _ => Err(de::Error::custom("AG_WIRE_INVALID_ACTION")),
                }
            }
        }
        d.deserialize_map(ActionVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequestEnvelope {
        #[serde(deserialize_with = "request")]
        action: Action,
    }
    fn request<'de, D: Deserializer<'de>>(d: D) -> Result<Action, D::Error> { decode(d, Phase::Request) }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResponseEnvelope {
        #[serde(deserialize_with = "response")]
        action: Action,
    }
    fn response<'de, D: Deserializer<'de>>(d: D) -> Result<Action, D::Error> { decode(d, Phase::Response) }

    #[test]
    fn pass_and_reject_controls() {
        for raw in [r#"{"action":{"reason":"ALLOW"}}"#,
                    r#"{"action":{"body":"Blocked","reason":"DENY","status_code":403}}"#] {
            assert!(serde_json::from_str::<RequestEnvelope>(raw).is_ok());
            assert!(serde_json::from_str::<ResponseEnvelope>(raw).is_ok());
        }
    }
    #[test]
    fn masks_are_directional_and_nonempty() {
        let req = r#"{"action":{"reason":"MASK","body":{"messages":[{"role":"user","content":"safe"}]}}}"#;
        let resp = r#"{"action":{"reason":"MASK","body":{"choices":[{"message":{"role":"assistant","content":"safe"}}]}}}"#;
        assert!(matches!(serde_json::from_str::<RequestEnvelope>(req).unwrap().action, Action::Mask { .. }));
        assert!(matches!(serde_json::from_str::<ResponseEnvelope>(resp).unwrap().action, Action::Mask { .. }));
        assert!(serde_json::from_str::<ResponseEnvelope>(req).is_err());
        assert!(serde_json::from_str::<RequestEnvelope>(resp).is_err());
    }
    #[test]
    fn malformed_actions_never_become_pass() {
        let actions = [r#"{}"#, r#"{"status":403,"body":"x"}"#,
            r#"{"status_code":"403","body":"x"}"#, r#"{"body":{}}"#,
            r#"{"reason":"OK","body":null}"#, r#"{"reason":"OK","status_code":null}"#,
            r#"{"reason":"OK","body":"x"}"#, r#"{"reason":"OK","status_code":403}"#,
            r#"{"reason":"OK","body":"x","status_code":true}"#,
            r#"{"reason":"OK","body":"x","status_code":403.0}"#,
            r#"{"reason":"OK","body":"x","status_code":200}"#,
            r#"{"reason":"OK","body":"x","status_code":600}"#,
            r#"{"reason":"OK","body":"x","status_code":65536}"#,
            r#"{"reason":"OK","body":"x","status_code":403,"extra":1}"#,
            r#"{"reason":"OK","reason":"OK"}"#, r#"{"reason":"OK","re\u0061son":"OK"}"#,
            r#"{"reason":null}"#, r#"{"reason":"  "}"#, r#"{"reason":false}"#,
            r#"{"reason":"OK","body":{"messages":[]}}"#,
            r#"{"reason":"OK","body":{"choices":[]}}"#,
            r#"{"reason":"OK","body":{"messages":[],"choices":[]}}"#,
            r#"{"reason":"OK","body":{"messages":[{"role":"user","content":"x","content":"y"}]}}"#,
            r#"{"reason":"OK","body":{"messages":[{"role":"user","content":"x","extra":0}]}}"#,
            r#"{"reason":"OK","body":{"messages":[{"role":"user","content":"x"}]},"status_code":403}"#];
        for action in actions {
            let raw = format!("{{\"action\":{action}}}");
            assert!(serde_json::from_str::<RequestEnvelope>(&raw).is_err(), "{action}");
            assert!(serde_json::from_str::<ResponseEnvelope>(&raw).is_err(), "{action}");
        }
    }
    #[test]
    fn closed_envelopes_reject_duplicate_unknown_trailing_json() {
        for raw in [r#"{"action":{"reason":"OK"},"action":{"reason":"OK"}}"#,
                    r#"{"action":{"reason":"OK"},"extra":1}"#,
                    r#"{"action":{"reason":"OK"}} {}"#] {
            assert!(serde_json::from_str::<RequestEnvelope>(raw).is_err());
            assert!(serde_json::from_str::<ResponseEnvelope>(raw).is_err());
        }
    }
}
