//! Effect RPC envelopes (`RpcMessage.ts`, JSON serialization): one message per text frame,
//! or a JSON array of messages. Ids are client-chosen per connection (JSON numbers from the
//! web client) and kept as raw JSON so they echo back unchanged.
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "_tag", rename_all_fields = "camelCase")]
pub enum ClientMsg {
    Request {
        id: Value,
        tag: String,
        #[serde(default)]
        payload: Value,
        trace_id: Option<String>,
        span_id: Option<String>,
        sampled: Option<bool>,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    Ack {
        request_id: Value,
    },
    Interrupt {
        request_id: Value,
    },
    Ping,
    Eof,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "_tag", rename_all_fields = "camelCase")]
pub enum ServerMsg {
    Chunk {
        request_id: Value,
        values: Vec<Value>,
    },
    Exit {
        request_id: Value,
        exit: Value,
    },
    Pong,
    Defect {
        defect: Value,
    },
    ClientProtocolError {
        error: Value,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Envelope {
    Client(ClientMsg),
    Server(ServerMsg),
}

#[derive(Debug)]
pub enum WireError {
    Json(serde_json::Error),
    UnknownTag(String),
}

pub fn parse_frame(text: &str) -> Result<Vec<Envelope>, WireError> {
    match serde_json::from_str(text).map_err(WireError::Json)? {
        Value::Array(items) => items.into_iter().map(parse_msg).collect(),
        v => Ok(vec![parse_msg(v)?]),
    }
}

fn parse_msg(v: Value) -> Result<Envelope, WireError> {
    let tag = v.get("_tag").and_then(Value::as_str).unwrap_or_default();
    match tag {
        "Request" | "Ack" | "Interrupt" | "Ping" | "Eof" => {
            serde_json::from_value(v).map(Envelope::Client)
        }
        "Chunk" | "Exit" | "Pong" | "Defect" | "ClientProtocolError" => {
            serde_json::from_value(v).map(Envelope::Server)
        }
        _ => return Err(WireError::UnknownTag(tag.to_owned())),
    }
    .map_err(WireError::Json)
}

impl Envelope {
    /// `(_tag, request id)`: the replay comparison key. Request uses `id`, replies `requestId`.
    pub fn key(&self) -> (&'static str, Option<&Value>) {
        use ClientMsg as C;
        use ServerMsg as S;
        match self {
            Envelope::Client(C::Request { id, .. }) => ("Request", Some(id)),
            Envelope::Client(C::Ack { request_id }) => ("Ack", Some(request_id)),
            Envelope::Client(C::Interrupt { request_id }) => ("Interrupt", Some(request_id)),
            Envelope::Client(C::Ping) => ("Ping", None),
            Envelope::Client(C::Eof) => ("Eof", None),
            Envelope::Server(S::Chunk { request_id, .. }) => ("Chunk", Some(request_id)),
            Envelope::Server(S::Exit { request_id, .. }) => ("Exit", Some(request_id)),
            Envelope::Server(S::Pong) => ("Pong", None),
            Envelope::Server(S::Defect { .. }) => ("Defect", None),
            Envelope::Server(S::ClientProtocolError { .. }) => ("ClientProtocolError", None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(text: &str) -> Envelope {
        let mut v = parse_frame(text).unwrap();
        assert_eq!(v.len(), 1);
        v.remove(0)
    }

    #[test]
    fn request() {
        let e = one(
            r#"{"_tag":"Request","id":"1","tag":"server.getConfig","payload":{},"headers":[]}"#,
        );
        assert_eq!(
            e,
            Envelope::Client(ClientMsg::Request {
                id: json!("1"),
                tag: "server.getConfig".into(),
                payload: json!({}),
                trace_id: None,
                span_id: None,
                sampled: None,
                headers: vec![],
            })
        );
    }

    #[test]
    fn parses_numeric_ids_from_real_frames() {
        // Envelope shapes from the real boot session (research section 2), neutral values.
        let req = one(
            r#"{"_tag":"Request","id":0,"tag":"subscribeServerConfig","payload":{},"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","sampled":true,"headers":[]}"#,
        );
        assert_eq!(
            req,
            Envelope::Client(ClientMsg::Request {
                id: json!(0),
                tag: "subscribeServerConfig".into(),
                payload: json!({}),
                trace_id: Some("0123456789abcdef0123456789abcdef".into()),
                span_id: Some("0123456789abcdef".into()),
                sampled: Some(true),
                headers: vec![],
            })
        );
        assert_eq!(req.key(), ("Request", Some(&json!(0))));
        assert_eq!(
            one(r#"{"_tag":"Ack","requestId":0}"#),
            Envelope::Client(ClientMsg::Ack {
                request_id: json!(0)
            })
        );
        assert_eq!(
            one(r#"{"_tag":"Interrupt","requestId":18}"#),
            Envelope::Client(ClientMsg::Interrupt {
                request_id: json!(18)
            })
        );
        let cause: Vec<_> = (0..9)
            .map(|_| json!({"_tag":"Interrupt","fiberId":1234}))
            .collect();
        let exit = json!({"_tag":"Failure","cause":cause});
        let text = json!({"_tag":"Exit","requestId":18,"exit":exit}).to_string();
        assert_eq!(
            one(&text),
            Envelope::Server(ServerMsg::Exit {
                request_id: json!(18),
                exit
            })
        );
    }

    #[test]
    fn chunk() {
        let e =
            one(r#"{"_tag":"Chunk","requestId":"2","values":[{"type":"snapshot","config":{}}]}"#);
        assert_eq!(
            e,
            Envelope::Server(ServerMsg::Chunk {
                request_id: json!("2"),
                values: vec![json!({"type":"snapshot","config":{}})],
            })
        );
    }

    #[test]
    fn exit_success_and_failure() {
        let e =
            one(r#"{"_tag":"Exit","requestId":"1","exit":{"_tag":"Success","value":{"ok":true}}}"#);
        assert_eq!(
            e,
            Envelope::Server(ServerMsg::Exit {
                request_id: json!("1"),
                exit: json!({"_tag":"Success","value":{"ok":true}}),
            })
        );
        let fail = json!({"_tag":"Failure","cause":[{"_tag":"Fail","error":{
            "_tag":"MachineAuthorizationError","message":"denied","requiredScope":"orchestration:read"}}]});
        let text = json!({"_tag":"Exit","requestId":"3","exit":fail}).to_string();
        assert_eq!(
            one(&text),
            Envelope::Server(ServerMsg::Exit {
                request_id: json!("3"),
                exit: fail
            })
        );
    }

    #[test]
    fn ping() {
        assert_eq!(one(r#"{"_tag":"Ping"}"#), Envelope::Client(ClientMsg::Ping));
    }

    #[test]
    fn array_frame_yields_many() {
        let v = parse_frame(r#"[{"_tag":"Ping"},{"_tag":"Ack","requestId":"1"}]"#).unwrap();
        assert_eq!(
            v,
            vec![
                Envelope::Client(ClientMsg::Ping),
                Envelope::Client(ClientMsg::Ack {
                    request_id: json!("1")
                }),
            ]
        );
    }

    #[test]
    fn unknown_tag() {
        assert!(matches!(
            parse_frame(r#"{"_tag":"Nope"}"#),
            Err(WireError::UnknownTag(t)) if t == "Nope"
        ));
    }

    #[test]
    fn not_json() {
        assert!(matches!(parse_frame("hello"), Err(WireError::Json(_))));
    }
}
