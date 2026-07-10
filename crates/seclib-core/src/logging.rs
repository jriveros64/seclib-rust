use std::io::Write;
use tracing::Subscriber;
use tracing_subscriber::{layer::Context, Layer};

tokio::task_local! {
    pub static CURRENT_CONTEXT: RequestContext;
}

#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub request_id: Option<String>,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub ip: Option<String>,
}

fn is_sensitive_key(key: &str) -> bool {
    let mut normalized = String::new();
    for c in key.chars() {
        if c.is_uppercase() {
            normalized.push('_');
            normalized.push(c.to_ascii_lowercase());
        } else {
            normalized.push(c);
        }
    }
    let key_lower = normalized.to_lowercase();

    let whitelist = &[
        "account_id",
        "card_type",
        "key_id",
        "key_type",
        "key_name",
        "key_len",
        "token_type",
        "kid",
    ];
    if whitelist.contains(&key_lower.as_str()) {
        return false;
    }

    let parts: Vec<&str> = key_lower.split(['-', '_']).collect();
    for part in &parts {
        if part.is_empty() {
            continue;
        }
        // High-sensitivity roots: any field carrying these is secret material.
        if [
            "password",
            "token",
            "secret",
            "authorization",
            "cookie",
            "pan",
            "cvv",
            "cvc",
        ]
        .contains(part)
        {
            return true;
        }
        // Medium-sensitivity roots: redact by default. Benign metadata fields
        // (key_id, key_type, account_id, card_type, ...) are already excluded above
        // via the whitelist; anything else carrying these roots is treated as secret
        // (api_key, private_key, signing_key, card_number, account_number, ...).
        if ["card", "account", "key"].contains(part) {
            return true;
        }
    }
    false
}

fn redact_value(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (k, v) in map {
                if is_sensitive_key(k) {
                    redacted.insert(k.clone(), redact_value(v));
                } else {
                    redacted.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(arr) => {
            let redacted = arr.iter().map(redact_value).collect();
            serde_json::Value::Array(redacted)
        }
        _ => serde_json::Value::String("***".to_string()),
    }
}

struct RedactingVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for RedactingVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let val_str = format!("{value:?}");
        if is_sensitive_key(name) {
            self.fields
                .insert(name.to_string(), serde_json::json!("***"));
        } else {
            self.fields
                .insert(name.to_string(), serde_json::json!(val_str));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let name = field.name();
        if is_sensitive_key(name) {
            self.fields
                .insert(name.to_string(), serde_json::json!("***"));
        } else {
            self.fields
                .insert(name.to_string(), serde_json::json!(value));
        }
    }
}

pub struct JsonFormattingLayer;

impl<S> Layer<S> for JsonFormattingLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let mut visitor = RedactingVisitor {
            fields: serde_json::Map::new(),
        };
        event.record(&mut visitor);

        let mut context_fields = serde_json::Map::new();

        // 1. Check tracing span context
        if let Some(span) = ctx.lookup_current() {
            let mut current = Some(span);
            while let Some(s) = current {
                if let Some(extensions) = s.extensions().get::<RequestContext>() {
                    if let Some(ref rid) = extensions.request_id {
                        context_fields.insert("request_id".to_string(), serde_json::json!(rid));
                    }
                    if let Some(ref uid) = extensions.user_id {
                        context_fields.insert("user_id".to_string(), serde_json::json!(uid));
                    }
                    if let Some(ref tid) = extensions.tenant_id {
                        context_fields.insert("tenant_id".to_string(), serde_json::json!(tid));
                    }
                    if let Some(ref ip) = extensions.ip {
                        context_fields.insert("ip".to_string(), serde_json::json!(ip));
                    }
                }
                current = s.parent();
            }
        }

        // 2. Check task-local context
        let _ = CURRENT_CONTEXT.try_with(|ctx| {
            if let Some(ref rid) = ctx.request_id {
                context_fields.insert("request_id".to_string(), serde_json::json!(rid));
            }
            if let Some(ref uid) = ctx.user_id {
                context_fields.insert("user_id".to_string(), serde_json::json!(uid));
            }
            if let Some(ref tid) = ctx.tenant_id {
                context_fields.insert("tenant_id".to_string(), serde_json::json!(tid));
            }
            if let Some(ref ip) = ctx.ip {
                context_fields.insert("ip".to_string(), serde_json::json!(ip));
            }
        });

        let mut log_obj = serde_json::Map::new();
        let now_str = chrono::Utc::now().to_rfc3339();
        log_obj.insert("timestamp".to_string(), serde_json::json!(now_str));
        log_obj.insert(
            "level".to_string(),
            serde_json::json!(event.metadata().level().to_string()),
        );

        let event_name = visitor
            .fields
            .remove("message")
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| event.metadata().name().to_string());
        log_obj.insert("event".to_string(), serde_json::json!(event_name));

        // Insert context fields
        for (k, v) in context_fields {
            log_obj.insert(k, v);
        }

        // Insert other visitor fields, making sure to redact if sensitive
        for (k, v) in visitor.fields {
            if is_sensitive_key(&k) {
                log_obj.insert(k, redact_value(&v));
            } else {
                log_obj.insert(k, v);
            }
        }

        if event.metadata().target() == "audit" {
            log_obj.insert("channel".to_string(), serde_json::json!("audit"));
        }

        let json_str = serde_json::to_string(&log_obj).unwrap_or_default();
        let _ = writeln!(std::io::stdout(), "{json_str}");
    }
}

pub fn log_audit(event_name: &str, outcome: &str, details: serde_json::Value) {
    tracing::info!(
        target: "audit",
        event = event_name,
        outcome = outcome,
        details = %details,
    );
}

pub fn configure_logging() {
    use tracing_subscriber::prelude::*;
    let layer = JsonFormattingLayer;
    let _ = tracing_subscriber::registry().with(layer).try_init();
}

#[cfg(test)]
mod tests {
    use super::is_sensitive_key;

    #[test]
    fn redacts_snake_and_camel_case_secrets() {
        // H-4/B-15: camelCase must normalize, and composite *_key/*_number fields
        // (api_key, private_key, card_number, ...) must be redacted, not leaked.
        for k in [
            "password",
            "access_token",
            "accessToken",
            "refreshToken",
            "client_secret",
            "clientSecret",
            "api_key",
            "apiKey",
            "private_key",
            "signing_key",
            "encryption_key",
            "card_number",
            "cardNumber",
            "account_number",
            "authorization",
            "Cookie",
            "cvv",
            "pan",
        ] {
            assert!(is_sensitive_key(k), "esperaba que '{k}' fuera sensible");
        }
    }

    #[test]
    fn keeps_benign_metadata_visible() {
        // Whitelisted metadata must remain visible (no over-redaction).
        for k in [
            "account_id",
            "accountId",
            "card_type",
            "cardType",
            "key_id",
            "key_type",
            "key_name",
            "key_len",
            "token_type",
            "kid",
            "user_id",
            "username",
            "request_id",
            "tenant_id",
        ] {
            assert!(!is_sensitive_key(k), "esperaba que '{k}' NO fuera sensible");
        }
    }
}
