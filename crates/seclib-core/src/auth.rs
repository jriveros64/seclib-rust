use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, TokenData};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

pub mod issuer;
pub mod mfa;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Error de autenticación: {0}")]
    Generic(String),

    #[error("IdP no disponible: {0}")]
    IdpUnavailable(String),
}

#[derive(Deserialize, Debug, Clone)]
struct Jwk {
    kty: String,
    kid: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct Jwks {
    keys: Vec<Jwk>,
}

fn jwk_to_decoding_key(jwk: &Jwk) -> Option<DecodingKey> {
    if jwk.kty == "RSA" {
        if let (Some(n), Some(e)) = (&jwk.n, &jwk.e) {
            return DecodingKey::from_rsa_components(n, e).ok();
        }
    } else if jwk.kty == "EC" {
        if let (Some(x), Some(y)) = (&jwk.x, &jwk.y) {
            return DecodingKey::from_ec_components(x, y).ok();
        }
    }
    None
}

pub struct JwksClient {
    jwks_url: String,
    cache: RwLock<HashMap<String, (DecodingKey, DateTime<Utc>)>>,
    client: reqwest::Client,
    update_mutex: tokio::sync::Mutex<()>,
}

impl JwksClient {
    pub fn new(jwks_url: String) -> Self {
        Self {
            jwks_url,
            cache: RwLock::new(HashMap::new()),
            client: reqwest::Client::new(),
            update_mutex: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        {
            let cache = self.cache.read().map_err(|e| {
                AuthError::Generic(format!("Error al adquirir lectura JWKS cache: {e}"))
            })?;
            if let Some((key, expires_at)) = cache.get(kid) {
                if Utc::now() < *expires_at {
                    return Ok(key.clone());
                }
            }
        }

        // Anti-thundering-herd lock
        let _guard = self.update_mutex.lock().await;

        // Double-check cache
        {
            let cache = self.cache.read().map_err(|e| {
                AuthError::Generic(format!("Error al adquirir lectura JWKS cache: {e}"))
            })?;
            if let Some((key, expires_at)) = cache.get(kid) {
                if Utc::now() < *expires_at {
                    return Ok(key.clone());
                }
            }
        }

        self.fetch_and_update_cache().await?;

        let cache = self.cache.read().map_err(|e| {
            AuthError::Generic(format!("Error al adquirir lectura JWKS cache: {e}"))
        })?;
        if let Some((key, _)) = cache.get(kid) {
            Ok(key.clone())
        } else {
            Err(AuthError::Generic(format!(
                "kid '{kid}' no encontrado en JWKS"
            )))
        }
    }

    async fn fetch_and_update_cache(&self) -> Result<(), AuthError> {
        let response = self
            .client
            .get(&self.jwks_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| AuthError::IdpUnavailable(e.to_string()))?;

        if response.status() != 200 {
            return Err(AuthError::IdpUnavailable(format!(
                "El IdP retornó status {}",
                response.status()
            )));
        }

        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| AuthError::Generic(format!("Error al parsear JWKS: {e}")))?;

        let expires_at = Utc::now() + Duration::hours(1);

        // Evict old cache keys by creating a fresh map (obsolete key eviction)
        let mut new_cache = HashMap::new();
        for jwk in jwks.keys {
            if let Some(key) = jwk_to_decoding_key(&jwk) {
                new_cache.insert(jwk.kid, (key, expires_at));
            }
        }

        let mut cache = self.cache.write().map_err(|e| {
            AuthError::Generic(format!("Error al adquirir escritura JWKS cache: {e}"))
        })?;
        *cache = new_cache;

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
    pub sub: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub struct OidcTenantConfig {
    pub jwks_client: JwksClient,
    pub issuer: String,
    pub audience: String,
}

pub struct TokenVerifier {
    jwks_client: JwksClient,
    issuer: String,
    audience: String,
    tenants: RwLock<HashMap<String, std::sync::Arc<OidcTenantConfig>>>,
}

impl TokenVerifier {
    pub fn new(jwks_url: String, issuer: String, audience: String) -> Self {
        Self {
            jwks_client: JwksClient::new(jwks_url),
            issuer,
            audience,
            tenants: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_tenant_config(
        &self,
        tenant_id: String,
        jwks_url: String,
        issuer: String,
        audience: String,
    ) -> Result<(), AuthError> {
        let mut tenants = self
            .tenants
            .write()
            .map_err(|e| AuthError::Generic(format!("Error al adquirir escritura tenants: {e}")))?;
        tenants.insert(
            tenant_id,
            std::sync::Arc::new(OidcTenantConfig {
                jwks_client: JwksClient::new(jwks_url),
                issuer,
                audience,
            }),
        );
        Ok(())
    }

    pub async fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return Err(AuthError::Generic(
                "Token malformado: no contiene payload".to_string(),
            ));
        }
        let decoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| {
                AuthError::Generic(format!("Error decodificando payload base64url: {e}"))
            })?;
        let unverified: serde_json::Value = serde_json::from_slice(&decoded_payload)
            .map_err(|e| AuthError::Generic(format!("Error parseando JSON de claims: {e}")))?;

        let tenant_id = unverified
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let tenant_config = {
            let tenants = self.tenants.read().map_err(|e| {
                AuthError::Generic(format!("Error al adquirir lectura tenants: {e}"))
            })?;
            tenants.get(tenant_id).cloned()
        };

        let (jwks_client, issuer, audience) = match &tenant_config {
            Some(cfg) => (&cfg.jwks_client, &cfg.issuer, &cfg.audience),
            None => (&self.jwks_client, &self.issuer, &self.audience),
        };

        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AuthError::Generic(format!("Header inválido: {e}")))?;

        let alg = match header.alg {
            jsonwebtoken::Algorithm::RS256 => jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::ES256 => jsonwebtoken::Algorithm::ES256,
            _ => {
                return Err(AuthError::Generic(format!(
                    "Algoritmo no soportado: {:?}",
                    header.alg
                )))
            }
        };

        let kid = header
            .kid
            .ok_or_else(|| AuthError::Generic("kid faltante en token".to_string()))?;
        let decoding_key = jwks_client.get_key(&kid).await?;

        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.set_audience(std::slice::from_ref(audience));
        validation.set_issuer(std::slice::from_ref(issuer));
        validation.leeway = 60;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let token_data: TokenData<Claims> = jsonwebtoken::decode(token, &decoding_key, &validation)
            .map_err(|e| AuthError::Generic(format!("Validación fallida: {e}")))?;

        Ok(token_data.claims)
    }
}

pub struct SessionManager {
    redis_client: Option<redis::Client>,
    cookie_name: String,
    fallback_store: RwLock<HashMap<String, (serde_json::Value, DateTime<Utc>)>>,
}

impl SessionManager {
    pub fn new(redis_url: Option<&str>, cookie_name: &str) -> Result<Self, AuthError> {
        let redis_client = match redis_url {
            Some(url) => {
                Some(redis::Client::open(url).map_err(|e| AuthError::Generic(e.to_string()))?)
            }
            None => None,
        };
        Ok(Self {
            redis_client,
            cookie_name: cookie_name.to_string(),
            fallback_store: RwLock::new(HashMap::new()),
        })
    }

    pub fn create_session(
        &self,
        session_data: serde_json::Value,
        expiry_seconds: i64,
    ) -> Result<String, AuthError> {
        if expiry_seconds <= 0 {
            return Err(AuthError::Generic(
                "El tiempo de expiración debe ser mayor que 0".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let session_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        if let Some(ref client) = self.redis_client {
            let mut conn = client
                .get_connection()
                .map_err(|e| AuthError::Generic(format!("Fallo al obtener conexión Redis: {e}")))?;
            let data_str = serde_json::to_string(&session_data)
                .map_err(|e| AuthError::Generic(e.to_string()))?;
            let key = format!("session:{session_id}");
            use redis::Commands;
            let _: () = conn
                .set_ex(key, data_str, expiry_seconds as u64)
                .map_err(|e| {
                    AuthError::Generic(format!("Fallo al guardar sesión en Redis: {e}"))
                })?;
        } else {
            let expires_at = Utc::now() + Duration::seconds(expiry_seconds);
            let mut store = self.fallback_store.write().map_err(|e| {
                AuthError::Generic(format!("Error al escribir fallback cache: {e}"))
            })?;
            store.insert(session_id.clone(), (session_data, expires_at));
        }

        Ok(session_id)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<serde_json::Value>, AuthError> {
        if let Some(ref client) = self.redis_client {
            let mut conn = client
                .get_connection()
                .map_err(|e| AuthError::Generic(format!("Fallo al obtener conexión Redis: {e}")))?;
            let key = format!("session:{session_id}");
            use redis::Commands;
            let data_str: Option<String> = conn
                .get(key)
                .map_err(|e| AuthError::Generic(format!("Fallo al leer sesión de Redis: {e}")))?;
            if let Some(s) = data_str {
                let val: serde_json::Value =
                    serde_json::from_str(&s).map_err(|e| AuthError::Generic(e.to_string()))?;
                Ok(Some(val))
            } else {
                Ok(None)
            }
        } else {
            let mut store = self.fallback_store.write().map_err(|e| {
                AuthError::Generic(format!("Error al adquirir escritura fallback cache: {e}"))
            })?;
            if let Some((val, expires_at)) = store.get(session_id) {
                if Utc::now() > *expires_at {
                    store.remove(session_id);
                    Ok(None)
                } else {
                    Ok(Some(val.clone()))
                }
            } else {
                Ok(None)
            }
        }
    }

    pub fn destroy_session(&self, session_id: &str) -> Result<(), AuthError> {
        if let Some(ref client) = self.redis_client {
            let mut conn = client
                .get_connection()
                .map_err(|e| AuthError::Generic(format!("Fallo al obtener conexión Redis: {e}")))?;
            let key = format!("session:{session_id}");
            use redis::Commands;
            let _: () = conn.del(key).map_err(|e| {
                AuthError::Generic(format!("Fallo al eliminar sesión de Redis: {e}"))
            })?;
        } else {
            let mut store = self.fallback_store.write().map_err(|e| {
                AuthError::Generic(format!("Error al adquirir escritura fallback cache: {e}"))
            })?;
            store.remove(session_id);
        }
        Ok(())
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }
}

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2, Params,
    };
    let params = Params::new(65536, 3, 4, None).map_err(|e| AuthError::Generic(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Generic(e.to_string()))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(hashed: &str, password: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let parsed_hash = match PasswordHash::new(hashed) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub async fn is_password_pwned(password: &str) -> Result<bool, AuthError> {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let sha1_hex = format!("{:X}", hasher.finalize());
    let (prefix, suffix) = sha1_hex.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(reqwest::Client::new);
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| AuthError::Generic(format!("Error de conexión a HIBP: {e}")))?;

    if response.status() != 200 {
        return Ok(true); // Fail closed
    }

    let text = response
        .text()
        .await
        .map_err(|e| AuthError::Generic(format!("Error al leer respuesta HIBP: {e}")))?;

    for line in text.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 {
            let resp_suffix = parts[0].trim().to_uppercase();
            let count_str = parts[1].trim();
            if resp_suffix == suffix {
                let count = count_str.parse::<u64>().unwrap_or(0);
                if count > 0 {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
