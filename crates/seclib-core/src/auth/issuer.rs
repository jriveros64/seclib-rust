use crate::store::SessionStore;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IssuerError {
    #[error("Token error: {0}")]
    Token(String),
    #[error("Invalid token type")]
    InvalidTokenType,
    #[error("Refresh token is expired or revoked")]
    TokenExpiredOrRevoked,
    #[error("Refresh token family is revoked")]
    FamilyRevoked,
    #[error("Replay attack detected: entire family has been revoked")]
    ReplayAttackDetected,
    #[error("Store error: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<String> for IssuerError {
    fn from(err: String) -> Self {
        IssuerError::Token(err)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CustomClaims {
    pub sub: String,
    pub tenant_id: String,
    pub r#type: String, // "access", "refresh", "mfa_challenge"
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenMetadata {
    pub parent_id: Option<String>,
    pub user_id: String,
    pub tenant_id: String,
    pub used: bool,
    pub family_id: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RotationResult {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone)]
pub struct JwtIssuer {
    key_bytes: Vec<u8>,
    algorithm: Algorithm,
    issuer: String,
    audience: String,
    access_expiry: Duration,
    refresh_expiry: Duration,
    mfa_expiry: Duration,
}

impl std::fmt::Debug for JwtIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtIssuer")
            .field("key_bytes", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("access_expiry", &self.access_expiry)
            .field("refresh_expiry", &self.refresh_expiry)
            .field("mfa_expiry", &self.mfa_expiry)
            .finish()
    }
}

impl JwtIssuer {
    pub fn new(
        key_bytes: Vec<u8>,
        algorithm: Algorithm,
        issuer: String,
        audience: String,
        access_expiry_mins: i64,
        refresh_expiry_days: i64,
        mfa_expiry_mins: i64,
    ) -> Self {
        Self {
            key_bytes,
            algorithm,
            issuer,
            audience,
            access_expiry: Duration::minutes(access_expiry_mins),
            refresh_expiry: Duration::days(refresh_expiry_days),
            mfa_expiry: Duration::minutes(mfa_expiry_mins),
        }
    }

    fn get_encoding_key(&self) -> Result<EncodingKey, IssuerError> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                Ok(EncodingKey::from_secret(&self.key_bytes))
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                EncodingKey::from_rsa_pem(&self.key_bytes)
                    .map_err(|e| IssuerError::Token(e.to_string()))
            }
            Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(&self.key_bytes)
                .map_err(|e| IssuerError::Token(e.to_string())),
            _ => Err(IssuerError::Token(format!(
                "Unsupported algorithm for signing: {:?}",
                self.algorithm
            ))),
        }
    }

    fn get_decoding_key(&self) -> Result<DecodingKey, IssuerError> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                Ok(DecodingKey::from_secret(&self.key_bytes))
            }
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                DecodingKey::from_rsa_pem(&self.key_bytes)
                    .map_err(|e| IssuerError::Token(e.to_string()))
            }
            Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(&self.key_bytes)
                .map_err(|e| IssuerError::Token(e.to_string())),
            _ => Err(IssuerError::Token(format!(
                "Unsupported algorithm for verification: {:?}",
                self.algorithm
            ))),
        }
    }

    pub fn generate_access_token(
        &self,
        user_id: &str,
        tenant_id: &str,
        roles: &[String],
        extra: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<String, IssuerError> {
        let now = Utc::now();
        let iat = now.timestamp() as u64;
        let exp = (now + self.access_expiry).timestamp() as u64;
        let jti = Uuid::new_v4().to_string();

        let mut extra_map = extra.unwrap_or_default();
        extra_map.insert("roles".to_string(), serde_json::json!(roles));

        let claims = CustomClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            r#type: "access".to_string(),
            iat,
            exp,
            jti,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            extra: extra_map,
        };

        let header = Header::new(self.algorithm);
        let enc_key = self.get_encoding_key()?;
        encode(&header, &claims, &enc_key).map_err(|e| IssuerError::Token(e.to_string()))
    }

    pub fn generate_mfa_token(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<String, IssuerError> {
        let now = Utc::now();
        let iat = now.timestamp() as u64;
        let exp = (now + self.mfa_expiry).timestamp() as u64;
        let jti = Uuid::new_v4().to_string();

        let claims = CustomClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            r#type: "mfa_challenge".to_string(),
            iat,
            exp,
            jti,
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            extra: serde_json::Map::new(),
        };

        let header = Header::new(self.algorithm);
        let enc_key = self.get_encoding_key()?;
        encode(&header, &claims, &enc_key).map_err(|e| IssuerError::Token(e.to_string()))
    }

    pub fn generate_refresh_token(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<(String, String), IssuerError> {
        let now = Utc::now();
        let iat = now.timestamp() as u64;
        let exp = (now + self.refresh_expiry).timestamp() as u64;
        let jti = Uuid::new_v4().to_string();

        let claims = CustomClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            r#type: "refresh".to_string(),
            iat,
            exp,
            jti: jti.clone(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            extra: serde_json::Map::new(),
        };

        let header = Header::new(self.algorithm);
        let enc_key = self.get_encoding_key()?;
        let token =
            encode(&header, &claims, &enc_key).map_err(|e| IssuerError::Token(e.to_string()))?;
        Ok((token, jti))
    }

    // justificado: register_refresh_token requires multiple metadata fields to fully persist the token session context
    #[allow(clippy::too_many_arguments)]
    pub async fn register_refresh_token(
        &self,
        store: &dyn SessionStore,
        jti: &str,
        user_id: &str,
        tenant_id: &str,
        roles: Vec<String>,
        parent_id: Option<String>,
        family_id: Option<String>,
    ) -> Result<(), IssuerError> {
        let family = family_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let meta = RefreshTokenMetadata {
            parent_id,
            user_id: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            used: false,
            family_id: family,
            roles,
        };
        let value = serde_json::to_string(&meta)?;
        let ttl = self.refresh_expiry.num_seconds() as u64;
        store.set(&format!("rt:{jti}"), &value, Some(ttl)).await?;
        Ok(())
    }

    pub fn decode_refresh_token(&self, token: &str) -> Result<CustomClaims, IssuerError> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_audience(std::slice::from_ref(&self.audience));
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.validate_exp = true;

        let dec_key = self.get_decoding_key()?;
        let token_data = decode::<CustomClaims>(token, &dec_key, &validation)
            .map_err(|e| IssuerError::Token(e.to_string()))?;

        if token_data.claims.r#type != "refresh" {
            return Err(IssuerError::InvalidTokenType);
        }
        Ok(token_data.claims)
    }

    pub async fn rotate_refresh_token(
        &self,
        store: &dyn SessionStore,
        refresh_token_str: &str,
    ) -> Result<RotationResult, IssuerError> {
        let claims = self.decode_refresh_token(refresh_token_str)?;
        let jti = &claims.jti;

        let meta_key = format!("rt:{jti}");
        let meta_str = store
            .get(&meta_key)
            .await?
            .ok_or(IssuerError::TokenExpiredOrRevoked)?;
        let meta: RefreshTokenMetadata = serde_json::from_str(&meta_str)?;

        let family_revoked_key = format!("rt_family:{}:revoked", meta.family_id);
        if store.get(&family_revoked_key).await?.is_some() {
            return Err(IssuerError::FamilyRevoked);
        }

        if meta.used {
            let ttl = self.refresh_expiry.num_seconds() as u64;
            store.set(&family_revoked_key, "revoked", Some(ttl)).await?;
            return Err(IssuerError::ReplayAttackDetected);
        }

        // Atomically set used = true using CAS
        let mut updated_meta = meta.clone();
        updated_meta.used = true;
        let updated_meta_str = serde_json::to_string(&updated_meta)?;
        let ttl = self.refresh_expiry.num_seconds() as u64;

        let success = store
            .compare_and_set(
                &meta_key,
                Some(&meta_str),
                Some(&updated_meta_str),
                Some(ttl),
            )
            .await?;

        if !success {
            // CAS failed: concurrent update is a replay attack!
            let ttl = self.refresh_expiry.num_seconds() as u64;
            store.set(&family_revoked_key, "revoked", Some(ttl)).await?;
            return Err(IssuerError::ReplayAttackDetected);
        }

        let (new_rt, new_jti) = self.generate_refresh_token(&claims.sub, &claims.tenant_id)?;
        self.register_refresh_token(
            store,
            &new_jti,
            &claims.sub,
            &claims.tenant_id,
            meta.roles.clone(),
            Some(jti.clone()),
            Some(meta.family_id.clone()),
        )
        .await?;

        let access_token =
            self.generate_access_token(&claims.sub, &claims.tenant_id, &meta.roles, None)?;

        Ok(RotationResult {
            access_token,
            refresh_token: new_rt,
        })
    }
}
