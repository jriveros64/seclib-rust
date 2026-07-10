use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use secrecy::SecretString;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize, Clone)]
pub struct SecuritySettings {
    #[serde(alias = "OIDC_CLIENT_ID")]
    pub oidc_client_id: String,
    #[serde(alias = "OIDC_CLIENT_SECRET")]
    pub oidc_client_secret: SecretString,
    #[serde(alias = "OIDC_ISSUER")]
    pub oidc_issuer: String,
    #[serde(alias = "OIDC_JWKS_URL")]
    pub oidc_jwks_url: String,
    #[serde(alias = "MASTER_KEY")]
    pub master_key: SecretString,
    #[serde(alias = "REDIS_URL", default = "default_redis_url")]
    pub redis_url: SecretString,
    #[serde(alias = "DATABASE_URL")]
    pub database_url: SecretString,
    #[serde(alias = "CORS_ALLOWED_ORIGINS", default = "default_cors_origins")]
    pub cors_allowed_origins: Vec<String>,
    #[serde(
        alias = "CORS_ALLOW_CREDENTIALS", // justificado: config mapping
        default = "default_cors_allow_credentials"
    )]
    pub cors_allow_credentials: bool,
}

fn default_redis_url() -> SecretString {
    SecretString::from("redis://localhost:6379/0".to_string())
}

fn default_cors_origins() -> Vec<String> {
    Vec::new()
}

fn default_cors_allow_credentials() -> bool {
    false
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Error al cargar la configuración: {0}")]
    Figment(#[from] figment::Error),
}

// justificado: Result incorporates Figment ConfigError which is large but load is only run once during initialization
#[allow(clippy::result_large_err)]
pub fn load_security_settings() -> Result<SecuritySettings, ConfigError> {
    let settings: SecuritySettings = Figment::new()
        .merge(Toml::file("seclib.toml"))
        .merge(Env::prefixed("SECLIB_"))
        .extract()?;
    Ok(settings)
}
