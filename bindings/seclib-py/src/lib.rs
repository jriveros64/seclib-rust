// justificado: PyO3 macro generated code can trigger useless_conversion warnings depending on python target versions
#![allow(clippy::useless_conversion)]
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use seclib_core::auth;
use seclib_core::authz;
use seclib_core::config;
use seclib_core::crypto;
use seclib_core::files;
use seclib_core::http;
use seclib_core::logging;
use secrecy::ExposeSecret;
use std::collections::HashSet;

// --- crypto Submodule ---
#[pyfunction]
fn generate_key() -> PyResult<Vec<u8>> {
    Ok(crypto::generate_key())
}

#[pyfunction]
fn encrypt_dek(kek: &[u8], dek: &[u8]) -> PyResult<Vec<u8>> {
    crypto::encrypt_dek(kek, dek).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn decrypt_dek(kek: &[u8], encrypted_dek: &[u8]) -> PyResult<Vec<u8>> {
    crypto::decrypt_dek(kek, encrypted_dek).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn encrypt_data(
    dek: &[u8],
    plaintext: &[u8],
    tenant_id: &str,
    field_name: &str,
    key_version: u32,
) -> PyResult<Vec<u8>> {
    crypto::encrypt_data(dek, plaintext, tenant_id, field_name, key_version)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(signature = (dek, payload, tenant_id, field_name, expected_version=None))]
fn decrypt_data(
    dek: Vec<u8>,
    payload: &[u8],
    tenant_id: &str,
    field_name: &str,
    expected_version: Option<u32>,
) -> PyResult<Vec<u8>> {
    // We pass a simple static DEK resolver closure
    crypto::decrypt_data(
        |_| Ok(dek.clone()),
        payload,
        tenant_id,
        field_name,
        expected_version,
    )
    .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn ed25519_sign(private_key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    crypto::ed25519_sign(private_key, message).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    crypto::ed25519_verify(public_key, message, signature)
}

// --- auth Submodule ---
#[pyfunction]
fn hash_password(password: &str) -> PyResult<String> {
    auth::hash_password(password).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn verify_password(hashed: &str, password: &str) -> bool {
    auth::verify_password(hashed, password)
}

#[pyfunction]
fn is_password_pwned(password: String) -> PyResult<bool> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    rt.block_on(async {
        auth::is_password_pwned(&password)
            .await
            .map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

// --- authz Submodule ---
#[pyfunction]
fn check_permission(roles: Vec<String>, required: &str) -> PyResult<()> {
    let perm = match required {
        "users:read" => authz::Permission::UsersRead,
        "users:manage" => authz::Permission::UsersManage,
        "files:upload" => authz::Permission::FilesUpload,
        "finance:read" => authz::Permission::FinanceRead,
        "finance:export" => authz::Permission::FinanceExport,
        "admin:*" => authz::Permission::Admin,
        _ => return Err(PyValueError::new_err("Invalid permission name")),
    };
    authz::check_permission(&roles, perm).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn verify_tenant(user_tenant_id: &str, resource_tenant_id: &str) -> PyResult<()> {
    authz::verify_tenant(user_tenant_id, resource_tenant_id)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

// --- http Submodule ---
#[pyfunction]
fn is_safe_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse() {
        http::is_safe_ip(ip)
    } else {
        false
    }
}

#[pyfunction]
fn resolve_and_verify_ssrf(url: &str) -> PyResult<String> {
    http::resolve_and_verify_ssrf(url)
        .map(|ip| ip.to_string())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn verify_webhook_signature(
    body: &[u8],
    secret: &str,
    signature: &str,
    timestamp: &str,
    tolerance_seconds: u64,
) -> bool {
    http::verify_webhook_signature(body, secret, signature, timestamp, tolerance_seconds)
}

// --- files Submodule ---
#[pyfunction]
fn sanitize_filename(filename: &str) -> String {
    files::sanitize_filename(filename)
}

#[pyfunction]
fn save_to_quarantine(file_data: &[u8], filename: &str, quarantine_dir: &str) -> PyResult<String> {
    files::save_to_quarantine(file_data, filename, quarantine_dir)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

#[pyfunction]
fn validate_identity(filepath: &str, allowed_extensions: HashSet<String>) -> PyResult<String> {
    files::validate_identity(filepath, &allowed_extensions)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn check_zip_bomb(filepath: &str) -> PyResult<()> {
    files::check_zip_bomb(filepath).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn sanitize_csv_cell(value: &str) -> String {
    files::sanitize_csv_cell(value)
}

#[pyfunction]
fn process_xlsx(filepath: &str, max_cells: usize) -> PyResult<Vec<Vec<String>>> {
    files::process_xlsx(filepath, max_cells).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn process_pdf(filepath: &str, max_pages: u32) -> PyResult<String> {
    files::process_pdf(filepath, max_pages).map_err(|e| PyValueError::new_err(e.to_string()))
}

// --- config Submodule ---
#[pyfunction]
fn load_security_settings() -> PyResult<PyObject> {
    // Return settings as dictionary or pyclass
    Python::with_gil(|py| {
        let settings =
            config::load_security_settings().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("OIDC_CLIENT_ID", settings.oidc_client_id)?;
        dict.set_item(
            "OIDC_CLIENT_SECRET",
            settings.oidc_client_secret.expose_secret(),
        )?;
        dict.set_item("OIDC_ISSUER", settings.oidc_issuer)?;
        dict.set_item("OIDC_JWKS_URL", settings.oidc_jwks_url)?;
        dict.set_item("MASTER_KEY", settings.master_key.expose_secret())?;
        dict.set_item("REDIS_URL", settings.redis_url.expose_secret())?;
        dict.set_item("DATABASE_URL", settings.database_url.expose_secret())?;
        dict.set_item("CORS_ALLOWED_ORIGINS", settings.cors_allowed_origins)?;
        dict.set_item("CORS_ALLOW_CREDENTIALS", settings.cors_allow_credentials)?;

        Ok(dict.to_object(py))
    })
}

// --- logging Submodule ---
#[pyfunction]
fn configure_logging() {
    logging::configure_logging();
}

#[pyfunction]
fn log_audit(event_name: &str, outcome: &str, details: String) -> PyResult<()> {
    let details_json = serde_json::from_str(&details).unwrap_or(serde_json::Value::String(details));
    logging::log_audit(event_name, outcome, details_json);
    Ok(())
}

#[pymodule]
fn seclib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    // crypto
    let crypto_mod = PyModule::new_bound(py, "crypto")?;
    crypto_mod.add_function(wrap_pyfunction!(generate_key, &crypto_mod)?)?;
    crypto_mod.add_function(wrap_pyfunction!(encrypt_dek, &crypto_mod)?)?;
    crypto_mod.add_function(wrap_pyfunction!(decrypt_dek, &crypto_mod)?)?;
    crypto_mod.add_function(wrap_pyfunction!(encrypt_data, &crypto_mod)?)?;
    crypto_mod.add_function(wrap_pyfunction!(decrypt_data, &crypto_mod)?)?;
    crypto_mod.add_function(wrap_pyfunction!(ed25519_sign, &crypto_mod)?)?;
    crypto_mod.add_function(wrap_pyfunction!(ed25519_verify, &crypto_mod)?)?;
    m.add_submodule(&crypto_mod)?;

    // auth
    let auth_mod = PyModule::new_bound(py, "auth")?;
    auth_mod.add_function(wrap_pyfunction!(hash_password, &auth_mod)?)?;
    auth_mod.add_function(wrap_pyfunction!(verify_password, &auth_mod)?)?;
    auth_mod.add_function(wrap_pyfunction!(is_password_pwned, &auth_mod)?)?;
    m.add_submodule(&auth_mod)?;

    // authz
    let authz_mod = PyModule::new_bound(py, "authz")?;
    authz_mod.add_function(wrap_pyfunction!(check_permission, &authz_mod)?)?;
    authz_mod.add_function(wrap_pyfunction!(verify_tenant, &authz_mod)?)?;
    m.add_submodule(&authz_mod)?;

    // http
    let http_mod = PyModule::new_bound(py, "http")?;
    http_mod.add_function(wrap_pyfunction!(is_safe_ip, &http_mod)?)?;
    http_mod.add_function(wrap_pyfunction!(resolve_and_verify_ssrf, &http_mod)?)?;
    http_mod.add_function(wrap_pyfunction!(verify_webhook_signature, &http_mod)?)?;
    m.add_submodule(&http_mod)?;

    // files
    let files_mod = PyModule::new_bound(py, "files")?;
    files_mod.add_function(wrap_pyfunction!(sanitize_filename, &files_mod)?)?;
    files_mod.add_function(wrap_pyfunction!(save_to_quarantine, &files_mod)?)?;
    files_mod.add_function(wrap_pyfunction!(validate_identity, &files_mod)?)?;
    files_mod.add_function(wrap_pyfunction!(check_zip_bomb, &files_mod)?)?;
    files_mod.add_function(wrap_pyfunction!(sanitize_csv_cell, &files_mod)?)?;
    files_mod.add_function(wrap_pyfunction!(process_xlsx, &files_mod)?)?;
    files_mod.add_function(wrap_pyfunction!(process_pdf, &files_mod)?)?;
    m.add_submodule(&files_mod)?;

    // config
    let secrets_mod = PyModule::new_bound(py, "secrets")?;
    secrets_mod.add_function(wrap_pyfunction!(load_security_settings, &secrets_mod)?)?;
    m.add_submodule(&secrets_mod)?;

    // logging
    let logging_mod = PyModule::new_bound(py, "logging")?;
    logging_mod.add_function(wrap_pyfunction!(configure_logging, &logging_mod)?)?;
    logging_mod.add_function(wrap_pyfunction!(log_audit, &logging_mod)?)?;
    m.add_submodule(&logging_mod)?;

    Ok(())
}
