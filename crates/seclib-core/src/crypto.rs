use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Error criptográfico: {0}")]
    Generic(String),

    #[error("Fallo al descifrar: {0}")]
    DecryptionFailed(String),
}

pub fn generate_key() -> Vec<u8> {
    Aes256Gcm::generate_key(&mut OsRng).to_vec()
}

pub fn encrypt_dek(kek: &[u8], dek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if kek.len() != 32 {
        return Err(CryptoError::Generic(
            "El KEK debe tener 32 bytes".to_string(),
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(kek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, dek)
        .map_err(|e| CryptoError::Generic(e.to_string()))?;

    let mut payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

pub fn decrypt_dek(kek: &[u8], encrypted_dek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if kek.len() != 32 {
        return Err(CryptoError::Generic(
            "El KEK debe tener 32 bytes".to_string(),
        ));
    }
    if encrypted_dek.len() < 12 {
        return Err(CryptoError::Generic(
            "El DEK cifrado es demasiado corto".to_string(),
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(kek);
    let cipher = Aes256Gcm::new(key);
    let (nonce_bytes, ciphertext) = encrypted_dek.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    Ok(plaintext)
}

pub fn encrypt_data(
    dek: &[u8],
    plaintext: &[u8],
    tenant_id: &str,
    field_name: &str,
    key_version: u32,
) -> Result<Vec<u8>, CryptoError> {
    if dek.len() != 32 {
        return Err(CryptoError::Generic(
            "El DEK debe tener 32 bytes".to_string(),
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // char count (Unicode scalar values) para igualar `len()` de Python (paridad de AAD, R-3)
    let aad = format!("{}:{}:{}", tenant_id.chars().count(), tenant_id, field_name);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| CryptoError::Generic(e.to_string()))?;

    let mut result = Vec::with_capacity(4 + nonce.len() + ciphertext.len());
    result.extend_from_slice(&key_version.to_be_bytes());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_data<F>(
    dek_resolver: F,
    payload: &[u8],
    tenant_id: &str,
    field_name: &str,
    expected_version: Option<u32>,
) -> Result<Vec<u8>, CryptoError>
where
    F: FnOnce(u32) -> Result<Vec<u8>, CryptoError>,
{
    if payload.len() < 16 {
        return Err(CryptoError::Generic(
            "El payload es demasiado corto".to_string(),
        ));
    }
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&payload[0..4]);
    let version = u32::from_be_bytes(version_bytes);

    if let Some(expected) = expected_version {
        if version != expected {
            return Err(CryptoError::DecryptionFailed(format!(
                "Discrepancia en la versión de clave: esperada {expected}, obtenida {version}"
            )));
        }
    }

    let nonce_bytes = &payload[4..16];
    let ciphertext = &payload[16..];
    let nonce = Nonce::from_slice(nonce_bytes);

    let resolved_dek = dek_resolver(version)?;
    if resolved_dek.len() != 32 {
        return Err(CryptoError::Generic(
            "El DEK resuelto debe tener 32 bytes".to_string(),
        ));
    }
    let key = Key::<Aes256Gcm>::from_slice(&resolved_dek);
    let cipher = Aes256Gcm::new(key);

    // char count (Unicode scalar values) para igualar `len()` de Python (paridad de AAD, R-3)
    let aad = format!("{}:{}:{}", tenant_id.chars().count(), tenant_id, field_name);
    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(plaintext)
}

pub fn ed25519_sign(private_key_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if private_key_bytes.len() != 32 {
        return Err(CryptoError::Generic(
            "La clave privada Ed25519 debe ser de 32 bytes".to_string(),
        ));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(private_key_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let signature = ed25519_dalek::Signer::sign(&signing_key, message);
    Ok(signature.to_bytes().to_vec())
}

pub fn ed25519_verify(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    if public_key_bytes.len() != 32 || signature_bytes.len() != 64 {
        return false;
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(public_key_bytes);
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pub_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(signature_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    ed25519_dalek::Verifier::verify(&verifying_key, message, &signature).is_ok()
}
