use chrono::{Duration, Utc};
use lopdf::dictionary;
use seclib_core::auth::{
    hash_password, is_password_pwned, verify_password, AuthError, Claims, TokenVerifier,
};
use seclib_core::authz::{check_permission, verify_tenant, Permission};
use seclib_core::config::load_security_settings;
use seclib_core::crypto::{decrypt_data, decrypt_dek, encrypt_data, encrypt_dek, generate_key};
use seclib_core::files::{
    check_zip_bomb, process_pdf, sanitize_csv_cell, sanitize_filename, scan_antivirus,
};
use seclib_core::http::{
    is_safe_ip, resolve_and_verify_ssrf, verify_webhook_signature, SecureClient,
};
use std::io::Write;
use std::net::IpAddr;

// Hardcoded RSA 2048-bit Key Pair for Mocking JWT
const PRIVATE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAoK444QgMHIoj/ldWgstpV12/bfHnw2iKLklZr5iKnbF0Nl+N\n\
2N/cKEG3H6zXkWNFWfjDRxUGXIMQavIiKFtvqYLnlBp/xEIxopBoAqIeVRRXxIkM\n\
IVn7ccFbfAFXhqcxwSe5fJA22cXwmpTTMSyaiXuRVc5hhRbHXOP4GAM/8pUZB+Hj\n\
6As1+Ev9IXl8/RuZniyiNW7uug+e3PrB7Q8NmQ/ugrhsBQuXloMr3RwGIaeJXW0O\n\
0rlVq0HylmtvzOsWfEK47mx8gOWl0dsOnZ/oUXqKsUNMJ3wy9lIWn6m9tvEQDd9w\n\
OMU+aEhJj8AtKxRfDy4c65uENQSIhYzxaj9IawIDAQABAoIBAEghbc83OZimOro2\n\
otNcVRGvN/w3F/+UslNNAkHdjHx16OFvy9GLzN0VgwtpH+xYUA2vqpoCSjTFcV1R\n\
DRxoz5uc9DB8JNcJkBaWFNr5w/wVgcDsdNGT/1h1oIfuYkhETgWTu6S7aKQiQ3xh\n\
St1MVKNbIUcPup9wNlbwz7KX4uEWbmuTV15BMsHuT5KD9ER+0t0zUaBeaoqMtVqt\n\
VrI5oX8KJN8Ar+5WkquG+4Xw1xm8sgjUu6iAaJHaQMkox7+nXptfnT2d8mTwXk7Q\n\
z+5dj5SPWg6sZHocWWnW6oEEDB4hKn7fZTCKhdj9y30B4VmTjDvMZO3qdCODdVOS\n\
Yy2HZwECgYEA4SbgT0lpw5UA+rIPzayB397V43HDvd0NVJ0fBuAYIlIYrmRCmMsC\n\
kl384IbMJFotwPXmTRyqQO4ghzW/Xs6RInv78akMwLMpMymJ+G+wi3DocX0PUJiS\n\
ZeUmvYYhbcv34F48TJHG751rr66y5ljXauzIwrlgmhs0pXG+uNV3+CECgYEAtrIJ\n\
hotGAIJmhzbAm0weTuRajJx5+/v1TuJPe/xKG8GpNzLX2UqdtDVXxD79GoaZP+px\n\
hUbaM3P6YPDcXpuUMvn99VgAm6cB7X7wlG3KoBHUseGfDdg1Q+BnJGdWSSWBnxDV\n\
rWqAq9VyKM3Tr8ROyyNmWvoF/bblbL6aMlEXvwsCgYA8v/OYERPjfMnV2sOe2CP2\n\
1rZZdzG8ge993CMqBL8eS45zR4Qcm/ImsgtwPY7JZDeiL/ci6VAa0uWd9eeb2hqY\n\
9mEldFqHiA/eyR98FA7LoPxm2rqOIYymx6yrSIyuhnFsbaDRfCf0MUKEFZwZwPDm\n\
3drRh5lEG4EZ/tXaI2cKYQKBgFg1GXhGYiP40bvS6aeRVsjMZBOjsRnCiqvthGbe\n\
ZoGEPUkTWTfmWMIbRybPKrDV78P2U5z/mnZhNq/7Wsqq3yDFpqIAPTrppXqfYVSo\n\
tb4XHdRMlNjAXOdKv0HKStTCMRU1sZUq6LkOMzIUPnKMm2ZkzxR5xs66sYaReC13\n\
DboFAoGBAITgtHufZPAzCgBP9HnJKMMLqKEGq+svW8SZlrOHsanxHQpUNVVZL2os\n\
+HhqojFwyqbIV/CvBGuf16Tm0AsQ8wCUpwyI/VE65ixxPJo7BoGqgDvhNcCfewWa\n\
26EOBRFbyHdj2tU/wnBKB+H/JsoHF3xsJ9kR+g4tY66a3qru8Cvx\n\
-----END RSA PRIVATE KEY-----";

const JWK_N: &str = "oK444QgMHIoj_ldWgstpV12_bfHnw2iKLklZr5iKnbF0Nl-N2N_cKEG3H6zXkWNFWfjDRxUGXIMQavIiKFtvqYLnlBp_xEIxopBoAqIeVRRXxIkMIVn7ccFbfAFXhqcxwSe5fJA22cXwmpTTMSyaiXuRVc5hhRbHXOP4GAM_8pUZB-Hj6As1-Ev9IXl8_RuZniyiNW7uug-e3PrB7Q8NmQ_ugrhsBQuXloMr3RwGIaeJXW0O0rlVq0HylmtvzOsWfEK47mx8gOWl0dsOnZ_oUXqKsUNMJ3wy9lIWn6m9tvEQDd9wOMU-aEhJj8AtKxRfDy4c65uENQSIhYzxaj9Iaw";
const JWK_E: &str = "AQAB";

#[test]
fn test_config_default_or_missing() {
    let settings = load_security_settings();
    assert!(settings.is_err());
}

#[test]
fn test_crypto_parity() {
    let key = generate_key();
    assert_eq!(key.len(), 32);

    let plaintext = b"datos_secretos_123";
    let tenant_id = "tenant_a";
    let field = "email";

    let encrypted = encrypt_data(&key, plaintext, tenant_id, field, 1).unwrap();

    let decrypted =
        decrypt_data(|_| Ok(key.clone()), &encrypted, tenant_id, field, Some(1)).unwrap();
    assert_eq!(decrypted, plaintext);

    let decrypted_bad_tenant =
        decrypt_data(|_| Ok(key.clone()), &encrypted, "tenant_b", field, Some(1));
    assert!(decrypted_bad_tenant.is_err());

    let decrypted_bad_field = decrypt_data(
        |_| Ok(key.clone()),
        &encrypted,
        tenant_id,
        "password",
        Some(1),
    );
    assert!(decrypted_bad_field.is_err());

    let decrypted_bad_ver =
        decrypt_data(|_| Ok(key.clone()), &encrypted, tenant_id, field, Some(2));
    assert!(decrypted_bad_ver.is_err());
}

#[test]
fn test_kek_dek_hierarchy() {
    let kek = generate_key();
    let dek = generate_key();

    let encrypted_dek = encrypt_dek(&kek, &dek).unwrap();
    let decrypted_dek = decrypt_dek(&kek, &encrypted_dek).unwrap();
    assert_eq!(decrypted_dek, dek);
}

#[test]
fn test_password_hashing() {
    let password = "SuperSecurePassword123!";
    let hashed = hash_password(password).unwrap();

    assert!(verify_password(&hashed, password));
    assert!(!verify_password(&hashed, "wrong_password"));
}

#[test]
fn test_authz_permissions() {
    let roles = vec!["viewer".to_string()];
    let res = check_permission(&roles, Permission::UsersRead);
    assert!(res.is_ok());

    let res_denied = check_permission(&roles, Permission::FinanceRead);
    assert!(res_denied.is_err());

    let roles_admin = vec!["admin".to_string()];
    let res_admin = check_permission(&roles_admin, Permission::FinanceExport);
    assert!(res_admin.is_ok());
}

#[test]
fn test_authz_verify_tenant_idor() {
    let res = verify_tenant("tenant_1", "tenant_1");
    assert!(res.is_ok());

    let res_mismatch = verify_tenant("tenant_1", "tenant_2");
    assert!(res_mismatch.is_err());
    assert_eq!(
        res_mismatch.unwrap_err().to_string(),
        "Recurso no encontrado"
    );
}

#[test]
fn test_http_ssrf_safe_ips() {
    let unsafe_ips = vec![
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        "10.0.0.1".parse::<IpAddr>().unwrap(),
        "192.168.1.1".parse::<IpAddr>().unwrap(),
        "172.16.0.1".parse::<IpAddr>().unwrap(),
        "169.254.169.254".parse::<IpAddr>().unwrap(),
        "::ffff:169.254.169.254".parse::<IpAddr>().unwrap(),
        "::1".parse::<IpAddr>().unwrap(),
        "fc00::1".parse::<IpAddr>().unwrap(),
    ];

    for ip in unsafe_ips {
        assert!(!is_safe_ip(ip), "IP {ip} should be unsafe");
    }

    let safe_ip = "8.8.8.8".parse::<IpAddr>().unwrap();
    assert!(is_safe_ip(safe_ip));
}

#[test]
fn test_webhook_signature_verification() {
    let secret = "whsec_secret_key";
    let body = b"{\"event\":\"user.created\"}";
    let timestamp = "1719878400";

    let verified = verify_webhook_signature(body, secret, "signature", timestamp, 300);
    assert!(!verified);
}

#[test]
fn test_files_filename_sanitization() {
    assert_eq!(sanitize_filename("test/../../../etc/passwd"), "passwd");
    assert_eq!(
        sanitize_filename("valid-name_123.pdf"),
        "valid-name_123.pdf"
    );
    assert_eq!(sanitize_filename(".hidden"), "safe_.hidden");
    assert_eq!(sanitize_filename(""), "unnamed_file");
}

#[test]
fn test_files_csv_cell_formula_sanitization() {
    assert_eq!(sanitize_csv_cell("=SUM(A1:A10)"), "'=SUM(A1:A10)");
    assert_eq!(sanitize_csv_cell("+123"), "'+123");
    assert_eq!(sanitize_csv_cell("-456"), "'-456");
    assert_eq!(sanitize_csv_cell("@hello"), "'@hello");
    assert_eq!(sanitize_csv_cell("\t=SUM(A1:A10)"), "'\t=SUM(A1:A10)");
    assert_eq!(sanitize_csv_cell("\r=SUM(A1:A10)"), "'\r=SUM(A1:A10)");
    assert_eq!(sanitize_csv_cell("\n=SUM(A1:A10)"), "'\n=SUM(A1:A10)");
    assert_eq!(sanitize_csv_cell("normal text"), "normal text");
}

#[tokio::test]
async fn test_password_pwned_real_or_fallback() {
    let pwned = is_password_pwned("123456").await;
    assert!(pwned.is_ok());
    assert!(pwned.unwrap());
}

#[tokio::test]
async fn test_http_ssrf_resolve_unsafe() {
    let res = resolve_and_verify_ssrf("http://127.0.0.1/admin");
    assert!(res.is_err());

    let res_metadata = resolve_and_verify_ssrf("http://169.254.169.254/latest/meta-data");
    assert!(res_metadata.is_err());
}

// === NEW RE-AUDIT TESTS (R-4) ===

#[tokio::test]
async fn test_jwt_validation_cases() {
    // 1. Setup mock server for JWKS
    let mut server = mockito::Server::new_async().await;
    let jwks_url = format!("{}/jwks.json", server.url());

    let jwks_mock = server.mock("GET", "/jwks.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"keys": [{{"kty": "RSA", "kid": "test_key", "use": "sig", "alg": "RS256", "n": "{JWK_N}", "e": "{JWK_E}"}}]}}"#
        ))
        .create_async()
        .await;

    let verifier = TokenVerifier::new(
        jwks_url,
        "https://issuer.com".to_string(),
        "client_id".to_string(),
    );

    // Helper to sign tokens
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();

    let mut extra = serde_json::Map::new();
    extra.insert("roles".to_string(), serde_json::json!(["viewer"]));

    // Case A: Valid token
    let claims = Claims {
        iss: "https://issuer.com".to_string(),
        aud: "client_id".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: Utc::now().timestamp() as u64,
        nbf: (Utc::now() - Duration::minutes(1)).timestamp() as u64,
        sub: "user_123".to_string(),
        extra: extra.clone(),
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test_key".to_string());
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    let verified = verifier.verify_token(&token).await;
    assert!(verified.is_ok());

    // Case B: alg none -> rejection
    let hs_key = jsonwebtoken::EncodingKey::from_secret(b"secret_key_123");
    let mut hs_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    hs_header.kid = Some("test_key".to_string());
    let unsecure_token = jsonwebtoken::encode(&hs_header, &claims, &hs_key).unwrap();
    let verified_unsecure = verifier.verify_token(&unsecure_token).await;
    assert!(verified_unsecure.is_err());

    // Case C: Expired token -> rejection
    let mut claims_expired = claims.clone();
    claims_expired.exp = (Utc::now() - Duration::hours(1)).timestamp() as u64;
    let mut exp_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    exp_header.kid = Some("test_key".to_string());
    let expired_token = jsonwebtoken::encode(&exp_header, &claims_expired, &encoding_key).unwrap();
    let verified_expired = verifier.verify_token(&expired_token).await;
    assert!(verified_expired.is_err());

    // Case D: Mismatched audience -> rejection
    let mut claims_bad_aud = claims.clone();
    claims_bad_aud.aud = "wrong_client_id".to_string();
    let mut aud_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    aud_header.kid = Some("test_key".to_string());
    let bad_aud_token = jsonwebtoken::encode(&aud_header, &claims_bad_aud, &encoding_key).unwrap();
    let verified_bad_aud = verifier.verify_token(&bad_aud_token).await;
    assert!(verified_bad_aud.is_err());

    jwks_mock.assert_async().await;
}

#[tokio::test]
async fn test_jwt_idp_unavailable_503() {
    // 2. Setup mock server that returns 500 Internal Server Error
    let mut server = mockito::Server::new_async().await;
    let jwks_url = format!("{}/jwks.json", server.url());

    let _jwks_mock = server
        .mock("GET", "/jwks.json")
        .with_status(500)
        .create_async()
        .await;

    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();
    let claims = Claims {
        iss: "https://issuer.com".to_string(),
        aud: "client_id".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: Utc::now().timestamp() as u64,
        nbf: (Utc::now() - Duration::minutes(1)).timestamp() as u64,
        sub: "user_123".to_string(),
        extra: serde_json::Map::new(),
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test_key".to_string());
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    let verifier = TokenVerifier::new(
        jwks_url,
        "https://issuer.com".to_string(),
        "client_id".to_string(),
    );
    let verified = verifier.verify_token(&token).await;

    assert!(verified.is_err());
    match verified.unwrap_err() {
        AuthError::IdpUnavailable(_) => {} // Correct! Return 503 fail-closed
        e => panic!("Expected AuthError::IdpUnavailable, got {e:?}"),
    }
}

#[test]
fn test_files_pdf_js_and_encrypted_rejection() {
    // 1. Test encrypted PDF
    let mut doc = lopdf::Document::with_version("1.7");

    let mut encrypt_dict = lopdf::Dictionary::new();
    encrypt_dict.set(
        "Filter",
        lopdf::Object::Name("Standard".as_bytes().to_vec()),
    );
    encrypt_dict.set("V", lopdf::Object::Integer(1));
    encrypt_dict.set("R", lopdf::Object::Integer(2));
    encrypt_dict.set(
        "O",
        lopdf::Object::String(vec![0; 32], lopdf::StringFormat::Hexadecimal),
    );
    encrypt_dict.set(
        "U",
        lopdf::Object::String(vec![0; 32], lopdf::StringFormat::Hexadecimal),
    );
    encrypt_dict.set("P", lopdf::Object::Integer(-4));

    let encrypt_id = doc.add_object(encrypt_dict);
    doc.trailer
        .set("Encrypt", lopdf::Object::Reference(encrypt_id));
    let temp_dir = std::env::temp_dir();
    let encrypted_pdf_path = temp_dir.join("encrypted.pdf");
    doc.save(&encrypted_pdf_path).unwrap();

    let res = process_pdf(encrypted_pdf_path.to_str().unwrap(), 10);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("cifrados"));

    // 2. Test PDF with Names.JavaScript tree
    let mut doc_js = lopdf::Document::with_version("1.7");
    let js_obj_id = doc_js.add_object(lopdf::dictionary! {
        "JavaScript" => lopdf::Object::Null,
    });
    let catalog_id = doc_js.add_object(lopdf::dictionary! {
        "Type" => "Catalog",
        "Names" => lopdf::Object::Reference(js_obj_id),
    });
    doc_js
        .trailer
        .set("Root", lopdf::Object::Reference(catalog_id));
    let js_pdf_path = temp_dir.join("js_names.pdf");
    doc_js.save(&js_pdf_path).unwrap();

    let res_js = process_pdf(js_pdf_path.to_str().unwrap(), 10);
    assert!(res_js.is_err());
    assert!(res_js.unwrap_err().to_string().contains("Names.JavaScript"));
}

#[tokio::test]
async fn test_files_clamav_antivirus_scan() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // 1. Setup Mock clamd server on dynamic local TCP port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut prefix = [0u8; 10];
            let _ = socket.read_exact(&mut prefix).await;
            loop {
                let mut len_bytes = [0u8; 4];
                if socket.read_exact(&mut len_bytes).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_bytes);
                if len == 0 {
                    break;
                }
                let mut chunk = vec![0u8; len as usize];
                if socket.read_exact(&mut chunk).await.is_err() {
                    break;
                }
            }
            let _ = socket
                .write_all(b"stream: Eicar-Test-Signature FOUND\n")
                .await;
        }
    });

    let temp_dir = std::env::temp_dir();

    // Test scan EICAR file
    let eicar_file = temp_dir.join("eicar.txt");
    std::fs::write(
        &eicar_file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();

    let eicar_file_str = eicar_file.to_str().unwrap().to_string();
    let scan_res =
        tokio::task::spawn_blocking(move || scan_antivirus(&eicar_file_str, "127.0.0.1", port))
            .await
            .unwrap();
    assert!(scan_res.is_err());
    assert!(scan_res
        .unwrap_err()
        .to_string()
        .contains("Malware detectado"));

    let _ = handle.await;
}

#[test]
fn test_files_zip_bomb_detection() {
    // 1. Synthetic ZIP bomb exceeding ratio (or entries)
    let temp_dir = std::env::temp_dir();
    let zip_path = temp_dir.join("zip_bomb.zip");

    let file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Add 1001 empty entries (limit is 1000)
    for i in 0..1005 {
        zip.start_file(format!("file_{i}.txt"), options).unwrap();
        zip.write_all(b"").unwrap();
    }
    zip.finish().unwrap();

    let bomb_res = check_zip_bomb(zip_path.to_str().unwrap());
    assert!(bomb_res.is_err());
    assert!(bomb_res
        .unwrap_err()
        .to_string()
        .contains("demasiadas entradas"));
}

#[tokio::test]
async fn test_http_retry_mechanics() {
    let mut server = mockito::Server::new_async().await;
    let mock_url = server.url();

    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = std::sync::Arc::new(AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let get_mock = server
        .mock("GET", "/test-retry")
        .with_status_code_from_request(move |_| {
            if counter_clone.fetch_add(1, Ordering::SeqCst) < 2 {
                503
            } else {
                200
            }
        })
        .with_body("SUCCESS")
        .expect(3)
        .create_async()
        .await;

    let client = SecureClient::new_allowing_loopback().unwrap();
    let res = client
        .request(
            reqwest::Method::GET,
            &format!("{mock_url}/test-retry"),
            reqwest::header::HeaderMap::new(),
            None,
        )
        .await;

    assert!(res.is_ok());
    assert_eq!(res.unwrap().status(), 200);

    get_mock.assert_async().await;

    // 2. POST request: fails immediately on 503 if no Idempotency-Key (R-4)
    let post_mock = server
        .mock("POST", "/test-retry")
        .with_status(503)
        .expect(1) // must be called exactly once (no retry!)
        .create_async()
        .await;

    let res_post = client
        .request(
            reqwest::Method::POST,
            &format!("{mock_url}/test-retry"),
            reqwest::header::HeaderMap::new(),
            Some(b"data".to_vec()),
        )
        .await;

    assert!(res_post.is_ok());
    assert_eq!(res_post.unwrap().status(), 503);

    post_mock.assert_async().await;
}

#[test]
fn test_webhook_extended_signature_verification() {
    let secret = "whsec_secret_key";
    let body = b"{\"event\":\"user.created\"}";

    // Fresh timestamp
    let now_ts = Utc::now().timestamp().to_string();

    // A. Valid signature -> true
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    use hmac::Mac;
    mac.update(now_ts.as_bytes());
    mac.update(b".");
    mac.update(body);
    let signature = hex::encode(mac.finalize().into_bytes());

    let verified = verify_webhook_signature(body, secret, &signature, &now_ts, 300);
    assert!(verified);

    // B. Altered signature -> false
    let verified_altered =
        verify_webhook_signature(body, secret, "invalid_signature", &now_ts, 300);
    assert!(!verified_altered);
}

#[test]
fn test_ssrf_no_env_backdoor() {
    std::env::set_var("ALLOW_LOOPBACK_FOR_TEST", "true");

    use std::net::IpAddr;
    let loopback_v4: IpAddr = "127.0.0.1".parse().unwrap();
    let loopback_v6: IpAddr = "::1".parse().unwrap();
    let metadata_v4: IpAddr = "169.254.169.254".parse().unwrap();
    let metadata_v6: IpAddr = "::ffff:169.254.169.254".parse().unwrap();

    assert!(!seclib_core::http::is_safe_ip(loopback_v4));
    assert!(!seclib_core::http::is_safe_ip(loopback_v6));
    assert!(!seclib_core::http::is_safe_ip(metadata_v4));
    assert!(!seclib_core::http::is_safe_ip(metadata_v6));

    // clean up
    std::env::remove_var("ALLOW_LOOPBACK_FOR_TEST");
}

#[tokio::test]
async fn test_multi_tenant_oidc_resolution() {
    let mut server = mockito::Server::new_async().await;
    let jwks_url = format!("{}/jwks.json", server.url());

    let _jwks_mock = server.mock("GET", "/jwks.json")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"keys": [{{"kty": "RSA", "kid": "tenant_key", "use": "sig", "alg": "RS256", "n": "{JWK_N}", "e": "{JWK_E}"}}]}}"#
        ))
        .create_async()
        .await;

    // Default configs
    let verifier = TokenVerifier::new(
        "http://invalid-default-jwks/jwks.json".to_string(),
        "https://default-issuer.com".to_string(),
        "default_client".to_string(),
    );

    // Register tenant OIDC dynamically
    verifier
        .add_tenant_config(
            "tenant_abc".to_string(),
            jwks_url,
            "https://tenant-issuer.com".to_string(),
            "tenant_client".to_string(),
        )
        .unwrap();

    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY_PEM.as_bytes()).unwrap();
    let mut extra = serde_json::Map::new();
    extra.insert("tenant_id".to_string(), serde_json::json!("tenant_abc"));

    let claims = Claims {
        iss: "https://tenant-issuer.com".to_string(),
        aud: "tenant_client".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: Utc::now().timestamp() as u64,
        nbf: (Utc::now() - Duration::minutes(1)).timestamp() as u64,
        sub: "tenant_user_123".to_string(),
        extra,
    };

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("tenant_key".to_string());
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    let verified = verifier.verify_token(&token).await;
    assert!(verified.is_ok(), "Error verifying: {:?}", verified.err());
    let verified_claims = verified.unwrap();
    assert_eq!(verified_claims.sub, "tenant_user_123");
}

#[tokio::test]
async fn test_egress_allowlist() {
    let client = SecureClient::new_allowing_loopback().unwrap();

    // Whitelist localhost
    let mut whitelist = std::collections::HashSet::new();
    whitelist.insert("localhost".to_string());
    let client = client.with_allowlist(whitelist);

    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/")
        .with_status(200)
        .create_async()
        .await;

    // host is "127.0.0.1" which is not in the whitelist
    let res = client
        .request(
            reqwest::Method::GET,
            &server.url(),
            reqwest::header::HeaderMap::new(),
            None,
        )
        .await;
    assert!(res.is_err());
    match res {
        Err(seclib_core::http::HttpError::EgressBlocked(_)) => {}
        other => panic!("Expected EgressBlocked error, got {other:?}"),
    }
}

#[test]
fn test_ed25519_primitives() {
    let mut key_arr = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key_arr);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let pub_key = signing_key.verifying_key();

    let message = b"hello world license verification";
    let sig = seclib_core::crypto::ed25519_sign(&key_arr, message).unwrap();
    assert_eq!(sig.len(), 64);

    let verified = seclib_core::crypto::ed25519_verify(pub_key.as_bytes(), message, &sig);
    assert!(verified);

    let verified_altered = seclib_core::crypto::ed25519_verify(
        pub_key.as_bytes(),
        b"hello world license verification altered",
        &sig,
    );
    assert!(!verified_altered);
}

#[tokio::test]
async fn test_in_memory_stores() {
    use seclib_core::store::{MemoryRateLimitStore, MemoryStore, RateLimitStore, SessionStore};

    let store = MemoryStore::new();
    assert!(store.get("key1").await.unwrap().is_none());
    store.set("key1", "val1", Some(10)).await.unwrap();
    assert_eq!(store.get("key1").await.unwrap().unwrap(), "val1");
    store.delete("key1").await.unwrap();
    assert!(store.get("key1").await.unwrap().is_none());

    let rl_store = MemoryRateLimitStore::new();
    assert_eq!(rl_store.increment("rl_key", 60).await.unwrap(), 1);
    assert_eq!(rl_store.increment("rl_key", 60).await.unwrap(), 2);
}

#[test]
fn test_mfa_totp() {
    use seclib_core::auth::mfa::{
        generate_totp_secret, get_totp_at_counter, get_totp_uri, verify_totp_code,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    let secret = generate_totp_secret();
    assert!(!secret.is_empty());

    let uri = get_totp_uri(&secret, "user@domain.com", "App");
    assert!(uri.contains(&secret));

    let decoded = seclib_core::auth::mfa::base32_decode(&secret).unwrap();
    let current_counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;

    let current_code = get_totp_at_counter(&decoded, current_counter).unwrap();
    assert_eq!(current_code.len(), 6);

    let is_valid = verify_totp_code(&secret, &current_code, 1);
    assert!(is_valid);
}

#[tokio::test]
async fn test_jwt_issuer_rtr() {
    use base64::Engine;
    use seclib_core::auth::issuer::JwtIssuer;
    use seclib_core::store::MemoryStore;

    let key_bytes = b"super_secret_symmetric_key_for_testing_purposes".to_vec();
    let store = MemoryStore::new();
    let issuer = JwtIssuer::new(
        key_bytes,
        jsonwebtoken::Algorithm::HS256,
        "https://my-issuer.com".to_string(),
        "my-audience".to_string(),
        15, // access_expiry_mins
        7,  // refresh_expiry_days
        15, // mfa_expiry_mins
    );

    // Generate access token
    let access = issuer
        .generate_access_token("user_abc", "tenant_123", &["admin".to_string()], None)
        .unwrap();
    assert!(!access.is_empty());

    // Generate and register refresh token
    let (refresh, jti) = issuer
        .generate_refresh_token("user_abc", "tenant_123")
        .unwrap();
    issuer
        .register_refresh_token(
            &store,
            &jti,
            "user_abc",
            "tenant_123",
            vec!["admin".to_string()],
            None,
            None,
        )
        .await
        .unwrap();

    let parts: Vec<&str> = access.split('.').collect();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(claims.get("sub").unwrap().as_str().unwrap(), "user_abc");
    assert_eq!(
        claims.get("tenant_id").unwrap().as_str().unwrap(),
        "tenant_123"
    );

    // Perform RTR rotation
    let rotation = issuer.rotate_refresh_token(&store, &refresh).await.unwrap();
    assert!(!rotation.access_token.is_empty());
    assert!(!rotation.refresh_token.is_empty());

    // Try to reuse the old refresh token (replay attack) -> should fail (be revoked)
    let replay_res = issuer.rotate_refresh_token(&store, &refresh).await;
    assert!(replay_res.is_err());
}

async fn get_test_db_pool() -> Result<sqlx::PgPool, sqlx::Error> {
    if let Ok(url) = std::env::var("TEST_DATABASE_URL") {
        return sqlx::PgPool::connect(&url).await;
    }
    if let Ok(url) = std::env::var("DATABASE_URL") {
        return sqlx::PgPool::connect(&url).await;
    }
    Err(sqlx::Error::Configuration(
        "TEST_DATABASE_URL or DATABASE_URL env var must be set".into(),
    ))
}

#[tokio::test]
async fn test_rls_isolation_real_postgres() {
    use sqlx::Row;
    let has_env_db =
        std::env::var("TEST_DATABASE_URL").is_ok() || std::env::var("DATABASE_URL").is_ok();
    let pool = match get_test_db_pool().await {
        Ok(p) => p,
        Err(e) => {
            if has_env_db {
                panic!("RLS test database connection failed: {e:?}");
            } else {
                println!("Skipping real postgres RLS test: Database not reachable");
                return;
            }
        }
    };

    // M-13: assert least-privilege role. If current_user were superuser/BYPASSRLS,
    // FORCE ROW LEVEL SECURITY would be bypassed and the isolation checks below would be
    // meaningless (false green). Fail loudly with a clear message instead of skipping.
    let role_row =
        sqlx::query("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&pool)
            .await
            .unwrap();
    let is_super: bool = role_row.get("rolsuper");
    let is_bypassrls: bool = role_row.get("rolbypassrls");
    assert!(
        !is_super && !is_bypassrls,
        "El test RLS requiere un rol NOSUPERUSER NOBYPASSRLS; current_user evade RLS y el test no probaría aislamiento."
    );

    // Create table and enable RLS
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_rls_table (
        id SERIAL PRIMARY KEY,
        tenant_id VARCHAR(50) NOT NULL,
        data VARCHAR(50) NOT NULL
    )",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("ALTER TABLE test_rls_table ENABLE ROW LEVEL SECURITY")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE test_rls_table FORCE ROW LEVEL SECURITY")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("DROP POLICY IF EXISTS test_rls_policy ON test_rls_table")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE POLICY test_rls_policy ON test_rls_table
        USING (tenant_id = current_setting('app.test_tenant_id', true))",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Clean data
    sqlx::query("DELETE FROM test_rls_table")
        .execute(&pool)
        .await
        .unwrap();

    // Test (a): tenant_a context inside a transaction (insert and query)
    let mut tx_a = pool.begin().await.unwrap();
    seclib_core::authz::set_db_session_tenant(&mut tx_a, "tenant_a", "app.test_tenant_id")
        .await
        .unwrap();
    sqlx::query("INSERT INTO test_rls_table (tenant_id, data) VALUES ('tenant_a', 'Data A')")
        .execute(&mut *tx_a)
        .await
        .unwrap();
    let rows_a = sqlx::query("SELECT id, tenant_id, data FROM test_rls_table")
        .fetch_all(&mut *tx_a)
        .await
        .unwrap();
    assert_eq!(rows_a.len(), 1);
    let tenant_id_a: String = rows_a[0].get("tenant_id");
    assert_eq!(tenant_id_a, "tenant_a");
    tx_a.commit().await.unwrap();

    // Test (b): tenant_b context inside another transaction (insert and query)
    let mut tx_b = pool.begin().await.unwrap();
    seclib_core::authz::set_db_session_tenant(&mut tx_b, "tenant_b", "app.test_tenant_id")
        .await
        .unwrap();
    sqlx::query("INSERT INTO test_rls_table (tenant_id, data) VALUES ('tenant_b', 'Data B')")
        .execute(&mut *tx_b)
        .await
        .unwrap();
    let rows_b = sqlx::query("SELECT id, tenant_id, data FROM test_rls_table")
        .fetch_all(&mut *tx_b)
        .await
        .unwrap();
    assert_eq!(rows_b.len(), 1);
    let tenant_id_b: String = rows_b[0].get("tenant_id");
    assert_eq!(tenant_id_b, "tenant_b");
    tx_b.commit().await.unwrap();

    // Test (c): setting empty context (fail-closed) - should see ZERO rows since it enforces POLICY and setting is not active/empty
    let rows_empty = sqlx::query("SELECT id, tenant_id, data FROM test_rls_table")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows_empty.len(), 0);

    // Clean up
    sqlx::query("DROP TABLE test_rls_table")
        .execute(&pool)
        .await
        .unwrap();
}
