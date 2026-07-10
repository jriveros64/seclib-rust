use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use sha1::Sha1;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

pub fn base32_decode(src: &str) -> Option<Vec<u8>> {
    let src = src.trim_end_matches('=');
    let mut dst = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for c in src.chars() {
        let val = match c.to_ascii_uppercase() {
            'A'..='Z' => c as u8 - b'A',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | (val as u32);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            dst.push((buffer >> bits) as u8);
        }
    }
    Some(dst)
}

pub fn base32_encode(src: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut dst = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for &b in src {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = (buffer >> bits) & 0x1f;
            dst.push(alphabet[idx as usize] as char);
        }
    }
    if bits > 0 {
        let idx = (buffer << (5 - bits)) & 0x1f;
        dst.push(alphabet[idx as usize] as char);
    }
    dst
}

fn url_encode(s: &str) -> String {
    let mut encoded = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{b:02X}"));
            }
        }
    }
    encoded
}

pub fn generate_totp_secret() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 20];
    rng.fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

pub fn get_totp_uri(secret_base32: &str, label: &str, issuer: &str) -> String {
    let encoded_label = url_encode(label);
    let encoded_issuer = url_encode(issuer);
    format!("otpauth://totp/{encoded_label}?secret={secret_base32}&issuer={encoded_issuer}")
}

pub fn get_totp_at_counter(secret_bytes: &[u8], counter: u64) -> Result<String, String> {
    let mut mac =
        HmacSha1::new_from_slice(secret_bytes).map_err(|e| format!("Invalid HMAC key: {e}"))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0xf) as usize;
    let code = (((result[offset] & 0x7f) as u32) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let code_mod = code % 1_000_000;
    Ok(format!("{code_mod:06}"))
}

pub fn verify_totp_code(secret_base32: &str, code: &str, window_steps: i64) -> bool {
    let clean_code = code.trim();
    if clean_code.len() != 6 || !clean_code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let secret_bytes = match base32_decode(secret_base32) {
        Some(b) => b,
        None => return false,
    };

    let now_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return false,
    };

    let current_counter = now_secs / 30;

    for i in -window_steps..=window_steps {
        let counter = if i < 0 {
            current_counter.saturating_sub((-i) as u64)
        } else {
            current_counter.saturating_add(i as u64)
        };
        if let Ok(expected_code) = get_totp_at_counter(&secret_bytes, counter) {
            use subtle::ConstantTimeEq;
            if expected_code
                .as_bytes()
                .ct_eq(clean_code.as_bytes())
                .unwrap_u8()
                == 1
            {
                return true;
            }
        }
    }

    false
}

pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let part1: u32 = rng.gen();
        let part2: u32 = rng.gen();
        codes.push(format!("{part1:08x}-{part2:08x}"));
    }
    codes
}

pub fn normalize_recovery_code(code: &str) -> String {
    code.trim().to_lowercase().replace(['-', ' '], "")
}
pub fn hash_recovery_code(code: &str) -> String {
    let normalized = normalize_recovery_code(code);
    use hmac::Hmac;
    type HmacSha256 = Hmac<Sha256>;
    let salt = b"seclib_recovery_code_salt_constant";
    // justificado: HMAC keys can be of any size so new_from_slice cannot fail
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC keys can be of any size");
    mac.update(normalized.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
