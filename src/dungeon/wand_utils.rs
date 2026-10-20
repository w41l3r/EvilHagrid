use anyhow::{bail, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_start_matches("0x").replace(':', "").replace(' ', "");
    if s.len() % 2 != 0 { bail!("odd hex length"); }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn bytes_to_hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02X}", x)).collect()
}

pub fn b64_encode(b: &[u8]) -> String {
    B64.encode(b)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let clean = s.replace(['\n', '\r', ' '], "");
    B64.decode(&clean).map_err(Into::into)
}

pub fn parse_key_arg(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.contains(':') || (s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())) {
        hex_to_bytes(s)
    } else if s.len() % 4 == 0 && s.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') {
        b64_decode(s)
    } else {
        bail!("key must be hex or base64");
    }
}

pub fn kirbi_to_b64(raw: &[u8]) -> String {
    b64_encode(raw)
}

pub fn b64_to_kirbi(s: &str) -> Result<Vec<u8>> {
    b64_decode(s)
}

pub fn now_plus_hours(h: i64) -> String {
    let ts = chrono::Utc::now() + chrono::Duration::hours(h);
    ts.format("%Y%m%d%H%M%SZ").to_string()
}

pub fn now_minus_seconds(s: i64) -> String {
    let ts = chrono::Utc::now() - chrono::Duration::seconds(s);
    ts.format("%Y%m%d%H%M%SZ").to_string()
}

pub fn generalized_time_now() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string()
}

pub fn random_nonce() -> u32 {
    rand::random()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn parse_spn(spn: &str) -> (String, String) {
    // MSSQLSvc/host.domain.com:1433  → ("MSSQLSvc", "host.domain.com")
    // HOST/dc01.corp.local           → ("HOST", "dc01.corp.local")
    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    if parts.len() == 2 {
        let host_part = parts[1].split(':').next().unwrap_or(parts[1]);
        (parts[0].to_owned(), host_part.to_owned())
    } else {
        (spn.to_owned(), String::new())
    }
}

pub fn domain_from_username(username: &str) -> Option<(&str, &str)> {
    if let Some(idx) = username.find('@') {
        Some((&username[..idx], &username[idx + 1..]))
    } else if let Some(idx) = username.find('\\') {
        Some((&username[idx + 1..], &username[..idx]))
    } else {
        None
    }
}
