use anyhow::{bail, Result};
use rand::random;

use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::request_magic::parse_kirbi_tgt_pub;

pub fn renew_ticket(tgt_kirbi: &[u8], domain: &str, dc: Option<&str>) -> Result<Vec<u8>> {
    let (ticket, session_key, cname) = parse_kirbi_tgt_pub(tgt_kirbi)?;
    let nonce: u32 = random();
    let sname = ticket.sname.clone();
    let ap_req = build_renew_ap_req(&ticket, &session_key, &cname, nonce)?;
    let pa_tgs = Rune::tgs_req(&ap_req);
    let mut tgs_req = TomeRequest::new_tgs_req(domain, sname, &[ETYPE_RC4_HMAC, ETYPE_AES256_CTS_HMAC_SHA1_96], vec![pa_tgs], nonce);
    tgs_req.body.kdc_options |= KDC_OPT_RENEW | KDC_OPT_RENEWABLE;

    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp = floo_network::send_receive_kdc(&dc_addr, &tgs_req.encode())?;
    if DarkProphecy::is_error(&resp) {
        let e = DarkProphecy::decode(&resp)?;
        bail!("renewal error {}: {}", e.error_code, error_string(e.error_code));
    }
    Ok(resp)
}

fn build_renew_ap_req(ticket: &Scroll, session_key: &MagicKey, cname: &Glyph, nonce: u32) -> Result<Vec<u8>> {
    use crate::dungeon::potions;
    use crate::dungeon::wand_utils;
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
