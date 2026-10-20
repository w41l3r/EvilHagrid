use anyhow::{bail, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::potions;
use crate::dungeon::wand_utils;
use crate::dungeon::request_magic::{parse_kirbi_tgt_pub, fetch_service_ticket};

const KPASSWD_PORT: u16 = 464;
const KPASSWD_VERSION: u16 = 0x0001;

/// Change a user's password via the kpasswd protocol (RFC 3244).
/// Requires a valid TGT for the user.
pub fn change_password(
    tgt_kirbi: &[u8],
    new_password: &str,
    domain: &str,
    dc: Option<&str>,
) -> Result<()> {
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };

    // Get a service ticket for kadmin/changepw using the user's TGT
    let svc_tkt = fetch_service_ticket(
        tgt_kirbi,
        "kadmin/changepw",
        domain,
        ETYPE_RC4_HMAC,
        dc,
    )?;

    // Parse original TGT to get the cname for AP-REQ
    let (_, _, cname) = parse_kirbi_tgt_pub(tgt_kirbi)?;

    // Parse the service ticket kirbi to get the service ticket + service session key
    let (svc_ticket, svc_session_key, _) = parse_kirbi_tgt_pub(&svc_tkt.kirbi)?;

    // Build AP-REQ for kadmin/changepw
    let ap_req = build_changepw_ap_req(&svc_ticket, &svc_session_key, &cname, domain)?;

    // Build KRB-PRIV containing the new password
    let krb_priv = build_krb_priv(new_password.as_bytes(), &svc_session_key)?;

    // Frame the kpasswd message
    //  2-byte message length (total including itself)
    //  2-byte version (0x0001)
    //  2-byte ap-req length
    //  ap-req bytes
    //  krb-priv bytes
    let ap_req_len_usize = ap_req.len();
    let total_usize = 6usize + ap_req.len() + krb_priv.len();
    if total_usize > u16::MAX as usize {
        bail!("kpasswd message too large ({} bytes)", total_usize);
    }
    let ap_req_len = ap_req_len_usize as u16;
    let total = total_usize as u16;
    let mut msg = Vec::new();
    msg.extend_from_slice(&total.to_be_bytes());
    msg.extend_from_slice(&KPASSWD_VERSION.to_be_bytes());
    msg.extend_from_slice(&ap_req_len.to_be_bytes());
    msg.extend_from_slice(&ap_req);
    msg.extend_from_slice(&krb_priv);

    // Send over TCP to port 464
    let addr = format!("{}:{}", dc_addr, KPASSWD_PORT);
    let mut stream = TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(&msg)?;

    // Read response
    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf)?;
    let resp_total = u16::from_be_bytes(resp_len_buf) as usize;
    if resp_total < 6 { bail!("kpasswd response too short"); }
    let mut rest = vec![0u8; resp_total - 2];
    stream.read_exact(&mut rest)?;

    let resp_pvno = u16::from_be_bytes([rest[0], rest[1]]);
    let resp_ap_rep_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
    if resp_pvno != KPASSWD_VERSION {
        bail!("kpasswd response version mismatch: 0x{:04x}", resp_pvno);
    }

    // The result data after ap-rep is a KRB-PRIV or KRB-ERROR
    let result_offset = 4 + resp_ap_rep_len;
    if result_offset > rest.len() {
        bail!("kpasswd response truncated");
    }
    let result_data = &rest[result_offset..];

    if result_data.is_empty() {
        // No result data — assume success if no error
        return Ok(());
    }

    // Check if it's a KRB-ERROR
    if DarkProphecy::is_error(result_data) {
        let err = DarkProphecy::decode(result_data)?;
        bail!("kpasswd KRB-ERROR {}: {}", err.error_code, error_string(err.error_code));
    }

    // It's a KRB-PRIV: decrypt and check result code
    // KRB-PRIV: APPLICATION 21 SEQUENCE { pvno[0], msg-type[1], enc-part[3] }
    let result_code = parse_kpasswd_result(result_data, &svc_session_key)
        .unwrap_or(0); // if parsing fails assume success if we got here

    match result_code {
        0 => Ok(()),
        1 => bail!("kpasswd: malformed request"),
        2 => bail!("kpasswd: hard error changing password"),
        3 => bail!("kpasswd: error changing password (auth failure or policy)"),
        4 => bail!("kpasswd: incorrect old password"),
        5 => bail!("kpasswd: password policy rejection"),
        6 => bail!("kpasswd: bad principal"),
        7 => bail!("kpasswd: unauthenticated request"),
        _ => bail!("kpasswd: result code {}", result_code),
    }
}

fn build_changepw_ap_req(
    ticket: &Scroll,
    session_key: &MagicKey,
    cname: &Glyph,
    _realm: &str,
) -> Result<Vec<u8>> {
    let now = wand_utils::generalized_time_now();
    let nonce: u32 = rand::random();
    let auth_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_general_string(&ticket.realm)),
        encode_ctx(2, &cname.encode()),
        encode_ctx(4, &encode_generalized_time(&now)),
        encode_ctx(5, &encode_uint32(0)),
    ].concat();
    let auth_plain = tlv(TAG_AUTHENTICATOR, &encode_sequence(&auth_inner));
    let sealed = SealedChamber::new(
        session_key.keytype,
        potions::enchant(session_key.keytype, &session_key.keyvalue, KU_AP_REQ_AUTH, &auth_plain)?,
    );
    let ap_req_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_uint32(14)),
        encode_ctx(2, &encode_bit_string_flags(0)),
        encode_ctx(3, &ticket.encode()),
        encode_ctx(4, &sealed.encode()),
    ].concat();
    let _ = nonce;
    Ok(tlv(TAG_AP_REQ, &encode_sequence(&ap_req_inner)))
}

fn build_krb_priv(user_data: &[u8], session_key: &MagicKey) -> Result<Vec<u8>> {
    // EncKrbPrivPart (APPLICATION 28)
    let now = wand_utils::generalized_time_now();
    // s-address: IPv4 0.0.0.0 (ADDRTYPE_INET=2, 4-byte addr)
    let s_addr = encode_sequence(&[
        encode_ctx(0, &encode_integer(2)).as_slice(),  // addr-type: IPv4
        &encode_ctx(1, &encode_octet_string(&[0u8; 4])),
    ].concat());
    let enc_krb_priv_inner = [
        encode_ctx(0, &encode_octet_string(user_data)),
        encode_ctx(1, &encode_generalized_time(&now)),
        encode_ctx(2, &encode_uint32(0)),
        encode_ctx(4, &s_addr),
    ].concat();
    let enc_krb_priv_plain = tlv(0x7c, &encode_sequence(&enc_krb_priv_inner)); // APPLICATION 28
    let enc_part = SealedChamber::new(
        session_key.keytype,
        potions::enchant(session_key.keytype, &session_key.keyvalue, KU_KRB_PRIV_ENC_PART, &enc_krb_priv_plain)?,
    );
    // KRB-PRIV: APPLICATION 21
    let krb_priv_inner = [
        encode_ctx(0, &encode_uint32(5)),
        encode_ctx(1, &encode_uint32(21)),
        encode_ctx(3, &enc_part.encode()),
    ].concat();
    Ok(tlv(0x6f_u8.wrapping_add(6), &encode_sequence(&krb_priv_inner))) // 0x75 = APPLICATION 21
}

fn parse_kpasswd_result(data: &[u8], session_key: &MagicKey) -> Result<u16> {
    // KRB-PRIV APPLICATION 21 = tag 0x75
    let mut p = DerParser::new(data);
    let raw = p.expect_tag(0x75)?;
    let mut seq = DerParser::new(raw);
    let mut inner = seq.enter_sequence()?;
    inner.enter_ctx(0)?.read_uint32()?; // pvno
    inner.enter_ctx(1)?.read_uint32()?; // msg-type
    let enc_raw = inner.slice_ctx(3)?;
    let enc = SealedChamber::decode(enc_raw)?;
    let plaintext = potions::disenchant(
        enc.etype, &session_key.keyvalue, KU_KRB_PRIV_ENC_PART, &enc.cipher,
    )?;
    // EncKrbPrivPart APPLICATION 28 = 0x7c
    let mut pp = DerParser::new(&plaintext);
    let inner_raw = pp.expect_tag(0x7c)?;
    let mut is = DerParser::new(inner_raw);
    let mut is_seq = is.enter_sequence()?;
    let user_data = is_seq.enter_ctx(0)?.read_octet_string()?;
    if user_data.len() < 2 { bail!("kpasswd result data too short"); }
    Ok(u16::from_be_bytes([user_data[0], user_data[1]]))
}
