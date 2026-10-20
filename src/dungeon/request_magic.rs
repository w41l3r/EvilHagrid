use anyhow::{bail, Result};
use rand::random;

use crate::dungeon::krb_structures::*;
use crate::dungeon::potions;
use crate::dungeon::floo_network;
use crate::dungeon::wand_utils;

pub struct TgtTicket {
    pub kirbi:      Vec<u8>,
    pub session_key: MagicKey,
    pub realm:      String,
    pub client:     String,
    pub start_time:  String,
    pub end_time:    String,
    pub flags:      u32,
}

pub struct TgsTicket {
    pub kirbi:       Vec<u8>,
    pub session_key: MagicKey,
    pub service:     String,
    pub realm:       String,
    pub end_time:    String,
}

// ── AS-REQ (request a TGT) ────────────────────────────────────────────────────

pub fn summon_tgt(
    username: &str,
    domain: &str,
    key: &[u8],
    etype: i32,
    dc: Option<&str>,
) -> Result<TgtTicket> {
    let nonce: u32 = random();
    let cname = Glyph::new_principal(username);
    let padata = vec![Rune::pac_request(true)];

    let as_req = TomeRequest::new_as_req(cname, domain, &[etype], padata, nonce);
    let encoded = as_req.encode();
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp_bytes = floo_network::send_receive_kdc(&dc_addr, &encoded)?;

    if DarkProphecy::is_error(&resp_bytes) {
        let err = DarkProphecy::decode(&resp_bytes)?;
        if err.error_code == KDC_ERR_PREAUTH_REQUIRED {
            return summon_tgt_with_preauth(username, domain, key, etype, &dc_addr, err);
        }
        bail!("AS-REP error {}: {}", err.error_code, error_string(err.error_code));
    }

    parse_as_rep(&resp_bytes, key, etype, username, domain)
}

fn summon_tgt_with_preauth(
    username: &str,
    domain: &str,
    key: &[u8],
    etype: i32,
    dc: &str,
    err: DarkProphecy,
) -> Result<TgtTicket> {
    // extract salt from ETYPE_INFO2 PA-DATA
    let salt = extract_salt_from_error(&err, username, domain, etype);
    let actual_key = if key.len() != key_len_for_etype(etype) {
        // treat key as password string
        let pass = std::str::from_utf8(key).unwrap_or("");
        potions::string_to_key(etype, pass, &salt)?
    } else {
        key.to_vec()
    };

    let now = wand_utils::generalized_time_now();
    let enc_ts = EncTimestamp { patimestamp: now, pausec: Some(0) }.encode();
    let sealed = SealedChamber::new(etype, potions::enchant(etype, &actual_key, KU_AS_REQ_PA_ENC_TIMESTAMP, &enc_ts)?);
    let pa_enc_ts = Rune {
        pa_type: PA_ENC_TIMESTAMP,
        pa_value: sealed.encode(),
    };
    let nonce: u32 = random();
    let cname = Glyph::new_principal(username);
    let padata = vec![Rune::pac_request(true), pa_enc_ts];
    let as_req = TomeRequest::new_as_req(cname, domain, &[etype], padata, nonce);
    let resp_bytes = floo_network::send_receive_kdc(dc, &as_req.encode())?;

    if DarkProphecy::is_error(&resp_bytes) {
        let e = DarkProphecy::decode(&resp_bytes)?;
        bail!("AS-REP error {}: {}", e.error_code, error_string(e.error_code));
    }
    parse_as_rep(&resp_bytes, &actual_key, etype, username, domain)
}

fn parse_as_rep(data: &[u8], key: &[u8], etype: i32, username: &str, domain: &str) -> Result<TgtTicket> {
    let rep = TomeReply::decode(data)?;
    let plaintext = potions::disenchant(rep.enc_part.etype, key, KU_AS_REP_ENC_PART, &rep.enc_part.cipher)?;
    let mut ep = DerParser::new(&plaintext);
    let inner = ep.expect_tag(TAG_ENC_AS_REP_PART)?;
    let mut p = DerParser::new(inner);
    let mut seq = p.enter_sequence()?;
    let session_key_bytes = seq.slice_ctx(0)?;
    let session_key = MagicKey::decode(session_key_bytes)?;
    // skip last-req [1], nonce [2], key-expiration [3] (optional)
    while !seq.is_empty() && seq.peek_tag().map_or(false, |t| t < ctx_tag(5)) {
        let _ = seq.read_tlv()?;
    }
    let flags = if seq.peek_tag() == Some(ctx_tag(5)) {
        seq.enter_ctx(5)?.read_bit_string_flags()?
    } else { TF_FORWARDABLE };
    let auth_time = if seq.peek_tag() == Some(ctx_tag(6)) {
        seq.enter_ctx(6)?.read_generalized_time()?
    } else { wand_utils::generalized_time_now() };
    let start_time = if seq.peek_tag() == Some(ctx_tag(7)) {
        seq.enter_ctx(7)?.read_generalized_time()?
    } else { auth_time.clone() };
    let end_time = if seq.peek_tag() == Some(ctx_tag(8)) {
        seq.enter_ctx(8)?.read_generalized_time()?
    } else { wand_utils::now_plus_hours(10) };

    let ticket = Scroll::decode(&rep.ticket)?;
    let cred_info = KrbCredInfo {
        key: session_key.clone(),
        prealm: Some(domain.to_ascii_uppercase()),
        pname: Some(Glyph::new_principal(username)),
        flags: Some(flags),
        auth_time: Some(auth_time),
        start_time: Some(start_time.clone()),
        end_time: Some(end_time.clone()),
        renew_till: None,
        srealm: Some(domain.to_ascii_uppercase()),
        sname: Some(ticket.sname.clone()),
    };
    let kirbi = build_kirbi(&ticket, cred_info);
    Ok(TgtTicket { kirbi, session_key, realm: domain.to_ascii_uppercase(), client: username.to_owned(), start_time, end_time, flags })
}

// ── TGS-REQ ────────────────────────────────────────────────────────────────────

pub fn fetch_service_ticket(
    tgt_kirbi: &[u8],
    spn: &str,
    domain: &str,
    request_etype: i32,
    dc: Option<&str>,
) -> Result<TgsTicket> {
    // Parse TGT from kirbi
    let (tgt_ticket, session_key) = parse_kirbi_tgt(tgt_kirbi)?;
    let nonce: u32 = random();
    let (svc, _host) = wand_utils::parse_spn(spn);
    let sname = if svc.to_lowercase() == "krbtgt" {
        Glyph::new_krbtgt(domain)
    } else {
        let parts: Vec<&str> = spn.splitn(2, '/').collect();
        if parts.len() == 2 {
            Glyph { kind: NT_SRV_INST, parts: parts.iter().map(|s| s.to_string()).collect() }
        } else {
            Glyph::new_principal(spn)
        }
    };

    // build AP-REQ authenticator
    let ap_req = build_ap_req(&tgt_ticket, &session_key, nonce)?;
    let pa_tgs = Rune::tgs_req(&ap_req);
    let tgs_req = TomeRequest::new_tgs_req(domain, sname, &[request_etype], vec![pa_tgs], nonce);

    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp_bytes = floo_network::send_receive_kdc(&dc_addr, &tgs_req.encode())?;

    if DarkProphecy::is_error(&resp_bytes) {
        let e = DarkProphecy::decode(&resp_bytes)?;
        bail!("TGS-REP error {}: {}", e.error_code, error_string(e.error_code));
    }
    parse_tgs_rep(&resp_bytes, &session_key, spn, domain)
}

fn parse_tgs_rep(data: &[u8], session_key: &MagicKey, spn: &str, domain: &str) -> Result<TgsTicket> {
    let rep = TomeReply::decode(data)?;
    let key_usage = KU_TGS_REP_ENC_PART_SESS;
    let plaintext = potions::disenchant(session_key.keytype, &session_key.keyvalue, key_usage, &rep.enc_part.cipher)?;
    let mut ep = DerParser::new(&plaintext);
    let inner = ep.expect_tag(TAG_ENC_TGS_REP_PART)?;
    let mut p = DerParser::new(inner);
    let mut seq = p.enter_sequence()?;
    let svc_session_key_bytes = seq.slice_ctx(0)?;
    let svc_session_key = MagicKey::decode(svc_session_key_bytes)?;
    while !seq.is_empty() && seq.peek_tag().map_or(false, |t| t < ctx_tag(8)) {
        let _ = seq.read_tlv()?;
    }
    let end_time = if seq.peek_tag() == Some(ctx_tag(8)) {
        seq.enter_ctx(8)?.read_generalized_time()?
    } else { wand_utils::now_plus_hours(8) };

    let ticket = Scroll::decode(&rep.ticket)?;
    let cred_info = KrbCredInfo {
        key: svc_session_key.clone(),
        prealm: Some(rep.crealm.clone()),
        pname: Some(rep.cname.clone()),
        flags: None,
        auth_time: None,
        start_time: None,
        end_time: Some(end_time.clone()),
        renew_till: None,
        srealm: Some(domain.to_ascii_uppercase()),
        sname: Some(ticket.sname.clone()),
    };
    let kirbi = build_kirbi(&ticket, cred_info);
    Ok(TgsTicket { kirbi, session_key: svc_session_key, service: spn.to_owned(), realm: domain.to_ascii_uppercase(), end_time })
}

fn build_ap_req(ticket: &Scroll, session_key: &MagicKey, nonce: u32) -> Result<Vec<u8>> {
    // Authenticator body
    let now = wand_utils::generalized_time_now();
    // cutime microseconds — use 0 for simplicity
    let auth_inner = [
        encode_ctx(0, &encode_uint32(5)),   // authenticator-vno
        encode_ctx(1, &encode_general_string(&ticket.realm)),
        encode_ctx(2, &ticket.sname.encode()), // cname placeholder (sname is fine for TGS-REQ)
        encode_ctx(4, &encode_generalized_time(&now)),
        encode_ctx(5, &encode_uint32(0)),   // cusec
    ]
    .concat();
    let authenticator_plain = tlv(TAG_AUTHENTICATOR, &encode_sequence(&auth_inner));
    let sealed_auth = SealedChamber::new(
        session_key.keytype,
        potions::enchant(session_key.keytype, &session_key.keyvalue, KU_TGS_REQ_AUTH, &authenticator_plain)?,
    );
    let ap_req_inner = [
        encode_ctx(0, &encode_uint32(5)),   // pvno
        encode_ctx(1, &encode_uint32(14)),  // msg-type AP-REQ
        encode_ctx(2, &encode_bit_string_flags(0)), // ap-options
        encode_ctx(3, &ticket.encode()),
        encode_ctx(4, &sealed_auth.encode()),
    ]
    .concat();
    Ok(tlv(TAG_AP_REQ, &encode_sequence(&ap_req_inner)))
}

pub fn parse_kirbi_tgt_pub(kirbi: &[u8]) -> Result<(Scroll, MagicKey)> {
    parse_kirbi_tgt(kirbi)
}

fn parse_kirbi_tgt(kirbi: &[u8]) -> Result<(Scroll, MagicKey)> {
    // KRB-CRED: APPLICATION 22 SEQUENCE { pvno, msg-type, tickets, enc-part }
    let mut p = DerParser::new(kirbi);
    let raw = p.expect_tag(TAG_KRB_CRED)?;
    let mut outer = DerParser::new(raw);
    let mut seq = outer.enter_sequence()?;
    seq.enter_ctx(0)?.read_uint32()?; // pvno
    seq.enter_ctx(1)?.read_uint32()?; // msg-type
    let tickets_raw = seq.slice_ctx(2)?;
    let mut tseq = DerParser::new(tickets_raw);
    let mut tlist = tseq.enter_sequence()?;
    let (_, ticket_bytes) = tlist.read_tlv()?;
    let mut wrapped = vec![TAG_TICKET];
    let tlen = encode_length(ticket_bytes.len());
    wrapped.extend_from_slice(&tlen);
    wrapped.extend_from_slice(ticket_bytes);
    let ticket = Scroll::decode_from_bytes(&wrapped)?;

    // enc-part of KRB-CRED is unencrypted in this context (etype=0)
    let enc_raw = seq.slice_ctx(3)?;
    let enc = SealedChamber::decode(enc_raw)?;
    // enc.cipher contains APPLICATION 29 (EncKrbCredPart)
    let mut cp = DerParser::new(&enc.cipher);
    let cred_raw = cp.expect_tag(0x7d)?;
    let mut cseq = DerParser::new(cred_raw);
    let mut cseq2 = cseq.enter_sequence()?;
    let infos_raw = cseq2.enter_ctx(0)?.enter_sequence()?;
    // first CredInfo
    let info_bytes = {
        let mut ip = infos_raw;
        let (_, b) = ip.read_tlv()?;
        b.to_vec()
    };
    let mut ip = DerParser::new(&info_bytes);
    let mut info_seq = ip.enter_sequence()?;
    let key_bytes = info_seq.slice_ctx(0)?;
    let session_key = MagicKey::decode(key_bytes)?;
    Ok((ticket, session_key))
}

fn extract_salt_from_error(err: &DarkProphecy, username: &str, domain: &str, etype: i32) -> String {
    if let Some(ref e_data) = err.e_data {
        let mut p = DerParser::new(e_data);
        if let Ok(mut seq) = p.enter_sequence() {
            while !seq.is_empty() {
                if let Ok((_, bytes)) = seq.read_tlv() {
                    let mut ep = DerParser::new(bytes);
                    if let Ok(pa_type) = ep.enter_ctx(0).and_then(|mut p| p.read_integer_i32()) {
                        if pa_type == PA_ETYPE_INFO2 {
                            if let Ok(pa_val) = ep.enter_ctx(1).and_then(|mut p| p.read_octet_string()) {
                                if let Ok(entries) = EtypeInfo2Entry::decode_list(&pa_val) {
                                    for e in entries {
                                        if e.etype == etype {
                                            if let Some(s) = e.salt { return s; }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    potions::kerberos_salt(username, domain)
}

fn key_len_for_etype(etype: i32) -> usize {
    match etype {
        ETYPE_RC4_HMAC => 16,
        ETYPE_AES128_CTS_HMAC_SHA1_96 => 16,
        ETYPE_AES256_CTS_HMAC_SHA1_96 => 32,
        _ => 0,
    }
}
