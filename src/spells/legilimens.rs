use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::dungeon::display_charm::*;
use crate::dungeon::krb_structures::*;
use crate::dungeon::wand_utils;

pub struct Legilimens;

impl super::Spell for Legilimens {
    fn incantation(&self) -> &'static str { "legilimens" }
    fn grimoire(&self) -> &'static str {
        "Parse and display a Kerberos ticket. /ticket: (base64 kirbi)"
    }

    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let b64 = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let raw = wand_utils::b64_to_kirbi(b64)?;
        describe_kirbi(&raw)
    }
}

pub fn describe_kirbi(data: &[u8]) -> Result<()> {
    let mut p = DerParser::new(data);
    let raw = p.expect_tag(TAG_KRB_CRED)?;
    let mut outer = DerParser::new(raw);
    let mut seq = outer.enter_sequence()?;
    seq.enter_ctx(0)?.read_uint32()?;
    seq.enter_ctx(1)?.read_uint32()?;
    let tickets_raw = seq.slice_ctx(2)?;
    let mut tseq = DerParser::new(tickets_raw);
    let mut tlist = tseq.enter_sequence()?;

    print_banner("Ticket Contents");
    let mut ticket_num = 0;
    while !tlist.is_empty() {
        ticket_num += 1;
        let (_, tkt_bytes) = tlist.read_tlv()?;
        let mut wt = vec![TAG_TICKET];
        wt.extend_from_slice(&encode_length(tkt_bytes.len()));
        wt.extend_from_slice(tkt_bytes);
        match Scroll::decode_from_bytes(&wt) {
            Ok(ticket) => {
                println!("  [Ticket #{}]", ticket_num);
                print_info("  ServiceName", &ticket.sname.to_string());
                print_info("  ServiceRealm", &ticket.realm);
                print_info("  EncryptionType", etype_string(ticket.enc_part.etype));
                if let Some(kvno) = ticket.enc_part.kvno {
                    print_info("  KVNO", &kvno.to_string());
                }
            }
            Err(e) => print_warning(&format!("ticket {} parse error: {}", ticket_num, e)),
        }
    }

    let enc_raw = seq.slice_ctx(3)?;
    let enc = SealedChamber::decode(enc_raw)?;
    let mut cp = DerParser::new(&enc.cipher);
    if let Ok(cred_raw) = cp.expect_tag(0x7d) {
        let mut cseq = DerParser::new(cred_raw);
        if let Ok(mut cseq2) = cseq.enter_sequence() {
            if let Ok(mut infos) = cseq2.enter_ctx(0).and_then(|mut p| p.enter_sequence()) {
                let mut info_num = 0;
                while !infos.is_empty() {
                    info_num += 1;
                    if let Ok((_, info_bytes)) = infos.read_tlv() {
                        let mut ip = DerParser::new(info_bytes);
                        if let Ok(mut info_seq) = ip.enter_sequence() {
                            println!("  [CredInfo #{}]", info_num);
                            if let Ok(key_bytes) = info_seq.slice_ctx(0).map(|b| b.to_vec()) {
                                if let Ok(key) = MagicKey::decode(&key_bytes) {
                                    print_info("  SessionKeyType", etype_string(key.keytype));
                                    print_info("  SessionKey", &wand_utils::bytes_to_hex(&key.keyvalue));
                                }
                            }
                            if info_seq.peek_tag() == Some(ctx_tag(1)) {
                                if let Ok(realm) = info_seq.enter_ctx(1).and_then(|mut p| p.read_general_string()) {
                                    print_info("  ClientRealm", &realm);
                                }
                            }
                            if info_seq.peek_tag() == Some(ctx_tag(2)) {
                                if let Ok(pname_bytes) = info_seq.slice_ctx(2).map(|b| b.to_vec()) {
                                    if let Ok(pname) = Glyph::decode(&pname_bytes) {
                                        print_info("  ClientName", &pname.to_string());
                                    }
                                }
                            }
                            if info_seq.peek_tag() == Some(ctx_tag(5)) {
                                if let Ok(st) = info_seq.enter_ctx(5).and_then(|mut p| p.read_generalized_time()) {
                                    print_info("  StartTime", &st);
                                }
                            }
                            if info_seq.peek_tag() == Some(ctx_tag(6)) {
                                if let Ok(et) = info_seq.enter_ctx(6).and_then(|mut p| p.read_generalized_time()) {
                                    print_info("  EndTime", &et);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
