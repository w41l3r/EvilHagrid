use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::dungeon::display_charm::*;
use crate::dungeon::potions;
use crate::dungeon::request_magic;
use crate::dungeon::key_ceremony;
use crate::dungeon::wand_utils;
use crate::dungeon::krb_structures::constants::*;

pub struct AccioTgt;

impl super::Spell for AccioTgt {
    fn incantation(&self) -> &'static str { "accio-tgt" }
    fn grimoire(&self) -> &'static str {
        "Request a TGT. /user: /domain: /password: or /rc4: or /aes256: \
        or /certificate:<pem_file> /certificatekey:<pem_file> [/dc:] [/outfile:]"
    }

    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let user   = args.get("user").ok_or_else(|| anyhow::anyhow!("/user: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc     = args.get("dc").map(|s| s.as_str());

        // PKINIT path
        if let Some(cert_path) = args.get("certificate") {
            let key_path = args.get("certificatekey")
                .ok_or_else(|| anyhow::anyhow!("/certificatekey:<pem_file> required with /certificate:"))?;
            let cert_pem = std::fs::read_to_string(cert_path)?;
            let key_pem  = std::fs::read_to_string(key_path)?;
            let etype = if args.contains_key("aes128") {
                ETYPE_AES128_CTS_HMAC_SHA1_96
            } else if args.contains_key("rc4") {
                ETYPE_RC4_HMAC
            } else {
                ETYPE_AES256_CTS_HMAC_SHA1_96
            };

            print_banner(&format!("PKINIT — summoning TGT for {}@{}", user, domain));
            let tgt = key_ceremony::pkinit_as_req(user, domain, &cert_pem, &key_pem, etype, dc)?;
            let b64 = wand_utils::kirbi_to_b64(&tgt.kirbi);
            print_success(&format!("TGT issued  start={} end={}", tgt.start_time, tgt.end_time));
            print_info("ServiceName", "krbtgt");
            print_info("EncryptionKey", &wand_utils::bytes_to_hex(&tgt.session_key.keyvalue));
            println!();
            println!("{}", b64);
            println!();
            if let Some(outfile) = args.get("outfile") {
                std::fs::write(outfile, &tgt.kirbi)?;
                print_success(&format!("Written to {}", outfile));
            }
            return Ok(());
        }

        let (key, etype) = resolve_key(args, user, domain)?;
        print_banner(&format!("Summoning TGT for {}@{}", user, domain));

        let tgt = request_magic::summon_tgt(user, domain, &key, etype, dc)?;
        let b64 = wand_utils::kirbi_to_b64(&tgt.kirbi);

        print_success(&format!("TGT issued  start={} end={}", tgt.start_time, tgt.end_time));
        print_info("ServiceName", "krbtgt");
        print_info("EncryptionKey", &wand_utils::bytes_to_hex(&tgt.session_key.keyvalue));
        println!();
        println!("{}", b64);
        println!();

        if let Some(outfile) = args.get("outfile") {
            std::fs::write(outfile, &tgt.kirbi)?;
            print_success(&format!("Written to {}", outfile));
        }
        Ok(())
    }
}

pub fn resolve_key(
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
        let etype = if args.contains_key("aes") {
            ETYPE_AES256_CTS_HMAC_SHA1_96
        } else {
            ETYPE_RC4_HMAC
        };
        let salt = potions::kerberos_salt(user, domain);
        let key = potions::string_to_key(etype, password, &salt)?;
        return Ok((key, etype));
    }
    bail!("/password: or /rc4: or /aes256: required")
}
