use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::dungeon::display_charm::*;
use crate::dungeon::potions;
use crate::dungeon::wand_utils;
use crate::dungeon::krb_structures::constants::*;

pub struct Transfigure;

impl super::Spell for Transfigure {
    fn incantation(&self) -> &'static str { "transfigure" }
    fn grimoire(&self) -> &'static str {
        "Compute Kerberos key hashes. /password: /user: /domain: [/dc:]"
    }

    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let password = args.get("password").ok_or_else(|| anyhow::anyhow!("/password: required"))?;
        let user     = args.get("user");
        let domain   = args.get("domain");

        print_banner("Key Transfiguration");
        let rc4 = potions::brew_nt_hash(password);
        print_info("rc4_hmac (NT)", &wand_utils::bytes_to_hex(&rc4));

        if let (Some(u), Some(d)) = (user, domain) {
            let salt = potions::kerberos_salt(u, d);
            print_info("Salt", &salt);
            let aes128 = potions::aes128_string_to_key(password, &salt, 4096);
            let aes256 = potions::aes256_string_to_key(password, &salt, 4096);
            print_info("aes128_cts_hmac_sha1", &wand_utils::bytes_to_hex(&aes128));
            print_info("aes256_cts_hmac_sha1", &wand_utils::bytes_to_hex(&aes256));
        } else {
            print_warning("Provide /user: and /domain: for AES key derivation");
        }
        Ok(())
    }
}
