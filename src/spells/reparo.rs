use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::mending;
use crate::dungeon::wand_utils;

pub struct Reparo;

impl super::Spell for Reparo {
    fn incantation(&self) -> &'static str { "reparo" }
    fn grimoire(&self) -> &'static str {
        "Renew a TGT. /ticket: /domain: [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let b64    = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc     = args.get("dc").map(|s| s.as_str());
        let kirbi  = wand_utils::b64_to_kirbi(b64)?;
        print_banner("Renewing TGT");
        let new_resp = mending::renew_ticket(&kirbi, domain, dc)?;
        print_success("Ticket renewed");
        println!("{}", wand_utils::kirbi_to_b64(&new_resp));
        Ok(())
    }
}
