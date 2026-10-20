use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;

pub struct Obliviate;

impl super::Spell for Obliviate {
    fn incantation(&self) -> &'static str { "obliviate" }
    fn grimoire(&self) -> &'static str {
        "Purge Kerberos tickets from a logon session. [/luid:] [Windows only]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let luid = args.get("luid").and_then(|s| {
            if s.starts_with("0x") { u64::from_str_radix(&s[2..], 16).ok() }
            else { s.parse().ok() }
        });
        print_banner("Purging tickets");
        ministry::purge_tickets(luid)?;
        print_success("Tickets purged");
        Ok(())
    }
}
