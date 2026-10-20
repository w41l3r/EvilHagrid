use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;

pub struct Pillage;

impl super::Spell for Pillage {
    fn incantation(&self) -> &'static str { "pillage" }
    fn grimoire(&self) -> &'static str {
        "Export cached Kerberos tickets [Windows only] [/luid:] [/service:] [/outdir:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let luid = args.get("luid").and_then(|s| {
            if s.starts_with("0x") { u64::from_str_radix(&s[2..], 16).ok() }
            else { s.parse().ok() }
        });
        print_banner("Extracting cached tickets");
        let tickets = ministry::dump_tickets(luid)?;
        print_success(&format!("Extracted {} ticket(s)", tickets.len()));
        Ok(())
    }
}
