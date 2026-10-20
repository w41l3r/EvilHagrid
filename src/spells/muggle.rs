use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::wand_utils;

pub struct Muggle;

impl super::Spell for Muggle {
    fn incantation(&self) -> &'static str { "muggle" }
    fn grimoire(&self) -> &'static str {
        "Convert between kirbi (base64) and binary .kirbi file. /ticket: or /file: [/outfile:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        if let Some(b64) = args.get("ticket") {
            let raw = wand_utils::b64_to_kirbi(b64)?;
            let outfile = args.get("outfile").map(|s| s.as_str()).unwrap_or("ticket.kirbi");
            std::fs::write(outfile, &raw)?;
            print_success(&format!("Kirbi written to {}", outfile));
        } else if let Some(file) = args.get("file") {
            let raw = std::fs::read(file)?;
            println!("{}", wand_utils::kirbi_to_b64(&raw));
        } else {
            anyhow::bail!("/ticket: or /file: required");
        }
        Ok(())
    }
}
