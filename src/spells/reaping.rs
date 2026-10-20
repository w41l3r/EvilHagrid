use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::reaper;

pub struct Reaping;

impl super::Spell for Reaping {
    fn incantation(&self) -> &'static str { "reaping" }
    fn grimoire(&self) -> &'static str {
        "Harvest and auto-renew TGTs. /domain: /password: or /rc4: [/interval:seconds] [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let interval = args.get("interval").and_then(|s| s.parse().ok()).unwrap_or(60u64);
        let dc = args.get("dc").map(|s| s.as_str());
        anyhow::bail!("harvest mode requires authentication credentials (/password: /rc4: etc.)")
    }
}
