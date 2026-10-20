use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::memory_charm;

pub struct Alohomora;

impl super::Spell for Alohomora {
    fn incantation(&self) -> &'static str { "alohomora" }
    fn grimoire(&self) -> &'static str {
        "Change a user password via kpasswd. /ticket: /newpassword: /domain: [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let b64 = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let pw  = args.get("newpassword").ok_or_else(|| anyhow::anyhow!("/newpassword: required"))?;
        let domain = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc = args.get("dc").map(|s| s.as_str());
        use crate::dungeon::wand_utils;
        let kirbi = wand_utils::b64_to_kirbi(b64)?;
        memory_charm::change_password(&kirbi, pw, domain, dc)
    }
}
