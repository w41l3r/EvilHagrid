use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct PhilosophersStone;

impl super::Spell for PhilosophersStone {
    fn incantation(&self) -> &'static str { "philosophers-stone" }
    fn grimoire(&self) -> &'static str {
        "Diamond ticket: request legitimate TGT then modify PAC. /user: /domain: /rc4: or /aes256: /sid: [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("Diamond tickets require decrypting a real TGT with the krbtgt key — not yet fully implemented")
    }
}
