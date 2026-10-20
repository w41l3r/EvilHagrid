use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct ConvertMuggle;

impl super::Spell for ConvertMuggle {
    fn incantation(&self) -> &'static str { "convert-muggle" }
    fn grimoire(&self) -> &'static str {
        "Convert an AS-REP response to a .kirbi file. /asrep: (base64) [/outfile:]"
    }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("asrep2kirbi conversion not yet implemented")
    }
}
