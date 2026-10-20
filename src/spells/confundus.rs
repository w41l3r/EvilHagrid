use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Confundus;

impl super::Spell for Confundus {
    fn incantation(&self) -> &'static str { "confundus" }
    fn grimoire(&self) -> &'static str {
        "Obtain a delegable TGT for the current user without elevation (TGTdeleg)"
    }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("tgtdeleg requires Windows SSPI interaction — Windows-only feature")
    }
}
