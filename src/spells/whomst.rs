use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Whomst;

impl super::Spell for Whomst {
    fn incantation(&self) -> &'static str { "whomst" }
    fn grimoire(&self) -> &'static str { "Display the current logon session LUID [Windows only]" }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("currentluid requires GetTokenInformation — Windows only")
    }
}
