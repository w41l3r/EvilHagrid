use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct MaraudersMap;

impl super::Spell for MaraudersMap {
    fn incantation(&self) -> &'static str { "marauders-map" }
    fn grimoire(&self) -> &'static str {
        "Monitor for new TGTs in the current session [Windows only] [/interval:seconds]"
    }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("monitor requires Windows LSA event subscription")
    }
}
