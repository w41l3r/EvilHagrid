use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;

pub struct Census;

impl super::Spell for Census {
    fn incantation(&self) -> &'static str { "census" }
    fn grimoire(&self) -> &'static str {
        "List Kerberos tickets (brief) [Windows only] [/luid:] [/service:]"
    }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("triage requires Windows LSA ticket enumeration")
    }
}
