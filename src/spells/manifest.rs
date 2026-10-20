use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Manifest;

impl super::Spell for Manifest {
    fn incantation(&self) -> &'static str { "manifest" }
    fn grimoire(&self) -> &'static str {
        "List Kerberos tickets (verbose) [Windows only] [/luid:] [/service:]"
    }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("klist requires Windows LSA ticket enumeration")
    }
}
