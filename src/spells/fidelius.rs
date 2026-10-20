use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Fidelius;

impl super::Spell for Fidelius {
    fn incantation(&self) -> &'static str { "fidelius" }
    fn grimoire(&self) -> &'static str {
        "Create a process with separate network credentials (createnetonly). /program: [/username: /password: /domain:] [Windows only]"
    }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("createnetonly requires CreateProcessWithLogonW — Windows only")
    }
}
