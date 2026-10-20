use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct SessionMap;

impl super::Spell for SessionMap {
    fn incantation(&self) -> &'static str { "session-map" }
    fn grimoire(&self) -> &'static str { "Enumerate logon sessions [Windows only] [/luid:]" }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("logonsession enumeration requires LsaEnumerateLogonSessions — Windows only")
    }
}
