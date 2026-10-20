use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct SortingHat;

impl super::Spell for SortingHat {
    fn incantation(&self) -> &'static str { "sorting-hat" }
    fn grimoire(&self) -> &'static str {
        "Scan for accounts with pre-auth disabled (AS-REP roastable). /domain: [/ldap:] [/dc:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        anyhow::bail!("pre-auth scan requires LDAP enumeration — use /users: with preauth-feast instead")
    }
}
