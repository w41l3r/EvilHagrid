use anyhow::{bail, Result};
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;
use crate::dungeon::wand_utils;

pub struct Portkey;

impl super::Spell for Portkey {
    fn incantation(&self) -> &'static str { "portkey" }
    fn grimoire(&self) -> &'static str {
        "Import a ticket into the current logon session (ptt). /ticket: (base64 kirbi) [Windows only]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let b64 = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let kirbi = wand_utils::b64_to_kirbi(b64)?;
        print_banner("Importing ticket via LSA");
        ministry::import_ticket(&kirbi)?;
        print_success("Ticket imported into current logon session");
        Ok(())
    }
}
