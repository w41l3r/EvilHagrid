use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::dungeon::display_charm::*;
use crate::dungeon::request_magic;
use crate::dungeon::wand_utils;
use crate::dungeon::krb_structures::constants::*;

pub struct AccioService;

impl super::Spell for AccioService {
    fn incantation(&self) -> &'static str { "accio-service" }
    fn grimoire(&self) -> &'static str {
        "Request a service ticket. /ticket: /spn: /domain: [/etype:rc4|aes256] [/dc:] [/outfile:]"
    }

    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let ticket_b64 = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: (base64 TGT kirbi) required"))?;
        let spn        = args.get("spn").ok_or_else(|| anyhow::anyhow!("/spn: required"))?;
        let domain     = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let dc         = args.get("dc").map(|s| s.as_str());
        let etype = match args.get("etype").map(|s| s.as_str()) {
            Some("aes256") => ETYPE_AES256_CTS_HMAC_SHA1_96,
            _ => ETYPE_RC4_HMAC,
        };
        let kirbi = wand_utils::b64_to_kirbi(ticket_b64)?;
        print_banner(&format!("Requesting service ticket for {}", spn));
        let svc_ticket = request_magic::fetch_service_ticket(&kirbi, spn, domain, etype, dc)?;
        let b64 = wand_utils::kirbi_to_b64(&svc_ticket.kirbi);
        print_success(&format!("Service ticket  spn={}  expiry={}", svc_ticket.service, svc_ticket.end_time));
        println!("{}", b64);
        println!();
        if let Some(outfile) = args.get("outfile") {
            std::fs::write(outfile, &svc_ticket.kirbi)?;
            print_success(&format!("Written to {}", outfile));
        }
        Ok(())
    }
}
