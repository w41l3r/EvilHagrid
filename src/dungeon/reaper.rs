use anyhow::Result;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use crate::dungeon::display_charm;
use crate::dungeon::mending;
use crate::dungeon::request_magic;
use crate::dungeon::wand_utils;

pub fn harvest_tgts(
    username: &str,
    domain: &str,
    key: &[u8],
    etype: i32,
    interval_seconds: u64,
    dc: Option<&str>,
) -> Result<()> {
    display_charm::print_banner(&format!(
        "Harvesting TGTs for {}@{} every {}s",
        username, domain, interval_seconds
    ));
    // key: session_key_hex → (end_time_str, kirbi_bytes)
    let mut seen: HashMap<String, (String, Vec<u8>)> = HashMap::new();

    loop {
        let now_str = wand_utils::generalized_time_now();

        // Compute 30-minute lookahead threshold for proactive renewal
        let threshold = {
            use chrono::Utc;
            (Utc::now() + chrono::Duration::minutes(30))
                .format("%Y%m%d%H%M%SZ")
                .to_string()
        };

        // Renew tickets expiring within the next 30 minutes
        let expiring: Vec<(String, Vec<u8>)> = seen
            .iter()
            .filter(|(_, (end, _))| end.as_str() <= threshold.as_str())
            .map(|(k, (_, kirbi))| (k.clone(), kirbi.clone()))
            .collect();

        for (old_key, kirbi) in expiring {
            match mending::renew_ticket(&kirbi, domain, dc) {
                Ok(_) => {
                    display_charm::print_success("Renewed expiring TGT");
                    seen.remove(&old_key);
                }
                Err(e) => display_charm::print_warning(&format!("renewal failed: {}", e)),
            }
        }

        // Request a fresh TGT (inserts new entry if session key differs)
        match request_magic::summon_tgt(username, domain, key, etype, dc) {
            Ok(tgt) => {
                let key_hex = wand_utils::bytes_to_hex(&tgt.session_key.keyvalue);
                if !seen.contains_key(&key_hex) {
                    display_charm::print_success(&format!(
                        "New TGT  client={}@{}  start={}  end={}",
                        tgt.client, tgt.realm, tgt.start_time, tgt.end_time
                    ));
                    display_charm::print_info("SessionKey", &key_hex);
                    seen.insert(key_hex, (tgt.end_time.clone(), tgt.kirbi));
                }
            }
            Err(e) => display_charm::print_warning(&format!("harvest tick error: {}", e)),
        }

        // Prune fully expired entries
        seen.retain(|_k, (expiry, _)| expiry.as_str() > now_str.as_str());

        thread::sleep(Duration::from_secs(interval_seconds));
    }
}
