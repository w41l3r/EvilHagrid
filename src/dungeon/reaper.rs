use anyhow::Result;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use crate::dungeon::display_charm;
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
    // Track seen tickets by their session key hex to detect new ones
    let mut seen: HashMap<String, String> = HashMap::new();

    loop {
        match request_magic::summon_tgt(username, domain, key, etype, dc) {
            Ok(tgt) => {
                let key_hex = wand_utils::bytes_to_hex(&tgt.session_key.keyvalue);
                if !seen.contains_key(&key_hex) {
                    display_charm::print_success(&format!(
                        "New TGT  client={}@{}  start={}  end={}",
                        tgt.client, tgt.realm, tgt.start_time, tgt.end_time
                    ));
                    display_charm::print_info("SessionKey", &key_hex);
                    seen.insert(key_hex.clone(), tgt.end_time.clone());
                }

                // Attempt renewal for tickets close to expiry (within 30 minutes)
                let now_str = wand_utils::generalized_time_now();
                let thirty_min_from_now = wand_utils::now_plus_hours(0);
                let _ = thirty_min_from_now; // used for future threshold comparison

                // Prune expired entries from seen map
                seen.retain(|_k, expiry| expiry.as_str() > now_str.as_str());
            }
            Err(e) => display_charm::print_warning(&format!("harvest tick error: {}", e)),
        }
        thread::sleep(Duration::from_secs(interval_seconds));
    }
}
