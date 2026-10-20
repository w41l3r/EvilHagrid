use anyhow::Result;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use crate::dungeon::display_charm;
use crate::dungeon::request_magic;
use crate::dungeon::wand_utils;

pub fn harvest_tgts(
    domain: &str,
    key: &[u8],
    etype: i32,
    interval_seconds: u64,
    dc: Option<&str>,
) -> Result<()> {
    display_charm::print_banner(&format!("Harvesting TGTs for {} every {}s", domain, interval_seconds));
    let mut seen: HashMap<String, String> = HashMap::new();
    loop {
        match request_magic::summon_tgt("current", domain, key, etype, dc) {
            Ok(tgt) => {
                let key_hex = wand_utils::bytes_to_hex(&tgt.session_key.keyvalue);
                if !seen.contains_key(&key_hex) {
                    display_charm::print_success(&format!(
                        "New TGT  client={}  expiry={}",
                        tgt.client, tgt.end_time
                    ));
                    seen.insert(key_hex, tgt.end_time.clone());
                }
                // auto-renew tickets close to expiry
                seen.retain(|k, expiry| {
                    let _ = k;
                    expiry.as_str() > wand_utils::generalized_time_now().as_str()
                });
            }
            Err(e) => display_charm::print_warning(&format!("harvest tick error: {}", e)),
        }
        thread::sleep(Duration::from_secs(interval_seconds));
    }
}
