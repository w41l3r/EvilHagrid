use anyhow::Result;
use std::collections::HashSet;
use std::thread;
use std::time::Duration;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;

pub struct MaraudersMap;

impl super::Spell for MaraudersMap {
    fn incantation(&self) -> &'static str { "marauders-map" }
    fn grimoire(&self) -> &'static str {
        "Monitor for new Kerberos tickets. [/interval:seconds] [/service:] [/ccache:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let interval_secs = args.get("interval")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);
        let service_filter = args.get("service").map(String::as_str);
        let ccache_path    = args.get("ccache").map(String::as_str);

        print_banner(&format!("Monitoring for new tickets every {}s — Ctrl+C to stop", interval_secs));

        let mut seen: HashSet<String> = HashSet::new();

        loop {
            let rows = {
                #[cfg(windows)]
                {
                    ministry::enumerate_sessions_and_tickets(service_filter)
                        .or_else(|_| ministry::read_ccache_tickets(ccache_path))
                }
                #[cfg(not(windows))]
                {
                    ministry::read_ccache_tickets(ccache_path)
                }
            };

            match rows {
                Ok(tickets) => {
                    for t in &tickets {
                        // Unique key: session + sname + etype
                        let key = format!("{}|{}|{}", t.luid, t.sname, t.etype);
                        if !seen.contains(&key) {
                            if service_filter.map_or(true, |sf|
                                t.sname.to_ascii_lowercase().contains(&sf.to_ascii_lowercase())
                            ) {
                                print_success(&format!(
                                    "[NEW] {}  user={}  sname={}  end={}  flags={}",
                                    t.luid, t.username, t.sname, t.end_time, t.flags
                                ));
                            }
                            seen.insert(key);
                        }
                    }
                }
                Err(e) => print_warning(&format!("monitor tick error: {}", e)),
            }
            thread::sleep(Duration::from_secs(interval_secs));
        }
    }
}
