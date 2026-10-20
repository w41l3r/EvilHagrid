use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;

pub struct Census;

impl super::Spell for Census {
    fn incantation(&self) -> &'static str { "census" }
    fn grimoire(&self) -> &'static str {
        "List Kerberos tickets across sessions [/luid:] [/service:] [/ccache:]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let service_filter = args.get("service").map(String::as_str);
        let ccache_path    = args.get("ccache").map(String::as_str);
        let luid_filter    = args.get("luid").and_then(|v| {
            if v.starts_with("0x") || v.starts_with("0X") {
                u64::from_str_radix(&v[2..], 16).ok()
            } else {
                v.parse::<u64>().ok()
            }
        });

        print_success("Enumerating Kerberos ticket sessions...");

        // ── Windows: LSA enumeration ──────────────────────────────────────────
        #[cfg(windows)]
        {
            match ministry::enumerate_sessions_and_tickets(service_filter) {
                Ok(rows) => {
                    render_ticket_table(&rows, luid_filter, service_filter);
                    return Ok(());
                }
                Err(e) => {
                    print_warning(&format!("LSA enumeration unavailable: {}", e));
                    print_warning("Falling back to ccache file parsing...");
                }
            }
        }

        // ── Cross-platform: ccache file parsing ───────────────────────────────
        let rows = ministry::read_ccache_tickets(ccache_path)?;
        if rows.is_empty() {
            print_warning("No tickets found.");
            return Ok(());
        }
        render_ticket_table(&rows, luid_filter, service_filter);
        Ok(())
    }
}

fn render_ticket_table(
    rows: &[ministry::CachedTicketRow],
    luid_filter: Option<u64>,
    service_filter: Option<&str>,
) {
    // Group by luid (session / ccache file)
    let mut sessions: Vec<&str> = Vec::new();
    for r in rows {
        if !sessions.contains(&r.luid.as_str()) {
            sessions.push(&r.luid);
        }
    }

    let mut shown = 0usize;
    for session in &sessions {
        // Apply /luid: filter (numeric sessions only — on Linux the luid is a file path)
        if let Some(lf) = luid_filter {
            let session_num: Option<u64> = if session.starts_with("0x") || session.starts_with("0X") {
                u64::from_str_radix(&session[2..], 16).ok()
            } else {
                session.parse::<u64>().ok()
            };
            if let Some(sn) = session_num {
                if sn != lf { continue; }
            }
        }

        // Collect tickets for this session
        let session_rows: Vec<&ministry::CachedTicketRow> = rows.iter()
            .filter(|r| &r.luid.as_str() == session)
            .filter(|r| {
                if let Some(sf) = service_filter {
                    r.sname.to_ascii_lowercase().contains(&sf.to_ascii_lowercase())
                } else {
                    true
                }
            })
            .collect();

        if session_rows.is_empty() { continue; }

        // Resolve luid as hex for display
        let luid_display = if let Ok(v) = session.parse::<u64>() {
            format!("0x{:016x}", v)
        } else {
            session.to_string()
        };

        let first = session_rows[0];
        println!();
        println!("  Session: {}", luid_display);
        if !first.username.is_empty() {
            println!("  User:    {}\\{}", first.domain, first.username);
        }
        println!("  Tickets: {}", session_rows.len());
        println!();

        let mut tbl = GrimoireTable::new(vec!["Service", "EType", "Flags", "End Time"]);
        for r in &session_rows {
            let etype_str = etype_name(r.etype);
            tbl.add_row(vec![
                r.sname.clone(),
                etype_str,
                r.flags.clone(),
                r.end_time.clone(),
            ]);
        }
        tbl.print();
        shown += session_rows.len();
    }

    if shown == 0 {
        print_warning("No tickets matched the given filter.");
    } else {
        println!();
        print_success(&format!("Total: {} ticket(s) across {} session(s)", shown, sessions.len()));
    }
}

fn etype_name(etype: i32) -> String {
    match etype {
        17 => "aes128-cts-hmac-sha1-96".to_owned(),
        18 => "aes256-cts-hmac-sha1-96".to_owned(),
        23 => "rc4-hmac".to_owned(),
        -128 => "rc4-hmac-exp".to_owned(),
        3  => "des-cbc-md5".to_owned(),
        _  => format!("etype-{}", etype),
    }
}
