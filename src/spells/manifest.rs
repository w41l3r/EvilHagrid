use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;
use crate::dungeon::ministry;

pub struct Manifest;

impl super::Spell for Manifest {
    fn incantation(&self) -> &'static str { "manifest" }
    fn grimoire(&self) -> &'static str {
        "Verbose Kerberos ticket list (klist). [/luid:] [/service:] [/ccache:]"
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

        print_success("Enumerating Kerberos tickets (verbose)...");

        // Try Windows LSA first on Windows
        #[cfg(windows)]
        {
            match ministry::enumerate_sessions_and_tickets(service_filter) {
                Ok(rows) => {
                    render_verbose_table(&rows, luid_filter, service_filter);
                    return Ok(());
                }
                Err(e) => {
                    print_warning(&format!("LSA enumeration unavailable: {}", e));
                    print_warning("Falling back to ccache file parsing...");
                }
            }
        }

        let rows = ministry::read_ccache_tickets(ccache_path)?;
        if rows.is_empty() {
            print_warning("No tickets found.");
            return Ok(());
        }
        render_verbose_table(&rows, luid_filter, service_filter);
        Ok(())
    }
}

fn render_verbose_table(
    rows: &[ministry::CachedTicketRow],
    luid_filter: Option<u64>,
    service_filter: Option<&str>,
) {
    let mut sessions: Vec<&str> = Vec::new();
    for r in rows {
        if !sessions.contains(&r.luid.as_str()) {
            sessions.push(&r.luid);
        }
    }

    for session in &sessions {
        if let Some(lf) = luid_filter {
            let sn: Option<u64> = if session.starts_with("0x") || session.starts_with("0X") {
                u64::from_str_radix(&session[2..], 16).ok()
            } else {
                session.parse::<u64>().ok()
            };
            if sn.map_or(false, |n| n != lf) { continue; }
        }

        let session_rows: Vec<&ministry::CachedTicketRow> = rows.iter()
            .filter(|r| &r.luid.as_str() == session)
            .filter(|r| service_filter.map_or(true, |sf|
                r.sname.to_ascii_lowercase().contains(&sf.to_ascii_lowercase())
            ))
            .collect();

        if session_rows.is_empty() { continue; }

        let luid_display = if let Ok(v) = session.parse::<u64>() {
            format!("0x{:016x}", v)
        } else {
            session.to_string()
        };

        let first = session_rows[0];
        println!();
        println!("  Session  : {}", luid_display);
        if !first.username.is_empty() {
            println!("  Principal: {}\\{}", first.domain, first.username);
        }
        println!();

        let mut tbl = GrimoireTable::new(vec![
            "ServiceName", "ClientName", "EType", "Flags", "Start", "End",
        ]);
        for r in &session_rows {
            tbl.add_row(vec![
                r.sname.clone(),
                if r.username.is_empty() { "-".to_owned() }
                else { format!("{}\\{}", r.domain, r.username) },
                etype_name(r.etype),
                r.flags.clone(),
                r.start_time.clone().unwrap_or_else(|| "-".to_owned()),
                r.end_time.clone(),
            ]);
        }
        tbl.print();
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
