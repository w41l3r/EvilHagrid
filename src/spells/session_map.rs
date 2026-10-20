use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct SessionMap;

impl super::Spell for SessionMap {
    fn incantation(&self) -> &'static str { "session-map" }
    fn grimoire(&self) -> &'static str { "Enumerate logon sessions. [/luid:]" }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        let luid_filter = args.get("luid").and_then(|v| {
            if v.starts_with("0x") || v.starts_with("0X") {
                u64::from_str_radix(&v[2..], 16).ok()
            } else {
                v.parse::<u64>().ok()
            }
        });

        #[cfg(windows)]
        {
            return enumerate_windows(luid_filter);
        }
        #[cfg(not(windows))]
        {
            return enumerate_ccache(luid_filter);
        }
    }
}

#[cfg(windows)]
fn enumerate_windows(luid_filter: Option<u64>) -> Result<()> {
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Security::Authentication::Identity::{
        LsaEnumerateLogonSessions, LsaFreeReturnBuffer,
    };
    use crate::dungeon::ministry::{lsa_handle, lsa_package_id};

    unsafe {
        let mut count: u32 = 0;
        let mut list: *mut LUID = std::ptr::null_mut();
        let status = LsaEnumerateLogonSessions(&mut count, &mut list);
        if status != 0 {
            anyhow::bail!("LsaEnumerateLogonSessions: 0x{:08x}", status);
        }

        print_success(&format!("Found {} logon session(s)", count));
        let mut tbl = GrimoireTable::new(vec!["LUID (hex)", "LowPart", "HighPart"]);
        for i in 0..count as usize {
            let luid = *list.add(i);
            let val = (luid.HighPart as u64) << 32 | luid.LowPart as u64;
            if luid_filter.map_or(false, |f| f != val) { continue; }
            tbl.add_row(vec![
                format!("0x{:016x}", val),
                format!("0x{:08x}", luid.LowPart),
                format!("0x{:08x}", luid.HighPart),
            ]);
        }
        tbl.print();
        let _ = LsaFreeReturnBuffer(list as *mut _);
    }
    Ok(())
}

#[cfg(not(windows))]
fn enumerate_ccache(_luid_filter: Option<u64>) -> Result<()> {
    print_success("Kerberos credential caches (POSIX):");
    let mut found = Vec::new();
    if let Ok(v) = std::env::var("KRB5CCNAME") {
        let v = v.trim_start_matches("FILE:").to_owned();
        if !v.is_empty() && std::path::Path::new(&v).exists() {
            found.push(v);
        }
    }
    if let Ok(rd) = std::fs::read_dir("/tmp") {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("krb5cc_") {
                let p = entry.path().display().to_string();
                if !found.contains(&p) { found.push(p); }
            }
        }
    }
    if found.is_empty() {
        print_warning("No ccache files found.");
    } else {
        let mut tbl = GrimoireTable::new(vec!["Path", "Size"]);
        for path in &found {
            let size = std::fs::metadata(path)
                .map(|m| format!("{} bytes", m.len()))
                .unwrap_or_else(|_| "?".to_owned());
            tbl.add_row(vec![path.clone(), size]);
        }
        tbl.print();
        print_success(&format!("{} ccache file(s) found", found.len()));
    }
    Ok(())
}
