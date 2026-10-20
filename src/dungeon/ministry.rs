//! Interaction with the Windows Local Security Authority (LSA).
//! All functions in this module are Windows-only.

use anyhow::{bail, Result};

#[cfg(windows)]
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{HANDLE, LUID, STATUS_SUCCESS},
        Security::Authentication::Identity::{
            LsaConnectUntrusted, LsaCallAuthenticationPackage,
            LsaLookupAuthenticationPackage, LsaFreeReturnBuffer,
            KERB_PURGE_TKT_CACHE_REQUEST, KERB_RETRIEVE_TKT_REQUEST,
            KERB_SUBMIT_TKT_REQUEST,
            KerbPurgeTicketCacheExMessage, KerbRetrieveTicketMessage,
            KerbSubmitTicketMessage,
        },
    },
};

#[cfg(windows)]
pub fn lsa_handle() -> Result<isize> {
    use std::mem::zeroed;
    unsafe {
        let mut handle: HANDLE = zeroed();
        let status = LsaConnectUntrusted(&mut handle);
        if status != STATUS_SUCCESS.0 as i32 {
            bail!("LsaConnectUntrusted failed: 0x{:08x}", status);
        }
        Ok(handle.0 as isize)
    }
}

#[cfg(windows)]
pub fn lsa_package_id(handle: isize) -> Result<u32> {
    use std::mem::zeroed;
    use windows::core::s;
    unsafe {
        let mut pkg_id: u32 = 0;
        let name = windows::Win32::Security::Authentication::Identity::LSA_STRING {
            Length: 12,
            MaximumLength: 13,
            Buffer: PCSTR("Kerberos\0".as_ptr()),
        };
        let status = LsaLookupAuthenticationPackage(
            HANDLE(handle as _),
            &name,
            &mut pkg_id,
        );
        if status != STATUS_SUCCESS.0 as i32 {
            bail!("LsaLookupAuthenticationPackage failed: 0x{:08x}", status);
        }
        Ok(pkg_id)
    }
}

#[cfg(windows)]
pub fn import_ticket(kirbi: &[u8]) -> Result<()> {
    use std::alloc::{alloc, Layout};
    use windows::Win32::Security::Authentication::Identity::KERB_SUBMIT_TKT_REQUEST;

    let handle_raw = lsa_handle()?;
    let pkg_id = lsa_package_id(handle_raw)?;
    let handle = HANDLE(handle_raw as _);

    let req_size = std::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>() + kirbi.len();
    let layout = Layout::from_size_align(req_size, 8).unwrap();
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() { bail!("allocation failed"); }

    unsafe {
        let req = ptr as *mut KERB_SUBMIT_TKT_REQUEST;
        (*req).MessageType = KerbSubmitTicketMessage;
        (*req).KerbCredSize = kirbi.len() as u32;
        (*req).KerbCredOffset = std::mem::size_of::<KERB_SUBMIT_TKT_REQUEST>() as u32;
        let dest = (req as *mut u8).add((*req).KerbCredOffset as usize);
        std::ptr::copy_nonoverlapping(kirbi.as_ptr(), dest, kirbi.len());

        let mut ret_buf = std::ptr::null_mut();
        let mut ret_len: u32 = 0;
        let mut status: i32 = 0;
        let result = LsaCallAuthenticationPackage(
            handle,
            pkg_id,
            ptr as *const _,
            req_size as u32,
            Some(&mut ret_buf),
            Some(&mut ret_len),
            Some(&mut status),
        );
        std::alloc::dealloc(ptr, layout);
        if !ret_buf.is_null() { let _ = LsaFreeReturnBuffer(ret_buf); }
        if result.is_err() || status != 0 {
            bail!("LsaCallAuthenticationPackage failed: result={:?} status=0x{:08x}", result, status);
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn dump_tickets(luid: Option<u64>) -> Result<Vec<Vec<u8>>> {
    // enumerate all tickets in the logon session via KerbRetrieveTicketMessage
    // This is a simplified implementation that enumerates cached tickets
    bail!("ticket dump via LSASS requires elevation; run as SYSTEM or with SeDebugPrivilege")
}

#[cfg(windows)]
pub fn purge_tickets(luid: Option<u64>) -> Result<()> {
    use windows::Win32::Security::Authentication::Identity::KERB_PURGE_TKT_CACHE_REQUEST;
    let handle_raw = lsa_handle()?;
    let pkg_id = lsa_package_id(handle_raw)?;
    let handle = HANDLE(handle_raw as _);
    let luid_val: LUID = if let Some(l) = luid {
        LUID { LowPart: l as u32, HighPart: (l >> 32) as i32 }
    } else {
        LUID { LowPart: 0, HighPart: 0 }
    };
    unsafe {
        let req = KERB_PURGE_TKT_CACHE_REQUEST {
            MessageType: KerbPurgeTicketCacheExMessage,
            LogonId: luid_val,
            ..Default::default()
        };
        let mut ret_buf = std::ptr::null_mut();
        let mut ret_len: u32 = 0;
        let mut status: i32 = 0;
        LsaCallAuthenticationPackage(
            handle,
            pkg_id,
            &req as *const _ as _,
            std::mem::size_of::<KERB_PURGE_TKT_CACHE_REQUEST>() as u32,
            Some(&mut ret_buf),
            Some(&mut ret_len),
            Some(&mut status),
        ).map_err(|e| anyhow::anyhow!("LSA purge failed: {}", e))?;
        if !ret_buf.is_null() { let _ = LsaFreeReturnBuffer(ret_buf); }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn import_ticket(_kirbi: &[u8]) -> Result<()> {
    bail!("ticket import (ptt) requires Windows")
}

#[cfg(not(windows))]
pub fn dump_tickets(_luid: Option<u64>) -> Result<Vec<Vec<u8>>> {
    bail!("ticket dump requires Windows")
}

#[cfg(not(windows))]
pub fn purge_tickets(_luid: Option<u64>) -> Result<()> {
    bail!("ticket purge requires Windows")
}

// ── Session / ticket enumeration ─────────────────────────────────────────────

#[derive(Debug)]
pub struct CachedTicketRow {
    pub luid:       String,
    pub username:   String,
    pub domain:     String,
    pub sname:      String,
    pub etype:      i32,
    pub end_time:   String,
    pub flags:      String,
}

#[cfg(windows)]
pub fn enumerate_sessions_and_tickets(service_filter: Option<&str>) -> Result<Vec<CachedTicketRow>> {
    // LsaEnumerateLogonSessions + KerbQueryTicketCacheEx2Message per session
    // Full implementation requires complex FFI structs; provide skeleton
    bail!("Full triage requires LsaEnumerateLogonSessions + KerbQueryTicketCacheEx2Message — elevation needed")
}

#[cfg(not(windows))]
pub fn enumerate_sessions_and_tickets(_service_filter: Option<&str>) -> Result<Vec<CachedTicketRow>> {
    bail!("ticket enumeration via LSA requires Windows")
}

/// Read tickets from POSIX Kerberos credential caches (ccache files).
/// Works on Linux/macOS where MIT krb5 or Heimdal stores tickets.
pub fn read_ccache_tickets(ccache_path: Option<&str>) -> Result<Vec<CachedTicketRow>> {
    let paths = collect_ccache_paths(ccache_path)?;
    let mut rows = Vec::new();
    for path in &paths {
        match parse_ccache_file(path) {
            Ok(mut r) => rows.append(&mut r),
            Err(e) => eprintln!("  [!] {}: {}", path, e),
        }
    }
    Ok(rows)
}

fn collect_ccache_paths(explicit: Option<&str>) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    if let Some(p) = explicit {
        paths.push(p.to_owned());
        return Ok(paths);
    }
    // $KRB5CCNAME
    if let Ok(v) = std::env::var("KRB5CCNAME") {
        let v = v.trim_start_matches("FILE:").to_owned();
        if !v.is_empty() && std::path::Path::new(&v).exists() {
            paths.push(v);
        }
    }
    // /tmp/krb5cc_<uid> and /tmp/krb5cc_*
    let uid = unsafe { libc_getuid() };
    let default = format!("/tmp/krb5cc_{}", uid);
    if std::path::Path::new(&default).exists() {
        paths.push(default);
    }
    if let Ok(rd) = std::fs::read_dir("/tmp") {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("krb5cc_") {
                let p = entry.path().display().to_string();
                if !paths.contains(&p) { paths.push(p); }
            }
        }
    }
    if paths.is_empty() {
        anyhow::bail!("no ccache files found; set $KRB5CCNAME or use /ccache:");
    }
    Ok(paths)
}

fn libc_getuid() -> u32 {
    #[cfg(unix)]
    unsafe { libc_uid() }
    #[cfg(not(unix))]
    { 0 }
}

#[cfg(unix)]
unsafe fn libc_uid() -> u32 {
    extern "C" { fn getuid() -> u32; }
    getuid()
}

/// Minimal ccache v4 parser (MIT krb5 format).
/// Spec: https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html
fn parse_ccache_file(path: &str) -> Result<Vec<CachedTicketRow>> {
    use std::io::{Cursor, Read};
    use byteorder::{BigEndian, ReadBytesExt};

    let data = std::fs::read(path)?;
    let mut cur = Cursor::new(&data);

    let file_format_version = cur.read_u16::<BigEndian>()?;
    let _tags_len = if file_format_version == 0x0504 {
        let hlen = cur.read_u16::<BigEndian>()?;
        cur.set_position(cur.position() + hlen as u64);
        hlen
    } else if file_format_version == 0x0503 {
        0
    } else {
        anyhow::bail!("unsupported ccache version 0x{:04x}", file_format_version);
    };

    let default_principal = read_ccache_principal(&mut cur)?;
    let mut rows = Vec::new();

    while cur.position() < data.len() as u64 {
        let client = match read_ccache_principal(&mut cur) {
            Ok(p) => p,
            Err(_) => break,
        };
        let server = match read_ccache_principal(&mut cur) {
            Ok(p) => p,
            Err(_) => break,
        };
        // keyblock: etype(2) + key_len(2) + key_data
        if cur.position() + 4 > data.len() as u64 { break; }
        let etype = cur.read_i16::<BigEndian>()? as i32;
        let key_len = cur.read_u16::<BigEndian>()? as u64;
        cur.set_position(cur.position() + key_len);
        // times: auth(4) + start(4) + end(4) + renew_till(4)
        if cur.position() + 16 > data.len() as u64 { break; }
        let _auth_time  = cur.read_u32::<BigEndian>()?;
        let _start_time = cur.read_u32::<BigEndian>()?;
        let end_time    = cur.read_u32::<BigEndian>()?;
        let _renew_till = cur.read_u32::<BigEndian>()?;
        let _is_skey    = cur.read_u8()?;
        let ticket_flags = cur.read_u32::<BigEndian>()?;
        // addresses count
        let addr_count = cur.read_u32::<BigEndian>()?;
        for _ in 0..addr_count {
            let _addrtype = cur.read_u16::<BigEndian>()?;
            let alen = cur.read_u32::<BigEndian>()? as u64;
            cur.set_position(cur.position() + alen);
        }
        // authdata count
        let ad_count = cur.read_u32::<BigEndian>()?;
        for _ in 0..ad_count {
            let _adtype = cur.read_u16::<BigEndian>()?;
            let adlen = cur.read_u32::<BigEndian>()? as u64;
            cur.set_position(cur.position() + adlen);
        }
        // ticket blob
        let tkt_len = cur.read_u32::<BigEndian>()? as u64;
        cur.set_position(cur.position() + tkt_len);
        // second ticket blob
        let tkt2_len = cur.read_u32::<BigEndian>()? as u64;
        cur.set_position(cur.position() + tkt2_len);

        let end_str = unix_ts_to_generalized(end_time);
        let flags_str = format_ticket_flags(ticket_flags);
        rows.push(CachedTicketRow {
            luid:     path.to_owned(),
            username: client.clone(),
            domain:   String::new(),
            sname:    server,
            etype,
            end_time:  end_str,
            flags:     flags_str,
        });
    }
    let _ = default_principal;
    Ok(rows)
}

fn read_ccache_principal(cur: &mut std::io::Cursor<&Vec<u8>>) -> anyhow::Result<String> {
    use byteorder::{BigEndian, ReadBytesExt};
    let _name_type  = cur.read_u32::<BigEndian>()?;
    let comp_count  = cur.read_u32::<BigEndian>()?;
    let realm_len   = cur.read_u32::<BigEndian>()? as usize;
    let mut realm   = vec![0u8; realm_len];
    use std::io::Read;
    cur.read_exact(&mut realm)?;
    let realm_str   = String::from_utf8_lossy(&realm).to_string();
    let mut parts   = Vec::new();
    for _ in 0..comp_count {
        let clen = cur.read_u32::<BigEndian>()? as usize;
        let mut comp = vec![0u8; clen];
        cur.read_exact(&mut comp)?;
        parts.push(String::from_utf8_lossy(&comp).to_string());
    }
    Ok(if parts.is_empty() { realm_str } else { format!("{}@{}", parts.join("/"), realm_str) })
}

fn unix_ts_to_generalized(ts: u32) -> String {
    if ts == 0 { return "never".to_owned(); }
    use chrono::{DateTime, Utc, TimeZone};
    let dt: DateTime<Utc> = Utc.timestamp_opt(ts as i64, 0).single().unwrap_or_default();
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn format_ticket_flags(flags: u32) -> String {
    let mut out = Vec::new();
    if flags & 0x4000_0000 != 0 { out.push("forwardable"); }
    if flags & 0x2000_0000 != 0 { out.push("forwarded"); }
    if flags & 0x1000_0000 != 0 { out.push("proxiable"); }
    if flags & 0x0080_0000 != 0 { out.push("renewable"); }
    if flags & 0x0020_0000 != 0 { out.push("pre-auth"); }
    if flags & 0x0004_0000 != 0 { out.push("ok-delegate"); }
    if out.is_empty() { "none".to_owned() } else { out.join(",") }
}
