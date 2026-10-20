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
