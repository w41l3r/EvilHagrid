use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Whomst;

impl super::Spell for Whomst {
    fn incantation(&self) -> &'static str { "whomst" }
    fn grimoire(&self) -> &'static str { "Display the current logon session LUID and identity." }
    fn cast(&self, _args: &HashMap<String, String>) -> Result<()> {
        #[cfg(windows)]
        {
            return whomst_windows();
        }
        #[cfg(not(windows))]
        {
            return whomst_unix();
        }
    }
}

#[cfg(windows)]
fn whomst_windows() -> Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_STATISTICS, TokenStatistics, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let process = GetCurrentProcess();
        let mut token: HANDLE = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token)
            .map_err(|e| anyhow::anyhow!("OpenProcessToken: {}", e))?;

        let mut stats: TOKEN_STATISTICS = std::mem::zeroed();
        let mut return_len: u32 = 0;
        GetTokenInformation(
            token,
            TokenStatistics,
            Some(&mut stats as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut return_len,
        ).map_err(|e| anyhow::anyhow!("GetTokenInformation: {}", e))?;

        let luid_val = (stats.AuthenticationId.HighPart as u64) << 32
            | stats.AuthenticationId.LowPart as u64;

        print_success("Current logon session:");
        print_info("LUID", &format!("0x{:016x} (low=0x{:x} high=0x{:x})",
            luid_val, stats.AuthenticationId.LowPart, stats.AuthenticationId.HighPart));
        print_info("LogonId", &format!("{}", luid_val));

        let _ = windows::Win32::Foundation::CloseHandle(token);
    }
    Ok(())
}

#[cfg(not(windows))]
fn whomst_unix() -> Result<()> {
    let uid = {
        #[cfg(unix)]
        unsafe { extern "C" { fn getuid() -> u32; fn getgid() -> u32; fn geteuid() -> u32; }
            (getuid(), getgid(), geteuid())
        }
        #[cfg(not(unix))]
        (0u32, 0u32, 0u32)
    };

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| format!("uid:{}", uid.0));

    print_success("Current identity (POSIX):");
    print_info("User",    &username);
    print_info("UID",     &uid.0.to_string());
    print_info("GID",     &uid.1.to_string());
    print_info("EUID",    &uid.2.to_string());

    if let Ok(ccache) = std::env::var("KRB5CCNAME") {
        print_info("KRB5CCNAME", &ccache);
    }
    Ok(())
}
