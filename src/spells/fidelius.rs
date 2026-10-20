use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Fidelius;

impl super::Spell for Fidelius {
    fn incantation(&self) -> &'static str { "fidelius" }
    fn grimoire(&self) -> &'static str {
        "Create a process with separate network credentials (createnetonly). \
        /program: [/username: /password: /domain:] [Windows only]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        #[cfg(windows)]
        {
            return create_net_only(args);
        }
        #[cfg(not(windows))]
        {
            let _ = args;
            anyhow::bail!("createnetonly requires Windows — use 'runas /netonly' on a Windows system")
        }
    }
}

#[cfg(windows)]
fn create_net_only(args: &HashMap<String, String>) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Threading::{
        CreateProcessWithLogonW, LOGON_NETCREDENTIALS_ONLY,
        PROCESS_INFORMATION, STARTUPINFOW, CREATE_NEW_CONSOLE,
    };

    let program = args.get("program")
        .ok_or_else(|| anyhow::anyhow!("/program: required (e.g. /program:cmd.exe)"))?;
    let username = args.get("username").map(String::as_str).unwrap_or("dummy");
    let domain   = args.get("domain").map(String::as_str).unwrap_or(".");
    let password = args.get("password").map(String::as_str).unwrap_or("dummy");

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let w_user    = to_wide(username);
    let w_domain  = to_wide(domain);
    let w_pass    = to_wide(password);
    let w_app     = to_wide(program);
    let mut w_cmd = to_wide(program);

    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        CreateProcessWithLogonW(
            PCWSTR(w_user.as_ptr()),
            PCWSTR(w_domain.as_ptr()),
            PCWSTR(w_pass.as_ptr()),
            LOGON_NETCREDENTIALS_ONLY,
            PCWSTR(w_app.as_ptr()),
            windows::core::PWSTR(w_cmd.as_mut_ptr()),
            CREATE_NEW_CONSOLE,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        ).map_err(|e| anyhow::anyhow!("CreateProcessWithLogonW: {}", e))?;

        print_success(&format!("Process created: PID={} TID={}", pi.dwProcessId, pi.dwThreadId));
        print_info("Program", program);
        print_info("Credentials", &format!("{}\\{}", domain, username));

        let _ = windows::Win32::Foundation::CloseHandle(pi.hProcess);
        let _ = windows::Win32::Foundation::CloseHandle(pi.hThread);
    }
    Ok(())
}
