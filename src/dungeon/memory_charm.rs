use anyhow::{bail, Result};
use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::potions;
use crate::dungeon::wand_utils;

pub fn change_password(
    tgt_kirbi: &[u8],
    new_password: &str,
    domain: &str,
    dc: Option<&str>,
) -> Result<()> {
    // RFC 3244 — Kerberos Set/Change Password (port 464)
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    bail!(
        "changepw against {}:464 for domain {} — not yet implemented (requires kpasswd protocol)",
        dc_addr,
        domain
    )
}
