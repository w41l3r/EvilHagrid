use anyhow::{bail, Result};
use ldap3::{LdapConn, Scope, SearchEntry};

/// Find accounts with Kerberos pre-authentication disabled (DONT_REQ_PREAUTH = 0x400000).
/// userAccountControl bit 22 (0x400000 = 4194304).
pub fn find_no_preauth_accounts(
    domain: &str,
    ldap_url: Option<&str>,
    dc: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<String>> {
    let url = if let Some(u) = ldap_url {
        u.to_owned()
    } else if let Some(d) = dc {
        format!("ldap://{}:389", d)
    } else {
        format!("ldap://{}:389", domain)
    };

    let base: String = domain
        .split('.')
        .map(|c| format!("DC={}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut ldap = LdapConn::new(&url)?;

    match (username, password) {
        (Some(u), Some(p)) => {
            ldap.simple_bind(u, p).map_err(|e| anyhow::anyhow!("LDAP bind failed: {}", e))?
                .success().map_err(|e| anyhow::anyhow!("LDAP bind error: {}", e))?;
        }
        _ => {
            // Anonymous bind — works on many AD configs for basic read access
            ldap.simple_bind("", "").map_err(|e| anyhow::anyhow!("LDAP anon bind failed: {}", e))?
                .success().map_err(|e| anyhow::anyhow!("LDAP anon bind error: {}", e))?;
        }
    }

    let filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";

    let (rs, _res) = ldap
        .search(&base, Scope::Subtree, filter, &["sAMAccountName", "userPrincipalName"])
        .map_err(|e| anyhow::anyhow!("LDAP search failed: {}", e))?
        .success()
        .map_err(|e| anyhow::anyhow!("LDAP search error: {}", e))?;

    let mut accounts = Vec::new();
    for entry in rs {
        let e = SearchEntry::construct(entry);
        if let Some(vals) = e.attrs.get("sAMAccountName") {
            for v in vals {
                if !v.is_empty() {
                    accounts.push(v.clone());
                }
            }
        }
    }

    ldap.unbind().ok();

    if accounts.is_empty() {
        bail!("No accounts with pre-auth disabled found in {}", base);
    }

    Ok(accounts)
}

/// Find Kerberoastable accounts (SPN set and not msDS-SupportedEncryptionTypes=0).
pub fn find_spn_accounts(
    domain: &str,
    ldap_url: Option<&str>,
    dc: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let url = if let Some(u) = ldap_url {
        u.to_owned()
    } else if let Some(d) = dc {
        format!("ldap://{}:389", d)
    } else {
        format!("ldap://{}:389", domain)
    };

    let base: String = domain
        .split('.')
        .map(|c| format!("DC={}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut ldap = LdapConn::new(&url)?;

    match (username, password) {
        (Some(u), Some(p)) => {
            ldap.simple_bind(u, p).map_err(|e| anyhow::anyhow!("LDAP bind failed: {}", e))?
                .success().map_err(|e| anyhow::anyhow!("LDAP bind error: {}", e))?;
        }
        _ => {
            ldap.simple_bind("", "")
                .map_err(|e| anyhow::anyhow!("LDAP anon bind: {}", e))?
                .success()
                .map_err(|e| anyhow::anyhow!("LDAP anon bind error: {}", e))?;
        }
    }

    let filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

    let (rs, _res) = ldap
        .search(&base, Scope::Subtree, filter, &["sAMAccountName", "servicePrincipalName"])
        .map_err(|e| anyhow::anyhow!("LDAP search: {}", e))?
        .success()
        .map_err(|e| anyhow::anyhow!("LDAP search error: {}", e))?;

    let mut accounts = Vec::new();
    for entry in rs {
        let e = SearchEntry::construct(entry);
        let sam = e.attrs.get("sAMAccountName")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        if let Some(spns) = e.attrs.get("servicePrincipalName") {
            for spn in spns {
                accounts.push((sam.clone(), spn.clone()));
            }
        }
    }

    ldap.unbind().ok();
    Ok(accounts)
}
