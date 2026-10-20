// RFC 4120 — Kerberos V5

pub const KRB5_PVNO: u8 = 5;

// Application tags (CONSTRUCTED bit set = 0x60 | n)
pub const TAG_TICKET:          u8 = 0x61;
pub const TAG_AUTHENTICATOR:   u8 = 0x62;
pub const TAG_ENC_TICKET_PART: u8 = 0x63;
pub const TAG_AS_REQ:          u8 = 0x6a;
pub const TAG_AS_REP:          u8 = 0x6b;
pub const TAG_TGS_REQ:         u8 = 0x6c;
pub const TAG_TGS_REP:         u8 = 0x6d;
pub const TAG_AP_REQ:          u8 = 0x6e;
pub const TAG_AP_REP:          u8 = 0x6f;
pub const TAG_KRB_CRED:        u8 = 0x76;
pub const TAG_ENC_AS_REP_PART: u8 = 0x79;
pub const TAG_ENC_TGS_REP_PART:u8 = 0x7a;
pub const TAG_KRB_ERROR:       u8 = 0x7e;

// Encryption types
pub const ETYPE_DES_CBC_MD5:         i32 = 3;
pub const ETYPE_DES3_CBC_SHA1:       i32 = 16;
pub const ETYPE_RC4_HMAC:            i32 = 23;
pub const ETYPE_AES128_CTS_HMAC_SHA1_96: i32 = 17;
pub const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;

// Checksum types
pub const CKSUMTYPE_CRC32:           i32 = 1;
pub const CKSUMTYPE_HMAC_MD5:        i32 = -138;
pub const CKSUMTYPE_HMAC_SHA1_DES3:  i32 = 12;
pub const CKSUMTYPE_HMAC_SHA1_96_AES128: i32 = 15;
pub const CKSUMTYPE_HMAC_SHA1_96_AES256: i32 = 16;

// Key usage numbers (RFC 4120 §7.5.1)
pub const KU_TICKET:                   i32 = 2; // Ticket enc-part (encrypted with server key)
pub const KU_AS_REQ_PA_ENC_TIMESTAMP: i32 = 1;
pub const KU_AS_REP_ENC_PART:         i32 = 3;
pub const KU_TGS_REQ_AUTH_CKSUM:      i32 = 6;
pub const KU_TGS_REQ_AUTH:            i32 = 7;
pub const KU_TGS_REP_ENC_PART_SESS:   i32 = 8;
pub const KU_TGS_REP_ENC_PART_SUBSESS:i32 = 9;
pub const KU_AP_REQ_AUTH_CKSUM:       i32 = 10;
pub const KU_AP_REQ_AUTH:             i32 = 11;
pub const KU_AP_REP_ENC_PART:         i32 = 12;
pub const KU_KRB_PRIV_ENC_PART:       i32 = 13;
pub const KU_KRB_CRED_ENC_PART:       i32 = 14;
pub const KU_KRB_SAFE_CKSUM:          i32 = 15;
pub const KU_AD_KDC_ISSUED:           i32 = 19;
pub const KU_GSS_ACCEPTOR_SEAL:       i32 = 22;
pub const KU_GSS_ACCEPTOR_SIGN:       i32 = 23;
pub const KU_GSS_INITIATOR_SEAL:      i32 = 24;
pub const KU_GSS_INITIATOR_SIGN:      i32 = 25;

// PA-DATA types
pub const PA_TGS_REQ:          i32 = 1;
pub const PA_ENC_TIMESTAMP:    i32 = 2;
pub const PA_PW_SALT:          i32 = 3;
pub const PA_ETYPE_INFO:       i32 = 11;
pub const PA_ETYPE_INFO2:      i32 = 19;
pub const PA_PK_AS_REQ:        i32 = 16;
pub const PA_PK_AS_REP:        i32 = 17;
pub const PA_PAC_REQUEST:      i32 = 128;
pub const PA_FOR_USER:         i32 = 129;
pub const PA_S4U_X509_USER:    i32 = 130;
pub const PA_PAC_OPTIONS:      i32 = 167;
pub const PA_KEY_LIST_REQ:     i32 = 168;
pub const PA_KEY_LIST_REP:     i32 = 169;
pub const PA_DMSA_KEY_PACKAGE: i32 = 170;

// Name types
pub const NT_UNKNOWN:        i32 = 0;
pub const NT_PRINCIPAL:      i32 = 1;
pub const NT_SRV_INST:       i32 = 2;
pub const NT_SRV_HST:        i32 = 3;
pub const NT_SRV_XHST:       i32 = 4;
pub const NT_UID:             i32 = 5;
pub const NT_X500_PRINCIPAL: i32 = 6;
pub const NT_SMTP_NAME:      i32 = 7;
pub const NT_ENTERPRISE:     i32 = 10;
pub const NT_MS_PRINCIPAL:   i32 = -128;

// Address types
pub const ADDRTYPE_IPV4: i32 = 2;
pub const ADDRTYPE_IPV6: i32 = 24;

// KDC error codes
pub const KDC_ERR_NONE:              i32 = 0;
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
pub const KDC_ERR_ETYPE_NOTSUPP:     i32 = 14;
pub const KDC_ERR_PREAUTH_FAILED:    i32 = 24;
pub const KDC_ERR_PREAUTH_REQUIRED:  i32 = 25;
pub const KRB_AP_ERR_SKEW:           i32 = 37;
pub const KRB_ERR_GENERIC:           i32 = 60;

// KDCOptions bit positions (MSB first in BIT STRING)
pub const KDC_OPT_RESERVED:     u32 = 0x8000_0000;
pub const KDC_OPT_FORWARDABLE:  u32 = 0x4000_0000;
pub const KDC_OPT_FORWARDED:    u32 = 0x2000_0000;
pub const KDC_OPT_PROXIABLE:    u32 = 0x1000_0000;
pub const KDC_OPT_PROXY:        u32 = 0x0800_0000;
pub const KDC_OPT_ALLOW_POSTDATE: u32 = 0x0400_0000;
pub const KDC_OPT_POSTDATED:    u32 = 0x0200_0000;
pub const KDC_OPT_RENEWABLE:    u32 = 0x0080_0000;
pub const KDC_OPT_CNAME_IN_ADDL_TKT: u32 = 0x0002_0000; // MS-SFU S4U2Proxy
pub const KDC_OPT_RENEWABLE_OK: u32 = 0x0000_0010;
pub const KDC_OPT_ENC_TKT_IN_SKEY: u32 = 0x0000_0008;
pub const KDC_OPT_RENEW:        u32 = 0x0000_0002;
pub const KDC_OPT_VALIDATE:     u32 = 0x0000_0001;

// TicketFlags (same bit layout as KDCOptions)
pub const TF_FORWARDABLE:  u32 = 0x4000_0000;
pub const TF_FORWARDED:    u32 = 0x2000_0000;
pub const TF_PROXIABLE:    u32 = 0x1000_0000;
pub const TF_PROXY:        u32 = 0x0800_0000;
pub const TF_MAY_POSTDATE: u32 = 0x0400_0000;
pub const TF_POSTDATED:    u32 = 0x0200_0000;
pub const TF_INVALID:      u32 = 0x0100_0000;
pub const TF_RENEWABLE:    u32 = 0x0080_0000;
pub const TF_INITIAL:      u32 = 0x0040_0000;
pub const TF_PRE_AUTHENT:  u32 = 0x0020_0000;
pub const TF_HW_AUTHENT:   u32 = 0x0010_0000;
pub const TF_OK_AS_DELEGATE: u32 = 0x0004_0000;

// Authorization data types
pub const AD_IF_RELEVANT:             i32 = 1;
pub const AD_KDC_ISSUED:              i32 = 4;
pub const AD_AND_OR:                  i32 = 5;
pub const AD_MANDATORY_FOR_KDC:       i32 = 8;
pub const AD_WIN2K_PAC:               i32 = 128;

pub fn error_string(code: i32) -> &'static str {
    match code {
        0  => "KDC_ERR_NONE",
        6  => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
        7  => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        14 => "KDC_ERR_ETYPE_NOTSUPP",
        24 => "KDC_ERR_PREAUTH_FAILED",
        25 => "KDC_ERR_PREAUTH_REQUIRED",
        37 => "KRB_AP_ERR_SKEW",
        60 => "KRB_ERR_GENERIC",
        _  => "KRB_ERR_UNKNOWN",
    }
}

pub fn etype_string(etype: i32) -> &'static str {
    match etype {
        3  => "des-cbc-md5",
        17 => "aes128-cts-hmac-sha1-96",
        18 => "aes256-cts-hmac-sha1-96",
        23 => "rc4-hmac",
        _  => "unknown",
    }
}
