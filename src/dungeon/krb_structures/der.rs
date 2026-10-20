use anyhow::{bail, Result};

// ── Tag helpers ──────────────────────────────────────────────────────────────

pub const UNIVERSAL_PRIMITIVE_INTEGER:    u8 = 0x02;
pub const UNIVERSAL_PRIMITIVE_BIT_STRING: u8 = 0x03;
pub const UNIVERSAL_PRIMITIVE_OCTET_STR:  u8 = 0x04;
pub const UNIVERSAL_PRIMITIVE_NULL:       u8 = 0x05;
pub const UNIVERSAL_PRIMITIVE_OID:        u8 = 0x06;
pub const UNIVERSAL_PRIMITIVE_GENERAL_STR:u8 = 0x1b;
pub const UNIVERSAL_PRIMITIVE_GENERALIZED_TIME: u8 = 0x18;
pub const UNIVERSAL_CONSTRUCTED_SEQUENCE: u8 = 0x30;

// Context tags: [n] EXPLICIT CONSTRUCTED = 0xa0 | n
pub fn ctx_tag(n: u8) -> u8 { 0xa0 | n }
// Application CONSTRUCTED = 0x60 | n
pub fn app_tag(n: u8) -> u8 { 0x60 | n }

// ── Length encoding / decoding ───────────────────────────────────────────────

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x1_0000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else if len < 0x100_0000 {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    } else {
        vec![0x84, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

pub fn decode_length(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() { bail!("empty length field"); }
    if bytes[0] < 0x80 {
        return Ok((bytes[0] as usize, 1));
    }
    let n = (bytes[0] & 0x7f) as usize;
    if n == 0 { bail!("indefinite length not supported"); }
    if bytes.len() < 1 + n { bail!("truncated length"); }
    let mut len = 0usize;
    for &b in &bytes[1..=n] { len = (len << 8) | b as usize; }
    Ok((len, 1 + n))
}

// ── Tag + length + value wrapper ─────────────────────────────────────────────

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

// ── Primitive encoders ───────────────────────────────────────────────────────

pub fn encode_integer(n: i64) -> Vec<u8> {
    let raw = encode_integer_bytes(n);
    tlv(UNIVERSAL_PRIMITIVE_INTEGER, &raw)
}

pub fn encode_uint32(n: u32) -> Vec<u8> {
    encode_integer(n as i64)
}

fn encode_integer_bytes(n: i64) -> Vec<u8> {
    if n == 0 { return vec![0]; }
    let mut bytes = n.to_be_bytes().to_vec();
    // strip leading sign-extension bytes but keep the sign bit correct
    while bytes.len() > 1 {
        let keep = if n >= 0 {
            bytes[0] != 0 || (bytes[1] & 0x80 != 0)
        } else {
            bytes[0] != 0xff || (bytes[1] & 0x80 == 0)
        };
        if keep { break; }
        bytes.remove(0);
    }
    bytes
}

pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    tlv(UNIVERSAL_PRIMITIVE_OCTET_STR, data)
}

pub fn encode_general_string(s: &str) -> Vec<u8> {
    tlv(UNIVERSAL_PRIMITIVE_GENERAL_STR, s.as_bytes())
}

pub fn encode_generalized_time(t: &str) -> Vec<u8> {
    tlv(UNIVERSAL_PRIMITIVE_GENERALIZED_TIME, t.as_bytes())
}

pub fn encode_bit_string_flags(flags: u32) -> Vec<u8> {
    // Kerberos bit strings: 4 octets + 1 unused-bits prefix byte = 5 bytes total
    let b = flags.to_be_bytes();
    let payload = [0x00, b[0], b[1], b[2], b[3]]; // 0 unused bits
    tlv(UNIVERSAL_PRIMITIVE_BIT_STRING, &payload)
}

pub fn encode_null() -> Vec<u8> {
    vec![UNIVERSAL_PRIMITIVE_NULL, 0x00]
}

// ── Sequence / explicit context wrappers ─────────────────────────────────────

pub fn encode_sequence(inner: &[u8]) -> Vec<u8> {
    tlv(UNIVERSAL_CONSTRUCTED_SEQUENCE, inner)
}

pub fn encode_ctx(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(ctx_tag(n), inner)
}

pub fn encode_app_sequence(app_n: u8, inner: &[u8]) -> Vec<u8> {
    // APPLICATION n CONSTRUCTED = 0x60 | n (never more than 30 for Kerberos)
    let tag = 0x60 | app_n;
    tlv(tag, &encode_sequence(inner))
}

// ── Parser state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DerParser<'a> {
    data: &'a [u8],
    pos:  usize,
}

impl<'a> DerParser<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    pub fn remaining(&self) -> usize { self.data.len() - self.pos }
    pub fn is_empty(&self) -> bool   { self.pos >= self.data.len() }
    pub fn position(&self) -> usize  { self.pos }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn read_tag_and_length(&mut self) -> Result<(u8, usize)> {
        if self.pos >= self.data.len() { bail!("unexpected end of data"); }
        let tag = self.data[self.pos]; self.pos += 1;
        let (len, consumed) = decode_length(&self.data[self.pos..])?;
        self.pos += consumed;
        Ok((tag, len))
    }

    pub fn read_value(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() { bail!("value extends past buffer"); }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, len) = self.read_tag_and_length()?;
        let val = self.read_value(len)?;
        Ok((tag, val))
    }

    pub fn expect_tag(&mut self, expected: u8) -> Result<&'a [u8]> {
        let (tag, val) = self.read_tlv()?;
        if tag != expected {
            bail!("expected tag 0x{:02x}, got 0x{:02x}", expected, tag);
        }
        Ok(val)
    }

    pub fn read_integer_i32(&mut self) -> Result<i32> {
        let bytes = self.expect_tag(UNIVERSAL_PRIMITIVE_INTEGER)?;
        if bytes.is_empty() { bail!("empty integer"); }
        let sign_extend = if bytes[0] & 0x80 != 0 { !0i32 } else { 0i32 };
        let mut n = sign_extend;
        for &b in bytes { n = (n << 8) | b as i32; }
        Ok(n)
    }

    pub fn read_uint32(&mut self) -> Result<u32> {
        Ok(self.read_integer_i32()? as u32)
    }

    pub fn read_octet_string(&mut self) -> Result<Vec<u8>> {
        Ok(self.expect_tag(UNIVERSAL_PRIMITIVE_OCTET_STR)?.to_vec())
    }

    pub fn read_general_string(&mut self) -> Result<String> {
        let bytes = self.expect_tag(UNIVERSAL_PRIMITIVE_GENERAL_STR)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn read_generalized_time(&mut self) -> Result<String> {
        let bytes = self.expect_tag(UNIVERSAL_PRIMITIVE_GENERALIZED_TIME)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn read_bit_string_flags(&mut self) -> Result<u32> {
        let bytes = self.expect_tag(UNIVERSAL_PRIMITIVE_BIT_STRING)?;
        // first byte = unused bits count; Kerberos always uses 0
        if bytes.len() < 5 { bail!("bit string too short for flags"); }
        let flag_bytes = &bytes[1..5];
        Ok(u32::from_be_bytes([flag_bytes[0], flag_bytes[1], flag_bytes[2], flag_bytes[3]]))
    }

    pub fn enter_sequence(&mut self) -> Result<DerParser<'a>> {
        let inner = self.expect_tag(UNIVERSAL_CONSTRUCTED_SEQUENCE)?;
        Ok(DerParser::new(inner))
    }

    pub fn enter_ctx(&mut self, n: u8) -> Result<DerParser<'a>> {
        let inner = self.expect_tag(ctx_tag(n))?;
        Ok(DerParser::new(inner))
    }

    pub fn enter_app(&mut self, app_n: u8) -> Result<DerParser<'a>> {
        let tag = 0x60 | app_n;
        let outer = self.expect_tag(tag)?;
        // unwrap the SEQUENCE inside
        let mut p = DerParser::new(outer);
        let inner = p.expect_tag(UNIVERSAL_CONSTRUCTED_SEQUENCE)?;
        Ok(DerParser::new(inner))
    }

    pub fn slice_ctx(&mut self, n: u8) -> Result<&'a [u8]> {
        self.expect_tag(ctx_tag(n))
    }

    /// Attempt to read context tag n; if next byte is different, return None.
    pub fn optional_ctx(&mut self, n: u8) -> Option<DerParser<'a>> {
        if self.peek_tag() == Some(ctx_tag(n)) {
            self.enter_ctx(n).ok()
        } else {
            None
        }
    }
}

// ── Time helpers ─────────────────────────────────────────────────────────────

pub fn generalized_time_now() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%SZ").to_string()
}

pub fn generalized_time_epoch() -> String {
    "19700101000000Z".to_string()
}

pub fn generalized_time_distant_future() -> String {
    "20371231235959Z".to_string()
}
