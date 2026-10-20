use super::der::*;
use super::constants::*;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Rune {
    pub pa_type:  i32,
    pub pa_value: Vec<u8>,
}

impl Rune {
    pub fn pac_request(include_pac: bool) -> Self {
        let inner = encode_sequence(&encode_ctx(0, &encode_boolean(include_pac)));
        Self { pa_type: PA_PAC_REQUEST, pa_value: inner }
    }

    pub fn tgs_req(ap_req_bytes: &[u8]) -> Self {
        Self { pa_type: PA_TGS_REQ, pa_value: ap_req_bytes.to_vec() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let inner = [
            encode_ctx(0, &encode_integer(self.pa_type as i64)),
            encode_ctx(1, &encode_octet_string(&self.pa_value)),
        ]
        .concat();
        encode_sequence(&inner)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let mut seq = p.enter_sequence()?;
        let pa_type  = seq.enter_ctx(0)?.read_integer_i32()?;
        let pa_value = seq.enter_ctx(1)?.read_octet_string()?;
        Ok(Self { pa_type, pa_value })
    }
}

pub fn encode_pa_list(runes: &[Rune]) -> Vec<u8> {
    let mut inner = Vec::new();
    for r in runes { inner.extend_from_slice(&r.encode()); }
    encode_sequence(&inner)
}

pub fn decode_pa_list(data: &[u8]) -> Result<Vec<Rune>> {
    let mut p = DerParser::new(data);
    let mut seq = p.enter_sequence()?;
    let mut list = Vec::new();
    while !seq.is_empty() {
        let (_, bytes) = seq.read_tlv()?;
        // re-wrap: Rune::decode expects the full TLV of a SEQUENCE
        let wrapped = encode_sequence(bytes);
        // Decode without the outer sequence wrap
        let mut inner = DerParser::new(bytes);
        let pa_type  = inner.enter_ctx(0)?.read_integer_i32()?;
        let pa_value = inner.enter_ctx(1)?.read_octet_string()?;
        drop(wrapped);
        list.push(Rune { pa_type, pa_value });
    }
    Ok(list)
}

fn encode_boolean(b: bool) -> Vec<u8> {
    let val: u8 = if b { 0xff } else { 0x00 };
    vec![0x01, 0x01, val]
}

#[derive(Debug, Clone)]
pub struct EtypeInfo2Entry {
    pub etype: i32,
    pub salt:  Option<String>,
    pub s2kparams: Option<Vec<u8>>,
}

impl EtypeInfo2Entry {
    pub fn decode_list(data: &[u8]) -> Result<Vec<Self>> {
        let mut p = DerParser::new(data);
        let mut seq = p.enter_sequence()?;
        let mut entries = Vec::new();
        while !seq.is_empty() {
            let (_, entry_bytes) = seq.read_tlv()?;
            let mut ep = DerParser::new(entry_bytes);
            let mut entry_seq = ep.enter_sequence()?;
            let etype = entry_seq.enter_ctx(0)?.read_integer_i32()?;
            let salt = if entry_seq.peek_tag() == Some(ctx_tag(1)) {
                Some(entry_seq.enter_ctx(1)?.read_general_string()?)
            } else {
                None
            };
            let s2kparams = if entry_seq.peek_tag() == Some(ctx_tag(2)) {
                Some(entry_seq.enter_ctx(2)?.read_octet_string()?)
            } else {
                None
            };
            entries.push(Self { etype, salt, s2kparams });
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone)]
pub struct EncTimestamp {
    pub patimestamp: String,
    pub pausec:      Option<u32>,
}

impl EncTimestamp {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = encode_ctx(0, &encode_generalized_time(&self.patimestamp));
        if let Some(us) = self.pausec {
            inner.extend_from_slice(&encode_ctx(1, &encode_uint32(us)));
        }
        encode_sequence(&inner)
    }
}
