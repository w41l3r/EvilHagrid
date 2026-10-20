use super::der::*;
use super::constants::*;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Glyph {
    pub kind: i32,
    pub parts: Vec<String>,
}

impl Glyph {
    pub fn new_principal(name: &str) -> Self {
        Self { kind: NT_PRINCIPAL, parts: vec![name.to_owned()] }
    }

    pub fn new_service(svc: &str, host: &str) -> Self {
        Self { kind: NT_SRV_INST, parts: vec![svc.to_owned(), host.to_owned()] }
    }

    pub fn new_krbtgt(domain: &str) -> Self {
        Self {
            kind: NT_SRV_INST,
            parts: vec!["krbtgt".to_owned(), domain.to_ascii_uppercase()],
        }
    }

    pub fn new_enterprise(upn: &str) -> Self {
        Self { kind: NT_ENTERPRISE, parts: vec![upn.to_owned()] }
    }

    pub fn to_string(&self) -> String {
        self.parts.join("/")
    }

    pub fn encode(&self) -> Vec<u8> {
        let name_type = encode_ctx(0, &encode_integer(self.kind as i64));
        let mut names_inner = Vec::new();
        for p in &self.parts {
            names_inner.extend_from_slice(&encode_general_string(p));
        }
        let name_string = encode_ctx(1, &encode_sequence(&names_inner));
        encode_sequence(&[name_type, name_string].concat())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let mut seq = p.enter_sequence()?;
        let kind = seq.enter_ctx(0)?.read_integer_i32()?;
        let mut names_ctx = seq.enter_ctx(1)?;
        let mut names_seq = names_ctx.enter_sequence()?;
        let mut parts = Vec::new();
        while !names_seq.is_empty() {
            parts.push(names_seq.read_general_string()?);
        }
        Ok(Self { kind, parts })
    }
}

pub type Realm = String;

pub fn encode_realm(realm: &str) -> Vec<u8> {
    encode_general_string(realm)
}

pub fn decode_realm(data: &[u8]) -> Result<String> {
    let mut p = DerParser::new(data);
    p.read_general_string()
}

pub fn encode_kerberos_time(ts: &str) -> Vec<u8> {
    encode_generalized_time(ts)
}
