use super::der::*;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct SealedChamber {
    pub etype:  i32,
    pub kvno:   Option<u32>,
    pub cipher: Vec<u8>,
}

impl SealedChamber {
    pub fn new(etype: i32, cipher: Vec<u8>) -> Self {
        Self { etype, kvno: None, cipher }
    }

    pub fn with_kvno(etype: i32, kvno: u32, cipher: Vec<u8>) -> Self {
        Self { etype, kvno: Some(kvno), cipher }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_ctx(0, &encode_integer(self.etype as i64)));
        if let Some(k) = self.kvno {
            inner.extend_from_slice(&encode_ctx(1, &encode_uint32(k)));
        }
        inner.extend_from_slice(&encode_ctx(2, &encode_octet_string(&self.cipher)));
        encode_sequence(&inner)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let mut seq = p.enter_sequence()?;
        let etype = seq.enter_ctx(0)?.read_integer_i32()?;
        let kvno = if seq.peek_tag() == Some(ctx_tag(1)) {
            Some(seq.enter_ctx(1)?.read_uint32()?)
        } else {
            None
        };
        let cipher = seq.enter_ctx(2)?.read_octet_string()?;
        Ok(Self { etype, kvno, cipher })
    }
}

#[derive(Debug, Clone)]
pub struct MagicKey {
    pub keytype:  i32,
    pub keyvalue: Vec<u8>,
}

impl MagicKey {
    pub fn encode(&self) -> Vec<u8> {
        let inner = [
            encode_ctx(0, &encode_integer(self.keytype as i64)),
            encode_ctx(1, &encode_octet_string(&self.keyvalue)),
        ]
        .concat();
        encode_sequence(&inner)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let mut seq = p.enter_sequence()?;
        let keytype  = seq.enter_ctx(0)?.read_integer_i32()?;
        let keyvalue = seq.enter_ctx(1)?.read_octet_string()?;
        Ok(Self { keytype, keyvalue })
    }
}

#[derive(Debug, Clone)]
pub struct Sigil {
    pub cksumtype: i32,
    pub checksum:  Vec<u8>,
}

impl Sigil {
    pub fn encode(&self) -> Vec<u8> {
        let inner = [
            encode_ctx(0, &encode_integer(self.cksumtype as i64)),
            encode_ctx(1, &encode_octet_string(&self.checksum)),
        ]
        .concat();
        encode_sequence(&inner)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let mut seq = p.enter_sequence()?;
        let cksumtype = seq.enter_ctx(0)?.read_integer_i32()?;
        let checksum  = seq.enter_ctx(1)?.read_octet_string()?;
        Ok(Self { cksumtype, checksum })
    }
}
