use super::der::*;
use super::constants::*;
use super::enc_types::SealedChamber;
use super::principal::{Glyph, encode_realm};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Scroll {
    pub tkt_vno:  u8,
    pub realm:    String,
    pub sname:    Glyph,
    pub enc_part: SealedChamber,
}

impl Scroll {
    pub fn encode(&self) -> Vec<u8> {
        let inner = [
            encode_ctx(0, &encode_uint32(self.tkt_vno as u32)),
            encode_ctx(1, &encode_realm(&self.realm)),
            encode_ctx(2, &self.sname.encode()),
            encode_ctx(3, &self.enc_part.encode()),
        ]
        .concat();
        // APPLICATION 1 CONSTRUCTED
        tlv(TAG_TICKET, &encode_sequence(&inner))
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let raw = p.expect_tag(TAG_TICKET)?;
        let mut seq = DerParser::new(raw);
        let mut inner = seq.enter_sequence()?;
        let tkt_vno = inner.enter_ctx(0)?.read_uint32()? as u8;
        let realm   = inner.enter_ctx(1)?.read_general_string()?;
        let sname   = {
            let bytes = inner.slice_ctx(2)?;
            Glyph::decode(bytes)?
        };
        let enc_raw = inner.slice_ctx(3)?;
        let enc_part = SealedChamber::decode(enc_raw)?;
        Ok(Self { tkt_vno, realm, sname, enc_part })
    }

    pub fn decode_from_bytes(data: &[u8]) -> Result<Self> {
        Self::decode(data)
    }
}

#[derive(Debug, Clone)]
pub struct ScrollVault {
    pub flags:       u32,
    pub session_key: super::enc_types::MagicKey,
    pub crealm:      String,
    pub cname:       Glyph,
    pub transited:   Vec<u8>,
    pub auth_time:   String,
    pub start_time:  Option<String>,
    pub end_time:    String,
    pub renew_till:  Option<String>,
    pub caddr:       Option<Vec<u8>>,
    pub auth_data:   Option<Vec<u8>>,
}

impl ScrollVault {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_ctx(0, &encode_bit_string_flags(self.flags)));
        inner.extend_from_slice(&encode_ctx(1, &self.session_key.encode()));
        inner.extend_from_slice(&encode_ctx(2, &encode_realm(&self.crealm)));
        inner.extend_from_slice(&encode_ctx(3, &self.cname.encode()));
        // transited (SEQUENCE with type + contents)
        let transited = encode_sequence(&[
            encode_ctx(0, &encode_integer(0)).as_slice(),
            &encode_ctx(1, &encode_octet_string(&self.transited)),
        ].concat());
        inner.extend_from_slice(&encode_ctx(4, &transited));
        inner.extend_from_slice(&encode_ctx(5, &encode_generalized_time(&self.auth_time)));
        if let Some(ref st) = self.start_time {
            inner.extend_from_slice(&encode_ctx(6, &encode_generalized_time(st)));
        }
        inner.extend_from_slice(&encode_ctx(7, &encode_generalized_time(&self.end_time)));
        if let Some(ref rt) = self.renew_till {
            inner.extend_from_slice(&encode_ctx(8, &encode_generalized_time(rt)));
        }
        if let Some(ref ad) = self.auth_data {
            inner.extend_from_slice(&encode_ctx(10, ad));
        }
        // APPLICATION 3 CONSTRUCTED
        tlv(TAG_ENC_TICKET_PART, &encode_sequence(&inner))
    }
}

pub struct KrbCredInfo {
    pub key:         super::enc_types::MagicKey,
    pub prealm:      Option<String>,
    pub pname:       Option<Glyph>,
    pub flags:       Option<u32>,
    pub auth_time:   Option<String>,
    pub start_time:  Option<String>,
    pub end_time:    Option<String>,
    pub renew_till:  Option<String>,
    pub srealm:      Option<String>,
    pub sname:       Option<Glyph>,
}

impl KrbCredInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_ctx(0, &self.key.encode()));
        if let Some(ref r) = self.prealm {
            inner.extend_from_slice(&encode_ctx(1, &encode_realm(r)));
        }
        if let Some(ref n) = self.pname {
            inner.extend_from_slice(&encode_ctx(2, &n.encode()));
        }
        if let Some(f) = self.flags {
            inner.extend_from_slice(&encode_ctx(3, &encode_bit_string_flags(f)));
        }
        if let Some(ref t) = self.auth_time {
            inner.extend_from_slice(&encode_ctx(4, &encode_generalized_time(t)));
        }
        if let Some(ref t) = self.start_time {
            inner.extend_from_slice(&encode_ctx(5, &encode_generalized_time(t)));
        }
        if let Some(ref t) = self.end_time {
            inner.extend_from_slice(&encode_ctx(6, &encode_generalized_time(t)));
        }
        if let Some(ref t) = self.renew_till {
            inner.extend_from_slice(&encode_ctx(7, &encode_generalized_time(t)));
        }
        if let Some(ref r) = self.srealm {
            inner.extend_from_slice(&encode_ctx(8, &encode_realm(r)));
        }
        if let Some(ref n) = self.sname {
            inner.extend_from_slice(&encode_ctx(9, &n.encode()));
        }
        encode_sequence(&inner)
    }
}

pub fn build_kirbi(ticket: &Scroll, cred_info: KrbCredInfo) -> Vec<u8> {
    let ticket_bytes = ticket.encode();
    let tickets_seq = {
        let mut t = Vec::new();
        t.extend_from_slice(&ticket_bytes);
        encode_sequence(&t)
    };
    let enc_cred_info = encode_sequence(&cred_info.encode());
    let enc_part = {
        let inner = [
            encode_ctx(0, &enc_cred_info),
        ].concat();
        let app_inner = encode_sequence(&inner);
        // EncKrbCredPart is APPLICATION 29
        let enc_krb_cred = tlv(0x7d, &app_inner);
        SealedChamber::new(0, enc_krb_cred)
    };
    let krb_cred_inner = [
        encode_ctx(0, &encode_uint32(KRB5_PVNO as u32)),
        encode_ctx(1, &encode_uint32(22)),
        encode_ctx(2, &tickets_seq),
        encode_ctx(3, &enc_part.encode()),
    ]
    .concat();
    tlv(TAG_KRB_CRED, &encode_sequence(&krb_cred_inner))
}
