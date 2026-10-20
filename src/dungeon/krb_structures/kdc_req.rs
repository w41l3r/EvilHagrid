use super::der::*;
use super::constants::*;
use super::enc_types::SealedChamber;
use super::principal::{Glyph, encode_realm};
use super::pa_data::Rune;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct TomeRequest {
    pub pvno:       u8,
    pub msg_type:   u8,
    pub padata:     Vec<Rune>,
    pub body:       RequestBody,
}

#[derive(Debug, Clone, Default)]
pub struct RequestBody {
    pub kdc_options:  u32,
    pub cname:        Option<Glyph>,
    pub realm:        String,
    pub sname:        Option<Glyph>,
    pub from:         Option<String>,
    pub till:         String,
    pub rtime:        Option<String>,
    pub nonce:        u32,
    pub etype:        Vec<i32>,
    pub additional_tickets: Vec<Vec<u8>>,
}

impl RequestBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_ctx(0, &encode_bit_string_flags(self.kdc_options)));
        if let Some(ref n) = self.cname {
            inner.extend_from_slice(&encode_ctx(1, &n.encode()));
        }
        inner.extend_from_slice(&encode_ctx(2, &encode_realm(&self.realm)));
        if let Some(ref n) = self.sname {
            inner.extend_from_slice(&encode_ctx(3, &n.encode()));
        }
        if let Some(ref t) = self.from {
            inner.extend_from_slice(&encode_ctx(4, &encode_generalized_time(t)));
        }
        inner.extend_from_slice(&encode_ctx(5, &encode_generalized_time(&self.till)));
        if let Some(ref t) = self.rtime {
            inner.extend_from_slice(&encode_ctx(6, &encode_generalized_time(t)));
        }
        inner.extend_from_slice(&encode_ctx(7, &encode_uint32(self.nonce)));
        let mut etype_inner = Vec::new();
        for e in &self.etype {
            etype_inner.extend_from_slice(&encode_integer(*e as i64));
        }
        inner.extend_from_slice(&encode_ctx(8, &encode_sequence(&etype_inner)));
        if !self.additional_tickets.is_empty() {
            let mut ticks = Vec::new();
            for t in &self.additional_tickets { ticks.extend_from_slice(t); }
            inner.extend_from_slice(&encode_ctx(11, &encode_sequence(&ticks)));
        }
        encode_sequence(&inner)
    }
}

impl TomeRequest {
    pub fn new_as_req(cname: Glyph, realm: &str, etypes: &[i32], padata: Vec<Rune>, nonce: u32) -> Self {
        Self {
            pvno: KRB5_PVNO,
            msg_type: 10,
            padata,
            body: RequestBody {
                kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_RENEWABLE_OK,
                cname: Some(cname),
                realm: realm.to_ascii_uppercase(),
                sname: Some(Glyph::new_krbtgt(realm)),
                till: generalized_time_distant_future(),
                rtime: Some(generalized_time_distant_future()),
                nonce,
                etype: etypes.to_vec(),
                ..Default::default()
            },
        }
    }

    pub fn new_tgs_req(
        realm: &str,
        sname: Glyph,
        etypes: &[i32],
        padata: Vec<Rune>,
        nonce: u32,
    ) -> Self {
        Self {
            pvno: KRB5_PVNO,
            msg_type: 12,
            padata,
            body: RequestBody {
                kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE,
                realm: realm.to_ascii_uppercase(),
                sname: Some(sname),
                till: generalized_time_distant_future(),
                nonce,
                etype: etypes.to_vec(),
                ..Default::default()
            },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let app_tag = if self.msg_type == 10 { 10u8 } else { 12u8 };
        let pa_inner = {
            let mut v = Vec::new();
            for r in &self.padata { v.extend_from_slice(&r.encode()); }
            v
        };
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_ctx(1, &encode_uint32(self.pvno as u32)));
        inner.extend_from_slice(&encode_ctx(2, &encode_uint32(self.msg_type as u32)));
        if !self.padata.is_empty() {
            inner.extend_from_slice(&encode_ctx(3, &encode_sequence(&pa_inner)));
        }
        inner.extend_from_slice(&encode_ctx(4, &self.body.encode()));
        // APPLICATION n CONSTRUCTED
        let tag = 0x60 | app_tag;
        tlv(tag, &encode_sequence(&inner))
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let tag = p.peek_tag().unwrap_or(0);
        let raw = p.expect_tag(tag)?;
        let mut outer = DerParser::new(raw);
        let mut seq = outer.enter_sequence()?;
        let pvno     = seq.enter_ctx(1)?.read_uint32()? as u8;
        let msg_type = seq.enter_ctx(2)?.read_uint32()? as u8;
        let padata = if seq.peek_tag() == Some(ctx_tag(3)) {
            let pa_raw = seq.slice_ctx(3)?;
            let mut pa_p = DerParser::new(pa_raw);
            let mut pa_seq = pa_p.enter_sequence()?;
            let mut list = Vec::new();
            while !pa_seq.is_empty() {
                let (_, bytes) = pa_seq.read_tlv()?;
                let mut ep = DerParser::new(bytes);
                let pa_type  = ep.enter_ctx(0)?.read_integer_i32()?;
                let pa_value = ep.enter_ctx(1)?.read_octet_string()?;
                list.push(Rune { pa_type, pa_value });
            }
            list
        } else {
            Vec::new()
        };
        let body_raw = seq.slice_ctx(4)?;
        let mut bp = DerParser::new(body_raw);
        let mut bseq = bp.enter_sequence()?;
        let kdc_options = bseq.enter_ctx(0)?.read_bit_string_flags()?;
        let cname = if bseq.peek_tag() == Some(ctx_tag(1)) {
            let b = bseq.slice_ctx(1)?;
            Some(Glyph::decode(b)?)
        } else { None };
        let realm = bseq.enter_ctx(2)?.read_general_string()?;
        let sname = if bseq.peek_tag() == Some(ctx_tag(3)) {
            let b = bseq.slice_ctx(3)?;
            Some(Glyph::decode(b)?)
        } else { None };
        let _from  = if bseq.peek_tag() == Some(ctx_tag(4)) {
            Some(bseq.enter_ctx(4)?.read_generalized_time()?)
        } else { None };
        let till   = bseq.enter_ctx(5)?.read_generalized_time()?;
        let rtime  = if bseq.peek_tag() == Some(ctx_tag(6)) {
            Some(bseq.enter_ctx(6)?.read_generalized_time()?)
        } else { None };
        let nonce  = bseq.enter_ctx(7)?.read_uint32()?;
        let mut etype_seq = bseq.enter_ctx(8)?.enter_sequence()?;
        let mut etype = Vec::new();
        while !etype_seq.is_empty() {
            etype.push(etype_seq.read_integer_i32()?);
        }
        Ok(Self {
            pvno, msg_type, padata,
            body: RequestBody {
                kdc_options, cname, realm, sname, from: _from, till, rtime, nonce, etype,
                additional_tickets: Vec::new(),
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct TomeReply {
    pub pvno:     u8,
    pub msg_type: u8,
    pub padata:   Vec<Rune>,
    pub crealm:   String,
    pub cname:    Glyph,
    pub ticket:   Vec<u8>,
    pub enc_part: SealedChamber,
}

impl TomeReply {
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let tag = p.peek_tag().unwrap_or(0);
        let raw = p.expect_tag(tag)?;
        let mut outer = DerParser::new(raw);
        let mut seq = outer.enter_sequence()?;
        let pvno     = seq.enter_ctx(0)?.read_uint32()? as u8;
        let msg_type = seq.enter_ctx(1)?.read_uint32()? as u8;
        let padata = if seq.peek_tag() == Some(ctx_tag(2)) {
            let pa_raw = seq.slice_ctx(2)?;
            let mut pa_p = DerParser::new(pa_raw);
            let mut pa_seq = pa_p.enter_sequence()?;
            let mut list = Vec::new();
            while !pa_seq.is_empty() {
                let (_, bytes) = pa_seq.read_tlv()?;
                let mut ep = DerParser::new(bytes);
                let pa_type  = ep.enter_ctx(0)?.read_integer_i32()?;
                let pa_value = ep.enter_ctx(1)?.read_octet_string()?;
                list.push(Rune { pa_type, pa_value });
            }
            list
        } else {
            Vec::new()
        };
        let crealm   = seq.enter_ctx(3)?.read_general_string()?;
        let cname    = { let b = seq.slice_ctx(4)?; Glyph::decode(b)? };
        let ticket   = seq.slice_ctx(5)?.to_vec();
        let enc_raw  = seq.slice_ctx(6)?;
        let enc_part = SealedChamber::decode(enc_raw)?;
        Ok(Self { pvno, msg_type, padata, crealm, cname, ticket, enc_part })
    }
}
