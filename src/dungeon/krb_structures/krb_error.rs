use super::der::*;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct DarkProphecy {
    pub pvno:       u8,
    pub msg_type:   u8,
    pub stime:      String,
    pub susec:      u32,
    pub error_code: i32,
    pub crealm:     Option<String>,
    pub cname:      Option<Vec<u8>>,
    pub realm:      String,
    pub sname:      Vec<u8>,
    pub e_text:     Option<String>,
    pub e_data:     Option<Vec<u8>>,
}

impl DarkProphecy {
    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut p = DerParser::new(data);
        let raw = p.expect_tag(0x7e)?;
        let mut outer = DerParser::new(raw);
        let mut seq = outer.enter_sequence()?;

        let pvno       = seq.enter_ctx(0)?.read_uint32()? as u8;
        let msg_type   = seq.enter_ctx(1)?.read_uint32()? as u8;
        let _ctime     = seq.optional_ctx(2).and_then(|mut p| p.read_generalized_time().ok());
        let _cusec     = seq.optional_ctx(3).and_then(|mut p| p.read_uint32().ok());
        let stime      = seq.enter_ctx(4)?.read_generalized_time()?;
        let susec      = seq.enter_ctx(5)?.read_uint32()?;
        let error_code = seq.enter_ctx(6)?.read_integer_i32()?;
        let crealm     = seq.optional_ctx(7).and_then(|mut p| p.read_general_string().ok());
        let cname      = if seq.peek_tag() == Some(ctx_tag(8)) {
            Some(seq.slice_ctx(8)?.to_vec())
        } else { None };
        let realm  = seq.enter_ctx(9)?.read_general_string()?;
        let sname  = seq.slice_ctx(10)?.to_vec();
        let e_text = seq.optional_ctx(11).and_then(|mut p| p.read_general_string().ok());
        let e_data = if seq.peek_tag() == Some(ctx_tag(12)) {
            Some(seq.enter_ctx(12)?.read_octet_string()?)
        } else { None };

        Ok(Self { pvno, msg_type, stime, susec, error_code, crealm, cname, realm, sname, e_text, e_data })
    }

    pub fn is_error(data: &[u8]) -> bool {
        data.first().copied() == Some(0x7e)
    }
}
