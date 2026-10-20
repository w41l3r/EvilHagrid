use anyhow::{bail, Result};
use rand::random;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::Sha256;

use crate::dungeon::krb_structures::*;
use crate::dungeon::floo_network;
use crate::dungeon::wand_utils;
use crate::dungeon::request_magic::TgtTicket;

// OIDs as byte arrays (content bytes only, without tag/length)
const OID_EC_PUBLIC_KEY: &[u8]    = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8]             = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SHA256: &[u8]           = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x04, 0x02, 0x01];
const OID_ECDSA_SHA256: &[u8]     = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_SIGNED_DATA: &[u8]      = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_PKINIT_AUTH_DATA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];
const PA_PK_AS_REQ: i32           = 16;
const PA_PK_AS_REP: i32           = 17;

// ── Public entry point ────────────────────────────────────────────────────────

pub fn pkinit_as_req(
    username: &str,
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
    etype: i32,
    dc: Option<&str>,
) -> Result<TgtTicket> {
    use p256::ecdh::EphemeralSecret;
    use p256::PublicKey;

    let cert_der = pem_to_der(cert_pem, "CERTIFICATE")?;
    let key_der  = pem_to_der_key(key_pem)?;

    // Load ECDSA signing key from PKCS#8 DER
    use pkcs8::DecodePrivateKey;
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der)
        .map_err(|e| anyhow::anyhow!("load ECDSA signing key: {:?}", e))?;

    let cert_info = parse_cert_issuer_serial(&cert_der)?;

    // Generate ephemeral ECDH keypair
    let client_dh_nonce: [u8; 32] = random();
    let ephemeral = EphemeralSecret::random(&mut rand::thread_rng());
    let client_pub = PublicKey::from(&ephemeral);
    let client_pub_bytes = client_pub.to_sec1_bytes().to_vec();

    // Build PKAuthenticator + AuthPack
    let nonce: u32 = random();
    let now = wand_utils::generalized_time_now();
    let pk_auth = build_pk_authenticator(&now, nonce)?;
    let auth_pack = build_auth_pack(&pk_auth, &client_pub_bytes, &client_dh_nonce)?;

    // Sign AuthPack in CMS SignedData
    let signed_data = build_cms_signed_data(&auth_pack, &signing_key, &cert_der, &cert_info)?;
    let pa_pkinit = build_pa_pk_as_req(&signed_data)?;

    // Send AS-REQ
    let cname = Glyph::new_principal(username);
    let pa_data = vec![
        Rune::pac_request(true),
        Rune { pa_type: PA_PK_AS_REQ, pa_value: pa_pkinit },
    ];
    let as_req = TomeRequest::new_as_req(cname, domain, &[etype], pa_data, nonce);
    let dc_addr = match dc {
        Some(d) => d.to_owned(),
        None => floo_network::resolve_dc(domain)?,
    };
    let resp = floo_network::send_receive_kdc(&dc_addr, &as_req.encode())?;

    if DarkProphecy::is_error(&resp) {
        let e = DarkProphecy::decode(&resp)?;
        bail!("PKINIT AS-REP error {}: {}", e.error_code, error_string(e.error_code));
    }

    // Parse AS-REP PA-PK-AS-REP to extract KDC ECDH public key
    let rep = TomeReply::decode(&resp)?;
    let server_pub_bytes = extract_kdc_ecdh_pub(&rep)?;

    // Compute ECDH shared secret Z (x-coordinate)
    let server_pub = p256::PublicKey::from_sec1_bytes(&server_pub_bytes)
        .map_err(|e| anyhow::anyhow!("parse KDC ECDH public key: {:?}", e))?;
    let shared = ephemeral.diffie_hellman(&server_pub);
    let z = shared.raw_secret_bytes().to_vec();

    // Derive AS session key from Z using X9.42 KDF
    let derived_key = kdf_x9_42(&z, etype, &client_dh_nonce, &[])?;

    // Decrypt enc-part of AS-REP with derived key
    parse_pkinit_as_rep(&resp, &derived_key, etype, username, domain)
}

// ── DER helpers for PKINIT ────────────────────────────────────────────────────

fn encode_oid(oid_bytes: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06, oid_bytes.len() as u8];
    v.extend_from_slice(oid_bytes);
    v
}

fn encode_raw_integer(bytes: &[u8]) -> Vec<u8> {
    // Wrap arbitrary bytes as a DER INTEGER TLV
    let mut v = vec![0x02];
    v.extend_from_slice(&encode_length(bytes.len()));
    v.extend_from_slice(bytes);
    v
}

fn build_pk_authenticator(now: &str, nonce: u32) -> Result<Vec<u8>> {
    let inner = [
        encode_ctx(0, &encode_integer(0)),                         // cusec
        encode_ctx(1, &encode_generalized_time(now)),              // ctime
        encode_ctx(2, &encode_integer(nonce as i64)),              // nonce
        encode_ctx(3, &encode_octet_string(&[0u8; 20])),           // paChecksum (placeholder)
    ].concat();
    Ok(encode_sequence(&inner))
}

fn build_spki_ecdh(pub_point: &[u8]) -> Vec<u8> {
    let alg = encode_sequence(&[encode_oid(OID_EC_PUBLIC_KEY), encode_oid(OID_P256)].concat());
    // BIT STRING: unused-bits=0, then the point
    let mut bit_str_content = vec![0x00u8];
    bit_str_content.extend_from_slice(pub_point);
    let bit_str = tlv(0x03, &bit_str_content);
    encode_sequence(&[alg, bit_str].concat())
}

fn build_auth_pack(pk_auth: &[u8], client_pub: &[u8], client_nonce: &[u8]) -> Result<Vec<u8>> {
    let spki = build_spki_ecdh(client_pub);
    let supported_cms = encode_ctx(2, &encode_sequence(&encode_sequence(&encode_oid(OID_ECDSA_SHA256))));
    let nonce_ctx = encode_ctx(3, &encode_octet_string(client_nonce));
    let inner = [
        encode_ctx(0, pk_auth),
        encode_ctx(1, &spki),
        supported_cms,
        nonce_ctx,
    ].concat();
    Ok(encode_sequence(&inner))
}

fn build_cms_signed_data(
    auth_pack: &[u8],
    signing_key: &p256::ecdsa::SigningKey,
    cert_der: &[u8],
    cert_info: &CertInfo,
) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::Signer;

    let mut hasher = Sha256::new();
    hasher.update(auth_pack);
    let digest = hasher.finalize();

    // encapContentInfo
    let enc_content = encode_sequence(&[
        encode_oid(OID_PKINIT_AUTH_DATA),
        tlv(0xa0, &encode_octet_string(auth_pack)),
    ].concat());

    // SHA-256 AlgorithmIdentifier
    let sha256_alg = encode_sequence(&[encode_oid(OID_SHA256), vec![0x05, 0x00]].concat());
    let digest_algos = tlv(0x31, &sha256_alg);

    // IssuerAndSerialNumber
    let issuer_serial = encode_sequence(&[
        cert_info.issuer_tlv.clone(),
        cert_info.serial_tlv.clone(),
    ].concat());

    // signerInfo
    let sig: p256::ecdsa::Signature = signing_key.sign(&digest);
    let sig_bytes = sig.to_der().as_bytes().to_vec();
    let signer_info = encode_sequence(&[
        encode_integer(3),                                         // CMSVersion 3
        encode_sequence(&[encode_integer(1), issuer_serial].concat()), // sid
        sha256_alg.clone(),                                        // digestAlgorithm
        encode_sequence(&encode_oid(OID_ECDSA_SHA256)),            // signatureAlgorithm
        encode_octet_string(&sig_bytes),                           // signature
    ].concat());
    let signer_infos = tlv(0x31, &signer_info);

    // certificates [0] IMPLICIT
    let mut certs_ctx = vec![0xa0u8];
    certs_ctx.extend_from_slice(&encode_length(cert_der.len()));
    certs_ctx.extend_from_slice(cert_der);

    let signed_data_inner = encode_sequence(&[
        encode_integer(3),
        digest_algos,
        enc_content,
        certs_ctx,
        signer_infos,
    ].concat());

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    Ok(encode_sequence(&[
        encode_oid(OID_SIGNED_DATA),
        tlv(0xa0, &signed_data_inner),
    ].concat()))
}

fn build_pa_pk_as_req(signed_data: &[u8]) -> Result<Vec<u8>> {
    Ok(encode_sequence(&encode_ctx(0, signed_data)))
}

// ── Parsing PA-PK-AS-REP ─────────────────────────────────────────────────────

fn extract_kdc_ecdh_pub(rep: &TomeReply) -> Result<Vec<u8>> {
    for pa in &rep.padata {
        if pa.pa_type == PA_PK_AS_REP {
            return scan_ec_point_in_bytes(&pa.pa_value);
        }
    }
    bail!("PA-PK-AS-REP not found in AS-REP padata")
}

fn scan_ec_point_in_bytes(data: &[u8]) -> Result<Vec<u8>> {
    // Find P-256 uncompressed EC point: 0x04 followed by 64 bytes
    for i in 0..data.len().saturating_sub(64) {
        if data[i] == 0x04 && i + 65 <= data.len() {
            let candidate = &data[i..i + 65];
            if p256::PublicKey::from_sec1_bytes(candidate).is_ok() {
                return Ok(candidate.to_vec());
            }
        }
    }
    bail!("could not find KDC ECDH public key in PA-PK-AS-REP")
}

// ── Key derivation (RFC 4556 §3.2.3.1, X9.42 KDF with SHA-1) ────────────────

fn kdf_x9_42(z: &[u8], etype: i32, party_u_nonce: &[u8], party_v_nonce: &[u8]) -> Result<Vec<u8>> {
    let (key_len, etype_oid): (usize, &[u8]) = match etype {
        ETYPE_RC4_HMAC => (16, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x11]),
        ETYPE_AES128_CTS_HMAC_SHA1_96 => (16, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x11]),
        ETYPE_AES256_CTS_HMAC_SHA1_96 => (32, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x12]),
        _ => bail!("unsupported etype {} for PKINIT key derivation", etype),
    };

    let key_info = encode_sequence(&encode_oid(etype_oid));
    let party_u = if party_u_nonce.is_empty() {
        vec![]
    } else {
        encode_ctx(0, &encode_octet_string(party_u_nonce))
    };
    let party_v = if party_v_nonce.is_empty() {
        vec![]
    } else {
        encode_ctx(1, &encode_octet_string(party_v_nonce))
    };
    let other_info = encode_sequence(&[key_info, party_u, party_v].concat());

    // K(i) = SHA1(4-byte-counter || Z || OtherInfo)
    let mut key_material = Vec::new();
    let mut counter = 1u32;
    while key_material.len() < key_len {
        let mut h = Sha1::new();
        h.update(counter.to_be_bytes());
        h.update(z);
        h.update(&other_info);
        key_material.extend_from_slice(&h.finalize());
        counter += 1;
    }
    key_material.truncate(key_len);
    Ok(key_material)
}

// ── Parse AS-REP with derived PKINIT key ─────────────────────────────────────

fn parse_pkinit_as_rep(
    data: &[u8],
    key: &[u8],
    _etype: i32,
    username: &str,
    domain: &str,
) -> Result<TgtTicket> {
    use crate::dungeon::potions;

    let rep = TomeReply::decode(data)?;
    let plaintext = potions::disenchant(rep.enc_part.etype, key, KU_AS_REP_ENC_PART, &rep.enc_part.cipher)?;
    let mut ep = DerParser::new(&plaintext);
    let inner = ep.expect_tag(TAG_ENC_AS_REP_PART)?;
    let mut p = DerParser::new(inner);
    let mut seq = p.enter_sequence()?;
    let session_key_bytes = seq.slice_ctx(0)?;
    let session_key = MagicKey::decode(session_key_bytes)?;

    while !seq.is_empty() && seq.peek_tag().map_or(false, |t| t < ctx_tag(5)) {
        let _ = seq.read_tlv()?;
    }
    let flags = if seq.peek_tag() == Some(ctx_tag(5)) {
        seq.enter_ctx(5)?.read_bit_string_flags()?
    } else { TF_FORWARDABLE };
    let auth_time = if seq.peek_tag() == Some(ctx_tag(6)) {
        seq.enter_ctx(6)?.read_generalized_time()?
    } else { wand_utils::generalized_time_now() };
    let start_time = if seq.peek_tag() == Some(ctx_tag(7)) {
        seq.enter_ctx(7)?.read_generalized_time()?
    } else { auth_time.clone() };
    let end_time = if seq.peek_tag() == Some(ctx_tag(8)) {
        seq.enter_ctx(8)?.read_generalized_time()?
    } else { wand_utils::now_plus_hours(10) };

    let ticket = Scroll::decode(&rep.ticket)?;
    let cred_info = KrbCredInfo {
        key: session_key.clone(),
        prealm: Some(domain.to_ascii_uppercase()),
        pname: Some(Glyph::new_principal(username)),
        flags: Some(flags),
        auth_time: Some(auth_time),
        start_time: Some(start_time.clone()),
        end_time: Some(end_time.clone()),
        renew_till: None,
        srealm: Some(domain.to_ascii_uppercase()),
        sname: Some(ticket.sname.clone()),
    };
    let kirbi = build_kirbi(&ticket, cred_info);
    Ok(TgtTicket {
        kirbi,
        session_key,
        realm: domain.to_ascii_uppercase(),
        client: username.to_owned(),
        start_time,
        end_time,
        flags,
    })
}

// ── Certificate utilities ─────────────────────────────────────────────────────

struct CertInfo {
    issuer_tlv: Vec<u8>,  // full TLV of the Name
    serial_tlv: Vec<u8>,  // full TLV of the serial INTEGER
}

fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    let marker = format!("-----BEGIN {}-----", label);
    let end_marker = format!("-----END {}-----", label);
    let start = pem.find(&marker)
        .ok_or_else(|| anyhow::anyhow!("missing PEM header: {}", label))?;
    let after = &pem[start + marker.len()..];
    let end = after.find(&end_marker)
        .ok_or_else(|| anyhow::anyhow!("missing PEM footer: {}", label))?;
    let b64 = after[..end].replace(['\n', '\r', ' '], "");
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(&b64)?)
}

fn pem_to_der_key(pem: &str) -> Result<Vec<u8>> {
    if pem.contains("BEGIN PRIVATE KEY") {
        return pem_to_der(pem, "PRIVATE KEY");
    }
    if pem.contains("BEGIN EC PRIVATE KEY") {
        let sec1 = pem_to_der(pem, "EC PRIVATE KEY")?;
        return sec1_to_pkcs8(&sec1);
    }
    bail!("unrecognised private key PEM type — expected PRIVATE KEY or EC PRIVATE KEY")
}

fn sec1_to_pkcs8(sec1: &[u8]) -> Result<Vec<u8>> {
    let alg_id = encode_sequence(&[encode_oid(OID_EC_PUBLIC_KEY), encode_oid(OID_P256)].concat());
    let pk_oct = encode_octet_string(sec1);
    Ok(encode_sequence(&[encode_integer(0), alg_id, pk_oct].concat()))
}

fn parse_cert_issuer_serial(cert_der: &[u8]) -> Result<CertInfo> {
    // Certificate ::= SEQUENCE { TBSCertificate, ... }
    // TBSCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, ... }
    let mut p = DerParser::new(cert_der);
    let mut outer = p.enter_sequence()?;
    let mut tbs = outer.enter_sequence()?;

    // Skip version [0] EXPLICIT if present (version 2/3 certificates)
    if tbs.peek_tag() == Some(0xa0) { let _ = tbs.read_tlv()?; }

    // serialNumber INTEGER — capture the full TLV
    let (serial_tag, serial_raw) = tbs.read_tlv()?;
    let serial_len_encoded = encode_length(serial_raw.len());
    let mut serial_tlv = vec![serial_tag];
    serial_tlv.extend_from_slice(&serial_len_encoded);
    serial_tlv.extend_from_slice(serial_raw);

    // signature AlgorithmIdentifier — skip
    let _ = tbs.read_tlv()?;

    // issuer Name — capture the full TLV (SEQUENCE of RDNs)
    let (issuer_tag, issuer_raw) = tbs.read_tlv()?;
    let issuer_len_encoded = encode_length(issuer_raw.len());
    let mut issuer_tlv = vec![issuer_tag];
    issuer_tlv.extend_from_slice(&issuer_len_encoded);
    issuer_tlv.extend_from_slice(issuer_raw);

    Ok(CertInfo { issuer_tlv, serial_tlv })
}
