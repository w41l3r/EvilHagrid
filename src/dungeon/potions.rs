use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use aes::{Aes128, Aes256};
use cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};

type HmacMd5  = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

use crate::dungeon::krb_structures::constants::*;

// ── NT hash (MD4 of UTF-16LE password) ───────────────────────────────────────

pub fn brew_nt_hash(password: &str) -> Vec<u8> {
    let utf16le: Vec<u8> = password.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    md4_digest(&utf16le)
}

fn md4_digest(data: &[u8]) -> Vec<u8> {
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xefcd_ab89;
    let mut c: u32 = 0x98ba_dcfe;
    let mut d: u32 = 0x1032_5476;

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            let idx = i * 4;
            *word = u32::from_le_bytes([chunk[idx], chunk[idx+1], chunk[idx+2], chunk[idx+3]]);
        }
        let (aa, bb, cc, dd) = (a, b, c, d);
        macro_rules! F { ($x:expr,$y:expr,$z:expr) => (($x & $y) | (!$x & $z)) }
        macro_rules! G { ($x:expr,$y:expr,$z:expr) => (($x & $y) | ($x & $z) | ($y & $z)) }
        macro_rules! H { ($x:expr,$y:expr,$z:expr) => ($x ^ $y ^ $z) }
        macro_rules! r1 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = $a.wrapping_add(F!($b,$c,$d)).wrapping_add(x[$k]).rotate_left($s);
        }}
        macro_rules! r2 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = $a.wrapping_add(G!($b,$c,$d)).wrapping_add(x[$k]).wrapping_add(0x5a82_7999).rotate_left($s);
        }}
        macro_rules! r3 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = $a.wrapping_add(H!($b,$c,$d)).wrapping_add(x[$k]).wrapping_add(0x6ed9_eba1).rotate_left($s);
        }}
        r1!(a,b,c,d, 0,3); r1!(d,a,b,c, 1,7); r1!(c,d,a,b, 2,11); r1!(b,c,d,a, 3,19);
        r1!(a,b,c,d, 4,3); r1!(d,a,b,c, 5,7); r1!(c,d,a,b, 6,11); r1!(b,c,d,a, 7,19);
        r1!(a,b,c,d, 8,3); r1!(d,a,b,c, 9,7); r1!(c,d,a,b,10,11); r1!(b,c,d,a,11,19);
        r1!(a,b,c,d,12,3); r1!(d,a,b,c,13,7); r1!(c,d,a,b,14,11); r1!(b,c,d,a,15,19);
        r2!(a,b,c,d, 0,3); r2!(d,a,b,c, 4,5); r2!(c,d,a,b, 8,9); r2!(b,c,d,a,12,13);
        r2!(a,b,c,d, 1,3); r2!(d,a,b,c, 5,5); r2!(c,d,a,b, 9,9); r2!(b,c,d,a,13,13);
        r2!(a,b,c,d, 2,3); r2!(d,a,b,c, 6,5); r2!(c,d,a,b,10,9); r2!(b,c,d,a,14,13);
        r2!(a,b,c,d, 3,3); r2!(d,a,b,c, 7,5); r2!(c,d,a,b,11,9); r2!(b,c,d,a,15,13);
        r3!(a,b,c,d, 0,3); r3!(d,a,b,c, 8,9); r3!(c,d,a,b, 4,11); r3!(b,c,d,a,12,15);
        r3!(a,b,c,d, 2,3); r3!(d,a,b,c,10,9); r3!(c,d,a,b, 6,11); r3!(b,c,d,a,14,15);
        r3!(a,b,c,d, 1,3); r3!(d,a,b,c, 9,9); r3!(c,d,a,b, 5,11); r3!(b,c,d,a,13,15);
        r3!(a,b,c,d, 3,3); r3!(d,a,b,c,11,9); r3!(c,d,a,b, 7,11); r3!(b,c,d,a,15,15);
        a = a.wrapping_add(aa); b = b.wrapping_add(bb);
        c = c.wrapping_add(cc); d = d.wrapping_add(dd);
    }
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&a.to_le_bytes()); out.extend_from_slice(&b.to_le_bytes());
    out.extend_from_slice(&c.to_le_bytes()); out.extend_from_slice(&d.to_le_bytes());
    out
}

// ── RC4-HMAC (etype 23) ───────────────────────────────────────────────────────

pub fn rc4_hmac_encrypt(key: &[u8], key_usage: i32, plaintext: &[u8]) -> Vec<u8> {
    let usage_bytes = (key_usage as u32).to_le_bytes();
    let k1 = hmac_md5(key, &usage_bytes);
    let mut confounder = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut confounder);
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);
    let ks = rc4_keystream(&hmac_md5(&k1, &confounder), data.len());
    let ciphertext: Vec<u8> = data.iter().zip(ks).map(|(a, b)| a ^ b).collect();
    let checksum = hmac_md5(&k1, &ciphertext);
    let mut out = checksum;
    out.extend_from_slice(&ciphertext);
    out
}

pub fn rc4_hmac_decrypt(key: &[u8], key_usage: i32, ciphertext_with_mac: &[u8]) -> Result<Vec<u8>> {
    if ciphertext_with_mac.len() < 24 { bail!("RC4-HMAC ciphertext too short"); }
    let (checksum, ciphertext) = ciphertext_with_mac.split_at(16);
    let usage_bytes = (key_usage as u32).to_le_bytes();
    let k1 = hmac_md5(key, &usage_bytes);
    let k3 = hmac_md5(&k1, checksum);
    let ks = rc4_keystream(&k3, ciphertext.len());
    let plaintext: Vec<u8> = ciphertext.iter().zip(ks).map(|(a, b)| a ^ b).collect();
    let expected_mac = hmac_md5(&k1, ciphertext);
    if expected_mac != checksum { bail!("RC4-HMAC integrity check failed"); }
    if plaintext.len() < 8 { bail!("plaintext too short after decrypt"); }
    Ok(plaintext[8..].to_vec())
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn rc4_keystream(key: &[u8], len: usize) -> Vec<u8> {
    use rc4::{Rc4, KeyInit as Rc4KeyInit, StreamCipher};
    // rc4 crate requires fixed-size key; use a 16-byte key (typical for HMAC-MD5 output)
    let k16: Vec<u8> = if key.len() == 16 { key.to_vec() } else {
        let mut k = vec![0u8; 16];
        let copy = key.len().min(16);
        k[..copy].copy_from_slice(&key[..copy]);
        k
    };
    type Rc4_16 = Rc4<rc4::consts::U16>;
    let mut stream = Rc4_16::new_from_slice(&k16).unwrap();
    let mut ks = vec![0u8; len];
    stream.apply_keystream(&mut ks);
    ks
}

// ── AES raw ECB single-block (for key derivation) ────────────────────────────

fn aes256_ecb_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

fn aes128_ecb_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut b = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

// ── AES string-to-key (RFC 3962) ──────────────────────────────────────────────

pub fn aes256_string_to_key(password: &str, salt: &str, iterations: u32) -> Vec<u8> {
    let mut tkey = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), iterations, &mut tkey);
    dk_aes256(&tkey, b"kerberos")
}

pub fn aes128_string_to_key(password: &str, salt: &str, iterations: u32) -> Vec<u8> {
    let mut tkey = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), iterations, &mut tkey);
    dk_aes128(&tkey, b"kerberos")
}

fn nfold(n_bits: usize, input: &[u8]) -> Vec<u8> {
    // n-fold algorithm from RFC 3961 §5.1
    let n = n_bits / 8;
    let k = input.len();
    let lcm = n * k / gcd(n, k);
    let reps = lcm / k;
    let mut buf = Vec::with_capacity(lcm);
    for i in 0..reps {
        let mut part = input.to_vec();
        let rotate = 13 * i % (8 * k);
        let byte_rot = rotate / 8;
        let bit_rot  = rotate % 8;
        part = rotate_bytes_right(&part, byte_rot, bit_rot);
        buf.extend_from_slice(&part);
    }
    // truncate/sum to n bytes
    let mut out = vec![0u8; n];
    let mut carry = 0u16;
    for i in (0..n).rev() {
        let sum: u16 = out[i] as u16 + buf.chunks(n).fold(0u16, |acc, chunk| {
            acc + chunk.get(i).copied().unwrap_or(0) as u16
        }) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn rotate_bytes_right(input: &[u8], bytes: usize, bits: usize) -> Vec<u8> {
    let n = input.len();
    let mut out = vec![0u8; n];
    for i in 0..n {
        let src = (i + n - bytes) % n;
        out[i] = (input[src] >> bits) | (input[(src + n - 1) % n] << (8 - bits));
    }
    out
}

fn dk_aes256(base_key: &[u8; 32], constant: &[u8]) -> Vec<u8> {
    let folded = nfold(128, constant);
    let mut block = [0u8; 16];
    block.copy_from_slice(&folded[..16]);
    let mut result = Vec::with_capacity(32);
    let b1 = aes256_ecb_block(base_key, &block);
    let b2 = aes256_ecb_block(base_key, &b1);
    result.extend_from_slice(&b1);
    result.extend_from_slice(&b2);
    result
}

fn dk_aes128(base_key: &[u8; 16], constant: &[u8]) -> Vec<u8> {
    let folded = nfold(128, constant);
    let mut block = [0u8; 16];
    block.copy_from_slice(&folded[..16]);
    let b = aes128_ecb_block(base_key, &block);
    b.to_vec()
}

// ── AES-CBC helpers (used in CTS) ────────────────────────────────────────────

fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 16 == 0, "AES-CBC input must be block-aligned");
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    let cipher = Aes256::new(GenericArray::from_slice(key));
    for block in data.chunks(16) {
        let mut b = [0u8; 16];
        for i in 0..16 { b[i] = block[i] ^ prev[i]; }
        let mut ga = GenericArray::from(b);
        cipher.encrypt_block(&mut ga);
        let enc: [u8; 16] = ga.into();
        out.extend_from_slice(&enc);
        prev = enc;
    }
    out
}

fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 16 == 0);
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    let cipher = Aes256::new(GenericArray::from_slice(key));
    for block in data.chunks(16) {
        let mut b: [u8; 16] = block.try_into().unwrap();
        let saved = b;
        let mut ga = GenericArray::from(b);
        cipher.decrypt_block(&mut ga);
        let dec: [u8; 16] = ga.into();
        for i in 0..16 { out.push(dec[i] ^ prev[i]); }
        prev = saved;
    }
    out
}

fn aes128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!(data.len() % 16 == 0);
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for block in data.chunks(16) {
        let b: [u8; 16] = block.try_into().unwrap();
        let saved = b;
        let mut ga = GenericArray::from(b);
        cipher.decrypt_block(&mut ga);
        let dec: [u8; 16] = ga.into();
        for i in 0..16 { out.push(dec[i] ^ prev[i]); }
        prev = saved;
    }
    out
}

// ── AES-256-CTS-HMAC-SHA1-96 (etype 18) ──────────────────────────────────────

pub fn aes256_cts_encrypt(key: &[u8], key_usage: i32, plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 { bail!("AES-256 key must be 32 bytes"); }
    let key32: [u8; 32] = key.try_into().unwrap();
    let ke = derive_aes256_subkey(&key32, key_usage, b"\xaa")?;
    let ki = derive_aes256_subkey(&key32, key_usage, b"\x55")?;
    let mut confounder = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut confounder);
    let mut data = confounder.to_vec();
    data.extend_from_slice(plaintext);
    let ciphertext = cts_encrypt_aes256(&ke.try_into().unwrap(), &data)?;
    let mut mac_input = confounder.to_vec();
    mac_input.extend_from_slice(plaintext);
    let mac = hmac_sha1_truncate(&ki, &mac_input, 12);
    let mut out = mac;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn aes256_cts_decrypt(key: &[u8], key_usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 { bail!("AES-256 key must be 32 bytes"); }
    if ciphertext.len() < 12 { bail!("AES-256-CTS ciphertext too short"); }
    let key32: [u8; 32] = key.try_into().unwrap();
    let ke = derive_aes256_subkey(&key32, key_usage, b"\xaa")?;
    let ki = derive_aes256_subkey(&key32, key_usage, b"\x55")?;
    let (mac, ct) = ciphertext.split_at(12);
    let plaintext = cts_decrypt_aes256(&ke.try_into().map_err(|_| anyhow::anyhow!("key len"))?, ct)?;
    if plaintext.len() < 16 { bail!("AES-256 plaintext too short after decrypt"); }
    let expected_mac = hmac_sha1_truncate(&ki, &plaintext, 12);
    if expected_mac != mac { bail!("AES-256 integrity check failed"); }
    Ok(plaintext[16..].to_vec())
}

pub fn aes128_cts_decrypt(key: &[u8], key_usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 16 { bail!("AES-128 key must be 16 bytes"); }
    if ciphertext.len() < 12 { bail!("AES-128-CTS ciphertext too short"); }
    let key16: [u8; 16] = key.try_into().unwrap();
    let ke = derive_aes128_subkey(&key16, key_usage, b"\xaa")?;
    let ki = derive_aes128_subkey(&key16, key_usage, b"\x55")?;
    let (mac, ct) = ciphertext.split_at(12);
    let plaintext = cts_decrypt_aes128(&ke.try_into().map_err(|_| anyhow::anyhow!("key len"))?, ct)?;
    if plaintext.len() < 16 { bail!("AES-128 plaintext too short after decrypt"); }
    let expected_mac = hmac_sha1_truncate(&ki, &plaintext, 12);
    if expected_mac != mac { bail!("AES-128 integrity check failed"); }
    Ok(plaintext[16..].to_vec())
}

fn derive_aes256_subkey(key: &[u8; 32], usage: i32, purpose: &[u8]) -> Result<Vec<u8>> {
    let usage_bytes = (usage as u32).to_be_bytes();
    let constant = [usage_bytes.as_slice(), purpose].concat();
    Ok(dk_aes256(key, &constant))
}

fn derive_aes128_subkey(key: &[u8; 16], usage: i32, purpose: &[u8]) -> Result<Vec<u8>> {
    let usage_bytes = (usage as u32).to_be_bytes();
    let constant = [usage_bytes.as_slice(), purpose].concat();
    Ok(dk_aes128(key, &constant))
}

fn hmac_sha1_truncate(key: &[u8], data: &[u8], truncate: usize) -> Vec<u8> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize().into_bytes();
    result[..truncate.min(result.len())].to_vec()
}

fn cts_encrypt_aes256(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 { bail!("CTS requires at least one block"); }
    let iv = [0u8; 16];
    if data.len() % 16 == 0 {
        return Ok(aes256_cbc_encrypt(key, &iv, data));
    }
    let blocks = (data.len() + 15) / 16;
    let last_block_size = data.len() - (blocks - 1) * 16;
    // pad last block and CBC-encrypt the whole thing
    let mut padded = data[..(blocks - 1) * 16].to_vec();
    let mut last_padded = [0u8; 16];
    last_padded[..last_block_size].copy_from_slice(&data[(blocks - 1) * 16..]);
    padded.extend_from_slice(&last_padded);
    let encrypted = aes256_cbc_encrypt(key, &iv, &padded);
    // swap last two ciphertext blocks (CTS)
    let n = encrypted.len();
    let mut out = encrypted[..n - 32].to_vec();
    out.extend_from_slice(&encrypted[n - 16..]);       // last full block → second-to-last slot
    out.extend_from_slice(&encrypted[n - 32..n - 32 + last_block_size]);
    Ok(out)
}

fn cts_decrypt_aes256(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 { bail!("CTS ciphertext too short"); }
    let iv = [0u8; 16];
    if data.len() % 16 == 0 {
        return Ok(aes256_cbc_decrypt(key, &iv, data));
    }
    let last_block_size = data.len() % 16;
    let full_blocks = data.len() / 16;
    // reconstruct standard CBC order for decryption
    let before_last_two = full_blocks.saturating_sub(1) * 16;
    let mut reordered = data[..before_last_two].to_vec();
    // the last partial block bytes complete the second-to-last ciphertext block
    let mut penultimate = [0u8; 16];
    penultimate[..last_block_size].copy_from_slice(&data[data.len() - last_block_size..]);
    penultimate[last_block_size..].copy_from_slice(&data[before_last_two..][..16 - last_block_size]);
    reordered.extend_from_slice(&penultimate);
    reordered.extend_from_slice(&data[before_last_two..before_last_two + 16]);
    let decrypted = aes256_cbc_decrypt(key, &iv, &reordered);
    Ok(decrypted[..before_last_two + 16 + last_block_size].to_vec())
}

fn cts_decrypt_aes128(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 16 { bail!("CTS-128 ciphertext too short"); }
    let iv = [0u8; 16];
    if data.len() % 16 == 0 {
        return Ok(aes128_cbc_decrypt(key, &iv, data));
    }
    let last_block_size = data.len() % 16;
    let full_blocks = data.len() / 16;
    let before_last_two = full_blocks.saturating_sub(1) * 16;
    let mut reordered = data[..before_last_two].to_vec();
    let mut penultimate = [0u8; 16];
    penultimate[..last_block_size].copy_from_slice(&data[data.len() - last_block_size..]);
    penultimate[last_block_size..].copy_from_slice(&data[before_last_two..][..16 - last_block_size]);
    reordered.extend_from_slice(&penultimate);
    reordered.extend_from_slice(&data[before_last_two..before_last_two + 16]);
    let decrypted = aes128_cbc_decrypt(key, &iv, &reordered);
    Ok(decrypted[..before_last_two + 16 + last_block_size].to_vec())
}

// ── Generic encrypt / decrypt dispatch ───────────────────────────────────────

pub fn enchant(etype: i32, key: &[u8], key_usage: i32, plaintext: &[u8]) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => Ok(rc4_hmac_encrypt(key, key_usage, plaintext)),
        ETYPE_AES256_CTS_HMAC_SHA1_96 => aes256_cts_encrypt(key, key_usage, plaintext),
        _ => bail!("unsupported etype {} for encryption", etype),
    }
}

pub fn disenchant(etype: i32, key: &[u8], key_usage: i32, ciphertext: &[u8]) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => rc4_hmac_decrypt(key, key_usage, ciphertext),
        ETYPE_AES256_CTS_HMAC_SHA1_96 => aes256_cts_decrypt(key, key_usage, ciphertext),
        ETYPE_AES128_CTS_HMAC_SHA1_96 => aes128_cts_decrypt(key, key_usage, ciphertext),
        _ => bail!("unsupported etype {}", etype),
    }
}

pub fn kerberos_salt(username: &str, domain: &str) -> String {
    let is_computer = username.ends_with('$');
    if is_computer {
        let name = username.trim_end_matches('$').to_ascii_lowercase();
        format!("{}host{}.{}", domain.to_ascii_uppercase(), name, domain.to_ascii_lowercase())
    } else {
        format!("{}{}", domain.to_ascii_uppercase(), username)
    }
}

pub fn string_to_key(etype: i32, password: &str, salt: &str) -> Result<Vec<u8>> {
    match etype {
        ETYPE_RC4_HMAC => Ok(brew_nt_hash(password)),
        ETYPE_AES256_CTS_HMAC_SHA1_96 => Ok(aes256_string_to_key(password, salt, 4096)),
        ETYPE_AES128_CTS_HMAC_SHA1_96 => Ok(aes128_string_to_key(password, salt, 4096)),
        _ => bail!("unsupported etype {} for string-to-key", etype),
    }
}
