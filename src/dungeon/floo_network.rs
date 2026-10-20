use anyhow::{bail, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket, SocketAddr};
use std::time::Duration;

const KDC_PORT: u16 = 88;
const UDP_MAX:  usize = 1400;
const TIMEOUT:  Duration = Duration::from_secs(10);

pub fn resolve_dc(domain: &str) -> Result<String> {
    // Try _kerberos._tcp SRV DNS lookup, fall back to domain name
    let srv = format!("_kerberos._tcp.{}", domain);
    if let Ok(ips) = dns_lookup::lookup_host(&srv) {
        if let Some(ip) = ips.first() {
            return Ok(ip.to_string());
        }
    }
    // Fall back to direct A record for domain
    if let Ok(ips) = dns_lookup::lookup_host(domain) {
        if let Some(ip) = ips.first() {
            return Ok(ip.to_string());
        }
    }
    bail!("could not resolve DC for domain {}", domain)
}

pub fn send_receive_kdc(dc: &str, request: &[u8]) -> Result<Vec<u8>> {
    if request.len() < UDP_MAX {
        match send_udp(dc, request) {
            Ok(resp) if resp.first().copied() != Some(0x7e) => return Ok(resp),
            Ok(resp) => return Ok(resp),
            Err(_) => {}
        }
    }
    send_tcp(dc, request)
}

fn send_udp(dc: &str, request: &[u8]) -> Result<Vec<u8>> {
    let addr: SocketAddr = format!("{}:{}", dc, KDC_PORT).parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    socket.send_to(request, addr)?;
    let mut buf = vec![0u8; 65535];
    let (n, _) = socket.recv_from(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

fn send_tcp(dc: &str, request: &[u8]) -> Result<Vec<u8>> {
    let addr = format!("{}:{}", dc, KDC_PORT);
    let mut stream = TcpStream::connect_timeout(
        &addr.parse()?,
        TIMEOUT,
    )?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    // TCP Kerberos: 4-byte big-endian length prefix
    let len = request.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(request)?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

pub fn send_as_req(domain: &str, request: &[u8]) -> Result<Vec<u8>> {
    let dc = resolve_dc(domain)?;
    send_receive_kdc(&dc, request)
}

pub fn send_tgs_req(domain: &str, request: &[u8]) -> Result<Vec<u8>> {
    let dc = resolve_dc(domain)?;
    send_receive_kdc(&dc, request)
}
