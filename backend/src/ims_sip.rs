//! Minimal 3GPP IMS SIP REGISTER primitives.

use anyhow::{anyhow, Result};
use std::net::Ipv6Addr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipRegistration {
    pub private_identity: String,
    pub public_identity: String,
    pub realm: String,
    pub nonce: String,
    pub aka_res_hex: String,
    pub call_id: String,
    pub cseq: u32,
    pub contact_host: Ipv6Addr,
    pub contact_port: u16,
}

pub fn parse_pcscf_address(output: &str) -> Option<Ipv6Addr> {
    output.lines().find_map(|line| {
        let (_, value) = line.split_once(':')?;
        let label = line.split_once(':')?.0.trim().to_ascii_lowercase();
        if !label.contains("p-cscf") && !label.contains("pcscf") {
            return None;
        }
        value
            .trim()
            .trim_matches(['\'', '"', '[', ']'])
            .parse()
            .ok()
    })
}

pub fn parse_pcscf_from_cgcontrdp(output: &str) -> Option<Ipv6Addr> {
    output.lines().find_map(|line| {
        let line = line.trim();
        if !line.to_ascii_uppercase().starts_with("+CGCONTRDP:") {
            return None;
        }
        line.split_once(':')?
            .1
            .split(',')
            .skip(8)
            .take(2)
            .map(|value| value.trim().trim_matches(['\'', '"', '[', ']']))
            .find_map(|value| value.parse().ok())
    })
}

fn md5_hex(value: &str) -> String {
    let digest = md5::compute(value.as_bytes());
    format!("{digest:x}")
}

pub fn aka_md5_response(
    username: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    aka_res_hex: &str,
) -> Result<String> {
    if username.is_empty() || realm.is_empty() || nonce.is_empty() || aka_res_hex.is_empty() {
        return Err(anyhow!("IMS AKA digest fields must not be empty"));
    }
    let ha1 = md5_hex(&format!("{username}:{realm}:{aka_res_hex}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    Ok(md5_hex(&format!("{ha1}:{nonce}:{ha2}")))
}

pub fn build_register(registration: &SipRegistration, branch: &str) -> Result<String> {
    if branch.is_empty() || registration.call_id.is_empty() {
        return Err(anyhow!("SIP branch and Call-ID are required"));
    }
    let uri = format!("sip:{}", registration.realm);
    let response = aka_md5_response(
        &registration.private_identity,
        &registration.realm,
        &registration.nonce,
        "REGISTER",
        &uri,
        &registration.aka_res_hex,
    )?;
    let contact_identity = registration
        .public_identity
        .strip_prefix("sip:")
        .unwrap_or(&registration.public_identity);
    let contact = format!("sip:{}@{}:{}", contact_identity, registration.contact_host, registration.contact_port);

    Ok(format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP [{}]:{};branch={branch};rport\r\n\
From: <{}>;tag=simadmin\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: {} REGISTER\r\n\
Contact: <{}>\r\n\
Max-Forwards: 70\r\n\
User-Agent: SimAdmin\r\n\
Authorization: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm=AKAv1-MD5\r\n\
Content-Length: 0\r\n\r\n",
        registration.contact_host,
        registration.contact_port,
        registration.public_identity,
        registration.public_identity,
        registration.call_id,
        registration.cseq,
        contact,
        registration.private_identity,
        registration.realm,
        registration.nonce,
        uri,
        response
    ))
}

pub fn build_initial_register(registration: &SipRegistration, branch: &str) -> Result<String> {
    if branch.is_empty() || registration.call_id.is_empty() {
        return Err(anyhow!("SIP branch and Call-ID are required"));
    }
    let uri = format!("sip:{}", registration.realm);
    let contact_identity = registration
        .public_identity
        .strip_prefix("sip:")
        .unwrap_or(&registration.public_identity);
    let contact = format!(
        "sip:{}@{}:{}",
        contact_identity, registration.contact_host, registration.contact_port
    );
    Ok(format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP [{}]:{};branch={branch};rport\r\n\
From: <{}>;tag=simadmin\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: {} REGISTER\r\n\
Contact: <{}>\r\n\
Max-Forwards: 70\r\n\
User-Agent: SimAdmin\r\n\
Content-Length: 0\r\n\r\n",
        registration.contact_host,
        registration.contact_port,
        registration.public_identity,
        registration.public_identity,
        registration.call_id,
        registration.cseq,
        contact
    ))
}

pub fn sip_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let mut fields = first_line.split_whitespace();
    if fields.next()? != "SIP/2.0" {
        return None;
    }
    fields.next()?.parse().ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityServer {
    pub client_spi: u32,
    pub server_spi: u32,
    pub client_port: u16,
    pub server_port: u16,
}

pub fn parse_security_server(response: &str) -> Option<SecurityServer> {
    let header = response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("security-server:"))?;
    let value = header.split_once(':')?.1;
    let parameter = |name: &str| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().trim_matches('"'))
        })
    };
    let parse_u32 = |name: &str| {
        let value = parameter(name)?;
        u32::from_str_radix(value.trim_start_matches("0x"), 16)
            .or_else(|_| value.parse())
            .ok()
    };
    Some(SecurityServer {
        client_spi: parse_u32("spi-c")?,
        server_spi: parse_u32("spi-s")?,
        client_port: parameter("port-c")?.parse().ok()?,
        server_port: parameter("port-s")?.parse().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaChallenge {
    pub realm: String,
    pub nonce: String,
}

pub fn build_security_client_header(
    client_spi: u32,
    server_spi: u32,
    client_port: u16,
    server_port: u16,
) -> String {
    format!(
        "Security-Client: ipsec-3gpp;prot=esp;mod=trans;spi-c=0x{client_spi:08x};spi-s=0x{server_spi:08x};port-c={client_port};port-s={server_port};alg=hmac-md5-96;ealg=null\r\n"
    )
}

pub fn build_register_with_security(
    registration: &SipRegistration,
    branch: &str,
    security_header: &str,
) -> Result<String> {
    let request = build_register(registration, branch)?;
    let marker = "Content-Length: 0\r\n";
    let position = request
        .find(marker)
        .ok_or_else(|| anyhow!("SIP REGISTER content length header is missing"))?;
    let mut secured = String::with_capacity(request.len() + security_header.len());
    secured.push_str(&request[..position]);
    secured.push_str(security_header);
    secured.push_str(&request[position..]);
    Ok(secured)
}

pub fn parse_aka_challenge(response: &str) -> Option<AkaChallenge> {
    let header = response.lines().find(|line| {
        line.to_ascii_lowercase().starts_with("www-authenticate:")
            && line.to_ascii_lowercase().contains("aka")
    })?;
    let value = header.split_once(':')?.1;
    let parameter = |name: &str| {
        value.split(',').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            (key.trim().eq_ignore_ascii_case(name))
                .then(|| value.trim().trim_matches('"').to_string())
        })
    };
    Some(AkaChallenge {
        realm: parameter("realm")?,
        nonce: parameter("nonce")?,
    })
}

pub async fn send_udp_request(
    local: Ipv6Addr,
    remote: Ipv6Addr,
    remote_port: u16,
    request: &str,
) -> Result<String> {
    send_udp_request_from_port(local, 0, remote, remote_port, request).await
}

pub async fn send_udp_request_from_port(
    local: Ipv6Addr,
    local_port: u16,
    remote: Ipv6Addr,
    remote_port: u16,
    request: &str,
) -> Result<String> {
    let socket = UdpSocket::bind((local, local_port)).await?;
    socket.connect((remote, remote_port)).await?;
    socket.send(request.as_bytes()).await?;
    let mut buffer = vec![0u8; 8192];
    let length = timeout(Duration::from_secs(10), socket.recv(&mut buffer))
        .await
        .map_err(|_| anyhow!("timed out waiting for SIP response"))??;
    Ok(String::from_utf8_lossy(&buffer[..length]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pcscf_ipv6() {
        assert_eq!(
            parse_pcscf_address("P-CSCF address: '[2001:db8::5]'"),
            Some("2001:db8::5".parse().unwrap())
        );
    }

    #[test]
    fn parses_pcscf_from_cgcontrdp() {
        let response = "+CGCONTRDP: 4,5,\"ims\",\"2001:db8::10\",\"::\",\"2001:db8::1\",\"::\",\"::\",\"2001:db8::5\",\"::\"";
        assert_eq!(
            parse_pcscf_from_cgcontrdp(response),
            Some("2001:db8::5".parse().unwrap())
        );
    }

    #[test]
    fn builds_aka_register() {
        let request = build_register(
            &SipRegistration {
                private_identity: "460001234567890".into(),
                public_identity: "sip:460001234567890@ims.example".into(),
                realm: "ims.example".into(),
                nonce: "nonce".into(),
                aka_res_hex: "0011223344556677".into(),
                call_id: "call-id".into(),
                cseq: 1,
                contact_host: "2001:db8::10".parse().unwrap(),
                contact_port: 5060,
            },
            "z9hG4bK-test",
        )
        .unwrap();
        assert!(request.starts_with("REGISTER sip:ims.example SIP/2.0"));
        assert!(request.contains("algorithm=AKAv1-MD5"));
    }

    #[test]
    fn parses_sip_status() {
        assert_eq!(sip_status_code("SIP/2.0 200 OK\r\n"), Some(200));
    }

    #[test]
    fn parses_aka_challenge() {
        let response = "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest algorithm=AKAv1-MD5, realm=\"ims.example\", nonce=\"abc\"\r\n";
        assert_eq!(
            parse_aka_challenge(response),
            Some(AkaChallenge {
                realm: "ims.example".into(),
                nonce: "abc".into()
            })
        );
    }

    #[test]
    fn builds_beta9_ipsec_security_header() {
        let header = build_security_client_header(1, 2, 5062, 5060);
        assert!(header.contains("alg=hmac-md5-96;ealg=null"));
        assert!(header.contains("spi-c=0x00000001"));
    }

    #[test]
    fn parses_security_server() {
        let response = "Security-Server: ipsec-3gpp;prot=esp;mod=trans;spi-c=0x1;spi-s=0x2;port-c=5062;port-s=5060;alg=hmac-md5-96;ealg=null\r\n";
        assert_eq!(
            parse_security_server(response),
            Some(SecurityServer {
                client_spi: 1,
                server_spi: 2,
                client_port: 5062,
                server_port: 5060
            })
        );
    }
}
