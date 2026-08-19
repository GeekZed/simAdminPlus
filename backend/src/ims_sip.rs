//! Minimal 3GPP IMS SIP REGISTER primitives.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::net::{IpAddr, Ipv6Addr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipRegistration {
    pub private_identity: String,
    pub public_identity: String,
    pub realm: String,
    pub nonce: String,
    pub aka_res: Vec<u8>,
    pub digest_algorithm: String,
    pub digest_qop: Option<String>,
    pub digest_opaque: Option<String>,
    pub digest_proxy: bool,
    pub cnonce: String,
    pub nonce_count: u32,
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
    parse_pcscf_candidates_from_cgcontrdp(output, "ims")
        .into_iter()
        .next()
}

pub fn parse_pcscf_candidates_from_cgcontrdp(output: &str, apn: &str) -> Vec<Ipv6Addr> {
    let mut candidates = Vec::new();
    for line in output.lines() {
        let Some((_, values)) = line.split_once("+CGCONTRDP:") else {
            continue;
        };
        let fields: Vec<&str> = values.split(',').map(str::trim).collect();
        if fields.len() < 8
            || !fields[2]
                .trim_matches(['\'', '"'])
                .eq_ignore_ascii_case(apn)
        {
            continue;
        }
        for field in fields.iter().skip(7).take(2) {
            for address in parse_cgcontrdp_addresses(field) {
                let IpAddr::V6(address) = address else {
                    continue;
                };
                if !address.is_unspecified() && !candidates.contains(&address) {
                    candidates.push(address);
                }
            }
        }
    }
    candidates
}

fn parse_cgcontrdp_addresses(field: &str) -> Vec<IpAddr> {
    field
        .trim_matches(|character| matches!(character, '\'' | '"' | '[' | ']'))
        .split_whitespace()
        .filter_map(|value| {
            if let Ok(address) = value.parse::<IpAddr>() {
                return Some(address);
            }
            let octets: Vec<u8> = value
                .split('.')
                .map(str::parse::<u8>)
                .collect::<Result<_, _>>()
                .ok()?;
            match octets.len() {
                4 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
                    octets[0], octets[1], octets[2], octets[3],
                ))),
                16 => {
                    let bytes: [u8; 16] = octets.try_into().ok()?;
                    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
                }
                _ => None,
            }
        })
        .collect()
}

fn md5_hex(value: &[u8]) -> String {
    let digest = md5::compute(value);
    format!("{digest:x}")
}

pub fn aka_md5_response(
    username: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    aka_res: &[u8],
) -> Result<String> {
    aka_md5_response_with_qop(
        username, realm, nonce, method, uri, aka_res, None, "", "",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn aka_md5_response_with_qop(
    username: &str,
    realm: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    aka_res: &[u8],
    qop: Option<&str>,
    cnonce: &str,
    nonce_count: &str,
) -> Result<String> {
    if username.is_empty() || realm.is_empty() || nonce.is_empty() || aka_res.is_empty() {
        return Err(anyhow!("IMS AKA digest fields must not be empty"));
    }
    let mut a1 = Vec::with_capacity(username.len() + realm.len() + aka_res.len() + 2);
    a1.extend_from_slice(username.as_bytes());
    a1.push(b':');
    a1.extend_from_slice(realm.as_bytes());
    a1.push(b':');
    a1.extend_from_slice(aka_res);
    let ha1 = md5_hex(&a1);
    let ha2 = md5_hex(format!("{method}:{uri}").as_bytes());
    let proof = match qop {
        Some(qop) if qop.eq_ignore_ascii_case("auth") => {
            if cnonce.is_empty() || nonce_count.is_empty() {
                return Err(anyhow!("IMS AKA qop requires cnonce and nonce count"));
            }
            format!("{ha1}:{nonce}:{nonce_count}:{cnonce}:auth:{ha2}")
        }
        Some(_) => return Err(anyhow!("IMS AKA digest qop is unsupported")),
        None => format!("{ha1}:{nonce}:{ha2}"),
    };
    Ok(md5_hex(proof.as_bytes()))
}

pub fn build_register(registration: &SipRegistration, branch: &str) -> Result<String> {
    if branch.is_empty() || registration.call_id.is_empty() {
        return Err(anyhow!("SIP branch and Call-ID are required"));
    }
    let uri = format!("sip:{}", registration.realm);
    if !registration.digest_algorithm.eq_ignore_ascii_case("AKAv1-MD5")
        && !registration.digest_algorithm.eq_ignore_ascii_case("MD5")
    {
        return Err(anyhow!("IMS AKA digest algorithm is unsupported"));
    }
    let nonce_count = format!("{:08x}", registration.nonce_count.max(1));
    let response = aka_md5_response_with_qop(
        &registration.private_identity,
        &registration.realm,
        &registration.nonce,
        "REGISTER",
        &uri,
        &registration.aka_res,
        registration.digest_qop.as_deref(),
        &registration.cnonce,
        &nonce_count,
    )?;
    let authorization_name = if registration.digest_proxy {
        "Proxy-Authorization"
    } else {
        "Authorization"
    };
    let mut authorization = format!(
        "{authorization_name}: Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm={}",
        registration.private_identity,
        registration.realm,
        registration.nonce,
        uri,
        response,
        registration.digest_algorithm,
    );
    if let Some(qop) = registration.digest_qop.as_deref() {
        authorization.push_str(&format!(
            ", qop={qop}, nc={nonce_count}, cnonce=\"{}\"",
            registration.cnonce
        ));
    }
    if let Some(opaque) = registration.digest_opaque.as_deref() {
        authorization.push_str(&format!(", opaque=\"{opaque}\""));
    }
    let contact_identity = registration
        .public_identity
        .strip_prefix("sip:")
        .unwrap_or(&registration.public_identity)
        .split('@')
        .next()
        .unwrap_or(&registration.private_identity);
    let contact_host = format!("[{}]", registration.contact_host);
    let contact = format!(
        "sip:{}@{}:{};transport=udp",
        contact_identity, contact_host, registration.contact_port
    );

    Ok(format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP [{}]:{};branch={branch};rport\r\n\
From: <{}>;tag=simadmin\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: {} REGISTER\r\n\
Contact: <{}>;+g.3gpp.smsip;expires=3600\r\n\
Expires: 3600\r\n\
P-Preferred-Identity: <{}>\r\n\
P-Access-Network-Info: 3GPP-E-UTRAN-FDD\r\n\
P-Visited-Network-ID: \"{}\"\r\n\
Max-Forwards: 70\r\n\
User-Agent: SimAdmin\r\n\
{authorization}\r\n\
Content-Length: 0\r\n\r\n",
        registration.contact_host,
        registration.contact_port,
        registration.public_identity,
        registration.public_identity,
        registration.call_id,
        registration.cseq,
        contact,
        registration.public_identity,
        registration.realm
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
        .unwrap_or(&registration.public_identity)
        .split('@')
        .next()
        .unwrap_or(&registration.private_identity);
    let contact_host = format!("[{}]", registration.contact_host);
    let contact = format!(
        "sip:{}@{}:{};transport=udp",
        contact_identity, contact_host, registration.contact_port
    );
    Ok(format!(
        "REGISTER {uri} SIP/2.0\r\n\
Via: SIP/2.0/UDP [{}]:{};branch={branch};rport\r\n\
From: <{}>;tag=simadmin\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: {} REGISTER\r\n\
Contact: <{}>;+g.3gpp.smsip;expires=3600\r\n\
Expires: 3600\r\n\
P-Preferred-Identity: <{}>\r\n\
P-Access-Network-Info: 3GPP-E-UTRAN-FDD\r\n\
P-Visited-Network-ID: \"{}\"\r\n\
Max-Forwards: 70\r\n\
User-Agent: SimAdmin\r\n\
Content-Length: 0\r\n\r\n",
        registration.contact_host,
        registration.contact_port,
        registration.public_identity,
        registration.public_identity,
        registration.call_id,
        registration.cseq,
        contact,
        registration.public_identity,
        registration.realm
    ))
}

pub fn has_header(message: &str, header_name: &str) -> bool {
    message.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(header_name))
    })
}

pub fn sip_status_code(response: &str) -> Option<u16> {
    let first_line = response.lines().next()?;
    let mut fields = first_line.split_whitespace();
    if fields.next()? != "SIP/2.0" {
        return None;
    }
    fields.next()?.parse().ok()
}

pub fn registration_expires(response: &str) -> u64 {
    let expires_header = response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("expires")
            .then(|| value.trim().parse::<u64>().ok())
            .flatten()
    });
    let contact_expires = response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("contact") {
            return None;
        }
        value.split(';').find_map(|parameter| {
            let (name, value) = parameter.trim().split_once('=')?;
            name.eq_ignore_ascii_case("expires")
                .then(|| value.trim_matches('"').parse::<u64>().ok())
                .flatten()
        })
    });
    contact_expires.or(expires_header).unwrap_or(3600)
}

pub fn registration_refresh_delay(response: &str) -> Duration {
    let expires = registration_expires(response).max(30);
    Duration::from_secs((expires * 4 / 5).max(15))
}

pub fn service_routes(response: &str) -> Vec<String> {
    response
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("service-route")
                .then(|| value.trim().to_string())
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityServer {
    pub client_spi: u32,
    pub server_spi: u32,
    pub client_port: u16,
    pub server_port: u16,
}

pub fn parse_security_server(response: &str) -> Option<SecurityServer> {
    let value = security_server_value(response)?;
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
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map(|hex| u32::from_str_radix(hex, 16).ok())
            .unwrap_or_else(|| value.parse().ok())
    };
    Some(SecurityServer {
        client_spi: parse_u32("spi-c")?,
        server_spi: parse_u32("spi-s")?,
        client_port: parameter("port-c")?.parse().ok()?,
        server_port: parameter("port-s")?.parse().ok()?,
    })
}

pub fn security_server_value(response: &str) -> Option<&str> {
    response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("security-server:"))?
        .split_once(':')
        .map(|(_, value)| value.trim())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaChallenge {
    pub realm: String,
    pub nonce: String,
    pub algorithm: String,
    pub qop: Option<String>,
    pub opaque: Option<String>,
    pub proxy: bool,
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

pub fn build_initial_register_with_security(
    registration: &SipRegistration,
    branch: &str,
    security_header: &str,
) -> Result<String> {
    let request = build_initial_register(registration, branch)?;
    insert_before_content_length(&request, security_header)
}

pub fn required_sec_agree_headers(security_client: &str) -> String {
    format!(
        "Supported: path, gruu, sec-agree\r\nRequire: sec-agree\r\nProxy-Require: sec-agree\r\n{security_client}"
    )
}

fn insert_before_content_length(request: &str, header: &str) -> Result<String> {
    let marker = "Content-Length: 0\r\n";
    let position = request
        .find(marker)
        .ok_or_else(|| anyhow!("SIP content length header is missing"))?;
    let mut result = String::with_capacity(request.len() + header.len());
    result.push_str(&request[..position]);
    result.push_str(header);
    result.push_str(&request[position..]);
    Ok(result)
}

pub fn parse_aka_challenge(response: &str) -> Option<AkaChallenge> {
    let header = response.lines().find(|line| {
        let lower = line.to_ascii_lowercase();
        (lower.starts_with("www-authenticate:") || lower.starts_with("proxy-authenticate:"))
            && lower.contains("aka")
    })?;
    let proxy = header
        .to_ascii_lowercase()
        .starts_with("proxy-authenticate:");
    let value = header.split_once(':')?.1;
    let parameters = parse_digest_parameters(value.trim().strip_prefix("Digest ")?);
    let parameter = |name: &str| {
        parameters
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let qop = parameter("qop").and_then(|value| {
        value
            .split([',', ' '])
            .any(|candidate| candidate.eq_ignore_ascii_case("auth"))
            .then(|| "auth".to_string())
    });
    Some(AkaChallenge {
        realm: parameter("realm")?,
        nonce: parameter("nonce")?,
        algorithm: parameter("algorithm").unwrap_or_else(|| "AKAv1-MD5".to_string()),
        qop,
        opaque: parameter("opaque"),
        proxy,
    })
}

fn parse_digest_parameters(input: &str) -> Vec<(String, String)> {
    let mut parameters = Vec::new();
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len()
            && (bytes[index] == b',' || bytes[index].is_ascii_whitespace())
        {
            index += 1;
        }
        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let key = input[key_start..index].trim().to_ascii_lowercase();
        index += 1;
        let value = if index < bytes.len() && bytes[index] == b'"' {
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            let value = input[value_start..index].to_string();
            index += usize::from(index < bytes.len());
            value
        } else {
            let value_start = index;
            while index < bytes.len() && bytes[index] != b',' {
                index += 1;
            }
            input[value_start..index].trim().to_string()
        };
        parameters.push((key, value));
    }
    parameters
}

pub fn build_resync_authorization_header(
    challenge: &AkaChallenge,
    username: &str,
    uri: &str,
    auts: &[u8],
    cnonce: &str,
    nonce_count: u32,
) -> Result<String> {
    if username.is_empty() || uri.is_empty() || auts.is_empty() {
        return Err(anyhow!("IMS AKA resynchronization fields must not be empty"));
    }
    let name = if challenge.proxy {
        "Proxy-Authorization"
    } else {
        "Authorization"
    };
    let mut header = format!(
        "{name}: Digest username=\"{username}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", response=\"\", algorithm={}, auts=\"{}\"",
        challenge.realm,
        challenge.nonce,
        challenge.algorithm,
        STANDARD.encode(auts),
    );
    if let Some(qop) = challenge.qop.as_deref() {
        if cnonce.is_empty() {
            return Err(anyhow!("IMS AKA resynchronization qop requires cnonce"));
        }
        header.push_str(&format!(
            ", qop={qop}, nc={:08x}, cnonce=\"{cnonce}\"",
            nonce_count.max(1)
        ));
    }
    if let Some(opaque) = challenge.opaque.as_deref() {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }
    Ok(header)
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
    fn parses_all_unique_pcscf_candidates() {
        let response = "+CGCONTRDP: 4,5,\"ims\",\"2001:db8::10\",\"::\",\"2001:db8::1\",\"::\",\"2001:db8::5\",\"2001:db8::6\"\r\n+CGCONTRDP: 5,6,\"ctnet\",\"2001:db8::20\",\"::\",\"2001:db8::1\",\"::\",\"2001:db8::99\",\"::\"";
        assert_eq!(
            parse_pcscf_candidates_from_cgcontrdp(response, "ims"),
            vec![
                "2001:db8::5".parse::<Ipv6Addr>().unwrap(),
                "2001:db8::6".parse::<Ipv6Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn parses_qualcomm_decimal_octet_pcscf() {
        let response = "+CGCONTRDP: 4,5,\"ims\",\"32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.16\",\"::\",\"::\",\"::\",\"36.14.0.102.192.0.64.20.0.0.0.0.0.0.0.1\",\"::\"";
        assert_eq!(
            parse_pcscf_candidates_from_cgcontrdp(response, "ims"),
            vec!["240e:66:c000:4014::1".parse::<Ipv6Addr>().unwrap()]
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
                aka_res: vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
                digest_algorithm: "AKAv1-MD5".into(),
                digest_qop: None,
                digest_opaque: None,
                digest_proxy: false,
                cnonce: "cnonce".into(),
                nonce_count: 1,
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
        assert!(request.contains(";+g.3gpp.smsip;expires=3600\r\n"));
        assert!(request.contains("P-Access-Network-Info: 3GPP-E-UTRAN-FDD\r\n"));
        assert!(request.contains("P-Visited-Network-ID: \"ims.example\"\r\n"));
    }

    #[test]
    fn initial_register_advertises_mt_sms_and_access_network() {
        let mut registration = SipRegistration {
            private_identity: "460001234567890@ims.example".into(),
            public_identity: "sip:460001234567890@ims.example".into(),
            realm: "ims.example".into(),
            nonce: String::new(),
            aka_res: Vec::new(),
            digest_algorithm: "AKAv1-MD5".into(),
            digest_qop: None,
            digest_opaque: None,
            digest_proxy: false,
            cnonce: "cnonce".into(),
            nonce_count: 1,
            call_id: "call-id".into(),
            cseq: 1,
            contact_host: "2001:db8::10".parse().unwrap(),
            contact_port: 5060,
        };
        let request = build_initial_register(&registration, "z9hG4bK-test").unwrap();
        assert!(request.contains(
            "Contact: <sip:460001234567890@[2001:db8::10]:5060;transport=udp>;+g.3gpp.smsip;expires=3600\r\n"
        ));
        assert!(request.contains("Expires: 3600\r\n"));
        assert!(request.contains(
            "P-Preferred-Identity: <sip:460001234567890@ims.example>\r\n"
        ));
        assert!(request.contains("P-Access-Network-Info: 3GPP-E-UTRAN-FDD\r\n"));
        assert!(request.contains("P-Visited-Network-ID: \"ims.example\"\r\n"));

        registration.realm = "other.example".into();
        assert!(has_header(
            &build_initial_register(&registration, "z9hG4bK-test-2").unwrap(),
            "p-visited-network-id"
        ));
    }

    #[test]
    fn parses_sip_status() {
        assert_eq!(sip_status_code("SIP/2.0 200 OK\r\n"), Some(200));
    }

    #[test]
    fn aka_digest_uses_binary_res_bytes() {
        let response = aka_md5_response(
            "user@ims.example",
            "ims.example",
            "nonce",
            "REGISTER",
            "sip:ims.example",
            &[0xde, 0xad, 0xbe, 0xef],
        )
        .unwrap();
        assert_eq!(response, "964462546fc1460f275809cfd4449a7a");
    }

    #[test]
    fn parses_aka_challenge() {
        let response = "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest algorithm=AKAv1-MD5, realm=\"ims.example\", nonce=\"abc\"\r\n";
        assert_eq!(
            parse_aka_challenge(response),
            Some(AkaChallenge {
                realm: "ims.example".into(),
                nonce: "abc".into(),
                algorithm: "AKAv1-MD5".into(),
                qop: None,
                opaque: None,
                proxy: false,
            })
        );
    }

    #[test]
    fn parses_proxy_challenge_with_qop_and_opaque() {
        let response = "SIP/2.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm=\"ims.example\", nonce=\"abc\", algorithm=AKAv1-MD5, qop=\"auth,auth-int\", opaque=\"xyz\"\r\n";
        let challenge = parse_aka_challenge(response).unwrap();
        assert!(challenge.proxy);
        assert_eq!(challenge.qop.as_deref(), Some("auth"));
        assert_eq!(challenge.opaque.as_deref(), Some("xyz"));
    }

    #[test]
    fn builds_qop_auth_digest() {
        let response = aka_md5_response_with_qop(
            "user@ims.example",
            "ims.example",
            "nonce",
            "REGISTER",
            "sip:ims.example",
            &[0xde, 0xad, 0xbe, 0xef],
            Some("auth"),
            "cnonce",
            "00000001",
        )
        .unwrap();
        assert_eq!(response, "1978b27b74c0ce9d628f8a67c53bf889");
    }

    #[test]
    fn builds_auts_resynchronization_authorization() {
        let challenge = AkaChallenge {
            realm: "ims.example".into(),
            nonce: "nonce".into(),
            algorithm: "AKAv1-MD5".into(),
            qop: Some("auth".into()),
            opaque: Some("opaque".into()),
            proxy: false,
        };
        let header = build_resync_authorization_header(
            &challenge,
            "user@ims.example",
            "sip:ims.example",
            &[0xaa, 0xbb],
            "cnonce",
            1,
        )
        .unwrap();
        assert!(header.starts_with("Authorization: Digest"));
        assert!(header.contains("response=\"\""));
        assert!(header.contains("auts=\"qrs=\""));
        assert!(header.contains("qop=auth, nc=00000001"));
        assert!(header.contains("opaque=\"opaque\""));
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

    #[test]
    fn parses_decimal_security_server_spis_as_decimal() {
        let response = "Security-Server: ipsec-3gpp;spi-c=12345678;spi-s=87654321;port-c=5062;port-s=5060\r\n";
        let security = parse_security_server(response).unwrap();
        assert_eq!(security.client_spi, 12_345_678);
        assert_eq!(security.server_spi, 87_654_321);
    }

    #[test]
    fn required_ipsec_offer_forces_security_agreement() {
        let headers = required_sec_agree_headers("Security-Client: ipsec-3gpp\r\n");
        assert!(headers.contains("Supported: path, gruu, sec-agree\r\n"));
        assert!(headers.contains("Require: sec-agree\r\n"));
        assert!(headers.contains("Proxy-Require: sec-agree\r\n"));
    }

    #[test]
    fn contact_expiry_controls_registration_refresh() {
        let response = "SIP/2.0 200 OK\r\nExpires: 3600\r\nContact: <sip:user@example>;expires=120\r\n\r\n";
        assert_eq!(registration_expires(response), 120);
        assert_eq!(registration_refresh_delay(response), Duration::from_secs(96));
    }

    #[test]
    fn preserves_service_routes_from_registration() {
        let response = "SIP/2.0 200 OK\r\nService-Route: <sip:[2001:db8::1]:5060;lr>\r\nService-Route: <sip:[2001:db8::2]:5060;lr>\r\n\r\n";
        assert_eq!(
            service_routes(response),
            vec![
                "<sip:[2001:db8::1]:5060;lr>",
                "<sip:[2001:db8::2]:5060;lr>"
            ]
        );
    }
}
