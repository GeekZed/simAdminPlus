//! Decoding of MT SMS carried in 3GPP IMS SIP MESSAGE bodies.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::db::{beijing_sms_now_string, Database, SmsMessage};
use crate::notification::NotificationSender;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingImsSms {
    pub phone_number: String,
    pub content: String,
    pub marker: String,
    pub concat: Option<ConcatInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcatInfo {
    pub reference: u16,
    pub total: u8,
    pub sequence: u8,
}

pub fn parse_sip_message(packet: &[u8]) -> Result<(HashMap<String, String>, Vec<u8>)> {
    let separator = packet
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("IMS SIP MESSAGE headers are incomplete"))?;
    let headers = std::str::from_utf8(&packet[..separator])?;
    let mut parsed = HashMap::new();
    for line in headers.lines().skip(1) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("IMS SIP MESSAGE header is malformed"))?;
        parsed.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    Ok((parsed, packet[separator + 4..].to_vec()))
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 || !input.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("IMS SMS body is not hexadecimal"));
    }
    (0..input.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&input[index..index + 2], 16).map_err(Into::into))
        .collect()
}

fn decode_address(bytes: &[u8], digits: usize) -> Result<(String, usize)> {
    let octets = digits.div_ceil(2);
    if bytes.len() < octets + 1 {
        return Err(anyhow!("IMS SMS address is truncated"));
    }
    let toa = bytes[0];
    let mut number = String::new();
    for byte in &bytes[1..octets + 1] {
        for nibble in [byte & 0x0f, byte >> 4] {
            if number.len() < digits && nibble <= 9 {
                number.push(char::from(b'0' + nibble));
            }
        }
    }
    if toa & 0x70 == 0x10 {
        number.insert(0, '+');
    }
    Ok((number, octets + 1))
}

fn gsm7_char(value: u8) -> char {
    if value < 0x20 {
        return match value {
            0x0a => '\n',
            0x0d => '\r',
            _ => ' ',
        };
    }
    if value < 0x7f {
        return value as char;
    }
    '?'
}

fn decode_gsm7(data: &[u8], septets: usize) -> String {
    (0..septets)
        .map(|index| {
            let bit = index * 7;
            let byte = bit / 8;
            let shift = bit % 8;
            let mut value = (data.get(byte).copied().unwrap_or_default() >> shift) & 0x7f;
            if shift > 1 {
                value |= data.get(byte + 1).copied().unwrap_or_default() << (8 - shift);
                value &= 0x7f;
            }
            gsm7_char(value)
        })
        .collect()
}

fn parse_concat_udh(data: &[u8]) -> Option<(ConcatInfo, usize)> {
    let header_length = *data.first()? as usize;
    if data.len() < header_length + 1 {
        return None;
    }
    let mut index = 1;
    while index + 2 <= header_length + 1 {
        let identifier = data[index];
        let length = data[index + 1] as usize;
        index += 2;
        if index + length > header_length + 1 {
            return None;
        }
        if identifier == 0x00 && length == 3 {
            return Some((
                ConcatInfo {
                    reference: data[index] as u16,
                    total: data[index + 1],
                    sequence: data[index + 2],
                },
                header_length + 1,
            ));
        }
        if identifier == 0x08 && length == 4 {
            return Some((
                ConcatInfo {
                    reference: u16::from_be_bytes([data[index], data[index + 1]]),
                    total: data[index + 2],
                    sequence: data[index + 3],
                },
                header_length + 1,
            ));
        }
        index += length;
    }
    None
}

fn decode_sms_deliver(tpdu: &[u8]) -> Result<(String, String, Option<ConcatInfo>)> {
    if tpdu.len() < 2 || tpdu[0] & 0x03 != 0x00 {
        return Err(anyhow!("IMS TPDU is not SMS-DELIVER"));
    }
    let address_digits = tpdu[1] as usize;
    let (phone_number, address_len) = decode_address(&tpdu[2..], address_digits)?;
    let mut index = 2 + address_len + 2 + 7;
    if tpdu.len() <= index {
        return Err(anyhow!("IMS SMS-DELIVER user data is missing"));
    }
    let dcs = tpdu[2 + address_len + 1];
    let length = tpdu[index] as usize;
    index += 1;
    let data = &tpdu[index..];
    let content = if dcs & 0x0c == 0x08 {
        if data.len() < length || length % 2 != 0 {
            return Err(anyhow!("IMS UCS2 SMS data is truncated"));
        }
        let (concat, header_bytes) = if tpdu[0] & 0x40 != 0 {
            parse_concat_udh(data)
                .map(|(info, length)| (Some(info), length))
                .unwrap_or((None, 0))
        } else {
            (None, 0)
        };
        if header_bytes > length {
            return Err(anyhow!("IMS SMS UDH exceeds user data length"));
        }
        let content_data = &data[header_bytes..length];
        let content = String::from_utf16(
            &content_data
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        )?;
        return Ok((phone_number, content, concat));
    } else if dcs & 0x0c == 0x00 {
        decode_gsm7(data, length)
    } else {
        String::from_utf8_lossy(&data[..length.min(data.len())]).into_owned()
    };
    Ok((phone_number, content, None))
}

pub fn decode_ims_sms(body_hex: &str) -> Result<IncomingImsSms> {
    let rp_data = decode_hex(body_hex)?;
    if rp_data.len() < 4 || rp_data[0] != 0x00 {
        return Err(anyhow!("IMS body is not RP-DATA"));
    }
    let mut index = 2;
    let originator_length = rp_data[index] as usize;
    index += 1 + originator_length;
    let destination_length = *rp_data
        .get(index)
        .ok_or_else(|| anyhow!("IMS RP-DATA destination is missing"))? as usize;
    index += 1 + destination_length;
    let user_data_length = *rp_data
        .get(index)
        .ok_or_else(|| anyhow!("IMS RP-DATA user data is missing"))? as usize;
    index += 1;
    if rp_data.len() < index + user_data_length {
        return Err(anyhow!("IMS RP-DATA user data is truncated"));
    }
    let (phone_number, content, concat) =
        decode_sms_deliver(&rp_data[index..index + user_data_length])?;
    let marker = format!("volte-mt:{:x}", md5::compute(body_hex.as_bytes()));
    Ok(IncomingImsSms {
        phone_number,
        content,
        marker,
        concat,
    })
}

pub fn decode_ims_sms_body(body: &[u8]) -> Result<IncomingImsSms> {
    let body_hex: String = if body.iter().all(|byte| byte.is_ascii_hexdigit() || byte.is_ascii_whitespace()) {
        String::from_utf8(body.to_vec())?
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect()
    } else {
        body.iter().map(|byte| format!("{byte:02X}")).collect()
    };
    decode_ims_sms(&body_hex)
}

pub fn build_rp_ack(body: &[u8]) -> Result<Vec<u8>> {
    let body_hex: String = if body.iter().all(|byte| byte.is_ascii_hexdigit() || byte.is_ascii_whitespace()) {
        String::from_utf8(body.to_vec())?
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect()
    } else {
        body.iter().map(|byte| format!("{byte:02X}")).collect()
    };
    let rp_data = decode_hex(&body_hex)?;
    if rp_data.len() < 2 || rp_data[0] != 0x00 {
        return Err(anyhow!("cannot acknowledge non-RP-DATA body"));
    }
    Ok(vec![0x02, rp_data[1]])
}

fn sip_ok_response(headers: &HashMap<String, String>) -> String {
    let mut response = String::from("SIP/2.0 200 OK\r\n");
    for name in ["via", "from", "to", "call-id", "cseq"] {
        if let Some(value) = headers.get(name) {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    response
}

fn header_uri(value: &str) -> Option<String> {
    if let Some((_, rest)) = value.split_once('<') {
        return Some(rest.split('>').next()?.to_string());
    }
    Some(value.split(';').next()?.trim().to_string())
}

pub fn build_rp_ack_message(
    headers: &HashMap<String, String>,
    local: std::net::Ipv6Addr,
    local_port: u16,
    body: &[u8],
) -> Result<Vec<u8>> {
    let target = header_uri(
        headers
            .get("from")
            .ok_or_else(|| anyhow!("IMS SMS From header is missing"))?,
    )
    .ok_or_else(|| anyhow!("IMS SMS From URI is missing"))?;
    let from = headers
        .get("to")
        .ok_or_else(|| anyhow!("IMS SMS To header is missing"))?;
    let to = headers
        .get("from")
        .ok_or_else(|| anyhow!("IMS SMS From header is missing"))?;
    let call_id = headers
        .get("call-id")
        .ok_or_else(|| anyhow!("IMS SMS Call-ID header is missing"))?;
    let cseq = headers
        .get("cseq")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(1)
        .saturating_add(1);
    let branch = format!("z9hG4bK-simadmin-rp-ack-{cseq}");
    let header = format!(
        "MESSAGE {target} SIP/2.0\r\nVia: SIP/2.0/UDP [{local}]:{local_port};branch={branch};rport\r\nFrom: {from}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {cseq} MESSAGE\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut packet = header.into_bytes();
    packet.extend_from_slice(body);
    Ok(packet)
}

pub async fn run_ims_sms_listener(
    local: std::net::Ipv6Addr,
    port: u16,
    database: Arc<Database>,
    notifications: Arc<NotificationSender>,
) -> Result<()> {
    let socket = UdpSocket::bind((local, port)).await?;
    let mut buffer = vec![0u8; 8192];
    let mut multipart: HashMap<(String, u16), Vec<Option<IncomingImsSms>>> = HashMap::new();
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];
        let Ok((headers, body)) = parse_sip_message(packet) else {
            continue;
        };
        let is_message = packet
            .windows(2)
            .position(|window| window == b"\r\n")
            .and_then(|end| std::str::from_utf8(&packet[..end]).ok())
            .is_some_and(|line| line.starts_with("MESSAGE "));
        let content_type = headers
            .get("content-type")
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();
        if !is_message || !content_type.contains("application/vnd.3gpp.sms") {
            continue;
        }
        let response = sip_ok_response(&headers);
        let _ = socket.send_to(response.as_bytes(), peer).await;
        if let Ok(ack) = build_rp_ack(&body) {
            if let Ok(packet) = build_rp_ack_message(&headers, local, port, &ack) {
                let _ = socket.send_to(&packet, peer).await;
            }
        }
        let Ok(mut incoming) = decode_ims_sms_body(&body) else {
            continue;
        };
        if let Some(concat) = incoming.concat.clone() {
            if concat.total == 0 || concat.sequence == 0 || concat.sequence > concat.total {
                continue;
            }
            let key = (incoming.phone_number.clone(), concat.reference);
            let segments = multipart
                .entry(key.clone())
                .or_insert_with(|| vec![None; concat.total as usize]);
            if segments.len() != concat.total as usize {
                *segments = vec![None; concat.total as usize];
            }
            segments[concat.sequence as usize - 1] = Some(incoming);
            if segments.iter().any(Option::is_none) {
                continue;
            }
            let segments = multipart.remove(&key).unwrap();
            let complete = segments.into_iter().flatten().collect::<Vec<_>>();
            let phone_number = complete[0].phone_number.clone();
            let content = complete
                .iter()
                .map(|segment| segment.content.as_str())
                .collect::<String>();
            let marker_input = complete
                .iter()
                .map(|segment| segment.marker.as_str())
                .collect::<String>();
            incoming = IncomingImsSms {
                phone_number,
                content,
                marker: format!("volte-mt:{:x}", md5::compute(marker_input.as_bytes())),
                concat: None,
            };
        }
        if database.sms_exists_by_pdu(&incoming.marker)? {
            continue;
        }
        let timestamp = beijing_sms_now_string();
        let id = database.insert_sms_at(
            "incoming",
            &incoming.phone_number,
            &incoming.content,
            &timestamp,
            "received",
            Some(&incoming.marker),
        )?;
        let message = SmsMessage {
            id,
            direction: "incoming".to_string(),
            phone_number: incoming.phone_number,
            content: incoming.content,
            timestamp,
            status: "received".to_string(),
            pdu: Some(incoming.marker),
        };
        let _ = notifications.forward_sms(&message).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ucs2_sms_deliver() {
        let tpdu = "040B912143658709F1000832122310123400044F60597D";
        let rp = format!("00000000{:02X}{}", tpdu.len() / 2, tpdu);
        let sms = decode_ims_sms(&rp).unwrap();
        assert_eq!(sms.phone_number, "+12345678901");
        assert_eq!(sms.content, "你好");
        assert!(sms.marker.starts_with("volte-mt:"));
    }

    #[test]
    fn decodes_ucs2_concat_header() {
        let tpdu = "440B912143658709F10008321223101234000A0500030102014F60597D";
        let rp = format!("00000000{:02X}{}", tpdu.len() / 2, tpdu);
        let sms = decode_ims_sms(&rp).unwrap();
        assert_eq!(sms.content, "你好");
        assert_eq!(
            sms.concat,
            Some(ConcatInfo {
                reference: 1,
                total: 2,
                sequence: 1
            })
        );
    }

    #[test]
    fn parses_sip_message_body() {
        let packet = b"MESSAGE sip:x SIP/2.0\r\nContent-Type: application/vnd.3gpp.sms\r\n\r\nAABB";
        let (headers, body) = parse_sip_message(packet).unwrap();
        assert_eq!(headers.get("content-type").unwrap(), "application/vnd.3gpp.sms");
        assert_eq!(body, b"AABB");
    }

    #[test]
    fn accepts_binary_sms_body() {
        let body = [0x00, 0x00, 0x00, 0x00, 0x01, 0x04];
        assert!(decode_ims_sms_body(&body).is_err());
    }

    #[test]
    fn builds_matching_rp_ack() {
        assert_eq!(build_rp_ack(&[0x00, 0x37, 0x00, 0x00]).unwrap(), vec![0x02, 0x37]);
    }

    #[test]
    fn builds_rp_ack_sip_message() {
        let mut headers = HashMap::new();
        headers.insert("from".into(), "<sip:network@example>;tag=n".into());
        headers.insert("to".into(), "<sip:me@example>;tag=m".into());
        headers.insert("call-id".into(), "call".into());
        headers.insert("cseq".into(), "1 MESSAGE".into());
        let packet = build_rp_ack_message(
            &headers,
            "2001:db8::10".parse().unwrap(),
            5062,
            &[0x02, 0x37],
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&packet).contains("MESSAGE sip:network@example SIP/2.0"));
        assert!(packet.ends_with(&[0x02, 0x37]));
    }
}
