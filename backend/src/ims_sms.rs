//! Decoding of MT SMS carried in 3GPP IMS SIP MESSAGE bodies.

use anyhow::{anyhow, Result};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::sync::Arc;

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

struct PendingRpAck {
    packet: Vec<u8>,
    deadline: tokio::time::Instant,
    attempts: u8,
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
    let body = &packet[separator + 4..];
    let content_length = parsed
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(body.len());
    if body.len() < content_length {
        return Err(anyhow!("IMS SIP MESSAGE body is truncated"));
    }
    Ok((parsed, body[..content_length].to_vec()))
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

fn gsm7_char(value: u8) -> Option<char> {
    Some(match value {
        0x00 => '@', 0x01 => '£', 0x02 => '$', 0x03 => '¥',
        0x04 => 'è', 0x05 => 'é', 0x06 => 'ù', 0x07 => 'ì',
        0x08 => 'ò', 0x09 => 'Ç', 0x0a => '\n', 0x0b => 'Ø',
        0x0c => 'ø', 0x0d => '\r', 0x0e => 'Å', 0x0f => 'å',
        0x10 => 'Δ', 0x11 => '_', 0x12 => 'Φ', 0x13 => 'Γ',
        0x14 => 'Λ', 0x15 => 'Ω', 0x16 => 'Π', 0x17 => 'Ψ',
        0x18 => 'Σ', 0x19 => 'Θ', 0x1a => 'Ξ', 0x1b => return None,
        0x1c => 'Æ', 0x1d => 'æ', 0x1e => 'ß', 0x1f => 'É',
        0x24 => '¤', 0x40 => '¡', 0x5b => 'Ä', 0x5c => 'Ö',
        0x5d => 'Ñ', 0x5e => 'Ü', 0x5f => '§', 0x60 => '¿',
        0x7b => 'ä', 0x7c => 'ö', 0x7d => 'ñ', 0x7e => 'ü',
        0x7f => 'à',
        value if (0x20..=0x7a).contains(&value) => value as char,
        _ => '�',
    })
}

fn gsm7_extension(value: u8) -> char {
    match value {
        0x0a => '\u{000c}', 0x14 => '^', 0x28 => '{', 0x29 => '}',
        0x2f => '\\', 0x3c => '[', 0x3d => '~', 0x3e => ']',
        0x40 => '|', 0x65 => '€', _ => '�',
    }
}

fn decode_gsm7(data: &[u8], septets: usize, bit_offset: usize) -> String {
    let values = (0..septets).map(|index| {
            let bit = bit_offset + index * 7;
            let byte = bit / 8;
            let shift = bit % 8;
            let mut value = (data.get(byte).copied().unwrap_or_default() >> shift) & 0x7f;
            if shift > 1 {
                value |= data.get(byte + 1).copied().unwrap_or_default() << (8 - shift);
                value &= 0x7f;
            }
            value
        });
    let mut escaped = false;
    let mut result = String::new();
    for value in values {
        if escaped {
            result.push(gsm7_extension(value));
            escaped = false;
        } else if let Some(character) = gsm7_char(value) {
            result.push(character);
        } else {
            escaped = true;
        }
    }
    if escaped {
        result.push('�');
    }
    result
}

fn parse_udh(data: &[u8]) -> Option<(Option<ConcatInfo>, usize)> {
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
                Some(ConcatInfo {
                    reference: data[index] as u16,
                    total: data[index + 1],
                    sequence: data[index + 2],
                }),
                header_length + 1,
            ));
        }
        if identifier == 0x08 && length == 4 {
            return Some((
                Some(ConcatInfo {
                    reference: u16::from_be_bytes([data[index], data[index + 1]]),
                    total: data[index + 2],
                    sequence: data[index + 3],
                }),
                header_length + 1,
            ));
        }
        index += length;
    }
    Some((None, header_length + 1))
}

fn decode_sms_deliver(tpdu: &[u8]) -> Result<(String, String, Option<ConcatInfo>, String)> {
    if tpdu.len() < 2 || tpdu[0] & 0x03 != 0x00 {
        return Err(anyhow!("IMS TPDU is not SMS-DELIVER"));
    }
    let address_digits = tpdu[1] as usize;
    let (phone_number, address_len) = decode_address(&tpdu[2..], address_digits)?;
    let timestamp_start = 2 + address_len + 2;
    let timestamp_end = timestamp_start + 7;
    let timestamp_key = tpdu
        .get(timestamp_start..timestamp_end)
        .ok_or_else(|| anyhow!("IMS SMS-DELIVER timestamp is missing"))?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut index = timestamp_end;
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
            parse_udh(data)
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
        return Ok((phone_number, content, concat, timestamp_key));
    } else if dcs & 0x0c == 0x00 {
        let (concat, header_bytes) = if tpdu[0] & 0x40 != 0 {
            parse_udh(data).unwrap_or((None, 0))
        } else {
            (None, 0)
        };
        let header_septets = (header_bytes * 8).div_ceil(7);
        if header_septets > length || data.len() * 8 < length * 7 {
            return Err(anyhow!("IMS GSM7 SMS data is truncated"));
        }
        let content = decode_gsm7(
            &data[header_bytes..],
            length - header_septets,
            header_septets * 7 - header_bytes * 8,
        );
        return Ok((phone_number, content, concat, timestamp_key));
    } else {
        String::from_utf8_lossy(&data[..length.min(data.len())]).into_owned()
    };
    Ok((phone_number, content, None, timestamp_key))
}

fn stable_ims_marker(
    phone_number: &str,
    content: &str,
    timestamp_key: &str,
    concat: Option<&ConcatInfo>,
) -> String {
    let concat_key = concat
        .map(|value| {
            format!(
                "{}:{}:{}",
                value.reference, value.total, value.sequence
            )
        })
        .unwrap_or_default();
    let identity = format!("{phone_number}\n{timestamp_key}\n{concat_key}\n{content}");
    format!("volte-mt:{:x}", md5::compute(identity.as_bytes()))
}

pub fn decode_ims_sms(body_hex: &str) -> Result<IncomingImsSms> {
    let rp_data = decode_hex(body_hex)?;
    if rp_data.len() < 4 || rp_data[0] != 0x01 {
        return Err(anyhow!("IMS body is not network-to-MS RP-DATA"));
    }
    let mut index = 2;
    let originator_length = rp_data[index] as usize;
    index += 1 + originator_length;
    let decode_at =
        |length_index: usize| -> Result<(String, String, Option<ConcatInfo>, String)> {
        let user_data_length = *rp_data
            .get(length_index)
            .ok_or_else(|| anyhow!("IMS RP-DATA user data is missing"))? as usize;
        let user_data_index = length_index + 1;
        if user_data_length == 0 || rp_data.len() < user_data_index + user_data_length {
            return Err(anyhow!("IMS RP-DATA user data is truncated"));
        }
        decode_sms_deliver(&rp_data[user_data_index..user_data_index + user_data_length])
        };
    let (phone_number, content, concat, timestamp_key) = decode_at(index).or_else(|_| {
        let destination_length = *rp_data
            .get(index)
            .ok_or_else(|| anyhow!("IMS RP-DATA destination is missing"))? as usize;
        decode_at(index + 1 + destination_length)
    })?;
    let marker = stable_ims_marker(
        &phone_number,
        &content,
        &timestamp_key,
        concat.as_ref(),
    );
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
    if rp_data.len() < 2 || rp_data[0] != 0x01 {
        return Err(anyhow!("cannot acknowledge non-MT RP-DATA body"));
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

fn random_hex_token(byte_count: usize) -> Result<String> {
    let mut bytes = vec![0u8; byte_count];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("IMS SMS transaction token generation failed"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn build_rp_ack_message(
    headers: &HashMap<String, String>,
    local: std::net::Ipv6Addr,
    local_port: u16,
    pcscf: std::net::SocketAddr,
    public_identity: &str,
    service_routes: &[String],
    security_verify: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>> {
    let target = header_uri(
        headers
            .get("from")
            .ok_or_else(|| anyhow!("IMS SMS From header is missing"))?,
    )
    .ok_or_else(|| anyhow!("IMS SMS From URI is missing"))?;
    let branch = format!("z9hG4bK-simadmin-rp-ack-{}", random_hex_token(8)?);
    let from_tag = random_hex_token(8)?;
    let call_id = format!("{}@simadmin", random_hex_token(16)?);
    let mut header = format!(
        "MESSAGE {target} SIP/2.0\r\nVia: SIP/2.0/UDP [{local}]:{local_port};branch={branch};rport\r\nMax-Forwards: 70\r\nFrom: <{public_identity}>;tag={from_tag}\r\nTo: <{target}>\r\nCall-ID: {call_id}\r\nCSeq: 1 MESSAGE\r\n"
    );
    if service_routes.is_empty() {
        let route_host = match pcscf.ip() {
            std::net::IpAddr::V4(address) => address.to_string(),
            std::net::IpAddr::V6(address) => format!("[{address}]"),
        };
        header.push_str(&format!(
            "Route: <sip:{route_host}:{};lr>\r\n",
            pcscf.port()
        ));
    } else {
        for route in service_routes {
            header.push_str(&format!("Route: {route}\r\n"));
        }
    }
    header.push_str(&format!(
        "In-Reply-To: {}\r\nP-Preferred-Identity: <{public_identity}>\r\nP-Access-Network-Info: 3GPP-E-UTRAN-FDD\r\nP-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.sms\r\n",
        headers
            .get("call-id")
            .ok_or_else(|| anyhow!("IMS SMS Call-ID header is missing"))?
    ));
    if let Some(security_verify) = security_verify {
        header.push_str(&format!("Security-Verify: {security_verify}\r\n"));
    }
    header.push_str(&format!(
        "Accept-Contact: *;+g.3gpp.smsip\r\nAccept: application/vnd.3gpp.sms\r\nUser-Agent: SimAdmin VoLTE\r\nContent-Type: application/vnd.3gpp.sms\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ));
    let mut packet = header.into_bytes();
    packet.extend_from_slice(body);
    Ok(packet)
}

async fn send_ims_delivery_ack(
    channel: &crate::ims_channel::ImsSipChannel,
    headers: &HashMap<String, String>,
    body: &[u8],
    registration: &crate::ims_sip::SipRegistration,
    service_routes: &[String],
    security_verify: Option<&str>,
    pending_rp_acks: &mut HashMap<(String, u32), PendingRpAck>,
) -> Result<()> {
    let ack = build_rp_ack(body)?;
    let route = channel.route();
    if let std::net::IpAddr::V6(local) = route.local.ip() {
        let packet = build_rp_ack_message(
            headers,
            local,
            route.local.port(),
            route.remote,
            &registration.public_identity,
            service_routes,
            security_verify,
            &ack,
        )?;
        channel.send(&packet).await?;
        if let Ok((ack_headers, _)) = parse_sip_message(&packet) {
            let call_id = ack_headers.get("call-id").cloned().unwrap_or_default();
            let cseq = ack_headers
                .get("cseq")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_default();
            pending_rp_acks.insert(
                (call_id, cseq),
                PendingRpAck {
                    packet,
                    deadline: tokio::time::Instant::now()
                        + std::time::Duration::from_secs(3),
                    attempts: 1,
                },
            );
        }
    }
    Ok(())
}

pub async fn run_ims_sms_listener(
    channel: crate::ims_channel::ImsSipChannel,
    mut registration: crate::ims_sip::SipRegistration,
    security_header: String,
    service_routes: Vec<String>,
    refresh_after: std::time::Duration,
    database: Arc<Database>,
    notifications: Arc<NotificationSender>,
) -> Result<()> {
    let mut multipart: HashMap<(String, u16), Vec<Option<IncomingImsSms>>> = HashMap::new();
    let mut pending_rp_acks: HashMap<(String, u32), PendingRpAck> = HashMap::new();
    let mut refresh_deadline = tokio::time::Instant::now() + refresh_after;
    let mut refresh_response_deadline = None;
    loop {
        let mut deadline = refresh_response_deadline.unwrap_or(refresh_deadline);
        if let Some(ack_deadline) = pending_rp_acks.values().map(|ack| ack.deadline).min() {
            deadline = deadline.min(ack_deadline);
        }
        let wait = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Some(packet) = channel.receive_optional(wait).await? else {
            let now = tokio::time::Instant::now();
            if refresh_response_deadline.is_some_and(|deadline| deadline <= now) {
                return Err(anyhow!("IMS REGISTER refresh timed out"));
            }
            let expired_ack = pending_rp_acks
                .iter()
                .find(|(_, ack)| ack.deadline <= now)
                .map(|(key, _)| key.clone());
            if let Some(key) = expired_ack {
                if pending_rp_acks
                    .get(&key)
                    .is_some_and(|ack| ack.attempts >= 3)
                {
                    pending_rp_acks.remove(&key);
                    tracing::warn!("IMS RP-ACK transaction expired after three attempts");
                    continue;
                }
                let ack = pending_rp_acks.get_mut(&key).unwrap();
                ack.attempts += 1;
                ack.deadline = now
                    + std::time::Duration::from_secs(3 * (1_u64 << (ack.attempts - 1)));
                let packet = ack.packet.clone();
                channel.send(&packet).await?;
                continue;
            }
            if refresh_deadline <= now {
                registration.cseq = registration.cseq.saturating_add(1);
                registration.nonce_count = registration.nonce_count.saturating_add(1);
                let branch = format!("z9hG4bK-simadmin-refresh-{}", registration.cseq);
                let request = crate::ims_sip::build_register_with_security(
                    &registration,
                    &branch,
                    &security_header,
                )?;
                channel.send(request.as_bytes()).await?;
                refresh_response_deadline = Some(
                    tokio::time::Instant::now() + std::time::Duration::from_secs(10),
                );
            }
            continue;
        };
        let Ok((headers, body)) = parse_sip_message(&packet) else {
            continue;
        };
        let is_register_response = packet.starts_with(b"SIP/2.0 ")
            && headers
                .get("cseq")
                .is_some_and(|value| value.to_ascii_uppercase().ends_with(" REGISTER"));
        if is_register_response && refresh_response_deadline.is_some() {
            let response = std::str::from_utf8(&packet)?;
            let status = crate::ims_sip::sip_status_code(response)
                .ok_or_else(|| anyhow!("IMS REGISTER refresh response is malformed"))?;
            if !(200..300).contains(&status) {
                return Err(anyhow!("IMS REGISTER refresh returned {status}"));
            }
            refresh_response_deadline = None;
            refresh_deadline = tokio::time::Instant::now()
                + crate::ims_sip::registration_refresh_delay(response);
            continue;
        }
        let is_message_response = packet.starts_with(b"SIP/2.0 ")
            && headers
                .get("cseq")
                .is_some_and(|value| value.to_ascii_uppercase().ends_with(" MESSAGE"));
        if is_message_response {
            let call_id = headers.get("call-id").cloned().unwrap_or_default();
            let cseq = headers
                .get("cseq")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_default();
            let status = std::str::from_utf8(&packet)
                .ok()
                .and_then(crate::ims_sip::sip_status_code)
                .unwrap_or_default();
            let matched = pending_rp_acks.contains_key(&(call_id.clone(), cseq));
            let reason = std::str::from_utf8(&packet)
                .ok()
                .and_then(|response| response.lines().next())
                .and_then(|line| line.splitn(3, ' ').nth(2))
                .unwrap_or("unknown");
            let warning = headers.get("warning").map(String::as_str).unwrap_or("none");
            tracing::info!(status, reason, warning, matched, "IMS RP-ACK SIP response received");
            if (200..300).contains(&status) {
                pending_rp_acks.remove(&(call_id, cseq));
            } else if status >= 300 {
                let key = (call_id, cseq);
                if pending_rp_acks
                    .get(&key)
                    .is_some_and(|ack| ack.attempts >= 3)
                {
                    pending_rp_acks.remove(&key);
                    tracing::warn!(status, "IMS RP-ACK rejected after three attempts");
                } else if let Some(ack) = pending_rp_acks.get_mut(&key) {
                    ack.deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(3 * (1_u64 << (ack.attempts - 1)));
                }
            }
            continue;
        }
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
        channel.send(response.as_bytes()).await?;
        let mut incoming = match decode_ims_sms_body(&body) {
            Ok(incoming) => incoming,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    body_bytes = body.len(),
                    "IMS MT SMS body could not be decoded"
                );
                continue;
            }
        };
        if let Err(error) = send_ims_delivery_ack(
            &channel,
            &headers,
            &body,
            &registration,
            &service_routes,
            channel.security_verify(),
            &mut pending_rp_acks,
        )
        .await
        {
            tracing::warn!(error = %error, marker = %incoming.marker, "IMS SMS RP-ACK failed");
        }
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
        if database.ims_sms_receipt_exists(&incoming.marker)? {
            continue;
        }
        let timestamp = beijing_sms_now_string();
        let id = database.insert_sms_at_with_transport(
            "incoming",
            &incoming.phone_number,
            &incoming.content,
            &timestamp,
            "received",
            Some(&incoming.marker),
            "volte_ims",
        )?;
        database.record_ims_sms_receipt(
            &incoming.marker,
            &incoming.phone_number,
            &incoming.content,
            id,
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
        let notifications = Arc::clone(&notifications);
        tokio::spawn(async move {
            let _ = notifications.forward_sms(&message).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ucs2_sms_deliver() {
        let tpdu = "040B912143658709F1000832122310123400044F60597D";
        let rp = format!("010000{:02X}{}", tpdu.len() / 2, tpdu);
        let sms = decode_ims_sms(&rp).unwrap();
        assert_eq!(sms.phone_number, "+12345678901");
        assert_eq!(sms.content, "你好");
        assert!(sms.marker.starts_with("volte-mt:"));
    }

    #[test]
    fn keeps_same_marker_when_ims_transaction_reference_changes() {
        let tpdu = "040B912143658709F1000832122310123400044F60597D";
        let first = decode_ims_sms(&format!("010000{:02X}{}", tpdu.len() / 2, tpdu)).unwrap();
        let replay = decode_ims_sms(&format!("010100{:02X}{}", tpdu.len() / 2, tpdu)).unwrap();
        assert_eq!(first.marker, replay.marker);
    }

    #[test]
    fn decodes_ucs2_concat_header() {
        let tpdu = "440B912143658709F10008321223101234000A0500030102014F60597D";
        let rp = format!("010000{:02X}{}", tpdu.len() / 2, tpdu);
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
    fn decodes_gsm7_default_alphabet() {
        assert_eq!(decode_gsm7(&[0xE8, 0x32, 0x9B, 0xFD, 0x06], 5, 0), "hello");
        assert_eq!(decode_gsm7(&[0x00], 1, 0), "@");
    }

    #[test]
    fn parses_sip_message_body() {
        let packet = b"MESSAGE sip:x SIP/2.0\r\nContent-Type: application/vnd.3gpp.sms\r\n\r\nAABB";
        let (headers, body) = parse_sip_message(packet).unwrap();
        assert_eq!(headers.get("content-type").unwrap(), "application/vnd.3gpp.sms");
        assert_eq!(body, b"AABB");
    }

    #[test]
    fn rejects_truncated_sip_body() {
        let packet = b"MESSAGE sip:user@example SIP/2.0\r\nContent-Length: 4\r\n\r\nabc";
        assert!(parse_sip_message(packet).is_err());
    }

    #[test]
    fn accepts_binary_sms_body() {
        let body = [0x01, 0x00, 0x00, 0x01, 0x04];
        assert!(decode_ims_sms_body(&body).is_err());
    }

    #[test]
    fn builds_matching_rp_ack() {
        assert_eq!(build_rp_ack(&[0x01, 0x37, 0x00, 0x00]).unwrap(), vec![0x02, 0x37]);
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
            "[2001:db8::2]:5060".parse().unwrap(),
            "sip:me@example",
            &["<sip:[2001:db8::2]:5060;lr>".to_string()],
            Some("ipsec-3gpp;spi-c=1"),
            &[0x02, 0x37],
        )
        .unwrap();
        let text = String::from_utf8_lossy(&packet);
        assert!(text.contains("MESSAGE sip:network@example SIP/2.0"));
        assert!(text.contains("From: <sip:me@example>;tag="));
        assert!(text.contains("To: <sip:network@example>\r\n"));
        assert!(text.contains("CSeq: 1 MESSAGE\r\n"));
        assert!(text.contains("In-Reply-To: call\r\n"));
        assert!(text.contains("Route: <sip:[2001:db8::2]:5060;lr>\r\n"));
        assert!(text.contains("Security-Verify: ipsec-3gpp;spi-c=1\r\n"));
        assert!(packet.ends_with(&[0x02, 0x37]));
    }

    #[test]
    fn rp_ack_requires_inbound_call_id() {
        let mut headers = HashMap::new();
        headers.insert("from".into(), "<sip:network@example>;tag=n".into());
        assert!(build_rp_ack_message(
            &headers,
            "2001:db8::10".parse().unwrap(),
            5062,
            "[2001:db8::2]:5060".parse().unwrap(),
            "sip:me@example",
            &[],
            None,
            &[0x02, 0x37],
        )
        .is_err());
    }
}
