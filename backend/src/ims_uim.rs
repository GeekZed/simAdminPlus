//! USIM application and AKA response parsing for native IMS.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaResponse {
    pub res: Vec<u8>,
    pub ck: Vec<u8>,
    pub ik: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaResync {
    pub auts: Vec<u8>,
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let clean: String = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if clean.len() % 2 != 0 || !clean.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!("USIM APDU response is not hexadecimal"));
    }
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).map_err(Into::into))
        .collect()
}

pub fn build_csim_command(apdu_hex: &str) -> Result<String> {
    let bytes = decode_hex(apdu_hex)?;
    if bytes.is_empty() {
        return Err(anyhow!("USIM APDU must not be empty"));
    }
    Ok(format!("AT+CSIM={},\"{}\"", apdu_hex.len(), apdu_hex))
}

pub fn extract_csim_hex(response: &str) -> Result<String> {
    let value = response
        .split('"')
        .nth(1)
        .ok_or_else(|| anyhow!("Modem response did not contain CSIM hex data"))?;
    decode_hex(value)?;
    Ok(value.to_string())
}

pub fn build_aka_auth_command(nonce: &str) -> Result<String> {
    let nonce = nonce.trim().trim_matches('"');
    let auth_data = STANDARD
        .decode(nonce)
        .or_else(|_| decode_hex(nonce))
        .map_err(|_| anyhow!("IMS AKA nonce is not base64 or hexadecimal"))?;
    if auth_data.len() != 32 {
        return Err(anyhow!("IMS AKA nonce must contain 16-byte RAND and AUTN"));
    }
    let apdu = format!(
        "008800812210{}{}",
        encode_hex(&auth_data[..16]),
        encode_hex(&auth_data[16..])
    );
    build_csim_command(&apdu)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

pub fn parse_aid_from_select_response(response_hex: &str) -> Result<Vec<u8>> {
    let bytes = decode_hex(response_hex)?;
    for index in 0..bytes.len().saturating_sub(1) {
        if bytes[index] == 0x84 {
            let length = bytes[index + 1] as usize;
            if index + 2 + length <= bytes.len() {
                return Ok(bytes[index + 2..index + 2 + length].to_vec());
            }
        }
    }
    Err(anyhow!("USIM AID was not present in SELECT response"))
}

pub fn parse_aka_response(response_hex: &str) -> Result<Result<AkaResponse, AkaResync>> {
    let bytes = decode_hex(response_hex)?;
    if bytes.len() < 2 || bytes[bytes.len() - 2..] != [0x90, 0x00] {
        return Err(anyhow!("USIM AKA APDU failed"));
    }
    let payload = &bytes[..bytes.len() - 2];
    let mut index = 0;
    let mut res = None;
    let mut ck = None;
    let mut ik = None;
    let mut auts = None;
    while index + 2 <= payload.len() {
        let tag = payload[index];
        let length = payload[index + 1] as usize;
        index += 2;
        if index + length > payload.len() {
            return Err(anyhow!("truncated USIM AKA response"));
        }
        let value = payload[index..index + length].to_vec();
        match tag {
            0xDB => res = Some(value),
            0xDC => ck = Some(value),
            0xDD => ik = Some(value),
            0xDE => auts = Some(value),
            _ => {}
        }
        index += length;
    }
    if let Some(auts) = auts {
        return Ok(Err(AkaResync { auts }));
    }
    Ok(Ok(AkaResponse {
        res: res.ok_or_else(|| anyhow!("USIM AKA RES was missing"))?,
        ck: ck.ok_or_else(|| anyhow!("USIM AKA CK was missing"))?,
        ik: ik.ok_or_else(|| anyhow!("USIM AKA IK was missing"))?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_usim_aid() {
        assert_eq!(
            parse_aid_from_select_response("62098407A0000000871002").unwrap(),
            vec![0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]
        );
    }

    #[test]
    fn builds_csim_command() {
        assert_eq!(
            build_csim_command("00A4040007A0000000871002").unwrap(),
            "AT+CSIM=24,\"00A4040007A0000000871002\""
        );
    }

    #[test]
    fn extracts_csim_response_hex() {
        assert_eq!(
            extract_csim_hex(r#"+CSIM: 144,0,"62098407A0000000871002""#).unwrap(),
            "62098407A0000000871002"
        );
    }

    #[test]
    fn builds_aka_auth_apdu_from_base64_nonce() {
        let nonce = STANDARD.encode([0x11u8; 32]);
        let command = build_aka_auth_command(&nonce).unwrap();
        assert!(command.contains("008800812210"));
        assert!(command.ends_with("\""));
    }

    #[test]
    fn parses_aka_material() {
        let response = "DB02AABB DC02CCDD DD02EEFF 9000";
        let parsed = parse_aka_response(response).unwrap().unwrap();
        assert_eq!(parsed.res, vec![0xAA, 0xBB]);
        assert_eq!(parsed.ck, vec![0xCC, 0xDD]);
        assert_eq!(parsed.ik, vec![0xEE, 0xFF]);
    }

    #[test]
    fn parses_auts_resync() {
        assert_eq!(
            parse_aka_response("DE02AABB9000").unwrap(),
            Err(AkaResync {
                auts: vec![0xAA, 0xBB]
            })
        );
    }
}
