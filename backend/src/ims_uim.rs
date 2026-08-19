//! USIM application and AKA response parsing for native IMS.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::time::Duration;
use tokio::process::Command;

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
    let (rand, autn) = decode_aka_nonce(nonce)?;
    let apdu = format!(
        "008800812210{}{}",
        encode_hex(&rand),
        encode_hex(&autn)
    );
    build_csim_command(&apdu)
}

fn decode_aka_nonce(nonce: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = nonce.trim().trim_matches('"');
    let auth_data = STANDARD
        .decode(nonce)
        .or_else(|_| decode_hex(nonce))
        .map_err(|_| anyhow!("IMS AKA nonce is not base64 or hexadecimal"))?;
    if auth_data.len() < 32 {
        return Err(anyhow!("IMS AKA nonce must contain RAND and AUTN"));
    }
    Ok((auth_data[..16].to_vec(), auth_data[16..32].to_vec()))
}

pub async fn authenticate_via_qmi(nonce: &str) -> Result<Result<AkaResponse, AkaResync>> {
    let (rand, autn) = decode_aka_nonce(nonce)?;
    let device = std::env::var("SIMADMIN_PRIMARY_QMI_DEVICE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/dev/wwan0qmi0".to_string());
    let slot = std::env::var("SIMADMIN_UIM_SLOT")
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(1);
    let card_status = run_qmicli(&device, &["--uim-get-card-status"]).await?;
    let aid = parse_usim_aid_from_card_status(&card_status)
        .map(|aid| encode_hex(&aid))
        .unwrap_or_else(|| "A0000000871002".to_string());
    let open_arg = format!("--uim-open-logical-channel={slot},{aid}");
    let open = run_qmicli(&device, &["--client-no-release-cid", &open_arg]).await?;
    let channel = open.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Open Logical Channel operation successfully completed:")?
            .trim()
            .parse::<u8>()
            .ok()
    }).ok_or_else(|| anyhow!("QMI UIM did not return a logical channel"))?;
    let client_id = open.lines().find_map(|line| {
        let (label, value) = line.trim().split_once(':')?;
        (label == "CID").then(|| value.trim().trim_matches('\'').to_string())
    }).filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("QMI UIM did not retain a client ID"))?;

    let mut apdu = format!(
        "008800812210{}{}00",
        encode_hex(&rand),
        encode_hex(&autn)
    );
    let response = send_qmi_apdu(&device, slot, channel, &client_id, &apdu).await;
    let response = match response {
        Ok(response) if response.len() >= 4 && response[response.len() - 4..response.len() - 2].eq_ignore_ascii_case("61") => {
            let length = &response[response.len() - 2..];
            send_qmi_apdu(
                &device,
                slot,
                channel,
                &client_id,
                &format!("00C00000{length}"),
            ).await
        }
        Ok(response) if response.len() >= 4 && response[response.len() - 4..response.len() - 2].eq_ignore_ascii_case("6C") => {
            apdu.replace_range(apdu.len() - 2.., &response[response.len() - 2..]);
            send_qmi_apdu(&device, slot, channel, &client_id, &apdu).await
        }
        response => response,
    };
    let close_arg = format!("--uim-close-logical-channel={slot},{channel}");
    let cid_arg = format!("--client-cid={client_id}");
    let _ = run_qmicli(&device, &[&cid_arg, &close_arg]).await;
    parse_aka_response(&response?)
}

pub fn parse_usim_aid_from_card_status(output: &str) -> Option<Vec<u8>> {
    let mut in_usim = false;
    let mut expects_aid = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Application type:") {
            in_usim = trimmed.to_ascii_lowercase().contains("'usim");
            expects_aid = false;
            continue;
        }
        if in_usim && trimmed == "Application ID:" {
            expects_aid = true;
            continue;
        }
        if expects_aid {
            let hex = trimmed.replace(':', "");
            if let Ok(aid) = decode_hex(&hex) {
                if aid.starts_with(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]) {
                    return Some(aid);
                }
            }
            expects_aid = false;
        }
    }
    None
}

async fn send_qmi_apdu(
    device: &str,
    slot: u8,
    channel: u8,
    client_id: &str,
    apdu: &str,
) -> Result<String> {
    let cid_arg = format!("--client-cid={client_id}");
    let send_arg = format!("--uim-send-apdu={slot},{channel},{apdu}");
    let output = run_qmicli(
        device,
        &[&cid_arg, "--client-no-release-cid", &send_arg],
    ).await?;
    let value = output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Send APDU operation successfully completed:")
    }).ok_or_else(|| anyhow!("QMI UIM did not return an APDU response"))?;
    Ok(value.trim().replace(':', ""))
}

async fn run_qmicli(device: &str, action: &[&str]) -> Result<String> {
    let mut args = vec!["-d", device, "--device-open-proxy", "--device-open-qmi"];
    args.extend_from_slice(action);
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("qmicli").kill_on_drop(true).args(args).output(),
    )
    .await
    .map_err(|_| anyhow!("QMI UIM operation timed out"))??;
    if !output.status.success() {
        return Err(anyhow!(
            "QMI UIM operation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8(output.stdout)?)
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
    if bytes.len() < 2 {
        return Err(anyhow!("USIM AKA APDU response is truncated"));
    }
    if bytes[bytes.len() - 2..] != [0x90, 0x00] {
        return Err(anyhow!(
            "USIM AKA APDU failed (SW={:02X}{:02X}, data_len={})",
            bytes[bytes.len() - 2],
            bytes[bytes.len() - 1],
            bytes.len() - 2
        ));
    }
    let payload = unwrap_authenticate_response(&bytes[..bytes.len() - 2])?;
    match payload.first().copied() {
        Some(0xDB) => {
            let (res, rest) = take_lv(&payload[1..])?;
            let (ck, rest) = take_lv(rest)?;
            let (ik, mut rest) = take_lv(rest)?;
            while !rest.is_empty() {
                let (_, next) = take_lv(rest)?;
                rest = next;
            }
            Ok(Ok(AkaResponse {
                res: res.to_vec(),
                ck: ck.to_vec(),
                ik: ik.to_vec(),
            }))
        }
        Some(0xDC) => {
            let (auts, rest) = take_lv(&payload[1..])?;
            if !rest.is_empty() {
                return Err(anyhow!("USIM AKA synchronization response has trailing data"));
            }
            Ok(Err(AkaResync {
                auts: auts.to_vec(),
            }))
        }
        _ => Err(anyhow!("USIM AKA response tag is invalid")),
    }
}

fn unwrap_authenticate_response(input: &[u8]) -> Result<&[u8]> {
    if matches!(input.first(), Some(0xDB | 0xDC)) {
        return Ok(input);
    }
    if input.len() >= 2 {
        let length = usize::from(input[1]);
        if input.len() == length + 2 && matches!(input.get(2), Some(0xDB | 0xDC)) {
            return Ok(&input[2..]);
        }
    }
    if input.len() >= 3 && input[1] == 0x81 {
        let length = usize::from(input[2]);
        if input.len() == length + 3 && matches!(input.get(3), Some(0xDB | 0xDC)) {
            return Ok(&input[3..]);
        }
    }
    Err(anyhow!("USIM AKA response wrapper is invalid"))
}

fn take_lv(input: &[u8]) -> Result<(&[u8], &[u8])> {
    let (&length, rest) = input
        .split_first()
        .ok_or_else(|| anyhow!("USIM AKA response is truncated"))?;
    let length = usize::from(length);
    if rest.len() < length {
        return Err(anyhow!("USIM AKA response is truncated"));
    }
    Ok(rest.split_at(length))
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
    fn parses_full_usim_aid_from_qmi_card_status() {
        let status = "Application [1]:\n  Application type:  'csim (4)'\n  Application ID:\n    A0:00:00:03:43:10:02\nApplication [2]:\n  Application type:  'usim (2)'\n  Application state: 'ready'\n  Application ID:\n    A0:00:00:00:87:10:02:FF:86:FF:03:89:FF:FF:FF:FF\n";
        assert_eq!(
            encode_hex(&parse_usim_aid_from_card_status(status).unwrap()),
            "A0000000871002FF86FF0389FFFFFFFF"
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
    fn ignores_aka_nonce_server_data_after_rand_and_autn() {
        let nonce = STANDARD.encode([0x11u8; 40]);
        let command = build_aka_auth_command(&nonce).unwrap();
        assert!(!command.contains(&"11".repeat(40)));
        assert!(command.contains(&"11".repeat(32)));
    }

    #[test]
    fn parses_aka_material() {
        let response = "DB02AABB02CCDD02EEFF9000";
        let parsed = parse_aka_response(response).unwrap().unwrap();
        assert_eq!(parsed.res, vec![0xAA, 0xBB]);
        assert_eq!(parsed.ck, vec![0xCC, 0xDD]);
        assert_eq!(parsed.ik, vec![0xEE, 0xFF]);
    }

    #[test]
    fn parses_auts_resync() {
        assert_eq!(
            parse_aka_response("DC02AABB9000").unwrap(),
            Err(AkaResync {
                auts: vec![0xAA, 0xBB]
            })
        );
    }

    #[test]
    fn parses_wrapped_aka_material_and_optional_tail() {
        let parsed = parse_aka_response("800DDB02AABB02CCDD02EEFF02CAFE9000")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.res, vec![0xAA, 0xBB]);
        assert_eq!(parsed.ck, vec![0xCC, 0xDD]);
        assert_eq!(parsed.ik, vec![0xEE, 0xFF]);
    }

    #[test]
    fn rejects_truncated_aka_material() {
        assert!(parse_aka_response("DB04AABB9000").is_err());
    }

    #[test]
    fn reports_apdu_status_without_exposing_payload() {
        assert_eq!(
            parse_aka_response("DEADBEEF9862").unwrap_err().to_string(),
            "USIM AKA APDU failed (SW=9862, data_len=4)"
        );
    }
}
