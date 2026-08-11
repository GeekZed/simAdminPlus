//! XFRM/IPsec primitives used by the native IMS registration path.
//!
//! The AKA worker supplies the negotiated keys and SPIs.  This module keeps
//! command construction and validation separate so an incomplete auth result
//! can never install a partial policy.

use anyhow::{anyhow, Result};
use std::net::Ipv6Addr;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspSecurityAssociation {
    pub local: Ipv6Addr,
    pub remote: Ipv6Addr,
    pub spi: u32,
    pub auth_key_hex: String,
}

impl EspSecurityAssociation {
    fn validate(&self) -> Result<()> {
        if self.spi == 0 {
            return Err(anyhow!("IPsec SPI must be non-zero"));
        }
        if self.auth_key_hex.is_empty() {
            return Err(anyhow!("IPsec authentication key must not be empty"));
        }
        if !is_hex(&self.auth_key_hex) {
            return Err(anyhow!("IPsec authentication key must be hexadecimal"));
        }
        Ok(())
    }

    fn args(&self) -> Vec<String> {
        vec![
            "xfrm".into(),
            "state".into(),
            "add".into(),
            "src".into(),
            self.local.to_string(),
            "dst".into(),
            self.remote.to_string(),
            "proto".into(),
            "esp".into(),
            "spi".into(),
            format!("0x{:08x}", self.spi),
            "mode".into(),
            "transport".into(),
            "auth-trunc".into(),
            "hmac(md5)".into(),
            self.auth_key_hex.clone(),
            "96".into(),
            "enc".into(),
            "ecb(cipher_null)".into(),
        ]
    }
}

fn is_hex(value: &str) -> bool {
    value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub async fn install_esp_state(sa: &EspSecurityAssociation) -> Result<()> {
    sa.validate()?;
    let mut args = sa.args();
    let mut output = Command::new("ip")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("file exists")
    {
        args[2] = "update".into();
        output = Command::new("ip")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await?;
    }
    if !output.status.success() {
        return Err(anyhow!(
            "failed to install IMS IPsec state: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

async fn install_policy(
    direction: &str,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    spi: u32,
    source_port: u16,
    destination_port: u16,
) -> Result<()> {
    let mut args = vec![
        "xfrm".to_string(),
        "policy".to_string(),
        "add".to_string(),
        "dir".to_string(),
        direction.to_string(),
        "src".to_string(),
        format!("{local}/128"),
        "dst".to_string(),
        format!("{remote}/128"),
        "proto".to_string(),
        "udp".to_string(),
        "sport".to_string(),
        source_port.to_string(),
        "dport".to_string(),
        destination_port.to_string(),
        "tmpl".to_string(),
        "src".to_string(),
        local.to_string(),
        "dst".to_string(),
        remote.to_string(),
        "proto".to_string(),
        "esp".to_string(),
        "spi".to_string(),
        format!("0x{spi:08x}"),
        "mode".to_string(),
        "transport".to_string(),
    ];
    let mut output = Command::new("ip")
        .args(&args)
        .output()
        .await?;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("file exists")
    {
        args[2] = "update".to_string();
        output = Command::new("ip").args(&args).output().await?;
    }
    if !output.status.success() {
        return Err(anyhow!(
            "failed to install IMS IPsec {direction} policy: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

pub async fn install_bidirectional_esp(
    local: Ipv6Addr,
    remote: Ipv6Addr,
    client_spi: u32,
    server_spi: u32,
    ik_hex: &str,
    local_send_port: u16,
    local_receive_port: u16,
    remote_client_port: u16,
    remote_send_port: u16,
) -> Result<()> {
    let outbound = EspSecurityAssociation {
        local,
        remote,
        spi: client_spi,
        auth_key_hex: ik_hex.to_string(),
    };
    let inbound = EspSecurityAssociation {
        local: remote,
        remote: local,
        spi: server_spi,
        auth_key_hex: ik_hex.to_string(),
    };
    install_esp_state(&outbound).await?;
    install_esp_state(&inbound).await?;
    install_policy(
        "out",
        local,
        remote,
        client_spi,
        local_send_port,
        remote_send_port,
    )
    .await?;
    install_policy(
        "in",
        remote,
        local,
        server_spi,
        remote_client_port,
        local_receive_port,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EspSecurityAssociation {
        EspSecurityAssociation {
            local: "2001:db8::1".parse().unwrap(),
            remote: "2001:db8::2".parse().unwrap(),
            spi: 0x1234,
            auth_key_hex: "aa".repeat(20),
        }
    }

    #[test]
    fn rejects_empty_keys() {
        let mut sa = sample();
        sa.auth_key_hex.clear();
        assert!(sa.validate().is_err());
    }

    #[test]
    fn builds_transport_esp_arguments() {
        let args = sample().args();
        assert_eq!(args[2], "add");
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "mode" && pair[1] == "transport"));
        assert!(args.iter().any(|value| value == "0x00001234"));
        assert!(args
            .windows(2)
            .any(|pair| pair[0] == "enc" && pair[1] == "ecb(cipher_null)"));
    }
}
