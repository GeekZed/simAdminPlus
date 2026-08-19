//! Session-owned Linux XFRM plan for IMS `ipsec-3gpp` signaling.

use anyhow::{anyhow, Result};
use ring::rand::{SecureRandom, SystemRandom};
use std::net::Ipv6Addr;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecAgree {
    pub spi_c: u32,
    pub spi_s: u32,
    pub port_c: u16,
    pub port_s: u16,
}

impl SecAgree {
    pub fn security_client_header(self) -> String {
        format!(
            "Security-Client: ipsec-3gpp;alg=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c={};spi-s={};port-c={};port-s={}\r\n",
            self.spi_c, self.spi_s, self.port_c, self.port_s
        )
    }
}

pub fn generate_ue_security(send_port: u16, receive_port: u16) -> Result<SecAgree> {
    if send_port == 0 || receive_port == 0 || send_port == receive_port {
        return Err(anyhow!("IMS security requires distinct non-zero ports"));
    }
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("failed to generate IMS security SPIs"))?;
    let spi_c = u32::from_be_bytes(bytes[..4].try_into().unwrap()).max(1);
    let mut spi_s = u32::from_be_bytes(bytes[4..].try_into().unwrap()).max(1);
    if spi_s == spi_c {
        spi_s = spi_s.wrapping_add(1).max(1);
    }
    Ok(SecAgree { spi_c, spi_s, port_c: send_port, port_s: receive_port })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmState {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub spi: u32,
    pub auth_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmPolicy {
    pub direction: &'static str,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub spi: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmPlan {
    pub states: Vec<XfrmState>,
    pub policies: Vec<XfrmPolicy>,
}

pub fn build_plan(
    ue: Ipv6Addr,
    pcscf: Ipv6Addr,
    ue_security: SecAgree,
    pcscf_security: SecAgree,
    ik: &[u8],
) -> Result<XfrmPlan> {
    if ik.is_empty() {
        return Err(anyhow!("IMS IPsec integrity key is empty"));
    }
    let auth_key_hex = encode_hex(ik);
    Ok(XfrmPlan {
        states: vec![
            XfrmState { src: ue, dst: pcscf, spi: pcscf_security.spi_s, auth_key_hex: auth_key_hex.clone() },
            XfrmState { src: pcscf, dst: ue, spi: ue_security.spi_s, auth_key_hex },
        ],
        policies: vec![
            XfrmPolicy { direction: "out", src: ue, dst: pcscf, source_port: ue_security.port_c, destination_port: pcscf_security.port_s, spi: pcscf_security.spi_s },
            XfrmPolicy { direction: "in", src: pcscf, dst: ue, source_port: pcscf_security.port_c, destination_port: ue_security.port_s, spi: ue_security.spi_s },
        ],
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let value: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("0x{value}")
}

fn state_add_args(state: &XfrmState) -> Vec<String> {
    vec![
        "xfrm".into(), "state".into(), "add".into(), "src".into(), state.src.to_string(),
        "dst".into(), state.dst.to_string(), "proto".into(), "esp".into(), "spi".into(),
        format!("0x{:08x}", state.spi), "mode".into(), "transport".into(),
        "auth-trunc".into(), "hmac(md5)".into(), state.auth_key_hex.clone(), "96".into(),
        "enc".into(), "ecb(cipher_null)".into(), String::new(),
    ]
}

fn state_delete_args(state: &XfrmState) -> Vec<String> {
    vec![
        "xfrm".into(), "state".into(), "delete".into(), "src".into(), state.src.to_string(),
        "dst".into(), state.dst.to_string(), "proto".into(), "esp".into(), "spi".into(),
        format!("0x{:08x}", state.spi),
    ]
}

fn policy_args(policy: &XfrmPolicy, action: &str) -> Vec<String> {
    let mut args = vec![
        "xfrm".into(), "policy".into(), action.into(), "dir".into(), policy.direction.into(),
        "src".into(), format!("{}/128", policy.src), "dst".into(), format!("{}/128", policy.dst),
        "proto".into(), "udp".into(), "sport".into(), policy.source_port.to_string(),
        "dport".into(), policy.destination_port.to_string(),
    ];
    if action == "add" {
        args.extend([
            "tmpl".into(), "src".into(), policy.src.to_string(), "dst".into(),
            policy.dst.to_string(), "proto".into(), "esp".into(), "spi".into(),
            format!("0x{:08x}", policy.spi), "mode".into(), "transport".into(),
        ]);
    }
    args
}

async fn run_ip(args: &[String]) -> Result<()> {
    let output = Command::new("ip").args(args).output().await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("ip {} failed: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim()))
    }
}

pub async fn install_plan(plan: &XfrmPlan) -> Result<()> {
    for state in &plan.states {
        if let Err(error) = run_ip(&state_add_args(state)).await {
            uninstall_plan(plan).await;
            return Err(error);
        }
    }
    for policy in &plan.policies {
        if let Err(error) = run_ip(&policy_args(policy, "add")).await {
            uninstall_plan(plan).await;
            return Err(error);
        }
    }
    Ok(())
}

pub async fn uninstall_plan(plan: &XfrmPlan) {
    for policy in plan.policies.iter().rev() {
        let _ = run_ip(&policy_args(policy, "delete")).await;
    }
    for state in plan.states.iter().rev() {
        let _ = run_ip(&state_delete_args(state)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security(spi_c: u32, spi_s: u32, port_c: u16, port_s: u16) -> SecAgree {
        SecAgree { spi_c, spi_s, port_c, port_s }
    }

    #[test]
    fn plan_uses_each_endpoints_negotiated_values() {
        let plan = build_plan(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            security(0x11, 0x12, 6000, 6001),
            security(0x21, 0x22, 7000, 7001),
            &[0xaa; 16],
        ).unwrap();
        assert_eq!(plan.states[0].spi, 0x22);
        assert_eq!(plan.states[1].spi, 0x12);
        assert_eq!((plan.policies[0].source_port, plan.policies[0].destination_port), (6000, 7001));
        assert_eq!((plan.policies[1].source_port, plan.policies[1].destination_port), (7000, 6001));
    }

    #[test]
    fn security_client_uses_rfc_integer_spis() {
        assert_eq!(
            security(1, 2, 5062, 5064).security_client_header(),
            "Security-Client: ipsec-3gpp;alg=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=1;spi-s=2;port-c=5062;port-s=5064\r\n"
        );
    }

    #[test]
    fn null_cipher_supplies_empty_keymat_argument() {
        let args = state_add_args(&XfrmState {
            src: "2001:db8::1".parse().unwrap(),
            dst: "2001:db8::2".parse().unwrap(),
            spi: 1,
            auth_key_hex: "0x00112233445566778899aabbccddeeff".into(),
        });
        assert_eq!(&args[args.len() - 3..], &["enc", "ecb(cipher_null)", ""]);
    }

    #[test]
    fn teardown_is_scoped_to_the_plan() {
        let plan = build_plan(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            security(1, 2, 6000, 6001),
            security(3, 4, 7000, 7001),
            &[0xaa; 16],
        ).unwrap();
        let policy_delete = policy_args(&plan.policies[0], "delete");
        assert_eq!(policy_delete[2], "delete");
        assert!(!policy_delete.contains(&"flush".to_string()));
        assert!(state_delete_args(&plan.states[0]).contains(&"0x00000004".to_string()));
    }
}
