//! Native IMS/VoLTE runtime boundary.
//!
//! The beta9 runtime is intentionally kept separate from ModemManager's
//! ordinary data and SMS paths.  This module currently exposes the persisted
//! runtime snapshot used by the API; the DATA6/QMI and SIP workers will update
//! the same snapshot as they are ported.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::task::JoinHandle;

use anyhow::{anyhow, Result};
use crate::config::ConfigManager;
use crate::db::Database;
use crate::notification::NotificationSender;
use zbus::Connection;

pub const RUNTIME_STATUS_PATH: &str = "/run/simadmin/volte-status.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub sms_ready: bool,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub last_error: String,
}

pub fn read_runtime_status() -> Option<RuntimeStatus> {
    let contents = fs::read_to_string(RUNTIME_STATUS_PATH).ok()?;
    serde_json::from_str(&contents).ok()
}

pub fn write_runtime_status(status: &RuntimeStatus) -> Result<()> {
    let path = Path::new(RUNTIME_STATUS_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid VoLTE runtime status path"))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(status)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmiBearerSettings {
    pub ipv6_address: String,
    pub ipv6_gateway: String,
    pub ipv6_prefix: u8,
    pub mtu: Option<u32>,
}

#[derive(Debug)]
struct ConfiguredImsNetwork {
    netdev: String,
    settings: QmiBearerSettings,
    pcscf_routes: Vec<std::net::Ipv6Addr>,
}

struct NativeImsRegistration {
    channel: crate::ims_channel::ImsSipChannel,
    xfrm_plan: crate::ims_ipsec::XfrmPlan,
    sip: crate::ims_sip::SipRegistration,
    security_header: String,
    service_routes: Vec<String>,
    refresh_after: Duration,
}

/// Parse the stable fields emitted by `qmicli --wds-get-current-settings`.
/// The parser intentionally ignores localized labels and fields that are not
/// needed by the IMS path; callers must still validate that both IPv6 values
/// are present before installing routes or XFRM policies.
pub fn parse_qmi_bearer_settings(output: &str) -> Option<QmiBearerSettings> {
    let value = |label: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(label))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };

    let address_value = value("IPv6 address:")?;
    let mut address_parts = address_value.split('/');
    let ipv6_address = address_parts.next()?.to_string();
    let ipv6_prefix = address_parts
        .next()
        .and_then(|prefix| prefix.parse::<u8>().ok())
        .or_else(|| value("IPv6 subnet prefix:").and_then(|prefix| prefix.parse().ok()))
        .filter(|prefix| *prefix <= 128)
        .unwrap_or(64);
    let ipv6_gateway = value("IPv6 gateway address:")?.split('/').next()?.to_string();
    let mtu = value("MTU:").and_then(|value| value.parse().ok());
    Some(QmiBearerSettings {
        ipv6_address,
        ipv6_gateway,
        ipv6_prefix,
        mtu,
    })
}

pub async fn configure_secondary_ipv6_interface(
    netdev: &str,
    settings: &QmiBearerSettings,
    pcscf: std::net::Ipv6Addr,
) -> Result<()> {
    if netdev.trim().is_empty() {
        return Err(anyhow!("secondary IMS network interface is unavailable"));
    }
    let address = settings
        .ipv6_address
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| anyhow!("secondary IMS IPv6 address is invalid"))?;
    let gateway = settings
        .ipv6_gateway
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| anyhow!("secondary IMS IPv6 gateway is invalid"))?;
    let prefix = settings.ipv6_prefix;
    for args in [
        vec![
            "link".to_string(),
            "set".to_string(),
            "dev".to_string(),
            netdev.to_string(),
            "up".to_string(),
        ],
        vec![
            "-6".to_string(),
            "addr".to_string(),
            "replace".to_string(),
            format!("{address}/{prefix}"),
            "dev".to_string(),
            netdev.to_string(),
        ],
        vec![
            "-6".to_string(),
            "route".to_string(),
            "replace".to_string(),
            format!("{pcscf}/128"),
            "via".to_string(),
            gateway.to_string(),
            "dev".to_string(),
            netdev.to_string(),
        ],
    ] {
        let output = Command::new("ip").args(args).output().await?;
        if !output.status.success() {
            return Err(anyhow!(
                "failed to configure secondary IMS interface: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    Ok(())
}

async fn cleanup_secondary_ipv6_interface(network: &ConfiguredImsNetwork) {
    let Ok(address) = network.settings.ipv6_address.parse::<std::net::Ipv6Addr>() else {
        return;
    };
    let Ok(gateway) = network.settings.ipv6_gateway.parse::<std::net::Ipv6Addr>() else {
        return;
    };

    for pcscf in &network.pcscf_routes {
        let _ = Command::new("ip")
            .args([
                "-6",
                "route",
                "del",
                &format!("{pcscf}/128"),
                "via",
                &gateway.to_string(),
                "dev",
                &network.netdev,
            ])
            .output()
            .await;
    }
    let _ = Command::new("ip")
        .args([
            "-6",
            "addr",
            "del",
            &format!("{}/{}", address, network.settings.ipv6_prefix),
            "dev",
            &network.netdev,
        ])
        .output()
        .await;
}

pub fn parse_qmi_packet_handle(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() == "Packet data handle" {
            let value = value.trim().trim_matches('\'');
            (!value.is_empty()).then(|| value.to_string())
        } else {
            None
        }
    })
}

pub fn parse_qmi_client_id(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() == "CID" {
            let value = value.trim().trim_matches('\'');
            (!value.is_empty()).then(|| value.to_string())
        } else {
            None
        }
    })
}

#[derive(Debug)]
pub struct QmiPacketSession {
    packet_handle: String,
    client_id: String,
}

pub fn secondary_netdev(qmi_device: &str) -> String {
    if let Ok(value) = std::env::var("SIMADMIN_SECONDARY_QMI_NETDEV") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    if qmi_device == "/dev/wwan0at2" {
        "wwan1".to_string()
    } else {
        String::new()
    }
}

pub fn parse_qmi_connection_status(output: &str) -> Option<bool> {
    output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        if label.trim() != "Connection status" {
            return None;
        }
        match value.trim().trim_matches('\'') {
            "connected" => Some(true),
            "disconnected" => Some(false),
            _ => None,
        }
    })
}

pub async fn start_secondary_ims_bearer(
    qmi_device: &str,
    apn: &str,
) -> Result<(QmiPacketSession, QmiBearerSettings)> {
    if qmi_device.trim().is_empty() || apn.trim().is_empty() {
        return Err(anyhow!("QMI device and IMS APN are required"));
    }

    let family_output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
                "--wds-set-ip-family=6",
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out setting secondary IMS IPv6 family"))??;
    if !family_output.status.success() {
        return Err(anyhow!(
            "qmicli failed to set secondary IMS IPv6 family: {}",
            String::from_utf8_lossy(&family_output.stderr).trim()
        ));
    }
    let start_arg = format!("--wds-start-network=apn={apn},ip-type=6");
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
                "--client-no-release-cid",
                &start_arg,
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out starting secondary IMS bearer"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to start secondary IMS bearer: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let handle = parse_qmi_packet_handle(&stdout)
        .ok_or_else(|| anyhow!("qmicli did not return a packet data handle"))?;
    let client_id = parse_qmi_client_id(&stdout)
        .ok_or_else(|| anyhow!("qmicli did not return the retained WDS client ID"))?;
    let session = QmiPacketSession {
        packet_handle: handle,
        client_id,
    };
    let mut last_error = None;
    for _ in 0..5 {
        match read_secondary_bearer_settings(qmi_device, &session).await {
            Ok(settings) => return Ok((session, settings)),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let _ = stop_secondary_ims_bearer(qmi_device, &session).await;
    Err(last_error.unwrap_or_else(|| anyhow!("secondary IMS bearer settings unavailable")))
}

pub async fn read_secondary_bearer_settings(
    qmi_device: &str,
    session: &QmiPacketSession,
) -> Result<QmiBearerSettings> {
    let cid_arg = format!("--client-cid={}", session.client_id);
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
                &cid_arg,
                "--client-no-release-cid",
                "--wds-get-current-settings",
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out reading secondary IMS bearer settings"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to read secondary IMS bearer settings: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_qmi_bearer_settings(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow!("secondary IMS bearer did not provide IPv6 settings"))
}

async fn register_native_ims(
    conn: &Connection,
    settings: &QmiBearerSettings,
    pcscf: std::net::Ipv6Addr,
    netdev: &str,
) -> Result<NativeImsRegistration> {
    let local: std::net::Ipv6Addr = settings
        .ipv6_address
        .parse()
        .map_err(|_| anyhow!("IMS bearer IPv6 address is invalid"))?;
    let modem_path = crate::modem_manager::find_modem_path(conn)
        .await
        .map_err(|error| anyhow!("cannot find modem for IMS AKA: {error}"))?;
    let identity = crate::modem_manager::current_sim_identity(conn)
        .await
        .ok_or_else(|| anyhow!("IMS modem identity is unavailable"))?;
    if identity.imsi.is_empty() {
        return Err(anyhow!("IMS modem IMSI is unavailable"));
    }
    let home_plmn =
        crate::ims_identity::resolve_home_plmn(&identity.imsi, Some(&identity.operator_id), None)?;
    let ims_identity = crate::ims_identity::derive_identity(&identity.imsi, &home_plmn);
    let domain = std::env::var("SIMADMIN_IMS_DOMAIN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(ims_identity.home_domain);
    let private_identity = format!("{}@{}", identity.imsi, domain);
    let public_identity = format!("sip:{}@{}", identity.imsi, domain);
    let route = crate::ims_channel::SipRoute {
        local: std::net::SocketAddr::new(local.into(), 0),
        remote: std::net::SocketAddr::new(pcscf.into(), 5060),
    };
    let mut channel = crate::ims_channel::ImsSipChannel::bind(route, Some(netdev))?;
    let receive_port = channel.reserve_security_receive_port()?;
    let ue_security = crate::ims_ipsec::generate_ue_security(
        channel.route().local.port(),
        receive_port,
    )?;
    let mut registration = crate::ims_sip::SipRegistration {
        private_identity,
        public_identity,
        realm: domain,
        nonce: String::new(),
        aka_res: Vec::new(),
        digest_algorithm: "AKAv1-MD5".to_string(),
        digest_qop: None,
        digest_opaque: None,
        digest_proxy: false,
        cnonce: format!("{:x}", md5::compute(format!("{}:cnonce", identity.imsi))),
        nonce_count: 1,
        call_id: format!(
            "simadmin-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ),
        cseq: 1,
        contact_host: local,
        contact_port: channel.route().local.port(),
    };
    let initial = crate::ims_sip::build_initial_register_with_security(
        &registration,
        "z9hG4bK-simadmin",
        &ue_security.security_client_header(),
    )?;
    channel.send(initial.as_bytes()).await?;
    let challenge_response = String::from_utf8(
        channel.receive(Duration::from_secs(10)).await?,
    )?;
    if !matches!(
        crate::ims_sip::sip_status_code(&challenge_response),
        Some(401 | 407)
    ) {
        return Err(anyhow!(
            "IMS initial REGISTER returned {:?}",
            crate::ims_sip::sip_status_code(&challenge_response)
        ));
    }
    let mut challenge = crate::ims_sip::parse_aka_challenge(&challenge_response)
        .ok_or_else(|| anyhow!("IMS 401 did not contain an AKA challenge"))?;
    let mut security = crate::ims_sip::parse_security_server(&challenge_response)
        .ok_or_else(|| anyhow!("IMS 401 did not contain Security-Server"))?;
    let mut security_verify = crate::ims_sip::security_server_value(&challenge_response)
        .ok_or_else(|| anyhow!("IMS Security-Server value is unavailable"))?
        .to_string();
    let mut resync_attempted = false;
    let aka = loop {
        let aka_command = crate::ims_uim::build_aka_auth_command(&challenge.nonce)?;
        let aka_output = crate::modem_manager::send_at_command(conn, &modem_path, &aka_command)
            .await
            .map_err(|error| anyhow!("IMS AKA APDU failed: {error}"))?;
        let aka_hex = crate::ims_uim::extract_csim_hex(&aka_output)?;
        match crate::ims_uim::parse_aka_response(&aka_hex)? {
            Ok(aka) => break aka,
            Err(resync) if !resync_attempted => {
                resync_attempted = true;
                registration.cseq = registration.cseq.saturating_add(1);
                registration.realm = challenge.realm.clone();
                let authorization = crate::ims_sip::build_resync_authorization_header(
                    &challenge,
                    &registration.private_identity,
                    &format!("sip:{}", registration.realm),
                    &resync.auts,
                    &registration.cnonce,
                    registration.nonce_count,
                )?;
                let headers = format!(
                    "{authorization}\r\n{}",
                    ue_security.security_client_header()
                );
                let request = crate::ims_sip::build_initial_register_with_security(
                    &registration,
                    "z9hG4bK-simadmin-auts",
                    &headers,
                )?;
                channel.send(request.as_bytes()).await?;
                let response = String::from_utf8(
                    channel.receive(Duration::from_secs(10)).await?,
                )?;
                if !matches!(crate::ims_sip::sip_status_code(&response), Some(401 | 407)) {
                    return Err(anyhow!(
                        "IMS AUTS REGISTER returned {:?}",
                        crate::ims_sip::sip_status_code(&response)
                    ));
                }
                challenge = crate::ims_sip::parse_aka_challenge(&response)
                    .ok_or_else(|| anyhow!("IMS AUTS response did not contain a new AKA challenge"))?;
                security = crate::ims_sip::parse_security_server(&response)
                    .ok_or_else(|| anyhow!("IMS AUTS response did not contain Security-Server"))?;
                security_verify = crate::ims_sip::security_server_value(&response)
                    .ok_or_else(|| anyhow!("IMS AUTS Security-Server value is unavailable"))?
                    .to_string();
            }
            Err(_) => return Err(anyhow!("IMS AKA synchronization failed twice")),
        }
    };
    let pcscf_security = crate::ims_ipsec::SecAgree {
        spi_c: security.client_spi,
        spi_s: security.server_spi,
        port_c: security.client_port,
        port_s: security.server_port,
    };
    let xfrm_plan = crate::ims_ipsec::build_plan(local, pcscf, ue_security, pcscf_security, &aka.ik)?;
    crate::ims_ipsec::install_plan(&xfrm_plan).await?;
    if let Err(error) = channel.activate_security(
        crate::ims_channel::SipRoute {
            local: std::net::SocketAddr::new(local.into(), ue_security.port_c),
            remote: std::net::SocketAddr::new(pcscf.into(), pcscf_security.port_s),
        },
        std::net::SocketAddr::new(local.into(), ue_security.port_s),
        std::net::SocketAddr::new(pcscf.into(), pcscf_security.port_c),
        security_verify,
    ) {
        crate::ims_ipsec::uninstall_plan(&xfrm_plan).await;
        return Err(error);
    }
    registration.realm = challenge.realm;
    registration.nonce = challenge.nonce;
    registration.digest_algorithm = challenge.algorithm;
    registration.digest_qop = challenge.qop;
    registration.digest_opaque = challenge.opaque;
    registration.digest_proxy = challenge.proxy;
    registration.aka_res = aka.res;
    registration.cseq = registration.cseq.saturating_add(1);
    registration.contact_port = ue_security.port_c;
    let security_header = format!(
        "{}Security-Verify: {}\r\n",
        ue_security.security_client_header(),
        channel.security_verify().unwrap_or_default()
    );
    let authenticated = crate::ims_sip::build_register_with_security(
        &registration,
        "z9hG4bK-simadmin-auth",
        &security_header,
    )?;
    if let Err(error) = channel.send(authenticated.as_bytes()).await {
        crate::ims_ipsec::uninstall_plan(&xfrm_plan).await;
        return Err(error);
    }
    let registered = match channel.receive(Duration::from_secs(10)).await {
        Ok(response) => match String::from_utf8(response) {
            Ok(response) => response,
            Err(error) => {
                crate::ims_ipsec::uninstall_plan(&xfrm_plan).await;
                return Err(error.into());
            }
        },
        Err(error) => {
            crate::ims_ipsec::uninstall_plan(&xfrm_plan).await;
            return Err(error);
        }
    };
    if crate::ims_sip::sip_status_code(&registered) != Some(200) {
        crate::ims_ipsec::uninstall_plan(&xfrm_plan).await;
        return Err(anyhow!(
            "IMS authenticated REGISTER returned {:?}",
            crate::ims_sip::sip_status_code(&registered)
        ));
    }
    if crate::ims_sip::registration_expires(&registered) == 0 {
        crate::ims_ipsec::uninstall_plan(&xfrm_plan).await;
        return Err(anyhow!("IMS REGISTER response expired the binding"));
    }
    let refresh_after = crate::ims_sip::registration_refresh_delay(&registered);
    let service_routes = crate::ims_sip::service_routes(&registered);
    Ok(NativeImsRegistration {
        channel,
        xfrm_plan,
        sip: registration,
        security_header,
        service_routes,
        refresh_after,
    })
}

pub async fn secondary_ims_bearer_connected(
    qmi_device: &str,
    session: &QmiPacketSession,
) -> Result<bool> {
    let cid_arg = format!("--client-cid={}", session.client_id);
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
                &cid_arg,
                "--client-no-release-cid",
                "--wds-get-packet-service-status",
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out reading secondary IMS bearer status"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to read secondary IMS bearer status: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_qmi_connection_status(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| anyhow!("secondary IMS bearer status was not recognized"))
}

pub async fn stop_secondary_ims_bearer(
    qmi_device: &str,
    session: &QmiPacketSession,
) -> Result<()> {
    if qmi_device.trim().is_empty() || session.packet_handle.trim().is_empty() {
        return Err(anyhow!("QMI device and packet handle are required"));
    }

    let stop_arg = format!("--wds-stop-network={}", session.packet_handle);
    let cid_arg = format!("--client-cid={}", session.client_id);
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("qmicli")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
                &cid_arg,
                &stop_arg,
            ])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("timed out stopping secondary IMS bearer"))??;

    if !output.status.success() {
        return Err(anyhow!(
            "qmicli failed to stop secondary IMS bearer: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

pub async fn run_secondary_ims_bearer_supervisor(
    config: Arc<ConfigManager>,
    conn: Arc<Connection>,
    database: Arc<Database>,
    notifications: Arc<NotificationSender>,
) {
    let mut active: Option<(String, QmiPacketSession)> = None;
    let mut sms_listener: Option<JoinHandle<()>> = None;
    let mut active_xfrm: Option<crate::ims_ipsec::XfrmPlan> = None;
    let mut active_network: Option<ConfiguredImsNetwork> = None;

    loop {
        let volte = config.get_config().volte;
        if !volte.feature_enabled {
            if let Some(listener) = sms_listener.take() {
                listener.abort();
            }
            if let Some(plan) = active_xfrm.take() {
                crate::ims_ipsec::uninstall_plan(&plan).await;
            }
            if let Some(network) = active_network.take() {
                cleanup_secondary_ipv6_interface(&network).await;
            }
            if let Some((device, handle)) = active.take() {
                let _ = stop_secondary_ims_bearer(&device, &handle).await;
            }
            let _ = write_runtime_status(&RuntimeStatus {
                phase: "disabled".to_string(),
                transport: "native_qmi".to_string(),
                ..RuntimeStatus::default()
            });
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        if active.is_none() {
            let device = std::env::var("SIMADMIN_SECONDARY_QMI_DEVICE")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    fs::read_to_string("/run/simadmin/secondary-qmi-device")
                        .ok()
                        .map(|value| value.trim().to_string())
                });
            let Some(device) = device else {
                let _ = write_runtime_status(&RuntimeStatus {
                    phase: "waiting_for_secondary_qmi".to_string(),
                    transport: "native_qmi".to_string(),
                    last_error: "secondary QMI device is unavailable".to_string(),
                    ..RuntimeStatus::default()
                });
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };
            let netdev = secondary_netdev(&device);

            let _ = write_runtime_status(&RuntimeStatus {
                phase: "starting_ims_bearer".to_string(),
                transport: "native_qmi".to_string(),
                interface: netdev.clone(),
                ..RuntimeStatus::default()
            });
            match start_secondary_ims_bearer(&device, "ims").await {
                Ok((handle, settings)) => {
                    active = Some((device.clone(), handle));
                    let mut pcscf_candidates = Vec::new();
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "usim_aid_selecting".to_string(),
                        transport: "native_qmi".to_string(),
                        ..RuntimeStatus::default()
                    });
                    match crate::modem_manager::find_modem_path(&conn).await {
                        Ok(modem_path) => {
                            let command = match crate::ims_uim::build_csim_command(
                                "00A4040007A0000000871002",
                            ) {
                                Ok(command) => command,
                                Err(error) => {
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "usim_aid_failed".to_string(),
                                        transport: "native_qmi".to_string(),
                                        last_error: error.to_string(),
                                        ..RuntimeStatus::default()
                                    });
                                    continue;
                                }
                            };
                            match crate::modem_manager::send_at_command(
                                &conn,
                                &modem_path,
                                &command,
                            )
                            .await
                            {
                                Ok(response) => match crate::ims_uim::extract_csim_hex(&response)
                                    .and_then(|hex| {
                                        crate::ims_uim::parse_aid_from_select_response(&hex)
                                            .map(|_| ())
                                    }) {
                                    Ok(()) => {}
                                    Err(error) => {
                                        let _ = write_runtime_status(&RuntimeStatus {
                                            phase: "usim_aid_failed".to_string(),
                                            transport: "native_qmi".to_string(),
                                            last_error: error.to_string(),
                                            ..RuntimeStatus::default()
                                        });
                                    }
                                },
                                Err(error) => {
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "usim_aid_failed".to_string(),
                                        transport: "native_qmi".to_string(),
                                        last_error: error,
                                        ..RuntimeStatus::default()
                                    });
                                }
                            }
                        }
                        Err(error) => {
                            let _ = write_runtime_status(&RuntimeStatus {
                                phase: "usim_aid_failed".to_string(),
                                transport: "native_qmi".to_string(),
                                last_error: error.to_string(),
                                ..RuntimeStatus::default()
                            });
                        }
                    }
                    if let Ok(modem_path) = crate::modem_manager::find_modem_path(&conn).await {
                        match crate::modem_manager::send_at_command(
                            &conn,
                            &modem_path,
                            "AT+CGCONTRDP",
                        )
                        .await
                        {
                            Ok(response) => {
                                pcscf_candidates = crate::ims_sip::parse_pcscf_candidates_from_cgcontrdp(
                                    &response,
                                    "ims",
                                );
                                if !pcscf_candidates.is_empty() {
                                    tracing::info!(count = pcscf_candidates.len(), "IMS P-CSCF candidates discovered");
                                    let _ = write_runtime_status(&RuntimeStatus {
                                        phase: "pcscf_discovered".to_string(),
                                        transport: "native_qmi".to_string(),
                                        ..RuntimeStatus::default()
                                    });
                                }
                            }
                            Err(error) => tracing::debug!(error = %error, "IMS P-CSCF AT query failed"),
                        }
                    }
                    let mut registration_succeeded = false;
                    for pcscf in pcscf_candidates {
                        let _ = write_runtime_status(&RuntimeStatus {
                            phase: "ims_registering".to_string(),
                            transport: "native_qmi_ipsec".to_string(),
                            interface: netdev.clone(),
                            ..RuntimeStatus::default()
                        });
                        if let Err(error) = configure_secondary_ipv6_interface(
                            &netdev,
                            &settings,
                            pcscf,
                        )
                        .await
                        {
                            let _ = write_runtime_status(&RuntimeStatus {
                                phase: "ims_interface_failed".to_string(),
                                transport: "native_qmi".to_string(),
                                interface: netdev.clone(),
                                last_error: error.to_string(),
                                ..RuntimeStatus::default()
                            });
                        } else {
                            match active_network.as_mut() {
                                Some(network) => {
                                    if !network.pcscf_routes.contains(&pcscf) {
                                        network.pcscf_routes.push(pcscf);
                                    }
                                }
                                None => {
                                    active_network = Some(ConfiguredImsNetwork {
                                        netdev: netdev.clone(),
                                        settings: settings.clone(),
                                        pcscf_routes: vec![pcscf],
                                    });
                                }
                            }
                            match register_native_ims(&conn, &settings, pcscf, &netdev).await {
                            Ok(session) => {
                                registration_succeeded = true;
                                active_xfrm = Some(session.xfrm_plan);
                                if volte.sms_enabled {
                                    let database_clone = Arc::clone(&database);
                                    let notifications_clone = Arc::clone(&notifications);
                                    sms_listener = Some(tokio::spawn(async move {
                                        if let Err(error) = crate::ims_sms::run_ims_sms_listener(
                                            session.channel,
                                            session.sip,
                                            session.security_header,
                                            session.service_routes,
                                            session.refresh_after,
                                            database_clone,
                                            notifications_clone,
                                        )
                                        .await
                                        {
                                            tracing::warn!(error = %error, "IMS SMS listener stopped");
                                        }
                                    }));
                                }
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "registered".to_string(),
                                    registered: true,
                                    sms_ready: volte.sms_enabled,
                                    transport: "native_qmi_ipsec".to_string(),
                                    interface: netdev.clone(),
                                    ..RuntimeStatus::default()
                                });
                                break;
                            }
                            Err(error) => {
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "register_failed".to_string(),
                                    transport: "native_qmi_ipsec".to_string(),
                                    last_error: error.to_string(),
                                    ..RuntimeStatus::default()
                                });
                            }
                            }
                        }
                    }
                    if !registration_succeeded {
                        if let Some(listener) = sms_listener.take() {
                            listener.abort();
                        }
                        if let Some(plan) = active_xfrm.take() {
                            crate::ims_ipsec::uninstall_plan(&plan).await;
                        }
                        if let Some(network) = active_network.take() {
                            cleanup_secondary_ipv6_interface(&network).await;
                        }
                        if let Some((active_device, active_handle)) = active.take() {
                            let _ = stop_secondary_ims_bearer(&active_device, &active_handle).await;
                        }
                        let _ = write_runtime_status(&RuntimeStatus {
                            phase: "bearer_connected".to_string(),
                            transport: "native_qmi".to_string(),
                            interface: netdev.clone(),
                            ..RuntimeStatus::default()
                        });
                    }
                }
                Err(error) => {
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "bearer_failed".to_string(),
                        transport: "native_qmi".to_string(),
                        last_error: error.to_string(),
                        ..RuntimeStatus::default()
                    });
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
            continue;
        }

        if sms_listener.as_ref().is_some_and(|listener| listener.is_finished()) {
            if let Some(listener) = sms_listener.take() {
                let _ = listener.await;
            }
            if let Some(plan) = active_xfrm.take() {
                crate::ims_ipsec::uninstall_plan(&plan).await;
            }
            if let Some(network) = active_network.take() {
                cleanup_secondary_ipv6_interface(&network).await;
            }
            if let Some((device, handle)) = active.take() {
                let _ = stop_secondary_ims_bearer(&device, &handle).await;
            }
            let _ = write_runtime_status(&RuntimeStatus {
                phase: "ims_session_lost".to_string(),
                transport: "native_qmi_ipsec".to_string(),
                last_error: "IMS SIP session stopped; reconnecting".to_string(),
                ..RuntimeStatus::default()
            });
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        let (device, handle) = active.as_ref().expect("active bearer exists");
        match secondary_ims_bearer_connected(device, handle).await {
            Ok(true) => {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(false) | Err(_) => {
                if let Some(listener) = sms_listener.take() {
                    listener.abort();
                }
                if let Some(plan) = active_xfrm.take() {
                    crate::ims_ipsec::uninstall_plan(&plan).await;
                }
                if let Some(network) = active_network.take() {
                    cleanup_secondary_ipv6_interface(&network).await;
                }
                let _ = stop_secondary_ims_bearer(device, handle).await;
                active = None;
                let _ = write_runtime_status(&RuntimeStatus {
                    phase: "bearer_disconnected".to_string(),
                    transport: "native_qmi".to_string(),
                    ..RuntimeStatus::default()
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeStatus;

    #[test]
    fn defaults_missing_runtime_fields() {
        let status: RuntimeStatus = serde_json::from_str(r#"{"registered":true}"#).unwrap();
        assert!(status.registered);
        assert!(!status.sms_ready);
        assert!(status.transport.is_empty());
    }

    #[test]
    fn parses_qmi_ipv6_settings() {
        let output = "IPv6 address: 2001:db8::10\nIPv6 gateway address: 2001:db8::1\nMTU: 1432";
        assert_eq!(
            super::parse_qmi_bearer_settings(output),
            Some(super::QmiBearerSettings {
                ipv6_address: "2001:db8::10".to_string(),
                ipv6_gateway: "2001:db8::1".to_string(),
                ipv6_prefix: 64,
                mtu: Some(1432),
            })
        );
    }

    #[test]
    fn strips_qmi_ipv6_prefix_lengths() {
        let output =
            "IPv6 address: 2001:db8::10/64\nIPv6 gateway address: 2001:db8::1/64\nMTU: 1432";
        let settings = super::parse_qmi_bearer_settings(output).unwrap();
        assert_eq!(settings.ipv6_address, "2001:db8::10");
        assert_eq!(settings.ipv6_gateway, "2001:db8::1");
        assert_eq!(settings.ipv6_prefix, 64);
    }

    #[test]
    fn parses_separate_qmi_ipv6_prefix() {
        let output = "IPv6 address: 2001:db8::10\nIPv6 subnet prefix: 56\nIPv6 gateway address: 2001:db8::1";
        assert_eq!(super::parse_qmi_bearer_settings(output).unwrap().ipv6_prefix, 56);
    }

    #[test]
    fn parses_qmi_packet_handle() {
        assert_eq!(
            super::parse_qmi_packet_handle("Packet data handle: '42'"),
            Some("42".to_string())
        );
        assert_eq!(
            super::parse_qmi_client_id("Service: 'wds'\nCID: '17'"),
            Some("17".to_string())
        );
    }

    #[test]
    fn derives_beta9_secondary_netdev() {
        assert_eq!(super::secondary_netdev("/dev/wwan0at2"), "wwan1");
    }

    #[test]
    fn parses_qmi_connection_status() {
        assert_eq!(
            super::parse_qmi_connection_status("Connection status: 'connected'"),
            Some(true)
        );
        assert_eq!(
            super::parse_qmi_connection_status("Connection status: 'disconnected'"),
            Some(false)
        );
    }
}
