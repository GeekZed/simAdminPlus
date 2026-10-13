//! Native IMS/VoLTE runtime boundary.
//!
//! The beta9 runtime is intentionally kept separate from ModemManager's
//! ordinary data and SMS paths.  This module currently exposes the persisted
//! runtime snapshot used by the API; the DATA6/QMI and SIP workers will update
//! the same snapshot as they are ported.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinHandle;

use anyhow::{anyhow, Result};
use crate::config::ConfigManager;
use crate::db::Database;
use crate::notification::NotificationSender;
use zbus::Connection;

pub const RUNTIME_STATUS_PATH: &str = "/run/simadmin/volte-status.json";

fn qmicli_with_timeout(seconds: &str) -> Command {
    let mut command = Command::new("timeout");
    command.args(["-k", "2", seconds, "qmicli"]);
    command
}

/// 原生 IMS 运行时的可观测状态。
///
/// 该结构同时用作「写状态文件」与「读状态给前端」的唯一载体，因此所有字段都
/// 标注 `#[serde(default)]`：新增诊断字段时，历史状态文件与既有 16 处写入
/// 点（均使用 `..RuntimeStatus::default()` 展开）都无需改动即可保持向后兼容。
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
    /// IMS 承载的地址族（如 `ipv6`）
    #[serde(default)]
    pub family: String,
    /// IMS 承载获得的本地 IPv6 地址
    #[serde(default)]
    pub local_ip: String,
    /// 实际完成注册的 P-CSCF 地址
    #[serde(default)]
    pub pcscf: String,
    /// IMS 承载建立时刻（RFC3339）
    #[serde(default)]
    pub session_started_at: String,
    /// SIP REGISTER 成功时刻（RFC3339）
    #[serde(default)]
    pub registered_at: String,
    /// 最近一次失败时刻（RFC3339），用于诊断间歇性失败
    #[serde(default)]
    pub last_failure_at: String,
    /// 失败原因摘要（已脱敏），与 `last_error` 并存便于前端分组展示
    #[serde(default)]
    pub registration_degraded_reason: String,
    /// 下次重试时刻（RFC3339）
    #[serde(default)]
    pub next_retry_at: String,
    /// 距下次重试的秒数
    #[serde(default)]
    pub retry_after_secs: Option<u64>,
    /// 注册成功累计次数
    #[serde(default)]
    pub reconnect_count: u64,
    /// 注册失败累计次数
    #[serde(default)]
    pub failure_count: u64,
}

/// 生成 RFC3339 时间戳；系统时钟不可用时返回空串，避免污染状态文件。
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn read_runtime_status() -> Option<RuntimeStatus> {
    let contents = fs::read_to_string(RUNTIME_STATUS_PATH).ok()?;
    serde_json::from_str(&contents).ok()
}

/// 手动重连请求标志文件。诊断页面的「重新连接」写入该文件，由 supervisor
/// 在下一轮循环中消费并丢弃现有承载，从而触发 IMS 上下文重建。
pub const RECONNECT_REQUEST_PATH: &str = "/run/simadmin/volte-reconnect-request";

/// 请求 supervisor 重建 IMS 承载。
pub fn request_reconnect() -> std::io::Result<()> {
    let path = Path::new(RECONNECT_REQUEST_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"1")
}

/// 消费一次重连请求；返回 true 表示需要丢弃当前承载。
pub fn consume_reconnect_request() -> bool {
    let path = Path::new(RECONNECT_REQUEST_PATH);
    if path.exists() {
        let _ = std::fs::remove_file(path);
        true
    } else {
        false
    }
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

#[derive(Debug)]
pub struct QmiPacketSession {
    packet_handle: String,
    keeper: tokio::process::Child,
}

fn parse_pdp_contexts(output: &str) -> Vec<(u8, String)> {
    output
        .lines()
        .filter_map(|line| {
            let start = line.find("+CGDCONT:")?;
            let fields = line[start + "+CGDCONT:".len()..]
                .trim()
                .trim_matches('\'')
                .split(',')
                .map(|field| field.trim().trim_matches('"'))
                .collect::<Vec<_>>();
            let profile_id = fields.first()?.parse().ok()?;
            let apn = fields.get(2)?.to_string();
            Some((profile_id, apn))
        })
        .collect()
}

fn select_ims_profile_id(contexts: &[(u8, String)]) -> Option<u8> {
    contexts
        .iter()
        .find(|(_, apn)| apn.eq_ignore_ascii_case("ims"))
        .map(|(profile_id, _)| *profile_id)
        .or_else(|| {
            (3..=16).find(|candidate| {
                !contexts
                    .iter()
                    .any(|(profile_id, _)| profile_id == candidate)
            })
        })
}

async fn prepare_ims_profile(conn: &Connection) -> Result<u8> {
    let modem_path = crate::modem_manager::find_modem_path(conn).await?;
    let contexts = crate::modem_manager::send_at_command(conn, &modem_path, "AT+CGDCONT?")
        .await
        .map_err(|error| anyhow!("failed to inspect PDP contexts: {error}"))?;
    let contexts = parse_pdp_contexts(&contexts);
    let profile_id = select_ims_profile_id(&contexts)
        .ok_or_else(|| anyhow!("no free IMS PDP profile is available"))?;

    let profile_exists = contexts
        .iter()
        .any(|(existing_id, apn)| *existing_id == profile_id && apn.eq_ignore_ascii_case("ims"));

    if !profile_exists {
        let define = format!("AT+CGDCONT={profile_id},\"IPV6\",\"ims\"");
        crate::modem_manager::send_at_command(conn, &modem_path, &define)
            .await
            .map_err(|error| anyhow!("failed to configure IMS PDP profile: {error}"))?;
    }
    let pcscf = format!("AT$QCPDPIMSCFGE={profile_id},1,1,1");
    crate::modem_manager::send_at_command(conn, &modem_path, &pcscf)
        .await
        .map_err(|error| anyhow!("failed to enable IMS P-CSCF reporting: {error}"))?;

    tracing::info!(profile_id, "IMS IPv6 PDP profile configured");
    Ok(profile_id)
}

fn ims_start_network_arg(apn: &str, profile_id: u8) -> String {
    format!("--wds-start-network=apn={apn},3gpp-profile={profile_id},ip-type=6")
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

pub async fn start_secondary_ims_bearer(
    qmi_device: &str,
    apn: &str,
    profile_id: u8,
) -> Result<(QmiPacketSession, QmiBearerSettings)> {
    if qmi_device.trim().is_empty() || apn.trim().is_empty() {
        return Err(anyhow!("QMI device and IMS APN are required"));
    }

    let start_arg = ims_start_network_arg(apn, profile_id);
    let mut keeper = Command::new("qmicli")
        .kill_on_drop(true)
        .args([
            "-d",
            qmi_device,
            "--device-open-proxy",
            "--device-open-qmi",
            "--device-open-net=net-raw-ip|net-no-qos-header",
            "--client-no-release-cid",
            &start_arg,
            "--wds-follow-network",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdout = keeper
        .stdout
        .take()
        .ok_or_else(|| anyhow!("qmicli secondary IMS bearer stdout is unavailable"))?;
    let mut lines = BufReader::new(stdout).lines();
    let handle = match tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(line) = lines.next_line().await? {
            if let Some(handle) = parse_qmi_packet_handle(&line) {
                return Ok(handle);
            }
        }
        Err(anyhow!("qmicli exited before returning a packet data handle"))
    })
    .await
    {
        Ok(Ok(handle)) => handle,
        Ok(Err(error)) => {
            let _ = keeper.kill().await;
            return Err(error);
        }
        Err(_) => {
            let _ = keeper.kill().await;
            return Err(anyhow!("timed out starting secondary IMS bearer"));
        }
    };
    tokio::spawn(async move {
        while let Ok(Some(_)) = lines.next_line().await {}
    });
    let mut session = QmiPacketSession {
        packet_handle: handle,
        keeper,
    };
    let mut last_error = None;
    for _ in 0..5 {
        match read_secondary_bearer_settings(qmi_device, &session).await {
            Ok(settings) => return Ok((session, settings)),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let _ = stop_secondary_ims_bearer(qmi_device, &mut session).await;
    Err(last_error.unwrap_or_else(|| anyhow!("secondary IMS bearer settings unavailable")))
}

pub async fn read_secondary_bearer_settings(
    qmi_device: &str,
    _session: &QmiPacketSession,
) -> Result<QmiBearerSettings> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        qmicli_with_timeout("15")
            .kill_on_drop(true)
            .args([
                "-d",
                qmi_device,
                "--device-open-proxy",
                "--device-open-qmi",
                "--device-open-net=net-raw-ip|net-no-qos-header",
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
    let security_offer = crate::ims_sip::required_sec_agree_headers(
        &ue_security.security_client_header(),
    );
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
        &security_offer,
    )?;
    channel.send(initial.as_bytes()).await?;
    let mut challenge_response = String::from_utf8(
        channel.receive(Duration::from_secs(10)).await?,
    )?;
    log_register_response_metadata("initial", &challenge_response);
    if crate::ims_sip::sip_status_code(&challenge_response) == Some(200) {
        registration.cseq = registration.cseq.saturating_add(1);
        let deregister = crate::ims_sip::build_initial_register_with_security(
            &registration,
            "z9hG4bK-simadmin-clear-binding",
            &format!("{security_offer}Expires: 0\r\n"),
        )?;
        channel.send(deregister.as_bytes()).await?;
        let deregister_response = String::from_utf8(
            channel.receive(Duration::from_secs(10)).await?,
        )?;
        log_register_response_metadata("clear_binding", &deregister_response);
        if matches!(crate::ims_sip::sip_status_code(&deregister_response), Some(401 | 407)) {
            challenge_response = deregister_response;
        } else if crate::ims_sip::sip_status_code(&deregister_response) == Some(200) {
            registration.cseq = registration.cseq.saturating_add(1);
            let retry = crate::ims_sip::build_initial_register_with_security(
                &registration,
                "z9hG4bK-simadmin-after-clear",
                &security_offer,
            )?;
            channel.send(retry.as_bytes()).await?;
            challenge_response = String::from_utf8(
                channel.receive(Duration::from_secs(10)).await?,
            )?;
            log_register_response_metadata("after_clear", &challenge_response);
        } else {
            return Err(anyhow!(
                "IMS stale-binding cleanup returned {:?}",
                crate::ims_sip::sip_status_code(&deregister_response)
            ));
        }
    }
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
        match crate::ims_uim::authenticate_via_qmi(&challenge.nonce).await? {
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
                    "{authorization}\r\n{security_offer}"
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
        security_offer,
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
    log_register_response_metadata("authenticated", &registered);
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
    if let Some(associated_uri) = crate::ims_sip::associated_uri(&registered) {
        registration.public_identity = associated_uri;
    }
    Ok(NativeImsRegistration {
        channel,
        xfrm_plan,
        sip: registration,
        security_header,
        service_routes,
        refresh_after,
    })
}

fn log_register_response_metadata(stage: &str, response: &str) {
    tracing::info!(
        stage,
        sip_status = ?crate::ims_sip::sip_status_code(response),
        aka_challenge = crate::ims_sip::has_header(response, "WWW-Authenticate")
            || crate::ims_sip::has_header(response, "Proxy-Authenticate"),
        security_server = crate::ims_sip::has_header(response, "Security-Server"),
        contact = crate::ims_sip::has_header(response, "Contact"),
        service_route = crate::ims_sip::has_header(response, "Service-Route"),
        associated_uri = crate::ims_sip::has_header(response, "P-Associated-URI"),
        expires = crate::ims_sip::has_header(response, "Expires"),
        warning = crate::ims_sip::has_header(response, "Warning"),
        sensitive_values = "redacted",
        "IMS REGISTER response metadata"
    );
}

pub async fn stop_secondary_ims_bearer(
    qmi_device: &str,
    session: &mut QmiPacketSession,
) -> Result<()> {
    if qmi_device.trim().is_empty() || session.packet_handle.trim().is_empty() {
        return Err(anyhow!("QMI device and packet handle are required"));
    }

    if session.keeper.try_wait()?.is_none() {
        session.keeper.start_kill()?;
        tokio::time::timeout(Duration::from_secs(5), session.keeper.wait())
            .await
            .map_err(|_| anyhow!("timed out stopping secondary IMS bearer"))??;
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
    // 跨轮次累计的重连/失败计数，用于前端展示 IMS 会话稳定性趋势
    let mut reconnect_count: u64 = 0;
    let mut failure_count: u64 = 0;

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
            if let Some((device, mut handle)) = active.take() {
                let _ = stop_secondary_ims_bearer(&device, &mut handle).await;
            }
            let _ = write_runtime_status(&RuntimeStatus {
                phase: "disabled".to_string(),
                transport: "native_qmi".to_string(),
                ..RuntimeStatus::default()
            });
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        // 诊断页「重新连接」：丢弃现有 IMS 承载，让本轮重新进入建立流程。
        if consume_reconnect_request() {
            if let Some(plan) = active_xfrm.take() {
                crate::ims_ipsec::uninstall_plan(&plan).await;
            }
            if let Some(network) = active_network.take() {
                cleanup_secondary_ipv6_interface(&network).await;
            }
            if let Some((device, mut handle)) = active.take() {
                let _ = stop_secondary_ims_bearer(&device, &mut handle).await;
            }
            let _ = write_runtime_status(&RuntimeStatus {
                phase: "reconnecting".to_string(),
                transport: "native_qmi".to_string(),
                ..RuntimeStatus::default()
            });
            tokio::time::sleep(Duration::from_secs(2)).await;
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
            // The secondary QMI device can appear before ModemManager has
            // finished bringing up the primary modem after a cold boot.
            // Starting an IMS bearer during that window leaves the QMI WDS
            // transaction stuck in `get-current-settings`.
            match crate::modem_manager::get_data_connection_status(&conn).await {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "waiting_for_modem".to_string(),
                        transport: "native_qmi".to_string(),
                        interface: secondary_netdev(&device),
                        last_error: "primary modem data connection is not ready".to_string(),
                        ..RuntimeStatus::default()
                    });
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
            let netdev = secondary_netdev(&device);

            let profile_id = match prepare_ims_profile(&conn).await {
                Ok(profile_id) => profile_id,
                Err(error) => {
                    tracing::warn!(error = %error, "IMS PDP profile preparation failed");
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "ims_profile_failed".to_string(),
                        transport: "native_qmi".to_string(),
                        interface: netdev.clone(),
                        last_error: error.to_string(),
                        ..RuntimeStatus::default()
                    });
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            let _ = write_runtime_status(&RuntimeStatus {
                phase: "starting_ims_bearer".to_string(),
                transport: "native_qmi".to_string(),
                interface: netdev.clone(),
                ..RuntimeStatus::default()
            });
            match start_secondary_ims_bearer(&device, "ims", profile_id).await {
                Ok((handle, settings)) => {
                    active = Some((device.clone(), handle));
                    let mut pcscf_candidates = Vec::new();
                    // 承载已建立：记录会话起点与 IMS 侧地址，后续诊断可据此
                    // 判断失败发生在「承载层」还是「注册层」。
                    let session_started_at = now_rfc3339();
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "ims_bearer_up".to_string(),
                        transport: "native_qmi".to_string(),
                        interface: netdev.clone(),
                        family: "ipv6".to_string(),
                        local_ip: settings.ipv6_address.clone(),
                        session_started_at: session_started_at.clone(),
                        ..RuntimeStatus::default()
                    });
                    let _ = write_runtime_status(&RuntimeStatus {
                        phase: "pcscf_discovering".to_string(),
                        transport: "native_qmi".to_string(),
                        ..RuntimeStatus::default()
                    });
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
                                        pcscf: pcscf_candidates
                                            .iter()
                                            .map(|c| c.to_string())
                                            .collect::<Vec<_>>()
                                            .join(", "),
                                        session_started_at: session_started_at.clone(),
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
                            family: "ipv6".to_string(),
                            local_ip: settings.ipv6_address.clone(),
                            pcscf: pcscf.to_string(),
                            session_started_at: session_started_at.clone(),
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
                                    family: "ipv6".to_string(),
                                    local_ip: settings.ipv6_address.clone(),
                                    pcscf: pcscf.to_string(),
                                    session_started_at: session_started_at.clone(),
                                    registered_at: now_rfc3339(),
                                    reconnect_count: reconnect_count,
                                    ..RuntimeStatus::default()
                                });
                                reconnect_count += 1;
                                break;
                            }
                            Err(error) => {
                                tracing::warn!(pcscf = %pcscf, error = %error, "IMS registration attempt failed");
                                failure_count += 1;
                                let _ = write_runtime_status(&RuntimeStatus {
                                    phase: "register_failed".to_string(),
                                    transport: "native_qmi_ipsec".to_string(),
                                    interface: netdev.clone(),
                                    family: "ipv6".to_string(),
                                    local_ip: settings.ipv6_address.clone(),
                                    pcscf: pcscf.to_string(),
                                    session_started_at: session_started_at.clone(),
                                    last_failure_at: now_rfc3339(),
                                    registration_degraded_reason: error.to_string(),
                                    failure_count,
                                    reconnect_count,
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
                        if let Some((active_device, mut active_handle)) = active.take() {
                            let _ = stop_secondary_ims_bearer(&active_device, &mut active_handle).await;
                        }
                        let _ = write_runtime_status(&RuntimeStatus {
                            phase: "register_failed".to_string(),
                            transport: "native_qmi".to_string(),
                            interface: netdev.clone(),
                            last_error: "all IMS P-CSCF registration attempts failed".to_string(),
                            ..RuntimeStatus::default()
                        });
                        tokio::time::sleep(Duration::from_secs(5)).await;
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
            if let Some((device, mut handle)) = active.take() {
                let _ = stop_secondary_ims_bearer(&device, &mut handle).await;
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

        let keeper_result = active
            .as_mut()
            .expect("active bearer exists")
            .1
            .keeper
            .try_wait();
        match keeper_result {
            Ok(None) => tokio::time::sleep(Duration::from_secs(30)).await,
            Err(error) => {
                tracing::warn!(error = %error, "secondary IMS bearer keeper could not be inspected; retaining registered session");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Ok(Some(status)) => {
                tracing::warn!(?status, "secondary IMS bearer keeper exited; reconnecting");
                if let Some(listener) = sms_listener.take() {
                    listener.abort();
                }
                if let Some(plan) = active_xfrm.take() {
                    crate::ims_ipsec::uninstall_plan(&plan).await;
                }
                if let Some(network) = active_network.take() {
                    cleanup_secondary_ipv6_interface(&network).await;
                }
                if let Some((device, mut handle)) = active.take() {
                    let _ = stop_secondary_ims_bearer(&device, &mut handle).await;
                }
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
    }

    #[test]
    fn selects_first_free_ims_pdp_profile() {
        let contexts = super::parse_pdp_contexts(
            "+CGDCONT: 1,\"IPV4V6\",\"ctlte\",\"0.0.0.0\"\n+CGDCONT: 2,\"IPV4V6\",\"ctwap\",\"0.0.0.0\"",
        );
        assert_eq!(contexts, vec![(1, "ctlte".to_string()), (2, "ctwap".to_string())]);
        assert_eq!(super::select_ims_profile_id(&contexts), Some(3));
    }

    #[test]
    fn reuses_existing_ims_pdp_profile() {
        let contexts = super::parse_pdp_contexts(
            "+CGDCONT: 1,\"IPV4V6\",\"ctlte\"\n+CGDCONT: 5,\"IPV6\",\"ims\"",
        );
        assert_eq!(super::select_ims_profile_id(&contexts), Some(5));
    }

    #[test]
    fn builds_beta9_profile_bound_wds_start_argument() {
        assert_eq!(
            super::ims_start_network_arg("ims", 3),
            "--wds-start-network=apn=ims,3gpp-profile=3,ip-type=6"
        );
    }

    #[test]
    fn derives_beta9_secondary_netdev() {
        assert_eq!(super::secondary_netdev("/dev/wwan0at2"), "wwan1");
    }

}
