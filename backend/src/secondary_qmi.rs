//! DATA6 secondary QMI endpoint initialization.
//!
//! beta9 prepares this endpoint before ModemManager starts.  The initializer
//! only owns the RPMSG binding and endpoint health; ordinary data remains on
//! the primary QMI path.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

pub const SECONDARY_DEVICE_STATE: &str = "/run/simadmin/secondary-qmi-device";
const RPMSG_DRIVER: &str = "rpmsg_wwan_ctrl";
const DATA6_NAME: &str = "DATA6_CNTL";

fn run_modprobe() -> Result<()> {
    let output = Command::new("modprobe")
        .arg(RPMSG_DRIVER)
        .output()
        .context("failed to execute modprobe")?;
    if !output.status.success() {
        return Err(anyhow!(
            "failed to load {RPMSG_DRIVER}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn data6_rpmsg_device() -> Result<PathBuf> {
    let root = Path::new("/sys/bus/rpmsg/devices");
    for entry in fs::read_dir(root).context("failed to inspect RPMSG devices")? {
        let path = entry?.path();
        let name = fs::read_to_string(path.join("name")).unwrap_or_default();
        if name.trim() == DATA6_NAME {
            return Ok(path);
        }
    }
    Err(anyhow!("DATA6 RPMSG device {DATA6_NAME} was not found"))
}

fn bind_data6(device: &Path) -> Result<()> {
    let override_path = device.join("driver_override");
    if !override_path.exists() {
        return Err(anyhow!("DATA6 driver_override is unavailable"));
    }
    fs::write(&override_path, RPMSG_DRIVER).context("failed to set DATA6 driver override")?;

    let bind_path = Path::new("/sys/bus/rpmsg/drivers")
        .join(RPMSG_DRIVER)
        .join("bind");
    if !bind_path.exists() {
        return Err(anyhow!("stock RPMSG driver bind node is unavailable"));
    }
    let device_name = device
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("DATA6 RPMSG device name is invalid"))?;
    let current_driver = fs::read_link(device.join("driver"))
        .ok()
        .and_then(|path| path.file_name().map(|name| name.to_owned()));
    if current_driver.as_deref() != Some(std::ffi::OsStr::new(RPMSG_DRIVER)) {
        fs::write(bind_path, device_name).context("failed to bind DATA6 RPMSG device")?;
    }
    Ok(())
}

fn configured_secondary_device() -> Option<String> {
    std::env::var("SIMADMIN_SECONDARY_QMI_DEVICE")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn qmi_device_ready(device: &str) -> bool {
    Command::new("qmicli")
        .args([
            "-d",
            device,
            "--device-open-proxy",
            "--device-open-qmi",
            "--device-open-net=net-raw-ip|net-no-qos-header",
            "--get-service-version-info",
        ])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn candidate_secondary_devices() -> Vec<String> {
    if let Some(device) = configured_secondary_device() {
        return vec![device];
    }

    let primary = std::env::var("SIMADMIN_PRIMARY_QMI_DEVICE")
        .unwrap_or_else(|_| "/dev/wwan0qmi0".to_string());
    let mut candidates = vec![
        "/dev/wwan0qmi1".to_string(),
        "/dev/wwan0at2".to_string(),
    ];
    if let Ok(entries) = fs::read_dir("/dev") {
        candidates.extend(entries.flatten().filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            name.starts_with("wwan0")
                .then(|| entry.path().to_string_lossy().into_owned())
        }));
    }
    candidates.retain(|device| device != &primary);
    candidates.sort();
    candidates.dedup();
    candidates
}

fn wait_for_secondary_device(timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    loop {
        for device in candidate_secondary_devices() {
            if Path::new(&device).exists() && qmi_device_ready(&device) {
                return Ok(device);
            }
        }

        if let Ok(device) = fs::read_to_string(SECONDARY_DEVICE_STATE) {
            let device = device.trim();
            if !device.is_empty() && Path::new(device).exists() {
                return Ok(device.to_string());
            }
        }

        if Instant::now() >= deadline {
            return Err(anyhow!("secondary QMI endpoint did not become ready"));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(unix)]
fn notify_ready() {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let socket = socket.to_string_lossy();
    let socket = if let Some(abstract_name) = socket.strip_prefix('@') {
        format!("\0{abstract_name}")
    } else {
        socket.into_owned()
    };
    if let Ok(datagram) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = datagram.send_to(b"READY=1\nSTATUS=DATA6 secondary QMI ready", socket);
    }
}

#[cfg(not(unix))]
fn notify_ready() {}

pub fn initialize_and_hold() -> Result<()> {
    run_modprobe()?;
    let device = data6_rpmsg_device()?;
    bind_data6(&device)?;
    fs::create_dir_all(Path::new(SECONDARY_DEVICE_STATE).parent().unwrap())?;
    let secondary = wait_for_secondary_device(Duration::from_secs(20))?;
    fs::write(SECONDARY_DEVICE_STATE, format!("{secondary}\n"))?;
    notify_ready();

    // Keep the systemd unit alive so ModemManager cannot reclaim the endpoint.
    loop {
        if !Path::new(&secondary).exists() {
            return Err(anyhow!("secondary QMI endpoint disappeared"));
        }
        thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(test)]
mod tests {
    use super::DATA6_NAME;

    #[test]
    fn uses_beta9_data6_name() {
        assert_eq!(DATA6_NAME, "DATA6_CNTL");
    }
}
