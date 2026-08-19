//! Long-lived SIP UDP channel for the dedicated IMS bearer.

use anyhow::{anyhow, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::ffi::CString;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;

const MAX_SIP_DATAGRAM: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SipRoute {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

pub struct ImsSipChannel {
    send_socket: Option<UdpSocket>,
    receive_socket: Option<UdpSocket>,
    reserved_receive_socket: Option<Socket>,
    route: SipRoute,
    interface: Option<String>,
    security_verify: Option<String>,
}

impl ImsSipChannel {
    pub fn bind(route: SipRoute, interface: Option<&str>) -> Result<Self> {
        let socket = build_socket(route.local, route.remote, interface)?;
        let route = SipRoute {
            local: socket.local_addr()?,
            remote: route.remote,
        };
        Ok(Self {
            send_socket: Some(socket),
            receive_socket: None,
            reserved_receive_socket: None,
            route,
            interface: interface.map(str::to_string),
            security_verify: None,
        })
    }

    pub fn reserve_security_receive_port(&mut self) -> Result<u16> {
        if let Some(socket) = self.reserved_receive_socket.as_ref() {
            return socket_port(socket);
        }
        let socket = build_bound_socket(
            SocketAddr::new(self.route.local.ip(), 0),
            self.interface.as_deref(),
        )?;
        let port = socket_port(&socket)?;
        self.reserved_receive_socket = Some(socket);
        Ok(port)
    }

    pub fn activate_security(
        &mut self,
        send_route: SipRoute,
        receive_local: SocketAddr,
        receive_remote: SocketAddr,
        security_verify: String,
    ) -> Result<()> {
        let reserved = self
            .reserved_receive_socket
            .take()
            .ok_or_else(|| anyhow!("IMS security receive port was not reserved"))?;
        if socket_addr(&reserved)? != receive_local {
            return Err(anyhow!("IMS security receive port changed"));
        }
        let receive_socket = connect_bound_socket(reserved, receive_remote)?;
        self.send_socket.take();
        let send_socket = build_socket(
            send_route.local,
            send_route.remote,
            self.interface.as_deref(),
        )?;
        self.route = SipRoute {
            local: send_socket.local_addr()?,
            remote: send_route.remote,
        };
        self.send_socket = Some(send_socket);
        self.receive_socket = Some(receive_socket);
        self.security_verify = Some(security_verify);
        Ok(())
    }

    pub fn route(&self) -> SipRoute {
        self.route
    }

    pub fn security_verify(&self) -> Option<&str> {
        self.security_verify.as_deref()
    }

    pub async fn send(&self, frame: &[u8]) -> Result<()> {
        let written = self
            .send_socket
            .as_ref()
            .ok_or_else(|| anyhow!("IMS send socket is unavailable"))?
            .send(frame)
            .await?;
        if written != frame.len() {
            return Err(anyhow!("IMS SIP datagram was only partially sent"));
        }
        Ok(())
    }

    pub async fn receive(&self, wait: Duration) -> Result<Vec<u8>> {
        let socket = self
            .receive_socket
            .as_ref()
            .or(self.send_socket.as_ref())
            .ok_or_else(|| anyhow!("IMS receive socket is unavailable"))?;
        let mut frame = vec![0u8; MAX_SIP_DATAGRAM];
        let length = tokio::time::timeout(wait, socket.recv(&mut frame))
            .await
            .map_err(|_| anyhow!("timed out waiting for IMS SIP datagram"))??;
        frame.truncate(length);
        Ok(frame)
    }
}

fn build_socket(
    local: SocketAddr,
    remote: SocketAddr,
    interface: Option<&str>,
) -> std::io::Result<UdpSocket> {
    if local.is_ipv4() != remote.is_ipv4() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "IMS address families differ",
        ));
    }
    let socket = build_bound_socket(local, interface)?;
    connect_bound_socket(socket, remote)
}

fn build_bound_socket(local: SocketAddr, interface: Option<&str>) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    bind_to_interface(&socket, interface)?;
    socket.bind(&local.into())?;
    Ok(socket)
}

fn connect_bound_socket(socket: Socket, remote: SocketAddr) -> std::io::Result<UdpSocket> {
    socket.connect(&remote.into())?;
    socket.set_nonblocking(true)?;
    let socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

fn socket_addr(socket: &Socket) -> std::io::Result<SocketAddr> {
    socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| std::io::Error::other("socket has no internet address"))
}

fn socket_port(socket: &Socket) -> Result<u16> {
    Ok(socket_addr(socket)?.port())
}

fn bind_to_interface(socket: &Socket, interface: Option<&str>) -> std::io::Result<()> {
    let Some(interface) = interface else {
        return Ok(());
    };
    let interface = CString::new(interface).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface contains NUL")
    })?;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            interface.as_ptr().cast(),
            interface.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keeps_initial_socket_for_request_and_response() {
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let route = SipRoute {
            local: "[::1]:0".parse().unwrap(),
            remote: server.local_addr().unwrap(),
        };
        let channel = ImsSipChannel::bind(route, None).unwrap();
        channel.send(b"REGISTER").await.unwrap();
        let mut request = [0u8; 32];
        let (length, peer) = server.recv_from(&mut request).await.unwrap();
        assert_eq!(&request[..length], b"REGISTER");
        server.send_to(b"SIP/2.0 401", peer).await.unwrap();
        assert_eq!(
            channel.receive(Duration::from_secs(1)).await.unwrap(),
            b"SIP/2.0 401"
        );
    }

    #[tokio::test]
    async fn reserves_a_distinct_security_receive_port() {
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let route = SipRoute {
            local: "[::1]:0".parse().unwrap(),
            remote: server.local_addr().unwrap(),
        };
        let mut channel = ImsSipChannel::bind(route, None).unwrap();
        let receive_port = channel.reserve_security_receive_port().unwrap();
        assert_ne!(receive_port, channel.route().local.port());
    }
}
