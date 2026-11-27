use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Method {
    #[default]
    Https,
    Tcp,
    Icmp,
}

pub fn endpoint(host: &str, port: u16, method: Method, cancel: &AtomicBool) -> Option<u32> {
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    let addresses = (host, port).to_socket_addrs().ok()?;
    let deadline = Instant::now() + Duration::from_secs(4);
    for address in addresses.take(4) {
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(1400));
        if timeout.is_zero() || cancel.load(Ordering::Relaxed) {
            break;
        }
        let result = match method {
            Method::Tcp => {
                let start = Instant::now();
                TcpStream::connect_timeout(&address, timeout)
                    .ok()
                    .map(|_| start.elapsed().as_millis().max(1) as u32)
            }
            Method::Icmp => echo(address, timeout),
            Method::Https => None,
        };
        if result.is_some() {
            return result;
        }
    }
    None
}

#[cfg(windows)]
fn echo(address: SocketAddr, timeout: Duration) -> Option<u32> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::{HANDLE, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{
            ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_SUCCESS, Icmp6CreateFile, Icmp6SendEcho2,
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
        },
        Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0},
    };
    struct Echo(HANDLE);
    impl Drop for Echo {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }
    let timeout = timeout.as_millis().max(1) as u32;
    let data = b"Orbit";
    let mut reply = [0usize; 64];
    let size = std::mem::size_of_val(&reply) as u32;
    let buffer = reply.as_mut_ptr().cast();
    match address {
        SocketAddr::V4(address) => {
            let handle = unsafe { IcmpCreateFile() };
            if handle == INVALID_HANDLE_VALUE {
                return None;
            }
            let echo = Echo(handle);
            let replies = unsafe {
                IcmpSendEcho(
                    echo.0,
                    u32::from_ne_bytes(address.ip().octets()),
                    data.as_ptr().cast(),
                    data.len() as u16,
                    null(),
                    buffer,
                    size,
                    timeout,
                )
            };
            if replies == 0 {
                return None;
            }
            let result = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
            (result.Status == IP_SUCCESS).then_some(result.RoundTripTime.max(1))
        }
        SocketAddr::V6(address) => {
            let handle = unsafe { Icmp6CreateFile() };
            if handle == INVALID_HANDLE_VALUE {
                return None;
            }
            let echo = Echo(handle);
            let local = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            let remote = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: address.ip().octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: address.scope_id(),
                },
                ..Default::default()
            };
            let replies = unsafe {
                Icmp6SendEcho2(
                    echo.0,
                    null_mut(),
                    None,
                    null(),
                    &local,
                    &remote,
                    data.as_ptr().cast(),
                    data.len() as u16,
                    null(),
                    buffer,
                    size,
                    timeout,
                )
            };
            if replies == 0 {
                return None;
            }
            let result = unsafe { &*reply.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>() };
            (result.Status == IP_SUCCESS).then_some(result.RoundTripTime.max(1))
        }
    }
}
#[cfg(not(windows))]
fn echo(_: SocketAddr, _: Duration) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_uses_node_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(
            endpoint(
                "127.0.0.1",
                listener.local_addr().unwrap().port(),
                Method::Tcp,
                &AtomicBool::new(false)
            )
            .is_some()
        );
    }
    #[cfg(windows)]
    #[test]
    fn icmp_replies_on_ipv4_and_on_hosts_with_ipv6_echo() {
        let timeout = Duration::from_secs(1);
        assert!(echo("127.0.0.1:0".parse().unwrap(), timeout).is_some());
        let ipv6_available = std::process::Command::new("ping.exe")
            .args(["-6", "-n", "1", "-w", "500", "::1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if ipv6_available {
            assert!(echo("[::1]:0".parse().unwrap(), timeout).is_some());
        }
    }
}
