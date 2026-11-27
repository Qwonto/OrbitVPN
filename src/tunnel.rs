use std::{
    net::{Ipv4Addr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

pub const NAME: &str = "Orbit VPN";
pub const DNS_ADDRESS: Ipv4Addr = Ipv4Addr::new(172, 28, 240, 2);
const ROUTE_TARGETS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)];

#[cfg(windows)]
fn route(address: Ipv4Addr) -> Option<(String, bool)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetBestInterface, GetIfEntry2, IF_TYPE_PPP, IF_TYPE_TUNNEL, MIB_IF_ROW2,
    };
    let mut index = 0;
    if unsafe { GetBestInterface(u32::from_ne_bytes(address.octets()), &mut index) } != 0 {
        return None;
    }
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    if unsafe { GetIfEntry2(&mut row) } != 0 {
        return None;
    }
    let name = |field: &[u16]| {
        String::from_utf16_lossy(
            &field[..field.iter().position(|&ch| ch == 0).unwrap_or(field.len())],
        )
    };
    let alias = name(&row.Alias);
    let description = name(&row.Description);
    let known_tunnel =
        looks_like_tunnel(&alias, &description) || matches!(row.Type, IF_TYPE_TUNNEL | IF_TYPE_PPP);
    Some((alias, known_tunnel))
}

#[cfg(not(windows))]
fn route(_: Ipv4Addr) -> Option<(String, bool)> {
    None
}

fn looks_like_tunnel(alias: &str, description: &str) -> bool {
    let names = format!("{alias} {description}").to_ascii_lowercase();
    [
        "happ-xray",
        "happ tunnel",
        "wintun",
        "wireguard",
        "openvpn",
        "tap-windows",
        "tailscale",
        "orbit vpn",
    ]
    .iter()
    .any(|value| names.contains(value))
}

pub fn competing_route(own_session: bool) -> Option<String> {
    ROUTE_TARGETS
        .into_iter()
        .filter_map(route)
        .find_map(|(alias, tunnel)| {
            (tunnel && !(own_session && alias.eq_ignore_ascii_case(NAME))).then_some(alias)
        })
}

pub fn system_routes_ready() -> bool {
    ROUTE_TARGETS
        .into_iter()
        .all(|address| route(address).is_some_and(|(alias, _)| alias.eq_ignore_ascii_case(NAME)))
}

pub fn bootstrap(host: &str, port: u16) -> Result<Vec<String>, String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(Vec::new());
    }
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|_| "Windows не смогла разрешить имя VPN-сервера до запуска туннеля.")?;
    let mut ips: Vec<_> = resolved.map(|addr| addr.ip()).collect();
    ips.sort_by_key(|ip| (ip.is_ipv6(), *ip));
    ips.dedup();
    if ips.is_empty() {
        return Err("VPN-сервер не вернул IP-адрес. Туннель не включён.".into());
    }
    Ok(ips.into_iter().map(|ip| ip.to_string()).collect())
}

fn dns_response_ok(bytes: &[u8]) -> bool {
    bytes.len() >= 12
        && bytes[..2] == [0x4f, 0x42]
        && bytes[2] & 0x82 == 0x80
        && bytes[3] & 0xf == 0
        && u16::from_be_bytes([bytes[6], bytes[7]]) > 0
}

pub fn dns_ready(address: std::net::SocketAddr) -> bool {
    // Ask the local resolver directly, independently of the Windows DNS cache.
    let query =
        b"\x4f\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let check = || -> std::io::Result<bool> {
        let socket = UdpSocket::bind(("0.0.0.0", 0))?;
        socket.set_read_timeout(Some(Duration::from_secs(9)))?;
        socket.connect(address)?;
        socket.send(query)?;
        let mut answer = [0_u8; 512];
        let size = socket.recv(&mut answer)?;
        Ok(dns_response_ok(&answer[..size]))
    };
    check().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_happ_and_other_virtual_vpns() {
        assert!(looks_like_tunnel("happ-xray", "Happ Tunnel"));
        assert!(looks_like_tunnel("VPN", "WireGuard Tunnel"));
        assert!(!looks_like_tunnel(
            "Ethernet",
            "Realtek PCIe GbE Family Controller"
        ));
    }

    #[test]
    fn requires_a_successful_dns_reply_with_answers() {
        let mut answer = [0x4f, 0x42, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        assert!(dns_response_ok(&answer));
        answer[3] |= 3;
        assert!(!dns_response_ok(&answer));
        answer[3] = 0x80;
        answer[7] = 0;
        assert!(!dns_response_ok(&answer));
    }
}
