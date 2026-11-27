use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_DNS: usize = u16::MAX as usize;
const UPSTREAMS: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];
type Query = dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync;

pub struct Resolver {
    local: SocketAddr,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Resolver {
    pub fn start(address: SocketAddr, client: reqwest::blocking::Client) -> io::Result<Self> {
        Self::bind(address, move |query| {
            UPSTREAMS.into_iter().find_map(|url| {
                let response = client
                    .post(url)
                    .header("Content-Type", "application/dns-message")
                    .header("Accept", "application/dns-message")
                    .body(query.to_vec())
                    .send()
                    .ok()?
                    .error_for_status()
                    .ok()?;
                let mut body = Vec::new();
                response
                    .take(MAX_DNS as u64 + 1)
                    .read_to_end(&mut body)
                    .ok()?;
                (body.len() >= 12
                    && body.len() <= MAX_DNS
                    && body[..2] == query[..2]
                    && body[2] & 0x80 != 0
                    && !matches!(body[3] & 15, 2 | 5))
                .then_some(body)
            })
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.local
    }

    fn bind(
        addr: SocketAddr,
        resolve: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> io::Result<Self> {
        assert!(addr.ip().is_loopback());
        let (tcp, udp, local) = bind_pair(addr)?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        tcp.set_nonblocking(true)?;
        let mut workers = Vec::new();
        let stop = Arc::new(AtomicBool::new(false));
        let udp = Arc::new(udp);
        let resolve: Arc<Query> = Arc::new(resolve);
        for _ in 0..4 {
            let (udp, resolve, stop) = (udp.clone(), resolve.clone(), stop.clone());
            workers.push(thread::spawn(move || {
                let mut buffer = vec![0; MAX_DNS];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((len, peer)) = udp.recv_from(&mut buffer)
                        && let Some(reply) = answer(&resolve, &buffer[..len])
                    {
                        let _ = udp.send_to(&reply, peer);
                    }
                }
            }));
        }
        let shutdown = stop.clone();
        workers.push(thread::spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                if let Ok((stream, _)) = tcp.accept() {
                    let _ = handle_tcp(stream, &resolve);
                } else {
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }));
        Ok(Self {
            local,
            stop,
            workers,
        })
    }
}

fn bind_pair(addr: SocketAddr) -> io::Result<(TcpListener, UdpSocket, SocketAddr)> {
    let mut last = io::Error::new(io::ErrorKind::AddrInUse, "DNS port unavailable");
    for _ in 0..if addr.port() == 0 { 16 } else { 1 } {
        let tcp = TcpListener::bind(addr)?;
        let local = tcp.local_addr()?;
        match UdpSocket::bind(local) {
            Ok(udp) => return Ok((tcp, udp, local)),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn answer(resolve: &Arc<Query>, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 {
        return None;
    }
    resolve(query).or_else(|| {
        Some(vec![
            query[0],
            query[1],
            0x80 | (query[2] & 1),
            0x82,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
    })
}

fn handle_tcp(mut stream: TcpStream, resolve: &Arc<Query>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut size = [0; 2];
    stream.read_exact(&mut size)?;
    let mut query = vec![0; u16::from_be_bytes(size) as usize];
    stream.read_exact(&mut query)?;
    if let Some(reply) = answer(resolve, &query) {
        stream.write_all(&(reply.len() as u16).to_be_bytes())?;
        stream.write_all(&reply)?;
    }
    Ok(())
}

impl Drop for Resolver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xray_can_relay_udp_to_the_loopback_resolver() {
        use std::process::{Command, Stdio};
        let Some(xray) = std::env::var_os("ORBIT_TEST_XRAY") else {
            return;
        };
        let dns = Resolver::bind("127.0.0.1:0".parse().unwrap(), |query| {
            let mut reply = query.to_vec();
            reply[2] |= 0x80;
            reply[7] = 1;
            Some(reply)
        })
        .unwrap();
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = serde_json::json!({
            "log":{"loglevel":"none"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"tunnel",
                "settings":{"address":"172.28.240.2","port":53,"network":"udp"}}],
            "outbounds":[{"protocol":"freedom","settings":{"redirect":dns.address().to_string()}}]
        });
        let mut child = Command::new(xray)
            .args(["run", "-format", "json", "-config", "stdin:"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&config).unwrap())
            .unwrap();
        let proxy = SocketAddr::from(([127, 0, 0, 1], port));
        thread::sleep(Duration::from_millis(250));
        let result = crate::tunnel::dns_ready(proxy);
        let _ = child.kill();
        let _ = child.wait();
        assert!(result);
    }

    #[test]
    fn answers_udp_and_tcp_on_one_loopback_port() {
        let resolver = Resolver::bind("127.0.0.1:0".parse().unwrap(), |query| {
            let mut reply = query.to_vec();
            reply[2] |= 0x80;
            reply[7] = 1;
            Some(reply)
        })
        .unwrap();
        let address = resolver.address();
        let query = [0x4f, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut answer = [0; 12];
        let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        udp.connect(address).unwrap();
        udp.send(&query).unwrap();
        assert_eq!(udp.recv(&mut answer).unwrap(), 12);
        assert_eq!(answer[7], 1);
        let mut tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        tcp.write_all(&[0, 12]).unwrap();
        tcp.write_all(&query).unwrap();
        let mut length = [0; 2];
        tcp.read_exact(&mut length).unwrap();
        assert_eq!(length, [0, 12]);
        tcp.read_exact(&mut answer).unwrap();
        assert_eq!(answer[7], 1);
    }
}
