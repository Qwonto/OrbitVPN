use crate::dns::Resolver;
use crate::probe::{self, Method};
use crate::subscription::{self, Country, Node, Subscription};
use crate::tunnel;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    Proxy,
    #[default]
    Tunnel,
}

pub enum Message {
    Import(String),
    Connect(Box<Node>, Mode),
    Refresh(String),
    RefreshPolicy(Option<RefreshPolicy>),
    Measure(Vec<(usize, Node)>, Option<Mode>, Method, Arc<AtomicBool>),
    Disconnect,
    Exit,
}

pub struct Connection {
    pub node: Node,
    pub port: u16,
    pub verified: bool,
    pub mode: Mode,
}

pub enum Event {
    Imported(Result<Subscription, String>),
    Refreshed {
        source: String,
        result: Result<Subscription, String>,
        manual: bool,
    },
    FailoverStarted(usize, Arc<AtomicBool>),
    Connected(Result<Connection, String>),
    Disconnected,
    Interrupted,
    Latency(usize, String, Option<u32>),
    Measured(Result<bool, String>),
    AutoConnecting,
}

struct Running {
    child: Child,
    mode: Mode,
    diagnostics: Option<XrayOutput>,
    resolver: Option<Resolver>,
    endpoint: Option<(String, u16)>,
}

#[derive(Clone, Copy)]
enum XrayFailure {
    Permission,
    Driver,
    WindowsDns,
    WindowsRoutes,
    Tls,
    Server,
}

impl XrayFailure {
    fn message(self) -> &'static str {
        match self {
            Self::Permission => {
                "Windows отказала Xray в доступе при создании туннеля или настройке DNS."
            }
            Self::Driver => "Xray не смог открыть драйвер Wintun. Туннель Windows не запущен.",
            Self::WindowsDns => "Xray не смог назначить DNS адаптеру Windows. Туннель отключён.",
            Self::WindowsRoutes => "Xray не смог добавить маршрут Windows. Туннель отключён.",
            Self::Tls => "Xray не смог пройти проверку TLS у выбранного сервера.",
            Self::Server => "Xray не смог подключиться к выбранному серверу.",
        }
    }
}

fn classify_xray_line(line: &str) -> Option<XrayFailure> {
    let line = line.to_ascii_lowercase();
    if line.contains("access is denied")
        || line.contains("access denied")
        || line.contains("error 5 (")
        || line.contains("отказано в доступе")
    {
        return Some(XrayFailure::Permission);
    }
    if line.contains("wintun")
        && ["unable", "failed", "error", "not found"]
            .iter()
            .any(|word| line.contains(word))
    {
        return Some(XrayFailure::Driver);
    }
    if line.contains("set dns") && (line.contains("unable") || line.contains("failed")) {
        return Some(XrayFailure::WindowsDns);
    }
    if line.contains("route") && (line.contains("unable to add") || line.contains("failed to add"))
    {
        return Some(XrayFailure::WindowsRoutes);
    }
    if line.contains("certificate") || line.contains("tls handshake") {
        return Some(XrayFailure::Tls);
    }
    if line.contains("failed to dial") || line.contains("connection refused") {
        return Some(XrayFailure::Server);
    }
    None
}

struct XrayOutput {
    latest: Arc<Mutex<Option<XrayFailure>>>,
    readers: Vec<thread::JoinHandle<()>>,
}

impl XrayOutput {
    fn read(child: &mut Child) -> Self {
        let latest = Arc::new(Mutex::new(None));
        let stream = |output: Box<dyn Read + Send>| {
            let latest = latest.clone();
            thread::spawn(move || {
                for line in BufReader::new(output).lines().map_while(Result::ok) {
                    if let Some(category) = classify_xray_line(&line)
                        && let Ok(mut last) = latest.lock()
                    {
                        *last = Some(category);
                    }
                }
            })
        };
        let mut readers = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            readers.push(stream(Box::new(stdout)));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(stream(Box::new(stderr)));
        }
        Self { latest, readers }
    }
}

impl Running {
    fn failure(&mut self, fallback: &str) -> String {
        let Some(output) = self.diagnostics.as_mut() else {
            return fallback.into();
        };
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            for reader in output.readers.drain(..) {
                let _ = reader.join();
            }
        }
        output
            .latest
            .lock()
            .ok()
            .and_then(|last| *last)
            .map_or_else(|| fallback.into(), |failure| failure.message().into())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        #[cfg(windows)]
        if self.mode == Mode::Tunnel {
            use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
            // Xray needs a console signal to remove its TUN routes before exit.
            if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, self.child.id()) } != 0 {
                let deadline = Instant::now() + Duration::from_secs(4);
                while Instant::now() < deadline {
                    if matches!(self.child.try_wait(), Ok(Some(_))) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(40));
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn xray_command(path: &Path, mode: Mode, test: bool) -> Command {
    let mut command = Command::new(path);
    command
        .args(["run", "-format", "json", "-config", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if mode == Mode::Tunnel || test {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    if let Some(parent) = path.parent() {
        command.current_dir(parent);
    }
    if test {
        command.arg("-test");
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            System::Console::{AllocConsole, GetConsoleWindow},
            UI::WindowsAndMessaging::{SW_HIDE, ShowWindow},
        };
        if mode == Mode::Tunnel && !test {
            if unsafe { GetConsoleWindow() }.is_null() {
                unsafe {
                    AllocConsole();
                    let window = GetConsoleWindow();
                    if !window.is_null() {
                        ShowWindow(window, SW_HIDE);
                    }
                }
            }
            command.creation_flags(0x0000_0200);
        } else {
            command.creation_flags(0x0800_0000);
        }
    }
    command
}

pub fn settings(node: &Node, port: u16, mode: Mode) -> Result<Value, String> {
    let mut config = json!({
        "log":{"loglevel":"none"},
        "inbounds":[{"listen":"127.0.0.1", "port":port, "protocol":"http", "tag":"local-http"}],
        "outbounds":[node.outbound()?]
    });
    if mode == Mode::Tunnel {
        config["log"]["loglevel"] = json!("warning");
        config["inbounds"].as_array_mut().unwrap().push(json!({
            "protocol":"tun", "tag":"orbit-tun", "settings":{
                "name":tunnel::NAME, "desc":tunnel::NAME,
                "gateway":["172.28.240.1/30", "fd72:2f72:6269::1/64"],
                "dns":[tunnel::DNS_ADDRESS.to_string()],
                "autoSystemRoutingTable":["0.0.0.0/0","::/0"],
                "autoOutboundsInterface":"auto",
                "autoSystemWfpBlockLeak":["dns"]
            }
        }));
        config["outbounds"].as_array_mut().unwrap().push(json!({
            "protocol": "freedom", "tag": "orbit-local-dns",
            "settings": {"redirect": "127.0.0.1:53053"}
        }));
        config["routing"] = json!({"rules": [
            {"type": "field", "inboundTag": ["orbit-tun"], "network": "tcp,udp",
             "port": "53", "ip": [tunnel::DNS_ADDRESS.to_string()], "outboundTag": "orbit-local-dns"}
        ]});
    }
    Ok(config)
}

fn launch(path: &Path, config: &[u8], mode: Mode, test: bool) -> Result<Running, String> {
    let mut child = xray_command(path, mode, test)
        .spawn()
        .map_err(|_| "Не удалось запустить Xray.")?;
    let diagnostics = (mode == Mode::Tunnel || test).then(|| XrayOutput::read(&mut child));
    let mut process = Running {
        child,
        mode: if test { Mode::Proxy } else { mode },
        diagnostics,
        resolver: None,
        endpoint: None,
    };
    process
        .child
        .stdin
        .take()
        .ok_or("Не удалось передать конфигурацию Xray.")?
        .write_all(config)
        .map_err(|_| "Xray не принял конфигурацию.")?;
    Ok(process)
}

const TEST_URL: &str = "https://connectivitycheck.gstatic.com/generate_204";
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

fn proxy_client(port: u16) -> Option<reqwest::blocking::Client> {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).ok()?;
    reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .http1_only()
        .pool_idle_timeout(Duration::from_secs(20))
        .tcp_keepalive(Duration::from_secs(20))
        .build()
        .ok()
}

fn request_latency(client: &reqwest::blocking::Client, url: &str) -> Option<u32> {
    let instant = Instant::now();
    let answer = client
        .get(url)
        .header(reqwest::header::CONNECTION, "keep-alive")
        .send()
        .ok()?;
    if answer.status() != 204 {
        return None;
    }
    answer.bytes().ok()?;
    Some(instant.elapsed().as_millis().max(1) as u32)
}

fn warm_latency(
    client: &reqwest::blocking::Client,
    url: &str,
    cancelled: &AtomicBool,
) -> Option<u32> {
    request_latency(client, url)?;
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    request_latency(client, url)
}

fn via_proxy<T>(
    path: &Path,
    node: &Node,
    cancelled: &AtomicBool,
    probe: impl FnOnce(&reqwest::blocking::Client) -> Option<T>,
) -> Option<T> {
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    let socket = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let address = socket.local_addr().ok()?;
    let config = serde_json::to_vec(&settings(node, address.port(), Mode::Proxy).ok()?).ok()?;
    drop(socket);
    let mut running = launch(path, &config, Mode::Proxy, false).ok()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !cancelled.load(Ordering::Relaxed) && Instant::now() < deadline {
        if !matches!(running.child.try_wait(), Ok(None)) {
            break;
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(90)).is_ok() {
            return probe(&proxy_client(address.port())?);
        }
        thread::sleep(Duration::from_millis(25));
    }
    None
}

fn measure_node(path: &Path, node: &Node, url: &str, cancelled: &AtomicBool) -> Option<u32> {
    via_proxy(path, node, cancelled, |client| {
        warm_latency(client, url, cancelled)
    })
}

fn web_reachable(client: &reqwest::blocking::Client) -> bool {
    request_latency(client, TEST_URL).is_some()
        || client
            .get("https://www.cloudflare.com/cdn-cgi/trace")
            .send()
            .is_ok_and(|response| response.status() == 200)
}

fn server_reachable(path: &Path, node: &Node) -> bool {
    via_proxy(path, node, &AtomicBool::new(false), |client| {
        web_reachable(client).then_some(())
    })
    .is_some()
}

fn measure(
    path: &Path,
    nodes: &[(usize, Node)],
    method: Method,
    cancelled: &AtomicBool,
    publish: impl Fn(Event),
) -> Vec<usize> {
    const PARALLEL: usize = 8;
    let next = std::sync::atomic::AtomicUsize::new(0);
    let (send, results) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..nodes.len().min(PARALLEL) {
            let send = send.clone();
            let next = &next;
            scope.spawn(move || {
                while !cancelled.load(Ordering::Relaxed) {
                    let Some((index, node)) = nodes.get(next.fetch_add(1, Ordering::Relaxed))
                    else {
                        break;
                    };
                    let elapsed = match method {
                        Method::Https => measure_node(path, node, TEST_URL, cancelled),
                        Method::Tcp | Method::Icmp => {
                            probe::endpoint(&node.host, node.port, method, cancelled)
                        }
                    };
                    if !cancelled.load(Ordering::Relaxed) {
                        let _ = send.send((*index, node.id(), elapsed));
                    }
                }
            });
        }
        drop(send);
        let mut ranks = Vec::new();
        for (index, id, elapsed) in results {
            publish(Event::Latency(index, id, elapsed));
            if let Some(ms) = elapsed {
                ranks.push((ms, index));
            }
        }
        ranks.sort_unstable();
        ranks.into_iter().map(|(_, index)| index).collect()
    })
}

struct ConnectError {
    message: String,
    retry: bool,
}
impl From<String> for ConnectError {
    fn from(message: String) -> Self {
        Self {
            message,
            retry: false,
        }
    }
}
impl From<&str> for ConnectError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl ConnectError {
    fn server(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retry: true,
        }
    }
}

fn start(
    path: &Path,
    current: &mut Option<Running>,
    node: &Node,
    mode: Mode,
) -> Result<Connection, ConnectError> {
    if !path.is_file() {
        return Err("Xray не найден. Запустите установщик Orbit VPN повторно.".into());
    }
    if mode == Mode::Tunnel {
        if !is_admin() {
            return Err("Для туннеля Windows запустите Orbit VPN от имени администратора.".into());
        }
        let own_session = current
            .as_ref()
            .is_some_and(|process| process.mode == Mode::Tunnel);
        if let Some(route) = tunnel::competing_route(own_session) {
            return Err(format!(
                "Интернет сейчас идёт через «{route}». Отключите этот VPN и повторите подключение."
            )
            .into());
        }
    }
    let socket = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Локальный порт недоступен.")?;
    let addr = socket
        .local_addr()
        .map_err(|_| "Локальный порт недоступен.")?;
    let mut settings = settings(node, addr.port(), mode)?;
    let config = serde_json::to_vec(&settings).map_err(|_| "Ошибка конфигурации.")?;
    let mut test = launch(path, &config, mode, true)?;
    if !test.child.wait().is_ok_and(|status| status.success()) {
        return Err(ConnectError::server(
            test.failure("Xray отклонил настройки сервера."),
        ));
    }
    drop(test);
    drop(current.take());
    let resolver = if mode == Mode::Tunnel {
        let addresses = tunnel::bootstrap(&node.host, node.port).map_err(ConnectError::server)?;
        if !server_reachable(path, node) {
            return Err(ConnectError::server(
                "Сервер не передаёт HTTPS ещё до запуска TUN. Маршруты Windows не изменены.",
            ));
        }
        if !addresses.is_empty() {
            settings["dns"] = json!({"hosts": {(&node.host): addresses}});
            settings["outbounds"][0]["streamSettings"]["sockopt"] =
                json!({"domainStrategy": "ForceIPv4v6"});
        }
        let client = proxy_client(addr.port()).ok_or("Не удалось настроить DNS через Xray.")?;
        let resolver = Resolver::start("127.0.0.1:0".parse().unwrap(), client)
            .map_err(|_| "Не удалось запустить локальный DNS. Туннель Windows не включён.")?;
        settings["outbounds"][1]["settings"]["redirect"] = json!(resolver.address().to_string());
        Some(resolver)
    } else {
        None
    };
    let config = if resolver.is_some() {
        serde_json::to_vec(&settings).map_err(|_| "Ошибка конфигурации DNS туннеля.")?
    } else {
        config
    };
    drop(socket);
    let mut process = launch(path, &config, mode, false)?;
    process.resolver = resolver;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if !matches!(process.child.try_wait(), Ok(None)) {
            return Err(process
                .failure("Xray завершился при запуске. Проверьте Wintun и права для режима VPN.")
                .into());
        }
        if mode == Mode::Tunnel && tunnel::system_routes_ready() {
            if let Err(error) = verify_tunnel(process.resolver.as_ref().unwrap().address()) {
                return Err(
                    if error.starts_with("Локальный DNS") || error.starts_with("Интернет")
                    {
                        ConnectError::server(process.failure(&error))
                    } else {
                        process.failure(&error).into()
                    },
                );
            }
            if !matches!(process.child.try_wait(), Ok(None)) {
                return Err("Xray завершился во время проверки туннеля.".into());
            }
            process.endpoint = Some((node.id(), addr.port()));
            *current = Some(process);
            return Ok(Connection {
                node: node.clone(),
                port: addr.port(),
                verified: true,
                mode,
            });
        }
        if mode == Mode::Proxy
            && TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok()
        {
            let verified = proxy_client(addr.port())
                .and_then(|client| request_latency(&client, TEST_URL))
                .is_some();
            if !matches!(process.child.try_wait(), Ok(None)) {
                return Err("Xray завершился во время проверки подключения.".into());
            }
            process.endpoint = Some((node.id(), addr.port()));
            *current = Some(process);
            return Ok(Connection {
                node: node.clone(),
                port: addr.port(),
                verified,
                mode,
            });
        }
        thread::sleep(Duration::from_millis(45));
    }
    if mode == Mode::Tunnel {
        Err(process
            .failure("Windows не направила интернет через Orbit VPN. Туннель отключён.")
            .into())
    } else {
        Err("Xray не открыл локальный порт вовремя.".into())
    }
}

fn verify_tunnel(dns_address: std::net::SocketAddr) -> Result<(), String> {
    if !tunnel::dns_ready(dns_address) {
        return Err("Локальный DNS не получил ответ по HTTPS через Xray. Туннель отключён.".into());
    }
    if !tunnel::dns_ready((tunnel::DNS_ADDRESS, 53).into()) {
        return Err("Xray TUN не доставил DNS-запрос до работающего локального резолвера. Туннель отключён.".into());
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .build()
        .map_err(|_| "Не удалось проверить интернет через туннель.")?;
    let online = web_reachable(&client);
    if !online {
        return Err("Интернет не отвечает через выбранный сервер. Туннель отключён.".into());
    }
    Ok(())
}

pub struct RefreshPolicy {
    pub source: String,
    pub interval: Duration,
    pub next: Instant,
}

fn retry_servers(
    runtime: &Path,
    current: &mut Option<Running>,
    servers: &[Node],
    failed: &str,
    mode: Mode,
    cancelled: &Arc<AtomicBool>,
    publish: impl Fn(Event),
) -> Result<Connection, String> {
    drop(current.take());
    if cancelled.load(Ordering::Relaxed) {
        return Err("Переподключение остановлено.".into());
    }
    let candidates: Vec<_> = servers
        .iter()
        .enumerate()
        .filter(|(_, node)| node.id() != failed)
        .map(|(index, node)| (index, node.clone()))
        .collect();
    if candidates.is_empty() {
        return Err("Соединение потеряно. В подписке нет другого сервера.".into());
    }
    if mode == Mode::Tunnel
        && let Some(route) = tunnel::competing_route(false)
    {
        return Err(format!(
            "Переподключение остановлено: основной маршрут занят адаптером «{route}»."
        ));
    }
    publish(Event::FailoverStarted(candidates.len(), cancelled.clone()));
    let ranked = measure(runtime, &candidates, Method::Https, cancelled, &publish);
    try_ranked(runtime, current, &candidates, ranked, mode, cancelled)
}

fn try_ranked(
    runtime: &Path,
    current: &mut Option<Running>,
    candidates: &[(usize, Node)],
    ranked: Vec<usize>,
    mode: Mode,
    cancelled: &AtomicBool,
) -> Result<Connection, String> {
    select_candidate(ranked, cancelled, |index| {
        let Some((_, node)) = candidates.iter().find(|(id, _)| *id == index) else {
            return Ok(None);
        };
        match start(runtime, current, node, mode) {
            Ok(connection) if connection.verified && !cancelled.load(Ordering::Relaxed) => {
                Ok(Some(connection))
            }
            Ok(_) => {
                drop(current.take());
                Ok(None)
            }
            Err(error) => Err(error),
        }
    })
}

fn select_candidate<T>(
    ranked: Vec<usize>,
    cancelled: &AtomicBool,
    mut connect: impl FnMut(usize) -> Result<Option<T>, ConnectError>,
) -> Result<T, String> {
    let mut last = None;
    for index in ranked {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        match connect(index) {
            Ok(Some(connection)) => return Ok(connection),
            Ok(None) => {}
            Err(error) if error.retry => {
                last = Some(error.message);
            }
            Err(error) => return Err(error.message),
        }
    }
    if cancelled.load(Ordering::Relaxed) {
        Err("Переподключение остановлено.".into())
    } else {
        Err(last.unwrap_or_else(|| "Ни один запасной сервер не ответил по HTTPS.".into()))
    }
}

fn refresh(
    source: String,
    countries: &[Country],
    manual: bool,
    policy: &mut Option<RefreshPolicy>,
    servers: &mut Vec<Node>,
) -> Event {
    let result = subscription::import(&source, countries);
    if let Ok(subscription) = &result {
        servers.clone_from(&subscription.nodes);
    }
    if let Some(policy) = policy.as_mut().filter(|policy| policy.source == source) {
        let delay = if result.is_ok() {
            policy.interval
        } else {
            policy.interval.min(Duration::from_secs(900))
        };
        policy.next = Instant::now() + delay;
    }
    Event::Refreshed {
        source,
        result,
        manual,
    }
}

pub fn spawn(
    countries: Arc<Vec<Country>>,
    runtime: PathBuf,
    ctx: eframe::egui::Context,
    mut servers: Vec<Node>,
    mut policy: Option<RefreshPolicy>,
    failover_cancel: Arc<AtomicBool>,
) -> (
    mpsc::Sender<Message>,
    mpsc::Receiver<Event>,
    thread::JoinHandle<()>,
) {
    const HEALTH_INTERVAL: Duration = Duration::from_secs(20);
    let (send, messages) = mpsc::channel();
    let (events, receive) = mpsc::channel();
    let worker = thread::spawn(move || {
        let notify = |event| {
            let _ = events.send(event);
            ctx.request_repaint();
        };
        let mut current = None::<Running>;
        let mut active_source = policy.as_ref().map(|value| value.source.clone());
        let mut health_at = Instant::now() + HEALTH_INTERVAL;
        let mut misses = 0;
        loop {
            let event = match messages.recv_timeout(Duration::from_millis(450)) {
                Ok(Message::RefreshPolicy(new_policy)) => {
                    policy = new_policy;
                    continue;
                }
                Ok(Message::Import(source)) => {
                    let result = subscription::import(&source, &countries);
                    if let Ok(subscription) = &result {
                        servers.clone_from(&subscription.nodes);
                        active_source = Some(source.trim().to_owned());
                        if policy
                            .as_ref()
                            .is_some_and(|old| old.source != source.trim())
                        {
                            policy = None;
                        }
                    }
                    Event::Imported(result)
                }
                Ok(Message::Refresh(source)) => {
                    if active_source.as_ref().is_some_and(|old| old != &source) {
                        Event::Refreshed {
                            source,
                            result: Err("Подписка изменилась. Повторите обновление.".into()),
                            manual: true,
                        }
                    } else {
                        active_source = Some(source.clone());
                        refresh(source, &countries, true, &mut policy, &mut servers)
                    }
                }
                Ok(Message::Connect(node, mode)) => {
                    let outcome = match start(&runtime, &mut current, &node, mode) {
                        Err(error) if error.retry && current.is_none() && servers.len() > 1 => {
                            retry_servers(
                                &runtime,
                                &mut current,
                                &servers,
                                &node.id(),
                                mode,
                                &failover_cancel,
                                &notify,
                            )
                        }
                        Err(error) => Err(error.message),
                        Ok(connection) if !connection.verified && servers.len() > 1 => {
                            retry_servers(
                                &runtime,
                                &mut current,
                                &servers,
                                &node.id(),
                                mode,
                                &failover_cancel,
                                &notify,
                            )
                        }
                        Ok(connection) => Ok(connection),
                    };
                    if outcome.is_err() && current.is_none() {
                        notify(Event::Interrupted);
                    }
                    Event::Connected(outcome)
                }
                Ok(Message::Measure(nodes, auto, method, cancelled)) => {
                    if (method == Method::Https || auto.is_some()) && !runtime.is_file() {
                        Event::Measured(Err("Xray не найден рядом с приложением.".into()))
                    } else if auto == Some(Mode::Tunnel) && !is_admin() {
                        Event::Measured(Err(
                            "Для режима TUN запустите Orbit VPN от имени администратора.".into(),
                        ))
                    } else if current
                        .as_ref()
                        .is_some_and(|running| running.mode == Mode::Tunnel)
                    {
                        Event::Measured(Err(
                            "Отключите активный TUN перед проверкой серверов.".into()
                        ))
                    } else {
                        let ranked = measure(&runtime, &nodes, method, &cancelled, &notify);
                        if cancelled.load(Ordering::Relaxed) {
                            Event::Measured(Ok(true))
                        } else if let Some(mode) = auto {
                            if ranked.is_empty() {
                                Event::Measured(
                                    Err("Ни один сервер не ответил на проверку.".into()),
                                )
                            } else {
                                notify(Event::AutoConnecting);
                                let outcome = try_ranked(
                                    &runtime,
                                    &mut current,
                                    &nodes,
                                    ranked,
                                    mode,
                                    &cancelled,
                                );
                                if outcome.is_err() && current.is_none() {
                                    notify(Event::Interrupted);
                                }
                                Event::Connected(outcome)
                            }
                        } else {
                            Event::Measured(Ok(false))
                        }
                    }
                }
                Ok(Message::Disconnect) => {
                    drop(current.take());
                    Event::Disconnected
                }
                Ok(Message::Exit) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let lost = current.as_mut().and_then(|running| {
                        let (id, port) = running.endpoint.as_ref()?;
                        let ended = !matches!(running.child.try_wait(), Ok(None));
                        if !ended && Instant::now() < health_at {
                            return None;
                        }
                        let healthy =
                            !ended && proxy_client(*port).as_ref().is_some_and(web_reachable);
                        misses = if healthy { 0 } else { misses + 1 };
                        health_at = Instant::now()
                            + if healthy {
                                HEALTH_INTERVAL
                            } else {
                                Duration::from_secs(5)
                            };
                        (ended || misses >= 2).then(|| (id.clone(), running.mode))
                    });
                    if let Some((failed, mode)) = lost {
                        notify(Event::Interrupted);
                        Event::Connected(retry_servers(
                            &runtime,
                            &mut current,
                            &servers,
                            &failed,
                            mode,
                            &failover_cancel,
                            &notify,
                        ))
                    } else if let Some(source) = policy
                        .as_ref()
                        .filter(|rule| Instant::now() >= rule.next)
                        .map(|rule| rule.source.clone())
                    {
                        refresh(source, &countries, false, &mut policy, &mut servers)
                    } else {
                        continue;
                    }
                }
            };
            if let Event::Connected(ref result) = event {
                if result.is_ok() {
                    misses = 0;
                    health_at = Instant::now() + HEALTH_INTERVAL;
                }
                if let Ok(root) = crate::preferences::root() {
                    let summary = match result {
                        Ok(connection) if connection.verified => "Проверка подключения пройдена.",
                        Ok(_) => "Локальный прокси запущен, проверка HTTPS не прошла.",
                        Err(error) => error.as_str(),
                    };
                    let report = format!("Orbit VPN {}\n{summary}\n", env!("CARGO_PKG_VERSION"));
                    let _ = crate::preferences::replace(
                        &root.join("last-connection.txt"),
                        report.as_bytes(),
                    );
                }
            }
            if events.send(event).is_err() {
                break;
            }
            ctx.request_repaint();
        }
        drop(current);
    });
    (send, receive, worker)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failover_tries_in_rank_order_and_stops_on_connection() {
        let cancel = AtomicBool::new(false);
        let mut tried = Vec::new();
        let endpoint = select_candidate(vec![3, 1, 5], &cancel, |index| {
            tried.push(index);
            if index == 3 {
                Err(ConnectError::server("server went offline"))
            } else {
                Ok(Some(index))
            }
        })
        .unwrap();
        assert_eq!(endpoint, 1);
        assert_eq!(tried, vec![3, 1]);
        assert!(
            select_candidate::<usize>(vec![1], &AtomicBool::new(true), |_| panic!("cancelled"))
                .is_err()
        );
    }

    #[test]
    fn failed_refresh_preserves_server_pool() {
        let countries = subscription::countries();
        let sample =
            b"vless://5164ed2c-b2ef-4ed1-bc5a-ea64c242c520@nl.example.invalid:443#Amsterdam";
        let mut servers = subscription::parse(sample, &countries).unwrap().nodes;
        let before = servers[0].id();
        let mut policy = Some(RefreshPolicy {
            source: "broken".into(),
            interval: Duration::from_secs(3600),
            next: Instant::now(),
        });
        let result = refresh(
            "broken".into(),
            &countries,
            false,
            &mut policy,
            &mut servers,
        );
        assert!(matches!(result, Event::Refreshed { result: Err(_), .. }));
        assert_eq!(servers[0].id(), before);
        assert!(policy.unwrap().next > Instant::now());
    }

    #[test]
    fn refresh_saved_url_when_requested() {
        if std::env::var_os("ORBIT_DIAG_REFRESH").is_none() {
            return;
        }
        let preferences = crate::preferences::Preferences::read().unwrap();
        if !preferences.source.starts_with("https://") {
            println!("Saved subscription is pasted text; there is no remote URL to refresh.");
            return;
        }
        let result = subscription::import(&preferences.source, &subscription::countries());
        match result {
            Ok(subscription) => println!(
                "Saved URL returned {} supported servers.",
                subscription.nodes.len()
            ),
            Err(error) => println!("Saved URL could not be refreshed: {error}"),
        }
    }

    #[test]
    fn classify_xray_output_without_exposing_configuration() {
        assert!(matches!(
            classify_xray_line(
                "Failed to start > proxy/tun: unable to set DNS > Access is denied."
            ),
            Some(XrayFailure::Permission)
        ));
        assert!(matches!(
            classify_xray_line("proxy/tun: unable to set DNS > invalid address"),
            Some(XrayFailure::WindowsDns)
        ));
        assert!(matches!(
            classify_xray_line("proxy/tun: unable to add system route"),
            Some(XrayFailure::WindowsRoutes)
        ));
        assert!(classify_xray_line("configuration contains credentials omitted here").is_none());
    }

    #[test]
    fn probe_saved_profile_when_requested() {
        if std::env::var_os("ORBIT_DIAG_PROFILE").is_none() {
            return;
        }
        let path = PathBuf::from(std::env::var_os("ORBIT_TEST_XRAY").unwrap());
        let preferences = crate::preferences::Preferences::read().unwrap();
        let subscription = preferences.subscription.expect("saved subscription");
        let sample = &subscription.nodes[..subscription.nodes.len().min(4)];
        let responses = thread::scope(|scope| {
            sample
                .iter()
                .map(|node| {
                    scope.spawn(|| {
                        via_proxy(&path, node, &AtomicBool::new(false), |client| {
                            let resolver =
                                Resolver::start("127.0.0.1:0".parse().unwrap(), client.clone())
                                    .ok()?;
                            tunnel::dns_ready(resolver.address()).then_some(())
                        })
                        .is_some()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        println!(
            "Saved provider DNS-over-HTTPS check through local Xray: {} of {} answered DNS.",
            responses.iter().filter(|status| **status).count(),
            responses.len()
        );
    }

    #[test]
    fn keep_alive_reuses_one_socket_for_two_requests() {
        use std::io::{BufRead, BufReader};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut headers = BufReader::new(stream.try_clone().unwrap());
            for _ in 0..2 {
                let mut line = String::new();
                headers.read_line(&mut line).unwrap();
                assert!(line.starts_with("GET /probe "));
                loop {
                    line.clear();
                    assert!(headers.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
                    .unwrap();
            }
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .http1_only()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert!(
            warm_latency(
                &client,
                &format!("http://{address}/probe"),
                &AtomicBool::new(false)
            )
            .is_some()
        );
        server.join().unwrap();
    }

    #[test]
    fn forwards_http_over_local_vless() {
        let Some(path) = std::env::var_os("ORBIT_TEST_XRAY").map(PathBuf::from) else {
            return;
        };
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_addr = origin.local_addr().unwrap();
        let reserve = || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let vless_addr = reserve();
        let proxy_addr = reserve();
        let user = "5164ed2c-b2ef-4ed1-bc5a-ea64c242c520";
        let server_config = json!({
            "log":{"loglevel":"none"},
            "inbounds":[{"listen":"127.0.0.1","port":vless_addr.port(),"protocol":"vless",
                "settings":{"clients":[{"id":user}],"decryption":"none"}}],
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[
                {"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":origin_addr.port()}
            ]}}]
        });
        let mut server = launch(
            &path,
            &serde_json::to_vec(&server_config).unwrap(),
            Mode::Proxy,
            false,
        )
        .unwrap();
        let uri = format!("vless://{user}@{vless_addr}?type=tcp#Amsterdam");
        let mut nodes = subscription::parse(uri.as_bytes(), &subscription::countries())
            .unwrap()
            .nodes;
        let node = nodes.remove(0);
        let client_config = settings(&node, proxy_addr.port(), Mode::Proxy).unwrap();
        let mut runtime = launch(
            &path,
            &serde_json::to_vec(&client_config).unwrap(),
            Mode::Proxy,
            false,
        )
        .unwrap();
        for (process, address) in [(&mut server, vless_addr), (&mut runtime, proxy_addr)] {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                assert!(
                    matches!(process.child.try_wait(), Ok(None)),
                    "test Xray process stopped"
                );
                if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                    break;
                }
                assert!(Instant::now() < deadline, "test listener did not start");
                thread::sleep(Duration::from_millis(25));
            }
        }
        let responder = thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            origin.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            for _ in 0..3 {
                let mut stream = loop {
                    match origin.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(20))
                        }
                        Err(error) => panic!("test server: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut lines = BufReader::new(&stream).lines();
                let request = lines.next().unwrap().unwrap();
                for line in lines {
                    if line.unwrap().is_empty() {
                        break;
                    }
                }
                let response: &[u8] = if request.starts_with("GET /health ") {
                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\norbit"
                };
                stream.write_all(response).unwrap();
            }
        });
        let body = reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap()
            .get(format!("http://{origin_addr}/"))
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(body, "orbit");
        let url = format!("http://{origin_addr}/health");
        assert!(measure_node(&path, &node, &url, &AtomicBool::new(false)).is_some_and(|ms| ms > 0));
        assert_eq!(
            measure_node(&path, &node, &url, &AtomicBool::new(true)),
            None
        );
        responder.join().unwrap();
    }

    #[test]
    fn validates_configs_against_bundled_xray_when_available() {
        let Some(path) = std::env::var_os("ORBIT_TEST_XRAY").map(PathBuf::from) else {
            return;
        };
        let source =
            b"vless://5164ed2c-b2ef-4ed1-bc5a-ea64c242c520@example.net:443?security=tls#Amsterdam";
        let node = subscription::parse(source, &subscription::countries())
            .unwrap()
            .nodes
            .remove(0);
        for mode in [Mode::Proxy, Mode::Tunnel] {
            let encoded = serde_json::to_vec(&settings(&node, 41289, mode).unwrap()).unwrap();
            let mut process = launch(&path, &encoded, mode, true).unwrap();
            assert!(process.child.wait().unwrap().success());
        }
    }
}
