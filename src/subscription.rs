use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use url::Url;

const CAP: usize = 2 * 1024 * 1024;

#[derive(Clone, Deserialize)]
pub struct Country {
    pub code: String,
    pub ru: String,
    pub en: String,
    pub lat: f32,
    pub lon: f32,
}

pub fn countries() -> Vec<Country> {
    serde_json::from_str(include_str!("../assets/countries.json")).expect("bundled country dataset")
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Node {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub network: String,
    pub security: String,
    pub country: Option<usize>,
    user: String,
    options: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Group {
    pub name: String,
    pub indices: Vec<usize>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Subscription {
    pub groups: Vec<Group>,
    pub nodes: Vec<Node>,
    pub rejected: usize,
}

fn words(value: &str) -> Vec<String> {
    value
        .to_lowercase()
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn guess_country(label: &str, host: &str, countries: &[Country]) -> Option<usize> {
    let mut chars = label.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(d) = chars.peek()
            && ('🇦'..='🇿').contains(&c)
            && ('🇦'..='🇿').contains(d)
        {
            let code = [c, *d].map(|letter| (b'A' + (letter as u32 - '🇦' as u32) as u8) as char);
            return countries
                .iter()
                .position(|country| country.code == code.iter().collect::<String>());
        }
    }

    let label_words = words(label);
    let alias = [
        (
            "NL",
            &[
                "amsterdam",
                "ams",
                "holland",
                "амстердам",
                "голландия",
                "нидерланды",
            ][..],
        ),
        ("DE", &["frankfurt", "berlin", "франкфурт", "берлин"][..]),
        ("FI", &["helsinki", "хельсинки"][..]),
        ("GB", &["london", "лондон", "uk"][..]),
        ("FR", &["paris", "париж"][..]),
        ("US", &["new york", "сша", "nyc", "usa"][..]),
        ("SE", &["stockholm", "стокгольм"][..]),
        ("PL", &["warsaw", "варшава"][..]),
        ("TR", &["istanbul", "стамбул"][..]),
        ("JP", &["tokyo", "токио"][..]),
        ("SG", &["singapore", "сингапур"][..]),
    ];
    let named = countries
        .iter()
        .enumerate()
        .filter_map(|(index, c)| {
            let names = [&c.ru, &c.en];
            let length = names
                .into_iter()
                .filter_map(|name| {
                    let terms = words(name);
                    (!terms.is_empty()
                        && label_words
                            .windows(terms.len())
                            .any(|window| window == terms))
                    .then_some(terms.len())
                })
                .max()?;
            Some((length, index))
        })
        .max();
    if let Some((_, index)) = named {
        return Some(index);
    }
    for (code, aliases) in alias {
        if aliases.iter().any(|value| {
            let terms = words(value);
            label_words
                .windows(terms.len())
                .any(|window| window == terms)
        }) {
            return countries.iter().position(|country| country.code == code);
        }
    }
    if let Some(prefix) = label
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .find(|word| !word.is_empty())
        && prefix.len() == 2
        && prefix.chars().all(|ch| ch.is_ascii_uppercase())
    {
        let code = if prefix == "UK" { "GB" } else { prefix };
        if let Some(index) = countries.iter().position(|country| country.code == code) {
            return Some(index);
        }
    }
    let first = host.split('.').next()?.split('-').next()?;
    (first.len() == 2 && host.contains('.'))
        .then(|| {
            countries
                .iter()
                .position(|country| country.code.eq_ignore_ascii_case(first))
        })
        .flatten()
}

fn decoded(text: &str) -> String {
    percent_decode_str(text).decode_utf8_lossy().into_owned()
}

impl Node {
    fn parse(line: &str, countries: &[Country]) -> Option<Self> {
        let url = Url::parse(line).ok()?;
        if url.scheme() != "vless" || url.password().is_some() || !matches!(url.path(), "" | "/") {
            return None;
        }
        let host = match url.host()? {
            url::Host::Domain(name) => name.to_string(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        };
        let port = url.port().filter(|port| *port > 0)?;
        let raw_user = decoded(url.username());
        let user = match uuid::Uuid::parse_str(&raw_user) {
            Ok(id) => id.to_string(),
            Err(_)
                if !raw_user.is_empty()
                    && raw_user.len() <= 30
                    && !raw_user
                        .chars()
                        .any(|ch| ch.is_control() || ch.is_whitespace()) =>
            {
                raw_user
            }
            Err(_) => return None,
        };
        let mut options = BTreeMap::<String, String>::new();
        for (key, value) in url.query_pairs().filter(|(_, value)| !value.is_empty()) {
            if options.len() >= 48
                || options
                    .insert(key.into_owned(), value.into_owned())
                    .is_some()
            {
                return None;
            }
        }
        let get = |name: &str, default: &str| {
            options
                .get(name)
                .map_or_else(|| default.to_owned(), Clone::clone)
        };
        let network = match get("type", "tcp").as_str() {
            "tcp" | "raw" => "raw",
            "ws" => "ws",
            "grpc" => "grpc",
            "xhttp" | "splithttp" => "xhttp",
            "httpupgrade" => "httpupgrade",
            _ => return None,
        }
        .to_owned();
        let security = get("security", "none");
        if !matches!(security.as_str(), "none" | "tls" | "reality")
            || !matches!(get("flow", "").as_str(), "" | "xtls-rprx-vision")
            || (network != "raw" && options.contains_key("flow"))
            || !matches!(get("allowInsecure", "0").as_str(), "0" | "false")
            || get("headerType", "none") != "none"
        {
            return None;
        }
        if security == "reality"
            && ((!options.contains_key("sni"))
                || URL_SAFE_NO_PAD
                    .decode(get("pbk", ""))
                    .map_or(true, |result| result.len() != 32))
        {
            return None;
        }
        let mut name = decoded(url.fragment().unwrap_or_default())
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .filter(|ch| !ch.is_control())
            .take(96)
            .collect::<String>();
        if name.is_empty() {
            name.clone_from(&host);
        }
        let country = guess_country(&name, &host, countries);
        if country.is_some() {
            name = name
                .trim_start_matches(|ch: char| ('🇦'..='🇿').contains(&ch) || ch == '\u{fe0f}')
                .trim_start()
                .to_owned();
            if name.is_empty() {
                name.clone_from(&host);
            }
        }
        let node = Self {
            name,
            host,
            port,
            network,
            security,
            country,
            user,
            options,
        };
        node.outbound().ok()?;
        Some(node)
    }

    pub fn provider_auto(&self) -> bool {
        let terms = words(&self.name);
        terms.iter().any(|word| {
            matches!(
                word.as_str(),
                "автовыбор" | "авто" | "automatic" | "auto" | "autoselect" | "urltest"
            )
        })
    }

    pub fn id(&self) -> String {
        format!(
            "{}:{}:{}:{:?}:{}",
            self.host,
            self.port,
            self.user,
            self.options,
            if self.provider_auto() { &self.name } else { "" }
        )
    }

    pub fn outbound(&self) -> Result<Value, &'static str> {
        let get = |name, default| self.options.get(name).map_or(default, String::as_str);
        let mut stream = json!({"network": self.network, "security": self.security});
        if self.security == "tls" {
            stream["tlsSettings"] =
                json!({"serverName":get("sni", &self.host), "fingerprint":get("fp", "chrome")});
            if let Some(alpn) = self.options.get("alpn") {
                stream["tlsSettings"]["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
            }
        } else if self.security == "reality" {
            stream["realitySettings"] = json!({
                "serverName":get("sni", ""), "fingerprint":get("fp", "chrome"), "password":get("pbk", ""),
                "shortId":get("sid", ""), "spiderX":get("spx", ""),
            });
            if let Some(verify) = self.options.get("pqv") {
                stream["realitySettings"]["mldsa65Verify"] = json!(verify);
            }
        }
        match self.network.as_str() {
            "ws" | "xhttp" | "httpupgrade" => {
                let key = format!("{}Settings", self.network);
                let path = get("path", "/");
                if !path.starts_with('/') {
                    return Err("Некорректный путь транспорта.");
                }
                stream[&key] = json!({"host":get("host", ""), "path":path});
                if self.network == "xhttp" {
                    stream[&key]["mode"] = json!(get("mode", "auto"));
                    if let Some(extra) = self.options.get("extra") {
                        let data: Value = serde_json::from_str(extra)
                            .map_err(|_| "Некорректные настройки XHTTP.")?;
                        if !data.as_object().is_some_and(|object| {
                            object.keys().all(|key| {
                                matches!(
                                    key.as_str(),
                                    "scMaxEachPostBytes"
                                        | "scMinPostsIntervalMs"
                                        | "xPaddingBytes"
                                        | "noGRPCHeader"
                                )
                            })
                        }) {
                            return Err("Неподдерживаемые параметры XHTTP.");
                        }
                        stream[&key]["extra"] = data;
                    }
                }
            }
            "grpc" => {
                stream["grpcSettings"] = json!({
                    "serviceName":get("serviceName", ""), "authority":get("authority", ""),
                    "multiMode":get("mode", "") == "multi",
                });
            }
            _ => {}
        }
        let mut user = json!({"id":self.user, "encryption":get("encryption", "none")});
        if let Some(flow) = self.options.get("flow") {
            user["flow"] = json!(flow);
        }
        Ok(
            json!({"protocol":"vless", "tag":"vpn", "streamSettings":stream,
            "settings":{"vnext":[{"address":self.host, "port":self.port, "users":[user]}]}}),
        )
    }
}

#[derive(Deserialize)]
struct Mihomo {
    proxies: Vec<Value>,
    #[serde(default, rename = "proxy-groups")]
    groups: Vec<MihomoGroup>,
}

#[derive(Deserialize)]
struct MihomoGroup {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    proxies: Vec<String>,
    #[serde(default, rename = "include-all")]
    include_all: bool,
    #[serde(default, rename = "include-all-proxies")]
    include_all_proxies: bool,
    #[serde(default)]
    filter: String,
    #[serde(default, rename = "exclude-filter")]
    exclude_filter: String,
}

fn mihomo_node(value: &Value, countries: &[Country]) -> Option<Node> {
    if value["type"].as_str()? != "vless" {
        return None;
    }
    let name = value["name"].as_str()?;
    let host = value["server"].as_str()?;
    let port = value["port"]
        .as_u64()
        .or_else(|| value["port"].as_str()?.parse().ok())?;
    let port = u16::try_from(port).ok().filter(|p| *p > 0)?;
    let user = value["uuid"].as_str()?;
    let host = match host.parse::<std::net::Ipv6Addr>() {
        Ok(ip) => format!("[{ip}]"),
        Err(_) => url::Host::parse(host).ok()?.to_string(),
    };
    let raw = format!("vless://{host}:{port}");
    let mut uri = Url::parse(&raw).ok()?;
    uri.set_username(user).ok()?;
    uri.set_fragment(Some(name));
    let network = value["network"].as_str().unwrap_or("tcp");
    let reality = &value["reality-opts"];
    let security = if reality.is_object() {
        "reality"
    } else if value["tls"].as_bool() == Some(true) {
        "tls"
    } else {
        "none"
    };
    if value["skip-cert-verify"].as_bool() == Some(true) {
        return None;
    }
    {
        let mut query = uri.query_pairs_mut();
        query
            .append_pair("type", network)
            .append_pair("security", security);
        for (from, to) in [
            ("servername", "sni"),
            ("client-fingerprint", "fp"),
            ("flow", "flow"),
            ("encryption", "encryption"),
        ] {
            if let Some(text) = value[from].as_str() {
                query.append_pair(to, text);
            }
        }
        for (from, to) in [("public-key", "pbk"), ("short-id", "sid")] {
            if let Some(text) = reality[from].as_str() {
                query.append_pair(to, text);
            }
        }
        if let Some(alpn) = value["alpn"].as_array() {
            query.append_pair(
                "alpn",
                &alpn
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        let transport = match network {
            "ws" => Some(&value["ws-opts"]),
            "httpupgrade" => Some(&value["http-upgrade-opts"]),
            "xhttp" | "splithttp" => Some(&value["xhttp-opts"]),
            _ => None,
        };
        if let Some(transport) = transport {
            for key in ["path", "mode", "host"] {
                if let Some(text) = transport[key].as_str() {
                    query.append_pair(key, text);
                }
            }
            if transport["host"].is_null() {
                if let Some(host) = transport["headers"]["Host"]
                    .as_str()
                    .or_else(|| transport["headers"]["host"].as_str())
                {
                    query.append_pair("host", host);
                }
            }
        }
        if network == "grpc" {
            if let Some(service) = value["grpc-opts"]["grpc-service-name"].as_str() {
                query.append_pair("serviceName", service);
            }
        }
    }
    Node::parse(uri.as_str(), countries)
}

fn from_mihomo(config: Mihomo, countries: &[Country]) -> Subscription {
    let mut nodes = Vec::new();
    let mut names = HashMap::new();
    let mut seen = HashMap::new();
    let mut rejected = 0;
    for value in &config.proxies {
        if let Some(node) = mihomo_node(value, countries) {
            let key = node.id();
            let index = if let Some(&index) = seen.get(&key) {
                index
            } else {
                if nodes.len() == 1000 {
                    break;
                }
                let index = nodes.len();
                seen.insert(key, index);
                nodes.push(node);
                index
            };
            if let Some(name) = value["name"].as_str() {
                names.insert(name, index);
            }
        } else {
            rejected += 1;
        }
    }
    let definitions: HashMap<_, _> = config
        .groups
        .iter()
        .map(|group| (group.name.as_str(), group))
        .collect();
    let groups = config
        .groups
        .iter()
        .filter(|group| group.kind == "url-test")
        .take(64)
        .filter_map(|group| {
            if (group.include_all || group.include_all_proxies)
                && (!group.filter.is_empty() || !group.exclude_filter.is_empty())
            {
                return None;
            }
            let mut pending: Vec<_> = group.proxies.iter().rev().map(String::as_str).collect();
            let mut visited = HashSet::new();
            let mut indices: Vec<_> = if group.include_all || group.include_all_proxies {
                (0..nodes.len()).collect()
            } else {
                Vec::new()
            };
            while let Some(name) = pending.pop() {
                if !visited.insert(name) {
                    continue;
                }
                if let Some(&index) = names.get(name) {
                    indices.push(index);
                } else if let Some(child) = definitions.get(name) {
                    pending.extend(child.proxies.iter().rev().map(String::as_str));
                }
            }
            indices.sort_unstable();
            indices.dedup();
            (!indices.is_empty()).then(|| Group {
                name: group.name.clone(),
                indices,
            })
        })
        .collect();
    Subscription {
        groups,
        nodes,
        rejected,
    }
}

pub fn parse(bytes: &[u8], countries: &[Country]) -> Result<Subscription, String> {
    if bytes.len() > CAP {
        return Err("Подписка больше 2 МБ.".into());
    }
    let plain = std::str::from_utf8(bytes)
        .map_err(|_| "Проверьте формат подписки.")?
        .trim_start_matches('\u{feff}')
        .trim();
    let mut decoded = Vec::new();
    if !plain
        .lines()
        .any(|line| line.trim().starts_with("vless://"))
    {
        let compact: String = plain.chars().filter(|ch| !ch.is_whitespace()).collect();
        decoded = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
            .into_iter()
            .find_map(|engine| engine.decode(&compact).ok())
            .unwrap_or_default();
    }
    let content = if decoded.is_empty() {
        plain
    } else {
        std::str::from_utf8(&decoded)
            .map_err(|_| "Подписка не содержит текст со ссылками.")?
            .trim_start_matches('\u{feff}')
    };
    if !content
        .lines()
        .any(|line| line.trim_start().starts_with("vless://"))
        && let Ok(config) = serde_yaml_ng::from_str::<Mihomo>(content)
    {
        let result = from_mihomo(config, countries);
        if !result.nodes.is_empty() {
            return Ok(result);
        }
    }
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut rejected = 0;
    for line in content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        match Node::parse(line, countries) {
            Some(node) => {
                if seen.insert(node.id()) && nodes.len() < 1000 {
                    nodes.push(node);
                }
            }
            None => rejected += 1,
        }
    }
    if nodes.is_empty() {
        return Err("В подписке нет поддерживаемых ссылок VLESS.".into());
    }
    Ok(Subscription {
        groups: Vec::new(),
        nodes,
        rejected,
    })
}

pub fn import(input: &str, countries: &[Country]) -> Result<Subscription, String> {
    let input = input.trim();
    if !input.starts_with("https://") {
        return parse(input.as_bytes(), countries);
    }
    let allowed = |url: &Url| {
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    };
    let url = Url::parse(input).map_err(|_| "Проверьте HTTPS-адрес подписки.")?;
    if !allowed(&url) || url.fragment().is_some() {
        return Err("Проверьте HTTPS-адрес подписки.".into());
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .user_agent(concat!("OrbitVPN/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if allowed(attempt.url()) && attempt.previous().len() < 5 {
                attempt.follow()
            } else {
                attempt.error("redirect")
            }
        }))
        .build()
        .map_err(|_| "Не удалось запустить HTTPS-запрос.")?;
    let response = client
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|_| "Подписка недоступна. Проверьте адрес и соединение.")?;
    let mut content = Vec::new();
    response
        .take((CAP + 1) as u64)
        .read_to_end(&mut content)
        .map_err(|_| "Не удалось прочитать подписку.")?;
    parse(&content, countries)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "5164ed2c-b2ef-4ed1-bc5a-ea64c242c520";

    #[test]
    fn imports_base64_and_finds_country() {
        let countries = countries();
        let link = format!(
            "vless://{ID}@example.net:443?security=tls#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam"
        );
        let encoded = URL_SAFE_NO_PAD.encode(format!("{link}\n{link}\nvmess://unsupported"));
        let result = parse(encoded.as_bytes(), &countries).unwrap();
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.rejected, 1);
        assert_eq!(countries[result.nodes[0].country.unwrap()].code, "NL");
    }

    #[test]
    fn keeps_provider_auto_alias_and_removes_emoji_from_name() {
        let links = format!(
            "vless://{ID}@example.net:443#%F0%9F%87%AA%F0%9F%87%AA%20Estonia\nvless://{ID}@example.net:443#Auto"
        );
        let sub = parse(links.as_bytes(), &countries()).unwrap();
        assert_eq!(sub.nodes.len(), 2);
        assert_eq!(sub.nodes[0].name, "Estonia");
        assert!(sub.nodes[1].provider_auto());
    }

    #[test]
    fn imports_named_mihomo_url_test_group() {
        let yaml = format!(
            "proxies:\n  - {{name: NL, type: vless, server: nl.example.net, port: 443, uuid: {ID}, tls: true}}\n  - {{name: EE, type: vless, server: ee.example.net, port: 443, uuid: {ID}}}\nproxy-groups:\n  - {{name: Regional auto, type: url-test, proxies: [EE, DIRECT]}}\n  - {{name: Everywhere, type: url-test, include-all-proxies: true}}"
        );
        let sub = parse(yaml.as_bytes(), &countries()).unwrap();
        assert_eq!(sub.nodes.len(), 2);
        assert_eq!(sub.groups[0].name, "Regional auto");
        assert_eq!(sub.groups[0].indices, vec![1]);
        assert_eq!(sub.groups[1].indices, vec![0, 1]);
    }

    #[test]
    fn rejects_disabling_tls_checks() {
        let link = format!("vless://{ID}@example.net:443?security=tls&allowInsecure=1");
        assert!(parse(link.as_bytes(), &countries()).is_err());
    }
}
