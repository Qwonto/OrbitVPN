#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod dns;
mod globe;
mod preferences;
mod probe;
mod runtime;
mod setup;
mod subscription;
mod tunnel;

use eframe::egui::*;
use globe::{Globe, MINT};
use preferences::Preferences;
use probe::Method;
use runtime::{Connection, Event, Message, Mode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
};
use subscription::{Country, Group, Node};

const BG: Color32 = Color32::from_rgb(11, 17, 21);
const SURFACE: Color32 = Color32::from_rgb(16, 25, 30);
const FRAME: Color32 = Color32::from_rgb(31, 47, 53);
const INK: Color32 = Color32::from_rgb(230, 245, 243);
const DIM: Color32 = Color32::from_rgb(145, 172, 174);
const ACTIVE: Color32 = Color32::from_rgb(24, 48, 46);
const ALERT: Color32 = Color32::from_rgb(247, 183, 146);

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Servers,
    Settings,
}
#[derive(Clone, Copy)]
enum Icon {
    Globe,
    Layers,
    Settings,
    Search,
    Pin,
    Power,
    Close,
    Arrow,
}

fn icon(p: &Painter, at: Pos2, kind: Icon, ink: Color32) {
    let stroke = Stroke::new(1.55_f32, ink);
    let line = |a: (f32, f32), b: (f32, f32)| {
        p.line_segment([at + vec2(a.0, a.1), at + vec2(b.0, b.1)], stroke);
    };
    let ring = |r| {
        p.circle_stroke(at, r, stroke);
    };
    match kind {
        Icon::Globe => {
            ring(8.);
            line((-7., 0.), (7., 0.));
            p.add(Shape::line(
                (-6..=6)
                    .map(|y| {
                        let f = y as f32;
                        at + vec2(3.4 * (1. - f * f / 56.).sqrt(), f)
                    })
                    .collect(),
                stroke,
            ));
            p.add(Shape::line(
                (-6..=6)
                    .map(|y| {
                        let f = y as f32;
                        at + vec2(-3.4 * (1. - f * f / 56.).sqrt(), f)
                    })
                    .collect(),
                stroke,
            ));
        }
        Icon::Layers => {
            for shift in [-5., 0., 5.] {
                p.line(
                    vec![
                        at + vec2(-7., shift - 2.),
                        at + vec2(0., shift + 2.),
                        at + vec2(7., shift - 2.),
                    ],
                    stroke,
                );
            }
        }
        Icon::Settings => {
            for (y, x) in [(-5., -3.), (0., 3.), (5., -1.)] {
                line((-8., y), (8., y));
                p.circle_filled(at + vec2(x, y), 2.5, ink);
            }
        }
        Icon::Search => {
            p.circle_stroke(at + vec2(-2., -2.), 4.8, stroke);
            line((2., 2.), (6., 6.));
        }
        Icon::Pin => {
            p.circle_stroke(at + vec2(0., -2.5), 5., stroke);
            line((-4., 1.), (0., 7.));
            line((4., 1.), (0., 7.));
        }
        Icon::Power => {
            p.add(Shape::line(
                (0..=26)
                    .map(|i| {
                        let a = 0.55 + i as f32 * 5.18 / 26.;
                        at + vec2(a.sin() * 7., -a.cos() * 7.)
                    })
                    .collect(),
                stroke,
            ));
            line((0., -9.), (0., -1.));
        }
        Icon::Close => {
            line((-5., -5.), (5., 5.));
            line((5., -5.), (-5., 5.));
        }
        Icon::Arrow => {
            line((-3., -5.), (2., 0.));
            line((2., 0.), (-3., 5.));
        }
    }
}

fn label(ui: &mut Ui, text: &str, size: f32, color: Color32) -> Response {
    ui.label(RichText::new(text).size(size).color(color))
}

fn action(ui: &mut Ui, text: &str, primary: bool, size: Vec2) -> Response {
    let (fill, ink, stroke) = if primary {
        (MINT, BG, Stroke::NONE)
    } else {
        (SURFACE, INK, Stroke::new(1_f32, FRAME))
    };
    let hover = if primary {
        Color32::from_rgb(164, 252, 219)
    } else {
        ACTIVE
    };
    ui.scope(|ui| {
        ui.style_mut().visuals.widgets.hovered.weak_bg_fill = hover;
        ui.style_mut().visuals.widgets.active.weak_bg_fill = hover;
        let button = Button::new(RichText::new(text).size(13.5).strong().color(ink))
            .fill(fill)
            .stroke(stroke)
            .corner_radius(9);
        ui.add_sized(size, button)
    })
    .inner
}

fn rail_button(ui: &mut Ui, kind: Icon, title: &str, active: bool) -> Response {
    let button = ui.add_sized(
        [43., 43.],
        Button::new("")
            .fill(if active { ACTIVE } else { BG })
            .stroke(if active {
                Stroke::new(1_f32, Color32::from_rgb(48, 85, 79))
            } else {
                Stroke::NONE
            })
            .corner_radius(10),
    );
    icon(
        ui.painter(),
        button.rect.center(),
        kind,
        if active || button.hovered() {
            MINT
        } else {
            DIM
        },
    );
    button.on_hover_text(title)
}

struct Active {
    connection: Connection,
    name: String,
    country: Option<usize>,
    id: String,
}

#[derive(Clone, Copy, Default)]
enum Ping {
    #[default]
    Untested,
    Measured(u32),
    Failed,
}

struct Scan {
    finished: usize,
    total: usize,
    cancel: Arc<AtomicBool>,
}

fn flag_textures(ctx: &Context) -> Vec<Option<TextureHandle>> {
    const SIZE: [usize; 2] = [48, 36];
    include_bytes!("../assets/flags.bin")
        .chunks_exact(SIZE[0] * SIZE[1] * 4)
        .enumerate()
        .map(|(i, bytes)| {
            bytes.iter().any(|&byte| byte != 0).then(|| {
                ctx.load_texture(
                    format!("flag-{i}"),
                    ColorImage::from_rgba_unmultiplied(SIZE, bytes),
                    TextureOptions::LINEAR,
                )
            })
        })
        .collect()
}

struct Orbit {
    countries: Arc<Vec<Country>>,
    globe: Globe,
    page: Page,
    nodes: Vec<Node>,
    groups: Vec<Group>,
    selected: Option<usize>,
    selected_group: Option<usize>,
    flags: Vec<Option<TextureHandle>>,
    ping: Vec<Ping>,
    scan: Option<Scan>,
    failover_cancel: Arc<AtomicBool>,
    active: Option<Active>,
    preview: Option<usize>,
    filter: String,
    source: String,
    preferences: Preferences,
    import_open: bool,
    pending: Option<&'static str>,
    notice: Option<(String, bool)>,
    mode: Mode,
    motion: bool,
    worker: Option<thread::JoinHandle<()>>,
    send: mpsc::Sender<Message>,
    events: mpsc::Receiver<Event>,
    snapshot: Option<PathBuf>,
    capture_requested: bool,
}

fn configure_theme(ctx: &Context) {
    ctx.set_theme(Theme::Dark);
    let mut style = (*ctx.global_style()).clone();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = SURFACE;
    style.visuals.widgets.inactive.bg_fill = SURFACE;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.hovered.bg_fill = ACTIVE;
    style.visuals.widgets.hovered.weak_bg_fill = ACTIVE;
    style.visuals.widgets.active.weak_bg_fill = ACTIVE;
    style.visuals.widgets.active.bg_fill = ACTIVE;
    style.visuals.selection.bg_fill = Color32::from_rgb(43, 91, 81);
    style.visuals.override_text_color = Some(INK);
    style.visuals.extreme_bg_color = Color32::from_rgb(10, 18, 23);
    style.spacing.item_spacing = vec2(9., 9.);
    style.spacing.interact_size = vec2(40., 34.);
    ctx.set_global_style(style);
    #[cfg(windows)]
    if let Ok(data) = std::fs::read(
        PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:/Windows".into()))
            .join("Fonts/segoeui.ttf"),
    ) {
        let mut fonts = FontDefinitions::default();
        fonts
            .font_data
            .insert("windows-ui".into(), Arc::new(FontData::from_owned(data)));
        fonts
            .families
            .entry(FontFamily::Proportional)
            .or_default()
            .insert(0, "windows-ui".into());
        ctx.set_fonts(fonts);
    }
}

fn server_groups(total: usize, imported: Vec<Group>) -> Vec<Group> {
    if total == 0 {
        return Vec::new();
    }
    let mut groups = vec![Group {
        name: "Автовыбор".into(),
        indices: (0..total).collect(),
    }];
    groups.extend(
        imported
            .into_iter()
            .filter(|group| group.name != "Автовыбор" || group.indices.len() != total),
    );
    groups
}

fn refresh_policy(preferences: &Preferences) -> Option<runtime::RefreshPolicy> {
    use std::time::{Duration, Instant};
    if preferences.refresh_hours == 0 || !preferences.source.starts_with("https://") {
        return None;
    }
    let seconds = u64::from(preferences.refresh_hours.min(24)) * 3600;
    let elapsed = preferences::unix_seconds().saturating_sub(preferences.refreshed_at);
    Some(runtime::RefreshPolicy {
        source: preferences.source.clone(),
        interval: Duration::from_secs(seconds),
        next: Instant::now() + Duration::from_secs(seconds.saturating_sub(elapsed)),
    })
}

impl Orbit {
    fn new(ctx: &Context, runtime_path: PathBuf, snapshot: Option<PathBuf>) -> Self {
        let countries = Arc::new(subscription::countries());
        let demo = snapshot.as_ref().map(|_| {
            let id = "5164ed2c-b2ef-4ed1-bc5a-ea64c242c520";
            let sample = [
                ("nl", "Amsterdam", "tcp", 63),
                ("ee", "Tallinn", "ws", 51),
                ("de", "Frankfurt", "tcp", 76),
                ("fi", "Helsinki", "grpc", 58),
            ];
            let links = sample
                .iter()
                .map(|(code, city, kind, _)| {
                    format!("vless://{id}@{code}.example.invalid:443?type={kind}#{city}")
                })
                .collect::<Vec<_>>()
                .join("\n");
            let sub = subscription::parse(links.as_bytes(), &countries).expect("demo subscription");
            let ping = sample
                .into_iter()
                .map(|(_, _, _, ms)| Ping::Measured(ms))
                .collect();
            (sub.nodes, ping)
        });
        let (preferences, load_error) = if snapshot.is_some() {
            (Preferences::default(), false)
        } else {
            match Preferences::read() {
                Ok(preferences) => (preferences, false),
                Err(_) => (Preferences::default(), true),
            }
        };
        let (nodes, groups, ping) = if let Some((nodes, ping)) = demo {
            let groups = server_groups(nodes.len(), Vec::new());
            (nodes, groups, ping)
        } else if let Some(cached) = preferences.subscription.as_ref() {
            let total = cached.nodes.len();
            (
                cached.nodes.clone(),
                server_groups(total, cached.groups.clone()),
                vec![Ping::Untested; total],
            )
        } else {
            Default::default()
        };
        let selected = (!nodes.is_empty()).then_some(0);
        configure_theme(ctx);
        let failover_cancel = Arc::new(AtomicBool::new(false));
        let (send, events, worker) = runtime::spawn(
            countries.clone(),
            runtime_path,
            ctx.clone(),
            nodes.clone(),
            refresh_policy(&preferences),
            failover_cancel.clone(),
        );
        Self {
            countries,
            globe: Globe::new(),
            page: Page::Servers,
            nodes,
            groups,
            selected,
            selected_group: None,
            flags: flag_textures(ctx),
            ping,
            scan: None,
            failover_cancel,
            active: None,
            preview: None,
            filter: String::new(),
            source: preferences.source.clone(),
            preferences,
            import_open: false,
            pending: None,
            notice: if load_error {
                Some(("Не удалось прочитать сохранённую подписку.".into(), true))
            } else {
                snapshot
                    .as_ref()
                    .map(|_| ("Демонстрационный список серверов".into(), false))
            },
            mode: Mode::default(),
            motion: true,
            send,
            events,
            worker: Some(worker),
            snapshot,
            capture_requested: false,
        }
    }

    fn receive(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            if !matches!(
                &event,
                Event::Latency(..)
                    | Event::Interrupted
                    | Event::AutoConnecting
                    | Event::FailoverStarted(..)
                    | Event::Refreshed { manual: false, .. }
            ) {
                self.pending = None;
            }
            match event {
                Event::Imported(Ok(result)) => {
                    let total = result.nodes.len();
                    self.notice = Some((
                        format!("Импортировано: {total}. Пропущено: {}.", result.rejected),
                        false,
                    ));
                    self.preferences.source = self.source.trim().to_owned();
                    self.preferences.subscription = Some(result.clone());
                    self.preferences.refreshed_at = preferences::unix_seconds();
                    self.update_refresh_policy();
                    if self.preferences.save().is_err() {
                        self.notice = Some((
                            "Подписка импортирована, но сохранить её не удалось.".into(),
                            true,
                        ));
                    }
                    self.groups = server_groups(total, result.groups);
                    self.ping = vec![Ping::Untested; total];
                    self.nodes = result.nodes;
                    self.filter.clear();
                    self.selected = Some(0);
                    self.selected_group = None;
                    self.preview = None;
                    self.import_open = false;
                }
                Event::Refreshed {
                    source,
                    result,
                    manual,
                } => {
                    if source != self.preferences.source {
                        continue;
                    }
                    match result {
                        Ok(subscription) => self.apply_refresh(subscription, manual),
                        Err(error) if manual => {
                            self.notice = Some((format!("{error} Список серверов сохранён."), true))
                        }
                        Err(_) => {}
                    }
                }
                Event::Connected(Ok(connection)) => {
                    self.scan = None;
                    let node = &connection.node;
                    let id = node.id();
                    if self.selected_group.is_none() {
                        self.selected =
                            self.nodes.iter().position(|candidate| candidate.id() == id);
                    }
                    self.active = Some(Active {
                        name: node.name.clone(),
                        country: node.country,
                        id,
                        connection,
                    });
                }
                Event::FailoverStarted(total, cancel) => {
                    self.active = None;
                    self.pending = Some("Ищу запасной сервер…");
                    self.scan = Some(Scan {
                        finished: 0,
                        total,
                        cancel,
                    });
                }
                Event::Latency(index, id, elapsed) => {
                    let at = if self.nodes.get(index).is_some_and(|node| node.id() == id) {
                        Some(index)
                    } else {
                        self.nodes.iter().position(|node| node.id() == id)
                    };
                    if let Some(value) = at.and_then(|index| self.ping.get_mut(index)) {
                        *value = elapsed.map_or(Ping::Failed, Ping::Measured);
                    }
                    if let Some(scan) = self.scan.as_mut() {
                        scan.finished += 1;
                    }
                }
                Event::AutoConnecting => {
                    self.scan = None;
                    self.pending = Some("Подключаюсь к быстрому серверу…");
                }
                Event::Measured(result) => {
                    self.scan = None;
                    self.notice = Some(match result {
                        Ok(true) => ("Проверка остановлена.".into(), false),
                        Ok(false) => ("Проверка завершена.".into(), false),
                        Err(error) => (error, true),
                    });
                }
                Event::Disconnected => {
                    self.active = None;
                    self.notice = None;
                }
                Event::Interrupted => {
                    if self.active.take().is_some() {
                        self.notice = Some(("Xray остановился. Подключение закрыто.".into(), true));
                    }
                }
                Event::Imported(Err(error)) | Event::Connected(Err(error)) => {
                    self.scan = None;
                    self.notice = Some((error, true));
                }
            }
        }
    }

    fn update_refresh_policy(&self) {
        let _ = self
            .send
            .send(Message::RefreshPolicy(refresh_policy(&self.preferences)));
    }

    fn apply_refresh(&mut self, result: subscription::Subscription, manual: bool) {
        let previous: std::collections::HashMap<_, _> = self
            .nodes
            .iter()
            .zip(&self.ping)
            .map(|(node, ping)| (node.id(), *ping))
            .collect();
        let selected = self
            .selected
            .and_then(|index| self.nodes.get(index))
            .map(Node::id);
        let group = self
            .selected_group
            .and_then(|index| self.groups.get(index))
            .map(|group| group.name.clone());
        self.preferences.refreshed_at = preferences::unix_seconds();
        self.preferences.subscription = Some(result.clone());
        self.nodes = result.nodes;
        self.groups = server_groups(self.nodes.len(), result.groups);
        self.ping = self
            .nodes
            .iter()
            .map(|node| previous.get(&node.id()).copied().unwrap_or_default())
            .collect();
        self.selected_group =
            group.and_then(|name| self.groups.iter().position(|group| group.name == name));
        self.selected = if self.selected_group.is_none() {
            selected
                .and_then(|id| self.nodes.iter().position(|node| node.id() == id))
                .or(Some(0))
        } else {
            None
        };
        if self.preferences.save().is_err() {
            self.notice = Some((
                "Подписка обновилась, но сохранить её не удалось.".into(),
                true,
            ));
        } else if manual {
            self.notice = Some((
                format!("Подписка обновлена. Серверов: {}.", self.nodes.len()),
                false,
            ));
        }
    }

    fn request(&mut self, request: Message, status: &'static str) {
        if matches!(
            &request,
            Message::Connect(..) | Message::Measure(_, Some(_), _, _)
        ) {
            self.failover_cancel.store(false, Ordering::Relaxed);
        } else if matches!(request, Message::Disconnect) {
            self.failover_cancel.store(true, Ordering::Relaxed);
        }
        if self.send.send(request).is_ok() {
            self.pending = Some(status);
            self.notice = None;
        } else {
            self.notice = Some((
                "Рабочий процесс остановился. Перезапустите Orbit VPN.".into(),
                true,
            ));
        }
    }

    fn measure(&mut self, indices: Vec<usize>, auto: bool) {
        let nodes: Vec<_> = indices
            .iter()
            .map(|&index| (index, self.nodes[index].clone()))
            .collect();
        if nodes.is_empty() {
            return;
        }
        for &index in &indices {
            self.ping[index] = Ping::Untested;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.request(
            Message::Measure(
                nodes,
                auto.then_some(self.mode),
                self.preferences.method,
                cancel.clone(),
            ),
            "Проверяю задержку серверов…",
        );
        if self.pending.is_some() {
            self.scan = Some(Scan {
                finished: 0,
                total: indices.len(),
                cancel,
            });
        }
    }

    fn connect_selected(&mut self) {
        if let Some(group) = self.selected_group {
            self.measure(self.groups[group].indices.clone(), true);
        } else if let Some(index) = self.selected {
            self.request(
                Message::Connect(Box::new(self.nodes[index].clone()), self.mode),
                "Проверяю подключение…",
            );
        }
    }

    fn scan_allowed(&self) -> bool {
        !self
            .active
            .as_ref()
            .is_some_and(|active| active.connection.mode == Mode::Tunnel)
    }

    fn country(&self) -> Option<usize> {
        if let Some(active) = self.active.as_ref() {
            return active.country;
        }
        self.selected
            .and_then(|i| self.nodes[i].country)
            .or(self.preview)
    }

    fn sidebar(&mut self, ui: &mut Ui, rect: Rect) {
        let p = ui.painter();
        p.rect_filled(rect, 0, Color32::from_rgb(10, 16, 19));
        p.line_segment(
            [rect.right_top(), rect.right_bottom()],
            Stroke::new(1_f32, FRAME),
        );
        p.circle_filled(rect.center_top() + vec2(0., 38.), 20., ACTIVE);
        icon(p, rect.center_top() + vec2(0., 38.), Icon::Globe, MINT);
        ui.scope_builder(
            UiBuilder::new().max_rect(Rect::from_min_max(
                rect.min + vec2(12., 91.),
                rect.max - vec2(12., 30.),
            )),
            |ui| {
                ui.spacing_mut().item_spacing.y = 12.;
                if rail_button(ui, Icon::Layers, "Серверы", self.page == Page::Servers).clicked()
                {
                    self.page = Page::Servers;
                }
                if rail_button(ui, Icon::Settings, "Настройки", self.page == Page::Settings)
                    .clicked()
                {
                    self.page = Page::Settings;
                }
            },
        );
        let p = ui.painter();
        let corner = rect.center_bottom() + vec2(0., -34.);
        let status = if self
            .active
            .as_ref()
            .is_some_and(|active| active.connection.verified)
        {
            MINT
        } else if self.active.is_some() {
            ALERT
        } else {
            DIM
        };
        p.circle_filled(corner, 11., status.gamma_multiply(0.15));
        p.circle_filled(corner, 4.5, status);
    }

    fn map(&mut self, ui: &mut Ui, rect: Rect) {
        let country = self
            .country()
            .and_then(|id| self.countries.get(id).map(|country| (id, country)));
        self.globe.look(country.map(|(_, c)| c));
        let map_rect = Rect::from_min_max(rect.min + vec2(5., 76.), rect.max - vec2(5., 100.));
        let verified = self
            .active
            .as_ref()
            .is_some_and(|active| active.connection.verified);
        self.globe
            .show(ui, map_rect, country, verified, self.motion);
        let p = ui.painter_at(rect);
        let x = rect.left() + 30.;
        let y = rect.top() + 27.;
        p.text(
            pos2(x, y),
            Align2::LEFT_TOP,
            "Orbit VPN",
            FontId::proportional(23.),
            INK,
        );
        p.text(
            pos2(x, y + 34.),
            Align2::LEFT_TOP,
            "Карта подключений",
            FontId::proportional(13.),
            DIM,
        );
        let y = rect.bottom() - 70.;
        let caption = country.map_or("Земля", |(_, c)| c.ru.as_str());
        p.text(
            pos2(x, y),
            Align2::LEFT_TOP,
            caption,
            FontId::proportional(25.),
            INK,
        );
        let detail = country.map_or_else(
            || "Выберите сервер, чтобы увидеть его страну".to_owned(),
            |(_, c)| {
                format!(
                    "{:.2}° {}  /  {:.2}° {}",
                    c.lat.abs(),
                    if c.lat < 0. { "S" } else { "N" },
                    c.lon.abs(),
                    if c.lon < 0. { "W" } else { "E" }
                )
            },
        );
        p.text(
            pos2(x, y + 34.),
            Align2::LEFT_TOP,
            detail,
            FontId::monospace(11.5),
            DIM,
        );
    }

    fn location(&self, id: Option<usize>) -> &str {
        id.map_or("Страна не определена", |index| {
            self.countries[index].ru.as_str()
        })
    }

    fn connection_card(&mut self, ui: &mut Ui) {
        let status = self.pending.unwrap_or_else(|| match self.active.as_ref() {
            Some(active) if active.connection.verified => "Подключено",
            Some(active) if active.connection.mode == Mode::Tunnel => {
                "Туннель запущен, интернет не подтверждён"
            }
            Some(_) => "Прокси запущен, интернет не подтверждён",
            None => "Отключено",
        });
        let mark = if self
            .active
            .as_ref()
            .is_some_and(|active| active.connection.verified)
        {
            MINT
        } else if self.active.is_some() {
            ALERT
        } else {
            DIM
        };
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1_f32, FRAME))
            .corner_radius(12)
            .inner_margin(15)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(vec2(36., 36.), Sense::hover());
                    ui.painter()
                        .rect_filled(r, 9, if self.active.is_some() { ACTIVE } else { BG });
                    icon(ui.painter(), r.center(), Icon::Power, mark);
                    ui.vertical(|ui| {
                        label(ui, status, 13.5, mark);
                        if let Some(active) = self.active.as_ref() {
                            label(
                                ui,
                                &format!(
                                    "{}  ·  {}",
                                    self.location(active.country),
                                    if active.connection.mode == Mode::Tunnel {
                                        "VPN Windows"
                                    } else {
                                        "HTTP-прокси"
                                    }
                                ),
                                12.,
                                DIM,
                            );
                        } else {
                            label(
                                ui,
                                if self.mode == Mode::Tunnel {
                                    "Туннель Windows · VLESS"
                                } else {
                                    "Локальный прокси · VLESS"
                                },
                                12.,
                                DIM,
                            );
                        }
                    });
                });
                if let Some(active) = &self.active {
                    let address = format!("127.0.0.1:{}", active.connection.port);
                    if active.connection.mode == Mode::Proxy {
                        ui.horizontal(|ui| {
                            label(ui, &address, 12., DIM);
                            if ui.small_button("Копировать").clicked() {
                                ui.ctx().copy_text(address.clone());
                            }
                        });
                    }
                    let name = active.name.as_str();
                    ui.add(
                        Label::new(RichText::new(name).size(12.).color(DIM))
                            .truncate()
                            .selectable(false),
                    );
                }
                ui.add_space(5.);
                let disabled = self.pending.is_some();
                let width = ui.available_width();
                ui.add_enabled_ui(!disabled, |ui| {
                    let group = self.selected_group.is_some();
                    let has_selection = group || self.selected.is_some();
                    let switch = has_selection
                        && self.active.as_ref().is_some_and(|active| {
                            group
                                || self
                                    .selected
                                    .is_some_and(|index| active.id != self.nodes[index].id())
                        });
                    let can_connect = has_selection && (!group || self.scan_allowed());
                    if switch {
                        ui.horizontal(|ui| {
                            ui.add_enabled_ui(can_connect, |ui| {
                                if action(
                                    ui,
                                    if group {
                                        "Автовыбор"
                                    } else {
                                        "Сменить сервер"
                                    },
                                    true,
                                    vec2(width * 0.56, 37.),
                                )
                                .clicked()
                                {
                                    self.connect_selected();
                                }
                            });
                            if action(ui, "Отключить", false, vec2(ui.available_width(), 37.))
                                .clicked()
                            {
                                self.request(Message::Disconnect, "Отключаю…");
                            }
                        });
                    } else if self.active.is_some() {
                        if action(ui, "Отключить", false, vec2(width, 37.)).clicked() {
                            self.request(Message::Disconnect, "Отключаю…");
                        }
                    } else {
                        ui.add_enabled_ui(can_connect, |ui| {
                            if action(ui, "Подключиться", true, vec2(width, 37.)).clicked()
                            {
                                self.connect_selected();
                            }
                        });
                    }
                });
            });
    }

    fn server_panel(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("Серверы").size(30.).strong());
                let count = if self.nodes.is_empty() {
                    "Нужна подписка VLESS".into()
                } else {
                    format!("Серверов в подписке: {}", self.nodes.len())
                };
                label(ui, &count, 13., DIM);
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_enabled_ui(self.pending.is_none(), |ui| {
                    if action(ui, "+  Подписка", false, vec2(118., 36.)).clicked() {
                        self.import_open = true;
                        self.notice = None;
                    }
                    if self.preferences.source.starts_with("https://")
                        && action(ui, "Обновить", false, vec2(94., 36.)).clicked()
                    {
                        self.request(
                            Message::Refresh(self.preferences.source.clone()),
                            "Обновляю подписку…",
                        );
                    }
                });
            });
        });
        ui.add_space(16.);
        self.connection_card(ui);
        if let Some((note, error)) = &self.notice {
            if !self.import_open {
                label(ui, note, 12., if *error { ALERT } else { DIM });
            }
        }
        ui.add_space(12.);
        if self.nodes.is_empty() {
            Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1_f32, FRAME))
                .corner_radius(12)
                .inner_margin(19)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let (r, _) = ui.allocate_exact_size(vec2(42., 42.), Sense::hover());
                    ui.painter().rect_filled(r, 10, ACTIVE);
                    icon(ui.painter(), r.center(), Icon::Pin, MINT);
                    ui.add_space(5.);
                    ui.label(RichText::new("Куда подключимся?").size(19.).strong());
                    label(
                        ui,
                        "Вставьте адрес подписки или ссылку vless://, чтобы выбрать сервер.",
                        13.,
                        DIM,
                    );
                    ui.add_space(8.);
                    ui.horizontal_wrapped(|ui| {
                        if action(ui, "Добавить подписку", true, vec2(155., 36.)).clicked()
                        {
                            self.import_open = true;
                            self.notice = None;
                        }
                        if action(ui, "Показать Нидерланды", false, vec2(164., 36.)).clicked()
                        {
                            self.preview = self
                                .countries
                                .iter()
                                .position(|country| country.code == "NL");
                        }
                    });
                });
            return;
        }
        ui.horizontal(|ui| {
            let (r, _) = ui.allocate_exact_size(vec2(22., 31.), Sense::hover());
            icon(ui.painter(), r.center(), Icon::Search, DIM);
            ui.add_sized(
                vec2(ui.available_width(), 32.),
                TextEdit::singleline(&mut self.filter)
                    .hint_text("Поиск по стране, серверу или адресу"),
            );
        });
        ui.add_space(6.);
        ui.horizontal(|ui| {
            if let Some(scan) = self.scan.as_ref() {
                let cancelled = scan.cancel.load(Ordering::Relaxed);
                label(
                    ui,
                    &format!("Проверено: {} / {}", scan.finished, scan.total),
                    12.,
                    MINT,
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_enabled_ui(!cancelled, |ui| {
                        if action(ui, "Остановить", false, vec2(104., 31.)).clicked() {
                            scan.cancel.store(true, Ordering::Relaxed);
                        }
                    });
                });
            } else {
                let allowed = self.scan_allowed();
                ui.add_enabled_ui(self.pending.is_none() && allowed, |ui| {
                    if action(ui, "Пинг всех серверов", false, vec2(155., 31.)).clicked()
                    {
                        self.measure((0..self.nodes.len()).collect(), false);
                    }
                })
                .response
                .on_disabled_hover_text("Отключите TUN перед измерением задержки.");
            }
        });
        ui.add_space(4.);
        let query = self.filter.to_lowercase();
        let matches: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| {
                let country = self.location(n.country).to_lowercase();
                (query.is_empty()
                    || n.name.to_lowercase().contains(&query)
                    || country.contains(&query)
                    || n.host.to_lowercase().contains(&query)
                    || n.country
                        .is_some_and(|id| self.countries[id].code.to_lowercase() == query))
                .then_some(i)
            })
            .collect();
        let groups: Vec<_> = self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| query.is_empty() || group.name.to_lowercase().contains(&query))
            .map(|(index, _)| index)
            .collect();
        if matches.is_empty() && groups.is_empty() {
            label(ui, "Серверы не найдены", 13., DIM);
        }
        ScrollArea::vertical()
            .id_salt("servers")
            .auto_shrink([false, false])
            .show_rows(ui, 56., groups.len() + matches.len(), |ui, rows| {
                ui.spacing_mut().item_spacing.y = 6.;
                for row in rows {
                    if let Some(&index) = groups.get(row) {
                        self.group_row(ui, index);
                    } else {
                        self.server_row(ui, matches[row - groups.len()]);
                    }
                }
            });
    }

    fn group_row(&mut self, ui: &mut Ui, index: usize) {
        let group = &self.groups[index];
        let selected = self.selected_group == Some(index);
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 56.), Sense::click());
        let painter = ui.painter();
        painter.rect(
            rect,
            10,
            if selected || response.hovered() {
                ACTIVE
            } else {
                SURFACE
            },
            Stroke::new(
                1_f32,
                if selected {
                    Color32::from_rgb(52, 104, 92)
                } else {
                    FRAME
                },
            ),
            StrokeKind::Inside,
        );
        let mark = Rect::from_center_size(rect.left_center() + vec2(28., 0.), vec2(34., 32.));
        painter.rect_filled(mark, 8, ACTIVE);
        icon(painter, mark.center(), Icon::Power, MINT);
        let title = WidgetText::from(RichText::new(&group.name).size(13.5).color(INK)).into_galley(
            ui,
            Some(TextWrapMode::Truncate),
            rect.width() - 100.,
            TextStyle::Body,
        );
        painter.galley(rect.min + vec2(55., 8.), title, INK);
        painter.text(
            rect.min + vec2(55., 30.),
            Align2::LEFT_TOP,
            format!("Быстрейший доступный · {}", group.indices.len()),
            FontId::proportional(11.),
            DIM,
        );
        icon(
            painter,
            rect.right_center() - vec2(17., 0.),
            Icon::Arrow,
            DIM,
        );
        if response.clicked() && self.pending.is_none() {
            self.selected_group = Some(index);
            self.selected = None;
            self.preview = None;
        }
        if response.double_clicked() && self.pending.is_none() && self.scan_allowed() {
            self.connect_selected();
        }
    }

    fn server_row(&mut self, ui: &mut Ui, index: usize) {
        let node = &self.nodes[index];
        let selected = self.selected == Some(index);
        let online = self
            .active
            .as_ref()
            .is_some_and(|active| active.id == node.id());
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 56.), Sense::click());
        let p = ui.painter();
        p.rect(
            rect,
            10,
            if selected || response.hovered() {
                ACTIVE
            } else {
                SURFACE
            },
            Stroke::new(
                1_f32,
                if selected {
                    Color32::from_rgb(52, 104, 92)
                } else {
                    FRAME
                },
            ),
            StrokeKind::Inside,
        );
        let mark = Rect::from_center_size(rect.left_center() + vec2(28., 0.), vec2(34., 32.));
        if let Some(flag) = node.country.and_then(|id| self.flags.get(id)?.as_ref()) {
            p.image(
                flag.id(),
                Rect::from_center_size(mark.center(), vec2(38., 28.5)),
                Rect::from_min_max(pos2(0., 0.), pos2(1., 1.)),
                Color32::WHITE,
            );
        } else {
            p.rect_filled(mark, 8, BG);
            icon(p, mark.center(), Icon::Globe, DIM);
        }
        let name = WidgetText::from(RichText::new(&node.name).size(13.5).color(INK)).into_galley(
            ui,
            Some(TextWrapMode::Truncate),
            rect.width() - 155.,
            TextStyle::Body,
        );
        p.galley(rect.min + vec2(55., 8.), name, INK);
        let protocol = if node.network == "raw" {
            "TCP"
        } else {
            node.network.as_str()
        };
        p.text(
            rect.min + vec2(55., 30.),
            Align2::LEFT_TOP,
            format!("{}  ·  {}", self.location(node.country), protocol),
            FontId::proportional(11.),
            DIM,
        );
        let (ping, color) = match self.ping[index] {
            Ping::Untested => ("—".to_owned(), DIM),
            Ping::Measured(ms) => (format!("{ms} мс"), if ms < 450 { MINT } else { ALERT }),
            Ping::Failed => ("Нет ответа".to_owned(), ALERT),
        };
        p.text(
            rect.right_center() - vec2(32., 0.),
            Align2::RIGHT_CENTER,
            ping,
            FontId::proportional(12.),
            color,
        );
        let end = rect.right_center() - vec2(17., 0.);
        if online {
            p.circle_filled(end, 4., MINT);
        } else {
            icon(p, end, Icon::Arrow, DIM);
        }
        if response.clicked() && self.pending.is_none() {
            self.selected_group = None;
            self.selected = Some(index);
            self.preview = None;
        }
        if response.double_clicked() && self.active.is_none() && self.pending.is_none() {
            self.request(
                Message::Connect(Box::new(self.nodes[index].clone()), self.mode),
                "Проверяю подключение…",
            );
        }
    }

    fn settings_panel(&mut self, ui: &mut Ui) {
        ui.label(RichText::new("Настройки").size(30.).strong());
        ui.add_space(12.);
        Frame::new().fill(SURFACE).stroke(Stroke::new(1_f32,FRAME)).corner_radius(12)
            .inner_margin(17).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Режим подключения").size(17.).strong());
                ui.add_enabled_ui(self.pending.is_none() && self.active.is_none(), |ui| {
                    ui.radio_value(&mut self.mode,Mode::Proxy,"Локальный HTTP-прокси");
                    label(ui,"Адрес появится после подключения. Укажите его в настройках нужного приложения.",12.5,DIM);
                    ui.add_space(5.);
                    ui.radio_value(&mut self.mode,Mode::Tunnel,"VPN для Windows (TUN)");
                    label(ui,"Направляет системный трафик через Wintun. Нужен запуск от имени администратора.",12.5,DIM);
                });
                if self.mode == Mode::Tunnel && !runtime::is_admin() {
                    label(ui,"Для этого запуска права администратора не получены.",12.5,ALERT);
                }
            });
        ui.add_space(10.);
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1_f32, FRAME))
            .corner_radius(12)
            .inner_margin(17)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Автообновление подписки").size(17.).strong());
                let before = self.preferences.refresh_hours;
                ui.horizontal_wrapped(|ui| {
                    for (hours, title) in [
                        (0, "Выкл."),
                        (1, "Каждый час"),
                        (6, "Каждые 6 часов"),
                        (24, "Раз в сутки"),
                    ] {
                        ui.radio_value(&mut self.preferences.refresh_hours, hours, title);
                    }
                });
                label(
                    ui,
                    "Для подписок с HTTPS-адресом, пока Orbit VPN открыт.",
                    12.5,
                    DIM,
                );
                if before != self.preferences.refresh_hours {
                    self.update_refresh_policy();
                    if self.preferences.save().is_err() {
                        self.notice =
                            Some(("Не удалось сохранить период автообновления.".into(), true));
                    }
                }
            });
        ui.add_space(10.);
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1_f32, FRAME))
            .corner_radius(12)
            .inner_margin(17)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Проверка задержки").size(17.).strong());
                let before = self.preferences.method;
                ui.add_enabled_ui(self.pending.is_none(), |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.radio_value(
                            &mut self.preferences.method,
                            Method::Https,
                            "HTTPS Keep-Alive",
                        );
                        ui.radio_value(&mut self.preferences.method, Method::Tcp, "TCP");
                        ui.radio_value(&mut self.preferences.method, Method::Icmp, "ICMP");
                    });
                });
                let details = match self.preferences.method {
                    Method::Https => "Повторный запрос через сервер по открытому HTTPS-соединению.",
                    Method::Tcp => "Время подключения к TCP-порту сервера.",
                    Method::Icmp => {
                        "Время ответа на ICMP Echo. Некоторые серверы не отвечают на него."
                    }
                };
                label(ui, details, 12.5, DIM);
                if before != self.preferences.method {
                    self.ping.fill(Ping::Untested);
                    if self.preferences.save().is_err() {
                        self.notice = Some(("Не удалось сохранить способ проверки.".into(), true));
                    }
                }
            });
        ui.add_space(10.);
        Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1_f32, FRAME))
            .corner_radius(12)
            .inner_margin(17)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Глобус").size(17.).strong());
                ui.checkbox(&mut self.motion, "Плавный поворот");
                if let Some(index) = self.selected {
                    let mut pick = self.nodes[index].country;
                    ui.add_enabled_ui(self.active.is_none() && self.pending.is_none(), |ui| {
                        ComboBox::from_label("Страна выбранного сервера")
                            .selected_text(self.location(pick))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut pick, None, "Не определена");
                                let mut list: Vec<_> = self.countries.iter().enumerate().collect();
                                list.sort_by(|(_, a), (_, b)| a.ru.cmp(&b.ru));
                                for (id, country) in list {
                                    ui.selectable_value(&mut pick, Some(id), &country.ru);
                                }
                            });
                    });
                    self.nodes[index].country = pick;
                }
            });
        ui.add_space(12.);
        label(
            ui,
            "Подписка и способ проверки сохраняются в профиле Windows.",
            12.,
            DIM,
        );
        if let Some((note, true)) = self.notice.as_ref() {
            label(ui, note, 12., ALERT);
        }
    }

    fn import_modal(&mut self, ctx: &Context) {
        let modal = Modal::new(Id::new("subscription-modal")).show(ctx, |ui| {
            ui.set_width(440.);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Подписка VLESS").size(23.).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if rail_button(ui, Icon::Close, "Закрыть", false).clicked()
                        && self.pending.is_none()
                    {
                        self.import_open = false;
                    }
                });
            });
            label(
                ui,
                "HTTPS-адрес, vless://, список ссылок или конфигурация Mihomo.",
                13.,
                DIM,
            );
            ui.add_space(5.);
            ui.add_enabled_ui(self.pending.is_none(), |ui| {
                ui.add(
                    TextEdit::multiline(&mut self.source)
                        .desired_rows(5)
                        .desired_width(f32::INFINITY)
                        .hint_text("https://…"),
                );
            });
            if let Some((note, error)) = &self.notice {
                label(ui, note, 12., if *error { ALERT } else { DIM });
            }
            ui.add_space(5.);
            ui.add_enabled_ui(
                self.pending.is_none() && !self.source.trim().is_empty(),
                |ui| {
                    if action(ui, "Импортировать", true, vec2(154., 38.)).clicked() {
                        self.request(Message::Import(self.source.clone()), "Загружаю подписку…");
                    }
                },
            );
            if let Some(status) = self.pending {
                label(ui, status, 12., DIM);
            }
        });
        if modal.should_close() && self.pending.is_none() {
            self.import_open = false;
        }
    }
}

impl eframe::App for Orbit {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.receive();
        let ctx = ui.ctx().clone();
        let area = ui.max_rect();
        ui.painter().rect_filled(area, 0, BG);
        let rail = Rect::from_min_max(area.min, pos2(area.left() + 68., area.bottom()));
        self.sidebar(ui, rail);
        let split = rail.right() + (area.right() - rail.right()) * 0.515;
        let map = Rect::from_min_max(pos2(rail.right(), area.top()), pos2(split, area.bottom()));
        self.map(ui, map);
        let p = ui.painter();
        let panel = Rect::from_min_max(pos2(split, area.top()), area.max);
        p.rect_filled(panel, 0, Color32::from_rgb(13, 21, 25));
        p.line_segment(
            [panel.left_top(), panel.left_bottom()],
            Stroke::new(1_f32, FRAME),
        );
        let inside = panel.shrink2(vec2(25., 26.));
        ui.scope_builder(UiBuilder::new().max_rect(inside), |ui| match self.page {
            Page::Servers => self.server_panel(ui),
            Page::Settings => {
                ScrollArea::vertical().show(ui, |ui| self.settings_panel(ui));
            }
        });
        if self.import_open {
            self.import_modal(&ctx);
        }
        capture_frame(&ctx, self.snapshot.as_ref(), &mut self.capture_requested);
    }
}

fn capture_frame(ctx: &Context, path: Option<&PathBuf>, capture_requested: &mut bool) {
    if let Some(path) = path {
        let image = ctx.input(|input| {
            input.events.iter().find_map(|event| match event {
                eframe::egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = image {
            if let Ok(file) = std::fs::File::create(path) {
                let mut writer =
                    png::Encoder::new(file, image.width() as u32, image.height() as u32);
                writer.set_color(png::ColorType::Rgba);
                if let Ok(mut writer) = writer.write_header() {
                    let _ = writer.write_image_data(image.as_raw());
                }
            }
            ctx.send_viewport_cmd(ViewportCommand::Close);
        } else {
            let time = ctx.input(|input| input.time);
            if time > 1.1 && !*capture_requested {
                *capture_requested = true;
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(UserData::default()));
            } else if time > 5.0 {
                ctx.send_viewport_cmd(ViewportCommand::Close);
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(80));
            }
        }
    }
}

impl Drop for Orbit {
    fn drop(&mut self) {
        if let Some(scan) = self.scan.as_ref() {
            scan.cancel.store(true, Ordering::Relaxed);
        }
        self.failover_cancel.store(true, Ordering::Relaxed);
        let _ = self.send.send(Message::Exit);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn main() {
    if let Err(error) = run() {
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MessageBoxW};
            let text: Vec<u16> = format!("Не удалось запустить Orbit VPN.\n{error}")
                .encode_utf16()
                .chain([0])
                .collect();
            let title: Vec<u16> = "Orbit VPN".encode_utf16().chain([0]).collect();
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    text.as_ptr(),
                    title.as_ptr(),
                    MB_ICONERROR,
                );
            }
        }
        #[cfg(not(windows))]
        eprintln!("{error}");
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let snapshot = args
        .windows(2)
        .find(|pair| pair[0] == "--snapshot")
        .map(|pair| PathBuf::from(&pair[1]));
    let root = preferences::root()?;
    let current = std::env::current_exe()?;
    let run_app = args.iter().any(|argument| argument == "--run-app");
    let setup = args.iter().any(|argument| argument == "--install")
        || (!run_app && snapshot.is_none() && !setup::installed(&current, &root));
    #[cfg(windows)]
    if !setup && snapshot.is_none() && !runtime::is_admin() {
        if run_app {
            return Err("Для запуска Orbit VPN нужны права администратора.".into());
        }
        setup::request_elevation(&current)?;
        return Ok(());
    }
    let (size, min) = if setup {
        ([650., 390.], [625., 365.])
    } else {
        ([1320., 810.], [875., 620.])
    };
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_icon(Arc::new(IconData {
                rgba: include_bytes!("../assets/orbit.rgba").to_vec(),
                width: 64,
                height: 64,
            }))
            .with_inner_size(size)
            .with_min_inner_size(min),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    if setup {
        eframe::run_native(
            "Установка Orbit VPN",
            options,
            Box::new(move |cc| {
                Ok(Box::new(setup::Setup::new(
                    &cc.egui_ctx,
                    current,
                    root,
                    snapshot,
                )))
            }),
        )?;
    } else {
        let runtime = setup::prepare_runtime(&root)?;
        eframe::run_native(
            "Orbit VPN",
            options,
            Box::new(move |cc| Ok(Box::new(Orbit::new(&cc.egui_ctx, runtime, snapshot)))),
        )?;
    }
    Ok(())
}
