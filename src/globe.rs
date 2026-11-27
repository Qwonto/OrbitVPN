use crate::subscription::Country;
use eframe::egui::*;

pub const MINT: Color32 = Color32::from_rgb(126, 240, 194);
const EDGE: Color32 = Color32::from_rgb(35, 67, 68);
const LAND: Color32 = Color32::from_rgb(77, 151, 146);

struct Dot {
    x: f32,
    y: f32,
    z: f32,
    code: usize,
}

pub struct Globe {
    points: Vec<Dot>,
    lat: f32,
    lon: f32,
    target: (f32, f32),
}

impl Globe {
    pub fn new() -> Self {
        let load = |bytes: &[u8]| f32::from_le_bytes(bytes.try_into().unwrap());
        let points = include_bytes!("../assets/globe.bin")
            .chunks_exact(13)
            .map(|p| Dot {
                x: load(&p[0..4]),
                y: load(&p[4..8]),
                z: load(&p[8..12]),
                code: p[12].into(),
            })
            .collect();
        Self {
            points,
            lat: 26.0,
            lon: -34.0,
            target: (26.0, -34.0),
        }
    }

    pub fn look(&mut self, selected: Option<&Country>) {
        self.target = selected.map_or((26., -15.), |country| (country.lat, country.lon));
    }

    pub fn show(
        &mut self,
        ui: &mut Ui,
        rect: Rect,
        country: Option<(usize, &Country)>,
        online: bool,
        motion: bool,
    ) {
        if motion {
            let alpha = 1.0 - (-ui.input(|input| input.stable_dt.clamp(0.001, 0.05)) * 5.2).exp();
            let arc = (self.target.1 - self.lon + 180.).rem_euclid(360.) - 180.;
            if arc.abs() + (self.target.0 - self.lat).abs() > 0.02 {
                self.lon += arc * alpha;
                self.lat += (self.target.0 - self.lat) * alpha;
                ui.ctx().request_repaint();
            } else {
                self.lat = self.target.0;
                self.lon = self.target.1;
            }
        } else {
            (self.lat, self.lon) = self.target;
        }

        let size = rect.size();
        let radius = (size.x * 0.382).min(size.y * 0.412);
        let center = rect.center() + vec2(0., 7.);
        let painter = ui.painter_at(rect);
        let face = Color32::from_rgb(10, 26, 30);
        for i in (0..16).rev() {
            let k = i as f32 / 16.;
            painter.circle_filled(
                center,
                radius * (1.0 + k * 0.30),
                Color32::from_rgba_unmultiplied(34, 105, 98, (6. * (1. - k)).ceil() as u8),
            );
        }
        for i in 0..75 {
            let v = (i * 37 + 13) as f32 / 79.;
            let w = (i * 61 + 37) as f32 / 83.;
            let point = rect.min + vec2(v.fract() * size.x, w.fract() * size.y);
            if point.distance(center) > radius * 1.11 {
                painter.circle_filled(
                    point,
                    if i % 7 == 0 { 1.05 } else { 0.65 },
                    Color32::from_rgb(35, 50 + (i % 5) as u8 * 3, 56 + (i % 6) as u8 * 3),
                );
            }
        }
        painter.circle_filled(center, radius, face);
        painter.circle_stroke(center, radius + 1., Stroke::new(1_f32, EDGE));
        painter.circle_stroke(
            center,
            radius * 1.055,
            Stroke::new(0.7_f32, Color32::from_rgb(19, 48, 52)),
        );
        let (slon, clon) = self.lon.to_radians().sin_cos();
        let (slat, clat) = self.lat.to_radians().sin_cos();
        let project = |x: f32, y: f32, z: f32| {
            let east = x * clon - z * slon;
            let forward = x * slon + z * clon;
            let north = y * clat - forward * slat;
            let depth = y * slat + forward * clat;
            (center + vec2(east, -north) * radius, depth)
        };
        for spot in &self.points {
            let (point, z) = project(spot.x, spot.y, spot.z);
            if z <= 0.008 {
                continue;
            }
            let contrast = 0.23 + 0.77 * z.sqrt();
            let selected = country.is_some_and(|(id, _)| spot.code == id + 1);
            let color = if selected {
                MINT
            } else if spot.code > 0 {
                LAND
            } else {
                EDGE
            };
            let scale = (radius / 265.).clamp(0.55, 1.3);
            let dot = if selected {
                2.25
            } else if spot.code > 0 {
                1.70
            } else {
                0.96
            };
            painter.circle_filled(
                point,
                (0.63 + z * 0.37) * scale * dot,
                color.gamma_multiply(contrast),
            );
        }
        if let Some((_, country)) = country {
            let (slo, clo) = country.lon.to_radians().sin_cos();
            let (sla, cla) = country.lat.to_radians().sin_cos();
            let (point, depth) = project(slo * cla, sla, clo * cla);
            if depth > 0.02 {
                let light = if online {
                    MINT
                } else {
                    Color32::from_rgb(148, 218, 205)
                };
                painter.circle_filled(point, 16., light.gamma_multiply(0.14));
                painter.circle_stroke(point, 11., Stroke::new(1_f32, light.gamma_multiply(0.6)));
                painter.circle_filled(point, 4.6, light);
                let end = point + vec2(29., -27.);
                painter.line(
                    vec![point + vec2(9., -8.), end, end + vec2(22., 0.)],
                    Stroke::new(0.8_f32, light.gamma_multiply(0.65)),
                );
                painter.text(
                    end + vec2(27., -1.),
                    Align2::LEFT_CENTER,
                    &country.code,
                    FontId::monospace(11.),
                    light,
                );
            }
        }
        for angle in [0.0_f32, 90., 180., 270.] {
            let (s, c) = angle.to_radians().sin_cos();
            let direction = vec2(c, s);
            painter.line_segment(
                [
                    center + direction * (radius + 7.),
                    center + direction * (radius + 12.),
                ],
                Stroke::new(1_f32, EDGE),
            );
        }
    }
}
