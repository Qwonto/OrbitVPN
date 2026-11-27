use crate::{
    ALERT, BG, DIM, FRAME, INK, SURFACE, action, configure_theme,
    globe::{Globe, MINT},
    label, preferences,
};
use eframe::egui::*;
use flate2::read::ZlibDecoder;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
};

const FILES: [&str; 6] = [
    "xray.exe",
    "wintun.dll",
    "geoip.dat",
    "geosite.dat",
    "LICENSE",
    "LICENSE-Wintun",
];
const EXECUTABLE: &str = "Orbit VPN.exe";

pub fn executable(root: &Path) -> PathBuf {
    root.join(EXECUTABLE)
}

pub fn installed(current: &Path, root: &Path) -> bool {
    fs::canonicalize(executable(root))
        .is_ok_and(|expected| fs::canonicalize(current).is_ok_and(|actual| expected == actual))
}

pub fn prepare_runtime(root: &Path) -> io::Result<PathBuf> {
    let target = root.join("runtime-26.11.9");
    fs::create_dir_all(&target)?;
    let mut remaining: &[u8] = include_bytes!("../assets/runtime.pack");
    for filename in FILES {
        let (header, rest) = remaining.split_at(40);
        let packed = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let unpacked = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let digest = &header[8..40];
        let (entry, rest) = rest.split_at(packed);
        remaining = rest;
        let path = target.join(filename);
        if fs::read(&path)
            .is_ok_and(|data| data.len() == unpacked && &Sha256::digest(&data)[..] == digest)
        {
            continue;
        }
        let mut buffer = Vec::with_capacity(unpacked);
        ZlibDecoder::new(entry)
            .take(unpacked as u64 + 1)
            .read_to_end(&mut buffer)?;
        if buffer.len() != unpacked || &Sha256::digest(&buffer)[..] != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Embedded runtime checksum mismatch",
            ));
        }
        preferences::replace(&path, &buffer)?;
    }
    Ok(target.join("xray.exe"))
}

pub fn install_at(current: &Path, root: &Path, shortcut: bool) -> io::Result<PathBuf> {
    prepare_runtime(root)?;
    let destination = executable(root);
    if !installed(current, root) {
        preferences::replace(&destination, &fs::read(current)?)?;
    }
    preferences::replace(
        &root.join("FLAG-ICONS-LICENSE.txt"),
        include_bytes!("../assets/FLAG-ICONS-LICENSE.txt"),
    )?;
    if shortcut {
        let icon = destination.with_extension("ico");
        preferences::replace(&icon, include_bytes!("../assets/orbit.ico"))?;
        desktop_shortcut(&destination, &icon)?;
    }
    Ok(destination)
}

#[cfg(windows)]
pub fn request_elevation(executable: &Path) -> io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr::null};
    use windows_sys::Win32::{
        Foundation::ERROR_CANCELLED,
        System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize},
        UI::{
            Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW},
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };
    let path: Vec<_> = executable.as_os_str().encode_wide().chain([0]).collect();
    let verb: Vec<_> = "runas".encode_utf16().chain([0]).collect();
    let arguments: Vec<_> = "--run-app".encode_utf16().chain([0]).collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: verb.as_ptr(),
        lpFile: path.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    let initialized = unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) } >= 0;
    let started = unsafe { ShellExecuteExW(&mut info) };
    let outcome = if started == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            Ok(())
        } else {
            Err(error)
        }
    } else {
        Ok(())
    };
    if initialized {
        unsafe { CoUninitialize() };
    }
    outcome
}

#[cfg(windows)]
fn desktop_shortcut(executable: &Path, icon: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    let windows = PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(|| "C:/Windows".into()));
    let powershell = windows.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let command = r#"$ErrorActionPreference='Stop'
$sh=New-Object -ComObject WScript.Shell
$desktop=$sh.SpecialFolders.Item('Desktop')
$link=$sh.CreateShortcut((Join-Path $desktop 'Orbit VPN.lnk'))
$link.TargetPath=$env:ORBIT_SETUP_TARGET
$link.WorkingDirectory=Split-Path $env:ORBIT_SETUP_TARGET
$link.Description='Orbit VPN'
$link.IconLocation=$env:ORBIT_SETUP_ICON+',0'
$link.Save()"#;
    let result = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .env("ORBIT_SETUP_TARGET", executable)
        .env("ORBIT_SETUP_ICON", icon)
        .creation_flags(0x0800_0000)
        .status()?;
    if result.success() {
        Ok(())
    } else {
        Err(io::Error::other("Desktop shortcut could not be created"))
    }
}

#[cfg(not(windows))]
fn desktop_shortcut(_: &Path, _: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows desktop required",
    ))
}

pub struct Setup {
    source: PathBuf,
    root: PathBuf,
    desktop: bool,
    error: Option<String>,
    result: Option<PathBuf>,
    progress: Option<mpsc::Receiver<io::Result<PathBuf>>>,
    globe: Globe,
    snapshot: Option<PathBuf>,
    capture_requested: bool,
}

impl Setup {
    pub fn new(ctx: &Context, source: PathBuf, root: PathBuf, snapshot: Option<PathBuf>) -> Self {
        configure_theme(ctx);
        Self {
            source,
            root,
            desktop: true,
            error: None,
            result: None,
            progress: None,
            globe: Globe::new(),
            snapshot,
            capture_requested: false,
        }
    }

    fn begin(&mut self, ctx: &Context) {
        let (sender, receiver) = mpsc::channel();
        self.progress = Some(receiver);
        self.error = None;
        let (source, root, desktop, ctx) = (
            self.source.clone(),
            self.root.clone(),
            self.desktop,
            ctx.clone(),
        );
        std::thread::spawn(move || {
            let result = install_at(&source, &root, desktop);
            let _ = sender.send(result);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for Setup {
    fn ui(&mut self, ui: &mut Ui, _: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(result) = self
            .progress
            .as_ref()
            .and_then(|progress| progress.try_recv().ok())
        {
            self.progress = None;
            match result {
                Ok(path) => self.result = Some(path),
                Err(error) => {
                    self.error = Some(
                        if error.kind() == io::ErrorKind::PermissionDenied
                            || error.raw_os_error() == Some(32)
                        {
                            "Закройте открытый Orbit VPN и повторите установку.".into()
                        } else {
                            format!("Ошибка установки: {error}")
                        },
                    )
                }
            }
        }
        let area = ui.max_rect();
        let split = area.left() + area.width() * 0.39;
        let left = Rect::from_min_max(area.min, pos2(split, area.bottom()));
        let right = Rect::from_min_max(pos2(split, area.top()), area.max);
        ui.painter().rect_filled(area, 0, BG);
        ui.painter().rect_filled(right, 0, SURFACE);
        ui.painter().line_segment(
            [right.left_top(), right.left_bottom()],
            Stroke::new(1_f32, FRAME),
        );
        self.globe
            .show(ui, left.shrink2(vec2(5., 22.)), None, false, false);
        ui.painter().text(
            left.center_bottom() - vec2(0., 26.),
            Align2::CENTER_CENTER,
            "Orbit VPN",
            FontId::proportional(17.),
            MINT,
        );
        let body = right.shrink2(vec2(26., 28.));
        ui.scope_builder(UiBuilder::new().max_rect(body), |ui| {
            let done = self.result.is_some();
            label(
                ui,
                if done {
                    "Установка завершена"
                } else {
                    "Установка Orbit VPN"
                },
                25.,
                INK,
            );
            ui.add_space(7.);
            if let Some(path) = self.result.as_ref() {
                label(
                    ui,
                    if self.desktop {
                        "Ярлык Orbit VPN на рабочем столе."
                    } else {
                        "Orbit VPN готов к запуску."
                    },
                    14.,
                    DIM,
                );
                ui.add_space(22.);
                if action(
                    ui,
                    "Открыть Orbit VPN",
                    true,
                    vec2(ui.available_width(), 42.),
                )
                .clicked()
                {
                    match Command::new(path).spawn() {
                        Ok(_) => ctx.send_viewport_cmd(ViewportCommand::Close),
                        Err(error) => {
                            self.error = Some(format!("Не удалось открыть Orbit VPN: {error}"))
                        }
                    }
                }
            } else {
                label(ui, "Установка в ваш профиль Windows.", 14., DIM);
                ui.add_space(9.);
                label(ui, &self.root.to_string_lossy(), 11.5, DIM);
                ui.add_space(10.);
                ui.add_enabled_ui(self.progress.is_none(), |ui| {
                    ui.checkbox(&mut self.desktop, "Создать ярлык на рабочем столе");
                    ui.add_space(7.);
                    if action(ui, "Установить", true, vec2(ui.available_width(), 42.)).clicked()
                    {
                        self.begin(&ctx);
                    }
                });
            }
            if self.progress.is_some() {
                ui.add(ProgressBar::new(0.5).animate(true).text("Установка…"));
                ctx.request_repaint_after(std::time::Duration::from_millis(70));
            }
            if let Some(error) = self.error.as_ref() {
                label(ui, error, 12.5, ALERT);
            }
        });
        crate::capture_frame(&ctx, self.snapshot.as_ref(), &mut self.capture_requested);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_bundle_installs_with_no_adjacent_files() {
        let root = std::env::temp_dir().join(format!("orbit-setup-test-{}", std::process::id()));
        let destination = install_at(&std::env::current_exe().unwrap(), &root, false).unwrap();
        assert!(destination.is_file());
        let engine = prepare_runtime(&root).unwrap();
        assert!(engine.is_file());
        fs::write(&engine, b"invalid").unwrap();
        assert_eq!(prepare_runtime(&root).unwrap(), engine);
        assert!(fs::metadata(engine).unwrap().len() > 20_000_000);
        for name in FILES {
            fs::remove_file(root.join("runtime-26.11.9").join(name)).unwrap();
        }
        fs::remove_dir(root.join("runtime-26.11.9")).unwrap();
        fs::remove_file(destination).unwrap();
        fs::remove_file(root.join("FLAG-ICONS-LICENSE.txt")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
