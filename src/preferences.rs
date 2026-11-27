use crate::{probe::Method, subscription::Subscription};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
#[derive(Deserialize, Serialize)]
#[serde(default)]
pub struct Preferences {
    pub source: String,
    pub subscription: Option<Subscription>,
    pub method: Method,
    pub refresh_hours: u32,
    pub refreshed_at: u64,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            source: String::new(),
            subscription: None,
            method: Method::default(),
            refresh_hours: 6,
            refreshed_at: 0,
        }
    }
}

pub fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
pub fn root() -> io::Result<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(|path| PathBuf::from(path).join("Orbit VPN"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "LOCALAPPDATA is unavailable"))
}
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
impl Preferences {
    pub fn read() -> io::Result<Self> {
        Self::read_at(&root()?)
    }
    pub fn save(&self) -> io::Result<()> {
        self.save_at(&root()?)
    }
    fn read_at(path: &Path) -> io::Result<Self> {
        let bytes = match fs::read(path.join("preferences.dat")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        Ok(serde_json::from_slice(&crypt(&bytes, false)?)?)
    }
    fn save_at(&self, path: &Path) -> io::Result<()> {
        let encrypted = crypt(&serde_json::to_vec(self)?, true)?;
        fs::create_dir_all(path)?;
        replace(&path.join("preferences.dat"), &encrypted)
    }
}
#[cfg(windows)]
fn crypt(bytes: &[u8], protect: bool) -> io::Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(io::Error::other)?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut result = CRYPT_INTEGER_BLOB::default();
    let flags = CRYPTPROTECT_UI_FORBIDDEN;
    unsafe {
        let ok = if protect {
            CryptProtectData(&input, null(), null(), null(), null(), flags, &mut result)
        } else {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                flags,
                &mut result,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let output = std::slice::from_raw_parts(result.pbData, result.cbData as usize).to_vec();
        LocalFree(result.pbData.cast());
        Ok(output)
    }
}
#[cfg(not(windows))]
fn crypt(_: &[u8], _: bool) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows DPAPI is required",
    ))
}
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn persists_encrypted_subscription_and_method() {
        let path = std::env::temp_dir().join(format!("orbit-prefs-{}", std::process::id()));
        let source = "https://example.invalid/private-subscription";
        let sample =
            b"vless://5164ed2c-b2ef-4ed1-bc5a-ea64c242c520@nl.example.invalid:443#Amsterdam";
        let prefs = Preferences {
            source: source.into(),
            method: Method::Icmp,
            refresh_hours: 24,
            refreshed_at: 1234,
            subscription: Some(
                crate::subscription::parse(sample, &crate::subscription::countries()).unwrap(),
            ),
        };
        prefs.save_at(&path).unwrap();
        prefs.save_at(&path).unwrap();
        let raw = fs::read(path.join("preferences.dat")).unwrap();
        assert!(
            !raw.windows(source.len())
                .any(|part| part == source.as_bytes())
        );
        let loaded = Preferences::read_at(&path).unwrap();
        assert_eq!(loaded.source, source);
        assert_eq!(loaded.method, Method::Icmp);
        assert_eq!((loaded.refresh_hours, loaded.refreshed_at), (24, 1234));
        assert_eq!(
            loaded.subscription.unwrap().nodes[0].host,
            "nl.example.invalid"
        );
        fs::remove_file(path.join("preferences.dat")).unwrap();
        fs::remove_dir(path).unwrap();
    }
}
