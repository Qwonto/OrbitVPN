use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=assets/orbit.ico");
    println!("cargo:rerun-if-changed=assets/orbit.rc");
    println!("cargo:rerun-if-env-changed=WINDRES");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let assets = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("assets");
    let (mut compiler, resource) = if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let resource = output.join("orbit.res");
        let mut compiler = Command::new("rc.exe");
        compiler
            .arg("/nologo")
            .arg("/fo")
            .arg(&resource)
            .arg("orbit.rc");
        (compiler, resource)
    } else {
        let resource = output.join("orbit-icon.o");
        let mut compiler =
            Command::new(env::var_os("WINDRES").unwrap_or_else(|| "windres.exe".into()));
        compiler
            .args(["-i", "orbit.rc", "-O", "coff", "-o"])
            .arg(&resource);
        (compiler, resource)
    };
    let status = compiler
        .current_dir(assets)
        .status()
        .expect("Windows icon resource compiler");
    assert!(status.success(), "Could not compile the Orbit VPN icon");
    println!("cargo:rustc-link-arg-bin=orbit-vpn={}", resource.display());
}
