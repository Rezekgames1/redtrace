fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rerun-if-changed=binaries/audit-helper.sha256");
        if let Ok(hash) = std::fs::read_to_string("binaries/audit-helper.sha256") {
            let hash = hash.trim();
            assert!(hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
            println!("cargo:rustc-env=REDTRACE_AUDIT_HELPER_SHA256={hash}");
        }
    }
    tauri_build::build()
}
