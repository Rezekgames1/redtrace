#[cfg(windows)]
fn main() {
    if let Err(error) = redtrace::audit::helper::serve() {
        eprintln!("audit helper: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows audit helper requires Windows");
    std::process::exit(1);
}
