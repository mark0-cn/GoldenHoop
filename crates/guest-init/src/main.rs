#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = goldenhoop_init::linux::run().await {
        eprintln!("goldenhoop guest init refused: {error}");
        if goldenhoop_init::is_guest_init_context() {
            // SAFETY: only actual root PID1 reaches this path; no host runner is started.
            unsafe {
                libc::reboot(libc::RB_POWER_OFF);
            }
        }
        std::process::exit(111);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("guest init requires Linux microVM PID1");
    std::process::exit(111);
}
