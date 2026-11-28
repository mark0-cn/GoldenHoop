#[test]
fn actual_cli_help_starts_on_the_platform_default_stack_without_credentials() {
    for args in [
        vec!["--help"],
        vec!["create", "--help"],
        vec!["isolated-create", "--help"],
        vec!["code-run", "--help"],
        vec!["snapshots", "--help"],
        vec!["snapshots", "create", "--help"],
        vec!["snapshots", "delete", "--help"],
        vec!["snapshots", "restore", "--help"],
        vec!["snapshots", "restoration", "--help"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_goldenhoop"))
            .args(&args)
            .env_remove("GOLDENHOOP_API_TOKEN")
            .output()
            .expect("start the actual CLI");
        assert!(
            output.status.success(),
            "CLI {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
}
