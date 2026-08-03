use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn binary_starts_with_config_file() {
    let tmp_path = std::env::temp_dir().join(format!(
        "oauth2-test-server-config-{}.yaml",
        std::process::id()
    ));

    fs::write(
        &tmp_path,
        "scheme: http\nhost: 127.0.0.1\nport: 0\ndefault_user_id: test-user\n",
    )
    .expect("failed to write temporary config file");

    let mut child = Command::new(env!("CARGO_BIN_EXE_oauth2-test-server"))
        .arg("--config")
        .arg(&tmp_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start oauth2-test-server binary");

    thread::sleep(Duration::from_millis(400));

    if let Some(status) = child
        .try_wait()
        .expect("failed to check oauth2-test-server status")
    {
        let output = child
            .wait_with_output()
            .expect("failed to collect process output");
        panic!(
            "expected process to stay running, exited with status {status}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(tmp_path);
}

#[test]
fn binary_fails_on_missing_config_file() {
    let missing_path = std::env::temp_dir().join(format!(
        "oauth2-test-server-missing-{}.yaml",
        std::process::id()
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_oauth2-test-server"))
        .arg("--config")
        .arg(&missing_path)
        .output()
        .expect("failed to run oauth2-test-server binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to load config file"));
}
