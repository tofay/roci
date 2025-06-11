//! Integration Tests for rpmoci
use std::{
    fs::{self},
    path::{Path, PathBuf},
    process::Command,
};

use test_temp_dir::TestTempDir;

// Path to ro binary under test
const EXE: &str = env!("CARGO_BIN_EXE_roci");

fn setup_test(fixture: &str) -> (TestTempDir, PathBuf) {
    // the test_temp_dir macro can't handle the integration test module path not containing ::,
    // so construct our own item path
    let out = test_temp_dir::TestTempDir::from_complete_item_path(&format!(
        "it::{}",
        std::thread::current().name().unwrap()
    ));
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/")
        .join(fixture);
    fs::copy(
        root.join("roci.toml"),
        out.as_path_untracked().join("roci.toml"),
    )
    .unwrap();

    let path = out.as_path_untracked().to_path_buf();
    (out, path)
}

fn build_and_run(image: &str, should_succeed: bool) -> std::process::Output {
    let (_tmp_dir, root) = setup_test(image);
    let status = Command::new(EXE)
        .arg("--tag=test")
        .arg(image)
        .env("RUST_LOG", "trace")
        .current_dir(&root)
        .status()
        .expect("failed to run rpmoci");
    assert!(status.success());
    copy_to_docker(image, &root);
    let output = Command::new("docker")
        .arg("run")
        .arg(format!("{}:test", image))
        .output()
        .expect("failed to run container");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    eprintln!("stderr: {}", stderr);
    if should_succeed {
        assert!(output.status.success());
    } else {
        assert!(!output.status.success());
    }
    output
}

fn copy_to_docker(image: &str, root: impl AsRef<Path>) {
    let status = Command::new("skopeo")
        .arg("copy")
        .arg(format!("oci:{}:test", image))
        .arg(format!("docker-daemon:{}:test", image))
        .current_dir(root.as_ref())
        .status()
        .expect("failed to run skopeo");
    assert!(status.success());
}

#[test]
fn test_curl() {
    // curl test includes linux-vdso, which should be skipped
    // and a cert file that is not an ELF file
    build_and_run("curl", true);
}
