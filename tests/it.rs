//! Integration Tests for gnoci
use std::{
    fs::{self},
    path::{Path, PathBuf},
    process::Command,
};

use test_temp_dir::TestTempDir;

// Path to binary under test
const EXE: &str = env!("CARGO_BIN_EXE_gnoci");

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
        root.join("gnoci.toml"),
        out.as_path_untracked().join("gnoci.toml"),
    )
    .unwrap();

    let path = out.as_path_untracked().to_path_buf();
    (out, path)
}

fn build_and_run(image: &str, root: &Path, should_succeed: bool) -> std::process::Output {
    build(image, root);
    let status = Command::new("skopeo")
        .arg("copy")
        .arg(format!("oci:{image}:test"))
        .arg(format!("docker-daemon:{image}:test"))
        .current_dir(root)
        .status()
        .expect("failed to run skopeo");
    assert!(status.success());
    let output = Command::new("docker")
        .arg("run")
        .arg(format!("{image}:test"))
        .output()
        .expect("failed to run container");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    eprintln!("stderr: {stderr}");
    if should_succeed {
        assert!(output.status.success());
    } else {
        assert!(!output.status.success());
    }
    output
}

fn build(image: &str, root: &Path) {
    let status = Command::new(EXE)
        .arg("--tag=test")
        .arg(image)
        .env("RUST_LOG", "trace")
        .current_dir(root)
        .status()
        .expect("failed to run gnoci");
    assert!(status.success());
}

#[test]
fn test_run() {
    let image = "curl-ubuntu";
    let (_tmp_dir, root) = setup_test(image);
    // curl test includes linux-vdso, which should be skipped
    // and a cert file that is not an ELF file
    build_and_run(image, &root, true);
}

#[test]
fn test_trivy() {
    let image = "curl-ubuntu";
    let (_tmp_dir, root) = setup_test(image);
    build(image, &root);

    // check trivy can scan the image. Get a json spdx and check for packages
    let output = Command::new("trivy")
        .arg("image")
        .arg("--format=json")
        .arg("--list-all-pkgs")
        .arg("--input")
        .arg(format!("./{image}"))
        .current_dir(&root)
        .output()
        .expect("failed to run trivy");
    assert!(
        output.status.success(),
        "trivy failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    // parse with serde_json
    let trivy_output: serde_json::Value =
        serde_json::from_str(stdout).expect("failed to parse json");

    eprintln!("Trivy output: {trivy_output:?}");
    let package_names = trivy_output
        .get("Results")
        .and_then(|results| results.as_array().and_then(|arr| arr.first()))
        .expect("Results should be an array")
        .get("Packages")
        .and_then(|packages| packages.as_array())
        .expect("Packages should be an array")
        .iter()
        .map(|pkg| {
            pkg.get("Name")
                .and_then(|name| name.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    eprintln!("Packages: {package_names:?}");
    // Check for a few specific packages
    assert!(package_names.contains(&"curl"));
    assert!(package_names.contains(&"libssl3t64"));
    assert!(package_names.contains(&"libgnutls30t64"));
}

#[test]
fn test_syft() {
    let image = "curl-ubuntu";
    let (_tmp_dir, root) = setup_test(image);
    build(image, &root);

    // check syft can scan the image
    let output = Command::new("syft")
        .arg("scan")
        .arg(format!("oci-dir:{image}"))
        .current_dir(&root)
        .output()
        .expect("failed to run trivy");
    assert!(
        output.status.success(),
        "syft failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    eprintln!("syft stdout: {stdout}");
    // Check for a few specific packages
    assert!(stdout.contains("libcurl4t64"));
    assert!(stdout.contains("libk5crypto3"));
}
