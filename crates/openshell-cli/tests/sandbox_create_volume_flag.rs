// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Smoke tests that verify the `--volume` flag is registered on `sandbox create`.
//!
//! These tests run the compiled `openshell` binary and inspect exit codes / help
//! output — no gRPC server required.

use std::process::Command;

fn openshell_bin() -> String {
    // Cargo sets CARGO_BIN_EXE_<binary-name> for integration tests in the same
    // crate. Fall back to a cargo-run invocation for environments where the
    // pre-built binary is not cached.
    std::env::var("CARGO_BIN_EXE_openshell")
        .unwrap_or_else(|_| "cargo run -p openshell-cli --".to_string())
}

/// Assert that `--volume` appears in `sandbox create --help`.
#[test]
fn volume_flag_appears_in_help() {
    let bin = openshell_bin();
    let output = Command::new(&bin)
        .args(["sandbox", "create", "--help"])
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(
        combined.contains("--volume"),
        "expected --volume in `sandbox create --help` output, got:\n{combined}"
    );
}

/// Passing `--volume /host:/container` must be accepted (exit 0 up to the
/// gateway connection attempt; before any gateway is reachable the command
/// exits non-zero due to connection failure, but the argument must at least
/// parse without a clap error).
///
/// We detect a clap parse error (exit code 2) vs a runtime error (exit != 2).
#[test]
fn volume_flag_two_field_spec_parses() {
    let bin = openshell_bin();
    let output = Command::new(&bin)
        .args([
            "sandbox",
            "create",
            "--from",
            "python",
            "--volume",
            "/host:/container",
        ])
        .env("OPENSHELL_ENDPOINT", "https://127.0.0.1:1") // unreachable → runtime error, not clap error
        .env("XDG_CONFIG_HOME", std::env::temp_dir().to_str().unwrap())
        .env("HOME", std::env::temp_dir().to_str().unwrap())
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    assert_ne!(
        output.status.code(),
        Some(2),
        "--volume /host:/container should not produce a clap parse error (exit 2);\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Three-field spec `<HOST>:<CONTAINER>:ro` must also parse without a clap error.
#[test]
fn volume_flag_three_field_ro_spec_parses() {
    let bin = openshell_bin();
    let output = Command::new(&bin)
        .args([
            "sandbox",
            "create",
            "--from",
            "python",
            "--volume",
            "/host:/container:ro",
        ])
        .env("OPENSHELL_ENDPOINT", "https://127.0.0.1:1")
        .env("XDG_CONFIG_HOME", std::env::temp_dir().to_str().unwrap())
        .env("HOME", std::env::temp_dir().to_str().unwrap())
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    assert_ne!(
        output.status.code(),
        Some(2),
        "--volume /host:/container:ro should not produce a clap parse error (exit 2);\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The flag must be repeatable: two `--volume` flags on the same invocation.
#[test]
fn volume_flag_repeats() {
    let bin = openshell_bin();
    let output = Command::new(&bin)
        .args([
            "sandbox", "create", "--from", "python", "--volume", "/a:/b", "--volume", "/c:/d:ro",
        ])
        .env("OPENSHELL_ENDPOINT", "https://127.0.0.1:1")
        .env("XDG_CONFIG_HOME", std::env::temp_dir().to_str().unwrap())
        .env("HOME", std::env::temp_dir().to_str().unwrap())
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    assert_ne!(
        output.status.code(),
        Some(2),
        "repeated --volume flags should not produce a clap parse error (exit 2);\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
