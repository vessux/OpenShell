// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Smoke tests that verify the `--volume` flag is registered on `sandbox create`.
//!
//! These tests run the compiled `openshell` binary and inspect exit codes / help
//! output — no gRPC server required.
//!
//! # Why subprocess instead of in-process
//!
//! `Cli` is a private type in `main.rs`, so `Cli::command()` / `Cli::try_parse_from`
//! cannot be called from tests. The public `run::sandbox_create` entry point accepts
//! already-parsed arguments, so calling it directly would bypass clap entirely. The
//! lifecycle integration test (`sandbox_create_lifecycle_integration.rs`) tests the
//! *runtime* path and requires a full mock gRPC+TLS server — that infrastructure is
//! out of scope for a pure parse-acceptance check.
//!
//! We therefore retain the subprocess approach. With `HOME` and `XDG_CONFIG_HOME`
//! pointing to an empty temp directory, no gateway is configured, so the binary
//! immediately exits with code 1 ("No active gateway") before any network I/O.
//! A clap parse failure exits with code 2; the test asserts the exact value is 1.

use std::process::Command;

/// Canonical path to the compiled `openshell` binary.
///
/// `CARGO_BIN_EXE_openshell` is set by Cargo for every integration test in the
/// same crate. Using `env!` fails at compile time rather than silently falling
/// back to a broken runtime path.
fn openshell_bin() -> &'static str {
    env!("CARGO_BIN_EXE_openshell")
}

/// Assert that `--volume` appears in `sandbox create --help`.
#[test]
fn volume_flag_appears_in_help() {
    let bin = openshell_bin();
    let output = Command::new(bin)
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

/// Passing `--volume /host:/container` must be accepted by clap.
///
/// With no gateway configured (empty HOME / XDG_CONFIG_HOME) the binary exits
/// with code 1 ("No active gateway") before any network I/O. A clap parse
/// failure would produce exit code 2. We assert the exact code is 1 to confirm
/// clap accepted the flag and only the runtime path failed.
#[test]
fn volume_flag_two_field_spec_parses() {
    let bin = openshell_bin();
    let output = Command::new(bin)
        .args([
            "sandbox",
            "create",
            "--from",
            "python",
            "--volume",
            "/host:/container",
        ])
        .env("XDG_CONFIG_HOME", std::env::temp_dir().to_str().unwrap())
        .env("HOME", std::env::temp_dir().to_str().unwrap())
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    let exit_code = output.status.code();
    assert_eq!(
        exit_code,
        Some(1),
        "--volume /host:/container should fail with exit 1 (no gateway configured), \
         not 2 (clap parse error) or 0 (unexpected success); \
         got exit {exit_code:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Three-field spec `<HOST>:<CONTAINER>:ro` must also parse without a clap error.
#[test]
fn volume_flag_three_field_ro_spec_parses() {
    let bin = openshell_bin();
    let output = Command::new(bin)
        .args([
            "sandbox",
            "create",
            "--from",
            "python",
            "--volume",
            "/host:/container:ro",
        ])
        .env("XDG_CONFIG_HOME", std::env::temp_dir().to_str().unwrap())
        .env("HOME", std::env::temp_dir().to_str().unwrap())
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    let exit_code = output.status.code();
    assert_eq!(
        exit_code,
        Some(1),
        "--volume /host:/container:ro should fail with exit 1 (no gateway configured), \
         not 2 (clap parse error) or 0 (unexpected success); \
         got exit {exit_code:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The flag must be repeatable: two `--volume` flags on the same invocation.
#[test]
fn volume_flag_repeats() {
    let bin = openshell_bin();
    let output = Command::new(bin)
        .args([
            "sandbox", "create", "--from", "python", "--volume", "/a:/b", "--volume", "/c:/d:ro",
        ])
        .env("XDG_CONFIG_HOME", std::env::temp_dir().to_str().unwrap())
        .env("HOME", std::env::temp_dir().to_str().unwrap())
        .output()
        .unwrap_or_else(|_| panic!("failed to run {bin}"));

    let exit_code = output.status.code();
    assert_eq!(
        exit_code,
        Some(1),
        "repeated --volume flags should fail with exit 1 (no gateway configured), \
         not 2 (clap parse error) or 0 (unexpected success); \
         got exit {exit_code:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
