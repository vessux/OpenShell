// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests for `openshell sandbox create --volume`. Gated behind the
//! `e2e` feature because they require a running podman daemon and pull
//! the community python image.

#![cfg(feature = "e2e")]

use std::process::Command;
use tempfile::TempDir;

fn openshell_bin() -> &'static str {
    env!("CARGO_BIN_EXE_openshell")
}

#[test]
fn volume_bind_round_trips() {
    let host = TempDir::new().expect("tempdir");
    std::fs::write(host.path().join("marker"), b"hello").expect("write marker");
    let host_path = host.path().to_str().expect("tempdir is utf8").to_string();

    let out = Command::new(openshell_bin())
        .args([
            "sandbox",
            "create",
            "--from",
            "python",
            "--volume",
            &format!("{host_path}:/host-bind"),
            "--no-tty",
            "--no-keep",
            "--",
            "cat",
            "/host-bind/marker",
        ])
        .output()
        .expect("run openshell");

    assert!(
        out.status.success(),
        "openshell exited with {:?}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello"),
        "expected 'hello' in stdout, got: {stdout}"
    );
}

#[test]
fn volume_bind_ro_blocks_write() {
    let host = TempDir::new().expect("tempdir");
    let host_path = host.path().to_str().expect("tempdir is utf8").to_string();

    let out = Command::new(openshell_bin())
        .args([
            "sandbox",
            "create",
            "--from",
            "python",
            "--volume",
            &format!("{host_path}:/host-bind:ro"),
            "--no-tty",
            "--no-keep",
            "--",
            "sh",
            "-c",
            "touch /host-bind/x && echo OK || echo BLOCKED",
        ])
        .output()
        .expect("run openshell");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BLOCKED"),
        "expected ro mount to block write; stdout: {stdout}"
    );
}
