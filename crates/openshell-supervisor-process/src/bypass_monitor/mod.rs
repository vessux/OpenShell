// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bypass detection monitor — tails kernel log messages via `dmesg --follow`
//! to detect and report direct connection attempts that bypass the HTTP
//! CONNECT proxy.
//!
//! When the sandbox network namespace has nftables log rules installed (see
//! `NetworkNamespace::install_bypass_rules`), the kernel writes a log line for
//! each dropped packet. This module reads those messages, parses the nftables
//! LOG format, and emits structured tracing events + denial aggregator entries.
//!
//! ## Graceful degradation
//!
//! Reading the kernel ring buffer requires `CAP_SYSLOG` to be satisfied
//! against the *initial* user namespace (`kernel.dmesg_restrict`). Rootful
//! container runtimes typically satisfy that directly; rootless runtimes that
//! nest the user namespace (e.g. rootless Podman) cannot — `cap_add
//! CAP_SYSLOG` only grants the capability inside the nested namespace, and
//! the kernel check is against the outer one, so the read fails with EPERM
//! even though the capability is present. Since this varies by runtime and
//! configuration, availability is probed empirically at startup with a real
//! read rather than assumed.
//!
//! If the probe (or the `dmesg --follow` reader itself) fails, the monitor
//! reports itself **degraded** — a `ConfigStateChange` OCSF event plus a
//! `warn!` log, emitted once per monitor lifetime — and stops. This is not
//! fatal: the nftables REJECT rules installed by
//! `NetworkNamespace::install_bypass_rules` still provide fast-fail UX
//! independent of this monitor; only the diagnostic visibility into bypass
//! attempts is lost.

mod procfs;

use openshell_core::activity::{ActivitySender, try_record_activity};
use openshell_core::denial::DenialEvent;
use openshell_ocsf::{
    ActionId, ActivityId, ConfidenceId, ConfigStateChangeBuilder, DetectionFindingBuilder,
    DispositionId, Endpoint, FindingInfo, NetworkActivityBuilder, Process, SeverityId, StateId,
    StatusId, ocsf_emit,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// A parsed nftables log entry from `/dev/kmsg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassEvent {
    /// Destination IP address.
    pub dst_addr: String,
    /// Destination port.
    pub dst_port: u16,
    /// Source port (used for process identity resolution).
    pub src_port: u16,
    /// Protocol (TCP or UDP).
    pub proto: String,
    /// UID of the process that initiated the connection.
    pub uid: Option<u32>,
}

/// Parse a nftables log line from `/dev/kmsg`.
///
/// Expected format (from the kernel LOG target):
/// ```text
/// ...,;openshell:bypass:<ns-id>:IN= OUT=veth-s-... SRC=10.200.0.2 DST=93.184.216.34
///  LEN=60 ... PROTO=TCP SPT=48012 DPT=443 ... UID=1000
/// ```
///
/// Returns `None` if the line doesn't match the expected prefix or is malformed.
pub fn parse_kmsg_line(line: &str, namespace_prefix: &str) -> Option<BypassEvent> {
    // Check that this line contains our namespace prefix.
    let prefix_pos = line.find(namespace_prefix)?;
    let relevant = &line[prefix_pos + namespace_prefix.len()..];

    let dst_addr = extract_field(relevant, "DST=")?;
    let dst_port = extract_field(relevant, "DPT=")?.parse::<u16>().ok()?;
    let src_port = extract_field(relevant, "SPT=")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let proto = extract_field(relevant, "PROTO=")
        .unwrap_or_else(|| "unknown".to_string())
        .to_lowercase();
    let uid = extract_field(relevant, "UID=").and_then(|s| s.parse::<u32>().ok());

    Some(BypassEvent {
        dst_addr,
        dst_port,
        src_port,
        proto,
        uid,
    })
}

/// Extract a single space-delimited field value from a nftables log line.
///
/// Given `"DST="` and a string like `"...DST=93.184.216.34 LEN=60..."`,
/// returns `Some("93.184.216.34")`.
fn extract_field(s: &str, key: &str) -> Option<String> {
    let start = s.find(key)? + key.len();
    let rest = &s[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let value = &rest[..end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Report the bypass monitor as degraded: it could not read the kernel ring
/// buffer, so bypass attempts will not be logged or aggregated. The
/// nftables REJECT rules installed by `NetworkNamespace::install_bypass_rules`
/// are a separate mechanism and still provide fast-fail UX.
///
/// Callers must invoke this at most once per monitor lifetime (on the
/// startup probe failing, or on the `dmesg --follow` reader exiting) —
/// never per read attempt or loop iteration — so a degraded monitor cannot
/// turn into a log-volume problem of its own.
fn report_degraded(reason: &str) {
    warn!(
        reason,
        "Bypass detection monitor degraded: kernel ring buffer read failed; \
         nftables REJECT rules still provide fast-fail, but bypass attempts \
         will not be logged"
    );
    let event = ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .state(StateId::Disabled, "degraded")
        .message(format!(
            "Bypass detection monitor degraded: {reason}. nftables REJECT rules \
             still provide fast-fail; diagnostic visibility into bypass attempts \
             is unavailable."
        ))
        .build();
    ocsf_emit!(event);
}

/// Describe why a process exited unsuccessfully, preferring its own stderr
/// (e.g. `read kernel buffer failed: Operation not permitted`) over the bare
/// exit status.
fn describe_failure(status: std::process::ExitStatus, stderr: &str) -> String {
    let stderr = stderr.trim();
    if stderr.is_empty() {
        format!("exited with {status}")
    } else {
        stderr.to_string()
    }
}

/// Probe whether reading the kernel ring buffer via `program args...` is
/// actually permitted, by running it to completion (no `--follow`) and
/// checking its exit status.
///
/// This is the real-read gate that replaces `dmesg --version`: `--version`
/// only proves the binary execs, which says nothing about whether
/// `kernel.dmesg_restrict` will let the read itself succeed. Under a nested
/// user namespace (rootless Podman) the read fails with EPERM even though
/// `dmesg` execs fine and `CAP_SYSLOG` is present in the container's own
/// capability set — see the module docs.
fn probe_ring_buffer_read(program: &str, args: &[&str]) -> Result<(), String> {
    use std::process::{Command, Stdio};

    match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(describe_failure(
            output.status,
            &String::from_utf8_lossy(&output.stderr),
        )),
        Err(e) => Err(format!("failed to exec {program}: {e}")),
    }
}

/// Generate a protocol-appropriate hint for the bypass event.
fn hint_for_event(event: &BypassEvent) -> &'static str {
    if event.proto == "udp" && event.dst_port == 53 {
        "DNS queries should route through the sandbox proxy; check resolver configuration"
    } else if event.proto == "udp" {
        "UDP traffic must route through the sandbox proxy"
    } else {
        "ensure process honors HTTP_PROXY/HTTPS_PROXY; for Node.js set NODE_USE_ENV_PROXY=1"
    }
}

/// Spawn the bypass monitor as a background tokio task.
///
/// Uses `dmesg --follow` to tail the kernel ring buffer for nftables log
/// entries matching the given namespace.
///
/// We use `dmesg` rather than reading `/dev/kmsg` directly because the
/// container runtime's device cgroup policy blocks direct `/dev/kmsg` access
/// even with `CAP_SYSLOG`. The `dmesg` command reads via the `syslog(2)`
/// syscall which is permitted with `CAP_SYSLOG` — *when* that capability is
/// checked against the same user namespace it was granted in; see the module
/// docs for why that can still fail under rootless runtimes.
///
/// Returns a `JoinHandle` if the monitor started, or `None` if the kernel
/// ring buffer could not be read (reported as degraded; see
/// `report_degraded`).
pub fn spawn(
    namespace_name: String,
    entrypoint_pid: Arc<AtomicU32>,
    denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
    activity_tx: Option<ActivitySender>,
) -> Option<tokio::task::JoinHandle<()>> {
    use std::io::{BufRead, Read};
    use std::process::{Command, Stdio};

    // A one-shot (non-follow) read exercises the same permission check as
    // `--follow` without blocking.
    if let Err(reason) = probe_ring_buffer_read("dmesg", &["--notime"]) {
        report_degraded(&reason);
        return None;
    }

    let namespace_prefix = format!("openshell:bypass:{namespace_name}:");
    debug!(
        namespace = %namespace_name,
        "Starting bypass detection monitor via dmesg --follow"
    );

    let handle = tokio::task::spawn_blocking(move || {
        // Start dmesg in follow mode to tail new kernel messages.
        let mut child = match Command::new("dmesg")
            .args(["--follow", "--notime"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                report_degraded(&format!("failed to start dmesg --follow: {e}"));
                return;
            }
        };

        let Some(stdout) = child.stdout.take() else {
            report_degraded("dmesg --follow produced no stdout");
            let _ = child.kill();
            let _ = child.wait();
            return;
        };

        // Drain stderr on a separate thread so a full pipe buffer never
        // blocks the follow reader; the captured text is only used if the
        // reader loop below ends (which — absent an external kill during
        // supervisor shutdown — means dmesg itself exited or failed) so we
        // can report *why*, instead of silently discarding it as before.
        let stderr_capture = child.stderr.take().map(|mut stderr| {
            std::thread::spawn(move || {
                let mut buf = String::new();
                let _ = stderr.read_to_string(&mut buf);
                buf
            })
        });

        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    debug!(error = %e, "Error reading dmesg line, continuing");
                    continue;
                }
            };

            let Some(event) = parse_kmsg_line(&line, &namespace_prefix) else {
                continue;
            };

            // Attempt process identity resolution (best-effort, TCP only).
            let pid = entrypoint_pid.load(Ordering::Acquire);
            let (binary, binary_pid, ancestors) =
                if event.proto == "tcp" && event.src_port > 0 && pid > 0 {
                    resolve_process_identity(pid, event.src_port)
                } else {
                    ("-".to_string(), "-".to_string(), "-".to_string())
                };

            let hint = hint_for_event(&event);
            let reason = "direct connection bypassed HTTP CONNECT proxy";

            // Dual-emit: Network Activity [4001] + Detection Finding [2004]
            {
                let dst_ep = if let Ok(ip) = event.dst_addr.parse::<std::net::IpAddr>() {
                    Endpoint::from_ip(ip, event.dst_port)
                } else {
                    Endpoint::from_domain(&event.dst_addr, event.dst_port)
                };

                let net_event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Refuse)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Medium)
                    .dst_endpoint(dst_ep.clone())
                    .actor_process(Process::from_bypass(&binary, &binary_pid, &ancestors))
                    .firewall_rule("bypass-detect", "nftables")
                    .observation_point(3)
                    .message(format!(
                        "BYPASS_DETECT {}:{} proto={} binary={binary} action=reject reason={reason}",
                        event.dst_addr, event.dst_port, event.proto,
                    ))
                    .build();
                ocsf_emit!(net_event);

                let finding_event = DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Open)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Medium)
                    .is_alert(true)
                    .confidence(ConfidenceId::High)
                    .finding_info(
                        FindingInfo::new("bypass-detect", "Proxy Bypass Detected")
                            .with_desc(reason),
                    )
                    .remediation(hint)
                    .evidence_pairs(&[
                        ("dst_addr", &event.dst_addr),
                        ("dst_port", &event.dst_port.to_string()),
                        ("proto", &event.proto),
                        ("binary", &binary),
                        ("binary_pid", &binary_pid),
                        ("ancestors", &ancestors),
                    ])
                    .message(format!(
                        "BYPASS_DETECT {}:{} proto={} binary={binary} hint={hint}",
                        event.dst_addr, event.dst_port, event.proto,
                    ))
                    .build();
                ocsf_emit!(finding_event);
            }

            // Send to denial aggregator if available.
            if let Some(ref tx) = denial_tx {
                let ancestors_vec: Vec<String> = if ancestors == "-" {
                    vec![]
                } else {
                    ancestors.split(" -> ").map(String::from).collect()
                };

                let _ = tx.send(DenialEvent {
                    host: event.dst_addr.clone(),
                    port: event.dst_port,
                    binary: binary.clone(),
                    ancestors: ancestors_vec,
                    deny_reason: "direct connection bypassed HTTP CONNECT proxy".to_string(),
                    denial_stage: "bypass".to_string(),
                    l7_method: None,
                    l7_path: None,
                });
            }
            if let Some(ref tx) = activity_tx {
                let _ = try_record_activity(tx, true, "bypass");
            }
        }

        // The reader loop above only ends when dmesg's stdout pipe closes —
        // nothing else in this task closes it, so that means dmesg itself
        // exited or failed (absent an external kill during supervisor
        // shutdown, in which case the whole process is going away anyway).
        // Report why, once, instead of the previous silent best-effort
        // kill+wait.
        let _ = child.kill();
        let stderr_text = stderr_capture.and_then(|h| h.join().ok());
        match child.wait() {
            Ok(status) if status.success() => {
                debug!("Bypass monitor: dmesg reader exited");
            }
            Ok(status) => {
                report_degraded(&describe_failure(status, &stderr_text.unwrap_or_default()));
            }
            Err(e) => {
                report_degraded(&format!("failed to wait on dmesg --follow: {e}"));
            }
        }
    });

    Some(handle)
}

/// Resolve process identity from a TCP source port.
///
/// Returns `(binary_path, pid, ancestors)` as display strings.
/// Falls back to `("-", "-", "-")` on any failure (race condition, etc.).
fn resolve_process_identity(entrypoint_pid: u32, src_port: u16) -> (String, String, String) {
    match procfs::resolve_tcp_peer_socket_owners(entrypoint_pid, src_port) {
        Ok(socket_owners) => {
            let mut identities = Vec::new();
            for owner in &socket_owners.owners {
                let Ok(binary_path) = procfs::binary_path(owner.pid.cast_signed()) else {
                    continue;
                };
                let ancestors = procfs::collect_ancestor_binaries(owner.pid, entrypoint_pid);
                identities.push((owner.pid, binary_path, ancestors));
            }

            if identities.is_empty() {
                return ("-".to_string(), "-".to_string(), "-".to_string());
            }

            identities.sort_by_key(|(pid, _, _)| *pid);
            let first_identity = (identities[0].1.clone(), identities[0].2.clone());
            let ambiguous = identities
                .iter()
                .skip(1)
                .any(|(_, binary_path, ancestors)| {
                    binary_path != &first_identity.0 || ancestors != &first_identity.1
                });

            if ambiguous {
                let pids = identities
                    .iter()
                    .map(|(pid, _, _)| pid.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let owner_summary = identities
                    .iter()
                    .map(|(pid, binary_path, ancestors)| {
                        let ancestors_str = if ancestors.is_empty() {
                            "-".to_string()
                        } else {
                            ancestors
                                .iter()
                                .map(|p| p.display().to_string())
                                .collect::<Vec<_>>()
                                .join(" -> ")
                        };
                        format!(
                            "pid={pid} binary={} ancestors=[{ancestors_str}]",
                            binary_path.display()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                return ("ambiguous".to_string(), pids, owner_summary);
            }

            let (pid, binary_path, ancestors) = identities.remove(0);
            let ancestors_str = if ancestors.is_empty() {
                "-".to_string()
            } else {
                ancestors
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            };
            (
                binary_path.display().to_string(),
                pid.to_string(),
                ancestors_str,
            )
        }
        Err(_) => ("-".to_string(), "-".to_string(), "-".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_ring_buffer_read_ok_on_success() {
        assert_eq!(probe_ring_buffer_read("true", &[]), Ok(()));
    }

    #[test]
    fn probe_ring_buffer_read_surfaces_stderr_reason_on_failure() {
        // Simulates the measured real-world failure: the binary execs fine
        // (this is exactly what `dmesg --version` would have missed) but the
        // read itself fails and says why on stderr.
        let err = probe_ring_buffer_read(
            "sh",
            &[
                "-c",
                "echo 'read kernel buffer failed: Operation not permitted' >&2; exit 1",
            ],
        )
        .unwrap_err();
        assert_eq!(err, "read kernel buffer failed: Operation not permitted");
    }

    #[test]
    fn probe_ring_buffer_read_falls_back_to_exit_status_without_stderr() {
        let err = probe_ring_buffer_read("sh", &["-c", "exit 1"]).unwrap_err();
        assert!(
            err.contains("exited with"),
            "expected a status-based reason, got: {err}"
        );
    }

    #[test]
    fn probe_ring_buffer_read_reports_exec_failure() {
        let err = probe_ring_buffer_read("openshell-bypass-monitor-test-no-such-binary", &[])
            .unwrap_err();
        assert!(
            err.contains("failed to exec"),
            "expected an exec-failure reason, got: {err}"
        );
    }

    #[test]
    fn describe_failure_prefers_stderr_over_status() {
        let status = std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .status()
            .expect("run sh");
        assert_eq!(
            describe_failure(status, "  Operation not permitted  \n"),
            "Operation not permitted"
        );
    }

    #[test]
    fn describe_failure_falls_back_to_status_when_stderr_empty() {
        let status = std::process::Command::new("sh")
            .args(["-c", "exit 7"])
            .status()
            .expect("run sh");
        let reason = describe_failure(status, "");
        assert!(
            reason.contains("exited with"),
            "expected a status-based reason, got: {reason}"
        );
    }

    #[test]
    fn parse_kmsg_line_tcp_bypass() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=10.200.0.2 DST=93.184.216.34 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 \
                    DF PROTO=TCP SPT=48012 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0 UID=1000";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "93.184.216.34");
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.src_port, 48012);
        assert_eq!(event.proto, "tcp");
        assert_eq!(event.uid, Some(1000));
    }

    #[test]
    fn parse_kmsg_line_udp_dns_bypass() {
        let line = "6,5678,9012,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=10.200.0.2 DST=8.8.8.8 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=0 \
                    DF PROTO=UDP SPT=53421 DPT=53 LEN=32 UID=1000";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "8.8.8.8");
        assert_eq!(event.dst_port, 53);
        assert_eq!(event.src_port, 53421);
        assert_eq!(event.proto, "udp");
        assert_eq!(event.uid, Some(1000));
    }

    #[test]
    fn parse_kmsg_line_no_uid() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=10.200.0.2 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=12345 DPT=6379";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "10.0.0.5");
        assert_eq!(event.dst_port, 6379);
        assert_eq!(event.proto, "tcp");
        assert_eq!(event.uid, None);
    }

    #[test]
    fn parse_kmsg_line_wrong_namespace_returns_none() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-other:IN= OUT=veth \
                    SRC=10.200.0.2 DST=1.2.3.4 PROTO=TCP SPT=1111 DPT=80";

        let result = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:");
        assert!(result.is_none());
    }

    #[test]
    fn parse_kmsg_line_unrelated_message_returns_none() {
        let line = "6,1234,5678,-;audit: type=1400 audit(1234567890.123:1): something else";
        let result = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:");
        assert!(result.is_none());
    }

    #[test]
    fn parse_kmsg_line_missing_dst_returns_none() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth \
                    SRC=10.200.0.2 PROTO=TCP SPT=1111 DPT=80";
        // Missing DST= field
        let result = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:");
        assert!(result.is_none());
    }

    #[test]
    fn parse_kmsg_line_ipv6_address() {
        let line = "6,1234,5678,-;openshell:bypass:sandbox-abcd1234:IN= OUT=veth-s-abcd1234 \
                    SRC=fd00::2 DST=2001:4860:4860::8888 LEN=60 PROTO=TCP SPT=55555 DPT=443 UID=1000";

        let event = parse_kmsg_line(line, "openshell:bypass:sandbox-abcd1234:").unwrap();
        assert_eq!(event.dst_addr, "2001:4860:4860::8888");
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.proto, "tcp");
    }

    #[test]
    fn hint_for_tcp_event() {
        let event = BypassEvent {
            dst_addr: "1.2.3.4".to_string(),
            dst_port: 443,
            src_port: 12345,
            proto: "tcp".to_string(),
            uid: None,
        };
        assert!(hint_for_event(&event).contains("HTTP_PROXY"));
    }

    #[test]
    fn hint_for_dns_bypass() {
        let event = BypassEvent {
            dst_addr: "8.8.8.8".to_string(),
            dst_port: 53,
            src_port: 12345,
            proto: "udp".to_string(),
            uid: None,
        };
        assert!(hint_for_event(&event).contains("DNS"));
    }

    #[test]
    fn hint_for_non_dns_udp() {
        let event = BypassEvent {
            dst_addr: "1.2.3.4".to_string(),
            dst_port: 5060,
            src_port: 12345,
            proto: "udp".to_string(),
            uid: None,
        };
        assert!(hint_for_event(&event).contains("UDP"));
    }

    #[test]
    fn resolve_process_identity_surfaces_ambiguous_shared_socket() {
        use std::ffi::CString;
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::AsRawFd;
        use std::time::{Duration, Instant};

        if !std::path::Path::new("/bin/sleep").exists() {
            eprintln!("skipping: /bin/sleep not available");
            return;
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_port = listener.local_addr().unwrap().port();
        let stream = TcpStream::connect(("127.0.0.1", listener_port)).expect("connect");
        let peer_port = stream.local_addr().unwrap().port();
        let (_accepted, _) = listener.accept().expect("accept");

        let fd = stream.as_raw_fd();
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            assert!(flags >= 0, "F_GETFD failed");
            assert_eq!(
                libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC),
                0,
                "F_SETFD failed"
            );
        }

        let sleep_path = CString::new("/bin/sleep").unwrap();
        let arg0 = CString::new("sleep").unwrap();
        let arg1 = CString::new("30").unwrap();
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "fork failed");
        if child_pid == 0 {
            // libc/syscall FFI requires unsafe
            #[allow(unsafe_code)]
            unsafe {
                libc::execl(
                    sleep_path.as_ptr(),
                    arg0.as_ptr(),
                    arg1.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
                libc::_exit(127);
            }
        }

        if std::fs::read_link(format!("/proc/{child_pid}/exe")).is_err()
            || std::fs::read_dir(format!("/proc/{child_pid}/fd")).is_err()
        {
            #[allow(unsafe_code)]
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                libc::waitpid(child_pid, std::ptr::null_mut(), 0);
            }
            eprintln!("skipping: cannot read /proc/{child_pid} (restricted /proc)");
            return;
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(link) = std::fs::read_link(format!("/proc/{child_pid}/exe"))
                && link.to_string_lossy().contains("sleep")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child pid {child_pid} did not exec into sleep within 2s"
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        let (binary, pid, ancestors) = resolve_process_identity(std::process::id(), peer_port);

        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        }

        assert_eq!(binary, "ambiguous");
        assert!(pid.contains(&std::process::id().to_string()));
        assert!(pid.contains(&child_pid.to_string()));
        assert!(ancestors.contains("binary="));
    }

    #[test]
    fn extract_field_basic() {
        let s = "DST=1.2.3.4 LEN=60";
        assert_eq!(extract_field(s, "DST="), Some("1.2.3.4".to_string()));
        assert_eq!(extract_field(s, "LEN="), Some("60".to_string()));
    }

    #[test]
    fn extract_field_missing() {
        let s = "DST=1.2.3.4 LEN=60";
        assert_eq!(extract_field(s, "PROTO="), None);
    }

    #[test]
    fn extract_field_at_end_of_string() {
        let s = "DST=1.2.3.4";
        assert_eq!(extract_field(s, "DST="), Some("1.2.3.4".to_string()));
    }
}
