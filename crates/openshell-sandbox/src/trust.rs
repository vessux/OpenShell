// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    Pypi,
    Npm,
}

impl Registry {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pypi" => Some(Self::Pypi),
            "npm" => Some(Self::Npm),
            _ => None,
        }
    }

    fn deps_dev_system(&self) -> &'static str {
        match self {
            Self::Pypi => "pypi",
            Self::Npm => "npm",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackageRef {
    pub registry: Registry,
    pub name: String,
    pub version: Option<String>,
}

pub fn parse_package_ref(registry: Registry, method: &str, path: &str) -> Option<PackageRef> {
    if method != "GET" {
        return None;
    }
    match registry {
        Registry::Pypi => parse_pypi(path),
        Registry::Npm => parse_npm(path),
    }
}

fn parse_pypi(path: &str) -> Option<PackageRef> {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    if segments.len() == 2 && segments[0] == "simple" {
        let name = normalize_pypi_name(segments[1]);
        if name.is_empty() {
            return None;
        }
        return Some(PackageRef {
            registry: Registry::Pypi,
            name,
            version: None,
        });
    }

    if segments.len() >= 2 && segments[0] == "packages" {
        let filename = segments.last()?;
        return parse_pypi_filename(filename);
    }

    None
}

fn normalize_pypi_name(name: &str) -> String {
    name.replace('-', "_").to_lowercase()
}

fn parse_pypi_filename(filename: &str) -> Option<PackageRef> {
    let base = filename
        .strip_suffix(".whl")
        .or_else(|| filename.strip_suffix(".tar.gz"))
        .or_else(|| filename.strip_suffix(".zip"))?;

    let mut parts = base.splitn(3, '-');
    let name = normalize_pypi_name(parts.next()?);
    let version = parts.next()?.to_string();

    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some(PackageRef {
        registry: Registry::Pypi,
        name,
        version: Some(version),
    })
}

fn parse_npm(path: &str) -> Option<PackageRef> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }

    let path = percent_decode_slash(path);

    if let Some(pkg_ref) = parse_npm_tarball(&path) {
        return Some(pkg_ref);
    }

    parse_npm_metadata(&path)
}

fn percent_decode_slash(s: &str) -> String {
    s.replace("%2f", "/").replace("%2F", "/")
}

fn parse_npm_tarball(path: &str) -> Option<PackageRef> {
    let dash_idx = path.find("/-/")?;
    let name = &path[..dash_idx];
    let rest = &path[dash_idx + 3..];

    let tarball = rest.strip_suffix(".tgz")?;

    let unscoped = if name.starts_with('@') {
        name.split('/').nth(1)?
    } else {
        name
    };

    let version_start = tarball.strip_prefix(unscoped)?.strip_prefix('-')?;
    if version_start.is_empty() {
        return None;
    }

    Some(PackageRef {
        registry: Registry::Npm,
        name: name.to_string(),
        version: Some(version_start.to_string()),
    })
}

fn parse_npm_metadata(path: &str) -> Option<PackageRef> {
    if path.starts_with('@') {
        let parts: Vec<&str> = path.splitn(4, '/').collect();
        if parts.len() < 2 {
            return None;
        }
        let name = format!("{}/{}", parts[0], parts[1]);
        let version = parts
            .get(2)
            .filter(|v| !v.is_empty())
            .map(|v| (*v).to_string());
        return Some(PackageRef {
            registry: Registry::Npm,
            name,
            version,
        });
    }

    let parts: Vec<&str> = path.splitn(3, '/').collect();
    let name = parts[0].to_string();
    if name.is_empty() || name.starts_with('-') {
        return None;
    }
    let version = parts
        .get(1)
        .filter(|v| !v.is_empty())
        .map(|v| (*v).to_string());
    Some(PackageRef {
        registry: Registry::Npm,
        name,
        version,
    })
}

#[derive(Debug, Clone)]
pub struct TrustResult {
    pub package_name: String,
    pub version: String,
    pub registry: String,
    pub critical_vulns: u32,
    pub high_vulns: u32,
    pub medium_vulns: u32,
    pub low_vulns: u32,
    pub license: String,
    pub is_stale: bool,
    pub lookup_failed: bool,
    fetched_at: Instant,
}

pub struct TrustCache {
    entries: RwLock<HashMap<String, TrustResult>>,
    ttl: Duration,
    client: reqwest::Client,
}

impl TrustCache {
    pub fn new(ttl: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            client,
        }
    }

    pub async fn get_or_fetch(&self, pkg: &PackageRef) -> TrustResult {
        let key = cache_key(pkg);

        if let Ok(entries) = self.entries.read() {
            if let Some(cached) = entries.get(&key) {
                if cached.fetched_at.elapsed() < self.ttl {
                    return cached.clone();
                }
            }
        }

        let result = fetch_trust(&self.client, pkg).await;

        if let Ok(mut entries) = self.entries.write() {
            entries.insert(key, result.clone());
        }

        result
    }
}

fn cache_key(pkg: &PackageRef) -> String {
    let version = pkg.version.as_deref().unwrap_or("latest");
    let system = pkg.registry.deps_dev_system();
    format!("{system}:{name}:{version}", name = pkg.name)
}

async fn fetch_trust(client: &reqwest::Client, pkg: &PackageRef) -> TrustResult {
    let fetch_start = Instant::now();
    tracing::debug!(package = %pkg.name, version = ?pkg.version, "trust: starting fetch");
    let failed = TrustResult {
        package_name: pkg.name.clone(),
        version: pkg.version.clone().unwrap_or_default(),
        registry: pkg.registry.deps_dev_system().to_string(),
        critical_vulns: 0,
        high_vulns: 0,
        medium_vulns: 0,
        low_vulns: 0,
        license: "LOOKUP_FAILED".to_string(),
        is_stale: false,
        lookup_failed: true,
        fetched_at: Instant::now(),
    };

    let system = pkg.registry.deps_dev_system();

    let version = match &pkg.version {
        Some(v) => v.clone(),
        None => match resolve_default_version(client, system, &pkg.name).await {
            Some(v) => v,
            None => return failed,
        },
    };

    let url = format!(
        "https://api.deps.dev/v3alpha/systems/{system}/packages/{name}/versions/{version}",
        name = url_encode(&pkg.name),
        version = url_encode(&version),
    );

    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => {
            tracing::debug!(package = %pkg.name, elapsed_ms = fetch_start.elapsed().as_millis(), "trust: version data fetched");
            r
        }
        Ok(r) => {
            tracing::debug!(package = %pkg.name, status = %r.status(), "trust: version lookup failed");
            return failed;
        }
        Err(e) => {
            tracing::debug!(package = %pkg.name, error = %e, "trust: version lookup error");
            return failed;
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return failed,
    };

    let (critical, high, medium, low) =
        classify_advisories(client, &body).await;
    tracing::debug!(
        package = %pkg.name,
        critical, high, medium, low,
        elapsed_ms = fetch_start.elapsed().as_millis(),
        "trust: classification complete"
    );

    let license = body
        .get("licenses")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string();

    let is_stale = body
        .get("publishedAt")
        .and_then(|v| v.as_str())
        .map(|ts| {
            let now = chrono::Utc::now();
            chrono::DateTime::parse_from_rfc3339(ts)
                .map(|dt| now.signed_duration_since(dt) > chrono::Duration::days(730))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    TrustResult {
        package_name: pkg.name.clone(),
        version: version.clone(),
        registry: pkg.registry.deps_dev_system().to_string(),
        critical_vulns: critical,
        high_vulns: high,
        medium_vulns: medium,
        low_vulns: low,
        license,
        is_stale,
        lookup_failed: false,
        fetched_at: Instant::now(),
    }
}

async fn classify_advisories(
    client: &reqwest::Client,
    body: &serde_json::Value,
) -> (u32, u32, u32, u32) {
    let advisory_ids: Vec<String> = body
        .get("advisoryKeys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.get("id").and_then(|id| id.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if advisory_ids.is_empty() {
        return (0, 0, 0, 0);
    }

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(5));
    let mut set = tokio::task::JoinSet::new();
    for id in &advisory_ids {
        let client = client.clone();
        let sem = semaphore.clone();
        let url = format!(
            "https://api.deps.dev/v3/advisories/{}",
            url_encode(id),
        );
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).send().await.ok()?;
            if !resp.status().is_success() {
                return None;
            }
            let val: serde_json::Value = resp.json().await.ok()?;
            val.get("cvss3Score").and_then(|s| s.as_f64())
        });
    }

    let mut scores = Vec::with_capacity(advisory_ids.len());
    while let Some(result) = set.join_next().await {
        scores.push(result.ok().flatten());
    }

    let mut critical = 0u32;
    let mut high = 0u32;
    let mut medium = 0u32;
    let mut low = 0u32;

    for score in scores {
        match score {
            Some(s) if s >= 9.0 => critical += 1,
            Some(s) if s >= 7.0 => high += 1,
            Some(s) if s >= 4.0 => medium += 1,
            Some(s) if s > 0.0 => low += 1,
            _ => high += 1,
        }
    }

    (critical, high, medium, low)
}

async fn resolve_default_version(
    client: &reqwest::Client,
    system: &str,
    name: &str,
) -> Option<String> {
    let url = format!(
        "https://api.deps.dev/v3alpha/systems/{system}/packages/{name}",
        name = url_encode(name),
    );
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("versions")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.last())
        .and_then(|v| v.get("versionKey"))
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn url_encode(s: &str) -> String {
    s.replace('/', "%2F").replace('@', "%40")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_simple_index() {
        let pkg = parse_package_ref(Registry::Pypi, "GET", "/simple/requests/").unwrap();
        assert_eq!(pkg.name, "requests");
        assert!(pkg.version.is_none());
    }

    #[test]
    fn pypi_simple_index_dashes_normalized() {
        let pkg = parse_package_ref(Registry::Pypi, "GET", "/simple/my-package/").unwrap();
        assert_eq!(pkg.name, "my_package");
    }

    #[test]
    fn pypi_download_wheel() {
        let pkg = parse_package_ref(
            Registry::Pypi,
            "GET",
            "/packages/ab/cd/requests-2.31.0-py3-none-any.whl",
        )
        .unwrap();
        assert_eq!(pkg.name, "requests");
        assert_eq!(pkg.version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn pypi_download_sdist() {
        let pkg = parse_package_ref(
            Registry::Pypi,
            "GET",
            "/packages/ab/cd/requests-2.31.0.tar.gz",
        )
        .unwrap();
        assert_eq!(pkg.name, "requests");
        assert_eq!(pkg.version.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn pypi_non_package_url() {
        assert!(parse_package_ref(Registry::Pypi, "GET", "/search/?q=requests").is_none());
    }

    #[test]
    fn pypi_post_ignored() {
        assert!(parse_package_ref(Registry::Pypi, "POST", "/simple/requests/").is_none());
    }

    #[test]
    fn npm_metadata_unscoped() {
        let pkg = parse_package_ref(Registry::Npm, "GET", "/express").unwrap();
        assert_eq!(pkg.name, "express");
        assert!(pkg.version.is_none());
    }

    #[test]
    fn npm_metadata_scoped() {
        let pkg = parse_package_ref(Registry::Npm, "GET", "/@babel/core").unwrap();
        assert_eq!(pkg.name, "@babel/core");
        assert!(pkg.version.is_none());
    }

    #[test]
    fn npm_metadata_scoped_encoded() {
        let pkg = parse_package_ref(Registry::Npm, "GET", "/@babel%2Fcore").unwrap();
        assert_eq!(pkg.name, "@babel/core");
    }

    #[test]
    fn npm_tarball_unscoped() {
        let pkg = parse_package_ref(Registry::Npm, "GET", "/express/-/express-4.18.2.tgz").unwrap();
        assert_eq!(pkg.name, "express");
        assert_eq!(pkg.version.as_deref(), Some("4.18.2"));
    }

    #[test]
    fn npm_tarball_scoped() {
        let pkg =
            parse_package_ref(Registry::Npm, "GET", "/@babel/core/-/core-7.24.0.tgz").unwrap();
        assert_eq!(pkg.name, "@babel/core");
        assert_eq!(pkg.version.as_deref(), Some("7.24.0"));
    }

    #[test]
    fn npm_non_package_url() {
        assert!(parse_package_ref(Registry::Npm, "GET", "/-/v1/security/audits").is_none());
    }

    #[test]
    fn cache_key_with_version() {
        let pkg = PackageRef {
            registry: Registry::Pypi,
            name: "requests".to_string(),
            version: Some("2.31.0".to_string()),
        };
        assert_eq!(cache_key(&pkg), "pypi:requests:2.31.0");
    }

    #[test]
    fn cache_key_without_version() {
        let pkg = PackageRef {
            registry: Registry::Npm,
            name: "express".to_string(),
            version: None,
        };
        assert_eq!(cache_key(&pkg), "npm:express:latest");
    }

    #[tokio::test]
    async fn classify_advisories_empty() {
        let client = reqwest::Client::new();
        let body = serde_json::json!({"advisoryKeys": []});
        let (c, h, m, l) = classify_advisories(&client, &body).await;
        assert_eq!((c, h, m, l), (0, 0, 0, 0));
    }

    #[tokio::test]
    async fn classify_advisories_missing_field() {
        let client = reqwest::Client::new();
        let body = serde_json::json!({});
        let (c, h, m, l) = classify_advisories(&client, &body).await;
        assert_eq!((c, h, m, l), (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore]
    async fn classify_advisories_live_urllib3() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let body: serde_json::Value = client
            .get("https://api.deps.dev/v3alpha/systems/pypi/packages/urllib3/versions/1.24.1")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let (c, h, m, l) = classify_advisories(&client, &body).await;
        assert!(c + h + m + l > 0, "urllib3 1.24.1 should have advisories");
        assert!(h > 0, "should have high-severity advisories (CVSS >= 7.0)");
    }
}
