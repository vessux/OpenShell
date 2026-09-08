// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parsing for `--volume HOST:CONTAINER[:ro]` specs.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindVolumeSpec {
    pub host: String,
    pub container: String,
    pub read_only: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VolumeParseError {
    #[error("--volume spec must have 2 or 3 colon-separated fields: {0}")]
    BadFieldCount(String),
    #[error("--volume spec third field must be 'ro': {0}")]
    BadReadOnlyToken(String),
    #[error("--volume host path must be absolute: {0}")]
    HostNotAbsolute(String),
    #[error("--volume host path does not exist: {0}")]
    HostMissing(String),
    #[error("--volume container path must be absolute: {0}")]
    ContainerNotAbsolute(String),
}

pub fn parse_volume_spec(s: &str) -> Result<BindVolumeSpec, VolumeParseError> {
    let parts: Vec<&str> = s.split(':').collect();
    let (host, container, read_only) = match parts.as_slice() {
        [h, c] => (h.to_string(), c.to_string(), false),
        [h, c, ro] => {
            if *ro != "ro" {
                return Err(VolumeParseError::BadReadOnlyToken(s.to_string()));
            }
            (h.to_string(), c.to_string(), true)
        }
        _ => return Err(VolumeParseError::BadFieldCount(s.to_string())),
    };
    if !Path::new(&host).is_absolute() {
        return Err(VolumeParseError::HostNotAbsolute(host));
    }
    if !Path::new(&host).exists() {
        return Err(VolumeParseError::HostMissing(host));
    }
    if !Path::new(&container).is_absolute() {
        return Err(VolumeParseError::ContainerNotAbsolute(container));
    }
    Ok(BindVolumeSpec {
        host,
        container,
        read_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_two_field_spec() {
        let dir = TempDir::new().unwrap();
        let host = dir.path().to_string_lossy().to_string();
        let spec = format!("{host}:/sandbox/repo");
        let parsed = parse_volume_spec(&spec).unwrap();
        assert_eq!(parsed.host, host);
        assert_eq!(parsed.container, "/sandbox/repo");
        assert!(!parsed.read_only);
    }

    #[test]
    fn parses_three_field_ro_spec() {
        let dir = TempDir::new().unwrap();
        let host = dir.path().to_string_lossy().to_string();
        let spec = format!("{host}:/c:ro");
        let parsed = parse_volume_spec(&spec).unwrap();
        assert!(parsed.read_only);
    }

    #[test]
    fn rejects_bad_field_count() {
        assert!(matches!(
            parse_volume_spec("a:b:c:d"),
            Err(VolumeParseError::BadFieldCount(_))
        ));
        assert!(matches!(
            parse_volume_spec("only-one"),
            Err(VolumeParseError::BadFieldCount(_))
        ));
    }

    #[test]
    fn rejects_bad_ro_token() {
        // /tmp exists on every Unix CI host so the path checks pass before
        // reaching the read-only token check.
        let r = parse_volume_spec("/tmp:/c:readonly");
        assert!(matches!(r, Err(VolumeParseError::BadReadOnlyToken(_))));
    }

    #[test]
    fn rejects_non_absolute_host() {
        let r = parse_volume_spec("rel/path:/c");
        assert!(matches!(r, Err(VolumeParseError::HostNotAbsolute(_))));
    }

    #[test]
    fn rejects_missing_host() {
        let r = parse_volume_spec("/definitely/does/not/exist/here:/c");
        assert!(matches!(r, Err(VolumeParseError::HostMissing(_))));
    }

    #[test]
    fn rejects_non_absolute_container() {
        let dir = TempDir::new().unwrap();
        let host = dir.path().to_string_lossy().to_string();
        let spec = format!("{host}:rel/path");
        let r = parse_volume_spec(&spec);
        assert!(matches!(r, Err(VolumeParseError::ContainerNotAbsolute(_))));
    }
}
