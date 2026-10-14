use crate::{
    ingest::{hex, sha256},
    service::{self, invalid},
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PkiState {
    pub version: u16,
    pub generation: u64,
    pub hosts: Vec<String>,
    pub ca_created: u64,
    pub ca_expires: u64,
    pub server_expires: u64,
    pub ca_sha256: String,
    pub active: String,
    #[serde(default)]
    pub previous_ca: Option<String>,
    #[serde(default)]
    pub pending_ca: Option<String>,
    #[serde(default)]
    pub pending_ca_created: Option<u64>,
    #[serde(default)]
    pub pending_ca_expires: Option<u64>,
}

pub fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}
fn ca_params(start: u64, end: u64) -> io::Result<CertificateParams> {
    let mut p = CertificateParams::default();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "REDTRACE Personal CA");
    p.distinguished_name = dn;
    p.not_before =
        time::OffsetDateTime::from_unix_timestamp(start as i64).map_err(io::Error::other)?;
    p.not_after =
        time::OffsetDateTime::from_unix_timestamp(end as i64).map_err(io::Error::other)?;
    Ok(p)
}
pub struct Pki {
    directory: PathBuf,
}
impl Pki {
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
    pub fn status(&self) -> io::Result<Option<PkiState>> {
        let path = self.directory.join("pki.json");
        if !path.exists() {
            return Ok(None);
        }
        let state: PkiState = serde_json::from_slice(&service::read_private(&path, 64 * 1024)?)
            .map_err(io::Error::other)?;
        if state.version != 1
            || state.generation == 0
            || state.hosts.is_empty()
            || state.hosts.len() > 16
            || state.ca_created >= state.ca_expires
            || state.ca_sha256.len() != 64
            || !state.ca_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || std::iter::once(&state.active)
                .chain(state.previous_ca.iter())
                .chain(state.pending_ca.iter())
                .any(|name| {
                    name.is_empty()
                        || name.len() > 128
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        {
            return Err(invalid("unsupported PKI state"));
        }
        Ok(Some(state))
    }
    pub fn provision(&self, hosts: Vec<String>, rotate_ca: bool) -> io::Result<PkiState> {
        if hosts.is_empty()
            || hosts.len() > 16
            || hosts.iter().any(|s| {
                s.is_empty()
                    || s.len() > 253
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
            })
        {
            return Err(invalid(
                "certificate SANs must be DNS names or IP addresses",
            ));
        }
        service::private_directory(&self.directory)?;
        let old = self.status()?;
        let generation = old.as_ref().map_or(Ok(1), |s| {
            s.generation
                .checked_add(1)
                .ok_or_else(|| invalid("PKI generation exhausted"))
        })?;
        let active = format!("generation-{generation}");
        let directory = self.directory.join(&active);
        service::private_directory(&directory)?;
        let (ca_key, created, expires, previous) = if !rotate_ca {
            if let Some(old) = &old {
                let key = String::from_utf8(service::read_private(
                    &self.directory.join(&old.active).join("ca.key"),
                    8192,
                )?)
                .map_err(io::Error::other)?;
                (
                    KeyPair::from_pem(&key).map_err(io::Error::other)?,
                    old.ca_created,
                    old.ca_expires,
                    old.previous_ca.clone(),
                )
            } else {
                (
                    KeyPair::generate().map_err(io::Error::other)?,
                    now().saturating_sub(300),
                    now() + 5 * 365 * 86400,
                    None,
                )
            }
        } else if let Some(pending) = old.as_ref().and_then(|s| s.pending_ca.as_ref()) {
            let key = String::from_utf8(service::read_private(
                &self.directory.join(pending).join("ca.key"),
                8192,
            )?)
            .map_err(io::Error::other)?;
            (
                KeyPair::from_pem(&key).map_err(io::Error::other)?,
                old.as_ref()
                    .and_then(|s| s.pending_ca_created)
                    .unwrap_or_else(|| now().saturating_sub(300)),
                old.as_ref()
                    .and_then(|s| s.pending_ca_expires)
                    .unwrap_or_else(|| now() + 5 * 365 * 86400),
                old.as_ref().map(|s| s.active.clone()),
            )
        } else {
            (
                KeyPair::generate().map_err(io::Error::other)?,
                now().saturating_sub(300),
                now() + 5 * 365 * 86400,
                old.as_ref().map(|s| s.active.clone()),
            )
        };
        if expires <= now() + 86400 {
            return Err(invalid(
                "CA expires soon; rotate the CA before renewing server certificate",
            ));
        }
        let ca = ca_params(created, expires)?
            .self_signed(&ca_key)
            .map_err(io::Error::other)?;
        let ca_pem = if !rotate_ca {
            if let Some(old) = &old {
                String::from_utf8(service::read_private(
                    &self.directory.join(&old.active).join("ca.pem"),
                    8192,
                )?)
                .map_err(io::Error::other)?
            } else {
                ca.pem()
            }
        } else if let Some(pending) = old.as_ref().and_then(|s| s.pending_ca.as_ref()) {
            String::from_utf8(service::read_private(
                &self.directory.join(pending).join("ca.pem"),
                8192,
            )?)
            .map_err(io::Error::other)?
        } else {
            ca.pem()
        };
        let mut params = CertificateParams::new(hosts.clone()).map_err(io::Error::other)?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before =
            time::OffsetDateTime::from_unix_timestamp(now().saturating_sub(300) as i64)
                .map_err(io::Error::other)?;
        let server_expires = (now() + 90 * 86400).min(expires);
        params.not_after = time::OffsetDateTime::from_unix_timestamp(server_expires as i64)
            .map_err(io::Error::other)?;
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let issuer = Issuer::new(ca_params(created, expires)?, &ca_key);
        let certificate = params.signed_by(&key, &issuer).map_err(io::Error::other)?;
        for (name, content) in [
            ("ca.key", ca_key.serialize_pem()),
            ("ca.pem", ca_pem.clone()),
            ("server.key", key.serialize_pem()),
            ("server.pem", certificate.pem()),
        ] {
            service::write_private(&directory.join(name), content.as_bytes())?;
        }
        let state = PkiState {
            version: 1,
            generation,
            hosts,
            ca_created: created,
            ca_expires: expires,
            server_expires,
            ca_sha256: hex(&sha256(ca_pem.as_bytes())),
            active,
            previous_ca: previous,
            pending_ca: if rotate_ca {
                None
            } else {
                old.as_ref().and_then(|s| s.pending_ca.clone())
            },
            pending_ca_created: if rotate_ca {
                None
            } else {
                old.as_ref().and_then(|s| s.pending_ca_created)
            },
            pending_ca_expires: if rotate_ca {
                None
            } else {
                old.as_ref().and_then(|s| s.pending_ca_expires)
            },
        };
        service::write_private(
            &self.directory.join("pki.json"),
            &serde_json::to_vec_pretty(&state).map_err(io::Error::other)?,
        )?;
        Ok(state)
    }
    pub fn paths(&self) -> io::Result<Option<(PathBuf, PathBuf)>> {
        Ok(self.status()?.map(|s| {
            (
                self.directory.join(&s.active).join("server.pem"),
                self.directory.join(&s.active).join("server.key"),
            )
        }))
    }
    pub fn trust_bundle(&self) -> io::Result<String> {
        let s = self
            .status()?
            .ok_or_else(|| invalid("configure collector TLS first"))?;
        let mut bundle = String::from_utf8(service::read_private(
            &self.directory.join(&s.active).join("ca.pem"),
            16384,
        )?)
        .map_err(io::Error::other)?;
        if let Some(old) = s.previous_ca {
            bundle.push_str(
                &String::from_utf8(service::read_private(
                    &self.directory.join(old).join("ca.pem"),
                    16384,
                )?)
                .map_err(io::Error::other)?,
            );
        }
        if let Some(pending) = s.pending_ca {
            bundle.push_str(
                &String::from_utf8(service::read_private(
                    &self.directory.join(pending).join("ca.pem"),
                    16384,
                )?)
                .map_err(io::Error::other)?,
            );
        }
        Ok(bundle)
    }
    pub fn prepare_rotation(&self) -> io::Result<PkiState> {
        let mut state = self
            .status()?
            .ok_or_else(|| invalid("configure PKI first"))?;
        if state.pending_ca.is_some() {
            return Ok(state);
        }
        let directory = format!("pending-{}", service::random_secret()?);
        let target = self.directory.join(&directory);
        service::private_directory(&target)?;
        let key = KeyPair::generate().map_err(io::Error::other)?;
        let created = now().saturating_sub(300);
        let expires = now() + 5 * 365 * 86400;
        let cert = ca_params(created, expires)?
            .self_signed(&key)
            .map_err(io::Error::other)?;
        service::write_private(&target.join("ca.key"), key.serialize_pem().as_bytes())?;
        service::write_private(&target.join("ca.pem"), cert.pem().as_bytes())?;
        state.pending_ca = Some(directory);
        state.pending_ca_created = Some(created);
        state.pending_ca_expires = Some(expires);
        service::write_private(
            &self.directory.join("pki.json"),
            &serde_json::to_vec_pretty(&state).map_err(io::Error::other)?,
        )?;
        Ok(state)
    }
    pub fn certificate_warning(&self) -> io::Result<serde_json::Value> {
        Ok(match self.status()? {
            Some(s) => {
                serde_json::json!({"configured":true,"days_remaining":s.server_expires.saturating_sub(now())/86400,"expired":s.server_expires<=now(),"renewal_due":s.server_expires<=now()+14*86400,"state":s})
            }
            None => serde_json::json!({"configured":false}),
        })
    }
}

pub fn load_trust(path: &Path) -> io::Result<Vec<reqwest::Certificate>> {
    let bytes = service::read_private(path, 64 * 1024)?;
    reqwest::Certificate::from_pem_bundle(&bytes).map_err(io::Error::other)
}
