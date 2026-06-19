//! TLS listener support.
//!
//! This module stays at the transport boundary: it builds a `TlsAcceptor` for
//! the server accept loop, while SOCKS5 negotiation and relay logic remain
//! unaware of whether the client stream is plaintext TCP or TLS-wrapped TCP.

use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_stream::StreamExt;

use crate::config::{AcmeConfig, Config, TlsConfig};
use crate::errors::{Error, Result};

/// A future that drives ACME certificate issuance and renewal. The server spawns
/// it once; issued certificates are then served through the acceptor's resolver
/// and renewed in the background without a restart.
pub type AcmeDriver = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The TLS acceptor for the listener, plus — for ACME — the renewal driver.
pub struct TlsSetup {
    pub acceptor: TlsAcceptor,
    pub acme_driver: Option<AcmeDriver>,
}

pub fn validate_config(config: &Config) -> Result<()> {
    // Pure validation for `--check` / service-install: build the acceptor (and,
    // for ACME, the renewal state) with no network I/O and no filesystem side
    // effects — in particular, do not create or write the ACME cache directory.
    let _ = build_acceptor(config.tls.as_ref(), false)?;
    Ok(())
}

pub fn load_acceptor(config: Option<&TlsConfig>) -> Result<Option<TlsSetup>> {
    // Runtime setup: also prepares (creates and write-probes) the ACME cache dir.
    build_acceptor(config, true)
}

fn build_acceptor(config: Option<&TlsConfig>, prepare_cache: bool) -> Result<Option<TlsSetup>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let setup = match config {
        TlsConfig::Files {
            cert_file,
            key_file,
        } => file_setup(cert_file, key_file)?,
        TlsConfig::Acme(acme) => acme_setup(acme, prepare_cache)?,
    };
    Ok(Some(setup))
}

fn file_setup(cert_file: &Path, key_file: &Path) -> Result<TlsSetup> {
    let certs = load_certs(cert_file)?;
    if certs.is_empty() {
        return Err(Error::Config(format!(
            "TLS certificate file {} did not contain any certificates",
            cert_file.display()
        )));
    }
    let key = load_private_key(key_file)?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("invalid TLS certificate/key pair: {e}")))?;
    Ok(TlsSetup {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        acme_driver: None,
    })
}

fn acme_setup(acme: &AcmeConfig, prepare_cache: bool) -> Result<TlsSetup> {
    // At runtime, create and write-probe the cache directory so an unwritable
    // path fails at startup rather than silently in the background renewal task.
    // Skipped for `--check`, which must not touch the filesystem.
    if prepare_cache {
        ensure_writable_dir(&acme.cache_dir)?;
    }
    // The state owns the resolver shared with the rustls config below, persists
    // the account/certs to the cache dir, and runs the order + renewal loop when
    // polled. TLS-ALPN-01 challenges are answered by the same acceptor.
    let mut state = rustls_acme::AcmeConfig::new(acme.domains.clone())
        .contact(acme.email.iter().map(|email| format!("mailto:{email}")))
        .cache(rustls_acme::caches::DirCache::new(acme.cache_dir.clone()))
        .directory_lets_encrypt(!acme.staging)
        .state();
    let acceptor = TlsAcceptor::from(state.default_rustls_config());
    let driver: AcmeDriver = Box::pin(async move {
        loop {
            match state.next().await {
                Some(Ok(ok)) => tracing::info!("acme: {ok:?}"),
                Some(Err(err)) => tracing::error!("acme error: {err:?}"),
                None => {
                    tracing::warn!(
                        "acme renewal task ended; TLS certificates will no longer be renewed"
                    );
                    break;
                }
            }
        }
    });
    Ok(TlsSetup {
        acceptor,
        acme_driver: Some(driver),
    })
}

/// Ensures `dir` exists and is writable, failing fast at startup otherwise.
/// `create_dir_all` alone is not enough: it succeeds on an existing directory
/// even when it is not writable, so probe by writing and removing a temp file.
fn ensure_writable_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        Error::Config(format!(
            "failed to create ACME cache directory {}: {e}",
            dir.display()
        ))
    })?;
    let probe = dir.join(".alighieri-acme-write-test");
    std::fs::write(&probe, [])
        .and_then(|()| std::fs::remove_file(&probe))
        .map_err(|e| {
            Error::Config(format!(
                "ACME cache directory {} is not writable: {e}",
                dir.display()
            ))
        })
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| {
        Error::Config(format!(
            "failed to open TLS certificate file {}: {e}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    CertificateDer::pem_reader_iter(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            Error::Config(format!(
                "failed to read TLS certificate file {}: {e}",
                path.display()
            ))
        })
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|e| {
        Error::Config(format!(
            "failed to open TLS private key file {}: {e}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    // Accepts PKCS#8, PKCS#1 (RSA), and SEC1 (EC) private keys.
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| match e {
        pem::Error::NoItemsFound => Error::Config(format!(
            "TLS private key file {} did not contain a supported private key",
            path.display()
        )),
        other => Error::Config(format!(
            "failed to read TLS private key file {}: {other}",
            path.display()
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUOCKlMVRPWTVj4douy93+KLpOLwMwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwMTE5MjIzNFoXDTI2MDYw
MjE5MjIzNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAhA94gPhVMU0tDg4YJGUI1JW7F6Vf5G//49yLXw66K2qH
nV5ByAMXlUQX57m6ahmxJOmjFJoDBN08NZk60dEyFpC0nmIXSDXVpr+vJOi1EsJs
FRDdpNK0A3b5sVzHFWnEqWpCi6+4fxYWqb0Vuda5oSAUydmDiTfzfVf/nGicfzGf
Zy2ELZQSszRyVWZ3bLH6hrtvutznULGF2D6hBvjuW9s35rYWbyyUOKt635FxxS3f
uy0K3uBlZHpw8XisxeNEOTD+qVe287BePRbMR8SdzA0OqEwM9l1bxtzoNRDIAKkt
0J/XxeXvaE6/SDKwHMyzhxjrdwX/KH60+j4olHTJpQIDAQABo1MwUTAdBgNVHQ4E
FgQU2J8UlQt9vqXo4xT4ZM/SYWDYikQwHwYDVR0jBBgwFoAU2J8UlQt9vqXo4xT4
ZM/SYWDYikQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARQSM
LYvV/uVww9MlMF8oE//7tVKsLOTlinycpy0ejfKqgAop8Nkwz40Fo/eEfckBQoXr
DGF/cjDKxMjgfr5/asPlzZdq/ExnzW3eoUJza8oqM/TtXql7IG4vNSIRpj3dy66Z
MjCel5Dd9p18S+krX5fh1FzQ1tuoL0GJbuEhWFfrfqhHudJEN6fEI7ZB2EGKPmtV
3dy8rz4293lcqoI5hA86OgXdpnQWlnhlEBG3I6whX/yWlAVkF99a63Fp3+w6AhT9
i35crrQgbBzWTR+kNv3NVKuaHHKVPoFyojQeY9joBcO3l2To6mMA/tDD2KfgSrtH
qx6grp6vJA4Nl4vJrQ==
-----END CERTIFICATE-----
"#;

    const KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCED3iA+FUxTS0O
DhgkZQjUlbsXpV/kb//j3ItfDroraoedXkHIAxeVRBfnubpqGbEk6aMUmgME3Tw1
mTrR0TIWkLSeYhdINdWmv68k6LUSwmwVEN2k0rQDdvmxXMcVacSpakKLr7h/Fhap
vRW51rmhIBTJ2YOJN/N9V/+caJx/MZ9nLYQtlBKzNHJVZndssfqGu2+63OdQsYXY
PqEG+O5b2zfmthZvLJQ4q3rfkXHFLd+7LQre4GVkenDxeKzF40Q5MP6pV7bzsF49
FsxHxJ3MDQ6oTAz2XVvG3Og1EMgAqS3Qn9fF5e9oTr9IMrAczLOHGOt3Bf8ofrT6
PiiUdMmlAgMBAAECggEABt8wN9PUSQu5SbcxielI/5joAqe8GOy8Dc0a4oAnb11s
f6OZPDFu/3kq3kfDm8RI+8D9l7OY7x6dBLP7w9HFL7fpcilsCTml67ajREIos/hy
e9kkE3DUZa7B+Pj5MhPOJDuviUnESbaqSLxaXlB+WdRLyKIdLl1/OdlDp42pARRO
kj9kH9Kia2hCShMiX5CrxpRFtdOKU6BA0wlj6SF4pHlQJHNVCJSR4WfCR5XIWa63
HA0segyuH6m82UZYXUML2GHk3s6Wr7zqzlF81Tv0Vu4Mwry5drdiRakTkin+HTYm
ZyTerGlyB0ksYWmqQKJkHhoBuGwJrpUAF3pCj//oEQKBgQC6UdiwRgxNYSZ0HGjS
pUHI+uAWfFPejQPK7xFyusRvYLx7zT9Lp5vJPH5Hg9z39j+G5fUKAjR1JUPhBDPm
t76KHIT8PAmmipFW+QqIo1/VrzSJxTLZbZBCaFEavUOpd5sFx3rT0WE/1bSwrw+K
jM9ktFuc/toeAi+mmGv8JQmxFQKBgQC1ct5hX1aCE02nkb7Vpulr1iIA02UL55yB
eyE2JAPefXW6yOZAD5EO/5TpY/7MPEMrpAv+JI5ZR0/ljztN/rlHNRHbhtmPMcUJ
nN5eH9vQn289rriS7mXrVKYFfPBJU9TG+ECsQTqKxabJjFDoLAtwdEHe8VlYERtz
6bk/gHE6UQKBgCRvfQB7skwvg2WRaK5IwuSaqte62GvdB7DXr4HQJDnjoPhU2tvg
mwZvXgJ+NugGr8WhkpmydK+z6eJHAB9OL2Syzw7Ebt6ymll3uieeS09uQ8ftWFRM
qLlTzQh9mo25ZgdrSwnBGFNzZzJmCZP+lVAMNR4ueFkF9GuPww477/lBAoGAI16T
2LlD3LE0lvCDGZSitaGVGUIb1Vk9mcPNsocMtgcQtutIbr5aEWlitqgGV/t7QHuG
1vB7Sw3qlh34enin1yiSJY/Awvf5p6kLc5+UMrORdJ2lXwbXmSrz/eff0vtjY7Gq
sak5ZymmHG2cq9VCGZaf7HxxZQhYqJyrvqQj7jECgYBmxf7RSrDoRP5jPK5xYwxu
f5wUomQ/exvJZK6JFj91DTnid0lw1Iu3aEDKMHh7uvlOWjR7KhOua2C5fBkvQDq3
BcfkLX4xS56xB/9dRW6Z1eocBakiC2Qp9OIz+1neQcPZ/UO1tZGvmaoHnjTI8zOX
TJmcpHqqAD9nQAqB4GvHPA==
-----END PRIVATE KEY-----
"#;

    #[test]
    fn loads_acceptor_from_pem_files() {
        let dir = tempfile::tempdir().unwrap();
        let cert_file = dir.path().join("server.crt");
        let key_file = dir.path().join("server.key");
        fs::write(&cert_file, CERT).unwrap();
        fs::write(&key_file, KEY).unwrap();

        let config = TlsConfig::Files {
            cert_file,
            key_file,
        };

        let setup = load_acceptor(Some(&config)).unwrap().unwrap();
        assert!(setup.acme_driver.is_none());
    }

    #[test]
    fn acme_config_builds_an_acceptor_and_driver() {
        // Constructing the ACME state and acceptor does no network I/O, so this
        // exercises the wiring offline.
        let dir = tempfile::tempdir().unwrap();
        let config = TlsConfig::Acme(crate::config::AcmeConfig {
            domains: vec!["proxy.example.com".into()],
            email: Some("admin@example.com".into()),
            cache_dir: dir.path().to_path_buf(),
            staging: true,
        });
        let setup = load_acceptor(Some(&config)).unwrap().unwrap();
        assert!(setup.acme_driver.is_some());
    }

    #[test]
    fn validation_is_side_effect_free_but_runtime_prepares_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("not-created-yet");
        let config = TlsConfig::Acme(crate::config::AcmeConfig {
            domains: vec!["proxy.example.com".into()],
            email: None,
            cache_dir: cache.clone(),
            staging: true,
        });

        // Pure validation must not touch the filesystem.
        build_acceptor(Some(&config), false).unwrap();
        assert!(!cache.exists(), "validation must not create the cache dir");

        // Runtime setup creates (and write-probes) it.
        build_acceptor(Some(&config), true).unwrap();
        assert!(cache.exists());
    }

    #[test]
    fn rejects_missing_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert_file = dir.path().join("server.crt");
        let key_file = dir.path().join("server.key");
        fs::write(&cert_file, CERT).unwrap();
        fs::write(&key_file, "not a private key").unwrap();

        let config = TlsConfig::Files {
            cert_file,
            key_file,
        };
        let err = match load_acceptor(Some(&config)) {
            Ok(_) => panic!("invalid private key was accepted"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("did not contain"));
    }
}
