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

use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};
use tokio_stream::StreamExt;

use crate::config::{AcmeConfig, Config, TlsConfig};
use crate::errors::{Error, Result};

/// A future that drives ACME certificate issuance and renewal. The server spawns
/// it once; issued certificates are then served through the listener's rustls
/// configs (which share the renewing resolver) and renewed in the background
/// without a restart.
pub type AcmeDriver = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The TLS listener for the server, plus — for ACME — the renewal driver.
pub struct TlsSetup {
    pub listener: TlsListener,
    pub acme_driver: Option<AcmeDriver>,
}

/// How accepted connections are wrapped in TLS.
///
/// ACME needs two rustls configs: TLS-ALPN-01 challenge handshakes (ALPN
/// `acme-tls/1`, sent by Let's Encrypt to prove domain control) must be answered
/// with a special challenge certificate, while everything else is served the
/// issued certificate. A plain acceptor cannot do this — it never negotiates
/// `acme-tls/1`, so the challenge fails and no certificate is ever issued — so we
/// peek each ClientHello and route it to the right config.
#[derive(Clone)]
pub enum TlsListener {
    /// A fixed certificate/key acceptor (`tls.certfile`/`tls.keyfile`).
    Manual(TlsAcceptor),
    /// ACME: `acme-tls/1` challenge handshakes go to `challenge`; all other
    /// connections to `default`, which serves the issued certificate.
    Acme {
        default: Arc<ServerConfig>,
        challenge: Arc<ServerConfig>,
    },
}

impl TlsListener {
    /// Completes the TLS handshake for an accepted connection.
    ///
    /// Returns `Ok(None)` when the connection was an ACME TLS-ALPN-01 challenge
    /// answered internally: Let's Encrypt only needs the handshake to present the
    /// challenge certificate, so the caller drops it. `Ok(Some(stream))` is a
    /// normal client connection to drive through SOCKS.
    pub async fn accept(&self, stream: TcpStream) -> std::io::Result<Option<TlsStream<TcpStream>>> {
        match self {
            TlsListener::Manual(acceptor) => acceptor.accept(stream).await.map(Some),
            TlsListener::Acme { default, challenge } => {
                let handshake = LazyConfigAcceptor::new(Acceptor::default(), stream).await?;
                if rustls_acme::is_tls_alpn_challenge(&handshake.client_hello()) {
                    // `into_stream(..).await` drives the handshake to completion,
                    // sending the challenge certificate Let's Encrypt validates.
                    // Then close cleanly with a close_notify — the connection
                    // carries no application data — rather than dropping it abruptly.
                    use tokio::io::AsyncWriteExt;
                    let mut challenge_tls = handshake.into_stream(challenge.clone()).await?;
                    let _ = challenge_tls.shutdown().await;
                    Ok(None)
                } else {
                    handshake.into_stream(default.clone()).await.map(Some)
                }
            }
        }
    }
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
        listener: TlsListener::Manual(TlsAcceptor::from(Arc::new(server_config))),
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
    // The state owns the resolver shared with both rustls configs below,
    // persists the account/certs to the cache dir, and runs the order + renewal
    // loop when polled. `default` serves the issued certificate to clients;
    // `challenge` carries the `acme-tls/1` ALPN and challenge certificate that
    // answer Let's Encrypt's TLS-ALPN-01 validation. The accept loop routes each
    // connection to the right one (see `TlsListener::accept`).
    let mut state = rustls_acme::AcmeConfig::new(acme.domains.clone())
        .contact(acme.email.iter().map(|email| format!("mailto:{email}")))
        .cache(rustls_acme::caches::DirCache::new(acme.cache_dir.clone()))
        .directory_lets_encrypt(!acme.staging)
        .state();
    let default = state.default_rustls_config();
    let challenge = state.challenge_rustls_config();
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
        listener: TlsListener::Acme { default, challenge },
        acme_driver: Some(driver),
    })
}

/// Ensures `dir` exists and is writable, failing fast at startup otherwise.
/// `create_dir_all` alone is not enough: it succeeds on an existing directory
/// even when it is not writable, so probe by writing and removing a temp file.
fn ensure_writable_dir(dir: &Path) -> Result<()> {
    // Reject a pre-placed symlink (or non-directory) at the cache path: an
    // attacker who can write the parent could otherwise redirect the ACME account
    // key and issued certificates elsewhere, since `create_dir_all` silently
    // follows a symlink to a directory.
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(Error::Config(format!(
                "ACME cache directory {} is a symlink; refusing to use it",
                dir.display()
            )));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(Error::Config(format!(
                "ACME cache path {} exists but is not a directory",
                dir.display()
            )));
        }
        _ => {} // does not exist yet, or is a real directory
    }
    create_private_dir(dir).map_err(|e| {
        Error::Config(format!(
            "failed to create ACME cache directory {}: {e}",
            dir.display()
        ))
    })?;
    // Probe with a per-run-unique name (pid + a high-resolution nonce) created
    // exclusively (create_new), so the probe never follows a symlink or clobbers
    // an existing file — the cache dir may be writable by a less-trusted user
    // than this process — and a stale probe left by a crashed run with a reused
    // pid cannot cause a false "not writable".
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(
        ".alighieri-acme-write-test.{}.{nonce}",
        std::process::id()
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file); // close before removing (Windows cannot remove an open file)
                        // The write already proved the directory writable, so a failed cleanup
                        // does not block startup, but warn so the leftover probe is visible.
            if let Err(e) = std::fs::remove_file(&probe) {
                tracing::warn!(
                    path = %probe.display(),
                    error = %e,
                    "could not remove ACME cache write-probe file"
                );
            }
            Ok(())
        }
        Err(e) => Err(Error::Config(format!(
            "ACME cache directory {} is not writable: {e}",
            dir.display()
        ))),
    }
}

/// Creates `dir` (and any missing parents) owner-only (mode `0700`) on Unix, so
/// the ACME account key and certificates it will hold are not group/other
/// readable. An already-existing directory is tightened to `0700` best-effort:
/// `DirBuilder`'s mode applies only to directories it creates, and a cache owned
/// by another user cannot be chmod'd by us, which only warns since it may be
/// deliberately managed elsewhere.
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "ACME cache directory is group/other-accessible (mode {mode:o}) and could not be tightened to 0700; it holds the ACME account key and issued certificates"
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
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
    fn acme_listener_offers_the_tls_alpn_challenge_protocol() {
        // Regression: the listener must answer TLS-ALPN-01. The challenge config
        // has to offer the `acme-tls/1` ALPN (or Let's Encrypt cannot negotiate
        // the challenge and no certificate is ever issued), while the default
        // config must NOT force it on ordinary clients.
        let dir = tempfile::tempdir().unwrap();
        let config = TlsConfig::Acme(crate::config::AcmeConfig {
            domains: vec!["proxy.example.com".into()],
            email: None,
            cache_dir: dir.path().to_path_buf(),
            staging: true,
        });
        let setup = load_acceptor(Some(&config)).unwrap().unwrap();
        let acme_tls = b"acme-tls/1".to_vec();
        match setup.listener {
            TlsListener::Acme { default, challenge } => {
                assert!(
                    challenge.alpn_protocols.contains(&acme_tls),
                    "challenge config must offer the acme-tls/1 ALPN"
                );
                assert!(
                    !default.alpn_protocols.contains(&acme_tls),
                    "default config must not force acme-tls/1 on normal clients"
                );
            }
            TlsListener::Manual(_) => panic!("expected an ACME listener"),
        }
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

    #[cfg(unix)]
    #[test]
    fn ensure_writable_dir_rejects_a_symlinked_cache_dir() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("cache");
        symlink(&real, &link).unwrap();

        let err = ensure_writable_dir(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_writable_dir_creates_a_private_cache_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("acme");

        ensure_writable_dir(&cache).unwrap();

        let mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "a fresh cache dir must be owner-only, got {mode:o}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_writable_dir_tightens_an_existing_loose_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("acme");
        fs::create_dir(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();

        ensure_writable_dir(&cache).unwrap();

        let mode = fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "an existing loose cache dir must be tightened, got {mode:o}"
        );
    }
}
