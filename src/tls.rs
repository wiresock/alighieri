//! TLS listener support.
//!
//! This module stays at the transport boundary: it builds a `TlsAcceptor` for
//! the server accept loop, while SOCKS5 negotiation and relay logic remain
//! unaware of whether the client stream is plaintext TCP or TLS-wrapped TCP.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::pem::{self, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::config::{Config, TlsConfig};
use crate::errors::{Error, Result};

pub fn validate_config(config: &Config) -> Result<()> {
    let _ = load_acceptor(config.tls.as_ref())?;
    Ok(())
}

pub fn load_acceptor(config: Option<&TlsConfig>) -> Result<Option<TlsAcceptor>> {
    let Some(config) = config else {
        return Ok(None);
    };

    let certs = load_certs(&config.cert_file)?;
    if certs.is_empty() {
        return Err(Error::Config(format!(
            "TLS certificate file {} did not contain any certificates",
            config.cert_file.display()
        )));
    }

    let key = load_private_key(&config.key_file)?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("invalid TLS certificate/key pair: {e}")))?;

    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
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

        let config = TlsConfig {
            cert_file,
            key_file,
        };

        assert!(load_acceptor(Some(&config)).unwrap().is_some());
    }

    #[test]
    fn rejects_missing_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert_file = dir.path().join("server.crt");
        let key_file = dir.path().join("server.key");
        fs::write(&cert_file, CERT).unwrap();
        fs::write(&key_file, "not a private key").unwrap();

        let config = TlsConfig {
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
