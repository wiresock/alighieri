//! Process-wide Alighieri connector for the local COM/DVC bridge.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::rdp::mux::{self, ClientHandle, RdpStream, ResolvedTarget};

use super::pipe;

const RECONNECT_MIN: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(5);

/// One reconnecting session manager is shared by every SOCKS connection.
pub(crate) struct RdpConnector {
    current: RwLock<Option<ClientHandle>>,
    shutdown: watch::Sender<bool>,
}

impl RdpConnector {
    pub(crate) fn start() -> Arc<Self> {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let connector = Arc::new(Self {
            current: RwLock::new(None),
            shutdown,
        });
        tokio::spawn(reconnect_loop(Arc::downgrade(&connector), shutdown_rx));
        connector
    }

    pub(crate) async fn resolve(
        &self,
        hostname: &str,
        port: u16,
        timeout: Duration,
    ) -> io::Result<ResolvedTarget> {
        self.handle()
            .await?
            .resolve(hostname, port, timeout)
            .await
            .map_err(mux::MuxError::into_io)
    }

    pub(crate) async fn open_ip(
        &self,
        address: SocketAddr,
        timeout: Duration,
    ) -> io::Result<RdpStream> {
        self.handle()
            .await?
            .open_ip(address, timeout)
            .await
            .map_err(mux::MuxError::into_io)
    }

    async fn handle(&self) -> io::Result<ClientHandle> {
        self.current.read().await.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "no compatible RDP Dynamic Virtual Channel is connected",
            )
        })
    }
}

impl Drop for RdpConnector {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

enum GenerationError {
    Pipe(io::Error),
    Handshake(mux::MuxError),
}

async fn connect_generation(
) -> Result<(ClientHandle, JoinHandle<Result<(), mux::MuxError>>), GenerationError> {
    let pipe = pipe::connect_client()
        .await
        .map_err(GenerationError::Pipe)?;
    mux::start_client_session(pipe)
        .await
        .map_err(GenerationError::Handshake)
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|requested| *requested).await;
}

async fn reconnect_loop(connector: Weak<RdpConnector>, mut shutdown: watch::Receiver<bool>) {
    let mut backoff = RECONNECT_MIN;
    loop {
        let generation = tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => return,
            result = connect_generation() => result,
        };

        match generation {
            Ok((handle, mut driver)) => {
                let Some(owner) = connector.upgrade() else {
                    driver.abort();
                    let _ = driver.await;
                    return;
                };
                *owner.current.write().await = Some(handle);
                drop(owner);

                info!("RDP Dynamic Virtual Channel transport is ready");
                backoff = RECONNECT_MIN;
                let outcome = tokio::select! {
                    biased;
                    _ = wait_for_shutdown(&mut shutdown) => {
                        driver.abort();
                        let _ = driver.await;
                        return;
                    }
                    result = &mut driver => result,
                };

                let Some(owner) = connector.upgrade() else {
                    return;
                };
                *owner.current.write().await = None;
                drop(owner);

                match outcome {
                    Ok(Ok(())) => debug!("RDP transport generation ended"),
                    Ok(Err(error)) => warn!(%error, "RDP transport generation was lost"),
                    Err(error) if error.is_cancelled() => return,
                    Err(error) => warn!(%error, "RDP transport driver failed"),
                }
            }
            Err(GenerationError::Handshake(error)) => {
                debug!(%error, "RDP bridge connected without a compatible agent");
            }
            Err(GenerationError::Pipe(error)) if error.kind() == io::ErrorKind::NotConnected => {
                debug!("waiting for an active RDP Dynamic Virtual Channel");
            }
            Err(GenerationError::Pipe(error)) => {
                warn!(%error, "failed to connect to the local RDP bridge");
            }
        }

        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = backoff.saturating_mul(2).min(RECONNECT_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_connector_persists_shutdown_for_late_observers() {
        let (shutdown, receiver) = watch::channel(false);
        let connector = RdpConnector {
            current: RwLock::new(None),
            shutdown,
        };

        drop(connector);
        assert!(*receiver.borrow());
    }
}
