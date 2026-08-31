//! Remote-session WTS Dynamic Virtual Channel actor.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use windows::core::{Error as WindowsError, PCSTR};
use windows::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, ERROR_TIMEOUT, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::RemoteDesktop::{
    WTSVirtualChannelClose, WTSVirtualChannelOpenEx, WTSVirtualChannelRead, WTSVirtualChannelWrite,
    WTS_CHANNEL_OPTION_DYNAMIC, WTS_CURRENT_SESSION,
};

use crate::rdp::mux::{self, AgentPolicy};

use super::pdu::DvcReassembler;
use super::transport::CHANNEL_NAME;

const CHANNEL_NAME_NUL: &[u8] = b"alighieri::rdp::v1\0";
const ACTOR_QUEUE_CAPACITY: usize = 512;
const BRIDGE_CAPACITY: usize = 128 * 1024;
const READ_BUFFER_SIZE: usize = 64 * 1024;
const READ_TIMEOUT_MS: u32 = 50;
const DVC_WRITE_CHUNK: usize = 1_590;
/// Bound consecutive writes so full-duplex reads and their flow-control frames
/// cannot be starved by a continuously replenished outbound queue.
const OUTBOUND_WRITE_BATCH: usize = 8;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Runs the remote agent in the current interactive RDP session. It retries a
/// lost/missing channel and creates a fresh ALRD generation on every reconnect.
pub async fn run_agent() -> io::Result<()> {
    let Some(policy) = parse_policy(std::env::args().skip(1))? else {
        return Ok(());
    };
    info!(channel = CHANNEL_NAME, "starting Alighieri RDP agent");

    loop {
        let bridge = match open_bridge().await {
            Ok(bridge) => bridge,
            Err(error) => {
                debug!(%error, "RDP Dynamic Virtual Channel is not available yet");
                tokio::select! {
                    result = tokio::signal::ctrl_c() => return result,
                    _ = tokio::time::sleep(RECONNECT_DELAY) => continue,
                }
            }
        };
        info!(
            channel = CHANNEL_NAME,
            "RDP Dynamic Virtual Channel connected"
        );
        tokio::select! {
            result = tokio::signal::ctrl_c() => return result,
            result = mux::run_agent_session(bridge, policy.clone()) => {
                match result {
                    Ok(()) => debug!("RDP agent generation ended"),
                    Err(error) => warn!(%error, "RDP agent generation was lost"),
                }
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

fn parse_policy(arguments: impl IntoIterator<Item = String>) -> io::Result<Option<AgentPolicy>> {
    let mut policy = AgentPolicy::default();
    for argument in arguments {
        match argument.to_ascii_lowercase().as_str() {
            "--deny-loopback" | "/deny-loopback" => policy.deny_loopback = true,
            "--deny-private" | "/deny-private" => policy.deny_private = true,
            "--deny-link-local" | "/deny-link-local" => policy.deny_link_local = true,
            "--help" | "-h" | "/?" => {
                println!("Usage: alighieri-rdp-agent.exe [options]");
                println!("  --deny-loopback    Reject remote loopback destinations");
                println!("  --deny-private     Reject RFC1918/unique-local destinations");
                println!("  --deny-link-local  Reject IPv4/IPv6 link-local destinations");
                return Ok(None);
            }
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown agent option '{unknown}'"),
                ));
            }
        }
    }
    Ok(Some(policy))
}

async fn open_bridge() -> io::Result<DuplexStream> {
    let (mux_side, actor_side) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (outbound_tx, outbound_rx) = mpsc::channel(ACTOR_QUEUE_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel(ACTOR_QUEUE_CAPACITY);
    let (ready_tx, ready_rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("alighieri-rdp-wts".into())
        .spawn(move || wts_actor(outbound_rx, inbound_tx, ready_tx))?;

    ready_rx
        .await
        .map_err(|_| io::Error::other("WTS actor stopped before initialization"))??;
    tokio::spawn(pump_bridge(actor_side, outbound_tx, inbound_rx));
    Ok(mux_side)
}

async fn pump_bridge(
    bridge: DuplexStream,
    outbound: mpsc::Sender<Vec<u8>>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
) {
    let (mut reader, mut writer) = tokio::io::split(bridge);
    let to_channel = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let count = reader.read(&mut buffer).await?;
            if count == 0 {
                return Ok::<(), io::Error>(());
            }
            outbound
                .send(buffer[..count].to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WTS actor closed"))?;
        }
    };
    let from_channel = async {
        while let Some(data) = inbound.recv().await {
            writer.write_all(&data).await?;
        }
        writer.shutdown().await
    };
    tokio::select! {
        result = to_channel => if let Err(error) = result { debug!(%error, "WTS outbound bridge stopped"); },
        result = from_channel => if let Err(error) = result { debug!(%error, "WTS inbound bridge stopped"); },
    }
}

fn wts_actor(
    mut outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    ready: oneshot::Sender<io::Result<()>>,
) {
    let channel = match open_channel() {
        Ok(channel) => {
            if ready.send(Ok(())).is_err() {
                close_channel(channel);
                return;
            }
            channel
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    let mut reassembler = DvcReassembler::new();
    let mut read_buffer = vec![0u8; READ_BUFFER_SIZE];
    loop {
        match drain_outbound_batch(&mut outbound, |data| write_channel(channel, data)) {
            Ok(OutboundQueueState::Open) => {}
            Ok(OutboundQueueState::Closed) => break,
            Err(error) => {
                debug!(%error, "WTS channel write failed");
                break;
            }
        }

        let mut count = 0u32;
        // SAFETY: the channel handle is owned exclusively by this actor thread;
        // the mutable buffer and count out pointer remain live for the call.
        let read = unsafe {
            WTSVirtualChannelRead(channel, READ_TIMEOUT_MS, &mut read_buffer, &mut count)
        };
        if let Err(error) = read {
            // A timeout is the actor's scheduling tick, not a session failure.
            // Inspect the error already captured by windows-rs rather than
            // consulting the thread-local last-error value a second time.
            if is_win32_error(&error, ERROR_TIMEOUT) {
                continue;
            }
            let win32 = win32_error_code(&error);
            debug!(%error, ?win32, "WTS channel read failed");
            break;
        }
        if count == 0 {
            break;
        }
        let count = count as usize;
        if count > read_buffer.len() {
            warn!(count, "WTS returned an impossible read length");
            break;
        }
        match reassembler.push(&read_buffer[..count]) {
            Ok(Some(message)) => {
                if inbound.blocking_send(message).is_err() {
                    break;
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!(%error, "malformed WTS DVC PDU sequence");
                break;
            }
        }
    }
    close_channel(channel);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutboundQueueState {
    Open,
    Closed,
}

fn drain_outbound_batch(
    outbound: &mut mpsc::Receiver<Vec<u8>>,
    mut write: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<OutboundQueueState> {
    for _ in 0..OUTBOUND_WRITE_BATCH {
        match outbound.try_recv() {
            Ok(data) => write(&data)?,
            Err(mpsc::error::TryRecvError::Empty) => return Ok(OutboundQueueState::Open),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Ok(OutboundQueueState::Closed);
            }
        }
    }

    if outbound.is_closed() && outbound.is_empty() {
        Ok(OutboundQueueState::Closed)
    } else {
        Ok(OutboundQueueState::Open)
    }
}

fn open_channel() -> io::Result<HANDLE> {
    // SAFETY: channel name is static ASCII with a trailing NUL. The returned
    // handle never leaves the single owner actor thread.
    let channel = unsafe {
        WTSVirtualChannelOpenEx(
            WTS_CURRENT_SESSION,
            PCSTR(CHANNEL_NAME_NUL.as_ptr()),
            WTS_CHANNEL_OPTION_DYNAMIC,
        )
    }
    .map_err(windows_error)?;
    if channel.is_invalid() || channel.0.is_null() {
        Err(io::Error::other("WTS returned an invalid DVC handle"))
    } else {
        Ok(channel)
    }
}

fn write_channel(channel: HANDLE, data: &[u8]) -> io::Result<()> {
    for chunk in data.chunks(DVC_WRITE_CHUNK) {
        let mut written = 0u32;
        // SAFETY: the actor exclusively owns `channel`; WTS copies the live
        // chunk before returning and initializes `written`.
        unsafe { WTSVirtualChannelWrite(channel, chunk, &mut written) }.map_err(windows_error)?;
        if written as usize != chunk.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("WTS wrote {written} of {} DVC bytes", chunk.len()),
            ));
        }
    }
    Ok(())
}

fn close_channel(channel: HANDLE) {
    // SAFETY: called exactly once by the actor that owns the channel handle.
    if let Err(error) = unsafe { WTSVirtualChannelClose(channel) } {
        if !is_win32_error(&error, ERROR_BROKEN_PIPE)
            && !is_win32_error(&error, ERROR_PIPE_NOT_CONNECTED)
        {
            let win32 = win32_error_code(&error);
            debug!(%error, ?win32, "failed to close WTS DVC handle");
        }
    }
}

fn is_win32_error(error: &WindowsError, expected: WIN32_ERROR) -> bool {
    win32_error_code(error) == Some(expected.0)
}

fn win32_error_code(error: &WindowsError) -> Option<u32> {
    let hresult = error.code().0 as u32;
    (hresult & 0xffff_0000 == 0x8007_0000).then_some(hresult & 0x0000_ffff)
}

fn windows_error(error: WindowsError) -> io::Error {
    match win32_error_code(&error) {
        Some(code) => io::Error::from_raw_os_error(code as i32),
        None => io::Error::other(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::HRESULT;

    #[test]
    fn policy_arguments_are_explicit_and_help_exits() {
        let policy = parse_policy([
            "--deny-loopback".to_owned(),
            "--deny-private".to_owned(),
            "--deny-link-local".to_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(policy.deny_loopback && policy.deny_private && policy.deny_link_local);
        assert!(parse_policy(["--help".to_owned()]).unwrap().is_none());
        assert!(parse_policy(["--unknown".to_owned()]).is_err());
    }

    #[test]
    fn outbound_drain_is_bounded_and_detects_disconnect() {
        let (sender, mut receiver) = mpsc::channel(OUTBOUND_WRITE_BATCH + 1);
        for value in 0..=OUTBOUND_WRITE_BATCH {
            sender.try_send(vec![value as u8]).unwrap();
        }

        let mut written = Vec::new();
        let state = drain_outbound_batch(&mut receiver, |data| {
            written.push(data[0]);
            Ok(())
        })
        .unwrap();
        assert_eq!(state, OutboundQueueState::Open);
        assert_eq!(written.len(), OUTBOUND_WRITE_BATCH);
        assert_eq!(receiver.len(), 1);

        drop(sender);
        let state = drain_outbound_batch(&mut receiver, |data| {
            written.push(data[0]);
            Ok(())
        })
        .unwrap();
        assert_eq!(state, OutboundQueueState::Closed);
        assert_eq!(written.len(), OUTBOUND_WRITE_BATCH + 1);
    }

    #[test]
    fn hresult_mapping_uses_captured_win32_code() {
        let timeout = WindowsError::from_hresult(HRESULT::from_win32(ERROR_TIMEOUT.0));
        assert!(is_win32_error(&timeout, ERROR_TIMEOUT));
        assert_eq!(
            windows_error(timeout).raw_os_error(),
            Some(ERROR_TIMEOUT.0 as i32)
        );

        let generic = WindowsError::from_hresult(HRESULT(0x8000_4005_u32 as i32));
        assert_eq!(win32_error_code(&generic), None);
        assert_eq!(windows_error(generic).raw_os_error(), None);
    }
}
