//! ALRD version 1 wire-format primitives.
//!
//! This module deliberately contains no COM, WTS, socket, or policy code. It
//! provides strongly typed frames, strict bounded validation, an incremental
//! decoder for DVC-sized arbitrary chunks, and exact-frame async I/O helpers.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Four-byte marker at the start of every ALRD frame.
pub const MAGIC: [u8; 4] = *b"ALRD";
/// The ALRD protocol version implemented by this codec.
pub const VERSION: u8 = 1;
/// Size of the fixed ALRD frame header.
pub const HEADER_LEN: usize = 16;
/// Largest payload admitted by the generic frame envelope.
pub const MAX_FRAME_PAYLOAD: usize = 65_536;
/// Largest DATA payload admitted by ALRD v1.
pub const MAX_DATA_PAYLOAD: usize = 16_384;
/// Largest UTF-8 hostname, in bytes.
pub const MAX_HOSTNAME_LEN: usize = 253;
/// Largest candidate set in one RESOLVE_OK frame.
pub const MAX_RESOLVE_ADDRESSES: usize = 16;
/// Largest UTF-8 OPEN_ERROR diagnostic, in bytes.
pub const MAX_DIAGNOSTIC_LEN: usize = 256;
/// Default and maximum receive window advertised by an ALRD v1 peer.
pub const INITIAL_WINDOW: u32 = 262_144;
/// Maximum number of simultaneous logical streams in one generation.
pub const MAX_STREAMS: u32 = 128;
/// Descriptive alias retained for call sites that spell out the receive side.
pub const INITIAL_RECEIVE_WINDOW: u32 = INITIAL_WINDOW;
/// Descriptive alias retained for call sites that spell out concurrency.
pub const MAX_CONCURRENT_STREAMS: u32 = MAX_STREAMS;
/// Bounded outbound DATA queue size per direction.
pub const DATA_QUEUE_CAPACITY: usize = 512;
/// Bounded outbound control queue size per direction.
pub const CONTROL_QUEUE_CAPACITY: usize = 256;
/// Maximum aggregate payload capacity of all per-stream inbound and outbound
/// buffers at one mux endpoint (two windows for every possible stream).
pub const MAX_STREAM_BUFFER_BYTES: usize = 2 * INITIAL_WINDOW as usize * MAX_STREAMS as usize;
/// Maximum aggregate DATA payload held by the shared ordered writer queue.
pub const MAX_ORDERED_DATA_QUEUE_BYTES: usize = DATA_QUEUE_CAPACITY * MAX_DATA_PAYLOAD;
/// Maximum number of undecoded bytes retained by [`FrameDecoder`].
pub const MAX_DECODER_BUFFERED: usize = 2 * (HEADER_LEN + MAX_FRAME_PAYLOAD);

const HELLO_PAYLOAD_LEN: usize = 24;
const IPV4_ADDRESS_LEN: usize = 7;
const IPV6_ADDRESS_LEN: usize = 23;

/// ALRD v1 message type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    Hello = 1,
    Resolve = 2,
    ResolveOk = 3,
    Open = 4,
    OpenOk = 5,
    OpenError = 6,
    Data = 7,
    ShutdownWrite = 8,
    Close = 9,
    WindowUpdate = 10,
    Ping = 11,
    Pong = 12,
}

impl MessageType {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn is_session(self) -> bool {
        matches!(
            self,
            MessageType::Hello | MessageType::Ping | MessageType::Pong
        )
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Resolve),
            3 => Ok(Self::ResolveOk),
            4 => Ok(Self::Open),
            5 => Ok(Self::OpenOk),
            6 => Ok(Self::OpenError),
            7 => Ok(Self::Data),
            8 => Ok(Self::ShutdownWrite),
            9 => Ok(Self::Close),
            10 => Ok(Self::WindowUpdate),
            11 => Ok(Self::Ping),
            12 => Ok(Self::Pong),
            other => Err(ProtocolError::UnknownMessageType(other)),
        }
    }
}

/// The endpoint role advertised in HELLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Role {
    Local = 1,
    Agent = 2,
}

impl Role {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn opposite(self) -> Self {
        match self {
            Role::Local => Role::Agent,
            Role::Agent => Role::Local,
        }
    }
}

impl TryFrom<u8> for Role {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Local),
            2 => Ok(Self::Agent),
            other => Err(ProtocolError::InvalidRole(other)),
        }
    }
}

/// Error code carried by OPEN_ERROR (also used for resolution failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpenErrorCode {
    General = 1,
    PolicyDenied = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    Timeout = 6,
    AddressTypeUnsupported = 7,
    ResourceLimit = 8,
}

impl OpenErrorCode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for OpenErrorCode {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::General),
            2 => Ok(Self::PolicyDenied),
            3 => Ok(Self::NetworkUnreachable),
            4 => Ok(Self::HostUnreachable),
            5 => Ok(Self::ConnectionRefused),
            6 => Ok(Self::Timeout),
            7 => Ok(Self::AddressTypeUnsupported),
            8 => Ok(Self::ResourceLimit),
            other => Err(ProtocolError::InvalidOpenErrorCode(other)),
        }
    }
}

/// Reason carried by CLOSE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CloseReason {
    Normal = 0,
    Cancelled = 1,
    Protocol = 2,
    Io = 3,
    ResourceLimit = 4,
}

impl CloseReason {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for CloseReason {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Cancelled),
            2 => Ok(Self::Protocol),
            3 => Ok(Self::Io),
            4 => Ok(Self::ResourceLimit),
            other => Err(ProtocolError::InvalidCloseReason(other)),
        }
    }
}

/// Capability advertisement carried by HELLO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub role: Role,
    pub min_version: u8,
    pub max_version: u8,
    pub max_data: u32,
    pub receive_window: u32,
    pub max_streams: u32,
    pub generation_nonce: u64,
}

impl Hello {
    /// Constructs the standard ALRD v1 capability advertisement.
    pub const fn new(role: Role, generation_nonce: u64) -> Self {
        Self {
            role,
            min_version: VERSION,
            max_version: VERSION,
            max_data: MAX_DATA_PAYLOAD as u32,
            receive_window: INITIAL_RECEIVE_WINDOW,
            max_streams: MAX_CONCURRENT_STREAMS,
            generation_nonce,
        }
    }

    /// Validates a version-1 advertisement without considering its peer.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.min_version == 0
            || self.min_version > self.max_version
            || !(self.min_version..=self.max_version).contains(&VERSION)
        {
            return Err(ProtocolError::InvalidHello(
                "version range does not include ALRD v1",
            ));
        }
        if !(1..=MAX_DATA_PAYLOAD as u32).contains(&self.max_data) {
            return Err(ProtocolError::InvalidHello(
                "max_data is outside ALRD v1 bounds",
            ));
        }
        if !(1..=INITIAL_RECEIVE_WINDOW).contains(&self.receive_window) {
            return Err(ProtocolError::InvalidHello(
                "receive_window is outside ALRD v1 bounds",
            ));
        }
        if !(1..=MAX_CONCURRENT_STREAMS).contains(&self.max_streams) {
            return Err(ProtocolError::InvalidHello(
                "max_streams is outside ALRD v1 bounds",
            ));
        }
        Ok(())
    }

    /// Validates the two advertisements and returns their smaller common limits.
    pub fn negotiate(&self, peer: &Hello) -> Result<NegotiatedLimits, ProtocolError> {
        self.validate()?;
        peer.validate()?;
        if peer.role != self.role.opposite() {
            return Err(ProtocolError::SameHelloRole(self.role));
        }
        Ok(NegotiatedLimits {
            max_data: self.max_data.min(peer.max_data),
            receive_window: self.receive_window.min(peer.receive_window),
            max_streams: self.max_streams.min(peer.max_streams),
        })
    }
}

/// Effective limits for a ready generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedLimits {
    pub max_data: u32,
    pub receive_window: u32,
    pub max_streams: u32,
}

/// A decoded ALRD v1 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello(Hello),
    Resolve {
        stream_id: u32,
        port: u16,
        hostname: String,
    },
    ResolveOk {
        stream_id: u32,
        addresses: Vec<SocketAddr>,
    },
    Open {
        stream_id: u32,
        address: SocketAddr,
    },
    OpenOk {
        stream_id: u32,
        bound_address: SocketAddr,
    },
    OpenError {
        stream_id: u32,
        code: OpenErrorCode,
        diagnostic: String,
    },
    Data {
        stream_id: u32,
        payload: Vec<u8>,
    },
    ShutdownWrite {
        stream_id: u32,
    },
    Close {
        stream_id: u32,
        reason: CloseReason,
    },
    WindowUpdate {
        stream_id: u32,
        credit: u32,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

impl Frame {
    pub const fn message_type(&self) -> MessageType {
        match self {
            Frame::Hello(_) => MessageType::Hello,
            Frame::Resolve { .. } => MessageType::Resolve,
            Frame::ResolveOk { .. } => MessageType::ResolveOk,
            Frame::Open { .. } => MessageType::Open,
            Frame::OpenOk { .. } => MessageType::OpenOk,
            Frame::OpenError { .. } => MessageType::OpenError,
            Frame::Data { .. } => MessageType::Data,
            Frame::ShutdownWrite { .. } => MessageType::ShutdownWrite,
            Frame::Close { .. } => MessageType::Close,
            Frame::WindowUpdate { .. } => MessageType::WindowUpdate,
            Frame::Ping { .. } => MessageType::Ping,
            Frame::Pong { .. } => MessageType::Pong,
        }
    }

    /// Returns zero for session frames and the logical stream ID otherwise.
    pub const fn stream_id(&self) -> u32 {
        match self {
            Frame::Hello(_) | Frame::Ping { .. } | Frame::Pong { .. } => 0,
            Frame::Resolve { stream_id, .. }
            | Frame::ResolveOk { stream_id, .. }
            | Frame::Open { stream_id, .. }
            | Frame::OpenOk { stream_id, .. }
            | Frame::OpenError { stream_id, .. }
            | Frame::Data { stream_id, .. }
            | Frame::ShutdownWrite { stream_id }
            | Frame::Close { stream_id, .. }
            | Frame::WindowUpdate { stream_id, .. } => *stream_id,
        }
    }

    /// Applies all context-free ALRD v1 bounds before encoding.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_stream_id(self.message_type(), self.stream_id())?;
        match self {
            Frame::Hello(hello) => hello.validate(),
            Frame::Resolve { port, hostname, .. } => {
                validate_port(self.message_type(), *port)?;
                validate_hostname(hostname)
            }
            Frame::ResolveOk { addresses, .. } => validate_address_list(addresses),
            Frame::Open { address, .. } => validate_port(self.message_type(), address.port()),
            Frame::OpenOk { bound_address, .. } => {
                validate_port(self.message_type(), bound_address.port())
            }
            Frame::OpenError { diagnostic, .. } => {
                if diagnostic.len() > MAX_DIAGNOSTIC_LEN {
                    Err(ProtocolError::DiagnosticTooLong(diagnostic.len()))
                } else if diagnostic.chars().any(char::is_control) {
                    Err(ProtocolError::DiagnosticContainsControl)
                } else {
                    Ok(())
                }
            }
            Frame::Data { payload, .. } => {
                if payload.is_empty() {
                    Err(ProtocolError::EmptyData)
                } else if payload.len() > MAX_DATA_PAYLOAD {
                    Err(ProtocolError::DataTooLarge(payload.len()))
                } else {
                    Ok(())
                }
            }
            Frame::ShutdownWrite { .. } | Frame::Close { .. } => Ok(()),
            Frame::WindowUpdate { credit, .. } => {
                if *credit == 0 {
                    Err(ProtocolError::ZeroWindowUpdate)
                } else {
                    Ok(())
                }
            }
            Frame::Ping { .. } | Frame::Pong { .. } => Ok(()),
        }
    }

    /// Serialises one complete frame.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut encoded = Vec::new();
        self.encode_into(&mut encoded)?;
        Ok(encoded)
    }

    /// Appends one complete frame to `output` atomically with respect to
    /// validation: an invalid frame leaves `output` unchanged.
    pub fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
        self.validate()?;
        let mut payload = Vec::new();
        match self {
            Frame::Hello(hello) => {
                payload.push(hello.role.as_u8());
                payload.push(hello.min_version);
                payload.push(hello.max_version);
                payload.push(0);
                put_u32(&mut payload, hello.max_data);
                put_u32(&mut payload, hello.receive_window);
                put_u32(&mut payload, hello.max_streams);
                put_u64(&mut payload, hello.generation_nonce);
            }
            Frame::Resolve { port, hostname, .. } => {
                put_u16(&mut payload, *port);
                put_u16(&mut payload, hostname.len() as u16);
                payload.extend_from_slice(hostname.as_bytes());
            }
            Frame::ResolveOk { addresses, .. } => {
                put_u16(&mut payload, addresses.len() as u16);
                for address in addresses {
                    encode_address(*address, &mut payload);
                }
            }
            Frame::Open { address, .. } => encode_address(*address, &mut payload),
            Frame::OpenOk { bound_address, .. } => encode_address(*bound_address, &mut payload),
            Frame::OpenError {
                code, diagnostic, ..
            } => {
                payload.push(code.as_u8());
                put_u16(&mut payload, diagnostic.len() as u16);
                payload.extend_from_slice(diagnostic.as_bytes());
            }
            Frame::Data { payload: bytes, .. } => payload.extend_from_slice(bytes),
            Frame::ShutdownWrite { .. } => {}
            Frame::Close { reason, .. } => payload.push(reason.as_u8()),
            Frame::WindowUpdate { credit, .. } => put_u32(&mut payload, *credit),
            Frame::Ping { nonce } | Frame::Pong { nonce } => put_u64(&mut payload, *nonce),
        }
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge(payload.len() as u32));
        }

        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&MAGIC);
        frame.push(VERSION);
        frame.push(self.message_type().as_u8());
        put_u16(&mut frame, 0);
        put_u32(&mut frame, self.stream_id());
        put_u32(&mut frame, payload.len() as u32);
        frame.extend_from_slice(&payload);
        output.extend_from_slice(&frame);
        Ok(())
    }

    /// Decodes exactly one complete frame and rejects trailing/coalesced bytes.
    pub fn decode_exact(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() < HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader {
                received: encoded.len(),
            });
        }
        let header = Header::decode(&encoded[..HEADER_LEN])?;
        let expected = HEADER_LEN + header.payload_len as usize;
        if encoded.len() < expected {
            return Err(ProtocolError::TruncatedFrame {
                message_type: header.message_type,
                expected,
                received: encoded.len(),
            });
        }
        if encoded.len() > expected {
            return Err(ProtocolError::TrailingFrameBytes(encoded.len() - expected));
        }
        decode_payload(header, &encoded[HEADER_LEN..])
    }
}

/// Parsed, validated fixed header. Payload-specific validation happens only
/// after all declared payload bytes are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub message_type: MessageType,
    pub stream_id: u32,
    pub payload_len: u32,
}

impl Header {
    pub fn decode(header: &[u8]) -> Result<Self, ProtocolError> {
        if header.len() < HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader {
                received: header.len(),
            });
        }
        if header[..4] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if header[4] != VERSION {
            return Err(ProtocolError::UnsupportedVersion(header[4]));
        }
        let message_type = MessageType::try_from(header[5])?;
        let flags = u16::from_le_bytes([header[6], header[7]]);
        if flags != 0 {
            return Err(ProtocolError::NonZeroFlags(flags));
        }
        let stream_id = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        validate_stream_id(message_type, stream_id)?;
        let payload_len = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        if payload_len as usize > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge(payload_len));
        }
        Ok(Self {
            message_type,
            stream_id,
            payload_len,
        })
    }
}

/// Fatal, peer-visible-independent validation failures in ALRD framing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("invalid ALRD magic")]
    InvalidMagic,
    #[error("unsupported ALRD version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown ALRD message type {0}")]
    UnknownMessageType(u8),
    #[error("ALRD v1 flags must be zero, got 0x{0:04x}")]
    NonZeroFlags(u16),
    #[error("session message {message_type:?} used nonzero stream ID {stream_id}")]
    NonZeroSessionStreamId {
        message_type: MessageType,
        stream_id: u32,
    },
    #[error("stream message {0:?} used stream ID zero")]
    ZeroStreamId(MessageType),
    #[error("ALRD payload length {0} exceeds the frame limit")]
    PayloadTooLarge(u32),
    #[error("truncated ALRD header: received {received} of {HEADER_LEN} bytes")]
    TruncatedHeader { received: usize },
    #[error("truncated {message_type:?} frame: received {received} of {expected} total bytes")]
    TruncatedFrame {
        message_type: MessageType,
        expected: usize,
        received: usize,
    },
    #[error("ALRD input contains {0} trailing bytes after one frame")]
    TrailingFrameBytes(usize),
    #[error("{message_type:?} payload is truncated while reading {field}")]
    TruncatedPayload {
        message_type: MessageType,
        field: &'static str,
    },
    #[error("{message_type:?} payload has {remaining} trailing bytes")]
    TrailingPayload {
        message_type: MessageType,
        remaining: usize,
    },
    #[error("invalid HELLO role {0}")]
    InvalidRole(u8),
    #[error("invalid HELLO reserved byte {0}")]
    NonZeroHelloReserved(u8),
    #[error("invalid HELLO: {0}")]
    InvalidHello(&'static str),
    #[error("both HELLO peers advertised role {0:?}")]
    SameHelloRole(Role),
    #[error("hostname is empty")]
    EmptyHostname,
    #[error("hostname length {0} exceeds the ALRD limit")]
    HostnameTooLong(usize),
    #[error("hostname is not valid UTF-8")]
    HostnameNotUtf8,
    #[error("hostname is structurally invalid: {0}")]
    InvalidHostname(String),
    #[error("RESOLVE_OK address count {0} exceeds the ALRD limit")]
    TooManyAddresses(usize),
    #[error("RESOLVE_OK contains duplicate address {0}")]
    DuplicateAddress(SocketAddr),
    #[error("unknown ALRD address family {0}")]
    InvalidAddressFamily(u8),
    #[error("{0:?} contains TCP port zero")]
    ZeroPort(MessageType),
    #[error("invalid OPEN_ERROR code {0}")]
    InvalidOpenErrorCode(u8),
    #[error("OPEN_ERROR diagnostic is not valid UTF-8")]
    DiagnosticNotUtf8,
    #[error("OPEN_ERROR diagnostic length {0} exceeds the ALRD limit")]
    DiagnosticTooLong(usize),
    #[error("OPEN_ERROR diagnostic contains a control character")]
    DiagnosticContainsControl,
    #[error("DATA payload must not be empty")]
    EmptyData,
    #[error("DATA payload length {0} exceeds the ALRD v1 limit")]
    DataTooLarge(usize),
    #[error("invalid CLOSE reason {0}")]
    InvalidCloseReason(u8),
    #[error("WINDOW_UPDATE credit must be nonzero")]
    ZeroWindowUpdate,
    #[error("incremental decoder exceeded its bounded undecoded buffer")]
    DecoderBufferLimit,
}

/// Combined transport/protocol error for the exact-frame async helpers.
#[derive(Debug, Error)]
pub enum FrameIoError {
    #[error("ALRD transport I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Incremental decoder for arbitrary fragmentation and coalescing.
///
/// At most [`MAX_DECODER_BUFFERED`] *undecoded* bytes are retained. A very large
/// input chunk containing many complete frames is processed in bounded slices,
/// so coalescing itself does not trip the retained-buffer limit.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    start: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len().saturating_sub(self.start)
    }

    /// Supplies another arbitrary byte chunk and returns every newly complete
    /// frame in wire order.
    pub fn push(&mut self, mut input: &[u8]) -> Result<Vec<Frame>, ProtocolError> {
        let mut frames = Vec::new();
        self.decode_available(&mut frames)?;
        while !input.is_empty() {
            self.compact();
            let available = MAX_DECODER_BUFFERED
                .checked_sub(self.buffered_len())
                .ok_or(ProtocolError::DecoderBufferLimit)?;
            if available == 0 {
                return Err(ProtocolError::DecoderBufferLimit);
            }
            let take = available.min(input.len());
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            self.decode_available(&mut frames)?;
        }
        self.compact_if_worthwhile();
        Ok(frames)
    }

    /// Verifies that the byte stream ended exactly on a frame boundary.
    pub fn finish(&self) -> Result<(), ProtocolError> {
        let remaining = &self.buffer[self.start..];
        if remaining.is_empty() {
            return Ok(());
        }
        if remaining.len() < HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader {
                received: remaining.len(),
            });
        }
        let header = Header::decode(&remaining[..HEADER_LEN])?;
        Err(ProtocolError::TruncatedFrame {
            message_type: header.message_type,
            expected: HEADER_LEN + header.payload_len as usize,
            received: remaining.len(),
        })
    }

    /// Drops all partial bytes, for use only when abandoning a generation.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.start = 0;
    }

    fn decode_available(&mut self, frames: &mut Vec<Frame>) -> Result<(), ProtocolError> {
        loop {
            let remaining = &self.buffer[self.start..];
            if remaining.len() < HEADER_LEN {
                return Ok(());
            }
            // Header validation happens as soon as all 16 bytes exist, before
            // waiting for or allocating according to its declared length.
            let header = Header::decode(&remaining[..HEADER_LEN])?;
            let frame_len = HEADER_LEN + header.payload_len as usize;
            if remaining.len() < frame_len {
                return Ok(());
            }
            let frame = decode_payload(header, &remaining[HEADER_LEN..frame_len])?;
            self.start += frame_len;
            frames.push(frame);
        }
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        self.buffer.drain(..self.start);
        self.start = 0;
    }

    fn compact_if_worthwhile(&mut self) {
        if self.start == self.buffer.len() {
            self.clear();
        } else if self.start >= HEADER_LEN + MAX_FRAME_PAYLOAD {
            self.compact();
        }
    }
}

/// Reads exactly one frame from an ordered byte stream. The fixed header is
/// validated before allocating the bounded payload buffer.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, FrameIoError> {
    let mut fixed = [0u8; HEADER_LEN];
    reader.read_exact(&mut fixed).await?;
    let header = Header::decode(&fixed)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(decode_payload(header, &payload)?)
}

/// Encodes and writes exactly one frame to an ordered byte stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), FrameIoError> {
    let encoded = frame.encode()?;
    writer.write_all(&encoded).await?;
    Ok(())
}

/// Encodes an IP socket address in ALRD's compact little-endian form.
/// IPv4-mapped IPv6 addresses are canonicalised to IPv4. IPv6 scope IDs are
/// retained so link-local destinations remain usable; flow information is
/// deliberately normalised to zero.
pub fn encode_address(address: SocketAddr, output: &mut Vec<u8>) {
    let address = canonicalize_address(address);
    match address {
        SocketAddr::V4(v4) => {
            output.push(1);
            put_u16(output, v4.port());
            output.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            output.push(2);
            put_u16(output, v6.port());
            output.extend_from_slice(&v6.ip().octets());
            put_u32(output, v6.scope_id());
        }
    }
}

/// Decodes one ALRD address prefix, returning the address and consumed bytes.
pub fn decode_address(input: &[u8]) -> Result<(SocketAddr, usize), ProtocolError> {
    let Some(&family) = input.first() else {
        return Err(ProtocolError::TruncatedPayload {
            message_type: MessageType::Open,
            field: "address family",
        });
    };
    let needed = match family {
        1 => IPV4_ADDRESS_LEN,
        2 => IPV6_ADDRESS_LEN,
        other => return Err(ProtocolError::InvalidAddressFamily(other)),
    };
    if input.len() < needed {
        return Err(ProtocolError::TruncatedPayload {
            message_type: MessageType::Open,
            field: "address",
        });
    }
    let port = u16::from_le_bytes([input[1], input[2]]);
    let address = if family == 1 {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(input[3], input[4], input[5], input[6])),
            port,
        )
    } else {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&input[3..19]);
        let scope_id = u32::from_le_bytes([input[19], input[20], input[21], input[22]]);
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, scope_id))
    };
    Ok((canonicalize_address(address), needed))
}

/// Canonicalises an IPv4-mapped IPv6 socket address and clears IPv6 flow info.
pub fn canonicalize_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(address) => SocketAddr::V4(address),
        SocketAddr::V6(address) => match IpAddr::V6(*address.ip()).to_canonical() {
            IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), address.port()),
            IpAddr::V6(ip) => {
                SocketAddr::V6(SocketAddrV6::new(ip, address.port(), 0, address.scope_id()))
            }
        },
    }
}

fn decode_payload(header: Header, payload: &[u8]) -> Result<Frame, ProtocolError> {
    debug_assert_eq!(payload.len(), header.payload_len as usize);
    let ty = header.message_type;
    let stream_id = header.stream_id;
    let mut cursor = PayloadCursor::new(ty, payload);
    let frame = match ty {
        MessageType::Hello => {
            cursor.require_exact_len(HELLO_PAYLOAD_LEN)?;
            let role = Role::try_from(cursor.u8("role")?)?;
            let min_version = cursor.u8("min_version")?;
            let max_version = cursor.u8("max_version")?;
            let reserved = cursor.u8("reserved")?;
            if reserved != 0 {
                return Err(ProtocolError::NonZeroHelloReserved(reserved));
            }
            let hello = Hello {
                role,
                min_version,
                max_version,
                max_data: cursor.u32("max_data")?,
                receive_window: cursor.u32("receive_window")?,
                max_streams: cursor.u32("max_streams")?,
                generation_nonce: cursor.u64("generation_nonce")?,
            };
            hello.validate()?;
            Frame::Hello(hello)
        }
        MessageType::Resolve => {
            let port = cursor.u16("port")?;
            let name_len = cursor.u16("name_len")? as usize;
            if name_len > MAX_HOSTNAME_LEN {
                return Err(ProtocolError::HostnameTooLong(name_len));
            }
            let raw = cursor.bytes(name_len, "hostname")?;
            let hostname = std::str::from_utf8(raw)
                .map_err(|_| ProtocolError::HostnameNotUtf8)?
                .to_owned();
            validate_hostname(&hostname)?;
            Frame::Resolve {
                stream_id,
                port,
                hostname,
            }
        }
        MessageType::ResolveOk => {
            let count = cursor.u16("count")? as usize;
            if count > MAX_RESOLVE_ADDRESSES {
                return Err(ProtocolError::TooManyAddresses(count));
            }
            let mut addresses = Vec::with_capacity(count);
            let mut unique = HashSet::with_capacity(count);
            for _ in 0..count {
                let (address, consumed) = decode_address_with_type(cursor.remaining(), ty)?;
                cursor.advance(consumed, "address")?;
                if !unique.insert(address) {
                    return Err(ProtocolError::DuplicateAddress(address));
                }
                addresses.push(address);
            }
            Frame::ResolveOk {
                stream_id,
                addresses,
            }
        }
        MessageType::Open => {
            let (address, consumed) = decode_address_with_type(cursor.remaining(), ty)?;
            cursor.advance(consumed, "address")?;
            Frame::Open { stream_id, address }
        }
        MessageType::OpenOk => {
            let (bound_address, consumed) = decode_address_with_type(cursor.remaining(), ty)?;
            cursor.advance(consumed, "bound address")?;
            Frame::OpenOk {
                stream_id,
                bound_address,
            }
        }
        MessageType::OpenError => {
            let code = OpenErrorCode::try_from(cursor.u8("code")?)?;
            let text_len = cursor.u16("text_len")? as usize;
            if text_len > MAX_DIAGNOSTIC_LEN {
                return Err(ProtocolError::DiagnosticTooLong(text_len));
            }
            let diagnostic = std::str::from_utf8(cursor.bytes(text_len, "diagnostic")?)
                .map_err(|_| ProtocolError::DiagnosticNotUtf8)?
                .to_owned();
            Frame::OpenError {
                stream_id,
                code,
                diagnostic,
            }
        }
        MessageType::Data => {
            if payload.is_empty() {
                return Err(ProtocolError::EmptyData);
            }
            if payload.len() > MAX_DATA_PAYLOAD {
                return Err(ProtocolError::DataTooLarge(payload.len()));
            }
            cursor.advance(payload.len(), "data")?;
            Frame::Data {
                stream_id,
                payload: payload.to_vec(),
            }
        }
        MessageType::ShutdownWrite => {
            cursor.require_exact_len(0)?;
            Frame::ShutdownWrite { stream_id }
        }
        MessageType::Close => {
            cursor.require_exact_len(1)?;
            let reason = CloseReason::try_from(cursor.u8("reason")?)?;
            Frame::Close { stream_id, reason }
        }
        MessageType::WindowUpdate => {
            cursor.require_exact_len(4)?;
            let credit = cursor.u32("credit")?;
            if credit == 0 {
                return Err(ProtocolError::ZeroWindowUpdate);
            }
            Frame::WindowUpdate { stream_id, credit }
        }
        MessageType::Ping | MessageType::Pong => {
            cursor.require_exact_len(8)?;
            let nonce = cursor.u64("nonce")?;
            if ty == MessageType::Ping {
                Frame::Ping { nonce }
            } else {
                Frame::Pong { nonce }
            }
        }
    };
    cursor.finish()?;
    frame.validate()?;
    Ok(frame)
}

fn validate_stream_id(message_type: MessageType, stream_id: u32) -> Result<(), ProtocolError> {
    if message_type.is_session() {
        if stream_id != 0 {
            return Err(ProtocolError::NonZeroSessionStreamId {
                message_type,
                stream_id,
            });
        }
    } else if stream_id == 0 {
        return Err(ProtocolError::ZeroStreamId(message_type));
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<(), ProtocolError> {
    if hostname.is_empty() {
        return Err(ProtocolError::EmptyHostname);
    }
    if hostname.len() > MAX_HOSTNAME_LEN {
        return Err(ProtocolError::HostnameTooLong(hostname.len()));
    }
    crate::net::validate_hostname(hostname).map_err(ProtocolError::InvalidHostname)
}

fn validate_port(message_type: MessageType, port: u16) -> Result<(), ProtocolError> {
    if port == 0 {
        Err(ProtocolError::ZeroPort(message_type))
    } else {
        Ok(())
    }
}

fn validate_address_list(addresses: &[SocketAddr]) -> Result<(), ProtocolError> {
    if addresses.len() > MAX_RESOLVE_ADDRESSES {
        return Err(ProtocolError::TooManyAddresses(addresses.len()));
    }
    let mut unique = HashSet::with_capacity(addresses.len());
    for &address in addresses {
        let address = canonicalize_address(address);
        validate_port(MessageType::ResolveOk, address.port())?;
        if !unique.insert(address) {
            return Err(ProtocolError::DuplicateAddress(address));
        }
    }
    Ok(())
}

fn decode_address_with_type(
    input: &[u8],
    message_type: MessageType,
) -> Result<(SocketAddr, usize), ProtocolError> {
    let Some(&family) = input.first() else {
        return Err(ProtocolError::TruncatedPayload {
            message_type,
            field: "address family",
        });
    };
    let needed = match family {
        1 => IPV4_ADDRESS_LEN,
        2 => IPV6_ADDRESS_LEN,
        other => return Err(ProtocolError::InvalidAddressFamily(other)),
    };
    if input.len() < needed {
        return Err(ProtocolError::TruncatedPayload {
            message_type,
            field: "address",
        });
    }
    decode_address(input)
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

struct PayloadCursor<'a> {
    message_type: MessageType,
    bytes: &'a [u8],
    position: usize,
}

impl<'a> PayloadCursor<'a> {
    fn new(message_type: MessageType, bytes: &'a [u8]) -> Self {
        Self {
            message_type,
            bytes,
            position: 0,
        }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn require_exact_len(&self, expected: usize) -> Result<(), ProtocolError> {
        if self.bytes.len() < expected {
            Err(ProtocolError::TruncatedPayload {
                message_type: self.message_type,
                field: "fixed payload",
            })
        } else if self.bytes.len() > expected {
            Err(ProtocolError::TrailingPayload {
                message_type: self.message_type,
                remaining: self.bytes.len() - expected,
            })
        } else {
            Ok(())
        }
    }

    fn bytes(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(ProtocolError::TruncatedPayload {
                message_type: self.message_type,
                field,
            })?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn advance(&mut self, len: usize, field: &'static str) -> Result<(), ProtocolError> {
        self.bytes(len, field).map(|_| ())
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, ProtocolError> {
        let bytes = self.bytes(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ProtocolError> {
        let bytes = self.bytes(4, field)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, ProtocolError> {
        let bytes = self.bytes(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        let remaining = self.bytes.len() - self.position;
        if remaining == 0 {
            Ok(())
        } else {
            Err(ProtocolError::TrailingPayload {
                message_type: self.message_type,
                remaining,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};
    use tokio::io::duplex;

    fn sample_frames() -> Vec<Frame> {
        vec![
            Frame::Hello(Hello::new(Role::Local, 0x0102_0304_0506_0708)),
            Frame::Resolve {
                stream_id: 1,
                port: 443,
                hostname: "example.test".into(),
            },
            Frame::ResolveOk {
                stream_id: 1,
                addresses: vec![
                    "192.0.2.4:443".parse().unwrap(),
                    "[2001:db8::4]:443".parse().unwrap(),
                ],
            },
            Frame::Open {
                stream_id: 1,
                address: "192.0.2.4:443".parse().unwrap(),
            },
            Frame::OpenOk {
                stream_id: 1,
                bound_address: "[2001:db8::20]:49152".parse().unwrap(),
            },
            Frame::OpenError {
                stream_id: 3,
                code: OpenErrorCode::ConnectionRefused,
                diagnostic: "refused".into(),
            },
            Frame::Data {
                stream_id: 1,
                payload: vec![0, 1, 2, 0xff],
            },
            Frame::ShutdownWrite { stream_id: 1 },
            Frame::Close {
                stream_id: 1,
                reason: CloseReason::Normal,
            },
            Frame::WindowUpdate {
                stream_id: 1,
                credit: 16_384,
            },
            Frame::Ping {
                nonce: u64::MAX - 1,
            },
            Frame::Pong {
                nonce: u64::MAX - 1,
            },
        ]
    }

    fn raw_frame(message_type: u8, flags: u16, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        raw_frame_with_version(VERSION, message_type, flags, stream_id, payload)
    }

    fn raw_frame_with_version(
        version: u8,
        message_type: u8,
        flags: u16,
        stream_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut result = Vec::with_capacity(HEADER_LEN + payload.len());
        result.extend_from_slice(&MAGIC);
        result.push(version);
        result.push(message_type);
        result.extend_from_slice(&flags.to_le_bytes());
        result.extend_from_slice(&stream_id.to_le_bytes());
        result.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        result.extend_from_slice(payload);
        result
    }

    fn exact_max_hostname() -> String {
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        )
    }

    #[test]
    fn all_message_types_have_stable_wire_values() {
        let expected = [
            MessageType::Hello,
            MessageType::Resolve,
            MessageType::ResolveOk,
            MessageType::Open,
            MessageType::OpenOk,
            MessageType::OpenError,
            MessageType::Data,
            MessageType::ShutdownWrite,
            MessageType::Close,
            MessageType::WindowUpdate,
            MessageType::Ping,
            MessageType::Pong,
        ];
        for (index, ty) in expected.into_iter().enumerate() {
            assert_eq!(ty.as_u8(), (index + 1) as u8);
            assert_eq!(MessageType::try_from((index + 1) as u8).unwrap(), ty);
        }
    }

    #[test]
    fn every_frame_roundtrips() {
        for frame in sample_frames() {
            let encoded = frame.encode().unwrap();
            assert_eq!(Frame::decode_exact(&encoded).unwrap(), frame);
        }
    }

    #[test]
    fn header_and_integer_fields_are_little_endian() {
        let frame = Frame::WindowUpdate {
            stream_id: 0x0102_0305,
            credit: 0x0607_0809,
        };
        let encoded = frame.encode().unwrap();
        assert_eq!(&encoded[..4], b"ALRD");
        assert_eq!(encoded[4], 1);
        assert_eq!(encoded[5], MessageType::WindowUpdate.as_u8());
        assert_eq!(&encoded[6..8], &[0, 0]);
        assert_eq!(&encoded[8..12], &[5, 3, 2, 1]);
        assert_eq!(&encoded[12..16], &[4, 0, 0, 0]);
        assert_eq!(&encoded[16..20], &[9, 8, 7, 6]);
    }

    #[test]
    fn decoder_accepts_every_single_split_and_one_byte_fragmentation() {
        for frame in sample_frames() {
            let encoded = frame.encode().unwrap();
            for split in 0..=encoded.len() {
                let mut decoder = FrameDecoder::new();
                let mut decoded = decoder.push(&encoded[..split]).unwrap();
                decoded.extend(decoder.push(&encoded[split..]).unwrap());
                assert_eq!(decoded, vec![frame.clone()], "split at {split}");
                assert_eq!(decoder.buffered_len(), 0);
                decoder.finish().unwrap();
            }

            let mut decoder = FrameDecoder::new();
            let mut decoded = Vec::new();
            for byte in &encoded {
                decoded.extend(decoder.push(std::slice::from_ref(byte)).unwrap());
                assert!(decoder.buffered_len() <= MAX_DECODER_BUFFERED);
            }
            assert_eq!(decoded, vec![frame]);
        }
    }

    #[test]
    fn decoder_accepts_coalesced_frames_and_preserves_order() {
        let expected = sample_frames();
        let mut encoded = Vec::new();
        for frame in &expected {
            frame.encode_into(&mut encoded).unwrap();
        }
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.push(&encoded).unwrap(), expected);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn decoder_processes_a_chunk_larger_than_its_retained_buffer_cap() {
        let ping = Frame::Ping { nonce: 42 }.encode().unwrap();
        let count = MAX_DECODER_BUFFERED / ping.len() + 100;
        let encoded = ping.repeat(count);
        assert!(encoded.len() > MAX_DECODER_BUFFERED);
        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(&encoded).unwrap();
        assert_eq!(frames.len(), count);
        assert!(frames
            .iter()
            .all(|frame| *frame == Frame::Ping { nonce: 42 }));
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn truncated_stream_is_reported_only_at_finish() {
        for frame in sample_frames() {
            let encoded = frame.encode().unwrap();
            for cut in 1..encoded.len() {
                let mut decoder = FrameDecoder::new();
                assert!(decoder.push(&encoded[..cut]).unwrap().is_empty());
                assert!(matches!(
                    decoder.finish(),
                    Err(ProtocolError::TruncatedHeader { .. })
                        | Err(ProtocolError::TruncatedFrame { .. })
                ));
            }
        }
    }

    #[test]
    fn exact_decode_rejects_short_and_trailing_input() {
        assert_eq!(
            Frame::decode_exact(b"ALR").unwrap_err(),
            ProtocolError::TruncatedHeader { received: 3 }
        );
        let encoded = Frame::Ping { nonce: 9 }.encode().unwrap();
        assert!(matches!(
            Frame::decode_exact(&encoded[..encoded.len() - 1]),
            Err(ProtocolError::TruncatedFrame { .. })
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            Frame::decode_exact(&trailing).unwrap_err(),
            ProtocolError::TrailingFrameBytes(1)
        );
    }

    #[test]
    fn header_rejects_magic_version_type_flags_and_stream_ids() {
        let mut invalid_magic = raw_frame(11, 0, 0, &[0; 8]);
        invalid_magic[0] = b'X';
        assert_eq!(
            Frame::decode_exact(&invalid_magic).unwrap_err(),
            ProtocolError::InvalidMagic
        );

        let bad_version = raw_frame_with_version(2, 11, 0, 0, &[0; 8]);
        assert_eq!(
            Frame::decode_exact(&bad_version).unwrap_err(),
            ProtocolError::UnsupportedVersion(2)
        );
        assert_eq!(
            Frame::decode_exact(&raw_frame(99, 0, 0, &[])).unwrap_err(),
            ProtocolError::UnknownMessageType(99)
        );
        assert_eq!(
            Frame::decode_exact(&raw_frame(11, 0x8000, 0, &[0; 8])).unwrap_err(),
            ProtocolError::NonZeroFlags(0x8000)
        );
        assert!(matches!(
            Frame::decode_exact(&raw_frame(11, 0, 1, &[0; 8])),
            Err(ProtocolError::NonZeroSessionStreamId { .. })
        ));
        assert_eq!(
            Frame::decode_exact(&raw_frame(7, 0, 0, &[1])).unwrap_err(),
            ProtocolError::ZeroStreamId(MessageType::Data)
        );
    }

    #[test]
    fn oversized_declared_length_is_rejected_from_header_alone() {
        let mut encoded = raw_frame(7, 0, 1, &[]);
        encoded[12..16].copy_from_slice(&((MAX_FRAME_PAYLOAD as u32) + 1).to_le_bytes());
        assert_eq!(
            Frame::decode_exact(&encoded).unwrap_err(),
            ProtocolError::PayloadTooLarge((MAX_FRAME_PAYLOAD as u32) + 1)
        );

        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decoder.push(&encoded).unwrap_err(),
            ProtocolError::PayloadTooLarge((MAX_FRAME_PAYLOAD as u32) + 1)
        );
        assert!(decoder.buffered_len() <= MAX_DECODER_BUFFERED);
    }

    #[test]
    fn complete_frames_with_truncated_or_extra_fixed_payloads_fail() {
        let short_hello = raw_frame(1, 0, 0, &[0; HELLO_PAYLOAD_LEN - 1]);
        assert!(matches!(
            Frame::decode_exact(&short_hello),
            Err(ProtocolError::TruncatedPayload { .. })
        ));
        let extra_shutdown = raw_frame(8, 0, 1, &[0]);
        assert_eq!(
            Frame::decode_exact(&extra_shutdown).unwrap_err(),
            ProtocolError::TrailingPayload {
                message_type: MessageType::ShutdownWrite,
                remaining: 1
            }
        );
        let extra_ping = raw_frame(11, 0, 0, &[0; 9]);
        assert_eq!(
            Frame::decode_exact(&extra_ping).unwrap_err(),
            ProtocolError::TrailingPayload {
                message_type: MessageType::Ping,
                remaining: 1
            }
        );
    }

    #[test]
    fn hello_roundtrip_negotiation_and_bounds() {
        let local = Hello::new(Role::Local, 1);
        let mut agent = Hello::new(Role::Agent, 2);
        agent.max_version = 2;
        agent.max_data = 4_096;
        agent.receive_window = 32_768;
        agent.max_streams = 7;
        let limits = local.negotiate(&agent).unwrap();
        assert_eq!(
            limits,
            NegotiatedLimits {
                max_data: 4_096,
                receive_window: 32_768,
                max_streams: 7,
            }
        );
        assert_eq!(
            local.negotiate(&Hello::new(Role::Local, 3)).unwrap_err(),
            ProtocolError::SameHelloRole(Role::Local)
        );

        for mutate in [
            |h: &mut Hello| h.min_version = 0,
            |h: &mut Hello| h.min_version = 2,
            |h: &mut Hello| h.max_version = 0,
            |h: &mut Hello| h.max_data = 0,
            |h: &mut Hello| h.max_data = MAX_DATA_PAYLOAD as u32 + 1,
            |h: &mut Hello| h.receive_window = 0,
            |h: &mut Hello| h.receive_window = INITIAL_WINDOW + 1,
            |h: &mut Hello| h.max_streams = 0,
            |h: &mut Hello| h.max_streams = MAX_STREAMS + 1,
        ] {
            let mut hello = Hello::new(Role::Agent, 2);
            mutate(&mut hello);
            assert!(matches!(
                hello.validate(),
                Err(ProtocolError::InvalidHello(_))
            ));
        }
    }

    #[test]
    fn hello_rejects_invalid_role_and_reserved_byte() {
        let mut payload =
            Frame::Hello(Hello::new(Role::Agent, 3)).encode().unwrap()[HEADER_LEN..].to_vec();
        payload[0] = 3;
        assert_eq!(
            Frame::decode_exact(&raw_frame(1, 0, 0, &payload)).unwrap_err(),
            ProtocolError::InvalidRole(3)
        );
        payload[0] = Role::Agent.as_u8();
        payload[3] = 1;
        assert_eq!(
            Frame::decode_exact(&raw_frame(1, 0, 0, &payload)).unwrap_err(),
            ProtocolError::NonZeroHelloReserved(1)
        );
    }

    #[test]
    fn hostname_maximum_roundtrips_and_overmaximum_fails() {
        let hostname = exact_max_hostname();
        assert_eq!(hostname.len(), MAX_HOSTNAME_LEN);
        let frame = Frame::Resolve {
            stream_id: 1,
            port: 53,
            hostname,
        };
        assert_eq!(
            Frame::decode_exact(&frame.encode().unwrap()).unwrap(),
            frame
        );

        let too_long = format!("{}e", exact_max_hostname());
        assert_eq!(
            Frame::Resolve {
                stream_id: 1,
                port: 53,
                hostname: too_long,
            }
            .encode()
            .unwrap_err(),
            ProtocolError::HostnameTooLong(MAX_HOSTNAME_LEN + 1)
        );
    }

    #[test]
    fn resolve_rejects_empty_structurally_invalid_invalid_utf8_and_trailing() {
        assert_eq!(
            Frame::Resolve {
                stream_id: 1,
                port: 80,
                hostname: String::new(),
            }
            .encode()
            .unwrap_err(),
            ProtocolError::EmptyHostname
        );
        assert!(matches!(
            Frame::Resolve {
                stream_id: 1,
                port: 80,
                hostname: "a..b".into(),
            }
            .encode(),
            Err(ProtocolError::InvalidHostname(_))
        ));

        let mut payload = Vec::new();
        put_u16(&mut payload, 80);
        put_u16(&mut payload, 2);
        payload.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(
            Frame::decode_exact(&raw_frame(2, 0, 1, &payload)).unwrap_err(),
            ProtocolError::HostnameNotUtf8
        );

        let mut trailing = Vec::new();
        put_u16(&mut trailing, 80);
        put_u16(&mut trailing, 1);
        trailing.extend_from_slice(b"aX");
        assert_eq!(
            Frame::decode_exact(&raw_frame(2, 0, 1, &trailing)).unwrap_err(),
            ProtocolError::TrailingPayload {
                message_type: MessageType::Resolve,
                remaining: 1,
            }
        );
    }

    #[test]
    fn ipv4_ipv6_and_mapped_addresses_roundtrip() {
        for address in [
            "0.0.0.0:0".parse().unwrap(),
            "203.0.113.17:65535".parse().unwrap(),
            "[::]:0".parse().unwrap(),
            "[2001:db8::dead:beef]:443".parse().unwrap(),
        ] {
            let mut encoded = Vec::new();
            encode_address(address, &mut encoded);
            let (decoded, consumed) = decode_address(&encoded).unwrap();
            assert_eq!(decoded, address);
            assert_eq!(consumed, encoded.len());
        }

        let mapped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:192.0.2.9".parse::<Ipv6Addr>().unwrap(),
            8080,
            0,
            0,
        ));
        let mut encoded = Vec::new();
        encode_address(mapped, &mut encoded);
        assert_eq!(encoded[0], 1);
        assert_eq!(
            decode_address(&encoded).unwrap().0,
            "192.0.2.9:8080".parse().unwrap()
        );
    }

    #[test]
    fn scoped_ipv6_roundtrips_and_flowinfo_is_normalized() {
        let ip = "fe80::1234".parse::<Ipv6Addr>().unwrap();
        let scoped_with_flow = SocketAddr::V6(SocketAddrV6::new(ip, 8443, 0xaabb_ccdd, 19));
        let canonical = SocketAddr::V6(SocketAddrV6::new(ip, 8443, 0, 19));

        let mut encoded = Vec::new();
        encode_address(scoped_with_flow, &mut encoded);
        assert_eq!(encoded.len(), IPV6_ADDRESS_LEN);
        assert_eq!(&encoded[19..23], &19u32.to_le_bytes());
        assert_eq!(
            decode_address(&encoded).unwrap(),
            (canonical, encoded.len())
        );
        assert_eq!(canonicalize_address(scoped_with_flow), canonical);

        // Scope IDs must survive both halves of remote candidate selection.
        let other_scope = SocketAddr::V6(SocketAddrV6::new(ip, 8443, 0, 20));
        let resolved = Frame::ResolveOk {
            stream_id: 1,
            addresses: vec![scoped_with_flow, other_scope],
        };
        assert_eq!(
            Frame::decode_exact(&resolved.encode().unwrap()).unwrap(),
            Frame::ResolveOk {
                stream_id: 1,
                addresses: vec![canonical, other_scope],
            }
        );
        let open = Frame::Open {
            stream_id: 1,
            address: scoped_with_flow,
        };
        assert_eq!(
            Frame::decode_exact(&open.encode().unwrap()).unwrap(),
            Frame::Open {
                stream_id: 1,
                address: canonical,
            }
        );

        // Flow information is not part of ALRD. Values that differ only by
        // flowinfo therefore identify the same candidate and must deduplicate.
        let same_with_other_flow = SocketAddr::V6(SocketAddrV6::new(ip, 8443, 0x0102_0304, 19));
        assert_eq!(
            Frame::ResolveOk {
                stream_id: 1,
                addresses: vec![scoped_with_flow, same_with_other_flow],
            }
            .encode()
            .unwrap_err(),
            ProtocolError::DuplicateAddress(canonical)
        );
    }

    #[test]
    fn port_bearing_control_frames_reject_zero_on_encode_and_decode() {
        let zero_v4 = "192.0.2.1:0".parse::<SocketAddr>().unwrap();
        let invalid_frames = [
            (
                Frame::Resolve {
                    stream_id: 1,
                    port: 0,
                    hostname: "example.test".into(),
                },
                MessageType::Resolve,
            ),
            (
                Frame::ResolveOk {
                    stream_id: 1,
                    addresses: vec![zero_v4],
                },
                MessageType::ResolveOk,
            ),
            (
                Frame::Open {
                    stream_id: 1,
                    address: zero_v4,
                },
                MessageType::Open,
            ),
            (
                Frame::OpenOk {
                    stream_id: 1,
                    bound_address: zero_v4,
                },
                MessageType::OpenOk,
            ),
        ];
        for (frame, message_type) in invalid_frames {
            assert_eq!(
                frame.encode().unwrap_err(),
                ProtocolError::ZeroPort(message_type)
            );
        }

        let mut resolve = Vec::new();
        put_u16(&mut resolve, 0);
        put_u16(&mut resolve, "example.test".len() as u16);
        resolve.extend_from_slice(b"example.test");

        let mut encoded_address = Vec::new();
        encode_address(zero_v4, &mut encoded_address);
        let mut resolve_ok = Vec::new();
        put_u16(&mut resolve_ok, 1);
        resolve_ok.extend_from_slice(&encoded_address);

        for (message_type, payload) in [
            (MessageType::Resolve, resolve),
            (MessageType::ResolveOk, resolve_ok),
            (MessageType::Open, encoded_address.clone()),
            (MessageType::OpenOk, encoded_address),
        ] {
            assert_eq!(
                Frame::decode_exact(&raw_frame(message_type.as_u8(), 0, 1, &payload)).unwrap_err(),
                ProtocolError::ZeroPort(message_type)
            );
        }
    }

    #[test]
    fn addresses_reject_unknown_family_and_truncation() {
        assert_eq!(
            decode_address(&[9]).unwrap_err(),
            ProtocolError::InvalidAddressFamily(9)
        );
        for bytes in [
            &[][..],
            &[1][..],
            &[1, 80, 0, 127][..],
            &[2, 80, 0, 1, 2][..],
        ] {
            assert!(matches!(
                decode_address(bytes),
                Err(ProtocolError::TruncatedPayload { .. })
            ));
        }
    }

    #[test]
    fn resolve_ok_enforces_count_deduplication_and_exact_addresses() {
        let sixteen: Vec<SocketAddr> = (1..=MAX_RESOLVE_ADDRESSES)
            .map(|last| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last as u8)), 443))
            .collect();
        let frame = Frame::ResolveOk {
            stream_id: 1,
            addresses: sixteen.clone(),
        };
        assert_eq!(
            Frame::decode_exact(&frame.encode().unwrap()).unwrap(),
            frame
        );

        let mut seventeen = sixteen;
        seventeen.push("198.51.100.1:443".parse().unwrap());
        assert_eq!(
            Frame::ResolveOk {
                stream_id: 1,
                addresses: seventeen,
            }
            .encode()
            .unwrap_err(),
            ProtocolError::TooManyAddresses(MAX_RESOLVE_ADDRESSES + 1)
        );

        let duplicate: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(
            Frame::ResolveOk {
                stream_id: 1,
                addresses: vec![duplicate, duplicate],
            }
            .encode()
            .unwrap_err(),
            ProtocolError::DuplicateAddress(duplicate)
        );

        let mut count = Vec::new();
        put_u16(&mut count, (MAX_RESOLVE_ADDRESSES + 1) as u16);
        assert_eq!(
            Frame::decode_exact(&raw_frame(3, 0, 1, &count)).unwrap_err(),
            ProtocolError::TooManyAddresses(MAX_RESOLVE_ADDRESSES + 1)
        );
    }

    #[test]
    fn diagnostic_maximum_and_utf8_rules() {
        let diagnostic = "x".repeat(MAX_DIAGNOSTIC_LEN);
        let frame = Frame::OpenError {
            stream_id: 1,
            code: OpenErrorCode::General,
            diagnostic,
        };
        assert_eq!(
            Frame::decode_exact(&frame.encode().unwrap()).unwrap(),
            frame
        );

        assert_eq!(
            Frame::OpenError {
                stream_id: 1,
                code: OpenErrorCode::General,
                diagnostic: "x".repeat(MAX_DIAGNOSTIC_LEN + 1),
            }
            .encode()
            .unwrap_err(),
            ProtocolError::DiagnosticTooLong(MAX_DIAGNOSTIC_LEN + 1)
        );

        let mut payload = vec![OpenErrorCode::General.as_u8()];
        put_u16(&mut payload, 1);
        payload.push(0xff);
        assert_eq!(
            Frame::decode_exact(&raw_frame(6, 0, 1, &payload)).unwrap_err(),
            ProtocolError::DiagnosticNotUtf8
        );

        for diagnostic in ["line\nbreak", "\u{1b}[31mred"] {
            assert_eq!(
                Frame::OpenError {
                    stream_id: 1,
                    code: OpenErrorCode::General,
                    diagnostic: diagnostic.into(),
                }
                .encode()
                .unwrap_err(),
                ProtocolError::DiagnosticContainsControl
            );

            let mut payload = vec![OpenErrorCode::General.as_u8()];
            put_u16(&mut payload, diagnostic.len() as u16);
            payload.extend_from_slice(diagnostic.as_bytes());
            assert_eq!(
                Frame::decode_exact(&raw_frame(6, 0, 1, &payload)).unwrap_err(),
                ProtocolError::DiagnosticContainsControl
            );
        }
    }

    #[test]
    fn data_minimum_maximum_and_overmaximum_rules() {
        assert_eq!(
            Frame::Data {
                stream_id: 1,
                payload: vec![],
            }
            .encode()
            .unwrap_err(),
            ProtocolError::EmptyData
        );
        for len in [1, 2, 255, 1_590, 4_096, MAX_DATA_PAYLOAD] {
            let frame = Frame::Data {
                stream_id: 1,
                payload: (0..len).map(|index| index as u8).collect(),
            };
            assert_eq!(
                Frame::decode_exact(&frame.encode().unwrap()).unwrap(),
                frame
            );
        }
        let too_large = raw_frame(7, 0, 1, &vec![0; MAX_DATA_PAYLOAD + 1]);
        assert_eq!(
            Frame::decode_exact(&too_large).unwrap_err(),
            ProtocolError::DataTooLarge(MAX_DATA_PAYLOAD + 1)
        );
    }

    #[test]
    fn invalid_codes_zero_credit_and_payload_shapes_are_rejected() {
        let mut open_error = vec![0, 0, 0];
        assert_eq!(
            Frame::decode_exact(&raw_frame(6, 0, 1, &open_error)).unwrap_err(),
            ProtocolError::InvalidOpenErrorCode(0)
        );
        open_error[0] = 9;
        assert_eq!(
            Frame::decode_exact(&raw_frame(6, 0, 1, &open_error)).unwrap_err(),
            ProtocolError::InvalidOpenErrorCode(9)
        );
        assert_eq!(
            Frame::decode_exact(&raw_frame(9, 0, 1, &[5])).unwrap_err(),
            ProtocolError::InvalidCloseReason(5)
        );
        assert_eq!(
            Frame::decode_exact(&raw_frame(10, 0, 1, &[0; 4])).unwrap_err(),
            ProtocolError::ZeroWindowUpdate
        );
        assert!(matches!(
            Frame::decode_exact(&raw_frame(4, 0, 1, &[])),
            Err(ProtocolError::TruncatedPayload { .. })
        ));
    }

    #[test]
    fn encode_into_is_atomic_on_validation_failure() {
        let mut output = vec![1, 2, 3];
        let invalid = Frame::WindowUpdate {
            stream_id: 1,
            credit: 0,
        };
        assert_eq!(
            invalid.encode_into(&mut output).unwrap_err(),
            ProtocolError::ZeroWindowUpdate
        );
        assert_eq!(output, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn async_helpers_roundtrip_over_a_fragmenting_duplex_stream() {
        let expected = Frame::Data {
            stream_id: 7,
            payload: vec![0x5a; MAX_DATA_PAYLOAD],
        };
        let (mut writer, mut reader) = duplex(37);
        let sent = expected.clone();
        let task = tokio::spawn(async move { write_frame(&mut writer, &sent).await.unwrap() });
        let received = read_frame(&mut reader).await.unwrap();
        task.await.unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn async_reader_surfaces_protocol_errors_before_payload_read() {
        let mut oversized = raw_frame(7, 0, 1, &[]);
        oversized[12..16].copy_from_slice(&((MAX_FRAME_PAYLOAD as u32) + 1).to_le_bytes());
        let mut input: &[u8] = &oversized;
        assert!(matches!(
            read_frame(&mut input).await,
            Err(FrameIoError::Protocol(ProtocolError::PayloadTooLarge(_)))
        ));
    }
}
