//! RTXP message framing.
//!
//! Every message on the XRPL peer-to-peer wire is prefixed with a 6-byte header:
//!
//!   Bytes 0–3: payload length (u32 big-endian, NOT including the 6-byte header)
//!   Bytes 4–5: message type   (u16 big-endian)
//!
//! Rippled also supports a 10-byte *compressed* header:
//!
//!   If byte 0 has the high bit set (0x80), the frame is compressed:
//!   Bytes 0–3: algorithm in bits 1-3 of byte 0 (LZ4 = 0x90), remaining bits = compressed size
//!   Bytes 4–5: message type (u16 big-endian)
//!   Bytes 6–9: uncompressed payload size (u32 big-endian)
//!
//! The payload is a Protocol Buffer-encoded body. This module handles only the
//! framing layer — encoding/decoding the header and splitting a raw byte stream
//! into discrete messages.
//!
//! Message type constants match rippled's `protocols/ripple.proto`.

use thiserror::Error;

// ── Message type codes ────────────────────────────────────────────────────────
// Source: https://github.com/XRPLF/rippled/blob/master/src/ripple/proto/ripple.proto

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Manifests               = 2,
    Ping                    = 3,
    Cluster                 = 5,
    Endpoints               = 15,
    Transaction             = 30,
    GetLedger               = 31,
    LedgerData              = 32,
    ProposeLedger           = 33,
    StatusChange            = 34,
    HaveSet                 = 35,
    Validation              = 41,
    GetObjects              = 42,
    ValidatorList           = 54,
    Squelch                 = 55,
    ValidatorListCollection = 56,
    ProofPathReq            = 57,
    ProofPathResponse       = 58,
    ReplayDeltaReq          = 59,
    ReplayDeltaResponse     = 60,
    HaveTransactions        = 63,
    Transactions            = 64,
    Unknown(u16),
}

impl MessageType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            2  => Self::Manifests,
            3  => Self::Ping,
            5  => Self::Cluster,
            15 => Self::Endpoints,
            30 => Self::Transaction,
            31 => Self::GetLedger,
            32 => Self::LedgerData,
            33 => Self::ProposeLedger,
            34 => Self::StatusChange,
            35 => Self::HaveSet,
            41 => Self::Validation,
            42 => Self::GetObjects,
            54 => Self::ValidatorList,
            55 => Self::Squelch,
            56 => Self::ValidatorListCollection,
            57 => Self::ProofPathReq,
            58 => Self::ProofPathResponse,
            59 => Self::ReplayDeltaReq,
            60 => Self::ReplayDeltaResponse,
            63 => Self::HaveTransactions,
            64 => Self::Transactions,
            n  => Self::Unknown(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::Manifests               => 2,
            Self::Ping                    => 3,
            Self::Cluster                 => 5,
            Self::Endpoints               => 15,
            Self::Transaction             => 30,
            Self::GetLedger               => 31,
            Self::LedgerData              => 32,
            Self::ProposeLedger           => 33,
            Self::StatusChange            => 34,
            Self::HaveSet                 => 35,
            Self::Validation              => 41,
            Self::GetObjects              => 42,
            Self::ValidatorList           => 54,
            Self::Squelch                 => 55,
            Self::ValidatorListCollection => 56,
            Self::ProofPathReq            => 57,
            Self::ProofPathResponse       => 58,
            Self::ReplayDeltaReq          => 59,
            Self::ReplayDeltaResponse     => 60,
            Self::HaveTransactions        => 63,
            Self::Transactions            => 64,
            Self::Unknown(n)              => n,
        }
    }
}

// ── Compression constants ────────────────────────────────────────────────────

/// The high bit in byte 0 signals a compressed frame.
const COMPRESSED_FLAG: u8 = 0x80;

/// LZ4 compression algorithm byte (bits 1-3 of byte 0).
const ALGORITHM_LZ4: u8 = 0x10;

/// Compressed header is 10 bytes: 4 compressed-size + 2 type + 4 uncompressed-size.
pub const COMPRESSED_HEADER_SIZE: usize = 10;

/// Minimum payload size to bother compressing.
const COMPRESS_THRESHOLD: usize = 70;

// ── Header ────────────────────────────────────────────────────────────────────

pub const HEADER_SIZE: usize = 6;
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64 MiB sanity cap

/// A decoded RTXP message header — supports both compressed and uncompressed frames.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub payload_len: u32,
    pub msg_type:    MessageType,
    /// If compressed: the uncompressed payload size.
    pub uncompressed_size: Option<u32>,
    /// Total header size for this frame (6 or 10).
    pub header_size: usize,
}

impl Header {
    pub fn new(msg_type: MessageType, payload_len: u32) -> Self {
        Self { payload_len, msg_type, uncompressed_size: None, header_size: HEADER_SIZE }
    }

    /// Encode to 6 bytes (uncompressed header).
    pub fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let len = self.payload_len.to_be_bytes();
        let typ = self.msg_type.to_u16().to_be_bytes();
        [len[0], len[1], len[2], len[3], typ[0], typ[1]]
    }

    /// Decode a header from the buffer. Detects compressed vs uncompressed.
    pub fn from_bytes(b: &[u8]) -> Result<Self, FrameError> {
        if b.len() < HEADER_SIZE {
            return Err(FrameError::Incomplete { need: HEADER_SIZE, have: b.len() });
        }

        if b[0] & COMPRESSED_FLAG != 0 {
            // Compressed frame — need 10 bytes
            if b.len() < COMPRESSED_HEADER_SIZE {
                return Err(FrameError::Incomplete { need: COMPRESSED_HEADER_SIZE, have: b.len() });
            }

            // Bytes 0-3: algorithm in bits 4-7 of byte 0, compressed size in lower 26 bits
            let algo = b[0] & 0xF0;
            if algo != (COMPRESSED_FLAG | ALGORITHM_LZ4) {
                return Err(FrameError::UnsupportedCompression { algo });
            }

            let compressed_len = u32::from_be_bytes([b[0] & 0x0F, b[1], b[2], b[3]]);
            let msg_type = MessageType::from_u16(u16::from_be_bytes([b[4], b[5]]));
            let uncompressed_size = u32::from_be_bytes([b[6], b[7], b[8], b[9]]);

            if compressed_len as usize > MAX_MESSAGE_SIZE {
                return Err(FrameError::Oversized { size: compressed_len as usize });
            }
            if uncompressed_size as usize > MAX_MESSAGE_SIZE {
                return Err(FrameError::Oversized { size: uncompressed_size as usize });
            }

            Ok(Self {
                payload_len: compressed_len,
                msg_type,
                uncompressed_size: Some(uncompressed_size),
                header_size: COMPRESSED_HEADER_SIZE,
            })
        } else {
            // Uncompressed frame — standard 6-byte header
            let payload_len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            let msg_type    = MessageType::from_u16(u16::from_be_bytes([b[4], b[5]]));
            if payload_len as usize > MAX_MESSAGE_SIZE {
                return Err(FrameError::Oversized { size: payload_len as usize });
            }
            Ok(Self { payload_len, msg_type, uncompressed_size: None, header_size: HEADER_SIZE })
        }
    }

    /// Returns true if this is a compressed frame.
    pub fn is_compressed(&self) -> bool {
        self.uncompressed_size.is_some()
    }
}

// ── Compression helpers ─────────────────────────────────────────────────────

/// Compress a payload using LZ4.
pub fn compress_message(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress a LZ4-compressed payload.
pub fn decompress_message(data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, FrameError> {
    // lz4_flex::compress_prepend_size prepends the original size, but rippled
    // sends raw compressed data (no size prefix). Use decompress directly.
    let mut out = vec![0u8; uncompressed_size];
    let written = lz4_flex::decompress_into(data, &mut out)
        .map_err(|e| FrameError::DecompressError(e.to_string()))?;
    out.truncate(written);
    Ok(out)
}

// ── Complete framed message ───────────────────────────────────────────────────

/// A fully framed RTXP message (header + payload).
#[derive(Debug, Clone)]
pub struct RtxpMessage {
    pub msg_type: MessageType,
    pub payload:  Vec<u8>,
}

impl RtxpMessage {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode to wire bytes (6-byte header + payload) — uncompressed.
    pub fn encode(&self) -> Vec<u8> {
        let header = Header::new(self.msg_type, self.payload.len() as u32);
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Encode to wire bytes with LZ4 compression (10-byte header + compressed payload).
    /// Only compresses if the payload exceeds the threshold; otherwise falls back to
    /// uncompressed encoding.
    pub fn encode_compressed(&self) -> Vec<u8> {
        if self.payload.len() <= COMPRESS_THRESHOLD {
            return self.encode();
        }

        let compressed = lz4_flex::compress(&self.payload);

        // If compression didn't help, send uncompressed
        if compressed.len() >= self.payload.len() {
            return self.encode();
        }

        let compressed_len = compressed.len() as u32;
        let uncompressed_len = self.payload.len() as u32;
        let msg_type_bytes = self.msg_type.to_u16().to_be_bytes();

        // Build the 10-byte compressed header
        let size_bytes = compressed_len.to_be_bytes();
        let algo_byte = COMPRESSED_FLAG | ALGORITHM_LZ4 | (size_bytes[0] & 0x0F);

        let mut buf = Vec::with_capacity(COMPRESSED_HEADER_SIZE + compressed.len());
        buf.push(algo_byte);
        buf.push(size_bytes[1]);
        buf.push(size_bytes[2]);
        buf.push(size_bytes[3]);
        buf.push(msg_type_bytes[0]);
        buf.push(msg_type_bytes[1]);
        buf.extend_from_slice(&uncompressed_len.to_be_bytes());
        buf.extend_from_slice(&compressed);
        buf
    }

    /// Try to decode one message from the front of `buf`.
    ///
    /// Returns `Ok(Some((msg, bytes_consumed)))` when a full message is available,
    /// `Ok(None)` when more bytes are needed, or `Err` on a malformed frame.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>, FrameError> {
        if buf.len() < HEADER_SIZE {
            return Ok(None); // need more bytes
        }
        let header = Header::from_bytes(buf)?;
        let total = header.header_size + header.payload_len as usize;
        if buf.len() < total {
            return Ok(None); // payload not yet fully received
        }
        let raw_payload = &buf[header.header_size..total];

        let payload = if let Some(uncompressed_size) = header.uncompressed_size {
            decompress_message(raw_payload, uncompressed_size as usize)?
        } else {
            raw_payload.to_vec()
        };

        Ok(Some((Self { msg_type: header.msg_type, payload }, total)))
    }
}

// ── Stream splitter ───────────────────────────────────────────────────────────

/// Accumulates incoming bytes and yields complete RTXP messages.
///
/// Designed to sit between a TLS stream and the application layer.
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feed raw bytes from the network into the decoder.
    /// Returns Err if the buffer would exceed MAX_MESSAGE_SIZE + COMPRESSED_HEADER_SIZE.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), FrameError> {
        if self.buf.len() + data.len() > MAX_MESSAGE_SIZE + COMPRESSED_HEADER_SIZE {
            return Err(FrameError::Oversized { size: self.buf.len() + data.len() });
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Try to extract the next complete message from the buffer.
    /// Returns `None` if more bytes are needed.
    /// Automatically decompresses compressed frames.
    pub fn next_message(&mut self) -> Result<Option<RtxpMessage>, FrameError> {
        match RtxpMessage::decode(&self.buf)? {
            None => Ok(None),
            Some((msg, consumed)) => {
                self.buf.drain(..consumed);
                Ok(Some(msg))
            }
        }
    }

    /// Drain all currently complete messages.
    pub fn drain_messages(&mut self) -> Result<Vec<RtxpMessage>, FrameError> {
        let mut out = Vec::new();
        while let Some(msg) = self.next_message()? {
            out.push(msg);
        }
        Ok(out)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buf.len()
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("incomplete header: need {need} bytes, have {have}")]
    Incomplete { need: usize, have: usize },
    #[error("message too large: {size} bytes exceeds {MAX_MESSAGE_SIZE}")]
    Oversized { size: usize },
    #[error("unsupported compression algorithm: 0x{algo:02x}")]
    UnsupportedCompression { algo: u8 },
    #[error("decompression error: {0}")]
    DecompressError(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let h = Header::new(MessageType::Ping, 42);
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        let decoded = Header::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload_len, 42);
        assert_eq!(decoded.msg_type, MessageType::Ping);
    }

    #[test]
    fn test_message_encode_decode_roundtrip() {
        let payload = b"hello peer".to_vec();
        let msg = RtxpMessage::new(MessageType::Transaction, payload.clone());
        let wire = msg.encode();
        assert_eq!(wire.len(), HEADER_SIZE + payload.len());

        let (decoded, consumed) = RtxpMessage::decode(&wire).unwrap().unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.msg_type, MessageType::Transaction);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_decode_incomplete_header() {
        let result = RtxpMessage::decode(&[0x00, 0x00]).unwrap();
        assert!(result.is_none(), "should return None when header is incomplete");
    }

    #[test]
    fn test_decode_incomplete_payload() {
        // Header says 100 bytes of payload, but we only have 10
        let header = Header::new(MessageType::Ping, 100).to_bytes();
        let partial: Vec<u8> = [header.as_ref(), &[0u8; 10]].concat();
        let result = RtxpMessage::decode(&partial).unwrap();
        assert!(result.is_none(), "should return None when payload is incomplete");
    }

    #[test]
    fn test_oversized_message_rejected() {
        let mut buf = [0u8; HEADER_SIZE];
        // Set payload_len = 128 MiB (over the 64 MiB cap)
        let big: u32 = 128 * 1024 * 1024;
        buf[..4].copy_from_slice(&big.to_be_bytes());
        assert!(Header::from_bytes(&buf).is_err(), "oversized message must be rejected");
    }

    #[test]
    fn test_frame_decoder_single_message() {
        let msg = RtxpMessage::new(MessageType::Validation, b"sig".to_vec());
        let wire = msg.encode();
        let mut dec = FrameDecoder::new();
        dec.feed(&wire).unwrap();
        let out = dec.next_message().unwrap().unwrap();
        assert_eq!(out.msg_type, MessageType::Validation);
        assert_eq!(out.payload, b"sig");
        assert_eq!(dec.buffered_bytes(), 0);
    }

    #[test]
    fn test_frame_decoder_byte_by_byte() {
        // Simulate receiving data one byte at a time
        let msg = RtxpMessage::new(MessageType::Ping, b"x".to_vec());
        let wire = msg.encode();
        let mut dec = FrameDecoder::new();
        let mut result = None;
        for byte in &wire {
            let _ = dec.feed(std::slice::from_ref(byte));
            if let Some(m) = dec.next_message().unwrap() {
                result = Some(m);
                break;
            }
        }
        let out = result.expect("should have decoded a message");
        assert_eq!(out.msg_type, MessageType::Ping);
    }

    #[test]
    fn test_frame_decoder_multiple_messages() {
        let msgs = vec![
            RtxpMessage::new(MessageType::Ping,       b"a".to_vec()),
            RtxpMessage::new(MessageType::Ping,       b"bb".to_vec()),
            RtxpMessage::new(MessageType::Cluster,    b"ccc".to_vec()),
        ];
        let wire: Vec<u8> = msgs.iter().flat_map(|m| m.encode()).collect();
        let mut dec = FrameDecoder::new();
        dec.feed(&wire).unwrap();
        let out = dec.drain_messages().unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].msg_type, MessageType::Ping);
        assert_eq!(out[1].msg_type, MessageType::Ping);
        assert_eq!(out[2].msg_type, MessageType::Cluster);
        assert_eq!(dec.buffered_bytes(), 0);
    }

    #[test]
    fn test_frame_decoder_split_across_feeds() {
        // Message arrives in two chunks split through the header
        let msg = RtxpMessage::new(MessageType::Transaction, b"payload data".to_vec());
        let wire = msg.encode();
        let (chunk1, chunk2) = wire.split_at(4); // split mid-header

        let mut dec = FrameDecoder::new();
        dec.feed(chunk1).unwrap();
        assert!(dec.next_message().unwrap().is_none(), "message should not be ready yet");
        dec.feed(chunk2).unwrap();
        let out = dec.next_message().unwrap().unwrap();
        assert_eq!(out.payload, b"payload data");
    }

    #[test]
    fn test_unknown_message_type_passes_through() {
        let msg = RtxpMessage::new(MessageType::Unknown(999), b"data".to_vec());
        let wire = msg.encode();
        let (decoded, _) = RtxpMessage::decode(&wire).unwrap().unwrap();
        assert_eq!(decoded.msg_type, MessageType::Unknown(999));
    }

    #[test]
    fn test_empty_payload_message() {
        let msg = RtxpMessage::new(MessageType::Ping, vec![]);
        let wire = msg.encode();
        assert_eq!(wire.len(), HEADER_SIZE);
        let (decoded, consumed) = RtxpMessage::decode(&wire).unwrap().unwrap();
        assert_eq!(consumed, HEADER_SIZE);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_compressed_roundtrip() {
        // Create a payload big enough to trigger compression
        let payload = vec![0x42u8; 200];
        let msg = RtxpMessage::new(MessageType::Transaction, payload.clone());
        let wire = msg.encode_compressed();

        // Should be a compressed frame (byte 0 has high bit set)
        assert!(wire[0] & COMPRESSED_FLAG != 0, "should be a compressed frame");

        let (decoded, consumed) = RtxpMessage::decode(&wire).unwrap().unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.msg_type, MessageType::Transaction);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_small_payload_not_compressed() {
        // Payload below threshold should not be compressed
        let payload = b"tiny".to_vec();
        let msg = RtxpMessage::new(MessageType::Ping, payload.clone());
        let wire = msg.encode_compressed();
        // Should be uncompressed (byte 0 low bit clear)
        assert!(wire[0] & COMPRESSED_FLAG == 0, "small payload should not be compressed");
        assert_eq!(wire.len(), HEADER_SIZE + payload.len());
    }
}
