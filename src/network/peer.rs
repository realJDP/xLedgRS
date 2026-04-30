//! Peer connection state machine.
//!
//! Tracks the lifecycle of a single peer connection without doing any I/O.
//! The actual TLS stream and Tokio wiring are provided by the outer runtime; this layer
//! decides what is valid at each stage and what transitions are allowed.
//!
//! # State diagram
//!
//! ```text
//!                ┌────────────┐
//!                │ Connecting │  (TLS being established)
//!                └─────┬──────┘
//!                      │ tls_established()
//!                ┌─────▼──────┐
//!                │Handshaking │  (HTTP upgrade in flight)
//!                └─────┬──────┘
//!           ┌──────────┴──────────┐
//!    101 ok │                     │ rejection / error
//!      ┌────▼────┐           ┌────▼────┐
//!      │ Active  │           │  Closed │
//!      └────┬────┘           └─────────┘
//!           │ disconnect() / error
//!      ┌────▼────┐
//!      │ Closing │  (draining outbound queue)
//!      └────┬────┘
//!           │ fully_closed()
//!      ┌────▼────┐
//!      │  Closed │
//!      └─────────┘
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::network::handshake::HandshakeInfo;
use crate::network::message::MessageType;
use crate::network::peerfinder::PeerfinderSlot;
use crate::network::resource::ResourceConsumer;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// TLS handshake in progress. No XRPL messages yet.
    Connecting,
    /// TLS up; waiting for HTTP upgrade exchange to complete.
    Handshaking,
    /// Fully connected. RTXP binary messages flow freely.
    Active,
    /// Disconnect requested; draining outbound queue before closing.
    Closing { reason: CloseReason },
    /// Connection terminated.
    Closed { reason: CloseReason },
}

impl PeerState {
    pub fn is_active(&self) -> bool {
        matches!(self, PeerState::Active)
    }
    pub fn is_closed(&self) -> bool {
        matches!(self, PeerState::Closed { .. })
    }
    pub fn is_open(&self) -> bool {
        !self.is_closed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// Clean disconnect requested locally.
    LocalDisconnect,
    /// Remote peer closed the connection.
    RemoteDisconnect,
    /// Handshake was rejected by the remote peer.
    HandshakeRejected(String),
    /// Protocol violation detected.
    ProtocolError(String),
    /// Idle timeout exceeded.
    Timeout,
    /// Too many peers — connection refused at handshake.
    TooManyPeers,
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LocalDisconnect => write!(f, "local disconnect"),
            Self::RemoteDisconnect => write!(f, "remote disconnect"),
            Self::HandshakeRejected(s) => write!(f, "handshake rejected: {s}"),
            Self::ProtocolError(s) => write!(f, "protocol error: {s}"),
            Self::Timeout => write!(f, "idle timeout"),
            Self::TooManyPeers => write!(f, "too many peers"),
        }
    }
}

// ── Direction ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Connection initiated by the local node.
    Outbound,
    /// Connection initiated by the remote peer.
    Inbound,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// Events fed into the state machine by the I/O layer.
#[derive(Debug)]
pub enum PeerEvent {
    /// TLS handshake completed successfully.
    TlsEstablished,
    /// The HTTP upgrade request has been exchanged for this connection.
    HandshakeSent,
    /// HTTP upgrade accepted — remote peer's handshake info decoded.
    HandshakeAccepted(HandshakeInfo),
    /// HTTP upgrade rejected by remote.
    HandshakeRejected(String),
    /// A complete RTXP message was received.
    MessageReceived(MessageType, Vec<u8>),
    /// Local code requested a clean disconnect.
    DisconnectRequested,
    /// The outbound queue is empty and the socket can close.
    OutboundDrained,
    /// Remote closed the connection.
    RemoteClosed,
    /// Any I/O or protocol error.
    Error(String),
    /// No traffic received within the idle window.
    IdleTimeout,
}

// ── Actions ───────────────────────────────────────────────────────────────────

/// Actions the I/O layer should take in response to state transitions.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerAction {
    /// Send the HTTP upgrade request.
    SendHandshakeRequest,
    /// Send the 101 Switching Protocols response.
    SendHandshakeResponse,
    /// Send a specific RTXP message.
    SendMessage(MessageType, Vec<u8>),
    /// Close the underlying socket.
    CloseSocket,
    /// Log a warning (non-fatal).
    Warn(String),
    /// No action needed.
    None,
}

// ── Peer ──────────────────────────────────────────────────────────────────────

/// Connection state for a single peer.
pub struct Peer {
    pub id: PeerId,
    pub addr: SocketAddr,
    pub direction: Direction,
    pub peerfinder_slot: Option<PeerfinderSlot>,
    pub resource_consumer: ResourceConsumer,
    pub state: PeerState,
    /// Set after a successful handshake.
    pub info: Option<HandshakeInfo>,
    /// Time of the most recent inbound traffic from this peer.
    pub last_rx: Instant,
    /// Idle duration before the connection times out.
    pub idle_timeout: Duration,
    /// Count of messages received/sent (for diagnostics).
    pub rx_count: u64,
    pub tx_count: u64,
}

/// A unique peer identifier.
///
/// This is currently a local counter rather than a node public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub u64);

impl Peer {
    pub fn new(
        id: PeerId,
        addr: SocketAddr,
        direction: Direction,
        resource_consumer: ResourceConsumer,
    ) -> Self {
        Self {
            id,
            addr,
            direction,
            peerfinder_slot: None,
            resource_consumer,
            state: PeerState::Connecting,
            info: None,
            last_rx: Instant::now(),
            idle_timeout: Duration::from_secs(90),
            rx_count: 0,
            tx_count: 0,
        }
    }

    pub fn set_resource_consumer(&mut self, consumer: ResourceConsumer) {
        self.resource_consumer = consumer;
    }

    pub fn set_peerfinder_slot(&mut self, slot: PeerfinderSlot) {
        self.peerfinder_slot = Some(slot);
    }

    // ── State machine ─────────────────────────────────────────────────────────

    /// Feed an event into the state machine. Returns the action to take.
    pub fn handle(&mut self, event: PeerEvent) -> PeerAction {
        match (&self.state, event) {
            // ── Connecting ────────────────────────────────────────────────────
            (PeerState::Connecting, PeerEvent::TlsEstablished) => {
                self.state = PeerState::Handshaking;
                match self.direction {
                    Direction::Outbound => PeerAction::SendHandshakeRequest,
                    Direction::Inbound => PeerAction::None, // wait for peer's request
                }
            }

            // ── Handshaking ───────────────────────────────────────────────────
            (PeerState::Handshaking, PeerEvent::HandshakeSent) => {
                PeerAction::None // waiting for response
            }

            (PeerState::Handshaking, PeerEvent::HandshakeAccepted(info)) => {
                self.info = Some(info);
                self.state = PeerState::Active;
                self.last_rx = Instant::now();
                match self.direction {
                    // Inbound connections respond with the 101 upgrade status.
                    Direction::Inbound => PeerAction::SendHandshakeResponse,
                    // Outbound connections already sent the request and only
                    // need to record the accepted state.
                    Direction::Outbound => PeerAction::None,
                }
            }

            (PeerState::Handshaking, PeerEvent::HandshakeRejected(reason)) => {
                self.state = PeerState::Closed {
                    reason: CloseReason::HandshakeRejected(reason),
                };
                PeerAction::CloseSocket
            }

            // ── Active ────────────────────────────────────────────────────────
            (PeerState::Active, PeerEvent::MessageReceived(msg_type, payload)) => {
                self.last_rx = Instant::now();
                self.rx_count += 1;
                // Validate that the message type makes sense in Active state
                if let Some(action) = self.validate_message(msg_type, &payload) {
                    return action;
                }
                PeerAction::None
            }

            (PeerState::Active, PeerEvent::DisconnectRequested) => {
                self.state = PeerState::Closing {
                    reason: CloseReason::LocalDisconnect,
                };
                PeerAction::None // wait for outbound queue to drain
            }

            // ── Closing ───────────────────────────────────────────────────────
            (PeerState::Closing { .. }, PeerEvent::OutboundDrained) => {
                let reason = match &self.state {
                    PeerState::Closing { reason } => reason.clone(),
                    _ => unreachable!(),
                };
                self.state = PeerState::Closed { reason };
                PeerAction::CloseSocket
            }

            // ── Any state: remote close or error ──────────────────────────────
            (_, PeerEvent::RemoteClosed) => {
                self.state = PeerState::Closed {
                    reason: CloseReason::RemoteDisconnect,
                };
                PeerAction::CloseSocket
            }

            (_, PeerEvent::Error(msg)) => {
                self.state = PeerState::Closed {
                    reason: CloseReason::ProtocolError(msg),
                };
                PeerAction::CloseSocket
            }

            (_, PeerEvent::IdleTimeout) => {
                self.state = PeerState::Closed {
                    reason: CloseReason::Timeout,
                };
                PeerAction::CloseSocket
            }

            // ── Unexpected event ──────────────────────────────────────────────
            (state, event) => {
                let warn = format!(
                    "unexpected event {:?} in state {:?} for peer {}",
                    std::mem::discriminant(&event),
                    std::mem::discriminant(state),
                    self.id.0,
                );
                PeerAction::Warn(warn)
            }
        }
    }

    /// Check whether the current time exceeds the idle deadline.
    pub fn check_idle(&mut self) -> PeerAction {
        if self.state.is_active() && self.last_rx.elapsed() > self.idle_timeout {
            self.handle(PeerEvent::IdleTimeout)
        } else {
            PeerAction::None
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn validate_message(&mut self, _msg_type: MessageType, _payload: &[u8]) -> Option<PeerAction> {
        // Certain message types are only valid in specific states or directions.
        // Return Some(action) to override the default None, e.g. to close on violation.
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::handshake::HandshakeInfo;

    fn peer(direction: Direction) -> Peer {
        let addr = "127.0.0.1:51235".parse().unwrap();
        let consumer = crate::network::resource::ResourceManager::default()
            .new_inbound_endpoint(addr, false, None);
        Peer::new(PeerId(1), addr, direction, consumer)
    }

    fn dummy_info() -> HandshakeInfo {
        HandshakeInfo {
            node_pubkey: vec![0x02; 33],
            session_signature: vec![0xAA; 64],
            protocol: "XRPL/2.2".to_string(),
            user_agent: Some("rippled-2.0".to_string()),
            network_id: None,
            network_time: None,
            closed_ledger: None,
            previous_ledger: None,
            features: None,
        }
    }

    #[test]
    fn test_initial_state() {
        let p = peer(Direction::Outbound);
        assert_eq!(p.state, PeerState::Connecting);
        assert!(p.info.is_none());
    }

    #[test]
    fn test_outbound_happy_path() {
        let mut p = peer(Direction::Outbound);

        // TLS up → should send handshake request
        let action = p.handle(PeerEvent::TlsEstablished);
        assert_eq!(action, PeerAction::SendHandshakeRequest);
        assert_eq!(p.state, PeerState::Handshaking);

        // Peer accepted → go active, no extra action needed for outbound
        let action = p.handle(PeerEvent::HandshakeAccepted(dummy_info()));
        assert_eq!(action, PeerAction::None);
        assert!(p.state.is_active());
        assert!(p.info.is_some());
    }

    #[test]
    fn test_inbound_happy_path() {
        let mut p = peer(Direction::Inbound);

        // TLS up → inbound waits for peer's request first
        let action = p.handle(PeerEvent::TlsEstablished);
        assert_eq!(action, PeerAction::None);
        assert_eq!(p.state, PeerState::Handshaking);

        // Peer sent their upgrade request → send 101 back
        let action = p.handle(PeerEvent::HandshakeAccepted(dummy_info()));
        assert_eq!(action, PeerAction::SendHandshakeResponse);
        assert!(p.state.is_active());
    }

    #[test]
    fn test_handshake_rejected() {
        let mut p = peer(Direction::Outbound);
        p.handle(PeerEvent::TlsEstablished);

        let action = p.handle(PeerEvent::HandshakeRejected("too many peers".into()));
        assert_eq!(action, PeerAction::CloseSocket);
        assert!(p.state.is_closed());
        assert!(matches!(
            p.state,
            PeerState::Closed {
                reason: CloseReason::HandshakeRejected(_)
            }
        ));
    }

    #[test]
    fn test_clean_disconnect() {
        let mut p = peer(Direction::Outbound);
        p.handle(PeerEvent::TlsEstablished);
        p.handle(PeerEvent::HandshakeAccepted(dummy_info()));
        assert!(p.state.is_active());

        p.handle(PeerEvent::DisconnectRequested);
        assert!(matches!(p.state, PeerState::Closing { .. }));

        let action = p.handle(PeerEvent::OutboundDrained);
        assert_eq!(action, PeerAction::CloseSocket);
        assert!(p.state.is_closed());
        assert!(matches!(
            p.state,
            PeerState::Closed {
                reason: CloseReason::LocalDisconnect
            }
        ));
    }

    #[test]
    fn test_remote_close_from_any_state() {
        for direction in [Direction::Inbound, Direction::Outbound] {
            let mut p = peer(direction);
            // Close before TLS even finishes
            let action = p.handle(PeerEvent::RemoteClosed);
            assert_eq!(action, PeerAction::CloseSocket);
            assert!(p.state.is_closed());
        }
    }

    #[test]
    fn test_error_closes_connection() {
        let mut p = peer(Direction::Outbound);
        p.handle(PeerEvent::TlsEstablished);
        p.handle(PeerEvent::HandshakeAccepted(dummy_info()));

        let action = p.handle(PeerEvent::Error("bad frame".into()));
        assert_eq!(action, PeerAction::CloseSocket);
        assert!(matches!(
            p.state,
            PeerState::Closed {
                reason: CloseReason::ProtocolError(_)
            }
        ));
    }

    #[test]
    fn test_message_received_increments_counter() {
        let mut p = peer(Direction::Outbound);
        p.handle(PeerEvent::TlsEstablished);
        p.handle(PeerEvent::HandshakeAccepted(dummy_info()));

        p.handle(PeerEvent::MessageReceived(MessageType::Ping, vec![]));
        p.handle(PeerEvent::MessageReceived(
            MessageType::Transaction,
            vec![1, 2, 3],
        ));
        assert_eq!(p.rx_count, 2);
    }

    #[test]
    fn test_idle_timeout_closes_active_peer() {
        let mut p = peer(Direction::Outbound);
        p.handle(PeerEvent::TlsEstablished);
        p.handle(PeerEvent::HandshakeAccepted(dummy_info()));

        // Force the last_rx timestamp into the past
        p.last_rx = Instant::now() - Duration::from_secs(120);
        p.idle_timeout = Duration::from_secs(90);

        let action = p.check_idle();
        assert_eq!(action, PeerAction::CloseSocket);
        assert!(matches!(
            p.state,
            PeerState::Closed {
                reason: CloseReason::Timeout
            }
        ));
    }

    #[test]
    fn test_idle_check_no_timeout_when_recent() {
        let mut p = peer(Direction::Outbound);
        p.handle(PeerEvent::TlsEstablished);
        p.handle(PeerEvent::HandshakeAccepted(dummy_info()));

        // last_rx is Instant::now() — should not time out
        let action = p.check_idle();
        assert_eq!(action, PeerAction::None);
    }

    #[test]
    fn test_unexpected_event_returns_warn() {
        let mut p = peer(Direction::Outbound);
        // Still in Connecting — OutboundDrained makes no sense here
        let action = p.handle(PeerEvent::OutboundDrained);
        assert!(matches!(action, PeerAction::Warn(_)));
    }
}
