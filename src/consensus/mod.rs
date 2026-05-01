//! xLedgRS purpose: Mod support for XRPL consensus and validation.
//! XRP Ledger Consensus Protocol (XRPLCP).
//!
//! XRPL uses a Federated Byzantine Agreement variant where each validator
//! trusts a Unique Node List (UNL). Consensus proceeds in rounds:
//!
//! ```text
//!  ┌──────┐   close    ┌───────────┐  converge  ┌──────────┐  validate  ┌───────────┐
//!  │ Open │ ─────────► │ Establish │ ──────────► │ Accepted │ ─────────► │ Validated │
//!  └──────┘            └───────────┘             └──────────┘            └───────────┘
//! ```
//!
//! **Open**: Collecting transactions into the open ledger.
//! **Establish**: Validators exchange proposals (tx set hashes) and converge.
//!   - Positions held by >50% of UNL are adopted each round.
//!   - Adoption thresholds rise by elapsed establish time: 50%, 65%, 70%, 95%.
//! **Accepted**: Consensus reached on a tx set. Apply transactions.
//! **Validated**: observed validation quorum on the configured UNL.

pub mod dispute;
pub mod manifest;
pub mod proposal;
pub mod round;
pub mod validation;

pub use dispute::DisputedTx;
pub use manifest::{Manifest, ManifestCache, ManifestError, REVOKE_SEQ};
pub use proposal::Proposal;
pub use round::{ConsensusMode, ConsensusPhase, ConsensusRound, RoundResult};
pub use validation::Validation;
