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
//!   - Threshold starts at 50%, rises to 65%, then 70%, then 80%.
//! **Accepted**: Consensus reached on a tx set. Apply transactions.
//! **Validated**: 80%+ of UNL sent matching validations — ledger is final.

pub mod dispute;
pub mod manifest;
pub mod proposal;
pub mod round;
pub mod validation;

pub use dispute::DisputedTx;
pub use manifest::{Manifest, ManifestCache, ManifestError, REVOKE_SEQ};
pub use proposal::Proposal;
pub use round::{ConsensusMode, ConsensusRound, ConsensusPhase, RoundResult};
pub use validation::Validation;
