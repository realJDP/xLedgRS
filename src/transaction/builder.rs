//! High-level transaction builder.
//!
//! Constructs, signs, and serializes XRPL transactions.
//!
//! # Example
//! ```rust,ignore
//! let kp = Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap();
//! let signed = TxBuilder::payment()
//!     .account(&kp)
//!     .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
//!     .amount(Amount::Xrp(1_000_000))
//!     .fee(12)
//!     .sequence(1)
//!     .sign(&kp);
//! println!("TxHash: {}", signed.hash_hex());
//! println!("Blob:   {}", signed.blob_hex());
//! ```

use crate::crypto::base58::decode_account;
use crate::crypto::keys::KeyPair;
use crate::transaction::amount::Amount;
use crate::transaction::field::{self};
use crate::transaction::serialize::{
    serialize_fields, signing_hash, Field, FieldValue, PREFIX_TX_SIGN,
};
use crate::transaction::TransactionType;
use anyhow::Result;

// ── Signed transaction ────────────────────────────────────────────────────────

/// A fully signed, serialized transaction ready to submit.
pub struct SignedTx {
    /// The transaction hash (32 bytes) — this is the ID on the ledger.
    pub hash: [u8; 32],
    /// The canonical binary encoding of the complete transaction.
    pub blob: Vec<u8>,
}

impl SignedTx {
    pub fn hash_hex(&self) -> String {
        hex::encode_upper(self.hash)
    }

    pub fn blob_hex(&self) -> String {
        hex::encode_upper(&self.blob)
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builds an XRPL transaction field-by-field, then signs it.
pub struct TxBuilder {
    tx_type: TransactionType,
    account: Option<[u8; 20]>,
    destination: Option<[u8; 20]>,
    amount: Option<Amount>,
    fee: u64,
    sequence: u32,
    flags: u32,
    last_ledger: Option<u32>,
    ticket_sequence: Option<u32>,
    dest_tag: Option<u32>,
    source_tag: Option<u32>,
    set_flag: Option<u32>,
    clear_flag: Option<u32>,
    transfer_rate: Option<u32>,
    tick_size: Option<u8>,
    limit_amount: Option<Amount>,
    taker_pays: Option<Amount>,
    taker_gets: Option<Amount>,
    send_max: Option<Amount>,
    deliver_min: Option<Amount>,
    offer_sequence: Option<u32>,
    finish_after: Option<u32>,
    cancel_after: Option<u32>,
    settle_delay: Option<u32>,
    expiration: Option<u32>,
    domain: Option<Vec<u8>>,
    public_key_field: Option<Vec<u8>>,
    channel: Option<[u8; 32]>,
    /// Extra arbitrary fields (for future tx types).
    extra: Vec<Field>,
}

impl TxBuilder {
    fn new(tx_type: TransactionType) -> Self {
        Self {
            tx_type,
            account: None,
            destination: None,
            amount: None,
            fee: 12, // minimum fee in drops
            sequence: 0,
            flags: 0,
            last_ledger: None,
            ticket_sequence: None,
            dest_tag: None,
            source_tag: None,
            set_flag: None,
            clear_flag: None,
            transfer_rate: None,
            tick_size: None,
            limit_amount: None,
            taker_pays: None,
            taker_gets: None,
            send_max: None,
            deliver_min: None,
            offer_sequence: None,
            finish_after: None,
            cancel_after: None,
            settle_delay: None,
            expiration: None,
            domain: None,
            public_key_field: None,
            channel: None,
            extra: Vec::new(),
        }
    }

    pub fn payment() -> Self {
        Self::new(TransactionType::Payment)
    }
    pub fn account_set() -> Self {
        Self::new(TransactionType::AccountSet)
    }
    pub fn trust_set() -> Self {
        Self::new(TransactionType::TrustSet)
    }
    pub fn offer_create() -> Self {
        Self::new(TransactionType::OfferCreate)
    }
    pub fn offer_cancel() -> Self {
        Self::new(TransactionType::OfferCancel)
    }
    pub fn escrow_create() -> Self {
        Self::new(TransactionType::EscrowCreate)
    }
    pub fn escrow_finish() -> Self {
        Self::new(TransactionType::EscrowFinish)
    }
    pub fn escrow_cancel() -> Self {
        Self::new(TransactionType::EscrowCancel)
    }
    pub fn paychan_create() -> Self {
        Self::new(TransactionType::PaymentChannelCreate)
    }
    pub fn paychan_fund() -> Self {
        Self::new(TransactionType::PaymentChannelFund)
    }
    pub fn paychan_claim() -> Self {
        Self::new(TransactionType::PaymentChannelClaim)
    }
    pub fn check_create() -> Self {
        Self::new(TransactionType::CheckCreate)
    }
    pub fn check_cash() -> Self {
        Self::new(TransactionType::CheckCash)
    }
    pub fn check_cancel() -> Self {
        Self::new(TransactionType::CheckCancel)
    }

    // ── Setters ───────────────────────────────────────────────────────────────

    /// Set the signing account from a keypair (derives address automatically).
    pub fn account(mut self, kp: &KeyPair) -> Self {
        let pubkey = match kp {
            KeyPair::Ed25519(k) => {
                let mut v = vec![0xED];
                v.extend_from_slice(&k.public_key_bytes());
                v
            }
            KeyPair::Secp256k1(k) => k.public_key_bytes(),
        };
        let id = crate::crypto::account_id(&pubkey);
        self.account = Some(id);
        self
    }

    /// Set the account address directly (r... string).
    pub fn account_address(mut self, addr: &str) -> Result<Self> {
        self.account = Some(decode_account(addr)?);
        Ok(self)
    }

    /// Set the destination address (r... string).
    pub fn destination(mut self, addr: &str) -> Result<Self> {
        self.destination = Some(decode_account(addr)?);
        Ok(self)
    }

    pub fn amount(mut self, amount: Amount) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn fee(mut self, drops: u64) -> Self {
        self.fee = drops;
        self
    }

    pub fn sequence(mut self, seq: u32) -> Self {
        self.sequence = seq;
        self
    }

    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn last_ledger_sequence(mut self, seq: u32) -> Self {
        self.last_ledger = Some(seq);
        self
    }

    pub fn ticket_sequence(mut self, seq: u32) -> Self {
        self.ticket_sequence = Some(seq);
        self
    }

    pub fn destination_tag(mut self, tag: u32) -> Self {
        self.dest_tag = Some(tag);
        self
    }

    pub fn source_tag(mut self, tag: u32) -> Self {
        self.source_tag = Some(tag);
        self
    }

    pub fn set_flag(mut self, flag: u32) -> Self {
        self.set_flag = Some(flag);
        self
    }

    pub fn clear_flag(mut self, flag: u32) -> Self {
        self.clear_flag = Some(flag);
        self
    }

    pub fn transfer_rate(mut self, rate: u32) -> Self {
        self.transfer_rate = Some(rate);
        self
    }

    pub fn tick_size(mut self, size: u8) -> Self {
        self.tick_size = Some(size);
        self
    }

    /// Set the LimitAmount for TrustSet transactions.
    pub fn limit_amount(mut self, amount: Amount) -> Self {
        self.limit_amount = Some(amount);
        self
    }

    /// Set TakerPays for OfferCreate.
    pub fn taker_pays(mut self, amount: Amount) -> Self {
        self.taker_pays = Some(amount);
        self
    }

    /// Set TakerGets for OfferCreate.
    pub fn taker_gets(mut self, amount: Amount) -> Self {
        self.taker_gets = Some(amount);
        self
    }

    pub fn send_max(mut self, amount: Amount) -> Self {
        self.send_max = Some(amount);
        self
    }

    pub fn deliver_min(mut self, amount: Amount) -> Self {
        self.deliver_min = Some(amount);
        self
    }

    /// Set OfferSequence for OfferCancel / EscrowFinish / EscrowCancel.
    pub fn offer_sequence(mut self, seq: u32) -> Self {
        self.offer_sequence = Some(seq);
        self
    }

    pub fn finish_after(mut self, time: u32) -> Self {
        self.finish_after = Some(time);
        self
    }

    pub fn cancel_after(mut self, time: u32) -> Self {
        self.cancel_after = Some(time);
        self
    }

    pub fn settle_delay(mut self, secs: u32) -> Self {
        self.settle_delay = Some(secs);
        self
    }

    pub fn expiration(mut self, time: u32) -> Self {
        self.expiration = Some(time);
        self
    }

    pub fn domain(mut self, domain: Vec<u8>) -> Self {
        self.domain = Some(domain);
        self
    }

    pub fn public_key_field(mut self, pk: Vec<u8>) -> Self {
        self.public_key_field = Some(pk);
        self
    }

    pub fn channel(mut self, ch: [u8; 32]) -> Self {
        self.channel = Some(ch);
        self
    }

    // ── Build fields list ─────────────────────────────────────────────────────

    pub fn build_fields(
        &self,
        signing_pubkey: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<Vec<Field>> {
        let account = self
            .account
            .ok_or_else(|| anyhow::anyhow!("account not set"))?;

        let mut fields = vec![
            Field {
                def: field::TRANSACTION_TYPE,
                value: FieldValue::UInt16(self.tx_type as u16),
            },
            Field {
                def: field::FLAGS,
                value: FieldValue::UInt32(self.flags),
            },
            Field {
                def: field::SEQUENCE,
                value: FieldValue::UInt32(self.sequence),
            },
            Field {
                def: field::FEE,
                value: FieldValue::Amount(Amount::Xrp(self.fee)),
            },
            Field {
                def: field::SIGNING_PUB_KEY,
                value: FieldValue::Blob(signing_pubkey),
            },
            Field {
                def: field::ACCOUNT,
                value: FieldValue::AccountID(account),
            },
        ];

        if let Some(tag) = self.source_tag {
            fields.push(Field {
                def: field::SOURCE_TAG,
                value: FieldValue::UInt32(tag),
            });
        }
        if let Some(os) = self.offer_sequence {
            fields.push(Field {
                def: field::OFFER_SEQUENCE,
                value: FieldValue::UInt32(os),
            });
        }
        if let Some(lls) = self.last_ledger {
            fields.push(Field {
                def: field::LAST_LEDGER_SEQUENCE,
                value: FieldValue::UInt32(lls),
            });
        }
        if let Some(ts) = self.ticket_sequence {
            fields.push(Field {
                def: field::TICKET_SEQUENCE,
                value: FieldValue::UInt32(ts),
            });
        }
        if let Some(flag) = self.set_flag {
            fields.push(Field {
                def: field::SET_FLAG,
                value: FieldValue::UInt32(flag),
            });
        }
        if let Some(flag) = self.clear_flag {
            fields.push(Field {
                def: field::CLEAR_FLAG,
                value: FieldValue::UInt32(flag),
            });
        }
        if let Some(rate) = self.transfer_rate {
            fields.push(Field {
                def: field::TRANSFER_RATE,
                value: FieldValue::UInt32(rate),
            });
        }
        if let Some(fa) = self.finish_after {
            fields.push(Field {
                def: field::FINISH_AFTER,
                value: FieldValue::UInt32(fa),
            });
        }
        if let Some(ca) = self.cancel_after {
            fields.push(Field {
                def: field::CANCEL_AFTER,
                value: FieldValue::UInt32(ca),
            });
        }
        if let Some(sd) = self.settle_delay {
            fields.push(Field {
                def: field::SETTLE_DELAY,
                value: FieldValue::UInt32(sd),
            });
        }
        if let Some(exp) = self.expiration {
            fields.push(Field {
                def: field::EXPIRATION,
                value: FieldValue::UInt32(exp),
            });
        }
        if let Some(size) = self.tick_size {
            fields.push(Field {
                def: field::TICK_SIZE,
                value: FieldValue::UInt8(size),
            });
        }
        if let Some(ref ch) = self.channel {
            fields.push(Field {
                def: field::CHANNEL,
                value: FieldValue::Hash256(*ch),
            });
        }
        if let Some(ref pk) = self.public_key_field {
            fields.push(Field {
                def: field::PUBLIC_KEY,
                value: FieldValue::Blob(pk.clone()),
            });
        }
        if let Some(ref domain) = self.domain {
            fields.push(Field {
                def: field::DOMAIN,
                value: FieldValue::Blob(domain.clone()),
            });
        }
        if let Some(ref amt) = self.amount {
            fields.push(Field {
                def: field::AMOUNT,
                value: FieldValue::Amount(amt.clone()),
            });
        }
        if let Some(ref lmt) = self.limit_amount {
            fields.push(Field {
                def: field::LIMIT_AMOUNT,
                value: FieldValue::Amount(lmt.clone()),
            });
        }
        if let Some(ref tp) = self.taker_pays {
            fields.push(Field {
                def: field::TAKER_PAYS,
                value: FieldValue::Amount(tp.clone()),
            });
        }
        if let Some(ref tg) = self.taker_gets {
            fields.push(Field {
                def: field::TAKER_GETS,
                value: FieldValue::Amount(tg.clone()),
            });
        }
        if let Some(ref send_max) = self.send_max {
            fields.push(Field {
                def: field::SEND_MAX,
                value: FieldValue::Amount(send_max.clone()),
            });
        }
        if let Some(ref deliver_min) = self.deliver_min {
            fields.push(Field {
                def: field::DELIVER_MIN,
                value: FieldValue::Amount(deliver_min.clone()),
            });
        }
        if let Some(dest) = self.destination {
            fields.push(Field {
                def: field::DESTINATION,
                value: FieldValue::AccountID(dest),
            });
        }
        if let Some(tag) = self.dest_tag {
            fields.push(Field {
                def: field::DESTINATION_TAG,
                value: FieldValue::UInt32(tag),
            });
        }
        if let Some(sig) = signature {
            fields.push(Field {
                def: field::TXN_SIGNATURE,
                value: FieldValue::Blob(sig),
            });
        }

        fields.extend_from_slice(&self.extra);
        Ok(fields)
    }

    // ── Sign ──────────────────────────────────────────────────────────────────

    /// Sign the transaction with a keypair and return a `SignedTx`.
    pub fn sign(self, kp: &KeyPair) -> Result<SignedTx> {
        // 1. Determine signing pubkey bytes (Ed25519 is prefixed with 0xED on-ledger)
        let signing_pubkey = match kp {
            KeyPair::Ed25519(k) => {
                let mut v = vec![0xED];
                v.extend_from_slice(&k.public_key_bytes());
                v
            }
            KeyPair::Secp256k1(k) => k.public_key_bytes(),
        };

        // 2. Build fields without signature to compute signing data
        let mut fields_for_signing = self.build_fields(signing_pubkey.clone(), None)?;

        // 3. Sign — Ed25519 needs the *raw* signing payload (it hashes internally
        //    via SHA-512), while secp256k1 needs the SHA-512-Half hash.
        let signature = match kp {
            KeyPair::Ed25519(_) => {
                // rippled passes raw (PREFIX_TX_SIGN || serialized_fields) to ed25519_sign.
                let mut payload = PREFIX_TX_SIGN.to_vec();
                payload.extend_from_slice(&serialize_fields(&mut fields_for_signing, true));
                kp.sign(&payload)
            }
            KeyPair::Secp256k1(sk) => {
                // signing_hash returns SHA512Half(STX\0 || fields) — already hashed.
                // Use sign_digest to avoid double-hashing (sign() would hash again).
                let hash_to_sign = signing_hash(&mut fields_for_signing);
                sk.sign_digest(&hash_to_sign)
            }
        };

        // 4. Rebuild with signature included
        let mut fields_final = self.build_fields(signing_pubkey, Some(signature))?;

        // 5. Serialize the full signed transaction
        let blob = serialize_fields(&mut fields_final, false);

        // 6. Compute the transaction hash (ID)
        let hash = {
            use crate::transaction::serialize::PREFIX_TX_ID;
            let mut payload = PREFIX_TX_ID.to_vec();
            payload.extend_from_slice(&blob);
            crate::crypto::sha512_first_half(&payload)
        };

        Ok(SignedTx { hash, blob })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Secp256k1KeyPair;

    fn genesis_keypair() -> KeyPair {
        KeyPair::Secp256k1(
            Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")
                .expect("genesis seed valid"),
        )
    }

    #[test]
    fn test_payment_signs_without_panic() {
        let kp = genesis_keypair();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .expect("signing should succeed");

        assert_eq!(signed.hash.len(), 32);
        assert!(!signed.blob.is_empty());
        println!("TxHash: {}", signed.hash_hex());
        println!("Blob:   {}", &signed.blob_hex()[..80]);
    }

    #[test]
    fn test_signing_is_deterministic() {
        let kp = genesis_keypair();
        let sign = || {
            TxBuilder::payment()
                .account(&kp)
                .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
                .unwrap()
                .amount(Amount::Xrp(500_000))
                .fee(12)
                .sequence(5)
                .sign(&kp)
                .unwrap()
        };
        let a = sign();
        let b = sign();
        assert_eq!(a.hash, b.hash, "same tx must produce same hash");
        assert_eq!(a.blob, b.blob, "same tx must produce same blob");
    }

    #[test]
    fn test_hash_changes_with_different_fields() {
        let kp = genesis_keypair();
        let a = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        let b = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(2_000_000)) // different amount
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        assert_ne!(
            a.hash, b.hash,
            "different amounts must produce different hashes"
        );
        assert_ne!(a.blob, b.blob);
    }

    #[test]
    fn test_blob_starts_with_transaction_type_field() {
        let kp = genesis_keypair();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        // First field must be TransactionType (field ID 0x12) with value 0x0000 (Payment)
        assert_eq!(
            signed.blob[0], 0x12,
            "first byte must be TransactionType field ID"
        );
        assert_eq!(signed.blob[1], 0x00, "Payment = 0");
        assert_eq!(signed.blob[2], 0x00);
    }

    #[test]
    fn test_destination_tag() {
        let kp = genesis_keypair();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .destination_tag(12345)
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        assert!(!signed.blob.is_empty());
    }
}
