//! Transaction authentication helpers for live submit paths.
//!
//! `parse_blob` intentionally accepts replay and multisign shapes that do not
//! have a top-level single signature. Live admission paths must call this
//! module before handing a transaction to the ledger engine.

use super::ParsedTx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAuthError {
    MissingSignature,
    UnsupportedMultiSign,
    MalformedMultiSign,
    BadSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSigner {
    pub account: [u8; 20],
    pub signing_account: [u8; 20],
}

pub fn verify_single_signature(tx: &ParsedTx) -> Result<[u8; 20], TxAuthError> {
    if !tx.signers.is_empty() {
        return Err(TxAuthError::UnsupportedMultiSign);
    }
    if tx.signing_pubkey.is_empty() || tx.signature.is_empty() {
        return Err(TxAuthError::MissingSignature);
    }

    let sig_ok = verify_signature(
        &tx.signing_pubkey,
        &tx.signing_hash,
        &tx.signing_payload,
        &tx.signature,
    );

    if !sig_ok {
        return Err(TxAuthError::BadSignature);
    }

    Ok(crate::crypto::account_id(&tx.signing_pubkey))
}

pub fn verify_multisign_signatures(tx: &ParsedTx) -> Result<Vec<VerifiedSigner>, TxAuthError> {
    if tx.signers.is_empty() {
        return Err(TxAuthError::MissingSignature);
    }
    if tx.signers.len() > 32 {
        return Err(TxAuthError::MalformedMultiSign);
    }
    if !tx.signing_pubkey.is_empty() || !tx.signature.is_empty() {
        return Err(TxAuthError::MalformedMultiSign);
    }

    let signing_fields = tx
        .signing_payload
        .get(4..)
        .ok_or(TxAuthError::MalformedMultiSign)?;
    let mut previous = None::<[u8; 20]>;
    let mut verified = Vec::with_capacity(tx.signers.len());

    for signer in &tx.signers {
        if signer.account == tx.account {
            return Err(TxAuthError::MalformedMultiSign);
        }
        if previous.map(|prev| prev >= signer.account).unwrap_or(false) {
            return Err(TxAuthError::MalformedMultiSign);
        }
        previous = Some(signer.account);

        let mut payload = crate::transaction::serialize::PREFIX_TX_MULTISIGN.to_vec();
        payload.extend_from_slice(signing_fields);
        payload.extend_from_slice(&signer.account);
        let signing_hash = crate::crypto::sha512_first_half(&payload);
        if !verify_signature(
            &signer.signing_pubkey,
            &signing_hash,
            &payload,
            &signer.signature,
        ) {
            return Err(TxAuthError::BadSignature);
        }

        verified.push(VerifiedSigner {
            account: signer.account,
            signing_account: crate::crypto::account_id(&signer.signing_pubkey),
        });
    }

    Ok(verified)
}

fn verify_signature(
    pubkey: &[u8],
    signing_hash: &[u8; 32],
    signing_payload: &[u8],
    signature: &[u8],
) -> bool {
    if pubkey.first() == Some(&0xED) && pubkey.len() == 33 {
        verify_ed25519(pubkey, signing_payload, signature)
    } else {
        crate::crypto::keys::verify_secp256k1_digest(pubkey, signing_hash, signature)
    }
}

fn verify_ed25519(pubkey: &[u8], signing_payload: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier;

    let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let Ok(pk_bytes): Result<[u8; 32], _> = pubkey[1..].try_into() else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify(signing_payload, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KeyPair, Secp256k1KeyPair};
    use crate::transaction::{builder::TxBuilder, parse_blob, Amount};

    fn genesis_kp() -> KeyPair {
        KeyPair::Secp256k1(Secp256k1KeyPair::from_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb").unwrap())
    }

    #[test]
    fn signed_single_signature_verifies() {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        let parsed = parse_blob(&signed.blob).unwrap();
        let signing_account = verify_single_signature(&parsed).unwrap();
        assert_eq!(signing_account, parsed.account);
    }

    #[test]
    fn tampered_single_signature_is_rejected() {
        let kp = genesis_kp();
        let signed = TxBuilder::payment()
            .account(&kp)
            .destination("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe")
            .unwrap()
            .amount(Amount::Xrp(1_000_000))
            .fee(12)
            .sequence(1)
            .sign(&kp)
            .unwrap();

        let mut parsed = parse_blob(&signed.blob).unwrap();
        parsed.signature[0] ^= 0x01;
        assert_eq!(
            verify_single_signature(&parsed),
            Err(TxAuthError::BadSignature)
        );
    }

    #[test]
    fn missing_single_signature_is_rejected() {
        let mut parsed = ParsedTx::default();
        parsed.account = [1u8; 20];
        assert_eq!(
            verify_single_signature(&parsed),
            Err(TxAuthError::MissingSignature)
        );
    }
}
