//! xLedgRS purpose: Trust Set legacy transactor for XRPL transaction apply.
use super::{check_reserve, TxHandler, TER};
use crate::ledger::keylet;
use crate::ledger::sle::{LedgerEntryType, SLE};
use crate::ledger::tx::balance_before_fee;
use crate::ledger::views::ApplyView;
use crate::transaction::ParsedTx;
use std::sync::Arc;

pub struct TrustSetHandler;

impl TxHandler for TrustSetHandler {
    fn preflight(&self, tx: &ParsedTx) -> Result<(), TER> {
        match &tx.limit_amount {
            Some(crate::transaction::amount::Amount::Iou { .. }) => Ok(()),
            _ => Err(TER::Malformed("temBAD_LIMIT")),
        }
    }

    fn do_apply(&self, tx: &ParsedTx, view: &mut dyn ApplyView) -> TER {
        let (limit_value, currency, counterparty) = match &tx.limit_amount {
            Some(crate::transaction::amount::Amount::Iou {
                value,
                currency,
                issuer,
            }) => (value.clone(), currency.clone(), *issuer),
            _ => return TER::Malformed("temBAD_LIMIT"),
        };

        // Look up existing trust line
        let tl_keylet = keylet::trustline(&tx.account, &counterparty, &currency.code);

        if let Some(tl_sle) = view.peek(&tl_keylet) {
            // Existing trust line -- modify the limit for sender's side
            let mut tl = (*tl_sle).clone();

            // Determine which side the sender is (low or high)
            let _sender_account = tl.get_field_account(8, 1); // check if sfAccount matches
                                                              // For RippleState, LowLimit issuer = low account, HighLimit issuer = high account
                                                              // Check the low/high accounts to determine the sender's side.
                                                              // Low account has sfLowLimit (6,6) with its issuer
                                                              // The limit_value goes into sfLowLimit or sfHighLimit depending on sender

            // Use the raw field patching approach and set the appropriate limit.
            // This is complex IOU amount encoding; delegate to encode helper
            let limit_bytes = {
                let mut buf = Vec::with_capacity(48);
                buf.extend_from_slice(&limit_value.to_bytes());
                buf.extend_from_slice(&currency.code);
                buf.extend_from_slice(&tx.account); // issuer = sender for their limit
                buf
            };

            // Determine if sender is low or high by checking the existing SLE
            let low_limit_issuer = extract_iou_issuer(&tl, 6, 6);
            let is_low = low_limit_issuer.map(|i| i == tx.account).unwrap_or(false);

            if is_low {
                tl.set_field_raw_pub(6, 6, &limit_bytes); // sfLowLimit
            } else {
                tl.set_field_raw_pub(6, 7, &limit_bytes); // sfHighLimit
            }

            view.update(Arc::new(tl));
        } else {
            // Reserve check uses the pre-fee balance, matching rippled's
            // reserve-creating transactor convention.
            let sender_keylet_chk = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet_chk) {
                let balance = sender_sle.balance_xrp().unwrap_or(0);
                let pre_fee_balance = balance_before_fee(balance, tx.fee);
                if let Err(ter) =
                    check_reserve(pre_fee_balance, sender_sle.owner_count(), 1, view.fees())
                {
                    return ter;
                }
            }

            // New trust line -- create it
            // Build a full RippleState SLE
            let (low, high) = if tx.account < counterparty {
                (tx.account, counterparty)
            } else {
                (counterparty, tx.account)
            };

            let is_sender_low = tx.account == low;

            let zero_iou = |issuer: &[u8; 20]| -> Vec<u8> {
                let mut buf = Vec::with_capacity(48);
                buf.extend_from_slice(&crate::transaction::amount::IouValue::ZERO.to_bytes());
                buf.extend_from_slice(&currency.code);
                buf.extend_from_slice(issuer);
                buf
            };

            let limit_iou =
                |val: &crate::transaction::amount::IouValue, issuer: &[u8; 20]| -> Vec<u8> {
                    let mut buf = Vec::with_capacity(48);
                    buf.extend_from_slice(&val.to_bytes());
                    buf.extend_from_slice(&currency.code);
                    buf.extend_from_slice(issuer);
                    buf
                };

            let mut data = Vec::with_capacity(256);
            // LedgerEntryType = RippleState (0x0072)
            crate::ledger::meta::write_field_header(&mut data, 1, 1);
            data.extend_from_slice(&0x0072u16.to_be_bytes());
            // Flags = 0
            crate::ledger::meta::write_field_header(&mut data, 2, 2);
            data.extend_from_slice(&0u32.to_be_bytes());
            // LowNode = 0
            crate::ledger::meta::write_field_header(&mut data, 3, 7);
            data.extend_from_slice(&0u64.to_be_bytes());
            // HighNode = 0
            crate::ledger::meta::write_field_header(&mut data, 3, 8);
            data.extend_from_slice(&0u64.to_be_bytes());
            // Balance = 0 (issuer = low account per rippled convention)
            crate::ledger::meta::write_field_header(&mut data, 6, 2);
            data.extend_from_slice(&zero_iou(&low));
            // LowLimit
            crate::ledger::meta::write_field_header(&mut data, 6, 6);
            if is_sender_low {
                data.extend_from_slice(&limit_iou(&limit_value, &low));
            } else {
                data.extend_from_slice(&zero_iou(&low));
            }
            // HighLimit
            crate::ledger::meta::write_field_header(&mut data, 6, 7);
            if !is_sender_low {
                data.extend_from_slice(&limit_iou(&limit_value, &high));
            } else {
                data.extend_from_slice(&zero_iou(&high));
            }

            view.insert(Arc::new(SLE::new(
                tl_keylet.key,
                LedgerEntryType::RippleState,
                data,
            )));

            // Increment owner count for both accounts
            let sender_keylet = keylet::account(&tx.account);
            if let Some(sender_sle) = view.peek(&sender_keylet) {
                let mut s = (*sender_sle).clone();
                s.set_owner_count(s.owner_count() + 1);
                view.update(Arc::new(s));
            }

            let peer_keylet = keylet::account(&counterparty);
            if let Some(peer_sle) = view.peek(&peer_keylet) {
                let mut p = (*peer_sle).clone();
                p.set_owner_count(p.owner_count() + 1);
                view.update(Arc::new(p));
            }
        }

        TER::Success
    }
}

/// Extract the 20-byte issuer from an IOU Amount field in an SLE.
/// IOU amounts are 48 bytes: 8 (value) + 20 (currency) + 20 (issuer).
pub fn extract_iou_issuer(sle: &SLE, type_code: u16, field_code: u16) -> Option<[u8; 20]> {
    let raw = sle.find_field_raw(type_code, field_code)?;
    if raw.len() >= 48 {
        let mut issuer = [0u8; 20];
        issuer.copy_from_slice(&raw[28..48]);
        Some(issuer)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::balance_before_fee;

    #[test]
    fn pre_fee_balance_restores_sender_balance_before_fee() {
        assert_eq!(balance_before_fee(1_199_989, 12), 1_200_001);
    }
}
