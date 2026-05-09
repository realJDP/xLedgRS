use crate::transaction::amount::{Amount, IouValue, Issue};

/// Explicit rounding direction for XRPL amount math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rounding {
    TowardZero,
    AwayFromZero,
}

/// Runtime amount family used by flow dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AmountKind {
    Xrp,
    Iou,
    Mpt,
}

/// Amount wrapper used by flow steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowAmount {
    amount: Amount,
}

impl FlowAmount {
    pub(crate) fn new(amount: Amount) -> Self {
        Self { amount }
    }

    pub(crate) fn as_amount(&self) -> &Amount {
        &self.amount
    }

    pub(crate) fn into_amount(self) -> Amount {
        self.amount
    }

    pub(crate) fn kind(&self) -> AmountKind {
        match self.amount {
            Amount::Xrp(_) => AmountKind::Xrp,
            Amount::Iou { .. } => AmountKind::Iou,
            Amount::Mpt(_) => AmountKind::Mpt,
        }
    }

    pub(crate) fn issue(&self) -> Option<Issue> {
        match &self.amount {
            Amount::Xrp(_) => Some(Issue::Xrp),
            Amount::Iou {
                currency, issuer, ..
            } => Some(Issue::Iou {
                currency: currency.clone(),
                issuer: *issuer,
            }),
            Amount::Mpt(raw) => {
                let (_, issuance) = Amount::Mpt(raw.clone()).mpt_parts()?;
                Some(Issue::Mpt(issuance))
            }
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        match &self.amount {
            Amount::Xrp(drops) => *drops == 0,
            Amount::Iou { value, .. } => value.is_zero(),
            Amount::Mpt(raw) => raw.is_empty(),
        }
    }

    pub(crate) fn same_issue(&self, other: &Self) -> bool {
        self.issue() == other.issue()
    }

    pub(crate) fn checked_add_same_issue(&self, other: &Self) -> Option<Self> {
        if !self.same_issue(other) {
            return None;
        }
        match (&self.amount, &other.amount) {
            (Amount::Xrp(a), Amount::Xrp(b)) => a.checked_add(*b).map(Amount::Xrp).map(Self::new),
            (
                Amount::Iou {
                    value,
                    currency,
                    issuer,
                },
                Amount::Iou { value: rhs, .. },
            ) => Some(Self::new(Amount::Iou {
                value: value.add(rhs),
                currency: currency.clone(),
                issuer: *issuer,
            })),
            _ => None,
        }
    }

    pub(crate) fn checked_sub_same_issue(&self, other: &Self) -> Option<Self> {
        if !self.same_issue(other) {
            return None;
        }
        match (&self.amount, &other.amount) {
            (Amount::Xrp(a), Amount::Xrp(b)) => a.checked_sub(*b).map(Amount::Xrp).map(Self::new),
            (
                Amount::Iou {
                    value,
                    currency,
                    issuer,
                },
                Amount::Iou { value: rhs, .. },
            ) => Some(Self::new(Amount::Iou {
                value: value.sub(rhs),
                currency: currency.clone(),
                issuer: *issuer,
            })),
            _ => None,
        }
    }

    pub(crate) fn mul_iou_rate(&self, rate: &IouValue, rounding: Rounding) -> Option<Self> {
        match &self.amount {
            Amount::Xrp(drops) => {
                let value = IouValue {
                    mantissa: *drops as i64,
                    exponent: 0,
                }
                .mul_round(rate, rounding == Rounding::AwayFromZero);
                if value.mantissa < 0 {
                    return None;
                }
                iou_to_drops(value).map(Amount::Xrp).map(Self::new)
            }
            Amount::Iou {
                value,
                currency,
                issuer,
            } => Some(Self::new(Amount::Iou {
                value: value.mul_round(rate, rounding == Rounding::AwayFromZero),
                currency: currency.clone(),
                issuer: *issuer,
            })),
            Amount::Mpt(_) => None,
        }
    }
}

impl From<Amount> for FlowAmount {
    fn from(amount: Amount) -> Self {
        Self::new(amount)
    }
}

fn iou_to_drops(value: IouValue) -> Option<u64> {
    if value.mantissa <= 0 {
        return Some(0);
    }
    let mantissa = value.mantissa as u128;
    let drops = if value.exponent >= 0 {
        mantissa.checked_mul(10u128.checked_pow(value.exponent as u32)?)?
    } else {
        mantissa / 10u128.checked_pow((-value.exponent) as u32)?
    };
    u64::try_from(drops).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::amount::Currency;

    #[test]
    fn flow_amount_tracks_issue_and_zero() {
        let xrp = FlowAmount::new(Amount::Xrp(0));
        assert_eq!(xrp.kind(), AmountKind::Xrp);
        assert_eq!(xrp.issue(), Some(Issue::Xrp));
        assert!(xrp.is_zero());

        let issuer = [7u8; 20];
        let usd = Currency::from_code("USD").unwrap();
        let iou = FlowAmount::new(Amount::Iou {
            value: IouValue::from_f64(1.0),
            currency: usd.clone(),
            issuer,
        });
        assert_eq!(
            iou.issue(),
            Some(Issue::Iou {
                currency: usd,
                issuer
            })
        );
        assert!(!iou.is_zero());
    }
}
