use super::FlowBook;
use crate::transaction::amount::{Currency, Issue};
use crate::transaction::parse::PathStep;
use std::collections::HashSet;

const TF_NO_RIPPLE_DIRECT: u32 = 0x0001_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowStrandSpec {
    pub(crate) steps: Vec<FlowStepSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FlowStepSpec {
    Direct { account: [u8; 20], issue: Issue },
    Book(FlowBook),
}

#[derive(Debug, Clone, Copy)]
struct NormalizedPathNode {
    account: Option<[u8; 20]>,
    currency: Option<[u8; 20]>,
    issuer: Option<[u8; 20]>,
}

impl NormalizedPathNode {
    fn account(account: [u8; 20]) -> Self {
        Self {
            account: Some(account),
            currency: None,
            issuer: None,
        }
    }

    fn offer(currency: Option<[u8; 20]>, issuer: Option<[u8; 20]>) -> Self {
        Self {
            account: None,
            currency,
            issuer,
        }
    }

    fn from_step(step: &PathStep) -> Self {
        Self {
            account: step.account,
            currency: step.currency,
            issuer: step.issuer,
        }
    }

    fn is_account(&self) -> bool {
        self.account.is_some()
    }

    fn is_offer(&self) -> bool {
        self.account.is_none() && (self.currency.is_some() || self.issuer.is_some())
    }
}

/// Validate explicit Payment paths before liquidity execution.
///
/// This is intentionally conservative. Batch 4 does not build BookStep
/// liquidity yet; it separates malformed path shape from legitimate-but-dry
/// liquidity.
pub(crate) fn validate_payment_paths(
    sender: &[u8; 20],
    destination: &[u8; 20],
    paths: &[Vec<PathStep>],
) -> Result<(), &'static str> {
    for path in paths {
        if path.is_empty() {
            return Err("temBAD_PATH");
        }

        for step in path {
            validate_step(sender, destination, step)?;
        }
    }
    Ok(())
}

/// Build non-mutating strand specs for Payment path execution.
///
/// This is the safe Phase-1 seam toward rippled's `toStrands`: it proves path
/// normalization and step selection before any live transaction execution is
/// routed through the new strand engine.
pub(crate) fn build_payment_strands(
    sender: &[u8; 20],
    destination: &[u8; 20],
    send_issue: Issue,
    deliver_issue: Issue,
    paths: &[Vec<PathStep>],
    flags: u32,
) -> Result<Vec<FlowStrandSpec>, &'static str> {
    build_payment_strands_with_domain(
        sender,
        destination,
        send_issue,
        deliver_issue,
        paths,
        flags,
        None,
    )
}

pub(crate) fn build_payment_strands_with_domain(
    sender: &[u8; 20],
    destination: &[u8; 20],
    send_issue: Issue,
    deliver_issue: Issue,
    paths: &[Vec<PathStep>],
    flags: u32,
    domain_id: Option<[u8; 32]>,
) -> Result<Vec<FlowStrandSpec>, &'static str> {
    if *sender == [0u8; 20]
        || *destination == [0u8; 20]
        || !is_consistent_payment_issue(&send_issue)
        || !is_consistent_payment_issue(&deliver_issue)
    {
        return Err("temBAD_PATH");
    }

    validate_payment_paths(sender, destination, paths)?;

    let mut strands = Vec::new();
    if (flags & TF_NO_RIPPLE_DIRECT) == 0 {
        push_unique_strand(
            &mut strands,
            payment_path_strand(
                *sender,
                *destination,
                send_issue.clone(),
                deliver_issue.clone(),
                &[],
                domain_id,
            )?,
        );
    }

    for path in paths {
        let strand = payment_path_strand(
            *sender,
            *destination,
            send_issue.clone(),
            deliver_issue.clone(),
            path,
            domain_id,
        )?;
        validate_strand_loops(*sender, &strand)?;
        push_unique_strand(&mut strands, strand);
    }

    if strands.is_empty() {
        return Err("temRIPPLE_EMPTY");
    }
    Ok(strands)
}

fn push_unique_strand(strands: &mut Vec<FlowStrandSpec>, strand: FlowStrandSpec) {
    if !strands.contains(&strand) {
        strands.push(strand);
    }
}

fn payment_path_strand(
    sender: [u8; 20],
    destination: [u8; 20],
    send_issue: Issue,
    deliver_issue: Issue,
    path: &[PathStep],
    domain_id: Option<[u8; 32]>,
) -> Result<FlowStrandSpec, &'static str> {
    let normalized = normalize_path(sender, destination, &send_issue, &deliver_issue, path)?;
    let mut steps = Vec::new();
    let mut current_issue = send_issue.clone();

    for idx in 0..normalized.len().saturating_sub(1) {
        let mut cur = normalized[idx];
        let next = normalized[idx + 1];

        apply_node_issue(&cur, &mut current_issue)?;
        let final_deliver_hop = next.account == Some(destination)
            && issue_currency(&current_issue) == issue_currency(&deliver_issue)
            && path.last().and_then(|step| step.account).is_some();
        if final_deliver_hop {
            // A trailing account node is a rippling hop, not a request to
            // re-issue the final deliver amount from that account.
            current_issue = deliver_issue.clone();
        }

        if cur.is_account() && next.is_account() {
            let cur_account = cur.account.expect("checked is_account");
            let next_account = next.account.expect("checked is_account");
            if let Issue::Iou { issuer, .. } = current_issue.clone() {
                if issuer != cur_account && issuer != next_account && !final_deliver_hop {
                    push_direct(&mut steps, issuer, current_issue.clone());
                    cur = NormalizedPathNode::account(issuer);
                }
            }
        } else if cur.is_account() && next.is_offer() {
            let cur_account = cur.account.expect("checked is_account");
            if let Issue::Iou { issuer, .. } = current_issue.clone() {
                if issuer != cur_account {
                    push_direct(&mut steps, issuer, current_issue.clone());
                    cur = NormalizedPathNode::account(issuer);
                }
            }
        } else if cur.is_offer() && next.is_account() {
            let next_account = next.account.expect("checked is_account");
            if issue_account(&current_issue).is_some_and(|issuer| issuer != next_account) {
                if current_issue == Issue::Xrp {
                    if idx != normalized.len() - 2 {
                        return Err("temBAD_PATH");
                    }
                    push_direct(&mut steps, next_account, Issue::Xrp);
                } else {
                    push_direct(&mut steps, next_account, current_issue.clone());
                }
            }
            continue;
        }

        if !next.is_offer()
            && next
                .currency
                .is_some_and(|currency| Some(currency) != issue_currency(&current_issue))
        {
            return Err("temBAD_PATH");
        }

        push_step_from_pair(&mut steps, cur, next, &current_issue, domain_id)?;
    }

    if steps.is_empty() {
        return Err("temBAD_PATH");
    }

    validate_strand_loops(
        sender,
        &FlowStrandSpec {
            steps: steps.clone(),
        },
    )?;
    Ok(FlowStrandSpec { steps })
}

fn normalize_path(
    sender: [u8; 20],
    destination: [u8; 20],
    send_issue: &Issue,
    deliver_issue: &Issue,
    path: &[PathStep],
) -> Result<Vec<NormalizedPathNode>, &'static str> {
    let mut normalized = Vec::with_capacity(path.len() + 4);
    normalized.push(NormalizedPathNode {
        account: Some(sender),
        currency: issue_currency(send_issue),
        issuer: issue_account(send_issue),
    });

    if let Issue::Iou { issuer, .. } = send_issue {
        if *issuer != sender && path.first().and_then(|step| step.account) != Some(*issuer) {
            normalized.push(NormalizedPathNode::account(*issuer));
        }
    }

    normalized.extend(path.iter().map(NormalizedPathNode::from_step));

    let last_currency = normalized
        .iter()
        .rev()
        .find_map(|node| node.currency)
        .ok_or("temBAD_PATH")?;
    if Some(last_currency) != issue_currency(deliver_issue) {
        normalized.push(NormalizedPathNode::offer(
            issue_currency(deliver_issue),
            issue_account(deliver_issue),
        ));
    }

    let ends_with_explicit_account = path.last().and_then(|step| step.account).is_some();
    if let Issue::Iou { issuer, .. } = &deliver_issue {
        if destination != *issuer
            && !ends_with_explicit_account
            && !normalized
                .last()
                .is_some_and(|node| node.account == Some(*issuer))
        {
            normalized.push(NormalizedPathNode::account(*issuer));
        }
    }

    if !normalized
        .last()
        .is_some_and(|node| node.account == Some(destination))
    {
        normalized.push(NormalizedPathNode::account(destination));
    }

    if normalized.len() < 2 {
        return Err("temBAD_PATH");
    }
    Ok(normalized)
}

fn apply_node_issue(
    node: &NormalizedPathNode,
    current_issue: &mut Issue,
) -> Result<(), &'static str> {
    if let Some(currency) = node.currency {
        if node.issuer.is_some() && currency == [0u8; 20] {
            return Err("temBAD_PATH");
        }
        if currency == [0u8; 20] {
            *current_issue = Issue::Xrp;
        } else {
            let issuer = node
                .issuer
                .or_else(|| issue_account(current_issue))
                .ok_or("temBAD_PATH")?;
            *current_issue = Issue::Iou {
                currency: Currency { code: currency },
                issuer,
            };
        }
        return Ok(());
    }

    match (node.account, node.issuer, current_issue.clone()) {
        (Some(account), _, Issue::Iou { currency, .. }) => {
            *current_issue = Issue::Iou {
                currency,
                issuer: account,
            };
        }
        (None, Some(issuer), Issue::Iou { currency, .. }) => {
            *current_issue = Issue::Iou { currency, issuer };
        }
        (None, Some(_), Issue::Xrp) => return Err("temBAD_PATH"),
        _ => {}
    }
    Ok(())
}

fn push_step_from_pair(
    steps: &mut Vec<FlowStepSpec>,
    cur: NormalizedPathNode,
    next: NormalizedPathNode,
    current_issue: &Issue,
    domain_id: Option<[u8; 32]>,
) -> Result<(), &'static str> {
    if cur.is_account() && next.is_account() {
        push_direct(
            steps,
            next.account.expect("checked is_account"),
            current_issue.clone(),
        );
        return Ok(());
    }

    if !next.is_offer() {
        return Err("temBAD_PATH");
    }

    let out_currency = next
        .currency
        .or_else(|| issue_currency(current_issue))
        .ok_or("temBAD_PATH")?;
    let out_issue = if out_currency == [0u8; 20] {
        Issue::Xrp
    } else {
        Issue::Iou {
            currency: Currency { code: out_currency },
            issuer: next
                .issuer
                .or_else(|| issue_account(current_issue))
                .ok_or("temBAD_PATH")?,
        }
    };

    if *current_issue == Issue::Xrp && out_issue == Issue::Xrp {
        return Err("temBAD_PATH");
    }
    if *current_issue != out_issue {
        steps.push(FlowStepSpec::Book(FlowBook::with_domain(
            current_issue.clone(),
            out_issue,
            domain_id,
        )));
    }
    Ok(())
}

fn push_direct(steps: &mut Vec<FlowStepSpec>, account: [u8; 20], issue: Issue) {
    if steps.last()
        == Some(&FlowStepSpec::Direct {
            account,
            issue: issue.clone(),
        })
    {
        return;
    }
    steps.push(FlowStepSpec::Direct { account, issue });
}

fn issue_currency(issue: &Issue) -> Option<[u8; 20]> {
    match issue {
        Issue::Xrp => Some([0u8; 20]),
        Issue::Iou { currency, .. } => Some(currency.code),
        Issue::Mpt(_) => None,
    }
}

fn issue_account(issue: &Issue) -> Option<[u8; 20]> {
    match issue {
        Issue::Iou { issuer, .. } => Some(*issuer),
        _ => None,
    }
}

fn is_consistent_payment_issue(issue: &Issue) -> bool {
    match issue {
        Issue::Xrp => true,
        Issue::Iou { currency, issuer } => !currency.is_xrp() && *issuer != [0u8; 20],
        Issue::Mpt(_) => false,
    }
}

fn validate_strand_loops(sender: [u8; 20], strand: &FlowStrandSpec) -> Result<(), &'static str> {
    let mut current_account = sender;
    let mut direct_sources = HashSet::<Issue>::new();
    let mut direct_destinations = HashSet::<Issue>::new();
    let mut book_outputs = HashSet::<Issue>::new();
    let mut previous_book_output = None::<Issue>;

    for step in &strand.steps {
        match step {
            FlowStepSpec::Direct { account, issue } => {
                if *account == current_account {
                    return Err("temBAD_PATH");
                }
                let (src_issue, dst_issue) = match issue {
                    Issue::Xrp => (Issue::Xrp, Issue::Xrp),
                    Issue::Iou { currency, .. } => (
                        Issue::Iou {
                            currency: currency.clone(),
                            issuer: current_account,
                        },
                        Issue::Iou {
                            currency: currency.clone(),
                            issuer: *account,
                        },
                    ),
                    Issue::Mpt(_) => return Err("temBAD_PATH"),
                };
                if book_outputs.contains(&src_issue)
                    && previous_book_output.as_ref() != Some(&src_issue)
                {
                    return Err("temBAD_PATH_LOOP");
                }
                if !direct_sources.insert(src_issue) || !direct_destinations.insert(dst_issue) {
                    return Err("temBAD_PATH_LOOP");
                }
                current_account = *account;
                previous_book_output = None;
            }
            FlowStepSpec::Book(book) => {
                if book.in_issue == book.out_issue {
                    return Err("temBAD_PATH");
                }
                if direct_sources.contains(&book.out_issue)
                    || direct_destinations.contains(&book.out_issue)
                    || !book_outputs.insert(book.out_issue.clone())
                {
                    return Err("temBAD_PATH_LOOP");
                }
                if let Issue::Iou { issuer, .. } = book.out_issue {
                    current_account = issuer;
                }
                previous_book_output = Some(book.out_issue.clone());
            }
        }
    }

    Ok(())
}

fn validate_step(
    sender: &[u8; 20],
    destination: &[u8; 20],
    step: &PathStep,
) -> Result<(), &'static str> {
    if step.account.is_none() && step.currency.is_none() && step.issuer.is_none() {
        return Err("temBAD_PATH");
    }

    if step.account.is_some_and(|account| account == [0u8; 20])
        || step.issuer.is_some_and(|issuer| issuer == [0u8; 20])
    {
        return Err("temBAD_PATH");
    }

    if step
        .account
        .as_ref()
        .is_some_and(|account| account == sender)
        || step
            .account
            .as_ref()
            .is_some_and(|account| account == destination)
    {
        return Err("temBAD_PATH_LOOP");
    }

    if step.currency.is_some_and(|currency| currency == [0u8; 20]) && step.issuer.is_some() {
        return Err("temBAD_PATH");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iou(currency_byte: u8, issuer_byte: u8) -> Issue {
        Issue::Iou {
            currency: Currency {
                code: [currency_byte; 20],
            },
            issuer: [issuer_byte; 20],
        }
    }

    #[test]
    fn empty_path_is_malformed() {
        assert_eq!(
            validate_payment_paths(&[1u8; 20], &[2u8; 20], &[vec![]]).unwrap_err(),
            "temBAD_PATH"
        );
    }

    #[test]
    fn account_loop_is_malformed() {
        let sender = [1u8; 20];
        let destination = [2u8; 20];
        let paths = vec![vec![PathStep {
            account: Some(sender),
            currency: None,
            issuer: None,
        }]];
        assert_eq!(
            validate_payment_paths(&sender, &destination, &paths).unwrap_err(),
            "temBAD_PATH_LOOP"
        );
    }

    #[test]
    fn issuer_without_currency_is_structurally_valid() {
        let paths = vec![vec![PathStep {
            account: None,
            currency: None,
            issuer: Some([3u8; 20]),
        }]];
        validate_payment_paths(&[1u8; 20], &[2u8; 20], &paths).expect("issuer-only path node");
    }

    #[test]
    fn account_with_issue_fields_is_structurally_valid_for_amm_paths() {
        let paths = vec![vec![PathStep {
            account: Some([3u8; 20]),
            currency: Some([4u8; 20]),
            issuer: Some([5u8; 20]),
        }]];
        validate_payment_paths(&[1u8; 20], &[2u8; 20], &paths)
            .expect("AMM-shaped account+issue path node");
    }

    #[test]
    fn default_path_builds_direct_same_issue() {
        let destination = [2u8; 20];
        let strands =
            build_payment_strands(&[1u8; 20], &destination, Issue::Xrp, Issue::Xrp, &[], 0)
                .expect("default path");

        assert_eq!(
            strands,
            vec![FlowStrandSpec {
                steps: vec![FlowStepSpec::Direct {
                    account: destination,
                    issue: Issue::Xrp,
                }],
            }]
        );
    }

    #[test]
    fn default_path_builds_book_for_cross_issue() {
        let destination = [2u8; 20];
        let send_issue = Issue::Xrp;
        let deliver_issue = iou(3, 4);
        let strands = build_payment_strands(
            &[1u8; 20],
            &destination,
            send_issue.clone(),
            deliver_issue.clone(),
            &[],
            0,
        )
        .expect("default path");

        assert_eq!(
            strands,
            vec![FlowStrandSpec {
                steps: vec![
                    FlowStepSpec::Book(FlowBook::new(send_issue, deliver_issue.clone())),
                    FlowStepSpec::Direct {
                        account: destination,
                        issue: deliver_issue,
                    },
                ],
            }]
        );
    }

    #[test]
    fn no_ripple_direct_without_paths_is_empty() {
        assert_eq!(
            build_payment_strands(
                &[1u8; 20],
                &[2u8; 20],
                Issue::Xrp,
                Issue::Xrp,
                &[],
                TF_NO_RIPPLE_DIRECT
            )
            .unwrap_err(),
            "temRIPPLE_EMPTY"
        );
    }

    #[test]
    fn explicit_path_builds_book_then_direct_account_step() {
        let destination = [2u8; 20];
        let path_account = [3u8; 20];
        let send_issue = Issue::Xrp;
        let intermediate_issue = iou(4, 5);
        let path_account_issue = Issue::Iou {
            currency: Currency { code: [4u8; 20] },
            issuer: path_account,
        };
        let deliver_issue = iou(6, 7);
        let paths = vec![vec![
            PathStep {
                account: None,
                currency: Some([4u8; 20]),
                issuer: Some([5u8; 20]),
            },
            PathStep {
                account: Some(path_account),
                currency: None,
                issuer: None,
            },
        ]];

        let strands = build_payment_strands(
            &[1u8; 20],
            &destination,
            send_issue.clone(),
            deliver_issue.clone(),
            &paths,
            TF_NO_RIPPLE_DIRECT,
        )
        .expect("explicit path");

        assert_eq!(
            strands,
            vec![FlowStrandSpec {
                steps: vec![
                    FlowStepSpec::Book(FlowBook::new(send_issue, intermediate_issue.clone())),
                    FlowStepSpec::Direct {
                        account: path_account,
                        issue: intermediate_issue.clone(),
                    },
                    FlowStepSpec::Book(FlowBook::new(path_account_issue, deliver_issue.clone())),
                    FlowStepSpec::Direct {
                        account: destination,
                        issue: deliver_issue,
                    },
                ],
            }]
        );
    }

    #[test]
    fn duplicate_explicit_paths_are_deduplicated() {
        let destination = [2u8; 20];
        let send_issue = Issue::Xrp;
        let deliver_issue = iou(4, 5);
        let path = vec![PathStep {
            account: None,
            currency: Some([4u8; 20]),
            issuer: Some([5u8; 20]),
        }];
        let paths = vec![path.clone(), path];

        let strands = build_payment_strands(
            &[1u8; 20],
            &destination,
            send_issue.clone(),
            deliver_issue.clone(),
            &paths,
            TF_NO_RIPPLE_DIRECT,
        )
        .expect("deduplicated explicit paths");

        assert_eq!(
            strands,
            vec![FlowStrandSpec {
                steps: vec![
                    FlowStepSpec::Book(FlowBook::new(send_issue, deliver_issue.clone())),
                    FlowStepSpec::Direct {
                        account: destination,
                        issue: deliver_issue,
                    },
                ],
            }]
        );
    }

    #[test]
    fn explicit_path_matching_default_is_deduplicated() {
        let destination = [2u8; 20];
        let send_issue = Issue::Xrp;
        let deliver_issue = iou(4, 5);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some([4u8; 20]),
            issuer: Some([5u8; 20]),
        }]];

        let strands = build_payment_strands(
            &[1u8; 20],
            &destination,
            send_issue.clone(),
            deliver_issue.clone(),
            &paths,
            0,
        )
        .expect("default and matching explicit path collapse");

        assert_eq!(strands.len(), 1);
        assert_eq!(
            strands[0],
            FlowStrandSpec {
                steps: vec![
                    FlowStepSpec::Book(FlowBook::new(send_issue, deliver_issue.clone())),
                    FlowStepSpec::Direct {
                        account: destination,
                        issue: deliver_issue,
                    },
                ],
            }
        );
    }

    #[test]
    fn currency_only_path_step_reuses_current_iou_issuer() {
        let destination = [2u8; 20];
        let send_issue = iou(3, 4);
        let deliver_issue = iou(5, 6);
        let paths = vec![vec![PathStep {
            account: None,
            currency: Some([7u8; 20]),
            issuer: None,
        }]];

        let strands = build_payment_strands(
            &[1u8; 20],
            &destination,
            send_issue.clone(),
            deliver_issue.clone(),
            &paths,
            TF_NO_RIPPLE_DIRECT,
        )
        .expect("currency-only explicit path");

        assert_eq!(
            strands[0].steps[1],
            FlowStepSpec::Book(FlowBook::new(send_issue, iou(7, 4)))
        );
    }

    #[test]
    fn issuer_only_path_step_switches_current_iou_issuer() {
        let sender = [1u8; 20];
        let destination = [2u8; 20];
        let issuer = [5u8; 20];
        let send_issue = iou(3, 1);
        let issuer_issue = iou(3, 5);
        let deliver_issue = iou(3, 6);
        let paths = vec![vec![PathStep {
            account: None,
            currency: None,
            issuer: Some(issuer),
        }]];

        let strands = build_payment_strands(
            &sender,
            &destination,
            send_issue.clone(),
            deliver_issue.clone(),
            &paths,
            TF_NO_RIPPLE_DIRECT,
        )
        .expect("issuer-only explicit path");

        assert_eq!(
            strands[0].steps[0],
            FlowStepSpec::Book(FlowBook::new(send_issue, issuer_issue.clone()))
        );
        assert_eq!(
            strands[0].steps[1],
            FlowStepSpec::Direct {
                account: [6u8; 20],
                issue: issuer_issue,
            }
        );
    }

    #[test]
    fn trailing_account_path_hop_returns_to_deliver_issue() {
        let sender = [1u8; 20];
        let intermediate = [3u8; 20];
        let destination = [2u8; 20];
        let issue = iou(3, 1);
        let paths = vec![vec![PathStep {
            account: Some(intermediate),
            currency: None,
            issuer: None,
        }]];

        let strands = build_payment_strands(
            &sender,
            &destination,
            issue.clone(),
            issue.clone(),
            &paths,
            TF_NO_RIPPLE_DIRECT,
        )
        .expect("explicit account path");

        assert_eq!(
            strands,
            vec![FlowStrandSpec {
                steps: vec![
                    FlowStepSpec::Direct {
                        account: intermediate,
                        issue: issue.clone(),
                    },
                    FlowStepSpec::Direct {
                        account: destination,
                        issue,
                    },
                ],
            }]
        );
    }

    #[test]
    fn zero_sender_or_destination_is_malformed() {
        assert_eq!(
            build_payment_strands(&[0u8; 20], &[2u8; 20], Issue::Xrp, iou(3, 4), &[], 0)
                .unwrap_err(),
            "temBAD_PATH"
        );
        assert_eq!(
            build_payment_strands(&[1u8; 20], &[0u8; 20], Issue::Xrp, iou(3, 4), &[], 0)
                .unwrap_err(),
            "temBAD_PATH"
        );
    }

    #[test]
    fn mpt_issue_is_not_supported_in_payment_paths() {
        assert_eq!(
            build_payment_strands(
                &[1u8; 20],
                &[2u8; 20],
                Issue::Mpt([3u8; 24]),
                iou(4, 5),
                &[],
                0
            )
            .unwrap_err(),
            "temBAD_PATH"
        );
    }

    #[test]
    fn book_output_reusing_direct_destination_issue_is_loop() {
        let sender = [1u8; 20];
        let issuer_a = [3u8; 20];
        let issue_a = iou(5, 3);
        let issue_b = iou(6, 4);
        let strand = FlowStrandSpec {
            steps: vec![
                FlowStepSpec::Direct {
                    account: issuer_a,
                    issue: issue_a.clone(),
                },
                FlowStepSpec::Book(FlowBook::new(iou(5, 3), issue_b.clone())),
                FlowStepSpec::Book(FlowBook::new(Issue::Xrp, issue_a)),
            ],
        };

        assert_eq!(
            validate_strand_loops(sender, &strand).unwrap_err(),
            "temBAD_PATH_LOOP"
        );
    }
}
