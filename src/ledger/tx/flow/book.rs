use crate::transaction::amount::Issue;

/// Flow-level book descriptor. Mirrors rippled's `Book` concept: input issue,
/// output issue, and an optional permissioned-domain identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowBook {
    pub(crate) in_issue: Issue,
    pub(crate) out_issue: Issue,
    pub(crate) domain_id: Option<[u8; 32]>,
}

impl FlowBook {
    pub(crate) fn new(in_issue: Issue, out_issue: Issue) -> Self {
        Self {
            in_issue,
            out_issue,
            domain_id: None,
        }
    }

    pub(crate) fn with_domain(
        in_issue: Issue,
        out_issue: Issue,
        domain_id: Option<[u8; 32]>,
    ) -> Self {
        Self {
            in_issue,
            out_issue,
            domain_id,
        }
    }

    pub(crate) fn is_cross_currency(&self) -> bool {
        self.in_issue != self.out_issue
    }
}
