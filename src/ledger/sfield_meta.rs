//! xLedgRS purpose: Sfield Meta support for XRPL ledger state and SHAMap logic.
//! SField metadata flags — controls which fields appear in transaction metadata.
//!
//! Matches rippled's sMD_* flags from SField.h and sfields.macro.
//! Used during metadata generation to filter fields in FinalFields,
//! PreviousFields, NewFields, and DeletedFinalFields.

/// Metadata flag bits (from rippled SField.h:128-141)
pub const SMD_NEVER: u8 = 0x00; // Never in metadata
pub const SMD_CHANGE_ORIG: u8 = 0x01; // Original value when field changes
pub const SMD_CHANGE_NEW: u8 = 0x02; // New value when field changes
pub const SMD_DELETE_FINAL: u8 = 0x04; // Final value when field is deleted
pub const SMD_CREATE: u8 = 0x08; // Value when field's node is created
pub const SMD_ALWAYS: u8 = 0x10; // Always included when node is affected
pub const SMD_DEFAULT: u8 = SMD_CHANGE_ORIG | SMD_CHANGE_NEW | SMD_DELETE_FINAL | SMD_CREATE; // 0x0F

/// Get the metadata flags for a field identified by (type_code, field_code).
/// Returns SMD_DEFAULT for most fields. Only specific fields have overrides.
pub fn field_meta_flags(type_code: u16, field_code: u16) -> u8 {
    match (type_code, field_code) {
        // sMD_Never: never appears in metadata
        (1, 1) => SMD_NEVER,  // sfLedgerEntryType
        (19, 1) => SMD_NEVER, // sfIndexes (Vector256)

        // sMD_DeleteFinal: only in deleted node's FinalFields
        (2, 5) => SMD_DELETE_FINAL, // sfPreviousTxnLgrSeq
        (5, 5) => SMD_DELETE_FINAL, // sfPreviousTxnID

        // sMD_Always: always in metadata when node is affected
        (5, 8) => SMD_ALWAYS, // sfRootIndex

        // Everything else: sMD_Default
        _ => SMD_DEFAULT,
    }
}

/// Check if a field should appear in metadata for a given context.
#[inline]
pub fn should_meta(type_code: u16, field_code: u16, context: u8) -> bool {
    (field_meta_flags(type_code, field_code) & context) != 0
}

#[inline]
fn should_meta_with_value(type_code: u16, field_code: u16, context: u8, data: &[u8]) -> bool {
    let flags = field_meta_flags(type_code, field_code);
    if flags & context == 0 {
        return false;
    }
    if flags & SMD_ALWAYS != 0 {
        return true;
    }
    !crate::ledger::meta::field_data_is_default(data)
}

/// Filter fields for CreatedNode NewFields.
/// Include fields with sMD_Create | sMD_Always that are non-default.
pub fn filter_for_created(
    fields: &[crate::ledger::meta::ParsedField],
) -> Vec<crate::ledger::meta::ParsedField> {
    fields
        .iter()
        .filter(|f| {
            should_meta_with_value(f.type_code, f.field_code, SMD_CREATE | SMD_ALWAYS, &f.data)
        })
        .cloned()
        .collect()
}

/// Filter fields for ModifiedNode FinalFields.
/// Include fields with sMD_Always | sMD_ChangeNew.
pub fn filter_for_modified_final(
    fields: &[crate::ledger::meta::ParsedField],
) -> Vec<crate::ledger::meta::ParsedField> {
    fields
        .iter()
        .filter(|f| {
            should_meta_with_value(
                f.type_code,
                f.field_code,
                SMD_ALWAYS | SMD_CHANGE_NEW,
                &f.data,
            )
        })
        .cloned()
        .collect()
}

/// Filter fields for ModifiedNode PreviousFields.
/// Include fields with sMD_ChangeOrig that changed between pre/post.
pub fn filter_for_modified_previous(
    fields: &[crate::ledger::meta::ParsedField],
) -> Vec<crate::ledger::meta::ParsedField> {
    fields
        .iter()
        .filter(|f| should_meta_with_value(f.type_code, f.field_code, SMD_CHANGE_ORIG, &f.data))
        .cloned()
        .collect()
}

/// Filter fields for DeletedNode FinalFields.
/// Include fields with sMD_Always | sMD_DeleteFinal.
pub fn filter_for_deleted_final(
    fields: &[crate::ledger::meta::ParsedField],
) -> Vec<crate::ledger::meta::ParsedField> {
    fields
        .iter()
        .filter(|f| {
            should_meta_with_value(
                f.type_code,
                f.field_code,
                SMD_ALWAYS | SMD_DELETE_FINAL,
                &f.data,
            )
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_entry_type_never_in_meta() {
        assert!(!should_meta(1, 1, SMD_CREATE | SMD_ALWAYS));
        assert!(!should_meta(1, 1, SMD_CHANGE_NEW | SMD_ALWAYS));
        assert!(!should_meta(1, 1, SMD_DELETE_FINAL | SMD_ALWAYS));
    }

    #[test]
    fn test_indexes_never_in_meta() {
        assert!(!should_meta(19, 1, SMD_CREATE | SMD_ALWAYS));
    }

    #[test]
    fn test_previous_txn_id_only_delete_final() {
        assert!(!should_meta(5, 5, SMD_CHANGE_NEW | SMD_ALWAYS)); // not in ModifiedNode FinalFields
        assert!(should_meta(5, 5, SMD_DELETE_FINAL | SMD_ALWAYS)); // in DeletedNode FinalFields
    }

    #[test]
    fn test_root_index_always() {
        assert!(should_meta(5, 8, SMD_ALWAYS)); // always included
        assert!(should_meta(5, 8, SMD_CHANGE_NEW | SMD_ALWAYS));
    }

    #[test]
    fn test_normal_field_default() {
        // sfBalance (6,2) — default flags
        assert!(should_meta(6, 2, SMD_CREATE));
        assert!(should_meta(6, 2, SMD_CHANGE_NEW));
        assert!(should_meta(6, 2, SMD_CHANGE_ORIG));
        assert!(should_meta(6, 2, SMD_DELETE_FINAL));
    }

    #[test]
    fn test_defaultish_values_are_suppressed_where_possible() {
        use crate::ledger::meta::ParsedField;

        let defaultish = ParsedField {
            type_code: 3,
            field_code: 4,
            data: vec![0; 8],
        };
        let non_default = ParsedField {
            type_code: 3,
            field_code: 4,
            data: vec![0, 0, 0, 0, 0, 0, 0, 1],
        };

        assert_eq!(filter_for_created(&[non_default.clone()]).len(), 1);
        assert!(filter_for_created(&[defaultish.clone()]).is_empty());
        assert!(filter_for_modified_final(&[defaultish.clone()]).is_empty());
        assert!(filter_for_modified_previous(&[defaultish.clone()]).is_empty());
        assert!(filter_for_deleted_final(&[defaultish]).is_empty());
    }
}
