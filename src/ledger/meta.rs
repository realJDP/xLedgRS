//! Binary transaction metadata parser.
//!
//! Parses XRPL binary metadata blobs to extract AffectedNodes with their
//! raw binary field data.  Used by the ledger follower to update the SHAMap
//! with exact binary SLEs (Serialized Ledger Entries).
//!
//! # Metadata structure (binary STObject)
//!
//! The metadata blob is an STObject containing:
//!   - TransactionResult (UInt8, type=16, field=??)
//!   - TransactionIndex (UInt32)
//!   - AffectedNodes (STArray, type=15, field=8 → header 0xF8 since field < 16... wait)
//!
//! Actually AffectedNodes has field code that needs checking. Let me just parse
//! generically.

/// A single affected node extracted from binary metadata.
#[derive(Clone)]
pub struct AffectedNode {
    pub action: Action,
    /// LedgerEntryType code (e.g. 0x0061 = AccountRoot)
    pub entry_type: u16,
    /// LedgerIndex — the 32-byte SHAMap key
    pub ledger_index: [u8; 32],
    /// For Modified: parsed fields from FinalFields (post-tx state)
    /// For Created: parsed fields from NewFields (initial state)
    /// For Deleted: parsed fields from FinalFields (pre-deletion state)
    pub fields: Vec<ParsedField>,
    /// For Modified: parsed fields from PreviousFields (only the fields that
    /// changed — the "before" values).  Combined with `fields` (FinalFields),
    /// pre-tx state = FinalFields with PreviousFields overrides.
    /// (rippled: sfields.macro sfPreviousFields = OBJECT field 6)
    pub previous_fields: Vec<ParsedField>,
    /// PreviousTxnID from the outer node level
    pub prev_txn_id: Option<[u8; 32]>,
    /// PreviousTxnLgrSeq from the outer node level
    pub prev_txn_lgrseq: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    Created,
    Modified,
    Deleted,
}

/// Patch an existing SLE binary with changed fields from metadata.
///
/// Surgical approach: walks the existing SLE byte-by-byte, copies each
/// field verbatim UNLESS it appears in the replacement set. Nested
/// STObjects/STArrays are never parsed — their raw bytes are preserved.
///
/// `deleted_fields` contains (type_code, field_code) pairs for fields that
/// were in PreviousFields but NOT in FinalFields — these were removed by
/// the transaction and must be omitted from the output.
pub fn patch_sle(
    existing_sle: &[u8],
    new_fields: &[ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
    deleted_fields: &[(u16, u16)],
) -> Vec<u8> {
    // Build lookup of replacement fields by (type_code, field_code)
    let mut replacements: std::collections::HashMap<(u16, u16), &ParsedField> =
        std::collections::HashMap::new();
    for f in new_fields {
        replacements.insert((f.type_code, f.field_code), f);
    }

    // Also prepare PreviousTxnID/LgrSeq replacements
    let ptid_data;
    if let Some(id) = prev_txn_id {
        ptid_data = Some(id);
        // Will handle inline
    } else {
        ptid_data = None;
    }

    // Walk existing SLE, copy or replace each field
    let mut out = Vec::with_capacity(existing_sle.len() + 64);
    let mut pos = 0;
    let mut seen_fields: std::collections::HashSet<(u16, u16)> = std::collections::HashSet::new();

    while pos < existing_sle.len() {
        let field_start = pos;

        // Read field header
        let (tc, fc, header_end) = read_field_header(existing_sle, pos);
        if header_end > existing_sle.len() { break; }

        let field_key = (tc, fc);
        seen_fields.insert(field_key);

        // Find end of this field's data
        let data_start = header_end;
        let data_end = skip_field_raw(existing_sle, data_start, tc);
        if data_end <= pos {
            tracing::warn!("patch_sle: forward-progress stall at pos={pos} tc={tc} fc={fc}, breaking");
            break; // forward-progress guard
        }

        // Check if this field was deleted by the transaction
        if deleted_fields.contains(&field_key) {
            pos = data_end;
            continue;
        }

        // Check if this field should be replaced
        let replaced = if field_key == (5, 5) && ptid_data.is_some() {
            // PreviousTxnID — replace with new value
            write_field_header(&mut out, 5, 5);
            out.extend_from_slice(&ptid_data.unwrap());
            true
        } else if field_key == (2, 5) && prev_txn_lgrseq.is_some() {
            // PreviousTxnLgrSeq — replace with new value
            write_field_header(&mut out, 2, 5);
            out.extend_from_slice(&prev_txn_lgrseq.unwrap().to_be_bytes());
            true
        } else if let Some(replacement) = replacements.get(&field_key) {
            // Field from FinalFields — write new value with proper header
            write_field_header(&mut out, tc, fc);
            if is_vl_type(tc) {
                encode_vl_length(&mut out, replacement.data.len());
            }
            out.extend_from_slice(&replacement.data);
            true
        } else {
            false
        };

        if !replaced {
            // Copy original bytes verbatim (header + data, including any nested structures)
            out.extend_from_slice(&existing_sle[field_start..data_end]);
        }

        pos = data_end;
    }

    // Add any new fields from FinalFields that weren't in the original SLE.
    // Insert each at the correct canonical position (sorted by type_code, field_code).
    // We do this by scanning the output to find where each new field belongs.
    for f in new_fields {
        if seen_fields.contains(&(f.type_code, f.field_code)) { continue; }

        // Find the insertion point: right before the first field with a
        // higher (type_code, field_code) than this new field.
        let new_key = (f.type_code, f.field_code);
        let mut insert_pos = out.len(); // default: append at end
        let mut scan = 0;
        while scan < out.len() {
            let (tc, fc, hend) = read_field_header(&out, scan);
            if hend > out.len() { break; }
            if (tc, fc) > new_key {
                insert_pos = scan;
                break;
            }
            let next = skip_field_raw(&out, hend, tc);
            if next <= scan { break; } // forward-progress guard
            scan = next;
        }

        // Serialize the new field
        let mut field_bytes = Vec::new();
        write_field_header(&mut field_bytes, f.type_code, f.field_code);
        if is_vl_type(f.type_code) {
            encode_vl_length(&mut field_bytes, f.data.len());
        }
        field_bytes.extend_from_slice(&f.data);

        // Insert at the correct position
        let tail = out.split_off(insert_pos);
        out.extend_from_slice(&field_bytes);
        out.extend(tail);
    }

    // Also add PreviousTxnID/LgrSeq if they weren't in the original SLE
    if ptid_data.is_some() && !seen_fields.contains(&(5, 5)) {
        let mut fb = Vec::new();
        write_field_header(&mut fb, 5, 5);
        fb.extend_from_slice(&ptid_data.unwrap());
        // Insert at correct canonical position (5,5)
        let mut scan = 0;
        let mut insert_pos = out.len();
        while scan < out.len() {
            let (tc, fc, hend) = read_field_header(&out, scan);
            if hend > out.len() { break; }
            if (tc, fc) > (5, 5) { insert_pos = scan; break; }
            let next = skip_field_raw(&out, hend, tc);
            if next <= scan { break; } // forward-progress guard
            scan = next;
        }
        let tail = out.split_off(insert_pos);
        out.extend(fb);
        out.extend(tail);
    }

    if prev_txn_lgrseq.is_some() && !seen_fields.contains(&(2, 5)) {
        let mut fb = Vec::new();
        write_field_header(&mut fb, 2, 5);
        fb.extend_from_slice(&prev_txn_lgrseq.unwrap().to_be_bytes());
        let mut scan = 0;
        let mut insert_pos = out.len();
        while scan < out.len() {
            let (tc, fc, hend) = read_field_header(&out, scan);
            if hend > out.len() { break; }
            if (tc, fc) > (2, 5) { insert_pos = scan; break; }
            let next = skip_field_raw(&out, hend, tc);
            if next <= scan { break; } // forward-progress guard
            scan = next;
        }
        let tail = out.split_off(insert_pos);
        out.extend(fb);
        out.extend(tail);
    }

    out
}

/// Build the PRE-TRANSACTION SLE binary for a ModifiedNode.
///
/// Takes FinalFields (post-tx state) and PreviousFields (changed values before
/// the tx), overlays PreviousFields onto FinalFields to reconstruct the state
/// as it was BEFORE the transaction was applied.
///
/// XRPL/rippled metadata semantics:
///   FinalFields = metadata projection of the post-tx state, not necessarily
///                 a complete serialized SLE
///   PreviousFields = fields that changed, with their pre-tx values
///
/// This helper only works when `final_fields` contains every field needed to
/// reconstruct the object. Callers must not assume that is true for every
/// ModifiedNode in transaction metadata.
pub fn build_pre_tx_sle(
    entry_type: u16,
    final_fields: &[ParsedField],
    previous_fields: &[ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    // Start with FinalFields (post-tx state)
    let mut merged: Vec<ParsedField> = final_fields.iter().map(|f| ParsedField {
        type_code: f.type_code,
        field_code: f.field_code,
        data: f.data.clone(),
    }).collect();

    // Override with PreviousFields (pre-tx values for changed fields)
    for pf in previous_fields {
        if let Some(existing) = merged.iter_mut().find(|f| f.type_code == pf.type_code && f.field_code == pf.field_code) {
            existing.data = pf.data.clone();
        } else {
            // PreviousFields has a field not in FinalFields — this field was
            // removed by the transaction. Add it back for pre-tx state.
            merged.push(ParsedField {
                type_code: pf.type_code,
                field_code: pf.field_code,
                data: pf.data.clone(),
            });
        }
    }

    // Use build_sle to assemble the canonical binary
    build_sle(entry_type, &merged, prev_txn_id, prev_txn_lgrseq)
}

/// Build a complete SLE binary for a newly created object.
///
/// For CreatedNode: prepends LedgerEntryType, adds PreviousTxnID and
/// PreviousTxnLgrSeq, then serializes in canonical order.
pub fn build_sle(
    entry_type: u16,
    new_fields: &[ParsedField],
    prev_txn_id: Option<[u8; 32]>,
    prev_txn_lgrseq: Option<u32>,
) -> Vec<u8> {
    let mut fields: Vec<ParsedField> = new_fields.iter().map(|f| ParsedField {
        type_code: f.type_code,
        field_code: f.field_code,
        data: f.data.clone(),
    }).collect();

    // Add LedgerEntryType (type=1, field=1)
    if !fields.iter().any(|f| f.type_code == 1 && f.field_code == 1) {
        fields.push(ParsedField {
            type_code: 1, field_code: 1,
            data: entry_type.to_be_bytes().to_vec(),
        });
    }

    // Add common required fields with default values if not present.
    // rippled always serializes required fields even when zero.
    // Flags (2,2) is required on ALL SLE types.
    add_default_u32(&mut fields, 2, 2, 0); // Flags

    // Add entry-type-specific required fields that default to zero.
    // Only add fields that rippled marks as soeREQUIRED for the ledger type.
    // Optional/default fields must stay absent when metadata omits them,
    // otherwise we synthesize extra bytes and change the ledger hash.
    match entry_type {
        0x006f => {
            // Offer: BookNode, OwnerNode
            add_default_u64(&mut fields, 3, 3, 0); // sfBookNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
        }
        0x0064 => {
            // DirectoryNode: Indexes is required even when the vector is empty.
            add_default_vector256(&mut fields, 19, 1);
        }
        0x0043 => {
            // Check: OwnerNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
        }
        0x0075 => {
            // Escrow: OwnerNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
        }
        0x0078 => {
            // PayChannel: OwnerNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
        }
        0x0070 => {
            // DepositPreauth: OwnerNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
        }
        0x0054 => {
            // Ticket: OwnerNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
        }
        0x0037 => {
            // NFTokenOffer: OwnerNode, NFTokenOfferNode
            add_default_u64(&mut fields, 3, 4, 0); // sfOwnerNode
            add_default_u64(&mut fields, 3, 12, 0); // sfNFTokenOfferNode
        }
        _ => {}
    }

    // Add PreviousTxnID
    if let Some(id) = prev_txn_id {
        if !fields.iter().any(|f| f.type_code == 5 && f.field_code == 5) {
            fields.push(ParsedField { type_code: 5, field_code: 5, data: id.to_vec() });
        }
    }

    // Add PreviousTxnLgrSeq
    if let Some(seq) = prev_txn_lgrseq {
        if !fields.iter().any(|f| f.type_code == 2 && f.field_code == 5) {
            fields.push(ParsedField { type_code: 2, field_code: 5, data: seq.to_be_bytes().to_vec() });
        }
    }

    serialize_fields(&mut fields)
}

/// Add a default UInt32 field if not already present.
fn add_default_u32(fields: &mut Vec<ParsedField>, tc: u16, fc: u16, val: u32) {
    if !fields.iter().any(|f| f.type_code == tc && f.field_code == fc) {
        fields.push(ParsedField { type_code: tc, field_code: fc, data: val.to_be_bytes().to_vec() });
    }
}

/// Add a default UInt64 field if not already present.
fn add_default_u64(fields: &mut Vec<ParsedField>, tc: u16, fc: u16, val: u64) {
    if !fields.iter().any(|f| f.type_code == tc && f.field_code == fc) {
        fields.push(ParsedField { type_code: tc, field_code: fc, data: val.to_be_bytes().to_vec() });
    }
}

/// Add a default empty Vector256 field if not already present.
fn add_default_vector256(fields: &mut Vec<ParsedField>, tc: u16, fc: u16) {
    if !fields.iter().any(|f| f.type_code == tc && f.field_code == fc) {
        fields.push(ParsedField { type_code: tc, field_code: fc, data: Vec::new() });
    }
}

/// Serialize a set of parsed fields into canonical binary STObject format.
fn serialize_fields(fields: &mut Vec<ParsedField>) -> Vec<u8> {
    // Sort by canonical order: (type_code, field_code)
    fields.sort_by_key(|f| (f.type_code, f.field_code));

    let mut out = Vec::with_capacity(256);
    for field in fields.iter() {
        write_field_header(&mut out, field.type_code, field.field_code);
        if is_vl_type(field.type_code) {
            encode_vl_length(&mut out, field.data.len());
        }
        out.extend_from_slice(&field.data);
    }
    out
}

/// Parse binary metadata and extract AffectedNodes with complete SLE binaries.
///
/// For Created/Modified nodes, reconstructs the full SLE by:
/// 1. Taking FinalFields/NewFields bytes
/// 2. Prepending LedgerEntryType
/// 3. Injecting PreviousTxnID and PreviousTxnLgrSeq
/// 4. Sorting all fields in canonical order
pub fn parse_metadata(data: &[u8]) -> Vec<AffectedNode> {
    parse_metadata_with_index(data).1
}

#[derive(Debug, Clone, Default)]
pub struct MetadataSummary {
    pub result: Option<crate::ledger::ter::TxResult>,
    pub tx_index: Option<u32>,
    pub delivered_amount: Option<crate::transaction::amount::Amount>,
}

pub fn parse_metadata_summary(data: &[u8]) -> MetadataSummary {
    let mut summary = MetadataSummary::default();
    let mut pos = 0;

    while pos < data.len() {
        let (type_code, field_code, new_pos) = read_field_header(data, pos);
        if new_pos > data.len() {
            break;
        }
        pos = new_pos;

        match (type_code, field_code) {
            (16, 3) if pos < data.len() => {
                summary.result = Some(crate::ledger::ter::TxResult::from_code(data[pos] as i32));
                pos += 1;
            }
            (2, 28) if pos + 4 <= data.len() => {
                summary.tx_index = Some(u32::from_be_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]));
                pos += 4;
            }
            (6, 18) => {
                if let Ok((amount, consumed)) =
                    crate::transaction::amount::Amount::from_bytes(&data[pos..])
                {
                    summary.delivered_amount = Some(amount);
                    pos = pos.saturating_add(consumed).min(data.len());
                } else {
                    pos = skip_field(data, pos, type_code);
                }
            }
            _ => {
                pos = skip_field(data, pos, type_code);
            }
        }
    }

    summary
}

/// Parse binary metadata, returning (sfTransactionIndex, AffectedNodes).
///
/// sfTransactionIndex is a UInt32 (type=2, field=28) that gives the
/// execution order of this transaction within the ledger.  This is
/// critical for correct delta application when multiple transactions
/// modify the same object.
pub fn parse_metadata_with_index(data: &[u8]) -> (Option<u32>, Vec<AffectedNode>) {
    let mut results = Vec::new();
    let mut tx_index: Option<u32> = None;
    let mut pos = 0;

    // Walk the top-level metadata STObject
    while pos < data.len() {
        let (type_code, field_code, new_pos) = read_field_header(data, pos);
        if new_pos > data.len() { break; }
        pos = new_pos;

        if type_code == 2 && field_code == 28 {
            // sfTransactionIndex (UInt32, type=2, field=28)
            if pos + 4 <= data.len() {
                tx_index = Some(u32::from_be_bytes([
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                ]));
            }
            pos += 4;
        } else if type_code == 15 {
            // STArray — could be AffectedNodes (field=8) or Memos etc.
            let nodes = parse_affected_array(data, &mut pos);
            results.extend(nodes);
        } else {
            // Skip this field
            pos = skip_field(data, pos, type_code);
        }
    }

    (tx_index, results)
}

/// Parse an STArray containing AffectedNode entries.
fn parse_affected_array(data: &[u8], pos: &mut usize) -> Vec<AffectedNode> {
    let mut results = Vec::new();

    loop {
        if *pos >= data.len() { break; }

        // Check for array end marker (0xF1)
        if data[*pos] == 0xF1 {
            *pos += 1;
            break;
        }

        // Read the STObject wrapper (CreatedNode=0xE3, DeletedNode=0xE4, ModifiedNode=0xE5)
        let (type_code, field_code, new_pos) = read_field_header(data, *pos);
        *pos = new_pos;

        if type_code != 14 {
            // Not an STObject — skip
            *pos = skip_field(data, *pos, type_code);
            continue;
        }

        let action = match field_code {
            3 => Action::Created,
            4 => Action::Deleted,
            5 => Action::Modified,
            _ => {
                // Unknown STObject in array — skip to end marker
                skip_to_object_end(data, pos);
                continue;
            }
        };

        // Parse the inner STObject (CreatedNode/ModifiedNode/DeletedNode)
        let node = parse_affected_node(data, pos, action);
        if let Some(n) = node {
            results.push(n);
        }
    }

    results
}

/// Parse a single AffectedNode STObject.
///
/// Extracts LedgerEntryType, LedgerIndex, and the fields (FinalFields or NewFields).
/// Reconstructs the complete SLE binary.
fn parse_affected_node(data: &[u8], pos: &mut usize, action: Action) -> Option<AffectedNode> {
    let mut entry_type: u16 = 0;
    let mut ledger_index = [0u8; 32];
    let mut fields_bytes: Option<Vec<u8>> = None; // FinalFields or NewFields raw content
    let mut previous_fields_bytes: Option<Vec<u8>> = None; // PreviousFields raw content
    let mut prev_txn_id: Option<[u8; 32]> = None;
    let mut prev_txn_lgrseq: Option<u32> = None;

    // Walk fields until object end marker (0xE1)
    loop {
        if *pos >= data.len() { break; }
        if data[*pos] == 0xE1 {
            *pos += 1;
            break;
        }

        let (tc, fc, new_pos) = read_field_header(data, *pos);
        *pos = new_pos;

        match (tc, fc) {
            (1, 1) => {
                // LedgerEntryType (UInt16)
                if *pos + 2 > data.len() { break; }
                entry_type = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
                *pos += 2;
            }
            (5, 5) => {
                // PreviousTxnID (Hash256, type=5, field=5)
                if *pos + 32 > data.len() { break; }
                let mut h = [0u8; 32];
                h.copy_from_slice(&data[*pos..*pos + 32]);
                prev_txn_id = Some(h);
                *pos += 32;
            }
            (5, 6) => {
                // LedgerIndex (Hash256, type=5, field=6) — the SHAMap key
                if *pos + 32 > data.len() { break; }
                ledger_index.copy_from_slice(&data[*pos..*pos + 32]);
                *pos += 32;
            }
            (2, 5) if fc == 5 => {
                // PreviousTxnLgrSeq (UInt32, type=2, field=5) — but wait,
                // field=5 for type=2 could be OwnerCount too? No, OwnerCount is field=13.
                // Let me check: sfPreviousTxnLgrSeq is UINT32 field 5. Actually wait...
                // sfSourceTag is UINT32 field 3
                // sfSequence is UINT32 field 4
                // sfPreviousTxnLgrSeq is UINT32 field 5 (0x25)
                // sfOwnerCount is UINT32 field 13 (0x2D)
                // So yes, (2, 5) = PreviousTxnLgrSeq at the outer node level
                if *pos + 4 > data.len() { break; }
                prev_txn_lgrseq = Some(u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap()));
                *pos += 4;
            }
            (14, 6) | (14, 7) | (14, 8) => {
                // PreviousFields(6), FinalFields(7), NewFields(8) — nested STObject
                // Extract the raw bytes between here and the matching 0xE1
                let start = *pos;
                skip_to_object_end(data, pos);
                let end = *pos - 1; // exclude the 0xE1 marker

                if end > start {
                    match fc {
                        6 => {
                            // PreviousFields — the "before" values for Modified nodes.
                            // (rippled: sfPreviousFields = OBJECT field 6)
                            previous_fields_bytes = Some(data[start..end].to_vec());
                        }
                        7 => {
                            // FinalFields — post-tx state for Modified, pre-deletion for Deleted.
                            if action == Action::Modified || action == Action::Deleted {
                                fields_bytes = Some(data[start..end].to_vec());
                            }
                        }
                        8 => {
                            // NewFields — initial state for Created nodes.
                            if action == Action::Created {
                                fields_bytes = Some(data[start..end].to_vec());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                // Skip unknown field
                *pos = skip_field(data, *pos, tc);
            }
        }
    }

    // Parse the fields bytes (FinalFields or NewFields)
    let parsed_fields = match fields_bytes {
        Some(fb) => parse_stobject_fields(&fb),
        None => vec![],
    };

    // Parse PreviousFields (only present for Modified nodes)
    let parsed_previous = match previous_fields_bytes {
        Some(pb) => parse_stobject_fields(&pb),
        None => vec![],
    };

    Some(AffectedNode {
        action,
        entry_type,
        ledger_index,
        fields: parsed_fields,
        previous_fields: parsed_previous,
        prev_txn_id,
        prev_txn_lgrseq,
    })
}

// ── Field parsing helpers ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedField {
    pub type_code: u16,
    pub field_code: u16,
    pub data: Vec<u8>,  // raw field data (without header, without VL prefix)
}

pub struct ParsedSLE {
    pub entry_type: u16,
    pub fields: Vec<ParsedField>,
    pub prev_txn_id: Option<[u8; 32]>,
    pub prev_txn_lgrseq: Option<u32>,
}

/// Parse a flat STObject (no nested objects) into individual fields.
fn parse_stobject_fields(data: &[u8]) -> Vec<ParsedField> {
    let mut fields = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tc, fc, new_pos) = read_field_header(data, pos);
        if tc == 0 && fc == 0 { break; }
        if tc == 14 && fc == 1 { break; } // end-of-object marker
        if tc == 15 && fc == 1 { break; } // end-of-array marker
        pos = new_pos;

        if tc == 14 || tc == 15 {
            // Nested STObject or STArray — skip to end marker and include as opaque blob
            let start = pos;
            if tc == 14 {
                skip_to_object_end(data, &mut pos);
            } else {
                skip_to_array_end(data, &mut pos);
            }
            // Include the full nested data with end marker
            let end = pos.min(data.len());
            let blob = data[start..end].to_vec();
            fields.push(ParsedField { type_code: tc, field_code: fc, data: blob });
            continue;
        }

        let (field_data, consumed) = read_field_data(data, pos, tc);
        pos += consumed;
        fields.push(ParsedField { type_code: tc, field_code: fc, data: field_data });
    }

    fields
}

pub fn parse_sle(data: &[u8]) -> Option<ParsedSLE> {
    let mut entry_type = None;
    let mut prev_txn_id = None;
    let mut prev_txn_lgrseq = None;
    let mut fields = Vec::new();

    for field in parse_stobject_fields(data) {
        match (field.type_code, field.field_code) {
            (1, 1) if field.data.len() >= 2 => {
                entry_type = Some(u16::from_be_bytes([field.data[0], field.data[1]]));
            }
            (5, 5) if field.data.len() >= 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&field.data[..32]);
                prev_txn_id = Some(h);
            }
            (2, 5) if field.data.len() >= 4 => {
                prev_txn_lgrseq = Some(u32::from_be_bytes([
                    field.data[0], field.data[1], field.data[2], field.data[3],
                ]));
            }
            _ => fields.push(field),
        }
    }

    Some(ParsedSLE {
        entry_type: entry_type?,
        fields,
        prev_txn_id,
        prev_txn_lgrseq,
    })
}

pub fn diff_previous_fields(pre: &[ParsedField], post: &[ParsedField]) -> Vec<ParsedField> {
    use std::collections::HashMap;

    let post_map: HashMap<(u16, u16), &ParsedField> = post.iter()
        .map(|field| ((field.type_code, field.field_code), field))
        .collect();

    pre.iter()
        .filter(|field| {
            post_map.get(&(field.type_code, field.field_code))
                .map(|post_field| post_field.data != field.data)
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

pub fn serialize_parsed_fields(fields: &[ParsedField]) -> Vec<u8> {
    let mut fields = fields.to_vec();
    serialize_fields(&mut fields)
}

fn write_stobject_field(buf: &mut Vec<u8>, field_code: u16, fields: &[ParsedField]) {
    write_field_header(buf, 14, field_code);
    buf.extend_from_slice(&serialize_parsed_fields(fields));
    buf.push(0xE1);
}

pub fn encode_metadata(result_code: i32, tx_index: u32, nodes: &[AffectedNode]) -> Vec<u8> {
    // rippled sorts AffectedNodes by LedgerIndex before serializing (TxMeta.cpp:207-209)
    let mut sorted_nodes: Vec<&AffectedNode> = nodes.iter().collect();
    sorted_nodes.sort_by_key(|n| n.ledger_index);

    let mut out = Vec::new();

    write_field_header(&mut out, 16, 3);
    out.push(result_code as u8);

    write_field_header(&mut out, 2, 28);
    out.extend_from_slice(&tx_index.to_be_bytes());

    write_field_header(&mut out, 15, 8);
    for node in &sorted_nodes {
        let wrapper_field = match node.action {
            Action::Created => 3,
            Action::Deleted => 4,
            Action::Modified => 5,
        };
        write_field_header(&mut out, 14, wrapper_field);

        write_field_header(&mut out, 1, 1);
        out.extend_from_slice(&node.entry_type.to_be_bytes());

        if let Some(seq) = node.prev_txn_lgrseq {
            write_field_header(&mut out, 2, 5);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        if let Some(prev_txn_id) = node.prev_txn_id {
            write_field_header(&mut out, 5, 5);
            out.extend_from_slice(&prev_txn_id);
        }

        write_field_header(&mut out, 5, 6);
        out.extend_from_slice(&node.ledger_index);

        // Apply shouldMeta field filtering matching rippled's metadata generation
        match node.action {
            Action::Created => {
                let filtered = crate::ledger::sfield_meta::filter_for_created(&node.fields);
                write_stobject_field(&mut out, 8, &filtered);
            }
            Action::Deleted => {
                let filtered = crate::ledger::sfield_meta::filter_for_deleted_final(&node.fields);
                write_stobject_field(&mut out, 7, &filtered);
            }
            Action::Modified => {
                let prev_filtered = crate::ledger::sfield_meta::filter_for_modified_previous(&node.previous_fields);
                let final_filtered = crate::ledger::sfield_meta::filter_for_modified_final(&node.fields);
                write_stobject_field(&mut out, 6, &prev_filtered);
                write_stobject_field(&mut out, 7, &final_filtered);
            }
        }

        out.push(0xE1);
    }
    out.push(0xF1);

    out
}

/// Read a field header (1-3 bytes) and return (type_code, field_code, new_pos).
pub(crate) fn read_field_header(data: &[u8], pos: usize) -> (u16, u16, usize) {
    if pos >= data.len() { return (0, 0, pos); }
    let b = data[pos];
    let top = (b >> 4) as u16;
    let bot = (b & 0x0F) as u16;

    if top == 0 && bot == 0 {
        if pos + 3 > data.len() { return (0, 0, data.len()); }
        (data[pos + 1] as u16, data[pos + 2] as u16, pos + 3)
    } else if top == 0 {
        if pos + 2 > data.len() { return (0, 0, data.len()); }
        (data[pos + 1] as u16, bot, pos + 2)
    } else if bot == 0 {
        if pos + 2 > data.len() { return (0, 0, data.len()); }
        (top, data[pos + 1] as u16, pos + 2)
    } else {
        (top, bot, pos + 1)
    }
}

/// Write a field header (1-3 bytes).
/// Public version of write_field_header for use by other modules.
pub fn write_field_header_pub(buf: &mut Vec<u8>, tc: u16, fc: u16) {
    write_field_header(buf, tc, fc);
}

pub(crate) fn write_field_header(buf: &mut Vec<u8>, tc: u16, fc: u16) {
    if tc < 16 && fc < 16 {
        buf.push(((tc << 4) | fc) as u8);
    } else if tc < 16 && fc >= 16 {
        buf.push((tc << 4) as u8);
        buf.push(fc as u8);
    } else if tc >= 16 && fc < 16 {
        buf.push(fc as u8);
        buf.push(tc as u8);
    } else {
        buf.push(0x00);
        buf.push(tc as u8);
        buf.push(fc as u8);
    }
}

/// Is this type VL-encoded (variable length prefix)?
pub(crate) fn is_vl_type(tc: u16) -> bool {
    tc == 7 || tc == 8 || tc == 19
}

/// Encode VL length prefix.
pub(crate) fn encode_vl_length(buf: &mut Vec<u8>, len: usize) {
    if len <= 192 {
        buf.push(len as u8);
    } else if len <= 12480 {
        let len = len - 193;
        buf.push((len / 256 + 193) as u8);
        buf.push((len % 256) as u8);
    } else {
        let len = len - 12481;
        buf.push((len / 65536 + 241) as u8);
        buf.push(((len / 256) % 256) as u8);
        buf.push((len % 256) as u8);
    }
}

/// Read field data based on type code. Returns (data, bytes_consumed).
fn read_field_data(data: &[u8], pos: usize, tc: u16) -> (Vec<u8>, usize) {
    match tc {
        1 => read_fixed(data, pos, 2),   // UInt16
        2 => read_fixed(data, pos, 4),   // UInt32
        3 => read_fixed(data, pos, 8),   // UInt64
        4 => read_fixed(data, pos, 16),  // Hash128
        5 => read_fixed(data, pos, 32),  // Hash256
        6 => {
            // Amount: 8 bytes XRP, 48 IOU, 33 MPT
            if pos >= data.len() { return (vec![], 8); }
            if (data[pos] & 0x80) != 0 {
                // IOU (bit 63 set)
                read_fixed(data, pos, 48)
            } else if (data[pos] & 0x20) != 0 {
                // MPT (bit 61 set)
                read_fixed(data, pos, 33)
            } else {
                read_fixed(data, pos, 8)
            }
        }
        7 | 8 | 19 => {
            // VL types (Blob, AccountID, Vector256)
            if pos >= data.len() { return (vec![], 0); }
            let (vl_len, vl_bytes) = decode_vl_length(data, pos);
            let start = pos + vl_bytes;
            let end = (start + vl_len).min(data.len());
            if start > data.len() { return (vec![], vl_bytes); }
            (data[start..end].to_vec(), vl_bytes + vl_len)
        }
        9 => read_fixed(data, pos, 8),   // NUMBER (64-bit on wire, same as UInt64)
        16 => read_fixed(data, pos, 1),  // UInt8
        17 => read_fixed(data, pos, 20), // Hash160
        18 => read_fixed(data, pos, 32), // Hash384 / UInt384 — rare but 32 bytes on wire
        20 => read_fixed(data, pos, 32), // UINT256 (for ISSUE type — 32 bytes)
        21 => read_fixed(data, pos, 24), // UINT192
        24 => {
            // ISSUE — variable length: 20 bytes (XRP), 40 bytes (IOU), 44 bytes (MPT).
            // First 20 bytes: currency-or-issuer. If all zeros → XRP (20 bytes).
            // Else: next 20 bytes: account. If all zeros → MPT (+4 seq = 44 total).
            // Else: IOU (40 bytes).
            if pos + 20 > data.len() { return (vec![], 20); }
            let first_20 = &data[pos..pos+20];
            if first_20 == &[0u8; 20] {
                read_fixed(data, pos, 20)  // XRP
            } else if pos + 40 <= data.len() && data[pos+20..pos+40] == [0u8; 20] {
                read_fixed(data, pos, 44)  // MPT (20 + 20 + 4)
            } else {
                read_fixed(data, pos, 40)  // IOU (20 + 20)
            }
        }
        _ => (vec![], 0),
    }
}

fn read_fixed(data: &[u8], pos: usize, size: usize) -> (Vec<u8>, usize) {
    let end = (pos + size).min(data.len());
    if pos >= data.len() { return (vec![], size); }
    (data[pos..end].to_vec(), size)
}

/// Decode VL length. Returns (length, bytes_consumed).
pub(crate) fn decode_vl_length(data: &[u8], pos: usize) -> (usize, usize) {
    if pos >= data.len() { return (0, 0); }
    let b1 = data[pos] as usize;
    if b1 <= 192 {
        (b1, 1)
    } else if b1 <= 240 {
        if pos + 1 >= data.len() { return (0, 1); }
        let b2 = data[pos + 1] as usize;
        (193 + ((b1 - 193) * 256) + b2, 2)
    } else if b1 <= 254 {
        if pos + 2 >= data.len() { return (0, 1); }
        let b2 = data[pos + 1] as usize;
        let b3 = data[pos + 2] as usize;
        (12481 + ((b1 - 241) * 65536) + (b2 * 256) + b3, 3)
    } else {
        (0, 1)
    }
}

/// Skip past an STObject to its end marker (0xE1).
fn skip_to_object_end(data: &[u8], pos: &mut usize) {
    let mut depth = 1;
    while *pos < data.len() && depth > 0 {
        // Always read the field header first — never check raw bytes.
        // 0xE1 can appear inside field data (Hash256, Vector256, etc.)
        let (tc, fc, new_pos) = read_field_header(data, *pos);
        *pos = new_pos;

        if tc == 14 && fc == 1 {
            // End-of-object marker
            depth -= 1;
        } else if tc == 15 && fc == 1 {
            // End-of-array marker (shouldn't happen inside object, but handle)
            depth -= 1;
        } else if tc == 14 {
            // Nested STObject — increment depth, its fields follow
            depth += 1;
        } else if tc == 15 {
            // Nested STArray — skip to its end
            skip_to_array_end(data, pos);
        } else {
            *pos = skip_field_raw(data, *pos, tc);
        }
    }
}

/// Skip past an STArray to its end marker (0xF1).
fn skip_to_array_end(data: &[u8], pos: &mut usize) {
    while *pos < data.len() {
        let (tc, fc, new_pos) = read_field_header(data, *pos);
        *pos = new_pos;

        if tc == 15 && fc == 1 {
            // End-of-array marker
            return;
        } else if tc == 14 && fc == 1 {
            // End-of-object marker (shouldn't happen at array level, but handle)
            return;
        } else if tc == 14 {
            // STObject element in array — skip to its end
            skip_to_object_end(data, pos);
        } else if tc == 15 {
            // Nested array
            skip_to_array_end(data, pos);
        } else {
            *pos = skip_field_raw(data, *pos, tc);
        }
    }
}

/// Skip a field's data without the header.
fn skip_field(data: &[u8], pos: usize, tc: u16) -> usize {
    skip_field_raw(data, pos, tc)
}

pub(crate) fn skip_field_raw(data: &[u8], pos: usize, tc: u16) -> usize {
    if pos >= data.len() { return data.len(); }
    match tc {
        1 => (pos + 2).min(data.len()),
        2 => (pos + 4).min(data.len()),
        3 => (pos + 8).min(data.len()),
        4 => (pos + 16).min(data.len()),
        5 => (pos + 32).min(data.len()),
        6 => {
            // Amount: IOU(48), XRP(8), MPT(33)
            if pos >= data.len() { return data.len(); }
            if (data[pos] & 0x80) != 0 {
                (pos + 48).min(data.len()) // IOU
            } else if (data[pos] & 0x20) != 0 {
                (pos + 33).min(data.len()) // MPT (bit 61 set)
            } else {
                (pos + 8).min(data.len()) // XRP
            }
        }
        7 | 8 | 19 => {
            // VL-encoded: Blob, AccountID, Vector256
            let (vl_len, vl_bytes) = decode_vl_length(data, pos);
            (pos + vl_bytes + vl_len).min(data.len())
        }
        9 => (pos + 8).min(data.len()),   // NUMBER (same as u64 on wire)
        10 => (pos + 4).min(data.len()),   // INT32
        11 => (pos + 8).min(data.len()),   // INT64
        14 => {
            let mut p = pos;
            skip_to_object_end(data, &mut p);
            p
        }
        15 => {
            let mut p = pos;
            skip_to_array_end(data, &mut p);
            p
        }
        16 => (pos + 1).min(data.len()),   // UINT8
        17 => (pos + 20).min(data.len()),  // HASH160
        18 => {
            // PathSet: terminated by 0x00
            let mut p = pos;
            while p < data.len() && data[p] != 0x00 {
                if data[p] == 0xFF {
                    // path boundary
                    p += 1;
                } else {
                    // path element: type(1) + optional account(20) + optional currency(20) + optional issuer(20)
                    let ptype = data[p];
                    p += 1;
                    if ptype & 0x01 != 0 { p += 20; } // account
                    if ptype & 0x10 != 0 { p += 20; } // currency
                    if ptype & 0x20 != 0 { p += 20; } // issuer
                }
            }
            if p < data.len() { p += 1; } // skip 0x00 terminator
            p.min(data.len())
        }
        20 => (pos + 12).min(data.len()),  // UINT96
        21 => (pos + 24).min(data.len()),  // UINT192
        22 => (pos + 48).min(data.len()),  // UINT384
        23 => (pos + 64).min(data.len()),  // UINT512
        24 => {
            // ISSUE: 20 bytes (XRP) or 20+20=40 bytes (IOU currency+issuer)
            // First byte determines: if currency starts with 0x00, it's 20 bytes total
            if pos + 20 > data.len() { return data.len(); }
            let all_zero = data[pos..pos+20].iter().all(|&b| b == 0);
            if all_zero { (pos + 20).min(data.len()) } else { (pos + 40).min(data.len()) }
        }
        25 => {
            // XCHAIN_BRIDGE: STObject-like, skip to end marker
            let mut p = pos;
            skip_to_object_end(data, &mut p);
            p
        }
        26 => (pos + 20).min(data.len()),  // CURRENCY
        _ => data.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_field_header_single_byte() {
        // type=1, field=1 → 0x11
        let (tc, fc, pos) = read_field_header(&[0x11], 0);
        assert_eq!((tc, fc, pos), (1, 1, 1));
    }

    #[test]
    fn test_read_field_header_extended_field() {
        // type=2, field=13 → 0x2D
        let (tc, fc, pos) = read_field_header(&[0x2D], 0);
        assert_eq!((tc, fc, pos), (2, 13, 1));
    }

    #[test]
    fn test_write_field_header_roundtrip() {
        let mut buf = Vec::new();
        write_field_header(&mut buf, 5, 5);
        let (tc, fc, _) = read_field_header(&buf, 0);
        assert_eq!((tc, fc), (5, 5));
    }

    #[test]
    fn test_vl_length_roundtrip() {
        for len in [0, 1, 100, 192, 193, 1000, 12480, 12481, 50000] {
            let mut buf = Vec::new();
            encode_vl_length(&mut buf, len);
            let (decoded, _) = decode_vl_length(&buf, 0);
            assert_eq!(decoded, len, "VL roundtrip failed for {}", len);
        }
    }

    #[test]
    fn test_patch_sle_malformed_input_no_hang() {
        use std::time::Instant;

        // Truncated VL header: type=7, field=3 (sfSigningPubKey) with no data after
        let truncated_vl = vec![0x73];
        let start = Instant::now();
        let result = patch_sle(&truncated_vl, &[], None, None, &[]);
        assert!(start.elapsed().as_millis() < 100, "patch_sle hung on truncated VL");
        // Should return something (possibly the truncated input unchanged)
        assert!(!result.is_empty() || truncated_vl.is_empty());

        // Unknown type code byte (0xFF = type=15, field=15 — STArray end marker)
        let unknown = vec![0xFF];
        let start = Instant::now();
        let result = patch_sle(&unknown, &[], None, None, &[]);
        assert!(start.elapsed().as_millis() < 100, "patch_sle hung on unknown type");
        let _ = result; // don't care about content, just that it returned

        // All zeros — degenerate input
        let zeros = vec![0x00; 64];
        let start = Instant::now();
        let result = patch_sle(&zeros, &[], None, None, &[]);
        assert!(start.elapsed().as_millis() < 100, "patch_sle hung on zero bytes");
        let _ = result;

        // Valid AccountRoot-like SLE followed by garbage
        let mut valid_then_garbage = Vec::new();
        valid_then_garbage.push(0x11); // type=1, field=1 (LedgerEntryType)
        valid_then_garbage.extend_from_slice(&0x0061u16.to_be_bytes());
        valid_then_garbage.push(0x22); // type=2, field=2 (Flags)
        valid_then_garbage.extend_from_slice(&0u32.to_be_bytes());
        valid_then_garbage.extend_from_slice(&[0xDE, 0xAD]); // garbage trailing bytes
        let start = Instant::now();
        let result = patch_sle(&valid_then_garbage, &[], None, None, &[]);
        assert!(start.elapsed().as_millis() < 100, "patch_sle hung on trailing garbage");
        let _ = result;
    }
}
