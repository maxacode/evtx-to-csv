// =============================================================================
// csv_exporter.rs — CSV Export Logic
//
// This module converts a slice of EventRecord structs into a CSV file on disk.
//
// COLUMN LAYOUT:
//   Fixed columns (always present, in a defined order):
//     timestamp, event_id, level, channel, computer, username, domain,
//     target_username, target_domain, process_id, process_name, ip_address,
//     port, logon_type, command_line, parent_process, workstation, auth_package
//
//   Dynamic columns (appended after fixed columns):
//     All unique keys found in `extra_fields` across ALL records, sorted
//     alphabetically. This means every CSV file produced from the same set of
//     event types will have a consistent column order even if not every record
//     has a value for every extra field.
//
// BEHAVIOUR:
//   - None values are written as empty strings (not "null" or "None").
//   - The csv crate handles quoting/escaping of commas, quotes, and newlines
//     inside field values automatically.
//   - The output path is created if the parent directory already exists; if the
//     parent directory does not exist the OS will return an error that we
//     surface as a descriptive Err(String).
//   - Writing is done record-by-record (streaming) so large exports don't
//     require holding two copies of all data in memory simultaneously.
// =============================================================================

use std::collections::BTreeSet;

use crate::types::EventRecord;

/// Write `records` to a CSV file at `output_path`.
///
/// Returns `Ok(())` on success or `Err(String)` with a human-readable message
/// if the file cannot be created or written to.
pub fn export_to_csv(records: &[EventRecord], output_path: &str) -> Result<(), String> {
    // Create (or overwrite) the output file. csv::Writer handles buffered I/O
    // internally so we don't need to wrap it in a BufWriter.
    let mut writer = csv::Writer::from_path(output_path)
        .map_err(|e| format!("Failed to create CSV file at '{}': {}", output_path, e))?;

    // -----------------------------------------------------------------------
    // Collect all unique extra_field keys across every record.
    //
    // We use a BTreeSet (sorted set) so that:
    //   a) The dynamic column order is deterministic across runs.
    //   b) The sort is alphabetical, which is the most user-friendly ordering
    //      when analysts open the CSV in Excel or a similar tool.
    //
    // This requires a single pass over all records before we start writing.
    // For typical IR file sizes (thousands to tens of thousands of records)
    // this is negligible overhead compared to I/O.
    // -----------------------------------------------------------------------
    let mut extra_keys: BTreeSet<String> = BTreeSet::new();
    for record in records {
        for key in record.extra_fields.keys() {
            extra_keys.insert(key.clone());
        }
    }

    // Convert to a Vec so we can index into it when writing rows.
    let extra_keys_vec: Vec<String> = extra_keys.into_iter().collect();

    // -----------------------------------------------------------------------
    // Write the header row
    //
    // Fixed column names first (matching the documented API contract order),
    // then the dynamically discovered extra field columns.
    // -----------------------------------------------------------------------

    // Build the header as a Vec<&str> — csv::Writer::write_record accepts any
    // iterable of AsRef<[u8]>, so &str works fine here.
    let fixed_header: Vec<&str> = vec![
        "timestamp", "event_id", "level", "channel", "computer", "username", "domain",
        "target_username", "target_domain", "process_id", "process_name", "ip_address",
        "port", "logon_type", "command_line", "parent_process", "workstation", "auth_package",
    ];

    // Determine which columns have at least one value across all records
    let mut active_fixed: Vec<bool> = vec![false; fixed_header.len()];
    let mut active_extra: Vec<bool> = vec![false; extra_keys_vec.len()];

    for record in records {
        // Check fixed fields
        let opt_check = |opt: &Option<String>| -> bool { opt.as_ref().map(|s| !s.is_empty()).unwrap_or(false) };
        if !record.timestamp.is_empty() { active_fixed[0] = true; }
        active_fixed[1] = true; // event_id
        if !record.level.is_empty() { active_fixed[2] = true; }
        if !record.channel.is_empty() { active_fixed[3] = true; }
        if !record.computer.is_empty() { active_fixed[4] = true; }
        if opt_check(&record.username) { active_fixed[5] = true; }
        if opt_check(&record.domain) { active_fixed[6] = true; }
        if opt_check(&record.target_username) { active_fixed[7] = true; }
        if opt_check(&record.target_domain) { active_fixed[8] = true; }
        if opt_check(&record.process_id) { active_fixed[9] = true; }
        if opt_check(&record.process_name) { active_fixed[10] = true; }
        if opt_check(&record.ip_address) { active_fixed[11] = true; }
        if opt_check(&record.port) { active_fixed[12] = true; }
        if opt_check(&record.logon_type) { active_fixed[13] = true; }
        if opt_check(&record.command_line) { active_fixed[14] = true; }
        if opt_check(&record.parent_process) { active_fixed[15] = true; }
        if opt_check(&record.workstation) { active_fixed[16] = true; }
        if opt_check(&record.auth_package) { active_fixed[17] = true; }

        // Check extra fields
        for (i, key) in extra_keys_vec.iter().enumerate() {
            if let Some(val) = record.extra_fields.get(key) {
                if !val.is_empty() && val != "-" && val != "0x0" {
                    active_extra[i] = true;
                }
            }
        }
    }

    // Build the final header by filtering out inactive columns
    let mut final_header: Vec<String> = Vec::new();
    for (i, &active) in active_fixed.iter().enumerate() {
        if active { final_header.push(fixed_header[i].to_string()); }
    }
    for (i, &active) in active_extra.iter().enumerate() {
        if active { final_header.push(extra_keys_vec[i].clone()); }
    }

    writer
        .write_record(&final_header)
        .map_err(|e| format!("Failed to write CSV header: {}", e))?;

    // -----------------------------------------------------------------------
    // Write data rows
    // -----------------------------------------------------------------------
    for record in records {
        let opt_str = |opt: &Option<String>| -> String { opt.as_deref().unwrap_or("").to_string() };
        let mut row: Vec<String> = Vec::new();

        // Fixed fields (only if active)
        if active_fixed[0] { row.push(record.timestamp.clone()); }
        if active_fixed[1] { row.push(record.event_id.to_string()); }
        if active_fixed[2] { row.push(record.level.clone()); }
        if active_fixed[3] { row.push(record.channel.clone()); }
        if active_fixed[4] { row.push(record.computer.clone()); }
        if active_fixed[5] { row.push(opt_str(&record.username)); }
        if active_fixed[6] { row.push(opt_str(&record.domain)); }
        if active_fixed[7] { row.push(opt_str(&record.target_username)); }
        if active_fixed[8] { row.push(opt_str(&record.target_domain)); }
        if active_fixed[9] { row.push(opt_str(&record.process_id)); }
        if active_fixed[10] { row.push(opt_str(&record.process_name)); }
        if active_fixed[11] { row.push(opt_str(&record.ip_address)); }
        if active_fixed[12] { row.push(opt_str(&record.port)); }
        if active_fixed[13] { row.push(opt_str(&record.logon_type)); }
        if active_fixed[14] { row.push(opt_str(&record.command_line)); }
        if active_fixed[15] { row.push(opt_str(&record.parent_process)); }
        if active_fixed[16] { row.push(opt_str(&record.workstation)); }
        if active_fixed[17] { row.push(opt_str(&record.auth_package)); }

        // Extra fields (only if active)
        for (i, key) in extra_keys_vec.iter().enumerate() {
            if active_extra[i] {
                row.push(record.extra_fields.get(key).cloned().unwrap_or_default());
            }
        }

        writer
            .write_record(&row)
            .map_err(|e| format!("Failed to write CSV row: {}", e))?;
    }

    // Flush the internal write buffer to disk. Without this, the last few rows
    // may be lost if the program exits before the buffer is auto-flushed.
    writer
        .flush()
        .map_err(|e| format!("Failed to flush CSV writer: {}", e))?;

    Ok(())
}
