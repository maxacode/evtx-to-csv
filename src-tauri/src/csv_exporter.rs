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
    let mut header: Vec<String> = vec![
        "timestamp".to_string(),
        "event_id".to_string(),
        "level".to_string(),
        "channel".to_string(),
        "computer".to_string(),
        "username".to_string(),
        "domain".to_string(),
        "target_username".to_string(),
        "target_domain".to_string(),
        "process_id".to_string(),
        "process_name".to_string(),
        "ip_address".to_string(),
        "port".to_string(),
        "logon_type".to_string(),
        "command_line".to_string(),
        "parent_process".to_string(),
        "workstation".to_string(),
        "auth_package".to_string(),
    ];

    // Append extra field column names after the fixed columns
    for key in &extra_keys_vec {
        header.push(key.clone());
    }

    writer
        .write_record(&header)
        .map_err(|e| format!("Failed to write CSV header: {}", e))?;

    // -----------------------------------------------------------------------
    // Write one data row per EventRecord
    //
    // The fixed columns are written in the same order as the header.
    // Option<String> fields are unwrapped to "" when None so the CSV cell
    // is empty rather than containing the Rust text "None".
    // -----------------------------------------------------------------------
    for record in records {
        // Helper closure: unwrap an Option<&String> to &str, defaulting to "".
        // Using a closure avoids repeating the pattern for every optional field.
        let opt_str = |opt: &Option<String>| -> String {
            opt.as_deref().unwrap_or("").to_string()
        };

        // Build the row with the 18 fixed columns in API-contract order.
        let mut row: Vec<String> = vec![
            record.timestamp.clone(),          // timestamp
            record.event_id.to_string(),       // event_id (u32 → String)
            record.level.clone(),              // level
            record.channel.clone(),            // channel
            record.computer.clone(),           // computer
            opt_str(&record.username),         // username (SubjectUserName)
            opt_str(&record.domain),           // domain (SubjectDomainName)
            opt_str(&record.target_username),  // target_username (TargetUserName)
            opt_str(&record.target_domain),    // target_domain (TargetDomainName)
            opt_str(&record.process_id),       // process_id
            opt_str(&record.process_name),     // process_name
            opt_str(&record.ip_address),       // ip_address
            opt_str(&record.port),             // port
            opt_str(&record.logon_type),       // logon_type
            opt_str(&record.command_line),     // command_line
            opt_str(&record.parent_process),   // parent_process
            opt_str(&record.workstation),      // workstation
            opt_str(&record.auth_package),     // auth_package
        ];

        // Append the extra field values in the same order as the header columns.
        // For each extra_key, look it up in this record's extra_fields map.
        // If the key doesn't exist in this record, write an empty string.
        for key in &extra_keys_vec {
            let value = record
                .extra_fields
                .get(key.as_str())
                .cloned()
                .unwrap_or_default(); // "" for missing keys
            row.push(value);
        }

        // Write the assembled row. The csv crate quotes any field that contains
        // commas, double-quotes, or newlines, so we don't need to escape manually.
        writer
            .write_record(&row)
            .map_err(|e| format!("Failed to write CSV row for event {}: {}", record.event_id, e))?;
    }

    // Flush the internal write buffer to disk. Without this, the last few rows
    // may be lost if the program exits before the buffer is auto-flushed.
    writer
        .flush()
        .map_err(|e| format!("Failed to flush CSV writer: {}", e))?;

    Ok(())
}
