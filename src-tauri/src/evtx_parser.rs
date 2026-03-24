// =============================================================================
// evtx_parser.rs — Windows .evtx File Parser
//
// Reads a Windows Event Log (.evtx) binary file and converts each record into
// the application's internal EventRecord struct.
//
// HIGH-LEVEL FLOW:
//   1. Open the .evtx file via evtx::EvtxParser::from_path.
//   2. Iterate records via .records_json() — each record becomes a JSON string.
//   3. Parse that JSON with serde_json into a generic Value tree.
//   4. Extract System-level fields (timestamp, event_id, level, channel, computer).
//   5. Build a flat name→value map from EventData *and* UserData payloads.
//   6. Map well-known keys to named struct fields; everything else → extra_fields.
//   7. Pass the collected records through the filter pipeline and return.
//
// EDGE CASES HANDLED:
//   - EventID can be a JSON number, a JSON string, OR an object whose "#text"
//     key holds either a string OR a number. All four forms are now handled.
//   - EventData.Data can be an array, a single object, or absent.
//   - Data items may have no "#attributes/Name" (unnamed/indexed items from
//     some providers) — these are stored as "Data_0", "Data_1", etc.
//   - Some providers put their payload in UserData instead of EventData.
//     Both are extracted and merged into the same flat map.
//   - UserData often has a nested XML→JSON structure; we flatten it recursively.
//   - Values of "-" (Windows "not applicable" sentinel) are normalised to None.
//   - Malformed individual records are skipped with a stderr warning rather
//     than aborting the entire file parse.
// =============================================================================

use std::collections::HashMap;

use serde_json::Value;

use crate::filters::apply_filters;
use crate::types::{EventRecord, FilterConfig};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse a .evtx file at `path`, apply `filters`, return matching records.
///
/// Returns `Err(String)` if the file cannot be opened or is not a valid .evtx.
/// Individual malformed records are skipped with a warning rather than causing
/// the whole parse to fail.
pub fn parse_evtx_file(path: &str, filters: &FilterConfig) -> Result<Vec<EventRecord>, String> {
    // Open and validate the .evtx file header/chunk structure.
    let mut parser = evtx::EvtxParser::from_path(path)
        .map_err(|e| format!("Failed to open .evtx file '{}': {}", path, e))?;

    let mut records: Vec<EventRecord> = Vec::new();

    for result in parser.records_json() {
        match result {
            Ok(record) => {
                match parse_single_record(&record.data) {
                    Ok(event) => records.push(event),
                    Err(e) => {
                        // Log the skip reason but continue — one bad record
                        // should not abort an entire file.
                        eprintln!(
                            "[evtx_parser] Skipping record (event_record_id={}): {}",
                            record.event_record_id, e
                        );
                    }
                }
            }
            Err(e) => {
                // The evtx crate itself failed to decode this record (corrupt chunk).
                eprintln!("[evtx_parser] Error reading record from '{}': {}", path, e);
            }
        }
    }

    // Apply the user's filter criteria after we have the full typed structs.
    let filtered = apply_filters(records, filters);
    Ok(filtered)
}

// ---------------------------------------------------------------------------
// Core record parser
// ---------------------------------------------------------------------------

/// Parse one JSON event string (from the evtx crate) into an EventRecord.
fn parse_single_record(json_str: &str) -> Result<EventRecord, String> {
    let root: Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {}", e))?;

    // Top-level key is always "Event".
    let event = root
        .get("Event")
        .ok_or_else(|| "Missing 'Event' key".to_string())?;

    // -----------------------------------------------------------------------
    // System fields
    // -----------------------------------------------------------------------
    let system = event
        .get("System")
        .ok_or_else(|| "Missing 'Event.System'".to_string())?;

    // Timestamp: Event.System.TimeCreated.#attributes.SystemTime (ISO 8601 UTC)
    let timestamp = system
        .pointer("/TimeCreated/#attributes/SystemTime")
        .and_then(Value::as_str)
        .unwrap_or("1970-01-01T00:00:00Z")
        .to_string();

    // EventID: may be a number, string, or object with "#text" that is itself
    // either a number OR a string. extract_event_id handles all four cases.
    let event_id = extract_event_id(system.get("EventID"))?;

    // Level: numeric code 0-5 → human-readable string.
    let level_raw = system
        .get("Level")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0u64);
    let level = map_level_code(level_raw);

    // Channel: e.g. "Security", "System", "Application".
    let channel = system
        .get("Channel")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    // Computer: hostname of the machine that generated the event.
    let computer = system
        .get("Computer")
        .and_then(Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    // -----------------------------------------------------------------------
    // Event payload fields (EventData + UserData)
    //
    // We extract both sections and merge them into a single flat map so that
    // the rest of the code doesn't need to care which section a field came from.
    // -----------------------------------------------------------------------
    let event_data_map = extract_all_event_data(event);

    // -----------------------------------------------------------------------
    // Named struct field extraction
    //
    // For each named field we try multiple common key names across different
    // event IDs and providers, in priority order.
    // -----------------------------------------------------------------------

    let username = extract_field(&event_data_map, "SubjectUserName");
    let domain   = extract_field(&event_data_map, "SubjectDomainName");

    // Process ID — three common names across different event schemas
    let process_id = extract_field(&event_data_map, "ProcessId")
        .or_else(|| extract_field(&event_data_map, "ProcessID"))
        .or_else(|| extract_field(&event_data_map, "NewProcessId"));

    // Process name — two common names
    let process_name = extract_field(&event_data_map, "ProcessName")
        .or_else(|| extract_field(&event_data_map, "NewProcessName"));

    // IP address — explicit names first, then a fuzzy scan for "ip"/"address"
    let ip_address = extract_field(&event_data_map, "IpAddress")
        .or_else(|| extract_field(&event_data_map, "SourceAddress"))
        .or_else(|| extract_field(&event_data_map, "ClientAddress"))
        .or_else(|| extract_field(&event_data_map, "RemoteAddress"))
        .or_else(|| find_field_by_name_fragment(&event_data_map, &["ipaddress", "sourceip", "remoteip", "clientip"]));

    // Port — same strategy
    let port = extract_field(&event_data_map, "IpPort")
        .or_else(|| extract_field(&event_data_map, "SourcePort"))
        .or_else(|| extract_field(&event_data_map, "ClientPort"))
        .or_else(|| extract_field(&event_data_map, "RemotePort"))
        .or_else(|| find_field_by_name_fragment(&event_data_map, &["port"]));

    let logon_type     = extract_field(&event_data_map, "LogonType");
    let command_line   = extract_field(&event_data_map, "CommandLine");
    let parent_process = extract_field(&event_data_map, "ParentProcessName");
    let target_username = extract_field(&event_data_map, "TargetUserName");
    let target_domain  = extract_field(&event_data_map, "TargetDomainName");
    let workstation    = extract_field(&event_data_map, "WorkstationName");
    let auth_package   = extract_field(&event_data_map, "AuthenticationPackageName");

    // -----------------------------------------------------------------------
    // extra_fields: everything not mapped to a named field above.
    // Preserves all source data for uncommon event types.
    // -----------------------------------------------------------------------
    const KNOWN_FIELDS: &[&str] = &[
        "SubjectUserName", "SubjectDomainName",
        "ProcessId", "ProcessID", "NewProcessId",
        "ProcessName", "NewProcessName",
        "IpAddress", "SourceAddress", "ClientAddress", "RemoteAddress",
        "IpPort", "SourcePort", "ClientPort", "RemotePort",
        "LogonType", "CommandLine", "ParentProcessName",
        "TargetUserName", "TargetDomainName",
        "WorkstationName", "AuthenticationPackageName",
    ];

    let extra_fields: HashMap<String, String> = event_data_map
        .into_iter()
        .filter(|(k, _)| !KNOWN_FIELDS.contains(&k.as_str()))
        .collect();

    Ok(EventRecord {
        timestamp,
        event_id,
        level,
        channel,
        computer,
        username,
        domain,
        process_id,
        process_name,
        ip_address,
        port,
        logon_type,
        command_line,
        parent_process,
        target_username,
        target_domain,
        workstation,
        auth_package,
        extra_fields,
    })
}

// ---------------------------------------------------------------------------
// extract_event_id
//
// EventID appears in FOUR possible JSON shapes from different providers:
//   1. JSON number  : 4624
//   2. JSON string  : "4624"
//   3. Object, #text is string: {"#text": "4624", "#attributes": {...}}
//   4. Object, #text is number: {"#text": 7000,   "#attributes": {...}}
//        ↑ This was the bug — the old code only handled case 3 and missed 4.
//
// We now try both as_u64() and as_str() when reading the "#text" field.
// ---------------------------------------------------------------------------
fn extract_event_id(value: Option<&Value>) -> Result<u32, String> {
    let v = value.ok_or_else(|| "Missing EventID field".to_string())?;

    // Case 1: plain JSON number (most common for Security/System/Application)
    if let Some(n) = v.as_u64() {
        return Ok(n as u32);
    }

    // Case 2: plain JSON string
    if let Some(s) = v.as_str() {
        return s
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("Cannot parse EventID string '{}' as u32", s));
    }

    // Cases 3 & 4: JSON object — the actual ID is in the "#text" sub-field.
    // "#text" may be a NUMBER (case 4, the previously-failing case) or a STRING (case 3).
    if let Some(text_val) = v.pointer("/#text") {
        // Try as a JSON number first (case 4 — this is what was broken before)
        if let Some(n) = text_val.as_u64() {
            return Ok(n as u32);
        }
        // Then try as a JSON string (case 3)
        if let Some(s) = text_val.as_str() {
            return s
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("Cannot parse EventID '#text' '{}' as u32", s));
        }
    }

    Err(format!("Unrecognised EventID format: {:?}", v))
}

// ---------------------------------------------------------------------------
// map_level_code — numeric Level → human-readable string
// ---------------------------------------------------------------------------
fn map_level_code(code: u64) -> String {
    match code {
        0 => "Information", // LogAlways
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "Unknown",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// extract_all_event_data
//
// Extracts data from BOTH EventData and UserData sections and merges them
// into one flat HashMap<String, String>.
//
// EventData: standard payload for most events — contains named Data elements.
// UserData: used by some providers (WMI, WER, Task Scheduler, etc.) — has a
//           nested XML→JSON structure that we flatten recursively.
// ---------------------------------------------------------------------------
fn extract_all_event_data(event: &Value) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // --- EventData section ---
    if let Some(event_data) = event.get("EventData") {
        extract_event_data_section(event_data, &mut map);
    }

    // --- UserData section ---
    // UserData wraps an arbitrary XML element; we flatten its children.
    if let Some(user_data) = event.get("UserData") {
        // UserData typically looks like: { "SomeElement": { "Field": "value", ... } }
        // We walk one level in and then flatten everything we find.
        if let Some(obj) = user_data.as_object() {
            for (_wrapper_key, wrapper_val) in obj {
                // The wrapper element itself may contain named fields directly
                flatten_json_to_map(wrapper_val, &mut map, "");
            }
        }
    }

    map
}

// ---------------------------------------------------------------------------
// extract_event_data_section
//
// Handles the EventData node specifically. EventData.Data can be:
//   A) An array of named Data objects: [{"#attributes":{"Name":"X"},"#text":"v"}, ...]
//   B) A single named Data object (same shape, not wrapped in array)
//   C) An array where some items have no Name attribute (indexed/unnamed data)
//   D) EventData fields directly as object keys (some legacy providers)
// ---------------------------------------------------------------------------
fn extract_event_data_section(event_data: &Value, map: &mut HashMap<String, String>) {
    // Check if there's a "Data" sub-key (most common structure)
    if let Some(data) = event_data.get("Data") {
        if let Some(arr) = data.as_array() {
            // Case A & C: array of Data elements
            for (idx, item) in arr.iter().enumerate() {
                insert_data_item(map, item, idx);
            }
        } else if data.is_object() {
            // Case B: single Data element (not wrapped in array)
            insert_data_item(map, data, 0);
        } else if let Some(s) = data.as_str() {
            // Rare: EventData.Data is a plain string — store as "Data"
            let trimmed = s.trim();
            if !trimmed.is_empty() && trimmed != "-" {
                map.insert("Data".to_string(), trimmed.to_string());
            }
        }
    } else {
        // Case D: EventData has direct key→value pairs (no Data sub-array).
        // Flatten any direct object properties (skip #attributes which is metadata).
        if let Some(obj) = event_data.as_object() {
            for (key, val) in obj {
                if key == "#attributes" {
                    continue; // metadata — skip
                }
                if let Some(s) = val.as_str() {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() && trimmed != "-" {
                        map.insert(key.clone(), trimmed.to_string());
                    }
                } else if let Some(n) = val.as_u64() {
                    map.insert(key.clone(), n.to_string());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// insert_data_item
//
// Extracts Name + value from one Data JSON object and inserts into the map.
//
// If the item has no "#attributes/Name", we fall back to "Data_<idx>" so that
// unnamed (indexed) Data elements are preserved rather than silently dropped.
// This was the second bug: unnamed Data items from many providers were lost.
// ---------------------------------------------------------------------------
fn insert_data_item(map: &mut HashMap<String, String>, item: &Value, idx: usize) {
    // Try to get the field name from #attributes.Name
    let name = item
        .pointer("/#attributes/Name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        // Fallback: use positional key so unnamed data is not lost
        .unwrap_or_else(|| format!("Data_{}", idx));

    // Get the field value from #text — may be a string, number, or boolean.
    let value = match item.get("#text") {
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() || t == "-" {
                return; // Windows "not applicable" sentinel — skip
            }
            t.to_string()
        }
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b))   => b.to_string(),
        // If item is itself a plain string (e.g. array of bare strings), use it directly
        _ => {
            if let Some(s) = item.as_str() {
                let t = s.trim();
                if t.is_empty() || t == "-" { return; }
                t.to_string()
            } else if let Some(n) = item.as_u64() {
                n.to_string()
            } else {
                return; // null, object, array — not a usable scalar
            }
        }
    };

    map.insert(name, value);
}

// ---------------------------------------------------------------------------
// flatten_json_to_map
//
// Recursively walks a JSON Value and inserts all string/number/bool leaf
// values into `map`. Used for UserData which has an arbitrary nested structure.
//
// `prefix` is prepended to key names at each nesting level (e.g. "Outer_Inner").
// At the top level, prefix is "" so keys are not prefixed.
// ---------------------------------------------------------------------------
fn flatten_json_to_map(value: &Value, map: &mut HashMap<String, String>, prefix: &str) {
    match value {
        Value::Object(obj) => {
            for (key, val) in obj {
                // Skip JSON metadata keys produced by the evtx crate
                if key == "#attributes" || key.starts_with('#') {
                    // But still try to read the #text sibling if present
                    continue;
                }
                // Build the new key with optional prefix
                let new_key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}_{}", prefix, key)
                };
                flatten_json_to_map(val, map, &new_key);
            }
            // Also check for a "#text" value directly on this object
            // (evtx emits {#attributes:{...}, #text:"value"} for XML elements with both)
            if let Some(text) = obj.get("#text") {
                let effective_key = if prefix.is_empty() { "Value".to_string() } else { prefix.to_string() };
                insert_scalar(map, &effective_key, text);
            }
        }
        _ => {
            // Leaf value — insert directly if it's a usable scalar
            if !prefix.is_empty() {
                insert_scalar(map, prefix, value);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// insert_scalar — insert a JSON scalar into the map (normalise "-" → skip)
// ---------------------------------------------------------------------------
fn insert_scalar(map: &mut HashMap<String, String>, key: &str, val: &Value) {
    let string_val = match val {
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() || t == "-" { return; }
            t.to_string()
        }
        Value::Number(n) => n.to_string(),
        Value::Bool(b)   => b.to_string(),
        _ => return,
    };
    map.insert(key.to_string(), string_val);
}

// ---------------------------------------------------------------------------
// extract_field — look up a key in the event data map
// ---------------------------------------------------------------------------
fn extract_field(map: &HashMap<String, String>, key: &str) -> Option<String> {
    // Values of "-" were already excluded during insertion, so any value
    // present in the map is guaranteed to be meaningful.
    map.get(key).cloned()
}

// ---------------------------------------------------------------------------
// find_field_by_name_fragment
//
// Scans the map for a field whose NAME contains any of the given fragments as
// a case-insensitive substring. Used as a fuzzy fallback for IP/port fields
// where providers use non-standard naming (e.g. "RemoteIPAddress", "DestPort").
// ---------------------------------------------------------------------------
fn find_field_by_name_fragment(
    map: &HashMap<String, String>,
    fragments: &[&str],
) -> Option<String> {
    for (key, value) in map {
        let key_lower = key.to_lowercase();
        if fragments.iter().any(|frag| key_lower.contains(frag)) {
            return Some(value.clone());
        }
    }
    None
}
