// =============================================================================
// types.rs — Shared Data Types
//
// This module defines the two core data structures that flow across the entire
// application: EventRecord and FilterConfig.
//
// EventRecord represents a single parsed Windows Event Log entry. Its fields
// cover the most commonly investigated columns during incident response (IR)
// work — timestamps, user context, process information, network indicators,
// and authentication details. Any EventData fields not covered by the named
// fields are stored in `extra_fields` as a generic key→value map so that no
// data from the source .evtx file is silently discarded.
//
// FilterConfig represents the user-supplied filter criteria coming from the
// frontend. All fields are Optional so that the frontend only needs to send the
// filters it actually wants to apply; absent filters are simply skipped.
//
// Both structs derive:
//   - Debug      : enables {:?} formatting for logging and test output
//   - Clone      : allows values to be duplicated without moving ownership
//   - Serialize  : converts structs → JSON for Tauri IPC responses to frontend
//   - Deserialize: converts JSON from Tauri IPC requests → structs
//
// Serde is configured with `rename_all = "snake_case"` so that Rust field names
// (already snake_case) map cleanly to the JSON keys the TypeScript frontend
// expects without any manual renaming.
// =============================================================================

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// EventRecord
//
// Represents one fully-parsed event from a .evtx file. Fields are split into:
//   - System fields   : metadata from Event.System (timestamp, IDs, level…)
//   - Known EventData : named fields extracted from Event.EventData.Data that
//                       are relevant for security investigations
//   - extra_fields    : catch-all for any remaining EventData.Data entries
//
// All optional fields use Option<String> so the CSV exporter and frontend can
// distinguish "not present" from "empty string", and enrichment checks can
// safely skip None fields without false-positive matches.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EventRecord {
    /// ISO 8601 UTC timestamp sourced from Event.System.TimeCreated.#attributes.SystemTime
    pub timestamp: String,

    /// Windows Event ID (e.g. 4624 = logon, 4688 = process creation).
    /// Stored as u32 since Event IDs are always non-negative integers < 65536.
    pub event_id: u32,

    /// Human-readable severity level derived from the numeric Level in Event.System:
    ///   0 → "Information", 1 → "Critical", 2 → "Error",
    ///   3 → "Warning",     4 → "Information", 5 → "Verbose"
    pub level: String,

    /// Log channel name, e.g. "Security", "System", "Application"
    pub channel: String,

    /// Hostname of the machine that generated the event (Event.System.Computer)
    pub computer: String,

    /// SubjectUserName — the user account that performed the action (if present)
    pub username: Option<String>,

    /// SubjectDomainName — domain of the subject user account (if present)
    pub domain: Option<String>,

    /// ProcessId or NewProcessId from EventData — the PID involved in the event
    pub process_id: Option<String>,

    /// ProcessName or NewProcessName — full path or name of the executable
    pub process_name: Option<String>,

    /// IpAddress / SourceAddress / ClientAddress — any IP indicator in the event
    pub ip_address: Option<String>,

    /// IpPort / SourcePort / ClientPort — network port associated with the event
    pub port: Option<String>,

    /// LogonType — numeric code for authentication type (e.g. "2" = interactive,
    /// "3" = network, "10" = remote interactive). Kept as String to avoid
    /// losing leading/trailing content and to stay consistent with CSV output.
    pub logon_type: Option<String>,

    /// CommandLine — the full command-line string from process-creation events
    pub command_line: Option<String>,

    /// ParentProcessName — the parent process that spawned the subject process
    pub parent_process: Option<String>,

    /// TargetUserName — the account that was acted upon (e.g. the account that
    /// was logged into, not the one initiating the logon)
    pub target_username: Option<String>,

    /// TargetDomainName — domain of the target user account
    pub target_domain: Option<String>,

    /// WorkstationName — the originating workstation for network logon events
    pub workstation: Option<String>,

    /// AuthenticationPackageName — e.g. "NTLM", "Kerberos", "Negotiate"
    pub auth_package: Option<String>,

    /// All remaining EventData.Data fields that don't match a named field above.
    /// The key is the `Name` attribute and the value is the `#text` content.
    /// This ensures no data is lost even for event types not explicitly modelled.
    pub extra_fields: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// FilterConfig
//
// Encapsulates all user-specified filter criteria. The frontend sends this as
// a JSON object in the `parse_evtx` command payload. Every field is Optional
// so the frontend only needs to include the filters it wants to activate.
//
// Time filtering supports two mutually-exclusive modes:
//   1. Relative: `relative_days` — "last N days" relative to now (takes priority)
//   2. Absolute: `date_from` + `date_to` — explicit ISO 8601 date range
//
// Text filters (hostname, username, etc.) are always case-insensitive partial
// matches so analysts don't need to know the exact capitalisation.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FilterConfig {
    /// Absolute start of the time range. Parsed as ISO 8601 (e.g. "2024-01-01T00:00:00Z").
    /// Ignored when `relative_days` is also set.
    pub date_from: Option<String>,

    /// Absolute end of the time range. Parsed as ISO 8601.
    /// Ignored when `relative_days` is also set.
    pub date_to: Option<String>,

    /// Relative time window in days from "now". When set, overrides date_from/date_to.
    /// Typical values: 1, 3, 7, 14, 30.
    pub relative_days: Option<u32>,

    /// Filter by process ID — keeps records whose `process_id` field contains
    /// this string (partial match, so "123" matches "1234").
    pub process_id: Option<String>,

    /// Filter by computer/hostname — case-insensitive partial match against
    /// EventRecord.computer.
    pub hostname: Option<String>,

    /// Filter by IP address — partial match against EventRecord.ip_address.
    pub ip_address: Option<String>,

    /// Filter by username — case-insensitive partial match against either
    /// EventRecord.username OR EventRecord.target_username.
    pub username: Option<String>,

    /// Name of an arbitrary EventData field to filter on (e.g. "SubStatus").
    /// Works together with `custom_field_value`; if only this is set, the
    /// filter keeps any record that has the named field present at all.
    pub custom_field_name: Option<String>,

    /// Value to match inside the field named by `custom_field_name`.
    /// Case-insensitive partial match. Ignored if `custom_field_name` is None.
    pub custom_field_value: Option<String>,

    /// When true, applies aggressive filtering and shortening for LLM analysis
    pub llm_optimized: Option<bool>,
}

// ---------------------------------------------------------------------------
// PatternSpec — one regex-based enrichment rule, loaded from signatures.json.
//
// This struct is Serialize + Deserialize so it can cross the Tauri IPC
// boundary (returned to the frontend in get_signatures_info) and also be
// read from the JSON file via serde_json.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSpec {
    /// Short machine-readable identifier, e.g. "ps_encoded_command"
    pub name: String,
    /// Risk level string: "Critical", "High", "Medium", or "Low"
    pub risk: String,
    /// MITRE ATT&CK tactic name, e.g. "Defense Evasion"
    pub tactic: String,
    /// MITRE ATT&CK technique ID, e.g. "T1027"
    pub mitre_id: String,
    /// Plain-English description shown in the enrichment report
    pub description: String,
    /// Regex pattern string (compiled at runtime by the enrichment engine)
    pub regex: String,
}

// ---------------------------------------------------------------------------
// SignaturesFile — top-level structure of signatures.json
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignaturesFile {
    #[allow(dead_code)]
    pub version: String,
    pub patterns: Vec<PatternSpec>,
}

// ---------------------------------------------------------------------------
// FileSummary
//
// Metadata summary for a loaded .evtx file, shown in the UI after import.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileSummary {
    /// Earliest event timestamp in ISO 8601 (from first record)
    pub start_time: Option<String>,
    /// Latest event timestamp in ISO 8601 (from last record)
    pub end_time: Option<String>,
    /// Total number of records successfully parsed from the file
    pub total_records: usize,
    /// Top 5 Event IDs by frequency
    pub event_ids: HashMap<u32, usize>,
}
