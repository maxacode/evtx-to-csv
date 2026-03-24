/**
 * types.ts
 * --------
 * Central type definitions shared across the entire frontend.
 *
 * This file defines the data contracts that mirror the Rust backend's
 * serialization format. All field names use snake_case to match Tauri's
 * default serde serialization (Rust structs → snake_case JSON).
 *
 * Interfaces exported here:
 *   - FilterConfig   — filter parameters sent to the `parse_evtx` Tauri command
 *   - EventRecord    — a single parsed Windows Event Log record returned by the backend
 *   - FileEntry      — frontend-only state object tracking one loaded .evtx file
 *
 * Helper functions exported here:
 *   - defaultFilters() — factory that returns a FilterConfig with all fields null
 */

// ---------------------------------------------------------------------------
// FilterConfig
// ---------------------------------------------------------------------------

/**
 * Configuration object for filtering events when parsing an .evtx file.
 * All fields are nullable — a null value means "no filter applied" for that field.
 *
 * IMPORTANT: Field names are snake_case to match Tauri/serde serialization.
 * Do NOT rename these to camelCase or the Rust backend will silently ignore them.
 */
export interface FilterConfig {
  /** ISO 8601 datetime string for the start of a date range filter (e.g. "2024-01-15T00:00:00") */
  date_from: string | null;

  /** ISO 8601 datetime string for the end of a date range filter */
  date_to: string | null;

  /**
   * Relative date filter — number of past days to include.
   * Valid values expected by the backend: 1, 3, 7, 14, 30.
   * When set, date_from and date_to should be null (mutually exclusive).
   */
  relative_days: number | null;

  /** Filter events by Process ID (as a string to handle edge cases like "N/A") */
  process_id: string | null;

  /** Filter events by the hostname/computer name that generated them */
  hostname: string | null;

  /** Filter events by source IP address (relevant for network/logon events) */
  ip_address: string | null;

  /** Filter events by the username associated with the event */
  username: string | null;

  /**
   * Filter by an arbitrary field inside the EventData XML blob.
   * The backend will check if the named field exists (and optionally matches a value).
   */
  custom_field_name: string | null;

  /**
   * Optional value to match against custom_field_name.
   * If null but custom_field_name is set, the filter just checks field existence.
   * If both are set, the backend checks for an exact match.
   */
  custom_field_value: string | null;

  /** When true, applies aggressive filtering and shortening for LLM analysis */
  llm_optimized: boolean;
}

// ---------------------------------------------------------------------------
// EventRecord
// ---------------------------------------------------------------------------

/**
 * Represents a single parsed Windows Event Log entry.
 * Returned by the `parse_evtx` Tauri command as an array.
 *
 * Most fields are nullable because not every event type populates every field.
 * For example, logon_type is only present on Security/4624 events.
 */
export interface EventRecord {
  /** ISO 8601 timestamp of when the event was recorded */
  timestamp: string;

  /** Windows Event ID (e.g. 4624 = Logon, 4688 = Process Create, 7045 = Service Install) */
  event_id: number;

  /** Severity level string: "Information", "Warning", "Error", "Critical", "Verbose" */
  level: string;

  /** Event channel (e.g. "Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational") */
  channel: string;

  /** Computer/hostname where the event originated */
  computer: string;

  /** Username associated with the event subject */
  username: string | null;

  /** Domain of the user/account */
  domain: string | null;

  /** Process ID that generated or is the subject of the event */
  process_id: string | null;

  /** Full path or name of the process */
  process_name: string | null;

  /** Source or destination IP address (relevant for network/auth events) */
  ip_address: string | null;

  /** Port number associated with the network connection */
  port: string | null;

  /**
   * Logon type code for Security/4624 events:
   * 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext,
   * 9=NewCredentials, 10=RemoteInteractive, 11=CachedInteractive
   */
  logon_type: string | null;

  /** Full command line string (from 4688/Sysmon process create events) */
  command_line: string | null;

  /** Parent process name/path (from 4688/Sysmon process create events) */
  parent_process: string | null;

  /** Target/destination username (relevant for privilege use, logon events) */
  target_username: string | null;

  /** Target/destination domain */
  target_domain: string | null;

  /** Workstation name for network logon events */
  workstation: string | null;

  /** Authentication package used (e.g. "NTLM", "Kerberos", "Negotiate") */
  auth_package: string | null;

  /**
   * Catch-all for any EventData fields that don't map to the standard columns above.
   * Keys are field names from the XML EventData, values are their string representations.
   */
  extra_fields: Record<string, string>;
}

// ---------------------------------------------------------------------------
// FileEntry
// ---------------------------------------------------------------------------

/**
 * Metadata summary for a loaded .evtx file.
 */
export interface FileSummary {
  start_time: string | null;
  end_time: string | null;
  total_records: number;
  event_ids: Record<number, number>;
}

/**
 * Frontend-only state object representing one loaded .evtx file.
 * This is NOT sent to the backend — it's purely for managing UI state.
 *
 * Each FileEntry tracks one file's filters, export name, and processing status.
 * The `id` field allows React-style keyed list updates.
 */
export interface FileEntry {
  /** Unique identifier for this entry — generated via crypto.randomUUID() */
  id: string;

  /** Absolute filesystem path to the .evtx file */
  path: string;

  /** Just the filename portion (e.g. "Security.evtx") — derived from path */
  name: string;

  /** Quick summary of the file (dates, record count, common IDs) */
  summary: FileSummary | null;

  /** The filter configuration for this specific file */
  filters: FilterConfig;

  /**
   * User-provided export filename, without the .csv extension.
   * Defaults to the source filename with .evtx removed.
   * Example: "Security" → will be saved as "Security.csv"
   */
  outputName: string;

  /**
   * Processing state machine:
   * - 'idle'    — loaded, not yet exported
   * - 'parsing' — currently calling parse_evtx and export_csv
   * - 'done'    — export completed successfully
   * - 'error'   — an error occurred during parsing or export
   */
  status: 'idle' | 'parsing' | 'done' | 'error';

  /** Number of EventRecord objects returned after applying filters (set after parse) */
  recordCount: number;

  /** Human-readable error message when status === 'error', null otherwise */
  errorMessage: string | null;
}

// ---------------------------------------------------------------------------
// Factory helpers
// ---------------------------------------------------------------------------

/**
 * Returns a fresh FilterConfig with every field set to null.
 * Use this when creating a new FileEntry to start with no active filters.
 *
 * Example:
 *   const entry: FileEntry = {
 *     id: crypto.randomUUID(),
 *     ...
 *     filters: defaultFilters(),
 *   };
 */
export function defaultFilters(): FilterConfig {
  return {
    date_from: null,
    date_to: null,
    relative_days: null,
    process_id: null,
    hostname: null,
    ip_address: null,
    username: null,
    custom_field_name: null,
    custom_field_value: null,
    llm_optimized: false,
  };
}
