// =============================================================================
// main.rs — Entry Point, Tauri Command Registration, Application State
//
// APPLICATION STATE (AppState):
//   Holds the currently-loaded pattern rules from signatures.json and the
//   resolved path to the file. Protected by Mutex so it can be shared safely
//   across async command invocations.
//
//   On startup, init_signatures() resolves the file using this priority:
//     1. App local data dir  (~/Library/Application Support/com.eventviewer.tocsv/)
//        — the user's writable copy; created on first launch from the bundle.
//     2. Tauri resource dir  — where tauri.conf.json "resources" entries land.
//     3. Working directory   — convenient in `tauri dev` (project root).
//
// COMMANDS EXPOSED TO FRONTEND:
//   parse_evtx              → parse .evtx with filters
//   export_csv              → write records to CSV
//   run_enrichment_check    → scan records, return Markdown report
//   enrich_records          → dedup + XML cleanup
//   read_suspicious_commands→ read bundled suspicious-commands.txt (for optional extra patterns)
//   reload_signatures       → re-read signatures.json, return {count, path}
//   get_signatures_info     → return current {count, path} without reloading
// =============================================================================

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod types;
mod evtx_parser;
mod filters;
mod csv_exporter;
mod enrichment;

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;
use types::{PatternSpec, SignaturesFile};

// ---------------------------------------------------------------------------
// AppState — shared mutable state managed by Tauri
// ---------------------------------------------------------------------------

/// Holds the currently-loaded enrichment signature rules and the path they
/// were loaded from. Mutex-protected for safe multi-command access.
pub struct AppState {
    /// Compiled pattern specs currently in use
    pub pattern_rules: Mutex<Vec<PatternSpec>>,
    /// Absolute path to the signatures.json file that was last loaded
    pub signatures_path: Mutex<PathBuf>,
}

// ---------------------------------------------------------------------------
// Signatures file resolution and loading
// ---------------------------------------------------------------------------

/// Load signatures.json, resolving its location in priority order.
/// Returns (rules, path). On first run the file is copied from the resource
/// bundle into the writable app local data directory.
fn init_signatures(app_handle: &tauri::AppHandle) -> (Vec<PatternSpec>, PathBuf) {
    // 1. Determine the paths we care about
    let doc_dir = dirs_next::document_dir().map(|d| d.join("evtx-to-csv"));
    let doc_path = doc_dir.as_ref().map(|d| d.join("signatures.json"));

    // Working directory (very important for `tauri dev`)
    let cwd_path = PathBuf::from("signatures.json");
    if cwd_path.exists() {
        if let Ok(rules) = load_signatures_from_path(&cwd_path) {
            let abs_path = cwd_path.canonicalize().unwrap_or(cwd_path);
            eprintln!("[main] SUCCESS: Loaded {} rules from working directory: {:?}", rules.len(), abs_path);
            return (rules, abs_path);
        }
    }

    // 2. Try loading from Priority 1: Documents folder
    if let Some(ref path) = doc_path {
...
            match load_signatures_from_path(path) {
                Ok(rules) => {
                    eprintln!("[main] SUCCESS: Loaded {} rules from Documents", rules.len());
                    return (rules, path.clone());
                }
                Err(e) => eprintln!("[main] ERR: Failed to load from Documents: {}", e),
            }
        }
    }

    // 3. Try loading from Priority 2: App Data folder
    if app_path.exists() {
        if let Ok(rules) = load_signatures_from_path(&app_path) {
            eprintln!("[main] SUCCESS: Loaded {} rules from AppData", rules.len());
            return (rules, app_path);
        }
    }

    // 4. Fallback: Seeding from Resource
    if let Some(resource_path) = app_handle.path_resolver().resolve_resource("signatures.json") {
        eprintln!("[main] Found bundled resource at {:?}", resource_path);
        if let Ok(content) = std::fs::read_to_string(&resource_path) {
            // Seed to Documents
            if let Some(ref path) = doc_path {
                if let Some(ref parent) = doc_dir {
                    let _ = std::fs::create_dir_all(parent);
                    if std::fs::write(path, &content).is_ok() {
                        if let Ok(rules) = load_signatures_from_path(path) {
                            eprintln!("[main] SUCCESS: Seeded and loaded from Documents: {:?}", path);
                            return (rules, path.clone());
                        }
                    } else {
                        eprintln!("[main] ERR: Failed to write to Documents path: {:?}", path);
                    }
                }
            }
        } else {
            eprintln!("[main] ERR: Failed to read bundled resource content");
        }
    } else {
        eprintln!("[main] WARN: signatures.json resource not found in bundle");
    }

    eprintln!("[main] CRITICAL: No signatures.json found anywhere.");
    let fallback = doc_path.unwrap_or_else(|| app_handle.path_resolver().app_local_data_dir().unwrap_or_else(|| PathBuf::from(".")).join("signatures.json"));
    (Vec::new(), fallback)
}

/// Read and deserialize signatures.json from an explicit path.
fn load_signatures_from_path(path: &PathBuf) -> Result<Vec<PatternSpec>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {:?}: {}", path, e))?;
    let file: SignaturesFile = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON in {:?}: {}", path, e))?;
    Ok(file.patterns)
}

// ---------------------------------------------------------------------------
// Tauri Commands
// ---------------------------------------------------------------------------

/// Parse a .evtx file with the given filter config; return matching EventRecords.
#[tauri::command]
fn parse_evtx(
    path: String,
    filters: types::FilterConfig,
) -> Result<Vec<types::EventRecord>, String> {
    evtx_parser::parse_evtx_file(&path, &filters)
}

/// Quickly scan an .evtx for record count and date ranges.
#[tauri::command]
fn get_evtx_summary(path: String) -> Result<types::FileSummary, String> {
    evtx_parser::get_evtx_summary(&path)
}

/// Write EventRecords to a CSV file at output_path.
#[tauri::command]
fn export_csv(
    records: Vec<types::EventRecord>,
    output_path: String,
    filters: types::FilterConfig,
) -> Result<(), String> {
    let final_records = if filters.llm_optimized.unwrap_or(false) {
        enrichment::optimize_for_llm(records)
    } else {
        records
    };
    csv_exporter::export_to_csv(&final_records, &output_path)
}

/// Scan records against all loaded signatures + event-ID rules; return Markdown report.
#[tauri::command]
fn run_enrichment_check(
    records: Vec<types::EventRecord>,
    state: tauri::State<AppState>,
) -> Result<String, String> {
    // Clone the current rules out of the Mutex so we don't hold the lock
    // across the (potentially slow) enrichment scan.
    let rules = state.pattern_rules.lock()
        .map_err(|_| "Failed to lock signature rules".to_string())?
        .clone();
    Ok(enrichment::run_enrichment(&records, &rules))
}

/// Dedup + clean records for a tighter IR-focused export.
#[tauri::command]
fn enrich_records(
    records: Vec<types::EventRecord>,
) -> Result<Vec<types::EventRecord>, String> {
    Ok(enrichment::enrich_records(records))
}

/// Reload signatures.json from disk and update the in-memory rules.
/// Returns a JSON object: { "count": N, "path": "/absolute/path/to/signatures.json" }
#[tauri::command]
fn reload_signatures(
    state: tauri::State<AppState>,
) -> Result<serde_json::Value, String> {
    // Get the current file path from state
    let path = state.signatures_path.lock()
        .map_err(|_| "Failed to lock path".to_string())?
        .clone();

    // Re-read from that path
    let new_rules = load_signatures_from_path(&path)
        .map_err(|e| format!("Reload failed: {}", e))?;

    let count = new_rules.len();

    // Replace the rules in state
    *state.pattern_rules.lock()
        .map_err(|_| "Failed to lock rules".to_string())? = new_rules;

    eprintln!("[main] Reloaded {} rules from {:?}", count, path);

    Ok(serde_json::json!({
        "count": count,
        "path": path.to_string_lossy()
    }))
}

/// Return current signature info without reloading from disk.
/// Returns: { "count": N, "path": "..." }
#[tauri::command]
fn get_signatures_info(
    state: tauri::State<AppState>,
) -> serde_json::Value {
    let count = state.pattern_rules.lock()
        .map(|r| r.len()).unwrap_or(0);
    let path = state.signatures_path.lock()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    serde_json::json!({ "count": count, "path": path })
}

// ---------------------------------------------------------------------------
// Application entry point
// ---------------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        // setup() runs before any window opens — ideal for initialising state.
        .setup(|app| {
            // ---------------------------------------------------------------
            // Initialise app state (signatures)
            // ---------------------------------------------------------------
            let (rules, path) = init_signatures(&app.handle());
            app.manage(AppState {
                pattern_rules:   Mutex::new(rules),
                signatures_path: Mutex::new(path),
            });

            // ---------------------------------------------------------------
            // Splash screen — show for 500 ms then swap to main window
            // ---------------------------------------------------------------
            let handle = app.handle();
            std::thread::spawn(move || {
                // Wait 500 ms on a background thread (never block the main thread)
                std::thread::sleep(Duration::from_millis(500));

                // Show the main window
                if let Some(main_win) = handle.get_window("main") {
                    let _ = main_win.show();
                    let _ = main_win.set_focus();
                }

                // Close the splash window
                if let Some(splash_win) = handle.get_window("splash") {
                    let _ = splash_win.close();
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_evtx_summary,
            parse_evtx,
            export_csv,
            run_enrichment_check,
            enrich_records,
            reload_signatures,
            get_signatures_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
