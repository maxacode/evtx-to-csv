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
// Persistence Commands
// ---------------------------------------------------------------------------

fn get_config_path(app_handle: &tauri::AppHandle) -> PathBuf {
    let data_dir = app_handle.path_resolver().app_local_data_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    // Ensure the directory exists
    let _ = std::fs::create_dir_all(&data_dir);
    data_dir.join("app_state.json")
}

#[tauri::command]
fn save_app_state(
    app_handle: tauri::AppHandle,
    state: types::AppStatePersistent,
) -> Result<(), String> {
    let path = get_config_path(&app_handle);
    let content = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("Serialization error: {}", e))?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write state file: {}", e))?;
    Ok(())
}

#[tauri::command]
fn load_app_state(
    app_handle: tauri::AppHandle,
) -> Result<Option<types::AppStatePersistent>, String> {
    let path = get_config_path(&app_handle);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read state file: {}", e))?;
    let state: types::AppStatePersistent = serde_json::from_str(&content)
        .map_err(|e| format!("Deserialization error: {}", e))?;
    Ok(Some(state))
}

// ---------------------------------------------------------------------------
// Signatures file resolution and loading
// ---------------------------------------------------------------------------

/// Load signatures.json, resolving its location in priority order.
/// Returns (rules, path). On first run the file is copied from the resource
/// bundle into the writable app local data directory.
fn init_signatures(app_handle: &tauri::AppHandle) -> (Vec<PatternSpec>, PathBuf) {
    // 1. Define paths
    let doc_dir = dirs_next::document_dir().map(|d| d.join("evtx-to-csv"));
    let doc_path = doc_dir.as_ref().map(|d| d.join("signatures.json"));
    
    // In `tauri dev`, CWD is usually `src-tauri`. Root is `..` (if we kept the root version)
    // But we also have a copy in `src-tauri` now.
    let cwd_path = PathBuf::from("signatures.json");
    
    let data_dir = app_handle.path_resolver().app_local_data_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    let app_path = data_dir.join("signatures.json");

    // 2. Seeding Logic: If Documents version doesn't exist, try to create it
    if let (Some(target), Some(parent)) = (&doc_path, &doc_dir) {
        if !target.exists() {
            // Try seeding from bundled resource
            let mut seeded = false;
            
            // Try resolving as "signatures.json" (matches tauri.conf.json resources)
            if let Some(res_path) = app_handle.path_resolver().resolve_resource("signatures.json") {
                if let Ok(content) = std::fs::read_to_string(&res_path) {
                    let _ = std::fs::create_dir_all(parent);
                    if std::fs::write(target, content).is_ok() {
                        seeded = true;
                        eprintln!("[main] Seeded signatures.json from resource to {:?}", target);
                    }
                }
            }

            // Fallback: seed from working directory (for dev)
            if !seeded && cwd_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&cwd_path) {
                    let _ = std::fs::create_dir_all(parent);
                    if std::fs::write(target, content).is_ok() {
                        seeded = true;
                        eprintln!("[main] Seeded signatures.json from CWD to {:?}", target);
                    }
                }
            }
        }
    }

    // 3. Loading Priority
    
    // Priority 1: Documents Folder (User editable)
    if let Some(ref path) = doc_path {
        if path.exists() {
            if let Ok(rules) = load_signatures_from_path(path) {
                eprintln!("[main] Loaded {} rules from Documents: {:?}", rules.len(), path);
                return (rules, path.clone());
            }
        }
    }

    // Priority 2: Working Directory (for dev if seeding failed)
    if cwd_path.exists() {
        if let Ok(rules) = load_signatures_from_path(&cwd_path) {
            let abs_path = cwd_path.canonicalize().unwrap_or(cwd_path);
            eprintln!("[main] Loaded {} rules from CWD: {:?}", rules.len(), abs_path);
            return (rules, abs_path);
        }
    }

    // Priority 3: Root directory (another dev fallback)
    let root_path = PathBuf::from("..").join("signatures.json");
    if root_path.exists() {
        if let Ok(rules) = load_signatures_from_path(&root_path) {
            let abs_path = root_path.canonicalize().unwrap_or(root_path);
            eprintln!("[main] Loaded {} rules from Root: {:?}", rules.len(), abs_path);
            return (rules, abs_path);
        }
    }

    // Priority 4: AppData
    if app_path.exists() {
        if let Ok(rules) = load_signatures_from_path(&app_path) {
            eprintln!("[main] Loaded {} rules from AppData", rules.len());
            return (rules, app_path);
        }
    }

    eprintln!("[main] CRITICAL: No signatures.json found anywhere.");
    let final_fallback = doc_path.unwrap_or(app_path);
    (Vec::new(), final_fallback)
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

/// Recursively find all .evtx files in a directory.
#[tauri::command]
fn list_evtx_in_dir(path: String, recursive: bool) -> Result<Vec<String>, String> {
    use std::fs;
    use std::path::Path;

    fn collect_files(dir: &Path, recursive: bool, acc: &mut Vec<String>) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    if recursive {
                        collect_files(&path, recursive, acc)?;
                    }
                } else if let Some(ext) = path.extension() {
                    if ext.to_string_lossy().eq_ignore_ascii_case("evtx") {
                        acc.push(path.to_string_lossy().to_string());
                    }
                }
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    let root_path = Path::new(&path);
    if !root_path.exists() {
        return Err(format!("Directory does not exist: {}", path));
    }
    
    collect_files(root_path, recursive, &mut files).map_err(|e| e.to_string())?;
    
    // Sort files alphabetically for a better UI experience
    files.sort();
    
    Ok(files)
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

/// Open a native directory picker and return the selected path.
#[tauri::command]
async fn select_directory() -> Result<Option<String>, String> {
    use tauri::api::dialog::blocking::FileDialogBuilder;
    
    let path = FileDialogBuilder::new().pick_folder();
    Ok(path.map(|p| p.to_string_lossy().to_string()))
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
            list_evtx_in_dir,
            export_csv,
            run_enrichment_check,
            enrich_records,
            reload_signatures,
            get_signatures_info,
            save_app_state,
            load_app_state,
            select_directory,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
