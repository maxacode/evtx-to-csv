/**
 * tauri-api.ts
 * ------------
 * Typed wrapper layer around all Tauri IPC commands and dialog APIs.
 *
 * This module is the single boundary between the Svelte UI and the Rust backend.
 * All Tauri `invoke` calls and dialog calls live here — components never call
 * `invoke` directly. This makes it easy to mock for testing and keeps the
 * API contract in one place.
 *
 * Functions exported:
 *   - openEvtxFiles()             — open a multi-select file dialog filtered to .evtx
 *   - saveFileDialog()            — open a save-as dialog for CSV output
 *   - saveReportDialog()          — open a save-as dialog for Markdown report output
 *   - parseEvtx()                 — invoke the parse_evtx Rust command
 *   - exportCsv()                 — invoke the export_csv Rust command
 *   - runEnrichmentCheck()        — invoke the run_enrichment_check Rust command
 *   - readSuspiciousCommands()    — invoke read_suspicious_commands (reads bundled file)
 *   - enrichRecords()             — invoke enrich_records (dedup + XML cleanup)
 *   - reloadSignatures()          — invoke reload_signatures (hot-reload signatures.json)
 *   - getSignaturesInfo()         — invoke get_signatures_info (rule count + file path)
 *
 * Error handling:
 *   All functions use try/catch and either return a safe fallback value or
 *   re-throw with a more descriptive message so the UI can display it.
 */

import { invoke } from '@tauri-apps/api/tauri';
import { open, save } from '@tauri-apps/api/dialog';
import { open as openShell } from '@tauri-apps/api/shell';
import type { FilterConfig, EventRecord } from './types';

// ---------------------------------------------------------------------------
// Shell / Path helpers
// ---------------------------------------------------------------------------

/**
 * Opens a file using the system default application.
 * @param path - Absolute path to the file
 */
export async function openFile(path: string): Promise<void> {
  try {
    await openShell(path);
  } catch (err) {
    console.error('[tauri-api] openFile error:', err);
  }
}

/**
 * Opens the folder containing the specified file.
 * @param path - Absolute path to the file
 */
export async function openFolder(path: string): Promise<void> {
  try {
    // Strip the filename to get the directory path
    const folderPath = path.replace(/[\\/][^\\/]+$/, '');
    await openShell(folderPath);
  } catch (err) {
    console.error('[tauri-api] openFolder error:', err);
  }
}

// ---------------------------------------------------------------------------
// File dialog helpers
// ---------------------------------------------------------------------------

/**
 * Opens a native file picker dialog that allows selecting one or more .evtx files.
 *
 * Returns an array of absolute file paths. Returns an empty array if the user
 * cancels the dialog (Tauri returns null on cancel).
 *
 * @returns Promise resolving to an array of selected file paths (may be empty)
 */
export async function openEvtxFiles(): Promise<string[]> {
  try {
    const result = await open({
      // Allow picking multiple files at once to batch-load several logs
      multiple: true,
      filters: [
        {
          name: 'Event Log',
          extensions: ['evtx'],
        },
      ],
    });

    // Tauri returns null when dialog is cancelled
    if (result === null) {
      return [];
    }

    // Normalize: open() returns string | string[] depending on `multiple`
    // Since multiple: true, it should always be string[] — but guard anyway
    if (Array.isArray(result)) {
      return result;
    }

    // Single string fallback (shouldn't happen with multiple: true, but be safe)
    return [result];
  } catch (err) {
    // Dialog errors are usually non-fatal (e.g. permissions) — log and return empty
    console.error('[tauri-api] openEvtxFiles error:', err);
    return [];
  }
}

/**
 * Opens a native save dialog pre-filled with the given default filename.
 * Used for choosing where to write the CSV export.
 *
 * @param defaultName - Suggested filename WITHOUT the .csv extension
 * @returns Promise resolving to the chosen absolute path, or null if cancelled
 */
export async function saveFileDialog(defaultName: string): Promise<string | null> {
  try {
    const result = await save({
      // Append .csv so the file picker shows the correct extension suggestion
      defaultPath: `${defaultName}.csv`,
      filters: [
        {
          name: 'CSV',
          extensions: ['csv'],
        },
      ],
    });

    // save() returns null on cancel
    return result ?? null;
  } catch (err) {
    console.error('[tauri-api] saveFileDialog error:', err);
    return null;
  }
}

/**
 * Opens a native save dialog for saving the enrichment analysis Markdown report.
 *
 * @param defaultName - Suggested filename WITHOUT the .md extension
 * @returns Promise resolving to the chosen absolute path, or null if cancelled
 */
export async function saveReportDialog(defaultName: string): Promise<string | null> {
  try {
    const result = await save({
      defaultPath: `${defaultName}.md`,
      filters: [
        {
          name: 'Markdown',
          extensions: ['md'],
        },
      ],
    });

    return result ?? null;
  } catch (err) {
    console.error('[tauri-api] saveReportDialog error:', err);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Backend command wrappers
// ---------------------------------------------------------------------------

/**
 * Invokes the Rust `parse_evtx` command to read and filter an .evtx file.
 *
 * The backend parses the binary event log format, applies all active filters
 * from the FilterConfig, and returns only matching EventRecord objects.
 *
 * @param path    - Absolute path to the .evtx file to parse
 * @param filters - FilterConfig describing which events to include
 * @returns Promise resolving to an array of matching EventRecord objects
 * @throws Error with descriptive message on backend failure
 */
export async function parseEvtx(path: string, filters: FilterConfig): Promise<EventRecord[]> {
  try {
    // Invoke the Rust command — field names must match the Rust handler's parameter names
    const records = await invoke<EventRecord[]>('parse_evtx', {
      path,
      filters,
    });

    return records;
  } catch (err) {
    // Wrap with context so the UI can show a meaningful error
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse ${path}: ${message}`);
  }
}

/**
 * Quickly scan an .evtx file for record count and date ranges.
 * @param path - Absolute path to the .evtx file
 */
export async function getEvtxSummary(path: string): Promise<import('./types').FileSummary> {
  try {
    return await invoke<import('./types').FileSummary>('get_evtx_summary', { path });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to get summary for ${path}: ${message}`);
  }
}

/**
 * Invokes the Rust `export_csv` command to write EventRecord data to a CSV file.
 *
 * The backend handles CSV formatting, header row generation, and field escaping.
 * The output file will be created or overwritten at outputPath.
 *
 * @param records    - Array of EventRecord objects to serialize
 * @param outputPath - Absolute path where the CSV file should be written
 * @throws Error with descriptive message on backend failure
 */
export async function exportCsv(records: EventRecord[], outputPath: string): Promise<void> {
  try {
    await invoke<void>('export_csv', {
      records,
      outputPath,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to export CSV to ${outputPath}: ${message}`);
  }
}

/**
 * Invokes the Rust `run_enrichment_check` command to analyze parsed events
 * against a library of known suspicious commands/patterns.
 *
 * The backend cross-references the EventRecord data with the rules loaded
 * in signatures.json and produces a Markdown report.
 *
 * @param records           - The parsed events to analyze
 * @returns Promise resolving to a Markdown-formatted report string
 * @throws Error with descriptive message on backend failure
 */
export async function runEnrichmentCheck(
  records: EventRecord[]
): Promise<string> {
  try {
    const report = await invoke<string>('run_enrichment_check', {
      records,
    });

    return report;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Enrichment check failed: ${message}`);
  }
}

/**
 * Invoke the Rust `enrich_records` command to deduplicate and clean records.
 *
 * What this does on the Rust side:
 *   - Parses TaskContent XML fields → compact IR summary (Cmd, Args, URI, RunAs…)
 *   - Normalises LogonType numbers → human-readable labels (e.g. "3 (Network)")
 *   - Deduplicates records by (timestamp + event_id + computer + username + ip)
 *   - Removes records with zero IR-relevant fields
 *
 * @param records - Raw parsed EventRecord array from parseEvtx()
 * @returns Promise resolving to a cleaned, deduplicated EventRecord array
 * @throws Error with descriptive message on backend failure
 */
export async function enrichRecords(records: EventRecord[]): Promise<EventRecord[]> {
  try {
    const enriched = await invoke<EventRecord[]>('enrich_records', { records });
    return enriched;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Enrich records failed: ${message}`);
  }
}

/**
 * Reload signatures.json from disk without restarting the app.
 * The Rust backend re-reads the file from its last-known path and recompiles
 * all regex rules. Returns updated info.
 *
 * @returns Promise resolving to { count: number; path: string }
 * @throws Error if the file cannot be read or parsed
 */
export async function reloadSignatures(): Promise<{ count: number; path: string }> {
  try {
    const result = await invoke<{ count: number; path: string }>('reload_signatures');
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to reload signatures: ${message}`);
  }
}

/**
 * Get current signature info (rule count + file path) without triggering a reload.
 * Called on app mount to populate the toolbar status indicator.
 *
 * @returns Promise resolving to { count: number; path: string }
 */
export async function getSignaturesInfo(): Promise<{ count: number; path: string }> {
  try {
    const result = await invoke<{ count: number; path: string }>('get_signatures_info');
    return result;
  } catch (err) {
    console.error('[tauri-api] getSignaturesInfo error:', err);
    return { count: 0, path: '' };
  }
}
