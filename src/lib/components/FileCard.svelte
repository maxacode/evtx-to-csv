<!--
  FileCard.svelte
  ---------------
  Represents a single loaded .evtx file in the main UI.

  Each FileCard is an independent, self-contained processing unit. It holds
  its own filter configuration (via FilterPanel), manages the export flow,
  and reports status back to the parent App.

  Props:
    entry             (FileEntry, bindable)  — the file's full state object
    suspiciousContent (string)               — contents of suspicious-commands.txt
    runEnrichment     (boolean)              — global toggle from App toolbar
    on:remove                                — dispatched when user clicks the × button
    on:update                                — dispatched with updated FileEntry when state changes

  Export flow (see "Export CSV" button handler):
    1. Open save dialog → get output CSV path
    2. Set status = 'parsing'
    3. Call parseEvtx(path, filters) → get EventRecord[]
    4. Call exportCsv(records, csvPath)
    5. If runEnrichment && suspiciousContent:
         a. Call runEnrichmentCheck(records, suspiciousContent)
         b. Derive report path: csvPath.replace(/\.csv$/i, '_report.md')
         c. Write markdown to disk via writeTextFile()
    6. Set status = 'done' and recordCount = records.length

  NOTE: writeTextFile from @tauri-apps/api/fs requires the following entry in
  src-tauri/tauri.conf.json under "tauri.allowlist":
      "fs": { "all": true, "scope": ["**"] }
  Without this, the enrichment report save will throw a permission error.

  Filter panel is collapsed by default to keep the card compact.
  A "▼ Filters" toggle button expands/collapses it with a smooth transition.
-->

<script lang="ts">
  import { createEventDispatcher, onMount } from 'svelte';
  import { writeTextFile } from '@tauri-apps/api/fs';
  import FilterPanel from './FilterPanel.svelte';
  import {
    saveFileDialog,
    parseEvtx,
    exportCsv,
    runEnrichmentCheck,
    enrichRecords,
    openFile,
    openFolder,
    getEvtxSummary
  } from '../tauri-api';
  import type { FileEntry } from '../types';

  // -------------------------------------------------------------------------
  // Props
  // -------------------------------------------------------------------------

  /** The full file entry state object — bindable for two-way sync with parent */
  export let entry: FileEntry;

  /**
   * Global enrichment toggle from the App toolbar.
   * When true, a _report.md is saved
   * alongside the CSV after export.
   */
  export let runEnrichment: boolean;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  onMount(() => {
    if (!entry.summary) {
      loadSummary();
    }
  });

  async function loadSummary() {
    try {
      entry.summary = await getEvtxSummary(entry.path);
      notifyUpdate();
    } catch (err) {
      console.error('Failed to load summary:', err);
    }
  }

  // -------------------------------------------------------------------------
  // Event dispatcher
  // -------------------------------------------------------------------------

  const dispatch = createEventDispatcher<{
    /** Emitted when the user clicks the × (remove) button */
    remove: void;
    /** Emitted after any state change so App can update its files array */
    update: FileEntry;
  }>();

  // -------------------------------------------------------------------------
  // Local UI state
  // -------------------------------------------------------------------------

  /** Controls whether the filter panel is expanded or collapsed */
  let filtersExpanded = false;

  /**
   * Brief toast-style success message shown after a successful export.
   * Cleared after a few seconds via setTimeout.
   */
  let successMessage: string | null = null;

  /** Timer handle for auto-clearing the success message */
  let successTimer: ReturnType<typeof setTimeout> | null = null;

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Emit an 'update' event so the parent App updates its files array.
   * Must be called after every mutation to `entry`.
   */
  function notifyUpdate() {
    dispatch('update', entry);
  }

  /**
   * Show a temporary success message that auto-dismisses after 4 seconds.
   */
  function showSuccess(message: string) {
    successMessage = message;
    // Clear any existing timer to prevent overlap
    if (successTimer) clearTimeout(successTimer);
    successTimer = setTimeout(() => {
      successMessage = null;
    }, 4000);
  }

  /**
   * Handle filter changes from the FilterPanel child component.
   * Resets the entry status to 'idle' so the status badge clears.
   */
  function handleFilterChange() {
    // When filters change, prior results are no longer valid — reset status
    if (entry.status === 'done' || entry.status === 'error') {
      entry.status = 'idle';
      entry.errorMessage = null;
      notifyUpdate();
    }
  }

  /**
   * Handle changes to the output filename input.
   * Strips any .csv extension the user may have typed (it's added automatically).
   */
  function handleOutputNameChange(event: Event) {
    const raw = (event.target as HTMLInputElement).value;
    // Remove trailing .csv if the user typed it — it's appended on save
    entry.outputName = raw.replace(/\.csv$/i, '');
    notifyUpdate();
  }

  // -------------------------------------------------------------------------
  // Export flow
  // -------------------------------------------------------------------------

  /**
   * Shared core: parse → optionally enrich → export CSV → optionally save report.
   *
   * @param doEnrich  When true, runs enrich_records() before writing the CSV.
   *                  Produces a smaller, cleaner file with deduped rows and
   *                  parsed TaskContent XML.
   */
  async function runExport(doEnrich: boolean) {
    // Guard: don't start a new export while one is already running
    if (entry.status === 'parsing') return;

    // Open a save dialog; the suggested name differs so the user can tell files apart
    const defaultName =
      (entry.outputName || entry.name.replace(/\.evtx$/i, '')) +
      (doEnrich ? '_enriched' : '');
    const savePath = await saveFileDialog(defaultName);

    // User cancelled the dialog — abort silently
    if (!savePath) return;

    // Show parsing state immediately so the UI feels responsive
    entry.status = 'parsing';
    entry.errorMessage = null;
    entry.recordCount = 0;
    notifyUpdate();

    try {
      // Step 1: Parse the .evtx file with the current filter settings
      let records = await parseEvtx(entry.path, entry.filters);

      // Step 2 (Enrich path only): deduplicate + clean TaskContent XML + normalise fields
      if (doEnrich) {
        records = await enrichRecords(records);
      }

      // Step 3: Write the CSV file to the user-chosen path
      await exportCsv(records, savePath, entry.filters);

      // Step 4: If the report toggle is on, run the enrichment check.
      // Built-in signatures from signatures.json are loaded at startup.
      // IMPORTANT: writeTextFile requires "fs": {"all":true,"scope":["**"]} in tauri.conf.json
      if (runEnrichment) {
        const reportMarkdown = await runEnrichmentCheck(records);
        const reportPath = savePath.replace(/\.csv$/i, '_report.md');
        await writeTextFile(reportPath, reportMarkdown);
      }
      // Update status + show success toast
      entry.status = 'done';
      entry.recordCount = records.length;
      entry.errorMessage = null;
      notifyUpdate();

      const enrichNote = doEnrich ? ' (enriched)' : '';
      const reportNote = runEnrichment ? ' + report.md' : '';
      showSuccess(
        `Exported ${records.length.toLocaleString()} record${records.length !== 1 ? 's' : ''}${enrichNote}${reportNote}`
      );
    } catch (err) {
      entry.status = 'error';
      entry.errorMessage = err instanceof Error ? err.message : String(err);
      notifyUpdate();
    }
  }

  /**
   * "Export CSV" button — raw export, no deduplication or XML parsing.
   * Gives the analyst the complete unmodified dataset.
   */
  async function handleExport() {
    await runExport(false);
  }

  /**
   * "Enrich & Export" button — deduplicates, cleans TaskContent XML,
   * normalises LogonType codes, and drops empty records before writing CSV.
   * Best for sharing/reporting; raw export is better for completeness.
   */
  async function handleEnrichExport() {
    await runExport(true);
  }

  // -------------------------------------------------------------------------
  // Computed display values
  // -------------------------------------------------------------------------

  /**
   * Count the number of non-null filter fields currently active.
   * Used to show a badge like "3 filters active" in the collapsed state.
   */
  $: activeFilterCount = Object.entries(entry.filters).filter(([, v]) => v !== null).length;

  /**
   * Map status to a display-friendly label for the status badge.
   */
  $: statusLabel = {
    idle: '',
    parsing: 'Parsing…',
    done: `${entry.recordCount.toLocaleString()} records`,
    error: 'Error',
  }[entry.status];
</script>

<!-- =========================================================================
     Template
     ========================================================================= -->

<article class="file-card" class:status-error={entry.status === 'error'}>

  <!-- -----------------------------------------------------------------------
       Header row: file icon, truncated name, remove button
       ----------------------------------------------------------------------- -->
  <header class="card-header">
    <!-- File icon (SVG) + filename -->
    <div class="file-info">
      <span class="file-icon" aria-hidden="true">
        <!-- Simple log/document icon -->
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M3 2h7l3 3v9a1 1 0 01-1 1H3a1 1 0 01-1-1V3a1 1 0 011-1z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
          <path d="M10 2v3h3" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
          <path d="M5 7h6M5 9.5h6M5 12h4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
        </svg>
      </span>
      <!-- Filename — truncated with ellipsis if too long via CSS -->
      <span class="file-name" title={entry.path}>{entry.name}</span>

      <!-- Quick action buttons: Open File / Open Folder -->
      <div class="header-actions">
        <button
          class="action-btn"
          on:click={() => openFile(entry.path)}
          title="Open source file in default viewer"
          aria-label="Open File"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
            <polyline points="15 3 21 3 21 9"></polyline>
            <line x1="10" y1="14" x2="21" y2="3"></line>
          </svg>
        </button>
        <button
          class="action-btn"
          on:click={() => openFolder(entry.path)}
          title="Open containing folder"
          aria-label="Open Folder"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
          </svg>
        </button>
      </div>

      <!-- Status badge (shown when status is not idle) -->
      {#if entry.status !== 'idle'}
        <span
          class="status-badge"
          class:badge-parsing={entry.status === 'parsing'}
          class:badge-done={entry.status === 'done'}
          class:badge-error={entry.status === 'error'}
        >
          {#if entry.status === 'parsing'}
            <!-- Animated spinner dot -->
            <span class="spinner" aria-hidden="true"></span>
          {/if}
          {statusLabel}
        </span>
      {/if}
    </div>

    <!-- Remove button -->
    <button
      class="remove-btn"
      aria-label={`Remove ${entry.name}`}
      on:click={() => dispatch('remove')}
      title="Remove file"
    >
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M2 2l10 10M12 2L2 12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
      </svg>
    </button>
  </header>

  <!-- -----------------------------------------------------------------------
       File Summary section
       ----------------------------------------------------------------------- -->
  {#if entry.summary}
    <div class="file-summary">
      <div class="summary-row">
        <span class="summary-item">
          <strong>Start:</strong> {new Date(entry.summary.start_time || '').toLocaleString()}
        </span>
        <span class="summary-item">
          <strong>End:</strong> {new Date(entry.summary.end_time || '').toLocaleString()}
        </span>
      </div>
      <div class="summary-row">
        <span class="summary-item">
          <strong>Total Records:</strong> {entry.summary.total_records.toLocaleString()}
        </span>
      </div>
      <div class="summary-ids">
        <strong>Top Event IDs:</strong>
        <div class="id-pills">
          {#each Object.entries(entry.summary.event_ids) as [id, count]}
            <span class="id-pill" title={`${count.toLocaleString()} occurrences`}>
              {id} <small>({count})</small>
            </span>
          {/each}
        </div>
      </div>
    </div>
  {/if}

  <!-- -----------------------------------------------------------------------
       Filters section (collapsible)
       ----------------------------------------------------------------------- -->
  <section class="filters-section">
    <!-- Toggle button with active-filter count badge -->
    <button
      class="filters-toggle"
      aria-expanded={filtersExpanded}
      on:click={() => (filtersExpanded = !filtersExpanded)}
    >
      <span class="toggle-arrow" class:expanded={filtersExpanded} aria-hidden="true">▶</span>
      <span>Filters</span>
      {#if activeFilterCount > 0}
        <!-- Shows how many filters are currently active -->
        <span class="filter-count-badge" title="{activeFilterCount} active filter(s)">
          {activeFilterCount}
        </span>
      {/if}
    </button>

    <!-- Filter panel — rendered but hidden via CSS when collapsed for smooth transition -->
    {#if filtersExpanded}
      <div class="filter-panel-wrapper">
        <FilterPanel
          bind:filters={entry.filters}
          on:change={handleFilterChange}
        />
      </div>
    {/if}
  </section>

  <!-- -----------------------------------------------------------------------
       Export section: output filename input + Export button + status area
       ----------------------------------------------------------------------- -->
  <section class="export-section">
    <!-- Output filename field -->
    <div class="export-row">
      <div class="output-field">
        <label class="field-label" for={`output-name-${entry.id}`}>Output filename</label>
        <div class="output-input-wrapper">
          <input
            id={`output-name-${entry.id}`}
            class="input output-input"
            type="text"
            placeholder={entry.name.replace(/\.evtx$/i, '')}
            value={entry.outputName}
            on:input={handleOutputNameChange}
          />
          <!-- Static .csv suffix indicator inside the input row -->
          <span class="csv-suffix">.csv</span>
        </div>
      </div>

      <!-- Button group: Export CSV (raw) + Enrich & Export (cleaned) -->
      <div class="btn-group">
        <!-- Raw export — full unmodified dataset -->
        <button
          class="export-btn"
          class:loading={entry.status === 'parsing'}
          disabled={entry.status === 'parsing'}
          on:click={handleExport}
          aria-busy={entry.status === 'parsing'}
          title="Export all records exactly as parsed (no deduplication)"
        >
          {#if entry.status === 'parsing'}
            <span class="btn-spinner" aria-hidden="true"></span>
            Exporting…
          {:else}
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <path d="M7 1v8M4 6l3 3 3-3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
              <path d="M2 10v2a1 1 0 001 1h8a1 1 0 001-1v-2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
            </svg>
            Export CSV
          {/if}
        </button>

        <!-- Enriched export — dedup + XML parsing + LogonType labels -->
        <button
          class="export-btn enrich-btn"
          class:loading={entry.status === 'parsing'}
          disabled={entry.status === 'parsing'}
          on:click={handleEnrichExport}
          aria-busy={entry.status === 'parsing'}
          title="Deduplicate, clean TaskContent XML, normalise LogonType codes, drop empty rows"
        >
          {#if entry.status !== 'parsing'}
            <!-- Sparkle/magic wand icon to signal "enriched" -->
            <svg width="13" height="13" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <path d="M2 12l8-8M7 2l1 2M12 7l-2-1M9 9l2 1M3 5l-1-2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              <circle cx="10" cy="4" r="1.2" fill="currentColor" opacity="0.7"/>
            </svg>
            Enrich &amp; Export
          {/if}
        </button>
      </div>
    </div>

    <!-- Status / feedback area -->
    {#if entry.status === 'error' && entry.errorMessage}
      <!-- Error state: show red error message -->
      <div class="status-area status-error-msg" role="alert">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <circle cx="7" cy="7" r="6" stroke="currentColor" stroke-width="1.4"/>
          <path d="M7 4v3.5M7 9.5v.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
        </svg>
        <span>{entry.errorMessage}</span>
      </div>

    {:else if successMessage}
      <!-- Success toast -->
      <div class="status-area status-success-msg" role="status">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <circle cx="7" cy="7" r="6" stroke="currentColor" stroke-width="1.4"/>
          <path d="M4.5 7l2 2 3-3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span>{successMessage}</span>
      </div>
    {/if}

    <!-- No warning needed — built-in signatures are always active in the Rust binary -->
  </section>

</article>

<!-- =========================================================================
     Styles
     ========================================================================= -->

<style>
  /* -------------------------------------------------------------------------
     Card container
     ------------------------------------------------------------------------- */
  .file-card {
    background: var(--color-bg-card);
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  .file-card:hover {
    border-color: #3d4260;
    box-shadow: 0 2px 12px rgba(0, 0, 0, 0.3);
  }

  /* Red border tint when the card has an error */
  .file-card.status-error {
    border-color: rgba(250, 82, 82, 0.4);
  }

  /* -------------------------------------------------------------------------
     Card header
     ------------------------------------------------------------------------- */
  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    min-height: 24px;
  }

  .file-info {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0; /* allow text truncation */
    flex: 1;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-left: 4px;
  }

  .action-btn {
    width: 26px;
    height: 26px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--color-bg-elevated);
    border: 1px solid var(--color-border);
    color: var(--color-text-dim);
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: all 0.15s;
    padding: 0;
  }

  .action-btn:hover {
    background: var(--color-bg);
    border-color: var(--color-accent);
    color: var(--color-accent);
  }

  /* -------------------------------------------------------------------------
     File Summary section
     ------------------------------------------------------------------------- */
  .file-summary {
    display: flex;
    flex-direction: column;
    gap: 8px;
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    padding: 10px 12px;
    font-size: 11px;
    color: var(--color-text-muted);
  }

  .summary-row {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  }

  .summary-item strong {
    color: var(--color-text-dim);
    margin-right: 4px;
  }

  .summary-ids {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .id-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .id-pill {
    background: var(--color-bg-elevated);
    border: 1px solid var(--color-border);
    padding: 2px 8px;
    border-radius: 12px;
    color: var(--color-text);
    font-weight: 600;
  }

  .id-pill small {
    font-weight: 400;
    color: var(--color-text-dim);
    margin-left: 2px;
  }

  /* SVG file icon */
  .file-icon {
    flex-shrink: 0;
    color: var(--color-accent);
    display: flex;
    align-items: center;
  }

  /* Truncate long filenames with ellipsis */
  .file-name {
    font-size: 13px;
    font-weight: 600;
    color: var(--color-text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  /* -------------------------------------------------------------------------
     Status badge
     ------------------------------------------------------------------------- */
  .status-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    font-weight: 500;
    padding: 2px 8px;
    border-radius: 20px;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .badge-parsing {
    background: rgba(250, 176, 5, 0.15);
    color: var(--color-warning);
    border: 1px solid rgba(250, 176, 5, 0.3);
  }

  .badge-done {
    background: rgba(64, 192, 87, 0.12);
    color: var(--color-success);
    border: 1px solid rgba(64, 192, 87, 0.25);
  }

  .badge-error {
    background: rgba(250, 82, 82, 0.12);
    color: var(--color-error);
    border: 1px solid rgba(250, 82, 82, 0.25);
  }

  /* Small rotating spinner dot for 'parsing' badge */
  .spinner {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    border: 1.5px solid var(--color-warning);
    border-top-color: transparent;
    animation: spin 0.8s linear infinite;
  }

  /* -------------------------------------------------------------------------
     Remove button
     ------------------------------------------------------------------------- */
  .remove-btn {
    flex-shrink: 0;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    background: transparent;
    color: var(--color-text-dim);
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }

  .remove-btn:hover {
    background: rgba(250, 82, 82, 0.15);
    color: var(--color-error);
  }

  /* -------------------------------------------------------------------------
     Filters section (collapsible)
     ------------------------------------------------------------------------- */
  .filters-section {
    display: flex;
    flex-direction: column;
    gap: 10px;
    border-top: 1px solid var(--color-border);
    padding-top: 12px;
  }

  .filters-toggle {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 500;
    color: var(--color-text-muted);
    background: transparent;
    border: none;
    cursor: pointer;
    padding: 0;
    transition: color 0.15s;
    width: fit-content;
  }

  .filters-toggle:hover {
    color: var(--color-text);
  }

  /* The ▶ arrow rotates 90° when expanded */
  .toggle-arrow {
    font-size: 9px;
    transition: transform 0.2s;
    display: inline-block;
  }

  .toggle-arrow.expanded {
    transform: rotate(90deg);
  }

  /* Small badge showing number of active filters */
  .filter-count-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: 9px;
    background: var(--color-accent);
    color: #fff;
    font-size: 10px;
    font-weight: 600;
  }

  /* Wrapper that provides padding around the FilterPanel */
  .filter-panel-wrapper {
    padding: 4px 0 4px;
  }

  /* -------------------------------------------------------------------------
     Export section
     ------------------------------------------------------------------------- */
  .export-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
    border-top: 1px solid var(--color-border);
    padding-top: 12px;
  }

  .export-row {
    display: flex;
    align-items: flex-end;
    gap: 10px;
  }

  /* Output filename field takes all remaining width */
  .output-field {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .field-label {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-text-muted);
  }

  /* Wrapper to position the .csv suffix inside the input row */
  .output-input-wrapper {
    display: flex;
    align-items: center;
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    transition: border-color 0.15s, box-shadow 0.15s;
  }

  .output-input-wrapper:focus-within {
    border-color: var(--color-accent);
    box-shadow: 0 0 0 2px rgba(92, 124, 250, 0.18);
  }

  .output-input {
    flex: 1;
    padding: 6px 10px;
    border: none;
    background: transparent;
    color: var(--color-text);
    font-size: 12px;
    font-family: inherit;
    outline: none;
    min-width: 0;
  }

  .output-input::placeholder {
    color: var(--color-text-dim);
  }

  /* ".csv" suffix indicator at the end of the output filename input */
  .csv-suffix {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-text-dim);
    padding: 0 10px 0 4px;
    white-space: nowrap;
    user-select: none;
  }

  /* -------------------------------------------------------------------------
     Button group: Export CSV + Enrich & Export side by side
     ------------------------------------------------------------------------- */
  .btn-group {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
    align-items: stretch;
  }

  /* -------------------------------------------------------------------------
     Export button (base styles shared by both export buttons)
     ------------------------------------------------------------------------- */
  .export-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 7px 12px;
    background: var(--color-accent);
    color: #fff;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
    transition: background 0.15s, opacity 0.15s, box-shadow 0.15s;
  }

  .export-btn:hover:not(:disabled) {
    background: var(--color-accent-hover);
    box-shadow: 0 2px 8px rgba(92, 124, 250, 0.3);
  }

  .export-btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* Enrich & Export button — teal/green to visually distinguish from raw export */
  .enrich-btn {
    background: #2f9e44; /* deep green — signals "cleaned/processed" */
  }

  .enrich-btn:hover:not(:disabled) {
    background: #37b24d;
    box-shadow: 0 2px 8px rgba(47, 158, 68, 0.35);
  }

  /* Inline spinner inside the export button while loading */
  .btn-spinner {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: #fff;
    animation: spin 0.7s linear infinite;
    flex-shrink: 0;
  }

  /* -------------------------------------------------------------------------
     Status messages
     ------------------------------------------------------------------------- */
  .status-area {
    display: flex;
    align-items: flex-start;
    gap: 7px;
    font-size: 12px;
    border-radius: var(--radius-sm);
    padding: 7px 10px;
    line-height: 1.4;
  }

  .status-area svg {
    flex-shrink: 0;
    margin-top: 1px;
  }

  .status-error-msg {
    background: rgba(250, 82, 82, 0.1);
    color: var(--color-error);
    border: 1px solid rgba(250, 82, 82, 0.25);
  }

  .status-success-msg {
    background: rgba(64, 192, 87, 0.1);
    color: var(--color-success);
    border: 1px solid rgba(64, 192, 87, 0.2);
  }

  /* -------------------------------------------------------------------------
     Animations
     ------------------------------------------------------------------------- */
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
