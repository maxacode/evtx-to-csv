<!--
  App.svelte
  ----------
  Root application component for EventViewer → CSV.

  This is the top-level UI shell. It owns global state, the toolbar, the
  empty-state view, the file card list, and drag-and-drop handling.

  State managed here:
    files             — array of FileEntry objects, one per loaded .evtx file
    runEnrichment     — global toggle: whether to generate _report.md on export
    suspiciousContent — full text of suspicious-commands.txt (used by enrichment)
    loadingSuspicious — true while the app is trying to auto-load the file

  On mount behavior:
    1. Tries to load suspicious-commands.txt from multiple paths automatically:
       - Tauri Resource directory (bundled with the app)
       - AppLocalData directory (user data folder)
       - Relative path './suspicious-commands.txt' (dev working directory)
    2. Sets up a window-level drag-and-drop listener for .evtx files
    3. Both listeners are cleaned up in onDestroy

  Adding files:
    - Toolbar "Add Files" button → native file picker (multi-select, .evtx only)
    - Drag-and-drop .evtx files onto the app window

  Enrichment note:
    The "Run Enrichment" toggle only has effect if suspiciousContent is loaded.
    Each FileCard shows a warning if enrichment is on but the file isn't loaded.

  Layout:
    ┌─────────────────────────────────────┐
    │  Header (title + subtitle)          │
    ├─────────────────────────────────────┤
    │  Toolbar (Add Files | Enrichment |  │
    │           Load suspicious…)         │
    ├─────────────────────────────────────┤
    │  File cards grid  (or empty state)  │
    └─────────────────────────────────────┘
-->

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import FileCard from './lib/components/FileCard.svelte';
  import { openEvtxFiles, reloadSignatures, getSignaturesInfo } from './lib/tauri-api';
  import { defaultFilters } from './lib/types';
  import type { FileEntry } from './lib/types';

  // -------------------------------------------------------------------------
  // Application state
  // -------------------------------------------------------------------------

  /** All loaded .evtx files, each represented as a FileEntry */
  let files: FileEntry[] = [];

  /**
   * Global enrichment toggle.
   * When true, each file's export will also produce a _report.md analysis file.
   * Defaults to true — analysts usually want the enrichment report.
   */
  let runEnrichment: boolean = true;

  /** Info about the currently-loaded signatures.json (rule count + file path) */
  let signaturesInfo: { count: number; path: string } = { count: 0, path: '' };

  /** True while a signatures reload is in progress */
  let refreshingSignatures = false;

  /** Toast message shown briefly after a successful reload */
  let refreshToast: string | null = null;
  let refreshToastTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * Whether a drag-over is currently in progress on the window.
   * Used to show a visual overlay/indication that drop is supported.
   */
  let isDragging: boolean = false;

  // -------------------------------------------------------------------------
  // Lifecycle: onMount
  // -------------------------------------------------------------------------

  // References to event listeners so we can remove them in onDestroy
  let cleanupDragOver: (() => void) | null = null;
  let cleanupDragLeave: (() => void) | null = null;
  let cleanupDrop: (() => void) | null = null;

  onMount(async () => {
    // Get current signature info from the Rust AppState (populated during app startup)
    signaturesInfo = await getSignaturesInfo();

    // 2. Set up drag-and-drop file loading
    setupDragAndDrop();
  });

  onDestroy(() => {
    // Clean up window-level event listeners to prevent memory leaks
    cleanupDragOver?.();
    cleanupDragLeave?.();
    cleanupDrop?.();
  });

  /**
   * Reload signatures.json from disk via the Rust reload_signatures command.
   * Updates the displayed rule count and file path without restarting the app.
   */
  async function handleRefreshSignatures(): Promise<void> {
    refreshingSignatures = true;
    try {
      signaturesInfo = await reloadSignatures();
      // Show a brief success toast
      refreshToast = `✓ Loaded ${signaturesInfo.count} rules`;
      if (refreshToastTimer) clearTimeout(refreshToastTimer);
      refreshToastTimer = setTimeout(() => { refreshToast = null; }, 3000);
    } catch (err) {
      refreshToast = `⚠ Reload failed: ${err instanceof Error ? err.message : String(err)}`;
      if (refreshToastTimer) clearTimeout(refreshToastTimer);
      refreshToastTimer = setTimeout(() => { refreshToast = null; }, 5000);
    } finally {
      refreshingSignatures = false;
    }
  }

  // -------------------------------------------------------------------------
  // Adding files
  // -------------------------------------------------------------------------

  /**
   * Opens a multi-select file picker filtered to .evtx files.
   * Creates a FileEntry for each selected path and appends to the files array.
   * Deduplicates: won't add a file that's already loaded (by path).
   */
  async function handleAddFiles(): Promise<void> {
    const paths = await openEvtxFiles();

    if (paths.length === 0) return; // Dialog was cancelled

    // Create a Set of already-loaded paths for O(1) dedup check
    const existingPaths = new Set(files.map((f) => f.path));

    const newEntries: FileEntry[] = paths
      .filter((p) => !existingPaths.has(p)) // Skip duplicates
      .map((p) => createFileEntry(p));

    files = [...files, ...newEntries];
  }

  /**
   * Factory: create a new FileEntry from a filesystem path.
   * Extracts the filename from the path using the last path separator.
   */
  function createFileEntry(path: string): FileEntry {
    // Extract just the filename from the full path
    // Works on both Windows (\) and macOS/Linux (/)
    const name = path.split(/[\\/]/).pop() ?? path;

    // Default outputName = filename without .evtx extension
    const outputName = name.replace(/\.evtx$/i, '');

    return {
      id: crypto.randomUUID(),
      path,
      name,
      filters: defaultFilters(),
      outputName,
      status: 'idle',
      recordCount: 0,
      errorMessage: null,
    };
  }

  // -------------------------------------------------------------------------
  // FileCard event handlers
  // -------------------------------------------------------------------------

  /**
   * Handle the 'remove' event from a FileCard.
   * Removes the entry with matching ID from the files array.
   */
  function handleRemoveFile(id: string): void {
    files = files.filter((f) => f.id !== id);
  }

  /**
   * Handle the 'update' event from a FileCard.
   * Replaces the matching entry in the files array with the updated version.
   */
  function handleUpdateFile(updated: FileEntry): void {
    files = files.map((f) => (f.id === updated.id ? updated : f));
  }

  // -------------------------------------------------------------------------
  // Drag-and-drop
  // -------------------------------------------------------------------------

  /**
   * Set up window-level drag-and-drop listeners.
   * Allows users to drag .evtx files directly onto the app window.
   *
   * Uses the HTML5 DataTransfer API (not Tauri's custom drag event) since
   * Tauri's WebView bridges native file drops through the standard DOM events.
   */
  function setupDragAndDrop(): void {
    function onDragOver(e: DragEvent) {
      e.preventDefault(); // Required to allow drop
      // Check that at least one dragged item looks like a file
      if (e.dataTransfer?.types.includes('Files')) {
        isDragging = true;
        if (e.dataTransfer) {
          e.dataTransfer.dropEffect = 'copy';
        }
      }
    }

    function onDragLeave(e: DragEvent) {
      // Only clear dragging state when leaving the window entirely
      // (relatedTarget is null when leaving the window)
      if (!e.relatedTarget) {
        isDragging = false;
      }
    }

    function onDrop(e: DragEvent) {
      e.preventDefault();
      isDragging = false;

      if (!e.dataTransfer) return;

      // Extract .evtx file paths from the drop event
      const droppedPaths: string[] = [];
      for (const file of Array.from(e.dataTransfer.files)) {
        // Filter to only .evtx files
        if (file.name.toLowerCase().endsWith('.evtx')) {
          // In Tauri's WebView, file.path is the native filesystem path
          // The standard File.path property exists in Tauri but not in browsers
          const filePath = (file as File & { path?: string }).path ?? file.name;
          droppedPaths.push(filePath);
        }
      }

      if (droppedPaths.length === 0) return;

      // Deduplicate and add to the files list
      const existingPaths = new Set(files.map((f) => f.path));
      const newEntries = droppedPaths
        .filter((p) => !existingPaths.has(p))
        .map((p) => createFileEntry(p));

      if (newEntries.length > 0) {
        files = [...files, ...newEntries];
      }
    }

    window.addEventListener('dragover', onDragOver);
    window.addEventListener('dragleave', onDragLeave);
    window.addEventListener('drop', onDrop);

    // Store cleanup functions for onDestroy
    cleanupDragOver = () => window.removeEventListener('dragover', onDragOver);
    cleanupDragLeave = () => window.removeEventListener('dragleave', onDragLeave);
    cleanupDrop = () => window.removeEventListener('drop', onDrop);
  }

  // -------------------------------------------------------------------------
  // Computed values
  // -------------------------------------------------------------------------

  /** Total number of loaded files that have been successfully exported */
  $: exportedCount = files.filter((f) => f.status === 'done').length;
</script>

<!-- =========================================================================
     Template
     ========================================================================= -->

<!-- Drop overlay — visible feedback when user drags files onto the window -->
{#if isDragging}
  <div class="drop-overlay" aria-hidden="true">
    <div class="drop-overlay-inner">
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M24 4v28M14 22l10 10 10-10" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M8 36v4a2 2 0 002 2h28a2 2 0 002-2v-4" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
      </svg>
      <span>Drop .evtx files to load</span>
    </div>
  </div>
{/if}

<div class="app-shell">

  <!-- -----------------------------------------------------------------------
       Header
       ----------------------------------------------------------------------- -->
  <header class="app-header">
    <div class="header-content">
      <!-- App title and subtitle -->
      <div class="app-title-group">
        <h1 class="app-title">
          <!-- Inline shield/log icon -->
          <span class="title-icon" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M11 2L3 5.5v6C3 16.1 6.8 19.9 11 21c4.2-1.1 8-4.9 8-9.5v-6L11 2z"
                    fill="rgba(92,124,250,0.18)" stroke="var(--color-accent)" stroke-width="1.5" stroke-linejoin="round"/>
              <path d="M7.5 11l2.5 2.5 4.5-4.5" stroke="var(--color-accent)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </span>
          evtx-to-csv
        </h1>
        <p class="app-subtitle">Incident Response Tool</p>
      </div>

      <!-- Header right: exported count badge if any files are done -->
      {#if exportedCount > 0}
        <span class="exported-badge">
          {exportedCount} exported
        </span>
      {/if}
    </div>
  </header>

  <!-- -----------------------------------------------------------------------
       Toolbar
       ----------------------------------------------------------------------- -->
  <div class="toolbar">
    <div class="toolbar-left">
      <!-- Add Files button -->
      <button class="btn btn-primary" on:click={handleAddFiles}>
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <path d="M7 1v12M1 7h12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
        Add Files
      </button>

      <!-- Divider -->
      <div class="toolbar-divider" aria-hidden="true"></div>

      <!-- Enrichment toggle -->
      <label class="enrichment-toggle" title="Generate an enrichment analysis report alongside the CSV export">
        <span class="toggle-track" class:on={runEnrichment}>
          <input
            type="checkbox"
            bind:checked={runEnrichment}
            class="sr-only"
            aria-label="Run enrichment report"
          />
          <span class="toggle-thumb"></span>
        </span>
        <span class="toggle-label">
          Run report.md
        </span>
      </label>
    </div>

    <!-- Signatures status + Refresh button -->
    <div class="toolbar-right">
      {#if refreshingSignatures && signaturesInfo.count === 0}
        <span class="sig-status sig-loading">
          <span class="btn-mini-spinner" aria-hidden="true"></span>
          Loading…
        </span>
      {:else}
        <!-- Signature count pill — hover shows the file path -->
        <span
          class="sig-status sig-ok"
          title={signaturesInfo.path
            ? `${signaturesInfo.count} rules loaded from:\n${signaturesInfo.path}\n\nEdit this file and click Refresh to apply changes.`
            : `${signaturesInfo.count} built-in enrichment rules active`}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
            <circle cx="5" cy="5" r="4" fill="var(--color-success)" opacity="0.25"/>
            <path d="M2.5 5l2 2 3-3" stroke="var(--color-success)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          {signaturesInfo.count} rules active
        </span>

        <!-- Refresh button — reloads signatures.json without app restart -->
        <button
          class="btn btn-secondary btn-refresh"
          on:click={handleRefreshSignatures}
          disabled={refreshingSignatures}
          title="Reload signatures.json from disk (no restart needed)"
        >
          {#if refreshingSignatures}
            <span class="btn-mini-spinner" aria-hidden="true"></span>
            Refreshing…
          {:else}
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <path d="M10 6A4 4 0 112 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              <path d="M10 3v3H7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            Refresh Rules
          {/if}
        </button>

        <!-- Toast shown after reload -->
        {#if refreshToast}
          <span class="refresh-toast" class:toast-error={refreshToast.startsWith('⚠')}>
            {refreshToast}
          </span>
        {/if}
      {/if}
    </div>
  </div>

  <!-- -----------------------------------------------------------------------
       Main content area
       ----------------------------------------------------------------------- -->
  <main class="main-content">

    {#if files.length === 0}
      <!-- Empty state: shown when no files are loaded -->
      <div class="empty-state">
        <!-- Large drop/upload illustration -->
        <div class="empty-icon" aria-hidden="true">
          <svg width="64" height="64" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
            <!-- Outer circle -->
            <circle cx="32" cy="32" r="30" stroke="var(--color-border)" stroke-width="1.5"/>
            <!-- Document shape -->
            <path d="M20 16h16l8 8v24a2 2 0 01-2 2H20a2 2 0 01-2-2V18a2 2 0 012-2z"
                  stroke="var(--color-text-dim)" stroke-width="1.5" stroke-linejoin="round"/>
            <!-- Dog-ear fold -->
            <path d="M36 16v8h8" stroke="var(--color-text-dim)" stroke-width="1.5" stroke-linejoin="round"/>
            <!-- Lines suggesting content -->
            <path d="M24 30h16M24 35h16M24 40h10" stroke="var(--color-text-dim)" stroke-width="1.4" stroke-linecap="round"/>
            <!-- Down arrow -->
            <path d="M32 46v6M29 49l3 3 3-3" stroke="var(--color-accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.5"/>
          </svg>
        </div>

        <h2 class="empty-title">No files loaded</h2>
        <p class="empty-description">
          Click <strong>Add Files</strong> to open Windows Event Log (.evtx) files,
          or drag and drop them here.
        </p>

        <!-- CTA button duplicated in empty state for discoverability -->
        <button class="btn btn-primary btn-lg" on:click={handleAddFiles}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M8 2v12M2 8h12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
          Add Files
        </button>

        <p class="empty-hint">Supported format: .evtx (Windows XML Event Log)</p>
      </div>

    {:else}
      <!-- File cards grid — responsive: 1 column on narrow, 2 columns on wide viewports -->
      <div class="file-grid">
        {#each files as entry (entry.id)}
          <FileCard
            bind:entry
            {runEnrichment}
            on:remove={() => handleRemoveFile(entry.id)}
            on:update={(e) => handleUpdateFile(e.detail)}
          />
        {/each}
      </div>
    {/if}

  </main>

  <!-- -----------------------------------------------------------------------
       Footer
       ----------------------------------------------------------------------- -->
  <footer class="app-footer">
    <span class="footer-text">
      evtx-to-csv &mdash; Incident Response Tool
    </span>
    {#if files.length > 0}
      <span class="footer-count">
        {files.length} file{files.length !== 1 ? 's' : ''} loaded
      </span>
    {/if}
  </footer>

</div>

<!-- =========================================================================
     Styles
     ========================================================================= -->

<style>
  /* -------------------------------------------------------------------------
     App shell layout
     Flex column that fills the full viewport height.
     ------------------------------------------------------------------------- */
  .app-shell {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--color-bg);
  }

  /* -------------------------------------------------------------------------
     Drop overlay — full-screen indicator when dragging files
     ------------------------------------------------------------------------- */
  .drop-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    background: rgba(15, 17, 23, 0.88);
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: none; /* Allows the underlying drop event to fire */
    border: 3px dashed var(--color-accent);
    border-radius: var(--radius);
    margin: 8px;
  }

  .drop-overlay-inner {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    color: var(--color-accent);
    font-size: 18px;
    font-weight: 600;
  }

  /* -------------------------------------------------------------------------
     Header
     ------------------------------------------------------------------------- */
  .app-header {
    background: var(--color-bg-card);
    border-bottom: 1px solid var(--color-border);
    padding: 0 24px;
    flex-shrink: 0;
  }

  .header-content {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 0;
    max-width: 1200px;
    margin: 0 auto;
    width: 100%;
  }

  .app-title-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .app-title {
    font-size: 18px;
    font-weight: 700;
    color: var(--color-text);
    display: flex;
    align-items: center;
    gap: 10px;
    letter-spacing: -0.01em;
  }

  .title-icon {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }

  .app-subtitle {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-text-muted);
    letter-spacing: 0.05em;
    text-transform: uppercase;
    padding-left: 32px; /* Align under title text, past the icon */
  }

  /* Badge showing count of files already exported in this session */
  .exported-badge {
    font-size: 12px;
    font-weight: 600;
    padding: 4px 12px;
    border-radius: 20px;
    background: rgba(64, 192, 87, 0.12);
    color: var(--color-success);
    border: 1px solid rgba(64, 192, 87, 0.25);
  }

  /* -------------------------------------------------------------------------
     Toolbar
     ------------------------------------------------------------------------- */
  .toolbar {
    background: var(--color-bg-card);
    border-bottom: 1px solid var(--color-border);
    padding: 0 24px;
    flex-shrink: 0;
  }

  /* Inner row: uses flex with space-between to push right items to the right */
  .toolbar > *,
  .toolbar-left,
  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 24px;
    max-width: 1200px;
    margin: 0 auto;
    width: 100%;
    /* Reset the max-width trick — toolbar should span full width */
    max-width: none;
  }

  .toolbar-divider {
    width: 1px;
    height: 20px;
    background: var(--color-border);
    flex-shrink: 0;
  }

  /* -------------------------------------------------------------------------
     Buttons
     ------------------------------------------------------------------------- */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 14px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    transition: background 0.15s, opacity 0.15s, box-shadow 0.15s;
    white-space: nowrap;
  }

  .btn-primary {
    background: var(--color-accent);
    color: #fff;
  }

  .btn-primary:hover {
    background: var(--color-accent-hover);
    box-shadow: 0 2px 8px rgba(92, 124, 250, 0.35);
  }

  .btn-secondary {
    background: var(--color-bg-elevated);
    color: var(--color-text-muted);
    border: 1px solid var(--color-border);
  }

  .btn-secondary:hover {
    color: var(--color-text);
    border-color: #3d4260;
    background: #272b3f;
  }

  /* Larger variant for the empty state CTA */
  .btn-lg {
    padding: 10px 20px;
    font-size: 14px;
  }

  /* Tiny spinner inside the "Loading…" secondary button */
  .btn-mini-spinner {
    width: 11px;
    height: 11px;
    border-radius: 50%;
    border: 1.5px solid rgba(134, 142, 150, 0.4);
    border-top-color: var(--color-text-muted);
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }

  /* -------------------------------------------------------------------------
     Enrichment toggle
     ------------------------------------------------------------------------- */
  .enrichment-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    user-select: none;
  }

  /* The toggle track (pill-shaped background) */
  .toggle-track {
    position: relative;
    width: 32px;
    height: 18px;
    background: var(--color-bg-elevated);
    border: 1px solid var(--color-border);
    border-radius: 9px;
    transition: background 0.2s, border-color 0.2s;
    flex-shrink: 0;
  }

  /* Active state: fill with accent color */
  .toggle-track.on {
    background: var(--color-accent);
    border-color: var(--color-accent);
  }

  /* The sliding thumb */
  .toggle-thumb {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 12px;
    height: 12px;
    background: #fff;
    border-radius: 50%;
    transition: transform 0.2s;
    pointer-events: none;
  }

  /* Slide thumb to the right when on */
  .toggle-track.on .toggle-thumb {
    transform: translateX(14px);
  }

  .toggle-label {
    font-size: 13px;
    font-weight: 500;
    color: var(--color-text-muted);
    display: flex;
    align-items: center;
    gap: 5px;
  }

  /* -------------------------------------------------------------------------
     Signatures status pill (right side of toolbar)
     ------------------------------------------------------------------------- */
  .sig-status {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    font-weight: 500;
    padding: 4px 10px;
    border-radius: 20px;
  }

  .sig-loading {
    color: var(--color-text-muted);
  }

  .sig-ok {
    color: var(--color-success);
    background: rgba(64, 192, 87, 0.08);
    border: 1px solid rgba(64, 192, 87, 0.2);
  }

  /* Refresh button — compact secondary style */
  .btn-refresh {
    padding: 4px 10px;
    font-size: 12px;
  }

  /* Toast that fades in after a successful/failed reload */
  .refresh-toast {
    font-size: 12px;
    font-weight: 500;
    color: var(--color-success);
    animation: fadeIn 0.2s ease;
  }

  .refresh-toast.toast-error {
    color: var(--color-warning);
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* -------------------------------------------------------------------------
     Main content
     ------------------------------------------------------------------------- */
  .main-content {
    flex: 1;
    padding: 24px;
    overflow-y: auto;
  }

  /* -------------------------------------------------------------------------
     File cards grid
     Responsive: 1 column on narrow screens, 2 columns on wider screens.
     ------------------------------------------------------------------------- */
  .file-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 16px;
    max-width: 1200px;
    margin: 0 auto;
  }

  /* At 900px+ viewport width, switch to 2-column layout */
  @media (min-width: 900px) {
    .file-grid {
      grid-template-columns: 1fr 1fr;
    }
  }

  /* On very wide screens (1400px+), 3 columns for power users with many files */
  @media (min-width: 1400px) {
    .file-grid {
      grid-template-columns: repeat(3, 1fr);
    }
  }

  /* -------------------------------------------------------------------------
     Empty state
     ------------------------------------------------------------------------- */
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 80px 24px;
    gap: 16px;
    max-width: 480px;
    margin: 0 auto;
  }

  .empty-icon {
    opacity: 0.5;
    margin-bottom: 8px;
  }

  .empty-title {
    font-size: 20px;
    font-weight: 600;
    color: var(--color-text);
  }

  .empty-description {
    font-size: 14px;
    color: var(--color-text-muted);
    line-height: 1.6;
  }

  .empty-description strong {
    color: var(--color-text);
  }

  .empty-hint {
    font-size: 12px;
    color: var(--color-text-dim);
    margin-top: 4px;
  }

  /* -------------------------------------------------------------------------
     Footer
     ------------------------------------------------------------------------- */
  .app-footer {
    border-top: 1px solid var(--color-border);
    padding: 8px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }

  .footer-text {
    font-size: 11px;
    color: var(--color-text-dim);
  }

  .footer-count {
    font-size: 11px;
    color: var(--color-text-muted);
  }

  /* -------------------------------------------------------------------------
     Animations
     ------------------------------------------------------------------------- */
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  /* -------------------------------------------------------------------------
     Screen reader only utility (scoped to App)
     ------------------------------------------------------------------------- */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }
</style>
