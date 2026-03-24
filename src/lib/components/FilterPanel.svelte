<!--
  FilterPanel.svelte
  ------------------
  A self-contained filter configuration UI for a single .evtx file.

  This component renders all the filter controls and manages local UI state
  (such as which date-filter mode is active). It does NOT hold or own the
  FilterConfig data — that lives in the parent (FileCard). Changes are
  propagated upward via two-way binding and a 'change' event.

  Props:
    filters  (FilterConfig, bindable) — the active filter configuration
    on:change                         — dispatched after any filter field changes

  Internal state:
    dateMode: 'relative' | 'range'  — which date filter UI to show

  Date filter logic:
    - 'relative' mode: 5 pill buttons (1/3/7/14/30 days). Clicking a selected
      pill deselects it. Setting a relative value clears date_from and date_to.
    - 'range' mode: two datetime-local inputs mapped to date_from / date_to.
      Setting range values clears relative_days.
    - Switching modes clears the currently active filter for the other mode.

  Layout: CSS grid, 2 columns for text inputs, custom field spans full width.
-->

<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { FilterConfig } from '../types';

  // -------------------------------------------------------------------------
  // Props
  // -------------------------------------------------------------------------

  /** The active filter configuration — bindable so parent stays in sync */
  export let filters: FilterConfig;

  // -------------------------------------------------------------------------
  // Event dispatcher
  // -------------------------------------------------------------------------

  /**
   * Dispatch a 'change' event whenever any filter field is mutated.
   * The parent (FileCard) listens to this to know when to re-render status.
   */
  const dispatch = createEventDispatcher<{
    change: FilterConfig;
  }>();

  // -------------------------------------------------------------------------
  // Local UI state
  // -------------------------------------------------------------------------

  /**
   * Controls which date filter UI section is displayed.
   * Defaults to 'relative' since that's the most common quick-filter pattern.
   * Switches to 'range' when the user clicks the "Date Range" tab.
   */
  let dateMode: 'relative' | 'range' =
    filters.date_from || filters.date_to ? 'range' : 'relative';

  // The relative_days pill options available to the user
  const RELATIVE_OPTIONS = [1, 3, 7, 14, 30] as const;

  // -------------------------------------------------------------------------
  // Helper: notify parent of filter changes
  // -------------------------------------------------------------------------

  /**
   * Call this after every mutation to filters to keep the parent in sync.
   * The parent binds to `filters` so mutations to the object are reflected
   * automatically in Svelte's reactivity, but we also dispatch an event so
   * the parent can react (e.g. reset status to 'idle').
   */
  function notify() {
    dispatch('change', filters);
  }

  // -------------------------------------------------------------------------
  // Date filter handlers
  // -------------------------------------------------------------------------

  /**
   * Switch between relative and range date modes.
   * Clears the other mode's values to prevent conflicting filters.
   */
  function setDateMode(mode: 'relative' | 'range') {
    dateMode = mode;
    if (mode === 'relative') {
      // Clear range values — they'd conflict with relative_days on the backend
      filters.date_from = null;
      filters.date_to = null;
    } else {
      // Clear relative value — range takes precedence when switching back
      filters.relative_days = null;
    }
    notify();
  }

  /**
   * Handle clicking a relative-days pill button.
   * If the clicked pill is already active, deselect it (toggle off).
   * Otherwise, select it and clear any date range values.
   */
  function toggleRelativeDays(days: number) {
    if (filters.relative_days === days) {
      // Deselect: clicking an already-active pill turns it off
      filters.relative_days = null;
    } else {
      filters.relative_days = days;
      // Mutually exclusive with date range
      filters.date_from = null;
      filters.date_to = null;
    }
    notify();
  }

  /**
   * Handle changes to the date_from datetime-local input.
   * Converts the HTML input value ("YYYY-MM-DDTHH:mm") to ISO string,
   * or sets null if the input is cleared.
   */
  function handleDateFrom(event: Event) {
    const value = (event.target as HTMLInputElement).value;
    filters.date_from = value ? value : null;
    // Clear relative when a range value is set
    if (filters.date_from) filters.relative_days = null;
    notify();
  }

  /**
   * Handle changes to the date_to datetime-local input.
   */
  function handleDateTo(event: Event) {
    const value = (event.target as HTMLInputElement).value;
    filters.date_to = value ? value : null;
    if (filters.date_to) filters.relative_days = null;
    notify();
  }

  // -------------------------------------------------------------------------
  // Text field handlers
  // -------------------------------------------------------------------------

  /** Update hostname filter and notify parent */
  function handleHostname(event: Event) {
    const value = (event.target as HTMLInputElement).value.trim();
    filters.hostname = value || null;
    notify();
  }

  /** Update username filter and notify parent */
  function handleUsername(event: Event) {
    const value = (event.target as HTMLInputElement).value.trim();
    filters.username = value || null;
    notify();
  }

  /** Update process_id filter and notify parent */
  function handleProcessId(event: Event) {
    const value = (event.target as HTMLInputElement).value.trim();
    filters.process_id = value || null;
    notify();
  }

  /** Update ip_address filter and notify parent */
  function handleIpAddress(event: Event) {
    const value = (event.target as HTMLInputElement).value.trim();
    filters.ip_address = value || null;
    notify();
  }

  /** Update custom_field_name and notify parent */
  function handleCustomFieldName(event: Event) {
    const value = (event.target as HTMLInputElement).value.trim();
    filters.custom_field_name = value || null;
    notify();
  }

  /** Update custom_field_value and notify parent */
  function handleCustomFieldValue(event: Event) {
    const value = (event.target as HTMLInputElement).value.trim();
    filters.custom_field_value = value || null;
    notify();
  }

  /** Toggle LLM optimization mode */
  function handleLlmOptimized(event: Event) {
    filters.llm_optimized = (event.target as HTMLInputElement).checked;
    notify();
  }

  // -------------------------------------------------------------------------
  // Reactive helpers for template bindings
  // -------------------------------------------------------------------------

  /**
   * Convert a nullable ISO string to the format expected by datetime-local inputs
   * ("YYYY-MM-DDTHH:mm"). Returns empty string if null (clears the input).
   */
  function toDatetimeLocal(iso: string | null): string {
    if (!iso) return '';
    // datetime-local doesn't support seconds or timezone — truncate to minutes
    return iso.slice(0, 16);
  }
</script>

<!-- =========================================================================
     Template
     ========================================================================= -->

<div class="filter-panel">

  <!-- -----------------------------------------------------------------------
       Section 1: Date Filter
       ----------------------------------------------------------------------- -->
  <div class="filter-section date-section">
    <div class="section-header">
      <span class="section-label">Date Filter</span>

      <!-- Mode toggle tabs: "Relative" vs "Date Range" -->
      <div class="mode-tabs" role="tablist" aria-label="Date filter mode">
        <button
          class="mode-tab"
          class:active={dateMode === 'relative'}
          role="tab"
          aria-selected={dateMode === 'relative'}
          on:click={() => setDateMode('relative')}
        >
          Relative
        </button>
        <button
          class="mode-tab"
          class:active={dateMode === 'range'}
          role="tab"
          aria-selected={dateMode === 'range'}
          on:click={() => setDateMode('range')}
        >
          Date Range
        </button>
      </div>
    </div>

    {#if dateMode === 'relative'}
      <!-- Relative mode: pill buttons for quick time-range selection -->
      <div class="pill-group" role="group" aria-label="Relative date filter">
        {#each RELATIVE_OPTIONS as days}
          <button
            class="pill"
            class:active={filters.relative_days === days}
            aria-pressed={filters.relative_days === days}
            on:click={() => toggleRelativeDays(days)}
          >
            {days === 1 ? '1 day' : `${days} days`}
          </button>
        {/each}
      </div>
    {:else}
      <!-- Range mode: two datetime inputs for explicit date boundaries -->
      <div class="date-range-grid">
        <div class="field">
          <label class="field-label" for="date-from">From</label>
          <input
            id="date-from"
            class="input"
            type="datetime-local"
            value={toDatetimeLocal(filters.date_from)}
            on:change={handleDateFrom}
          />
        </div>
        <div class="field">
          <label class="field-label" for="date-to">To</label>
          <input
            id="date-to"
            class="input"
            type="datetime-local"
            value={toDatetimeLocal(filters.date_to)}
            on:change={handleDateTo}
          />
        </div>
      </div>
    {/if}
  </div>

  <!-- -----------------------------------------------------------------------
       Section 2: Standard text filters (2-column grid)
       ----------------------------------------------------------------------- -->
  <div class="filter-grid">

    <!-- Hostname -->
    <div class="field">
      <label class="field-label" for="filter-hostname">Hostname</label>
      <input
        id="filter-hostname"
        class="input"
        type="text"
        placeholder="Filter by hostname…"
        value={filters.hostname ?? ''}
        on:input={handleHostname}
      />
    </div>

    <!-- Username -->
    <div class="field">
      <label class="field-label" for="filter-username">Username</label>
      <input
        id="filter-username"
        class="input"
        type="text"
        placeholder="Filter by username…"
        value={filters.username ?? ''}
        on:input={handleUsername}
      />
    </div>

    <!-- Process ID -->
    <div class="field">
      <label class="field-label" for="filter-pid">Process ID</label>
      <input
        id="filter-pid"
        class="input"
        type="text"
        placeholder="Filter by process ID…"
        value={filters.process_id ?? ''}
        on:input={handleProcessId}
      />
    </div>

    <!-- IP Address -->
    <div class="field">
      <label class="field-label" for="filter-ip">IP Address</label>
      <input
        id="filter-ip"
        class="input"
        type="text"
        placeholder="Filter by IP address…"
        value={filters.ip_address ?? ''}
        on:input={handleIpAddress}
      />
    </div>

  </div>

  <!-- -----------------------------------------------------------------------
       Section 3: Custom EventData field filter (spans full width)
       ----------------------------------------------------------------------- -->
  <div class="filter-section custom-field-section">
    <span class="section-label">Custom EventData Field</span>
    <p class="section-hint">
      Match events where this EventData field exists — and optionally where its value matches.
    </p>
    <div class="custom-field-grid">
      <div class="field">
        <label class="field-label" for="filter-custom-name">Field name</label>
        <input
          id="filter-custom-name"
          class="input"
          type="text"
          placeholder="e.g. SubjectLogonId"
          value={filters.custom_field_name ?? ''}
          on:input={handleCustomFieldName}
        />
      </div>
      <div class="field">
        <label class="field-label" for="filter-custom-value">
          Value <span class="optional-tag">(optional)</span>
        </label>
        <input
          id="filter-custom-value"
          class="input"
          type="text"
          placeholder="Leave empty to check existence only"
          value={filters.custom_field_value ?? ''}
          on:input={handleCustomFieldValue}
        />
      </div>
    </div>
  </div>

  <!-- -----------------------------------------------------------------------
       Section 4: LLM Optimization toggle
       ----------------------------------------------------------------------- -->
  <div class="filter-section llm-section">
    <label class="llm-toggle" title="Aggressively trim noise and shorten strings to save LLM tokens">
      <input
        type="checkbox"
        checked={filters.llm_optimized}
        on:change={handleLlmOptimized}
      />
      <div class="llm-content">
        <span class="llm-label">Optimize for LLM Analysis</span>
        <span class="llm-hint">Filters noisy Event IDs, shortens paths, and drops empty columns.</span>
      </div>
    </label>
  </div>

</div>

<!-- =========================================================================
     Styles
     ========================================================================= -->

<style>
  /* Root container — no background, the parent card provides it */
  .filter-panel {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  /* -------------------------------------------------------------------------
     Filter section wrapper
     ------------------------------------------------------------------------- */
  .filter-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  /* Header row inside date section: label + mode tabs side by side */
  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  /* Small uppercase label for section groups */
  .section-label {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--color-text-muted);
  }

  /* Subtle helper text below section labels */
  .section-hint {
    font-size: 11px;
    color: var(--color-text-dim);
    margin: 0;
    line-height: 1.4;
  }

  /* -------------------------------------------------------------------------
     Mode toggle tabs (Relative / Date Range)
     ------------------------------------------------------------------------- */
  .mode-tabs {
    display: flex;
    gap: 2px;
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-sm);
    padding: 2px;
  }

  .mode-tab {
    font-size: 11px;
    font-weight: 500;
    padding: 3px 10px;
    border-radius: 3px;
    border: none;
    background: transparent;
    color: var(--color-text-muted);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }

  .mode-tab:hover {
    color: var(--color-text);
  }

  /* Active tab gets accent background */
  .mode-tab.active {
    background: var(--color-accent);
    color: #fff;
  }

  /* -------------------------------------------------------------------------
     Relative date pill buttons
     ------------------------------------------------------------------------- */
  .pill-group {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .pill {
    font-size: 12px;
    font-weight: 500;
    padding: 4px 12px;
    border-radius: 20px;
    border: 1px solid var(--color-border);
    background: var(--color-bg);
    color: var(--color-text-muted);
    cursor: pointer;
    transition: border-color 0.15s, color 0.15s, background 0.15s;
  }

  .pill:hover {
    border-color: var(--color-accent);
    color: var(--color-text);
  }

  /* Active pill: filled with accent color */
  .pill.active {
    background: var(--color-accent);
    border-color: var(--color-accent);
    color: #fff;
  }

  /* -------------------------------------------------------------------------
     Date range grid: two datetime inputs side by side
     ------------------------------------------------------------------------- */
  .date-range-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }

  /* -------------------------------------------------------------------------
     Standard filter grid: 2 columns for text inputs
     ------------------------------------------------------------------------- */
  .filter-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }

  /* -------------------------------------------------------------------------
     Custom field grid: two inputs side by side spanning full card width
     ------------------------------------------------------------------------- */
  .custom-field-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }

  /* -------------------------------------------------------------------------
     Individual field: label + input stacked vertically
     ------------------------------------------------------------------------- */
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  /* Small label above each input */
  .field-label {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-text-muted);
    display: flex;
    align-items: center;
    gap: 4px;
  }

  /* "(optional)" inline tag in custom field label */
  .optional-tag {
    font-weight: 400;
    color: var(--color-text-dim);
    font-style: italic;
  }

  /* -------------------------------------------------------------------------
     Text / datetime inputs
     ------------------------------------------------------------------------- */
  .input {
    width: 100%;
    box-sizing: border-box;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-border);
    background: var(--color-bg);
    color: var(--color-text);
    font-size: 12px;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }

  .input:hover {
    border-color: #3d4260;
  }

  .input:focus {
    border-color: var(--color-accent);
    box-shadow: 0 0 0 2px rgba(92, 124, 250, 0.18);
  }

  /* Fix datetime-local calendar icon coloring in dark mode */
  .input[type='datetime-local']::-webkit-calendar-picker-indicator {
    filter: invert(0.7);
    cursor: pointer;
  }

  /* Placeholder text color */
  .input::placeholder {
    color: var(--color-text-dim);
  }

  /* -------------------------------------------------------------------------
     LLM Optimization toggle
     ------------------------------------------------------------------------- */
  .llm-section {
    border-top: 1px dashed var(--color-border);
    padding-top: 12px;
    margin-top: 4px;
  }

  .llm-toggle {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    cursor: pointer;
    user-select: none;
    background: rgba(92, 124, 250, 0.05);
    border: 1px solid rgba(92, 124, 250, 0.15);
    padding: 10px;
    border-radius: var(--radius-sm);
    transition: background 0.15s, border-color 0.15s;
  }

  .llm-toggle:hover {
    background: rgba(92, 124, 250, 0.08);
    border-color: rgba(92, 124, 250, 0.3);
  }

  .llm-toggle input {
    margin-top: 3px;
    width: 14px;
    height: 14px;
    cursor: pointer;
  }

  .llm-content {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .llm-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--color-accent);
  }

  .llm-hint {
    font-size: 11px;
    color: var(--color-text-dim);
  }
</style>
