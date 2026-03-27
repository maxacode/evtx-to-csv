# TODO: evtx-to-csv Improvements

A list of planned features, enhancements, and technical debt for the `evtx-to-csv` project.

## 🚀 High Priority (Core Functionality)

- [ ] **Asynchronous Processing & Progress Bars:** Transition long-running tasks like `.evtx` parsing and CSV exporting to an asynchronous model using Tauri events. Show real-time progress bars for each file card.
- [ ] **Cancellation Support:** Allow users to cancel an ongoing export or enrichment process for individual files.
- [ ] **Improved Error Handling:** Provide more descriptive error messages in the UI (e.g., if a file is locked, corrupted, or if permissions are missing).
- [ ] **Recursive Folder Support:** Allow users to drag-and-drop or select folders. Automatically find and load all `.evtx` files within the directory (optionally recursive).

## ✨ UI/UX Enhancements

- [ ] **Settings Page:** Implement a dedicated settings view to configure:
    - Default export directory.
    - Custom `signatures.json` path.
    - Default enrichment toggle state.
    - Theme selection (Dark/Light/System).
- [ ] **Session Persistence:** Save the list of loaded files and their filter configurations so they persist across application restarts.
- [ ] **Recently Used Files/Folders:** Add a "Recent" section to the file picker or toolbar for quick access.
- [ ] **Column Selection:** Allow users to toggle which CSV columns are exported instead of using a hardcoded IR-focused set.
- [ ] **In-App Log Viewer:** Add a basic preview window to inspect event records directly in the app before exporting, with highlighting for suspicious hits.

## 🔍 Enrichment & Analysis

- [ ] **Advanced Signatures:** Move beyond simple regex. Support multi-event correlation (e.g., Event ID 4624 followed by 4625) and stateful detections.
- [ ] **External API Integration:**
    - **VirusTotal:** Check command-line hashes or suspicious filenames.
            - But have it check only hashes/ips/domains that are not well known. Or have a local DB of google Microsoft/google hashes. 
    - **IPVoid/AbuseIPDB:** Automatically lookup external IP addresses found in logs.
    - **Whois:** Enrich domain information.
- [ ] **Custom Report Templates:** Allow users to provide their own Markdown templates for the `report.md` output.
- [ ] **Sigma Rule Support:** Explore converting or supporting Sigma rules for more standardized detection logic.

## ⚙️ Backend & Performance

- [ ] **Streaming Exports:** Implement streaming CSV writing to handle massive `.evtx` files (GBs+) without loading all matching records into memory.
- [ ] **Parallel Processing:** Ensure that multiple files are processed in parallel using a thread pool (e.g., `rayon`) for maximum performance on multi-core systems.
- [ ] **JSON/JSONL Export:** Add support for exporting records to JSON or JSONL formats for better integration with SIEMs or other analysis tools.
- [ ] **Automated Testing:**
    - Add Rust unit tests for the filter logic and enrichment engine.
    - Add Svelte component tests for the frontend.
    - Implement CI (GitHub Actions) to run tests and build artifacts.

## 📚 Documentation

- [ ] **User Guide:** Create a detailed user guide or Wiki explaining features, filters, and how to write effective signatures.
- [ ] **Signature Library:** Expand the default `signatures.json` with more community-contributed IR patterns.
- [ ] **Developer Docs:** Document the internal architecture and Tauri command API for future contributors.
