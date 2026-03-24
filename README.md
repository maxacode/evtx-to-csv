# evtx-to-csv

[version: 0.1.0] [tauri: v1] [rust] [svelte: 4] [license: MIT] [platform: macOS | Windows]

A high-performance desktop application for incident responders that parses Windows Event Log `.evtx` files, applies per-file filters, exports records to CSV, and runs an automated enrichment check against known-suspicious command patterns.

---

## Features

- **Multi-file loading** — add and manage multiple `.evtx` files in a single session; each file is processed independently
- **Quick Actions** — each file card includes buttons to **Open File** (in system default viewer) and **Open Folder** for rapid access to source logs
- **Per-file filter panel** — every loaded file has its own filter configuration:
  - Date range filter (absolute from/to datetime) or relative filter (last 1 / 3 / 7 / 14 / 30 days)
  - Hostname / computer name (case-insensitive partial match)
  - Username (matches `SubjectUserName` and `TargetUserName`)
  - Process ID
  - IP address (matches any IP-related EventData field)
  - Custom field filter — specify any arbitrary EventData field name, with an optional value to match against
- **CSV export** — each file is exported to an individually-named `.csv` file; output filename is editable per file
- **IR-focused CSV columns**:
  `timestamp`, `event_id`, `level`, `channel`, `computer`, `username`, `domain`, `target_username`, `target_domain`, `process_id`, `process_name`, `ip_address`, `port`, `logon_type`, `command_line`, `parent_process`, `workstation`, `auth_package` — plus every additional `EventData` field appended as extra columns so no data is lost
- **Incident Response enrichment** — scans event fields against regex patterns from `signatures.json` and generates a `report.md` alongside the CSV output; toggle with a checkbox (enabled by default)
- **Dark-themed UI** — designed for extended use during incident response engagements
- **Drag-and-drop** — drop `.evtx` files directly onto the window to load them
- **Cross-platform** — builds for macOS and Windows via Tauri

---

## Prerequisites

| Tool | Minimum Version |
|------|----------------|
| Rust | 1.70+ |
| Node.js | 18+ |
| npm | bundled with Node.js |

Install Rust via [rustup](https://rustup.rs/). Tauri also requires platform-specific dependencies — see the [Tauri v1 prerequisites guide](https://tauri.app/v1/guides/getting-started/prerequisites).

---

## Installation

```bash
git clone https://github.com/maksderevencha/evtx-to-csv.git
cd evtx-to-csv
npm install
```

---

## Development

Starts the Vite dev server and opens the Tauri window with hot-reload:

```bash
npm run tauri dev
```

---

## Build

Compiles the frontend, bundles the Rust backend, and produces a native installer:

```bash
npm run tauri build
```

Output artifacts are written to `src-tauri/target/release/bundle/`.

---

## Usage

1. **Add files** — click "Add Files" (or drag and drop) to load one or more `.evtx` files. Each file appears as a card in the file list.
2. **Quick Access** — Use the "Open File" or "Open Folder" icons on each card to quickly locate the source `.evtx` file on your system.
3. **Configure filters** — expand a file card's filter panel to set date ranges, hostnames, usernames, or any other criteria. Filters are independent per file.
4. **Set output names** — each file card shows an editable output filename field (defaults to the source filename without the `.evtx` extension). Adjust as needed.
5. **Export** — click "Export CSV" or "Enrich & Export" to open the OS save dialog. Each file is written to an individually-named `.csv` at the chosen location.
6. **Review enrichment report** — if the enrichment checkbox is enabled, a `_report.md` is generated in the same directory as the CSV file. It lists every event that matched a suspicious pattern, grouped by pattern category.

---

## Enrichment / signatures.json

`signatures.json` defines the regex patterns used by the enrichment engine.

### Customization

Edit `signatures.json` to add new patterns. The app supports hot-reloading signatures via the "Refresh Rules" button in the toolbar. Regex syntax follows the [Rust `regex` crate](https://docs.rs/regex/latest/regex/) (RE2-compatible).

---

## Project Structure

```
evtx-to-csv/
├── src/                        # Svelte / TypeScript frontend
│   └── lib/
│       └── types.ts            # Shared TypeScript type definitions
├── src-tauri/                  # Rust / Tauri backend
│   ├── src/
│   │   └── types.rs            # Rust struct definitions
│   ├── Cargo.toml              # Rust dependencies manifest
│   ├── build.rs                # Tauri build script
│   └── tauri.conf.json         # Tauri application configuration
├── signatures.json             # Enrichment regex pattern definitions
├── package.json                # Node.js dependencies and npm scripts
├── README.md
└── .gitignore
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
