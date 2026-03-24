# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] - 2026-03-23

### Added

- Initial release
- Tauri v1 + Svelte 4 + TypeScript project scaffold
- EVTX file parsing via Rust `evtx` crate (v0.8)
- Multi-file support: load and manage multiple `.evtx` files simultaneously
- Per-file filter panel with:
  - Date range filter (from/to datetime)
  - Relative date filter: 1, 3, 7, 14, 30 days
  - Hostname filter (case-insensitive partial match)
  - Username filter (matches `SubjectUserName` and `TargetUserName`)
  - Process ID filter
  - IP Address filter (matches any IP-related EventData field)
  - Custom field filter (field name + optional value)
- CSV export with IR-focused columns: `timestamp`, `event_id`, `level`, `channel`, `computer`, `username`, `domain`, `target_username`, `target_domain`, `process_id`, `process_name`, `ip_address`, `port`, `logon_type`, `command_line`, `parent_process`, `workstation`, `auth_package`, plus all additional EventData fields
- Incident Response enrichment check against `suspicious-commands.txt` regex patterns
  - Detects: PowerShell obfuscation/download/bypass, LOLBin abuse, defense evasion, credential dumping, remote access tools, persistence mechanisms
  - Outputs `report.md` alongside the CSV export
  - Toggle checkbox (enabled by default)
- Dark-themed UI designed for incident responders
- Drag-and-drop `.evtx` file support
- Cross-platform builds: macOS and Windows
- `.gitignore` for Rust, Node, and Tauri artifacts
