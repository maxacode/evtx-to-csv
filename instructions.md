# Enrichment Signature Instructions

This document explains how to add, modify, and manage detection signatures for the evtx-to-csv enrichment engine.

## Unified Signature Format (`signatures.json`)

All detections are now stored in a single JSON file: `signatures.json`. This file is located in the project root (for development) and is copied to your **Documents/evtx-to-csv/** folder for easy user access.

### Signature Structure

Each detection is a `PatternSpec` object inside the `patterns` array:

```json
{
  "name": "unique_identifier",
  "risk": "Critical | High | Medium | Low",
  "tactic": "MITRE ATT&CK Tactic (e.g., Execution)",
  "mitre_id": "MITRE ATT&CK ID (e.g., T1059.001)",
  "description": "Plain-English explanation of the threat and why it was flagged.",
  "regex": "(?i)your_regex_pattern_here"
}
```

### Field Definitions

- **name**: A short, unique slug (e.g., `ps_encoded_command`). Used for internal tracking.
- **risk**: The severity level. This determines the emoji and color in the Markdown report:
  - `Critical` (🔴)
  - `High` (🟠)
  - `Medium` (🟡)
  - `Low` (🔵)
- **tactic**: The high-level MITRE ATT&CK category.
- **mitre_id**: The specific technique or sub-technique ID.
- **description**: A detailed explanation of the finding. This is shown directly to the analyst in the final report.
- **regex**: A Rust-compatible regular expression. 
  - Use `(?i)` at the start for case-insensitive matching.
  - Use `\\b` for word boundaries (must be double-escaped in JSON).
  - Test your regexes at [regex101.com](https://regex101.com/) (select the Rust flavor).

---

## How to Add a New Detection

1.  **Open `signatures.json`**: Locate the file in your `Documents/evtx-to-csv/` folder.
2.  **Add a new entry**: Add a new JSON object to the `patterns` array.
3.  **Validate JSON**: Ensure you haven't missed any commas or quotes.
4.  **Refresh in App**: Open evtx-to-csv and click the **Refresh** button next to the signature count. The app will immediately reload the file from your Documents folder.

### Example: Detecting `psexec` usage

```json
{
  "name": "lateral_psexec",
  "risk": "High",
  "tactic": "Lateral Movement",
  "mitre_id": "T1570",
  "description": "PsExec detected. PsExec is a powerful Sysinternals tool often used by attackers to execute commands on remote systems.",
  "regex": "(?i)\\bpsexec(?:c)?(?:\\.exe)?\\b"
}
```

---

## Best Practices

- **Avoid overly broad regexes**: Patterns like `(?i)cmd` will trigger thousands of false positives. Be specific (e.g., `(?i)\\bcmd\\.exe\\b.*/c`).
- **Use word boundaries**: `\\b` prevents partial matches (e.g., `\\bnet\\b` matches the `net` command but not `network`).
- **Document the "Why"**: Use the `description` field to provide context. Imagine an analyst who has never seen this specific command before—help them understand the risk.
