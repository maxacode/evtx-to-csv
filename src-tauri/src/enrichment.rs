// =============================================================================
// enrichment.rs — Automated Enrichment Engine
//
// Runs an automated enrichment check against known-suspicious command patterns
// and exports a structured Markdown report with risk ratings, MITRE ATT&CK
// mappings, and plain-English analysis for every finding.
//
// PATTERN SOURCES:
//   • signatures.json  — external user-editable regex signature library
//                        loaded at startup and reloadable via the Refresh button
//   • suspicious-commands.txt  — optional legacy supplemental patterns
//
// HOW IT WORKS:
//   1. compile_pattern_specs() → compiles PatternSpec vec from signatures.json
//                                into CompiledRule vec ready for matching
//   2. parse_user_patterns()   → supplements with any extra patterns from
//                                suspicious_content (additive, not required)
//   3. run_event_id_rules()    → fires rules based on event ID + field conditions
//      (e.g. Event 1102 = log clear CRITICAL, Event 4769 RC4 = Kerberoasting HIGH)
//   4. run_pattern_rules()     → scans every text field of every record against regexes
//   5. run_heuristic_checks()  → groups records by PID; 3+ recon commands within
//                                5 minutes from the same process → CRITICAL escalation
//   6. build_report()          → renders findings as a rich Markdown report
//
// REPORT FORMAT:
//   Risk emoji header (🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🔵 LOW) per finding,
//   with Event ID, timestamp, computer, user, MITRE ID + tactic, matched field,
//   matched value, and a plain-English reasoning paragraph.
// =============================================================================

use std::collections::HashMap;
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use crate::types::{EventRecord, PatternSpec};

// =============================================================================
// Risk level enum
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    fn label(&self) -> &'static str {
        match self { Risk::Critical=>"CRITICAL", Risk::High=>"HIGH", Risk::Medium=>"MEDIUM", Risk::Low=>"LOW" }
    }
    fn emoji(&self) -> &'static str {
        match self { Risk::Critical=>"🔴", Risk::High=>"🟠", Risk::Medium=>"🟡", Risk::Low=>"🔵" }
    }
}

// =============================================================================
// Rule & Finding types
// =============================================================================

/// A compiled pattern rule ready for matching.
struct CompiledRule {
    name:        String,
    risk:        Risk,
    tactic:      String,
    mitre_id:    String,
    description: String,
    regex:       Regex,
}

/// One match found during the enrichment scan.
#[derive(Debug, Clone)]
struct Finding {
    rule_name:     String,
    risk:          Risk,
    tactic:        String,
    mitre_id:      String,
    description:   String,
    event_id:      u32,
    timestamp:     String,
    computer:      String,
    username:      String,
    matched_field: String,
    matched_value: String,
}

// =============================================================================
// compile_pattern_specs — convert PatternSpec vec into CompiledRule vec
// =============================================================================

/// Compile externally-loaded PatternSpec entries into regex-ready CompiledRule values.
/// Rules whose regex fails to compile are skipped with a warning to stderr.
fn compile_pattern_specs(specs: &[PatternSpec]) -> Vec<CompiledRule> {
    specs.iter().filter_map(|spec| {
        let risk = match spec.risk.as_str() {
            "Critical" => Risk::Critical,
            "High"     => Risk::High,
            "Medium"   => Risk::Medium,
            _          => Risk::Low,
        };
        match Regex::new(&spec.regex) {
            Ok(re) => Some(CompiledRule {
                name:        spec.name.clone(),
                risk,
                tactic:      spec.tactic.clone(),
                mitre_id:    spec.mitre_id.clone(),
                description: spec.description.clone(),
                regex:       re,
            }),
            Err(e) => {
                eprintln!("[enrichment] Rule '{}' regex failed: {}", spec.name, e);
                None
            }
        }
    }).collect()
}

// =============================================================================
// Public entry point — run_enrichment
// =============================================================================

/// Run the full enrichment pipeline against `records` and return a Markdown report.
///
/// `pattern_specs` — the currently-loaded rules from signatures.json (passed in
/// from AppState so that a hot-reload via reload_signatures is reflected immediately).
pub fn run_enrichment(records: &[EventRecord], pattern_specs: &[PatternSpec]) -> String {
    // Compile the externally-loaded pattern rules
    let compiled_rules = compile_pattern_specs(pattern_specs);

    let mut findings = Vec::new();
    run_event_id_rules(records, &mut findings);
    run_pattern_rules(records, &compiled_rules, &mut findings);
    run_heuristic_checks(records, &mut findings);
    findings.sort_by(|a, b| b.risk.cmp(&a.risk));
    build_report(records.len(), &findings)
}

// =============================================================================
// EVENT-ID SPECIFIC RULES
// Sourced from generic-suspicious.txt (Windows Event Threat Library)
// These fire based on event ID + optional field conditions, not regex.
// =============================================================================

fn run_event_id_rules(records: &[EventRecord], findings: &mut Vec<Finding>) {
    for record in records {
        let u = record.username.as_deref().unwrap_or("-");
        let tu = record.target_username.as_deref().unwrap_or("");
        let display_user = if !tu.is_empty() && tu != "-" { tu } else { u };

        match record.event_id {

            // -------------------------------------------------------------------
            // 1102 — Security Log Cleared — ALWAYS CRITICAL
            // Source: generic-suspicious.txt "Log Cleared" + suspicious-commands.txt
            // -------------------------------------------------------------------
            1102 => findings.push(Finding {
                rule_name:     "event_log_cleared".into(),
                risk:          Risk::Critical,
                tactic:        "Defense Evasion".into(),
                mitre_id:      "T1070.001".into(),
                description:   format!(
                    "CRITICAL: The Windows Security event log was cleared by '{user}'. \
                     Log clearing is an immediate red flag — it destroys the forensic \
                     timeline and suggests the actor is in clean-up mode after completing \
                     their primary objective. Per generic-suspicious.txt: immediate \
                     investigation required. Identify all activity BEFORE this event.",
                    user = display_user
                ),
                event_id:      record.event_id,
                timestamp:     record.timestamp.clone(),
                computer:      record.computer.clone(),
                username:      display_user.to_string(),
                matched_field: "EventID".into(),
                matched_value: "1102 — Audit Log Cleared".into(),
            }),

            // -------------------------------------------------------------------
            // 4719 — System Audit Policy Changed — HIGH
            // Disabling Process Creation or Account Logon auditing hides activity.
            // -------------------------------------------------------------------
            4719 => findings.push(Finding {
                rule_name:     "audit_policy_changed".into(),
                risk:          Risk::High,
                tactic:        "Defense Evasion".into(),
                mitre_id:      "T1562.002".into(),
                description:   "Audit policy modified — success/failure auditing may have \
                     been disabled for Process Creation or Account Logon events. \
                     Attackers do this to prevent future actions from appearing in the \
                     event log.".into(),
                event_id:      record.event_id,
                timestamp:     record.timestamp.clone(),
                computer:      record.computer.clone(),
                username:      display_user.to_string(),
                matched_field: "EventID".into(),
                matched_value: "4719 — Audit Policy Changed".into(),
            }),

            // -------------------------------------------------------------------
            // 4720 — User Account Created — MEDIUM
            // -------------------------------------------------------------------
            4720 => findings.push(Finding {
                rule_name:     "user_account_created".into(),
                risk:          Risk::Medium,
                tactic:        "Persistence".into(),
                mitre_id:      "T1136.001".into(),
                description:   format!(
                    "New local account '{new_user}' created by '{actor}'. \
                     Attackers create backdoor accounts for persistent access. \
                     Correlate with Event 4732 (group membership add) to detect \
                     unauthorized administrator account creation.",
                    new_user = display_user,
                    actor = u
                ),
                event_id:      record.event_id,
                timestamp:     record.timestamp.clone(),
                computer:      record.computer.clone(),
                username:      u.to_string(),
                matched_field: "TargetUserName".into(),
                matched_value: display_user.to_string(),
            }),

            // -------------------------------------------------------------------
            // 4697 — Service Installed — HIGH
            // Flag non-standard names or paths pointing to user/temp folders.
            // -------------------------------------------------------------------
            4697 => {
                // Check if the service binary path points to a suspicious location
                let svc_name = record.extra_fields.get("ServiceName")
                    .or(record.extra_fields.get("serviceName"))
                    .map(|s| s.as_str()).unwrap_or("-");
                let svc_path = record.extra_fields.get("ServiceFileName")
                    .or(record.extra_fields.get("ImagePath"))
                    .map(|s| s.as_str()).unwrap_or("");

                let suspicious_path = svc_path.to_lowercase().contains("\\temp\\")
                    || svc_path.to_lowercase().contains("\\appdata\\")
                    || svc_path.to_lowercase().contains("\\downloads\\")
                    || svc_path.to_lowercase().contains("\\users\\public\\");

                findings.push(Finding {
                    rule_name:     "service_installed".into(),
                    risk:          if suspicious_path { Risk::Critical } else { Risk::High },
                    tactic:        "Persistence".into(),
                    mitre_id:      "T1543.003".into(),
                    description:   format!(
                        "Service '{name}' installed with binary path: '{path}'. \
                         {sus}Malicious services are installed for persistent, \
                         SYSTEM-level execution that survives reboots. \
                         Verify the binary is signed and expected.",
                        name = svc_name,
                        path = svc_path,
                        sus = if suspicious_path { "⚠️ Binary path points to a user/temp directory — HIGH SUSPICION. " } else { "" }
                    ),
                    event_id:      record.event_id,
                    timestamp:     record.timestamp.clone(),
                    computer:      record.computer.clone(),
                    username:      u.to_string(),
                    matched_field: "ServiceFileName".into(),
                    matched_value: format!("{} → {}", svc_name, svc_path),
                });
            },

            // -------------------------------------------------------------------
            // 4698 / 4702 — Scheduled Task Created / Modified — MEDIUM
            // Escalate to HIGH if command contains suspicious paths or keywords.
            // -------------------------------------------------------------------
            4698 | 4702 => {
                let task_name = record.extra_fields.get("TaskName")
                    .or(record.extra_fields.get("taskName"))
                    .map(|s| s.as_str()).unwrap_or("-");

                // Check TaskContent for suspicious execution patterns
                let task_content = record.extra_fields.get("TaskContent")
                    .or(record.extra_fields.get("taskContent"))
                    .map(|s| s.as_str()).unwrap_or("");

                let sus_content = task_content.to_lowercase().contains("cmd.exe /c")
                    || task_content.to_lowercase().contains("powershell")
                    || task_content.to_lowercase().contains("\\temp\\")
                    || task_content.to_lowercase().contains("\\appdata\\")
                    || task_content.to_lowercase().contains("http");

                findings.push(Finding {
                    rule_name:     if record.event_id == 4698 { "schtask_created".into() } else { "schtask_modified".into() },
                    risk:          if sus_content { Risk::High } else { Risk::Medium },
                    tactic:        "Persistence".into(),
                    mitre_id:      "T1053.005".into(),
                    description:   format!(
                        "Scheduled task '{name}' {action}. {sus}\
                         Review the task's Action command for suspicious binaries, \
                         temp paths, or network download cradles.",
                        name   = task_name,
                        action = if record.event_id == 4698 { "created" } else { "modified" },
                        sus    = if sus_content { "⚠️ Task content contains suspicious commands (cmd /c, powershell, temp path, or HTTP). " } else { "" }
                    ),
                    event_id:      record.event_id,
                    timestamp:     record.timestamp.clone(),
                    computer:      record.computer.clone(),
                    username:      u.to_string(),
                    matched_field: "TaskName".into(),
                    matched_value: task_name.to_string(),
                });
            },

            // -------------------------------------------------------------------
            // 4624 — Successful Logon
            // Flag LogonType 10 (RDP) and LogonType 3 (Network) with notable IPs.
            // -------------------------------------------------------------------
            4624 => {
                let logon_type = record.logon_type.as_deref().unwrap_or("").trim();
                // Accept raw number "10" or enriched string "10 (RemoteInteractive)"
                let is_rdp = logon_type.starts_with("10");
                let is_network = logon_type.starts_with('3');
                let ip = record.ip_address.as_deref().unwrap_or("").trim();

                // Only flag if there's an IP (not a local/empty logon)
                let has_ip = !ip.is_empty() && ip != "-" && ip != "::1"
                    && !ip.starts_with("127.") && !ip.starts_with("169.254.");

                if is_rdp && has_ip {
                    findings.push(Finding {
                        rule_name:     "rdp_logon_external".into(),
                        risk:          Risk::Medium,
                        tactic:        "Lateral Movement".into(),
                        mitre_id:      "T1021.001".into(),
                        description:   format!(
                            "RDP logon (LogonType 10) from external address {ip} \
                             as '{user}'. Unexpected RDP from outside the known subnet \
                             may indicate remote access by an attacker. \
                             Correlate with VPN logs.",
                            ip = ip, user = display_user
                        ),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      display_user.to_string(),
                        matched_field: "LogonType + IpAddress".into(),
                        matched_value: format!("Type 10 (RDP) from {}", ip),
                    });
                } else if is_network && has_ip {
                    // Only report network logons from non-local IPs as low signal
                    findings.push(Finding {
                        rule_name:     "network_logon".into(),
                        risk:          Risk::Low,
                        tactic:        "Lateral Movement".into(),
                        mitre_id:      "T1078".into(),
                        description:   format!(
                            "Network logon (LogonType 3) from {ip} as '{user}'. \
                             Review whether this source IP is expected. \
                             High-volume Type-3 events from a single IP can indicate \
                             password spraying or lateral movement.",
                            ip = ip, user = display_user
                        ),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      display_user.to_string(),
                        matched_field: "LogonType + IpAddress".into(),
                        matched_value: format!("Type 3 (Network) from {}", ip),
                    });
                }
            },

            // -------------------------------------------------------------------
            // 4768 — Kerberos TGT Request
            // High volume of 0x6 (user not found) failures = user enumeration.
            // -------------------------------------------------------------------
            4768 => {
                let result_code = record.extra_fields.get("Status")
                    .or(record.extra_fields.get("ResultCode"))
                    .or(record.extra_fields.get("FailureCode"))
                    .map(|s| s.as_str()).unwrap_or("");

                if result_code == "0x6" || result_code == "0X6" {
                    findings.push(Finding {
                        rule_name:     "kerberos_user_enumeration".into(),
                        risk:          Risk::Medium,
                        tactic:        "Discovery".into(),
                        mitre_id:      "T1087".into(),
                        description:   "Kerberos TGT request failed with 0x6 (KDC_ERR_C_PRINCIPAL_UNKNOWN \
                             — user not found). High volume of these from a single source indicates \
                             Kerberos-based user enumeration (e.g. Kerbrute, Impacket GetNPUsers).".into(),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      display_user.to_string(),
                        matched_field: "Status/FailureCode".into(),
                        matched_value: "0x6 — User not found".into(),
                    });
                }
            },

            // -------------------------------------------------------------------
            // 4769 — Kerberos Service Ticket
            // EncryptionType 0x17 (RC4) = potential Kerberoasting.
            // -------------------------------------------------------------------
            4769 => {
                let enc_type = record.extra_fields.get("TicketEncryptionType")
                    .or(record.extra_fields.get("encryptionType"))
                    .map(|s| s.as_str()).unwrap_or("");

                if enc_type == "0x17" || enc_type == "0X17" || enc_type == "23" {
                    findings.push(Finding {
                        rule_name:     "kerberoasting_rc4".into(),
                        risk:          Risk::High,
                        tactic:        "Credential Access".into(),
                        mitre_id:      "T1558.003".into(),
                        description:   format!(
                            "Kerberos service ticket requested with RC4 encryption (0x17) \
                             for '{svc}' by '{user}'. RC4 tickets are targeted by Kerberoasting \
                             attacks — the ticket is crackable offline to recover the service \
                             account password. Modern environments should use AES.",
                            svc  = record.extra_fields.get("ServiceName").map(|s|s.as_str()).unwrap_or("-"),
                            user = display_user
                        ),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      display_user.to_string(),
                        matched_field: "TicketEncryptionType".into(),
                        matched_value: "0x17 (RC4-HMAC)".into(),
                    });
                }
            },

            // -------------------------------------------------------------------
            // 5140 — Network Share Access
            // Flag access to C$ or ADMIN$ from non-admin workstations.
            // -------------------------------------------------------------------
            5140 => {
                let share = record.extra_fields.get("ShareName")
                    .or(record.extra_fields.get("shareName"))
                    .map(|s| s.as_str()).unwrap_or("");

                if share.contains("C$") || share.contains("ADMIN$") || share.contains("IPC$") {
                    findings.push(Finding {
                        rule_name:     "admin_share_access".into(),
                        risk:          Risk::High,
                        tactic:        "Lateral Movement".into(),
                        mitre_id:      "T1021.002".into(),
                        description:   format!(
                            "Administrative share '{share}' accessed by '{user}' from '{ip}'. \
                             Access to C$ or ADMIN$ from non-server workstations strongly \
                             suggests lateral movement via SMB (e.g. PsExec, Impacket SMBExec, \
                             ransomware spreading).",
                            share = share,
                            user  = display_user,
                            ip    = record.ip_address.as_deref().unwrap_or("-")
                        ),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      display_user.to_string(),
                        matched_field: "ShareName".into(),
                        matched_value: share.to_string(),
                    });
                }
            },

            // -------------------------------------------------------------------
            // 7040 — Service State Changed
            // Defender or EDR service changed to Disabled.
            // -------------------------------------------------------------------
            7040 => {
                let svc_name = record.extra_fields.get("ServiceName")
                    .or(record.extra_fields.get("param1"))
                    .map(|s| s.as_str()).unwrap_or("");

                let is_security_svc = svc_name.to_lowercase().contains("defender")
                    || svc_name.to_lowercase().contains("windefend")
                    || svc_name.to_lowercase().contains("sense")
                    || svc_name.to_lowercase().contains("mpssvc")
                    || svc_name.to_lowercase().contains("bits");

                if is_security_svc {
                    findings.push(Finding {
                        rule_name:     "security_service_disabled".into(),
                        risk:          Risk::High,
                        tactic:        "Defense Evasion".into(),
                        mitre_id:      "T1562.001".into(),
                        description:   format!(
                            "Security service '{svc}' start type changed (possibly to Disabled). \
                             Attackers disable Windows Defender, Windows Firewall, or EDR \
                             services before deploying their payload to avoid detection.",
                            svc = svc_name
                        ),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      display_user.to_string(),
                        matched_field: "ServiceName".into(),
                        matched_value: svc_name.to_string(),
                    });
                }
            },

            _ => {} // No event-ID-specific rule for this ID
        }
    }
}

// =============================================================================
// Pattern rule matching — scan every text field of every record
// =============================================================================

fn run_pattern_rules(records: &[EventRecord], rules: &[CompiledRule], findings: &mut Vec<Finding>) {
    for record in records {
        let fields = scannable_fields(record);
        let u = record.username.as_deref()
            .or(record.target_username.as_deref())
            .unwrap_or("-");

        for (field_label, field_value) in &fields {
            for rule in rules {
                if rule.regex.is_match(field_value) {
                    findings.push(Finding {
                        rule_name:     rule.name.clone(),
                        risk:          rule.risk.clone(),
                        tactic:        rule.tactic.clone(),
                        mitre_id:      rule.mitre_id.clone(),
                        description:   rule.description.clone(),
                        event_id:      record.event_id,
                        timestamp:     record.timestamp.clone(),
                        computer:      record.computer.clone(),
                        username:      u.to_string(),
                        matched_field: field_label.clone(),
                        matched_value: field_value.clone(),
                    });
                    break; // One finding per (record × rule) — don't double-count same rule
                }
            }
        }
    }
}

// =============================================================================
// Heuristic: 3+ recon commands from the same PID within 5 minutes → CRITICAL
// Sourced from generic-suspicious.txt SOC tier-3 escalation rule
// =============================================================================

fn run_heuristic_checks(records: &[EventRecord], findings: &mut Vec<Finding>) {
    // Build discovery command detector
    let recon_re = Regex::new(
        r"(?i)\b(?:whoami|ipconfig|hostname|systeminfo|net\s+user|net\s+group|arp\s+-a|route\s+print|netstat|tasklist|nltest)\b"
    ).unwrap();

    // Group records that contain discovery commands by (computer + process_id)
    // Using process_id as the grouping key; fall back to computer alone if PID is absent.
    let mut groups: HashMap<String, Vec<(DateTime<Utc>, &EventRecord)>> = HashMap::new();

    for record in records {
        if let Some(ref cmd) = record.command_line {
            if recon_re.is_match(cmd) {
                if let Ok(ts) = record.timestamp.parse::<DateTime<Utc>>() {
                    let key = format!(
                        "{}:{}",
                        record.computer,
                        record.process_id.as_deref().unwrap_or("nopid")
                    );
                    groups.entry(key).or_default().push((ts, record));
                }
            }
        }
        // Also scan extra_fields for discovery commands
        for val in record.extra_fields.values() {
            if recon_re.is_match(val) {
                if let Ok(ts) = record.timestamp.parse::<DateTime<Utc>>() {
                    let key = format!(
                        "{}:{}",
                        record.computer,
                        record.process_id.as_deref().unwrap_or("nopid")
                    );
                    groups.entry(key.clone()).or_default().push((ts, record));
                    break;
                }
            }
        }
    }

    // For each group, find any 5-minute window containing 3+ recon events
    for (key, mut events) in groups {
        events.sort_by_key(|(ts, _)| *ts);

        for i in 0..events.len() {
            let window_start = events[i].0;
            let window_end   = window_start + Duration::minutes(5);

            let count = events[i..]
                .iter()
                .take_while(|(ts, _)| *ts <= window_end)
                .count();

            if count >= 3 {
                let (ts, record) = events[i];
                let u = record.username.as_deref().unwrap_or("-");

                findings.push(Finding {
                    rule_name:     "heuristic_recon_cluster".into(),
                    risk:          Risk::Critical,
                    tactic:        "Discovery".into(),
                    mitre_id:      "T1082 / T1087 / T1033".into(),
                    description:   format!(
                        "HEURISTIC ESCALATION: {count} reconnaissance commands detected from \
                         process group '{key}' within a 5-minute window (starting {ts}). \
                         Per SOC tier-3 logic: clustering of discovery commands (whoami, \
                         ipconfig, net user, systeminfo) from a single process indicates \
                         active hands-on-keyboard reconnaissance after initial access.",
                        count = count,
                        key   = key,
                        ts    = ts.format("%H:%M:%S UTC")
                    ),
                    event_id:      record.event_id,
                    timestamp:     record.timestamp.clone(),
                    computer:      record.computer.clone(),
                    username:      u.to_string(),
                    matched_field: "command_line (cluster)".into(),
                    matched_value: format!("{} recon cmds in 5 min", count),
                });
                break; // One heuristic finding per group
            }
        }
    }
}

// =============================================================================
// Field collection — all scannable text fields from an EventRecord
// =============================================================================

fn scannable_fields(record: &EventRecord) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut push = |label: &str, opt: &Option<String>| {
        if let Some(ref v) = opt {
            if !v.is_empty() { fields.push((label.to_string(), v.clone())); }
        }
    };
    push("command_line",    &record.command_line);
    push("process_name",    &record.process_name);
    push("parent_process",  &record.parent_process);
    push("username",        &record.username);
    push("target_username", &record.target_username);
    if !record.computer.is_empty() {
        fields.push(("computer".to_string(), record.computer.clone()));
    }
    for (k, v) in &record.extra_fields {
        if !v.is_empty() { fields.push((format!("extra.{}", k), v.clone())); }
    }
    fields
}

// =============================================================================
// Report builder — renders findings into a rich Markdown document
// =============================================================================

fn build_report(total: usize, findings: &[Finding]) -> String {
    let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    // Tally by risk level
    let critical = findings.iter().filter(|f| f.risk == Risk::Critical).count();
    let high     = findings.iter().filter(|f| f.risk == Risk::High).count();
    let medium   = findings.iter().filter(|f| f.risk == Risk::Medium).count();
    let low      = findings.iter().filter(|f| f.risk == Risk::Low).count();

    let mut report = format!(
        "# 🔍 Automated Enrichment Report\n\n\
         | Field | Value |\n\
         |-------|-------|\n\
         | Generated | {ts} |\n\
         | Events Analyzed | {total} |\n\
         | Total Findings | {count} |\n\
         | 🔴 Critical | {critical} |\n\
         | 🟠 High | {high} |\n\
         | 🟡 Medium | {medium} |\n\
         | 🔵 Low | {low} |\n\n\
         > Patterns sourced from: signatures.json · suspicious-commands.txt (supplemental)\n\n\
         ---\n\n",
        ts       = ts,
        total    = total,
        count    = findings.len(),
        critical = critical,
        high     = high,
        medium   = medium,
        low      = low,
    );

    if findings.is_empty() {
        report.push_str("## Findings\n\n✅ No suspicious activity detected against known signatures.\n");
        return report;
    }

    report.push_str("## Findings\n\n");

    for (idx, f) in findings.iter().enumerate() {
        // Truncate very long matched values for readability
        let display_val = if f.matched_value.len() > 250 {
            format!("{}…", &f.matched_value[..250])
        } else {
            f.matched_value.clone()
        };

        report.push_str(&format!(
            "### {emoji} [{risk}] Finding #{n} — `{rule}`\n\n\
             | Field | Value |\n\
             |-------|-------|\n\
             | Event ID | **{eid}** |\n\
             | Timestamp | {ts} |\n\
             | Computer | `{comp}` |\n\
             | User | `{user}` |\n\
             | MITRE | [{mitre}](https://attack.mitre.org/techniques/{mitre_url}/) — {tactic} |\n\
             | Matched Field | `{field}` |\n\
             | Matched Value | `{val}` |\n\n\
             **Analysis:** {desc}\n\n\
             ---\n\n",
            emoji     = f.risk.emoji(),
            risk      = f.risk.label(),
            n         = idx + 1,
            rule      = f.rule_name,
            eid       = f.event_id,
            ts        = f.timestamp,
            comp      = f.computer,
            user      = f.username,
            mitre     = f.mitre_id,
            mitre_url = f.mitre_id.replace('.', "/"),
            tactic    = f.tactic,
            field     = f.matched_field,
            val       = display_val,
            desc      = f.description,
        ));
    }

    report
}

// =============================================================================
// enrich_records — dedup + TaskContent XML cleanup (unchanged logic)
// =============================================================================

pub fn enrich_records(mut records: Vec<EventRecord>) -> Vec<EventRecord> {
    // Step 1: parse TaskContent XML → compact IR summary
    for record in records.iter_mut() {
        let task_key = record.extra_fields.keys()
            .find(|k| k.to_lowercase() == "taskcontent")
            .cloned();
        if let Some(key) = task_key {
            if let Some(xml) = record.extra_fields.get(&key).cloned() {
                if xml.trim_start().starts_with('<') {
                    record.extra_fields.insert(key, parse_task_xml(&xml));
                }
            }
        }
    }
    // Step 2: normalise LogonType numbers
    for record in records.iter_mut() {
        if let Some(ref lt) = record.logon_type.clone() {
            record.logon_type = Some(map_logon_type(lt.trim()));
        }
    }
    // Step 3: deduplicate
    let mut seen = std::collections::HashSet::new();
    records.retain(|r| seen.insert(dedup_key(r)));
    // Step 4: drop records with no IR value
    records.retain(has_ir_value);
    records
}

// ---------------------------------------------------------------------------
// parse_task_xml — extract IR fields from Windows Task Scheduler XML
// ---------------------------------------------------------------------------
fn parse_task_xml(xml: &str) -> String {
    let extract = |tag: &str| -> Option<String> {
        let pat = format!(r"(?s)<{tag}(?:\s[^>]*)?>\s*([^<]+?)\s*</{tag}>", tag = tag);
        Regex::new(&pat).ok()?
            .captures(xml)?.get(1)
            .map(|m| m.as_str().trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(v) = extract("URI")         { parts.push(format!("URI:{}", v)); }
    if let Some(v) = extract("Description") { parts.push(format!("Desc:{}", v)); }
    if let Some(v) = extract("Command")     { parts.push(format!("Cmd:{}", v)); }
    if let Some(v) = extract("Arguments")   { parts.push(format!("Args:{}", v)); }
    if let Some(v) = extract("UserId")      { parts.push(format!("RunAs:{}", v)); }
    if let Some(v) = extract("RunLevel")    { parts.push(format!("Level:{}", v)); }
    if let Some(v) = extract("Hidden")      { parts.push(format!("Hidden:{}", v)); }
    if let Some(v) = extract("Enabled")     { parts.push(format!("Enabled:{}", v)); }
    // IP scan
    if let Ok(re) = Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b") {
        let ips: Vec<&str> = re.find_iter(xml).map(|m| m.as_str()).collect();
        if !ips.is_empty() { parts.push(format!("IPs:{}", ips.join(","))); }
    }
    if parts.is_empty() {
        format!("[raw xml] {}", xml.chars().take(300).collect::<String>().trim())
    } else {
        parts.join(" | ")
    }
}

fn map_logon_type(code: &str) -> String {
    match code {
        "0"  => "0 (System)",
        "2"  => "2 (Interactive)",
        "3"  => "3 (Network)",
        "4"  => "4 (Batch)",
        "5"  => "5 (Service)",
        "7"  => "7 (Unlock)",
        "8"  => "8 (NetworkCleartext)",
        "9"  => "9 (NewCredentials)",
        "10" => "10 (RemoteInteractive/RDP)",
        "11" => "11 (CachedInteractive)",
        "12" => "12 (CachedRemoteInteractive)",
        "13" => "13 (CachedUnlock)",
        other => other,
    }.to_string()
}

fn dedup_key(r: &EventRecord) -> String {
    format!("{}|{}|{}|{}|{}|{}|{}|{}",
        r.timestamp, r.event_id, r.computer,
        r.username.as_deref().unwrap_or(""),
        r.target_username.as_deref().unwrap_or(""),
        r.ip_address.as_deref().unwrap_or(""),
        r.process_id.as_deref().unwrap_or(""),
        r.command_line.as_deref().unwrap_or(""),
    )
}

fn has_ir_value(r: &EventRecord) -> bool {
    r.username.is_some() || r.target_username.is_some() || r.ip_address.is_some()
        || r.process_id.is_some() || r.process_name.is_some() || r.command_line.is_some()
        || r.logon_type.is_some() || r.parent_process.is_some() || r.workstation.is_some()
        || r.auth_package.is_some() || !r.extra_fields.is_empty()
}
