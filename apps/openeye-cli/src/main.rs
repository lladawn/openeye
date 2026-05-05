// Rust CLI entry point for the production-path OpenEye command. It mirrors the
// Node MVP CLI: replay a demo, ingest normalized probe events from stdin, and
// explain alert rules without sending sensitive context anywhere.
use std::io::{self, BufRead};
use std::thread;
use std::time::Duration;

use openeye_core::{Alert, Config, Event, EventKind, ProcessInfo, RuleEngine, Severity};

// Dispatches the requested subcommand and prints a compact error on failure.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    let result = match command {
        "demo" => run_demo(),
        "ingest" => run_ingest(),
        "explain" => run_explain(args.get(2).map(String::as_str)),
        _ => {
            print_help();
            Ok(())
        }
    };

    if let Err(error) = result {
        eprintln!("openeye: {error}");
        std::process::exit(1);
    }
}

// Replays synthetic suspicious activity through the real Rust rule engine.
fn run_demo() -> Result<(), String> {
    let mut engine = RuleEngine::new(Config::default());
    let process = ProcessInfo::new(4242, Some(1), "cursor", "cursor-agent --workspace ~/Code/openeye");
    let events = vec![
        Event::new(1, process.clone(), EventKind::FileRead, "/Users/dawn/Code/openeye/README.md", "workspace context"),
        Event::new(2, process.clone(), EventKind::FileRead, "/Users/dawn/Code/openeye/.env", "read project env"),
        Event::new(3, process.clone(), EventKind::NetworkSend, "https://api.openai.com/v1/responses", "POST /v1/responses").with_bytes(18_400),
        Event::new(4, process.clone(), EventKind::FileRead, "/Users/dawn/.ssh/id_ed25519", "read private key"),
        Event::new(5, process.clone(), EventKind::NetworkConnect, "https://203.0.113.10/upload", "connect"),
        Event::new(6, process.clone(), EventKind::FileRead, "/Users/dawn/Library/Application Support/Bitcoin/wallets/main", "wallet scan"),
        Event::new(7, process, EventKind::ClipboardRead, "NSPasteboard.general", "clipboard read").user_initiated(false),
    ];

    for event in events {
        print_event(&event, Severity::Info);
        for alert in engine.evaluate(event) {
            print_alert(&alert);
        }
        thread::sleep(Duration::from_millis(450));
    }

    Ok(())
}

// Reads tab-separated key=value events from stdin for external collectors.
fn run_ingest() -> Result<(), String> {
    let stdin = io::stdin();
    let mut engine = RuleEngine::new(Config::default());

    for line in stdin.lock().lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let event = parse_event_line(&line)?;
        print_event(&event, Severity::Info);
        for alert in engine.evaluate(event) {
            print_alert(&alert);
        }
    }

    Ok(())
}

// Prints a local explanation for a rule name without including file contents.
fn run_explain(rule: Option<&str>) -> Result<(), String> {
    let Some(rule) = rule else {
        return Err("usage: openeye explain RULE_NAME".into());
    };

    let explanation = match rule {
        "SSH_KEY_EXFIL" => "The process read a likely SSH private key, then contacted the network within five seconds. Treat this as possible credential theft until you verify the destination.",
        "ENV_PLUS_NET" => "The process read a .env file and then sent data over the network. API keys or tokens may have been exposed if the payload included file contents.",
        "WALLET_FILE_READ" => "The process touched a known wallet storage path. That is unusual for an AI tool and should be investigated before continuing.",
        "BLIND_CLIPBOARD" => "The process read clipboard contents without a matching paste action. Clipboard data often contains passwords, tokens, or wallet addresses.",
        "MCP_MANIFEST_CHANGE" => "An MCP server's advertised tools changed compared with the saved baseline. Review the diff before trusting the server again.",
        _ => "This alert matched one of OpenEye's local rules. Review the process, target path or domain, and surrounding events before deciding whether to trust it.",
    };

    println!("{explanation}");
    Ok(())
}

// Converts one ingestion line into the core Event shape used by the rules.
fn parse_event_line(line: &str) -> Result<Event, String> {
    let fields = split_key_values(line);
    let process = ProcessInfo::new(
        fields.get("pid").and_then(|value| value.parse().ok()).unwrap_or(0),
        fields.get("ppid").and_then(|value| value.parse().ok()),
        fields.get("process").cloned().unwrap_or_else(|| "unknown".into()),
        fields.get("command").cloned().unwrap_or_default(),
    );

    let kind = match fields.get("kind").map(String::as_str) {
        Some("FILE_READ") => EventKind::FileRead,
        Some("FILE_WRITE") => EventKind::FileWrite,
        Some("NETWORK_CONNECT") => EventKind::NetworkConnect,
        Some("NETWORK_SEND") => EventKind::NetworkSend,
        Some("CLIPBOARD_READ") => EventKind::ClipboardRead,
        Some("PROCESS_EXEC") => EventKind::ProcessExec,
        Some("MCP_MANIFEST_CHANGE") => EventKind::McpManifestChange,
        other => return Err(format!("unknown or missing kind: {other:?}")),
    };

    let mut event = Event::new(
        fields.get("id").and_then(|value| value.parse().ok()).unwrap_or(0),
        process,
        kind,
        fields.get("target").cloned().unwrap_or_default(),
        fields.get("detail").cloned().unwrap_or_default(),
    );

    if let Some(timestamp_ms) = fields.get("timestamp_ms").and_then(|value| value.parse().ok()) {
        event = event.with_timestamp(timestamp_ms);
    }

    if let Some(bytes) = fields.get("bytes").and_then(|value| value.parse().ok()) {
        event = event.with_bytes(bytes);
    }

    if fields.get("user_initiated").map(String::as_str) == Some("true") {
        event = event.user_initiated(true);
    }

    Ok(event)
}

// Parses the lightweight probe format: key=value pairs separated by tabs.
fn split_key_values(line: &str) -> std::collections::HashMap<String, String> {
    line.split('\t')
        .filter_map(|part| part.split_once('='))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect()
}

// Prints a raw event in the terminal feed format.
fn print_event(event: &Event, severity: Severity) {
    println!(
        "{} [{}] [{}:{}] {} {} {}",
        color_label(severity.as_str(), &severity),
        event.timestamp_ms,
        event.process.name,
        event.process.pid,
        event.kind,
        event.target,
        event.detail
    );
}

// Prints an alert plus the recommended next action.
fn print_alert(alert: &Alert) {
    println!(
        "{} [{}] [{}] {} -> {}",
        color_label(alert.severity.as_str(), &alert.severity),
        alert.rule,
        alert.process,
        alert.description,
        alert.target
    );
    println!("  action: {}", alert.recommended_action);
}

// Applies ANSI colors based on severity.
fn color_label(label: &str, severity: &Severity) -> String {
    let code = match severity {
        Severity::Info => "32",
        Severity::Warning => "33",
        Severity::Critical => "31",
    };
    format!("\x1b[{code}m[{label}]\x1b[0m")
}

// Shows available commands and a minimal ingestion example.
fn print_help() {
    println!("OpenEye MVP");
    println!();
    println!("Commands:");
    println!("  openeye demo");
    println!("  openeye ingest     # reads tab-separated key=value events from stdin");
    println!("  openeye explain RULE_NAME");
    println!();
    println!("Ingest example:");
    println!("  kind=FILE_READ\tpid=42\tprocess=cursor\ttarget=/Users/me/.ssh/id_ed25519");
}
