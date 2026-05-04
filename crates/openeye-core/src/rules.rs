use std::collections::{HashMap, VecDeque};

use crate::config::Config;
use crate::event::{Event, EventKind, Severity};

const SSH_EXFIL_WINDOW_MS: u128 = 5_000;
const ENV_EXFIL_WINDOW_MS: u128 = 10_000;
const RING_WINDOW_MS: u128 = 30_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alert {
    pub rule: &'static str,
    pub severity: Severity,
    pub process: String,
    pub target: String,
    pub description: String,
    pub recommended_action: String,
}

#[derive(Clone, Debug)]
pub struct RuleEngine {
    config: Config,
    recent_by_pid: HashMap<u32, VecDeque<Event>>,
}

impl RuleEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            recent_by_pid: HashMap::new(),
        }
    }

    pub fn evaluate(&mut self, event: Event) -> Vec<Alert> {
        if !self.config.process_filter.matches(&event.process) {
            return Vec::new();
        }

        let mut alerts = Vec::new();
        self.evaluate_stateless(&event, &mut alerts);
        self.evaluate_temporal(&event, &mut alerts);
        self.remember(event);
        alerts
    }

    fn evaluate_stateless(&self, event: &Event, alerts: &mut Vec<Alert>) {
        match event.kind {
            EventKind::FileRead => {
                if is_ssh_private_key(&event.target) {
                    alerts.push(alert(
                        "SSH_KEY_READ",
                        Severity::Critical,
                        event,
                        "AI-related process read a likely SSH private key.",
                        "Stop the process, inspect its recent network activity, and rotate the key if exfiltration is suspected.",
                    ));
                }

                if is_env_file(&event.target) {
                    alerts.push(alert(
                        "ENV_FILE_READ",
                        Severity::Warning,
                        event,
                        "AI-related process read a .env file.",
                        "Check whether the tool needed this file. Rotate exposed API keys if the read was unexpected.",
                    ));
                }

                if self.matches_any_pattern(&event.target, &self.config.wallet_patterns) {
                    alerts.push(alert(
                        "WALLET_FILE_READ",
                        Severity::Critical,
                        event,
                        "AI-related process touched a known wallet storage path.",
                        "Close the process, move funds if needed, and audit extension or wallet access.",
                    ));
                }

                if self.matches_any_pattern(&event.target, &self.config.browser_profile_patterns) {
                    alerts.push(alert(
                        "BROWSER_PROFILE_READ",
                        Severity::Warning,
                        event,
                        "AI-related process read a browser profile path.",
                        "Review whether cookies, sessions, or extension state may have been exposed.",
                    ));
                }
            }
            EventKind::ClipboardRead => {
                if !event.user_initiated {
                    alerts.push(alert(
                        "BLIND_CLIPBOARD",
                        Severity::Critical,
                        event,
                        "Process read the clipboard without a matching user paste action.",
                        "Inspect clipboard contents and stop the process if the access was unexpected.",
                    ));
                }
            }
            EventKind::NetworkSend => {
                if event.bytes.unwrap_or_default() > 100_000 {
                    alerts.push(alert(
                        "LARGE_FILE_EXFIL",
                        Severity::Warning,
                        event,
                        "Process sent a large outbound payload.",
                        "Verify the destination and payload purpose before continuing.",
                    ));
                }
            }
            EventKind::ProcessExec => {
                let detail = event.detail.to_ascii_lowercase();
                if detail.contains("bash") || detail.contains(" zsh") || detail.contains(" sh ") {
                    alerts.push(alert(
                        "CHILD_PROCESS_SPAWN",
                        Severity::Warning,
                        event,
                        "AI-related process spawned a shell.",
                        "Review the command arguments for command injection or workspace escape.",
                    ));
                }
            }
            EventKind::McpManifestChange => {
                alerts.push(alert(
                    "MCP_MANIFEST_CHANGE",
                    Severity::Critical,
                    event,
                    "MCP tool manifest changed from the stored baseline.",
                    "Review added, removed, or modified tools before trusting this server.",
                ));
            }
            EventKind::NetworkConnect | EventKind::FileWrite => {}
        }
    }

    fn evaluate_temporal(&self, event: &Event, alerts: &mut Vec<Alert>) {
        if !matches!(event.kind, EventKind::NetworkConnect | EventKind::NetworkSend) {
            return;
        }

        let Some(recent) = self.recent_by_pid.get(&event.process.pid) else {
            return;
        };

        if recent.iter().any(|prior| {
            prior.kind == EventKind::FileRead
                && is_ssh_private_key(&prior.target)
                && event.timestamp_ms.saturating_sub(prior.timestamp_ms) <= SSH_EXFIL_WINDOW_MS
        }) {
            alerts.push(alert(
                "SSH_KEY_EXFIL",
                Severity::Critical,
                event,
                "Process read an SSH key and quickly made an outbound network request.",
                "Disconnect network access for this process and rotate the SSH key immediately.",
            ));
        }

        if recent.iter().any(|prior| {
            prior.kind == EventKind::FileRead
                && is_env_file(&prior.target)
                && event.timestamp_ms.saturating_sub(prior.timestamp_ms) <= ENV_EXFIL_WINDOW_MS
        }) {
            alerts.push(alert(
                "ENV_PLUS_NET",
                Severity::Critical,
                event,
                "Process read a .env file and soon sent data over the network.",
                "Assume secrets may be exposed until the destination and payload are verified.",
            ));
        }
    }

    fn remember(&mut self, event: Event) {
        let pid = event.process.pid;
        let timestamp = event.timestamp_ms;
        let recent = self.recent_by_pid.entry(pid).or_default();
        recent.push_back(event);

        while recent
            .front()
            .map(|front| timestamp.saturating_sub(front.timestamp_ms) > RING_WINDOW_MS)
            .unwrap_or(false)
        {
            recent.pop_front();
        }
    }

    fn matches_any_pattern(&self, path: &str, patterns: &[String]) -> bool {
        let normalized = normalize_path(path);
        patterns
            .iter()
            .map(|pattern| normalize_path(pattern))
            .any(|pattern| normalized.starts_with(&pattern) || normalized.contains(&pattern))
    }
}

fn alert(rule: &'static str, severity: Severity, event: &Event, description: &str, recommended_action: &str) -> Alert {
    Alert {
        rule,
        severity,
        process: event.process.name.clone(),
        target: event.target.clone(),
        description: description.into(),
        recommended_action: recommended_action.into(),
    }
}

fn is_ssh_private_key(path: &str) -> bool {
    let path = normalize_path(path);
    path.contains("/.ssh/id_")
        && !path.ends_with(".pub")
        && !path.ends_with("_known_hosts")
        && !path.ends_with("/known_hosts")
}

fn is_env_file(path: &str) -> bool {
    normalize_path(path).rsplit('/').next() == Some(".env")
}

fn normalize_path(path: &str) -> String {
    let mut path = path.replace('\\', "/");
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy();
        if path.starts_with("~/") {
            path = path.replacen('~', &home, 1);
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ProcessInfo;

    fn event(kind: EventKind, target: &str, ts: u128) -> Event {
        Event::new(
            1,
            ProcessInfo::new(7, Some(1), "cursor", "cursor-agent"),
            kind,
            target,
            "",
        )
        .with_timestamp(ts)
    }

    #[test]
    fn detects_ssh_key_read() {
        let mut engine = RuleEngine::new(Config::default());
        let alerts = engine.evaluate(event(EventKind::FileRead, "~/.ssh/id_ed25519", 1_000));
        assert!(alerts.iter().any(|alert| alert.rule == "SSH_KEY_READ"));
    }

    #[test]
    fn detects_env_plus_network_correlation() {
        let mut engine = RuleEngine::new(Config::default());
        engine.evaluate(event(EventKind::FileRead, "/tmp/project/.env", 1_000));
        let alerts = engine.evaluate(event(EventKind::NetworkSend, "https://unknown.example/upload", 5_000));
        assert!(alerts.iter().any(|alert| alert.rule == "ENV_PLUS_NET"));
    }

    #[test]
    fn ignores_non_ai_process() {
        let mut engine = RuleEngine::new(Config::default());
        let process = ProcessInfo::new(99, None, "TextEdit", "TextEdit");
        let event = Event::new(1, process, EventKind::FileRead, "~/.ssh/id_rsa", "");
        assert!(engine.evaluate(event).is_empty());
    }
}

