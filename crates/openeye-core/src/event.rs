use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    FileRead,
    FileWrite,
    NetworkConnect,
    NetworkSend,
    ClipboardRead,
    ProcessExec,
    McpManifestChange,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileRead => "FILE_READ",
            Self::FileWrite => "FILE_WRITE",
            Self::NetworkConnect => "NETWORK_CONNECT",
            Self::NetworkSend => "NETWORK_SEND",
            Self::ClipboardRead => "CLIPBOARD_READ",
            Self::ProcessExec => "PROCESS_EXEC",
            Self::McpManifestChange => "MCP_MANIFEST_CHANGE",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub command: String,
}

impl ProcessInfo {
    pub fn new(pid: u32, parent_pid: Option<u32>, name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            pid,
            parent_pid,
            name: name.into(),
            command: command.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub id: u64,
    pub timestamp_ms: u128,
    pub process: ProcessInfo,
    pub kind: EventKind,
    pub target: String,
    pub detail: String,
    pub bytes: Option<u64>,
    pub user_initiated: bool,
}

impl Event {
    pub fn new(id: u64, process: ProcessInfo, kind: EventKind, target: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id,
            timestamp_ms: now_ms(),
            process,
            kind,
            target: target.into(),
            detail: detail.into(),
            bytes: None,
            user_initiated: false,
        }
    }

    pub fn with_timestamp(mut self, timestamp_ms: u128) -> Self {
        self.timestamp_ms = timestamp_ms;
        self
    }

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }

    pub fn user_initiated(mut self, value: bool) -> Self {
        self.user_initiated = value;
        self
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

