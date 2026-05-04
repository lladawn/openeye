use crate::event::ProcessInfo;

#[derive(Clone, Debug)]
pub struct ProcessFilter {
    names: Vec<String>,
}

impl ProcessFilter {
    pub fn new(names: Vec<String>) -> Self {
        Self { names }
    }

    pub fn matches(&self, process: &ProcessInfo) -> bool {
        let name = process.name.to_ascii_lowercase();
        let command = process.command.to_ascii_lowercase();

        name.contains("mcp")
            || command.contains("mcp")
            || self.names.iter().any(|candidate| {
                let candidate = candidate.to_ascii_lowercase();
                name == candidate || command.contains(&candidate)
            })
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self::new(vec![
            "cursor".into(),
            "claude".into(),
            "claude-desktop".into(),
            "codex".into(),
            "python3".into(),
            "node".into(),
            "npm".into(),
            "npx".into(),
            "ollama".into(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_default_ai_processes() {
        let filter = ProcessFilter::default();
        let process = ProcessInfo::new(42, None, "node", "node server.js");
        assert!(filter.matches(&process));
    }

    #[test]
    fn matches_mcp_by_substring() {
        let filter = ProcessFilter::default();
        let process = ProcessInfo::new(42, None, "weather-mcp-server", "weather-mcp-server");
        assert!(filter.matches(&process));
    }
}

