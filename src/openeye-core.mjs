const SSH_EXFIL_WINDOW_MS = 5000;
const ENV_EXFIL_WINDOW_MS = 10000;
const RING_WINDOW_MS = 30000;

export const eventKinds = new Set([
  "FILE_READ",
  "FILE_WRITE",
  "NETWORK_CONNECT",
  "NETWORK_SEND",
  "CLIPBOARD_READ",
  "PROCESS_EXEC",
  "MCP_MANIFEST_CHANGE"
]);

export const defaultConfig = {
  processNames: ["cursor", "claude", "claude-desktop", "codex", "python3", "node", "npm", "npx", "ollama"],
  walletPatterns: [
    "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
    "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "~/Library/Application Support/Ledger Live",
    "~/Library/Application Support/Bitcoin/wallets",
    "~/.ethereum/keystore",
    "~/Library/Ethereum",
    "~/.bitcoin"
  ],
  browserProfilePatterns: [
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Application Support/Firefox/Profiles",
    "~/.mozilla/firefox"
  ]
};

export class RuleEngine {
  constructor(config = defaultConfig) {
    this.config = config;
    this.recentByPid = new Map();
  }

  evaluate(event) {
    if (!this.matchesProcess(event.process)) {
      return [];
    }

    const alerts = [];
    this.evaluateStateless(event, alerts);
    this.evaluateTemporal(event, alerts);
    this.remember(event);
    return alerts;
  }

  matchesProcess(process) {
    const name = String(process?.name || "").toLowerCase();
    const command = String(process?.command || "").toLowerCase();
    return name.includes("mcp") ||
      command.includes("mcp") ||
      this.config.processNames.some((candidate) => name === candidate || command.includes(candidate));
  }

  evaluateStateless(event, alerts) {
    if (event.kind === "FILE_READ") {
      if (isSshPrivateKey(event.target)) {
        alerts.push(alert("SSH_KEY_READ", "CRITICAL", event, "AI-related process read a likely SSH private key.", "Stop the process, inspect recent network activity, and rotate the key if exfiltration is suspected."));
      }
      if (isEnvFile(event.target)) {
        alerts.push(alert("ENV_FILE_READ", "WARNING", event, "AI-related process read a .env file.", "Check whether the tool needed this file. Rotate exposed API keys if the read was unexpected."));
      }
      if (matchesAny(event.target, this.config.walletPatterns)) {
        alerts.push(alert("WALLET_FILE_READ", "CRITICAL", event, "AI-related process touched a known wallet storage path.", "Close the process, move funds if needed, and audit extension or wallet access."));
      }
      if (matchesAny(event.target, this.config.browserProfilePatterns)) {
        alerts.push(alert("BROWSER_PROFILE_READ", "WARNING", event, "AI-related process read a browser profile path.", "Review whether cookies, sessions, or extension state may have been exposed."));
      }
    }

    if (event.kind === "CLIPBOARD_READ" && !event.userInitiated) {
      alerts.push(alert("BLIND_CLIPBOARD", "CRITICAL", event, "Process read the clipboard without a matching user paste action.", "Inspect clipboard contents and stop the process if access was unexpected."));
    }

    if (event.kind === "NETWORK_SEND" && Number(event.bytes || 0) > 100000) {
      alerts.push(alert("LARGE_FILE_EXFIL", "WARNING", event, "Process sent a large outbound payload.", "Verify the destination and payload purpose before continuing."));
    }

    if (event.kind === "PROCESS_EXEC" && /\b(bash|zsh|sh)\b/.test(String(event.detail || "").toLowerCase())) {
      alerts.push(alert("CHILD_PROCESS_SPAWN", "WARNING", event, "AI-related process spawned a shell.", "Review the command arguments for command injection or workspace escape."));
    }

    if (event.kind === "MCP_MANIFEST_CHANGE") {
      alerts.push(alert("MCP_MANIFEST_CHANGE", "CRITICAL", event, "MCP tool manifest changed from the stored baseline.", "Review added, removed, or modified tools before trusting this server."));
    }
  }

  evaluateTemporal(event, alerts) {
    if (event.kind !== "NETWORK_CONNECT" && event.kind !== "NETWORK_SEND") {
      return;
    }

    const recent = this.recentByPid.get(event.process.pid) || [];
    if (recent.some((prior) => prior.kind === "FILE_READ" && isSshPrivateKey(prior.target) && event.timestampMs - prior.timestampMs <= SSH_EXFIL_WINDOW_MS)) {
      alerts.push(alert("SSH_KEY_EXFIL", "CRITICAL", event, "Process read an SSH key and quickly made an outbound network request.", "Disconnect network access for this process and rotate the SSH key immediately."));
    }
    if (recent.some((prior) => prior.kind === "FILE_READ" && isEnvFile(prior.target) && event.timestampMs - prior.timestampMs <= ENV_EXFIL_WINDOW_MS)) {
      alerts.push(alert("ENV_PLUS_NET", "CRITICAL", event, "Process read a .env file and soon sent data over the network.", "Assume secrets may be exposed until the destination and payload are verified."));
    }
  }

  remember(event) {
    const recent = this.recentByPid.get(event.process.pid) || [];
    recent.push(event);
    while (recent.length && event.timestampMs - recent[0].timestampMs > RING_WINDOW_MS) {
      recent.shift();
    }
    this.recentByPid.set(event.process.pid, recent);
  }
}

export function parseEventLine(line) {
  const fields = Object.fromEntries(line.split("\t").filter(Boolean).map((part) => {
    const index = part.indexOf("=");
    if (index === -1) {
      return [part.trim(), ""];
    }
    return [part.slice(0, index).trim(), part.slice(index + 1).trim()];
  }));

  if (!eventKinds.has(fields.kind)) {
    throw new Error(`unknown or missing kind: ${fields.kind || "(missing)"}`);
  }

  return {
    id: Number(fields.id || 0),
    timestampMs: Number(fields.timestamp_ms || Date.now()),
    process: {
      pid: Number(fields.pid || 0),
      parentPid: fields.ppid ? Number(fields.ppid) : null,
      name: fields.process || "unknown",
      command: fields.command || ""
    },
    kind: fields.kind,
    target: fields.target || "",
    detail: fields.detail || "",
    bytes: fields.bytes ? Number(fields.bytes) : undefined,
    userInitiated: fields.user_initiated === "true"
  };
}

export function demoEvents() {
  const process = { pid: 4242, parentPid: 1, name: "cursor", command: "cursor-agent --workspace ~/Code/openeye" };
  const now = Date.now();
  return [
    event(1, now, process, "FILE_READ", "/Users/dawn/Code/openeye/README.md", "workspace context"),
    event(2, now + 1000, process, "FILE_READ", "/Users/dawn/Code/openeye/.env", "read project env"),
    { ...event(3, now + 2000, process, "NETWORK_SEND", "https://api.openai.com/v1/responses", "POST /v1/responses"), bytes: 18400 },
    event(4, now + 3000, process, "FILE_READ", "/Users/dawn/.ssh/id_ed25519", "read private key"),
    event(5, now + 3500, process, "NETWORK_CONNECT", "https://203.0.113.10/upload", "connect"),
    event(6, now + 4000, process, "FILE_READ", "/Users/dawn/Library/Application Support/Bitcoin/wallets/main", "wallet scan"),
    { ...event(7, now + 4500, process, "CLIPBOARD_READ", "NSPasteboard.general", "clipboard read"), userInitiated: false }
  ];
}

export function explain(rule) {
  return {
    SSH_KEY_EXFIL: "The process read a likely SSH private key, then contacted the network within five seconds. Treat this as possible credential theft until you verify the destination.",
    ENV_PLUS_NET: "The process read a .env file and then sent data over the network. API keys or tokens may have been exposed if the payload included file contents.",
    WALLET_FILE_READ: "The process touched a known wallet storage path. That is unusual for an AI tool and should be investigated before continuing.",
    BLIND_CLIPBOARD: "The process read clipboard contents without a matching paste action. Clipboard data often contains passwords, tokens, or wallet addresses.",
    MCP_MANIFEST_CHANGE: "An MCP server's advertised tools changed compared with the saved baseline. Review the diff before trusting the server again."
  }[rule] || "This alert matched one of OpenEye's local rules. Review the process, target path or domain, and surrounding events before deciding whether to trust it.";
}

function event(id, timestampMs, process, kind, target, detail) {
  return { id, timestampMs, process, kind, target, detail, userInitiated: false };
}

function alert(rule, severity, event, description, recommendedAction) {
  return { rule, severity, process: event.process.name, target: event.target, description, recommendedAction };
}

function isSshPrivateKey(path) {
  const normalized = normalizePath(path);
  return normalized.includes("/.ssh/id_") && !normalized.endsWith(".pub");
}

function isEnvFile(path) {
  return normalizePath(path).split("/").pop() === ".env";
}

function matchesAny(path, patterns) {
  const normalized = normalizePath(path);
  return patterns.some((pattern) => {
    const candidate = normalizePath(pattern);
    return normalized.startsWith(candidate) || normalized.includes(candidate);
  });
}

function normalizePath(path) {
  const home = process.env.HOME || "";
  return String(path || "").replaceAll("\\", "/").replace(/^~(?=\/)/, home);
}

