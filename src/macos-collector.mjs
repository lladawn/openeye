// Best-effort macOS collector. It uses built-in ps and lsof snapshots so
// OpenEye can observe real local process/file/socket activity before the
// native Endpoint Security collector exists.
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_LSOF_ARGS = ["-nP", "-w", "-F", "pcftn"];

export class MacosCollector {
  // Tracks seen file/socket handles so repeated lsof scans emit new activity
  // instead of flooding the UI with the same open descriptors forever.
  constructor(options = {}) {
    this.intervalMs = options.intervalMs || 2500;
    this.maxEventsPerScan = options.maxEventsPerScan || 350;
    this.rootPid = options.rootPid || process.pid;
    this.seenFiles = new Set();
    this.seenConnections = new Set();
    this.sequence = 1;
  }

  // Captures one process table and one lsof table, then converts them into
  // normalized OpenEye events.
  async snapshot() {
    const [processes, lsofRecords] = await Promise.all([
      collectProcesses(),
      collectLsof().catch((error) => ({ records: [], error }))
    ]);

    markInternalProcesses(processes, this.rootPid);
    const processByPid = new Map(processes.map((process) => [process.pid, process]));
    const events = this.eventsFromLsof(lsofRecords.records, processByPid);

    return {
      timestampMs: Date.now(),
      processes,
      events,
      errors: lsofRecords.error ? [String(lsofRecords.error.message || lsofRecords.error)] : []
    };
  }

  // Converts lsof records into file and network events attached to processes.
  eventsFromLsof(records, processByPid) {
    const events = [];

    for (const record of records) {
      if (!record.name || !record.pid) {
        continue;
      }

      const process = processByPid.get(record.pid) || {
        pid: record.pid,
        parentPid: null,
        name: record.command || "unknown",
        command: record.command || ""
      };

      if (isNetworkName(record.name) || record.type === "IPv4" || record.type === "IPv6") {
        const key = `${record.pid}:net:${record.name}`;
        if (this.seenConnections.has(key)) {
          continue;
        }
        this.seenConnections.add(key);
        events.push(this.event(process, "NETWORK_CONNECT", record.name, record.fd || ""));
      } else if (isInterestingPath(record.name, record.type)) {
        const key = `${record.pid}:file:${record.name}`;
        if (this.seenFiles.has(key)) {
          continue;
        }
        this.seenFiles.add(key);
        events.push(this.event(process, "FILE_READ", record.name, record.fd || ""));
      }

      if (events.length >= this.maxEventsPerScan) {
        break;
      }
    }

    return events;
  }

  // Builds a normalized event object from collector output.
  event(process, kind, target, detail) {
    return {
      id: this.sequence++,
      timestampMs: Date.now(),
      process,
      kind,
      target,
      detail,
      userInitiated: false
    };
  }
}

// Reads the macOS process table and returns process metadata used by events.
export async function collectProcesses() {
  const { stdout } = await execFileAsync("/bin/ps", ["-axo", "pid=,ppid=,command="], {
    maxBuffer: 8 * 1024 * 1024
  });

  return stdout
    .split("\n")
    .map((line) => line.match(/^\s*(\d+)\s+(\d+)\s+(.+)$/))
    .filter(Boolean)
    .map((match) => {
      const command = match[3] || "unknown";
      const commandPath = command.match(/^"([^"]+)"/)?.[1] || command.split(/\s+/)[0] || "unknown";
      return {
        pid: Number(match[1]),
        parentPid: Number(match[2]),
        name: commandPath.split("/").pop(),
        command,
        internal: false
      };
    });
}

// Marks OpenEye and its child ps/lsof probes so the UI can hide them by default.
function markInternalProcesses(processes, rootPid) {
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  const internalPids = new Set([rootPid]);

  let changed = true;
  while (changed) {
    changed = false;
    for (const process of processes) {
      if (internalPids.has(process.parentPid) && !internalPids.has(process.pid)) {
        internalPids.add(process.pid);
        changed = true;
      }
    }
  }

  for (const process of processes) {
    const command = String(process.command || "").toLowerCase();
    const name = String(process.name || "").toLowerCase();
    process.internal = internalPids.has(process.pid) ||
      internalPids.has(process.parentPid) ||
      command.includes("/users/dawn/code/openeye/") ||
      command.includes("src/openeye.mjs app") ||
      command.includes("src/server.mjs") ||
      (name === "lsof" && internalPids.has(process.parentPid)) ||
      (name === "ps" && internalPids.has(process.parentPid));
  }

  for (const process of processes) {
    if (process.internal && process.parentPid && byPid.has(process.parentPid)) {
      byPid.get(process.parentPid).internal = true;
    }
  }
}

// Runs lsof in machine-readable field mode.
async function collectLsof() {
  const { stdout } = await execFileAsync("/usr/sbin/lsof", DEFAULT_LSOF_ARGS, {
    maxBuffer: 32 * 1024 * 1024
  });

  return { records: parseLsof(stdout) };
}

// Parses lsof -F output into flat records, one per open descriptor.
export function parseLsof(output) {
  const records = [];
  let currentProcess = {};
  let currentFile = null;

  for (const rawLine of output.split("\n")) {
    if (!rawLine) {
      continue;
    }

    const field = rawLine[0];
    const value = rawLine.slice(1);

    if (field === "p") {
      currentProcess = { pid: Number(value) };
      currentFile = null;
    } else if (field === "c") {
      currentProcess.command = value;
    } else if (field === "f") {
      currentFile = { ...currentProcess, fd: value };
      records.push(currentFile);
    } else if (field === "t" && currentFile) {
      currentFile.type = value;
    } else if (field === "n" && currentFile) {
      currentFile.name = value;
    }
  }

  return records;
}

// Identifies lsof names that represent network sockets.
function isNetworkName(name) {
  return /\b(TCP|UDP)\b/.test(name) || name.includes("->");
}

// Keeps high-signal file paths and drops devices, pipes, and noisy system libs.
function isInterestingPath(name, type) {
  if (!name.startsWith("/")) {
    return false;
  }

  if (["CHR", "unix", "KQUEUE", "PIPE", "IPv4", "IPv6"].includes(type)) {
    return false;
  }

  return !name.startsWith("/System/Library/") &&
    !name.startsWith("/usr/lib/") &&
    !name.startsWith("/dev/") &&
    !name.includes("/.Trash/");
}
