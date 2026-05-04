#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const args = new Set(process.argv.slice(2));
const stateDir = resolveStateDir();
const baselinePath = path.join(stateDir, "mcp-baseline.json");

if (args.has("--help")) {
  console.log("Usage: openeye-mcp-auditor --demo | --manifest manifest.json");
  process.exit(0);
}

const manifest = args.has("--demo")
  ? demoManifest()
  : readManifest(process.argv[process.argv.indexOf("--manifest") + 1]);

fs.mkdirSync(stateDir, { recursive: true });
const previous = fs.existsSync(baselinePath)
  ? JSON.parse(fs.readFileSync(baselinePath, "utf8"))
  : null;

if (!previous) {
  fs.writeFileSync(baselinePath, JSON.stringify(manifest, null, 2));
  console.log("MCP baseline saved. Re-run after a manifest changes to detect drift.");
  process.exit(0);
}

const diffs = diffTools(previous, manifest);
if (diffs.length === 0) {
  console.log("MCP manifest unchanged.");
} else {
  console.log("MCP_MANIFEST_CHANGE");
  for (const diff of diffs) {
    console.log(`${diff.type}\t${diff.name}\t${diff.detail}`);
  }
  fs.writeFileSync(baselinePath, JSON.stringify(manifest, null, 2));
}

function readManifest(file) {
  if (!file) {
    console.error("missing --manifest file");
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function demoManifest() {
  return {
    server: "demo-mcp",
    tools: [
      { name: "search_docs", description: "Search workspace docs", inputSchema: { type: "object" } },
      { name: "read_file", description: "Read an allowed workspace file", inputSchema: { type: "object" } }
    ]
  };
}

function diffTools(previous, current) {
  const before = new Map((previous.tools || []).map((tool) => [tool.name, JSON.stringify(tool)]));
  const after = new Map((current.tools || []).map((tool) => [tool.name, JSON.stringify(tool)]));
  const diffs = [];

  for (const [name, value] of after) {
    if (!before.has(name)) {
      diffs.push({ type: "ADDED", name, detail: value });
    } else if (before.get(name) !== value) {
      diffs.push({ type: "CHANGED", name, detail: value });
    }
  }

  for (const [name] of before) {
    if (!after.has(name)) {
      diffs.push({ type: "REMOVED", name, detail: "missing from current manifest" });
    }
  }

  return diffs;
}

function resolveStateDir() {
  if (process.env.OPENEYE_STATE_DIR) {
    return process.env.OPENEYE_STATE_DIR;
  }

  const homeState = path.join(process.env.HOME || ".", ".openeye");
  try {
    fs.mkdirSync(homeState, { recursive: true });
    return homeState;
  } catch {
    return path.join(process.cwd(), ".openeye");
  }
}
