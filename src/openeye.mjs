#!/usr/bin/env node
import readline from "node:readline";
import { RuleEngine, demoEvents, explain, parseEventLine } from "./openeye-core.mjs";

const command = process.argv[2] || "help";

if (command === "demo") {
  await runDemo();
} else if (command === "ingest") {
  await runIngest();
} else if (command === "explain") {
  const rule = process.argv[3];
  if (!rule) {
    console.error("usage: openeye explain RULE_NAME");
    process.exit(1);
  }
  console.log(explain(rule));
} else {
  printHelp();
}

async function runDemo() {
  const engine = new RuleEngine();
  for (const event of demoEvents()) {
    printEvent(event);
    for (const alert of engine.evaluate(event)) {
      printAlert(alert);
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

async function runIngest() {
  const engine = new RuleEngine();
  const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of input) {
    if (!line.trim()) {
      continue;
    }
    const event = parseEventLine(line);
    printEvent(event);
    for (const alert of engine.evaluate(event)) {
      printAlert(alert);
    }
  }
}

function printEvent(event) {
  console.log(`${color("[INFO]", "32")} [${event.timestampMs}] [${event.process.name}:${event.process.pid}] ${event.kind} ${event.target} ${event.detail || ""}`);
}

function printAlert(alert) {
  const code = alert.severity === "CRITICAL" ? "31" : alert.severity === "WARNING" ? "33" : "32";
  console.log(`${color(`[${alert.severity}]`, code)} [${alert.rule}] [${alert.process}] ${alert.description} -> ${alert.target}`);
  console.log(`  action: ${alert.recommendedAction}`);
}

function color(text, code) {
  return process.stdout.isTTY ? `\x1b[${code}m${text}\x1b[0m` : text;
}

function printHelp() {
  console.log("OpenEye MVP");
  console.log("");
  console.log("Commands:");
  console.log("  openeye demo");
  console.log("  openeye ingest");
  console.log("  openeye explain RULE_NAME");
  console.log("");
  console.log("Ingest example:");
  console.log("  kind=FILE_READ\\tpid=42\\tprocess=cursor\\ttarget=/Users/me/.ssh/id_ed25519");
}

