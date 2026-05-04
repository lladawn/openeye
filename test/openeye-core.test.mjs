import assert from "node:assert/strict";
import test from "node:test";
import { RuleEngine, parseEventLine } from "../src/openeye-core.mjs";

const processInfo = { pid: 7, parentPid: 1, name: "cursor", command: "cursor-agent" };

test("detects SSH key reads", () => {
  const engine = new RuleEngine();
  const alerts = engine.evaluate({
    id: 1,
    timestampMs: 1000,
    process: processInfo,
    kind: "FILE_READ",
    target: "/Users/dawn/.ssh/id_ed25519",
    detail: ""
  });

  assert.ok(alerts.some((alert) => alert.rule === "SSH_KEY_READ"));
});

test("detects .env plus network correlation", () => {
  const engine = new RuleEngine();
  engine.evaluate({
    id: 1,
    timestampMs: 1000,
    process: processInfo,
    kind: "FILE_READ",
    target: "/tmp/app/.env",
    detail: ""
  });
  const alerts = engine.evaluate({
    id: 2,
    timestampMs: 3000,
    process: processInfo,
    kind: "NETWORK_SEND",
    target: "https://example.invalid/upload",
    detail: ""
  });

  assert.ok(alerts.some((alert) => alert.rule === "ENV_PLUS_NET"));
});

test("ignores non-AI processes", () => {
  const engine = new RuleEngine();
  const alerts = engine.evaluate({
    id: 1,
    timestampMs: 1000,
    process: { pid: 99, parentPid: 1, name: "TextEdit", command: "TextEdit" },
    kind: "FILE_READ",
    target: "/Users/dawn/.ssh/id_rsa",
    detail: ""
  });

  assert.equal(alerts.length, 0);
});

test("parses tab separated ingest lines", () => {
  const event = parseEventLine("kind=FILE_READ\tpid=42\tprocess=codex\ttarget=/tmp/.env");
  assert.equal(event.kind, "FILE_READ");
  assert.equal(event.process.pid, 42);
  assert.equal(event.target, "/tmp/.env");
});

