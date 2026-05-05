#!/usr/bin/env node
// Local OpenEye dashboard server. It polls the macOS collector, evaluates
// alerts, serves the static UI, and streams state changes over SSE.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { RuleEngine, defaultConfig, explainActivity } from "./openeye-core.mjs";
import { MacosCollector } from "./macos-collector.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, "..", "public");

export function startServer(options = {}) {
  const port = Number(options.port || process.env.PORT || 3737);
  const collector = new MacosCollector({ intervalMs: options.intervalMs || 2500 });
  const engine = new RuleEngine({ ...defaultConfig, monitorAllProcesses: true });
  const clients = new Set();
  const state = {
    startedAt: Date.now(),
    lastScanAt: null,
    processes: [],
    events: [],
    alerts: [],
    errors: []
  };

  // Routes API, SSE, and static dashboard requests through one local server.
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host}`);

    if (url.pathname === "/api/state") {
      sendJson(response, viewState(state, { includeInternal: url.searchParams.get("includeInternal") === "true" }));
      return;
    }

    if (url.pathname === "/api/explain") {
      const id = Number(url.searchParams.get("id"));
      const item = state.alerts.find((alert) => alert.id === id) || state.events.find((event) => event.id === id);
      sendJson(response, { explanation: explainActivity(item) });
      return;
    }

    if (url.pathname === "/events") {
      const includeInternal = url.searchParams.get("includeInternal") === "true";
      response.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive"
      });
      response.write(`event: state\ndata: ${JSON.stringify(viewState(state, { includeInternal }))}\n\n`);
      const client = { response, includeInternal };
      clients.add(client);
      request.on("close", () => clients.delete(client));
      return;
    }

    serveStatic(url.pathname, response);
  });

  // Polls macOS, stores bounded history, evaluates rules, and broadcasts state.
  async function scan() {
    try {
      const snapshot = await collector.snapshot();
      state.lastScanAt = snapshot.timestampMs;
      state.processes = snapshot.processes;
      state.errors = snapshot.errors;

      for (const event of snapshot.events) {
        remember(state.events, event, 1000);
        for (const alert of engine.evaluate(event)) {
          remember(state.alerts, { ...alert, id: event.id, timestampMs: event.timestampMs, kind: "ALERT", internal: Boolean(event.process?.internal) }, 300);
        }
      }

      broadcast(clients, "state", state);
    } catch (error) {
      state.errors = [String(error.message || error)];
      broadcast(clients, "state", state);
    }
  }

  server.listen(port, "127.0.0.1", () => {
    console.log(`OpenEye dashboard: http://127.0.0.1:${port}`);
    scan();
    setInterval(scan, collector.intervalMs);
  });

  return server;
}

// Builds the client-facing state, optionally including OpenEye's own internals.
function viewState(state, options = {}) {
  const includeInternal = options.includeInternal || false;
  const processes = includeInternal ? state.processes : state.processes.filter((process) => !process.internal);
  const events = includeInternal ? state.events : state.events.filter((event) => !event.process?.internal);
  const alerts = includeInternal ? state.alerts : state.alerts.filter((alert) => !alert.internal);
  const networkEvents = events.filter((event) => event.kind === "NETWORK_CONNECT" || event.kind === "NETWORK_SEND");
  const fileEvents = events.filter((event) => event.kind === "FILE_READ" || event.kind === "FILE_WRITE");
  return {
    ...state,
    processes,
    events: events.slice(-350).reverse(),
    alerts: alerts.slice(-100).reverse(),
    hiddenInternal: {
      processes: state.processes.length - processes.length,
      events: state.events.length - events.length,
      alerts: state.alerts.length - alerts.length
    },
    stats: {
      processes: processes.length,
      events: events.length,
      alerts: alerts.length,
      network: networkEvents.length,
      files: fileEvents.length,
      critical: alerts.filter((alert) => alert.severity === "CRITICAL").length,
      warnings: alerts.filter((alert) => alert.severity === "WARNING").length
    },
    topProcesses: topProcesses(events, processes)
  };
}

// Ranks processes by observed activity for the sidebar.
function topProcesses(events, processes) {
  const counts = new Map();
  for (const event of events) {
    const key = `${event.process.pid}:${event.process.name}`;
    const entry = counts.get(key) || { ...event.process, count: 0, network: 0, files: 0 };
    entry.count += 1;
    if (event.kind.startsWith("NETWORK")) entry.network += 1;
    if (event.kind.startsWith("FILE")) entry.files += 1;
    counts.set(key, entry);
  }

  if (counts.size === 0) {
    return processes.slice(0, 20).map((process) => ({ ...process, count: 0, network: 0, files: 0 }));
  }

  return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, 30);
}

// Appends to a bounded in-memory list.
function remember(list, item, limit) {
  list.push(item);
  if (list.length > limit) {
    list.splice(0, list.length - limit);
  }
}

// Sends each SSE client the view it requested, filtered or internal-inclusive.
function broadcast(clients, event, data) {
  for (const client of clients) {
    const payload = `event: ${event}\ndata: ${JSON.stringify(viewState(data, { includeInternal: client.includeInternal }))}\n\n`;
    client.response.write(payload);
  }
}

// Writes a JSON response with a consistent content type.
function sendJson(response, data) {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify(data));
}

// Serves dashboard assets from public/ and prevents path traversal.
function serveStatic(requestPath, response) {
  const cleanPath = requestPath === "/" ? "/index.html" : requestPath;
  const filePath = path.normalize(path.join(publicDir, cleanPath));

  if (!filePath.startsWith(publicDir)) {
    response.writeHead(403);
    response.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      response.writeHead(404);
      response.end("Not found");
      return;
    }
    response.writeHead(200, { "Content-Type": contentType(filePath) });
    response.end(content);
  });
}

// Maps static asset extensions to simple content types.
function contentType(filePath) {
  if (filePath.endsWith(".js")) return "text/javascript";
  if (filePath.endsWith(".css")) return "text/css";
  if (filePath.endsWith(".html")) return "text/html";
  return "application/octet-stream";
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer({ port: process.argv[2] });
}
