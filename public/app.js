// Browser-side controller for the OpenEye dashboard. It receives server-sent
// state snapshots, applies local filters, and renders the live activity views.
let currentState = null;
let paused = false;
let localEvents = [];
let source = null;

const els = {
  status: document.querySelector("#status"),
  processCount: document.querySelector("#processCount"),
  eventCount: document.querySelector("#eventCount"),
  networkCount: document.querySelector("#networkCount"),
  fileCount: document.querySelector("#fileCount"),
  alertCount: document.querySelector("#alertCount"),
  feedRows: document.querySelector("#feedRows"),
  alertList: document.querySelector("#alertList"),
  processList: document.querySelector("#processList"),
  explanation: document.querySelector("#explanation"),
  searchInput: document.querySelector("#searchInput"),
  kindFilter: document.querySelector("#kindFilter"),
  internalToggle: document.querySelector("#internalToggle"),
  hiddenNote: document.querySelector("#hiddenNote"),
  pauseButton: document.querySelector("#pauseButton"),
  clearButton: document.querySelector("#clearButton")
};

connect();

// Re-render local views when filters change; no server round-trip needed.
els.searchInput.addEventListener("input", () => currentState && render(currentState));
els.kindFilter.addEventListener("change", () => currentState && render(currentState));
els.internalToggle.addEventListener("change", () => reconnect());

// Pauses rendering without closing the SSE stream.
els.pauseButton.addEventListener("click", () => {
  paused = !paused;
  els.pauseButton.textContent = paused ? ">" : "II";
  els.pauseButton.title = paused ? "Resume live updates" : "Pause live updates";
});

// Clears the current client-side view; new server events will repopulate it.
els.clearButton.addEventListener("click", () => {
  localEvents = [];
  render({ ...currentState, events: [], alerts: [] });
});

// Opens an SSE connection, including internal OpenEye activity only when asked.
function connect() {
  const query = els.internalToggle.checked ? "?includeInternal=true" : "";
  source = new EventSource(`/events${query}`);
  source.addEventListener("state", (event) => {
    if (paused) {
      return;
    }
    currentState = JSON.parse(event.data);
    localEvents = currentState.events;
    render(currentState);
  });
  source.onerror = () => {
    els.status.textContent = "Connection interrupted. Retrying...";
  };
}

// Reconnects after toggling internal visibility and immediately refreshes state.
function reconnect() {
  if (source) {
    source.close();
  }
  fetch(`/api/state${els.internalToggle.checked ? "?includeInternal=true" : ""}`)
    .then((response) => response.json())
    .then((state) => {
      currentState = state;
      localEvents = state.events;
      render(state);
    })
    .catch(() => {});
  connect();
}

// Updates all dashboard regions from one server state snapshot.
function render(state) {
  const stats = state.stats || {};
  els.processCount.textContent = stats.processes || 0;
  els.eventCount.textContent = stats.events || 0;
  els.networkCount.textContent = stats.network || 0;
  els.fileCount.textContent = stats.files || 0;
  els.alertCount.textContent = stats.alerts || 0;
  const hidden = state.hiddenInternal || {};
  els.hiddenNote.textContent = hidden.events ? `${hidden.events} internal events hidden` : "";
  els.status.textContent = statusText(state);
  renderFeed(state);
  renderAlerts(state.alerts || []);
  renderProcesses(state.topProcesses || []);
}

// Renders the main activity table with alert rows folded into the event stream.
function renderFeed(state) {
  const query = els.searchInput.value.trim().toLowerCase();
  const kind = els.kindFilter.value;
  const alertsAsEvents = (state.alerts || []).map((alert) => ({ ...alert, kind: "ALERT", target: alert.target, process: { name: alert.process, pid: "" } }));
  const rows = [...alertsAsEvents, ...(localEvents.length ? localEvents : state.events || [])]
    .filter((item) => !kind || item.kind.includes(kind) || item.severity === kind)
    .filter((item) => !query || searchable(item).includes(query))
    .slice(0, 350);

  els.feedRows.innerHTML = rows.map((item) => `
    <tr data-id="${item.id || ""}" data-kind="${escapeHtml(item.kind)}">
      <td>${formatTime(item.timestampMs)}</td>
      <td>${escapeHtml(item.process?.name || item.process || "unknown")}<br><small>${escapeHtml(String(item.process?.pid || ""))}</small></td>
      <td>${badge(item)}</td>
      <td class="target">${escapeHtml(item.description || item.target || "")}</td>
    </tr>
  `).join("");

  els.feedRows.querySelectorAll("tr").forEach((row, index) => {
    row.addEventListener("click", () => explain(rows[index]));
  });
}

// Renders recent alerts in the right sidebar.
function renderAlerts(alerts) {
  if (!alerts.length) {
    els.alertList.innerHTML = `<div class="empty">No alerts yet.</div>`;
    return;
  }

  els.alertList.innerHTML = alerts.slice(0, 12).map((alert, index) => `
    <div class="item" data-index="${index}">
      <strong>${escapeHtml(alert.rule)} ${badge(alert)}</strong>
      <span>${escapeHtml(alert.process)} -> ${escapeHtml(alert.target)}</span>
    </div>
  `).join("");

  els.alertList.querySelectorAll(".item").forEach((item, index) => {
    item.addEventListener("click", () => explain(alerts[index]));
  });
}

// Renders the most active processes from the filtered event set.
function renderProcesses(processes) {
  if (!processes.length) {
    els.processList.innerHTML = `<div class="empty">Waiting for process snapshot.</div>`;
    return;
  }

  els.processList.innerHTML = processes.slice(0, 18).map((process) => `
    <div class="item">
      <div>
        <strong>${escapeHtml(process.name || "unknown")}</strong>
        <span>pid ${escapeHtml(String(process.pid))}</span>
      </div>
      <span>${process.count || 0}</span>
    </div>
  `).join("");
}

// Shows a short explanation for the selected event or alert.
async function explain(item) {
  if (!item) {
    return;
  }

  if (item.rule) {
    const response = await fetch(`/api/explain?id=${item.id}`);
    const data = await response.json();
    els.explanation.textContent = data.explanation;
    return;
  }

  if (item.kind === "NETWORK_CONNECT" || item.kind === "NETWORK_SEND") {
    els.explanation.textContent = `${item.process?.name || "This process"} opened a network connection to ${item.target}. Check whether that destination matches what you expect from the app.`;
  } else if (item.kind === "FILE_READ") {
    els.explanation.textContent = `${item.process?.name || "This process"} had this file open during an lsof scan: ${item.target}. This is real activity, but not yet ESF-level syscall tracing.`;
  } else {
    els.explanation.textContent = `${item.process?.name || "This process"} produced ${item.kind}: ${item.target || item.description || ""}`;
  }
}

// Builds the visual label used for event kinds and alert severities.
function badge(item) {
  const severity = String(item.severity || "").toLowerCase();
  const kind = String(item.kind || item.rule || "");
  const cls = severity || (kind.startsWith("FILE") ? "file" : kind.startsWith("NETWORK") ? "network" : "");
  return `<span class="badge ${cls}">${escapeHtml(item.severity || item.rule || item.kind)}</span>`;
}

// Produces the compact connection/scanning status line.
function statusText(state) {
  if (state.errors?.length) {
    return `Monitoring with warnings: ${state.errors[0]}`;
  }
  if (!state.lastScanAt) {
    return "Starting local monitor...";
  }
  const suffix = els.internalToggle.checked ? " Internals visible." : " Internals hidden.";
  return `Live on 127.0.0.1. Last scan ${formatTime(state.lastScanAt)}.${suffix}`;
}

// Combines fields that should be searchable in the live feed.
function searchable(item) {
  return [
    item.kind,
    item.rule,
    item.severity,
    item.process?.name,
    item.process,
    item.target,
    item.description
  ].filter(Boolean).join(" ").toLowerCase();
}

// Formats epoch milliseconds for table display.
function formatTime(timestampMs) {
  if (!timestampMs) return "";
  return new Date(timestampMs).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// Escapes text inserted with innerHTML.
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;"
  })[char]);
}
