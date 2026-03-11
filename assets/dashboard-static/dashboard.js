const api = {
  pipelineStatus: "/api/pipeline-status",
  alerts: "/api/alerts?status=active&limit=25",
  devices: "/api/devices?status=unknown&limit=12",
  networkHealth: "/api/network-health",
  build: "/build.json",
};

const elements = {
  pipelineStatus: document.querySelector("#pipeline-status"),
  activeAlerts: document.querySelector("#active-alerts"),
  unknownDevices: document.querySelector("#unknown-devices"),
  networkHealth: document.querySelector("#network-health"),
  alertCount: document.querySelector("#alert-count"),
  deviceCount: document.querySelector("#device-count"),
  lastRefresh: document.querySelector("#last-refresh"),
  dashboardBuild: document.querySelector("#dashboard-build"),
  refreshButton: document.querySelector("#refresh-button"),
  alertTemplate: document.querySelector("#alert-template"),
  deviceTemplate: document.querySelector("#device-template"),
  detailDrawer: document.querySelector("#detail-drawer"),
  detailClose: document.querySelector("#detail-close"),
  detailKind: document.querySelector("#detail-kind"),
  detailTitle: document.querySelector("#detail-title"),
  detailMeta: document.querySelector("#detail-meta"),
  detailTriageSection: document.querySelector("#detail-triage-section"),
  detailTriageBadge: document.querySelector("#detail-triage-badge"),
  detailTriageSummary: document.querySelector("#detail-triage-summary"),
  alertReviewSection: document.querySelector("#alert-review-section"),
  detailActions: document.querySelector("#detail-actions"),
  reviewVerdict: document.querySelector("#review-verdict"),
  reviewComment: document.querySelector("#review-comment"),
  reviewResolve: document.querySelector("#review-resolve"),
};

const detailState = {
  type: null,
  alertId: null,
  deviceIp: null,
};

async function getJson(url, fallback) {
  try {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error(`Failed to fetch ${url}`, error);
    return fallback;
  }
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function setEmpty(container, text) {
  container.innerHTML = `<div class="empty">${text}</div>`;
}

function label(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatTimestamp(value) {
  if (!value) {
    return "Unknown";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString();
}

function formatJson(value) {
  if (!value || (typeof value === "object" && !Object.keys(value).length)) {
    return "No data available.";
  }
  return JSON.stringify(value, null, 2);
}

function formatConfidence(value) {
  if (value == null || value === "") {
    return "n/a";
  }
  const numeric = Number(value);
  if (Number.isNaN(numeric)) {
    return value;
  }
  return `${Math.round(numeric * 100)}%`;
}

function normalizeVerdictForSelect(value) {
  const verdict = String(value || "").toLowerCase();
  if (["allowlisted", "benign", "expected", "false_positive", "likely_benign"].includes(verdict)) {
    return "likely_benign";
  }
  if (["compromised", "confirmed_malicious", "likely_malicious", "malicious", "suspicious"].includes(verdict)) {
    return "likely_malicious";
  }
  return "needs_review";
}

function effectiveVerdict(alert) {
  return alert.user_verdict || alert.triage_verdict || alert.verdict || "needs_review";
}

function alertSourceLabel(alert) {
  const triageName = alert?.triage_reasoning?.device_context?.friendly_name;
  return triageName || alert.src_name || alert.src_ip || alert.domain || alert.kind || "Alert";
}

function alertDestinationLabel(alert) {
  const triageDomain = alert?.triage_reasoning?.adguard_context?.domain;
  const dstIp = alert?.dst_ip;
  const domain = alert?.domain || triageDomain;
  if (domain && dstIp) {
    return `${domain} (${dstIp})`;
  }
  return dstIp || domain || "review";
}

function verdictClass(verdict) {
  const normalized = normalizeVerdictForSelect(verdict);
  return `verdict-${normalized}`;
}

function showError(error) {
  console.error(error);
  window.alert(`Dashboard action failed: ${error.message}`);
}

function detailMetaTable(entries) {
  return Object.entries(entries)
    .map(([key, value]) => `<div><dt>${key}</dt><dd>${value ?? "n/a"}</dd></div>`)
    .join("");
}

function renderPipelineStatus(payload) {
  if (!payload) {
    elements.pipelineStatus.innerHTML = `<div class="empty">No pipeline status available yet.</div>`;
    return;
  }

  const sections = [
    {
      title: "Ingest",
      values: {
        Status: payload.ingest?.status,
        "Last Run": formatTimestamp(payload.ingest?.last_run),
        "Gap Free Since": formatTimestamp(payload.ingest?.gap_free_since),
        "PCAPs / 24h": payload.ingest?.pcaps_processed_24h ?? 0,
        "Errors / 24h": payload.ingest?.errors_24h ?? 0,
      },
    },
    {
      title: "Analysis",
      values: {
        Status: payload.analysis?.status,
        "Last Run": formatTimestamp(payload.analysis?.last_run),
        "Avg Runtime": payload.analysis?.avg_processing_time_sec ? `${payload.analysis.avg_processing_time_sec}s` : "n/a",
        "Last Runtime": payload.analysis?.last_duration_sec ? `${payload.analysis.last_duration_sec}s` : "n/a",
        "Errors / 24h": payload.analysis?.errors_24h ?? 0,
      },
    },
    {
      title: "RITA",
      values: {
        Status: payload.rita?.status,
        "Last Import": payload.rita?.status === "disabled" ? "Disabled" : formatTimestamp(payload.rita?.last_import),
        "Dataset MB": payload.rita?.dataset_size_mb ?? 0,
        "Records": payload.rita?.status === "disabled" ? "n/a" : (payload.rita?.records_count ?? 0),
      },
    },
  ];

  elements.pipelineStatus.innerHTML = sections
    .map((section) => {
      const values = Object.entries(section.values)
        .map(([key, value]) => `<div><dt>${key}</dt><dd>${value ?? "n/a"}</dd></div>`)
        .join("");
      return `
        <article class="card">
          <h3>${section.title}</h3>
          <dl class="detail-grid">${values}</dl>
        </article>
      `;
    })
    .join("");
}

function formatNarrativeValue(value) {
  if (value == null || value === "") {
    return null;
  }
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : null;
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function buildEvidenceNarrative(evidence) {
  const entries = Object.entries(evidence || {})
    .filter(([key, value]) => key !== "label" && formatNarrativeValue(value) != null)
    .slice(0, 6);
  if (!entries.length) {
    return "";
  }

  const parts = entries.map(([key, value]) => `${label(key).toLowerCase()} ${formatNarrativeValue(value)}`);
  return `Evidence observed: ${parts.join("; ")}.`;
}

function buildTriageNarrative(alert) {
  const narrative = [];
  const summary = alert.triage_summary;
  if (summary) {
    narrative.push(summary.trim());
  }

  const recommendation = (alert.recommendation?.reason || "").trim();
  if (recommendation && recommendation !== summary) {
    narrative.push(`Recommendation: ${recommendation}`);
  }

  const comparisonNotes = (alert.triage_reasoning?.comparison_notes || []).filter(Boolean);
  if (comparisonNotes.length) {
    narrative.push(`Historical comparison: ${comparisonNotes.join(" ")}`);
  }

  const evidenceNarrative = buildEvidenceNarrative(alert.evidence || {});
  if (evidenceNarrative) {
    narrative.push(evidenceNarrative);
  }

  return narrative.join(" ").trim();
}

function setTriageBadge(verdict, confidence) {
  const normalized = normalizeVerdictForSelect(verdict);
  elements.detailTriageBadge.className = `panel-meta ${verdictClass(normalized)}`;
  elements.detailTriageBadge.textContent = `${label(normalized)}${confidence != null ? ` · ${formatConfidence(confidence)}` : ""}`;
}

function openDrawer() {
  elements.detailDrawer.classList.remove("hidden");
}

function closeDrawer() {
  detailState.type = null;
  detailState.alertId = null;
  detailState.deviceIp = null;
  elements.detailDrawer.classList.add("hidden");
  elements.reviewComment.value = "";
  elements.reviewVerdict.value = "needs_review";
}

async function resolveAlertFromReview() {
  if (!detailState.alertId) {
    return;
  }

  const body = {
    user_verdict: elements.reviewVerdict.value,
    user_comment: elements.reviewComment.value.trim(),
    reviewed_by: "dashboard",
    status: "resolved",
  };

  try {
    await postJson(`/api/alerts/${detailState.alertId}/review`, body);
    await refreshAll();
    closeDrawer();
  } catch (error) {
    showError(error);
  }
}

function configureAlertDrawer(alert) {
  detailState.type = "alert";
  detailState.alertId = alert.alert_id;
  detailState.deviceIp = null;

  elements.detailTriageSection.classList.remove("hidden");
  elements.alertReviewSection.classList.remove("hidden");
  elements.detailKind.textContent = label(alert.kind);
  elements.detailTitle.textContent = `${alertSourceLabel(alert)} → ${alertDestinationLabel(alert)}`;
  elements.detailMeta.classList.add("hidden");
  elements.detailMeta.innerHTML = "";

  setTriageBadge(alert.triage_verdict || "needs_review", alert.triage_confidence);
  elements.detailTriageSummary.textContent = buildTriageNarrative(alert) || "No triage summary available.";
  elements.reviewVerdict.value = normalizeVerdictForSelect(alert.triage_verdict || alert.verdict || "needs_review");
  elements.reviewComment.value = alert.user_comment || "";
  openDrawer();
}

async function showAlertDetails(alertId) {
  const alert = await getJson(`/api/alerts/${alertId}`, null);
  if (!alert) {
    return;
  }
  configureAlertDrawer(alert);
}

async function showDeviceDetails(ip) {
  const device = await getJson(`/api/devices/${ip}`, null);
  if (!device) {
    return;
  }

  detailState.type = "device";
  detailState.alertId = null;
  detailState.deviceIp = ip;

  elements.detailTriageSection.classList.add("hidden");
  elements.alertReviewSection.classList.add("hidden");
  elements.detailMeta.classList.remove("hidden");
  elements.detailKind.textContent = "Device";
  elements.detailTitle.textContent = device.friendly_name || device.ip;
  elements.detailMeta.innerHTML = detailMetaTable({
    IP: device.ip,
    Type: device.device_type || "unknown",
    Manufacturer: device.manufacturer || "unknown",
    "First Seen": formatTimestamp(device.first_seen),
    "Last Seen": formatTimestamp(device.last_seen),
    "Total Connections": device.total_connections || 0,
    "Unique Destinations": device.unique_destinations_count || 0,
    Monitored: device.is_monitored ? "yes" : "no",
    Trusted: device.is_trusted ? "yes" : "no",
  });
  openDrawer();
}

function renderAlerts(payload) {
  const alerts = payload?.alerts || [];
  elements.alertCount.textContent = `${alerts.length} alerts`;

  if (!alerts.length) {
    setEmpty(elements.activeAlerts, "No active alerts in the current rolling window.");
    return;
  }

  elements.activeAlerts.innerHTML = "";
  for (const alert of alerts) {
    const node = elements.alertTemplate.content.cloneNode(true);
    const severityBadge = node.querySelector(".severity");
    const kindBadge = node.querySelector(".kind");

    severityBadge.textContent = alert.severity || "unknown";
    severityBadge.classList.add(`severity-${alert.severity || "info"}`);
    kindBadge.textContent = label(alert.kind);
    kindBadge.classList.add(verdictClass(effectiveVerdict(alert)));

    node.querySelector(".card-title").textContent = `${alertSourceLabel(alert)} → ${alertDestinationLabel(alert)}`;
    node.querySelector(".card-copy").textContent = alert.triage_summary || alert.recommendation?.reason || alert.evidence?.detection_type || "No recommendation available.";

    const detailGrid = node.querySelector(".detail-grid");
    detailGrid.innerHTML = detailMetaTable({
      Status: alert.status,
      "Suggested Verdict": label(alert.triage_verdict || "needs_review"),
      Confidence: formatConfidence(alert.triage_confidence),
      "First Seen": formatTimestamp(alert.first_seen),
      "Last Seen": formatTimestamp(alert.last_seen),
      Occurrences: alert.occurrence_count,
      Source: alertSourceLabel(alert) || "n/a",
      Destination: alertDestinationLabel(alert) || "n/a",
    });

    node.querySelector(".details").addEventListener("click", () => showAlertDetails(alert.alert_id));

    elements.activeAlerts.appendChild(node);
  }
}

function renderDevices(payload) {
  const devices = payload?.devices || [];
  elements.deviceCount.textContent = `${devices.length} devices`;

  if (!devices.length) {
    setEmpty(elements.unknownDevices, "No unknown devices are currently visible.");
    return;
  }

  elements.unknownDevices.innerHTML = "";
  for (const device of devices) {
    const node = elements.deviceTemplate.content.cloneNode(true);
    node.querySelector(".card-title").textContent = device.friendly_name || device.ip;
    node.querySelector(".card-copy").textContent = `Last seen ${formatTimestamp(device.last_seen)}. ${device.total_connections || 0} connections.`;
    node.querySelector(".details").addEventListener("click", () => showDeviceDetails(device.ip));
    elements.unknownDevices.appendChild(node);
  }
}

function renderNetworkHealth(payload) {
  if (!payload) {
    setEmpty(elements.networkHealth, "No network health data available.");
    return;
  }

  const devices = payload.devices || {};
  const alerts = payload.alerts || {};
  elements.networkHealth.innerHTML = `
    <article class="card">
      <h3>Devices</h3>
      <dl class="detail-grid">
        <div><dt>Total</dt><dd>${devices.total || 0}</dd></div>
        <div><dt>Known</dt><dd>${devices.known || 0}</dd></div>
        <div><dt>Unknown</dt><dd>${devices.unknown || 0}</dd></div>
      </dl>
    </article>
    <article class="card">
      <h3>Alerts</h3>
      <dl class="detail-grid">
        <div><dt>Total</dt><dd>${alerts.total || 0}</dd></div>
        <div><dt>Active</dt><dd>${alerts.active || 0}</dd></div>
        <div><dt>Severities</dt><dd>${Object.entries(alerts.by_severity || {}).map(([key, value]) => `${key}:${value}`).join(", ") || "n/a"}</dd></div>
      </dl>
    </article>
  `;
}

async function refreshAll() {
  const [build, status, alerts, devices, networkHealth] = await Promise.all([
    getJson(api.build, null),
    getJson(api.pipelineStatus, null),
    getJson(api.alerts, { alerts: [] }),
    getJson(api.devices, { devices: [] }),
    getJson(api.networkHealth, null),
  ]);

  elements.dashboardBuild.textContent = build?.generated_at ? formatTimestamp(build.generated_at) : "Unavailable";
  elements.lastRefresh.textContent = new Date().toLocaleString();
  renderPipelineStatus(status);
  renderAlerts(alerts);
  renderDevices(devices);
  renderNetworkHealth(networkHealth);
}

elements.refreshButton.addEventListener("click", () => refreshAll());
elements.detailClose.addEventListener("click", closeDrawer);
elements.detailDrawer.addEventListener("click", (event) => {
  if (event.target === elements.detailDrawer) {
    closeDrawer();
  }
});
elements.reviewResolve.addEventListener("click", resolveAlertFromReview);

refreshAll();
setInterval(refreshAll, 30000);
