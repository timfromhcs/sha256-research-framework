/**
 * Frontend Controller for SHA-256 Research Platform v3.0
 * Pure ES6 client of headless REST and WebSocket API.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tabs
  const navButtons = document.querySelectorAll(".nav-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      navButtons.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const tabId = "tab-" + btn.getAttribute("data-tab");
      const targetPane = document.getElementById(tabId);
      if (targetPane) targetPane.classList.add("active");

      // Load data for active tab
      loadTabData(btn.getAttribute("data-tab"));
    });
  });

  // Initialize Data
  refreshDashboard();
  setupWebSocket();

  // Button Listeners
  document.getElementById("btn-quick-campaign")?.addEventListener("click", runQuickCampaign);
  document.getElementById("btn-start-campaign")?.addEventListener("click", runQuickCampaign);
  document.getElementById("btn-stop-campaign")?.addEventListener("click", stopCampaign);
  document.getElementById("btn-refresh-experiments")?.addEventListener("click", loadExperiments);
  document.getElementById("btn-create-hypothesis")?.addEventListener("click", createHypothesis);
  document.getElementById("btn-submit-verify")?.addEventListener("click", submitVerification);
});

async function apiRequest(endpoint, method = "GET", body = null) {
  const options = { method, headers: { "Content-Type": "application/json" } };
  if (body) options.body = JSON.stringify(body);
  const resp = await fetch(endpoint, options);
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || err.detail || resp.statusText);
  }
  return resp.json();
}

function loadTabData(tabName) {
  if (tabName === "dashboard") refreshDashboard();
  else if (tabName === "experiments") loadExperiments();
  else if (tabName === "hypotheses") loadHypotheses();
  else if (tabName === "models") loadModels();
  else if (tabName === "evidence") loadEvidence();
  else if (tabName === "reports") loadReports();
}

async function refreshDashboard() {
  try {
    const status = await apiRequest("/api/status");
    document.getElementById("metric-system-state").textContent = status.status;
    document.getElementById("metric-device-name").textContent = status.device;
    document.getElementById("metric-exp-count").textContent = status.counts?.experiments || 0;
    document.getElementById("metric-hyp-count").textContent = status.counts?.hypotheses || 0;
    document.getElementById("metric-vulkan-state").textContent = status.vulkan_available ? "ACTIVE (Vulkan 1.4)" : "CPU ONLY";

    const sys = await apiRequest("/api/system");
    const mbBudget = Math.round(sys.memory_budget_bytes / (1024 * 1024));
    document.getElementById("metric-memory-budget").textContent = `Memory Budget: ${mbBudget} MB`;
  } catch (e) {
    console.error("Failed to load dashboard:", e);
  }
}

async function loadExperiments() {
  try {
    const data = await apiRequest("/api/experiments");
    const tbody = document.querySelector("#experiments-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    (data.experiments || []).forEach(exp => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${exp.id}</code></td>
        <td>${exp.hypothesis_id || ""}</td>
        <td><strong>${exp.rounds}</strong></td>
        <td>${exp.solver || ""}</td>
        <td><span class="badge ${getStatusBadge(exp.status)}">${exp.status}</span></td>
        <td>${exp.outcome || "-"}</td>
        <td>${exp.classification || "-"}</td>
        <td>${exp.created_at || ""}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("Failed to load experiments:", e);
  }
}

async function loadHypotheses() {
  try {
    const data = await apiRequest("/api/hypotheses");
    const tbody = document.querySelector("#hypotheses-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    (data.hypotheses || []).forEach(h => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${h.id}</code></td>
        <td><strong>${h.title}</strong></td>
        <td>${h.description || ""}</td>
        <td>${h.falsification_criteria || ""}</td>
        <td><span class="badge badge-${(h.trust_level || 'l0').toLowerCase()}">${h.trust_level || 'L0'}</span></td>
        <td><span class="badge badge-success">${h.status}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("Failed to load hypotheses:", e);
  }
}

async function loadModels() {
  try {
    const data = await apiRequest("/api/models");
    const tbody = document.querySelector("#models-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    (data.models || []).forEach(m => {
      const tr = document.createElement("tr");
      const mbSize = Math.round((m.size_bytes || 0) / (1024 * 1024));
      tr.innerHTML = `
        <td><code>${m.model_id}</code></td>
        <td><strong>${m.name}</strong></td>
        <td>${m.model_class}</td>
        <td>${m.runtime}</td>
        <td>${m.backend}</td>
        <td>${mbSize} MB</td>
        <td><span class="badge ${m.is_loaded ? 'badge-success' : 'badge-secondary'}">${m.is_loaded ? 'LOADED' : 'IDLE'}</span></td>
        <td>
          ${m.is_loaded 
            ? `<button class="btn btn-danger btn-sm" onclick="unloadModel('${m.model_id}')">Unload</button>` 
            : `<button class="btn btn-primary btn-sm" onclick="loadModel('${m.model_id}')">Load</button>`}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("Failed to load models:", e);
  }
}

window.loadModel = async function(modelId) {
  try {
    await apiRequest(`/api/models/${modelId}/load`, "POST");
    loadModels();
  } catch (e) { alert("Load failed: " + e.message); }
};

window.unloadModel = async function(modelId) {
  try {
    await apiRequest(`/api/models/${modelId}/unload`, "POST");
    loadModels();
  } catch (e) { alert("Unload failed: " + e.message); }
};

async function loadEvidence() {
  try {
    const data = await apiRequest("/api/evidence");
    const tbody = document.querySelector("#evidence-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    (data.artifacts || []).forEach(a => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${a.sha256_hash.substring(0, 16)}...</code></td>
        <td><code>${a.experiment_id || ""}</code></td>
        <td>${a.relative_path}</td>
        <td>${a.size_bytes}</td>
        <td>${a.description || ""}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("Failed to load evidence:", e);
  }
}

async function loadReports() {
  try {
    const data = await apiRequest("/api/reports");
    const tbody = document.querySelector("#reports-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    (data.reports || []).forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${r.id}</code></td>
        <td><strong>${r.title}</strong></td>
        <td>${r.report_type}</td>
        <td>${r.file_path}</td>
        <td>${r.created_at}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error("Failed to load reports:", e);
  }
}

async function runQuickCampaign() {
  const roundsInput = document.getElementById("quick-target-rounds");
  const solverInput = document.getElementById("quick-solver");
  const targetRounds = parseInt(roundsInput ? roundsInput.value : 4, 10);
  const solver = solverInput ? solverInput.value : "cadical";

  const resBox = document.getElementById("quick-campaign-result");
  if (resBox) {
    resBox.classList.remove("hidden");
    resBox.textContent = `Launching autonomous research cycle on ${targetRounds} rounds (${solver})...`;
  }

  try {
    const res = await apiRequest("/api/campaign/start", "POST", { target_rounds: targetRounds, solver });
    if (resBox) resBox.textContent = `Campaign cycle triggered: Status ${res.status}. Watching live events...`;
  } catch (e) {
    if (resBox) resBox.textContent = "Error: " + e.message;
  }
}

async function stopCampaign() {
  try {
    await apiRequest("/api/campaign/stop", "POST");
    alert("Campaign paused/stopped.");
  } catch (e) { alert(e.message); }
}

async function createHypothesis() {
  const title = document.getElementById("new-hyp-title").value;
  const description = document.getElementById("new-hyp-desc").value;
  if (!title) return alert("Title required");
  try {
    await apiRequest("/api/hypotheses", "POST", { title, description });
    document.getElementById("new-hyp-title").value = "";
    document.getElementById("new-hyp-desc").value = "";
    loadHypotheses();
  } catch (e) { alert(e.message); }
}

async function submitVerification() {
  const msgA = document.getElementById("ver-msg-a").value;
  const msgB = document.getElementById("ver-msg-b").value;
  const rounds = parseInt(document.getElementById("ver-rounds").value, 10);
  const box = document.getElementById("verifier-verdict-box");

  try {
    const verdict = await apiRequest("/api/verify", "POST", {
      message_a_hex: msgA,
      message_b_hex: msgB,
      rounds: rounds
    });
    box.classList.remove("hidden");
    box.innerHTML = `
      <h3>Verification Verdict</h3>
      <p><strong>Is Valid:</strong> ${verdict.is_valid ? '<span class="text-success">YES (Verified)</span>' : '<span class="text-danger">NO (Rejected)</span>'}</p>
      <p><strong>Classification:</strong> ${verdict.classification}</p>
      <p><strong>Trust Level:</strong> <span class="badge badge-${(verdict.trust_level || 'l1').toLowerCase()}">${verdict.trust_level}</span></p>
      <pre>${verdict.verifier_output || ''}</pre>
    `;
  } catch (e) {
    box.classList.remove("hidden");
    box.innerHTML = `<span class="text-danger">Verification Error: ${e.message}</span>`;
  }
}

function getStatusBadge(status) {
  if (status === "COMPLETED") return "badge-success";
  if (status === "RUNNING") return "badge-info";
  if (status === "QUEUED") return "badge-warning";
  if (status === "FAILED" || status === "REJECTED") return "badge-danger";
  return "badge-secondary";
}

function setupWebSocket() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${window.location.host}/ws/events`;
  try {
    const ws = new WebSocket(wsUrl);
    const logBox = document.getElementById("live-events-box");
    const campBox = document.getElementById("campaign-output-log");

    ws.onopen = () => {
      document.getElementById("ws-status").textContent = "● Live Stream";
      document.getElementById("ws-status").className = "badge badge-info";
    };

    ws.onmessage = (event) => {
      const line = `[${new Date().toLocaleTimeString()}] ${event.data}\n`;
      if (logBox) {
        logBox.textContent += line;
        logBox.scrollTop = logBox.scrollHeight;
      }
      if (campBox) {
        campBox.textContent += line;
        campBox.scrollTop = campBox.scrollHeight;
      }
    };

    ws.onclose = () => {
      document.getElementById("ws-status").textContent = "○ Disconnected";
      document.getElementById("ws-status").className = "badge badge-danger";
      setTimeout(setupWebSocket, 3000);
    };
  } catch (e) {
    console.error("WebSocket error:", e);
  }
}
