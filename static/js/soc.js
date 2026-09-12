let selected = null;

function qs(id){ return document.getElementById(id); }

function badge(text, colorVar){
  return `<span style="padding:4px 8px; border-radius:999px; border:1px solid var(--border); color:${colorVar}; font-weight:600;">${text}</span>`;
}

function sevColor(sev){
  if(sev === "critical") return "var(--critical-red)";
  if(sev === "high") return "var(--high-orange)";
  if(sev === "medium") return "var(--medium-yellow)";
  return "var(--low-green)";
}

async function loadAlerts(){
  const status = qs("filterStatus").value;
  const severity = qs("filterSeverity").value;
  const q = qs("searchBox").value.trim();

  const res = await fetch(`/api/soc/alerts?status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(q)}`);
  const data = await res.json();

  const tbody = qs("socBody");
  tbody.innerHTML = "";

  if(!data.alerts || data.alerts.length === 0){
    tbody.innerHTML = `<tr><td colspan="5" style="padding:15px; color: var(--text-secondary); text-align:center;">No alerts.</td></tr>`;
    return;
  }

  data.alerts.forEach(a => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onmouseenter = () => tr.style.background = "#1c232c";
    tr.onmouseleave = () => tr.style.background = "transparent";
    tr.onclick = () => selectAlert(a);

    tr.innerHTML = `
      <td style="padding:12px 15px; border-bottom:1px solid var(--border); color: var(--text-secondary);">${new Date(a.created_at).toLocaleString()}</td>
      <td style="padding:12px 15px; border-bottom:1px solid var(--border);">${badge(a.severity.toUpperCase(), sevColor(a.severity))}</td>
      <td style="padding:12px 15px; border-bottom:1px solid var(--border);">${a.status}</td>
      <td style="padding:12px 15px; border-bottom:1px solid var(--border);">${a.title}</td>
      <td style="padding:12px 15px; border-bottom:1px solid var(--border); font-family: ui-monospace, monospace;">${a.ip || "-"}</td>
    `;
    tbody.appendChild(tr);
  });
}

function selectAlert(a){
  selected = a;

  qs("detailEmpty").style.display = "none";
  qs("detailBox").style.display = "block";

  qs("dId").innerText = a.id;
  qs("dTitle").innerText = a.title || "-";
  qs("dSummary").innerText = a.summary || "-";
  qs("dIp").innerText = a.ip || "-";
  qs("dAsset").innerText = a.asset || "-";
  qs("dHTS").innerText = (a.hybrid_threat_score ?? "-");

  // ✅ Investigation fields
  qs("statusSelect").value = a.status || "new";
  qs("assigneeInput").value = a.assignee || "";
  qs("prioritySelect").value = a.priority || "p3";
  qs("caseSummary").value = a.case_summary || "";

  renderNotes(a.notes || []);
}

function renderNotes(notes){
  const wrap = qs("notesList");
  wrap.innerHTML = "";

  if(!notes.length){
    wrap.innerHTML = `<div style="color: var(--text-secondary);">No notes yet.</div>`;
    return;
  }

  notes.forEach(n => {
    const div = document.createElement("div");
    div.style.border = "1px solid var(--border)";
    div.style.borderRadius = "8px";
    div.style.padding = "10px";
    div.style.marginBottom = "8px";
    div.style.background = "#10141a";

    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; color: var(--text-secondary); font-size: 0.85rem;">
        <span style="font-family: ui-monospace, monospace;">${n.author || "analyst"}</span>
        <span style="font-family: ui-monospace, monospace;">${new Date(n.ts).toLocaleString()}</span>
      </div>
      <div style="margin-top:6px;">${n.text}</div>
    `;
    wrap.appendChild(div);
  });
}

async function saveAlert(){
  if(!selected) return;

  const payload = {
    status: qs("statusSelect").value,
    assignee: qs("assigneeInput").value.trim() || null,
    priority: qs("prioritySelect").value,
    case_summary: qs("caseSummary").value.trim()
  };

  const res = await fetch(`/api/soc/alerts/${selected.id}`, {
    method: "PATCH",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });

  if(!res.ok){ alert("Save failed"); return; }

  selected = await res.json();
  selectAlert(selected);
  await loadAlerts();
}

async function addNote(){
  if(!selected) return;

  const text = qs("noteText").value.trim();
  if(text.length < 2) return;

  const author = qs("noteAuthor").value.trim() || "analyst";

  const res = await fetch(`/api/soc/alerts/${selected.id}/notes`, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({text, author})
  });

  if(!res.ok){ alert("Note failed"); return; }

  const data = await res.json();
  selected.notes = data.notes;

  qs("noteText").value = "";
  renderNotes(selected.notes);
  await loadAlerts();
}

async function deleteAlert(){
  if(!selected) return;
  if(!confirm("Delete this SOC case?")) return;

  const res = await fetch(`/api/soc/alerts/${selected.id}`, {method:"DELETE"});
  if(!res.ok){ alert("Delete failed"); return; }

  selected = null;
  qs("detailBox").style.display = "none";
  qs("detailEmpty").style.display = "block";
  await loadAlerts();
}

async function ingestFromPackets(onlySuccessful){
  const res = await fetch("/api/soc/ingest_from_packets", {
    method:"POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({max: 50, only_successful: onlySuccessful})
  });

  const data = await res.json();
  alert(`SOC ingest done. Created: ${data.created}`);
  await loadAlerts();
}

function exportJSON(){
  const status = qs("filterStatus").value;
  const severity = qs("filterSeverity").value;
  const q = qs("searchBox").value.trim();

  fetch(`/api/soc/alerts?status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(q)}`)
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "soc_cases.json";
      a.click();
      URL.revokeObjectURL(a.href);
    });
}

window.addEventListener("DOMContentLoaded", () => {
  qs("filterStatus").onchange = loadAlerts;
  qs("filterSeverity").onchange = loadAlerts;

  let t=null;
  qs("searchBox").addEventListener("input", () => {
    clearTimeout(t);
    t=setTimeout(loadAlerts, 250);
  });

  loadAlerts();
});
