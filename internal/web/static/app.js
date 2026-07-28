const state = { tab: "functions", page: 0, limit: 25, query: "", config: null, selectedHash: null };
const $ = (id) => document.getElementById(id);
const fmt = new Intl.NumberFormat();
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

async function boot() {
  try {
    const [config, stats] = await Promise.all([api("/api/v1/config"), api("/api/v1/stats")]);
    state.config = config;
    $("server-name").textContent = config.server_name;
    $("lumina-address").textContent = config.lumina_addr;
    $("connection-flags").textContent = `${config.tls ? "TLS enabled" : "plaintext"} · history ${config.history_limit || "off"}`;
    $("stat-functions").textContent = fmt.format(stats.functions);
    $("stat-versions").textContent = fmt.format(stats.versions);
    $("stat-files").textContent = fmt.format(stats.files);
    $("stat-users").textContent = fmt.format(stats.users);
    $("server-status").textContent = "Server online";
    document.querySelector(".status").classList.add("online");
    $("danger-zone").hidden = !config.allow_deletes;
  } catch (error) {
    $("server-status").textContent = "Server unavailable";
  }
  loadResults();
}

async function loadResults() {
  $("results").innerHTML = '<div class="empty">Loading knowledge…</div>';
  const endpoint = state.tab === "functions" ? "/api/v1/functions" : "/api/v1/files";
  const params = new URLSearchParams({ q: state.query, limit: state.limit, offset: state.page * state.limit });
  try {
    const data = await api(`${endpoint}?${params}`);
    renderResults(data.items);
    $("previous").disabled = state.page === 0;
    $("next").disabled = data.items.length < state.limit;
    $("page-label").textContent = `Page ${state.page + 1}`;
  } catch (error) {
    $("results").innerHTML = `<div class="empty"><div><strong>Could not load records</strong><br>${esc(error.message)}</div></div>`;
  }
}

function renderResults(items) {
  if (!items.length) {
    $("results").innerHTML = '<div class="empty"><div><strong>No records found.</strong><br>Push metadata from IDA or try another search.</div></div>';
    return;
  }
  if (state.tab === "functions") {
    $("results").innerHTML = items.map((item) => `
      <button class="result-row" data-hash="${esc(item.hash)}">
        <strong>${esc(item.name)}</strong>
        <code>${esc(item.hash)}</code>
        <span>Length<b>${fmt.format(item.length)} B</b></span>
        <span>Score<b>${fmt.format(item.score)}</b></span>
        <span>Versions<b>${fmt.format(item.popularity)}</b></span>
      </button>`).join("");
    document.querySelectorAll("[data-hash]").forEach((row) => row.addEventListener("click", () => openFunction(row.dataset.hash)));
  } else {
    $("results").innerHTML = items.map((item) => `
      <button class="result-row" data-file="${esc(item.md5)}">
        <strong>${esc(item.path || "Unknown source path")}</strong>
        <code>${esc(item.md5)}</code>
        <span>Functions<b>${fmt.format(item.functions)}</b></span>
        <span>Updated<b>${esc(shortDate(item.updated_at))}</b></span>
        <span>Type<b>MD5</b></span>
      </button>`).join("");
    document.querySelectorAll("[data-file]").forEach((row) => row.addEventListener("click", () => showFile(row.dataset.file)));
  }
}

async function showFile(md5) {
  state.tab = "functions";
  state.query = "";
  state.page = 0;
  setActiveTab();
  $("results").innerHTML = '<div class="empty">Loading file functions…</div>';
  try {
    const items = await api(`/api/v1/files/${md5}/functions`);
    renderResults(items);
    $("search-input").value = "";
    $("page-label").textContent = `File ${md5.slice(0, 8)}…`;
    $("previous").disabled = true;
    $("next").disabled = true;
  } catch (error) {
    $("results").innerHTML = `<div class="empty">${esc(error.message)}</div>`;
  }
}

async function openFunction(hash) {
  state.selectedHash = hash;
  $("detail-title").textContent = "Loading…";
  $("detail-hash").textContent = hash;
  $("detail-content").innerHTML = '<div class="empty">Reading metadata…</div>';
  $("detail-dialog").showModal();
  try {
    const data = await api(`/api/v1/functions/${hash}`);
    const versions = data.versions;
    $("detail-title").textContent = versions[0].name;
    $("detail-content").innerHTML = versions.map((version, index) => `
      <article class="version ${index === 0 ? "best" : ""}">
        <div class="version-head"><h3>${index === 0 ? "Selected metadata" : `Version ${index + 1}`}</h3><small>score ${fmt.format(version.score)}</small></div>
        <dl>
          <dt>Function</dt><dd>${esc(version.name)} · ${fmt.format(version.length)} bytes</dd>
          <dt>Source file</dt><dd>${esc(version.file_path || version.file_md5)}</dd>
          <dt>IDA database</dt><dd>${esc(version.idb_path || "—")}</dd>
          <dt>Contributor</dt><dd>${esc(version.hostname || "—")}</dd>
          <dt>Updated</dt><dd>${esc(new Date(version.updated_at).toLocaleString())}</dd>
        </dl>
        ${renderComments(version.comments)}
      </article>`).join("");
  } catch (error) {
    $("detail-content").innerHTML = `<div class="empty">${esc(error.message)}</div>`;
  }
}

function renderComments(comments) {
  const valid = (comments || []).filter((comment) => comment.type !== "parse-error");
  if (!valid.length) return '<p>No decoded comments in this metadata record.</p>';
  return `<div>${valid.map((comment) => `<div class="comment"><b>${esc(comment.type)}${comment.offset != null ? ` +0x${comment.offset.toString(16)}` : ""}</b><br>${esc(comment.text)}</div>`).join("")}</div>`;
}

function setActiveTab() {
  document.querySelectorAll("[data-tab]").forEach((button) => button.classList.toggle("active", button.dataset.tab === state.tab));
  $("search-input").placeholder = state.tab === "functions" ? "Search by function name or 128-bit hash" : "Search by source path or file MD5";
}

document.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => {
  state.tab = button.dataset.tab; state.page = 0; state.query = ""; $("search-input").value = ""; setActiveTab(); loadResults();
}));
$("search-form").addEventListener("submit", (event) => { event.preventDefault(); state.query = $("search-input").value.trim(); state.page = 0; loadResults(); });
$("previous").addEventListener("click", () => { if (state.page > 0) state.page--; loadResults(); });
$("next").addEventListener("click", () => { state.page++; loadResults(); });
$("dialog-close").addEventListener("click", () => $("detail-dialog").close());
$("detail-dialog").addEventListener("click", (event) => { if (event.target === $("detail-dialog")) $("detail-dialog").close(); });
$("token-cancel").addEventListener("click", () => $("token-dialog").close());
$("delete-button").addEventListener("click", () => {
  if (state.config.admin_protected && !sessionStorage.getItem("luxToken")) $("token-dialog").showModal();
  else deleteSelected();
});
$("token-form").addEventListener("submit", (event) => {
  event.preventDefault(); sessionStorage.setItem("luxToken", $("token-input").value); $("token-input").value = ""; $("token-dialog").close(); deleteSelected();
});

async function deleteSelected() {
  if (!state.selectedHash || !confirm(`Delete every stored version of ${state.selectedHash}?`)) return;
  const token = sessionStorage.getItem("luxToken") || "";
  try {
    await api(`/api/v1/functions/${state.selectedHash}`, { method: "DELETE", headers: token ? { Authorization: `Bearer ${token}` } : {} });
    $("detail-dialog").close();
    await Promise.all([loadResults(), boot()]);
  } catch (error) {
    if (/token|required|unauthorized/i.test(error.message)) sessionStorage.removeItem("luxToken");
    alert(error.message);
  }
}

function shortDate(value) { return value ? new Date(value).toLocaleDateString() : "—"; }
boot();
