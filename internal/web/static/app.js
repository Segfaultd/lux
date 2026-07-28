"use strict";

const state = {
  config: null,
  pages: {
    projects: { page: 0, query: "", more: false },
    functions: { page: 0, query: "", more: false },
    files: { page: 0, query: "", more: false },
  },
  history: { view: "history", page: 0, more: false },
  sessionQuery: "",
  limit: 50,
};
const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));
const date = (value) => value ? new Date(value).toLocaleString() : "—";
const number = new Intl.NumberFormat();
const deleteAttrs = () => state.config?.allow_deletes ? "" : 'disabled title="Enable LUX_ALLOW_DELETES to use destructive actions"';

function adminOptions(method = "GET", body) {
  const token = sessionStorage.getItem("luxAdminToken") || "";
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return { method, headers, body: body === undefined ? undefined : JSON.stringify(body) };
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) {
    const error = new Error(body.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function notify(message, kind = "ok") {
  const notice = $("notice");
  notice.textContent = message;
  notice.className = kind;
  notice.hidden = false;
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => { notice.hidden = true; }, 5000);
}

function handleError(error) {
  if (error.status === 401) {
    sessionStorage.removeItem("luxAdminToken");
    updateLockState();
  }
  notify(error.message, "error");
}

function updateLockState() {
  const unlocked = Boolean(sessionStorage.getItem("luxAdminToken"));
  $("admin-state").textContent = unlocked ? "Token loaded" : "Locked";
  $("admin-lock").disabled = !unlocked;
}

function emptyRow(message = "No records.") {
  return `<tr><td colspan="10">${esc(message)}</td></tr>`;
}

async function boot() {
  updateLockState();
  try {
    const [config, stats] = await Promise.all([api("/api/v1/config"), api("/api/v1/stats")]);
    state.config = config;
    $("server-status").textContent = `${config.server_name} online`;
    renderStats(stats);
    renderConfig(config);
  } catch (error) {
    $("server-status").textContent = "Server unavailable";
    handleError(error);
  }
}

function renderStats(stats) {
  const values = [
    ["Functions", stats.functions],
    ["Metadata versions", stats.versions],
    ["Files", stats.files],
    ["Contributors", stats.users],
    ["IDA accounts", stats.accounts],
    ["Projects / IDBs", stats.databases],
    ["Pushes", stats.pushes],
    ["History records", stats.history_records],
  ];
  $("stats").innerHTML = values.map(([label, value]) =>
    `<div><strong>${number.format(value)}</strong><span>${esc(label)}</span></div>`).join("");
}

async function loadUserStats(event) {
  event.preventDefault();
  const usernames = String(new FormData(event.target).get("username") || "").trim();
  const table = $("user-stats-table");
  table.innerHTML = '<tr><td colspan="6">Loading…</td></tr>';
  try {
    const data = await api(`/api/v1/stats?username=${encodeURIComponent(usernames)}`);
    table.innerHTML = data.items.length ? data.items.map((stats) => `
      <tr><td><strong>${esc(stats.username)}</strong></td>
        <td>${number.format(stats.functions)}</td><td>${number.format(stats.pushes)}</td>
        <td>${number.format(stats.history_records)}</td><td>${number.format(stats.databases)}</td>
        <td>${number.format(stats.files)}</td></tr>`).join("") :
      '<tr><td colspan="6">No matching users.</td></tr>';
  } catch (error) {
    table.innerHTML = `<tr><td colspan="6">${esc(error.message)}</td></tr>`;
    handleError(error);
  }
}

function configRows(config) {
  return [
    ["Server name", config.server_name],
    ["Lumina address", config.lumina_addr],
    ["Transport", config.tls ? "TLS" : "Plaintext"],
    ["Admin token", config.admin_protected ? "Configured" : "Not configured"],
    ["Destructive actions", config.allow_deletes ? "Enabled" : "Disabled"],
    ["History limit", config.history_limit || "Disabled"],
  ];
}

function renderConfig(config) {
  const rows = configRows(config).map(([key, value]) =>
    `<tr><th>${esc(key)}</th><td><code>${esc(value)}</code></td></tr>`).join("");
  $("connection-summary").innerHTML = rows;
  $("server-config").innerHTML = rows;
}

async function loadAccounts() {
  $("accounts-table").innerHTML = emptyRow("Loading…");
  try {
    const data = await api("/api/v1/accounts", adminOptions());
    $("accounts-table").innerHTML = data.items.length ? data.items.map((account) => `
      <tr>
        <td><strong>${esc(account.username)}</strong></td>
        <td><input type="email" value="${esc(account.email || "")}" maxlength="320"
          data-account-field="email" data-username="${esc(account.username)}"></td>
        <td><input value="${esc(account.license_id || "")}" maxlength="16"
          data-account-field="license_id" data-username="${esc(account.username)}"></td>
        <td>
          <label><input type="checkbox" data-account-field="is_admin"
            data-username="${esc(account.username)}" ${account.is_admin ? "checked" : ""}> Admin</label><br>
          <label><input type="checkbox" data-account-field="can_delete_history"
            data-username="${esc(account.username)}" ${account.can_delete_history ? "checked" : ""}> Delete history</label>
        </td>
        <td>${account.enabled ? "Enabled" : "Disabled"}</td>
        <td>${account.password_set ? "Set" : "Not set"}</td>
        <td>${esc(date(account.last_login_at))}</td>
        <td>${esc(date(account.created_at))}</td>
        <td class="actions">
          <button data-account="password" data-username="${esc(account.username)}">Set password</button>
          <button data-account="sessions" data-username="${esc(account.username)}">Disconnect sessions</button>
          <button data-account="toggle" data-enabled="${account.enabled}" data-username="${esc(account.username)}">${account.enabled ? "Disable" : "Enable"}</button>
          <button class="danger" data-account="delete" data-username="${esc(account.username)}">Delete</button>
        </td>
      </tr>`).join("") : emptyRow();
  } catch (error) {
    $("accounts-table").innerHTML = emptyRow(error.message);
    handleError(error);
  }
}

async function accountAction(button) {
  const username = button.dataset.username;
  try {
    if (button.dataset.account === "password") {
      const password = prompt(`New password for ${username} (8–72 bytes):`);
      if (password === null) return;
      await api(`/api/v1/accounts/${encodeURIComponent(username)}/password`, adminOptions("PUT", { password }));
    } else if (button.dataset.account === "toggle") {
      await api(`/api/v1/accounts/${encodeURIComponent(username)}`, adminOptions("PATCH", { enabled: button.dataset.enabled !== "true" }));
    } else if (button.dataset.account === "sessions") {
      if (!confirm(`Disconnect every active session for "${username}"?`)) return;
      const result = await api(`/api/v1/accounts/${encodeURIComponent(username)}/sessions`, adminOptions("DELETE"));
      notify(`Disconnected ${result.terminated} session(s) for ${username}.`);
      await loadSessions();
      return;
    } else {
      if (!confirm(`Delete login account "${username}"? Historical attribution remains.`)) return;
      await api(`/api/v1/accounts/${encodeURIComponent(username)}`, adminOptions("DELETE"));
    }
    notify(`Account ${username} updated.`);
    await Promise.all([loadAccounts(), refreshStats()]);
  } catch (error) { handleError(error); }
}

async function loadSessions() {
  const body = $("sessions-table");
  body.innerHTML = emptyRow("Loading…");
  try {
    const data = await api("/api/v1/sessions", adminOptions());
    const query = state.sessionQuery.toLocaleLowerCase();
    const sessions = data.items.filter((item) => !query || [
      item.username, item.is_admin ? "admin" : "regular",
      item.can_delete_history ? "delete history" : "",
      item.remote_address, item.hostname,
      item.current_operation, item.last_operation,
    ].some((value) => String(value || "").toLocaleLowerCase().includes(query)));
    body.innerHTML = sessions.length ? sessions.map((item) => `
      <tr>
        <td>${item.id}</td>
        <td><strong>${esc(item.username)}</strong><br>${item.is_admin ? "Administrator" : "Regular user"}${item.can_delete_history ? " / delete history" : ""}</td>
        <td><code>${esc(item.remote_address)}</code><br>${esc(item.hostname || "—")}</td>
        <td>${item.protocol_version}</td>
        <td>${esc(date(item.connected_at))}</td>
        <td>${esc(date(item.last_activity_at))}</td>
        <td>${esc(item.current_operation || item.last_operation || "idle")}</td>
        <td>${number.format(item.requests)} / ${number.format(item.errors)}</td>
        <td>${number.format(item.bytes_read)} in / ${number.format(item.bytes_written)} out</td>
        <td><button class="danger" data-session-terminate="${item.id}">Terminate</button></td>
      </tr>`).join("") : emptyRow(query ? "No matching sessions." : "No active sessions.");
  } catch (error) {
    body.innerHTML = emptyRow(error.message);
    handleError(error);
  }
}

async function terminateSession(button) {
  const id = button.dataset.sessionTerminate;
  if (!confirm(`Terminate Lumina session ${id}?`)) return;
  try {
    await api(`/api/v1/sessions/${id}`, adminOptions("DELETE"));
    notify(`Session ${id} terminated.`);
    await loadSessions();
  } catch (error) { handleError(error); }
}

async function setAccountField(input) {
  const username = input.dataset.username;
  const field = input.dataset.accountField;
  const value = input.type === "checkbox" ? input.checked : input.value.trim();
  try {
    await api(`/api/v1/accounts/${encodeURIComponent(username)}`, adminOptions("PATCH", { [field]: value }));
    notify(`Account ${username} updated.`);
    await loadAccounts();
  } catch (error) {
    handleError(error);
    await loadAccounts();
  }
}

async function loadCollection(resource) {
  const page = state.pages[resource];
  const tbody = $(`${resource}-table`);
  tbody.innerHTML = emptyRow("Loading…");
  const params = new URLSearchParams({
    q: page.query, limit: state.limit, offset: page.page * state.limit,
  });
  try {
    const data = await api(`/api/v1/${resource}?${params}`);
    page.more = data.items.length === state.limit;
    renderCollection(resource, data.items);
    updatePager(resource);
  } catch (error) {
    tbody.innerHTML = emptyRow(error.message);
    handleError(error);
  }
}

function renderCollection(resource, items) {
  if (resource === "projects") {
    $("projects-table").innerHTML = items.length ? items.map((item) => `
      <tr class="clickable" data-project-id="${item.id}">
        <td>${item.id}</td><td>${esc(item.idb_path)}</td><td>${esc(item.file_path || item.file_md5)}</td>
        <td>${esc(item.username || "—")} / ${esc(item.hostname || "—")}</td>
        <td>${number.format(item.functions)} (${number.format(item.versions)} versions)</td><td>${esc(date(item.updated_at))}</td>
      </tr>`).join("") : emptyRow();
  } else if (resource === "functions") {
    $("functions-table").innerHTML = items.length ? items.map((item) => `
      <tr class="clickable" data-function-hash="${esc(item.hash)}">
        <td><strong>${esc(item.name)}</strong></td><td><code>${esc(item.hash)}</code></td>
        <td>${number.format(item.length)}</td><td>${number.format(item.score)}</td>
        <td>${number.format(item.popularity)}</td><td>${esc(date(item.updated_at))}</td>
      </tr>`).join("") : emptyRow();
  } else {
    $("files-table").innerHTML = items.length ? items.map((item) => `
      <tr class="clickable" data-file-md5="${esc(item.md5)}">
        <td>${esc(item.path || "—")}</td><td><code>${esc(item.md5)}</code></td>
        <td>${number.format(item.functions)}</td><td>${esc(date(item.updated_at))}</td>
      </tr>`).join("") : emptyRow();
  }
}

function updatePager(resource) {
  const page = state.pages[resource];
  const pager = document.querySelector(`[data-pager="${resource}"]`);
  pager.querySelector('[data-dir="-1"]').disabled = page.page === 0;
  pager.querySelector('[data-dir="1"]').disabled = !page.more;
  pager.querySelector("span").textContent = `Page ${page.page + 1}`;
}

async function openProject(id) {
  const target = $("project-detail");
  target.innerHTML = "<p>Loading…</p>";
  try {
    const project = await api(`/api/v1/projects/${id}`);
    target.innerHTML = `
      <h2>Project ${project.id}</h2>
      <form id="project-edit">
        <label>File path<input name="file_path" value="${esc(project.file_path)}"></label>
        <label>IDB path<input name="idb_path" value="${esc(project.idb_path)}"></label>
        <dl>
          <dt>File MD5</dt><dd><code>${esc(project.file_md5)}</code></dd>
          <dt>Account</dt><dd>${esc(project.username || "—")}</dd>
          <dt>Host</dt><dd>${esc(project.hostname || "—")}</dd>
          <dt>Functions</dt><dd>${project.functions} unique / ${project.versions} versions</dd>
          <dt>Created</dt><dd>${esc(date(project.created_at))}</dd>
        </dl>
        <div class="actions"><button type="submit">Save paths</button><button type="button" class="danger" id="project-delete" ${deleteAttrs()}>Delete project</button></div>
      </form>
      <h3>Contributed functions</h3>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Hash</th><th>Score</th><th></th></tr></thead>
      <tbody>${project.function_versions.length ? project.function_versions.map((version) => `
        <tr><td>${esc(version.name)}</td><td><code>${esc(version.hash)}</code></td><td>${version.score}</td>
        <td><button data-open-function="${esc(version.hash)}">Open</button></td></tr>`).join("") : emptyRow()}</tbody></table></div>`;
    $("project-edit").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.target);
      try {
        await api(`/api/v1/projects/${id}`, adminOptions("PATCH", {
          file_path: form.get("file_path"), idb_path: form.get("idb_path"),
        }));
        notify(`Project ${id} saved.`);
        await loadCollection("projects");
        await openProject(id);
      } catch (error) { handleError(error); }
    });
    $("project-delete").addEventListener("click", async () => {
      if (!confirm(`Delete project ${id} and every metadata version it contributed?`)) return;
      try {
        await api(`/api/v1/projects/${id}`, adminOptions("DELETE"));
        target.innerHTML = "<p>Project deleted.</p>";
        notify(`Project ${id} deleted.`);
        await Promise.all([loadCollection("projects"), refreshStats()]);
      } catch (error) { handleError(error); }
    });
  } catch (error) { target.innerHTML = `<p>${esc(error.message)}</p>`; handleError(error); }
}

function historyParams() {
  const form = new FormData($("history-filter"));
  const params = new URLSearchParams({
    limit: state.limit,
    offset: state.history.page * state.limit,
  });
  for (const name of ["q", "username", "license_id", "project_id", "chronological"]) {
    const value = String(form.get(name) || "").trim();
    if (value) params.set(name, value);
  }
  if (state.history.view === "history") {
    for (const name of [
      "name", "hash", "idb", "input", "file_md5", "push_id",
      "history_id_from", "history_id_to", "push_id_from", "push_id_to",
    ]) {
      const value = String(form.get(name) || "").trim();
      if (value) params.set(name, value);
    }
  }
  for (const name of ["from", "to"]) {
    const value = String(form.get(name) || "").trim();
    if (value) params.set(name, new Date(value).toISOString());
  }
  return params;
}

async function loadHistory() {
  const body = $("history-table");
  body.innerHTML = emptyRow("Loading…");
  try {
    const data = await api(`/api/v1/${state.history.view}?${historyParams()}`);
    state.history.more = data.items.length === state.limit;
    renderHistory(data.items);
    const pager = $("history-pager");
    pager.querySelector('[data-dir="-1"]').disabled = state.history.page === 0;
    pager.querySelector('[data-dir="1"]').disabled = !state.history.more;
    pager.querySelector("span").textContent = `Page ${state.history.page + 1}`;
  } catch (error) {
    body.innerHTML = emptyRow(error.message);
    handleError(error);
  }
}

function renderHistory(items) {
  if (state.history.view === "pushes") {
    $("history-head").innerHTML = "<tr><th>ID</th><th>Time</th><th>User / host</th><th>IDB</th><th>Submitted</th><th>Changed</th><th>Source</th></tr>";
    $("history-table").innerHTML = items.length ? items.map((push) => `
      <tr class="clickable" data-push-id="${push.id}">
        <td>${push.id}</td><td>${esc(date(push.pushed_at))}</td>
        <td>${esc(push.username || "—")} / ${esc(push.hostname || "—")}</td>
        <td>${esc(push.idb_path)}</td><td>${number.format(push.submitted_functions)}</td>
        <td>${number.format(push.changed_functions)}</td><td>${esc(push.source)}</td>
      </tr>`).join("") : emptyRow();
    return;
  }
  $("history-head").innerHTML = "<tr><th>ID</th><th>Time</th><th>Operation</th><th>Name</th><th>Hash</th><th>User</th><th>Push</th><th>Score</th></tr>";
  $("history-table").innerHTML = items.length ? items.map((change) => `
    <tr class="clickable" data-history-id="${change.id}">
      <td>${change.id}</td><td>${esc(date(change.changed_at))}</td><td>${esc(change.operation)}</td>
      <td><strong>${esc(change.name)}</strong></td><td><code>${esc(change.hash)}</code></td>
      <td>${esc(change.username || "—")}</td><td>${change.push_id}</td><td>${number.format(change.score)}</td>
    </tr>`).join("") : emptyRow();
}

async function openHistory(id) {
  const target = $("history-detail");
  target.innerHTML = "<p>Loading…</p>";
  try {
    const diff = await api(`/api/v1/history/${id}`);
    const change = diff.change;
    target.innerHTML = `
      <h2>Change ${change.id}</h2>
      <dl>
        <dt>Operation</dt><dd>${esc(change.operation)}</dd>
        <dt>Function</dt><dd>${esc(change.name)} / <code>${esc(change.hash)}</code></dd>
        <dt>Length / score</dt><dd>${number.format(change.length)} / ${number.format(change.score)}</dd>
        <dt>Push / project</dt><dd>${change.push_id} / ${change.project_id}</dd>
        <dt>Identity</dt><dd>${esc(change.username || "—")} @ ${esc(change.hostname || "—")}</dd>
        <dt>IDB</dt><dd>${esc(change.idb_path)}</dd>
        <dt>Changed</dt><dd>${esc(date(change.changed_at))}</dd>
      </dl>
      <div class="actions">
        <button id="history-open-function">Open function</button>
        <button id="history-restore">Restore this revision</button>
        <button id="history-delete" class="danger" ${deleteAttrs()}>Delete revision</button>
      </div>
      <h3>Changes from previous revision</h3>
      ${renderHistoryDiff(diff.fields)}
      <h3>Structured metadata</h3>
      ${renderMetadataDocument(diff.metadata_document, false)}
      <details><summary>Raw metadata</summary><textarea readonly>${esc(change.metadata)}</textarea></details>`;
    $("history-open-function").addEventListener("click", () => openFunction(change.hash));
    $("history-restore").addEventListener("click", async () => {
      if (!confirm(`Restore revision ${change.id} as the current metadata for ${change.hash}?`)) return;
      try {
        await api(`/api/v1/history/${change.id}/restore`, adminOptions("POST"));
        notify(`Revision ${change.id} restored as a new history record.`);
        await Promise.all([loadHistory(), refreshStats()]);
        target.innerHTML = "<p>Revision restored. Select a record to inspect it.</p>";
      } catch (error) { handleError(error); }
    });
    $("history-delete").addEventListener("click", async () => {
      if (!confirm(`Delete revision ${change.id}? The current function will move to the newest remaining revision.`)) return;
      try {
        await api(`/api/v1/history/${change.id}`, adminOptions("DELETE"));
        notify(`Revision ${change.id} deleted.`);
        await Promise.all([loadHistory(), refreshStats(), loadCollection("functions")]);
        target.innerHTML = "<p>Revision deleted.</p>";
      } catch (error) { handleError(error); }
    });
  } catch (error) { target.innerHTML = `<p>${esc(error.message)}</p>`; handleError(error); }
}

function renderHistoryDiff(fields) {
  if (!fields.length) return "<p>No field-level differences.</p>";
  return `<div class="table-wrap"><table class="diff-table"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
    <tbody>${fields.map((field) => `<tr><th>${esc(field.field)}</th>
      <td>${renderDiffValue(field.before)}</td><td>${renderDiffValue(field.after)}</td></tr>`).join("")}</tbody></table></div>`;
}

function renderDiffValue(value) {
  if (value === undefined || value === null) return "—";
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return `<pre>${esc(text)}</pre>`;
}

async function openPush(id) {
  const target = $("history-detail");
  target.innerHTML = "<p>Loading…</p>";
  try {
    const push = await api(`/api/v1/pushes/${id}`);
    target.innerHTML = `
      <h2>Push ${push.id}</h2>
      <dl>
        <dt>Time</dt><dd>${esc(date(push.pushed_at))}</dd>
        <dt>Source</dt><dd>${esc(push.source)} / protocol ${push.protocol_version}</dd>
        <dt>Identity</dt><dd>${esc(push.username || "—")} @ ${esc(push.hostname || "—")}</dd>
        <dt>Project</dt><dd>${push.project_id} / ${esc(push.idb_path)}</dd>
        <dt>Input</dt><dd>${esc(push.file_path)} / <code>${esc(push.file_md5)}</code></dd>
        <dt>Functions</dt><dd>${number.format(push.submitted_functions)} submitted / ${number.format(push.changed_functions)} changed</dd>
      </dl>
      <div class="actions"><button id="push-delete" class="danger" ${deleteAttrs()}>Delete push and revisions</button></div>
      <h3>Changes in this push</h3>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Operation</th><th>Hash</th><th></th></tr></thead>
      <tbody>${push.changes.length ? push.changes.map((change) => `<tr><td>${esc(change.name)}</td><td>${esc(change.operation)}</td>
        <td><code>${esc(change.hash)}</code></td><td><button data-history-id="${change.id}">Diff</button></td></tr>`).join("") : emptyRow()}</tbody></table></div>`;
    $("push-delete").addEventListener("click", async () => {
      if (!confirm(`Delete push ${push.id} and its ${push.changes.length} revision(s)?`)) return;
      try {
        await api(`/api/v1/pushes/${push.id}`, adminOptions("DELETE"));
        notify(`Push ${push.id} deleted.`);
        await Promise.all([loadHistory(), refreshStats(), loadCollection("functions"), loadCollection("projects")]);
        target.innerHTML = "<p>Push deleted.</p>";
      } catch (error) { handleError(error); }
    });
  } catch (error) { target.innerHTML = `<p>${esc(error.message)}</p>`; handleError(error); }
}

async function openFunction(hash) {
  showSection("functions");
  const target = $("function-detail");
  target.innerHTML = "<p>Loading…</p>";
  try {
    const data = await api(`/api/v1/functions/${hash}`);
    target.innerHTML = `
      <h2>${esc(data.versions[0].name)}</h2>
      <p><code>${esc(hash)}</code></p>
      <div class="actions"><button class="danger" id="function-delete" ${deleteAttrs()}>Delete all versions</button></div>
      <h3>Metadata versions</h3>
      <div id="version-list">${data.versions.map(renderVersion).join("")}</div>`;
    $("function-delete").addEventListener("click", async () => {
      if (!confirm(`Delete every metadata version for ${hash}?`)) return;
      try {
        await api(`/api/v1/functions/${hash}`, adminOptions("DELETE"));
        target.innerHTML = "<p>Function deleted.</p>";
        notify("Function deleted.");
        await Promise.all([loadCollection("functions"), refreshStats()]);
      } catch (error) { handleError(error); }
    });
  } catch (error) { target.innerHTML = `<p>${esc(error.message)}</p>`; handleError(error); }
}

function renderVersion(version) {
  const comments = (version.comments || []).filter((comment) => comment.type !== "parse-error");
  return `<article class="version" data-version-id="${version.id}" data-version-hash="${esc(version.hash)}">
    <div class="version-heading"><strong>Version ${version.id}</strong><span>score ${version.score} · project ${version.project_id}</span></div>
    <form class="version-edit">
      <label>Name<input name="name" value="${esc(version.name)}"></label>
      <label>Length<input name="length" type="number" min="0" max="4294967295" value="${version.length}"></label>
      <label>Raw metadata (hex)<textarea name="metadata" spellcheck="false">${esc(version.metadata)}</textarea></label>
      <div class="actions"><button type="submit">Save raw version</button></div>
    </form>
    <dl>
      <dt>Source</dt><dd>${esc(version.file_path)} / <code>${esc(version.file_md5)}</code></dd>
      <dt>IDB</dt><dd>${esc(version.idb_path)}</dd>
      <dt>Identity</dt><dd>${esc(version.username || "—")} @ ${esc(version.hostname || "—")}</dd>
      <dt>Updated</dt><dd>${esc(date(version.updated_at))}</dd>
      <dt>Decoded comments</dt><dd>${comments.length ? comments.map((comment) => esc(comment.text)).join("<br>") : "None"}</dd>
    </dl>
    <div class="actions">
      <button type="button" data-explore-version="${version.id}">Open metadata explorer</button>
      <button type="button" class="danger" data-delete-version="${version.id}" ${deleteAttrs()}>Delete version</button>
    </div>
    <div class="metadata-explorer" id="metadata-explorer-${version.id}" hidden></div>
  </article>`;
}

async function saveVersion(form) {
  const version = form.closest("[data-version-id]");
  const id = version.dataset.versionId;
  const data = new FormData(form);
  try {
    await api(`/api/v1/metadata/${id}`, adminOptions("PATCH", {
      name: data.get("name"), length: Number(data.get("length")), metadata: data.get("metadata").trim(),
    }));
    notify(`Metadata version ${id} saved.`);
    await Promise.all([openFunction(version.dataset.versionHash), loadCollection("functions")]);
  } catch (error) { handleError(error); }
}

async function deleteVersion(button) {
  const id = button.dataset.deleteVersion;
  const version = button.closest("[data-version-id]");
  if (!confirm(`Delete metadata version ${id}?`)) return;
  try {
    await api(`/api/v1/metadata/${id}`, adminOptions("DELETE"));
    notify(`Metadata version ${id} deleted.`);
    await Promise.all([openFunction(version.dataset.versionHash), loadCollection("functions"), refreshStats()]);
  } catch (error) {
    if (error.status === 404) {
      $("function-detail").innerHTML = "<p>No versions remain.</p>";
      await loadCollection("functions");
    }
    handleError(error);
  }
}

async function openMetadataExplorer(id) {
  const target = $(`metadata-explorer-${id}`);
  if (!target) return;
  target.hidden = false;
  target.innerHTML = "<p>Loading structured metadata…</p>";
  try {
    const data = await api(`/api/v1/metadata/${id}/structured`);
    target.innerHTML = renderMetadataDocument(data.document, true, id, data.hash);
  } catch (error) {
    target.innerHTML = `<p>${esc(error.message)}</p>`;
    handleError(error);
  }
}

function renderMetadataDocument(document, editable, versionId = "", hash = "") {
  if (!document) return "<p>No structured metadata document.</p>";
  const summary = document.summary || {};
  const status = document.error ? `<p class="metadata-error">${esc(document.error)}</p>` : "";
  const chunks = (document.chunks || []).map((chunk) =>
    renderMetadataChunk(chunk, editable, versionId, hash)).join("");
  const append = editable ? `
    <form class="structured-append" data-version-id="${versionId}" data-version-hash="${esc(hash)}">
      <h4>Append raw chunk</h4>
      <div class="metadata-grid">
        <label>Chunk code<input name="code" type="number" min="1" max="4294967295" required></label>
        <label>Payload (hex)<textarea name="payload" spellcheck="false" placeholder="Leave empty for an empty payload"></textarea></label>
      </div>
      <button type="submit">Append chunk</button>
    </form>` : "";
  return `<div class="metadata-summary">
      <span>${number.format(document.size || 0)} bytes</span>
      <span>${number.format(summary.known_chunks || 0)} known</span>
      <span>${number.format(summary.unknown_chunks || 0)} unknown</span>
      <span>${number.format(summary.comments || 0)} comments</span>
      <span>${number.format(summary.stack_points || 0)} stack points</span>
      <span>${number.format(summary.decode_failures || 0)} decode errors</span>
    </div>${status}${chunks || "<p>No metadata chunks.</p>"}${append}`;
}

function renderMetadataChunk(chunk, editable, versionId, hash) {
  const badges = `${chunk.known ? "known" : "unknown"} · ${esc(chunk.format)} · ${number.format(chunk.size)} bytes`;
  const decoded = chunkDecodedValue(chunk);
  if (!editable) {
    return `<section class="metadata-chunk">
      <header><strong>${esc(chunk.key)}</strong><span>code ${chunk.code} · ${badges}</span></header>
      ${chunk.error ? `<p class="metadata-error">${esc(chunk.error)}</p>` : ""}
      <pre>${esc(JSON.stringify(decoded, null, 2))}</pre>
      <details><summary>Raw payload</summary><textarea readonly>${esc(chunk.payload)}</textarea></details>
    </section>`;
  }
  const kind = chunkEditorKind(chunk);
  return `<form class="metadata-chunk structured-chunk" data-version-id="${versionId}"
      data-version-hash="${esc(hash)}" data-chunk-index="${chunk.index}" data-chunk-code="${chunk.code}" data-chunk-kind="${kind}">
    <header><strong>${esc(chunk.key)}</strong><span>code ${chunk.code} · ${badges}</span></header>
    ${chunk.error ? `<p class="metadata-error">${esc(chunk.error)}</p>` : ""}
    ${renderChunkEditor(chunk, kind)}
    <div class="actions">
      <button type="submit">Save chunk</button>
      <button type="button" class="danger" data-remove-chunk="${chunk.index}">Remove chunk</button>
    </div>
  </form>`;
}

function chunkDecodedValue(chunk) {
  if (chunk.type !== undefined) return chunk.type;
  if (chunk.elapsed_seconds !== undefined) return { elapsed_seconds: chunk.elapsed_seconds };
  if (chunk.text !== undefined) return { text: chunk.text };
  if (chunk.comments !== undefined) return chunk.comments;
  if (chunk.stack_points !== undefined) return chunk.stack_points;
  return { payload: chunk.payload };
}

function chunkEditorKind(chunk) {
  if (chunk.code === 1) return "type";
  if (chunk.code === 2) return "elapsed";
  if (chunk.code === 3 || chunk.code === 4) return "text";
  if (chunk.code >= 5 && chunk.code <= 7) return "comments";
  if (chunk.code === 8) return "stack";
  return "raw";
}

function renderChunkEditor(chunk, kind) {
  if (kind === "type" && chunk.type) {
    return `<div class="metadata-grid">
      <label>Source<input name="source" type="number" min="0" max="255" value="${chunk.type.source}"></label>
      <label>Serialized type (hex)<textarea name="type" spellcheck="false">${esc(chunk.type.type)}</textarea></label>
      <label>Serialized fields (hex)<textarea name="fields" spellcheck="false">${esc(chunk.type.fields || "")}</textarea></label>
    </div>`;
  }
  if (kind === "elapsed" && chunk.elapsed_seconds !== undefined) {
    return `<label>Elapsed seconds<input name="elapsed_seconds" type="number" value="${chunk.elapsed_seconds}"></label>`;
  }
  if (kind === "text" && chunk.text !== undefined) {
    return `<label>Comment<textarea name="text">${esc(chunk.text)}</textarea></label>`;
  }
  if (kind === "comments" && !chunk.error) {
    const extra = chunk.code === 7;
    const rows = (chunk.comments || []).map((comment) => renderCommentRow(comment, extra)).join("");
    return `<div class="metadata-rows">${rows}</div>
      <button type="button" data-add-comment="${extra ? "extra" : "instruction"}">Add comment</button>`;
  }
  if (kind === "stack" && !chunk.error) {
    const rows = (chunk.stack_points || []).map(renderStackPointRow).join("");
    return `<div class="metadata-rows">${rows}</div><button type="button" data-add-stack-point>Add stack point</button>`;
  }
  return `<label>Raw payload (hex)<textarea name="payload" spellcheck="false">${esc(chunk.payload)}</textarea></label>`;
}

function renderCommentRow(comment = {}, extra = false) {
  const type = comment.type || (extra ? "anterior" : "instruction");
  return `<div class="metadata-row metadata-comment-row">
    <label>Offset<input data-field="offset" type="number" min="0" max="4294967295" value="${comment.offset ?? 0}" required></label>
    ${extra ? `<label>Kind<select data-field="type">
      <option value="anterior" ${type === "anterior" ? "selected" : ""}>Anterior</option>
      <option value="posterior" ${type === "posterior" ? "selected" : ""}>Posterior</option>
    </select></label>` : ""}
    <label>Text<textarea data-field="text">${esc(comment.text || "")}</textarea></label>
    <button type="button" class="danger" data-remove-row>Remove</button>
  </div>`;
}

function renderStackPointRow(point = {}) {
  return `<div class="metadata-row metadata-stack-row">
    <label>Offset<input data-field="offset" type="number" min="0" max="4294967295" value="${point.offset ?? 0}" required></label>
    <label>Stack delta<input data-field="delta" type="number" value="${point.delta ?? 0}" required></label>
    <button type="button" class="danger" data-remove-row>Remove</button>
  </div>`;
}

async function saveStructuredChunk(form) {
  const mutation = {
    operation: "set",
    index: Number(form.dataset.chunkIndex),
  };
  const kind = form.dataset.chunkKind;
  if (kind === "type") {
    mutation.type = {
      source: Number(form.elements.source.value),
      type: form.elements.type.value.trim(),
      fields: form.elements.fields.value.trim(),
    };
  } else if (kind === "elapsed") {
    mutation.elapsed_seconds = Number(form.elements.elapsed_seconds.value);
  } else if (kind === "text") {
    mutation.text = form.elements.text.value;
  } else if (kind === "comments") {
    mutation.comments = [...form.querySelectorAll(".metadata-comment-row")].map((row) => ({
      offset: Number(row.querySelector('[data-field="offset"]').value),
      type: row.querySelector('[data-field="type"]')?.value || "instruction",
      text: row.querySelector('[data-field="text"]').value,
    }));
  } else if (kind === "stack") {
    mutation.stack_points = [...form.querySelectorAll(".metadata-stack-row")].map((row) => ({
      offset: Number(row.querySelector('[data-field="offset"]').value),
      delta: Number(row.querySelector('[data-field="delta"]').value),
    }));
  } else {
    mutation.payload = form.elements.payload.value.trim();
  }
  await mutateStructuredMetadata(form, mutation, `Chunk ${form.dataset.chunkIndex} saved.`);
}

async function mutateStructuredMetadata(element, mutation, message) {
  const id = element.dataset.versionId;
  const hash = element.dataset.versionHash;
  try {
    await api(`/api/v1/metadata/${id}/structured`, adminOptions("PATCH", { mutations: [mutation] }));
    notify(message);
    await openFunction(hash);
    await openMetadataExplorer(id);
    await loadCollection("functions");
  } catch (error) { handleError(error); }
}

async function removeStructuredChunk(button) {
  const form = button.closest(".structured-chunk");
  if (!confirm(`Remove metadata chunk ${form.dataset.chunkIndex} (${form.dataset.chunkCode})?`)) return;
  await mutateStructuredMetadata(form, {
    operation: "remove", index: Number(form.dataset.chunkIndex),
  }, `Chunk ${form.dataset.chunkIndex} removed.`);
}

async function appendStructuredChunk(form) {
  await mutateStructuredMetadata(form, {
    operation: "append",
    code: Number(form.elements.code.value),
    payload: form.elements.payload.value.trim(),
  }, "Metadata chunk appended.");
}

async function openFile(md5) {
  const target = $("file-detail");
  target.innerHTML = "<p>Loading…</p>";
  try {
    const functions = await api(`/api/v1/files/${md5}/functions`);
    target.innerHTML = `<h2>File</h2><p><code>${esc(md5)}</code></p><h3>Functions</h3>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Hash</th><th>Versions</th><th></th></tr></thead>
      <tbody>${functions.length ? functions.map((fn) => `<tr><td>${esc(fn.name)}</td><td><code>${esc(fn.hash)}</code></td>
      <td>${fn.popularity}</td><td><button data-open-function="${esc(fn.hash)}">Open</button></td></tr>`).join("") : emptyRow()}</tbody></table></div>`;
  } catch (error) { target.innerHTML = `<p>${esc(error.message)}</p>`; handleError(error); }
}

async function refreshStats() {
  try { renderStats(await api("/api/v1/stats")); } catch (error) { handleError(error); }
}

function showSection(name) {
  document.querySelectorAll(".page").forEach((section) => section.classList.toggle("active", section.id === `section-${name}`));
  document.querySelectorAll("nav [data-section]").forEach((button) => button.classList.toggle("active", button.dataset.section === name));
  if (name === "accounts") loadAccounts();
  if (name === "sessions") loadSessions();
  if (name === "history") loadHistory();
  if (state.pages[name]) loadCollection(name);
}

document.addEventListener("click", (event) => {
  const section = event.target.closest("[data-section]");
  if (section) showSection(section.dataset.section);
  const reload = event.target.closest("[data-reload]");
  if (reload) {
    if (reload.dataset.reload === "accounts") loadAccounts();
    else if (reload.dataset.reload === "sessions") loadSessions();
    else loadCollection(reload.dataset.reload);
  }
  const project = event.target.closest("[data-project-id]");
  if (project) openProject(project.dataset.projectId);
  const history = event.target.closest("[data-history-id]");
  if (history) openHistory(history.dataset.historyId);
  const push = event.target.closest("[data-push-id]");
  if (push) openPush(push.dataset.pushId);
  const fn = event.target.closest("[data-function-hash]");
  if (fn) openFunction(fn.dataset.functionHash);
  const file = event.target.closest("[data-file-md5]");
  if (file) openFile(file.dataset.fileMd5);
  const openFn = event.target.closest("[data-open-function]");
  if (openFn) openFunction(openFn.dataset.openFunction);
  const account = event.target.closest("[data-account]");
  if (account) accountAction(account);
  const session = event.target.closest("[data-session-terminate]");
  if (session) terminateSession(session);
  const deleteButton = event.target.closest("[data-delete-version]");
  if (deleteButton) deleteVersion(deleteButton);
  const explorer = event.target.closest("[data-explore-version]");
  if (explorer) openMetadataExplorer(explorer.dataset.exploreVersion);
  const removeChunk = event.target.closest("[data-remove-chunk]");
  if (removeChunk) removeStructuredChunk(removeChunk);
  const removeRow = event.target.closest("[data-remove-row]");
  if (removeRow) removeRow.closest(".metadata-row").remove();
  const addComment = event.target.closest("[data-add-comment]");
  if (addComment) {
    addComment.previousElementSibling.insertAdjacentHTML(
      "beforeend", renderCommentRow({}, addComment.dataset.addComment === "extra"));
  }
  const addStackPoint = event.target.closest("[data-add-stack-point]");
  if (addStackPoint) {
    addStackPoint.previousElementSibling.insertAdjacentHTML("beforeend", renderStackPointRow());
  }
});

document.addEventListener("change", (event) => {
  const field = event.target.closest("[data-account-field]");
  if (field) setAccountField(field);
});

document.querySelectorAll("[data-history-view]").forEach((button) => button.addEventListener("click", () => {
  state.history.view = button.dataset.historyView;
  state.history.page = 0;
  document.querySelectorAll("[data-history-view]").forEach((item) =>
    item.classList.toggle("active", item === button));
  $("history-detail").innerHTML = "<p>Select a change or push.</p>";
  loadHistory();
}));
$("history-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  state.history.page = 0;
  loadHistory();
});
$("history-filter").addEventListener("reset", () => {
  setTimeout(() => {
    state.history.page = 0;
    loadHistory();
  }, 0);
});
$("session-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  state.sessionQuery = new FormData(event.target).get("q").trim();
  loadSessions();
});
$("session-filter").addEventListener("reset", () => {
  setTimeout(() => {
    state.sessionQuery = "";
    loadSessions();
  }, 0);
});
$("history-pager").addEventListener("click", (event) => {
  const button = event.target.closest("[data-dir]");
  if (!button) return;
  state.history.page = Math.max(0, state.history.page + Number(button.dataset.dir));
  loadHistory();
});

document.addEventListener("submit", (event) => {
  const search = event.target.closest(".search-form");
  if (!search) return;
  event.preventDefault();
  const resource = search.dataset.resource;
  state.pages[resource].query = new FormData(search).get("q").trim();
  state.pages[resource].page = 0;
  loadCollection(resource);
});

document.addEventListener("submit", (event) => {
  const structured = event.target.closest(".structured-chunk");
  if (structured) {
    event.preventDefault();
    saveStructuredChunk(structured);
    return;
  }
  const append = event.target.closest(".structured-append");
  if (append) {
    event.preventDefault();
    appendStructuredChunk(append);
    return;
  }
  const version = event.target.closest(".version-edit");
  if (version) {
    event.preventDefault();
    saveVersion(version);
  }
});

document.querySelectorAll("[data-pager]").forEach((pager) => pager.addEventListener("click", (event) => {
  const button = event.target.closest("[data-dir]");
  if (!button) return;
  const resource = pager.dataset.pager;
  state.pages[resource].page = Math.max(0, state.pages[resource].page + Number(button.dataset.dir));
  loadCollection(resource);
}));

$("admin-login").addEventListener("submit", (event) => {
  event.preventDefault();
  const token = $("admin-token").value;
  if (token) sessionStorage.setItem("luxAdminToken", token);
  $("admin-token").value = "";
  updateLockState();
  notify("Admin token loaded for this browser tab.");
});
$("admin-lock").addEventListener("click", () => {
  sessionStorage.removeItem("luxAdminToken");
  updateLockState();
  notify("Admin token removed.");
});
$("user-stats-filter").addEventListener("submit", loadUserStats);
$("account-create").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/accounts", adminOptions("POST", {
      username: $("account-username").value.trim(), password: $("account-password").value,
      email: $("account-email").value.trim(),
      license_id: $("account-license-id").value.trim(),
      is_admin: $("account-is-admin").checked,
      can_delete_history: $("account-can-delete-history").checked,
    }));
    event.target.reset();
    notify("Account created.");
    await Promise.all([loadAccounts(), refreshStats()]);
  } catch (error) { handleError(error); }
});

boot();
