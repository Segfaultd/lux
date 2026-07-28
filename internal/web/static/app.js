"use strict";

const state = {
  config: null,
  pages: {
    projects: { page: 0, query: "", more: false },
    functions: { page: 0, query: "", more: false },
    files: { page: 0, query: "", more: false },
  },
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
  ];
  $("stats").innerHTML = values.map(([label, value]) =>
    `<div><strong>${number.format(value)}</strong><span>${esc(label)}</span></div>`).join("");
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
        <td>${account.enabled ? "Enabled" : "Disabled"}</td>
        <td>${account.password_set ? "Set" : "Not set"}</td>
        <td>${esc(date(account.last_login_at))}</td>
        <td>${esc(date(account.created_at))}</td>
        <td class="actions">
          <button data-account="password" data-username="${esc(account.username)}">Set password</button>
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
    } else {
      if (!confirm(`Delete login account "${username}"? Historical attribution remains.`)) return;
      await api(`/api/v1/accounts/${encodeURIComponent(username)}`, adminOptions("DELETE"));
    }
    notify(`Account ${username} updated.`);
    await Promise.all([loadAccounts(), refreshStats()]);
  } catch (error) { handleError(error); }
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
  return `<form class="version" data-version-id="${version.id}" data-version-hash="${esc(version.hash)}">
    <div class="version-heading"><strong>Version ${version.id}</strong><span>score ${version.score} · project ${version.project_id}</span></div>
    <label>Name<input name="name" value="${esc(version.name)}"></label>
    <label>Length<input name="length" type="number" min="0" max="4294967295" value="${version.length}"></label>
    <label>Raw metadata (hex)<textarea name="metadata" spellcheck="false">${esc(version.metadata)}</textarea></label>
    <dl>
      <dt>Source</dt><dd>${esc(version.file_path)} / <code>${esc(version.file_md5)}</code></dd>
      <dt>IDB</dt><dd>${esc(version.idb_path)}</dd>
      <dt>Identity</dt><dd>${esc(version.username || "—")} @ ${esc(version.hostname || "—")}</dd>
      <dt>Updated</dt><dd>${esc(date(version.updated_at))}</dd>
      <dt>Decoded comments</dt><dd>${comments.length ? comments.map((comment) => esc(comment.text)).join("<br>") : "None"}</dd>
    </dl>
    <div class="actions"><button type="submit">Save version</button><button type="button" class="danger" data-delete-version="${version.id}" ${deleteAttrs()}>Delete version</button></div>
  </form>`;
}

async function saveVersion(form) {
  const id = form.dataset.versionId;
  const data = new FormData(form);
  try {
    await api(`/api/v1/metadata/${id}`, adminOptions("PATCH", {
      name: data.get("name"), length: Number(data.get("length")), metadata: data.get("metadata").trim(),
    }));
    notify(`Metadata version ${id} saved.`);
    await Promise.all([openFunction(form.dataset.versionHash), loadCollection("functions")]);
  } catch (error) { handleError(error); }
}

async function deleteVersion(button) {
  const id = button.dataset.deleteVersion;
  const form = button.closest("form");
  if (!confirm(`Delete metadata version ${id}?`)) return;
  try {
    await api(`/api/v1/metadata/${id}`, adminOptions("DELETE"));
    notify(`Metadata version ${id} deleted.`);
    await Promise.all([openFunction(form.dataset.versionHash), loadCollection("functions"), refreshStats()]);
  } catch (error) {
    if (error.status === 404) {
      $("function-detail").innerHTML = "<p>No versions remain.</p>";
      await loadCollection("functions");
    }
    handleError(error);
  }
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
  if (state.pages[name]) loadCollection(name);
}

document.addEventListener("click", (event) => {
  const section = event.target.closest("[data-section]");
  if (section) showSection(section.dataset.section);
  const reload = event.target.closest("[data-reload]");
  if (reload) reload.dataset.reload === "accounts" ? loadAccounts() : loadCollection(reload.dataset.reload);
  const project = event.target.closest("[data-project-id]");
  if (project) openProject(project.dataset.projectId);
  const fn = event.target.closest("[data-function-hash]");
  if (fn) openFunction(fn.dataset.functionHash);
  const file = event.target.closest("[data-file-md5]");
  if (file) openFile(file.dataset.fileMd5);
  const openFn = event.target.closest("[data-open-function]");
  if (openFn) openFunction(openFn.dataset.openFunction);
  const account = event.target.closest("[data-account]");
  if (account) accountAction(account);
  const deleteButton = event.target.closest("[data-delete-version]");
  if (deleteButton) deleteVersion(deleteButton);
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
  const version = event.target.closest("[data-version-id]");
  if (!version) return;
  event.preventDefault();
  saveVersion(version);
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
$("account-create").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/accounts", adminOptions("POST", {
      username: $("account-username").value.trim(), password: $("account-password").value,
    }));
    event.target.reset();
    notify("Account created.");
    await Promise.all([loadAccounts(), refreshStats()]);
  } catch (error) { handleError(error); }
});

boot();
