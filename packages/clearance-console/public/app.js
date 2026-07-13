/* Clearance operator console — dark dense control plane.
 * Talks only to same-origin /api/*; the server injects operator auth + scope.
 * Never put the operator bearer token in the browser.
 */

const view = document.getElementById("view");
const title = document.getElementById("page-title");
const healthPill = document.getElementById("health-pill");
const cliHint = document.getElementById("cli-hint");
const envLabel = document.getElementById("env-label");

/** Mirrors @clearance/management MANAGEMENT_SURFACES consoleRoute keys. */
const routes = {
  overview: {
    title: "Overview",
    cli: "clearance overview --json",
    render: renderOverview,
  },
  users: {
    title: "Users",
    cli: "clearance users list --json",
    render: renderUsers,
  },
  organizations: {
    title: "Organizations",
    cli: "clearance orgs list --json",
    render: renderOrgs,
  },
  members: {
    title: "Members",
    cli: "clearance orgs members list --org <id> --json",
    render: renderMembers,
  },
  sessions: {
    title: "Sessions",
    cli: "clearance sessions list --json",
    render: renderSessions,
  },
  roles: {
    title: "Roles",
    cli: "clearance roles list --json",
    render: renderRoles,
  },
  events: {
    title: "Events",
    cli: "clearance events list --json",
    render: renderEvents,
  },
  readiness: {
    title: "Readiness",
    cli: "clearance readiness check --org <id> --json",
    render: renderReadiness,
  },
  settings: {
    title: "Settings",
    cli: "clearance doctor --json",
    render: renderSettings,
  },
};

/** Escape text for safe interpolation into HTML (stored/reflected XSS defense). */
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[c],
  );
}

/** Attribute-safe escape (same mapping; explicit for call sites). */
function escapeAttr(s) {
  return escapeHtml(s);
}

function formatWhen(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

function cliBlock(command) {
  const cmd = String(command ?? "");
  return `<div class="cli-block" data-cli="${escapeAttr(cmd)}">
    <span class="cli-label">CLI</span>
    <code class="cli-cmd">${escapeHtml(cmd)}</code>
    <button type="button" class="ghost copy-cli" data-copy="${escapeAttr(cmd)}" title="Copy CLI">Copy</button>
  </div>`;
}

function stateLoading(msg) {
  return `<div class="state state-loading" role="status">${escapeHtml(msg || "Loading…")}</div>`;
}

function stateError(msg, cli) {
  return `<div class="state state-error" role="alert">
    <strong>Error</strong>
    <p>${escapeHtml(msg)}</p>
    ${cli ? cliBlock(cli) : ""}
  </div>`;
}

function stateEmpty(msg, cli) {
  return `<div class="state state-empty">
    <p>${escapeHtml(msg)}</p>
    ${cli ? cliBlock(cli) : ""}
  </div>`;
}

function wireCopyButtons(root) {
  (root || document).querySelectorAll("[data-copy]").forEach((btn) => {
    if (btn.dataset.copyBound) return;
    btn.dataset.copyBound = "1";
    btn.addEventListener("click", async () => {
      const text = btn.getAttribute("data-copy") || "";
      try {
        await navigator.clipboard.writeText(text);
        const prev = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = prev;
        }, 1200);
      } catch {
        // Fallback for non-secure contexts
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
          btn.textContent = "Copied";
          setTimeout(() => {
            btn.textContent = "Copy";
          }, 1200);
        } finally {
          ta.remove();
        }
      }
    });
  });
}

function setFormMessage(el, text, kind) {
  if (!el) return;
  el.textContent = text || "";
  el.className = `form-msg ${kind || ""}`.trim();
}

/** Format API error with optional remediation for operator feedback. */
function formatApiError(err) {
  const msg = err?.message || "Request failed";
  if (err?.remediation) return `${msg} — ${err.remediation}`;
  return msg;
}

/** True when the signed-in operator may mutate (admin). Viewers inspect only. */
function canMutate() {
  return operatorRole === "admin";
}

/**
 * Explicit confirmation for destructive admin mutations (mirrors CLI --yes).
 * Returns false when confirm is unavailable (non-browser test contexts).
 */
function confirmDestructive(message) {
  if (typeof window === "undefined" || typeof window.confirm !== "function") {
    return false;
  }
  return window.confirm(message);
}

/**
 * Parse permission textarea: one resource:action per line.
 * Trims blanks client-side and drops case-insensitive duplicates.
 */
function parsePermissionsText(text) {
  const seen = new Set();
  const out = [];
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const token = line.trim().toLowerCase();
    if (!token) continue;
    if (seen.has(token)) continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}

function permissionsToText(perms) {
  if (!Array.isArray(perms)) return "";
  return perms.join("\n");
}

/** Operator session CSRF (set after login / session fetch). Never stores upstream token. */
let operatorCsrf = null;
let operatorRole = null;
let activeRouteName = "overview";
let navigationVersion = 0;

/**
 * Same-origin API client. Does not send Authorization or scope headers —
 * the console server injects the upstream operator bearer token after local session auth.
 * Mutations include X-CSRF-Token from the operator session.
 */
async function api(path, init = {}) {
  const headers = { "content-type": "application/json", ...(init.headers || {}) };
  // Strip any accidental auth overrides from callers.
  delete headers.authorization;
  delete headers.Authorization;
  delete headers["x-clearance-project-id"];
  delete headers["X-Clearance-Project-Id"];
  delete headers["x-clearance-environment-id"];
  delete headers["X-Clearance-Environment-Id"];

  const method = (init.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD" && operatorCsrf) {
    headers["x-csrf-token"] = operatorCsrf;
  }

  const res = await fetch(`/api${path}`, {
    ...init,
    headers,
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      data?.error?.message ||
      data?.message ||
      res.statusText ||
      `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.code = data?.error?.code;
    err.remediation = data?.error?.remediation;
    // Session expiry mid-use: route back to the login view. Scoped to app.js
    // data calls only — never the login/session/config endpoints themselves
    // (a bad password must not loop, the boot probe must not double-render),
    // and never inherited by setup.js, which has its own token-based fetch.
    if (
      res.status === 401 &&
      !path.startsWith("/console/") &&
      operatorCsrf !== null
    ) {
      operatorCsrf = null;
      operatorRole = null;
      showLogin("Session expired — sign in again.");
    }
    throw err;
  }
  return data;
}

async function ensureOperatorSession() {
  try {
    const s = await api("/console/session");
    operatorCsrf = s.csrf || null;
    operatorRole = s.role || null;
    return s;
  } catch {
    operatorCsrf = null;
    operatorRole = null;
    return null;
  }
}

async function consoleLogin(username, password) {
  const data = await api("/console/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  operatorCsrf = data.csrf || null;
  operatorRole = data.role || null;
  return data;
}

async function consoleLogout() {
  try {
    await api("/console/logout", { method: "POST", body: "{}" });
  } finally {
    operatorCsrf = null;
    operatorRole = null;
  }
}

// ---------------------------------------------------------------------------
// Login view (markup lives in index.html so the served page provably contains
// it — see form[data-testid="console-login"]; this code only toggles/wires it)
// ---------------------------------------------------------------------------
const loginHost = document.getElementById("login-host");
const loginForm = document.getElementById("console-login-form");
const loginNotice = document.getElementById("login-notice");
const loginError = document.getElementById("login-error");
const signoutBtn = document.getElementById("signout-btn");
const appShell = document.querySelector(".app");

function showLogin(notice) {
  if (appShell) appShell.hidden = true;
  if (signoutBtn) signoutBtn.hidden = true;
  if (loginHost) loginHost.hidden = false;
  if (loginNotice) {
    loginNotice.textContent = notice || "";
    loginNotice.hidden = !notice;
  }
  if (loginError) loginError.hidden = true;
  const username = document.getElementById("login-username");
  if (username) username.focus();
}

function showApp(session) {
  if (loginHost) loginHost.hidden = true;
  if (appShell) appShell.hidden = false;
  if (signoutBtn) {
    const who = session?.username
      ? `${session.username} (${session.role || "operator"})`
      : "";
    signoutBtn.textContent = who ? `Sign out · ${who}` : "Sign out";
    signoutBtn.title = who ? `Signed in as ${who}` : "Sign out";
    signoutBtn.hidden = false;
  }
}

if (loginForm) {
  loginForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const username = document.getElementById("login-username")?.value?.trim() ?? "";
    const password = document.getElementById("login-password")?.value ?? "";
    const submit = document.getElementById("login-submit");
    if (submit) submit.disabled = true;
    if (loginError) loginError.hidden = true;
    try {
      const session = await consoleLogin(username, password);
      loginForm.reset();
      showApp(session);
      bootAuthenticated();
    } catch (e) {
      if (loginError) {
        loginError.textContent = formatApiError(e);
        loginError.hidden = false;
      }
    } finally {
      if (submit) submit.disabled = false;
    }
  });
}

if (signoutBtn) {
  signoutBtn.addEventListener("click", async () => {
    try {
      await consoleLogout();
    } catch {
      /* session already gone server-side or CSRF stale — either way, local
         state is cleared in consoleLogout's finally; show login regardless */
    }
    showLogin("Signed out.");
  });
}

function setRoute(name, params) {
  const route = routes[name] || routes.overview;
  activeRouteName = routes[name] ? name : "overview";
  const routeVersion = ++navigationVersion;
  title.textContent = route.title;
  cliHint.textContent = route.cli;
  cliHint.setAttribute("data-copy", route.cli);
  document.querySelectorAll(".rail button[data-route]").forEach((b) => {
    const active = b.dataset.route === activeRouteName;
    b.classList.toggle("active", active);
    if (active) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  const qs = params?.org ? `?org=${encodeURIComponent(params.org)}` : "";
  history.replaceState({}, "", `/${name === "overview" ? "overview" : name}${qs}`);
  route.render({ ...(params || {}), routeVersion });
}

document.querySelectorAll(".rail button[data-route]").forEach((b) => {
  b.addEventListener("click", () => setRoute(b.dataset.route));
});

if (cliHint) {
  cliHint.style.cursor = "pointer";
  cliHint.title = "Click to copy CLI";
  cliHint.addEventListener("click", async () => {
    const text = cliHint.getAttribute("data-copy") || cliHint.textContent || "";
    try {
      await navigator.clipboard.writeText(text);
      healthPill.title = "CLI copied";
    } catch {
      /* ignore */
    }
  });
}

async function refreshHealth() {
  try {
    const d = await api("/health");
    const ver = d.version || d.releaseVersion || "?";
    healthPill.textContent = `v${ver}`;
    healthPill.className = "pill ok";
  } catch {
    healthPill.textContent = "api offline";
    healthPill.className = "pill fail";
  }
}

async function refreshConsoleConfig() {
  try {
    await ensureOperatorSession();
    const cfg = await api("/console/config");
    if (envLabel) {
      const parts = [];
      if (cfg.environmentLabel) parts.push(cfg.environmentLabel);
      else if (cfg.environmentId) parts.push(cfg.environmentId);
      else parts.push("development");
      if (cfg.projectId) parts.push(cfg.projectId);
      if (cfg.authenticated) parts.push(cfg.role || "operator");
      envLabel.textContent = parts.join(" · ");
      envLabel.title = [
        cfg.authenticated
          ? `session: ${cfg.username} (${cfg.role})`
          : "session: not signed in",
        cfg.hasOperatorToken ? "upstream token: server" : "upstream token: MISSING",
        cfg.projectId ? `project: ${cfg.projectId}` : "project: (api default)",
        cfg.environmentId ? `env: ${cfg.environmentId}` : "env: (api default)",
      ].join("\n");
    }
  } catch {
    if (envLabel) envLabel.textContent = "development";
  }
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
async function renderOverview() {
  view.innerHTML = stateLoading("Loading overview…");
  try {
    const data = await api("/v1/overview");
    const events = Array.isArray(data.recentEvents) ? data.recentEvents : [];
    view.innerHTML = `
      ${cliBlock("clearance overview --json")}
      <div class="grid">
        <div class="card"><div class="label">Total users</div><div class="value">${escapeHtml(data.totalUsers ?? 0)}</div></div>
        <div class="card"><div class="label">Active users</div><div class="value">${escapeHtml(data.activeUsers ?? 0)}</div></div>
        <div class="card"><div class="label">Organizations</div><div class="value">${escapeHtml(data.organizations ?? 0)}</div></div>
        <div class="card"><div class="label">Sessions</div><div class="value">${escapeHtml(data.activeSessions ?? 0)}</div></div>
      </div>
      <div class="card">
        <div class="label">Recent events</div>
        ${
          events.length === 0
            ? stateEmpty("No events yet — run clearance init", "clearance init --name my-app --json")
            : `<table>
          <thead><tr><th>Action</th><th>Outcome</th><th>Message</th><th>When</th></tr></thead>
          <tbody>
            ${events
              .map(
                (e) => `
              <tr>
                <td>${escapeHtml(e.action)}</td>
                <td>${escapeHtml(e.outcome)}</td>
                <td>${escapeHtml(e.message)}</td>
                <td>${escapeHtml(formatWhen(e.createdAt))}</td>
              </tr>`,
              )
              .join("")}
          </tbody>
        </table>`
        }
      </div>
      <p class="meta-foot">Release ${escapeHtml(data.releaseVersion)} · schema v${escapeHtml(data.schemaVersion)}</p>
    `;
    wireCopyButtons(view);
  } catch (e) {
    view.innerHTML = stateError(
      `Failed to load overview: ${e.message}`,
      "clearance overview --json",
    );
    wireCopyButtons(view);
  }
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------
async function renderUsers() {
  view.innerHTML = `
    ${cliBlock("clearance users list --json")}
    <form class="form-row" id="u-form" autocomplete="off">
      <input id="u-email" name="email" type="email" required placeholder="email@company.com" />
      <input id="u-name" name="name" type="text" required placeholder="Name" />
      <button type="submit" class="primary" id="u-create">Create user</button>
    </form>
    ${cliBlock('clearance users create --email a@b.com --name "A" --json')}
    <div id="u-form-msg" class="form-msg" aria-live="polite"></div>
    <div id="u-table">${stateLoading("Loading users…")}</div>
  `;
  wireCopyButtons(view);

  const form = document.getElementById("u-form");
  const msg = document.getElementById("u-form-msg");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const email = document.getElementById("u-email").value.trim();
    const name = document.getElementById("u-name").value.trim();
    if (!email || !name) {
      setFormMessage(msg, "Email and name are required", "err");
      return;
    }
    setFormMessage(msg, "Creating…", "");
    try {
      await api("/v1/users", {
        method: "POST",
        body: JSON.stringify({ email, name }),
      });
      setFormMessage(msg, `Created ${email}`, "ok");
      form.reset();
      await loadUsersTable();
    } catch (e) {
      setFormMessage(msg, e.message, "err");
    }
  });

  await loadUsersTable();
}

async function loadUsersTable() {
  const host = document.getElementById("u-table");
  if (!host) return;
  host.innerHTML = stateLoading("Loading users…");
  try {
    const data = await api("/v1/users");
    const users = Array.isArray(data.users) ? data.users : [];
    if (users.length === 0) {
      host.innerHTML = stateEmpty(
        "No users yet",
        'clearance users create --email a@b.com --name "A" --json',
      );
      wireCopyButtons(host);
      return;
    }
    host.innerHTML = `
      <table>
        <thead><tr><th>Email</th><th>Name</th><th>Status</th><th>ID</th></tr></thead>
        <tbody>
          ${users
            .map(
              (u) => `<tr>
            <td>${escapeHtml(u.email)}</td>
            <td>${escapeHtml(u.name)}</td>
            <td>${escapeHtml(u.status)}</td>
            <td><code>${escapeHtml(u.id)}</code></td>
          </tr>`,
            )
            .join("")}
        </tbody>
      </table>`;
  } catch (e) {
    host.innerHTML = stateError(
      `Failed to load users: ${e.message}`,
      "clearance users list --json",
    );
    wireCopyButtons(host);
  }
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------
async function renderOrgs() {
  view.innerHTML = `
    ${cliBlock("clearance orgs list --json")}
    <form class="form-row" id="o-form" autocomplete="off">
      <input id="o-name" name="name" type="text" required placeholder="Organization name" />
      <input id="o-slug" name="slug" type="text" placeholder="slug (optional)" />
      <button type="submit" class="primary" id="o-create">Create organization</button>
    </form>
    ${cliBlock("clearance orgs create --name Acme --json")}
    <div id="o-form-msg" class="form-msg" aria-live="polite"></div>
    <div id="o-table">${stateLoading("Loading organizations…")}</div>
  `;
  wireCopyButtons(view);

  const form = document.getElementById("o-form");
  const msg = document.getElementById("o-form-msg");
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const name = document.getElementById("o-name").value.trim();
    const slug = document.getElementById("o-slug").value.trim();
    if (!name) {
      setFormMessage(msg, "Name is required", "err");
      return;
    }
    setFormMessage(msg, "Creating…", "");
    try {
      const body = { name };
      if (slug) body.slug = slug;
      await api("/v1/organizations", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setFormMessage(msg, `Created ${name}`, "ok");
      form.reset();
      await loadOrgsTable();
    } catch (e) {
      setFormMessage(msg, e.message, "err");
    }
  });

  await loadOrgsTable();
}

async function loadOrgsTable() {
  const host = document.getElementById("o-table");
  if (!host) return;
  host.innerHTML = stateLoading("Loading organizations…");
  try {
    const data = await api("/v1/organizations");
    const orgs = Array.isArray(data.organizations) ? data.organizations : [];
    if (orgs.length === 0) {
      host.innerHTML = stateEmpty(
        "No organizations yet",
        "clearance orgs create --name Acme --json",
      );
      wireCopyButtons(host);
      return;
    }
    host.innerHTML = `
      <table>
        <thead><tr><th>Name</th><th>Slug</th><th>Status</th><th>ID</th><th></th></tr></thead>
        <tbody>
          ${orgs
            .map(
              (o) => `<tr>
            <td>${escapeHtml(o.name)}</td>
            <td>${escapeHtml(o.slug)}</td>
            <td>${escapeHtml(o.status)}</td>
            <td><code>${escapeHtml(o.id)}</code></td>
            <td class="row-actions">
              <button type="button" class="ghost" data-members-org="${escapeAttr(o.id)}">Members</button>
              <button type="button" class="ghost" data-ready-org="${escapeAttr(o.id)}">Readiness</button>
            </td>
          </tr>`,
            )
            .join("")}
        </tbody>
      </table>`;
    host.querySelectorAll("[data-members-org]").forEach((btn) => {
      btn.addEventListener("click", () =>
        setRoute("members", { org: btn.getAttribute("data-members-org") }),
      );
    });
    host.querySelectorAll("[data-ready-org]").forEach((btn) => {
      btn.addEventListener("click", () =>
        setRoute("readiness", { org: btn.getAttribute("data-ready-org") }),
      );
    });
  } catch (e) {
    host.innerHTML = stateError(
      `Failed to load organizations: ${e.message}`,
      "clearance orgs list --json",
    );
    wireCopyButtons(host);
  }
}

// ---------------------------------------------------------------------------
// Sessions — list under principal-derived scope; revoke with confirmation
// Never renders token / bearer / credential material even if upstream leaks it.
// ---------------------------------------------------------------------------
/** @type {{ loading: boolean, revokingId: string|null }} */
let sessionsState = { loading: false, revokingId: null };
let sessionsLoadVersion = 0;

const SESSION_SENSITIVE_KEY = /token|secret|password|authorization|bearer|cookie|credential/i;

/** Safe session view for table rows — strips any credential-like keys. */
function sanitizeSessionForUi(raw) {
  if (!raw || typeof raw !== "object") return null;
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (SESSION_SENSITIVE_KEY.test(k)) continue;
    out[k] = v;
  }
  return {
    id: String(out.id ?? ""),
    principalId: String(out.principalId ?? ""),
    status: out.status === "revoked" ? "revoked" : "active",
    createdAt: out.createdAt ? String(out.createdAt) : "",
    expiresAt: out.expiresAt ? String(out.expiresAt) : "",
    revokedAt: out.revokedAt ? String(out.revokedAt) : "",
    ipAddress: out.ipAddress ? String(out.ipAddress) : "",
    userAgent: out.userAgent ? String(out.userAgent) : "",
    projectId: out.projectId ? String(out.projectId) : "",
    environmentId: out.environmentId ? String(out.environmentId) : "",
  };
}

function sessionStatusBadge(status) {
  const s = status === "revoked" ? "revoked" : "active";
  const cls = s === "active" ? "badge badge-ok" : "badge badge-locked";
  return `<span class="${cls}">${escapeHtml(s)}</span>`;
}

function sessionRowHtml(session, mutable) {
  const actions =
    session.status === "revoked"
      ? `<span class="muted">Revoked</span>`
      : mutable
        ? `<button type="button" class="ghost danger-action" data-revoke-session="${escapeAttr(session.id)}" ${sessionsState.revokingId === session.id ? "disabled aria-busy=\"true\"" : ""}>Revoke</button>`
        : `<span class="muted">View only</span>`;
  return `<tr data-session-id="${escapeAttr(session.id)}" data-session-status="${escapeAttr(session.status)}">
    <td><code>${escapeHtml(session.id)}</code></td>
    <td><code>${escapeHtml(session.principalId)}</code></td>
    <td>${sessionStatusBadge(session.status)}</td>
    <td>${escapeHtml(formatWhen(session.createdAt))}</td>
    <td>${escapeHtml(formatWhen(session.expiresAt) || "—")}</td>
    <td class="ua-cell" title="${escapeAttr(session.userAgent || "")}">${escapeHtml(session.ipAddress || "—")}${session.userAgent ? `<div class="row-sub">${escapeHtml(session.userAgent.length > 48 ? `${session.userAgent.slice(0, 48)}…` : session.userAgent)}</div>` : ""}</td>
    <td>${actions}</td>
  </tr>`;
}

async function renderSessions(params) {
  await ensureOperatorSession();
  if (
    activeRouteName !== "sessions" ||
    params?.routeVersion !== navigationVersion
  ) return;
  sessionsState = { loading: false, revokingId: null };
  view.innerHTML = `
    ${cliBlock("clearance sessions list --json")}
    <p class="meta-foot">Active auth sessions under the operator project/environment scope. Revoke requires confirmation (same as CLI <code>--yes</code>). Session tokens are never shown.</p>
    ${
      canMutate()
        ? ""
        : `<div class="card role-viewer-note" role="status">
      <p>Signed in as <strong>viewer</strong> — you can inspect sessions. Revoke requires an admin operator session.</p>
      ${cliBlock("clearance sessions list --json")}
    </div>`
    }
    <div id="sess-form-msg" class="form-msg" aria-live="polite"></div>
    <div id="sess-table">${stateLoading("Loading sessions…")}</div>
  `;
  wireCopyButtons(view);
  await loadSessionsTable();
}

async function loadSessionsTable() {
  const host = document.getElementById("sess-table");
  if (!host) return;
  const requestVersion = ++sessionsLoadVersion;
  sessionsState.loading = true;
  host.innerHTML = stateLoading("Loading sessions…");
  const mutable = canMutate();
  try {
    const data = await api("/v1/sessions");
    if (requestVersion !== sessionsLoadVersion) return;
    const raw = Array.isArray(data.sessions) ? data.sessions : [];
    const sessions = raw.map(sanitizeSessionForUi).filter(Boolean);
    if (sessions.length === 0) {
      host.innerHTML = stateEmpty(
        "No active sessions",
        "clearance sessions list --json",
      );
      wireCopyButtons(host);
      return;
    }
    host.innerHTML = `
      <div class="card">
        <div class="label">Sessions <span class="badge">${escapeHtml(String(sessions.length))}</span></div>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Auth sessions table"><table class="sessions-table" aria-label="Auth sessions">
          <thead>
            <tr>
              <th scope="col">Session id</th>
              <th scope="col">Principal</th>
              <th scope="col">Status</th>
              <th scope="col">Created</th>
              <th scope="col">Expires</th>
              <th scope="col">Client</th>
              <th scope="col"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            ${sessions.map((s) => sessionRowHtml(s, mutable)).join("")}
          </tbody>
        </table></div>
      </div>
      ${cliBlock("clearance sessions revoke <id> --yes --json")}
    `;
    wireCopyButtons(host);
    if (mutable) {
      host.querySelectorAll("[data-revoke-session]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-revoke-session");
          if (!id || sessionsState.revokingId) return;
          await revokeSessionById(id);
        });
      });
    }
  } catch (e) {
    if (requestVersion !== sessionsLoadVersion) return;
    host.innerHTML = stateError(
      `Failed to load sessions: ${formatApiError(e)}`,
      "clearance sessions list --json",
    );
    wireCopyButtons(host);
  } finally {
    if (requestVersion === sessionsLoadVersion) {
      sessionsState.loading = false;
    }
  }
}

async function revokeSessionById(sessionId) {
  const msg = document.getElementById("sess-form-msg");
  if (!canMutate()) {
    setFormMessage(msg, "Viewer role cannot revoke sessions", "err");
    return;
  }
  if (sessionsState.revokingId) return;

  const ok = confirmDestructive(
    `Revoke session ${sessionId}?\n\nThe user will be signed out of that session. This cannot be undone (matches CLI: clearance sessions revoke ${sessionId} --yes).`,
  );
  if (!ok) {
    setFormMessage(msg, "Revoke cancelled", "");
    return;
  }

  sessionsState.revokingId = sessionId;
	const btn = [...document.querySelectorAll("[data-revoke-session]")].find(
		(candidate) => candidate.getAttribute("data-revoke-session") === sessionId,
	);
  if (btn) {
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
  }
  setFormMessage(msg, "Revoking…", "");
  try {
    const result = await api(`/v1/sessions/${encodeURIComponent(sessionId)}/revoke`, {
      method: "POST",
      body: "{}",
    });
    const idempotent = result?.idempotent === true;
    setFormMessage(
      msg,
      idempotent
        ? `Session ${sessionId} was already revoked`
        : `Revoked session ${sessionId}`,
      "ok",
    );
    // Clear guard before reload so re-rendered rows are not stuck disabled.
    sessionsState.revokingId = null;
    await loadSessionsTable();
  } catch (e) {
    setFormMessage(msg, formatApiError(e), "err");
    sessionsState.revokingId = null;
    if (btn) {
      btn.removeAttribute("aria-busy");
      btn.disabled = false;
    }
  }
}

// ---------------------------------------------------------------------------
// Members — list/add/update/remove under a selected organization
// ---------------------------------------------------------------------------
/** @type {{ orgId: string|null, saving: boolean, mutatingId: string|null }} */
let membersState = { orgId: null, saving: false, mutatingId: null };
let membersLoadVersion = 0;

const MEMBER_ROLE_OPTIONS = ["owner", "admin", "member"];

function membersCliList(orgId) {
  return orgId
    ? `clearance orgs members list --org ${orgId} --json`
    : "clearance orgs members list --org <id> --json";
}

function membersMutationFormHtml(orgId) {
  if (!canMutate()) {
    return `<div class="card role-viewer-note" role="status">
      <p>Signed in as <strong>viewer</strong> — you can inspect members. Add, update, and remove require an admin operator session.</p>
      ${cliBlock(membersCliList(orgId))}
    </div>`;
  }
  return `
    <div class="card" id="m-form-card">
      <div class="label" id="m-form-title">Add member</div>
      <form id="m-form" class="member-form" autocomplete="off" novalidate>
        <div class="field">
          <label class="field-label" for="m-principal">Principal id</label>
          <input id="m-principal" name="principalId" type="text" required maxlength="128" placeholder="usr_…" aria-required="true" />
        </div>
        <div class="field">
          <label class="field-label" for="m-role">Role</label>
          <select id="m-role" name="role" required aria-required="true">
            ${MEMBER_ROLE_OPTIONS.map(
              (r) =>
                `<option value="${escapeAttr(r)}" ${r === "member" ? "selected" : ""}>${escapeHtml(r)}</option>`,
            ).join("")}
            <option value="__custom">Custom slug…</option>
          </select>
        </div>
        <div class="field" id="m-custom-role-wrap" hidden>
          <label class="field-label" for="m-role-custom">Custom role slug</label>
          <input id="m-role-custom" name="roleCustom" type="text" maxlength="48" placeholder="billing-ops" pattern="[a-z][a-z0-9-]*" title="Lowercase alphanumeric with hyphens" />
        </div>
        <div class="form-row member-form-actions">
          <button type="submit" class="primary" id="m-add">Add member</button>
        </div>
      </form>
      <div id="m-form-msg" class="form-msg" aria-live="polite"></div>
      ${cliBlock(
        orgId
          ? `clearance orgs members add --org ${orgId} --user <id> --role member --json`
          : "clearance orgs members add --org <id> --user <id> --role member --json",
      )}
    </div>
  `;
}

function resolveMemberRoleFromForm() {
  const select = document.getElementById("m-role");
  const custom = document.getElementById("m-role-custom");
  if (!select) return "";
  if (select.value === "__custom") {
    return (custom?.value || "").trim().toLowerCase();
  }
  return select.value;
}

function memberRowHtml(member, orgId, mutable) {
  const role = String(member.role || "");
  const status = String(member.status || "active");
  const actions = mutable
    ? `<div class="row-actions">
        <label class="sr-only" for="m-role-${escapeAttr(member.id)}">Role for ${escapeAttr(member.principalId)}</label>
        <select id="m-role-${escapeAttr(member.id)}" class="inline-select" data-member-role="${escapeAttr(member.id)}" data-original-role="${escapeAttr(role)}" aria-label="Role for ${escapeAttr(member.principalId)}">
          ${[...new Set([...MEMBER_ROLE_OPTIONS, role])]
            .filter(Boolean)
            .map(
              (r) =>
                `<option value="${escapeAttr(r)}" ${r === role ? "selected" : ""}>${escapeHtml(r)}</option>`,
            )
            .join("")}
        </select>
        <button type="button" class="ghost" data-update-member="${escapeAttr(member.id)}" disabled>Update</button>
        <button type="button" class="ghost danger-action" data-remove-member="${escapeAttr(member.id)}" ${membersState.mutatingId === member.id ? "disabled" : ""}>Remove</button>
      </div>`
    : `<span class="muted">View only</span>`;
  return `<tr data-member-id="${escapeAttr(member.id)}" data-org-id="${escapeAttr(orgId)}">
    <td><code>${escapeHtml(member.principalId)}</code></td>
    <td><code>${escapeHtml(role)}</code></td>
    <td>${escapeHtml(status)}</td>
    <td><code>${escapeHtml(member.id)}</code></td>
    <td>${escapeHtml(formatWhen(member.updatedAt || member.createdAt))}</td>
    <td>${actions}</td>
  </tr>`;
}

async function renderMembers(params) {
  await ensureOperatorSession();
  if (
    activeRouteName !== "members" ||
    params?.routeVersion !== navigationVersion
  ) return;
  membersState = { orgId: null, saving: false, mutatingId: null };
  view.innerHTML = stateLoading("Loading organizations…");
  let orgs = [];
  try {
    orgs = (await api("/v1/organizations")).organizations || [];
    if (
      activeRouteName !== "members" ||
      params?.routeVersion !== navigationVersion
    ) return;
  } catch (e) {
    view.innerHTML = stateError(
      `Failed to load organizations: ${formatApiError(e)}`,
      "clearance orgs list --json",
    );
    wireCopyButtons(view);
    return;
  }

  const fromUrl = new URLSearchParams(location.search).get("org");
  const orgId = params?.org || fromUrl || orgs[0]?.id || null;
  membersState.orgId = orgId;

  if (!orgId) {
    view.innerHTML = stateEmpty(
      "No organizations — create one first",
      "clearance orgs create --name Acme --json",
    );
    wireCopyButtons(view);
    return;
  }

  const cli = membersCliList(orgId);
  view.innerHTML = `
    ${cliBlock(cli)}
    <div class="form-row">
      <label class="field-label" for="m-org">Organization</label>
      <select id="m-org" aria-label="Organization">
        ${orgs
          .map(
            (o) =>
              `<option value="${escapeAttr(o.id)}" ${o.id === orgId ? "selected" : ""}>${escapeHtml(o.name)} (${escapeHtml(o.id)})</option>`,
          )
          .join("")}
      </select>
      <button type="button" class="ghost" id="m-reload">Reload</button>
    </div>
    ${membersMutationFormHtml(orgId)}
    <div id="m-table">${stateLoading("Loading members…")}</div>
  `;
  wireCopyButtons(view);

  // Keep URL reload-safe when org changes
  const orgSelect = document.getElementById("m-org");
  orgSelect?.addEventListener("change", (e) => {
    setRoute("members", { org: e.target.value });
  });
  document.getElementById("m-reload")?.addEventListener("click", () => {
    setRoute("members", { org: document.getElementById("m-org")?.value || orgId });
  });

  if (canMutate()) {
    const form = document.getElementById("m-form");
    const roleSelect = document.getElementById("m-role");
    const customWrap = document.getElementById("m-custom-role-wrap");
    roleSelect?.addEventListener("change", () => {
      if (customWrap) customWrap.hidden = roleSelect.value !== "__custom";
      if (roleSelect.value === "__custom") {
        document.getElementById("m-role-custom")?.focus();
      }
    });
    form?.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      await addMemberFromForm();
    });
  }

  await loadMembersTable(orgId);
}

async function addMemberFromForm() {
  const msg = document.getElementById("m-form-msg");
  if (!canMutate()) {
    setFormMessage(msg, "Viewer role cannot add members", "err");
    return;
  }
  if (membersState.saving) return;

  const orgId = document.getElementById("m-org")?.value || membersState.orgId;
  const principalEl = document.getElementById("m-principal");
  const principalId = principalEl?.value.trim() || "";
  const role = resolveMemberRoleFromForm();

  if (!orgId) {
    setFormMessage(msg, "Select an organization", "err");
    return;
  }
  if (!principalId) {
    setFormMessage(msg, "Principal id is required", "err");
    principalEl?.focus();
    return;
  }
  if (!role) {
    setFormMessage(msg, "Role is required", "err");
    const customEl = document.getElementById("m-role-custom");
    if (document.getElementById("m-role")?.value === "__custom" && customEl) {
      customEl.focus();
    } else {
      document.getElementById("m-role")?.focus();
    }
    return;
  }

  const confirmed = confirmDestructive(
    `Add principal ${principalId} to organization ${orgId} as ${role}?\n\nCLI equivalent: clearance orgs members add --org ${orgId} --user ${principalId} --role ${role} --json`,
  );
  if (!confirmed) {
    setFormMessage(msg, "Add member cancelled", "");
    return;
  }

  const addBtn = document.getElementById("m-add");
  membersState.saving = true;
  if (addBtn) {
    addBtn.disabled = true;
    addBtn.setAttribute("aria-busy", "true");
  }
  setFormMessage(msg, "Adding member…", "");
  try {
    const result = await api(
      `/v1/organizations/${encodeURIComponent(orgId)}/members`,
      {
        method: "POST",
        body: JSON.stringify({ principalId, role }),
      },
    );
    const membership = result?.membership;
    setFormMessage(
      msg,
      `Added ${principalId} as ${membership?.role || role}`,
      "ok",
    );
    document.getElementById("m-form")?.reset();
    const roleSelect = document.getElementById("m-role");
    if (roleSelect) roleSelect.value = "member";
    const customWrap = document.getElementById("m-custom-role-wrap");
    if (customWrap) customWrap.hidden = true;
    await loadMembersTable(orgId);
  } catch (e) {
    setFormMessage(msg, formatApiError(e), "err");
    if (e.code === "MEMBER_PRINCIPAL_REQUIRED" || e.code === "USER_NOT_FOUND") {
      principalEl?.focus();
    }
  } finally {
    membersState.saving = false;
    if (addBtn) {
      addBtn.removeAttribute("aria-busy");
      addBtn.disabled = false;
    }
  }
}

async function loadMembersTable(orgId) {
  const host = document.getElementById("m-table");
  if (!host || !orgId) return;
  const requestVersion = ++membersLoadVersion;
  host.innerHTML = stateLoading("Loading members…");
  const mutable = canMutate();
  const cli = membersCliList(orgId);
  try {
    const data = await api(
      `/v1/organizations/${encodeURIComponent(orgId)}/members`,
    );
    if (requestVersion !== membersLoadVersion) return;
    const members = Array.isArray(data.members) ? data.members : [];
    if (members.length === 0) {
      host.innerHTML = stateEmpty(
        "No members in this organization",
        `clearance orgs members add --org ${orgId} --user <id> --role member --json`,
      );
      wireCopyButtons(host);
      return;
    }
    host.innerHTML = `
      <div class="card">
        <div class="label">Members <span class="badge">${escapeHtml(String(members.length))}</span></div>
        <div class="table-scroll" tabindex="0" role="region" aria-label="Organization members table"><table class="members-table" aria-label="Organization members">
          <thead>
            <tr>
              <th scope="col">Principal</th>
              <th scope="col">Role</th>
              <th scope="col">Status</th>
              <th scope="col">Membership id</th>
              <th scope="col">Updated</th>
              <th scope="col"><span class="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            ${members.map((m) => memberRowHtml(m, orgId, mutable)).join("")}
          </tbody>
        </table></div>
      </div>
      ${cliBlock(`clearance orgs members update --org ${orgId} --member <id> --role <role> --json`)}
      ${cliBlock(`clearance orgs members remove --org ${orgId} --member <id> --yes --json`)}
    `;
    wireCopyButtons(host);

    if (mutable) {
		host.querySelectorAll("[data-member-role]").forEach((select) => {
			select.addEventListener("change", () => {
				const id = select.getAttribute("data-member-role");
				const button = [...host.querySelectorAll("[data-update-member]")].find(
					(candidate) => candidate.getAttribute("data-update-member") === id,
				);
				if (button) {
					button.disabled = select.value === select.getAttribute("data-original-role");
				}
			});
		});
      host.querySelectorAll("[data-update-member]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-update-member");
          if (!id || membersState.mutatingId) return;
			const select = [...host.querySelectorAll("[data-member-role]")].find(
				(candidate) => candidate.getAttribute("data-member-role") === id,
			);
          const role = select?.value || "";
          await updateMemberRole(orgId, id, role);
        });
      });
      host.querySelectorAll("[data-remove-member]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-remove-member");
          if (!id || membersState.mutatingId) return;
          await removeMemberById(orgId, id);
        });
      });
    }
  } catch (e) {
    if (requestVersion !== membersLoadVersion) return;
    host.innerHTML = stateError(
      `Failed to load members: ${formatApiError(e)}`,
      cli,
    );
    wireCopyButtons(host);
  }
}

async function updateMemberRole(orgId, memberId, role) {
  const msg = document.getElementById("m-form-msg");
  if (!canMutate()) {
    setFormMessage(msg, "Viewer role cannot update members", "err");
    return;
  }
  if (membersState.mutatingId) return;
  if (!role) {
    setFormMessage(msg, "Role is required", "err");
    return;
  }

  const ok = confirmDestructive(
    `Update membership ${memberId} to role "${role}"?\n\nCLI equivalent: clearance orgs members update --org ${orgId} --member ${memberId} --role ${role} --json`,
  );
  if (!ok) {
    setFormMessage(msg, "Update cancelled", "");
    return;
  }

  membersState.mutatingId = memberId;
	const row = [...document.querySelectorAll("[data-member-id]")].find(
		(candidate) => candidate.getAttribute("data-member-id") === memberId,
	);
  row?.querySelectorAll("button, select").forEach((el) => {
    el.disabled = true;
    if (el.tagName === "BUTTON") el.setAttribute("aria-busy", "true");
  });
  setFormMessage(msg, "Updating member…", "");
  try {
    const result = await api(
      `/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ role }),
      },
    );
    setFormMessage(
      msg,
      `Updated membership → ${result?.membership?.role || role}`,
      "ok",
    );
    // Clear before reload so action controls are not baked disabled into HTML.
    membersState.mutatingId = null;
    await loadMembersTable(orgId);
  } catch (e) {
    setFormMessage(msg, formatApiError(e), "err");
    membersState.mutatingId = null;
    row?.querySelectorAll("button, select").forEach((el) => {
      el.disabled = false;
      el.removeAttribute("aria-busy");
    });
  }
}

async function removeMemberById(orgId, memberId) {
  const msg = document.getElementById("m-form-msg");
  if (!canMutate()) {
    setFormMessage(msg, "Viewer role cannot remove members", "err");
    return;
  }
  if (membersState.mutatingId) return;

  const ok = confirmDestructive(
    `Remove membership ${memberId} from organization ${orgId}?\n\nThis is destructive (matches CLI --yes). Owner invariants still apply — the final owner cannot be removed.`,
  );
  if (!ok) {
    setFormMessage(msg, "Remove cancelled", "");
    return;
  }

  membersState.mutatingId = memberId;
	const row = [...document.querySelectorAll("[data-member-id]")].find(
		(candidate) => candidate.getAttribute("data-member-id") === memberId,
	);
  row?.querySelectorAll("button, select").forEach((el) => {
    el.disabled = true;
    if (el.tagName === "BUTTON") el.setAttribute("aria-busy", "true");
  });
  setFormMessage(msg, "Removing member…", "");
  try {
    const result = await api(
      `/v1/organizations/${encodeURIComponent(orgId)}/members/${encodeURIComponent(memberId)}`,
      { method: "DELETE" },
    );
    setFormMessage(
      msg,
      `Removed membership ${result?.membership?.id || memberId}`,
      "ok",
    );
    membersState.mutatingId = null;
    await loadMembersTable(orgId);
  } catch (e) {
    setFormMessage(msg, formatApiError(e), "err");
    membersState.mutatingId = null;
    row?.querySelectorAll("button, select").forEach((el) => {
      el.disabled = false;
      el.removeAttribute("aria-busy");
    });
  }
}

// ---------------------------------------------------------------------------
// Roles — list built-in + custom; validate-before-save for create/update
// ---------------------------------------------------------------------------
/** @type {{ mode: 'create'|'edit', roleId?: string, validated: null|{ name?: string, slug?: string, permissions?: string[] }, saving?: boolean }} */
let rolesFormState = { mode: "create", validated: null, saving: false };
let rolesValidationVersion = 0;

function isBuiltInRole(role) {
  return (
    role?.kind === "built_in" ||
    String(role?.id || "").startsWith("role_builtin_")
  );
}

function clearRolesValidation() {
	rolesValidationVersion += 1;
  rolesFormState.validated = null;
  const preview = document.getElementById("r-validate-preview");
  if (preview) {
    preview.hidden = true;
    preview.innerHTML = "";
  }
  const saveBtn = document.getElementById("r-save");
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.setAttribute("aria-disabled", "true");
  }
}

function showValidatedPreview(validated) {
  const preview = document.getElementById("r-validate-preview");
  if (!preview) return;
  const perms = Array.isArray(validated.permissions) ? validated.permissions : [];
  preview.hidden = false;
  preview.innerHTML = `
    <div class="label">Normalized (not saved yet)</div>
    <dl class="role-preview">
      ${
        validated.name !== undefined
          ? `<div><dt>Name</dt><dd>${escapeHtml(validated.name)}</dd></div>`
          : ""
      }
      ${
        validated.slug !== undefined
          ? `<div><dt>Slug</dt><dd><code>${escapeHtml(validated.slug)}</code></dd></div>`
          : ""
      }
      <div>
        <dt>Permissions (${perms.length})</dt>
        <dd>${
          perms.length
            ? `<ul class="perm-list">${perms.map((p) => `<li><code>${escapeHtml(p)}</code></li>`).join("")}</ul>`
            : "<span class=\"muted\">—</span>"
        }</dd>
      </div>
    </dl>
    <p class="meta-foot">Review normalized permissions, then save to persist.</p>
  `;
  const saveBtn = document.getElementById("r-save");
  if (saveBtn) {
    saveBtn.disabled = false;
    saveBtn.removeAttribute("aria-disabled");
    saveBtn.focus();
  }
}

function setRolesFormMode(mode, role) {
  rolesFormState.mode = mode;
  rolesFormState.roleId = role?.id;
  rolesFormState.validated = null;
  const title = document.getElementById("r-form-title");
  const saveBtn = document.getElementById("r-save");
  const slugInput = document.getElementById("r-slug");
  const cancelBtn = document.getElementById("r-cancel-edit");
  if (!title || !saveBtn) return;

  if (mode === "edit" && role) {
    title.textContent = `Edit custom role · ${role.slug || role.name}`;
    document.getElementById("r-name").value = role.name || "";
    if (slugInput) {
      slugInput.value = role.slug || "";
      slugInput.disabled = true;
      slugInput.title = "Slug cannot be changed after create";
    }
    document.getElementById("r-desc").value = role.description || "";
    document.getElementById("r-perms").value = permissionsToText(role.permissions);
    saveBtn.textContent = "Save role";
    if (cancelBtn) cancelBtn.hidden = false;
  } else {
    title.textContent = "Create custom role";
    document.getElementById("r-name").value = "";
    if (slugInput) {
      slugInput.value = "";
      slugInput.disabled = false;
      slugInput.title = "";
    }
    document.getElementById("r-desc").value = "";
    document.getElementById("r-perms").value = "";
    saveBtn.textContent = "Create role";
    if (cancelBtn) cancelBtn.hidden = true;
  }
  clearRolesValidation();
}

async function validateRolesForm() {
  const msg = document.getElementById("r-form-msg");
  const nameEl = document.getElementById("r-name");
  const slugEl = document.getElementById("r-slug");
  const permsEl = document.getElementById("r-perms");
  const name = nameEl?.value.trim() || "";
  const slug = slugEl?.value.trim() || "";
  const permissions = parsePermissionsText(permsEl?.value);

  if (!name) {
    setFormMessage(msg, "Role name is required", "err");
    nameEl?.focus();
    return null;
  }
  if (permissions.length === 0) {
    setFormMessage(msg, "Add at least one resource:action permission (one per line)", "err");
    permsEl?.focus();
    return null;
  }

  // Reflect client-side normalize (trim/dedupe) back into the textarea for clarity
  if (permsEl) permsEl.value = permissions.join("\n");

	clearRolesValidation();
	const requestVersion = rolesValidationVersion;
	const validateBtn = document.getElementById("r-validate");
	const form = document.getElementById("r-form");
	if (validateBtn) validateBtn.disabled = true;
	form?.setAttribute("aria-busy", "true");
  setFormMessage(msg, "Validating…", "");
  const body = { name, permissions };
	// The slug is immutable during edit, yet it still belongs to the draft being
	// validated. Sending it prevents a renamed role from being validated against
	// an unrelated derived slug.
	if (slug) body.slug = slug;

  try {
    const result = await api("/v1/roles/validate", {
      method: "POST",
      body: JSON.stringify(body),
    });
		// Input may have changed while validation was in flight. Never enable Save
		// for a response that no longer describes the visible form.
		if (requestVersion !== rolesValidationVersion) return null;
    rolesFormState.validated = {
      name: result.name ?? name,
      slug: result.slug ?? (slug || undefined),
      permissions: Array.isArray(result.permissions) ? result.permissions : permissions,
    };
    // Show server-normalized permissions in the editor
    if (permsEl && rolesFormState.validated.permissions) {
      permsEl.value = rolesFormState.validated.permissions.join("\n");
    }
    if (slugEl && rolesFormState.validated.slug && rolesFormState.mode === "create") {
      slugEl.value = rolesFormState.validated.slug;
    }
    showValidatedPreview(rolesFormState.validated);
    setFormMessage(
      msg,
      "Validation passed — review normalized permissions, then save",
      "ok",
    );
    return rolesFormState.validated;
  } catch (e) {
		if (requestVersion !== rolesValidationVersion) return null;
    clearRolesValidation();
    setFormMessage(msg, formatApiError(e), "err");
    if (e.code === "ROLE_NAME_REQUIRED" || e.code === "ROLE_NAME_INVALID") {
      nameEl?.focus();
    } else if (
      e.code === "ROLE_SLUG_REQUIRED" ||
      e.code === "ROLE_SLUG_INVALID" ||
      e.code === "ROLE_RESERVED"
    ) {
      slugEl?.focus();
    } else {
      permsEl?.focus();
    }
    return null;
	} finally {
		if (validateBtn) validateBtn.disabled = false;
		form?.removeAttribute("aria-busy");
  }
}

async function saveRolesForm() {
  const msg = document.getElementById("r-form-msg");
  if (!canMutate()) {
    setFormMessage(msg, "Viewer role cannot create or update roles", "err");
    return;
  }
	if (rolesFormState.saving) return;

  let validated = rolesFormState.validated;
  if (!validated) {
    validated = await validateRolesForm();
    if (!validated) return;
    // Require explicit second step after first validate
    setFormMessage(
      msg,
      "Validation passed — review normalized permissions, then click save again to persist",
      "ok",
    );
    return;
  }

  const description = document.getElementById("r-desc")?.value.trim() || "";
	const saveBtn = document.getElementById("r-save");
	rolesFormState.saving = true;
	if (saveBtn) {
		saveBtn.disabled = true;
		saveBtn.setAttribute("aria-busy", "true");
	}
  setFormMessage(msg, "Saving…", "");
  try {
    if (rolesFormState.mode === "edit" && rolesFormState.roleId) {
      const body = {
        name: validated.name,
        permissions: validated.permissions,
      };
      if (description) body.description = description;
      else body.description = null;
      await api(`/v1/roles/${encodeURIComponent(rolesFormState.roleId)}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      setFormMessage(msg, `Updated role ${validated.slug || validated.name}`, "ok");
    } else {
      const body = {
        name: validated.name,
        permissions: validated.permissions,
      };
      if (validated.slug) body.slug = validated.slug;
      if (description) body.description = description;
      await api("/v1/roles", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setFormMessage(msg, `Created role ${validated.slug || validated.name}`, "ok");
    }
    setRolesFormMode("create");
    await loadRolesTable();
  } catch (e) {
    setFormMessage(msg, formatApiError(e), "err");
	} finally {
		rolesFormState.saving = false;
		if (saveBtn) {
			saveBtn.removeAttribute("aria-busy");
			if (rolesFormState.validated) saveBtn.disabled = false;
		}
  }
}

function rolesMutationFormHtml() {
  if (!canMutate()) {
    return `<div class="card role-viewer-note" role="status">
      <p>Signed in as <strong>viewer</strong> — you can inspect roles. Create and update require an admin operator session.</p>
      ${cliBlock("clearance roles list --json")}
    </div>`;
  }
  return `
    <div class="card" id="r-form-card">
      <div class="label" id="r-form-title">Create custom role</div>
      <form id="r-form" class="role-form" autocomplete="off" novalidate>
        <div class="field">
          <label class="field-label" for="r-name">Name</label>
          <input id="r-name" name="name" type="text" required maxlength="64" placeholder="Billing ops" aria-required="true" />
        </div>
        <div class="field">
          <label class="field-label" for="r-slug">Slug <span class="optional">(optional on create)</span></label>
          <input id="r-slug" name="slug" type="text" maxlength="48" placeholder="billing-ops" pattern="[a-z][a-z0-9-]*" title="Lowercase alphanumeric with hyphens" />
        </div>
        <div class="field field-full">
          <label class="field-label" for="r-desc">Description <span class="optional">(optional)</span></label>
          <input id="r-desc" name="description" type="text" maxlength="256" placeholder="Short description" />
        </div>
        <div class="field field-full">
          <label class="field-label" for="r-perms">Permissions</label>
          <p class="field-hint" id="r-perms-hint">One <code>resource:action</code> per line. Blanks are trimmed; duplicates are dropped client-side. Validate before save.</p>
          <textarea id="r-perms" name="permissions" rows="6" required aria-describedby="r-perms-hint" aria-required="true" placeholder="billing:read&#10;billing:write"></textarea>
        </div>
        <div class="form-row role-form-actions">
          <button type="button" class="ghost" id="r-validate">Validate</button>
          <button type="submit" class="primary" id="r-save" disabled aria-disabled="true">Create role</button>
          <button type="button" class="ghost" id="r-cancel-edit" hidden>Cancel edit</button>
        </div>
      </form>
      <div id="r-form-msg" class="form-msg" aria-live="polite"></div>
      <div id="r-validate-preview" class="role-validate-preview" hidden aria-live="polite"></div>
      ${cliBlock('clearance roles validate --name "Billing" --permission billing:read --json')}
      ${cliBlock('clearance roles create --name "Billing" --permission billing:read --json')}
    </div>
  `;
}

function roleRowHtml(role, mutable) {
  const builtIn = isBuiltInRole(role);
  const kindLabel = builtIn ? "Built-in" : "Custom";
  const kindClass = builtIn ? "kind-builtin" : "kind-custom";
  const perms = Array.isArray(role.permissions) ? role.permissions : [];
  const permPreview =
    perms.length <= 4
      ? perms.map((p) => escapeHtml(p)).join(", ")
      : `${perms
          .slice(0, 3)
          .map((p) => escapeHtml(p))
          .join(", ")} +${perms.length - 3}`;
  const actions = builtIn
    ? `<span class="badge badge-locked" title="Built-in roles cannot be updated">Immutable</span>`
    : mutable
      ? `<button type="button" class="ghost" data-edit-role="${escapeAttr(role.id)}">Edit</button>`
      : `<span class="muted">View only</span>`;
  return `<tr class="${escapeAttr(kindClass)}" data-role-id="${escapeAttr(role.id)}" data-role-kind="${escapeAttr(builtIn ? "built_in" : "custom")}">
    <td><span class="badge ${escapeAttr(kindClass)}">${escapeHtml(kindLabel)}</span></td>
    <td>
      <strong>${escapeHtml(role.name)}</strong>
      ${role.description ? `<div class="row-sub">${escapeHtml(role.description)}</div>` : ""}
      ${builtIn ? `<div class="row-sub muted">System hierarchy · not editable</div>` : ""}
    </td>
    <td><code>${escapeHtml(role.slug)}</code></td>
    <td class="perm-cell" title="${escapeAttr(perms.join("\n"))}"><code>${permPreview || "—"}</code></td>
    <td>${actions}</td>
  </tr>`;
}

async function renderRoles() {
  await ensureOperatorSession();
  rolesFormState = { mode: "create", validated: null, saving: false };
  view.innerHTML = `
    ${cliBlock("clearance roles list --json")}
    <p class="meta-foot">Built-in roles (owner → admin → member) are system hierarchy and immutable. Custom roles are validated before save.</p>
    ${rolesMutationFormHtml()}
    <div id="r-table">${stateLoading("Loading roles…")}</div>
  `;
  wireCopyButtons(view);

  if (canMutate()) {
    const form = document.getElementById("r-form");
    const validateBtn = document.getElementById("r-validate");
    const cancelBtn = document.getElementById("r-cancel-edit");
    form?.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      await saveRolesForm();
    });
    validateBtn?.addEventListener("click", async () => {
      await validateRolesForm();
    });
    cancelBtn?.addEventListener("click", () => {
      setRolesFormMode("create");
      setFormMessage(document.getElementById("r-form-msg"), "", "");
    });
    // Any edit invalidates prior validate result
    ["r-name", "r-slug", "r-desc", "r-perms"].forEach((id) => {
      document.getElementById(id)?.addEventListener("input", () => {
        if (rolesFormState.validated) clearRolesValidation();
      });
    });
  }

  await loadRolesTable();
}

async function loadRolesTable() {
  const host = document.getElementById("r-table");
  if (!host) return;
  host.innerHTML = stateLoading("Loading roles…");
  const mutable = canMutate();
  try {
    const data = await api("/v1/roles");
    const roles = Array.isArray(data.roles) ? data.roles : [];
    if (roles.length === 0) {
      host.innerHTML = stateEmpty(
        "No roles returned",
        "clearance roles list --json",
      );
      wireCopyButtons(host);
      return;
    }
    const builtIns = roles.filter((r) => isBuiltInRole(r));
    const custom = roles.filter((r) => !isBuiltInRole(r));
    // Preserve API order within groups (built-ins first by hierarchy)
    host.innerHTML = `
      <div class="card">
        <div class="label">Built-in roles <span class="badge badge-locked">Immutable</span></div>
        ${
          builtIns.length === 0
            ? stateEmpty("No built-in roles in response")
            : `<table class="roles-table">
          <thead><tr><th>Kind</th><th>Name</th><th>Slug</th><th>Permissions</th><th></th></tr></thead>
          <tbody>
            ${builtIns.map((r) => roleRowHtml(r, mutable)).join("")}
          </tbody>
        </table>`
        }
      </div>
      <div class="card">
        <div class="label">Custom roles</div>
        ${
          custom.length === 0
            ? stateEmpty(
                "No custom roles yet",
                'clearance roles create --name "Billing" --permission billing:read --json',
              )
            : `<table class="roles-table">
          <thead><tr><th>Kind</th><th>Name</th><th>Slug</th><th>Permissions</th><th></th></tr></thead>
          <tbody>
            ${custom.map((r) => roleRowHtml(r, mutable)).join("")}
          </tbody>
        </table>`
        }
      </div>
    `;
    wireCopyButtons(host);

    if (mutable) {
      host.querySelectorAll("[data-edit-role]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-edit-role");
          const role = roles.find((r) => r.id === id);
          if (!role || isBuiltInRole(role)) return;
          setRolesFormMode("edit", role);
          document.getElementById("r-form-card")?.scrollIntoView({ block: "nearest" });
          document.getElementById("r-name")?.focus();
          setFormMessage(
            document.getElementById("r-form-msg"),
            "Editing custom role — validate before save",
            "",
          );
        });
      });
    }
  } catch (e) {
    host.innerHTML = stateError(
      `Failed to load roles: ${formatApiError(e)}`,
      "clearance roles list --json",
    );
    wireCopyButtons(host);
  }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------
async function renderEvents() {
  view.innerHTML = `
    ${cliBlock("clearance events list --json")}
    <div id="e-table">${stateLoading("Loading events…")}</div>
  `;
  wireCopyButtons(view);
  const host = document.getElementById("e-table");
  try {
    const data = await api("/v1/events?limit=50");
    const events = Array.isArray(data.events) ? data.events : [];
    if (events.length === 0) {
      host.innerHTML = stateEmpty(
        "No events yet — mutations and CLI commands write the audit log",
        "clearance events list --json",
      );
      wireCopyButtons(host);
      return;
    }
    host.innerHTML = `
      <table>
        <thead><tr><th>Action</th><th>Actor</th><th>Outcome</th><th>Correlation</th><th>Message</th></tr></thead>
        <tbody>
          ${events
            .map(
              (e) => `<tr>
            <td>${escapeHtml(e.action)}</td>
            <td>${escapeHtml(e.actor)}</td>
            <td>${escapeHtml(e.outcome)}</td>
            <td><code>${escapeHtml(e.correlationId)}</code></td>
            <td>${escapeHtml(e.message)}</td>
          </tr>`,
            )
            .join("")}
        </tbody>
      </table>`;
  } catch (e) {
    host.innerHTML = stateError(
      `Failed to load events: ${e.message}`,
      "clearance events list --json",
    );
    wireCopyButtons(host);
  }
}

// ---------------------------------------------------------------------------
// Readiness — same report as CLI `clearance readiness check/report --json`
// ---------------------------------------------------------------------------
async function renderReadiness(params) {
  view.innerHTML = stateLoading("Loading organizations…");
  let orgs = [];
  try {
    orgs = (await api("/v1/organizations")).organizations || [];
  } catch (e) {
    view.innerHTML = stateError(
      `Failed to load organizations: ${e.message}`,
      "clearance orgs list --json",
    );
    wireCopyButtons(view);
    return;
  }

  const fromUrl = new URLSearchParams(location.search).get("org");
  const orgId = params?.org || fromUrl || orgs[0]?.id;

  if (!orgId) {
    view.innerHTML = stateEmpty(
      "No organizations — create one first",
      "clearance orgs create --name Acme --json",
    );
    wireCopyButtons(view);
    return;
  }

  const cli = `clearance readiness check --org ${orgId} --json`;
  view.innerHTML = `
    ${cliBlock(cli)}
    <div class="form-row">
      <label class="field-label" for="ready-org">Organization</label>
      <select id="ready-org">
        ${orgs
          .map(
            (o) =>
              `<option value="${escapeAttr(o.id)}" ${o.id === orgId ? "selected" : ""}>${escapeHtml(o.name)} (${escapeHtml(o.id)})</option>`,
          )
          .join("")}
      </select>
      <button type="button" class="primary" id="ready-run">Run readiness check</button>
    </div>
    <div id="ready-form-msg" class="form-msg" aria-live="polite"></div>
    <div id="ready-report">${stateLoading("Loading report…")}</div>
  `;
  wireCopyButtons(view);

  document.getElementById("ready-org").onchange = (e) => {
    setRoute("readiness", { org: e.target.value });
  };
  document.getElementById("ready-run").onclick = async () => {
    const id = document.getElementById("ready-org").value;
    const msg = document.getElementById("ready-form-msg");
    setFormMessage(msg, "Running check…", "");
    try {
      await api("/v1/readiness/check", {
        method: "POST",
        body: JSON.stringify({ organizationId: id }),
      });
      setFormMessage(msg, "Check complete", "ok");
      setRoute("readiness", { org: id });
    } catch (e) {
      setFormMessage(msg, e.message, "err");
    }
  };

  await loadReadinessReport(orgId);
}

async function loadReadinessReport(orgId) {
  const host = document.getElementById("ready-report");
  if (!host) return;
  host.innerHTML = stateLoading("Loading report…");
  const cli = `clearance readiness check --org ${orgId} --json`;
  try {
    let reportBody;
    try {
      reportBody = await api(`/v1/readiness/${encodeURIComponent(orgId)}`);
    } catch (e) {
      // No report yet — run check once so console matches CLI check path
      const missing =
        e.status === 404 ||
        e.code === "READINESS_NOT_FOUND" ||
        /not found|no readiness/i.test(e.message || "");
      if (!missing) throw e;
      reportBody = await api("/v1/readiness/check", {
        method: "POST",
        body: JSON.stringify({ organizationId: orgId }),
      });
    }
    const report = reportBody?.report;
    if (!report) {
      host.innerHTML = stateEmpty("No readiness report", cli);
      wireCopyButtons(host);
      return;
    }
    const checks = Array.isArray(report.checks) ? report.checks : [];
    const actions = Array.isArray(report.remainingCustomerActions)
      ? report.remainingCustomerActions
      : [];
    const statusClass = String(report.overall || "")
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "");
    host.innerHTML = `
      <div class="grid">
        <div class="card"><div class="label">Overall</div><div class="value value-sm"><span class="dot ${escapeAttr(statusClass)}"></span> ${escapeHtml(report.overall)}</div></div>
        <div class="card"><div class="label">Organization</div><div class="value value-sm"><code>${escapeHtml(report.organizationId)}</code></div></div>
        <div class="card"><div class="label">Signature</div><div class="value value-sm"><code id="ready-signature">${escapeHtml(report.signature)}</code></div></div>
        <div class="card"><div class="label">Generated</div><div class="value value-sm">${escapeHtml(formatWhen(report.generatedAt) || report.generatedAt)}</div></div>
      </div>
      <div class="card">
        <div class="label">Checks (same source as CLI readiness check/report)</div>
        <div class="checks" id="ready-checks">
          ${
            checks.length === 0
              ? `<div class="empty">No checks in report</div>`
              : checks
                  .map(
                    (c) =>
                      `<div class="check" data-check-id="${escapeAttr(c.id)}"><span class="dot ${escapeAttr(c.status)}"></span><strong>${escapeHtml(c.name)}</strong> — ${escapeHtml(c.detail)}${c.fingerprint ? ` <code>${escapeHtml(c.fingerprint)}</code>` : ""}</div>`,
                  )
                  .join("")
          }
        </div>
      </div>
      ${
        actions.length
          ? `<div class="card"><div class="label">Remaining customer actions</div><ul class="action-list">${actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul></div>`
          : ""
      }
      ${cliBlock(cli)}
    `;
    wireCopyButtons(host);
  } catch (e) {
    host.innerHTML = stateError(`Failed to load readiness: ${e.message}`, cli);
    wireCopyButtons(host);
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
async function renderSettings() {
  view.innerHTML = `
    ${cliBlock("clearance doctor --json")}
    <div id="s-body">${stateLoading("Loading settings…")}</div>
  `;
  wireCopyButtons(view);
  const host = document.getElementById("s-body");
  try {
    const [settings, doctor] = await Promise.all([
      api("/v1/settings"),
      api("/v1/doctor"),
    ]);
    const checks = Array.isArray(doctor.checks) ? doctor.checks : [];
    const configJson = JSON.stringify(settings.config ?? {}, null, 2);
    host.innerHTML = `
      <div class="grid">
        <div class="card"><div class="label">Release</div><div class="value value-sm">${escapeHtml(settings.releaseVersion)}</div></div>
        <div class="card"><div class="label">Schema</div><div class="value">${escapeHtml(settings.schemaVersion)}</div></div>
        <div class="card"><div class="label">Telemetry</div><div class="value value-sm">${escapeHtml(settings.telemetry?.default ?? "disabled")}</div></div>
        <div class="card"><div class="label">Doctor</div><div class="value value-sm">${doctor.ok ? "healthy" : "issues"}</div></div>
      </div>
      <div class="grid">
        <div class="card"><div class="label">Store</div><div class="value value-sm">${escapeHtml(settings.storeBackend ?? "—")}</div></div>
        <div class="card"><div class="label">Auth mode</div><div class="value value-sm">${escapeHtml(settings.auth?.mode ?? "bearer-operator")}</div></div>
        <div class="card"><div class="label">Project scope</div><div class="value value-sm"><code>${escapeHtml(settings.scope?.projectId ?? "—")}</code></div></div>
        <div class="card"><div class="label">Env scope</div><div class="value value-sm"><code>${escapeHtml(settings.scope?.environmentId ?? "—")}</code></div></div>
      </div>
      <div class="card">
        <div class="label">Doctor checks (same source as CLI)</div>
        <div class="checks">
          ${
            checks.length === 0
              ? stateEmpty("No doctor checks returned")
              : checks
                  .map(
                    (c) =>
                      `<div class="check"><span class="dot ${escapeAttr(c.status)}"></span><strong>${escapeHtml(c.name)}</strong> — ${escapeHtml(c.detail)}</div>`,
                  )
                  .join("")
          }
        </div>
      </div>
      <div class="card">
        <div class="label">Config (from API)</div>
        <pre class="config-pre">${escapeHtml(configJson)}</pre>
      </div>
      ${cliBlock("clearance doctor --json")}
    `;
    wireCopyButtons(host);
  } catch (e) {
    host.innerHTML = stateError(
      `Failed to load settings: ${e.message}`,
      "clearance doctor --json",
    );
    wireCopyButtons(host);
  }
}

// ---------------------------------------------------------------------------
// Boot: session-gated. Unauthenticated → login view; authenticated → surfaces.
// ---------------------------------------------------------------------------
function bootAuthenticated() {
  const path = location.pathname.replace(/^\//, "") || "overview";
  const routeName = routes[path] ? path : "overview";
  const orgParam = new URLSearchParams(location.search).get("org");
  setRoute(routeName, orgParam ? { org: orgParam } : undefined);
  refreshHealth();
  refreshConsoleConfig();
}

async function boot() {
  const session = await ensureOperatorSession();
  if (!session) {
    showLogin();
    return;
  }
  showApp(session);
  bootAuthenticated();
}

boot();
setInterval(refreshHealth, 15000);

// Export helpers for behavioral tests when loaded under node with jsdom-less source analysis.
// (Browser ignores this; node tests read the source.)
if (typeof globalThis !== "undefined") {
  globalThis.__clearanceConsole = {
    escapeHtml,
    escapeAttr,
    routes: Object.keys(routes),
    parsePermissionsText,
    formatApiError,
    canMutate,
    sanitizeSessionForUi,
    confirmDestructive,
  };
}
