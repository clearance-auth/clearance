const kind = location.pathname.endsWith("/scim") ? "scim" : "sso";
const params = new URLSearchParams(location.search);
const token = params.get("token") || "";
const organizationId = params.get("org") || "";
const form = document.getElementById("setup-form");
const result = document.getElementById("result");

document.getElementById("title").textContent = `${kind.toUpperCase()} setup`;
if (kind === "scim") document.getElementById("sso-fields").hidden = true;
const protocol = form.querySelector?.('select[name="protocol"]') ?? null;
const oidcFields = document.getElementById("oidc-fields");
const samlFields = document.getElementById("saml-fields");
function syncProtocolFields() {
  const saml = protocol?.value === "saml";
  if (oidcFields) oidcFields.hidden = saml;
  if (samlFields) samlFields.hidden = !saml;
}
protocol?.addEventListener("change", syncProtocolFields);
syncProtocolFields();
if (!token || !organizationId) {
  form.hidden = true;
  result.textContent = "This setup link is incomplete. Ask your administrator for a new link.";
}

function escapeText(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * SCIM one-time handoff: plaintext token and endpoint stay only in this page's
 * memory/DOM for the current response. Do not write the secret to durable
 * browser storage, cookies, the address bar, or re-request it later.
 */
function renderScimHandoff(handoff) {
  result.replaceChildren();
  const wrap = document.createElement("div");
  wrap.className = "setup-handoff";

  const ok = document.createElement("p");
  ok.className = "setup-success";
  ok.textContent = "SCIM connection saved successfully.";
  wrap.appendChild(ok);

  const warn = document.createElement("p");
  warn.className = "setup-warning";
  warn.setAttribute("role", "alert");
  warn.textContent =
    handoff.warning ||
    "Save and copy this SCIM bearer token and endpoint now. Clearance cannot show the token again.";
  wrap.appendChild(warn);

  function row(label, value, copyId) {
    const block = document.createElement("div");
    block.className = "setup-secret-row";
    const title = document.createElement("div");
    title.className = "setup-secret-label";
    title.textContent = label;
    const pre = document.createElement("code");
    pre.className = "setup-secret-value";
    pre.dataset.copyId = copyId;
    pre.textContent = value;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "setup-copy";
    btn.textContent = "Copy";
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(value);
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = "Copy";
        }, 1500);
      } catch {
        btn.textContent = "Select & copy manually";
      }
    });
    block.append(title, pre, btn);
    return block;
  }

  if (handoff.endpoint) {
    wrap.appendChild(row("SCIM endpoint (absolute)", handoff.endpoint, "endpoint"));
  }
  if (handoff.bearerToken) {
    wrap.appendChild(row("SCIM bearer token (one-time)", handoff.bearerToken, "token"));
  }

  result.appendChild(wrap);
}

function renderSsoSuccess() {
  result.replaceChildren();
  const ok = document.createElement("p");
  ok.className = "setup-success";
  ok.textContent = "SSO connection saved successfully.";
  result.appendChild(ok);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(form).entries());
  body.token = token;
  body.organizationId = organizationId;
  result.textContent = "Saving…";
  const response = await fetch(`/api/setup/${kind}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  // Drop capability token from the address bar immediately (never keep it in history).
  history.replaceState({}, "", location.pathname);
  if (!response.ok) {
    result.textContent =
      payload.error?.message || "Setup failed. Ask your administrator for a new link.";
    return;
  }
  form.hidden = true;
  if (kind === "scim" && payload.scimHandoff) {
    renderScimHandoff(payload.scimHandoff);
    return;
  }
  if (kind === "scim") {
    // Success without handoff payload — still clear, never invent a token.
    result.textContent =
      "SCIM connection saved successfully. If you did not see a bearer token, ask your administrator to issue a new setup link.";
    return;
  }
  renderSsoSuccess();
});

// Exported for console unit tests (no-op in browsers that ignore it).
if (typeof globalThis !== "undefined") {
  globalThis.__clearanceSetup = {
    kind,
    escapeText,
    renderScimHandoff,
    renderSsoSuccess,
  };
}
