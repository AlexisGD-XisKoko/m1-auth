// Panel de administración de M1 (PM-02 a PM-05). Sin dependencias ni build.
// El access token vive SOLO en memoria: al recargar la página hay que volver a entrar.
"use strict";

const state = { token: null, refresh: null, me: null };
const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
  return node; // textContent siempre: nada de innerHTML con datos del servidor (XSS)
}

function toast(msg, isError = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isError ? " error-bg" : "");
  setTimeout(() => t.classList.add("hidden"), 3500);
}

async function api(path, { method = "GET", body, query } = {}) {
  const url = new URL(path, location.origin);
  if (query) Object.entries(query).forEach(([k, v]) => v !== "" && v != null && url.searchParams.set(k, v));
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && state.token) logout(true);
    throw new Error(data.detail || `Error ${res.status}`);
  }
  return data;
}

function decodeJwt(token) {
  const part = (p) => JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/")));
  const [h, p] = token.split(".");
  return { header: part(h), claims: part(p) };
}

const fmt = (iso) => (iso ? new Date(iso).toISOString().replace("T", " ").slice(0, 19) : "—");
const badge = (txt) => el("span", { class: `badge b-${String(txt).toLowerCase()}` }, txt);

function confirmDialog(text, withReason = false) {
  return new Promise((resolve) => {
    const dlg = $("#confirm");
    $("#confirm-text").textContent = text;
    $("#reason-wrap").classList.toggle("hidden", !withReason);
    dlg.onclose = () => resolve(dlg.returnValue === "ok" ? $("#reason").value : null);
    dlg.showModal();
  });
}

// --- Sesión -----------------------------------------------------------------------------
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  const form = new FormData(e.target);
  try {
    const tokens = await api("/auth/login", {
      method: "POST",
      body: { email: form.get("email"), password: form.get("password") },
    });
    state.token = tokens.access_token;
    state.refresh = tokens.refresh_token;
    state.me = await api("/auth/me");
    if (state.me.role !== "admin") {
      state.token = null;
      throw new Error("Esta cuenta no tiene rol admin.");
    }
    e.target.reset();
    showApp();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
});

async function logout(expired = false) {
  try {
    if (state.token && state.refresh && !expired) {
      await api("/auth/logout", { method: "POST", body: { refresh_token: state.refresh } });
    }
  } catch (_) { /* ignorar */ }
  Object.assign(state, { token: null, refresh: null, me: null });
  $("#app-view").classList.add("hidden");
  $("#session").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  if (expired) toast("La sesión expiró; vuelve a iniciar sesión.", true);
}
$("#logout").addEventListener("click", () => logout());

function showApp() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  $("#session").classList.remove("hidden");
  $("#whoami").textContent = `${state.me.nombre} · ${state.me.email}`;
  const { header, claims } = decodeJwt(state.token);
  const box = $("#token-info");
  box.replaceChildren(
    el("b", {}, "JWT de la sesión "),
    el("code", {}, `alg=${header.alg}`), " ",
    el("code", {}, `kid=${header.kid}`), " ",
    el("code", {}, `role=${claims.role}`), " ",
    el("code", {}, `idh=${claims.idh.slice(0, 16)}…`), " ",
    el("span", { class: "muted" }, `expira ${new Date(claims.exp * 1000).toLocaleTimeString()}`),
  );
  loadUsers();
}

// --- Pestañas -----------------------------------------------------------------------------
const loaders = { users: loadUsers, enroll: () => {}, certs: loadCerts, devices: loadDevices, audit: loadAudit };
document.querySelectorAll(".tabs button").forEach((btn) =>
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("hidden", t.id !== `tab-${btn.dataset.tab}`));
    loaders[btn.dataset.tab]();
  }),
);

function emptyRow(tbody, cols, text) {
  tbody.replaceChildren(el("tr", {}, el("td", { colspan: String(cols), class: "empty" }, text)));
}

// --- Usuarios (PM-03) -------------------------------------------------------------------------
async function loadUsers() {
  const tbody = $("#users-body");
  try {
    const data = await api("/admin/users", { query: { q: $("#user-q").value, role: $("#user-role").value } });
    if (!data.items.length) return emptyRow(tbody, 6, "Sin usuarios que coincidan.");
    tbody.replaceChildren(...data.items.map((u) => {
      const roleSel = el("select", {}, ...["buyer", "staff", "admin"].map((r) => {
        const o = el("option", {}, r);
        if (r === u.role) o.selected = true;
        return o;
      }));
      roleSel.addEventListener("change", async () => {
        try { await api(`/admin/users/${u.id}`, { method: "PATCH", body: { role: roleSel.value } }); toast("Rol actualizado"); }
        catch (err) { toast(err.message, true); roleSel.value = u.role; }
      });
      const toggle = u.status === "ACTIVE"
        ? el("button", { class: "ghost danger", onclick: () => setStatus(u, "DEACTIVATED") }, "Desactivar")
        : el("button", { class: "ghost", onclick: () => setStatus(u, "ACTIVE") }, u.status === "LOCKED" ? "Desbloquear" : "Activar");
      return el("tr", {}, el("td", {}, u.nombre), el("td", {}, u.email), el("td", {}, roleSel),
        el("td", {}, badge(u.status)), el("td", {}, String(u.failed_attempts)), el("td", {}, toggle));
    }));
  } catch (err) { emptyRow(tbody, 6, err.message); }
}
async function setStatus(u, status) {
  if (status === "DEACTIVATED" && !(await confirmDialog(`¿Desactivar a ${u.email}? Se revocan sus sesiones.`))) return;
  try { await api(`/admin/users/${u.id}`, { method: "PATCH", body: { status } }); toast("Estado actualizado"); loadUsers(); }
  catch (err) { toast(err.message, true); }
}
$("#user-search").addEventListener("click", loadUsers);
$("#user-create").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  try { await api("/admin/users", { method: "POST", body: f }); e.target.reset(); toast("Usuario creado"); loadUsers(); }
  catch (err) { toast(err.message, true); }
});

// --- Enrolamiento (PM-04) ------------------------------------------------------------------------
$("#enroll-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  try {
    const r = await api("/devices/enrollment-codes", { method: "POST", body: f });
    const box = $("#enroll-result");
    const code = el("code", { class: "big" }, r.enrollment_code);
    box.replaceChildren(
      el("p", {}, `Código para «${r.device_name}». Se muestra UNA sola vez; vence ${fmt(r.expires_at)} UTC.`),
      code,
      el("button", { class: "ghost", onclick: () => navigator.clipboard.writeText(r.enrollment_code).then(() => toast("Copiado")) }, "Copiar"),
    );
    box.classList.remove("hidden");
    e.target.reset();
  } catch (err) { toast(err.message, true); }
});

// --- Certificados (PM-04) -------------------------------------------------------------------------
async function loadCerts() {
  const tbody = $("#certs-body");
  try {
    const rows = await api("/pki/certificates", { query: { profile: $("#cert-profile").value, status: $("#cert-status").value } });
    if (!rows.length) return emptyRow(tbody, 6, "Aún no hay certificados emitidos.");
    tbody.replaceChildren(...rows.map((c) => el("tr", {},
      el("td", {}, el("code", {}, c.serial.slice(0, 16) + "…")), el("td", {}, c.subject), el("td", {}, c.profile),
      el("td", {}, fmt(c.not_after)), el("td", {}, badge(c.status)),
      el("td", {}, c.status === "VALID" ? el("button", { class: "ghost danger", onclick: () => revokeCert(c) }, "Revocar") : c.reason || ""),
    )));
  } catch (err) { emptyRow(tbody, 6, err.message); }
}
async function revokeCert(c) {
  const reason = await confirmDialog(`¿Revocar el certificado ${c.serial.slice(0, 16)}…? Aparecerá en la CRL.`, true);
  if (!reason) return;
  try { await api("/pki/revoke", { method: "POST", body: { serial_number: c.serial, reason } }); toast("Certificado revocado"); loadCerts(); }
  catch (err) { toast(err.message, true); }
}
$("#cert-search").addEventListener("click", loadCerts);

// --- Dispositivos -----------------------------------------------------------------------------------
async function loadDevices() {
  const tbody = $("#devices-body");
  try {
    const rows = await api("/devices");
    if (!rows.length) return emptyRow(tbody, 5, "Ningún escáner enrolado todavía.");
    tbody.replaceChildren(...rows.map((d) => el("tr", {},
      el("td", {}, d.nombre), el("td", {}, el("code", {}, (d.cert_serial || "—").slice(0, 16))),
      el("td", {}, fmt(d.enrolled_at)), el("td", {}, badge(d.status)),
      el("td", {}, d.status === "ACTIVE" ? el("button", { class: "ghost danger", onclick: () => revokeDevice(d) }, "Desactivar") : ""),
    )));
  } catch (err) { emptyRow(tbody, 5, err.message); }
}
async function revokeDevice(d) {
  if (!(await confirmDialog(`¿Desactivar «${d.nombre}»? Su certificado se revoca.`))) return;
  try { await api(`/devices/${d.id}/revoke`, { method: "POST" }); toast("Dispositivo desactivado"); loadDevices(); }
  catch (err) { toast(err.message, true); }
}

// --- Bitácora (PM-05) ---------------------------------------------------------------------------------
async function loadAudit() {
  const tbody = $("#audit-body");
  const since = $("#audit-since").value;
  try {
    const data = await api("/admin/audit", { query: { action: $("#audit-action").value, since: since ? `${since}T00:00:00Z` : "" } });
    if (!data.items.length) return emptyRow(tbody, 7, "Sin eventos para ese filtro.");
    tbody.replaceChildren(...data.items.map((a) => el("tr", {},
      el("td", {}, String(a.id)), el("td", {}, fmt(a.timestamp)), el("td", {}, el("code", {}, a.action)),
      el("td", {}, a.actor.slice(0, 36)), el("td", {}, (a.target || "").slice(0, 40)), el("td", {}, a.ip_address || ""),
      el("td", {}, a.tsa_token ? "✓" : ""),
    )));
  } catch (err) { emptyRow(tbody, 7, err.message); }
}
$("#audit-search").addEventListener("click", loadAudit);
$("#rotate-key").addEventListener("click", async () => {
  if (!(await confirmDialog("¿Rotar la llave de firma JWT? La anterior sigue publicada en el JWKS durante la transición."))) return;
  try { const r = await api("/admin/signing-keys/rotate", { method: "POST" }); toast(`Nueva llave: ${r.new_kid}`); loadAudit(); }
  catch (err) { toast(err.message, true); }
});
