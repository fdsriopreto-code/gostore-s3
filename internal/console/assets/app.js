"use strict";
/* gostore console — dependency-free SPA. Every S3/admin request is AWS SigV4
   signed in the browser with Web Crypto, same-origin with the API. */

const REGION = "us-east-1";
const te = new TextEncoder();

/* ============================ crypto / SigV4 ============================ */
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, typeof msg === "string" ? te.encode(msg) : msg));
}
const hx = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256hex = async (s) => hx(await crypto.subtle.digest("SHA-256", te.encode(s)));
async function signingKey(secret, ds) {
  let k = te.encode("AWS4" + secret);
  for (const p of [ds, REGION, "s3", "aws4_request"]) k = await hmac(k, p);
  return k;
}
const encC = (s) => encodeURIComponent(s).replace(/[!*'()]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
const encP = (p) => p.split("/").map(encC).join("/");
const canonQ = (q) => Object.keys(q).sort().map((k) => encC(k) + "=" + encC(q[k] ?? "")).join("&");

const session = {
  get ak() { return sessionStorage.getItem("gs_ak") || ""; },
  get sk() { return sessionStorage.getItem("gs_sk") || ""; },
  set(a, s) { sessionStorage.setItem("gs_ak", a); sessionStorage.setItem("gs_sk", s); },
  clear() { sessionStorage.clear(); },
};

async function sign(method, path, { query = {}, contentType, extraHeaders = {} } = {}) {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const ds = amzDate.slice(0, 8), host = location.host, ph = "UNSIGNED-PAYLOAD";
  const hdr = { "x-amz-date": amzDate, "x-amz-content-sha256": ph, ...extraHeaders };
  if (contentType) hdr["content-type"] = contentType;
  const signed = [...Object.keys(hdr).map((h) => h.toLowerCase()), "host"].sort();
  const ch = signed.map((h) => h + ":" + (h === "host" ? host : String(hdr[h]).trim()) + "\n").join("");
  const cr = [method, encP(path), canonQ(query), ch, signed.join(";"), ph].join("\n");
  const scope = `${ds}/${REGION}/s3/aws4_request`;
  const sts = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256hex(cr)].join("\n");
  const sig = hx(await hmac(await signingKey(session.sk, ds), sts));
  hdr["Authorization"] = `AWS4-HMAC-SHA256 Credential=${session.ak}/${scope}, SignedHeaders=${signed.join(";")}, Signature=${sig}`;
  const qs = canonQ(query);
  return { url: location.origin + encP(path) + (qs ? "?" + qs : ""), headers: hdr };
}
async function api(method, path, opts = {}) {
  const { url, headers } = await sign(method, path, opts);
  return fetch(url, { method, headers, body: opts.body });
}
// Files above this go up as a multipart upload: split into parts, several in
// flight at once, each part retried on failure, and the whole thing aborted
// server-side if it can't finish. Big videos/archives upload faster and a
// blip doesn't cost you the whole transfer.
const MPU_THRESHOLD = 16 * 1024 * 1024;
const MPU_PART = 8 * 1024 * 1024; // must be >= 5 MiB except the last part
const MPU_CONCURRENCY = 2;        // 2 x 8 MiB in flight per upload keeps server RAM modest

async function upload(path, file, onProgress) {
  if (file.size <= MPU_THRESHOLD) return uploadSingle(path, file, onProgress);
  return uploadMultipart(path, file, onProgress);
}

function uploadSingle(path, file, onProgress) {
  return new Promise(async (res, rej) => {
    const { url, headers } = await sign("PUT", "/" + path, { contentType: file.type || "application/octet-stream" });
    const x = new XMLHttpRequest();
    x.open("PUT", url);
    for (const [k, v] of Object.entries(headers)) x.setRequestHeader(k, v);
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    x.onload = () => (x.status < 300 ? res() : rej(new Error(exErr(x.responseText, x.status))));
    x.onerror = () => rej(new Error("network error"));
    x.send(file);
  });
}

function xhrSend(method, url, headers, body, onBytes) {
  return new Promise((res, rej) => {
    const x = new XMLHttpRequest();
    x.open(method, url);
    for (const [k, v] of Object.entries(headers)) x.setRequestHeader(k, v);
    if (onBytes) x.upload.onprogress = (e) => e.lengthComputable && onBytes(e.loaded);
    x.onload = () => (x.status < 300 ? res(x) : rej(new Error(exErr(x.responseText, x.status))));
    x.onerror = () => rej(new Error("network error"));
    x.send(body);
  });
}

async function uploadMultipart(path, file, onProgress) {
  const ct = file.type || "application/octet-stream";
  const initRes = await api("POST", "/" + path, { query: { uploads: "" }, contentType: ct });
  if (!initRes.ok) throw new Error(exErr(await initRes.text(), initRes.status));
  const uploadId = new DOMParser().parseFromString(await initRes.text(), "text/xml")
    .getElementsByTagName("UploadId")[0]?.textContent;
  if (!uploadId) throw new Error("server did not return an upload id");

  const nParts = Math.ceil(file.size / MPU_PART);
  const parts = new Array(nParts);
  const done = new Array(nParts).fill(0);
  const bump = () => onProgress(done.reduce((a, b) => a + b, 0) / file.size);

  try {
    let next = 0;
    const worker = async () => {
      for (;;) {
        const i = next++;
        if (i >= nParts) return;
        const start = i * MPU_PART, end = Math.min(start + MPU_PART, file.size);
        const blob = file.slice(start, end), pn = i + 1;
        for (let attempt = 1; ; attempt++) {
          try {
            const { url, headers } = await sign("PUT", "/" + path, { query: { partNumber: String(pn), uploadId } });
            const x = await xhrSend("PUT", url, headers, blob, (loaded) => { done[i] = loaded; bump(); });
            parts[i] = { n: pn, etag: (x.getResponseHeader("ETag") || "").replace(/"/g, "") };
            done[i] = end - start; bump();
            break;
          } catch (e) {
            if (attempt >= 3) throw e;
            await new Promise((r) => setTimeout(r, 400 * attempt));
          }
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(MPU_CONCURRENCY, nParts) }, worker));

    const body = "<CompleteMultipartUpload>" +
      parts.map((p) => `<Part><PartNumber>${p.n}</PartNumber><ETag>"${p.etag}"</ETag></Part>`).join("") +
      "</CompleteMultipartUpload>";
    const cRes = await api("POST", "/" + path, { query: { uploadId }, contentType: "application/xml", body });
    if (!cRes.ok) throw new Error(exErr(await cRes.text(), cRes.status));
  } catch (e) {
    try { await api("DELETE", "/" + path, { query: { uploadId } }); } catch (_) {}
    throw e;
  }
}
async function presignPut(path, expires = 3600) {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const ds = amzDate.slice(0, 8), scope = `${ds}/${REGION}/s3/aws4_request`;
  const q = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${session.ak}/${scope}`,
    "X-Amz-Date": amzDate, "X-Amz-Expires": String(expires), "X-Amz-SignedHeaders": "host",
  };
  const cr = ["PUT", encP("/" + path), canonQ(q), "host:" + location.host + "\n", "host", "UNSIGNED-PAYLOAD"].join("\n");
  const sts = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256hex(cr)].join("\n");
  q["X-Amz-Signature"] = hx(await hmac(await signingKey(session.sk, ds), sts));
  return location.origin + encP("/" + path) + "?" + canonQ(q);
}

async function presignGet(path, expires = 3600, extraQuery = {}) {
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const ds = amzDate.slice(0, 8), scope = `${ds}/${REGION}/s3/aws4_request`;
  const q = {
    ...extraQuery,
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${session.ak}/${scope}`,
    "X-Amz-Date": amzDate, "X-Amz-Expires": String(expires), "X-Amz-SignedHeaders": "host",
  };
  const cr = ["GET", encP("/" + path), canonQ(q), "host:" + location.host + "\n", "host", "UNSIGNED-PAYLOAD"].join("\n");
  const sts = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256hex(cr)].join("\n");
  q["X-Amz-Signature"] = hx(await hmac(await signingKey(session.sk, ds), sts));
  return location.origin + encP("/" + path) + "?" + canonQ(q);
}

/* ============================ dom helpers ============================ */
const $ = (s, r = document) => r.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null) continue;
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(c));
  return n;
};
const ic = (d) => {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("class", "i"); s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
  s.innerHTML = d; return s;
};
const ICON = {
  dash: '<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="5" rx="1.5"/><rect x="13" y="12" width="8" height="9" rx="1.5"/><rect x="3" y="15" width="8" height="6" rx="1.5"/>',
  bucket: '<path d="M5 8h14l-1.6 12.5A2 2 0 0 1 15.4 22H8.6a2 2 0 0 1-2-1.5L5 8z"/><path d="M8 8V6a4 4 0 0 1 8 0v2"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M17 6l2 2M15 8l2 2"/>',
  gauge: '<path d="M12 13 16 9"/><path d="M4.5 18a9 9 0 1 1 15 0"/><circle cx="12" cy="13" r="1.4" fill="currentColor"/>',
  book: '<path d="M4 5a2 2 0 0 1 2-2h12v16H6a2 2 0 0 0-2 2z"/><path d="M4 19a2 2 0 0 0 2 2h12"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
  up: '<path d="M12 19V5M5 12l7-7 7 7"/>', down: '<path d="M12 5v14M19 12l-7 7-7-7"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13M9 7V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>', copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
  link: '<path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>', refresh: '<path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5"/>',
  chev: '<path d="M9 6l6 6-6 6"/>', ext: '<path d="M14 4h6v6M20 4l-9 9M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/>',
  arrowLeft: '<path d="M19 12H5M12 19l-7-7 7-7"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  layers: '<path d="M12 3 2 8l10 5 10-5z"/><path d="M2 13l10 5 10-5M2 18l10 5 10-5"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', branch: '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="9" r="2.5"/><path d="M6 8.5v7M6 15.5A9 9 0 0 0 15 9"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>', term: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
  code: '<path d="M8 6l-6 6 6 6M16 6l6 6-6 6M13 4l-2 16"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>', gear: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.6-2-3.4-2.3 1a7 7 0 0 0-1.7-1L14.6 2h-5l-.6 2.5a7 7 0 0 0-1.7 1l-2.3-1-2 3.4L3 10.9a7 7 0 0 0 0 2.2L1 14.7l2 3.4 2.3-1a7 7 0 0 0 1.7 1L9.6 22h5l.6-2.5a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.6a7 7 0 0 0 .1-1.1z"/>',
};

function toast(msg, kind = "") {
  const t = el("div", { class: kind }, msg);
  $("#toast").append(t);
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 200); }, kind === "err" ? 6500 : 3200);
}
const fmtSize = (n) => {
  if (n == null || n === "") return "";
  n = Number(n); const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
};
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : "");
// fmtDuration turns a seconds count into a compact "2d 3h" / "5m" string.
const fmtDuration = (s) => {
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + "d " + h + "h";
  if (h > 0) return h + "h " + m + "m";
  if (m > 0) return m + "m";
  return s + "s";
};
// parseSize turns "2 GB" / "500mb" / "1073741824" into bytes (0 if blank/NaN).
function parseSize(s) {
  s = String(s || "").trim().toLowerCase();
  if (!s) return 0;
  const m = s.match(/^([\d.]+)\s*(b|kb|mb|gb|tb|kib|mib|gib|tib)?$/);
  if (!m) return NaN;
  const mul = { b: 1, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12, kib: 1024, mib: 1048576, gib: 1073741824, tib: 1099511627776 };
  return Math.round(parseFloat(m[1]) * (mul[m[2] || "b"] || 1));
}
const relTime = (s) => {
  if (!s) return "";
  const d = (Date.now() - new Date(s)) / 1000;
  if (d < 60) return "just now"; if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago"; if (d < 2592000) return Math.floor(d / 86400) + "d ago";
  return new Date(s).toLocaleDateString();
};
const parseXml = (s) => new DOMParser().parseFromString(s, "application/xml");
function exErr(body, status) {
  const m = (body || "").match(/<Message>([^<]+)<\/Message>/) || (body || "").match(/"error"\s*:\s*"([^"]+)"/);
  return m ? m[1] : `HTTP ${status}`;
}
async function must(resp) {
  if (!resp.ok && resp.status !== 204) throw new Error(exErr(await resp.text(), resp.status));
  return resp;
}
function copyText(t) { navigator.clipboard?.writeText(t).then(() => toast("Copied", "ok"), () => toast("Copy failed", "err")); }

/* ---------- code block with mini highlighter ---------- */
function hl(code, lang) {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const span = (c, t) => `<span class="tok-${c}">${t}</span>`;
  const s = esc(code);
  // Single pass per language: one regex with alternatives, one replace. Doing
  // it in one pass (instead of chained .replace calls) means the inserted
  // <span class="tok-*"> markup is never re-scanned, so a later rule can't
  // match inside an earlier rule's output (e.g. the flag rule matching the
  // "-k" in class="tok-k").
  if (lang === "json") {
    return s.replace(/("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+\.?\d*)/g,
      (m, str, colon, kw, num) =>
        str !== undefined ? (colon ? span("f", str) + colon : span("s", str))
        : kw !== undefined ? span("k", kw)
        : span("n", num));
  }
  if (lang === "xml") {
    return s.replace(/(&lt;\/?)([\w:-]+)|([\w:-]+)=(&quot;.*?&quot;|".*?")/g,
      (m, open, tag, attr, val) =>
        tag !== undefined ? open + span("f", tag)
        : span("n", attr) + "=" + span("s", val));
  }
  if (lang === "bash" || lang === "sh") {
    return s.replace(/(#[^\n]*)|('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")|\b(aws|mc|curl|export|gostore)\b|(--?[a-z][\w-]*)/g,
      (m, c, str, kw, flag) =>
        c !== undefined ? span("c", c)
        : str !== undefined ? span("s", str)
        : kw !== undefined ? span("k", kw)
        : span("n", flag));
  }
  return s.replace(/(\/\/[^\n]*|#[^\n]*)|('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`)|\b(const|let|var|func|import|from|return|new|async|await|package|type|struct|if|else|for|def|class|with|as)\b|\b([A-Z]\w+)\b/g,
    (m, c, str, kw, cap) =>
      c !== undefined ? span("c", c)
      : str !== undefined ? span("s", str)
      : kw !== undefined ? span("k", kw)
      : span("f", cap));
}
function codeBlock(code, lang = "bash", label) {
  const wrap = el("div", { class: "code" });
  const bar = el("div", { class: "bar" },
    el("span", { class: "lang" }, label || lang),
    el("button", { onclick: () => copyText(code) }, "Copy"));
  const pre = el("pre");
  pre.innerHTML = hl(code.trim(), lang);
  wrap.append(bar, pre);
  return wrap;
}
const callout = (title, body, kind = "") => el("div", { class: "callout " + kind }, title ? el("b", {}, title) : null, body);

/* ---------- modal ---------- */
function modal(title, hint, fields, onOK, okLabel = "Create") {
  const d = $("#modal"); d.innerHTML = "";
  d.append(el("h3", {}, title));
  if (hint) d.append(el("p", { class: "hint" }, hint));
  const inp = {};
  for (const f of fields) {
    d.append(el("label", { class: "field-label" }, f.label));
    let n;
    if (f.type === "select") { n = el("select"); for (const o of f.options) n.append(el("option", { value: o.value ?? o }, o.label ?? o)); n.value = f.value ?? ""; }
    else if (f.type === "textarea") n = el("textarea", {}, f.value ?? "");
    else n = el("input", { type: f.type === "password" ? "password" : "text", value: f.value ?? "", spellcheck: "false", readonly: f.readonly ? "" : null });
    inp[f.name] = n; d.append(n);
  }
  const btns = el("div", { class: "btns" });
  btns.append(el("button", { class: "ghost", onclick: () => d.close() }, "Cancel"));
  const ok = el("button", { class: "primary" }, okLabel);
  ok.onclick = async () => {
    const v = {}; for (const k in inp) v[k] = inp[k].value.trim();
    ok.disabled = true;
    try {
      // onOK may return false to keep the dialog open (e.g. it swapped in
      // its own content like the credentials reveal).
      const keepOpen = (await onOK(v)) === false;
      if (!keepOpen) d.close();
    } catch (e) { toast(e.message, "err"); ok.disabled = false; }
  };
  btns.append(ok); d.append(btns); d.showModal();
  setTimeout(() => d.querySelector("input,textarea,select")?.focus(), 30);
}

/* ---------- drawer ---------- */
function closeDrawer() { $("#drawer").classList.remove("on"); $("#scrim").classList.remove("on"); }
$("#scrim").onclick = closeDrawer;
addEventListener("keydown", (e) => {
  if (e.key === "Escape") { closeDrawer(); return; }
  // "/" focuses the folder filter when not already typing somewhere.
  const tag = (e.target.tagName || "").toLowerCase();
  if (e.key === "/" && tag !== "input" && tag !== "textarea") {
    const f = document.querySelector("#view .search input");
    if (f) { e.preventDefault(); f.focus(); }
  }
});
function openDrawer(build) { const d = $("#drawer"); d.innerHTML = ""; build(d); d.classList.add("on"); $("#scrim").classList.add("on"); }

/* ============================ routing ============================ */
const NAV = [
  { group: "", items: [
    { id: "dashboard", title: "Dashboard", icon: ICON.dash },
    { id: "buckets", title: "Buckets", icon: ICON.bucket },
    { id: "keys", title: "Access Keys", icon: ICON.key },
    { id: "monitoring", title: "Monitoring", icon: ICON.gauge },
    { id: "docs", title: "Documentation", icon: ICON.book },
  ]},
];
let SERVER = {}; // filled from admin/v1/info

function route() { return (location.hash.replace(/^#\/?/, "") || "dashboard"); }
function go(r) { location.hash = "#/" + r; }

function renderNav() {
  const box = $("#navlinks"); box.innerHTML = "";
  const cur = route();
  for (const g of NAV) {
    if (g.group) box.append(el("div", { class: "grp" }, g.group));
    for (const it of g.items) {
      const on = it.id === "dashboard" ? cur === "dashboard"
        : it.id === "docs" ? cur.startsWith("docs")
        : cur === it.id || cur.startsWith(it.id + "/");
      const a = el("a", { class: on ? "active" : "" }, ic(it.icon), it.title);
      a.onclick = () => go(it.id);
      box.append(a);
    }
  }
}

const DOC_GROUPS = ["Get started", "Access control", "Data management", "Reference", "Operations"];

let lastConsoleRoute = "dashboard";

let pollTimers = [];
function stopPolls() { pollTimers.forEach(clearInterval); pollTimers = []; }

// renderSeq guards against overlapping renders: a view that awaits can check
// that it is still the current render before appending, so two renders racing
// (e.g. a hashchange during an in-flight render) never double-append.
let renderSeq = 0;

async function render() {
  ++renderSeq;
  if (thumbObs) { thumbObs.disconnect(); thumbObs = null; }
  stopPolls();
  renderNav();
  $("#sidenav").classList.remove("open");
  const v = $("#view");
  v.innerHTML = ""; v.className = "wrap";
  v.append(el("div", { class: "empty" }, el("span", { class: "spin" })));
  const r = route();
  // Reading mode: a doc page hides the app sidebar and shows a back arrow.
  const reading = r === "docs" || r.startsWith("docs/");
  $("#app").classList.toggle("reading", reading);
  if (!reading) lastConsoleRoute = r;
  try {
    if (r === "dashboard") await viewDashboard(v);
    else if (r === "buckets") await viewBuckets(v);
    else if (r.startsWith("buckets/")) await viewBucket(v, decodeURIComponent(r.slice(8)));
    else if (r === "keys") await viewKeys(v);
    else if (r === "monitoring") await viewMonitoring(v);
    else if (r === "docs" || r.startsWith("docs/")) viewDocs(v, r.startsWith("docs/") ? r.slice(5) : DOCS[0].id);
    else viewDocs(v, DOCS[0].id);
  } catch (e) {
    v.innerHTML = "";
    v.append(el("div", { class: "empty" }, ic(ICON.info), el("h3", {}, "Something went wrong"), el("div", { class: "muted" }, e.message)));
    toast(e.message, "err");
  }
}
addEventListener("hashchange", render);

function pageHeader(v, title, desc, actions) {
  v.innerHTML = "";
  const h = el("div", { class: "pageh" }, el("div", {}, el("h2", {}, title), desc ? el("div", { class: "desc" }, desc) : null));
  if (actions) h.append(el("div", { class: "actions" }, ...actions));
  v.append(h);
}

/* ============================ views ============================ */
async function viewDashboard(v) {
  const seq = renderSeq;
  let info = {};
  try { info = await (await api("GET", "/gostore/admin/v1/info")).json(); } catch {}
  if (seq !== renderSeq) return; // a newer render superseded us
  SERVER = info;
  pageHeader(v, "Dashboard", "Overview of your gostore deployment.");

  const hero = el("div", { class: "hero" },
    el("h3", {}, ic(ICON.term), "Your S3 endpoint"),
    el("div", { class: "kvbig" },
      kvRow("Endpoint", location.origin, true),
      kvRow("Region", info.region || REGION, true),
      kvRow("Addressing", "path-style (required)", false),
      kvRow("Signature", "AWS Signature V4", false),
      kvRow("Access key", session.ak, true)));
  v.append(hero);

  // Disk usage bar: used vs free across the deployment's drives.
  if (info.totalSpace && info.freeSpace != null) {
    const total = info.totalSpace, free = info.freeSpace, used = Math.max(0, total - free);
    const pct = total > 0 ? Math.round((used / total) * 100) : 0;
    const cls = pct >= 90 ? "crit" : pct >= 75 ? "warn" : "";
    v.append(el("div", { class: "cap" },
      el("div", { class: "caph" }, ic(ICON.gauge), el("span", { class: "t" }, "Disk usage"),
        el("span", { class: "pct" }, pct + "%")),
      el("div", { class: "track" }, el("span", { class: cls, style: "width:" + pct + "%" })),
      el("div", { class: "lbl" },
        el("span", { html: "<b>" + fmtSize(used) + "</b> used" }),
        el("span", { html: "<b>" + fmtSize(free) + "</b> free of " + fmtSize(total) }))));
  }

  const tiles = el("div", { class: "grid stat-tiles" });
  const tile = (k, val, icon) => tiles.append(el("div", { class: "tile" },
    el("div", { class: "k" }, ic(icon), k), el("div", { class: "v", html: val })));
  tile("Mode", info.mode || "—", ICON.layers);
  tile("Drives", (info.drives ?? "—") + "", ICON.gauge);
  tile("Total space", fmtSize(info.totalSpace) || "—", ICON.bucket);
  tile("Free space", fmtSize(info.freeSpace) || "—", ICON.bucket);
  tile("Access keys", (info.users ?? "—") + (info.serviceAccounts ? " + " + info.serviceAccounts + " svc" : ""), ICON.key);
  tile("Policies", (info.policies ?? "—") + "", ICON.shield);
  if (info.dataInitialized) tile("Storage initialized", relTime(info.dataInitialized), ICON.clock);
  v.append(tiles);

  // Live activity metrics (observability) — read-only, auto-refreshing every
  // 5s via the shared poll timers (stopPolls() clears them on navigation).
  try {
    const mx = await (await api("GET", "/gostore/admin/v1/metrics")).json();
    if (seq !== renderSeq) return;
    v.append(el("h3", { style: "margin:26px 0 8px;font-size:15px" }, "Activity"));
    const mrow = el("div", { class: "mrow" });
    const cells = {};
    const cell = (id, k) => {
      const mv = el("div", { class: "mv" });
      cells[id] = mv;
      mrow.append(el("div", { class: "mcell" }, el("div", { class: "mk" }, k), mv));
    };
    cell("req", "Requests"); cell("avg", "Avg latency"); cell("p95", "p95 latency");
    cell("in", "Data in"); cell("out", "Data out"); cell("err", "Errors");
    cell("up", "Uptime"); cell("gr", "Goroutines");
    const fill = (m) => {
      cells.req.textContent = (m.requests || 0).toLocaleString();
      cells.avg.innerHTML = (m.avgLatencyMs || 0).toFixed(1) + " <small>ms</small>";
      cells.p95.innerHTML = (m.p95Ms || 0).toFixed(0) + " <small>ms</small>";
      cells.in.textContent = fmtSize(m.bytesIn || 0);
      cells.out.textContent = fmtSize(m.bytesOut || 0);
      cells.err.textContent = (m.errors || 0).toLocaleString();
      cells.up.textContent = fmtDuration(m.uptimeSeconds || 0);
      cells.gr.textContent = (m.goroutines || 0).toLocaleString();
    };
    fill(mx);
    v.append(mrow);
    pollTimers.push(setInterval(async () => {
      try {
        const m = await (await api("GET", "/gostore/admin/v1/metrics")).json();
        if (seq === renderSeq) fill(m);
      } catch {}
    }, 5000));
  } catch {}

  // Storage by bucket — relative bars from the scanner's accounting.
  try {
    const du = await (await api("GET", "/gostore/admin/v1/datausage")).json();
    if (seq !== renderSeq) return;
    const bs = Object.entries(du.buckets || {})
      .map(([n, u]) => ({ n, bytes: u.bytes || 0, objects: u.objects || 0 }))
      .filter((b) => b.bytes > 0).sort((a, b) => b.bytes - a.bytes).slice(0, 8);
    if (bs.length) {
      v.append(el("h3", { style: "margin:26px 0 8px;font-size:15px" }, "Storage by bucket"));
      const max = bs[0].bytes || 1;
      v.append(el("div", { class: "card pad" }, el("div", { class: "usebars" },
        ...bs.map((b) => el("div", { class: "ub" },
          el("div", { class: "ubn" }, b.n),
          el("div", { class: "ubt" }, el("span", { style: "width:" + Math.max(3, Math.round(b.bytes / max * 100)) + "%" })),
          el("div", { class: "ubv" }, fmtSize(b.bytes) + " · " + b.objects.toLocaleString()))))));
    }
  } catch {}

  if (info.volumeWasEmptyAtBoot) {
    v.append(el("div", { class: "callout warn", style: "margin-top:16px" },
      el("b", {}, "This volume was empty when gostore started"),
      el("span", { html:
        "If this is your first run, ignore it. But if buckets or access keys keep disappearing after a restart/redeploy, "
        + "the data directory <code>" + (info.dataDir || "/data") + "</code> is <b>not persistent</b>. Everything "
        + "(objects, metadata, IAM) lives there — there is no external database. "
        + "<b>Fix:</b> in your PaaS/Docker config add a <b>persistent volume mount</b> at <code>"
        + (info.dataDir || "/data") + "</code> and keep that same volume across deploys. "
        + "Check the live state any time at <code>" + location.origin + "/gostore/health/persistence</code>." })));
  }

  v.append(el("h3", { style: "margin:26px 0 4px;font-size:15px" }, "Quick start"));
  v.append(el("p", { class: "muted small" }, "Point the AWS CLI at this endpoint and you're storing objects:"));
  v.append(codeBlock(
`aws configure set aws_access_key_id ${session.ak}
aws configure set aws_secret_access_key <YOUR_SECRET_KEY>
aws configure set default.region ${info.region || REGION}
aws configure set default.s3.addressing_style path

aws --endpoint-url ${location.origin} s3 mb s3://my-first-bucket
aws --endpoint-url ${location.origin} s3 cp ./file.zip s3://my-first-bucket/
aws --endpoint-url ${location.origin} s3 ls s3://my-first-bucket`, "bash", "shell"));
  v.append(el("p", { class: "small" }, "Full SDK guides are under ", el("a", { onclick: () => go("docs/connect") }, "Documentation"), "."));
}
function kvRow(k, val, copyable) {
  return [el("span", { class: "k" }, k),
    el("span", { class: "v" }, el("code", {}, val || "—"),
      copyable && val ? el("button", { class: "ghost iconbtn", onclick: () => copyText(val), title: "Copy" }, ic(ICON.copy)) : null)];
}

async function viewBuckets(v) {
  const doc = parseXml(await (await must(await api("GET", "/"))).text());
  const names = [...doc.getElementsByTagName("Name")].map((n) => n.textContent);
  const dates = [...doc.getElementsByTagName("CreationDate")].map((n) => n.textContent);
  pageHeader(v, "Buckets", names.length + (names.length === 1 ? " bucket" : " buckets"), [
    el("button", { class: "ghost", onclick: render }, ic(ICON.refresh), "Refresh"),
    el("button", { class: "primary", onclick: () => modal("Create bucket", "3–63 chars · lowercase letters, digits, - and .",
      [{ name: "name", label: "Bucket name" },
       { name: "lock", label: "Object Lock", type: "select", options: [{ label: "Disabled", value: "" }, { label: "Enabled (implies versioning)", value: "1" }] }],
      async (val) => {
        const h = val.lock ? { "x-amz-bucket-object-lock-enabled": "true" } : {};
        await must(await api("PUT", "/" + val.name, { extraHeaders: h })); toast("Bucket created", "ok"); render();
      }) }, ic(ICON.plus), "Create bucket"),
  ]);
  if (!names.length) { v.append(emptyState(ICON.bucket, "No buckets yet", "Create one to start storing objects.")); return; }

  // Per-bucket usage (objects + size) from the scanner's accounting pass —
  // best-effort: needs admin, and is blank until the first scan.
  let usage = {};
  try {
    const du = await (await api("GET", "/gostore/admin/v1/datausage")).json();
    if (du && du.buckets) usage = du.buckets;
  } catch {}

  const tb = el("tbody");
  names.forEach((n, i) => {
    const u = usage[n];
    tb.append(el("tr", { class: "clk", onclick: () => go("buckets/" + encodeURIComponent(n)) },
      el("td", {}, el("div", { class: "nm folder" }, ic(ICON.bucket), el("span", {}, n))),
      el("td", { class: "num" }, u ? (u.objects ?? 0).toLocaleString() : "—"),
      el("td", { class: "num" }, u ? fmtSize(u.bytes || 0) : "—"),
      el("td", { class: "muted" }, relTime(dates[i])),
      el("td", { class: "act" }, el("button", { class: "danger sm", onclick: async (e) => {
        e.stopPropagation();
        if (!confirm(`Delete bucket "${n}"?  It must be empty.`)) return;
        try { await must(await api("DELETE", "/" + n)); toast("Deleted", "ok"); render(); } catch (err) { toast(err.message, "err"); }
      } }, ic(ICON.trash), "Delete"))));
  });
  v.append(el("div", { class: "card" }, el("table", {}, el("thead", {}, el("tr", {},
    el("th", {}, "Name"), el("th", { class: "num" }, "Objects"), el("th", { class: "num" }, "Size"),
    el("th", {}, "Created"), el("th", {}))), tb)));
}
const emptyState = (icon, h, sub) => el("div", { class: "empty" }, ic(icon), el("h3", {}, h), el("div", { class: "muted" }, sub));

let bucketTab = "objects";
async function viewBucket(v, b) {
  pageHeader(v, b, null, [
    el("button", { class: bucketTab === "objects" ? "primary" : "ghost", onclick: () => { bucketTab = "objects"; render(); } }, "Objects"),
    el("button", { class: bucketTab === "settings" ? "primary" : "ghost", onclick: () => { bucketTab = "settings"; render(); } }, ic(ICON.gear), "Settings"),
  ]);
  v.append(el("div", { class: "crumbs" },
    linkEl("Buckets", () => go("buckets")), el("span", { class: "sep" }, "/"),
    linkEl(b, () => { bucketPrefix = ""; render(); })));
  if (bucketTab === "settings") return bucketSettings(v, b);
  await bucketObjects(v, b);
}
const linkEl = (t, fn) => { const a = el("a", {}, t); a.onclick = fn; return a; };

// Lazy image thumbnails in the object listing: the server renders a small
// JPEG via GET /bucket/key?preview; an IntersectionObserver only asks for the
// ones that scroll into view.
const THUMB_EXT = new Set(["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp"]);
let thumbObs = null;
function nameCell(bucket, key, nm) {
  const ext = (nm.split(".").pop() || "").toLowerCase();
  if (!THUMB_EXT.has(ext)) return el("div", { class: "nm" }, ic(ICON.file), el("span", {}, nm));
  const holder = el("span", { class: "thumb" }, ic(ICON.file));
  holder.dataset.bucket = bucket; holder.dataset.key = key;
  if (!thumbObs) {
    thumbObs = new IntersectionObserver((ents) => {
      for (const e of ents) {
        if (!e.isIntersecting) continue;
        const h = e.target; thumbObs.unobserve(h);
        presignGet(h.dataset.bucket + "/" + h.dataset.key, 600, { preview: "64" }).then((u) => {
          const img = new Image();
          img.onload = () => { h.innerHTML = ""; h.append(img); };
          img.src = u;
        }).catch(() => {});
      }
    }, { rootMargin: "300px" });
  }
  thumbObs.observe(holder);
  return el("div", { class: "nm" }, holder, el("span", {}, nm));
}

let bucketPrefix = "";
let objSort = { col: "name", dir: 1 }; // dir: 1 asc, -1 desc
async function bucketObjects(v, b) {
  const fi = el("input", { type: "file", multiple: "true", style: "display:none" });
  fi.onchange = () => doUpload(b, [...fi.files].map((f) => ({ file: f, path: f.name })));
  const fd = el("input", { type: "file", multiple: "true", style: "display:none" });
  fd.webkitdirectory = true;
  fd.onchange = () => doUpload(b, [...fd.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
  const sInput = el("input", {
    placeholder: "Filter this folder — press Enter to search the whole bucket",
    oninput: (e) => filterRows(e.target.value),
    onkeydown: (e) => { if (e.key === "Enter" && e.target.value.trim()) bucketSearch(b, e.target.value.trim()); },
  });
  const tb = el("div", { class: "toolbar" },
    el("div", { class: "search" }, ic(ICON.search), sInput),
    el("button", { class: "ghost", onclick: render }, ic(ICON.refresh)),
    el("button", { class: "ghost", onclick: () => folderStats(b, bucketPrefix) }, ic(ICON.gauge), "Folder stats"),
    el("div", { class: "grow" }),
    el("button", { class: "ghost", onclick: async () => {
      const k = prompt("Key for the upload link (relative to this folder):", "");
      if (!k) return;
      const full = bucketPrefix + k;
      const url = await presignPut(b + "/" + full, 3600);
      modal("Upload link — valid 1 hour", "Anyone with this URL can upload to " + b + "/" + full + " with a single PUT.", [
        { name: "u", label: "Presigned PUT URL", value: url, readonly: true },
        { name: "c", label: "Example", value: `curl -T ./file '${url}'`, readonly: true },
      ], async () => {}, "Done");
    } }, ic(ICON.link), "Upload link"),
    el("button", { class: "ghost", onclick: () => newFolder(b) }, ic(ICON.folder), "New folder"),
    el("button", { class: "ghost", onclick: () => fd.click() }, ic(ICON.folder), "Upload folder"), fd,
    el("button", { class: "primary", onclick: () => fi.click() }, ic(ICON.up), "Upload"), fi);
  v.append(tb);
  const drop = el("div", { id: "drop" });
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("hot"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("hot"); }));
  drop.addEventListener("drop", (e) => { e.preventDefault(); doUpload(b, dropEntries(e.dataTransfer)); });
  drop.append(el("div", { id: "uplist" }));
  v.append(drop);

  if (bucketPrefix) {
    const parts = bucketPrefix.split("/").filter(Boolean);
    const cr = el("div", { class: "crumbs" }, linkEl("· root", () => { bucketPrefix = ""; render(); }));
    let acc = "";
    for (const seg of parts) { acc += seg + "/"; const a = acc; cr.append(el("span", { class: "sep" }, "/"), linkEl(seg, () => { bucketPrefix = a; render(); })); }
    v.append(cr);
  }

  const res = await must(await api("GET", "/" + b, { query: { "list-type": "2", delimiter: "/", prefix: bucketPrefix, "max-keys": "1000" } }));
  const doc = parseXml(await res.text());
  const prefixes = [...doc.getElementsByTagName("CommonPrefixes")].map((n) => n.getElementsByTagName("Prefix")[0].textContent);
  const objs = [...doc.getElementsByTagName("Contents")].map((c) => ({
    key: c.getElementsByTagName("Key")[0].textContent,
    size: c.getElementsByTagName("Size")[0]?.textContent,
    lm: c.getElementsByTagName("LastModified")[0]?.textContent,
    etag: (c.getElementsByTagName("ETag")[0]?.textContent || "").replace(/"/g, ""),
  })).filter((o) => o.key !== bucketPrefix);

  if (!prefixes.length && !objs.length) { v.append(emptyState(ICON.folder, "Empty folder", "Drag files here or use Upload.")); return; }
  const skey = objSort.col === "modified" ? (o) => o.lm || "" : objSort.col === "size" ? (o) => +o.size || 0 : (o) => o.key.toLowerCase();
  objs.sort((a, c) => { const x = skey(a), y = skey(c); return (x < y ? -1 : x > y ? 1 : 0) * objSort.dir; });
  const sortableTh = (label, col, cls) => {
    const active = objSort.col === col;
    return el("th", { class: (cls || "") + " sorth" + (active ? " on" : ""), onclick: () => { objSort = { col, dir: active ? -objSort.dir : 1 }; render(); } },
      label, active ? el("span", { class: "sarrow" }, objSort.dir > 0 ? " ▲" : " ▼") : null);
  };
  const tbody = el("tbody");
  const selAll = el("input", { type: "checkbox" });
  selAll.onchange = () => { tbody.querySelectorAll(".rc").forEach((c) => { c.checked = selAll.checked; }); syncBulk(); };
  if (bucketPrefix) {
    const parent = bucketPrefix.replace(/[^/]+\/$/, "");
    tbody.append(el("tr", { class: "clk", onclick: () => { bucketPrefix = parent; render(); } },
      el("td", {}), el("td", {}, el("div", { class: "nm folder" }, ic(ICON.up), el("span", {}, ".."))), el("td", {}), el("td", {}), el("td", {})));
  }
  const folderRows = {};
  for (const p of prefixes) {
    const sizeCell = el("td", { class: "num muted small" }, "");
    folderRows[p.slice(bucketPrefix.length)] = sizeCell;
    tbody.append(el("tr", { class: "clk", onclick: () => { bucketPrefix = p; render(); } },
      el("td", {}), el("td", {}, el("div", { class: "nm folder" }, ic(ICON.folder), el("span", {}, p.slice(bucketPrefix.length)))),
      el("td", { class: "muted" }, ""), sizeCell, el("td", {})));
  }
  // Recursive per-folder usage from the last background scan (async, best-effort).
  if (prefixes.length) (async () => {
    try {
      const du = await (await api("GET", "/gostore/admin/v1/du", { query: { bucket: b, prefix: bucketPrefix } })).json();
      for (const [name, cell] of Object.entries(folderRows)) {
        const u = (du.folders || {})[name];
        if (u) { cell.textContent = fmtSize(u.bytes) + " · " + u.objects; cell.title = "recursive size · object count (from the last scan)"; }
      }
    } catch {}
  })();
  for (const o of objs) {
    const nm = o.key.slice(bucketPrefix.length);
    const chk = el("input", { type: "checkbox", class: "rc", onclick: (e) => e.stopPropagation(), onchange: syncBulk });
    chk.dataset.key = o.key;
    tbody.append(el("tr", { class: "clk", "data-name": nm.toLowerCase(), onclick: () => objectDrawer(b, o) },
      el("td", {}, chk),
      el("td", {}, nameCell(b, o.key, nm)),
      el("td", { class: "muted" }, relTime(o.lm)),
      el("td", { class: "num" }, fmtSize(o.size)),
      el("td", { class: "act" },
        el("button", { class: "ghost iconbtn", title: "Download", onclick: (e) => { e.stopPropagation(); dl(b, o.key); } }, ic(ICON.down)),
        el("button", { class: "ghost iconbtn", title: "Copy share link", onclick: async (e) => { e.stopPropagation(); copyText(await presignGet(b + "/" + o.key)); } }, ic(ICON.link)))));
  }
  const bulk = el("div", { class: "toolbar hidden", id: "bulkbar" },
    el("span", { class: "muted small", id: "bulkn" }),
    el("button", { class: "ghost sm", onclick: () => bulkDl(b, tbody) }, ic(ICON.down), "Download selected"),
    el("button", { class: "danger sm", onclick: () => bulkDel(b, tbody) }, ic(ICON.trash), "Delete selected"));
  v.append(bulk);
  v.append(el("div", { class: "card" }, el("table", {}, el("thead", {}, el("tr", {},
    el("th", { style: "width:34px" }, selAll), sortableTh("Name", "name"), sortableTh("Modified", "modified"), sortableTh("Size", "size", "num"), el("th", {}))), tbody)));

  function syncBulk() {
    const n = tbody.querySelectorAll(".rc:checked").length;
    bulk.classList.toggle("hidden", !n); $("#bulkn").textContent = n + " selected";
  }
}
async function bulkDel(b, tbody) {
  const keys = [...tbody.querySelectorAll(".rc:checked")].map((c) => c.dataset.key);
  if (!confirm(`Delete ${keys.length} object(s)?`)) return;
  const body = `<Delete>${keys.map((k) => `<Object><Key>${k.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</Key></Object>`).join("")}</Delete>`;
  await must(await api("POST", "/" + b, { query: { delete: "" }, contentType: "application/xml", body }));
  toast("Deleted " + keys.length, "ok"); render();
}
async function bulkDl(b, tbody) {
  const keys = [...tbody.querySelectorAll(".rc:checked")].map((c) => c.dataset.key);
  if (!keys.length) return;
  toast("Starting " + keys.length + " download(s)…", "ok");
  for (const k of keys) { dl(b, k); await new Promise((r) => setTimeout(r, 350)); }
}
async function newFolder(b) {
  const name = (prompt("New folder name:", "") || "").trim().replace(/^\/+|\/+$/g, "");
  if (!name) return;
  const key = bucketPrefix + name + "/";
  await must(await api("PUT", "/" + b + "/" + key, { body: "" }));
  toast("Folder created", "ok"); render();
}
function filterRows(q) {
  q = q.toLowerCase();
  document.querySelectorAll("#view tbody tr[data-name]").forEach((tr) => { tr.style.display = !q || tr.dataset.name.includes(q) ? "" : "none"; });
}

// bucketSearch walks the ENTIRE bucket (all prefixes) and lists matches.
async function bucketSearch(b, term) {
  const t0 = term.toLowerCase();
  const v = $("#view");
  v.innerHTML = "";
  pageHeader(v, "Search: " + term, "in bucket " + b, [
    el("button", { class: "ghost", onclick: render }, ic(ICON.arrowLeft), "Back to browser"),
  ]);
  const status = el("p", { class: "muted small" }, "Scanning…");
  v.append(status);
  const hits = []; let token = "", scanned = 0;
  try {
    do {
      const q = { "list-type": "2", "max-keys": "1000" };
      if (token) q["continuation-token"] = token;
      const doc = parseXml(await (await api("GET", "/" + b, { query: q })).text());
      for (const c of doc.getElementsByTagName("Contents")) {
        const k = t(c, "Key"); scanned++;
        if (k.toLowerCase().includes(t0)) hits.push({ key: k, size: +t(c, "Size"), lm: t(c, "LastModified"), etag: t(c, "ETag").replace(/"/g, "") });
      }
      token = t(doc, "IsTruncated") === "true" ? t(doc, "NextContinuationToken") : "";
      status.textContent = `Scanned ${scanned}, ${hits.length} match${hits.length === 1 ? "" : "es"}…`;
    } while (token && scanned < 50000 && hits.length < 1000);
  } catch (e) { status.textContent = "Search failed: " + e.message; return; }
  status.textContent = `${hits.length} match${hits.length === 1 ? "" : "es"} in ${scanned} objects` + (scanned >= 50000 ? " (stopped at 50k)" : "");
  if (!hits.length) { v.append(emptyState(ICON.search, "No matches", "Nothing in " + b + " contains “" + term + "”.")); return; }
  const tb = el("tbody");
  for (const o of hits) tb.append(el("tr", { class: "clk", onclick: () => objectDrawer(b, o) },
    el("td", {}, nameCell(b, o.key, o.key)),
    el("td", { class: "muted" }, relTime(o.lm)),
    el("td", { class: "num" }, fmtSize(o.size)),
    el("td", { class: "act" }, el("button", { class: "ghost iconbtn", title: "Download", onclick: (e) => { e.stopPropagation(); dl(b, o.key); } }, ic(ICON.down)))));
  v.append(el("div", { class: "card" }, el("table", {}, el("thead", {}, el("tr", {},
    el("th", {}, "Key"), el("th", {}, "Modified"), el("th", {}, "Size"), el("th", {}))), tb)));
}
// dropEntries turns a drop DataTransfer into [{file, path}], walking dropped
// directories (webkitGetAsEntry must be called synchronously here).
function dropEntries(dt) {
  const roots = [...(dt.items || [])]
    .map((it) => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null))
    .filter(Boolean);
  if (!roots.length) return Promise.resolve([...dt.files].map((f) => ({ file: f, path: f.name })));
  const out = [];
  const readAll = (rd) => new Promise((res) => {
    const acc = [];
    const step = () => rd.readEntries((batch) => { if (!batch.length) return res(acc); acc.push(...batch); step(); }, () => res(acc));
    step();
  });
  const fileOf = (e) => new Promise((res, rej) => e.file(res, rej));
  async function walk(entry, prefix) {
    if (entry.isFile) { out.push({ file: await fileOf(entry), path: prefix + entry.name }); }
    else if (entry.isDirectory) { for (const c of await readAll(entry.createReader())) await walk(c, prefix + entry.name + "/"); }
  }
  return (async () => { for (const r of roots) await walk(r, ""); return out; })();
}

async function doUpload(b, entriesOrPromise) {
  const entries = await entriesOrPromise;
  if (!entries.length) return;
  const list = $("#uplist");
  let ok = 0, fail = 0;
  for (const { file, path } of entries) {
    const row = el("div", { class: "up" }, ic(ICON.file), el("span", {}, path), el("span", { class: "bar" }, el("span", {})));
    list.append(row);
    const fill = row.querySelector(".bar>span");
    try {
      await upload(b + "/" + bucketPrefix + path, file, (p) => (fill.style.width = (p * 100).toFixed(0) + "%"));
      fill.style.width = "100%"; row.style.opacity = ".5"; ok++;
    } catch (e) { toast(path + ": " + e.message, "err"); row.remove(); fail++; }
  }
  toast(`Uploaded ${ok}${fail ? ", " + fail + " failed" : ""}`, fail ? "err" : "ok");
  setTimeout(render, 400);
}
async function dl(b, key, query) {
  try {
    const r = await must(await api("GET", "/" + b + "/" + key, { query: query || {} }));
    const a = el("a", { href: URL.createObjectURL(await r.blob()), download: key.split("/").pop() });
    document.body.append(a); a.click(); a.remove();
  } catch (e) { toast(e.message, "err"); }
}

async function objectDrawer(b, o) {
  openDrawer((d) => {
    d.append(el("div", { class: "dh" }, ic(ICON.file), el("h3", {}, o.key.split("/").pop()),
      el("button", { class: "ghost iconbtn", onclick: closeDrawer }, "✕")));
    const tabs = el("div", { class: "tabs" }), body = el("div", { class: "db" });
    d.append(tabs, body);
    const tab = (id, label, fn, on) => {
      const btn = el("button", { class: on ? "on" : "", onclick: () => { tabs.querySelectorAll("button").forEach((x) => x.classList.remove("on")); btn.classList.add("on"); body.innerHTML = ""; fn(body); } }, label);
      tabs.append(btn); if (on) fn(body); return btn;
    };
    const s3uri = "s3://" + b + "/" + o.key;
    const ext0 = (o.key.split(".").pop() || "").toLowerCase();
    const EDITABLE = ["txt", "json", "csv", "log", "md", "xml", "yaml", "yml", "html", "js", "css", "svg", "ini", "conf", "sh", "env"];
    tab("d", "Details", (c) => {
      c.append(el("div", { class: "kv" },
        el("div", { class: "k" }, "Key"), el("div", { class: "v" }, o.key),
        el("div", { class: "k" }, "S3 URI"), el("div", { class: "v" }, el("code", {}, s3uri),
          el("button", { class: "ghost iconbtn", title: "Copy", onclick: () => copyText(s3uri) }, ic(ICON.copy))),
        el("div", { class: "k" }, "URL"), el("div", { class: "v" }, el("code", {}, location.origin + "/" + b + "/" + o.key),
          el("button", { class: "ghost iconbtn", title: "Copy", onclick: () => copyText(location.origin + "/" + b + "/" + o.key) }, ic(ICON.copy))),
        el("div", { class: "k" }, "Size"), el("div", { class: "v" }, fmtSize(o.size) + ` (${o.size} B)`),
        el("div", { class: "k" }, "Modified"), el("div", { class: "v" }, fmtDate(o.lm)),
        el("div", { class: "k" }, "ETag"), el("div", { class: "v" }, el("code", {}, o.etag))));
      c.append(el("div", { class: "row" },
        el("button", { class: "primary", onclick: () => dl(b, o.key) }, ic(ICON.down), "Download"),
        el("button", { class: "ghost", onclick: async () => {
          const nk = prompt("Move / rename to (full key within the bucket):", o.key);
          if (!nk || nk === o.key) return;
          try {
            await must(await api("PUT", "/" + b + "/" + nk, {
              extraHeaders: { "x-amz-copy-source": "/" + b + "/" + encP(o.key) },
            }));
            await must(await api("DELETE", "/" + b + "/" + o.key));
            toast("Moved to " + nk, "ok"); closeDrawer(); render();
          } catch (e) { toast(e.message, "err"); }
        } }, ic(ICON.folder), "Move / rename"),
        el("button", { class: "danger", onclick: async () => {
          if (!confirm("Delete " + o.key + "?")) return;
          try { await must(await api("DELETE", "/" + b + "/" + o.key)); toast("Deleted", "ok"); closeDrawer(); render(); } catch (e) { toast(e.message, "err"); }
        } }, ic(ICON.trash), "Delete")));
    }, true);
    if (EDITABLE.includes(ext0) && o.size <= 1048576) tab("e", "Edit", async (c) => {
      c.append(el("div", { class: "empty" }, el("span", { class: "spin" })));
      let text;
      try { text = await (await api("GET", "/" + b + "/" + o.key)).text(); }
      catch (e) { c.innerHTML = ""; c.append(el("div", { class: "muted small" }, e.message)); return; }
      c.innerHTML = "";
      const ta = el("textarea", { style: "min-height:340px;width:100%;font:12px/1.6 var(--mono)", spellcheck: "false" }, text);
      const save = el("button", { class: "primary" }, ic(ICON.up), "Save");
      save.onclick = async () => {
        save.disabled = true;
        try {
          const ctMap = { json: "application/json", html: "text/html", css: "text/css", js: "text/javascript", svg: "image/svg+xml", xml: "application/xml", csv: "text/csv", md: "text/markdown" };
          await must(await api("PUT", "/" + b + "/" + o.key, { contentType: (ctMap[ext0] || "text/plain") + "; charset=utf-8", body: ta.value }));
          toast("Saved", "ok"); closeDrawer(); render();
        } catch (e) { toast(e.message, "err"); save.disabled = false; }
      };
      c.append(ta, el("div", { class: "toolbar" }, save,
        el("button", { class: "ghost", onclick: () => (ta.value = text) }, "Revert")));
    });
    tab("p", "Preview", async (c) => {
      c.append(el("div", { class: "empty" }, el("span", { class: "spin" })));
      let url;
      try { url = await presignGet(b + "/" + o.key, 3600); } catch (e) { c.innerHTML = ""; c.append(el("div", { class: "muted small" }, e.message)); return; }
      const ext = (o.key.split(".").pop() || "").toLowerCase();
      const V = ["mp4", "webm", "ogv", "ogg", "mov", "m4v"], I = ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "svg", "ico"];
      const A = ["mp3", "wav", "flac", "aac", "m4a", "oga"], T = ["txt", "json", "csv", "log", "md", "xml", "yaml", "yml", "html", "js", "css"];
      c.innerHTML = "";
      let node;
      if (V.includes(ext)) node = el("video", { src: url, controls: "", preload: "metadata", style: "width:100%;border-radius:var(--r2);background:#000;max-height:70vh" });
      else if (I.includes(ext)) {
        // scaled server-side for non-vector formats so a huge photo shows fast
        const raster = ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp"].includes(ext);
        const isrc = raster ? await presignGet(b + "/" + o.key, 3600, { preview: "1024" }) : url;
        node = el("img", { src: isrc, style: "max-width:100%;border-radius:var(--r2)" });
      }
      else if (A.includes(ext)) node = el("audio", { src: url, controls: "", style: "width:100%" });
      else if (ext === "pdf") node = el("iframe", { src: url, style: "width:100%;height:70vh;border:1px solid var(--border);border-radius:var(--r2)" });
      else if (T.includes(ext)) {
        node = el("pre", { class: "code", style: "max-height:62vh;overflow:auto;white-space:pre-wrap" }, "loading…");
        try { const rr = await fetch(url); node.textContent = (await rr.text()).slice(0, 200000); } catch { node.textContent = "(could not load)"; }
      } else node = el("div", { class: "muted small" }, "No inline preview for ." + (ext || "?") + " — use Download or the Share tab.");
      c.append(node);
      if (V.includes(ext) || A.includes(ext))
        c.append(el("p", { class: "muted small", style: "margin-top:10px" },
          "Streams via HTTP range requests — the player fetches only the bytes it needs, so playback and seeking start immediately without downloading the whole file."));
    });
    tab("s", "Share", (c) => {
      const sel = el("select"); for (const [l, val] of [["15 minutes", 900], ["1 hour", 3600], ["24 hours", 86400], ["7 days", 604800]]) sel.append(el("option", { value: val }, l));
      const out = el("textarea", { readonly: "", style: "min-height:84px" });
      c.append(el("label", { class: "field-label" }, "Link expires in"), sel,
        el("button", { class: "primary", style: "margin-top:12px", onclick: async () => { out.value = await presignGet(b + "/" + o.key, +sel.value); } }, ic(ICON.link), "Generate link"),
        el("div", { style: "margin-top:10px" }, out),
        el("button", { class: "ghost sm", style: "margin-top:6px", onclick: () => copyText(out.value) }, ic(ICON.copy), "Copy"));
    });
    tab("v", "Versions", async (c) => {
      c.append(el("div", { class: "empty" }, el("span", { class: "spin" })));
      try {
        const doc = parseXml(await (await api("GET", "/" + b, { query: { versions: "", prefix: o.key } })).text());
        const rows = [];
        for (const x of doc.getElementsByTagName("Version")) rows.push({ id: t(x, "VersionId"), latest: t(x, "IsLatest") === "true", size: t(x, "Size"), lm: t(x, "LastModified"), dm: false });
        for (const x of doc.getElementsByTagName("DeleteMarker")) rows.push({ id: t(x, "VersionId"), latest: t(x, "IsLatest") === "true", lm: t(x, "LastModified"), dm: true });
        c.innerHTML = "";
        if (!rows.length) { c.append(el("div", { class: "muted small" }, "This bucket is not versioned, or the key has no versions.")); return; }
        for (const rv of rows) c.append(el("div", { class: "kv", style: "grid-template-columns:1fr auto;align-items:center" },
          el("div", {}, el("code", {}, rv.id), rv.latest ? el("span", { class: "pill ok" }, "latest") : null, rv.dm ? el("span", { class: "pill warn" }, "delete marker") : null,
            el("div", { class: "muted small" }, fmtDate(rv.lm) + (rv.size ? " · " + fmtSize(rv.size) : ""))),
          el("div", { class: "row" },
            rv.dm ? null : el("button", { class: "ghost iconbtn", onclick: () => dl(b, o.key, { versionId: rv.id }) }, ic(ICON.down)),
            el("button", { class: "danger iconbtn", onclick: async () => { if (!confirm("Permanently delete this version?")) return; try { await must(await api("DELETE", "/" + b + "/" + o.key, { query: { versionId: rv.id } })); toast("Version deleted", "ok"); } catch (e) { toast(e.message, "err"); } } }, ic(ICON.trash)))));
      } catch (e) { c.innerHTML = ""; c.append(el("div", { class: "muted small" }, e.message)); }
    });
    tab("t", "Tags", async (c) => {
      try {
        const doc = parseXml(await (await api("GET", "/" + b + "/" + o.key, { query: { tagging: "" } })).text());
        const tags = [...doc.getElementsByTagName("Tag")].map((x) => [t(x, "Key"), t(x, "Value")]);
        const ta = el("textarea", { placeholder: "key=value\nenv=prod" }, tags.map(([k, val]) => `${k}=${val}`).join("\n"));
        c.append(el("label", { class: "field-label" }, "One key=value per line"), ta,
          el("button", { class: "primary", style: "margin-top:12px", onclick: async () => {
            const set = ta.value.split("\n").map((l) => l.split("=")).filter((p) => p[0].trim());
            const xml = `<Tagging><TagSet>${set.map(([k, val]) => `<Tag><Key>${k.trim()}</Key><Value>${(val || "").trim()}</Value></Tag>`).join("")}</TagSet></Tagging>`;
            try { await must(await api("PUT", "/" + b + "/" + o.key, { query: { tagging: "" }, contentType: "application/xml", body: xml })); toast("Tags saved", "ok"); } catch (e) { toast(e.message, "err"); }
          } }, "Save tags"));
      } catch (e) { c.append(el("div", { class: "muted small" }, e.message)); }
    });
  });
}
const t = (node, tag) => node.getElementsByTagName(tag)[0]?.textContent || "";

// file-type classification for the folder-stats breakdown
const FILE_TYPES = [
  ["Images", ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "tiff", "tif", "heic", "heif", "avif", "ico"]],
  ["Videos", ["mp4", "mov", "avi", "mkv", "webm", "flv", "wmv", "m4v", "mpg", "mpeg", "3gp"]],
  ["Audio", ["mp3", "wav", "flac", "aac", "ogg", "m4a", "wma", "opus"]],
  ["PDF", ["pdf"]],
  ["Documents", ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "md", "rtf", "odt", "pages"]],
  ["Data", ["json", "xml", "yaml", "yml", "sql", "log", "ndjson", "parquet"]],
  ["Archives", ["zip", "gz", "tar", "rar", "7z", "bz2", "xz", "tgz"]],
];
function classifyKey(key) {
  const i = key.lastIndexOf(".");
  if (i < 0 || i === key.length - 1) return "Other";
  const ext = key.slice(i + 1).toLowerCase();
  for (const [name, exts] of FILE_TYPES) if (exts.includes(ext)) return name;
  return "Other";
}

// folderStats walks a prefix recursively and shows a count/size breakdown by
// file type in a drawer.
async function folderStats(b, prefix) {
  openDrawer((d) => {
    d.append(el("div", { class: "dh" }, ic(ICON.gauge),
      el("h3", {}, "Folder stats"),
      el("button", { class: "ghost iconbtn", onclick: closeDrawer }, "✕")));
    const body = el("div", { class: "db" });
    const loc = prefix ? b + "/" + prefix : b;
    const status = el("p", { class: "muted small" }, "Scanning " + loc + " …");
    body.append(status);
    d.append(body);
    (async () => {
      const cats = {};
      let total = 0, totalSize = 0, token = "";
      try {
        do {
          const q = { "list-type": "2", "max-keys": "1000" };
          if (prefix) q.prefix = prefix;
          if (token) q["continuation-token"] = token;
          const doc = parseXml(await (await api("GET", "/" + b, { query: q })).text());
          for (const c of doc.getElementsByTagName("Contents")) {
            const k = t(c, "Key");
            if (k.endsWith("/")) continue;
            const sz = +t(c, "Size");
            const cat = classifyKey(k);
            if (!cats[cat]) cats[cat] = { n: 0, size: 0 };
            cats[cat].n++; cats[cat].size += sz;
            total++; totalSize += sz;
          }
          token = t(doc, "IsTruncated") === "true" ? t(doc, "NextContinuationToken") : "";
          status.textContent = "Scanning " + loc + " … " + total.toLocaleString() + " files";
        } while (token && total < 200000);
      } catch (e) { body.innerHTML = ""; body.append(el("p", { class: "muted" }, "Failed: " + e.message)); return; }
      body.innerHTML = "";
      body.append(el("div", { class: "kv" },
        el("span", { class: "k" }, "Location"), el("span", { class: "v" }, loc),
        el("span", { class: "k" }, "Files"), el("span", { class: "v" }, total.toLocaleString()),
        el("span", { class: "k" }, "Total size"), el("span", { class: "v" }, fmtSize(totalSize))));
      if (!total) { body.append(emptyState(ICON.bucket, "Empty", "No files under this prefix.")); return; }
      const order = [...FILE_TYPES.map((x) => x[0]), "Other"].filter((c) => cats[c]);
      const max = Math.max(1, ...order.map((c) => cats[c].n));
      const bars = el("div", { class: "usebars", style: "margin-top:6px" });
      for (const c of order) bars.append(el("div", { class: "ub" },
        el("div", { class: "ubn" }, c),
        el("div", { class: "ubt" }, el("span", { style: "width:" + Math.max(3, Math.round(cats[c].n / max * 100)) + "%" })),
        el("div", { class: "ubv" }, cats[c].n.toLocaleString() + " · " + fmtSize(cats[c].size))));
      body.append(bars);
      if (total >= 200000) body.append(el("p", { class: "muted small" }, "Stopped at 200k files."));
    })();
  });
}

async function bucketSettings(v, b) {
  const sec = (title, ...nodes) => { v.append(el("h3", { style: "margin:24px 0 8px;font-size:15px" }, title)); nodes.forEach((n) => v.append(n)); };
  const editor = async (label, q, ctype, preset) => {
    let cur = "";
    try { const r = await api("GET", "/" + b, { query: { [q]: "" } }); if (r.ok) { const txt = await r.text(); if (!txt.startsWith("<Error") && !/NoSuch/.test(txt)) cur = ctype === "application/json" ? JSON.stringify(JSON.parse(txt), null, 2) : txt; } } catch {}
    const ta = el("textarea", { placeholder: preset || "" }, cur);
    const bar = el("div", { class: "toolbar" });
    if (preset) bar.append(el("button", { class: "ghost sm", onclick: () => ta.value = preset }, "Insert example"));
    bar.append(
      el("button", { class: "primary sm", onclick: async () => { try { await must(await api("PUT", "/" + b, { query: { [q]: "" }, contentType: ctype, body: ta.value })); toast(label + " saved", "ok"); } catch (e) { toast(e.message, "err"); } } }, "Save"),
      el("button", { class: "danger sm", onclick: async () => { await api("DELETE", "/" + b, { query: { [q]: "" } }); ta.value = ""; toast(label + " removed", "ok"); } }, "Remove"));
    sec(label, ta, bar);
  };

  // --- Public access (one-click anonymous read) ---
  {
    let pol = null;
    try {
      const r = await api("GET", "/" + b, { query: { policy: "" } });
      if (r.ok) { const txt = await r.text(); if (txt.trim().startsWith("{")) pol = JSON.parse(txt); }
    } catch {}
    const arr = (x) => (Array.isArray(x) ? x : x == null ? [] : [x]);
    const isPublic = !!pol && arr(pol.Statement).some((st) =>
      st.Effect === "Allow" &&
      (st.Principal === "*" || st.Principal?.AWS === "*" || arr(st.Principal?.AWS).includes("*")) &&
      arr(st.Action).includes("s3:GetObject") &&
      arr(st.Resource).some((rr) => rr === `arn:aws:s3:::${b}/*` || rr === "arn:aws:s3:::*"));
    const pill = el("span", { class: "pill" + (isPublic ? " ok" : "") }, isPublic ? "Public — anonymous read" : "Private");
    const btn = el("button", { class: (isPublic ? "danger" : "primary") + " sm" }, isPublic ? "Make private" : "Make public");
    btn.onclick = async () => {
      try {
        if (isPublic) {
          await must(await api("DELETE", "/" + b, { query: { policy: "" } }));
          toast("Bucket is now private", "ok");
        } else {
          const body = JSON.stringify({ Version: "2012-10-17", Statement: [
            { Effect: "Allow", Principal: "*", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${b}/*`] }] });
          await must(await api("PUT", "/" + b, { query: { policy: "" }, contentType: "application/json", body }));
          toast("Bucket is publicly readable now", "ok");
        }
        render();
      } catch (e) { toast(e.message, "err"); }
    };
    sec("Public access",
      el("div", { class: "row", style: "align-items:center;gap:12px" }, pill, btn),
      el("p", { class: "muted small" },
        "When public, anyone can GET objects at ", el("code", {}, location.origin + "/" + b + "/<key>"),
        " with no credentials — good for serving images/video on a site. Upload, list and delete still need a key. "
        + "For cross-origin playback in a browser you also need CORS (below)."));
  }

  // --- Quota ---
  {
    let qb = 0, qo = 0;
    try { const r = await api("GET", "/" + b, { query: { quota: "" } }); if (r.ok) { const j = await r.json(); qb = j.bytes || 0; qo = j.objects || 0; } } catch {}
    const bytesIn = el("input", { value: qb ? fmtSize(qb) : "", placeholder: "e.g. 20 GB — blank = no limit", style: "max-width:260px" });
    const objIn = el("input", { type: "number", min: "0", value: qo || "", placeholder: "max objects — blank = no limit", style: "max-width:260px" });
    sec("Quota",
      el("div", { class: "kv", style: "grid-template-columns:auto 1fr;max-width:520px" },
        el("div", { class: "k" }, "Max size"), bytesIn,
        el("div", { class: "k" }, "Max objects"), objIn),
      el("div", { class: "toolbar" },
        el("button", { class: "primary sm", onclick: async () => {
          const bytes = parseSize(bytesIn.value);
          if (Number.isNaN(bytes)) return toast("Size not understood — use e.g. 20 GB", "err");
          try {
            await must(await api("PUT", "/" + b, { query: { quota: "" }, contentType: "application/json",
              body: JSON.stringify({ bytes, objects: Number(objIn.value) || 0 }) }));
            toast("Quota saved", "ok"); render();
          } catch (e) { toast(e.message, "err"); }
        } }, "Save"),
        el("button", { class: "danger sm", onclick: async () => {
          try { await api("DELETE", "/" + b, { query: { quota: "" } }); toast("Quota removed", "ok"); render(); } catch (e) { toast(e.message, "err"); }
        } }, "Remove")),
      el("p", { class: "muted small" }, "Soft limit checked against the last background scan, so a burst can briefly overshoot. Writes past the limit get <code>403 QuotaExceeded</code>."));
  }

  // compression at rest
  {
    let con = false;
    try { con = (await (await api("GET", "/" + b, { query: { compression: "" } })).json()).enabled; } catch {}
    const cbox = el("input", { type: "checkbox" }); cbox.checked = !!con;
    sec("Compression at rest",
      el("label", { class: "row", style: "gap:8px" }, cbox,
        el("span", {}, "zstd-compress new objects on disk (erasure, non-SSE, single-part; already-compressed types are skipped)")),
      el("button", { class: "primary sm", style: "margin-top:8px", onclick: async () => {
        try { await must(await api("PUT", "/" + b, { query: { compression: "" }, contentType: "application/json", body: JSON.stringify({ enabled: cbox.checked }) })); toast("Compression " + (cbox.checked ? "on" : "off"), "ok"); } catch (e) { toast(e.message, "err"); }
      } }, "Apply"),
      el("p", { class: "muted small" }, "Applies to objects written after this — existing objects are untouched. 2–5× smaller for logs/JSON/text."));
  }

  // default encryption at rest (SSE-S3)
  {
    let encOn = false;
    try { encOn = (await api("GET", "/" + b, { query: { encryption: "" } })).ok; } catch {}
    const ebox = el("input", { type: "checkbox" }); ebox.checked = encOn;
    sec("Default encryption (SSE-S3)",
      el("label", { class: "row", style: "gap:8px" }, ebox,
        el("span", {}, "encrypt every new object at rest with AES-256 (server-managed key)")),
      el("button", { class: "primary sm", style: "margin-top:8px", onclick: async () => {
        try {
          if (ebox.checked) {
            await must(await api("PUT", "/" + b, { query: { encryption: "" }, contentType: "application/xml",
              body: "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>" }));
          } else {
            await api("DELETE", "/" + b, { query: { encryption: "" } });
          }
          toast("Default encryption " + (ebox.checked ? "on" : "off"), "ok");
        } catch (e) { toast(e.message, "err"); }
      } }, "Apply"),
      el("p", { class: "muted small" }, "Applies to objects written after this. Existing objects are untouched."));
  }

  // versioning
  let vstat = "";
  try { vstat = t(parseXml(await (await api("GET", "/" + b, { query: { versioning: "" } })).text()), "Status"); } catch {}
  const vsel = el("select"); for (const o of [["Off", ""], ["Enabled", "Enabled"], ["Suspended", "Suspended"]]) vsel.append(el("option", { value: o[1] }, o[0]));
  vsel.value = vstat;
  sec("Versioning", el("div", { class: "row", style: "max-width:360px" }, vsel,
    el("button", { class: "primary sm", onclick: async () => {
      if (!vsel.value) return toast("S3 can't fully disable versioning once enabled — use Suspended.", "err");
      try { await must(await api("PUT", "/" + b, { query: { versioning: "" }, contentType: "application/xml", body: `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>${vsel.value}</Status></VersioningConfiguration>` })); toast("Versioning: " + vsel.value, "ok"); } catch (e) { toast(e.message, "err"); }
    } }, "Apply")));

  await editor("Bucket policy", "policy", "application/json",
    JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: "*", Action: ["s3:GetObject"], Resource: [`arn:aws:s3:::${b}/*`] }] }, null, 2));
  await editor("Lifecycle (ILM)", "lifecycle", "application/xml",
    `<LifecycleConfiguration>
  <Rule><ID>expire-logs</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule>
  <Rule><ID>tier-cold</ID><Status>Enabled</Status><Filter><Prefix>archive/</Prefix></Filter><Transition><Days>90</Days><StorageClass>cold</StorageClass></Transition></Rule>
</LifecycleConfiguration>`);
  await editor("Replication", "replication", "application/json",
    JSON.stringify([{ id: "r1", prefix: "", destBucket: "backup", destEndpoint: "", deleteReplication: true }], null, 2));
  await editor("CORS", "cors", "application/xml",
    `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod><AllowedHeader>*</AllowedHeader></CORSRule></CORSConfiguration>`);
  v.append(el("div", { class: "toolbar" }, el("button", { class: "ghost sm", onclick: async () => {
    try {
      await must(await api("PUT", "/" + b, { query: { cors: "" }, contentType: "application/xml",
        body: "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod><AllowedHeader>*</AllowedHeader></CORSRule></CORSConfiguration>" }));
      toast("CORS set: any origin can GET/HEAD (browser playback works)", "ok"); render();
    } catch (e) { toast(e.message, "err"); }
  } }, ic(ICON.plus), "Quick: allow browser playback from any origin")));
  await editor("Event notifications", "notification", "application/json",
    JSON.stringify({ webhooks: [{ id: "w1", url: "https://example.com/hook", events: ["s3:ObjectCreated:*"], prefix: "", suffix: "" }] }, null, 2));

  // --- Ingest keys (drop-a-backup tokens for any backend) ---
  {
    const box = el("div", { class: "card", style: "margin:20px 0" });
    box.append(el("div", { class: "row", style: "justify-content:space-between;align-items:center" },
      el("h3", { style: "margin:0;font-size:15px" }, "Ingest keys"),
      el("button", { class: "primary sm", onclick: async () => {
        const prefix = prompt("Prefix this key can write under (e.g. pg/ ):", "pg/") || "";
        try {
          const j = await (await must(await api("POST", "/gostore/admin/v1/ingest-keys", { query: { bucket: b }, contentType: "application/json", body: JSON.stringify({ prefix, label: "" }) }))).json();
          modal("Ingest key — copy it now, shown once", "Any backend can now upload with a single header, no SigV4:", [
            { name: "t", label: "Token", value: j.token, readonly: true },
            { name: "c", label: "Example", value: j.example, readonly: true },
          ], async () => {}, "Done");
          render();
        } catch (e) { toast(e.message, "err"); }
      } }, ic(ICON.key), "Generate ingest key")));
    box.append(el("p", { class: "muted small" }, "Write-only, prefix-scoped, no expiry. Great for pushing a DB dump into a bucket: ",
      el("code", {}, "pg_dump ... | curl -T - -H 'Authorization: Bearer <token>' " + location.origin + "/gostore/ingest/" + b + "/pg/dump.sql")));
    const list = el("div"); box.append(list);
    (async () => {
      let keys = [];
      try { keys = await (await api("GET", "/gostore/admin/v1/ingest-keys", { query: { bucket: b } })).json(); } catch {}
      if (!keys.length) { list.append(el("p", { class: "muted small" }, "No ingest keys.")); return; }
      const tb = el("tbody");
      for (const k of keys) tb.append(el("tr", {},
        el("td", {}, el("code", { style: "font-size:11.5px" }, k.id)),
        el("td", {}, el("code", {}, (k.prefix || "(any)"))),
        el("td", { class: "muted" }, relTime(k.createdAt)),
        el("td", { class: "act" }, el("button", { class: "ghost sm danger", onclick: async () => { try { await api("DELETE", "/gostore/admin/v1/ingest-keys", { query: { bucket: b, id: k.id } }); render(); } catch (e) { toast(e.message, "err"); } } }, "Revoke"))));
      list.append(el("div", { class: "card", style: "margin-top:8px" }, el("table", {}, el("thead", {}, el("tr", {}, ...["ID", "Prefix", "Created", ""].map((h) => el("th", {}, h)))), tb)));
    })();
    v.append(box);
  }

  // --- Static website hosting ---
  {
    let idx = "index.html", errd = "", on = false;
    try {
      const doc = parseXml(await (await api("GET", "/" + b, { query: { website: "" } })).text());
      idx = t(doc, "Suffix") || "index.html"; errd = t(doc, "Key") || ""; on = true;
    } catch {}
    const iIn = el("input", { value: idx, placeholder: "index.html", style: "max-width:220px" });
    const eIn = el("input", { value: errd, placeholder: "404.html (optional)", style: "max-width:220px" });
    sec("Static website hosting",
      el("p", { class: "muted small" }, on ? "Enabled — a plain GET of “/” or “dir/” serves the index document; a miss serves the error document." : "Serve this bucket as a static site. Combine with a public-read policy (above) and a domain via GOSTORE_TLS_DOMAIN for HTTPS. MinIO needs a reverse proxy for this."),
      el("div", { class: "row", style: "gap:10px;flex-wrap:wrap" },
        el("label", { class: "muted small" }, "Index"), iIn,
        el("label", { class: "muted small" }, "Error"), eIn,
        el("button", { class: "primary sm", onclick: async () => {
          const body = `<WebsiteConfiguration><IndexDocument><Suffix>${(iIn.value.trim() || "index.html")}</Suffix></IndexDocument>${eIn.value.trim() ? `<ErrorDocument><Key>${eIn.value.trim()}</Key></ErrorDocument>` : ""}</WebsiteConfiguration>`;
          try { await must(await api("PUT", "/" + b, { query: { website: "" }, contentType: "application/xml", body })); toast("Website hosting enabled", "ok"); render(); } catch (e) { toast(e.message, "err"); }
        } }, on ? "Update" : "Enable"),
        on ? el("button", { class: "ghost sm", onclick: async () => {
          try { await api("DELETE", "/" + b, { query: { website: "" } }); toast("Website hosting disabled", "ok"); render(); } catch (e) { toast(e.message, "err"); }
        } }, "Disable") : null));
  }

  // --- Snapshots (point-in-time restore) ---
  {
    const sw = el("div", { class: "card", style: "margin:20px 0" });
    const head = el("div", { class: "row", style: "justify-content:space-between;align-items:center" },
      el("h3", { style: "margin:0;font-size:15px" }, "Snapshots — time travel"),
      el("button", { class: "primary sm", onclick: async () => {
        try { const j = await (await must(await api("POST", "/gostore/admin/v1/snapshot", { query: { bucket: b } }))).json(); toast("Snapshot " + j.id + " (" + j.objects + " objects)", "ok"); render(); }
        catch (e) { toast(e.message, "err"); }
      } }, ic(ICON.clock || ICON.info), "Take snapshot now"));
    sw.append(head);
    sw.append(el("p", { class: "muted small" }, "Records the version of every object right now. A restore rolls the whole bucket back to that instant — non-destructively (every change is a new version). Needs versioning enabled."));
    const list = el("div"); sw.append(list);
    (async () => {
      let snaps = [];
      try { snaps = await (await api("GET", "/gostore/admin/v1/snapshots", { query: { bucket: b } })).json(); } catch {}
      if (!snaps.length) { list.append(el("p", { class: "muted small" }, "No snapshots yet.")); return; }
      const tb = el("tbody");
      for (const s of snaps) {
        tb.append(el("tr", {},
          el("td", {}, el("code", { style: "font-size:11.5px" }, s.id)),
          el("td", { class: "muted" }, relTime(s.createdAt)),
          el("td", { class: "num muted" }, s.objects + " obj / " + fmtSize(s.bytes)),
          el("td", { class: "act" },
            el("button", { class: "ghost sm", onclick: async () => {
              try { const p = await (await api("POST", "/gostore/admin/v1/snapshot/restore", { query: { bucket: b, id: s.id, dryRun: "1" } })).json();
                if (!confirm("Restore bucket \"" + b + "\" to " + s.id + "?\n\n" + p.restored + " objects rolled back, " + p.removed + " newer objects removed, " + p.unchanged + " unchanged.\n\nNon-destructive (creates new versions).")) return;
                const r = await (await must(await api("POST", "/gostore/admin/v1/snapshot/restore", { query: { bucket: b, id: s.id } }))).json();
                toast("Restored: " + r.restored + " back, " + r.removed + " removed", "ok"); render();
              } catch (e) { toast(e.message, "err"); }
            } }, "Restore"),
            el("button", { class: "ghost sm danger", onclick: async () => { try { await api("DELETE", "/gostore/admin/v1/snapshot", { query: { bucket: b, id: s.id } }); render(); } catch (e) { toast(e.message, "err"); } } }, "Delete"))));
      }
      list.append(el("div", { class: "card", style: "margin-top:8px" }, el("table", {}, el("thead", {}, el("tr", {}, ...["Snapshot", "Taken", "Size", ""].map((h) => el("th", {}, h)))), tb)));
    })();
    v.append(sw);
  }

  // --- Danger zone ---
  v.append(el("h3", { style: "margin:28px 0 8px;font-size:15px;color:var(--red,#c0392b)" }, "Danger zone"));
  v.append(el("div", { class: "toolbar" }, el("button", { class: "danger sm", onclick: async () => {
    const c = prompt('This deletes EVERY object in "' + b + '" (all versions). Type the bucket name to confirm:');
    if (c !== b) return;
    try {
      const j = await (await must(await api("POST", "/gostore/admin/v1/buckets/empty", { query: { bucket: b } }))).json();
      toast("Emptied " + b + " (" + j.deleted + " deleted)", "ok"); render();
    } catch (e) { toast(e.message, "err"); }
  } }, ic(ICON.trash), "Empty bucket")));
}

function randHex(bytes) {
  const b = new Uint8Array(bytes); crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// credsModal shows a freshly-minted key ONCE, with copy + download.
function credsModal(ak, sk, note) {
  const d = $("#modal"); d.innerHTML = "";
  d.append(el("h3", {}, "Access key created"));
  d.append(el("div", { class: "callout warn" },
    el("b", {}, "Copy the secret key now"),
    "It is shown only once and cannot be retrieved later. Save it in a password manager or download the credentials file."));
  if (note) d.append(el("p", { class: "hint" }, note));
  const row = (label, val) => {
    d.append(el("label", { class: "field-label" }, label));
    const i = el("input", { value: val, readonly: "", spellcheck: "false" });
    const r = el("div", { class: "creds-row" }, i,
      el("button", { class: "ghost", onclick: () => copyText(val) }, ic(ICON.copy), "Copy"));
    d.append(r);
  };
  row("Access key ID", ak);
  row("Secret access key", sk);
  const btns = el("div", { class: "btns" });
  const dl = el("button", { class: "ghost" }, ic(ICON.download), "Download .json");
  dl.onclick = () => {
    const blob = new Blob([JSON.stringify({
      accessKeyId: ak, secretAccessKey: sk,
      endpoint: location.origin, region: SERVER.region || REGION,
    }, null, 2)], { type: "application/json" });
    const a = el("a", { href: URL.createObjectURL(blob), download: ak + ".credentials.json" });
    document.body.append(a); a.click(); a.remove();
  };
  const done = el("button", { class: "primary" }, "Done");
  done.onclick = () => { d.close(); render(); };
  btns.append(dl, done); d.append(btns);
  // If it's already open (invoked from inside another modal's submit), just
  // keep it open — calling showModal() twice throws.
  if (!d.open) d.showModal();
}

async function viewKeys(v) {
  const [ur, sr] = await Promise.all([api("GET", "/gostore/admin/v1/users"), api("GET", "/gostore/admin/v1/service-accounts")]);
  if (ur.status === 403) { pageHeader(v, "Access Keys"); v.append(emptyState(ICON.lock, "No admin permission", "Your key can't manage users. Sign in with an admin key.")); return; }
  const users = (await (await must(ur)).json()) || [];
  const svcs = sr.ok ? (await sr.json()) || [] : [];
  pageHeader(v, "Access Keys", users.length + " users · " + svcs.length + " service accounts", [
    el("button", { class: "ghost", onclick: render }, ic(ICON.refresh), "Refresh"),
    el("button", { class: "ghost", onclick: () => modal("Custom access key", "Choose your own access key ID (≥ 3 chars) and secret (≥ 8 chars).", [
      { name: "accessKey", label: "Access key ID" }, { name: "secretKey", label: "Secret access key", type: "password" },
      { name: "policy", label: "Policy", type: "select", value: "readwrite", options: ["readwrite", "readonly", "writeonly", "consoleAdmin", "diagnostics"] },
    ], async (val) => {
      await must(await api("PUT", "/gostore/admin/v1/users", { contentType: "application/json", body: JSON.stringify({ accessKey: val.accessKey, secretKey: val.secretKey, policies: [val.policy] }) }));
      credsModal(val.accessKey, val.secretKey, "Policy: " + val.policy);
      return false; // keep the dialog open — credsModal swapped its content in
    }) }, ic(ICON.plus), "Custom key"),
    el("button", { class: "primary", onclick: () => modal("Generate access key",
      "A random access key ID + secret are generated. The secret is shown once — copy or download it.", [
      { name: "policy", label: "Policy", type: "select", value: "readwrite", options: ["readwrite", "readonly", "writeonly", "consoleAdmin", "diagnostics"] },
    ], async (val) => {
      const ak = "gk" + randHex(9), sk = randHex(24);
      await must(await api("PUT", "/gostore/admin/v1/users", { contentType: "application/json", body: JSON.stringify({ accessKey: ak, secretKey: sk, policies: [val.policy] }) }));
      credsModal(ak, sk, "Policy: " + val.policy + " · this key is persisted on the server.");
      return false; // keep the dialog open — credsModal swapped its content in
    }, "Generate") }, ic(ICON.key), "Generate access key"),
  ]);
  const tb = el("tbody");
  for (const u of users) tb.append(el("tr", {},
    el("td", {}, el("div", { class: "nm" }, ic(ICON.key), el("code", {}, u.accessKey))),
    el("td", { class: "muted" }, "user"),
    el("td", {}, (u.policies || []).map((p) => el("span", { class: "pill" }, p))),
    el("td", {}, el("span", { class: "pill" + (u.status !== "disabled" ? " ok" : " warn") }, u.status || "enabled")),
    el("td", { class: "act" },
      el("button", { class: "ghost sm", title: "Rotate secret key", onclick: async () => {
        if (!confirm("Rotate the secret for " + u.accessKey + "? The old secret stops working immediately.")) return;
        try {
          const j = await (await must(await api("POST", "/gostore/admin/v1/users/rotate-secret", {
            contentType: "application/json", body: JSON.stringify({ accessKey: u.accessKey }) }))).json();
          credsModal(j.accessKey, j.secretKey, "New secret for an existing key — update your clients.");
        } catch (e) { toast(e.message, "err"); }
      } }, ic(ICON.refresh)),
      el("button", { class: "danger sm", onclick: async () => {
        if (!confirm("Delete user " + u.accessKey + "?")) return;
        await api("DELETE", "/gostore/admin/v1/users", { query: { accessKey: u.accessKey } }); toast("Deleted", "ok"); render();
      } }, ic(ICON.trash)))));
  for (const s of svcs) tb.append(el("tr", {},
    el("td", {}, el("div", { class: "nm" }, ic(ICON.key), el("code", {}, s.accessKey))),
    el("td", { class: "muted" }, "service account"),
    el("td", {}, el("span", { class: "pill" }, "parent: " + s.parentUser)),
    el("td", {}, el("span", { class: "pill ok" }, s.status || "enabled")),
    el("td", { class: "act" }, el("button", { class: "danger sm", onclick: async () => {
      await api("DELETE", "/gostore/admin/v1/service-accounts", { query: { accessKey: s.accessKey } }); toast("Deleted", "ok"); render();
    } }, ic(ICON.trash)))));
  v.append(el("div", { class: "card" }, el("table", {}, el("thead", {}, el("tr", {},
    el("th", {}, "Access key"), el("th", {}, "Type"), el("th", {}, "Policy"), el("th", {}, "Status"), el("th", {}))), tb)));

  try {
    const me = await (await api("GET", "/gostore/admin/v1/whoami")).json();
    const pol = me.isRoot ? "root (full access)" : (me.policies && me.policies.length ? me.policies.join(", ") : "none");
    v.append(el("p", { class: "small muted", style: "margin-top:14px" },
      "You are signed in as ", el("code", {}, me.accessKey), " — ",
      me.isAdmin ? "admin" : "not admin", " · policies: ", el("b", {}, pol),
      me.parentUser ? " · parent: " + me.parentUser : ""));
  } catch {}

  v.append(el("p", { class: "small muted", style: "margin-top:6px" }, "Policy language and STS are covered in ",
    el("a", { onclick: () => go("docs/iam") }, "Documentation → IAM & Policies"), "."));
}

async function viewMonitoring(v) {
  const j = await (await must(await api("GET", "/gostore/admin/v1/info"))).json();
  pageHeader(v, "Monitoring", j.version);
  const tiles = el("div", { class: "grid stat-tiles" });
  const tile = (k, val) => tiles.append(el("div", { class: "tile" }, el("div", { class: "k" }, k), el("div", { class: "v" }, String(val))));
  tile("Mode", j.mode); tile("Drives", j.drives); tile("Parity", j.parity ?? "—");
  tile("Total space", fmtSize(j.totalSpace) || "—"); tile("Free space", fmtSize(j.freeSpace) || "—");
  tile("Access keys", j.users + (j.serviceAccounts ? " + " + j.serviceAccounts + " svc" : "")); tile("Policies", j.policies); tile("Region", j.region);
  v.append(tiles);

  // --- Data health ---
  {
    const dh = el("div", { class: "card", style: "margin:20px 0" });
    dh.append(el("div", { class: "row", style: "justify-content:space-between;align-items:center" },
      el("h3", { style: "margin:0;font-size:15px" }, "Data health"),
      el("div", { class: "row", style: "gap:8px" },
        el("button", { class: "ghost sm", onclick: async () => { try { await must(await api("POST", "/gostore/admin/v1/scrub")); toast("Deep scrub started", "ok"); setTimeout(render, 800); } catch (e) { toast(e.message, "err"); } } }, "Run deep scrub"),
        el("button", { class: "ghost sm", onclick: async () => { const r = await (await api("GET", "/gostore/admin/v1/audit/verify")).json(); toast(r.intact ? `Audit chain intact (${r.entries} entries)` : `AUDIT CHAIN BROKEN at seq ${r.brokenAtSeq}`, r.intact ? "ok" : "err"); } }, "Verify audit log"))));
    const grid = el("div", { class: "grid stat-tiles" });
    const cell = (k, val, warn) => grid.append(el("div", { class: "tile" }, el("div", { class: "k" }, k), el("div", { class: "v", style: warn ? "color:var(--red,#c0392b)" : "" }, String(val))));
    let metricsText = "";
    try { metricsText = await (await fetch(location.origin + "/gostore/metrics")).text(); } catch {}
    const mv = (re) => { const m = metricsText.match(re); return m ? m[1] : "0"; };
    let scrub = null; try { scrub = await (await api("GET", "/gostore/admin/v1/scrub")).json(); } catch {}
    if (scrub) {
      cell("Deep scrub", scrub.running ? `running — ${scrub.objectsScanned} scanned` : (scrub.neverRun ? "never run" : "idle"));
      cell("Objects repaired (last scrub)", scrub.objectsRepaired ?? 0);
      cell("Unrecoverable", scrub.unrecoverable ?? 0, (scrub.unrecoverable ?? 0) > 0);
    }
    const integ = mv(/gostore_integrity_failures_total (\d+)/);
    cell("Integrity failures", integ, +integ > 0);
    cell("Read-repairs queued", mv(/gostore_read_repair_queued_total (\d+)/));
    cell("Heal ok / error", mv(/gostore_heal_objects_total\{result="ok"\} (\d+)/) + " / " + mv(/gostore_heal_objects_total\{result="error"\} (\d+)/));
    cell("Read-only", mv(/gostore_read_only (\d+)/) === "1" ? "YES" : "no", mv(/gostore_read_only (\d+)/) === "1");
    let cl = null; try { cl = await (await api("GET", "/gostore/admin/v1/cluster")).json(); } catch {}
    if (cl && cl.peersTotal) cell("Peers up", `${cl.peersUp} / ${cl.peersTotal}`, cl.peersUp < cl.peersTotal);
    dh.append(grid);
    dh.append(el("p", { class: "muted small" }, "Deep scrub verifies every shard's bitrot hash on a weekly cadence; the audit log is hash-chained so any edit is detectable. Neither is something MinIO's community edition surfaces."));
    v.append(dh);
  }

  // --- Automatic backup ---
  try {
    const bk = await (await api("GET", "/gostore/admin/v1/backup")).json();
    const cfg = bk.config || {};
    const tiers = bk.tiers || [];
    const bc = el("div", { class: "card", style: "margin:20px 0" });
    bc.append(el("div", { class: "row", style: "justify-content:space-between;align-items:center" },
      el("h3", { style: "margin:0;font-size:15px" }, "Automatic backup"),
      el("div", { class: "row", style: "gap:8px" },
        el("button", {
          class: "ghost sm", disabled: tiers.length ? null : "disabled",
          onclick: async () => { try { await must(await api("POST", "/gostore/admin/v1/backup/run")); toast("Backup started", "ok"); setTimeout(render, 1200); } catch (e) { toast(e.message, "err"); } }
        }, "Back up now"),
        el("button", {
          class: "ghost sm", disabled: tiers.length ? null : "disabled",
          onclick: async () => { try { await must(await api("POST", "/gostore/admin/v1/backup/verify")); toast("Verify started — watch the status", "ok"); setTimeout(render, 1500); } catch (e) { toast(e.message, "err"); } }
        }, "Verify backup"),
        el("button", {
          class: "ghost sm", disabled: tiers.length ? null : "disabled",
          onclick: async () => {
            if (!confirm("Restore from the backup tier?\n\nThis pulls objects that are MISSING locally back from the remote backup — for disaster recovery. Existing local objects are NOT overwritten.")) return;
            try { await must(await api("POST", "/gostore/admin/v1/backup/restore")); toast("Restore started — watch the status", "ok"); setTimeout(render, 1500); } catch (e) { toast(e.message, "err"); }
          }
        }, "Restore from tier"))));
    if (bk.verify) {
      const vs = bk.verify;
      const bad = (vs.mismatched || 0) + (vs.missingRemote || 0);
      bc.append(el("p", { class: "muted small", style: bad > 0 ? "color:var(--red)" : "" },
        (vs.running ? "Verifying… " : "Last verify: ") +
        `${vs.ok || 0} ok, ${vs.mismatched || 0} mismatched, ${vs.missingRemote || 0} not backed up (of ${vs.checked || 0} checked)` +
        (vs.lastError ? " — " + vs.lastError : "")));
    }
    if (bk.restore) {
      const rs = bk.restore;
      bc.append(el("p", { class: "muted small" },
        (rs.running ? "Restoring… " : "Last restore: ") +
        `${rs.restored || 0} restored, ${rs.skipped || 0} skipped, ${rs.errors || 0} errors` +
        (rs.lastError ? " — " + rs.lastError : "")));
    }

    if (!tiers.length) {
      bc.append(el("p", { class: "muted small" }, "No remote tier is configured. Set ",
        el("code", {}, "GOSTORE_TIER_<NAME>=s3,https://endpoint,region,bucket,access,secret[,prefix]"),
        " (any S3-compatible target — Backblaze B2, Cloudflare R2, Wasabi, another gostore) and restart to enable scheduled off-site backups."));
    } else {
      const enabled = el("input", { type: "checkbox" });
      if (cfg.enabled) enabled.checked = true;
      const tierSel = el("select", {}, ...tiers.map((t) => el("option", { value: t, selected: t === cfg.tier ? "selected" : null }, t)));
      const iv = el("input", { type: "number", min: "1", value: String(cfg.intervalHours || 24), style: "width:80px" });
      const pfx = el("input", { type: "text", value: cfg.prefix || "", placeholder: "(all keys)", style: "width:160px" });
      const form = el("div", { class: "grid", style: "gap:10px;margin:12px 0;max-width:520px" },
        el("label", { class: "row", style: "gap:8px;align-items:center" }, enabled, "Enabled — mirror every object to the tier below on a schedule"),
        el("label", { class: "row", style: "gap:8px;align-items:center" }, "Destination tier", tierSel),
        el("label", { class: "row", style: "gap:8px;align-items:center" }, "Every", iv, "hours"),
        el("label", { class: "row", style: "gap:8px;align-items:center" }, "Key prefix", pfx),
        el("button", {
          class: "primary sm", style: "justify-self:start",
          onclick: async () => {
            try {
              await must(await api("PUT", "/gostore/admin/v1/backup", {
                contentType: "application/json",
                body: JSON.stringify({
                  enabled: enabled.checked, tier: tierSel.value,
                  intervalHours: parseInt(iv.value, 10) || 24, prefix: pfx.value.trim(),
                }),
              }));
              toast("Backup settings saved", "ok"); setTimeout(render, 600);
            } catch (e) { toast(e.message, "err"); }
          }
        }, "Save"));
      bc.append(form);
      const st = bk.status;
      if (st) {
        const line = st.running
          ? `Running — ${st.copied} copied, ${st.skipped} unchanged, ${st.errors} errors`
          : (st.lastRun
            ? `Last run ${relTime(st.lastRun)} — ${st.copied} copied (${fmtSize(st.bytesCopied)}), ${st.skipped} unchanged, ${st.errors} errors`
            : "Never run yet");
        bc.append(el("p", { class: "small", style: st.errors ? "color:var(--red,#c0392b)" : "" }, line));
        if (st.lastError) bc.append(el("p", { class: "small muted" }, "Last error: " + st.lastError));
      }
    }
    bc.append(el("p", { class: "muted small" }, "Incremental: an object is skipped when the tier already holds it at the same size. Runs are single-flight and survive restarts. Backups are plain S3 objects on the remote — restore with any S3 client."));
    v.append(bc);
  } catch {}

  // --- Replication ---
  try {
    const rep = await (await api("GET", "/gostore/admin/v1/replication")).json();
    const rc = el("div", { class: "card", style: "margin:20px 0" });
    rc.append(el("h3", { style: "margin:0 0 8px;font-size:15px" }, "Replication"));
    const pend = rep.pending || 0;
    rc.append(el("p", { class: "muted small", style: pend > 0 ? "color:var(--amber)" : "" },
      pend === 0 ? "Queue empty — all replicated." : `${pend} event${pend === 1 ? "" : "s"} pending in the durable retry queue.`));
    rc.append(el("p", { class: "muted small" }, "Rules are set per bucket (Settings → ?replication). To replicate objects written before a rule existed, run backfill: ",
      el("code", {}, "POST /gostore/admin/v1/replication/backfill?bucket=NAME"), "."));
    v.append(rc);
  } catch {}

  let du = null;
  try { du = await (await api("GET", "/gostore/admin/v1/datausage")).json(); } catch {}
  if (du && du.buckets && Object.keys(du.buckets).length) {
    v.append(el("h3", { style: "margin:24px 0 8px;font-size:15px" }, "Usage by bucket"));
    const tb = el("tbody");
    for (const [name, u] of Object.entries(du.buckets).sort())
      tb.append(el("tr", {}, el("td", {}, el("code", {}, name)), el("td", {}, String(u.objects)), el("td", {}, fmtSize(u.bytes))));
    tb.append(el("tr", {}, el("td", {}, el("b", {}, "Total")), el("td", {}, el("b", {}, String(du.totalObjects))), el("td", {}, el("b", {}, fmtSize(du.totalBytes)))));
    v.append(el("div", { class: "card" }, el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "Bucket"), el("th", {}, "Objects"), el("th", {}, "Size"))), tb)));
    v.append(el("p", { class: "muted small" }, "From the last background scan (", relTime(du.lastUpdate), ")."));
  }
  v.append(el("p", { class: "muted small", style: "margin-top:14px" },
    "Prometheus metrics: ", el("code", {}, location.origin + "/gostore/metrics"),
    " (open by default; set ", el("code", {}, "GOSTORE_METRICS_TOKEN"), " to require a bearer token). ",
    "Includes ", el("code", {}, "gostore_integrity_failures_total"), " — objects that failed end-to-end checksum verification on read; a non-zero value means shard corruption slipped past bitrot checks and should be investigated."));

  // Live request feed / trace — no external audit sink needed. Click a row
  // for the full picture (S3 action, error code, request id, cache result).
  v.append(el("h3", { style: "margin:26px 0 8px;font-size:15px" }, "Recent requests"));
  let feedErrOnly = false;
  const feedToggle = el("button", { class: "ghost sm", onclick: () => { feedErrOnly = !feedErrOnly; feedToggle.textContent = feedErrOnly ? "Show all" : "Errors only"; loadFeed(); } }, "Errors only");
  v.append(el("div", { class: "toolbar", style: "margin:0 0 8px" }, feedToggle));
  const feed = el("div", { class: "card", style: "overflow:auto;max-height:420px" });
  v.append(feed);
  const traceRow = (e) => {
    const kv = (k, val) => val ? el("div", { class: "row", style: "gap:8px" }, el("span", { class: "muted small", style: "min-width:110px" }, k), el("code", { style: "font-size:12px;word-break:break-all" }, String(val))) : null;
    openDrawer((d) => {
      d.append(el("div", { class: "dh" }, ic(ICON.term), el("h3", {}, e.method + " " + e.path)));
      d.append(el("div", { style: "display:flex;flex-direction:column;gap:8px;padding:14px 0" },
        kv("Time", new Date(e.time).toLocaleString()),
        kv("Status", e.status + (e.err ? "  " + e.err : "")),
        kv("S3 action", e.action),
        kv("Duration", e.durMs + " ms"),
        kv("Size", e.bytes ? fmtSize(e.bytes) : "0"),
        kv("Access key", e.accessKey || "anon"),
        kv("Client IP", e.ip),
        kv("Cache", e.cache),
        kv("Request ID", e.reqId)));
      if (e.err) d.append(el("p", { class: "muted small" }, "The request was rejected — the S3 error code above is what the client received. Common causes: AccessDenied (policy/IAM), SignatureDoesNotMatch (clock skew or wrong secret), NoSuchKey, QuotaExceeded, SlowDown (rate limit)."));
    });
  };
  const loadFeed = async () => {
    let rows;
    try { rows = await (await api("GET", "/gostore/admin/v1/activity", { query: { limit: "80" } })).json(); }
    catch { return; }
    if (!Array.isArray(rows)) return;
    const tb = el("tbody");
    for (const e of rows) {
      if (feedErrOnly && e.status < 400) continue;
      const cls = e.status >= 400 ? "warn" : "ok";
      tb.append(el("tr", { class: "clk", onclick: () => traceRow(e) },
        el("td", { class: "muted", style: "white-space:nowrap" }, new Date(e.time).toLocaleTimeString()),
        el("td", {}, el("span", { class: "pill" }, e.method)),
        el("td", {}, el("code", { style: "font-size:11.5px" }, e.path)),
        el("td", {}, el("span", { class: "pill " + cls }, String(e.status)), e.err ? el("span", { class: "muted small" }, " " + e.err) : null, e.cache === "HIT" ? el("span", { class: "pill ok", style: "margin-left:4px" }, "cache") : null),
        el("td", { class: "num muted" }, e.bytes ? fmtSize(e.bytes) : ""),
        el("td", { class: "muted", style: "white-space:nowrap" }, e.durMs + " ms"),
        el("td", { class: "muted" }, e.accessKey || "anon"),
        el("td", { class: "muted" }, e.ip || "")));
    }
    feed.innerHTML = "";
    feed.append(el("table", {}, el("thead", {}, el("tr", {},
      ...["Time", "Method", "Path", "Status", "Size", "Took", "Key", "IP"].map((h) => el("th", {}, h)))), tb));
  };
  await loadFeed();
  pollTimers.push(setInterval(loadFeed, 4000));
  const row = el("div", { class: "toolbar" });
  row.append(el("button", { onclick: async (e) => {
    e.target.disabled = true;
    try { const rep = await (await must(await api("POST", "/gostore/admin/v1/scanner/run"))).json(); toast(`Scan: ${rep.objectsExpired} expired, ${rep.noncurrentVersionsExpired} versions, ${rep.multipartUploadsAborted} uploads aborted`, "ok"); }
    catch (err) { toast(err.message, "err"); } e.target.disabled = false;
  } }, ic(ICON.clock), "Run lifecycle scan"));
  if (j.mode === "erasure") row.append(el("button", { onclick: async (e) => {
    e.target.disabled = true;
    try { const rep = await (await must(await api("POST", "/gostore/admin/v1/heal"))).json(); toast(`Heal: ${rep.objectsHealed}/${rep.objectsScanned} objects, ${rep.shardsRewritten} shards`, "ok"); }
    catch (err) { toast(err.message, "err"); } e.target.disabled = false;
  } }, ic(ICON.refresh), "Run heal"));
  v.append(row);
}

/* ============================ docs ============================ */
function viewDocs(v, id) {
  const d = DOCS.find((x) => x.id === id) || DOCS[0];
  v.innerHTML = ""; v.className = "wrap";

  const back = el("div", { class: "docs-back" },
    ic(ICON.arrowLeft), "Back to console");
  back.onclick = () => go(lastConsoleRoute || "dashboard");
  v.append(back);

  pageHeader(v, "Documentation", "Everything you need to connect to and operate gostore.");

  const shell = el("div", { class: "docs-shell" });
  const toc = el("div", { class: "docs-toc" });
  for (const grp of DOC_GROUPS) {
    const items = DOCS.filter((x) => x.group === grp);
    if (!items.length) continue;
    toc.append(el("div", { class: "grp" }, grp));
    for (const it of items) {
      const a = el("a", { class: it.id === d.id ? "active" : "" }, it.title);
      a.onclick = () => go("docs/" + it.id);
      toc.append(a);
    }
  }
  const content = el("div", { class: "docs-content" });
  const prose = el("div", { class: "prose" });
  prose.append(el("h2", {}, d.title));
  d.body(prose, { origin: location.origin, region: SERVER.region || REGION, ak: session.ak });
  content.append(prose);

  // prev / next within the doc order
  const idx = DOCS.indexOf(d);
  const foot = el("div", { class: "toolbar", style: "justify-content:space-between;margin-top:44px;border-top:1px solid var(--border);padding-top:18px" });
  foot.append(idx > 0 ? el("button", { class: "ghost", onclick: () => go("docs/" + DOCS[idx - 1].id) }, "← " + DOCS[idx - 1].title) : el("span"));
  foot.append(idx < DOCS.length - 1 ? el("button", { class: "ghost", onclick: () => go("docs/" + DOCS[idx + 1].id) }, DOCS[idx + 1].title + " →") : el("span"));
  content.append(foot);

  shell.append(toc, content);
  v.append(shell);
  content.scrollIntoView({ block: "nearest" });
}
const P = (t) => el("p", {}, t);
const UL = (...items) => { const u = el("ul"); items.forEach((i) => u.append(el("li", { html: i }))); return u; };
function TBL(head, rows) {
  const tb = el("tbody");
  rows.forEach((r) => tb.append(el("tr", {}, ...r.map((c) => el("td", { html: c })))));
  return el("div", { class: "card", style: "overflow:hidden;margin:14px 0" }, el("table", {}, el("thead", {}, el("tr", {}, ...head.map((h) => el("th", {}, h)))), tb));
}

const DOCS = [
  { id: "getting-started", group: "Get started", icon: ICON.book, title: "Getting started", body: (c, x) => {
    c.append(P("gostore is an S3-compatible object storage server. Anything that speaks the Amazon S3 API — the AWS CLI, the AWS SDKs, MinIO's mc, s3fs, rclone, Cyberduck — works against it. This console is served by the same process as the API."));
    c.append(el("h3", {}, "1. Your endpoint & credentials"));
    c.append(TBL(["Setting", "Value"], [
      ["Endpoint URL", `<code>${x.origin}</code>`],
      ["Region", `<code>${x.region}</code>`],
      ["Addressing style", "<b>path-style</b> — virtual-host style is not enabled by default"],
      ["Signature", "AWS Signature Version 4"],
      ["Access key", `<code>${x.ak}</code> (this session)`],
      ["Secret key", "the one you signed in with — the console never displays it"],
    ]));
    c.append(callout("HTTPS", "For production either put a TLS terminator (Caddy, nginx, your PaaS) in front, or let gostore do it: set <code>GOSTORE_TLS_DOMAIN=your.host</code> and <code>GOSTORE_ADDRESS=:443</code> and it fetches + renews a Let's Encrypt cert itself (see the Server configuration doc). SDKs refuse to send credentials over plain HTTP.", "warn"));
    c.append(el("h3", {}, "2. Create a bucket and upload"));
    c.append(P("From this console: Buckets → Create bucket, then open it and drag files (or a whole folder) in — files over 16&nbsp;MiB upload as a multipart transfer (parts in parallel, each retried on failure); a dropped folder keeps its structure as key prefixes. Open any object → <b>Preview</b> to play video/audio (streamed via range requests) or view images, PDFs and text inline, or <b>Edit</b> a small text/JSON/config object in place and save it back. From the CLI:"));
    c.append(codeBlock(
`aws --endpoint-url ${x.origin} --region ${x.region} \\
  s3 mb s3://my-bucket
echo "hello gostore" > hello.txt
aws --endpoint-url ${x.origin} s3 cp hello.txt s3://my-bucket/
aws --endpoint-url ${x.origin} s3 ls s3://my-bucket
aws --endpoint-url ${x.origin} s3 cp s3://my-bucket/hello.txt -`, "bash", "shell"));
    c.append(el("h3", {}, "3. Next steps"));
    c.append(UL(
      "<a onclick=\"location.hash='#/docs/connect'\">Connect an SDK</a> — code for JS, Python, Go, CLI, mc",
      "<b>Serve media directly:</b> open a bucket → Settings → <b>Public access → Make public</b>, then anyone can load <code>" + x.origin + "/&lt;bucket&gt;/&lt;key&gt;</code> in a <code>&lt;video&gt;</code>/<code>&lt;img&gt;</code> tag. Add the one-click CORS rule for cross-origin playback.",
      "<a onclick=\"location.hash='#/docs/presigned'\">Presigned URLs</a> — share private objects without credentials",
      "<a onclick=\"location.hash='#/docs/iam'\">IAM & policies</a> — users, service accounts, scoped access",
      "<a onclick=\"location.hash='#/docs/versioning'\">Versioning</a>, <a onclick=\"location.hash='#/docs/object-lock'\">Object Lock</a>, <a onclick=\"location.hash='#/docs/lifecycle'\">Lifecycle</a>, <a onclick=\"location.hash='#/docs/replication'\">Replication</a>",
    ));
  }},

  { id: "connect", group: "Get started", icon: ICON.code, title: "Connect an SDK", body: (c, x) => {
    c.append(P("The pattern is always the same: point the S3 client at a custom endpoint, force path-style addressing, and use SigV4 with your access/secret key. Pick your language."));

    c.append(el("h3", {}, "AWS CLI"));
    c.append(codeBlock(
`aws configure set aws_access_key_id ${x.ak}
aws configure set aws_secret_access_key <SECRET>
aws configure set default.region ${x.region}
aws configure set default.s3.addressing_style path
# every command then just needs --endpoint-url:
aws --endpoint-url ${x.origin} s3 ls
aws --endpoint-url ${x.origin} s3api list-buckets`, "bash", "shell"));
    c.append(P("Or set it once in <code>~/.aws/config</code>:"));
    c.append(codeBlock(
`[profile gostore]
region = ${x.region}
s3 =
    addressing_style = path
    endpoint_url = ${x.origin}
s3api =
    endpoint_url = ${x.origin}`, "bash", "ini"));

    c.append(el("h3", {}, "JavaScript / TypeScript — @aws-sdk/client-s3 (v3)"));
    c.append(codeBlock(
`import { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const s3 = new S3Client({
  endpoint: "${x.origin}",
  region: "${x.region}",
  forcePathStyle: true,
  credentials: { accessKeyId: "${x.ak}", secretAccessKey: process.env.GOSTORE_SECRET },
});

await s3.send(new PutObjectCommand({ Bucket: "my-bucket", Key: "a.txt", Body: "hi" }));
const out = await s3.send(new GetObjectCommand({ Bucket: "my-bucket", Key: "a.txt" }));
console.log(await out.Body.transformToString());

const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: "my-bucket", Key: "a.txt" }), { expiresIn: 3600 });`, "js", "javascript"));

    c.append(el("h3", {}, "Python — boto3"));
    c.append(codeBlock(
`import boto3
s3 = boto3.client(
    "s3",
    endpoint_url="${x.origin}",
    region_name="${x.region}",
    aws_access_key_id="${x.ak}",
    aws_secret_access_key="SECRET",
    config=boto3.session.Config(s3={"addressing_style": "path"}, signature_version="s3v4"),
)
s3.put_object(Bucket="my-bucket", Key="a.txt", Body=b"hi")
print(s3.get_object(Bucket="my-bucket", Key="a.txt")["Body"].read())
url = s3.generate_presigned_url("get_object", Params={"Bucket": "my-bucket", "Key": "a.txt"}, ExpiresIn=3600)`, "python", "python"));

    c.append(el("h3", {}, "Go — aws-sdk-go-v2"));
    c.append(codeBlock(
`cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithRegion("${x.region}"),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("${x.ak}", "SECRET", "")),
)
s3c := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("${x.origin}")
    o.UsePathStyle = true
})
_, _ = s3c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("my-bucket"), Key: aws.String("a.txt"), Body: strings.NewReader("hi")})`, "go", "go"));

    c.append(el("h3", {}, "MinIO client (mc)"));
    c.append(codeBlock(
`mc alias set gs ${x.origin} ${x.ak} SECRET
mc mb gs/my-bucket
mc cp ./file.zip gs/my-bucket/
mc ls gs/my-bucket
mc cat gs/my-bucket/file.zip | sha256sum`, "bash", "shell"));
    c.append(callout("mc admin", "gostore does not implement MinIO's encrypted <code>mc admin</code> RPC. Manage users/policies from this console or the native admin API (see <a onclick=\"location.hash='#/docs/admin-api'\">Admin API</a>).", ""));

    c.append(el("h3", {}, "rclone"));
    c.append(codeBlock(
`rclone config create gs s3 provider Other \\
  access_key_id ${x.ak} secret_access_key SECRET \\
  endpoint ${x.origin} region ${x.region} force_path_style true
rclone copy ./data gs:my-bucket/data`, "bash", "shell"));
  }},

  { id: "presigned", group: "Get started", icon: ICON.link, title: "Presigned URLs", body: (c, x) => {
    c.append(P("A presigned URL embeds a time-limited SigV4 signature in the query string, so anyone can GET (or PUT) that one object without credentials. gostore verifies the signature and the expiry."));
    c.append(el("h3", {}, "From the console"));
    c.append(P("Open any object → <b>Share</b> tab → choose an expiry → <b>Generate link</b>. Max 7 days."));
    c.append(el("h3", {}, "From an SDK"));
    c.append(codeBlock(
`# aws cli
aws --endpoint-url ${x.origin} s3 presign s3://my-bucket/report.pdf --expires-in 3600`, "bash", "shell"));
    c.append(codeBlock(
`// JS v3
const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: "b", Key: "k" }), { expiresIn: 900 });
// upload target:
const putUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: "b", Key: "k" }), { expiresIn: 900 });`, "js", "javascript"));
    c.append(callout("How it verifies", "gostore checks <code>X-Amz-Algorithm=AWS4-HMAC-SHA256</code>, recomputes the signature over the canonical request with <code>UNSIGNED-PAYLOAD</code> and <code>SignedHeaders=host</code>, and rejects the request once <code>X-Amz-Date + X-Amz-Expires</code> has passed.", ""));
  }},

  { id: "operations", group: "Reference", icon: ICON.layers, title: "Supported operations", body: (c) => {
    c.append(P("The S3 API surface gostore implements. Anything not listed returns <code>NotImplemented</code> or is accepted-and-ignored."));
    c.append(el("h3", {}, "Service & bucket"));
    c.append(TBL(["Operation", "Notes"], [
      ["ListBuckets", "GET /"],
      ["CreateBucket / DeleteBucket / HeadBucket", "delete requires empty bucket unless <code>x-amz-force-delete</code>"],
      ["GetBucketLocation", ""],
      ["Get/Put/DeleteBucketPolicy", "AWS policy JSON, with Principal"],
      ["Get/Put/DeleteBucketTagging", ""],
      ["Get/Put/DeleteBucketCors", "drives OPTIONS preflight + response headers"],
      ["Get/PutBucketVersioning", "Enabled / Suspended"],
      ["Get/PutObjectLockConfiguration", "<code>?object-lock</code>, bucket default retention"],
      ["Get/Put/DeleteBucketLifecycleConfiguration", "Expiration, NoncurrentVersionExpiration, AbortIncompleteMultipartUpload"],
      ["Get/Put/DeleteBucketReplication", "native JSON shape (not the AWS XML)"],
      ["Get/PutBucketNotificationConfiguration", "webhook targets, native JSON"],
      ["Get/Put/DeleteBucketWebsite", "static-site hosting: <code>?website</code> with IndexDocument/ErrorDocument; a query-less GET of <code>/</code> or <code>dir/</code> then serves the index, a miss the error doc. Pairs with a public-read policy + <code>GOSTORE_TLS_DOMAIN</code> for HTTPS — no reverse proxy."],
      ["Get/PutBucketCompression", "gostore extra: <code>?compression</code> <code>{enabled:bool}</code> — transparent zstd compression at rest for new objects (erasure, non-SSE, single-part; already-compressed content-types skipped). Stored bytes shrink 2–5× for logs/JSON/text; the S3 ETag stays the plaintext md5."],
    ]));
    c.append(el("h3", {}, "Object"));
    c.append(TBL(["Operation", "Notes"], [
      ["PutObject", "incl. <code>aws-chunked</code> streaming; <code>x-amz-server-side-encryption: AES256</code>; conditional <code>If-None-Match: *</code> / <code>If-None-Match: &quot;etag&quot;</code> / <code>If-Match: &quot;etag&quot;</code> → 412 (optimistic concurrency)"],
      ["POST /{bucket} (POST Object)", "browser form upload (<code>multipart/form-data</code>) with a base64 <code>policy</code> + SigV4 signature; supports <code>starts-with</code>, <code>eq</code>, <code>content-length-range</code> conditions, <code>${filename}</code>, <code>success_action_redirect</code>/<code>_status</code>. Upload straight from a web page with no backend proxy."],
      ["Append (<code>x-amz-write-offset-bytes: N</code> on PutObject)", "appends the body iff <code>N</code> equals the current object size, else <code>409 InvalidWriteOffset</code>; returns <code>x-amz-object-size</code>. Concurrency-safe (optimistic — a racing append 409s and retries). Read-modify-write, so the target caps at <code>GOSTORE_APPEND_MAX</code> (64 MiB) — rotate beyond that. Non-versioned buckets only. MinIO / non-Express S3 don't have this."],
      ["GetObject / HeadObject", "Range, If-Match / If-None-Match / If-*-Since, <code>?versionId</code>; small hot objects served from RAM (<code>x-gostore-cache: HIT</code>)"],
      ["Per-object TTL", "gostore extra: on PutObject, <code>X-Gostore-Expires</code> (RFC3339) or <code>X-Gostore-Expire-After</code> (<code>72h</code>, <code>7d</code>, <code>2w</code>…) — the object 404s and is deleted after that instant, no lifecycle rule needed"],
      ["DeleteObject / DeleteObjects", "versioned delete adds a marker; <code>x-amz-bypass-governance-retention</code>"],
      ["CopyObject / UploadPartCopy", "<code>x-amz-metadata-directive</code>"],
      ["ListObjectsV2 / ListObjects / ListObjectVersions", "prefix, delimiter, pagination"],
      ["CreateMultipartUpload … CompleteMultipartUpload", "full multipart, min part 5 MiB"],
      ["GET /{bucket}/{key}?w=&h=&fit=&format=&q=", "gostore extra: on-the-fly image render — <code>w</code>/<code>h</code> px, <code>fit=contain|cover</code> (cover centre-crops), <code>format=jpeg|png</code>, <code>q</code> 1–100. <code>?preview[=N]</code> is the legacy longest-side form. Result is cached in RAM per transform. Needs <code>s3:GetObject</code>."],
      ["Get/Put/DeleteObjectTagging", ""],
      ["Get/PutObjectRetention, Get/PutObjectLegalHold", "GOVERNANCE / COMPLIANCE / legal hold"],
    ]));
  }},

  { id: "iam", group: "Access control", icon: ICON.shield, title: "IAM & policies", body: (c, x) => {
    c.append(P("gostore has its own identity system: a root credential (from <code>GOSTORE_ROOT_USER/PASSWORD</code>), named users, and service accounts. State is JSON replicated across the volumes — no external database."));
    c.append(el("h3", {}, "Users & service accounts"));
    c.append(UL(
      "<b>User</b> — an access/secret key pair with one or more attached policies. Create from <a onclick=\"location.hash='#/keys'\">Access Keys</a> or the admin API.",
      "<b>Service account</b> — a child credential of a user (or root). Inherits the parent's policies, optionally narrowed by an inline session policy (intersection).",
      "<b>Root</b> — bypasses all policy checks. Use it to bootstrap, then create scoped users.",
    ));
    c.append(el("h3", {}, "Canned policies"));
    c.append(el("div", { class: "optbl" }, ...[
      ["readwrite", "s3:* on everything"], ["readonly", "Get / List only"], ["writeonly", "Put / multipart only"],
      ["consoleAdmin", "s3:* + admin:* — full console access"], ["diagnostics", "admin:ServerInfo / StorageInfo / HealthInfo"],
    ].map(([n, d]) => el("div", {}, el("code", {}, n), " — " + d))));
    c.append(el("h3", {}, "Custom policy language"));
    c.append(P("A subset of AWS IAM / bucket-policy syntax: <code>Version</code>, <code>Statement[]</code> with <code>Effect</code>, <code>Action</code> / <code>NotAction</code>, <code>Resource</code>, <code>Principal</code> (bucket policies), and <code>Condition</code> (<code>StringEquals</code>, <code>StringLike</code>, <code>IpAddress</code>, …). <code>*</code> and <code>?</code> wildcards. An explicit <code>Deny</code> always wins."));
    c.append(codeBlock(
`{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::team-*", "arn:aws:s3:::team-*/*"] },
    { "Effect": "Deny",
      "Action": ["s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::team-archive/*"] }
  ]
}`, "json", "policy.json"));
    c.append(codeBlock(
`# create a custom policy, then a user bound to it
curl -s -X PUT "${x.origin}/gostore/admin/v1/policies?name=team-rw" \\
  --aws-sigv4 "aws:amz:${x.region}:s3" --user "$AK:$SK" \\
  -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \\
  --data-binary @policy.json
curl -s -X PUT "${x.origin}/gostore/admin/v1/users" \\
  --aws-sigv4 "aws:amz:${x.region}:s3" --user "$AK:$SK" \\
  -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \\
  -d '{"accessKey":"alice","secretKey":"alicesecret1","policies":["team-rw"]}'`, "bash", "shell"));
    c.append(el("h3", {}, "STS — temporary credentials"));
    c.append(P("<code>POST /</code> with <code>Action=AssumeRole</code> (SigV4-signed by an existing key) returns short-lived credentials carrying your effective policy, optionally narrowed by an inline <code>Policy</code> param. <code>DurationSeconds</code> 900–43200."));
    c.append(codeBlock(
`aws --endpoint-url ${x.origin} sts assume-role \\
  --role-arn arn:aws:iam::gostore:role/any --role-session-name s1 \\
  --duration-seconds 3600`, "bash", "shell"));
  }},

  { id: "versioning", group: "Data management", icon: ICON.layers, title: "Versioning", body: (c, x) => {
    c.append(P("When a bucket is versioned, every PUT keeps the previous version and a DELETE (without a version id) just writes a <i>delete marker</i>. Nothing is lost until you delete a specific version."));
    c.append(el("h3", {}, "Enable it"));
    c.append(codeBlock(
`aws --endpoint-url ${x.origin} s3api put-bucket-versioning \\
  --bucket my-bucket --versioning-configuration Status=Enabled`, "bash", "shell"));
    c.append(P("Or in the console: open the bucket → <b>Settings</b> → Versioning → Enabled."));
    c.append(el("h3", {}, "Work with versions"));
    c.append(codeBlock(
`# list every version + delete marker
aws --endpoint-url ${x.origin} s3api list-object-versions --bucket my-bucket

# read a specific version
aws --endpoint-url ${x.origin} s3api get-object \\
  --bucket my-bucket --key a.txt --version-id <VID> out.txt

# add a delete marker (object "disappears" from GET, versions kept)
aws --endpoint-url ${x.origin} s3api delete-object --bucket my-bucket --key a.txt

# permanently remove one version
aws --endpoint-url ${x.origin} s3api delete-object \\
  --bucket my-bucket --key a.txt --version-id <VID>`, "bash", "shell"));
    c.append(UL(
      "The response headers <code>x-amz-version-id</code> and <code>x-amz-delete-marker</code> tell you what happened.",
      "<b>Suspended</b> keeps existing versions but new writes overwrite the <code>null</code> version.",
      "Available on the single-disk and erasure backends.",
    ));
  }},

  { id: "object-lock", group: "Data management", icon: ICON.lock, title: "Object Lock (WORM)", body: (c, x) => {
    c.append(P("Object Lock protects individual object <i>versions</i> from deletion or overwrite for a period of time (retention) or indefinitely (legal hold). It requires versioning and must be turned on at bucket creation."));
    c.append(el("h3", {}, "Create a locked bucket"));
    c.append(codeBlock(
`aws --endpoint-url ${x.origin} s3api create-bucket \\
  --bucket vault --object-lock-enabled-for-bucket`, "bash", "shell"));
    c.append(P("From the console: Buckets → Create bucket → Object Lock: <i>Enabled</i>."));
    c.append(el("h3", {}, "Retention modes"));
    c.append(TBL(["Mode", "Behaviour"], [
      ["GOVERNANCE", "delete/overwrite refused, <b>unless</b> the caller sends <code>x-amz-bypass-governance-retention: true</code> and has the <code>s3:BypassGovernanceRetention</code> permission"],
      ["COMPLIANCE", "absolute — no one, including root, can delete or shorten the retention until it expires"],
      ["Legal hold", "ON/OFF flag, independent of retention; blocks deletion while ON"],
    ]));
    c.append(codeBlock(
`# put a 30-day GOVERNANCE retention on a version
aws --endpoint-url ${x.origin} s3api put-object-retention \\
  --bucket vault --key q4.pdf \\
  --retention '{"Mode":"GOVERNANCE","RetainUntilDate":"2026-12-31T00:00:00Z"}'

# legal hold
aws --endpoint-url ${x.origin} s3api put-object-legal-hold \\
  --bucket vault --key q4.pdf --legal-hold Status=ON`, "bash", "shell"));
    c.append(callout("Erasure backend", "Object Lock works on both backends. COMPLIANCE retention can be extended but never shortened or removed.", "tip"));
  }},

  { id: "lifecycle", group: "Data management", icon: ICON.clock, title: "Lifecycle (ILM)", body: (c, x) => {
    c.append(P("Lifecycle rules expire objects automatically. A background scanner (hourly by default, <code>GOSTORE_SCAN_INTERVAL</code>) walks each bucket and applies its enabled rules. You can also trigger a pass from Monitoring → <i>Run lifecycle scan</i>."));
    c.append(el("h3", {}, "Rule types"));
    c.append(UL(
      "<b>Expiration</b> — delete objects older than N <code>Days</code> (or past a <code>Date</code>), filtered by prefix. On versioned buckets this adds a delete marker.",
      "<b>NoncurrentVersionExpiration</b> — permanently delete non-current versions older than N days.",
      "<b>AbortIncompleteMultipartUpload</b> — abort multipart uploads started more than N days ago.",
    ));
    c.append(codeBlock(
`<LifecycleConfiguration>
  <Rule>
    <ID>expire-logs</ID>
    <Status>Enabled</Status>
    <Filter><Prefix>logs/</Prefix></Filter>
    <Expiration><Days>30</Days></Expiration>
  </Rule>
  <Rule>
    <ID>tidy-uploads</ID>
    <Status>Enabled</Status>
    <Filter><Prefix></Prefix></Filter>
    <AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload>
  </Rule>
</LifecycleConfiguration>`, "xml", "lifecycle.xml"));
    c.append(codeBlock(
`aws --endpoint-url ${x.origin} s3api put-bucket-lifecycle-configuration \\
  --bucket my-bucket --lifecycle-configuration file://lifecycle.json`, "bash", "shell"));
    c.append(callout("Object-locked objects", "The scanner skips any object version that is protected by retention or legal hold.", ""));
  }},

  { id: "replication", group: "Data management", icon: ICON.branch, title: "Replication", body: (c, x) => {
    c.append(P("Replication asynchronously copies object writes and deletes to a destination — another bucket on this server, or a remote S3-compatible endpoint (signed with its own credentials). Best-effort: 3 retries, then logged."));
    c.append(el("h3", {}, "Configure (native JSON)"));
    c.append(codeBlock(
`[
  {
    "id": "to-backup",
    "prefix": "important/",
    "destBucket": "backup",
    "destEndpoint": "",            // empty = a bucket on THIS server
    "deleteReplication": true
  },
  {
    "id": "offsite",
    "prefix": "",
    "destBucket": "dr-bucket",
    "destEndpoint": "https://s3.us-west-2.amazonaws.com",
    "destRegion": "us-west-2",
    "destAccessKey": "AKIA...",
    "destSecretKey": "..."
  }
]`, "json", "replication.json"));
    c.append(codeBlock(
`curl -s -X PUT "${x.origin}/my-bucket?replication" \\
  --aws-sigv4 "aws:amz:${x.region}:s3" --user "$AK:$SK" \\
  -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \\
  --data-binary @replication.json`, "bash", "shell"));
    c.append(P("Or paste the JSON in the bucket's <b>Settings → Replication</b> editor."));
    c.append(callout("Secrets", "<code>GET ?replication</code> masks <code>destSecretKey</code> as <code>***</code>; re-saving with <code>***</code> keeps the stored value. There is no persistent retry queue yet.", "warn"));
  }},

  { id: "encryption", group: "Data management", icon: ICON.lock, title: "Encryption at rest (SSE-S3)", body: (c, x) => {
    c.append(P("Send <code>x-amz-server-side-encryption: AES256</code> on a PUT and gostore stores the object encrypted: a per-object AES-256 data key, wrapped by a local master key, encrypting the bytes in 64 KiB AES-GCM chunks. GET / HEAD / Range decrypt transparently."));
    c.append(codeBlock(
`aws --endpoint-url ${x.origin} s3api put-object \\
  --bucket my-bucket --key secret.bin --body ./secret.bin \\
  --server-side-encryption AES256

# JS v3
new PutObjectCommand({ Bucket: "b", Key: "k", Body: buf, ServerSideEncryption: "AES256" })`, "bash", "shell"));
    c.append(UL(
      "The <code>ETag</code> stays the MD5 of the <i>plaintext</i>; the reported object size is the plaintext size.",
      "Master key (local mode): <code>GOSTORE_KMS_MASTER_KEY</code> (base64 of 32 bytes) or auto-generated to <code>.gostore.sys/kms/master.key</code>.",
      "<b>External KMS</b>: set <code>GOSTORE_KMS_VAULT_ADDR</code> + <code>GOSTORE_KMS_VAULT_TOKEN</code> (+ <code>GOSTORE_KMS_VAULT_KEY</code>, default <code>gostore</code>) and per-object data keys are wrapped/unwrapped by HashiCorp Vault's Transit engine — the master key never enters the gostore process and Vault owns rotation. Legacy locally-wrapped objects still decrypt (auto-detected by a <code>vault:</code> prefix). <code>/gostore/admin/v1/info</code> reports <code>kms</code>.",
      "Set default encryption per request; a bucket-level default and SSE-C are not implemented yet. On the erasure backend, single-part PUT only.",
    ));
  }},

  { id: "admin-api", group: "Reference", icon: ICON.term, title: "Admin API", body: (c, x) => {
    c.append(P("A native JSON admin API under <code>/gostore/admin/v1/</code>. Every call is SigV4-signed and requires the <code>admin:*</code> permission (the <code>consoleAdmin</code> policy, or root). This console uses it."));
    c.append(TBL(["Method & path", "Body / query", "Purpose"], [
      ["GET /gostore/admin/v1/info", "—", "mode, drives, capacity, counts"],
      ["GET /gostore/admin/v1/users", "—", "list users"],
      ["PUT /gostore/admin/v1/users", "<code>{accessKey,secretKey,policies[]}</code>", "create/update a user"],
      ["POST /gostore/admin/v1/users/status", "<code>{accessKey,status}</code>", "enable / disable"],
      ["DELETE /gostore/admin/v1/users?accessKey=", "—", "delete a user (+ its service accounts)"],
      ["GET / PUT / DELETE /gostore/admin/v1/policies?name=", "policy JSON", "manage custom policies"],
      ["GET /gostore/admin/v1/service-accounts?parentUser=", "—", "list"],
      ["POST /gostore/admin/v1/service-accounts", "<code>{parentUser?,accessKey?,secretKey?,policy?}</code>", "create (returns the secret once)"],
      ["DELETE /gostore/admin/v1/service-accounts?accessKey=", "—", "delete"],
      ["POST /gostore/admin/v1/heal", "—", "reconstruct missing/corrupt shards (erasure)"],
      ["POST /gostore/admin/v1/scanner/run", "—", "run one scan pass now (lifecycle + usage + heal sample)"],
      ["GET /gostore/admin/v1/scrub", "—", "deep-scrub progress (running, objectsScanned, objectsRepaired, unrecoverable)"],
      ["POST /gostore/admin/v1/scrub", "—", "force a full deep scrub now (verify + repair every object)"],
      ["GET/POST /gostore/admin/v1/readonly", "<code>{enabled:bool}</code>", "read-only mode — reject every write with <code>503 ServerReadOnly</code> while still serving reads. Entered automatically when write quorum is impossible (auto-clears); a manual hold does not."],
      ["POST /gostore/admin/v1/snapshot?bucket=X", "—", "record the version of every live object now (bucket versioning required). Returns <code>{id, objects, bytes}</code>."],
      ["GET /gostore/admin/v1/snapshots?bucket=X", "—", "list snapshots for a bucket"],
      ["POST /gostore/admin/v1/snapshot/restore?bucket=X&id=Y[&dryRun=1]", "—", "roll the whole bucket back to snapshot Y — non-destructive (each rollback is a new version; newer objects get a delete marker). <code>dryRun=1</code> returns the plan only."],
      ["DELETE /gostore/admin/v1/snapshot?bucket=X&id=Y", "—", "delete a snapshot manifest"],
      ["GET /gostore/admin/v1/cluster", "—", "per-peer up/down as seen from this node (circuit-breaker view, kept fresh by a 15s monitor) + backend health"],
      ["GET /gostore/admin/v1/audit?limit=N&after=SEQ", "—", "tamper-evident audit log: every successful mutation as a hash-chained entry, also written to <code>&lt;vol0&gt;/.gostore.sys/audit/audit-YYYYMMDD.jsonl</code>"],
      ["GET /gostore/admin/v1/audit/verify", "—", "walk the chain; reports <code>{entries, intact, brokenAtSeq}</code> — any edited or removed entry breaks it"],
      ["GET /gostore/admin/v1/datausage", "—", "per-bucket object counts &amp; byte totals from the last scan"],
      ["GET /gostore/admin/v1/du?bucket=X&amp;prefix=P/", "—", "storage used by one folder and its immediate sub-folders (from the last scan): <code>{self, folders}</code>"],
      ["GET/PUT /gostore/admin/v1/backup", "<code>{enabled, tier, intervalHours, prefix?}</code>", "scheduled self-backup: mirror every object to a remote S3 tier (<code>GOSTORE_TIER_&lt;NAME&gt;</code>) on a fixed cadence. Incremental (skips objects the tier already holds at the same size), single-flight, survives restarts."],
      ["POST /gostore/admin/v1/backup/run", "—", "run the self-backup once, now (returns <code>202 {started:true}</code>)"],
      ["GET /gostore/admin/v1/whoami", "—", "<b>any authenticated key</b>: your identity, effective policies, admin?"],
      ["POST /gostore/admin/v1/users/rotate-secret", "<code>{accessKey, secretKey?}</code>", "give an existing user a fresh secret (old one dies immediately)"],
      ["POST /gostore/admin/v1/buckets/empty?bucket=X", "—", "delete every object (all versions) without deleting the bucket"],
      ["GET /gostore/admin/v1/activity?limit=N", "—", "last N HTTP requests as a trace: method, path, status, S3 action, error code, cache result, key, IP, request id, duration — no external audit sink needed"],
      ["GET /gostore/admin/v1/pool", "—", "erasure-set layout + any running decommission/rebalance"],
      ["POST /gostore/admin/v1/pool/decommission?set=N", "—", "drain set N onto the others, then it can be removed"],
      ["POST /gostore/admin/v1/pool/rebalance", "—", "relocate objects that no longer hash to the set they live on"],
    ]));
    c.append(el("h3", {}, "Not under /admin — no auth"));
    c.append(TBL(["Method & path", "Purpose"], [
      ["GET /gostore/metrics", "Prometheus exposition (request counts, capacity, per-bucket usage). Open unless <code>GOSTORE_METRICS_TOKEN</code> is set (then send <code>Authorization: Bearer &lt;token&gt;</code>)."],
      ["GET /gostore/health/persistence", "is the data volume persistent? bucket/user counts"],
      ["PUT/POST /gostore/ingest/{bucket}/{key}", "write-only upload with an ingest token (<code>Authorization: Bearer gik_…</code> or <code>X-Gostore-Ingest-Key</code>) instead of SigV4. Prefix-scoped, no expiry. A key ending in <code>/</code> auto-dates the filename. Mint keys in bucket Settings → Ingest keys, or <code>POST /gostore/admin/v1/ingest-keys?bucket=X {prefix,label}</code>."],
    ]));
    c.append(el("h3", {}, "Per-bucket quota (S3-style sub-resource)"));
    c.append(TBL(["Method & path", "Body", "Purpose"], [
      ["GET /{bucket}?quota", "—", "current <code>{bytes, objects}</code> (0 = no limit)"],
      ["PUT /{bucket}?quota", "<code>{\"bytes\":N,\"objects\":M}</code>", "set a soft quota (checked against the last scan)"],
      ["DELETE /{bucket}?quota", "—", "remove the quota"],
    ]));
    c.append(el("h3", {}, "Example — curl with SigV4"));
    c.append(codeBlock(
`AK=${x.ak}; SK=<secret>
curl -s "${x.origin}/gostore/admin/v1/info" \\
  --aws-sigv4 "aws:amz:${x.region}:s3" --user "$AK:$SK" \\
  -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" | jq`, "bash", "shell"));
    c.append(el("h3", {}, "Health (no auth)"));
    c.append(codeBlock(
`curl ${x.origin}/gostore/health/live       # process up
curl ${x.origin}/gostore/health/ready      # storage has quorum
curl ${x.origin}/gostore/health/selftest   # full write/read/verify/delete round-trip`, "bash", "shell"));
  }},

  { id: "cluster", group: "Operations", icon: ICON.branch, title: "Multi-node cluster", body: (c, x) => {
    c.append(P("gostore can spread one erasure set across several nodes. Each node runs the same binary; disks from every node form a single pool. A namespace write-lock needs a quorum (N/2+1) of nodes to grant it."));
    c.append(el("h3", {}, "Start each node"));
    c.append(codeBlock(
`export GOSTORE_CLUSTER_SECRET=a-shared-secret     # same on every node
export GOSTORE_ROOT_USER=admin GOSTORE_ROOT_PASSWORD=change-me-32chars

# node1:
GOSTORE_CLUSTER_SELF=http://node1:9000 gostore server \\
  http://node1:9000/data/d{1...4} http://node2:9000/data/d{1...4}

# node2 — identical args, only SELF changes:
GOSTORE_CLUSTER_SELF=http://node2:9000 gostore server \\
  http://node1:9000/data/d{1...4} http://node2:9000/data/d{1...4}`, "bash", "shell"));
    c.append(UL(
      "8 disks → 4 data + 4 parity → the pool survives losing a whole node.",
      "Inter-node traffic is under <code>/gostore/internal/</code>, authed with a bearer token — run it on a private network or behind mTLS.",
      "Point clients at any node's S3 endpoint.",
    ));
    c.append(el("h3", {}, "What's shared automatically"));
    c.append(UL(
      "IAM (users, policies, service accounts) and per-bucket config are stored as objects under <code>.gostore.sys/</code> — erasure-coded across every disk of every node, read back majority-wins — and reloaded on each node every 30s. Create a user on any node; it works on all of them.",
      "A write that reaches quorum but not every disk is queued for background re-heal (<code>GOSTORE_MRF_INTERVAL</code>, default 5m).",
      "A replaced or freshly-added disk is detected at startup and repopulated by an automatic heal pass.",
      "Namespace locks retry with backoff up to 10s; if a lock holder loses quorum mid-operation, its context is cancelled so the write aborts instead of racing.",
      "Capacity management: <code>POST /gostore/admin/v1/pool/decommission?set=N</code> drains a set onto the others so its disks can be pulled; <code>/pool/rebalance</code> evens out placement after a change. Both run online and survive a restart.",
    ));
    c.append(callout("Current limits", "Membership is static — restart every node with the same topology to add or remove nodes. Small disk RPCs share one multiplexed connection per peer; bulk shard transfers use their own HTTP stream. Capacity changes are handled by decommission + rebalance (Admin API → <code>/pool</code>).", "warn"));
  }},

  { id: "config", group: "Operations", icon: ICON.term, title: "Server configuration", body: (c) => {
    c.append(P("All configuration is environment variables passed to the <code>gostore server</code> process. No config file, no database."));
    c.append(el("h3", {}, "Persistence — read this first"));
    c.append(P("Everything gostore stores — object data, object metadata, buckets, <b>and every access key / user / policy you create</b> — lives on the volume directory (<code>/data</code> in the Docker image). There is no external database."));
    c.append(callout("If keys or buckets vanish after a restart",
      "Your volume is not persistent. On Docker / a PaaS you must mount a <b>named volume or a persistent disk</b> to <code>/data</code> and keep that same mount across redeploys — an anonymous volume or the container's writable layer is wiped when the container is replaced. gostore logs <code>data volume was EMPTY at startup</code> on every boot when this is the case, and the Dashboard shows a warning. Compose: <code>volumes: [gostore-data:/data]</code>. EasyPanel/Coolify: add a persistent volume mapped to <code>/data</code>.", "warn"));
    c.append(el("h3", {}, "Core"));
    c.append(TBL(["Variable", "Purpose"], [
      ["GOSTORE_ROOT_USER / GOSTORE_ROOT_PASSWORD", "root credential (password &ge; 8 chars)"],
      ["GOSTORE_REGION", "region reported to clients (default <code>us-east-1</code>)"],
      ["GOSTORE_ADDRESS / GOSTORE_CONSOLE_ADDRESS", "listen addresses (default <code>:9000</code> / <code>:9001</code>)"],
      ["GOSTORE_DOMAIN", "comma-list of domains to enable virtual-host-style addressing"],
      ["GOSTORE_KMS_MASTER_KEY", "base64 of 32 bytes for SSE-S3 (local mode); auto-generated to <code>.gostore.sys/kms/master.key</code> if unset"],
      ["GOSTORE_KMS_VAULT_ADDR / _TOKEN / _KEY", "when set, per-object data keys are wrapped by HashiCorp Vault's Transit engine instead of the local master key"],
      ["GOSTORE_LOG_LEVEL / GOSTORE_LOG_JSON", "<code>debug|info|warn|error</code> / <code>1</code> for JSON logs"],
      ["GOSTORE_NO_CONTENT_TYPE_SNIFF", "set to <code>1</code> to stop guessing an object's Content-Type from its key extension when the client sent none / <code>application/octet-stream</code>"],
      ["GOSTORE_METRICS_TOKEN", "when set, <code>GET /gostore/metrics</code> requires <code>Authorization: Bearer &lt;token&gt;</code> (otherwise the endpoint is open)"],
      ["GOSTORE_RATE_LIMIT / GOSTORE_RATE_BURST", "requests/sec per access key (per IP for anonymous), and bucket size — over the limit gets <code>503 SlowDown</code>. Unset = no limit."],
      ["GOSTORE_IDLE_TIMEOUT", "kill a request whose body stalls this long (default <code>90s</code>, <code>0</code> disables) so a hung upload can't pin an object's lock"],
      ["GOSTORE_LIST_MAX_KEYS", "ceiling on keys one namespace walk holds in memory (default <code>2000000</code>); past it, listing is truncated — use a prefix"],
    ]));
    c.append(el("h3", {}, "Background work & erasure tuning"));
    c.append(TBL(["Variable", "Default", "Purpose"], [
      ["GOSTORE_SCAN_INTERVAL", "1h", "cadence of the scanner (lifecycle + data-usage + heal sample)"],
      ["GOSTORE_INLINE_MAX", "131072", "objects up to this many bytes are stored inside xl.meta; <code>0</code> disables"],
      ["GOSTORE_MRF_INTERVAL", "5m", "cadence of the partial-write re-heal worker"],
      ["GOSTORE_LIST_CACHE_TTL", "15s", "per-bucket listing cache lifetime; <code>0</code> disables (re-walk every page)"],
      ["GOSTORE_FSYNC", "on", "fsync the parent directory after every object/metadata commit so it survives a power loss; set <code>0</code> to trade that for throughput"],
      ["GOSTORE_OBJ_CACHE", "134217728", "byte budget for the in-RAM hot-object cache (whole-object GET/HEAD of small current-version objects); <code>0</code> disables"],
      ["GOSTORE_OBJ_CACHE_MAX_OBJ", "1048576", "largest object eligible for the RAM cache"],
      ["GOSTORE_OBJ_CACHE_TTL", "10s", "how long a cached object may be served before re-fetch (bounds staleness after a write on another cluster node)"],
      ["GOSTORE_APPEND_MAX", "67108864", "largest size an append target (<code>x-amz-write-offset-bytes</code>) may reach — append is read-modify-write"],
      ["GOSTORE_SCRUB_INTERVAL", "168h", "cadence of the guaranteed full deep scrub (verify + repair every object's shards); <code>0</code> disables. Status at <code>GET /gostore/admin/v1/scrub</code>."],
      ["GOSTORE_HEAL_CONCURRENCY", "2", "max objects repaired at once across all heal paths (read-repair, MRF, scanner sample, deep scrub); <code>0</code> = unlimited"],
      ["GOSTORE_HEAL_SLEEP", "0", "cooldown after each repaired object so background heal never starves client I/O"],
      ["GOSTORE_MULTIPART_TTL", "168h", "abort incomplete multipart uploads older than this even with no lifecycle rule; <code>0</code> disables"],
      ["GOSTORE_DISK_OP_TIMEOUT", "30s", "hard cap on each fast/metadata disk op so a hung disk can't stall a write past its namespace lock; <code>0</code> disables"],
      ["GOSTORE_ALLOW_FORMAT_MISMATCH", "0", "set <code>1</code> to start even when a disk's on-disk position (set/disk index) disagrees with the configured order — only during a deliberate topology migration"],
      ["GOSTORE_MAX_INFLIGHT_BYTES", "536870912", "cap on total request-body bytes in flight for writes; over it new writes get <code>503 SlowDown</code>"],
      ["GOSTORE_MEM_LIMIT_BYTES", "0", "when set, heap-in-use above this sheds new writes with 503 for ~5s (memory backpressure); <code>0</code> disables"],
      ["GOSTORE_MEM_LIMIT / GOMEMLIMIT", "auto (cgroup)", "soft Go memory ceiling (bytes or <code>256MiB</code>/<code>1g</code>). Unset, gostore reads the container's cgroup limit and sets it to ~90% so the GC returns RAM to the OS on a small VPS. A 3-min scavenger also frees idle heap after a spike."],
      ["GOSTORE_DEDUP", "0", "set <code>1</code> for content-addressed dedup: byte-identical objects (erasure, non-SSE) share one set of shard files under <code>.gostore.sys/cas/&lt;sha256&gt;/</code>; unreferenced blobs are removed by a mark-and-sweep GC on the deep-scrub cadence. Server-side copies of identical content become near-free."],
      ["GOSTORE_TIER_&lt;NAME&gt;", "—", "register a remote cold-storage tier: <code>endpoint|region|bucket|access|secret[|prefix]</code>. A lifecycle <code>&lt;Transition&gt;&lt;Days&gt;N&lt;/Days&gt;&lt;StorageClass&gt;name&lt;/StorageClass&gt;&lt;/Transition&gt;</code> rule then moves cold objects there (local stub, transparent GET rehydration, remote-delete on DELETE)."],
    ]));
    c.append(el("h3", {}, "Built-in HTTPS (Let's Encrypt)"));
    c.append(P("Set <code>GOSTORE_TLS_DOMAIN</code> and gostore obtains and renews its own certificate — no nginx/Caddy in front. Point <code>GOSTORE_ADDRESS</code> at <code>:443</code>, publish port 80 as well (ACME HTTP-01 challenge + a redirect to https). MinIO can't do this."));
    c.append(TBL(["Variable", "Purpose"], [
      ["GOSTORE_TLS_DOMAIN", "comma-list of hostnames to get a cert for (e.g. <code>s3.example.com</code>)"],
      ["GOSTORE_TLS_EMAIL", "optional ACME account email (renewal notices)"],
      ["GOSTORE_TLS_HTTP_ADDR", "address for the ACME challenge / redirect listener (default <code>:80</code>)"],
    ]));
    c.append(callout("Certs are cached", "under <code>&lt;volume&gt;/.gostore.sys/acme/</code>, so they persist across restarts. Keep that volume persistent (see above) or you'll re-issue on every deploy and hit Let's Encrypt rate limits.", "warn"));
    c.append(el("h3", {}, "Cluster"));
    c.append(TBL(["Variable", "Purpose"], [
      ["GOSTORE_CLUSTER_SELF", "this node's own base URL, e.g. <code>http://node1:9000</code>"],
      ["GOSTORE_CLUSTER_SECRET", "shared bearer token for inter-node RPC — identical on every node"],
    ]));
    c.append(callout("Anonymous mode", "<code>GOSTORE_ALLOW_ANONYMOUS=1</code> accepts unsigned requests and skips authorization. Debugging only — never in production.", "warn"));
  }},

  { id: "limits", group: "Operations", icon: ICON.info, title: "Limits & compatibility", body: (c) => {
    c.append(P("gostore targets functional parity with MinIO for single-node deployments. Known gaps:"));
    c.append(UL(
      "<b>SSE-KMS / SSE-C</b> — only SSE-S3. Multipart SSE on the erasure backend: single-part only.",
      "<b>IAM groups</b> and <b>OIDC / LDAP</b> STS federation.",
      "<b>Lifecycle</b> storage-class transitions (only expiration).",
      "<b>Replication</b> has no persistent retry queue (best-effort, 3 tries).",
      "<b>Cluster</b>: static membership (topology changes need a restart); decommission/rebalance are online but replay object writes rather than moving raw shards.",
      "Virtual-host-style addressing is off by default (set <code>GOSTORE_DOMAIN</code> to enable). SigV2 is not supported — SigV4 only.",
    ));
    c.append(callout("What definitely works", "Buckets, objects, multipart, range & conditional requests, presigned URLs, versioning, Object Lock, lifecycle expiry, tagging, bucket policies (incl. anonymous), CORS, SSE-S3, event webhooks, replication, IAM users/service-accounts/policies (cluster-wide via the object layer), STS AssumeRole, erasure coding with interleaved-bitrot protection, inline small objects, MRF + scanner + new-disk auto-heal, per-bucket data-usage stats, per-bucket listing cache, and a multi-node cluster.", "tip"));
  }},
];

/* ============================ boot ============================ */
async function verify() {
  const r = await api("GET", "/");
  if (!r.ok) throw new Error(exErr(await r.text(), r.status));
}
async function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#whoami").textContent = session.ak;
  try { SERVER = await (await api("GET", "/gostore/admin/v1/info")).json(); } catch { SERVER = {}; }
  // Setting location.hash fires 'hashchange' -> render(). Only render()
  // directly when the hash is already set, so boot never renders twice.
  if (!location.hash) location.hash = "#/dashboard";
  else render();
}
$("#loginBtn").onclick = async () => {
  const ak = $("#ak").value.trim(), sk = $("#sk").value.trim();
  $("#loginErr").textContent = "";
  const b = $("#loginBtn"); b.disabled = true; b.textContent = "Signing in…";
  session.set(ak, sk);
  try { await verify(); await showApp(); }
  catch (e) { session.clear(); $("#loginErr").textContent = e.message; }
  finally { b.disabled = false; b.textContent = "Sign in"; }
};
$("#sk").addEventListener("keydown", (e) => e.key === "Enter" && $("#loginBtn").click());
$("#logout").onclick = () => { session.clear(); location.hash = ""; location.reload(); };
$("#menuBtn").onclick = () => $("#sidenav").classList.toggle("open");

if (session.ak && session.sk) api("GET", "/").then((r) => (r.ok ? showApp() : session.clear()));
