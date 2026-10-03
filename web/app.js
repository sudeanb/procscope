/* ProcScope dashboard: live over WebSocket (/stream) or replay (?replay=url).
   Render-only state machine: no framework, no build step. */
"use strict";

const feedBody = document.querySelector("#feed tbody");
const treeEl = document.querySelector("#tree");
const topBody = document.querySelector("#top tbody");
const heat = document.querySelector("#heat");
const heatLegend = document.querySelector("#heat-legend");
const filterInput = document.querySelector("#filter");
const statusEl = document.querySelector("#status");

const FEED_MAX = 250;
const BUCKETS = 60;
const TOP_SYSCALLS = 12;

let events = [];            // rolling event log (filtered)
let counts = new Map();     // syscall name -> {n, us}
let buckets = [];           // per-second totals, newest last
let topNames = [];          // heatmap legend

function passFilter(f, ev) {
  if (!f) return true;
  for (const term of f.split(/\s+/).filter(Boolean)) {
    const [k, v] = term.split("=", 2);
    if (v === undefined) continue;
    if (k === "pid" && String(ev.pid) !== v) return false;
    if (k === "comm" && !glob(v, ev.comm || "")) return false;
    if (k === "syscall" && ev.syscall && !glob(v, ev.syscall.name)) return false;
    if (k === "path" && !(ev.path && matchPath(v, ev.path))) return false;
  }
  return true;
}
function glob(p, s) {
  const re = new RegExp("^" + p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
  return re.test(s);
}
function matchPath(p, s) {
  if (!p.includes("*")) return s.endsWith("/" + p) || s === p;
  return glob(p.replace(/\*\*/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\u0000/g, ".*"), s);
}

function render() {
  const f = filterInput.value.trim();
  // feed
  const rows = [];
  for (let i = events.length - 1; i >= 0 && rows.length < FEED_MAX; i--) {
    const ev = events[i];
    if (!passFilter(f, ev)) continue;
    const sc = ev.syscall;
    const t = new Date(ev.ts).toISOString().slice(11, 23);
    if (!sc) {
      rows.push(`<tr><td>${t}</td><td>${ev.pid}</td><td>${ev.comm}</td><td>${ev.kind}</td><td></td><td></td><td></td></tr>`);
      continue;
    }
    const res = sc.ret < 0 ? `${sc.ret} ${sc.err || ""}` : sc.ret;
    const cls = sc.ret < 0 ? "err" : "ok";
    rows.push(`<tr><td>${t}</td><td>${ev.pid}</td><td>${ev.comm}</td>` +
      `<td>${sc.name}(${sc.args.slice(0, 3).join(", ")})</td>` +
      `<td class="${cls}">${res}</td><td class="num">${sc.dur_us}</td>` +
      `<td class="path">${ev.path || ""}</td></tr>`);
  }
  feedBody.innerHTML = rows.join("");

  // top syscalls
  const sorted = [...counts.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, TOP_SYSCALLS);
  topBody.innerHTML = sorted.map(([name, s]) =>
    `<tr><td>${name}</td><td class="num">${s.n.toLocaleString()}</td><td class="num">${(s.us / s.n).toFixed(1)}</td></tr>`).join("");

  drawHeat(sorted.map(([n]) => n));
}

function drawHeat(names) {
  topNames = names;
  const ctx = heat.getContext("2d");
  const { width: W, height: H } = heat;
  ctx.clearRect(0, 0, W, H);
  if (!names.length || !buckets.length) return;
  const cols = Math.min(BUCKETS, Math.max(buckets.length, 1));
  const cw = W / BUCKETS, ch = H / names.length;
  let max = 0;
  for (const b of buckets) for (const n of names) max = Math.max(max, (b[n] || 0));
  names.forEach((name, row) => {
    buckets.forEach((b, col) => {
      const v = b[name] || 0;
      const x = W - (buckets.length - col) * cw;
      const a = max ? Math.sqrt(v / max) : 0;
      ctx.fillStyle = v ? `rgba(88,166,255,${0.15 + 0.85 * a})` : "#12181f";
      ctx.fillRect(x, row * ch, cw - 0.5, ch - 0.5);
    });
  });
  heatLegend.textContent = names.slice(0, 8).join(" · ");
}

function ingest(ev) {
  events.push(ev);
  if (events.length > 4000) events.splice(0, events.length - 4000);
  const sec = Math.floor(Date.now() / 1000);
  const last = buckets[buckets.length - 1];
  if (!last || last.sec !== sec) {
    buckets.push({ sec, ...(ev.syscall ? { [ev.syscall.name]: 1 } : {}) });
    if (buckets.length > BUCKETS) buckets.shift();
  } else if (ev.syscall) {
    last[ev.syscall.name] = (last[ev.syscall.name] || 0) + 1;
  }
  if (ev.syscall) {
    const s = counts.get(ev.syscall.name) || { n: 0, us: 0 };
    s.n++; s.us += ev.syscall.dur_us;
    counts.set(ev.syscall.name, s);
  }
  if (ev.kind === "spawn" || ev.kind === "exit") renderTree(ev);
  render();
}

// process tree: maintained from /tree polls (serve mode) or spawn/exit events
const procs = new Map();
function renderTree() {
  const rows = [...procs.values()].sort((a, b) => a.pid - b.pid).slice(0, 40);
  treeEl.innerHTML = rows.map(p =>
    `<li>${p.ppid ? p.pid + " ← " + p.ppid : p.pid} ${p.comm}<span class="cpu">${p.cpu_pct.toFixed(1)}% ${(p.rss_kb / 1024).toFixed(0)}MB</span></li>`).join("");
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const f = filterInput.value.trim();
  const ws = new WebSocket(`${proto}://${location.host}/stream${f ? "?filter=" + encodeURIComponent(f) : ""}`);
  statusEl.textContent = "connecting…"; statusEl.className = "status connecting";
  ws.onopen = () => { statusEl.textContent = "live"; statusEl.className = "status ok"; };
  ws.onmessage = (m) => { try { ingest(JSON.parse(m.data)); } catch {} };
  ws.onclose = () => {
    statusEl.textContent = "disconnected — retrying"; statusEl.className = "status down";
    setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();
}

setInterval(() => { // tree polling is a second, coarse channel
  fetch("/tree").then(r => r.json()).then(rows => {
    procs.clear();
    for (const p of rows) procs.set(p.pid, p);
    renderTree();
  }).catch(() => {});
}, 2000);

const replay = new URLSearchParams(location.search).get("replay");
if (replay) {
  statusEl.textContent = "replay"; statusEl.className = "status ok";
  fetch(replay).then(r => r.json()).then(list => {
    let i = 0;
    const tick = () => {
      const batchEnd = Math.min(i + 40, list.length);
      for (; i < batchEnd; i++) ingest(list[i]);
      if (i < list.length) setTimeout(tick, 16);
    };
    tick();
  });
} else {
  filterInput.addEventListener("change", () => { events = []; connect(); });
  connect();
}
