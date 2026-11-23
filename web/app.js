/* Offline PCAP receiving station — vanilla JS frontend.
 *
 * State model: one selected capture, one selected session. All rendering is
 * driven by the JSON the FastAPI backend returns; this file holds no
 * reassembly logic of its own.
 */
"use strict";

const state = {
  captures: new Map(),   // capture_id -> overview
  selectedCapture: null,
  selectedSession: null, // full session detail payload
  samples: [],
  activeTab: "messages",
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};

function toast(message, isError = false) {
  const t = $("#toast");
  t.textContent = message;
  t.className = isError ? "toast error" : "toast";
  t.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { t.hidden = true; }, 3200);
}

async function api(path, options) {
  const resp = await fetch(path, options);
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (_) { /* no body */ }
    throw new Error(detail);
  }
  return resp.json();
}

// ---------------------------------------------------------------------- //
// Bootstrap
// ---------------------------------------------------------------------- //
async function init() {
  $("#file-input").addEventListener("change", onUpload);
  $("#refresh-samples").addEventListener("click", loadSamples);
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal-backdrop").addEventListener("click", (e) => {
    if (e.target === $("#modal-backdrop")) closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });
  await Promise.all([loadSamples(), refreshCaptures()]);
}

async function loadSamples() {
  const container = $("#sample-list");
  container.innerHTML = "";
  container.appendChild(el("span", "spinner"));
  try {
    const data = await api("/api/samples");
    state.samples = data.samples;
    container.innerHTML = "";
    if (!state.samples.length) {
      container.appendChild(el("p", "muted", "samples/ 目录下没有 PCAP。"));
      return;
    }
    for (const sample of state.samples) {
      const item = el("div", "sample-item");
      item.appendChild(el("div", "name", sample.file));
      item.appendChild(el("div", "meta", "内置可视化样例"));
      item.addEventListener("click", () => loadSample(sample.file, item));
      container.appendChild(item);
    }
  } catch (err) {
    container.innerHTML = "";
    container.appendChild(el("p", "muted", "样例加载失败：" + err.message));
  }
}

async function loadSample(name, node) {
  document.querySelectorAll(".sample-item").forEach((n) => n.classList.remove("active"));
  node.classList.add("active");
  try {
    const overview = await api(`/api/samples/load/${encodeURIComponent(name)}`, { method: "POST" });
    await refreshCaptures();
    selectCapture(overview.capture_id);
    toast(`已加载样例 ${name}`);
  } catch (err) {
    toast(err.message, true);
  }
}

async function onUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  try {
    const overview = await api("/api/captures/upload", { method: "POST", body: form });
    await refreshCaptures();
    selectCapture(overview.capture_id);
    toast(`已分析 ${file.name}`);
  } catch (err) {
    toast("上传失败：" + err.message, true);
  } finally {
    event.target.value = "";
  }
}

async function refreshCaptures() {
  const data = await api("/api/captures");
  state.captures.clear();
  const container = $("#capture-list");
  container.innerHTML = "";
  if (!data.captures.length) {
    container.appendChild(el("p", "muted", "尚未加载任何抓包。"));
    return;
  }
  for (const cap of data.captures) {
    state.captures.set(cap.capture_id, cap);
    const item = el("div", "capture-item");
    if (cap.capture_id === state.selectedCapture) item.classList.add("active");
    item.appendChild(el("div", "name", cap.file_name));
    const meta = `${cap.packet_count} 包 · ${cap.stats.session_count} 会话 · ${cap.stats.message_count} 消息`;
    item.appendChild(el("div", "meta", meta));
    item.addEventListener("click", () => selectCapture(cap.capture_id));
    container.appendChild(item);
  }
}

async function selectCapture(captureId) {
  state.selectedCapture = captureId;
  state.selectedSession = null;
  document.querySelectorAll(".capture-item").forEach((n) => n.classList.remove("active"));
  await refreshCaptures();
  const cap = state.captures.get(captureId);
  if (!cap || !cap.sessions.length) {
    renderEmpty("该抓包中没有可识别的 TCP 会话。");
    return;
  }
  await openSession(captureId, cap.sessions[0].session_id);
}

async function openSession(captureId, sessionId) {
  try {
    state.selectedSession = await api(
      `/api/captures/${captureId}/sessions/${sessionId}`
    );
    state.selectedSession._captureId = captureId;
    renderSession();
  } catch (err) {
    toast("会话加载失败：" + err.message, true);
  }
}

function renderEmpty(text) {
  $("#empty-state").hidden = false;
  $("#session-view").hidden = true;
  $("#empty-state").querySelector("h2").textContent = text;
}

// ---------------------------------------------------------------------- //
// Session rendering
// ---------------------------------------------------------------------- //
function renderSession() {
  $("#empty-state").hidden = true;
  const view = $("#session-view");
  view.hidden = false;
  view.innerHTML = "";
  const detail = state.selectedSession;
  const summary = detail.session;

  view.appendChild(renderSessionHead(summary));
  view.appendChild(renderStats(summary, detail.messages));
  view.appendChild(renderTabs());

  const panel = el("div", "tab-panel");
  view.appendChild(panel);
  renderTabContent(panel);
}

function renderSessionHead(summary) {
  const head = el("div", "session-head");
  head.appendChild(el("div", "ep", summary.endpoint || `${summary.src} → ${summary.dst}`));
  const badges = el("div", "badges");
  const addBadge = (cls, label) => {
    const b = el("span", `badge ${cls}`);
    b.appendChild(el("span", "dot"));
    b.append(label);
    badges.appendChild(b);
  };
  addBadge(summary.complete ? "good" : "warn", summary.complete ? "状态：完整" : "状态：有缺口");
  addBadge("info", `实例 #${summary.instance}`);
  addBadge("info", `${summary.packet_count} 个 TCP 报文`);
  if (summary.is_tls) addBadge("crit", "TLS（不解密）");
  if (summary.non_http) addBadge("warn", "非 HTTP 数据");
  if (summary.conflict_count) addBadge("crit", `重叠冲突 ×${summary.conflict_count}`);
  if (summary.has_gap) addBadge("warn", "存在缺失字节");
  head.appendChild(badges);

  const exportRow = el("div", "export-row");
  const reportBtn = el("button", "btn btn-sm", "导出 JSON 报告");
  reportBtn.addEventListener("click", () => downloadExport("report"));
  const zipBtn = el("button", "btn btn-sm", "导出 ZIP（文件+缺口标记）");
  zipBtn.addEventListener("click", () => downloadExport("zip"));
  exportRow.append(reportBtn, zipBtn);
  head.appendChild(exportRow);

  if (summary.parse_errors && summary.parse_errors.length) {
    const errBox = el("div", "conflict-box");
    errBox.appendChild(el("h4", null, "解析告警"));
    for (const e of summary.parse_errors) errBox.appendChild(el("div", null, e));
    head.appendChild(errBox);
  }
  return head;
}

function renderStats(summary, messages) {
  const row = el("div", "stats-row");
  const tiles = [
    ["请求数", summary.request_count],
    ["响应数", summary.response_count],
    ["消息总数", summary.message_count],
    ["冲突区域", summary.conflict_count],
  ];
  for (const [label, value] of tiles) {
    const tile = el("div", "stat-tile");
    tile.appendChild(el("div", "label", label));
    tile.appendChild(el("div", "value", String(value)));
    row.appendChild(tile);
  }
  return row;
}

function renderTabs() {
  const wrap = el("div", "tabs");
  const tabs = [
    ["messages", "请求 / 响应"],
    ["reassembly", "重组依据"],
    ["packets", `报文 (${state.selectedSession.packets.length})`],
  ];
  for (const [key, label] of tabs) {
    const tab = el("button", "tab" + (state.activeTab === key ? " active" : ""), label);
    tab.addEventListener("click", () => {
      state.activeTab = key;
      renderSession();
    });
    wrap.appendChild(tab);
  }
  return wrap;
}

function renderTabContent(panel) {
  const detail = state.selectedSession;
  if (state.activeTab === "messages") renderMessagesTab(panel, detail);
  else if (state.activeTab === "reassembly") renderReassemblyTab(panel, detail);
  else renderPacketsTab(panel, detail);
}

// ---------------------------------------------------------------------- //
// Messages tab
// ---------------------------------------------------------------------- //
function renderMessagesTab(panel, detail) {
  if (detail.session.is_tls) {
    panel.appendChild(el("p", "muted", detail.session.tls_reason || "TLS 流量不解析。"));
    return;
  }
  const messages = detail.messages;
  if (!messages.length) {
    panel.appendChild(el("p", "muted", "没有可解析的 HTTP 消息。"));
    return;
  }

  // Group into exchanges using the pairs array from the backend.
  const pairs = detail.pairs || [];
  const byKey = new Map(messages.map((m) => [`${m.direction}:${m.index}`, m]));
  if (!pairs.length) {
    for (const m of messages) panel.appendChild(renderExchange([m], detail));
    return;
  }
  // Walk pairs preserving order, grouping each request with its response(s).
  const seen = new Set();
  for (const [reqIdx, respIdx] of pairs) {
    const group = [];
    if (reqIdx !== null) {
      const req = byKey.get(`c2s:${reqIdx}`);
      if (req && !seen.has(req.id)) { group.push(req); seen.add(req.id); }
    }
    if (respIdx !== null) {
      const resp = byKey.get(`s2c:${respIdx}`);
      if (resp && !seen.has(resp.id)) { group.push(resp); seen.add(resp.id); }
    }
    if (group.length) panel.appendChild(renderExchange(group, detail));
  }
  for (const m of messages) {
    if (!seen.has(m.id)) panel.appendChild(renderExchange([m], detail));
  }
}

function renderExchange(group, detail) {
  const wrap = el("div", "exchange");
  const head = el("div", "exchange-head");
  const first = group[0];
  head.appendChild(el("span", "arrow", first.kind === "request" ? "→" : "←"));
  head.appendChild(el("span", "line", group.map((m) => m.start_line).join("  ⇄  ")));
  const anyGap = group.some((m) => m.gap || !m.complete);
  const anyConflict = group.some((m) => m.conflict_impact !== "none");
  if (anyGap) head.appendChild(statusPill("warn", "缺口"));
  if (anyConflict) head.appendChild(statusPill("crit", "冲突"));
  head.addEventListener("click", () => {
    const body = wrap.querySelector(".exchange-body");
    body.hidden = !body.hidden;
  });
  wrap.appendChild(head);

  const body = el("div", "exchange-body");
  for (const msg of group) body.appendChild(renderMessageCard(msg, detail));
  wrap.appendChild(body);
  return wrap;
}

function statusPill(cls, text) {
  const p = el("span", `badge ${cls}`);
  p.appendChild(el("span", "dot"));
  p.append(text);
  return p;
}

function renderMessageCard(msg, detail) {
  const card = el("div", `msg-card ${msg.direction}`);
  const header = el("div", "msg-card-header");
  header.appendChild(el("span", "title", msg.display_title || msg.start_line));
  header.appendChild(el("span", "framing", `定界：${framingLabel(msg.framing)}`));
  if (!msg.complete) header.appendChild(statusPill("warn", "不完整"));
  if (msg.conflict_impact !== "none")
    header.appendChild(statusPill("crit", `冲突影响：${impactLabel(msg.conflict_impact)}`));
  card.appendChild(header);

  const body = el("div", "msg-card-body");
  body.appendChild(renderLengthBars(msg));
  body.appendChild(renderHeaderTable(msg));
  if (msg.chunks && msg.chunks.length) body.appendChild(renderChunks(msg, detail));
  if (msg.conflicts && msg.conflicts.length) body.appendChild(renderConflicts(msg));
  body.appendChild(renderBodyViewer(msg));
  body.appendChild(renderProvenance(msg, detail));
  card.appendChild(body);
  return card;
}

function framingLabel(f) {
  return {
    "content-length": "Content-Length",
    chunked: "分块传输 (chunked)",
    close: "连接关闭 (close-delimited)",
    none: "无响应体 / 无定界",
    unknown: "未知（缺口）",
  }[f] || f;
}

function impactLabel(i) {
  return { header: "头部", body: "消息体", framing: "分块帧", none: "无" }[i] || i;
}

// Horizontal 3-bar length comparison: wire vs reassembled vs decoded.
function renderLengthBars(msg) {
  const wrap = el("div");
  wrap.appendChild(el("h4", null, "长度对比（网络原始 / 重组 / 解压）"));
  const L = msg.lengths;
  const rows = [
    ["wire", "网络原始长度", L.raw_wire, "--series-wire"],
    ["reasm", "重组内容", L.reassembled, "--series-reasm"],
    ["dec", "解压后文件", L.body_decoded, "--series-dec"],
  ];
  const max = Math.max(1, ...rows.map((r) => r[2]));
  const bars = el("div", "length-bars");
  for (const [cls, label, value, token] of rows) {
    const row = el("div", "length-bar-row");
    const lab = el("div", "bar-label");
    const sw = el("span", "swatch");
    sw.style.background = `var(${token})`;
    lab.append(sw, label);
    const track = el("div", "length-track");
    const fill = el("div", `length-fill ${cls}`);
    fill.style.width = `${Math.max(2, (value / max) * 100)}%`;
    track.appendChild(fill);
    row.append(lab, track, el("div", "length-value", `${value} B`));
    bars.appendChild(row);
  }
  wrap.appendChild(bars);
  const note = [];
  if (L.raw_wire > L.reassembled)
    note.push(`网络长度比重组多 ${L.raw_wire - L.reassembled} B（重复/重传报文也计入线上字节）。`);
  if (L.body_decoded > L.body_encoded)
    note.push(`解压后比传输体大 ${L.body_decoded - L.body_encoded} B。`);
  if (msg.gap) note.push("该消息含缺口，长度只覆盖已重组部分。");
  wrap.appendChild(el("div", "length-note", note.join(" ") || "三种长度一致或按编码正常变化。"));
  return wrap;
}

function renderHeaderTable(msg) {
  const table = el("table", "header-table");
  const tbody = el("tbody");
  const firstRow = el("tr");
  firstRow.appendChild(el("th", null, msg.kind === "request" ? "请求行" : "状态行"));
  firstRow.appendChild(el("td", null, msg.start_line));
  tbody.appendChild(firstRow);
  for (const h of msg.headers) {
    const tr = el("tr");
    tr.appendChild(el("th", null, h.name));
    const td = el("td");
    td.appendChild(el("code", null, h.value));
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  return table;
}

function renderChunks(msg, detail) {
  const wrap = el("div");
  wrap.appendChild(el("h4", null, `分块帧（${msg.chunks.length} 个 chunk）`));
  const list = el("div", "chunk-list");
  for (const c of msg.chunks) {
    const row = el("div", "chunk-row");
    row.appendChild(el("span", "idx", `#${c.index}`));
    row.append(`size=${c.size} B`, ` 数据区间 [${c.data_start} .. ${c.data_end})`);
    list.appendChild(row);
  }
  wrap.appendChild(list);
  return wrap;
}

function renderConflicts(msg) {
  const box = el("div", "conflict-box");
  box.appendChild(el("h4", null, `重叠内容冲突（${msg.conflicts.length} 处，双方字节均保留）`));
  for (const c of msg.conflicts) {
    const range = el("div", "meta-item");
    range.appendChild(el("div", "k", `数据偏移 [${c.start} .. ${c.end})，${c.end - c.start} 字节`));
    box.appendChild(range);
    const primary = el("div", "conflict-version");
    primary.appendChild(el("span", "tag", "先到版本"));
    const pcode = el("code", null, c.existing_text || c.existing_hex);
    primary.appendChild(pcode);
    box.appendChild(primary);
    const alt = el("div", "conflict-version");
    alt.appendChild(el("span", "tag", "冲突版本"));
    alt.appendChild(el("code", null, c.alternative_text || c.alternative_hex));
    box.appendChild(alt);
    const src = el("div", "conflict-sources");
    const pFrames = c.existing_sources.map((s) => `#${s.frame_number}`).join(", ");
    const aFrames = c.alternative_sources.map((s) => `#${s.frame_number}`).join(", ");
    src.textContent = `先到报文：${pFrames} ｜ 冲突报文：${aFrames}（点击下方溯源可查看原始报文）`;
    box.appendChild(src);
  }
  return box;
}

function renderBodyViewer(msg) {
  const wrap = el("div");
  wrap.appendChild(el("h4", null, "消息体 / 文件内容"));
  const viewer = el("div", "body-viewer");
  const toolbar = el("div", "body-toolbar");
  const content = el("div", "body-content");

  const hasDecoded = msg.body && msg.body.decoded_b64 && msg.body.decoded_len > 0 &&
    msg.body.encoded_len !== msg.body.decoded_len;
  const modes = [];
  if (hasDecoded) modes.push(["decoded", "解压后文本", msg.body.decoded_text]);
  modes.push(["encoded", "传输体（重组）", msg.body.encoded_text]);
  if (!msg.has_body) {
    content.textContent = "（该消息没有响应体/请求体）";
    viewer.append(toolbar, content);
    wrap.appendChild(viewer);
    return wrap;
  }
  let active = modes[0][0];
  const show = (mode) => {
    active = mode;
    const found = modes.find((m) => m[0] === mode);
    content.textContent = found ? found[2] : "";
    content.classList.toggle("raw", mode === "encoded");
    toolbar.querySelectorAll(".seg-btn").forEach((b) =>
      b.classList.toggle("active", b.dataset.mode === mode));
  };
  for (const [mode, label] of modes) {
    const btn = el("button", "seg-btn", label);
    btn.dataset.mode = mode;
    btn.addEventListener("click", () => show(mode));
    toolbar.appendChild(btn);
  }
  if (msg.decode_error) {
    const err = el("span", "seg-btn", "解压失败：" + msg.decode_error);
    err.style.borderColor = "var(--critical)";
    err.style.color = "var(--critical)";
    toolbar.appendChild(err);
  }
  viewer.append(toolbar, content);
  show(active);
  wrap.appendChild(viewer);
  return wrap;
}

function renderProvenance(msg, detail) {
  const wrap = el("div");
  wrap.appendChild(el("h4", null, `重组溯源（${msg.source_packets.length} 个报文）`));
  const list = el("div", "chunk-list");
  for (const src of msg.source_packets) {
    const row = el("div", "chunk-row clickable");
    row.style.cursor = "pointer";
    row.appendChild(el("span", "idx", `帧 #${src.frame_number}`));
    row.append(`seq=0x${(src.seq >>> 0).toString(16)}`, ` 数据偏移 ${src.mono_start}`);
    row.addEventListener("click", () => openPacket(src.packet_index));
    list.appendChild(row);
  }
  wrap.appendChild(list);
  const hint = el("div", "length-note", "点击任意一行可查看该报文的完整头部与十六进制载荷。");
  wrap.appendChild(hint);
  return wrap;
}

// ---------------------------------------------------------------------- //
// Reassembly tab: block / gap / conflict layout
// ---------------------------------------------------------------------- //
function renderReassemblyTab(panel, detail) {
  const layout = detail.layout;
  panel.appendChild(el("p", "muted",
    "每个色块是一个已重组的数据块（点击查看来源报文）；斜纹区是缺失字节，红线标注重叠冲突位置。"));
  for (const dir of ["c2s", "s2c"]) {
    const d = layout[dir];
    const box = el("div", "layout-direction");
    const h = el("h4");
    const tag = el("span", `dir-tag ${dir}`, dir === "c2s" ? "客户端 → 服务端" : "服务端 → 客户端");
    h.appendChild(tag);
    h.append(` 连续前缀 ${d.contig_end} B` +
      (d.expected_end !== null ? ` ／ FIN 声明 ${d.expected_end} B` : " ／ 未见 FIN"));
    box.appendChild(h);

    const total = Math.max(d.expected_end || 0, d.contig_end,
      ...d.blocks.map((b) => b.end), 1);
    const track = el("div", "segment-track");
    for (const block of d.blocks) {
      const seg = el("div", "seg-block");
      seg.style.left = `${(block.start / total) * 100}%`;
      seg.style.width = `${Math.max(1.5, (block.length / total) * 100)}%`;
      seg.textContent = `${block.length}B`;
      seg.title = `块 [${block.start}..${block.end})，来源报文 ` +
        block.sources.map((s) => `#${s.frame_number}`).join(", ");
      const firstPkt = block.sources[0];
      if (firstPkt) seg.addEventListener("click", () => openPacket(firstPkt.packet_index));
      track.appendChild(seg);
    }
    for (const gap of d.gaps) {
      const g = el("div", "gap-block");
      g.style.left = `${(gap.start / total) * 100}%`;
      g.style.width = `${Math.max(1.5, (gap.length / total) * 100)}%`;
      g.title = `缺口 [${gap.start}..${gap.end})，缺 ${gap.length} B`;
      track.appendChild(g);
    }
    for (const conflict of d.conflicts) {
      const marker = el("div", "conflict-marker");
      marker.style.left = `${(conflict.start / total) * 100}%`;
      marker.title = `冲突 [${conflict.start}..${conflict.end})`;
      track.appendChild(marker);
    }
    box.appendChild(track);
    box.appendChild(el("div", "axis-note",
      `块数 ${d.blocks.length} ｜ 缺口 ${d.gaps.length} ｜ 冲突 ${d.conflicts.length}` +
      (d.fin_seen ? " ｜ 已见 FIN" : "")));
    panel.appendChild(box);
  }

  // Table view (accessibility relief for the chart).
  panel.appendChild(el("h4", null, "块明细（表格视图）"));
  const table = el("table", "packet-table");
  const thead = el("thead");
  const hr = el("tr");
  ["方向", "起始", "结束", "长度", "来源帧"].forEach((t) => hr.appendChild(el("th", null, t)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const dir of ["c2s", "s2c"]) {
    for (const b of layout[dir].blocks) {
      const tr = el("tr");
      tr.appendChild(el("td", null, dir));
      tr.appendChild(el("td", null, String(b.start)));
      tr.appendChild(el("td", null, String(b.end)));
      tr.appendChild(el("td", null, String(b.length)));
      tr.appendChild(el("td", null, b.sources.map((s) => `#${s.frame_number}`).join(", ")));
      tbody.appendChild(tr);
    }
  }
  table.appendChild(tbody);
  panel.appendChild(table);
}

// ---------------------------------------------------------------------- //
// Packets tab
// ---------------------------------------------------------------------- //
function renderPacketsTab(panel, detail) {
  const table = el("table", "packet-table");
  const thead = el("thead");
  const hr = el("tr");
  ["帧", "方向", "标志", "序号 seq", "确认 ack", "载荷长度", "时间"].forEach((t) =>
    hr.appendChild(el("th", null, t)));
  thead.appendChild(hr);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const pkt of detail.packets) {
    const tr = el("tr", "clickable");
    tr.addEventListener("click", () => openPacket(pkt.index));
    tr.appendChild(el("td", null, `#${pkt.frame_number}`));
    const dirTd = el("td");
    dirTd.appendChild(el("span", `dir-pill ${pkt.direction}`, pkt.direction));
    tr.appendChild(dirTd);
    tr.appendChild(el("td", "flag-cell", pkt.flags));
    tr.appendChild(el("td", null, String(pkt.seq)));
    tr.appendChild(el("td", null, String(pkt.ack)));
    tr.appendChild(el("td", null, `${pkt.raw_len} B`));
    tr.appendChild(el("td", null, new Date(pkt.timestamp * 1000).toISOString().substring(11, 23)));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  panel.appendChild(table);
}

// ---------------------------------------------------------------------- //
// Packet modal with hex dump
// ---------------------------------------------------------------------- //
async function openPacket(packetIndex) {
  const captureId = state.selectedSession._captureId;
  const sessionId = state.selectedSession.session.session_id;
  const backdrop = $("#modal-backdrop");
  $("#modal-content").innerHTML = '<span class="spinner"></span>';
  backdrop.hidden = false;
  try {
    const pkt = await api(
      `/api/captures/${captureId}/sessions/${sessionId}/packets/${packetIndex}`
    );
    renderPacketModal(pkt);
  } catch (err) {
    $("#modal-content").textContent = "报文加载失败：" + err.message;
  }
}

function renderPacketModal(pkt) {
  const root = $("#modal-content");
  root.innerHTML = "";
  root.appendChild(el("h3", null, `报文 #${pkt.frame_number}（索引 ${pkt.index}）`));

  const meta = el("div", "meta-grid");
  const items = [
    ["源", pkt.src], ["目的", pkt.dst], ["方向", pkt.direction],
    ["标志", pkt.flags], ["序号", pkt.seq], ["确认号", pkt.ack],
    ["TCP 载荷", `${pkt.raw_len} B`], ["IP 总长", `${pkt.ip_total_len} B`],
  ];
  for (const [k, v] of items) {
    const item = el("div", "meta-item");
    item.appendChild(el("div", "k", k));
    item.appendChild(el("div", "v", String(v)));
    meta.appendChild(item);
  }
  root.appendChild(meta);

  const hexTitle = el("h4", null, `载荷十六进制（${pkt.raw_len} 字节）`);
  root.appendChild(hexTitle);
  const dump = el("div", "hex-dump");
  dump.innerHTML = toHexDump(pkt.payload_hex);
  root.appendChild(dump);
}

function toHexDump(hex) {
  if (!hex) return "<span class='muted'>（无载荷）</span>";
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(hex.slice(i, i + 2));
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hexPart = chunk.map((b) => b.toUpperCase()).join(" ").padEnd(47);
    const ascii = chunk
      .map((b) => {
        const code = parseInt(b, 16);
        return code >= 32 && code < 127 ? String.fromCharCode(code) : "·";
      })
      .join("");
    lines.push(
      `<span class="hex-offset">${off.toString(16).padStart(8, "0")}</span>  ` +
      `${hexPart}  ${escapeHtml(ascii)}`
    );
  }
  return lines.join("\n");
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function closeModal() {
  $("#modal-backdrop").hidden = true;
}

// ---------------------------------------------------------------------- //
// Export
// ---------------------------------------------------------------------- //
function downloadExport(kind) {
  const captureId = state.selectedSession._captureId;
  const url = kind === "zip"
    ? `/api/captures/${captureId}/export/zip`
    : `/api/captures/${captureId}/export/report`;
  // Plain navigation triggers the Content-Disposition download.
  const a = document.createElement("a");
  a.href = url;
  a.download = "";
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast(kind === "zip" ? "正在导出 ZIP（含 .gap 标记）" : "正在导出 JSON 报告");
}

init();
