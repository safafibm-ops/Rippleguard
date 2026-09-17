/* RippleGuard console.
   No framework, no build step, no CDN. The graph is a hand-written
   force-directed SVG renderer so the whole thing works offline. */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const num = (v, d = 1) => (v === null || v === undefined) ? '—' : Number(v).toFixed(d);

const state = { scanId: null, result: null, graph: null, sim: null };

function toast(msg, ms = 6000) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(t._t); t._t = setTimeout(() => (t.hidden = true), ms);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || body.error || `HTTP ${r.status}`);
  return body;
}

/* ------------------------------------------------------------- samples -- */
async function loadSamples() {
  try {
    const { samples } = await api('/api/samples');
    $('#samples').innerHTML = samples.map(s => `
      <button data-sample="${esc(s.id)}">
        <b>${esc(s.label || s.id)}</b><span>${esc(s.note || '')}</span>
      </button>`).join('');
    $$('#samples button').forEach(b => b.onclick = () => {
      const s = samples.find(x => x.id === b.dataset.sample);
      runScan({ files: s.files, source_files: pickSources(s) });
    });
  } catch (e) { /* samples are optional */ }
}

function pickSources(sample) {
  const out = {};
  (sample.source_files || []).forEach(f => { if (sample.files[f]) out[f] = sample.files[f]; });
  return out;
}

/* ---------------------------------------------------------------- scan -- */
async function runScan(payload) {
  $('#run').disabled = true;
  $('#stages-block').hidden = false;
  $('#stages').innerHTML = '<li class="running"><i class="st"></i><span class="sname">Starting</span></li>';
  try {
    const { scan_id } = await api('/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    state.scanId = scan_id;
    await poll(scan_id);
  } catch (e) {
    toast(e.message);
    $('#stages').innerHTML = `<li class="error"><i class="st"></i><span class="sdet">${esc(e.message)}</span></li>`;
  } finally { $('#run').disabled = false; }
}

async function poll(id) {
  for (;;) {
    const s = await api(`/api/scan/${id}/status`);
    renderStages(s.stages);
    if (s.status === 'complete') { await loadResult(id); return; }
    if (s.status === 'error') { toast(s.error || 'Scan failed'); return; }
    await new Promise(r => setTimeout(r, 450));
  }
}

function renderStages(stages) {
  $('#stages').innerHTML = stages.map(s => `
    <li class="${esc(s.state)}"><i class="st"></i>
      <span><span class="sname">${esc(s.name)}</span>
      <span class="sdet">${esc(s.detail)}</span></span></li>`).join('');
}

async function loadResult(id) {
  state.result = await api(`/api/scan/${id}`);
  state.graph = await api(`/api/scan/${id}/graph`);
  $('#welcome').hidden = true;
  $('#tabs').hidden = false;
  renderSources();
  renderOverview();
  renderGraph();
  fillSelectors();
  renderModel();
  show('overview');
}

function renderSources() {
  const r = state.result;
  $('#sources-block').hidden = false;
  $('#sources').innerHTML = r.sources.map(s => `
    <li><span>${esc(s.name)}</span><span class="${esc(s.state)}">${esc(s.state)}</span></li>`).join('');
  const notes = [];
  (r.build_report.degraded || []).forEach(d => notes.push(d));
  if (!r.osv_available) notes.push(
    'OSV was unreachable, so the exploit channel could not be evaluated. ' +
    'Its weight was redistributed. This is NOT a clean bill of health.');
  if (r.build_report.truncated_at_limit) notes.push(
    'Package limit reached; the graph is truncated.');
  $('#degraded').innerHTML = notes.map(esc).join('<br><br>');
}

/* ------------------------------------------------------------ overview -- */
function renderOverview() {
  const r = state.result, s = r.summary;
  $('#tiles').innerHTML = [
    tile(s.portfolio_score, 'Portfolio risk (top 10 avg)', 'trust'),
    tile(s.packages, 'Packages in tree'),
    tile(s.vulnerable_packages, r.osv_available ? 'With a known advisory' : 'Advisories unavailable', 'exploit'),
    tile(s.packages_on_floating_ranges, 'On floating version ranges', 'trust'),
    tile(s.packages_with_install_hooks, 'Run code at install time', 'structure'),
    tile(s.publishing_identities, 'Publishing identities'),
    tile(s.max_depth, 'Max dependency depth'),
    tile(s.top_blast_radius ? num(s.top_blast_radius.blast_radius, 0) : '—',
         'Largest blast radius', 'structure'),
  ].join('');

  const inv = r.rank_inversion;
  $('#inversion-note').textContent = inv.explanation;
  const hl = inv.headline_inversion;
  $('#inversion').innerHTML = `
    <div class="inv-col left"><h4>Ranked by CVSS — what a scanner shows you</h4>
      ${inv.by_cvss.map(x => invRow(x, 'cvss', hl)).join('')}</div>
    <svg id="inv-links"></svg>
    <div class="inv-col right"><h4>Ranked by trust channel — RippleGuard</h4>
      ${inv.by_trust.map(x => invRow(x, 'trust', hl)).join('')}</div>`;
  drawInversionLinks(inv);

  if (hl) {
    const el = document.createElement('div');
    el.className = 'disclaim';
    el.style.margin = '0 16px 16px';
    el.innerHTML = `<b>${esc(hl.name)}</b> carries ${hl.vuln_count === 0
      ? 'no known advisory at all' : `${hl.vuln_count} advisory/advisories`},
      so CVSS ranks it #${hl.cvss_rank}. On the publishing path it ranks
      #${hl.trust_rank}${hl.has_install_hook ? ' — it executes code during install' : ''}
      and it is declared on a <span class="mono">${esc(hl.range_kind)}</span> range.
      That is a ${hl.movement} place difference in what you would work on first.`;
    $('#inversion').after(el);
  }

  $('#blastlist').innerHTML = r.blast_ranking.map(b => `
    <div class="row" data-node="${esc(b.id)}">
      <span class="nm">${esc(b.name)}</span>
      <span class="meta">${b.reached_packages} pkgs${b.reaches_application ? ' · reaches app' : ''}</span>
      <span class="bar b-structure"><i style="width:${b.blast_radius}%"></i></span>
      <span class="meta">${num(b.blast_radius, 0)}</span>
    </div>`).join('') || '<p class="tiny" style="padding:0 16px">No packages resolved.</p>';
  $$('#blastlist .row').forEach(el => el.onclick = () => {
    $('#sim-target').value = el.dataset.node; show('simulate'); runSim();
  });

  $('#maintainers').innerHTML = r.maintainer_risk.map(m => `
    <div class="row" style="cursor:default">
      <span class="nm">${esc(m.maintainer)}</span>
      <span class="meta">${m.packages_in_this_app} here${
        m.packages_in_registry ? ` · ${m.packages_in_registry.toLocaleString()} on npm` : ''}</span>
    </div>`).join('') || '<p class="tiny" style="padding:0 16px">Publisher data unavailable.</p>';
}

const tile = (v, k, accent) =>
  `<div class="tile ${accent ? 'accent-' + accent : ''}">
     <div class="v">${esc(v)}</div><div class="k">${esc(k)}</div></div>`;

function invRow(x, side, hl) {
  const rank = side === 'cvss' ? x.cvss_rank : x.trust_rank;
  const score = side === 'cvss'
    ? (x.cvss ? `CVSS ${num(x.cvss)}` : 'no CVE')
    : num(x.trust_score, 0);
  const isHl = hl && hl.id === x.id;
  return `<div class="inv-row ${isHl ? 'hl' : ''}" data-id="${esc(x.id)}">
    <span class="rk">${rank}</span>
    <span class="nm">${esc(x.name)}</span>
    ${x.has_install_hook ? '<span class="tagh">hook</span>' : ''}
    <span class="sc">${esc(score)}</span></div>`;
}

/* Connector lines between the same package in both columns. */
function drawInversionLinks(inv) {
  const svg = $('#inv-links');
  const host = $('#inversion');
  const rows = new Map();
  $$('.inv-col.left .inv-row').forEach(el => rows.set(el.dataset.id, { l: el }));
  $$('.inv-col.right .inv-row').forEach(el => {
    const e = rows.get(el.dataset.id); if (e) e.r = el;
  });
  const hostBox = host.getBoundingClientRect();
  const svgBox = svg.getBoundingClientRect();
  svg.setAttribute('viewBox', `0 0 ${svgBox.width || 74} ${hostBox.height}`);
  svg.style.height = hostBox.height + 'px';
  let out = '';
  for (const [, { l, r }] of rows) {
    if (!r) continue;
    const a = l.getBoundingClientRect(), b = r.getBoundingClientRect();
    const y1 = a.top - hostBox.top + a.height / 2;
    const y2 = b.top - hostBox.top + b.height / 2;
    const w = svgBox.width || 74;
    const moved = Math.abs(y1 - y2) > 12;
    out += `<path d="M0 ${y1} C ${w * 0.45} ${y1}, ${w * 0.55} ${y2}, ${w} ${y2}"
      fill="none" stroke="${moved ? 'var(--trust)' : 'var(--line)'}"
      stroke-width="${moved ? 1.3 : 1}" opacity="${moved ? 0.75 : 0.35}"/>`;
  }
  svg.innerHTML = out;
}

/* --------------------------------------------------------------- graph -- */
let sim = { nodes: [], links: [], raf: null };

function renderGraph() {
  const svg = $('#graph');
  const data = state.graph;
  $('#graph-note').textContent = data.truncated
    ? `Showing the ${data.nodes.length} highest-scoring nodes of a larger tree.`
    : `${data.nodes.length} nodes, ${data.edges.length} dependency edges. Drag to reposition; click for evidence.`;

  const W = svg.clientWidth || 900, H = 620;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const byId = new Map();
  sim.nodes = data.nodes.map((n, i) => {
    const a = (i / data.nodes.length) * Math.PI * 2;
    const rr = n.kind === 'app' ? 0 : 120 + ((n.depth || 2) * 55) + (i % 7) * 9;
    const o = { ...n, x: W / 2 + Math.cos(a) * rr, y: H / 2 + Math.sin(a) * rr, vx: 0, vy: 0 };
    byId.set(n.id, o); return o;
  });
  sim.links = data.edges.map(e => ({ s: byId.get(e.source), t: byId.get(e.target), ...e }))
    .filter(l => l.s && l.t);

  runForce(W, H);
  paint(svg, W, H);
}

/* Simple spring/repulsion relaxation. O(n^2) is fine at a few hundred nodes. */
function runForce(W, H) {
  const N = sim.nodes;
  for (let step = 0; step < 260; step++) {
    const k = 1 - step / 300;
    for (let i = 0; i < N.length; i++) {
      for (let j = i + 1; j < N.length; j++) {
        const a = N[i], b = N[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy || 0.01;
        if (d2 > 90000) continue;
        const f = 900 / d2;
        const d = Math.sqrt(d2);
        const fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
      }
    }
    for (const l of sim.links) {
      const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - 70) * 0.012;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      l.s.vx += fx; l.s.vy += fy; l.t.vx -= fx; l.t.vy -= fy;
    }
    for (const n of N) {
      n.vx += (W / 2 - n.x) * 0.0035;
      n.vy += (H / 2 - n.y) * 0.0035;
      if (n.kind === 'app') { n.vx *= 0.2; n.vy *= 0.2; }
      n.x += n.vx * k; n.y += n.vy * k;
      n.vx *= 0.82; n.vy *= 0.82;
      n.x = Math.max(24, Math.min(W - 24, n.x));
      n.y = Math.max(24, Math.min(H - 24, n.y));
    }
  }
}

function nodeColor(n) {
  if (n.kind === 'app') return '#e8eef7';
  if (n.trust >= n.exploit) return 'var(--trust)';
  return 'var(--exploit)';
}
function nodeRadius(n) {
  if (n.kind === 'app') return 13;
  return 4 + Math.sqrt(Math.max(n.score, 1)) * 0.75;
}

function paint(svg, W, H, highlight = null) {
  const risky = $('#onlyrisky').checked;
  const visible = new Set(sim.nodes
    .filter(n => !risky || n.kind === 'app' || n.score >= 40)
    .map(n => n.id));

  let out = '<g class="edges">';
  for (const l of sim.links) {
    if (!visible.has(l.s.id) || !visible.has(l.t.id)) continue;
    const on = highlight && highlight.has(l.t.id) && highlight.has(l.s.id);
    out += `<line x1="${l.s.x.toFixed(1)}" y1="${l.s.y.toFixed(1)}"
      x2="${l.t.x.toFixed(1)}" y2="${l.t.y.toFixed(1)}"
      stroke="${on ? 'var(--trust)' : '#253143'}"
      stroke-width="${on ? 1.8 : 0.7}"
      opacity="${on ? 0.95 : 0.4 + l.floatiness * 0.35}"/>`;
  }
  out += '</g><g class="nodes">';
  for (const n of sim.nodes) {
    if (!visible.has(n.id)) continue;
    const r = nodeRadius(n);
    const dim = highlight && !highlight.has(n.id);
    out += `<g class="gn" data-id="${esc(n.id)}" opacity="${dim ? 0.18 : 1}">`;
    if (n.hook) out += `<circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}"
      r="${(r + 3.5).toFixed(1)}" fill="none" stroke="var(--structure)" stroke-width="1.4"/>`;
    out += `<circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="${r.toFixed(1)}"
      fill="${nodeColor(n)}" stroke="#10141c" stroke-width="1"/>`;
    if (n.kind === 'app' || n.score >= 45 || (highlight && highlight.has(n.id)))
      out += `<text x="${(n.x + r + 4).toFixed(1)}" y="${(n.y + 3.5).toFixed(1)}"
        font-size="9.5" fill="#9fabbd" font-family="var(--mono)">${esc(n.label)}</text>`;
    out += '</g>';
  }
  out += '</g>';
  svg.innerHTML = out;
  $$('.gn', svg).forEach(g => g.onclick = () => showDetail(g.dataset.id));
}

$('#onlyrisky').addEventListener('change', () => paint($('#graph'), 900, 620));

/* -------------------------------------------------------------- detail -- */
async function showDetail(id) {
  const box = $('#detail');
  box.innerHTML = '<p class="empty">Loading evidence…</p>';
  try {
    const f = await api(`/api/scan/${state.scanId}/package/${encodeURIComponent(id)}`);
    const ex = await api(`/api/scan/${state.scanId}/explain`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: id, use_llm: true }),
    });
    box.innerHTML = detailHtml(f, ex);
    $('#d-sim').onclick = () => { $('#sim-target').value = id; show('simulate'); runSim(); };
    $('#d-rem').onclick = () => { $('#rem-target').value = id; show('remediate'); runRem(); };
  } catch (e) { box.innerHTML = `<p class="empty">${esc(e.message)}</p>`; }
}

function detailHtml(f, ex) {
  const b = f.score_breakdown;
  const total = b.reduce((s, x) => s + x.points, 0) || 1;
  const seg = (name, cls) => {
    const p = b.find(x => x.factor.startsWith(name));
    return p ? `<i class="${cls}" style="width:${(p.points / total) * 100}%"></i>` : '';
  };
  const d = ex.deterministic;
  return `
    <h3>${esc(f.name)}<span style="color:var(--muted)">@${esc(f.version)}</span></h3>
    <div>
      ${f.direct ? '<span class="tag t-direct">direct</span>' : '<span class="tag">transitive</span>'}
      <span class="tag">${esc(f.scope)}</span>
      ${f.trust.has_install_hook ? '<span class="tag t-hook">install hook</span>' : ''}
      ${f.exploit.vulnerabilities.length ? `<span class="tag t-vuln">${f.exploit.vulnerabilities.length} advisory</span>` : ''}
      <span class="tag t-float">${esc(f.trust.range_kind)}</span>
    </div>
    <div class="scorebar">${seg('Exploit', 's-exploit')}${seg('Trust', 's-trust')}${seg('Structural', 's-structure')}</div>
    <div style="display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted)">
      <span>RippleGuard score</span><span class="mono" style="color:var(--text);font-size:15px">${num(f.rippleguard_score)}</span>
    </div>
    ${f.score_note ? `<p class="tiny" style="color:var(--structure)">${esc(f.score_note)}</p>` : ''}

    <p class="sec-h">Verdict</p>
    <p style="font-size:12.5px;margin:0">${esc(d.verdict)}</p>
    ${ex.llm && ex.llm.ok ? `<p style="font-size:12.5px;color:#b4bfcf;margin-top:8px">${esc(ex.llm.text)}
      <span class="tiny" style="display:block">Written by ${esc(ex.llm.model)} from the evidence bundle only; ${esc(ex.llm.grounding)}.</span></p>`
      : `<p class="tiny">${ex.llm_enabled ? 'Model narration unavailable' + (ex.llm && ex.llm.error ? ` (${esc(ex.llm.error)})` : '') + '; the evidence below is generated deterministically.'
        : 'Set ANTHROPIC_API_KEY to add a written narration. Everything below is computed without a model.'}</p>`}

    <p class="sec-h">Trust channel — ${num(f.trust_score)}</p>
    <ul class="breakdown">${f.trust.components.map(c => `
      <li><div class="f"><span>${esc(c.factor)}</span><span class="pts">+${num(c.points)}</span></div>
      <div class="ev">${esc(c.evidence)}</div></li>`).join('')}</ul>

    <p class="sec-h">Exploit channel — ${num(f.exploit_score)}</p>
    ${f.exploit.components.length ? `<ul class="breakdown">${f.exploit.components.map(c => `
      <li><div class="f"><span>${esc(c.factor)}</span><span class="pts">+${num(c.points)}</span></div>
      <div class="ev">${esc(c.evidence)}</div></li>`).join('')}</ul>`
      : `<p class="tiny">${esc(f.exploit.note || 'No advisory matched.')}</p>`}
    ${f.exploit.vulnerabilities.map(v => `<p class="tiny"><span class="mono">${esc(v.id)}</span>
      ${v.cve ? esc(v.cve) + ' · ' : ''}CVSS ${num(v.cvss)} ${esc(v.severity_label || '')}
      ${v.fixed_version ? '· fixed in ' + esc(v.fixed_version) : '· no published fix'}<br>${esc(v.summary)}</p>`).join('')}

    <p class="sec-h">Structural position — ${num(f.structural_score)}</p>
    <table class="kv">
      <tr><td>Depth from application</td><td class="mono">${esc(f.metrics.depth)}</td></tr>
      <tr><td>Dependents in this app</td><td class="mono">${esc(f.metrics.in_app_dependents)}</td></tr>
      <tr><td>Dependents on the registry</td><td class="mono">${f.metrics.ecosystem_dependents ? f.metrics.ecosystem_dependents.toLocaleString() : '—'}</td></tr>
      <tr><td>PageRank share</td><td class="mono">${num(f.metrics.pagerank_normalised, 3)}</td></tr>
      <tr><td>Betweenness</td><td class="mono">${num(f.metrics.betweenness, 4)}</td></tr>
      <tr><td>Publisher fan-out</td><td class="mono">${f.metrics.maintainer_fanout || '—'}</td></tr>
    </table>

    <p class="sec-h">Reachability</p>
    <p class="tiny"><b>${esc(f.reachability.state)}</b> — ${esc(f.reachability.explanation)}.
    ${f.reachability.evidence.length ? 'Seen in ' + f.reachability.evidence.map(esc).join(', ') + '.' : ''}
    <br>${esc(state.result.reachability_disclaimer)}</p>

    <div style="display:flex;gap:8px;margin-top:14px">
      <button id="d-sim">Simulate compromise</button>
      <button id="d-rem">Model fixes</button>
    </div>`;
}

/* ----------------------------------------------------------- simulate --- */
function fillSelectors() {
  const opts = state.result.findings.map(f =>
    `<option value="${esc(f.id)}">${esc(f.name)}@${esc(f.version)} — RG ${num(f.rippleguard_score, 0)}</option>`).join('');
  $('#sim-target').innerHTML = opts;
  $('#rem-target').innerHTML = opts;
  const top = state.result.blast_ranking[0];
  if (top) $('#sim-target').value = top.id;
}

async function runSim() {
  const id = $('#sim-target').value;
  $('#sim-out').innerHTML = '<p class="tiny" style="padding:0 16px 16px">Propagating…</p>';
  try {
    const s = await api(`/api/scan/${state.scanId}/simulate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: id }),
    });
    state.sim = s;
    $('#sim-out').innerHTML = `
      <div class="disclaim">${esc(s.disclaimer)}</div>
      <div class="simgrid">
        ${tile(s.reached_packages, 'Packages reached', 'trust')}
        ${tile(s.reached_applications, 'Applications reached', 'trust')}
        ${tile(s.max_propagation_depth, 'Propagation depth')}
        ${tile(num(s.blast_radius.score, 0), 'Blast radius / 100', 'structure')}
        ${tile(num(s.application_exposure, 2), 'Exposure at the app')}
        ${tile(s.ecosystem.registry_dependents !== null && s.ecosystem.registry_dependents !== undefined
          ? s.ecosystem.registry_dependents.toLocaleString() : '—', 'Registry dependents')}
      </div>
      <div style="padding:0 16px 8px">
        <p class="sec-h" style="border:0;padding:0">Blast radius arithmetic</p>
        <ul class="breakdown">${s.blast_radius.breakdown.map(x =>
          `<li><div class="f"><span>${esc(x.factor)}</span><span class="pts">+${num(x.points)}</span></div></li>`).join('')}</ul>
        <p class="tiny">${esc(s.ecosystem.note)}</p>
      </div>
      <p class="sec-h" style="padding:0 16px">Highest-exposure propagation paths</p>
      ${s.top_paths.map(p => `
        <div class="path">
          <div class="chain">${p.steps.map((st, i) => `
            ${i ? `<span class="arrow">▸</span><span class="w">${num(st.edge_weight, 2)}</span><span class="arrow">▸</span>` : ''}
            <span class="hop ${i === p.steps.length - 1 ? 'terminal' : ''}">${esc(st.label)}</span>`).join('')}
            <span class="w">exposure ${num(p.exposure, 2)}</span></div>
          <div class="why">${esc(p.why)}</div>
        </div>`).join('')}`;
    animateOnGraph(s);
  } catch (e) { $('#sim-out').innerHTML = `<p class="tiny" style="padding:0 16px 16px">${esc(e.message)}</p>`; }
}

/* The one piece of non-user-triggered motion in the app: the compromise
   spreading outward through the graph, one hop at a time. */
function animateOnGraph(s) {
  const byHop = new Map();
  s.reached.forEach(r => {
    if (!byHop.has(r.hops)) byHop.set(r.hops, []);
    byHop.get(r.hops).push(r.id);
  });
  const hops = [...byHop.keys()].sort((a, b) => a - b);
  const lit = new Set([s.compromised]);
  const svg = $('#graph');
  let i = 0;
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const step = () => {
    if (i < hops.length) { byHop.get(hops[i]).forEach(x => lit.add(x)); i++; }
    paint(svg, 900, 620, lit);
    if (i < hops.length && !reduce) setTimeout(step, 420);
  };
  if (reduce) { hops.forEach(h => byHop.get(h).forEach(x => lit.add(x))); paint(svg, 900, 620, lit); }
  else step();
}

/* ---------------------------------------------------------- remediate --- */
async function runRem() {
  const id = $('#rem-target').value;
  $('#rem-out').innerHTML = '<p class="tiny" style="padding:0 16px 16px">Re-scoring the tree under each action…</p>';
  try {
    const r = await api(`/api/scan/${state.scanId}/remediate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: id }),
    });
    const rows = r.options.filter(o => !o.error);
    $('#rem-out').innerHTML = `
      <table class="remtable">
        <thead><tr><th>Action</th><th>RippleGuard score</th><th>Blast radius</th>
        <th>Exploit</th><th>Trust</th><th>Effort</th><th>Fixes</th></tr></thead>
        <tbody>${rows.map(o => `
          <tr class="${o.action === r.recommended ? 'best' : ''}">
            <td><span class="act">${esc(o.description)}</span>
              ${o.changes.map(c => `<div class="tiny mono">${esc(c)}</div>`).join('')}</td>
            <td><span class="beforeafter"><span class="b">${num(o.before.rippleguard)}</span>→
              <span class="a">${num(o.after.rippleguard)}</span></span>
              <span class="delta ${o.risk_reduction > 1 ? 'good' : 'none'}">−${num(o.risk_reduction)}</span></td>
            <td><span class="beforeafter"><span class="b">${num(o.before.blast_radius, 0)}</span>→
              <span class="a">${num(o.after.blast_radius, 0)}</span></span></td>
            <td class="delta ${o.exploit_reduction > 1 ? 'good' : 'none'}">−${num(o.exploit_reduction)}</td>
            <td class="delta ${o.trust_reduction > 1 ? 'good' : 'none'}">−${num(o.trust_reduction)}</td>
            <td class="mono">${o.effort}/5</td>
            <td class="tiny">${esc(o.fixes_channel)}</td>
          </tr>`).join('')}</tbody>
      </table>
      <div class="disclaim" style="margin:16px">${esc(r.channel_insight)}</div>
      <p class="tiny" style="padding:0 16px 16px">Ranked by ${esc(r.ranking_rule)}.
        ${esc(r.effort_note)}</p>`;
  } catch (e) { $('#rem-out').innerHTML = `<p class="tiny" style="padding:0 16px 16px">${esc(e.message)}</p>`; }
}

/* --------------------------------------------------------------- model -- */
async function renderModel() {
  const m = await api('/api/model');
  const r = state.result;
  const wtable = (title, obj, note) => `
    <div class="panel"><div class="panel-head"><h3>${esc(title)}</h3>
      ${note ? `<p>${esc(note)}</p>` : ''}</div>
      <table class="kv">${Object.entries(obj).map(([k, v]) =>
        `<tr><td>${esc(k.replace(/_/g, ' '))}</td><td class="mono">${esc(v)}</td></tr>`).join('')}</table></div>`;
  $('#model-out').innerHTML = `
    <div class="disclaim" style="margin:0 0 18px">${esc(m.disclaimer)}</div>
    <div class="split">
      ${wtable('Trust channel weights', m.trust_channel_weights,
        'Would a malicious publish reach your build automatically?')}
      ${wtable('Exploit channel weights', m.exploit_channel_weights,
        'Is a known vulnerability reachable from your code?')}
    </div>
    <div class="split">
      ${wtable('Blend weights', m.blend_weights)}
      ${wtable('Version floatiness table', m.floatiness_table,
        'Declared range → how automatically a new publish is inherited.')}
    </div>
    <div class="panel"><div class="panel-head"><h3>What each structural metric means</h3></div>
      <table class="kv">${Object.entries(r.metric_docs).map(([k, v]) =>
        `<tr><td>${esc(k.replace(/_/g, ' '))}</td><td>${esc(v)}</td></tr>`).join('')}</table></div>
    <div class="panel"><div class="panel-head"><h3>How this scan was resolved</h3></div>
      <table class="kv">
        <tr><td>Resolvers used</td><td>${esc((r.build_report.resolvers_used || []).join('; ') || 'none')}</td></tr>
        <tr><td>Packages resolved</td><td class="mono">${esc(r.build_report.packages_resolved)}</td></tr>
        <tr><td>Registry metadata</td><td class="mono">${esc(r.registry_report.packages_with_registry_metadata)} packages</td></tr>
        <tr><td>Publisher fan-out</td><td>${esc(r.registry_report.maintainer_fanout_note || '')}</td></tr>
        <tr><td>Ecosystem reach</td><td>${esc(r.ecosystem_report.note)}</td></tr>
        <tr><td>Reachability method</td><td>${esc(r.reachability_disclaimer)}</td></tr>
        <tr><td>Scan duration</td><td class="mono">${esc(r.duration_seconds)}s</td></tr>
      </table></div>`;
}

/* ------------------------------------------------------------ evaluate -- */
async function runEval() {
  $('#eval-out').innerHTML = '<p class="tiny" style="padding:16px">Scoring rankings against the IOC list…</p>';
  const e = await api(`/api/scan/${state.scanId}/evaluate`);
  if (e.error) { $('#eval-out').innerHTML = `<p class="tiny" style="padding:16px">${esc(e.error)}</p>`; return; }
  const names = Object.keys(e.rankings || {});
  $('#eval-out').innerHTML = `
    <div style="padding:16px">
      <table class="kv">
        <tr><td>Ground-truth packages</td><td class="mono">${e.ground_truth_packages}</td></tr>
        <tr><td>Matched in this scan</td><td class="mono">${e.matched_in_this_scan} of ${e.scanned_packages}</td></tr>
        <tr><td>Source</td><td>${esc(e.ground_truth_source)}</td></tr>
      </table>
      ${names.length ? `<table class="remtable" style="margin-top:14px">
        <thead><tr><th>Ranking</th><th>ROC-AUC</th><th>Avg precision</th>
        <th>P@5</th><th>P@10</th><th>R@10</th></tr></thead><tbody>
        ${names.map(n => { const v = e.rankings[n]; return `<tr class="${n === 'rippleguard_trust' ? 'best' : ''}">
          <td class="act">${esc(n.replace(/_/g, ' '))}</td>
          <td class="mono">${num(v.roc_auc, 3)}</td><td class="mono">${num(v.average_precision, 3)}</td>
          <td class="mono">${num(v.precision_at_5, 2)}</td><td class="mono">${num(v.precision_at_10, 2)}</td>
          <td class="mono">${num(v.recall_at_10, 2)}</td></tr>`; }).join('')}
        </tbody></table>` : ''}
      <div class="disclaim" style="margin:16px 0">${esc(e.verdict || '')}</div>
      <p class="tiny">${esc(e.caveat)}</p>
    </div>`;
}

/* ----------------------------------------------------------------- nav -- */
function show(view) {
  $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.view === view));
  $$('.view').forEach(v => v.hidden = v.id !== 'view-' + view);
  if (view === 'overview' && state.result) drawInversionLinks(state.result.rank_inversion);
  if (view === 'graph' && state.graph) paint($('#graph'), 900, 620);
}

$$('#tabs button').forEach(b => b.onclick = () => show(b.dataset.view));
$('#run').onclick = () => {
  const repo = $('#repo').value.trim();
  const text = $('#manifest').value.trim();
  if (repo) return runScan({ repo_url: repo });
  if (text) return runScan({ files: { [$('#filename').value]: text } });
  toast('Enter a GitHub repository URL, paste a manifest, or pick a sample.');
};
$('#sim-run').onclick = runSim;
$('#rem-run').onclick = runRem;
document.addEventListener('click', e => { if (e.target.id === 'eval-run') runEval(); });
window.addEventListener('resize', () => {
  if (state.result && !$('#view-overview').hidden) drawInversionLinks(state.result.rank_inversion);
});

loadSamples();
