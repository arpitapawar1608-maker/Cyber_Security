/* SentinelLog front-end: interactive charts, alert-queue filtering and AJAX status updates */
const PAGE = document.body.dataset.page;
const C = {blue: '#2563eb', red: '#dc2626', amber: '#f59e0b', green: '#16a34a', slate: '#64748b', purple: '#7c3aed', cyan: '#0891b2'};
const SEV = {Critical: '#b91c1c', High: '#ea580c', Medium: '#f59e0b', Low: '#16a34a'};
const STATUS = {Open: '#dc2626', Investigating: '#f59e0b', Resolved: '#16a34a', 'False Positive': '#94a3b8'};
const STATUSES = ['Open', 'Investigating', 'Resolved', 'False Positive'];
const palette = [C.blue, C.red, C.amber, C.green, C.purple, C.cyan, C.slate];
const charts = {};

if (window.Chart) {
  Chart.defaults.font.family = 'Inter, "Segoe UI", system-ui, sans-serif';
  Chart.defaults.color = '#64748b';
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
}
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const srcQuery = () => { const s = $('sourceFilter'); return s && s.value ? `source_id=${s.value}` : ''; };
async function getJSON(url) { const r = await fetch(url); if (!r.ok) throw new Error(r.status); return r.json(); }
function mk(id, cfg) {
  const el = $(id); if (!el || !window.Chart) return;
  if (charts[id]) charts[id].destroy();
  cfg.options = Object.assign({responsive: true, maintainAspectRatio: false}, cfg.options || {});
  charts[id] = new Chart(el, cfg);
}
const isEmpty = (o) => !o || !Object.keys(o).length;

function trendChart(id, t) {
  mk(id, {type: 'line', data: {labels: t.labels, datasets: [
    {label: 'Failed', data: t.failed, borderColor: C.red, backgroundColor: 'rgba(220,38,38,.12)', fill: true, tension: .3, pointRadius: 1},
    {label: 'Successful', data: t.success, borderColor: C.blue, backgroundColor: 'rgba(37,99,235,.08)', fill: true, tension: .3, pointRadius: 1}]},
    options: {interaction: {mode: 'index', intersect: false}, plugins: {legend: {position: 'bottom'}}, scales: {y: {beginAtZero: true}, x: {ticks: {maxTicksLimit: 10}}}}});
}
function barChart(id, labels, data, color, horizontal) {
  mk(id, {type: 'bar', data: {labels, datasets: [{label: 'Count', data, backgroundColor: color, borderRadius: 6}]},
    options: {indexAxis: horizontal ? 'y' : 'x', plugins: {legend: {display: false}}, scales: {x: {beginAtZero: true}, y: {beginAtZero: true}}}});
}
function doughnut(id, map, colors) {
  const labels = Object.keys(map);
  mk(id, {type: 'doughnut', data: {labels, datasets: [{data: labels.map((k) => map[k]), backgroundColor: labels.map((k, i) => colors[k] || palette[i % 7]), borderWidth: 2}]},
    options: {cutout: '62%', plugins: {legend: {position: 'bottom'}}}});
}

/* ---------------- dashboard ---------------- */
async function loadQueue() {
  const p = new URLSearchParams();
  if ($('fSeverity').value) p.set('severity', $('fSeverity').value);
  if ($('fStatus').value) p.set('status', $('fStatus').value);
  const sq = srcQuery(); if (sq) p.set('source_id', $('sourceFilter').value);
  const d = await getJSON('/api/alerts?' + p.toString());
  $('alertRows').innerHTML = d.rows.length ? d.rows.map((a) => `<tr>
    <td>${a.alert_id}</td><td><span class="badge sev-${a.severity.toLowerCase()}">${a.severity}</span></td><td><b>${esc(a.alert_type)}</b></td>
    <td><code>${esc(a.ip_address)}</code></td><td>${esc(a.username)}</td>
    <td><div class="score"><i style="width:${a.score}%" class="sev-bg-${a.severity.toLowerCase()}"></i></div><small>${a.score}</small></td>
    <td>${esc(a.created_at)}</td>
    <td><select class="status-select st-${a.status.toLowerCase().replace(' ', '-')}" data-id="${a.alert_id}">${STATUSES.map((s) => `<option ${s === a.status ? 'selected' : ''}>${s}</option>`).join('')}</select></td></tr>`).join('')
    : '<tr><td colspan="8" class="muted">No alerts. Upload logs and run anomaly detection on the Prediction page.</td></tr>';
}
async function initDashboard() {
  const d = await getJSON('/api/dashboard?' + srcQuery());
  $('k_total').textContent = d.kpis.total.toLocaleString();
  $('k_failed').textContent = d.kpis.failed.toLocaleString();
  $('k_rate').textContent = d.kpis.failure_rate + '%';
  $('k_ips').textContent = d.kpis.unique_ips;
  $('k_open').textContent = d.kpis.open_alerts;
  $('k_crit').textContent = d.kpis.critical;
  trendChart('trendChart', d.trend);
  barChart('ipChart', d.top_ips.map((i) => i.ip), d.top_ips.map((i) => i.failed), C.red, true);
  doughnut('sevChart', isEmpty(d.alerts.severity) ? {'No alerts': 1} : d.alerts.severity, Object.assign({'No alerts': '#e2e8f0'}, SEV));
  doughnut('statusChart', isEmpty(d.alerts.status) ? {'No alerts': 1} : d.alerts.status, Object.assign({'No alerts': '#e2e8f0'}, STATUS));
  loadQueue();
}
function initQueueEvents() {
  $('fSeverity').onchange = loadQueue; $('fStatus').onchange = loadQueue;
  $('alertRows').addEventListener('change', async (e) => {          // AJAX status update
    const sel = e.target.closest('.status-select'); if (!sel) return;
    const r = await fetch(`/api/alerts/${sel.dataset.id}/status`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({status: sel.value})});
    if (r.ok) { sel.className = 'status-select st-' + sel.value.toLowerCase().replace(' ', '-'); initDashboard(); }
    else alert('Could not update status');
  });
}

/* ---------------- analytics ---------------- */
async function initAnalytics() {
  const a = await getJSON('/api/analytics?' + srcQuery());
  const d = a.descriptive, k = d.kpis;
  $('descKpis').innerHTML = [['Events', k.total, ''], ['Failed', k.failed, 'red'], ['Failure rate', k.failure_rate + '%', 'amber'], ['Unique IPs', k.unique_ips, '']]
    .map(([l, v, c]) => `<div class="kpi ${c}"><span>${l}</span><b>${v}</b></div>`).join('');
  trendChart('trendChart', d.trend);
  doughnut('eventChart', Object.fromEntries(d.event_types.map((e) => [e.type, e.count])), {});
  barChart('ipChart', d.top_ips.map((i) => i.ip), d.top_ips.map((i) => i.failed), C.red, true);
  const g = a.diagnostic;
  barChart('hourChart', [...Array(24).keys()].map((h) => String(h).padStart(2, '0') + ':00'), g.hourly, C.purple, false);
  $('findings').innerHTML = g.findings.map((f) => `<li>${esc(f)}</li>`).join('');
  $('profiles').innerHTML = g.profiles.length ? g.profiles.map((p) => `<tr><td><code>${esc(p.ip)}</code></td><td class="bad">${p.failed}</td><td>${p.total}</td>
    <td>${p.fail_ratio}%</td><td>${p.users}</td><td>${esc(p.first_seen)}</td><td>${esc(p.last_seen)}</td><td><span class="pill">${esc(p.pattern)}</span></td></tr>`).join('')
    : '<tr><td colspan="8" class="muted">No failed events.</td></tr>';

  const n3 = (x) => (x === null || x === undefined ? '–' : Number(x).toFixed(3));
  $('clsRows').innerHTML = a.classification ? a.classification.map((m) => `<tr><td><b>${esc(m.model)}</b></td><td>${n3(m.accuracy)}</td><td>${n3(m.precision)}</td><td>${n3(m.recall)}</td><td>${n3(m.f1)}</td>
    <td><code>${m.tn} / ${m.fp} / ${m.fn} / ${m.tp}</code></td></tr>`).join('') : '<tr><td colspan="6" class="muted">Run anomaly detection on the Prediction page.</td></tr>';
  const rg = a.regression;
  $('regRows').innerHTML = rg.available ? rg.models.map((m) => `<tr><td><b>${esc(m.model)}</b></td><td>${n3(m.mae)}</td><td>${n3(m.mse)}</td><td>${n3(m.rmse)}</td><td>${n3(m.r2)}</td></tr>`).join('')
    : '<tr><td colspan="5" class="muted">Not enough hourly data.</td></tr>';
  const cl = a.clustering;
  $('clusterKpis').innerHTML = cl.available ? `<div class="kpi"><span>Silhouette score</span><b>${n3(cl.silhouette)}</b></div><div class="kpi"><span>Clusters (k)</span><b>${cl.k}</b></div>` : '';
  $('clusterRows').innerHTML = cl.available ? cl.clusters.map((c) => `<tr><td>${c.cluster}</td><td>${c.windows}</td><td>${c.avg_failed}</td><td>${c.avg_total}</td><td>${c.avg_accounts}</td><td><span class="pill">${esc(c.interpretation)}</span></td></tr>`).join('')
    : '<tr><td colspan="6" class="muted">Not enough data.</td></tr>';

  const fc = a.forecast;
  if (fc.available) {
    const hl = fc.history.labels, fl = fc.forecast.labels;
    $('fcKpis').innerHTML = `<div class="kpi red"><span>Expected failed logins, next hour</span><b>${fc.forecast.values[0]}</b></div>
      <div class="kpi amber"><span>Expected failed logins, next 6 hours</span><b>${fc.total}</b></div><div class="kpi"><span>Model</span><b style="font-size:18px">${esc(fc.model)}</b></div>`;
    mk('forecastChart', {type: 'line', data: {labels: hl.concat(fl), datasets: [
      {label: 'Observed', data: fc.history.values.concat(fl.map(() => null)), borderColor: C.blue, tension: .3, pointRadius: 1},
      {label: 'Forecast', data: hl.map(() => null).concat(fc.forecast.values), borderColor: C.red, borderDash: [6, 4], tension: .3, pointRadius: 3}]},
      options: {plugins: {legend: {position: 'bottom'}}, scales: {y: {beginAtZero: true}, x: {ticks: {maxTicksLimit: 8}}}}});
    $('fcRows').innerHTML = fl.map((l, i) => `<tr><td>${esc(l)}</td><td><b>${fc.forecast.values[i]}</b></td></tr>`).join('');
  } else {
    $('fcKpis').innerHTML = '';
    $('fcRows').innerHTML = '<tr><td colspan="2" class="muted">At least 12 hours of logs are needed.</td></tr>';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const sf = $('sourceFilter');
  if (PAGE === 'dashboard') { initQueueEvents(); initDashboard(); sf.onchange = initDashboard; }
  if (PAGE === 'analytics') { initAnalytics(); sf.onchange = initAnalytics; }
});
