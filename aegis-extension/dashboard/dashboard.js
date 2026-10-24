/**
 * Aegis SME Analytics Dashboard — dashboard.js
 * PR-04: SME Owner Dashboard (feat/w4-4-sme-analytics-dashboard)
 *
 * Responsibilities:
 *  - Load/persist detection log from chrome.storage.local (key: aegis_detection_log)
 *  - Load/persist sensitivity thresholds from chrome.storage.local (key: aegis_sensitivity)
 *  - Render 7-day bar chart and risk-distribution donut chart (native Canvas 2D API)
 *  - Render analysis log table with filter, search, and pagination
 *  - Render model metric gauge rings via SVG stroke-dashoffset animation
 *  - Ping backend /api/v1/stats for server-side aggregates; fall back to local log
 *  - Handle sensitivity slider save / reset
 *  - Listen for chrome.storage.onChanged to reflect new scans in real-time
 *
 * Storage schema
 * ──────────────
 * aegis_detection_log  : Array<DetectionEntry> (max 100, newest first)
 *   DetectionEntry = {
 *     emailHash   : string,
 *     sender      : string,
 *     subject     : string,
 *     score       : number,     // 0-100
 *     riskLevel   : "Safe"|"Warning"|"Critical",
 *     analyzedAt  : ISO8601 string,
 *     source      : "backend"|"offline_fallback",
 *   }
 *
 * aegis_sensitivity    : { warningThreshold: number, criticalThreshold: number }
 *   defaults           : { warningThreshold: 45, criticalThreshold: 75 }
 */

'use strict';

// ─── Constants ─────────────────────────────────────────────────────────────
const DETECTION_LOG_KEY  = 'aegis_detection_log';
const SENSITIVITY_KEY    = 'aegis_sensitivity';
const LOG_MAX_ENTRIES    = 100;
const LOG_PAGE_SIZE      = 15;
const DEFAULT_SENSITIVITY = { warningThreshold: 45, criticalThreshold: 75 };

// ─── State ──────────────────────────────────────────────────────────────────
let _allEntries   = [];    // full detection log (newest first)
let _filteredEntries = []; // after filter + search
let _currentFilter   = 'all';
let _currentPage     = 1;
let _backendBase     = 'http://localhost:8000';

// ─── Storage helpers ────────────────────────────────────────────────────────
function storageGet(keys) {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(keys, resolve);
    } else {
      // Dev fallback: use localStorage
      const result = {};
      keys.forEach(k => {
        const raw = localStorage.getItem(k);
        if (raw) try { result[k] = JSON.parse(raw); } catch (_) {}
      });
      resolve(result);
    }
  });
}

function storageSet(data) {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set(data, resolve);
    } else {
      Object.entries(data).forEach(([k, v]) => localStorage.setItem(k, JSON.stringify(v)));
      resolve();
    }
  });
}

function storageClear(keys) {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.remove(keys, resolve);
    } else {
      keys.forEach(k => localStorage.removeItem(k));
      resolve();
    }
  });
}

// ─── Backend helpers ────────────────────────────────────────────────────────
async function getBackendBase() {
  const data = await storageGet(['aegis_backend_url']);
  return (data.aegis_backend_url || 'http://localhost:8000').replace(/\/$/, '');
}

async function pingBackend(base) {
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 2000);
    const res  = await fetch(`${base}/api/v1/health`, { signal: ctrl.signal });
    clearTimeout(tid);
    return res.ok;
  } catch (_) { return false; }
}

async function fetchBackendStats(base) {
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 2500);
    const res  = await fetch(`${base}/api/v1/stats`, { signal: ctrl.signal });
    clearTimeout(tid);
    if (res.ok) return res.json();
  } catch (_) {}
  return null;
}

// ─── DOM helpers ────────────────────────────────────────────────────────────
function qs(id) { return document.getElementById(id); }

function setKpi(id, val, delta) {
  const el = qs(`kpi-${id}-val`);
  if (el) el.textContent = val;
  const de = qs(`kpi-${id}-delta`);
  if (de && delta !== undefined) de.textContent = delta;
}

// ─── Navigation ─────────────────────────────────────────────────────────────
function initNavigation() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const section = link.dataset.section;
      activateSection(section);
    });
  });
}

function activateSection(sectionId) {
  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.section === sectionId);
    l.removeAttribute('aria-current');
    if (l.dataset.section === sectionId) l.setAttribute('aria-current', 'page');
  });
  document.querySelectorAll('.dash-section').forEach(s => {
    s.classList.toggle('active', s.id === `section-${sectionId}`);
  });
}

// ─── KPI & Stats ─────────────────────────────────────────────────────────────
function computeLocalStats(entries) {
  const total    = entries.length;
  const critical = entries.filter(e => e.riskLevel === 'Critical').length;
  const warning  = entries.filter(e => e.riskLevel === 'Warning').length;
  const safe     = entries.filter(e => e.riskLevel === 'Safe').length;
  const fp       = entries.filter(e => e.userOverride).length;
  return { total, critical, warning, safe, fp };
}

function renderKpis(stats) {
  setKpi('total',    stats.total    ?? '—');
  setKpi('phishing', stats.critical ?? '—');
  setKpi('warning',  stats.warning  ?? '—');
  setKpi('safe',     stats.safe     ?? '—');
  setKpi('fp',       stats.fp       ?? '—');

  const subtitle = qs('topbar-subtitle');
  if (subtitle) {
    subtitle.textContent = stats.total > 0
      ? `${stats.total} emails analyzed · ${stats.critical} critical threat${stats.critical !== 1 ? 's' : ''} detected`
      : 'No emails analyzed yet on this device.';
  }
}

// ─── 7-Day Bar Chart ─────────────────────────────────────────────────────────
function buildDailyBuckets(entries) {
  const buckets = {};
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    buckets[key] = { Critical: 0, Warning: 0, Safe: 0 };
  }
  entries.forEach(entry => {
    const key = (entry.analyzedAt || '').slice(0, 10);
    if (buckets[key]) {
      buckets[key][entry.riskLevel] = (buckets[key][entry.riskLevel] || 0) + 1;
    }
  });
  return buckets;
}

function getNiceYAxis(maxVal) {
  if (maxVal <= 0) return { max: 4, ticks: [4, 3, 2, 1, 0] };
  if (maxVal <= 3) return { max: 4, ticks: [4, 3, 2, 1, 0] };
  if (maxVal <= 7) return { max: 8, ticks: [8, 6, 4, 2, 0] };
  if (maxVal <= 9) return { max: 10, ticks: [10, 8, 6, 4, 2, 0] };
  if (maxVal <= 14) return { max: 16, ticks: [16, 12, 8, 4, 0] };
  if (maxVal <= 18) return { max: 20, ticks: [20, 15, 10, 5, 0] };
  if (maxVal <= 35) return { max: 40, ticks: [40, 30, 20, 10, 0] };
  if (maxVal <= 50) return { max: 50, ticks: [50, 40, 30, 20, 10, 0] };
  const step = Math.ceil(maxVal / 4);
  const niceMax = step * 4;
  const ticks = [niceMax, step * 3, step * 2, step, 0];
  return { max: niceMax, ticks };
}

function renderBarChart(entries) {
  let container = qs('bar-chart');
  if (!container) return;

  // Upgrade canvas to div if needed
  if (container.tagName === 'CANVAS') {
    const div = document.createElement('div');
    div.id = 'bar-chart';
    div.className = 'aegis-bar-chart';
    div.setAttribute('aria-label', '7-day detection activity bar chart');
    container.parentNode.replaceChild(div, container);
    container = div;
  }

  const buckets = buildDailyBuckets(entries);
  const days = Object.keys(buckets);
  const maxVal = Math.max(1, ...days.map(d => Math.max(buckets[d].Critical, buckets[d].Warning, buckets[d].Safe)));
  const { max: niceMax, ticks } = getNiceYAxis(maxVal);

  const tiers = [
    { key: 'Critical', label: 'Critical', colorClass: 'aegis-bar--critical' },
    { key: 'Warning',  label: 'Warning',  colorClass: 'aegis-bar--warning'  },
    { key: 'Safe',     label: 'Safe',     colorClass: 'aegis-bar--safe'     },
  ];

  // Gridlines HTML
  const gridHtml = ticks.map(t => {
    const pct = (t / niceMax) * 100;
    const isBase = t === 0;
    return `<div class="aegis-gridline ${isBase ? 'aegis-gridline--base' : ''}" style="bottom: ${pct}%;"></div>`;
  }).join('');

  // Y-axis ticks HTML
  const yAxisHtml = ticks.map(t => `<div class="aegis-chart-y-tick">${t}</div>`).join('');

  // Days columns HTML
  const daysHtml = days.map((day, di) => {
    const dateObj = new Date(day + 'T00:00:00');
    const weekday = dateObj.toLocaleDateString('en-US', { weekday: 'short' });
    const monthDay = dateObj.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const fullWeekday = dateObj.toLocaleDateString('en-US', { weekday: 'long' });
    const b = buckets[day];
    const dayTotal = b.Critical + b.Warning + b.Safe;

    let alignClass = '';
    if (di <= 1) alignClass = 'align-left';
    else if (di >= 5) alignClass = 'align-right';

    const barsHtml = tiers.map(t => {
      const count = b[t.key] || 0;
      if (count === 0) {
        return `<div class="aegis-bar-slot"><div class="aegis-bar aegis-bar--zero" title="${t.label}: 0"></div></div>`;
      }
      const pct = Math.min(100, Math.max(8, (count / niceMax) * 100));
      const valClass = pct > 25 ? 'aegis-bar-val--inside' : 'aegis-bar-val--floating';
      return `<div class="aegis-bar-slot">
        <div class="aegis-bar ${t.colorClass}" style="height: ${pct}%;" title="${t.label}: ${count}">
          <span class="aegis-bar-val ${valClass}">${count}</span>
        </div>
      </div>`;
    }).join('');

    return `
      <div class="aegis-day-col ${alignClass}" data-date="${day}">
        <div class="aegis-day-tooltip">
          <div class="aegis-tooltip-title">${fullWeekday.toUpperCase()}, ${monthDay.toUpperCase()}</div>
          <div class="aegis-tooltip-row">
            <span><span class="aegis-tooltip-dot aegis-tooltip-dot--red"></span> Critical</span>
            <strong>${b.Critical}</strong>
          </div>
          <div class="aegis-tooltip-row">
            <span><span class="aegis-tooltip-dot aegis-tooltip-dot--amber"></span> Warning</span>
            <strong>${b.Warning}</strong>
          </div>
          <div class="aegis-tooltip-row">
            <span><span class="aegis-tooltip-dot aegis-tooltip-dot--green"></span> Safe</span>
            <strong>${b.Safe}</strong>
          </div>
          <div class="aegis-tooltip-total">
            <span>TOTAL</span>
            <strong>${dayTotal}</strong>
          </div>
        </div>
        <div class="aegis-bars-group">
          ${barsHtml}
        </div>
        <div class="aegis-x-label">
          <span class="aegis-day-name">${weekday}</span>
          <span class="aegis-day-date">${monthDay}</span>
        </div>
      </div>
    `;
  }).join('');

  container.innerHTML = `
    <div class="aegis-chart-viewport">
      <div class="aegis-chart-y-axis">
        ${yAxisHtml}
      </div>
      <div class="aegis-chart-stage">
        <div class="aegis-chart-gridlines">
          ${gridHtml}
        </div>
        <div class="aegis-chart-columns">
          ${daysHtml}
        </div>
      </div>
    </div>
  `;

  // Badge
  const total7 = days.reduce((sum, d) => sum + buckets[d].Critical + buckets[d].Warning + buckets[d].Safe, 0);
  const badge = qs('chart-activity-badge');
  if (badge) badge.textContent = `${total7} this week`;
}

// ─── Donut Chart ─────────────────────────────────────────────────────────────
function renderDonutChart(stats) {
  const canvas = qs('donut-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2, cy = H / 2, r = 75, thickness = 22;
  const total = stats.total || 1;
  const slices = [
    { label: 'Critical', val: stats.critical || 0, color: '#d93025' },
    { label: 'Warning',  val: stats.warning  || 0, color: '#b06000' },
    { label: 'Safe',     val: stats.safe     || 0, color: '#188038' },
  ];

  if (total === 0 || (stats.critical === 0 && stats.warning === 0 && stats.safe === 0)) {
    // empty state ring
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.strokeStyle = '#e8eaed';
    ctx.lineWidth = thickness;
    ctx.stroke();

    const center = qs('donut-center-pct');
    if (center) center.textContent = '—';
    return;
  }

  let startAngle = -Math.PI / 2;
  slices.forEach(slice => {
    const angle = (slice.val / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, startAngle + angle);
    ctx.strokeStyle = slice.color;
    ctx.lineWidth = thickness;
    ctx.lineCap = 'butt';
    ctx.stroke();
    startAngle += angle;
  });

  // Inner ring background
  ctx.beginPath();
  ctx.arc(cx, cy, r - thickness / 2 - 2, 0, Math.PI * 2);
  ctx.fillStyle = 'rgba(0,0,0,0)';
  ctx.fill();

  // Center % label
  const phishingPct = Math.round(((stats.critical || 0) / total) * 100);
  const center = qs('donut-center-pct');
  if (center) center.textContent = `${phishingPct}%`;
}

// ─── Analysis Log Table ───────────────────────────────────────────────────────
function formatTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-US', {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch (_) { return iso; }
}

function getVerdictBadge(riskLevel) {
  const level = (riskLevel || 'safe').toLowerCase();
  const map = {
    critical: ['Critical', 'verdict-badge--critical'],
    warning:  ['Warning',  'verdict-badge--warning'],
    safe:     ['Safe',     'verdict-badge--safe'],
  };
  const [label, cls] = map[level] || ['Safe', 'verdict-badge--safe'];
  return `<span class="verdict-badge ${cls}">${label}</span>`;
}

function getScoreColor(score) {
  if (score >= 75) return 'color: #d93025; font-weight: 800;';
  if (score >= 45) return 'color: #b06000; font-weight: 800;';
  return 'color: #188038; font-weight: 800;';
}

function applyFilterAndSearch() {
  const searchVal = (qs('log-search')?.value || '').toLowerCase().trim();

  _filteredEntries = _allEntries.filter(e => {
    const matchFilter = _currentFilter === 'all' || e.riskLevel === _currentFilter;
    const matchSearch = !searchVal ||
      (e.sender  || '').toLowerCase().includes(searchVal) ||
      (e.subject || '').toLowerCase().includes(searchVal);
    return matchFilter && matchSearch;
  });

  _currentPage = 1;
  renderLogTable();
}

function renderLogTable() {
  const tbody    = qs('log-tbody');
  const emptyEl  = qs('log-empty');
  const pageInfo = qs('page-info');
  const prevBtn  = qs('page-prev');
  const nextBtn  = qs('page-next');
  if (!tbody) return;

  const total  = _filteredEntries.length;
  const pages  = Math.max(1, Math.ceil(total / LOG_PAGE_SIZE));
  _currentPage = Math.min(_currentPage, pages);
  const start  = (_currentPage - 1) * LOG_PAGE_SIZE;
  const slice  = _filteredEntries.slice(start, start + LOG_PAGE_SIZE);

  if (total === 0) {
    tbody.innerHTML = '';
    if (emptyEl) { emptyEl.classList.add('visible'); }
    if (pageInfo) pageInfo.textContent = 'Page 0 / 0';
    if (prevBtn)  prevBtn.disabled = true;
    if (nextBtn)  nextBtn.disabled = true;
    return;
  }

  if (emptyEl) emptyEl.classList.remove('visible');
  if (pageInfo) pageInfo.textContent = `Page ${_currentPage} / ${pages}`;
  if (prevBtn)  prevBtn.disabled = _currentPage <= 1;
  if (nextBtn)  nextBtn.disabled = _currentPage >= pages;

  tbody.innerHTML = slice.map(e => `
    <tr role="row">
      <td class="col-time">${formatTime(e.analyzedAt)}</td>
      <td class="col-sender" title="${(e.sender || '').replace(/"/g, '&quot;')}">${escHtml(e.sender || '—')}</td>
      <td class="col-subject" title="${(e.subject || '').replace(/"/g, '&quot;')}">${escHtml(e.subject || '(No subject)')}</td>
      <td class="col-score" style="${getScoreColor(e.score || 0)}">${e.score ?? '—'}%</td>
      <td>${getVerdictBadge(e.riskLevel)}</td>
    </tr>
  `).join('');
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function initLogControls() {
  // Filter buttons
  document.querySelectorAll('.log-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.log-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _currentFilter = btn.dataset.filter;
      applyFilterAndSearch();
    });
  });

  // Search
  const searchInput = qs('log-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => applyFilterAndSearch());
  }

  // Pagination
  const prevBtn = qs('page-prev');
  const nextBtn = qs('page-next');
  if (prevBtn) prevBtn.addEventListener('click', () => { _currentPage--; renderLogTable(); });
  if (nextBtn) nextBtn.addEventListener('click', () => { _currentPage++; renderLogTable(); });

  // Clear log
  const clearBtn = qs('btn-clear-log');
  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      if (!confirm('Clear the entire local detection log? This cannot be undone.')) return;
      await storageClear([DETECTION_LOG_KEY]);
      _allEntries = [];
      applyFilterAndSearch();
      renderKpis(computeLocalStats([]));
      renderBarChart([]);
      renderDonutChart(computeLocalStats([]));
    });
  }
}

// ─── Sensitivity Sliders ──────────────────────────────────────────────────────
function initSensitivityControls(saved) {
  const wSlider  = qs('slider-warning');
  const cSlider  = qs('slider-critical');
  const wBadge   = qs('badge-warning');
  const cBadge   = qs('badge-critical');
  const wLabel   = qs('prev-warn-label');
  const cLabel   = qs('prev-crit-label');
  const toast    = qs('sens-toast');

  if (!wSlider || !cSlider) return;

  // Apply saved values
  wSlider.value = saved.warningThreshold;
  cSlider.value = saved.criticalThreshold;
  updateSensUI();

  wSlider.addEventListener('input', () => {
    // Enforce warning < critical
    if (parseInt(wSlider.value) >= parseInt(cSlider.value)) {
      cSlider.value = parseInt(wSlider.value) + 5;
    }
    updateSensUI();
  });

  cSlider.addEventListener('input', () => {
    if (parseInt(cSlider.value) <= parseInt(wSlider.value)) {
      wSlider.value = parseInt(cSlider.value) - 5;
    }
    updateSensUI();
  });

  // Save button
  const saveBtn  = qs('btn-save-sensitivity');
  const resetBtn = qs('btn-reset-sensitivity');

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const newSens = {
        warningThreshold:  parseInt(wSlider.value),
        criticalThreshold: parseInt(cSlider.value),
      };
      await storageSet({ [SENSITIVITY_KEY]: newSens });
      if (toast) {
        toast.textContent = '✓ Thresholds saved — applied on next email scan.';
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
      }
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      wSlider.value = DEFAULT_SENSITIVITY.warningThreshold;
      cSlider.value = DEFAULT_SENSITIVITY.criticalThreshold;
      updateSensUI();
    });
  }

  function updateSensUI() {
    const wVal = parseInt(wSlider.value);
    const cVal = parseInt(cSlider.value);
    if (wBadge) wBadge.textContent = `${wVal}%`;
    if (cBadge) cBadge.textContent = `${cVal}%`;
    if (wLabel) wLabel.textContent = `≥ ${wVal}% Warning`;
    if (cLabel) cLabel.textContent = `≥ ${cVal}% Critical`;
  }
}

// ─── Model Metric Rings ───────────────────────────────────────────────────────
function animateMetricRings() {
  const rings = [
    { ringId: 'ring-accuracy',  pct: 94.3, color: '#1a73e8' },
    { ringId: 'ring-precision', pct: 93.1, color: '#b06000' },
    { ringId: 'ring-recall',    pct: 95.8, color: '#7b3f9e' },
    { ringId: 'ring-f1',        pct: 94.4, color: '#188038' },
    { ringId: 'ring-fpr',       pct: 5.7,  color: '#d93025' },
    { ringId: 'ring-latency',   pct: 72,   color: '#000000' },
  ];

  // circumference = 2πr = 2 × π × 32 ≈ 201.06
  const circumference = 2 * Math.PI * 32;

  rings.forEach(({ ringId, pct, color }) => {
    const el = qs(ringId);
    if (!el) return;
    el.style.stroke = color;
    // Animate after a brief delay so the browser registers the initial state
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const offset = circumference * (1 - pct / 100);
        el.style.strokeDashoffset = String(offset);
      });
    });
  });
}

// ─── Backend Status ───────────────────────────────────────────────────────────
async function updateBackendStatus() {
  const dot  = qs('backend-dot');
  const text = qs('backend-status-text');
  const base = await getBackendBase();
  _backendBase = base;

  const online = await pingBackend(base);
  if (dot)  { dot.className  = 'status-dot ' + (online ? 'online' : 'offline'); }
  if (text) { text.textContent = online ? 'Backend Online' : 'Backend Offline'; }
  return online;
}

// ─── Real-time storage listener ───────────────────────────────────────────────
function initStorageListener() {
  if (typeof chrome === 'undefined' || !chrome.storage) return;
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes[DETECTION_LOG_KEY]) {
      _allEntries = changes[DETECTION_LOG_KEY].newValue || [];
      const stats = computeLocalStats(_allEntries);
      renderKpis(stats);
      renderBarChart(_allEntries);
      renderDonutChart(stats);
      applyFilterAndSearch();
    }
  });
}

// ─── Whitelist button ─────────────────────────────────────────────────────────
function initWhitelistButton() {
  const btn = qs('btn-open-whitelist');
  if (!btn) return;
  btn.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.tabs.create({ url: chrome.runtime.getURL('whitelist/whitelist_dashboard.html') });
    }
  });
}

// ─── Refresh button ───────────────────────────────────────────────────────────
function initRefreshButton() {
  const btn = qs('btn-refresh-stats');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    btn.style.opacity = '0.5';
    btn.style.pointerEvents = 'none';
    await loadAndRender();
    btn.style.opacity = '';
    btn.style.pointerEvents = '';
  });
}

// ─── Main load & render ───────────────────────────────────────────────────────
async function loadAndRender() {
  // 1. Load detection log from local storage
  const stored = await storageGet([DETECTION_LOG_KEY, SENSITIVITY_KEY]);
  _allEntries  = stored[DETECTION_LOG_KEY] || [];
  const sens   = stored[SENSITIVITY_KEY]   || DEFAULT_SENSITIVITY;

  // 2. Compute local stats
  const localStats = computeLocalStats(_allEntries);

  // 3. Try backend stats (merge if available)
  let stats = localStats;
  const backendOnline = await updateBackendStatus();
  if (backendOnline) {
    const serverStats = await fetchBackendStats(_backendBase);
    if (serverStats) {
      // Merge: prefer server totals, keep local FP count
      stats = {
        total:    Math.max(localStats.total, serverStats.total   || 0),
        critical: Math.max(localStats.critical, serverStats.critical || 0),
        warning:  Math.max(localStats.warning,  serverStats.warning  || 0),
        safe:     Math.max(localStats.safe,      serverStats.safe     || 0),
        fp:       localStats.fp,
      };
    }
  }

  // 4. Render
  renderKpis(stats);
  renderBarChart(_allEntries);
  renderDonutChart(stats);

  // 5. Filter + log table
  applyFilterAndSearch();

  // 6. Sensitivity sliders
  initSensitivityControls(sens);

  // 7. Metric rings (animate in)
  animateMetricRings();
}

// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initNavigation();
  initLogControls();
  initStorageListener();
  initWhitelistButton();
  initRefreshButton();
  await loadAndRender();
});
