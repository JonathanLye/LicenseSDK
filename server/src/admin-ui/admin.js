/* LicenseSDK Admin — Shared JS */
const API_BASE = '/api/v1/admin';

// ── Auth ──────────────────────────────────────────────────────────
function getSecret() {
  let s = sessionStorage.getItem('adminSecret');
  if (!s) { s = localStorage.getItem('adminSecret'); }
  return s;
}

function requireAuth() {
  if (!getSecret()) { window.location.href = '/admin/'; }
}

function logout() {
  sessionStorage.removeItem('adminSecret');
  localStorage.removeItem('adminSecret');
  window.location.href = '/admin/';
}

// ── Toast ─────────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 3000);
}

// ── API fetch wrapper ─────────────────────────────────────────────
async function api(path, options = {}) {
  const secret = getSecret();
  if (!secret) { window.location.href = '/admin/'; return null; }

  const url = `${API_BASE}${path}`;
  const headers = { 'X-Admin-Secret': secret };
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      toast('Session expired — please log in again', 'error');
      logout();
      return null;
    }
    const data = await res.json();
    if (!res.ok) { throw new Error(data.error || `HTTP ${res.status}`); }
    return data;
  } catch (err) {
    if (err.name !== 'Error') throw err;
    throw err;
  }
}

// ── Navigation highlight ──────────────────────────────────────────
function highlightNav(pageId) {
  document.querySelectorAll('.sidebar nav a').forEach(a => {
    a.classList.toggle('active', a.dataset.page === pageId);
  });
}

// ── Format helpers ────────────────────────────────────────────────
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function fmtBool(v) { return v ? '✓' : '✗'; }

// ── Table render helpers ──────────────────────────────────────────
function renderTable(headers, rows, emptyMsg = '暂无数据') {
  if (!rows || rows.length === 0) {
    return `<div class="empty-state">${emptyMsg}</div>`;
  }
  let html = '<table><thead><tr>';
  headers.forEach(h => { html += `<th>${h}</th>`; });
  html += '</tr></thead><tbody>';
  rows.forEach(row => { html += '<tr>' + row.map(c => `<td>${c ?? '—'}</td>`).join('') + '</tr>'; });
  html += '</tbody></table>';
  return html;
}

function showLoading(container) {
  container.innerHTML = '<div class="loading">加载中</div>';
}

function showError(container, msg) {
  container.innerHTML = `<div class="error-state">${msg}</div>`;
}
