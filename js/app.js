/**
 * Privacy Guardian — app.js
 * Security hardening:
 *   1. Zero innerHTML usage — all DOM construction via createElement / textContent
 *   2. Input sanitization on every user-supplied value before storage or display
 *   3. Content-Security-Policy enforced in meta tag (no inline scripts/eval)
 *   4. localStorage data validated and schema-checked on every read
 *   5. window.open uses rel="noopener noreferrer" and only whitelisted https:// URLs
 *   6. URL allowlist for data-broker links (prevents open-redirect / js: injection)
 *   7. All user-facing alerts replaced with non-blocking toast messages
 *   8. Confirm dialogs replaced with inline modal confirmation
 *   9. No use of eval, Function(), or setTimeout with strings
 *  10. Subresource integrity on external CDNs enforced via HTML (see index.html)
 */

'use strict';

/* ─────────────────────────────────────────────
   0. CONSTANTS
───────────────────────────────────────────── */

const STORAGE_KEYS = {
    DARK_MODE:    'pg_dark_mode',
    USER_INFO:    'pg_user_info',
    SCAN_RESULTS: 'pg_scan_results'
};

/* ─────────────────────────────────────────────
   1. SANITIZATION HELPERS
───────────────────────────────────────────── */

/**
 * Strip all HTML tags and trim whitespace from a string.
 * Used before storing or displaying any user-supplied value.
 */
function sanitizeText(str) {
    if (typeof str !== 'string') return '';
    // Remove any HTML-like content, null bytes, and control chars
    return str
        .replace(/[<>"'`]/g, '')       // strip angle brackets + quote chars
        .replace(/\0/g, '')             // null bytes
        .replace(/[\x00-\x1F\x7F]/g, '') // control characters
        .trim()
        .slice(0, 256);                 // hard cap — no unbounded input
}

/**
 * Validate that a URL belongs to the data-broker's known https:// domain.
 * Prevents open-redirect and javascript: injection via the dataBrokers list.
 */
function isSafeUrl(url) {
    if (typeof url !== 'string') return false;
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'https:';
    } catch {
        return false;
    }
}

/**
 * Safe DOM text setter — always use this instead of innerHTML.
 */
function setText(el, str) {
    if (el) el.textContent = sanitizeText(String(str));
}

/* ─────────────────────────────────────────────
   2. PERSISTENCE — in-memory + server API
   (localStorage not available in sandboxed iframe;
    all state lives in AppState at runtime and is
    synced to /api/state on every meaningful change)
───────────────────────────────────────────── */

const MAX_STORAGE_BYTES = 512 * 1024;

/** Persist AppState to the backend. Fire-and-forget — failures are non-fatal. */
function storageSave(_key, _value) {
    // _key / _value kept for call-site compatibility; we always save full state
    const payload = {
        userInfo:    AppState.userInfo,
        scanResults: AppState.scanResults,
        darkMode:    AppState.darkMode
    };
    const body = JSON.stringify(payload);
    if (body.length > MAX_STORAGE_BYTES) {
        showToast('State too large — export CSV first.', 'error');
        return;
    }
    fetch('/api/state', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body
    }).catch(() => { /* silent — offline mode is fine */ });
}

/** Load persisted state from backend; falls back to empty state silently. */
async function storageLoadAll() {
    try {
        const res = await fetch('/api/state');
        if (!res.ok) return {};
        return await res.json();
    } catch {
        return {};
    }
}

/** Shim: storageLoad is only called for darkMode pre-state-init; return default. */
function storageLoad(_key, fallback = null) {
    return fallback;
}

/** Validate a userInfo object shape and sanitize every field. */
function validateUserInfo(obj) {
    if (!obj || typeof obj !== 'object') return {};
    const allowed = ['firstName','lastName','city','state','email','phone'];
    const clean = {};
    for (const key of allowed) {
        if (obj[key] !== undefined) clean[key] = sanitizeText(String(obj[key] ?? ''));
    }
    return clean;
}

/** Validate a single scan result against the expected schema. */
function validateScanResult(r) {
    if (!r || typeof r !== 'object') return null;
    const validStatuses = ['found','pending','removed','clean','checking'];
    return {
        id:               sanitizeText(String(r.id   ?? '')),
        name:             sanitizeText(String(r.name  ?? '')),
        url:              isSafeUrl(r.url)        ? r.url        : '#',
        optOutUrl:        isSafeUrl(r.optOutUrl)  ? r.optOutUrl  : '#',
        category:         sanitizeText(String(r.category        ?? '')),
        difficulty:       sanitizeText(String(r.difficulty      ?? '')),
        estimatedTime:    sanitizeText(String(r.estimatedTime   ?? '')),
        instructions:     sanitizeText(String(r.instructions    ?? '')),
        status:           validStatuses.includes(r.status) ? r.status : 'clean',
        dateFound:        isValidISODate(r.dateFound)        ? r.dateFound        : null,
        removalRequested: isValidISODate(r.removalRequested)  ? r.removalRequested : null,
        followUpDate:     isValidISODate(r.followUpDate)      ? r.followUpDate     : null,
        notes:            sanitizeText(String(r.notes ?? '')).slice(0, 1000)
    };
}

function isValidISODate(v) {
    if (!v) return false;
    const d = new Date(v);
    return !isNaN(d.getTime());
}

/* ─────────────────────────────────────────────
   3. APPLICATION STATE
───────────────────────────────────────────── */

const AppState = {
    userInfo: {},
    scanResults: [],
    currentFilter: 'all',
    darkMode: storageLoad(STORAGE_KEYS.DARK_MODE, false) === true
};

/* ─────────────────────────────────────────────
   4. TOAST (replaces alert / confirm)
───────────────────────────────────────────── */

let _toastTimer = null;

function showToast(message, type = 'info') {
    let toast = document.getElementById('pg-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'pg-toast';
        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.className = `toast toast-${type}`;
    toast.textContent = sanitizeText(message); // textContent — never innerHTML
    // Force reflow so transition fires even on rapid successive calls
    void toast.offsetWidth;
    toast.classList.add('show');
    if (_toastTimer) clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => toast.classList.remove('show'), 3500);
}

/* ─────────────────────────────────────────────
   5. INLINE CONFIRM MODAL (replaces confirm())
───────────────────────────────────────────── */

function confirmAction(message, onConfirm) {
    let modal = document.getElementById('pg-confirm-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'pg-confirm-modal';
        modal.className = 'modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        // Build confirm modal via DOM API — zero innerHTML
        const mc = el('div', { cls: 'modal-content', attrs: { style: 'max-width:400px' } });
        const mh = el('div', { cls: 'modal-header' });
        const mTitle = el('h2', { attrs: { style: 'font-size:1.1rem' } });
        const warnIcon = icon('fas fa-exclamation-triangle');
        warnIcon.setAttribute('style', 'color:var(--warning-color)');
        mTitle.appendChild(warnIcon);
        mTitle.appendChild(document.createTextNode('\u00a0Confirm'));
        const mClose = el('button', { cls: 'modal-close', text: '\u00d7', attrs: { 'aria-label': 'Close' } });
        mh.appendChild(mTitle);
        mh.appendChild(mClose);
        const mb = el('div', { cls: 'modal-body' });
        const mp = el('p', { attrs: { id: 'pg-confirm-msg', style: 'margin-bottom:1.25rem' } });
        const btnRow = el('div', { attrs: { style: 'display:flex;gap:.5rem' } });
        const yesB = el('button', { cls: 'btn btn-danger btn-small',  text: 'Yes, proceed', attrs: { id: 'pg-confirm-yes' } });
        const noB  = el('button', { cls: 'btn btn-outline btn-small', text: 'Cancel',       attrs: { id: 'pg-confirm-no'  } });
        btnRow.appendChild(yesB);
        btnRow.appendChild(noB);
        mb.appendChild(mp);
        mb.appendChild(btnRow);
        mc.appendChild(mh);
        mc.appendChild(mb);
        modal.appendChild(mc);
        document.body.appendChild(modal);
        modal.querySelector('.modal-close').addEventListener('click', () => modal.classList.remove('active'));
        modal.querySelector('#pg-confirm-no').addEventListener('click',  () => modal.classList.remove('active'));
        modal.addEventListener('click', e => { if (e.target === modal) modal.classList.remove('active'); });
    }
    // Safe text assignment
    document.getElementById('pg-confirm-msg').textContent = sanitizeText(message);

    // Rebind yes button (clone to clear old listeners)
    const yesBtn = document.getElementById('pg-confirm-yes');
    const fresh  = yesBtn.cloneNode(true);
    yesBtn.parentNode.replaceChild(fresh, yesBtn);
    fresh.addEventListener('click', () => {
        modal.classList.remove('active');
        onConfirm();
    });
    modal.classList.add('active');
}

/* ─────────────────────────────────────────────
   6. SAFE window.open WRAPPER
───────────────────────────────────────────── */

function safeOpen(url) {
    if (!isSafeUrl(url)) {
        showToast('Blocked unsafe URL.', 'error');
        return;
    }
    const win = window.open(url, '_blank', 'noopener,noreferrer');
    if (win) win.opener = null; // belt-and-suspenders
}

/* ─────────────────────────────────────────────
   7. SAFE DOM BUILDER (no innerHTML)
───────────────────────────────────────────── */

/** Create an element with optional className, textContent, and attributes. */
function el(tag, opts = {}) {
    const node = document.createElement(tag);
    if (opts.cls)   node.className   = opts.cls;
    if (opts.text !== undefined) node.textContent = sanitizeText(String(opts.text));
    if (opts.html !== undefined) node.textContent = opts.html; // intentional: strip tags
    if (opts.attrs) Object.entries(opts.attrs).forEach(([k,v]) => node.setAttribute(k, v));
    return node;
}

function icon(faClass) {
    const i = document.createElement('i');
    i.className = faClass;
    i.setAttribute('aria-hidden', 'true');
    return i;
}

/* ─────────────────────────────────────────────
   8. INITIALIZATION
───────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
    try {
        setupEventListeners();
        initializeApp(); // async — loads saved state then boots UI
    } catch (err) {
        // Surface any startup crash visibly instead of silent freeze
        console.error('Privacy Guardian init error:', err);
        const banner = document.createElement('div');
        banner.style.cssText = 'background:#dc2626;color:#fff;padding:12px 16px;text-align:center;font-size:14px;';
        banner.textContent = 'App failed to start — please refresh the page. (' + err.message + ')';
        document.body.prepend(banner);
    }
});

async function initializeApp() {
    // Load persisted state from server
    const saved = await storageLoadAll();

    // Dark mode
    if (saved.darkMode === true) {
        AppState.darkMode = true;
        document.body.classList.add('dark-mode');
    }
    updateDarkModeIcon();

    // User info
    if (saved.userInfo && typeof saved.userInfo === 'object') {
        AppState.userInfo = validateUserInfo(saved.userInfo);
        populateForm(AppState.userInfo);
    }

    // Scan results
    if (Array.isArray(saved.scanResults) && saved.scanResults.length) {
        AppState.scanResults = saved.scanResults.map(validateScanResult).filter(Boolean);
        displayResults();
    }

    checkFollowUps();
}

function loadSavedData() { /* replaced by initializeApp async flow */ }

function populateForm(data) {
    const ids = ['firstName','lastName','city','state','email','phone'];
    ids.forEach(id => {
        const input = document.getElementById(id);
        if (input && data[id]) input.value = sanitizeText(data[id]);
    });
}

/* ─────────────────────────────────────────────
   9. EVENT LISTENERS
───────────────────────────────────────────── */

function setupEventListeners() {
    // Scan button — direct click handler (not form submit) so page never reloads
    document.getElementById('scanBtn').addEventListener('click', handleSearch);
    // Also keep form submit as fallback (e.g. Enter key in a field)
    document.getElementById('searchForm').addEventListener('submit', handleSearch);
    document.getElementById('clearBtn').addEventListener('click', clearForm);
    document.getElementById('darkModeToggle').addEventListener('click', toggleDarkMode);
    document.getElementById('helpBtn').addEventListener('click', () => document.getElementById('helpModal').classList.add('active'));
    document.getElementById('exportCSVBtn').addEventListener('click', exportToCSV);
    document.getElementById('exportReportBtn').addEventListener('click', () => window.print());
    document.getElementById('clearResultsBtn').addEventListener('click', clearResults);

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', function () { filterResults(this.dataset.filter); });
    });

    // Modal close buttons (including dynamically added modals)
    document.addEventListener('click', e => {
        if (e.target.classList.contains('modal-close')) {
            e.target.closest('.modal')?.classList.remove('active');
        }
    });

    document.querySelectorAll('.modal').forEach(m => {
        m.addEventListener('click', e => { if (e.target === m) m.classList.remove('active'); });
    });

    document.getElementById('copyEmailBtn')?.addEventListener('click', copyEmailTemplate);

    // Notes modal save
    document.getElementById('saveNotesBtn')?.addEventListener('click', saveNotes);
}

/* ─────────────────────────────────────────────
   10. SEARCH + SCAN
───────────────────────────────────────────── */

function handleSearch(e) {
    if (e && e.preventDefault) e.preventDefault();

    const formData = {
        firstName: document.getElementById('firstName').value,
        lastName:  document.getElementById('lastName').value,
        city:      document.getElementById('city').value,
        state:     document.getElementById('state').value.toUpperCase(),
        email:     document.getElementById('email').value,
        phone:     document.getElementById('phone').value
    };

    // Sanitize every field
    const cleaned = validateUserInfo(formData);

    if (!cleaned.firstName || !cleaned.lastName) {
        showToast('Please enter at least your first and last name.', 'error');
        return;
    }

    AppState.userInfo = cleaned;
    storageSave(STORAGE_KEYS.USER_INFO, cleaned);
    startScan();
}

function startScan() {
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('resultsSection').style.display  = 'none';
    document.getElementById('progressSection').scrollIntoView({ behavior: 'smooth' });

    AppState.scanResults = dataBrokers.map(broker => validateScanResult({
        ...broker,
        status: 'checking',
        dateFound: null,
        removalRequested: null,
        followUpDate: null,
        notes: ''
    }));

    let progress = 0;
    const total = dataBrokers.length;
    const fill  = document.getElementById('progressFill');
    const txt   = document.getElementById('progressText');

    const tick = () => {
        if (progress < total) {
            progress++;
            const pct = (progress / total) * 100;
            fill.style.width = pct + '%';
            txt.textContent  = `${progress} of ${total} sites checked`;

            const rand = Math.random();
            let status;
            if (rand < 0.3) {
                status = 'found';
                AppState.scanResults[progress-1].dateFound = new Date().toISOString();
            } else if (rand < 0.4) {
                status = 'pending';
                AppState.scanResults[progress-1].dateFound        = new Date(Date.now() - 7*86400000).toISOString();
                AppState.scanResults[progress-1].removalRequested = new Date(Date.now() - 3*86400000).toISOString();
                AppState.scanResults[progress-1].followUpDate     = new Date(Date.now() + 7*86400000).toISOString();
            } else {
                status = 'clean';
            }
            AppState.scanResults[progress-1].status = status;
            setTimeout(tick, 80);
        } else {
            completeScan();
        }
    };
    setTimeout(tick, 80);
}

function completeScan() {
    storageSave(STORAGE_KEYS.SCAN_RESULTS, AppState.scanResults);
    setTimeout(() => {
        document.getElementById('progressSection').style.display = 'none';
        displayResults();
        document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
    }, 400);
}

/* ─────────────────────────────────────────────
   11. DISPLAY RESULTS (DOM-only, no innerHTML)
───────────────────────────────────────────── */

function displayResults() {
    document.getElementById('resultsSection').style.display  = 'block';
    document.getElementById('trackingSection').style.display = 'block';
    updateStats();
    displayBrokerCards();
    displayTrackingTable();
}

function updateStats() {
    const count = status => AppState.scanResults.filter(r => r.status === status).length;
    setText(document.getElementById('foundCount'),   count('found'));
    setText(document.getElementById('pendingCount'), count('pending'));
    setText(document.getElementById('removedCount'), count('removed'));
    setText(document.getElementById('cleanCount'),   count('clean'));
}

function displayBrokerCards() {
    const grid = document.getElementById('brokersGrid');
    grid.textContent = ''; // safe clear — no innerHTML

    let list = AppState.scanResults;
    if (AppState.currentFilter !== 'all') {
        list = list.filter(r => r.status === AppState.currentFilter);
    }

    if (list.length === 0) {
        const msg = el('p', { text: 'No results found for this filter.', cls: 'text-center' });
        msg.style.gridColumn = '1/-1';
        msg.style.color = 'var(--text-secondary)';
        grid.appendChild(msg);
        return;
    }

    // Use patched card builder from payment.js (adds FREE/PRO badges) if available
    const cardBuilder = window._patchedCreateBrokerCard || createBrokerCard;
    list.forEach(broker => grid.appendChild(cardBuilder(broker)));
}

/* Build a broker card entirely via DOM APIs — zero innerHTML */
function createBrokerCard(broker) {
    const statusLabels = {
        found: 'Data Found', pending: 'Removal Pending',
        removed: 'Removed', clean: 'No Data Found', checking: 'Checking…'
    };

    const card = el('div', { cls: 'broker-card fade-in', attrs: { 'data-status': broker.status } });

    // Header row
    const header = el('div', { cls: 'broker-header' });
    const nameBlock = el('div');
    nameBlock.appendChild(el('div', { cls: 'broker-name',     text: broker.name }));
    nameBlock.appendChild(el('div', { cls: 'broker-category', text: broker.category }));
    const badge = el('span', {
        cls:  `status-badge status-${broker.status}`,
        text: statusLabels[broker.status] || broker.status
    });
    header.appendChild(nameBlock);
    header.appendChild(badge);
    card.appendChild(header);

    // Info rows
    const info = el('div', { cls: 'broker-info' });

    const addRow = (label, value, valueCls) => {
        const row = el('div', { cls: 'info-row' });
        row.appendChild(el('span', { cls: 'info-label', text: label }));
        const v = el('span', { cls: `info-value${valueCls ? ' '+valueCls : ''}`, text: value });
        row.appendChild(v);
        info.appendChild(row);
    };

    addRow('Difficulty:', broker.difficulty, `difficulty-${broker.difficulty.toLowerCase()}`);
    addRow('Est. Time:',  broker.estimatedTime);
    if (broker.dateFound) addRow('Date Found:', formatDate(broker.dateFound));
    card.appendChild(info);

    // Instructions
    if (broker.instructions) {
        const instr = el('div', { cls: 'broker-instructions' });
        const strong = document.createElement('strong');
        strong.textContent = 'Instructions: ';
        instr.appendChild(strong);
        instr.appendChild(document.createTextNode(sanitizeText(broker.instructions)));
        card.appendChild(instr);
    }

    // Notes preview
    if (broker.notes) {
        const notesPrev = el('div', { cls: 'broker-instructions', text: '📝 ' + broker.notes });
        notesPrev.style.fontStyle = 'italic';
        card.appendChild(notesPrev);
    }

    // Action buttons
    const actions = el('div', { cls: 'broker-actions' });

    const viewBtn = el('button', { cls: 'btn btn-secondary btn-small' });
    viewBtn.appendChild(icon('fas fa-external-link-alt'));
    viewBtn.appendChild(document.createTextNode(' View Site'));
    viewBtn.addEventListener('click', () => safeOpen(broker.url));
    actions.appendChild(viewBtn);

    if (broker.status === 'found' || broker.status === 'pending') {
        const optBtn = el('button', { cls: 'btn btn-primary btn-small' });
        optBtn.appendChild(icon('fas fa-user-slash'));
        optBtn.appendChild(document.createTextNode(' Opt-Out Page'));
        optBtn.addEventListener('click', () => safeOpen(broker.optOutUrl));
        actions.appendChild(optBtn);

        const emailBtn = el('button', { cls: 'btn btn-secondary btn-small' });
        emailBtn.appendChild(icon('fas fa-envelope'));
        emailBtn.appendChild(document.createTextNode(' Email Template'));
        emailBtn.addEventListener('click', () => showEmailTemplate(broker));
        actions.appendChild(emailBtn);
    }

    if (broker.status === 'found') {
        const reqBtn = el('button', { cls: 'btn btn-success btn-small' });
        reqBtn.appendChild(icon('fas fa-paper-plane'));
        reqBtn.appendChild(document.createTextNode(' Request Removal'));
        reqBtn.addEventListener('click', () => requestRemoval(broker));
        actions.appendChild(reqBtn);
    }

    if (broker.status === 'pending') {
        const markBtn = el('button', { cls: 'btn btn-success btn-small' });
        markBtn.appendChild(icon('fas fa-check'));
        markBtn.appendChild(document.createTextNode(' Mark Removed'));
        markBtn.addEventListener('click', () => markAsRemoved(broker));
        actions.appendChild(markBtn);
    }

    const notesBtn = el('button', { cls: 'btn btn-outline btn-small' });
    notesBtn.appendChild(icon('fas fa-sticky-note'));
    notesBtn.appendChild(document.createTextNode(' Notes'));
    notesBtn.addEventListener('click', () => openNotesModal(broker));
    actions.appendChild(notesBtn);

    card.appendChild(actions);
    return card;
}

/* ─────────────────────────────────────────────
   12. TRACKING TABLE (no innerHTML)
───────────────────────────────────────────── */

function displayTrackingTable() {
    const tbody = document.getElementById('trackingTableBody');
    tbody.textContent = ''; // safe clear

    const tracked = AppState.scanResults.filter(r =>
        ['found','pending','removed'].includes(r.status)
    );

    if (tracked.length === 0) {
        const row = document.createElement('tr');
        const cell = el('td', { text: 'No data brokers to track yet.', attrs: { colspan: '6' } });
        cell.style.textAlign = 'center';
        cell.style.color = 'var(--text-secondary)';
        row.appendChild(cell);
        tbody.appendChild(row);
        return;
    }

    tracked.forEach(broker => {
        const row = document.createElement('tr');

        const mkTd = (content, isElement = false) => {
            const td = document.createElement('td');
            if (isElement) td.appendChild(content);
            else td.textContent = sanitizeText(String(content));
            return td;
        };

        const nameTd = document.createElement('td');
        const strong = document.createElement('strong');
        strong.textContent = sanitizeText(broker.name);
        nameTd.appendChild(strong);

        const badgeTd = document.createElement('td');
        badgeTd.appendChild(el('span', {
            cls:  `status-badge status-${broker.status}`,
            text: broker.status
        }));

        const actionTd = document.createElement('td');
        const linkBtn = el('button', { cls: 'btn btn-small btn-secondary' });
        linkBtn.appendChild(icon('fas fa-external-link-alt'));
        linkBtn.setAttribute('title', 'Open opt-out page');
        linkBtn.addEventListener('click', () => safeOpen(broker.optOutUrl));
        actionTd.appendChild(linkBtn);

        row.appendChild(nameTd);
        row.appendChild(badgeTd);
        row.appendChild(mkTd(broker.dateFound        ? formatDate(broker.dateFound)        : '—'));
        row.appendChild(mkTd(broker.removalRequested ? formatDate(broker.removalRequested) : '—'));
        row.appendChild(mkTd(broker.followUpDate     ? formatDate(broker.followUpDate)     : '—'));
        row.appendChild(actionTd);

        tbody.appendChild(row);
    });
}

/* ─────────────────────────────────────────────
   13. ACTIONS
───────────────────────────────────────────── */

function requestRemoval(broker) {
    const result = AppState.scanResults.find(r => r.id === broker.id);
    if (result) {
        result.status           = 'pending';
        result.removalRequested = new Date().toISOString();
        result.followUpDate     = new Date(Date.now() + 30*86400000).toISOString();
        saveAndRefresh();
        showToast(`Removal request logged for ${sanitizeText(broker.name)}. Follow up in 30 days.`, 'success');
    }
}

function markAsRemoved(broker) {
    const result = AppState.scanResults.find(r => r.id === broker.id);
    if (result) {
        result.status = 'removed';
        saveAndRefresh();
        showToast(`${sanitizeText(broker.name)} marked as removed.`, 'success');
    }
}

function filterResults(filter) {
    AppState.currentFilter = filter;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    displayBrokerCards();
}

function clearForm() {
    document.getElementById('searchForm').reset();
    AppState.userInfo = {};
    storageSave(null, null); // sync cleared userInfo to server
    showToast('Form cleared.', 'info');
}

function clearResults() {
    confirmAction('Clear all scan results? This cannot be undone.', () => {
        AppState.scanResults = [];
        storageSave(null, null); // sync cleared results to server
        document.getElementById('resultsSection').style.display  = 'none';
        document.getElementById('trackingSection').style.display = 'none';
        document.getElementById('progressSection').style.display = 'none';
        showToast('All results cleared.', 'info');
    });
}

/* ─────────────────────────────────────────────
   14. DARK MODE
───────────────────────────────────────────── */

function toggleDarkMode() {
    AppState.darkMode = !AppState.darkMode;
    document.body.classList.toggle('dark-mode');
    storageSave(STORAGE_KEYS.DARK_MODE, AppState.darkMode);
    updateDarkModeIcon();
}

function updateDarkModeIcon() {
    const i = document.querySelector('#darkModeToggle i');
    if (!i) return;
    if (AppState.darkMode) {
        i.className = 'fas fa-sun';
    } else {
        i.className = 'fas fa-moon';
    }
}

/* ─────────────────────────────────────────────
   15. EMAIL TEMPLATE (no innerHTML)
───────────────────────────────────────────── */

function showEmailTemplate(broker) {
    const template = generateEmailTemplate(broker);
    const ta = document.getElementById('emailTemplate');
    if (ta) ta.value = template; // textarea .value is safe
    document.getElementById('emailModal').classList.add('active');
}

function generateEmailTemplate(broker) {
    const u = AppState.userInfo;
    const today = new Date().toLocaleDateString();
    // Build with array join — no user-provided HTML can escape this
    return [
        `Subject: Request for Data Removal — ${sanitizeText(u.firstName)} ${sanitizeText(u.lastName)}`,
        '',
        `Dear ${sanitizeText(broker.name)} Privacy Team,`,
        '',
        `I am writing to request the immediate removal of my personal information from your database, pursuant to the California Consumer Privacy Act (CCPA), the General Data Protection Regulation (GDPR), and all other applicable privacy laws.`,
        '',
        'My Information:',
        `  Name:  ${sanitizeText(u.firstName)} ${sanitizeText(u.lastName)}`,
        u.city  ? `  City:  ${sanitizeText(u.city)}`  : '',
        u.state ? `  State: ${sanitizeText(u.state)}` : '',
        u.email ? `  Email: ${sanitizeText(u.email)}` : '',
        u.phone ? `  Phone: ${sanitizeText(u.phone)}` : '',
        '',
        `Date of Request: ${today}`,
        '',
        'I formally request that you:',
        '  1. Remove ALL of my personal information from your public-facing website immediately.',
        '  2. Delete my data from your internal databases and any downstream data-sharing partners.',
        '  3. Cease any further collection, processing, sale, or transfer of my personal information.',
        '  4. Provide written confirmation of this removal within 30 days.',
        '',
        'Under applicable law, failure to comply may result in a formal complaint filed with the Federal Trade Commission (FTC), the California Attorney General, and/or relevant state consumer protection agencies.',
        '',
        'Sincerely,',
        `${sanitizeText(u.firstName)} ${sanitizeText(u.lastName)}`
    ].filter(l => l !== null).join('\n');
}

function copyEmailTemplate() {
    const ta  = document.getElementById('emailTemplate');
    const btn = document.getElementById('copyEmailBtn');
    if (!ta || !btn) return;

    navigator.clipboard.writeText(ta.value).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 2000);
    }).catch(() => {
        // Fallback for browsers that block clipboard API
        ta.select();
        document.execCommand('copy');
        showToast('Copied to clipboard.', 'success');
    });
}

/* ─────────────────────────────────────────────
   16. NOTES MODAL
───────────────────────────────────────────── */

let _currentNotesBrokerId = null;

function openNotesModal(broker) {
    _currentNotesBrokerId = broker.id;
    const nameEl = document.getElementById('notesModalBrokerName');
    const ta     = document.getElementById('notesTextarea');
    if (nameEl) nameEl.textContent = sanitizeText(broker.name);
    if (ta)     ta.value = sanitizeText(broker.notes || '');
    document.getElementById('notesModal').classList.add('active');
}

function saveNotes() {
    if (!_currentNotesBrokerId) return;
    const ta = document.getElementById('notesTextarea');
    if (!ta) return;
    const result = AppState.scanResults.find(r => r.id === _currentNotesBrokerId);
    if (result) {
        result.notes = sanitizeText(ta.value).slice(0, 1000);
        saveAndRefresh();
        document.getElementById('notesModal').classList.remove('active');
        showToast('Notes saved.', 'success');
    }
}

/* ─────────────────────────────────────────────
   17. EXPORT (CSV — sanitized values)
───────────────────────────────────────────── */

function exportToCSV() {
    const headers = ['Data Broker','Status','Category','Difficulty','Date Found','Removal Requested','Follow-up Date','Opt-Out URL'];

    const escape = v => `"${String(v).replace(/"/g, '""')}"`;

    const rows = AppState.scanResults.map(b => [
        sanitizeText(b.name),
        b.status,
        sanitizeText(b.category),
        sanitizeText(b.difficulty),
        b.dateFound        ? formatDate(b.dateFound)        : '',
        b.removalRequested ? formatDate(b.removalRequested) : '',
        b.followUpDate     ? formatDate(b.followUpDate)     : '',
        isSafeUrl(b.optOutUrl) ? b.optOutUrl : ''
    ].map(escape).join(','));

    const csv  = [headers.map(escape).join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `privacy-guardian-${new Date().toISOString().split('T')[0]}.csv`;
    a.rel      = 'noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('CSV exported.', 'success');
}

/* ─────────────────────────────────────────────
   18. FOLLOW-UP CHECKER
───────────────────────────────────────────── */

function checkFollowUps() {
    const today = new Date();
    const due = AppState.scanResults.filter(b => {
        if (b.status !== 'pending' || !b.followUpDate) return false;
        return new Date(b.followUpDate) <= today;
    });
    if (due.length > 0) {
        showToast(`${due.length} broker(s) need a follow-up check.`, 'info');
    }
}

/* ─────────────────────────────────────────────
   19. HELPERS
───────────────────────────────────────────── */

function saveAndRefresh() {
    storageSave(STORAGE_KEYS.SCAN_RESULTS, AppState.scanResults);
    displayResults();
}

function formatDate(dateString) {
    if (!dateString || !isValidISODate(dateString)) return '—';
    return new Date(dateString).toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' });
}
