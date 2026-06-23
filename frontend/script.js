const API_BASE_URL = 'http://localhost:5000';

let selectedFiles = [];
let analysisResults = [];
let scanHistory = JSON.parse(localStorage.getItem('maldetect_history') || '[]');

const dropZone      = document.getElementById('dropZone');
const fileInput     = document.getElementById('fileInput');
const fileListDiv   = document.getElementById('fileList');
const analyzeBtn    = document.getElementById('analyzeBtn');
const resultsDiv    = document.getElementById('results');
const statisticsDiv = document.getElementById('statistics');
const fileCountEl   = document.getElementById('fileCount');
const resultCountEl = document.getElementById('resultCount');
const apiStatusEl   = document.getElementById('apiStatus');

// ── Page navigation ───────────────────────────────────────────
function showPage(name, el) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('page-' + name).classList.add('active');
    if (el) el.classList.add('active');
    if (name === 'history') renderHistory();
    if (name === 'reports') renderReportPreview();
    if (name === 'settings') {
        const dot = document.getElementById('settingApiDot');
        const apiDot = apiStatusEl.querySelector('.status-dot');
        if (dot && apiDot) dot.className = apiDot.className;
    }
}

// ── Theme ─────────────────────────────────────────────────────
function toggleTheme() {
    const html = document.documentElement;
    const isDark = html.getAttribute('data-theme') === 'dark';
    html.setAttribute('data-theme', isDark ? 'light' : 'dark');
    localStorage.setItem('maldetect_theme', isDark ? 'light' : 'dark');
}

(function() {
    const saved = localStorage.getItem('maldetect_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const toggle = document.getElementById('themeToggle');
    if (toggle) toggle.checked = saved === 'dark';
})();

// ── Drag & drop ───────────────────────────────────────────────
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', e => { e.preventDefault(); dropZone.classList.remove('drag-over'); });
dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    addFiles(Array.from(e.dataTransfer.files));
});
fileInput.addEventListener('change', e => addFiles(Array.from(e.target.files)));

// ── File management ───────────────────────────────────────────
function addFiles(files) {
    const allowed = ['.exe', '.dll', '.sys', '.bin'];
    files.forEach(file => {
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        if (!allowed.includes(ext)) {
            alert(`"${file.name}" is not supported.\nOnly .exe, .dll, .sys files are accepted.`);
            return;
        }
        if (!selectedFiles.find(f => f.name === file.name && f.size === file.size)) {
            selectedFiles.push({ name: file.name, size: file.size, file });
        }
    });
    renderFileList();
    syncButtons();
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    renderFileList();
    syncButtons();
}

function renderFileList() {
    fileCountEl.textContent = `${selectedFiles.length} file${selectedFiles.length !== 1 ? 's' : ''}`;
    if (selectedFiles.length === 0) { fileListDiv.innerHTML = ''; return; }
    fileListDiv.innerHTML = selectedFiles.map((f, i) => `
        <div class="file-item">
            <div class="file-info">
                <i class="ti ti-file-code file-icon"></i>
                <div>
                    <div class="file-name">${escapeHtml(f.name)}</div>
                    <div class="file-size">${formatSize(f.size)}</div>
                </div>
            </div>
            <button class="btn-remove" onclick="removeFile(${i})"><i class="ti ti-x"></i></button>
        </div>
    `).join('');
}

function syncButtons() { analyzeBtn.disabled = selectedFiles.length === 0; }

// ── Analysis ──────────────────────────────────────────────────
async function analyzeFiles() {
    if (selectedFiles.length === 0) return;
    analyzeBtn.disabled = true;
    analysisResults = [];

    resultsDiv.innerHTML = `
        <div class="loading-wrap">
            <div class="spinner"></div>
            <div class="loading-text">Analyzing ${selectedFiles.length} file${selectedFiles.length !== 1 ? 's' : ''}…</div>
        </div>`;
    statisticsDiv.innerHTML = '';

    for (let i = 0; i < selectedFiles.length; i++) {
        const fileObj = selectedFiles[i];
        const loadingText = document.querySelector('.loading-text');
        if (loadingText) loadingText.textContent = `Analyzing file ${i + 1} of ${selectedFiles.length}: ${fileObj.name}`;

        try {
            const formData = new FormData();
            formData.append('file', fileObj.file);
            const response = await fetch(`${API_BASE_URL}/analyze`, { method: 'POST', body: formData });
            const result = await response.json();
            analysisResults.push({ ...result, filename: fileObj.name });
        } catch (err) {
            analysisResults.push({ filename: fileObj.name, error: 'Could not reach the backend server.' });
        }
    }

    // Save to history
    analysisResults.forEach(r => {
        if (!r.error) {
            scanHistory.unshift({ ...r, scan_time: new Date().toISOString() });
        }
    });
    if (scanHistory.length > 100) scanHistory = scanHistory.slice(0, 100);
    localStorage.setItem('maldetect_history', JSON.stringify(scanHistory));

    renderResults();
    renderStatistics();
    analyzeBtn.disabled = false;
}

// ── Render results ────────────────────────────────────────────
function renderResults() {
    if (analysisResults.length === 0) return;
    resultCountEl.textContent = `${analysisResults.length} result${analysisResults.length !== 1 ? 's' : ''}`;
    resultsDiv.innerHTML = analysisResults.map(r => r.error ? renderErrorCard(r) : renderResultCard(r)).join('');
}

function renderResultCard(r) {
    const malPct  = (r.malicious_probability * 100).toFixed(1);
    const confPct = (r.confidence * 100).toFixed(1);
    const isMal   = r.is_malicious;
    const risk    = (r.risk_level || 'Low').toLowerCase();
    const barClass = risk === 'high' ? 'danger' : risk === 'medium' ? 'warning' : 'safe';

    // PE Info section
    const peSection = r.pe_info && Object.keys(r.pe_info).length > 0 ? `
        <details class="pe-toggle">
            <summary><i class="ti ti-code"></i> PE file details</summary>
            <div class="pe-grid">
                ${r.pe_info.entry_point ? `<div class="pe-item"><div class="pe-key">Entry point</div><div class="pe-val">${escapeHtml(String(r.pe_info.entry_point))}</div></div>` : ''}
                ${r.pe_info.has_signature !== undefined ? `<div class="pe-item"><div class="pe-key">Signature</div><div class="pe-val">${r.pe_info.has_signature ? 'Signed' : 'Not signed'}</div></div>` : ''}
                ${r.pe_info.sections?.length ? `<div class="pe-item"><div class="pe-key">Sections</div><div class="pe-val">${r.pe_info.sections.map(s => escapeHtml(s)).join(', ')}</div></div>` : ''}
                ${r.pe_info.imports?.length ? `<div class="pe-item"><div class="pe-key">Top imports</div><div class="pe-val">${r.pe_info.imports.slice(0,5).map(s => escapeHtml(s)).join(', ')}</div></div>` : ''}
            </div>
        </details>` : '';

    // VirusTotal section
    let vtSection = '';
    if (r.vt_info && r.vt_info.vt_found) {
        const vtMal   = r.vt_info.vt_malicious || 0;
        const vtTotal = r.vt_info.vt_total || 0;
        const vtColor = vtMal > 10 ? 'var(--danger)' : vtMal > 0 ? 'var(--warning)' : 'var(--success)';
        const vtName  = r.vt_info.vt_name ? `<div class="pe-item"><div class="pe-key">Known as</div><div class="pe-val">${escapeHtml(r.vt_info.vt_name)}</div></div>` : '';
        vtSection = `
        <details class="pe-toggle">
            <summary><i class="ti ti-world"></i> VirusTotal Community Reference</summary>
            <div style="margin-top:8px;">
                <div class="vt-notice">
                    <i class="ti ti-lock" style="color:var(--success);"></i>
                    Your file was <strong>NOT uploaded</strong> to VirusTotal — only its SHA256 hash was checked. Your file remains private.
                </div>
                <div class="pe-grid" style="margin-top:8px;">
                    <div class="pe-item">
                        <div class="pe-key">VT Detections</div>
                        <div class="pe-val" style="color:${vtColor};font-weight:600;">
                            ${vtMal} / ${vtTotal} vendors flagged
                        </div>
                    </div>
                    <div class="pe-item">
                        <div class="pe-key">SHA256</div>
                        <div class="pe-val" style="font-size:10px;word-break:break-all;">${r.vt_info.hash}</div>
                    </div>
                    ${vtName}
                </div>
            </div>
        </details>`;
    } else if (r.vt_info && !r.vt_info.vt_found && r.vt_info.hash) {
        vtSection = `
        <details class="pe-toggle">
            <summary><i class="ti ti-world"></i> VirusTotal Community Reference</summary>
            <div style="margin-top:8px;">
                <div class="vt-notice">
                    <i class="ti ti-lock" style="color:var(--success);"></i>
                    Your file was <strong>NOT uploaded</strong> to VirusTotal — only its SHA256 hash was checked.
                </div>
                <div style="margin-top:8px;font-size:12px;color:var(--text-muted);">
                    Hash not found in VirusTotal database — this may be a new or rare file.
                </div>
                <div class="pe-item" style="margin-top:6px;">
                    <div class="pe-key">SHA256</div>
                    <div class="pe-val" style="font-size:10px;word-break:break-all;">${r.vt_info.hash}</div>
                </div>
            </div>
        </details>`;
    }

    return `
        <div class="result-card ${isMal ? 'danger' : 'safe'}">
            <div class="result-top">
                <div>
                    <div class="result-filename">${escapeHtml(r.filename)}</div>
                    <div class="result-meta">${r.analysis_timestamp ? formatTimestamp(r.analysis_timestamp) : ''}</div>
                </div>
                <div class="verdict-badge ${isMal ? 'malicious' : 'safe'}">
                    <i class="ti ti-${isMal ? 'alert-triangle' : 'shield-check'}"></i>
                    ${isMal ? 'Malicious' : 'Safe'}
                </div>
            </div>
            <div class="risk-row">
                <span class="risk-label">Malicious</span>
                <div class="prob-bar-wrap"><div class="prob-bar-fill ${barClass}" style="width:${malPct}%"></div></div>
                <span class="prob-pct">${malPct}%</span>
                <span class="risk-pill ${risk}">${r.risk_level || 'Low'}</span>
            </div>
            <div class="risk-row">
                <span class="risk-label">Confidence</span>
                <div class="prob-bar-wrap"><div class="prob-bar-fill safe" style="width:${confPct}%"></div></div>
                <span class="prob-pct">${confPct}%</span>
            </div>
            ${peSection}
            ${vtSection}
        </div>`;
}

function renderErrorCard(r) {
    return `
        <div class="result-card danger">
            <div class="result-top">
                <div>
                    <div class="result-filename">${escapeHtml(r.filename)}</div>
                    <div class="result-meta" style="color:var(--danger);margin-top:4px;">
                        <i class="ti ti-alert-circle"></i> ${escapeHtml(r.error)}
                    </div>
                </div>
                <div class="verdict-badge malicious"><i class="ti ti-x"></i> Error</div>
            </div>
        </div>`;
}

// ── Statistics ────────────────────────────────────────────────
function renderStatistics() {
    const total    = analysisResults.length;
    const malCount = analysisResults.filter(r => r.is_malicious === true).length;
    const safeCount = analysisResults.filter(r => r.is_malicious === false).length;
    const withConf = analysisResults.filter(r => r.confidence != null);
    const avgConf  = withConf.length
        ? (withConf.reduce((s, r) => s + r.confidence, 0) / withConf.length * 100).toFixed(1) : '—';

    statisticsDiv.innerHTML = `
        <div class="stat-card"><div class="stat-label">Total analyzed</div><div class="stat-number accent">${total}</div></div>
        <div class="stat-card"><div class="stat-label">Safe files</div><div class="stat-number success">${safeCount}</div></div>
        <div class="stat-card"><div class="stat-label">Malicious files</div><div class="stat-number danger">${malCount}</div></div>
        <div class="stat-card"><div class="stat-label">Avg confidence</div><div class="stat-number">${avgConf}${avgConf !== '—' ? '%' : ''}</div></div>`;
}

// ── Clear ─────────────────────────────────────────────────────
function clearAll() {
    selectedFiles = []; analysisResults = [];
    renderFileList(); syncButtons();
    fileInput.value = '';
    fileCountEl.textContent = '0 files';
    resultCountEl.textContent = '';
    statisticsDiv.innerHTML = '';
    resultsDiv.innerHTML = `
        <div class="empty-state">
            <i class="ti ti-shield-search empty-icon"></i>
            <p>No results yet</p>
            <small>Upload files and click Run analysis</small>
        </div>`;
}

// ── History ───────────────────────────────────────────────────
function renderHistory() {
    const container = document.getElementById('historyList');
    if (scanHistory.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="padding:60px 0;">
                <i class="ti ti-history empty-icon"></i>
                <p>No scan history yet</p>
                <small>Run an analysis to see results here</small>
            </div>`;
        return;
    }
    container.innerHTML = scanHistory.map(r => `
        <div class="history-card ${r.is_malicious ? 'danger' : 'safe'}">
            <div class="history-top">
                <span class="history-filename">${escapeHtml(r.filename)}</span>
                <div class="verdict-badge ${r.is_malicious ? 'malicious' : 'safe'}">
                    <i class="ti ti-${r.is_malicious ? 'alert-triangle' : 'shield-check'}"></i>
                    ${r.is_malicious ? 'Malicious' : 'Safe'}
                </div>
            </div>
            <div class="history-meta">
                <span><i class="ti ti-clock" style="font-size:12px;"></i> ${formatTimestamp(r.scan_time || r.analysis_timestamp)}</span>
                <span>Malicious: ${(r.malicious_probability * 100).toFixed(1)}%</span>
                <span>Confidence: ${(r.confidence * 100).toFixed(1)}%</span>
                <span class="risk-pill ${(r.risk_level||'low').toLowerCase()}">${r.risk_level || 'Low'}</span>
                ${r.vt_info && r.vt_info.vt_found ? `<span style="color:var(--text-muted);">VT: ${r.vt_info.vt_malicious}/${r.vt_info.vt_total}</span>` : ''}
            </div>
        </div>
    `).join('');
}

function clearHistory() {
    if (!confirm('Clear all scan history?')) return;
    scanHistory = [];
    localStorage.removeItem('maldetect_history');
    renderHistory();
}

// ── Reports / PDF ─────────────────────────────────────────────
function renderReportPreview() {
    const preview = document.getElementById('reportPreview');
    const actions = document.getElementById('reportActions');

    if (scanHistory.length === 0) {
        preview.innerHTML = `
            <div class="empty-state" style="padding:60px 0;">
                <i class="ti ti-file-analytics empty-icon"></i>
                <p>No data to report yet</p>
                <small>Run a scan first, then come back to generate a report</small>
            </div>`;
        actions.style.display = 'none';
        return;
    }

    const total    = scanHistory.length;
    const malCount = scanHistory.filter(r => r.is_malicious).length;
    const safeCount = total - malCount;

    preview.innerHTML = `
        <h3 style="font-size:16px;font-weight:600;color:var(--text-primary);margin-bottom:16px;">
            <i class="ti ti-file-analytics" style="color:var(--accent);"></i> Report Summary
        </h3>
        <div class="stats-row" style="margin-bottom:20px;">
            <div class="stat-card"><div class="stat-label">Total scans</div><div class="stat-number accent">${total}</div></div>
            <div class="stat-card"><div class="stat-label">Safe</div><div class="stat-number success">${safeCount}</div></div>
            <div class="stat-card"><div class="stat-label">Malicious</div><div class="stat-number danger">${malCount}</div></div>
            <div class="stat-card"><div class="stat-label">Detection rate</div><div class="stat-number">${total ? ((malCount/total)*100).toFixed(1) : 0}%</div></div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:12.5px;">
            <thead>
                <tr style="border-bottom:1px solid var(--border);color:var(--text-muted);text-align:left;">
                    <th style="padding:8px 12px;">File</th>
                    <th style="padding:8px 12px;">Verdict</th>
                    <th style="padding:8px 12px;">Malicious %</th>
                    <th style="padding:8px 12px;">VT Detections</th>
                    <th style="padding:8px 12px;">Risk</th>
                    <th style="padding:8px 12px;">Scanned</th>
                </tr>
            </thead>
            <tbody>
                ${scanHistory.slice(0, 20).map(r => `
                    <tr style="border-bottom:1px solid var(--border);">
                        <td style="padding:8px 12px;color:var(--text-primary);">${escapeHtml(r.filename.length > 25 ? r.filename.substring(0,23)+'..' : r.filename)}</td>
                        <td style="padding:8px 12px;color:${r.is_malicious ? 'var(--danger)' : 'var(--success)'};">${r.is_malicious ? '⚠ Malicious' : '✓ Safe'}</td>
                        <td style="padding:8px 12px;color:var(--text-secondary);">${(r.malicious_probability*100).toFixed(1)}%</td>
                        <td style="padding:8px 12px;color:var(--text-secondary);">${r.vt_info && r.vt_info.vt_found ? `${r.vt_info.vt_malicious}/${r.vt_info.vt_total}` : 'N/A'}</td>
                        <td style="padding:8px 12px;color:var(--text-secondary);">${r.risk_level || 'Low'}</td>
                        <td style="padding:8px 12px;color:var(--text-muted);">${formatTimestamp(r.scan_time || r.analysis_timestamp)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        ${scanHistory.length > 20 ? `<p style="font-size:12px;color:var(--text-muted);margin-top:10px;">Showing 20 of ${scanHistory.length} records</p>` : ''}`;
    actions.style.display = 'flex';
}

function downloadPDF() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const total    = scanHistory.length;
    const malCount = scanHistory.filter(r => r.is_malicious).length;
    const safeCount = total - malCount;
    const now      = new Date().toLocaleString();

    doc.setFillColor(108, 99, 255);
    doc.rect(0, 0, 210, 30, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('MalDetect — Analysis Report', 14, 18);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(`Generated: ${now}   |   Model: Random Forest · EMBER`, 14, 26);

    doc.setTextColor(30, 30, 50);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Summary', 14, 42);

    const boxes = [
        { label: 'Total Scans', value: total,     color: [108, 99, 255] },
        { label: 'Safe Files',  value: safeCount,  color: [34, 197, 94]  },
        { label: 'Malicious',   value: malCount,   color: [239, 68, 68]  },
        { label: 'Detection %', value: total ? ((malCount/total)*100).toFixed(1)+'%' : '0%', color: [245, 158, 11] }
    ];
    boxes.forEach((b, i) => {
        const x = 14 + i * 47;
        doc.setFillColor(...b.color);
        doc.roundedRect(x, 46, 43, 22, 3, 3, 'F');
        doc.setTextColor(255,255,255);
        doc.setFontSize(16);
        doc.setFont('helvetica', 'bold');
        doc.text(String(b.value), x + 21.5, 57, { align: 'center' });
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        doc.text(b.label, x + 21.5, 64, { align: 'center' });
    });

    doc.setTextColor(30, 30, 50);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Scan Results', 14, 80);

    const headers = ['File', 'Verdict', 'Mal%', 'VT', 'Risk', 'Scanned'];
    const colW    = [55, 25, 20, 20, 18, 44];
    let y = 86;

    doc.setFillColor(240, 241, 248);
    doc.rect(14, y - 5, 182, 8, 'F');
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(80, 80, 120);
    let x = 14;
    headers.forEach((h, i) => { doc.text(h, x + 2, y); x += colW[i]; });
    y += 6;

    doc.setFont('helvetica', 'normal');
    scanHistory.forEach((r, idx) => {
        if (y > 270) { doc.addPage(); y = 20; }
        if (idx % 2 === 0) { doc.setFillColor(248, 249, 252); doc.rect(14, y - 4, 182, 7, 'F'); }
        const vtText = r.vt_info && r.vt_info.vt_found ? `${r.vt_info.vt_malicious}/${r.vt_info.vt_total}` : 'N/A';
        const row = [
            r.filename.length > 28 ? r.filename.substring(0, 26) + '..' : r.filename,
            r.is_malicious ? 'Malicious' : 'Safe',
            (r.malicious_probability * 100).toFixed(1) + '%',
            vtText,
            r.risk_level || 'Low',
            formatTimestamp(r.scan_time || r.analysis_timestamp).substring(0, 18)
        ];
        x = 14;
        row.forEach((cell, i) => {
            if (i === 1) doc.setTextColor(r.is_malicious ? 200 : 22, r.is_malicious ? 50 : 180, r.is_malicious ? 50 : 80);
            else doc.setTextColor(30, 30, 50);
            doc.text(cell, x + 2, y);
            x += colW[i];
        });
        y += 7;
    });

    doc.setFontSize(8);
    doc.setTextColor(150, 150, 170);
    doc.text('Generated by MalDetect · Random Forest trained on EMBER Dataset · VT hash lookup only — files never uploaded', 14, 290);
    doc.save(`maldetect_report_${Date.now()}.pdf`);
}

// ── Health check ──────────────────────────────────────────────
async function checkHealth() {
    const dot  = apiStatusEl.querySelector('.status-dot');
    const text = apiStatusEl.querySelector('.status-text');
    try {
        const res  = await fetch(`${API_BASE_URL}/health`);
        const data = await res.json();
        if (data.model_loaded) {
            dot.className  = 'status-dot online';
            text.textContent = 'API connected';
        } else {
            dot.className  = 'status-dot offline';
            text.textContent = 'Model not loaded';
        }
    } catch {
        dot.className  = 'status-dot offline';
        text.textContent = 'API offline';
    }
}

// ── Helpers ───────────────────────────────────────────────────
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
}
function formatTimestamp(ts) {
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
}
function escapeHtml(text) {
    const d = document.createElement('div');
    d.textContent = text;
    return d.innerHTML;
}

// ── Init ──────────────────────────────────────────────────────
checkHealth();
setInterval(checkHealth, 30000);
