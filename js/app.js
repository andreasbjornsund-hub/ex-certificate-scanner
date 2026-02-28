/**
 * Ex Certificate Scanner — Application Logic
 */

(function() {
    'use strict';

    // === DOM refs ===
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const processing = document.getElementById('processing');
    const results = document.getElementById('results');
    const certCard = document.getElementById('certCard');
    const rawText = document.getElementById('rawText');
    const confidenceFill = document.getElementById('confidenceFill');
    const confidencePct = document.getElementById('confidencePct');
    const historyList = document.getElementById('historyList');

    // State
    let currentResult = null;
    const STORAGE_KEY = 'exscanner_history';

    // === Navigation ===
    document.querySelectorAll('.nav-links a[href^="#"]').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            const target = link.getAttribute('href').substring(1);
            showSection(target);
            document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
            link.classList.add('active');
            // Close mobile menu
            document.querySelector('.nav-links').classList.remove('open');
        });
    });

    document.querySelector('.hamburger')?.addEventListener('click', () => {
        document.querySelector('.nav-links').classList.toggle('open');
    });

    function showSection(id) {
        ['scanner', 'history', 'about'].forEach(s => {
            const el = document.getElementById(s);
            if (!el) return;
            if (s === 'scanner') {
                el.closest('main').style.display = s === id ? '' : 'none';
            } else {
                el.style.display = s === id ? '' : 'none';
            }
        });
        if (id === 'history') renderHistory();
    }

    // === File Upload ===
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type === 'application/pdf') processFile(file);
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) processFile(fileInput.files[0]);
    });

    // === PDF Processing ===
    async function processFile(file) {
        dropZone.style.display = 'none';
        results.style.display = 'none';
        processing.style.display = '';

        try {
            const arrayBuffer = await file.arrayBuffer();
            const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;

            // Step 1: Try text extraction with pdf.js
            let fullText = '';
            for (let i = 1; i <= pdf.numPages; i++) {
                const page = await pdf.getPage(i);
                const content = await page.getTextContent();
                const pageText = content.items.map(item => item.str).join(' ');
                fullText += pageText + '\n\n';
            }

            // Step 2: If text is too short, it's likely a scanned/image PDF → use OCR
            const strippedText = fullText.replace(/\s+/g, '').trim();
            let usedOcr = false;

            if (strippedText.length < 50) {
                processing.querySelector('p').textContent = 'Scanned PDF detected — running OCR (this may take 30-60 seconds)...';
                fullText = await ocrPdf(pdf);
                usedOcr = true;
            }

            // Parse
            const parsed = ExParser.parse(fullText);
            const conf = ExParser.confidence(parsed);
            currentResult = {
                ...parsed,
                fileName: file.name,
                scannedAt: new Date().toISOString(),
                confidence: conf,
                usedOcr: usedOcr
            };

            // Save to history
            saveToHistory(currentResult);

            // Render
            renderResults(currentResult, conf);
            rawText.textContent = fullText;

        } catch (err) {
            console.error('PDF processing error:', err);
            processing.innerHTML = `
                <div style="color: #f85149; text-align: center; padding: 40px;">
                    <p style="font-size: 1.2rem; margin-bottom: 8px;">Failed to process PDF</p>
                    <p style="color: #8b949e;">${err.message || 'Unknown error'}</p>
                    <button class="btn btn-secondary" style="margin-top: 16px;" onclick="location.reload()">Try Again</button>
                </div>
            `;
        }
    }

    // === OCR for scanned PDFs ===
    async function ocrPdf(pdf) {
        let fullText = '';
        const worker = await Tesseract.createWorker('eng');

        for (let i = 1; i <= pdf.numPages; i++) {
            processing.querySelector('p').textContent = `Running OCR — page ${i} of ${pdf.numPages}...`;

            const page = await pdf.getPage(i);
            const viewport = page.getViewport({ scale: 2.0 }); // Higher scale = better OCR
            const canvas = document.createElement('canvas');
            canvas.width = viewport.width;
            canvas.height = viewport.height;
            const ctx = canvas.getContext('2d');

            await page.render({ canvasContext: ctx, viewport: viewport }).promise;

            const { data } = await worker.recognize(canvas);
            fullText += data.text + '\n\n';
        }

        await worker.terminate();
        return fullText;
    }

    // === Render Results ===
    function renderResults(data, conf) {
        processing.style.display = 'none';
        results.style.display = '';

        // Confidence bar
        confidenceFill.style.width = conf + '%';
        confidenceFill.className = 'confidence-fill' + (conf >= 60 ? '' : conf >= 30 ? ' medium' : ' low');
        confidencePct.textContent = conf + '%';
        confidencePct.style.color = conf >= 60 ? '#4df4a4' : conf >= 30 ? '#d29922' : '#f85149';

        // OCR badge
        const ocrNote = data.usedOcr ? ' <span style="background:#d29922;color:#1a2535;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;margin-left:8px;">OCR</span>' : '';
        document.querySelector('.confidence-label').innerHTML = 'Extraction confidence:' + ocrNote;

        // Certificate card
        const typeBadge = data.certType ? `<span class="cert-type-badge">${esc(data.certType)}</span>` : '';

        certCard.innerHTML = `
            <div class="cert-card-header">
                <h3>Certificate ${typeBadge}</h3>
                <div class="cert-number">${esc(data.certNumber) || '<span class="not-found">Not detected</span>'}</div>
            </div>
            <div class="cert-grid">
                ${field('Ex Marking', data.marking, true)}
                ${data.markings && data.markings.length > 1 ? fieldFull('Additional Markings', data.markings.slice(1).join('\n')) : ''}
                ${field('Gas Group', data.gasGroup ? `${data.gasGroup}${data.gasGroupInfo ? ' — ' + data.gasGroupInfo : ''}` : null)}
                ${field('Temperature Class', data.tempClass ? `${data.tempClass} (max ${data.tempClassMax})` : null)}
                ${field('Equipment Protection Level', data.epl)}
                ${field('Protection Type(s)', data.protectionTypes.length ? data.protectionTypes.map(p => `${p.code} — ${p.description}`).join('<br>') : null)}
                ${field('Zone', data.zone)}
                ${field('IP Rating', data.ipRating)}
                ${field('Ambient Temperature', data.ambientTemp)}
                ${field('Manufacturer', data.manufacturer)}
                ${field('Equipment / Model', data.equipment)}
                ${field('Notified Body', data.notifiedBody)}
                ${field('Issue Date', data.issueDate)}
                ${field('Expiry Date', data.expiryDate)}
                ${field('ATEX Category', data.category)}
                ${field('Equipment Group', data.group)}
                ${field('Standards', data.standard)}
                ${data.specialConditions ? fieldFull('Special Conditions', data.specialConditions) : ''}
            </div>
        `;
    }

    function field(label, value, highlight = false) {
        const cls = value ? (highlight ? 'highlight' : '') : 'not-found';
        const display = value || 'Not detected';
        return `
            <div class="cert-field">
                <div class="cert-field-label">${esc(label)}</div>
                <div class="cert-field-value ${cls}">${value ? display : esc(display)}</div>
            </div>
        `;
    }

    function fieldFull(label, value) {
        return `
            <div class="cert-field full-width">
                <div class="cert-field-label">${esc(label)}</div>
                <div class="cert-field-value">${esc(value)}</div>
            </div>
        `;
    }

    function esc(s) {
        if (!s) return '';
        const el = document.createElement('span');
        el.textContent = s;
        return el.innerHTML;
    }

    // === Actions ===
    document.getElementById('copyJson')?.addEventListener('click', () => {
        if (!currentResult) return;
        const { raw, ...clean } = currentResult;
        navigator.clipboard.writeText(JSON.stringify(clean, null, 2));
        toast('Copied JSON to clipboard');
    });

    document.getElementById('exportCsv')?.addEventListener('click', () => {
        if (!currentResult) return;
        exportCsv([currentResult]);
    });

    document.getElementById('scanAnother')?.addEventListener('click', () => {
        results.style.display = 'none';
        dropZone.style.display = '';
        fileInput.value = '';
        currentResult = null;
    });

    document.getElementById('exportAllCsv')?.addEventListener('click', () => {
        const history = getHistory();
        if (!history.length) return toast('No history to export');
        exportCsv(history);
    });

    document.getElementById('clearHistory')?.addEventListener('click', () => {
        if (!confirm('Clear all scan history?')) return;
        localStorage.removeItem(STORAGE_KEY);
        renderHistory();
        toast('History cleared');
    });

    // === History ===
    function getHistory() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
        catch { return []; }
    }

    function saveToHistory(result) {
        const history = getHistory();
        const { raw, ...clean } = result;
        history.unshift(clean);
        // Keep max 50
        if (history.length > 50) history.length = 50;
        localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    }

    function renderHistory() {
        const history = getHistory();
        if (!history.length) {
            historyList.innerHTML = '<p class="empty-state">No certificates scanned yet.</p>';
            return;
        }
        historyList.innerHTML = history.map((h, i) => `
            <div class="history-item" data-index="${i}">
                <div class="history-item-left">
                    <h4>${esc(h.certNumber || h.fileName || 'Unknown certificate')}</h4>
                    <p>${esc(h.manufacturer || '')} ${h.equipment ? '— ' + esc(h.equipment) : ''}</p>
                </div>
                <div class="history-item-right">
                    <div class="history-item-marking">${esc(h.marking || '—')}</div>
                    <div class="history-item-date">${h.scannedAt ? new Date(h.scannedAt).toLocaleDateString() : ''}</div>
                </div>
            </div>
        `).join('');

        // Click to view details
        historyList.querySelectorAll('.history-item').forEach(el => {
            el.addEventListener('click', () => {
                const idx = parseInt(el.dataset.index);
                const item = history[idx];
                if (!item) return;
                currentResult = item;
                showSection('scanner');
                document.querySelector('.nav-links a[href="#scanner"]').classList.add('active');
                document.querySelector('.nav-links a[href="#history"]').classList.remove('active');
                dropZone.style.display = 'none';
                renderResults(item, item.confidence || 0);
                rawText.textContent = item.raw || '(Raw text not stored in history)';
            });
        });
    }

    // === CSV Export ===
    function exportCsv(items) {
        const fields = [
            'certNumber', 'certType', 'marking', 'gasGroup', 'tempClass',
            'epl', 'zone', 'ipRating', 'ambientTemp', 'manufacturer',
            'equipment', 'notifiedBody', 'issueDate', 'expiryDate',
            'category', 'group', 'standard', 'specialConditions', 'fileName', 'scannedAt'
        ];
        const header = fields.join(',');
        const rows = items.map(item =>
            fields.map(f => {
                let val = item[f];
                if (Array.isArray(val)) val = val.map(v => v.code || v).join('; ');
                if (val == null) val = '';
                return `"${String(val).replace(/"/g, '""')}"`;
            }).join(',')
        );
        const csv = header + '\n' + rows.join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ex-certificates-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        toast('CSV exported');
    }

    // === Toast ===
    function toast(msg) {
        const el = document.createElement('div');
        el.className = 'toast';
        el.textContent = msg;
        document.body.appendChild(el);
        setTimeout(() => el.remove(), 2500);
    }
})();
