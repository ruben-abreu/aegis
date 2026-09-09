let scanners = {};
let currentScanId = null; // scan shown in the results pane
let activeScanId = null; // scan still running, followed until it finishes
let pollInterval = null;
let currentEvidence = '';
let historyScans = [];
let historyTotal = 0;
let visibleScans = 10;

const SCAN_POLL_MS = 500;
const EVIDENCE_VISIBLE_KEY = 'technicalEvidenceVisible';
const HISTORY_EXPANDED_KEY = 'historyExpanded';

document.addEventListener('DOMContentLoaded', () => {
  initDarkMode();
  setHistoryExpanded(localStorage.getItem(HISTORY_EXPANDED_KEY) === 'true');
  // The dropdown has to be populated before a saved scanner can be selected.
  loadScanners().then(() => { restoreLastSelection(); loadScans(); });
  setupFormHandler();
  setupScannerOptions();
  setupModalHandler();
  setupVisibilityHandler();
  document.getElementById('historySearch').addEventListener('input', () => {
    visibleScans = 10;
    renderHistory();
  });
  document.getElementById('target').addEventListener('input', clearFormError);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      const exportMenu = document.querySelector('.export-menu[open]');
      if (exportMenu) {
        exportMenu.open = false;
        exportMenu.querySelector('summary').focus();
        return;
      }
    }
    if (event.key === 'Escape' && document.body.classList.contains('results-expanded')) {
      toggleResultsExpanded();
    }
  });
  document.addEventListener('click', event => {
    if (!event.target.closest('.export-menu')) {
      document.querySelectorAll('.export-menu').forEach(menu => { menu.open = false; });
    }
  });
});

// Scanning the same target across several risk vectors is the normal workflow,
// so the last choice is kept instead of being cleared after each run.
function rememberLastSelection(target, scanner) {
  localStorage.setItem('lastTarget', target);
  localStorage.setItem('lastScanner', scanner);
}

function restoreLastSelection() {
  const target = localStorage.getItem('lastTarget');
  const scanner = localStorage.getItem('lastScanner');
  const scannerSelect = document.getElementById('scanner');

  if (target) document.getElementById('target').value = target;
  // Ignore a stale scanner id that no longer exists.
  if (scanner && scannerSelect.querySelector(`option[value="${scanner}"]`)) {
    scannerSelect.value = scanner;
  }
  syncScannerOptions();
}

function setupScannerOptions() {
  document.getElementById('scanner').addEventListener('change', syncScannerOptions);
  syncScannerOptions();
}

function syncScannerOptions() {
  const scanner = document.getElementById('scanner').value;
  const isTlsConfig = scanner === 'tls_config';
  const option = document.getElementById('tlsExtendedOption');
  const checkbox = document.getElementById('checkCiphers');
  const serverNote = document.getElementById('serverSoftwareNote');

  option.hidden = !isTlsConfig;
  serverNote.hidden = scanner !== 'server_software';
  if (!isTlsConfig) checkbox.checked = false;
  const isEmail = scanner === 'email';
  document.getElementById('target').placeholder = isEmail
    ? 'example.com or selector._domainkey.example.com'
    : scanner === 'ports' ? 'example.com:25 or 1.2.3.4:161/udp' : 'example.com:443';
  document.getElementById('targetHint').textContent = isEmail
    ? 'Domain or full DKIM selector hostname. No port needed.'
    : 'Enter a domain or IP address, including the port.';
  clearFormError();
}

function clearFormError() {
  document.getElementById('formError').hidden = true;
  document.getElementById('target').removeAttribute('aria-invalid');
}

function showFormError(message) {
  const error = document.getElementById('formError');
  error.textContent = message;
  error.hidden = false;
}

function toggleResultsExpanded() {
  const expanded = document.body.classList.toggle('results-expanded');
  const button = document.getElementById('expandResults');
  button.textContent = expanded ? 'Exit expanded view' : 'Expand results';
  button.setAttribute('aria-pressed', String(expanded));
  document.querySelectorAll('.scan-panel, .history-panel, header, footer').forEach(element => {
    element.inert = expanded;
  });
  button.focus({ preventScroll: true });
}

function setWorkspaceStatus(message) {
  const status = document.getElementById('workspaceStatus');
  status.textContent = message;
  status.classList.toggle('needs-attention', /unable|interrupted|retrying/i.test(message));
}

function setHistoryExpanded(expanded) {
  document.querySelector('.history-panel').classList.toggle('history-collapsed', !expanded);
  document.getElementById('historyBody').hidden = !expanded;
  document.getElementById('toggleHistory').setAttribute('aria-expanded', String(expanded));
}

function toggleHistory() {
  const expanded = document.getElementById('historyBody').hidden;
  setHistoryExpanded(expanded);
  localStorage.setItem(HISTORY_EXPANDED_KEY, String(expanded));
}

// Only this browser changes this instance's data, so the history is refreshed
// on the events that change it rather than on a permanent timer. A scan in
// flight is the one thing that changes on its own, and that is polled only
// while the tab is actually being looked at.
function setupVisibilityHandler() {
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopScanPolling();
      return;
    }
    loadScans();
    if (activeScanId) startPolling(activeScanId);
  });
}

function stopScanPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = null;
}

function toggleDarkMode() {
  const isDark = document.body.classList.toggle('dark-mode');
  localStorage.setItem('darkMode', isDark);
  syncDarkModeLabel(isDark);
}

function initDarkMode() {
  const isDark = localStorage.getItem('darkMode') === 'true';
  document.body.classList.toggle('dark-mode', isDark);
  syncDarkModeLabel(isDark);
}

function syncDarkModeLabel(isDark) {
  const button = document.getElementById('darkModeToggle');
  button.textContent = isDark ? 'Light mode' : 'Dark mode';
  button.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
}

function colorizeOutput(text) {
  const lines = text.split('\n');
  return lines
    .map(line => {
      if (!line.trim()) return `<div class="output-line"></div>`;

      let className = 'output-info';

      if (/^[=─━-]{4,}$/.test(line.trim())) {
        className = 'output-divider';
      } else if (/^\s*\[\+\]\s+[A-Z][A-Z /()–-]+$/.test(line)) {
        className = 'output-section';
      } else if (line.includes('[✓]')) {
        className = 'output-success';
      } else if (line.includes('[✗]')) {
        className = 'output-error';
      } else if (line.includes('[!]')) {
        className = 'output-warning';
      } else if (line.includes('[*]')) {
        className = 'output-title';
      }

      return `<div class="output-line ${className}">${escapeHtml(line)}</div>`;
    })
    .join('');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function loadScanners() {
  try {
    const response = await fetch('/api/scanners');
    // Server sends an ordered list; keep that order in the dropdown.
    const list = await response.json();
    scanners = Object.fromEntries(list.map(s => [s.id, s.label]));

    const select = document.getElementById('scanner');
    select.innerHTML = '<option value="">Select a scanner...</option>';

    list.forEach(({ id, label }) => {
      const option = document.createElement('option');
      option.value = id;
      option.textContent = label;
      select.appendChild(option);
    });
  } catch (error) {
    console.error('Error loading scanners:', error);
    showToast('Error loading scanners', 'error');
  }
}

function renderHistory() {
  const query = document.getElementById('historySearch').value.trim().toLowerCase();
  const matches = historyScans.filter(scan =>
    `${scan.target} ${scanners[scan.scanner] || scan.scanner} ${scan.status}`.toLowerCase().includes(query));
  const scans = matches.slice(0, visibleScans);
  document.getElementById('historyCount').textContent = historyTotal > historyScans.length
    ? `Latest ${historyScans.length} of ${historyTotal} stored`
    : `${historyTotal} stored`;
  document.getElementById('clearHistoryBtn').style.display = historyTotal ? '' : 'none';
  // Keep pagination at the end of the scrollable list, not in a fixed footer.
  let moreButton = document.getElementById('showMoreScans');
  if (!moreButton) {
    moreButton = document.createElement('button');
    moreButton.id = 'showMoreScans';
    moreButton.className = 'btn-history-more';
    moreButton.onclick = showMoreScans;
  }
  moreButton.hidden = matches.length <= visibleScans;
  moreButton.textContent = `Show more (${Math.max(0, matches.length - visibleScans)} remaining)`;
  document.getElementById('scansList').innerHTML = scans.length ? scans.map(scan => `
    <div class="scan-item${scan.id === currentScanId ? ' selected' : ''}">
      <button class="scan-open" onclick="viewScan(${scan.id}, true)" aria-current="${scan.id === currentScanId}">
        <span class="scan-target">${escapeHtml(scan.target)}</span>
        <span class="scan-item-meta">${escapeHtml(scanners[scan.scanner] || scan.scanner)}</span>
        <span class="scan-item-footer">
          <span class="scan-item-meta">${new Date(scan.timestamp).toLocaleString()}</span>
          <span class="status ${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
        </span>
      </button>
      <button class="btn btn-danger scan-delete" onclick="deleteScan(event, ${scan.id})"
        aria-label="Delete scan for ${escapeHtml(scan.target).replace(/"/g, '&quot;')}">Delete</button>
    </div>`).join('') : `<p class="loading">${query ? 'No matching recent scans.' : 'No scans yet. Run your first scan.'}</p>`;
  document.getElementById('scansList').appendChild(moreButton);
}

function showMoreScans() {
  visibleScans += 10;
  renderHistory();
}

async function loadScans() {
  try {
    const response = await fetch('/api/scans');
    if (!response.ok) throw new Error('Unable to load history');
    const { scans: allScans, total } = await response.json();
    historyScans = allScans;
    historyTotal = total;
    renderHistory();
    if (!currentScanId && allScans.length) viewScan(allScans[0].id);

    // A scan left running by a page reload should keep streaming.
    const running = allScans.find(s => s.status === 'running');
    if (running && !pollInterval && !document.hidden) {
      activeScanId = running.id;
      startPolling(running.id);
    }
  } catch (error) {
    console.error('Error loading scans:', error);
    if (!historyScans.length) document.getElementById('scansList').innerHTML =
      '<p class="loading">History unavailable. <button class="btn" onclick="loadScans()">Retry</button></p>';
  }
}

async function clearHistory() {
  const label = document.getElementById('historyCount').textContent;
  if (
    !confirm(
      `Delete ALL stored scans (${label})?\n\nThis cannot be undone. Export anything you still need first.`,
    )
  ) {
    return;
  }

  try {
    const response = await fetch('/api/scans', { method: 'DELETE' });
    if (!response.ok) {
      showToast('Error clearing history', 'error');
      return;
    }
    const { deleted } = await response.json();
    currentScanId = null;
    activeScanId = null;
    stopScanPolling();
    document.getElementById('resultsDisplay').innerHTML =
      '<p class="loading">Run a scan to see results</p>';
    document.getElementById('resultsDisplay').classList.remove('has-evidence');
    currentEvidence = '';
    setWorkspaceStatus('Ready to scan');
    showToast(`Deleted ${deleted} scan(s)`, 'success');
    loadScans();
  } catch (error) {
    console.error('Error clearing history:', error);
    showToast('Error clearing history', 'error');
  }
}

function setupFormHandler() {
  document.getElementById('scanForm').addEventListener('submit', async e => {
    e.preventDefault();

    const targetInput = document.getElementById('target').value.trim();
    const scanner = document.getElementById('scanner').value;
    clearFormError();

    if (!targetInput || !scanner) {
      showFormError('Please fill in all required fields.');
      return;
    }

    if (scanner !== 'email' && !targetInput.includes(':')) {
      showFormError('Include a port for this scanner, for example example.com:443.');
      document.getElementById('target').setAttribute('aria-invalid', 'true');
      document.getElementById('target').focus();
      return;
    }

    const checkCiphers =
      scanner === 'tls_config' && document.getElementById('checkCiphers').checked;

    const submitButton = document.getElementById('startScanBtn');
    submitButton.disabled = true;
    submitButton.textContent = 'Starting…';
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: targetInput,
          scanner,
          check_ciphers: checkCiphers,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        currentScanId = data.id;
        const resultsDisplay = document.getElementById('resultsDisplay');
        resultsDisplay.classList.remove('has-evidence');
        currentEvidence = '';
        resultsDisplay.innerHTML = '<p class="loading">Scan starting… Results will appear here.</p>';
        setWorkspaceStatus('Scan in progress');
        resultsDisplay.scrollIntoView({ block: 'nearest' });
        showToast('Scan started!', 'success');
        rememberLastSelection(targetInput, scanner);

        startPolling(data.id);
        loadScans();
      } else {
        const error = await response.json();
        showFormError(error.error || 'Unable to start the scan. Please try again.');
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      showFormError('Unable to connect. Check the server and try again.');
    } finally {
      submitButton.disabled = false;
      submitButton.innerHTML = 'Start Scan <span aria-hidden="true">→</span>';
    }
  });
}

function startPolling(scanId) {
  stopScanPolling();
  activeScanId = scanId;

  let pending = false;
  const poll = async () => {
    if (pending || activeScanId !== scanId) return;
    pending = true;
    try {
      const response = await fetch(`/api/scan-status/${scanId}`);
      if (!response.ok) throw new Error('Unable to load scan status');
      const data = await response.json();
      if (activeScanId !== scanId) return;

      // Keep following in the background if the user clicked another scan,
      // so its status chip still updates when it finishes.
      if (currentScanId === scanId) {
        const resultsDisplay = document.getElementById('resultsDisplay');
        resultsDisplay.classList.remove('has-evidence');
        currentEvidence = '';
        const previousOutput = resultsDisplay.querySelector('.live-output');
        const outputFocused = previousOutput && document.activeElement === previousOutput;
        const previousScroll = previousOutput ? previousOutput.scrollTop : 0;
        const followOutput = !previousOutput || previousOutput.scrollHeight - previousScroll - previousOutput.clientHeight < 50;
        const scan = historyScans.find(item => item.id === scanId);
        resultsDisplay.innerHTML = `
                <div class="results-header">
                    <div class="result-identity">
                      <span class="result-target">${escapeHtml(scan ? scan.target : 'Scan in progress')}</span>
                      <span class="result-meta"><span class="live-indicator" aria-hidden="true"></span>${escapeHtml(data.status)}</span>
                    </div>
                </div>
                <div class="live-output" tabindex="0" aria-label="Live scan output">${colorizeOutput(data.output || '')}</div>
            `;
        const output = resultsDisplay.querySelector('.live-output');
        if (outputFocused) output.focus({ preventScroll: true });
        output.scrollTop = followOutput ? output.scrollHeight : previousScroll;
        setWorkspaceStatus(data.status === 'running' ? 'Scan in progress' : data.status);
      }

      if (data.status !== 'running') {
        stopScanPolling();
        activeScanId = null;
        loadScans();
        if (currentScanId === scanId) viewScan(scanId);
      }
    } catch (error) {
      console.error('Error polling scan:', error);
      if (currentScanId === scanId) setWorkspaceStatus('Connection interrupted · retrying…');
    } finally {
      pending = false;
    }
  };
  pollInterval = setInterval(poll, SCAN_POLL_MS);
  poll();
}

async function viewScan(scanId, focusResults = false) {
  try {
    currentScanId = scanId;
    document.querySelectorAll('.scan-open').forEach(button => {
      const selected = button.getAttribute('onclick') === `viewScan(${scanId}, true)`;
      button.setAttribute('aria-current', String(selected));
      button.parentElement.classList.toggle('selected', selected);
    });
    if (focusResults) {
      document.getElementById('resultsDisplay').scrollIntoView({ block: 'nearest' });
      document.getElementById('resultsDisplay').focus({ preventScroll: true });
    }

    // A scan still in flight keeps its live view; startPolling paints it.
    if (scanId === activeScanId) {
      setWorkspaceStatus('Scan in progress');
      document.getElementById('resultsDisplay').innerHTML = '<p class="loading">Loading live output…</p>';
      return;
    }

    const response = await fetch(`/api/scan/${scanId}`);
    if (!response.ok) throw new Error('Unable to load scan');
    const scan = await response.json();
    if (currentScanId !== scanId) return;

    const resultsDisplay = document.getElementById('resultsDisplay');

    const colorizedOutput = colorizeOutput(scan.results.output || '');
    const evidence = scan.results.evidence || '';
    const hasEvidence = evidence.trim().length > 0;
    const evidenceVisible =
      hasEvidence && localStorage.getItem(EVIDENCE_VISIBLE_KEY) === 'true';
    currentEvidence = evidence;
    resultsDisplay.classList.toggle('has-evidence', hasEvidence);

    const resultBody = hasEvidence
      ? `
            <div class="result-tabs" role="group" aria-label="Result view">
                <button class="result-tab${evidenceVisible ? '' : ' active'}" data-view="assessment"
                    aria-pressed="${String(!evidenceVisible)}"
                    onclick="setResultPane('assessment', this)">Assessment</button>
                <button class="result-tab${evidenceVisible ? ' active' : ''}" data-view="evidence"
                    aria-pressed="${String(evidenceVisible)}"
                    onclick="setResultPane('evidence', this)">Technical Evidence</button>
            </div>
            <div class="results-workspace${evidenceVisible ? ' evidence-open' : ''}">
                <section class="result-pane assessment-pane${evidenceVisible ? ' mobile-hidden' : ''}"
                    data-result-pane="assessment" tabindex="0" aria-label="Assessment output">
                    <div class="pane-heading">Assessment</div>
                    <div>${colorizedOutput}</div>
                </section>
                <section class="result-pane evidence-pane${evidenceVisible ? '' : ' mobile-hidden'}"
                    data-result-pane="evidence" tabindex="0" aria-label="Technical evidence output">
                    <div class="pane-heading evidence-heading">
                        <span>Technical Evidence</span>
                        <button class="btn-copy-evidence" onclick="copyEvidence()">Copy</button>
                    </div>
                    <pre class="evidence-output">${escapeHtml(evidence)}</pre>
                </section>
            </div>
        `
      : `<div class="results-workspace"><section class="result-pane assessment-pane" tabindex="0" aria-label="Assessment output"><div class="pane-heading">Assessment</div>${colorizedOutput}</section></div>`;

    resultsDisplay.innerHTML = `
            <div class="results-header">
                <div class="result-identity">
                    <span class="result-target">${escapeHtml(scan.target)}</span>
                    <div class="result-meta">
                      <span>${escapeHtml(scanners[scan.scanner] || scan.scanner)}</span>
                      <span class="status ${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
                      <span>${new Date(scan.timestamp).toLocaleString()}</span>
                    </div>
                </div>
                <div class="export-buttons">
                    ${
                      hasEvidence
                        ? `<button class="btn-evidence-toggle"
                              aria-expanded="${String(evidenceVisible)}"
                              onclick="toggleTechnicalEvidence(this)">${
                                evidenceVisible ? 'Hide Evidence' : 'View Evidence'
                              }</button>`
                        : ''
                    }
                    <details class="export-menu">
                      <summary class="btn-export">Export <span aria-hidden="true">⌄</span></summary>
                      <div class="export-options">
                        <button class="btn-export" onclick="exportScan(${scanId}, 'txt')">Export TXT</button>
                        <button class="btn-export" onclick="exportScan(${scanId}, 'json')">Export JSON</button>
                      </div>
                    </details>
                </div>
            </div>
            ${resultBody}
        `;
    setWorkspaceStatus(scan.status === 'completed' ? 'Scan complete' : scan.status);
  } catch (error) {
    if (currentScanId !== scanId) return;
    console.error('Error loading scan:', error);
    setWorkspaceStatus('Unable to load results');
    showToast('Error loading scan', 'error');
  }
}

function toggleTechnicalEvidence(button) {
  const workspace = document.querySelector('#resultsDisplay .results-workspace');
  if (!workspace) return;

  setResultPane(workspace.classList.contains('evidence-open') ? 'assessment' : 'evidence');
}

function setResultPane(paneName) {
  const resultsDisplay = document.getElementById('resultsDisplay');
  const isOpen = paneName === 'evidence';
  localStorage.setItem(EVIDENCE_VISIBLE_KEY, String(isOpen));
  resultsDisplay.querySelector('.results-workspace').classList.toggle('evidence-open', isOpen);
  const toggle = resultsDisplay.querySelector('.btn-evidence-toggle');
  toggle.setAttribute('aria-expanded', String(isOpen));
  toggle.textContent = isOpen ? 'Hide Evidence' : 'View Evidence';
  resultsDisplay.querySelectorAll('.result-pane').forEach(pane => {
    pane.classList.toggle('mobile-hidden', pane.dataset.resultPane !== paneName);
  });
  resultsDisplay.querySelectorAll('.result-tab').forEach(button => {
    const selected = button.dataset.view === paneName;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-pressed', String(selected));
  });
}

async function copyEvidence() {
  try {
    await navigator.clipboard.writeText(currentEvidence);
    showToast('Technical evidence copied', 'success');
  } catch (error) {
    console.error('Error copying technical evidence:', error);
    showToast('Unable to copy technical evidence', 'error');
  }
}

function exportScan(scanId, format) {
  document.querySelectorAll('.export-menu').forEach(menu => { menu.open = false; });
  // Hitting the endpoint directly lets the server set the filename.
  window.location.href = `/api/export/${scanId}?format=${format}`;
  showToast(`Exporting ${format.toUpperCase()}...`, 'success');
}

async function deleteScan(event, scanId) {
  event.stopPropagation();

  if (!confirm('Are you sure you want to delete this scan?')) {
    return;
  }

  try {
    const response = await fetch(`/api/delete-scan/${scanId}`, {
      method: 'DELETE',
    });

    if (response.ok) {
      showToast('Scan deleted', 'success');
      if (activeScanId === scanId) {
        stopScanPolling();
        activeScanId = null;
      }
      if (currentScanId === scanId) {
        const resultsDisplay = document.getElementById('resultsDisplay');
        resultsDisplay.classList.remove('has-evidence');
        resultsDisplay.innerHTML =
          '<p class="loading">Run a scan to see results</p>';
        currentScanId = null;
        currentEvidence = '';
        setWorkspaceStatus('Ready to scan');
      }
      loadScans();
    } else {
      showToast('Error deleting scan', 'error');
    }
  } catch (error) {
    console.error('Error deleting scan:', error);
    showToast('Error deleting scan', 'error');
  }
}

function setupModalHandler() {
  const modal = document.getElementById('resultsModal');
  const closeBtn = document.querySelector('.close');

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      modal.classList.add('hidden');
    });
  }

  modal.addEventListener('click', e => {
    if (e.target === modal) {
      modal.classList.add('hidden');
    }
  });
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
}
