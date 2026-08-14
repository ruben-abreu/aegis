let scanners = {};
let currentScanId = null;
let pollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  initDarkMode();
  loadScanners();
  loadScans();
  setupFormHandler();
  setupModalHandler();
  setInterval(loadScans, 3000);
});

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
  document.getElementById('darkModeToggle').textContent = isDark
    ? '☀️ Light Mode'
    : '🌙 Dark Mode';
}

function colorizeOutput(text) {
  const lines = text.split('\n');
  return lines
    .map(line => {
      if (!line.trim()) return `<div class="output-line"></div>`;

      let className = 'output-info';

      if (line.includes('[✓]')) {
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

const VISIBLE_SCANS = 5;

async function loadScans() {
  try {
    const response = await fetch('/api/scans');
    const { scans: allScans, total } = await response.json();

    const scansList = document.getElementById('scansList');
    const countLabel = document.getElementById('historyCount');
    const clearBtn = document.getElementById('clearHistoryBtn');

    if (!allScans.length) {
      scansList.innerHTML =
        '<p class="loading">No scans yet. Run your first scan!</p>';
      countLabel.textContent = '';
      clearBtn.style.display = 'none';
      return;
    }

    const scans = allScans.slice(0, VISIBLE_SCANS);

    // Nothing is auto-deleted, so say how much history is hidden.
    countLabel.textContent =
      total > scans.length
        ? `showing ${scans.length} of ${total} stored`
        : `${total} stored`;
    clearBtn.style.display = '';

    scansList.innerHTML = scans
      .map(
        scan => `
            <div class="scan-item" onclick="viewScan(${scan.id})">
                <div class="scan-item-info">
                    <h3>${escapeHtml(scan.target)}</h3>
                    <div class="scan-item-meta">
                        <strong>${escapeHtml(scanners[scan.scanner] || scan.scanner)}</strong> &middot;
                        ${new Date(scan.timestamp).toLocaleString()}
                    </div>
                </div>
                <div class="scan-item-actions">
                    <span class="status ${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
                    <button class="btn btn-danger" onclick="deleteScan(event, ${scan.id})">Delete</button>
                </div>
            </div>
        `,
      )
      .join('');

    if (!currentScanId) {
      viewScan(scans[0].id);
    }
  } catch (error) {
    console.error('Error loading scans:', error);
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
    if (pollInterval) clearInterval(pollInterval);
    document.getElementById('resultsDisplay').innerHTML =
      '<p class="loading">Run a scan to see results</p>';
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

    if (!targetInput || !scanner) {
      showToast('Please fill in all required fields', 'error');
      return;
    }

    if (!targetInput.includes(':')) {
      showToast('Format required: apple.com:443 or 1.2.3.4:161/udp', 'error');
      return;
    }

    try {
      const resultsDisplay = document.getElementById('resultsDisplay');
      resultsDisplay.innerHTML = '<p class="loading">Scan starting...</p>';

      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: targetInput,
          scanner,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        currentScanId = data.id;
        showToast('Scan started!', 'success');
        document.getElementById('scanForm').reset();

        startPolling(data.id);
        loadScans();
      } else {
        const error = await response.json();
        showToast(error.error || 'Error starting scan', 'error');
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      showToast('Error starting scan', 'error');
    }
  });
}

function startPolling(scanId) {
  if (pollInterval) clearInterval(pollInterval);

  pollInterval = setInterval(async () => {
    try {
      const response = await fetch(`/api/scan-status/${scanId}`);
      const data = await response.json();

      const resultsDisplay = document.getElementById('resultsDisplay');
      const colorizedOutput = colorizeOutput(data.output);

      resultsDisplay.innerHTML = `
                <div style="margin-bottom: 15px; border-bottom: 1px solid #444; padding-bottom: 10px; color: #9cdcfe;">
                    <strong>Status:</strong> ${data.status === 'running' ? '⏳ Running...' : '✓ Completed'}
                </div>
                <div>${colorizedOutput}</div>
            `;

      resultsDisplay.parentElement.scrollTop =
        resultsDisplay.parentElement.scrollHeight;

      if (data.status !== 'running') {
        clearInterval(pollInterval);
        loadScans();
      }
    } catch (error) {
      console.error('Error polling scan:', error);
    }
  }, 500);
}

async function viewScan(scanId) {
  try {
    currentScanId = scanId;
    if (pollInterval) clearInterval(pollInterval);

    const response = await fetch(`/api/scan/${scanId}`);
    const scan = await response.json();

    const resultsDisplay = document.getElementById('resultsDisplay');

    const colorizedOutput = colorizeOutput(scan.results.output);

    resultsDisplay.innerHTML = `
            <div class="results-header">
                <div>
                    <strong>Target:</strong> ${escapeHtml(scan.target)} |
                    <strong>Risk Vector:</strong> ${escapeHtml(scanners[scan.scanner] || scan.scanner)} |
                    <strong>Status:</strong> ${escapeHtml(scan.status)}
                </div>
                <div class="export-buttons">
                    <button class="btn-export" onclick="exportScan(${scanId}, 'txt')">Export TXT</button>
                    <button class="btn-export" onclick="exportScan(${scanId}, 'json')">Export JSON</button>
                </div>
            </div>
            <div>${colorizedOutput}</div>
        `;
  } catch (error) {
    console.error('Error loading scan:', error);
    showToast('Error loading scan', 'error');
  }
}

function exportScan(scanId, format) {
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
      if (currentScanId === scanId) {
        document.getElementById('resultsDisplay').innerHTML =
          '<p class="loading">Run a scan to see results</p>';
        currentScanId = null;
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
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
}
