// Dependency-free UI state tests. Run with: node --test tests/test_ui.js
// Layout and browser semantics are additionally checked in a real browser.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');

function fixture() {
  const elements = new Map();
  const selectors = new Map();
  const groups = new Map();
  class Element {
    constructor() {
      const classes = new Set();
      this.classList = {
        contains: name => classes.has(name),
        add: name => classes.add(name),
        remove: name => classes.delete(name),
        toggle(name, force = !classes.has(name)) {
          force ? classes.add(name) : classes.delete(name);
          return force;
        },
      };
      this.attributes = {};
      this.listeners = {};
      this.dataset = {};
      this.style = {};
      this.value = '';
      this.hidden = false;
      this.disabled = false;
      this.checked = false;
      this.html = '';
    }
    set innerHTML(value) { this.html = value; }
    get innerHTML() { return this.html; }
    set textContent(value) {
      this.text = String(value);
      this.html = this.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
    get textContent() { return this.text; }
    setAttribute(key, value) { this.attributes[key] = value; }
    getAttribute(key) { return this.attributes[key]; }
    removeAttribute(key) { delete this.attributes[key]; }
    addEventListener(name, handler) { this.listeners[name] = handler; }
    querySelector(selector) { return selectors.get(selector); }
    querySelectorAll(selector) { return groups.get(selector) || []; }
    focus() { this.focused = true; }
    scrollIntoView() {}
    appendChild(element) { element.parentElement = this; }
    remove() {}
  }
  const get = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const body = new Element();
  const stored = new Map();
  const context = vm.createContext({
    document: {
      body, hidden: false,
      addEventListener() {}, getElementById: get,
      createElement: () => new Element(),
      querySelector: selector => selectors.get(selector),
      querySelectorAll: selector => groups.get(selector) || [],
    },
    localStorage: {getItem: key => stored.get(key) ?? null, setItem: (key, value) => stored.set(key, value)},
    console: {error() {}},
    setInterval: () => 1, clearInterval() {}, setTimeout() {},
    window: {location: {}, matchMedia: () => ({matches: false})}, navigator: {clipboard: {writeText: async () => {}}},
    fetch: async () => { throw new Error('Unexpected network request'); },
  });
  selectors.set('.scan-panel', new Element());
  selectors.set('.history-panel', new Element());
  selectors.set('.results-workspace', new Element());
  selectors.set('#resultsDisplay .results-workspace', selectors.get('.results-workspace'));
  selectors.set('.btn-evidence-toggle', new Element());
  groups.set('.result-pane', ['assessment', 'evidence'].map(name => {
    const element = new Element(); element.dataset.resultPane = name; return element;
  }));
  groups.set('.result-tab', ['assessment', 'evidence'].map(name => {
    const element = new Element(); element.dataset.view = name; return element;
  }));
  groups.set('.scan-panel, .history-panel, header, footer', Array.from({length: 4}, () => new Element()));
  vm.runInContext(source, context);
  return {context, get, selectors, groups, stored, body, run: code => vm.runInContext(code, context)};
}

test('evidence preference synchronizes desktop, mobile and saved state', () => {
  const f = fixture();
  f.context.setResultPane('evidence');
  assert.equal(f.stored.get('technicalEvidenceVisible'), 'true');
  assert.equal(f.selectors.get('.results-workspace').classList.contains('evidence-open'), true);
  assert.equal(f.groups.get('.result-pane')[0].classList.contains('mobile-hidden'), true);
  assert.equal(f.groups.get('.result-tab')[1].getAttribute('aria-pressed'), 'true');
  f.context.toggleTechnicalEvidence();
  assert.equal(f.stored.get('technicalEvidenceVisible'), 'false');
  assert.equal(f.groups.get('.result-pane')[0].classList.contains('mobile-hidden'), false);
  assert.equal(f.selectors.get('.btn-evidence-toggle').textContent, 'View Evidence');
});

test('expanded view restores surrounding controls on exit', () => {
  const f = fixture();
  f.context.toggleResultsExpanded();
  assert.equal(f.body.classList.contains('results-expanded'), true);
  assert.equal(f.get('expandResults').getAttribute('aria-pressed'), 'true');
  assert.ok(f.groups.get('.scan-panel, .history-panel, header, footer').every(e => e.inert));
  f.context.toggleResultsExpanded();
  assert.ok(f.groups.get('.scan-panel, .history-panel, header, footer').every(e => !e.inert));
  assert.equal(f.get('expandResults').focused, true);
});

test('target hints and optional checks retain scanner-specific behavior', () => {
  const f = fixture();
  f.get('scanner').value = 'tls_config';
  f.get('checkCiphers').checked = true;
  f.context.syncScannerOptions();
  assert.equal(f.get('tlsExtendedOption').hidden, false);
  assert.equal(f.get('checkCiphers').checked, true);
  f.get('scanner').value = 'email';
  f.context.syncScannerOptions();
  assert.equal(f.get('checkCiphers').checked, false);
  assert.match(f.get('targetHint').textContent, /No port needed/);
  f.get('scanner').value = 'server_software';
  f.context.syncScannerOptions();
  assert.equal(f.get('serverSoftwareNote').hidden, false);
});

test('new scan stays visible without a setup toggle or auto-collapse logic', () => {
  const template = fs.readFileSync(path.join(__dirname, '../templates/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../static/style.css'), 'utf8');
  assert.doesNotMatch(template + source + css, /toggleSetup|toggleScanSetup|setScanSetupExpanded|setup-collapsed|Hide setup|Edit setup/);
  assert.match(template, /<form id="scanForm">/);
  assert.match(css, /main:has\(\.history-collapsed\) \{ grid-template-rows: minmax\(0,1fr\) auto;/);
});

test('recent scans are collapsed by default and remember the chosen visibility', () => {
  const f = fixture();
  f.run("setHistoryExpanded(localStorage.getItem(HISTORY_EXPANDED_KEY) === 'true')");
  assert.equal(f.get('historyBody').hidden, true);
  f.context.toggleHistory();
  assert.equal(f.get('historyBody').hidden, false);
  assert.equal(f.get('toggleHistory').getAttribute('aria-expanded'), 'true');
  assert.equal(f.stored.get('historyExpanded'), 'true');
  f.run("setHistoryExpanded(localStorage.getItem(HISTORY_EXPANDED_KEY) === 'true')");
  assert.equal(f.get('historyBody').hidden, false);
  f.context.toggleHistory();
  assert.equal(f.stored.get('historyExpanded'), 'false');
  assert.equal(f.selectors.get('.history-panel').classList.contains('history-collapsed'), true);
});

test('compact scan setup omits redundant captions but keeps options and warnings', () => {
  const template = fs.readFileSync(path.join(__dirname, '../templates/index.html'), 'utf8');
  assert.doesNotMatch(template, /Local workspace|>WORKSPACE<|Choose what to inspect\.|scannerHint/);
  assert.doesNotMatch(source, /scannerHint|Inspect TLS configuration/);
  assert.match(template, /<h2>New scan<\/h2>/);
  assert.match(template, /id="tlsExtendedOption"/);
  assert.match(template, /id="serverSoftwareNote"/);
});

test('history searches loaded records, expands and escapes target HTML', () => {
  const f = fixture();
  f.run(`historyScans = Array.from({length: 12}, (_, id) => ({id, target: 'example' + id + '.com', scanner:'tls_certs', status:'completed', timestamp:'2026-09-08T12:00:00'})); historyTotal=72;`);
  f.context.renderHistory();
  assert.equal(f.get('showMoreScans').parentElement, f.get('scansList'));
  assert.equal((f.get('scansList').innerHTML.match(/class="scan-open"/g) || []).length, 10);
  assert.equal(f.get('historyCount').textContent, 'Latest 12 of 72 stored');
  f.context.showMoreScans();
  assert.equal((f.get('scansList').innerHTML.match(/class="scan-open"/g) || []).length, 12);
  f.get('historySearch').value = 'example11';
  f.context.renderHistory();
  assert.equal((f.get('scansList').innerHTML.match(/class="scan-open"/g) || []).length, 1);
  f.get('historySearch').value = '';
  f.run(`historyScans[0].target = '<img src=x onerror="bad()">';`);
  f.context.renderHistory();
  assert.ok(!f.get('scansList').innerHTML.includes('<img'));
  assert.match(f.get('scansList').innerHTML, /&quot;bad\(\)&quot;/);
});

test('failed submission preserves the previous results and enables retry', async () => {
  const f = fixture();
  f.get('target').value = 'example.com:443';
  f.get('scanner').value = 'tls_certs';
  f.get('resultsDisplay').innerHTML = 'Previous assessment';
  f.context.fetch = async () => ({ok: false, json: async () => ({error: 'Busy'})});
  f.context.setupFormHandler();
  await f.get('scanForm').listeners.submit({preventDefault() {}});
  assert.equal(f.get('resultsDisplay').innerHTML, 'Previous assessment');
  assert.equal(f.get('formError').textContent, 'Busy');
  assert.equal(f.get('startScanBtn').disabled, false);
});

test('portless input is blocked for TLS but accepted for email and DKIM', async () => {
  const f = fixture();
  f.get('target').value = 's02._domainkey.example.com';
  f.get('scanner').value = 'tls_certs';
  let payload;
  f.context.fetch = async (url, options) => {
    payload = JSON.parse(options.body);
    return {ok: true, json: async () => ({id: 13})};
  };
  f.run('startPolling = () => {}; loadScans = () => {};');
  f.context.setupFormHandler();
  await f.get('scanForm').listeners.submit({preventDefault() {}});
  assert.equal(payload, undefined);
  assert.equal(f.get('target').getAttribute('aria-invalid'), 'true');
  f.get('scanner').value = 'email';
  await f.get('scanForm').listeners.submit({preventDefault() {}});
  assert.equal(payload.target, 's02._domainkey.example.com');
  assert.equal(payload.scanner, 'email');
  assert.equal(payload.check_ciphers, false);
});

test('late history responses cannot replace the most recently selected scan', async () => {
  const f = fixture();
  const responses = {};
  f.context.fetch = url => new Promise(resolve => { responses[url] = resolve; });
  const older = f.context.viewScan(1);
  const newer = f.context.viewScan(2);
  const response = id => ({ok: true, json: async () => ({target: `example${id}.com`, scanner: 'tls_certs', status:'completed', timestamp:'2026-09-08T12:00:00', results:{output: 'Assessment', evidence: ''}})});
  responses['/api/scan/2'](response(2));
  await newer;
  responses['/api/scan/1'](response(1));
  await older;
  assert.match(f.get('resultsDisplay').innerHTML, /example2.com/);
  assert.doesNotMatch(f.get('resultsDisplay').innerHTML, /example1.com/);
  assert.match(f.get('resultsDisplay').innerHTML, /result-pane assessment-pane/);
});

test('scan rendering restores evidence preference and both export formats', async () => {
  const f = fixture();
  f.stored.set('technicalEvidenceVisible', 'true');
  f.context.fetch = async () => ({ok: true, json: async () => ({target:'example.com', scanner:'tls_certs', status:'completed', timestamp:'2026-09-08T12:00:00', results:{output:'[✓] Valid <certificate>', evidence:'$ openssl x509\nserial=ABC'}})});
  await f.context.viewScan(1);
  const html = f.get('resultsDisplay').innerHTML;
  assert.match(html, /results-workspace evidence-open/);
  assert.match(html, /&lt;certificate&gt;/);
  assert.match(html, /serial=ABC/);
  assert.match(html, /exportScan\(1, 'txt'\)/);
  assert.match(html, /exportScan\(1, 'json'\)/);
});
