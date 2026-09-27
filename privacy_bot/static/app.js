/* Privacy Bot dashboard — vanilla JS, no build, no external requests.
 *
 * Rules this file follows:
 *  - Every URL is resolved against the document base, so the app works under /privacy-bot/ and at root.
 *  - Backend text reaches the DOM only through textContent. There is no path from an API response to
 *    innerHTML; the only innerHTML use is the trusted ICONS constant defined below.
 *  - Writes carry X-Privacy-Bot: 1 (contract requirement). Errors surface FastAPI {detail}.
 *  - Nothing here invents a number: every count comes from an array the backend returned, and a source
 *    that did not complete a check is reported as unknown, never as clean.
 */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ dom */

  var PATH = location.pathname || '/';
  var API_BASE = /\/$/.test(PATH) ? PATH : PATH.replace(/[^/]*$/, '');
  function apiUrl(path) { return API_BASE + String(path).replace(/^\//, ''); }

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  function add(node, child) {
    if (child === null || child === undefined || child === false || child === '') return node;
    if (Array.isArray(child)) { child.forEach(function (c) { add(node, c); }); return node; }
    node.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
    return node;
  }

  /* `text` always goes through textContent. `html` is only ever used for the ICONS constant. */
  function el(tag, props) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (k) {
        var v = props[k];
        if (v === null || v === undefined || v === false) return;
        if (k === 'class') node.className = v;
        else if (k === 'text') node.textContent = String(v);
        else if (k === 'html') node.innerHTML = v;
        else if (k === 'dataset') Object.keys(v).forEach(function (dk) { node.dataset[dk] = v[dk]; });
        else if (k === 'value') node.value = v;
        else if (k === 'href') {
          var safe = safeUrl(v);
          if (safe) {
            node.setAttribute('href', safe);
            node.setAttribute('rel', 'noreferrer noopener');
            node.setAttribute('target', '_blank');
          }
        } else if (k === 'disabled' || k === 'checked' || k === 'hidden' || k === 'selected' || k === 'open' || k === 'required') node[k] = true;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
        else node.setAttribute(k, v === true ? '' : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) add(node, arguments[i]);
    return node;
  }

  var ICONS = {
    overview: '<path d="M4 13a8 8 0 0 1 16 0"/><path d="M12 13l3.2-3.4"/><path d="M4 18h16"/>',
    exposures: '<circle cx="11" cy="11" r="2.4"/><path d="M11 4.4a6.6 6.6 0 0 1 0 13.2"/><path d="M11 1.2a9.8 9.8 0 0 1 0 19.6"/><path d="M17.5 17.5 21 21"/>',
    removals: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 7.2 12 12.6l8.5-5.4"/><path d="M8 16h8"/>',
    credit: '<path d="M4 19V9"/><path d="M9 19V5"/><path d="M14 19v-7"/><path d="M19 19V8"/><path d="M3 21h18"/>',
    sources: '<ellipse cx="12" cy="6" rx="7" ry="2.6"/><path d="M5 6v11c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6"/><path d="M5 11.5c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6"/>',
    research: '<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H19v15H6.5A2.5 2.5 0 0 0 4 20.5z"/><path d="M9 7.5h6"/><path d="M9 11h6"/>',
    identity: '<circle cx="10" cy="8.5" r="3.3"/><path d="M4 20a6 6 0 0 1 12 0"/><path d="M17.5 15.5h3M19 14v3"/>',
    theme: '<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M6 6l1.4 1.4M16.6 16.6 18 18M18 6l-1.4 1.4M7.4 16.6 6 18"/>',
    scan: '<path d="M20 11a8 8 0 1 0-1.4 5.4"/><path d="M20 5v6h-6"/>',
    external: '<path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M18 14v5a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>'
  };

  function icon(name) {
    return el('span', {
      class: 'ic', 'aria-hidden': 'true',
      html: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" focusable="false">' + (ICONS[name] || ICONS.overview) + '</svg>'
    });
  }

  function paintIcons(root) {
    $$('[data-icon]', root || document).forEach(function (n) {
      if (n.dataset.painted) return;
      n.dataset.painted = '1';
      n.textContent = '';
      add(n, icon(n.dataset.icon));
    });
  }

  /* ------------------------------------------------------------ formatting */

  function blank(v) { return v === null || v === undefined || v === ''; }
  function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function str(v) { return blank(v) ? '' : typeof v === 'object' ? jsonPretty(v) : String(v); }

  function humanKey(v) {
    if (v === 'verified_removed') return 'Removed in checked scope';
    var raw = blank(v) ? 'unknown' : String(v);
    return raw.replace(/[_\-.]+/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function safeUrl(v) {
    if (blank(v)) return '';
    try {
      var u = new URL(String(v), location.href);
      return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : '';
    } catch (e) { return ''; }
  }

  function jsonPretty(v) {
    try { return JSON.stringify(v, null, 2); } catch (e) { return String(v); }
  }

  function fmtDateTime(v) {
    if (blank(v)) return '';
    var d = new Date(v);
    if (isNaN(d.getTime())) return String(v);
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  function fmtDate(v) {
    if (blank(v)) return '';
    var d = new Date(v);
    if (isNaN(d.getTime())) return String(v);
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
  }

  function timeAgo(v) {
    if (blank(v)) return '';
    var t = new Date(v).getTime();
    if (isNaN(t)) return '';
    var secs = Math.round((t - Date.now()) / 1000);
    var future = secs < 0;
    var s = Math.abs(secs);
    var suffix = future ? ' from now' : ' ago';
    if (s < 90) return future ? 'in under a minute' : 'just now';
    var units = [['minute', 60], ['hour', 3600], ['day', 86400], ['week', 604800], ['month', 2592000], ['year', 31536000]];
    for (var i = 0; i < units.length; i++) {
      var next = units[i + 1];
      if (!next || s < next[1]) {
        var n = Math.round(s / units[i][1]);
        return n + ' ' + units[i][0] + (n === 1 ? '' : 's') + suffix;
      }
    }
    return s + ' seconds' + suffix;
  }

  /* A timestamp that never claims a time the backend did not send. */
  function stamp(v, fallback) {
    if (blank(v)) return el('span', { class: 'muted', text: fallback || 'no timestamp from the backend' });
    return el('time', { datetime: String(v), title: fmtDateTime(v) + ' · ' + timeAgo(v) }, fmtDateTime(v));
  }

  function splitLines(v) {
    return String(blank(v) ? '' : v).split(/\r?\n/).map(function (s) { return s.trim(); }).filter(function (s) { return s.length; });
  }
  function joinLines(v) { return arr(v).join('\n'); }

  /* --------------------------------------------------------------- status */

  var SOURCE_STATUS = {
    not_checked: { kind: 'neutral', label: 'Not checked', cover: 'never looked at — no findings here means unknown, not clean' },
    needs_setup: { kind: 'neutral', label: 'Needs setup', cover: 'not configured enough to check — no coverage claimed' },
    needs_login: { kind: 'warn', label: 'Needs login', cover: 'the page was not reachable as you — no coverage claimed' },
    blocked: { kind: 'bad', label: 'Blocked', cover: 'the site refused the check — no coverage claimed' },
    checked: { kind: 'good', label: 'Checked', cover: 'the page was read at the last check' },
    error: { kind: 'bad', label: 'Error', cover: 'the check failed — no coverage claimed' }
  };
  var FINDING_STATUS = { candidate: 'info', confirmed: 'warn', dismissed: 'neutral' };
  var REMOVAL_STATUS = { draft: 'neutral', submitting: 'warn', submitted: 'info', acknowledged: 'warn', verified_removed: 'good', rejected: 'bad', uncertain: 'warn', reappeared: 'bad' };
  /* Mirrors the transitions the backend enforces on PATCH api/removals/{id}. */
  var REMOVAL_TRANSITIONS = {
    draft: ['draft', 'submitted'],
    submitted: ['submitted', 'acknowledged', 'verified_removed', 'rejected'],
    acknowledged: ['acknowledged', 'verified_removed', 'rejected'],
    uncertain: ['uncertain', 'submitted', 'acknowledged', 'verified_removed', 'rejected'],
    reappeared: ['reappeared', 'submitted', 'verified_removed'],
    verified_removed: [],
    rejected: []
  };
  var RUN_STATUS = { running: 'info', started: 'info', ok: 'good', success: 'good', checked: 'good', skipped: 'neutral', blocked: 'bad', error: 'bad', failed: 'bad' };
  var SEVERITY = { important: 'bad', high: 'bad', critical: 'bad', medium: 'warn', low: 'info', routine: 'neutral', info: 'neutral' };

  var SOURCE_KIND_MAP = (function () {
    var m = {};
    Object.keys(SOURCE_STATUS).forEach(function (k) { m[k] = SOURCE_STATUS[k].kind; });
    return m;
  })();

  function badge(value, kindMap, label) {
    var key = blank(value) ? 'unknown' : String(value).toLowerCase();
    return el('span', { class: 'badge badge-' + ((kindMap && kindMap[key]) || 'neutral') },
      el('span', { class: 'badge-dot', 'aria-hidden': 'true' }), label || humanKey(key));
  }

  function chips(values, cls) {
    return el('div', { class: 'row gap-sm' }, arr(values).map(function (v) { return el('span', { class: 'chip ' + (cls || ''), text: str(v) }); }));
  }

  function emptyBlock(title, note, cta) {
    return el('div', { class: 'empty' },
      el('p', { class: 'empty-title', text: title }),
      note ? el('p', { class: 'empty-note', text: str(note) }) : null,
      cta || null);
  }

  function notice(kind, title, lines) {
    var list = Array.isArray(lines) ? lines : (lines ? [lines] : []);
    var kids = [el('p', { class: 'notice-title', text: title })];
    list.forEach(function (line) {
      if (!line) return;
      kids.push(line.nodeType ? line : el('p', { text: str(line) }));
    });
    return el('div', { class: 'notice notice-' + kind, role: kind === 'bad' ? 'alert' : 'note' }, kids);
  }

  /* card(title, {badge, actions, cls}, ...children) */
  function card(title, opts) {
    var o = opts || {};
    var kids = Array.prototype.slice.call(arguments, 2);
    var body = el('div', { class: 'stack' });
    add(body, kids);
    var head = title ? el('div', { class: 'card-head' }, el('h2', { text: title }), o.badge || null, o.actions || null) : null;
    return el('section', { class: 'card' + (o.cls ? ' ' + o.cls : '') }, head, body);
  }

  function metric(value, label, sub, tone) {
    return el('div', { class: 'card metric' },
      el('p', { class: 'metric-num' + (tone ? ' is-' + tone : ''), text: value }),
      el('p', { class: 'metric-label', text: label }),
      sub ? el('p', { class: 'metric-sub', text: sub }) : null);
  }

  function linkOrText(url, text) {
    var href = safeUrl(url);
    if (!href) return el('span', { class: 'wrap-any', text: text || str(url) || 'no link recorded' });
    return el('a', { href: href, class: 'wrap-any' }, text || href);
  }

  function kv(pairs) {
    var node = el('dl', { class: 'kv' });
    pairs.forEach(function (p) {
      add(node, el('dt', null, p[0]));
      add(node, el('dd', null, p[1]));
    });
    return node;
  }

  /* ------------------------------------------------------------------ state */

  var DEFAULT_PROFILE = { name: '', email: '', phone: '', addresses: [], aliases: [], country: 'GB' };
  var DEFAULT_SETTINGS = { interval_hours: 24, enabled: false, notify_soft: false };
  var DEFAULT_CONFIG = { watch_url: '', terms: [], empty_selector: '', match_selector: '', report_selector: '', report_url: '' };

  var state = {
    data: null,
    connections: null,
    connectionsError: null,
    loadError: null,
    loadStatus: null,
    authed: false,
    offline: false,
    loading: false,
    lastLoadedAt: null,
    view: 'overview',
    filters: { exposureText: '', exposureSource: '', exposureStatus: '' },
    previewed: {},
    openEditors: {},
    creditDraft: '',
    creditExtract: null,
    busyButton: null,
    drafts: {}
  };

  /* Every write re-reads the dashboard, so unsaved typing is kept here and dropped only when that
     same form saves. Key: view|formId|fieldName. */
  function draftKey(formId, key) {
    return state.view + '|' + (formId || 'form') + '|' + key;
  }

  function clearDrafts(formId) {
    Object.keys(state.drafts).forEach(function (k) {
      if (k.indexOf('|' + formId + '|') >= 0) delete state.drafts[k];
    });
  }

  function D(key, fallback) {
    var v = state.data && state.data[key];
    return blank(v) ? fallback : v;
  }
  function profile() { return Object.assign({}, DEFAULT_PROFILE, isObj(D('profile')) ? D('profile') : null); }
  function settings() { return Object.assign({}, DEFAULT_SETTINGS, isObj(D('settings')) ? D('settings') : null); }
  function sources() { return arr(D('sources')); }
  function findings() { return arr(D('findings')); }
  function removals() { return arr(D('removals')); }
  function alerts() { return arr(D('alerts')); }
  function runs() { return arr(D('runs')); }
  function credit() { return arr(D('credit')); }
  function research() { return arr(D('research')); }

  function sourceById(id) {
    var key = String(id);
    return sources().filter(function (s) { return String(s.id) === key; })[0] || null;
  }
  function sourceName(id) {
    if (blank(id)) return 'no source recorded';
    var s = sourceById(id);
    return s ? (str(s.name) || String(s.id)) : 'source ' + String(id);
  }
  function findingById(id) {
    if (blank(id)) return null;
    var key = String(id);
    return findings().filter(function (f) { return String(f.id) === key; })[0] || null;
  }

  /* Honest source coverage: only a source that completed a check may claim anything. */
  function coverage() {
    var list = sources();
    var c = { total: list.length, enabled: 0, byStatus: {}, lastChecked: null, uncovered: [] };
    list.forEach(function (s) {
      if (s.enabled !== false) c.enabled++;
      var st = blank(s.status) ? 'not_checked' : String(s.status);
      if (!SOURCE_STATUS[st]) st = 'not_checked';
      c.byStatus[st] = (c.byStatus[st] || 0) + 1;
      if (st === 'checked' && !blank(s.last_checked)) {
        var t = new Date(s.last_checked).getTime();
        if (!isNaN(t) && (!c.lastChecked || t > c.lastChecked)) c.lastChecked = t;
      }
      if (st !== 'checked') c.uncovered.push(s);
    });
    return c;
  }

  function statusPhrase(c) {
    var keys = Object.keys(SOURCE_STATUS).filter(function (k) { return c.byStatus[k]; });
    if (!keys.length) return '';
    return keys.map(function (k) { return c.byStatus[k] + ' ' + SOURCE_STATUS[k].label.toLowerCase(); }).join(', ');
  }

  function coverageSummary() {
    var c = coverage();
    if (!c.total) return 'No sources are connected, so nothing has been checked at all. Zero findings is not an all-clear.';
    var checked = c.byStatus.checked || 0;
    var last = c.lastChecked ? ' Last completed check ' + fmtDateTime(new Date(c.lastChecked).toISOString()) + '.' : '';
    if (checked === c.total) return 'All ' + c.total + ' connected source' + (c.total === 1 ? '' : 's') + ' reported a completed check.' + last;
    return checked + ' of ' + c.total + ' source' + (c.total === 1 ? '' : 's') + ' reported a completed check. Not covered: ' +
      statusPhrase(c) + '.' + last;
  }

  function scheduleText() {
    if (!state.data) return 'not loaded yet';
    var s = settings();
    return (s.enabled ? 'on, every ' + (Number(s.interval_hours) || 1) + ' hours' : 'off (manual runs only)') +
      (s.notify_soft ? ' · soft credit enquiries also notify' : ' · soft credit enquiries stay history-only');
  }

  /* -------------------------------------------------------------------- api */

  function fail(message, status, data) {
    var e = new Error(message);
    e.status = status;
    e.data = data;
    return e;
  }
  function errorMessage(err) {
    if (!err) return 'Something went wrong.';
    return err.message || String(err);
  }

  function api(path, opts) {
    var o = opts || {};
    var method = (o.method || 'GET').toUpperCase();
    var init = { method: method, headers: { Accept: 'application/json' }, credentials: 'same-origin' };
    if (method !== 'GET' && method !== 'HEAD') init.headers['X-Privacy-Bot'] = '1';
    if (o.form !== undefined && o.form !== null) {
      init.body = o.form; /* FormData — the browser sets the multipart boundary itself */
    } else if (o.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(o.body);
    }
    return window.fetch(apiUrl(path), init).then(function (res) {
      if (res.status === 401) {
        state.authed = false;
        showLogin();
        throw fail('This dashboard is locked — sign in with the Privacy Bot API token.', 401, null);
      }
      return res.text().then(function (text) {
        var data = null;
        if (text) { try { data = JSON.parse(text); } catch (e) { data = { detail: text.slice(0, 300) }; } }
        if (!res.ok) {
          var detail = isObj(data) && typeof data.detail === 'string' && data.detail ? data.detail : '';
          if (!detail && res.status === 404) {
            detail = 'No route for ' + method + ' ' + apiUrl(path) + '. This UI follows docs/CONTRACT.md exactly, so the service behind this prefix may not implement it yet.';
          }
          if (!detail) detail = 'The backend answered HTTP ' + res.status + ' for ' + method + ' ' + path + '.';
          throw fail(detail, res.status, data);
        }
        return data;
      });
    }, function () {
      throw fail('Could not reach ' + apiUrl(path) + '. Is the Privacy Bot service running on this host?', 0, null);
    });
  }

  /* ------------------------------------------------------------ ui plumbing */

  var toasts = $('#toasts');

  function toast(message, kind) {
    add(toasts, el('div', { class: 'toast' + (kind ? ' toast-' + kind : ''), text: str(message) }));
    while (toasts.children.length > 2) toasts.firstChild.remove();
    var host = toasts.lastChild;
    setTimeout(function () { if (host && host.parentNode) host.parentNode.removeChild(host); }, kind === 'bad' ? 9000 : 5200);
  }

  function setBusy(btn, on) {
    if (!btn) return;
    if (on) { btn.setAttribute('data-busy', '1'); btn.disabled = true; }
    else { btn.removeAttribute('data-busy'); btn.disabled = false; }
  }

  /* One in-flight action at a time: the button is disabled, errors surface honestly. */
  function withBusy(btn, fn) {
    if (state.busyButton) { toast('One action at a time — the previous request is still running.', 'warn'); return Promise.resolve(); }
    state.busyButton = btn || true;
    setBusy(btn, true);
    return Promise.resolve().then(fn).then(function (res) {
      state.busyButton = null;
      if (btn && btn.isConnected) setBusy(btn, false);
      return res;
    }, function (err) {
      state.busyButton = null;
      if (btn && btn.isConnected) setBusy(btn, false);
      toast(errorMessage(err), 'bad');
    });
  }

  function fieldRow(opts) {
    var o = opts || {};
    var id = 'f-' + o.key + '-' + Math.random().toString(36).slice(2, 7);
    var base = {
      class: 'input' + (o.mono ? ' mono' : ''), id: id, name: o.key,
      placeholder: blank(o.placeholder) ? '' : String(o.placeholder),
      spellcheck: 'false', 'aria-describedby': o.hint ? id + '-h' : null
    };
    var input;
    if (o.type === 'select') {
      input = el('select', base, arr(o.options).map(function (opt) {
        var val = isObj(opt) ? opt.value : opt;
        var lab = isObj(opt) ? opt.label : humanKey(opt);
        return el('option', { value: val, text: lab, selected: String(val) === String(blank(o.value) ? '' : o.value) });
      }));
    } else if (o.type === 'textarea') {
      input = el('textarea', Object.assign({}, base, { rows: o.rows || 4 }));
      input.value = blank(o.value) ? '' : String(o.value);
    } else {
      input = el('input', Object.assign({}, base, {
        type: o.type || 'text',
        value: blank(o.value) ? '' : String(o.value),
        autocomplete: o.autocomplete || 'off',
        inputmode: o.inputmode || null,
        required: !!o.required
      }));
    }
    var err = el('p', { class: 'field-error', role: 'alert', hidden: true });
    var hint = o.hint ? el('span', { class: 'hint', id: id + '-h', text: o.hint }) : null;
    var wrap = el('div', { class: 'field' },
      el('label', { class: 'label', for: id, text: o.label || humanKey(o.key) }),
      input, hint, err);
    var dkey = draftKey(o.form, o.key);
    if (o.secret) {
      /* a write-only box never keeps a draft: no secret sits in page memory after a re-read */
      input.setAttribute('autocomplete', 'new-password');
    } else {
      if (state.drafts[dkey] !== undefined) input.value = state.drafts[dkey];
      var remember = function () { state.drafts[dkey] = input.value; };
      input.addEventListener('input', remember);
      input.addEventListener('change', remember);
    }
    input.api = {
      key: o.key, wrap: wrap, error: err, input: input, json: !!o.json,
      setError: function (m) { err.hidden = false; err.textContent = m; input.setAttribute('aria-invalid', 'true'); },
      clearError: function () { err.hidden = true; err.textContent = ''; input.removeAttribute('aria-invalid'); }
    };
    return input.api;
  }

  function readFields(fields) {
    var out = {};
    var ok = true;
    fields.forEach(function (f) {
      f.clearError();
      var raw = f.input.type === 'checkbox' ? f.input.checked : f.input.value;
      if (f.json) {
        var text = String(raw || '').trim();
        if (!text) { out[f.key] = null; return; }
        try { out[f.key] = JSON.parse(text); }
        catch (e) { f.setError('This has to be valid JSON — check for trailing commas and straight quotes.'); ok = false; }
        return;
      }
      out[f.key] = blank(raw) ? '' : String(raw).trim();
    });
    return ok ? out : null;
  }

  function checkbox(key, label, checked, hint, form) {
    var id = 'c-' + key + '-' + Math.random().toString(36).slice(2, 7);
    var dkey = draftKey(form, key);
    if (state.drafts[dkey] !== undefined) checked = state.drafts[dkey];
    var input = el('input', { type: 'checkbox', id: id, name: key, checked: !!checked });
    input.addEventListener('change', function () { state.drafts[dkey] = input.checked; });
    var wrap = el('label', { class: 'check', for: id },
      input,
      el('span', null, el('span', { class: 'strong', text: label }), hint ? el('span', { class: 'hint', text: hint }) : null));
    return { input: input, wrap: wrap, key: key };
  }

  function button(label, onclick, cls) {
    return el('button', { class: 'btn ' + (cls || 'btn-primary'), type: 'button', text: label, onclick: onclick });
  }

  /* ------------------------------------------------------------------ login */

  var loginDialog = $('#login'), loginForm = $('#login-form'), loginError = $('#login-error');

  function showLogin() {
    $('#btn-signout').hidden = true;
    if (!loginDialog.open) {
      loginDialog.showModal();
      setTimeout(function () { var i = $('#login-token'); if (i) i.focus(); }, 30);
    }
  }

  function initLogin() {
    loginForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = $('#login-token'), btn = $('#login-submit');
      var token = input.value || '';
      loginError.hidden = true;
      if (!token.trim()) {
        loginError.hidden = false;
        loginError.textContent = 'Enter the API token for this deployment.';
        return;
      }
      setBusy(btn, true);
      api('api/login', { method: 'POST', body: { token: token } }).then(function () {
        input.value = '';
        state.authed = true;
        state.offline = false;
        loginDialog.close();
        $('#btn-signout').hidden = state.accessMode === 'network';
        toast('Signed in — the session cookie lives on this host only.', 'good');
        return load({ reason: 'login' });
      }).catch(function (err) {
        loginError.hidden = false;
        loginError.textContent = err.status === 401 ? 'That token was not accepted.' : errorMessage(err);
        input.select();
      }).then(function () { if (btn.isConnected) setBusy(btn, false); });
    });
    loginDialog.addEventListener('cancel', function () { $('#login-token').value = ''; });

    $('#btn-signout').addEventListener('click', function () {
      var btn = this;
      withBusy(btn, function () {
        return api('api/logout', { method: 'POST', body: {} }).then(function () {
          state.data = null;
          state.authed = false;
          state.lastLoadedAt = null;
          render();
          toast('Signed out. The session cookie is cleared.', 'good');
          showLogin();
        });
      });
    });
  }

  /* ------------------------------------------------------------- load/write */

  function load(opts) {
    var o = opts || {};
    if (state.loading) return Promise.resolve();
    state.loading = true;
    $('#btn-refresh').disabled = true;
    if (!state.data) $('#view-sub').textContent = 'Loading your dashboard…';

    return Promise.all([
      api('api/dashboard'),
      api('api/connections').catch(function (err) { return { __error: errorMessage(err), __status: err.status }; })
    ]).then(function (res) {
      state.data = isObj(res[0]) ? res[0] : {};
      var c = res[1];
      var connFailed = isObj(c) && c.__error;
      state.connections = connFailed ? null : (isObj(c) ? c : {});
      state.connectionsError = connFailed && c.__status !== 401 ? c.__error : null;
      state.offline = false;
      state.authed = true;
      state.loadError = null;
      state.lastLoadedAt = new Date().toISOString();
      $('#btn-signout').hidden = state.accessMode === 'network';
      render();
    }).catch(function (err) {
      state.offline = true;
      state.loadError = errorMessage(err);
      state.loadStatus = err.status;
      if (err.status !== 401) render();
      if (o.notify !== false && err.status !== 401) toast(state.loadError, 'bad');
    }).then(function () {
      state.loading = false;
      $('#btn-refresh').disabled = false;
      updateChrome();
    });
  }

  /* Every write re-reads the dashboard, so the screen always shows what the backend kept. */
  function write(path, method, body, message, form) {
    return api(path, { method: method, body: body, form: form }).then(function (res) {
      if (message) toast(message, 'good');
      return load({ notify: false }).then(function () { return res; });
    });
  }

  /* ------------------------------------------------------------ chrome/router */

  var VIEWS = {
    overview: { title: 'Overview', sub: 'What has actually been checked, and what is still unknown.' },
    exposures: { title: 'Exposures', sub: 'Pages a source matched against your identity, with each one’s coverage limits.' },
    removals: { title: 'Removals', sub: 'Drafts you send, the exact preview before sending, and what came back.' },
    credit: { title: 'Credit', sub: 'UK Experian, Equifax and TransUnion snapshots. Soft enquiries stay history.' },
    sources: { title: 'Sources & connections', sub: 'Every watched site, its mode, its last check and its setup state.' },
    research: { title: 'Research', sub: 'The shipped reading list. None of it is verified against your own data.' },
    identity: { title: 'Identity & setup', sub: 'The minimum data used to match you, plus sending and notification settings.' }
  };

  function setView(view) {
    state.view = VIEWS[view] ? view : 'overview';
    if (location.hash.slice(1) !== state.view) history.replaceState(null, '', '#' + state.view);
    render();
  }

  function initRouter() {
    $$('#nav .nav-item').forEach(function (btn) {
      btn.addEventListener('click', function () { setView(btn.dataset.view); });
    });
    window.addEventListener('hashchange', function () {
      var v = location.hash.slice(1);
      if (VIEWS[v] && v !== state.view) { state.view = v; render(); }
    });
    if (VIEWS[location.hash.slice(1)]) state.view = location.hash.slice(1);
  }

  function updateChrome() {
    var meta = VIEWS[state.view];
    $('#view-title').textContent = meta.title;
    $('#view-sub').textContent = !state.data && state.loadError ? state.loadError : meta.sub;

    var stampEl = $('#stamp');
    if (state.offline && !state.data) stampEl.textContent = 'Not connected · ' + (state.loadStatus ? 'HTTP ' + state.loadStatus : 'no response');
    else if (state.lastLoadedAt) stampEl.textContent = 'Read ' + fmtDateTime(state.lastLoadedAt) + ' · ' + timeAgo(state.lastLoadedAt);
    else stampEl.textContent = 'Nothing read yet';

    var counts = {
      alerts: alerts().filter(function (a) { return !a.read; }).length,
      exposures: findings().filter(function (f) { return f.status !== 'dismissed'; }).length,
      removals: removals().filter(function (r) { return ['draft', 'uncertain', 'acknowledged'].indexOf(String(r.status)) >= 0; }).length,
      credit: credit().reduce(function (n, a) { return n + (Number(a.important_count) || 0); }, 0),
      sources: sources().filter(function (s) { return ['needs_setup', 'needs_login', 'blocked', 'error'].indexOf(String(s.status)) >= 0; }).length
    };
    $$('#nav .count').forEach(function (n) {
      var v = counts[n.dataset.count];
      if (v > 0) { n.textContent = String(v); n.hidden = false; }
      else { n.textContent = ''; n.hidden = true; }
    });

    var c = coverage();
    $('#sched-line').textContent = state.data
      ? 'Schedule: ' + scheduleText() + '. Last completed check ' + (c.lastChecked ? timeAgo(new Date(c.lastChecked).toISOString()) : 'never recorded') + '.'
      : 'Schedule: not loaded yet yet.';

    $$('#nav .nav-item').forEach(function (b) {
      if (b.dataset.view === state.view) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
  }

  var THEME_KEY = 'privacy-bot.theme'; /* the only thing kept in local storage — no personal data */

  function applyTheme(mode) {
    if (mode === 'light' || mode === 'dark') document.documentElement.setAttribute('data-theme', mode);
    else document.documentElement.removeAttribute('data-theme');
    $('#theme-label').textContent = 'Theme: ' + mode;
    try { localStorage.setItem(THEME_KEY, mode); } catch (e) { /* private mode: the choice simply will not persist */ }
  }

  function initTheme() {
    var stored = 'auto';
    try { stored = localStorage.getItem(THEME_KEY) || 'auto'; } catch (e) { /* ignore */ }
    applyTheme(['auto', 'light', 'dark'].indexOf(stored) >= 0 ? stored : 'auto');
    $('#btn-theme').addEventListener('click', function () {
      var order = ['auto', 'light', 'dark'];
      var cur = $('#theme-label').textContent.replace('Theme: ', '');
      applyTheme(order[(order.indexOf(cur) + 1) % order.length]);
    });
  }

  function initTopbar() {
    $('#btn-refresh').addEventListener('click', function () {
      withBusy(this, function () { return load({ reason: 'manual', notify: true }); });
    });
    $('#btn-scan').addEventListener('click', function () {
      var btn = this;
      withBusy(btn, function () {
        return api('api/scan', { method: 'POST', body: {} }).then(function (res) {
          var started = arr(res && res.runs).length;
          toast(started
            ? 'Scan started: ' + started + ' run' + (started === 1 ? '' : 's') + ' recorded. Results land under Exposures when a run finishes.'
            : 'No sources are enabled. Choose sources to check first.', started ? 'good' : 'warn');
          return load({ notify: false });
        });
      });
    });
  }

  /* ----------------------------------------------------------------- render */

  var RENDERERS = {
    overview: viewOverview, exposures: viewExposures, removals: viewRemovals, credit: viewCredit,
    sources: viewSources, research: viewResearch, identity: viewIdentity
  };

  function render() {
    updateChrome();
    $('#boot').hidden = !!state.data || !!state.loadError;
    var host = $('#view-' + state.view);
    $$('.view').forEach(function (v) { v.hidden = v.id !== 'view-' + state.view; });
    host.textContent = '';
    host.setAttribute('aria-busy', state.loading ? 'true' : 'false');
    add(host, notReadNotice());
    add(host, RENDERERS[state.view]());
    paintIcons(host);
  }

  /* Until a read succeeds, every view says so rather than showing defaults as if they were real. */
  function notReadNotice() {
    if (state.data) return null;
    return notice('warn', 'Nothing below is your real state yet' + (state.loadError ? ' — ' + state.loadError : '.'),
      ['The forms are shown so you can see what this page does, and they will fail until the backend answers.',
        state.loadStatus === 404
          ? 'The UI asks for exactly the routes in docs/CONTRACT.md (GET api/dashboard, GET api/connections, GET api/session). A 404 means the service is not deployed behind this prefix.'
          : '']);
  }

  function sourceOptions() {
    return sources().map(function (s) {
      return { value: s.id, label: (str(s.name) || String(s.id)) + ' · ' + humanKey(s.kind || 'unknown') };
    });
  }

  /* ---------------------------------------------------------------- overview */

  function viewOverview() {
    var c = coverage();
    var open = findings().filter(function (f) { return f.status !== 'dismissed'; });
    var confirmed = open.filter(function (f) { return f.status === 'confirmed'; });
    var drafts = removals().filter(function (r) { return String(r.status) === 'draft'; });
    var sent = removals().filter(function (r) { return ['submitting', 'submitted', 'acknowledged'].indexOf(String(r.status)) >= 0; });
    var verified = removals().filter(function (r) { return String(r.status) === 'verified_removed' && !blank(r.verification_scope); });
    var unread = alerts().filter(function (a) { return !a.read; });
    var important = credit().reduce(function (n, a) { return n + (Number(a.important_count) || 0); }, 0);
    var withSnapshot = credit().filter(function (a) { return !blank(a.latest_at); }).length;
    var p = profile();

    var steps = [];
    if (!p.name && !p.email && !p.phone && !arr(p.addresses).length) {
      steps.push('Add your name and email in Identity & setup.');
    }
    if (!c.total) steps.push('No source is connected, so nothing is being watched. Add your first broker or credit source under Sources.');
    else if (!c.enabled) steps.push('Choose and enable your sources. Your accounts and personal details have not been checked yet.');
    if (c.uncovered.length) {
      if (c.enabled) steps.push(c.uncovered.length + ' sources need attention. Open Sources for login, setup and check results.');
    }
    if (state.connections && !state.connections.smtp) {
      steps.push('Set up email sending when you are ready to submit removal requests. You can prepare drafts first.');
    }

    var out = [];

    var monitoring = D('monitoring') || {};
    if (monitoring.status === 'error') {
      out.push(card('Scheduled monitoring needs attention', { cls: 'card--alert' },
        el('p', { text: 'A check or its saved state failed. Automatic retries are delayed to avoid repeatedly querying your providers.' }),
        el('p', { class: 'soft muted' }, 'Next retry: ', stamp(monitoring.retry_at, 'unknown'), '. Check the service before relying on its coverage.')));
    }

    if (steps.length) {
      out.push(card('Start here', { cls: 'card--alert' },
        el('div', { class: 'list' }, steps.map(function (s, i) {
          return el('div', { class: 'item item--sub' }, el('div', { class: 'item-lead' },
            el('span', { class: 'badge badge-solid', text: 'Step ' + (i + 1) }),
            el('p', { class: 'item-title', text: s })));
        }))));
    }

    out.push(card('Source coverage', {
      badge: c.total
        ? ((c.byStatus.checked === c.total) ? badge('checked', SOURCE_KIND_MAP, 'All sources checked') : badge('incomplete', { incomplete: 'warn' }, 'Coverage incomplete'))
        : badge('not_checked', SOURCE_KIND_MAP, 'Nothing connected')
    },
      el('div', { class: 'coverage' },
        el('div', {
          class: 'coverage-bar', role: 'img',
          'aria-label': (c.byStatus.checked || 0) + ' of ' + c.total + ' sources checked'
        }, Object.keys(SOURCE_STATUS).map(function (k) {
          var n = c.byStatus[k] || 0;
          var seg = { checked: 'checked', needs_login: 'login', blocked: 'blocked', needs_setup: 'setup', not_checked: 'setup', error: 'error' }[k];
          if (!n) return null;
          var bar = el('i', { class: 'seg-' + seg, title: SOURCE_STATUS[k].label + ': ' + n });
          bar.style.flexGrow = String(n); /* CSSOM write: an inline style attribute would be blocked by the deployment CSP */
          return bar;
        })),
        el('p', { class: 'soft', text: c.total ? statusPhrase(c) : 'No sources connected' })),
      el('p', { class: 'soft', text: coverageSummary() }),
      kv([
        ['Last checked', c.lastChecked ? stamp(new Date(c.lastChecked).toISOString()) : el('span', { class: 'muted', text: 'no source reports a completed check' })],
        ['Schedule', scheduleText()],
        ['Last refreshed', state.lastLoadedAt ? stamp(state.lastLoadedAt) : el('span', { class: 'muted', text: 'never' })]
      ])));

    out.push(el('div', { class: 'grid grid-metrics' },
      metric(String(open.length), 'Exposures not dismissed', open.length ? confirmed.length + ' of them confirmed' : 'nothing matched so far', open.length ? 'warn' : null),
      metric(String(drafts.length), 'Drafts to review', drafts.length ? 'nothing has been sent for these' : 'no drafts waiting', drafts.length ? 'warn' : null),
      metric(String(sent.length), 'Requests sent', verified.length + ' removals with recorded checks', null),
      metric(String(unread.length), 'Unread alerts', unread.length ? 'listed below' : 'nothing unread', unread.length ? 'bad' : null),
      metric(String(important), 'Credit items flagged important', withSnapshot ? withSnapshot + ' of 3 agencies have a snapshot' : 'no agency snapshot', important ? 'bad' : null)));

    out.push(card('Alerts', { badge: unread.length ? el('span', { class: 'badge badge-bad', text: unread.length + ' unread' }) : null },
      alerts().length
        ? el('div', { class: 'list' }, alerts().slice(0, 12).map(alertItem))
        : emptyBlock('No alerts', 'Nothing has been flagged for review. That covers only sources that completed a check — ' + coverageSummary().toLowerCase())));

    out.push(card('Recent runs', {},
      runs().length
        ? el('div', { class: 'list' }, runs().slice(0, 10).map(function (r) {
          return el('div', { class: 'item' },
            el('div', { class: 'item-lead' },
              badge(r.status, RUN_STATUS),
              el('p', { class: 'item-title', text: sourceName(r.source_id) }),
              el('span', { class: 'spacer' }),
              stamp(r.created_at, 'no timestamp')),
            el('p', { class: 'item-body', text: str(r.detail) || (r.no_match ? 'The page was read and did not match your details. No match on that page, nothing more.' : 'No detail recorded.') }));
        }))
        : emptyBlock('No runs recorded', 'Enable your sources, then run a scan to start monitoring.')));

    return out;
  }

  function alertItem(a) {
    return el('div', { class: 'item' + (a.read ? '' : ' item--unread') },
      el('div', { class: 'item-lead' },
        badge(a.severity, SEVERITY),
        badge(a.kind, null, humanKey(a.kind || 'alert')),
        el('p', { class: 'item-title', text: str(a.title) || 'Untitled alert' }),
        el('span', { class: 'spacer' }),
        stamp(a.created_at, 'no timestamp')),
      blank(a.detail) ? null : el('p', { class: 'item-body', text: str(a.detail) }),
      el('div', { class: 'item-actions' },
        blank(a.agency) ? null : el('span', { class: 'chip', text: 'agency: ' + str(a.agency) }),
        a.read ? el('span', { class: 'muted soft', text: 'Already read' })
          : button('Mark read', function () {
            var btn = this;
            withBusy(btn, function () {
              return write('api/alerts/' + encodeURIComponent(a.id) + '/read', 'POST', {}, 'Alert marked read.', null);
            });
          }, 'btn-quiet')));
  }

  /* ---------------------------------------------------------------- exposures */

  function viewExposures() {
    var f = state.filters;
    var listHost = el('div', { class: 'list' });
    var countLabel = el('span', { class: 'muted soft' });
    var out = [];

    out.push(notice('info', 'How to read this list', [
      'A finding is one page that one source matched against your details. No match on that page means no match on that page — it does not mean a broker holds nothing about you.',
      coverageSummary()
    ]));

    out.push(card('Coverage per source', {},
      sources().length
        ? el('div', { class: 'table-wrap' }, el('table', { class: 'data' },
          el('thead', null, el('tr', null, ['Source', 'Kind · mode', 'Status', 'Last check', 'Findings', 'What it proves'].map(function (h, i) {
            return el('th', { class: i === 4 ? 'num' : null, text: h });
          }))),
          el('tbody', null, sources().map(function (s) {
            var mine = findings().filter(function (x) { return String(x.source_id) === String(s.id); });
            var st = SOURCE_STATUS[String(s.status || 'not_checked')] ? String(s.status || 'not_checked') : 'not_checked';
            var checked = st === 'checked';
            return el('tr', null,
              el('td', null, el('span', { class: 'strong', text: str(s.name) || String(s.id) })),
              el('td', { class: 'muted', text: humanKey(s.kind || 'unknown') + ' · ' + humanKey(s.mode || 'unknown') }),
              el('td', null, badge(st, SOURCE_KIND_MAP)),
              el('td', null, stamp(s.last_checked, 'never')),
              el('td', { class: 'num', text: checked ? String(mine.length) : '—' }),
              el('td', { class: 'muted soft', text: checked
                ? (mine.length ? 'matched ' + mine.length + ' page' + (mine.length === 1 ? '' : 's') + ' at that check' : 'the page was readable and did not match your details')
                : SOURCE_STATUS[st].cover }));
          }))))
        : emptyBlock('No sources', 'Add a source and this table shows what each one has and has not looked at.')));

    function refresh() {
      var filtered = findings().filter(function (x) {
        if (f.exposureSource && String(x.source_id) !== String(f.exposureSource)) return false;
        if (f.exposureStatus && String(x.status) !== f.exposureStatus) return false;
        if (f.exposureText) {
          var hay = (str(x.title) + ' ' + str(x.url) + ' ' + arr(x.matched).join(' ') + ' ' + str(x.detail)).toLowerCase();
          if (hay.indexOf(f.exposureText.toLowerCase()) < 0) return false;
        }
        return true;
      });
      listHost.textContent = '';
      add(listHost, filtered.length
        ? filtered.map(findingItem)
        : emptyBlock(findings().length ? 'No findings match these filters' : 'No exposures recorded',
          findings().length ? 'Clear the filters to see everything the backend returned.'
            : 'Nothing has been matched yet. ' + coverageSummary()));
      countLabel.textContent = filtered.length + ' of ' + findings().length + ' findings shown';
    }

    var filters = el('div', { class: 'filters' },
      el('label', { class: 'sr-only', for: 'ex-q', text: 'Search findings' }),
      el('input', {
        class: 'input', id: 'ex-q', type: 'search', value: f.exposureText,
        placeholder: 'Search title, link or matched term',
        oninput: function (e) { f.exposureText = e.target.value; refresh(); }
      }),
      el('label', { class: 'sr-only', for: 'ex-s', text: 'Filter by source' }),
      el('select', {
        class: 'input', id: 'ex-s',
        onchange: function (e) { f.exposureSource = e.target.value; refresh(); }
      },
        [el('option', { value: '', text: 'All sources' })].concat(sourceOptions().map(function (o) {
          return el('option', { value: o.value, text: o.label, selected: String(o.value) === f.exposureSource });
        }))),
      el('label', { class: 'sr-only', for: 'ex-st', text: 'Filter by status' }),
      el('select', {
        class: 'input', id: 'ex-st',
        onchange: function (e) { f.exposureStatus = e.target.value; refresh(); }
      },
        [el('option', { value: '', text: 'Any status' })].concat(['candidate', 'confirmed', 'dismissed'].map(function (s) {
          return el('option', { value: s, text: humanKey(s), selected: s === f.exposureStatus });
        }))),
      countLabel);

    out.push(card('Findings', { actions: filters }, listHost));
    refresh();
    return out;
  }

  function findingItem(x) {
    var src = sourceById(x.source_id);
    var srcStatus = src ? String(src.status || 'not_checked') : 'not_checked';
    return el('div', { class: 'item' },
      el('div', { class: 'item-lead' },
        badge(x.status, FINDING_STATUS),
        el('p', { class: 'item-title', text: str(x.title) || 'Untitled page' }),
        el('span', { class: 'spacer' }),
        el('span', { class: 'muted soft nowrap', text: sourceName(x.source_id) })),
      el('div', { class: 'item-meta' },
        el('span', null, 'first seen ', blank(x.first_seen) ? 'unknown' : ''), x.first_seen ? stamp(x.first_seen) : null,
        el('span', null, 'last seen ', blank(x.last_seen) ? 'unknown' : ''), x.last_seen ? stamp(x.last_seen) : null),
      x.url ? el('p', { class: 'item-body' }, linkOrText(x.url)) : null,
      arr(x.matched).length
        ? el('p', { class: 'row gap-sm' }, el('span', { class: 'muted soft', text: 'Matched:' }), chips(x.matched, 'chip-match'))
        : el('p', { class: 'muted soft', text: 'No matched terms recorded for this finding.' }),
      blank(x.detail) ? null : el('p', { class: 'item-body', text: str(x.detail) }),
      el('div', { class: 'item-actions' },
        x.status !== 'candidate' ? button('Mark candidate', function () { patchFinding(this, x.id, 'candidate'); }, 'btn-quiet') : null,
        x.status !== 'confirmed' ? button('Confirm', function () { patchFinding(this, x.id, 'confirmed'); }, 'btn-quiet') : null,
        x.status !== 'dismissed' ? button('Dismiss', function () { patchFinding(this, x.id, 'dismissed'); }, 'btn-quiet') : null,
        srcStatus === 'checked' ? null : el('span', { class: 'muted soft', text: 'this source last reported: ' + humanKey(srcStatus) }),
        src && src.kind !== 'broker'
          ? el('span', { class: 'muted soft', text: 'credit and breach findings do not use a removal request — they need their own provider process' })
          : button('Draft removal request', function () {
            var p = profile();
            if (!p.name || !p.email) {
              toast('Add your name and a contact email on Identity & setup first — a broker must be able to reply to you.', 'warn');
              return;
            }
            if (x.status !== 'confirmed') {
              toast('Confirm that this listing is yours first, so a removal request is never sent on a guess.', 'warn');
              return;
            }
            var btn = this;
            withBusy(btn, function () {
              return write('api/removals', 'POST', { finding_id: x.id }, 'Draft created from this finding — read the preview before anything is sent.', null);
            }).then(function () { setView('removals'); });
          }, 'btn-primary')));
  }

  function patchFinding(btn, id, status) {
    withBusy(btn, function () {
      return write('api/findings/' + encodeURIComponent(id), 'PATCH', { status: status }, 'Finding set to ' + humanKey(status) + '.', null);
    });
  }

  /* ----------------------------------------------------------------- removals */

  function viewRemovals() {
    var opts = sourceOptions().filter(function (o) { return sourceById(o.value).kind === 'broker'; });
    var select = el('select', { class: 'input', id: 'rm-src' },
      opts.length ? opts.map(function (o) { return el('option', { value: o.value, text: o.label }); })
        : [el('option', { value: '', text: 'No sources connected' })]);

    var out = [card('New draft from a source', {},
      el('p', { class: 'soft muted', text: 'A draft carries only the identity fields on the Identity & setup tab. Creating a draft contacts nobody — nothing leaves this machine until you press Send on a preview you have opened.' }),
      el('div', { class: 'row' },
        el('label', { class: 'sr-only', for: 'rm-src', text: 'Source to draft for' }),
        select,
        button('Create draft', function () {
          if (!select.value) { toast('Pick a source first — or add one under Sources.', 'warn'); return; }
          var btn = this;
          withBusy(btn, function () { return write('api/removals', 'POST', { source_id: select.value }, 'Draft created from the source.', null); });
        }, 'btn-primary')))];

    out.push(el('div', { class: 'list' }, removals().length ? removals().map(removalItem)
      : [emptyBlock('No removal requests yet', 'Draft one from an exposure or from a source above. Until you press Send on a preview, Privacy Bot has contacted nobody.')]));

    return out;
  }

  function removalItem(r) {
    var key = String(r.id);
    var open = !!state.openEditors[key];
    var finding = findingById(r.finding_id);

    /* The editor is built lazily so the open/closed state survives a re-read. */
    var editorHost = el('div', { class: 'stack' });
    var details = el('details', { class: 'editor', open: open },
      el('summary', null, open ? 'Hide request editor' : 'Preview, edit and send'),
      editorHost);
    if (open) add(editorHost, removalEditor(r));
    details.addEventListener('toggle', function () {
      if (details.open) {
        state.openEditors[key] = true;
        if (!editorHost.childNodes.length) add(editorHost, removalEditor(r));
      } else {
        delete state.openEditors[key];
      }
    });

    return el('div', { class: 'item card--flat' },
      el('div', { class: 'item-lead' },
        badge(r.status, REMOVAL_STATUS),
        el('p', { class: 'item-title', text: str(r.subject) || 'Removal request (no subject recorded)' }),
        el('span', { class: 'spacer' }),
        el('span', { class: 'muted soft nowrap', text: 'id ' + String(r.id) })),
      el('div', { class: 'item-meta' },
        el('span', { class: 'strong', text: sourceName(r.source_id) }),
        el('span', null, 'created '), stamp(r.created_at, 'unknown'),
        el('span', null, 'updated '), stamp(r.updated_at, 'never')),
      el('p', { class: 'item-body' },
        el('span', { class: 'muted', text: 'recipient: ' }),
        blank(r.recipient) ? el('span', { class: 'muted', text: 'not set on the draft — set it before sending' })
          : el('span', { class: 'mono', text: str(r.recipient) })),
      finding ? el('p', { class: 'item-body' },
        el('span', { class: 'muted', text: 'finding: ' }),
        el('span', null, str(finding.title) || 'untitled'),
        finding.url ? ' ' : null,
        finding.url ? linkOrText(finding.url, 'open the page') : null) : null,
      blank(r.note) ? el('p', { class: 'muted soft', text: 'No status note recorded.' }) : el('p', { class: 'item-body', text: str(r.note) }),
      r.verification_scope ? el('p', { class: 'item-body', text: 'Checked scope: ' + str(r.verification_scope) })
        : (r.status === 'verified_removed' ? el('p', { class: 'muted soft', text: 'This older removal record has no scope recorded. It does not establish removal from every broker database.' }) : null),
      r.verification_recorded_at ? el('p', { class: 'muted soft' }, 'Verification recorded ', stamp(r.verification_recorded_at)) : null,
      details);
  }

  function removalEditor(r) {
    var key = String(r.id);
    var previewed = !!state.previewed[key];
    var status = blank(r.status) ? 'draft' : String(r.status);
    var isDraft = status === 'draft';
    var allowed = REMOVAL_TRANSITIONS[status];

    var fTo = fieldRow({ key: 'recipient', label: 'Recipient (one broker privacy email address)', value: r.recipient, placeholder: 'privacy@example-broker.com', form: 'removal-' + key });
    var fBody = fieldRow({ key: 'body', label: 'Request body', type: 'textarea', rows: 10, value: r.body, hint: 'This is exactly what will be sent.', form: 'removal-' + key });
    var fNote = fieldRow({ key: 'note', label: 'Status note', type: 'textarea', rows: 3, value: r.note, hint: 'Any status change needs evidence here: what you sent, what they replied, or what a re-check showed.', form: 'removal-' + key });
    var fScope = fieldRow({ key: 'verification_scope', label: 'What you checked for removal', type: 'textarea', rows: 2, value: r.verification_scope,
      hint: 'Required when recording removal. Name the listing or search, whether you were signed in, and anything left unchecked. Public disappearance does not prove paid or other records were deleted. Do not buy access just to verify.', form: 'removal-' + key });

    if (!isDraft) {
      /* The backend refuses to rewrite a request once it has left the machine. */
      fTo.input.disabled = true;
      fBody.input.disabled = true;
    }

    var statusOptions = allowed && allowed.length
      ? allowed.map(function (s) { return { value: s, label: humanKey(s) + (s === status ? ' (current)' : '') }; })
      : [{ value: status, label: humanKey(status) }];
    var fStatus = fieldRow({
      key: 'status', label: 'Status', type: 'select', value: status, options: statusOptions,
      hint: allowed
        ? 'Record submission, a reply, or your verification evidence before changing status.'
        : 'The request is being processed. Check its send result before changing status.'
    });
    if (!allowed) fStatus.input.disabled = true;

    var previewHost = el('div', { class: 'stack' });

    var sendBtn = button('Send removal request', function () {
      /* Sending mails what the backend holds, not what is currently typed in this browser. */
      if (String(fTo.input.value || '').trim() !== String(r.recipient || '').trim()
        || String(fBody.input.value || '') !== String(r.body || '')) {
        fTo.setError('Save your changes, then preview the saved request before sending.');
        return;
      }
      var btn = this;
      withBusy(btn, function () {
        return api('api/removals/' + encodeURIComponent(r.id) + '/send', { method: 'POST', body: { confirm: true } }).then(function (res) {
          delete state.previewed[key];
          return load({ notify: false }).then(function () {
            var now = res && res.status ? String(res.status) : 'uncertain';
            toast(now === 'submitted'
              ? 'Accepted by SMTP and marked submitted. That is not proof of delivery, and certainly not of removal.'
              : 'The send outcome is uncertain — automatic retry is off. Check your mailbox before touching this request again.',
              now === 'submitted' ? 'good' : 'warn');
          });
        });
      });
    }, 'btn-send');
    sendBtn.disabled = !previewed || !isDraft;
    sendBtn.title = !isDraft ? 'Only a draft can be sent'
      : previewed ? 'Sends this request once through the configured SMTP connection' : 'Open the exact preview first';

    var previewBtn = button('Show exact preview', function () {
      previewHost.textContent = '';
      add(previewHost, el('div', { class: 'preview' },
        kv([
          ['To', str(fTo.input.value) || el('span', { class: 'muted', text: 'not set — the send will be refused until you give one address' })],
          ['Subject', str(r.subject) || el('span', { class: 'muted', text: 'no subject recorded on this draft' })],
          ['Source', sourceName(r.source_id)],
          ['Opt-out page', r.privacy_url ? linkOrText(r.privacy_url, 'the broker’s own opt-out page') : el('span', { class: 'muted', text: 'not recorded' })]
        ]),
        el('p', { class: 'preview-body', text: str(fBody.input.value) || '(empty body — nothing would be sent)' }),
        el('p', { class: 'muted soft', text: 'Preview built ' + fmtDateTime(new Date().toISOString()) + '. Nothing has been sent.' })));
      state.previewed[key] = true;
      sendBtn.disabled = !isDraft;
      sendBtn.title = isDraft ? 'Sends this request once through the configured SMTP connection' : 'Only a draft can be sent';
    }, 'btn-quiet');

    var saveBtn = button('Save changes', function () {
      var vals = readFields([fTo, fBody, fNote, fStatus, fScope]);
      if (!vals) { toast('Fix the highlighted field.', 'warn'); return; }
      if (vals.status !== status && !vals.note) {
        fNote.setError('A status change needs evidence: what you sent, what came back, or what the re-check showed.');
        return;
      }
      if (vals.status === 'verified_removed' && !vals.verification_scope) {
        fScope.setError('Record exactly which listing or search you checked and whether you were signed in.');
        return;
      }
      if (!isDraft) {
        /* sent requests are immutable apart from the note/status */
        delete vals.recipient;
        delete vals.body;
      }
      var btn = this;
      withBusy(btn, function () {
        return write('api/removals/' + encodeURIComponent(r.id), 'PATCH', vals, 'Saved.', null)
          .then(function () { clearDrafts('removal-' + key); delete state.previewed[key]; });
      });
    }, 'btn-quiet');

    return [
      isDraft ? null : el('p', { class: 'muted soft', text: 'A sent request cannot be rewritten — the recipient and body are locked. Record what happened in the note instead.' }),
      el('div', { class: 'field-grid' }, fTo.wrap, fStatus.wrap),
      fBody.wrap,
      fNote.wrap,
      fScope.wrap,
      el('div', { class: 'form-foot' }, saveBtn, previewBtn,
        el('span', { class: 'spacer' }),
        el('span', { class: 'secret-note', text: isDraft ? 'Draft — nothing has been sent' : 'Backend status: ' + humanKey(status) })),
      previewHost,
      el('div', { class: 'form-foot' }, sendBtn,
        el('span', {
          class: 'muted soft',
          text: !isDraft ? 'Sending happens once, from the draft state only.'
            : previewed ? 'Send is enabled because you opened the preview. It asks the broker to remove you; a sent request is never reported as a removal.'
              : 'Send stays disabled until you have looked at the exact text.'
        }))
    ];
  }

  /* ------------------------------------------------------------------- credit */

  function viewCredit() {
    var out = [];
    var agencies = credit();

    var withSnap = agencies.filter(function (a) { return !blank(a.latest_at); }).length;
    out.push(card('Agencies', {
      badge: el('span', { class: 'badge badge-' + (withSnap ? 'info' : 'neutral'), text: withSnap + ' of ' + Math.max(agencies.length, 3) + ' agencies have a snapshot' })
    },
      withSnap ? null : el('p', { class: 'soft muted', text: 'No agency snapshot is stored on this machine yet. An empty credit tab is not “no fraud” — it means nothing has been imported or captured.' }),
      agencies.length
        ? el('div', { class: 'grid grid-two' }, agencies.map(agencyCard))
        : emptyBlock('No credit snapshot imported',
          'Nothing has been imported for Experian, Equifax or TransUnion. An empty credit tab is not “no fraud” — it means this machine has never seen your file. Import a report below, or connect a credit source in browser mode.')));

    var fReport = fieldRow({
      key: 'report', label: 'Canonical report JSON', type: 'textarea', rows: 12, mono: true, json: true, value: state.creditDraft,
      placeholder: '{"agency":"experian","report_date":"2026-09-26","complete":true,"searches":[],"accounts":[],"addresses":[],"public_records":[]}',
      hint: 'All four arrays are required by the contract and complete must be true. A partial file is rejected rather than stored as a snapshot.'
    });

    var importBtn = button('Import report', function () {
      var vals = readFields([fReport]);
      if (!vals) return;
      var problems = checkReport(vals.report);
      if (problems.length) {
        fReport.setError('Not importable: ' + problems.join(' '));
        toast('The report was not sent. The missing parts are listed under the field.', 'warn');
        return;
      }
      var btn = this;
      withBusy(btn, function () {
        state.creditDraft = '';
        return api('api/credit/import', { method: 'POST', body: { report: vals.report } }).then(function (res) {
          var r = isObj(res) ? res : {};
          var message = r.duplicate
            ? 'That exact report is already stored — nothing new was recorded.'
            : r.baseline
              ? 'Baseline snapshot stored. Later imports are compared against it by stable ID.'
              : arr(r.events).length + ' change' + (arr(r.events).length === 1 ? '' : 's') + ' recorded against the previous snapshot.';
          toast(message, r.duplicate ? 'warn' : 'good');
          return load({ notify: false });
        });
      });
    }, 'btn-primary');

    var exampleBtn = button('Load canonical example', function () {
      var btn = this;
      withBusy(btn, function () {
        return api('api/credit/example').then(function (ex) {
          var report = isObj(ex) && isObj(ex.report) ? ex.report : ex;
          fReport.input.value = jsonPretty(report);
          state.creditDraft = fReport.input.value;
          fReport.clearError();
          toast('Synthetic example loaded. It shows the shape only — it is not your data.', 'info');
        });
      });
    }, 'btn-quiet');

    out.push(card('Import a report you already have', {},
      el('p', { class: 'soft muted', text: 'Paste the canonical JSON from your exporter, or the shape you get from the example button. Soft enquiries stay history-only, so importing does not raise an alert because someone looked at your file; unknown enquiry types are flagged for review instead of guessed.' }),
      fReport.wrap,
      el('div', { class: 'form-foot' }, importBtn, exampleBtn)));

    var fileInput = el('input', { class: 'input', type: 'file', id: 'credit-file', accept: '.pdf,.txt,.json,.csv,.html,text/plain,application/json,application/pdf' });
    var extractHost = el('div', { class: 'stack' });

    var extractBtn = button('Extract from file', function () {
      var file = fileInput.files && fileInput.files[0];
      if (!file) { toast('Choose the PDF, text or JSON export you downloaded from the agency.', 'warn'); return; }
      var form = new FormData();
      form.append('file', file, file.name);
      var btn = this;
      withBusy(btn, function () {
        return api('api/credit/extract', { method: 'POST', form: form }).then(function (res) {
          state.creditExtract = isObj(res) ? res : {};
          renderExtract(extractHost, state.creditExtract, fReport);
          if (state.creditExtract.needs_review || !isObj(state.creditExtract.report)) {
            toast('The extractor could not make a clean report from that file. Nothing was stored.', 'warn');
          } else {
            toast('Candidate report extracted. Review it before importing.', 'info');
          }
        });
      });
    }, 'btn-primary');

    out.push(card('Extract from a downloaded file', {},
      el('p', { class: 'soft muted', text: 'Files are read locally. JSON reports can be imported after review; PDF and text reports need conversion into the report format above.' }),
      el('div', { class: 'row' },
        el('label', { class: 'sr-only', for: 'credit-file', text: 'Credit report file' }),
        fileInput, extractBtn),
      extractHost));

    if (state.creditExtract) renderExtract(extractHost, state.creditExtract, fReport);

    return out;
  }

  function renderExtract(host, res, fReport) {
    host.textContent = '';
    var report = res.report;
    var text = str(res.text);

    if (isObj(report) && !res.needs_review) {
      add(host, notice('good', 'Extracted a candidate report',
        ['Check every field before importing — extraction records what the file said, not what is true.']));
    } else {
      add(host, notice('warn', 'Needs reviewed normalisation — this is not a snapshot', [
        str(res.detail) || 'The extractor could not turn this file into a canonical report.',
        'Nothing was stored. Fix the JSON in the editor above, or import your own; it goes through the same validation as everything else.'
      ]));
    }

    if (isObj(report)) {
      add(host, el('div', { class: 'form-foot' },
        button('Put extracted report in the editor', function () {
          fReport.input.value = jsonPretty(report);
          fReport.clearError();
          state.creditDraft = fReport.input.value;
          toast('Loaded into the editor above. Check agency, dates and stable IDs, then import.', 'info');
        }, 'btn-quiet')));
      add(host, el('pre', { class: 'code', text: jsonPretty(report) }));
    }

    if (text) {
      add(host, el('details', { class: 'editor' },
        el('summary', null, 'Raw text the extractor read (' + text.length + ' characters)'),
        el('pre', { class: 'code', text: text })));
    }
  }

  function agencyCard(a) {
    var events = arr(a.events);
    return el('section', { class: 'card card--flat' },
      el('div', { class: 'card-head' },
        el('h3', { text: humanKey(a.agency || 'unknown agency') }),
        blank(a.latest_at) ? el('span', { class: 'badge badge-neutral', text: 'No snapshot' })
          : el('span', { class: 'badge badge-good', text: 'Snapshot ' + fmtDate(a.latest_at) })),
      kv([
        ['Latest', stamp(a.latest_at, 'never imported')],
        ['Snapshots', blank(a.snapshot_count) ? el('span', { class: 'muted', text: 'not reported' }) : el('span', { class: 'num', text: String(a.snapshot_count) })],
        ['Important', blank(a.important_count) ? el('span', { class: 'muted', text: 'not reported' }) : el('span', { class: 'num', text: String(a.important_count) })],
        ['Soft enquiries', blank(a.soft_count) ? el('span', { class: 'muted', text: 'not reported' }) : el('span', { class: 'num', text: String(a.soft_count) })]
      ]),
      el('p', { class: 'muted soft', text: 'Soft enquiry counts are history, not a threat. Hard searches, new accounts and address changes are what the alerts are for.' }),
      events.length
        ? el('div', { class: 'list' }, events.slice(0, 10).map(function (e) {
          return el('div', { class: 'item item--sub' },
            el('div', { class: 'item-lead' }, badge(e.severity, SEVERITY), el('p', { class: 'item-title', text: str(e.title) || humanKey(e.kind) })),
            el('p', { class: 'item-body', text: str(e.detail) }));
        }))
        : el('p', { class: 'muted soft', text: blank(a.latest_at) ? 'No comparison yet — the first import becomes the baseline.' : 'No differences reported against the previous snapshot.' }));
  }

  /* Mirrors the contract shape so the user gets a readable message before a round trip. */
  function checkReport(r) {
    var problems = [];
    if (!isObj(r)) return ['this field must contain one JSON object, not a list or a bare value.'];
    if (['experian', 'equifax', 'transunion'].indexOf(String(r.agency)) < 0) problems.push('agency must be experian, equifax or transunion.');
    if (blank(r.report_date)) problems.push('report_date (YYYY-MM-DD) is missing.');
    else if (isNaN(new Date(r.report_date).getTime())) problems.push('report_date is not a date.');
    if (r.complete !== true) problems.push('complete must be true — a partial report is never stored as a snapshot.');
    ['searches', 'accounts', 'addresses', 'public_records'].forEach(function (k) {
      if (!Array.isArray(r[k])) problems.push(k + ' must be an array (an empty one is fine).');
    });
    arr(r.searches).forEach(function (s, i) {
      if (isObj(s) && !blank(s.type) && ['hard', 'soft', 'unknown'].indexOf(String(s.type)) < 0) {
        problems.push('search ' + (i + 1) + ' type must be hard, soft or unknown.');
      }
    });
    return problems;
  }

  /* ------------------------------------------------------------------ sources */

  function viewSources() {
    var adding = !!state.openEditors.new;
    var out = [card('Add a source', {},
      el('p', { class: 'soft muted', text: 'Use broker discovery to search by name, watch a known page, or open a browser for account access. ' + 'Dark-web exposure is answered only through HIBP stealer-log metadata — this deployment refuses Tor and never browses onion sites. Review search candidates to confirm they belong to you.' }),
      adding ? sourceForm(null) : button('Add a source', function () {
        state.openEditors.new = true;
        render();
      }, 'btn-primary'))];

    out.push(el('div', { class: 'list' }, sources().length ? sources().map(sourceItem)
      : [emptyBlock('No sources connected', 'Nothing is being watched. Add a broker below, or point a credit source at your own report page.')]));

    return out;
  }

  function sourceItem(s) {
    var editing = !!state.openEditors['src' + s.id];
    var mine = findings().filter(function (x) { return String(x.source_id) === String(s.id); });
    var st = SOURCE_STATUS[String(s.status || 'not_checked')] ? String(s.status || 'not_checked') : 'not_checked';

    var enabledBox = el('input', {
      type: 'checkbox', checked: s.enabled !== false,
      onchange: function (e) {
        var box = e.target;
        withBusy(box, function () {
          return write('api/sources/' + encodeURIComponent(s.id), 'PATCH', { enabled: box.checked },
            (str(s.name) || 'Source') + (box.checked ? ' enabled for scheduled checks.' : ' excluded from scheduled checks. You can still run an explicit manual check.'), null);
        });
      }
    });

    return el('div', { class: 'item' },
      el('div', { class: 'item-lead' },
        badge(st, SOURCE_KIND_MAP),
        el('p', { class: 'item-title', text: str(s.name) || String(s.id) }),
        el('span', { class: 'spacer' }),
        s.enabled === false ? el('span', { class: 'badge badge-neutral', text: 'Disabled' }) : null),
      el('div', { class: 'row gap-sm' },
        el('span', { class: 'chip', text: 'kind: ' + humanKey(s.kind || 'unknown') }),
        el('span', { class: 'chip', text: 'mode: ' + humanKey(s.mode || 'unknown') }),
        el('span', { class: 'chip', text: 'region: ' + (str(s.region) || 'not set') })),
      kv([
        ['Last check', stamp(s.last_checked, 'never checked')],
        ['Watch page', s.url ? linkOrText(s.url) : el('span', { class: 'muted', text: 'not set' })],
        ['Privacy policy', s.privacy_url ? linkOrText(s.privacy_url) : el('span', { class: 'muted', text: 'not set' })],
        ['Detail', str(s.detail) || el('span', { class: 'muted', text: 'no detail from the last run' })],
        ['Findings', el('span', { class: 'num', text: st === 'checked' ? String(mine.length) : 'unknown (no completed check)' })]
      ]),
      el('div', { class: 'item-actions' },
        button('Scan this source', function () {
          var btn = this;
          withBusy(btn, function () {
            return api('api/scan', { method: 'POST', body: { source_id: s.id } }).then(function (res) {
              var n = arr(res && res.runs).length;
              return load({ notify: false }).then(function () {
                toast(n ? 'Scan started for ' + (str(s.name) || s.id) + '.'
                  : 'The backend recorded no run for ' + (str(s.name) || s.id) + ' — check its mode and config.', n ? 'good' : 'warn');
              });
            });
          });
        }, 'btn-primary'),
        el('a', { class: 'btn btn-quiet', href: browserUrl(s.id) }, icon('external'), 'Private browser'),
        button(editing ? 'Close editor' : 'Edit', function () {
          var k = 'src' + s.id;
          if (state.openEditors[k]) delete state.openEditors[k];
          else state.openEditors[k] = true;
          render();
        }, 'btn-quiet'),
        el('label', { class: 'check' }, enabledBox, el('span', null, el('span', { class: 'strong', text: 'Enabled' })))),
      editing ? sourceForm(s) : null);
  }

  function sourceForm(s) {
    var isNew = !s;
    /* each editor keeps its own unsaved typing; a shared namespace leaks one card's text into another */
    var formId = 'source-' + (isNew ? 'new' : s.id);
    var cfg = Object.assign({}, DEFAULT_CONFIG, isObj(s && s.config) ? s.config : null);
    var currentKind = s ? String(s.kind || 'broker') : 'broker';

    /* The three UK agency connections ship in the catalogue; the backend refuses a fourth. */
    var kindOptions = isNew
      ? [{ value: 'broker', label: 'broker — a people-search site' },
         { value: 'breach', label: 'breach — Have I Been Pwned lookup' },
         { value: 'darkweb', label: 'darkweb — HIBP stealer-log metadata only' }]
      : [{ value: 'broker', label: 'broker — a people-search site' },
         { value: 'credit', label: 'credit — a UK credit agency connection' },
         { value: 'breach', label: 'breach — Have I Been Pwned lookup' },
         { value: 'darkweb', label: 'darkweb — HIBP stealer-log metadata only' }];

    var fName = fieldRow({ key: 'name', label: 'Display name', value: s && s.name, placeholder: 'Example Data Broker', required: true , form: formId });
    var fKind = fieldRow({ key: 'kind', label: 'Kind', type: 'select', value: currentKind, options: kindOptions , form: formId });
    var fMode = fieldRow({
      key: 'mode', label: 'Mode', type: 'select', value: (s && s.mode) || 'manual', form: formId,
      options: [{ value: 'manual', label: 'manual — you report what you saw' },
                { value: 'discovery', label: 'Search this broker for my name' },
                { value: 'http', label: 'http — the bot fetches the page' },
                { value: 'browser', label: 'browser — private browser you can log into' },
                { value: 'hibp', label: 'hibp — Have I Been Pwned API' },
                { value: 'hibp_stealer', label: 'hibp_stealer — stealer-log metadata only' }]
    });
    var fRegion = fieldRow({ key: 'region', label: 'Region', value: (s && s.region) || 'GB', hint: 'This installation covers the UK.' , form: formId });
    var fUrl = fieldRow({ key: 'url', label: 'Watch URL', value: s && s.url, placeholder: 'https://www.example-broker.com/search?q=…' , form: formId });
    var fPrivacy = fieldRow({ key: 'privacy_url', label: 'Privacy / opt-out URL', value: s && s.privacy_url , form: formId });
    var fConfig = fieldRow({
      key: 'config', label: 'Config JSON', type: 'textarea', rows: 9, mono: true, json: true, value: jsonPretty(cfg), form: formId,
      hint: 'Keys: watch_url, terms (up to 30 short strings), empty_selector, match_selector, report_selector, report_url. A credit browser source returns canonical report JSON in report_selector.'
    });
    var cEnabled = checkbox('enabled', 'Enabled', !s || s.enabled !== false, 'Include this source in scheduled checks.', formId);

    var submit = button(isNew ? 'Add source' : 'Save source', function () {
      var vals = readFields([fName, fKind, fMode, fRegion, fUrl, fPrivacy, fConfig]);
      if (!vals) { toast('Fix the highlighted field — the config block must be valid JSON.', 'warn'); return; }
      if (!vals.name) { fName.setError('Give it a name you will still recognise in a month.'); return; }
      if (vals.kind === 'darkweb' && vals.mode !== 'hibp_stealer') {
        fMode.setError('A darkweb source is answered only by hibp_stealer — this deployment does not browse onion sites.');
        return;
      }
      if (vals.kind === 'credit' && vals.mode !== 'browser') {
        fMode.setError('A credit agency connection is read through the private browser.');
        return;
      }
      if (vals.url && !safeUrl(vals.url)) { fUrl.setError('Use a full http(s) URL, or leave it empty for a manual source.'); return; }
      if (vals.privacy_url && !safeUrl(vals.privacy_url)) { fPrivacy.setError('Use a full http(s) URL, or leave it empty.'); return; }
      if (!isObj(vals.config)) { fConfig.setError('Config has to be a JSON object.'); return; }
      var terms = vals.config.terms === undefined ? [] : vals.config.terms;
      if (!Array.isArray(terms) || terms.length > 30 || terms.some(function (t) { return typeof t !== 'string' || t.length > 300; })) {
        fConfig.setError('terms must be an array of up to 30 short strings.');
        return;
      }

      var payload = {
        name: vals.name, kind: vals.kind, region: vals.region || 'GB', url: vals.url,
        privacy_url: vals.privacy_url, mode: vals.mode, config: vals.config, enabled: cEnabled.input.checked
      };
      var btn = this;
      withBusy(btn, function () {
        if (isNew) {
          return write('api/sources', 'POST', payload, 'Source added. Run a check when you are ready.', null)
            .then(function () { delete state.openEditors.new; clearDrafts(formId); });
        }
        return write('api/sources/' + encodeURIComponent(s.id), 'PATCH', payload, 'Source saved.', null)
          .then(function () { delete state.openEditors['src' + s.id]; clearDrafts(formId); });
      });
    }, 'btn-primary');

    var cancel = isNew ? null : button('Cancel', function () {
      delete state.openEditors['src' + s.id];
      render();
    }, 'btn-ghost');

    return el('form', {
      class: 'card card--flat',
      onsubmit: function (e) { e.preventDefault(); submit.click(); }
    },
      el('h3', { text: isNew ? 'New source' : 'Edit ' + (str(s.name) || String(s.id)) }),
      isNew ? el('p', { class: 'soft muted', text: 'The broker, breach and agency connections shipped with this deployment are already listed below — add one only if you are pointing at a page that is not in that list. URLs are checked so a source cannot aim this machine at your own network.' }) : null,
      el('div', { class: 'field-grid' }, fKind.wrap, fMode.wrap, fName.wrap, fRegion.wrap),
      fUrl.wrap, fPrivacy.wrap, fConfig.wrap, cEnabled.wrap,
      el('div', { class: 'form-foot' }, submit, cancel,
        el('span', { class: 'spacer' }),
        el('span', { class: 'secret-note', text: 'Writes send X-Privacy-Bot: 1 · the contract exposes no delete route' })));
  }

  function browserUrl(sourceId) {
    return API_BASE + 'browser.html' + (blank(sourceId) ? '' : '?source=' + encodeURIComponent(sourceId));
  }

  /* ---------------------------------------------------------------- research */

  function viewResearch() {
    var list = research();
    return [
      notice('info', 'What this list is',
        'Reference material shipped with the deployment. Privacy Bot has not checked any of it against your own exposures, and a broker listed somewhere is not evidence that it holds data about you.'),
      card('Reference list', { badge: el('span', { class: 'badge badge-neutral', text: list.length + ' entries' }) },
        list.length
          ? el('div', { class: 'list' }, list.map(function (r) {
            return el('div', { class: 'item' },
              el('div', { class: 'item-lead' },
                el('p', { class: 'item-title', text: str(r.name) || 'Untitled entry' }),
                blank(r.license) ? null : el('span', { class: 'chip', text: 'licence: ' + str(r.license) })),
              blank(r.description) ? null : el('p', { class: 'item-body', text: str(r.description) }),
              el('p', { class: 'item-meta' }, linkOrText(r.url)));
          }))
          : emptyBlock('No research entries', 'The catalogue shipped with this deployment is empty. Use the private browser to look a broker up yourself.')),
      card('Do it by hand', {},
        el('p', { class: 'soft muted', text: 'The private browser keeps its profile on this machine, so a login you do there does not pass through any third-party service. Use it for the sites that refuse a headless check, and for handling a login, OTP or CAPTCHA yourself.' }),
        el('div', { class: 'row' },
          el('a', { class: 'btn btn-primary', href: browserUrl('') }, icon('external'), 'Open private browser'),
          sources().length ? el('span', { class: 'muted soft', text: 'Pick a source inside it to run that source’s extraction.' }) : null))
    ];
  }

  /* -------------------------------------------------------- identity/settings */

  function viewIdentity() {
    return [profileCard(), monitorCard(), connectionsCard(), dataCard()];
  }

  function profileCard() {
    var p = profile();
    var fName = fieldRow({ key: 'name', label: 'Full name', value: p.name, autocomplete: 'name', form: 'profile' });
    var fEmail = fieldRow({ key: 'email', label: 'Email', type: 'email', value: p.email, autocomplete: 'email', form: 'profile' });
    var fPhone = fieldRow({ key: 'phone', label: 'Phone', type: 'tel', value: p.phone, autocomplete: 'tel', form: 'profile' });
    var fCountry = fieldRow({ key: 'country', label: 'Country', value: 'GB', hint: 'UK credit coverage: Experian, Equifax and TransUnion.' });
    fCountry.input.readOnly = true;
    var fAddr = fieldRow({
      key: 'addresses', label: 'Addresses (one per line)', type: 'textarea', rows: 4, value: joinLines(p.addresses), form: 'profile',
      hint: 'Add a previous address only where a broker asks for it; each line becomes a separate match target.'
    });
    var fAlias = fieldRow({
      key: 'aliases', label: 'Other names used (one per line)', type: 'textarea', rows: 3, value: joinLines(p.aliases), form: 'profile',
      hint: 'Maiden names, spelling variants, initials. Used for matching only.'
    });

    return card('Identity used for matching', {
      badge: p.name ? el('span', { class: 'badge badge-good', text: 'Profile set' }) : el('span', { class: 'badge badge-warn', text: 'Not filled in' })
    },
      el('p', { class: 'soft muted', text: 'A removal request carries only what you type here. Leave a field empty and it is simply not sent — there is no hidden profile behind it.' }),
      el('div', { class: 'field-grid' }, fName.wrap, fEmail.wrap, fPhone.wrap, fCountry.wrap),
      fAddr.wrap, fAlias.wrap,
      el('div', { class: 'form-foot' },
        button('Save profile', function () {
          var vals = readFields([fName, fEmail, fPhone, fCountry]);
          if (!vals) return;
          var payload = {
            name: vals.name, email: vals.email, phone: vals.phone,
            country: (vals.country || 'GB').toUpperCase(),
            addresses: splitLines(fAddr.input.value), aliases: splitLines(fAlias.input.value)
          };
          var btn = this;
          withBusy(btn, function () {
            return write('api/profile', 'PUT', payload, 'Profile saved.', null).then(function () { clearDrafts('profile'); });
          });
        }, 'btn-primary'),
        el('span', {
          class: 'muted soft',
          text: state.lastLoadedAt ? 'Shown as read at ' + fmtDateTime(state.lastLoadedAt) : 'Not loaded yet'
        })));
  }

  function monitorCard() {
    var s = settings();
    var fInterval = fieldRow({ key: 'interval_hours', label: 'Check every (hours)', type: 'number', value: s.interval_hours, inputmode: 'numeric', hint: 'Applies to sources that are enabled.', form: 'monitor' });
    var cEnabled = checkbox('enabled', 'Run checks on the schedule', s.enabled, 'Off means nothing runs unless you press Run scan.', 'monitor');
    var cSoft = checkbox('notify_soft', 'Notify me about soft credit enquiries too', s.notify_soft,
      'Off by design: soft enquiries are history. Hard searches, new accounts and address changes alert regardless.', 'monitor');

    return card('Monitoring and notifications', {},
      el('div', { class: 'field-grid' }, fInterval.wrap),
      cEnabled.wrap, cSoft.wrap,
      el('div', { class: 'form-foot' },
        button('Save monitoring settings', function () {
          var hours = Number(fInterval.input.value);
          if (!isFinite(hours) || hours < 1 || hours > 720) { fInterval.setError('Give a whole number of hours between 1 and 720 (30 days).'); return; }
          var payload = { interval_hours: Math.round(hours), enabled: cEnabled.input.checked, notify_soft: cSoft.input.checked };
          var btn = this;
          withBusy(btn, function () {
            return write('api/settings', 'PUT', payload, 'Settings saved.', null).then(function () { clearDrafts('monitor'); });
          });
        }, 'btn-primary'),
        el('span', { class: 'secret-note', text: 'Now: ' + scheduleText() })));
  }

  function connectionsCard() {
    var c = state.connections || {};
    var ns = state.data && isObj(state.data.notification_status) ? state.data.notification_status : null;

    function pill(label, configured) {
      return el('span', { class: 'badge badge-' + (configured ? 'good' : 'neutral') },
        el('span', { class: 'badge-dot', 'aria-hidden': 'true' }),
        label + ': ' + (configured ? 'configured' : 'not configured'));
    }

    var fHibp = fieldRow({ key: 'hibp_api_key', label: 'HIBP API key', type: 'password', secret: true, form: 'connections', hint: 'Used for breach and stealer-log lookups. Blank keeps what is already stored.' });
    var fHost = fieldRow({ key: 'smtp_host', label: 'SMTP host', placeholder: 'smtp.example.co.uk' });
    var fPort = fieldRow({
      key: 'smtp_port', label: 'SMTP port', type: 'select',
      options: [{ value: '', label: 'Leave unset / keep stored' },
                { value: '587', label: '587 — STARTTLS' }, { value: '465', label: '465 — implicit TLS' }],
      hint: 'Use TLS on port 587 or 465.'
    });
    var fUser = fieldRow({ key: 'smtp_user', label: 'SMTP username', autocomplete: 'username', hint: 'Leave blank to use an unauthenticated relay or keep the stored login.' });
    var fPass = fieldRow({ key: 'smtp_password', label: 'SMTP password', type: 'password', secret: true, form: 'connections', hint: 'Blank means “do not change the stored secret”.' });
    var fFrom = fieldRow({ key: 'smtp_from', label: 'From address', type: 'email', placeholder: 'privacy-bot@example.com' });
    var fNotify = fieldRow({ key: 'notification_url', label: 'Notification endpoint (HTTPS)', placeholder: 'https://…', hint: 'Where important alerts are pushed. Blank keeps the stored value.' });

    var writeOnly = [fHibp, fPass, fHost, fPort, fUser, fFrom, fNotify];

    return card('Connections', {
      badge: el('div', { class: 'row gap-sm' },
        pill('Send (SMTP)', !!c.smtp), pill('HIBP', !!c.hibp), pill('Notifications', !!c.notifications),
        el('span', { class: 'badge badge-neutral' }, el('span', { class: 'badge-dot', 'aria-hidden': 'true' }), 'Direct dark web: off by design'))
    },
      el('p', { class: 'soft muted', text: 'The API reports only whether each connection is configured, never the secret itself. These boxes are write-only: after a save they are cleared and no stored value comes back.' }),
      state.connectionsError ? notice('bad', 'Connections could not be read', state.connectionsError) : null,
      c.detail ? el('p', { class: 'soft muted', text: str(c.detail) }) : null,
      fHibp.wrap,
      el('fieldset', { class: 'group' },
        el('legend', null, 'Send (SMTP) — used for removal requests'),
        el('div', { class: 'field-grid' }, fHost.wrap, fPort.wrap, fUser.wrap, fFrom.wrap),
        fPass.wrap),
      fNotify.wrap,
      ns ? el('p', { class: 'muted soft', text: 'Last notification attempt: ' + humanKey(ns.status || 'not_configured') + (ns.at ? ' at ' + fmtDateTime(ns.at) : '') + (ns.detail ? ' — ' + str(ns.detail) : '') }) : null,
      el('div', { class: 'form-foot' },
        button('Save connections', function () {
          var vals = readFields(writeOnly);
          if (!vals) return;
          var payload = {};
          Object.keys(vals).forEach(function (k) { if (!blank(vals[k])) payload[k] = vals[k]; });
          if (!Object.keys(payload).length) {
            toast('Nothing to save — every box is empty, and an empty box means “keep what is stored”.', 'warn');
            return;
          }
          var btn = this;
          withBusy(btn, function () {
            return api('api/connections', { method: 'PUT', body: payload }).then(function (res) {
              if (isObj(res)) state.connections = res;
              writeOnly.forEach(function (f) { f.input.value = ''; f.clearError(); });
              clearDrafts('connections');
              toast('Connections saved. The page cannot read secret values back, so the boxes are empty again.', 'good');
              return load({ notify: false });
            });
          });
        }, 'btn-primary'),
        el('span', { class: 'secret-note', text: 'Stored encrypted · never returned by the API' })));
  }

  function dataCard() {
    var p = profile();
    var c = coverage();
    var held = [
      p.name ? 'name' : '', p.email ? 'email' : '', p.phone ? 'phone' : '',
      arr(p.addresses).length ? arr(p.addresses).length + ' addresses' : '',
      arr(p.aliases).length ? arr(p.aliases).length + ' aliases' : ''
    ].filter(Boolean).join(', ');

    return card('What this deployment holds', {},
      kv([
        ['Identity fields', held || el('span', { class: 'muted', text: 'none set' })],
        ['Sources', String(c.total) + ' connected, ' + c.enabled + ' enabled'],
        ['Coverage', coverageSummary()],
        ['Kept by this page', 'Nothing but your theme choice — no analytics, no external requests, no personal data in local storage.']
      ]),
      el('div', { class: 'form-foot' },
        el('a', { class: 'btn btn-quiet', href: browserUrl('') }, icon('external'), 'Private browser'),
        button('Re-read everything', function () {
          var btn = this;
          withBusy(btn, function () { return load({ notify: true }); });
        }, 'btn-quiet')));
  }

  /* --------------------------------------------------------------------- boot */

  function boot() {
    paintIcons(document);
    initRouter();
    initTheme();
    initTopbar();
    initLogin();
    render();

    api('api/session').then(function (res) {
      state.accessMode = res && res.access_mode || 'token';
      var authed = isObj(res) ? (res.authenticated !== undefined ? !!res.authenticated : !!res.ok) : false;
      if (authed) {
        state.authed = true;
        $('#btn-signout').hidden = state.accessMode === 'network';
        return load({ reason: 'startup' });
      }
      showLogin();
    }).catch(function (err) {
      if (err.status === 401) return; /* showLogin already ran inside api() */
      state.offline = true;
      state.loadError = errorMessage(err);
      state.loadStatus = err.status;
      render();
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
