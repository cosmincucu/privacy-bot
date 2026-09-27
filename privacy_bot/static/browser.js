/* Privacy Bot private browser.
 * Contract: POST api/browser/{source_id}/start · GET api/browser/{id} ·
 *           POST api/browser/{id}/action {action:click|type|key|scroll|goto|refresh,…} ·
 *           POST api/browser/{id}/close · POST api/browser/{id}/capture
 * Screenshots arrive as {source_id,url,title,width,height,image:<data URI>}.
 * Text reaches the DOM through textContent only. Writes carry X-Privacy-Bot: 1.
 */
'use strict';

(function () {
  var PATH = location.pathname || '/';
  var BASE = /\/$/.test(PATH) ? PATH : PATH.replace(/[^/]*$/, '');
  function apiUrl(path) { return BASE + String(path).replace(/^\//, ''); }

  function $(id) { return document.getElementById(id); }
  var screen = $('screen'), hint = $('hint'), errBox = $('error'), meta = $('meta');

  var session = { sourceId: '', id: '', open: false, width: 1280, height: 900 };
  var busy = false;
  var timer = null;

  function showErr(message) {
    errBox.textContent = message || '';
    errBox.hidden = !message;
  }

  function setMeta(text) { meta.textContent = text; }

  function request(path, method, body) {
    var init = { method: method, headers: { Accept: 'application/json' }, credentials: 'same-origin' };
    if (method !== 'GET') {
      init.headers['X-Privacy-Bot'] = '1';
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body || {});
    }
    return window.fetch(apiUrl(path), init).then(function (res) {
      if (res.status === 401) {
        throw new Error('This page needs a signed-in session. Sign in on the Privacy Bot dashboard first, then reload.');
      }
      return res.text().then(function (text) {
        var data = null;
        if (text) { try { data = JSON.parse(text); } catch (e) { data = { detail: text.slice(0, 300) }; } }
        if (!res.ok) {
          var detail = data && typeof data.detail === 'string' && data.detail ? data.detail
            : (res.status === 404
              ? 'No route for ' + method + ' ' + apiUrl(path) + '. The browser endpoints in docs/CONTRACT.md may not be served behind this prefix yet.'
              : 'The backend answered HTTP ' + res.status + ' for ' + method + ' ' + path + '.');
          throw new Error(detail);
        }
        return data || {};
      });
    }, function () {
      throw new Error('Could not reach ' + apiUrl(path) + '. Is the Privacy Bot service running on this host?');
    });
  }

  function paintShot(data) {
    if (!data) return;
    if (typeof data.image === 'string' && data.image.indexOf('data:image') === 0) {
      screen.src = data.image;
      screen.hidden = false;
      hint.hidden = true;
      session.width = Number(data.width) || session.width;
      session.height = Number(data.height) || session.height;
      var when = new Date().toLocaleString();
      setMeta((data.title ? String(data.title) + ' · ' : '') +
        (data.url ? String(data.url) + ' · ' : '') +
        session.width + '×' + session.height + ' · view refreshed ' + when);
    } else if (data.closed) {
      screen.hidden = true;
      screen.removeAttribute('src');
      hint.hidden = false;
      hint.textContent = 'Session closed. The profile stays on this machine; open it again when you need it.';
      setMeta('Session closed' + (data.url ? ' · last page ' + String(data.url) : ''));
    }
  }

  function run(action, body) {
    if (busy) return Promise.resolve();
    if (!session.id) { showErr('Open a session first.'); return Promise.resolve(); }
    busy = true;
    showErr('');
    return request('api/browser/' + encodeURIComponent(session.id) + '/' + action, 'POST', body || {})
      .then(paintShot)
      .catch(function (err) { showErr(err.message); })
      .then(function () { busy = false; });
  }

  function tick() {
    if (busy || !session.id || !session.open) return;
    busy = true;
    request('api/browser/' + encodeURIComponent(session.id), 'GET')
      .then(paintShot)
      .catch(function (err) { showErr(err.message); })
      .then(function () { busy = false; });
  }

  function setAuto(on) {
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(tick, 5000);
  }

  function populate() {
    return request('api/dashboard', 'GET').then(function (data) {
      var sel = $('source');
      var list = (data && Array.isArray(data.sources)) ? data.sources : [];
      sel.textContent = '';
      if (!list.length) {
        sel.appendChild(option('', 'No sources connected — add one on the dashboard'));
        showErr('No sources exist yet, so there is nothing to open. Add a source on the dashboard first.');
        return;
      }
      list.forEach(function (s) {
        var kind = String(s.kind || 'unknown');
        /* The backend refuses a browser session for the two API-only kinds. */
        var openable = kind !== 'darkweb' && kind !== 'breach';
        var o = option(s.id, (s.name || s.id) + ' · ' + kind + ' · ' + (s.mode || 'unknown') + (openable ? '' : ' · API only, no browser session'));
        o.disabled = !openable;
        sel.appendChild(o);
      });
      var wanted = new URLSearchParams(location.search).get('source');
      if (wanted) {
        for (var i = 0; i < sel.options.length; i++) {
          if (sel.options[i].value === String(wanted)) sel.selectedIndex = i;
        }
      } else {
        /* a browser-mode source is the one that needs a login, so prefer it */
        for (var j = 0; j < list.length; j++) {
          if (String(list[j].mode) === 'browser') { sel.selectedIndex = j; break; }
        }
      }
    }, function (err) {
      showErr(err.message);
    });
  }

  function option(value, label) {
    var o = document.createElement('option');
    o.value = value;
    o.textContent = label;
    return o;
  }

  $('open').addEventListener('click', function () {
    var src = $('source').value;
    if (!src) { showErr('Pick a source to open.'); return; }
    showErr('');
    busy = true;
    request('api/browser/' + encodeURIComponent(src) + '/start', 'POST', {})
      .then(function (data) {
        session.sourceId = src;
        session.id = String(data.session_id || data.id || data.source_id || src);
        session.open = true;
        paintShot(data);
        if (data.url) $('url').value = String(data.url);
        setMeta('Session open (' + session.id + ') — the page is loading.');
        setAuto($('auto').checked);
      })
      .catch(function (err) { showErr(err.message); })
      .then(function () { busy = false; });
  });

  $('close').addEventListener('click', function () {
    if (!session.id) { showErr('There is no session to close.'); return; }
    showErr('');
    busy = true;
    request('api/browser/' + encodeURIComponent(session.id) + '/close', 'POST', {})
      .then(function (data) {
        session.open = false;
        setAuto(false);
        paintShot(data && Object.keys(data).length ? data : { closed: true });
        session.id = '';
      })
      .catch(function (err) { showErr(err.message); })
      .then(function () { busy = false; });
  });

  $('refresh').addEventListener('click', function () { run('action', { action: 'refresh' }); });
  $('go').addEventListener('click', function () {
    var url = $('url').value.trim();
    if (!url) { showErr('Type an address to go to.'); return; }
    run('action', { action: 'goto', url: url });
  });
  $('back').addEventListener('click', function () { run('action', { action: 'key', key: 'Alt+ArrowLeft' }); });
  $('fwd').addEventListener('click', function () { run('action', { action: 'key', key: 'Alt+ArrowRight' }); });

  $('type').addEventListener('click', function () {
    var box = $('typing');
    var text = box.value;
    if (!text) { showErr('Type the text you want to enter in the focused field.'); return; }
    box.value = ''; /* wipe it from this page as soon as it has been handed over */
    run('action', { action: 'type', text: text });
  });
  $('clear-type').addEventListener('click', function () { $('typing').value = ''; });
  $('typing').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); $('type').click(); }
  });

  Array.prototype.forEach.call(document.querySelectorAll('[data-key]'), function (btn) {
    btn.addEventListener('click', function () { run('action', { action: 'key', key: btn.getAttribute('data-key') }); });
  });
  Array.prototype.forEach.call(document.querySelectorAll('[data-scroll]'), function (btn) {
    btn.addEventListener('click', function () { run('action', { action: 'scroll', dy: Number(btn.getAttribute('data-scroll')) }); });
  });

  screen.addEventListener('click', function (e) {
    var rect = screen.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    var x = (e.clientX - rect.left) * (session.width / rect.width);
    var y = (e.clientY - rect.top) * (session.height / rect.height);
    run('action', { action: 'click', x: Math.round(x), y: Math.round(y) });
  });

  $('auto').addEventListener('change', function (e) { setAuto(e.target.checked); });

  window.addEventListener('beforeunload', function () { if (timer) clearInterval(timer); });

  /* Capture runs this source's real extraction: it stores findings and records a run. */
  $('capture').addEventListener('click', function () {
    if (!session.id) { showErr('Open a session first — the extraction reads the page that is on screen.'); return; }
    showErr('');
    busy = true;
    request('api/browser/' + encodeURIComponent(session.id) + '/capture', 'POST', {})
      .then(function (data) {
        var card = $('capture-card');
        var out = $('capture-out');
        var note = $('capture-note');
        card.hidden = false;
        out.textContent = JSON.stringify(data || {}, null, 2);
        var runs = (data && Array.isArray(data.runs)) ? data.runs : [];
        note.textContent = runs.length
          ? 'The extraction ran as a real check on ' + runs[0].status + ' — anything it matched is stored under Exposures, and a run was recorded. No match means no match on this page; it does not mean the broker holds nothing about you.'
          : 'The backend returned no run for this capture, so nothing was stored. Check the source mode and configuration.';
      })
      .catch(function (err) { showErr(err.message); })
      .then(function () { busy = false; });
  });

  populate();
})();
