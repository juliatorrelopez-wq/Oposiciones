/* Acceso con contraseña. El contenido viaja cifrado (AES-256-GCM, clave PBKDF2-SHA256) en contenido.enc.js.
   "Recordarme" guarda la clave derivada (nunca la contraseña) en localStorage.
   Si falta DecompressionStream (iOS anterior a 16.4) se avisa de actualizar. */
(function () {
  'use strict';
  var CLAVE_LS = 'opos-acceso-clave-v1';
  var C = window.OPOS_CIFRADO;
  var $ = function (s) { return document.querySelector(s); };
  function b64(s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  function a64(buf) { var u = new Uint8Array(buf), s = ''; for (var i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(s); }
  function msg(t, mal) { var m = $('#accMsg'); m.textContent = t; m.className = 'acc-msg' + (mal ? ' mal' : ''); }
  function ocupado(si) { var b = $('#accEntrar'); b.disabled = si; b.textContent = si ? 'Abriendo…' : 'Entrar'; $('#accPass').disabled = si; }

  function soporte() { return !!(window.crypto && crypto.subtle && window.DecompressionStream && C); }

  function derivar(pass) {
    var enc = new TextEncoder().encode(pass);
    return crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(C.salt), iterations: C.it },
        base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
    });
  }
  function importar(raw) { return crypto.subtle.importKey('raw', b64(raw), { name: 'AES-GCM' }, true, ['decrypt']); }

  function descifrar(clave) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(C.iv) }, clave, b64(C.d)).then(function (plano) {
      var ds = new Blob([plano]).stream().pipeThrough(new DecompressionStream('gzip'));
      return new Response(ds).text();
    });
  }

  function arrancar(texto) {
    var archivos = JSON.parse(texto);
    document.body.classList.add('acc-dentro');
    $('#app').innerHTML = '';
    for (var i = 0; i < archivos.length; i++) {
      var s = document.createElement('script');
      s.textContent = archivos[i][1] + '\n//# sourceURL=' + archivos[i][0];
      document.body.appendChild(s);
    }
    window.ACCESO_MS = Math.round(performance.now() - (window.ACCESO_T0 || 0));
    document.dispatchEvent(new Event('DOMContentLoaded'));
    window.ACCESO_LISTO = true;
  }

  function entrar(clave, recordar) {
    return descifrar(clave).then(function (texto) {
      window.OPOS_CLAVE_ACCESO = clave; // clave derivada (no la contraseña): la usa "Pasar progreso" para cifrar el código
      if (recordar) return crypto.subtle.exportKey('raw', clave).then(function (raw) {
        try { localStorage.setItem(CLAVE_LS, JSON.stringify({ salt: C.salt, k: a64(raw) })); } catch (e) {}
        return texto;
      });
      return texto;
    }).then(arrancar);
  }

  function enviar(ev) {
    ev.preventDefault();
    var pass = $('#accPass').value;
    if (!pass) { msg('Escribe la contraseña.', true); return; }
    window.ACCESO_T0 = performance.now();
    ocupado(true); msg('Comprobando la contraseña…');
    derivar(pass).then(function (clave) {
      return entrar(clave, $('#accRecordar').checked).catch(function (e) {
        if (e && e.name === 'OperationError') throw e;
        console.error(e); msg('No se pudo abrir el contenido en este navegador.', true); ocupado(false); throw null;
      });
    }).catch(function (e) {
      if (e === null) return;
      ocupado(false); $('#accPass').value = ''; $('#accPass').focus();
      msg('Contraseña incorrecta. Revísala y vuelve a intentarlo.', true);
    });
  }

  function salir() {
    try { localStorage.removeItem(CLAVE_LS); } catch (e) {}
    location.reload();
  }

  document.addEventListener('click', function (ev) {
    if (ev.target && ev.target.id === 'accSalir') { ev.preventDefault(); salir(); }
  });

  /* Versión nueva: GitHub Pages guarda index.html hasta 10 minutos en caché. Se pide version.json sin caché y, si
     el id no coincide con el de esta página, se recarga una sola vez con ?b=<id> (otra URL, así no sale de caché).
     Con la app ya abierta se comprueba al volver a la pestaña y se ofrece actualizar, sin recargar a la fuerza. */
  var BUILD = (document.querySelector('meta[name="opos-build"]') || {}).content || '';
  function versionRemota() {
    if (!/^https?:$/.test(location.protocol)) return Promise.resolve(null);
    return fetch('version.json?t=' + Date.now(), { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) { return j && j.build; }, function () { return null; });
  }
  function limpiarUrl() {
    if (/[?&]b=/.test(location.search)) { try { history.replaceState(null, '', location.pathname + location.hash); } catch (e) {} }
  }
  function recargarA(b) {
    var k = 'opos-recarga-' + b;
    try { if (sessionStorage.getItem(k)) return false; sessionStorage.setItem(k, '1'); } catch (e) { return false; }
    location.replace(location.pathname + '?b=' + encodeURIComponent(b) + location.hash); return true;
  }
  window.OPOS_BUILD = BUILD;
  window.OPOS_VERSION_LISTA = versionRemota().then(function (b) {
    if (b && BUILD && b !== BUILD && !window.ACCESO_LISTO && recargarA(b)) return 'recargando';
    limpiarUrl(); return b;
  });
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState !== 'visible' || !window.ACCESO_LISTO) return;
    versionRemota().then(function (b) {
      if (!b || !BUILD || b === BUILD || document.getElementById('accNueva')) return;
      var d = document.createElement('div'); d.id = 'accNueva'; d.className = 'acc-nueva'; d.setAttribute('role', 'status');
      d.innerHTML = 'Hay una versión nueva de la app. <button type="button" class="btn prim" id="accActualizar">Actualizar</button>';
      document.body.appendChild(d);
      document.getElementById('accActualizar').onclick = function () { try { sessionStorage.setItem('opos-recarga-' + b, '1'); } catch (e) {} location.replace(location.pathname + '?b=' + encodeURIComponent(b) + location.hash); };
    });
  });

  if (!soporte()) {
    msg('Este navegador no permite abrir el contenido cifrado. Usa una versión reciente de Chrome, Edge, Firefox o Safari (en iPhone, iOS 16.4 o posterior).', true);
    ocupado(true); return;
  }
  $('#accForm').addEventListener('submit', enviar);

  var guardada = null;
  try { guardada = JSON.parse(localStorage.getItem(CLAVE_LS) || 'null'); } catch (e) {}
  if (guardada && guardada.k && guardada.salt === C.salt) {
    window.ACCESO_T0 = performance.now();
    ocupado(true); msg('Abriendo con la sesión guardada…');
    Promise.race([window.OPOS_VERSION_LISTA, new Promise(function (r) { setTimeout(r, 2500); })]).then(function (v) { if (v === 'recargando') throw 'recargando'; return importar(guardada.k); }).then(function (clave) { return entrar(clave, false); }).catch(function (e) {
      if (e === 'recargando') return;
      try { localStorage.removeItem(CLAVE_LS); } catch (e) {}
      ocupado(false); msg('La sesión guardada ya no es válida. Escribe la contraseña.', true);
    });
  } else {
    if (guardada) { try { localStorage.removeItem(CLAVE_LS); } catch (e) {} }
    $('#accPass').focus();
  }
})();
