/* Acceso con contraseña. El contenido viaja cifrado (AES-256-GCM, clave PBKDF2-SHA256) en contenido.enc.js.
   "Recordarme" guarda la clave derivada (nunca la contraseña) en localStorage. */
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

  if (!soporte()) {
    msg('Este navegador no permite abrir el contenido cifrado. Usa una versión reciente de Chrome, Edge, Firefox o Safari.', true);
    ocupado(true); return;
  }
  $('#accForm').addEventListener('submit', enviar);

  var guardada = null;
  try { guardada = JSON.parse(localStorage.getItem(CLAVE_LS) || 'null'); } catch (e) {}
  if (guardada && guardada.k && guardada.salt === C.salt) {
    window.ACCESO_T0 = performance.now();
    ocupado(true); msg('Abriendo con la sesión guardada…');
    importar(guardada.k).then(function (clave) { return entrar(clave, false); }).catch(function () {
      try { localStorage.removeItem(CLAVE_LS); } catch (e) {}
      ocupado(false); msg('La sesión guardada ya no es válida. Escribe la contraseña.', true);
    });
  } else {
    if (guardada) { try { localStorage.removeItem(CLAVE_LS); } catch (e) {} }
    $('#accPass').focus();
  }
})();
