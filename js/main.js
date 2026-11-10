// Interfaz de la herramienta. La lógica está en parseo.js, osv.js, agregar.js y cvss.js (con pruebas).
import { parsear, detectarFormato } from './parseo.js';
import { consultarLote, obtenerDetalles } from './osv.js';
import { agregar } from './agregar.js';
import { NOMBRE_NIVEL } from './cvss.js';
import { anilloSalud, barrasSeveridad, apilada, esc, num } from './graficas.js';
import { EJEMPLO, NOMBRE_EJEMPLO } from './ejemplo.js';
import { iniciarTema } from './tema.js';

const $ = (id) => document.getElementById(id);
const FORMATO = { requirements: 'requirements.txt', 'package.json': 'package.json', 'package-lock': 'package-lock.json', vacio: 'vacío', 'json-invalido': 'JSON inválido', 'json-desconocido': 'JSON sin dependencias' };
const MAX_BYTES = 15 * 1024 * 1024;
const params = new URLSearchParams(location.search);
const FORZAR_RESPALDO = params.has('sin-conexion');

let control = null;
let nombreArchivo = NOMBRE_EJEMPLO;
let respaldo = null;

const urlSegura = (u) => (typeof u === 'string' && /^https?:\/\//i.test(u) ? u : null);
const fechaLarga = (iso) => new Date(iso).toLocaleDateString('es-CO', { day: 'numeric', month: 'long', year: 'numeric' });
const hora = (d) => d.toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' });
const plural = (n, uno, varios) => `${num(n)} ${n === 1 ? uno : varios}`;

// ---------------------------------------------------------------- estados

function marcarEjemplo(es) {
  $('zona').classList.toggle('es-ejemplo', es);
  $('chip-ejemplo').hidden = !es;
}

function mostrarFormato() {
  const f = detectarFormato($('texto').value, nombreArchivo);
  $('chip-formato').textContent = FORMATO[f] || f;
}

function estadoCargando(texto) {
  $('hud').setAttribute('aria-busy', 'true');
  $('estado').innerHTML = `<span class="chip chip-carga">Consultando</span><span>${esc(texto)}</span>`;
  $('veredicto').textContent = 'Consultando…';
  $('explica').textContent = 'Pidiendo a OSV.dev las vulnerabilidades conocidas de cada versión.';
  $('progreso').hidden = false;
  $('progreso').firstElementChild.style.width = '4%';
  $('analizar').disabled = true;
}

function progreso(hechos, total) {
  $('progreso').firstElementChild.style.width = `${Math.round(5 + (95 * hechos) / Math.max(1, total))}%`;
  $('estado').innerHTML = `<span class="chip chip-carga">Consultando</span><span>Detalles ${num(hechos)} de ${num(total)}</span>`;
}

function terminarCarga() {
  $('hud').setAttribute('aria-busy', 'false');
  $('progreso').hidden = true;
  $('analizar').disabled = false;
}

function vaciarResultados() {
  $('anillo').innerHTML = anilloSalud(null, '?');
  $('barras').innerHTML = barrasSeveridad({});
  for (const id of ['m-deps', 'm-vuln', 'm-hall', 'm-sinv']) $(id).textContent = '–';
  $('lista').innerHTML = '';
  $('desglose').innerHTML = '';
  $('formula').textContent = 'salud = 100 − Σ descuentos';
  $('otras').innerHTML = '';
  $('combo').hidden = true;
}

function mostrarError(mensaje, { puedeRespaldo = true } = {}) {
  terminarCarga();
  vaciarResultados();
  $('veredicto').innerHTML = '<em>No se pudo</em>';
  $('explica').textContent = mensaje;
  $('estado').innerHTML = '<span class="chip chip-error">Error</span>'
    + (puedeRespaldo ? '<button type="button" class="boton-linea mini" id="ver-respaldo">Ver el ejemplo sin conexión</button>' : '');
  const b = $('ver-respaldo');
  if (b) b.addEventListener('click', () => { cargarEjemplo(); analizar({ forzarRespaldo: true }); });
}

// ---------------------------------------------------------------- pintar

function fichaVuln(v) {
  const s = v.severidad;
  const etiqueta = s.puntuacion !== null ? `${NOMBRE_NIVEL[s.nivel]} ${num(s.puntuacion, 1)}` : NOMBRE_NIVEL[s.nivel];
  const fuente = urlSegura(v.fuente);
  const cves = v.cves.length ? ` · ${v.cves.map(esc).join(', ')}` : '';
  const corrige = v.corrige ? `corrige en <b>${esc(v.corrige)}</b>` : (v.sinCorreccion ? '<b>sin versión corregida publicada</b>' : 'corrección no indicada');
  return `<li class="vuln">
    <span class="sev sev-${s.nivel}" title="Severidad: ${esc(s.fuente)}">${esc(etiqueta)}</span>
    <div>
      <a class="vuln-id" href="${esc(v.enlace)}" target="_blank" rel="noopener">${esc(v.id)}</a><span class="vuln-meta">${cves}</span>
      <p class="vuln-res">${esc(v.resumen)}</p>
      <p class="vuln-meta">${corrige}${fuente ? ` · <a href="${esc(fuente)}" target="_blank" rel="noopener">fuente</a>` : ''}${v.publicada ? ` · publicada ${esc(v.publicada.slice(0, 10))}` : ''}</p>
    </div>
  </li>`;
}

function tarjeta(d) {
  const visibles = d.vulns.slice(0, 3).map(fichaVuln).join('');
  const resto = d.vulns.slice(3);
  const nivel = d.peor.nivel;
  let arreglo;
  if (d.corregirA) arreglo = `Para cerrar todas: actualiza a <code>${esc(d.corregirA)}</code> o superior.`;
  else arreglo = 'No hay una versión corregida publicada para estas vulnerabilidades: considera reemplazar el paquete.';
  const notas = [];
  if (d.sinCorreccion && d.corregirA) notas.push(`${plural(d.sinCorreccion, 'vulnerabilidad no tiene', 'vulnerabilidades no tienen')} versión corregida.`);
  if (d.aproximada) notas.push(`Rango «${esc(d.declarada)}»: se consultó la versión mínima (${esc(d.version)}), es el peor caso. Con un lockfile sabrías la exacta.`);
  if (d.grupo && !['requirements', 'lockfile'].includes(d.grupo)) notas.push(`Grupo: ${esc(d.grupo)}.`);
  return `<li class="dep" data-nivel="${nivel}">
    <div class="dep-cabeza">
      <span class="sev sev-${nivel}">${NOMBRE_NIVEL[nivel]}</span>
      <h3>${esc(d.nombre)}<span class="ver">${esc(d.version)}${d.aproximada ? ' (mín.)' : ''}</span></h3>
      <span class="dep-n">${d.vulns.length}<small>${d.vulns.length === 1 ? 'vulnerab.' : 'vulnerabs.'}</small></span>
    </div>
    <div class="dep-cuerpo">
      ${apilada(d.vulns)}
      <p class="arreglo">${arreglo}</p>
      ${notas.length ? `<p class="nota-dep">${notas.join(' ')}</p>` : ''}
      <ul class="vulns">${visibles}</ul>
      ${resto.length ? `<details class="mas"><summary>Ver ${plural(resto.length, 'más', 'más')}</summary><ul class="vulns">${resto.map(fichaVuln).join('')}</ul></details>` : ''}
    </div>
  </li>`;
}

function pintar(res, parseo, meta) {
  terminarCarga();
  const { salud, conteo } = res;
  $('anillo').innerHTML = anilloSalud(salud.puntos, salud.rango.letra);
  $('barras').innerHTML = barrasSeveridad(conteo);
  $('m-deps').textContent = num(res.porDependencia.length + res.sinVersion.length);
  $('m-vuln').textContent = num(res.vulnerables.length);
  $('m-hall').textContent = num(res.totalHallazgos);
  $('m-sinv').textContent = num(res.sinVersion.length);

  const peor = res.vulnerables[0]?.vulns[0];
  if (!res.totalHallazgos) {
    $('veredicto').innerHTML = `<span class="bien">No</span>, ninguna conocida · rango ${esc(salud.rango.letra)}`;
    $('explica').textContent = res.porDependencia.length
      ? `OSV.dev no tiene vulnerabilidades registradas para ${plural(res.porDependencia.length, 'versión consultada', 'versiones consultadas')}.${res.sinVersion.length ? ` ${plural(res.sinVersion.length, 'dependencia no tiene', 'dependencias no tienen')} versión fija y no se pudo verificar.` : ''}`
      : 'Ninguna dependencia tiene versión: no hay nada que consultar. Fija las versiones (==, o un lockfile).';
  } else {
    const d0 = res.vulnerables[0];
    $('veredicto').innerHTML = `<em>Sí</em>: ${plural(res.totalHallazgos, 'vulnerabilidad', 'vulnerabilidades')} en ${plural(res.vulnerables.length, 'paquete', 'paquetes')} · salud ${salud.puntos}/100, rango ${esc(salud.rango.letra)} «${esc(salud.rango.texto)}»`;
    const p = peor.severidad.puntuacion !== null ? `, CVSS ${num(peor.severidad.puntuacion, 1)}` : '';
    $('explica').innerHTML = `La más grave: <b>${esc(peor.cves[0] || peor.id)}</b> en ${esc(d0.nombre)} ${esc(d0.version)} (${NOMBRE_NIVEL[peor.severidad.nivel].toLowerCase()}${p}). ${peor.corrige ? `Se corrige en ${esc(peor.corrige)}.` : ''}`;
  }
  const combo = $('combo');
  if (!res.totalHallazgos && res.porDependencia.length) { combo.textContent = '¡Logro! Sin vulnerabilidades'; combo.hidden = false; }
  else if (conteo.critica) { combo.textContent = `Combo ×${conteo.critica} ${conteo.critica === 1 ? "crítica" : "críticas"}`; combo.hidden = false; }
  else combo.hidden = true;

  if (meta.modo === 'vivo') {
    const extra = meta.fallidos?.length ? ` · ${plural(meta.fallidos.length, 'detalle no llegó', 'detalles no llegaron')} (quedan «sin clasificar»)` : '';
    $('estado').innerHTML = `<span class="chip chip-vivo">En vivo · OSV.dev</span><span>${hora(new Date())} · ${plural(res.idsCrudos, 'registro', 'registros')}${extra}</span>`;
  } else {
    $('estado').innerHTML = `<span class="chip chip-error">Sin conexión: datos de ejemplo del ${esc(fechaLarga(meta.fecha))}</span><span class="motivo">${esc(meta.motivo)}</span>`;
  }

  $('lista').innerHTML = res.vulnerables.length
    ? res.vulnerables.map(tarjeta).join('')
    : `<li class="limpio"><strong>Nivel superado</strong>Ninguna versión consultada tiene vulnerabilidades conocidas en OSV.dev hoy. Vuelve a revisar de vez en cuando: cada semana se publican avisos nuevos.</li>`;

  // Desglose de la salud
  const n = res.porDependencia.length + res.sinVersion.length;
  const ds = salud.desglose;
  $('formula').textContent = n
    ? `${n} dependencias → ${num(salud.porDep, 1)} pts cada una · ${ds.length ? `100 − (${ds.map((x) => num(x.descuento, 1)).join(' + ')})` : '100 − 0'} = ${salud.puntos}`
    : 'Sin dependencias.';
  const motivo = (m) => (m === 'sinVersion' ? 'sin versión fija' : `peor: ${NOMBRE_NIVEL[m].toLowerCase()}`);
  $('desglose').innerHTML = ds.length
    ? ds.map((x) => `<li><span>${esc(x.nombre)}${x.version ? ` ${esc(x.version)}` : ''} · ${motivo(x.motivo)}</span><b>−${num(x.descuento, 1)}</b></li>`).join('')
    : '<li><span>Nada que descontar.</span><b>−0</b></li>';

  // Sin hallazgos / sin verificar / ignoradas
  const filas = [
    ...res.limpias.map((d) => `<tr><td>${esc(d.nombre)}</td><td><code>${esc(d.version)}</code></td><td>Sin vulnerabilidades conocidas${d.aproximada ? ' (versión mínima del rango)' : ''}</td></tr>`),
    ...res.sinVersion.map((d) => `<tr><td>${esc(d.nombre)}</td><td><code>${esc(d.declarada)}</code></td><td>Sin versión fija: no se puede verificar. Criterio A.8.19 «dependencias con versión fija».</td></tr>`),
    ...parseo.ignoradas.slice(0, 20).map((g) => `<tr><td>${esc(g.texto)}</td><td>${g.linea ? `línea ${g.linea}` : ''}</td><td>Ignorada: ${esc(g.motivo)}</td></tr>`),
  ];
  $('otras').innerHTML = filas.length
    ? `<table class="tabla-mini"><thead><tr><th>Paquete</th><th>Versión</th><th>Estado</th></tr></thead><tbody>${filas.join('')}</tbody></table>${parseo.ignoradas.length > 20 ? `<p class="chiquita">…y ${parseo.ignoradas.length - 20} líneas ignoradas más.</p>` : ''}`
    : '<p class="vacio">Todas las dependencias tienen hallazgos.</p>';
}

// ---------------------------------------------------------------- flujo

async function cargarRespaldo() {
  if (respaldo) return respaldo;
  const r = await fetch(new URL('../datos/osv-respaldo.json', import.meta.url));
  if (!r.ok) throw new Error('No se pudo leer el respaldo local.');
  respaldo = await r.json();
  return respaldo;
}

async function analizar({ forzarRespaldo = false } = {}) {
  control?.abort();
  control = new AbortController();
  const señal = control.signal;
  const texto = $('texto').value;
  const esEjemplo = texto === EJEMPLO;
  let parseo;
  try {
    parseo = parsear(texto, nombreArchivo);
  } catch (e) {
    mostrarError(e.message, { puedeRespaldo: false });
    return;
  }
  const consultadas = parseo.deps.filter((d) => d.version);
  const sinVersion = parseo.deps.filter((d) => !d.version);
  estadoCargando(`${plural(consultadas.length, 'paquete', 'paquetes')} de ${FORMATO[parseo.formato]}`);

  const usarRespaldo = async (motivo) => {
    const r = await cargarRespaldo();
    const res = agregar(consultadas, r.resultados, r.detalles, sinVersion);
    pintar(res, parseo, { modo: 'respaldo', fecha: r.fecha, motivo });
  };

  try {
    if (esEjemplo && (forzarRespaldo || FORZAR_RESPALDO)) {
      await usarRespaldo(forzarRespaldo ? 'Mostrando la respuesta guardada de OSV.dev.' : 'Modo sin conexión forzado (?sin-conexion).');
      return;
    }
    const resultados = consultadas.length ? await consultarLote(consultadas, { señal }) : [];
    const ids = resultados.flatMap((r) => r.vulns.map((v) => v.id));
    progreso(0, ids.length);
    const { detalles, fallidos } = await obtenerDetalles(ids, { señal, alAvanzar: progreso });
    if (ids.length && fallidos.length === new Set(ids).size) {
      const e = new Error('OSV.dev respondió la consulta, pero no entregó ningún detalle: puede que se haya cortado la conexión.');
      e.tipo = 'red';
      throw e;
    }
    pintar(agregar(consultadas, resultados, detalles, sinVersion), parseo, { modo: 'vivo', fallidos });
  } catch (e) {
    if (e?.name === 'AbortError') return;
    if (esEjemplo) {
      try { await usarRespaldo(`${e.message} Se muestra la respuesta guardada.`); } catch { mostrarError(e.message, { puedeRespaldo: false }); }
    } else {
      mostrarError(`${e.message} Tu archivo sigue aquí: vuelve a intentarlo cuando haya conexión.`);
    }
  }
}

function cargarEjemplo() {
  $('texto').value = EJEMPLO;
  nombreArchivo = NOMBRE_EJEMPLO;
  marcarEjemplo(true);
  mostrarFormato();
}

async function leerArchivo(archivo) {
  if (!archivo) return;
  if (archivo.size > MAX_BYTES) {
    mostrarError(`El archivo pesa ${num(archivo.size / 1048576, 1)} MB; el máximo es 15 MB.`, { puedeRespaldo: false });
    return;
  }
  const texto = await archivo.text(); // se lee en el navegador; no se sube a ningún lado
  $('texto').value = texto;
  nombreArchivo = archivo.name;
  marcarEjemplo(texto === EJEMPLO);
  mostrarFormato();
  analizar();
}

// ---------------------------------------------------------------- arranque

function iniciar() {
  iniciarTema($('tema'));
  vaciarResultados();
  cargarEjemplo();

  $('analizar').addEventListener('click', () => analizar());
  $('ejemplo').addEventListener('click', () => { cargarEjemplo(); analizar(); });
  $('limpiar').addEventListener('click', () => {
    control?.abort();
    $('texto').value = '';
    nombreArchivo = '';
    marcarEjemplo(false);
    mostrarFormato();
    terminarCarga();
    vaciarResultados();
    $('veredicto').textContent = 'Esperando archivo';
    $('explica').textContent = 'Pega o arrastra un requirements.txt, package.json o package-lock.json y pulsa Analizar.';
    $('estado').innerHTML = '<span class="chip chip-carga">En espera</span>';
    $('texto').focus();
  });
  let t;
  $('texto').addEventListener('input', () => {
    marcarEjemplo($('texto').value === EJEMPLO);
    if ($('texto').value !== EJEMPLO && nombreArchivo === NOMBRE_EJEMPLO) nombreArchivo = '';
    clearTimeout(t);
    t = setTimeout(mostrarFormato, 200);
  });
  $('texto').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); analizar(); }
  });
  $('archivo').addEventListener('change', (e) => { leerArchivo(e.target.files[0]); e.target.value = ''; });

  const zona = $('zona');
  let profundidad = 0;
  zona.addEventListener('dragenter', (e) => { e.preventDefault(); profundidad++; zona.classList.add('arrastrando'); });
  zona.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
  zona.addEventListener('dragleave', () => { if (--profundidad <= 0) { profundidad = 0; zona.classList.remove('arrastrando'); } });
  zona.addEventListener('drop', (e) => {
    e.preventDefault();
    profundidad = 0;
    zona.classList.remove('arrastrando');
    leerArchivo(e.dataTransfer.files[0]);
  });
  // Soltar fuera de la zona no debe abrir el archivo en la pestaña.
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  analizar();
}

iniciar();
