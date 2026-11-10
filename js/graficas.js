// Gráficas en SVG propio (texto). Funciones puras: datos → cadena SVG/HTML.
import { NIVELES, NOMBRE_NIVEL } from './cvss.js';

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const num = (x, d = 0) => Number(x).toLocaleString('es-CO', { minimumFractionDigits: d, maximumFractionDigits: d });

/** Color del anillo según los puntos (rojo malo → cian bueno). */
export function colorSalud(p) {
  if (p >= 85) return 'var(--ok)';
  if (p >= 70) return 'var(--s-baja)';
  if (p >= 50) return 'var(--s-media)';
  if (p >= 30) return 'var(--s-alta)';
  return 'var(--s-critica)';
}

/** Anillo de salud tipo HUD con la puntuación y la letra del rango. */
export function anilloSalud(puntos, letra, { titulo = 'Puntuación de salud' } = {}) {
  const r = 70;
  const c = 2 * Math.PI * r;
  const p = Math.max(0, Math.min(100, puntos ?? 0));
  const off = c * (1 - p / 100);
  const col = colorSalud(p);
  const marcas = Array.from({ length: 20 }, (_, i) => {
    const a = (i / 20) * 2 * Math.PI - Math.PI / 2;
    const x1 = 90 + Math.cos(a) * 82; const y1 = 90 + Math.sin(a) * 82;
    const x2 = 90 + Math.cos(a) * 87; const y2 = 90 + Math.sin(a) * 87;
    return `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="currentColor" stroke-width="2" opacity="0.35"/>`;
  }).join('');
  return `<svg class="anillo" viewBox="0 0 180 180" role="img" aria-label="${esc(titulo)}: ${puntos ?? '–'} de 100, rango ${esc(letra ?? '–')}">
  <g style="color:var(--tinta)">${marcas}</g>
  <circle class="pista" cx="90" cy="90" r="${r}"/>
  <circle class="arco" cx="90" cy="90" r="${r}" stroke="${col}" stroke-dasharray="${c.toFixed(2)}" stroke-dashoffset="${off.toFixed(2)}" transform="rotate(-90 90 90)"/>
  <circle class="borde" cx="90" cy="90" r="${r + 8}"/><circle class="borde" cx="90" cy="90" r="${r - 8}"/>
  <text class="n" x="90" y="98" text-anchor="middle">${puntos ?? '–'}</text>
  <text class="de" x="90" y="116" text-anchor="middle">DE 100</text>
  <g transform="translate(140 140) rotate(-8)"><rect class="letra-fondo" x="-20" y="-20" width="40" height="40" fill="${col}"/>
  <text class="letra" x="0" y="11" text-anchor="middle" fill="#0A090A">${esc(letra ?? '?')}</text></g>
</svg>`;
}

/** Barras horizontales del conteo por severidad (HTML accesible: una lista). */
export function barrasSeveridad(conteo) {
  const max = Math.max(1, ...NIVELES.map((n) => conteo[n] || 0));
  return NIVELES.map((n) => {
    const v = conteo[n] || 0;
    const w = Math.round((v / max) * 100);
    return `<li><span class="sev sev-${n}">${NOMBRE_NIVEL[n]}</span><span class="pista-b" aria-hidden="true"><i class="b-${n}" style="width: ${w}%; background: var(--s-${n})"></i></span><b>${v}</b></li>`;
  }).join('');
}

/** Barra apilada (HTML) con las vulnerabilidades de una dependencia por severidad. */
export function apilada(vulns) {
  const total = vulns.length || 1;
  const c = Object.fromEntries(NIVELES.map((n) => [n, 0]));
  vulns.forEach((v) => c[v.severidad.nivel]++);
  const partes = NIVELES.filter((n) => c[n]).map((n) => `<i class="b-${n}" style="width:${((c[n] / total) * 100).toFixed(2)}%" title="${NOMBRE_NIVEL[n]}: ${c[n]}"></i>`).join('');
  const texto = NIVELES.filter((n) => c[n]).map((n) => `${c[n]} ${NOMBRE_NIVEL[n].toLowerCase()}`).join(', ');
  return `<div class="apilada" role="img" aria-label="${esc(texto)}">${partes}</div>`;
}

/** Gráfica de columnas (SVG) del conteo por severidad, para /proceso/. */
export function columnasSeveridad(conteo, { ancho = 520, alto = 260 } = {}) {
  const m = { i: 40, d: 12, s: 22, b: 46 };
  const max = Math.max(1, ...NIVELES.map((n) => conteo[n] || 0));
  const paso = Math.ceil(max / 4 / 5) * 5 || 1;
  const tope = paso * 4;
  const an = (ancho - m.i - m.d) / NIVELES.length;
  const y = (v) => m.s + (alto - m.s - m.b) * (1 - v / tope);
  let s = `<svg class="grafica" viewBox="0 0 ${ancho} ${alto}" role="img" aria-label="Vulnerabilidades del ejemplo por severidad: ${NIVELES.map((n) => `${NOMBRE_NIVEL[n]} ${conteo[n] || 0}`).join(', ')}">`;
  for (let v = 0; v <= tope; v += paso) s += `<line class="g-reji" x1="${m.i}" x2="${ancho - m.d}" y1="${y(v)}" y2="${y(v)}"/><text class="g-eje" x="${m.i - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
  NIVELES.forEach((n, i) => {
    const v = conteo[n] || 0;
    const x = m.i + i * an + an * 0.18;
    const w = an * 0.64;
    s += `<rect class="f-${n}" x="${x}" y="${y(v)}" width="${w}" height="${y(0) - y(v)}" stroke="var(--tinta)" stroke-width="2"/>`;
    s += `<text class="g-val" x="${x + w / 2}" y="${y(v) - 6}" text-anchor="middle">${v}</text>`;
    s += `<text class="g-eje" x="${x + w / 2}" y="${alto - m.b + 18}" text-anchor="middle">${NOMBRE_NIVEL[n]}</text>`;
  });
  s += `<line class="g-base" x1="${m.i}" x2="${ancho - m.d}" y1="${y(0)}" y2="${y(0)}"/></svg>`;
  return s;
}

/** Barras horizontales apiladas por dependencia (SVG), para /proceso/. */
export function barrasPorDependencia(porDependencia, { ancho = 520 } = {}) {
  const filas = porDependencia.slice().sort((a, b) => b.vulns.length - a.vulns.length);
  const fila = 30;
  const m = { i: 168, d: 40, s: 8, b: 24 };
  const alto = m.s + filas.length * fila + m.b;
  const max = Math.max(1, ...filas.map((d) => d.vulns.length));
  const x = (v) => m.i + (ancho - m.i - m.d) * (v / max);
  let s = `<svg class="grafica" viewBox="0 0 ${ancho} ${alto}" role="img" aria-label="Vulnerabilidades por dependencia del ejemplo: ${filas.map((d) => `${esc(d.nombre)} ${d.vulns.length}`).join(', ')}">`;
  filas.forEach((d, i) => {
    const yy = m.s + i * fila;
    s += `<text class="g-eje" x="${m.i - 8}" y="${yy + 18}" text-anchor="end">${esc(d.nombre)} ${esc(d.version)}</text>`;
    let acum = 0;
    for (const n of NIVELES) {
      const k = d.vulns.filter((v) => v.severidad.nivel === n).length;
      if (!k) continue;
      s += `<rect class="f-${n}" x="${x(acum)}" y="${yy + 4}" width="${x(acum + k) - x(acum)}" height="${fila - 10}" stroke="var(--tinta)" stroke-width="1.5"/>`;
      acum += k;
    }
    s += `<text class="g-val" x="${x(acum) + 6}" y="${yy + 18}">${d.vulns.length}</text>`;
  });
  s += `<line class="g-base" x1="${m.i}" x2="${m.i}" y1="${m.s}" y2="${alto - m.b + 4}"/></svg>`;
  return s;
}

/** Comparación ids crudos (lo que devuelve OSV) vs vulnerabilidades únicas tras unir alias. */
export function barrasAlias(porDependencia, { ancho = 520 } = {}) {
  const filas = porDependencia.filter((d) => d.idsCrudos).sort((a, b) => b.idsCrudos - a.idsCrudos);
  const fila = 36;
  const m = { i: 128, d: 40, s: 8, b: 10 };
  const alto = m.s + filas.length * fila + m.b;
  const max = Math.max(1, ...filas.map((d) => d.idsCrudos));
  const x = (v) => m.i + (ancho - m.i - m.d) * (v / max);
  let s = `<svg class="grafica" viewBox="0 0 ${ancho} ${alto}" role="img" aria-label="Identificadores devueltos por OSV frente a vulnerabilidades únicas por dependencia">`;
  filas.forEach((d, i) => {
    const yy = m.s + i * fila;
    s += `<text class="g-eje" x="${m.i - 8}" y="${yy + 20}" text-anchor="end">${esc(d.nombre)}</text>`;
    s += `<rect x="${m.i}" y="${yy + 4}" width="${x(d.idsCrudos) - m.i}" height="13" fill="var(--papel-2)" stroke="var(--tinta)" stroke-width="1.5"/>`;
    s += `<rect x="${m.i}" y="${yy + 19}" width="${x(d.vulns.length) - m.i}" height="13" fill="var(--cian)" stroke="var(--tinta)" stroke-width="1.5"/>`;
    s += `<text class="g-val" x="${x(d.idsCrudos) + 5}" y="${yy + 15}">${d.idsCrudos}</text><text class="g-val" x="${x(d.vulns.length) + 5}" y="${yy + 30}">${d.vulns.length}</text>`;
  });
  s += `</svg>`;
  return s;
}

export { num };
