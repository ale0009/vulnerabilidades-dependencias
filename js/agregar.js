// Agregación de resultados de OSV: une alias (GHSA ↔ PYSEC ↔ CVE), elige severidad y versión
// que corrige, cuenta por severidad y calcula la «puntuación de salud». Funciones puras.

import { severidadDeVuln, NIVELES } from './cvss.js';
import { versionQueCorrige, maximaVersion } from './versiones.js';
import { normalizarPypi } from './parseo.js';

/** Se queda solo con los campos que usa la herramienta (para el respaldo guardado). */
export function recortarVuln(v) {
  return {
    id: v.id,
    summary: v.summary,
    details: v.summary ? undefined : String(v.details || '').slice(0, 400),
    aliases: v.aliases || [],
    published: v.published,
    severity: v.severity,
    database_specific: v.database_specific?.severity ? { severity: v.database_specific.severity } : undefined,
    affected: (v.affected || []).map((a) => ({ package: { name: a.package?.name, ecosystem: a.package?.ecosystem }, ranges: a.ranges })),
    references: (v.references || []).filter((r) => r.type === 'ADVISORY' || r.type === 'WEB').slice(0, 3),
  };
}

const mismoPaquete = (a, dep) => {
  if (!a?.package || a.package.ecosystem !== dep.ecosistema) return false;
  return dep.ecosistema === 'PyPI' ? normalizarPypi(a.package.name) === normalizarPypi(dep.nombre) : a.package.name === dep.nombre;
};

const RANGO_NIVEL = Object.fromEntries(NIVELES.map((n, i) => [n, i])); // critica=0 … sin=4

/** Compara severidades: primero el nivel, luego la puntuación. Negativo si a es más grave. */
export function compararSeveridad(a, b) {
  if (RANGO_NIVEL[a.nivel] !== RANGO_NIVEL[b.nivel]) return RANGO_NIVEL[a.nivel] - RANGO_NIVEL[b.nivel];
  return (b.puntuacion ?? -1) - (a.puntuacion ?? -1);
}

/**
 * Agrupa los ids que OSV devolvió para una dependencia: dos ids son la misma vulnerabilidad
 * si uno aparece en los alias del otro o comparten un alias (p. ej. el mismo CVE).
 */
export function agruparAlias(ids, detalles) {
  const padre = new Map();
  const raiz = (x) => { while (padre.get(x) !== x) { padre.set(x, padre.get(padre.get(x))); x = padre.get(x); } return x; };
  const unir = (a, b) => { const ra = raiz(a); const rb = raiz(b); if (ra !== rb) padre.set(rb, ra); };
  const dueñoDeClave = new Map();
  for (const id of ids) padre.set(id, id);
  for (const id of ids) {
    const claves = [id, ...((detalles[id]?.aliases) || [])];
    for (const c of claves) {
      if (dueñoDeClave.has(c)) unir(dueñoDeClave.get(c), id);
      else dueñoDeClave.set(c, id);
    }
  }
  const grupos = new Map();
  for (const id of ids) {
    const r = raiz(id);
    if (!grupos.has(r)) grupos.set(r, []);
    grupos.get(r).push(id);
  }
  return [...grupos.values()];
}

const prioridadId = (id) => (id.startsWith('GHSA-') ? 0 : id.startsWith('CVE-') ? 1 : 2);

/** Convierte un grupo de ids en una ficha de vulnerabilidad para una dependencia. */
export function fichaDeGrupo(grupo, detalles, dep) {
  const ids = [...grupo].sort((a, b) => prioridadId(a) - prioridadId(b) || a.localeCompare(b));
  const registros = ids.map((id) => detalles[id]).filter(Boolean);
  const todos = new Set(ids);
  registros.forEach((r) => (r.aliases || []).forEach((a) => todos.add(a)));
  const cves = [...todos].filter((x) => x.startsWith('CVE-')).sort();
  const otros = [...todos].filter((x) => x !== ids[0] && !x.startsWith('CVE-')).sort();

  let severidad = { nivel: 'sin', puntuacion: null, fuente: 'sin dato', vector: null };
  for (const r of registros) {
    const s = severidadDeVuln(r);
    if (compararSeveridad(s, severidad) < 0) severidad = s;
  }
  // Todos los rangos de todos los registros del grupo, juntos: la versión que corrige es la del
  // rango que contiene la versión instalada (p. ej. Django 2.2.x se corrige en 2.2.28, no en 4.0.4).
  const rangos = registros.flatMap((r) => (r.affected || []).filter((a) => mismoPaquete(a, dep)).flatMap((a) => a.ranges || []));
  const conRango = rangos.length > 0;
  const corrige = conRango ? versionQueCorrige(dep.version, rangos) : null;
  const conResumen = registros.find((r) => r.summary);
  const resumen = conResumen ? conResumen.summary : (registros.find((r) => r.details)?.details || '').split('\n')[0].slice(0, 160);
  const aviso = registros.flatMap((r) => r.references || []).find((ref) => ref.type === 'ADVISORY') || registros.flatMap((r) => r.references || [])[0];
  const publicada = registros.map((r) => r.published).filter(Boolean).sort()[0] || null;

  return {
    id: ids[0],
    ids,
    cves,
    otros,
    resumen: resumen || 'Sin resumen en el registro.',
    severidad,
    corrige,
    sinCorreccion: conRango && !corrige,
    publicada,
    enlace: `https://osv.dev/vulnerability/${encodeURIComponent(ids[0])}`,
    fuente: aviso ? aviso.url : null,
  };
}

export const PESO_SALUD = { critica: 1, alta: 0.7, media: 0.4, baja: 0.15, sin: 0.4, sinVersion: 0.1 };
export const RANGOS = [
  { min: 100, letra: 'S', texto: 'Impecable' },
  { min: 85, letra: 'A', texto: 'Sana' },
  { min: 70, letra: 'B', texto: 'Con algún rasguño' },
  { min: 50, letra: 'C', texto: 'Herida' },
  { min: 30, letra: 'D', texto: 'Grave' },
  { min: 0, letra: 'F', texto: 'Crítica' },
];

/**
 * Puntuación de salud (calculada aquí, no es un estándar):
 * cada dependencia declarada vale lo mismo (100 / N puntos) y se le descuenta una fracción
 * según su PEOR hallazgo: crítica 100 %, alta 70 %, media 40 %, baja 15 %, sin clasificar 40 %.
 * Una dependencia sin versión consultable descuenta 10 % (no se puede verificar: criterio A.8.19).
 */
export function puntuacionSalud(porDependencia, sinVersion) {
  const n = porDependencia.length + sinVersion.length;
  if (!n) return { puntos: 100, rango: RANGOS[0], porDep: 0, desglose: [] };
  const porDep = 100 / n;
  const desglose = [];
  for (const d of porDependencia) {
    if (!d.vulns.length) continue;
    const peso = PESO_SALUD[d.peor.nivel];
    desglose.push({ nombre: d.nombre, version: d.version, motivo: d.peor.nivel, descuento: peso * porDep });
  }
  for (const d of sinVersion) desglose.push({ nombre: d.nombre, version: null, motivo: 'sinVersion', descuento: PESO_SALUD.sinVersion * porDep });
  const total = desglose.reduce((s, x) => s + x.descuento, 0);
  const puntos = Math.max(0, Math.round(100 - total));
  const rango = RANGOS.find((r) => puntos >= r.min);
  return { puntos, rango, porDep, desglose: desglose.sort((a, b) => b.descuento - a.descuento) };
}

/**
 * Agregación completa.
 * @param {Array} consultadas  dependencias enviadas a OSV (mismo orden que resultados)
 * @param {Array} resultados   results[] de /v1/querybatch: [{ vulns: [{ id, modified }] }]
 * @param {Object} detalles    id → registro de /v1/vulns/{id}
 * @param {Array} sinVersion   dependencias que no se pudieron consultar
 */
export function agregar(consultadas, resultados, detalles, sinVersion = []) {
  const porDependencia = consultadas.map((dep, i) => {
    const ids = [...new Set((resultados[i]?.vulns || []).map((v) => v.id))];
    const vulns = agruparAlias(ids, detalles).map((g) => fichaDeGrupo(g, detalles, dep)).sort((a, b) => compararSeveridad(a.severidad, b.severidad));
    const peor = vulns.length ? vulns[0].severidad : null;
    const corregirA = maximaVersion(vulns.map((v) => v.corrige));
    return { ...dep, vulns, peor, corregirA, sinCorreccion: vulns.filter((v) => v.sinCorreccion).length, idsCrudos: ids.length };
  });
  const conteo = Object.fromEntries(NIVELES.map((n) => [n, 0]));
  for (const d of porDependencia) for (const v of d.vulns) conteo[v.severidad.nivel]++;
  const vulnerables = porDependencia.filter((d) => d.vulns.length).sort((a, b) => compararSeveridad(a.peor, b.peor) || b.vulns.length - a.vulns.length);
  return {
    porDependencia,
    vulnerables,
    limpias: porDependencia.filter((d) => !d.vulns.length),
    sinVersion,
    conteo,
    totalHallazgos: Object.values(conteo).reduce((a, b) => a + b, 0),
    idsCrudos: porDependencia.reduce((s, d) => s + d.idsCrudos, 0),
    salud: puntuacionSalud(porDependencia, sinVersion),
  };
}
