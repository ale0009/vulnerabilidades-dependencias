// Severidad de una vulnerabilidad OSV.
// OSV entrega el vector CVSS (texto), no la puntuación: aquí se calcula la puntuación base
// CVSS v3.0/v3.1 con las fórmulas de la especificación de FIRST. Para CVSS v4 (otra fórmula,
// basada en tablas) se usa la etiqueta de severidad de la base de datos de origen (GitHub).

const PESOS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};
const PR = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };

/** Redondeo hacia arriba a un decimal, como lo define CVSS v3.1 (Apéndice A). */
export function redondearArriba(x) {
  const entero = Math.round(x * 100000);
  if (entero % 10000 === 0) return entero / 100000;
  return (Math.floor(entero / 10000) + 1) / 10;
}

/** Puntuación base CVSS v3.x a partir del vector "CVSS:3.1/AV:N/AC:L/...". null si no es válido. */
export function puntuacionCvss3(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
  const S = m.S;
  if (!PESOS.AV[m.AV] || !PESOS.AC[m.AC] || !PESOS.UI[m.UI] || !(S === 'U' || S === 'C') || !PR[S][m.PR]) return null;
  if (!(m.C in PESOS.C) || !(m.I in PESOS.I) || !(m.A in PESOS.A)) return null;
  const iss = 1 - (1 - PESOS.C[m.C]) * (1 - PESOS.I[m.I]) * (1 - PESOS.A[m.A]);
  const impacto = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const explotabilidad = 8.22 * PESOS.AV[m.AV] * PESOS.AC[m.AC] * PR[S][m.PR] * PESOS.UI[m.UI];
  if (impacto <= 0) return 0;
  const base = S === 'U' ? Math.min(impacto + explotabilidad, 10) : Math.min(1.08 * (impacto + explotabilidad), 10);
  return redondearArriba(base);
}

export const NIVELES = ['critica', 'alta', 'media', 'baja', 'sin'];
export const NOMBRE_NIVEL = { critica: 'Crítica', alta: 'Alta', media: 'Media', baja: 'Baja', sin: 'Sin clasificar' };

/** Rangos cualitativos de CVSS v3: 9,0–10 crítica · 7,0–8,9 alta · 4,0–6,9 media · 0,1–3,9 baja. */
export function nivelDePuntuacion(p) {
  if (p === null || p === undefined || Number.isNaN(p)) return 'sin';
  if (p >= 9) return 'critica';
  if (p >= 7) return 'alta';
  if (p >= 4) return 'media';
  if (p > 0) return 'baja';
  return 'sin';
}

const ETIQUETAS = { CRITICAL: 'critica', HIGH: 'alta', MODERATE: 'media', MEDIUM: 'media', LOW: 'baja' };

/**
 * Severidad de un registro OSV: { nivel, puntuacion, fuente, vector }.
 * Prioridad: CVSS v3 calculado > etiqueta de la base de datos (database_specific.severity) > sin clasificar.
 */
export function severidadDeVuln(vuln) {
  let mejor = null;
  for (const s of vuln?.severity || []) {
    if (s.type === 'CVSS_V3') {
      const p = puntuacionCvss3(s.score);
      if (p !== null && (mejor === null || p > mejor.puntuacion)) mejor = { puntuacion: p, vector: s.score };
    }
  }
  if (mejor) return { nivel: nivelDePuntuacion(mejor.puntuacion), puntuacion: mejor.puntuacion, fuente: 'CVSS v3', vector: mejor.vector };
  const etiqueta = String(vuln?.database_specific?.severity || '').toUpperCase();
  if (ETIQUETAS[etiqueta]) {
    const v4 = (vuln?.severity || []).find((s) => s.type === 'CVSS_V4');
    return { nivel: ETIQUETAS[etiqueta], puntuacion: null, fuente: v4 ? 'etiqueta (CVSS v4)' : 'etiqueta de la fuente', vector: v4?.score ?? null };
  }
  return { nivel: 'sin', puntuacion: null, fuente: 'sin dato', vector: null };
}
