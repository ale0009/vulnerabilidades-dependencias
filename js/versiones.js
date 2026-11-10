// Comparación de versiones "suficientemente buena" para PyPI (PEP 440) y npm (SemVer).
// No pretende cubrir todo PEP 440 (épocas, versiones locales): se usa solo para elegir
// la versión que corrige una vulnerabilidad, y OSV ya decide qué versión está afectada.

const ORDEN_PRE = { dev: 0, a: 1, alpha: 1, b: 2, beta: 2, c: 3, rc: 3, pre: 3, preview: 3 };

/** "2.2.0rc1" → { rel: [2,2,0], pre: [3, 1] | null, post: n | null } */
export function analizarVersion(v) {
  const s = String(v).trim().toLowerCase().replace(/^v/, '').split('+')[0];
  const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/);
  if (!m) return { rel: [], pre: [-1, 0], post: null, crudo: s };
  const rel = m[1].split('.').map(Number);
  while (rel.length > 1 && rel[rel.length - 1] === 0) rel.pop(); // 1.0.0 == 1.0 == 1
  let resto = m[2].replace(/^[-_.]/, '');
  let pre = null;
  let post = null;
  const mp = resto.match(/^(post|rev|r)[-_.]?(\d*)/);
  if (mp) { post = Number(mp[2] || 0); resto = resto.slice(mp[0].length).replace(/^[-_.]/, ''); }
  const mpre = resto.match(/^(dev|alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d*)/);
  if (mpre) pre = [ORDEN_PRE[mpre[1]], Number(mpre[2] || 0)];
  else if (resto) pre = [ORDEN_PRE.pre, 0]; // sufijo desconocido (p. ej. "-next.1"): se trata como prelanzamiento
  return { rel, pre, post, crudo: s };
}

/** Devuelve -1, 0 o 1. */
export function compararVersiones(a, b) {
  const x = analizarVersion(a);
  const y = analizarVersion(b);
  const n = Math.max(x.rel.length, y.rel.length);
  for (let i = 0; i < n; i++) {
    const d = (x.rel[i] ?? 0) - (y.rel[i] ?? 0);
    if (d) return Math.sign(d);
  }
  // Mismo número de versión: prelanzamiento < final < post.
  const peso = (p) => (p.pre ? -1 : p.post !== null ? 1 : 0);
  if (peso(x) !== peso(y)) return Math.sign(peso(x) - peso(y));
  if (x.pre && y.pre) {
    if (x.pre[0] !== y.pre[0]) return Math.sign(x.pre[0] - y.pre[0]);
    if (x.pre[1] !== y.pre[1]) return Math.sign(x.pre[1] - y.pre[1]);
  }
  if (x.post !== null && y.post !== null && x.post !== y.post) return Math.sign(x.post - y.post);
  return 0;
}

/**
 * Dado el "affected" de OSV para un paquete, encuentra la versión que corrige la vulnerabilidad
 * para la versión dada. Recorre los rangos ECOSYSTEM/SEMVER: si version ∈ [introduced, fixed) → fixed.
 * Si ningún rango la contiene, devuelve la menor corrección mayor que la versión.
 * Devuelve null si no hay versión corregida publicada.
 */
export function versionQueCorrige(version, rangos = []) {
  const candidatos = [];
  for (const rango of rangos) {
    if (rango.type === 'GIT') continue;
    let desde = null;
    for (const ev of rango.events || []) {
      if ('introduced' in ev) desde = ev.introduced;
      else if ('fixed' in ev) {
        candidatos.push(ev.fixed);
        const dentro = (desde === '0' || desde === null || compararVersiones(version, desde) >= 0) && compararVersiones(version, ev.fixed) < 0;
        if (dentro) return ev.fixed;
        desde = null;
      } else if ('last_affected' in ev || 'limit' in ev) {
        desde = null;
      }
    }
  }
  const mayores = candidatos.filter((f) => compararVersiones(f, version) > 0).sort(compararVersiones);
  return mayores[0] ?? null;
}

/** La mayor de una lista de versiones (ignora null). */
export function maximaVersion(lista) {
  const v = lista.filter(Boolean);
  if (!v.length) return null;
  return v.reduce((a, b) => (compararVersiones(a, b) >= 0 ? a : b));
}
