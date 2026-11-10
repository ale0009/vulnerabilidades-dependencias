// Parseo de manifiestos de dependencias. Funciones puras: texto → lista de dependencias.
// Formatos: requirements.txt (PyPI), package.json y package-lock.json v1/v2/v3 (npm).
//
// Cada dependencia: { nombre, version, ecosistema, exacta, aproximada, declarada, linea, grupo }
//  - exacta:     la versión está fijada (== en Python, "1.2.3" sin rango en npm, o viene del lockfile).
//  - aproximada: se consulta la versión MÍNIMA del rango (>=, ~=, ^, ~): el resultado es el peor caso.
//  - version:    null si no hay forma de saber qué versión se instala (no se consulta a OSV).

/** Normaliza un nombre de PyPI según PEP 503: minúsculas y [-_.]+ → "-". */
export function normalizarPypi(nombre) {
  return nombre.trim().toLowerCase().replace(/[-_.]+/g, '-');
}

/** Detecta el formato del texto pegado (y usa el nombre del archivo si lo hay). */
export function detectarFormato(texto, nombreArchivo = '') {
  const n = nombreArchivo.toLowerCase();
  const t = texto.trim();
  if (t.startsWith('{')) {
    try {
      const j = JSON.parse(t);
      if (j && typeof j === 'object') {
        if ('lockfileVersion' in j || (j.packages && typeof j.packages === 'object')) return 'package-lock';
        if (j.dependencies || j.devDependencies || j.peerDependencies || j.optionalDependencies || n.endsWith('package.json')) return 'package.json';
        return 'json-desconocido';
      }
    } catch { return 'json-invalido'; }
  }
  if (!t) return 'vacio';
  return 'requirements';
}

// ---------------------------------------------------------------- requirements.txt

const OPERADORES = /(===|==|~=|!=|>=|<=|>|<)/;

/**
 * Parsea un requirements.txt. Soporta comentarios (# al inicio o tras un espacio),
 * extras (requests[security]), marcadores de entorno (; python_version < "3.8"),
 * continuaciones con "\" y --hash. Ignora opciones (-r, -e, --index-url) y URLs.
 */
export function parsearRequirements(texto) {
  const deps = [];
  const ignoradas = [];
  // Une las líneas que terminan en "\" conservando el número de la primera.
  const lineas = [];
  let acumulada = null;
  texto.split(/\r?\n/).forEach((cruda, i) => {
    const sinBarra = cruda.replace(/\\\s*$/, '');
    const continua = sinBarra !== cruda;
    if (acumulada) { acumulada.txt += ' ' + sinBarra; } else { acumulada = { txt: sinBarra, n: i + 1 }; }
    if (!continua) { lineas.push(acumulada); acumulada = null; }
  });
  if (acumulada) lineas.push(acumulada);

  for (const { txt, n } of lineas) {
    // Comentario: "#" al inicio o precedido de espacio (no rompe URLs con #egg=).
    let l = txt.replace(/(^|\s)#.*$/, '').trim();
    if (!l) continue;
    if (l.startsWith('-')) { ignoradas.push({ linea: n, texto: l, motivo: 'opción de pip' }); continue; }
    if (/^[a-z+]+:\/\//i.test(l) || / @ /.test(l)) { ignoradas.push({ linea: n, texto: l, motivo: 'URL o ruta, no un paquete de PyPI' }); continue; }
    l = l.replace(/\s--hash[=\s]\S+/g, '').trim();
    const [req] = l.split(';'); // quita marcadores de entorno
    const m = req.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
    if (!m) { ignoradas.push({ linea: n, texto: l, motivo: 'no se reconoce' }); continue; }
    const nombre = normalizarPypi(m[1]);
    const espec = m[3].replace(/\s+/g, '');
    const dep = { nombre, version: null, ecosistema: 'PyPI', exacta: false, aproximada: false, declarada: espec || '(sin versión)', linea: n, grupo: 'requirements' };
    if (espec) {
      const partes = espec.split(',').filter(Boolean);
      const exacta = partes.find((p) => /^===?[^=]/.test(p) && !p.includes('*'));
      const minimo = partes.find((p) => p.startsWith('>=') || p.startsWith('~='));
      if (exacta) {
        dep.version = exacta.replace(/^===?/, '');
        dep.exacta = true;
      } else if (minimo) {
        dep.version = minimo.slice(2);
        dep.aproximada = true;
      } else if (!OPERADORES.test(espec)) {
        ignoradas.push({ linea: n, texto: l, motivo: 'no se reconoce' });
        continue;
      }
    }
    deps.push(dep);
  }
  return { deps, ignoradas };
}

// ---------------------------------------------------------------- npm

/**
 * Convierte un rango de npm a { version, exacta, aproximada }.
 * "1.2.3" o "=1.2.3" → exacta · "^1.2.3", "~1.2.3", ">=1.2.3" → mínima del rango (aproximada)
 * "*", "latest", "", "x", URLs, git, file:, workspace: → sin versión consultable.
 */
export function versionDeRangoNpm(rango) {
  const r = String(rango ?? '').trim();
  if (!r || r === '*' || r === 'latest' || /^[xX]$/.test(r)) return { version: null, exacta: false, aproximada: false };
  if (/^(npm:|git|github:|file:|link:|workspace:|https?:)/.test(r) || r.includes('/')) return { version: null, exacta: false, aproximada: false };
  if (/\|\|/.test(r)) {
    // Varios rangos: se toma el primero (el más bajo suele ir primero).
    return { ...versionDeRangoNpm(r.split('||')[0]), aproximada: true, exacta: false };
  }
  const exacta = r.match(/^=?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$/);
  if (exacta) return { version: exacta[1], exacta: true, aproximada: false };
  const min = r.match(/^(?:\^|~|>=|>)\s*v?(\d+(?:\.(?:\d+|[xX*]))?(?:\.(?:\d+|[xX*]))?(?:-[0-9A-Za-z.-]+)?)/);
  if (min) {
    const partes = min[1].split('-')[0].split('.').map((p) => (/^\d+$/.test(p) ? p : '0'));
    while (partes.length < 3) partes.push('0');
    const pre = min[1].includes('-') ? '-' + min[1].split('-').slice(1).join('-') : '';
    return { version: partes.join('.') + pre, exacta: false, aproximada: true };
  }
  const xr = r.match(/^(\d+)(?:\.(\d+|[xX*]))?(?:\.[xX*])?$/); // "1.x", "1.2.x", "1"
  if (xr) return { version: `${xr[1]}.${/^\d+$/.test(xr[2] ?? '') ? xr[2] : '0'}.0`, exacta: false, aproximada: true };
  return { version: null, exacta: false, aproximada: false };
}

const GRUPOS_NPM = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

/** Parsea un package.json: dependencies, devDependencies, optional y peer. */
export function parsearPackageJson(texto) {
  const j = typeof texto === 'string' ? JSON.parse(texto) : texto;
  const deps = [];
  const ignoradas = [];
  for (const grupo of GRUPOS_NPM) {
    for (const [nombre, rango] of Object.entries(j[grupo] || {})) {
      const v = versionDeRangoNpm(rango);
      deps.push({ nombre, ecosistema: 'npm', declarada: String(rango) || '(vacío)', linea: null, grupo, ...v });
    }
  }
  return { deps, ignoradas };
}

/** Nombre del paquete a partir de la clave "node_modules/a/node_modules/@b/c" → "@b/c". */
export function nombreDesdeRuta(ruta) {
  const i = ruta.lastIndexOf('node_modules/');
  return i === -1 ? ruta : ruta.slice(i + 'node_modules/'.length);
}

/**
 * Parsea package-lock.json. v2/v3 usan "packages" (claves con la ruta en node_modules);
 * v1 usa "dependencies" anidadas. Devuelve versiones exactas, sin duplicar nombre@versión.
 */
export function parsearLockfile(texto) {
  const j = typeof texto === 'string' ? JSON.parse(texto) : texto;
  const vistos = new Map();
  const ignoradas = [];
  const agregar = (nombre, info, grupo) => {
    if (!nombre || !info) return;
    if (info.link) { ignoradas.push({ linea: null, texto: nombre, motivo: 'enlace local (workspace)' }); return; }
    if (!info.version || !/^\d/.test(info.version)) { ignoradas.push({ linea: null, texto: `${nombre}@${info.version ?? '?'}`, motivo: 'sin versión del registro' }); return; }
    const clave = `${nombre}@${info.version}`;
    if (!vistos.has(clave)) {
      vistos.set(clave, { nombre, version: info.version, ecosistema: 'npm', exacta: true, aproximada: false, declarada: info.version, linea: null, grupo: info.dev ? 'dev' : grupo });
    }
  };
  if (j.packages && typeof j.packages === 'object') {
    for (const [ruta, info] of Object.entries(j.packages)) {
      if (ruta === '') continue; // el propio proyecto
      if (!ruta.includes('node_modules/')) continue; // carpetas de workspaces
      agregar(info.name || nombreDesdeRuta(ruta), info, 'lockfile');
    }
  } else if (j.dependencies) {
    const recorrer = (deps) => {
      for (const [nombre, info] of Object.entries(deps || {})) {
        agregar(nombre, info, 'lockfile');
        if (info && info.dependencies) recorrer(info.dependencies);
      }
    };
    recorrer(j.dependencies);
  }
  return { deps: [...vistos.values()], ignoradas, lockfileVersion: j.lockfileVersion ?? null };
}

/** Punto de entrada: detecta el formato y parsea. Lanza Error con un mensaje en español si no puede. */
export function parsear(texto, nombreArchivo = '') {
  const formato = detectarFormato(texto, nombreArchivo);
  if (formato === 'vacio') throw new Error('No hay nada que analizar: pega un archivo o arrastra uno.');
  if (formato === 'json-invalido') throw new Error('Parece JSON pero no se puede leer: revisa que esté completo (comas, llaves).');
  if (formato === 'json-desconocido') throw new Error('Es un JSON, pero no tiene "dependencies", "devDependencies" ni "packages": no parece un package.json ni un package-lock.json.');
  let r;
  if (formato === 'requirements') r = parsearRequirements(texto);
  else if (formato === 'package.json') r = parsearPackageJson(texto);
  else r = parsearLockfile(texto);
  if (!r.deps.length) throw new Error('No se encontró ninguna dependencia en el texto.');
  return { formato, ...r };
}
