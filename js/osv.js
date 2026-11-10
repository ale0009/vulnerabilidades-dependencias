// Cliente mínimo de la API pública de OSV.dev (sin clave, con CORS).
// Solo viajan nombre + versión + ecosistema; el archivo completo nunca sale del navegador.

export const API = 'https://api.osv.dev/v1';
const LOTE = 1000; // límite de consultas por llamada a /querybatch

/** Cuerpo de /querybatch para una lista de dependencias con versión. */
export function cuerpoConsulta(deps) {
  return { queries: deps.map((d) => ({ package: { name: d.nombre, ecosystem: d.ecosistema }, version: d.version })) };
}

async function pedirJson(fetchFn, url, opciones, señal) {
  let r;
  try {
    r = await fetchFn(url, { ...opciones, signal: señal });
  } catch (e) {
    if (e?.name === 'AbortError') throw e;
    const err = new Error('No hubo respuesta de OSV.dev: puede que no haya conexión a internet o que un bloqueador corte la petición.');
    err.tipo = 'red';
    throw err;
  }
  if (!r.ok) {
    const err = new Error(`OSV.dev respondió ${r.status}${r.status === 429 ? ' (demasiadas consultas: espera un minuto)' : r.status >= 500 ? ' (falla del servicio)' : ''}.`);
    err.tipo = 'http';
    err.estado = r.status;
    throw err;
  }
  return r.json();
}

/**
 * /v1/querybatch en lotes de 1000. Devuelve results[] alineado con deps.
 * Si una consulta trae next_page_token (paquetes con cientos de avisos), se repite esa consulta con el token.
 */
export async function consultarLote(deps, { fetchFn = fetch, señal } = {}) {
  const resultados = [];
  for (let i = 0; i < deps.length; i += LOTE) {
    const parte = deps.slice(i, i + LOTE);
    const cuerpo = cuerpoConsulta(parte);
    const r = await pedirJson(fetchFn, `${API}/querybatch`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cuerpo) }, señal);
    const res = r.results || [];
    for (let k = 0; k < parte.length; k++) {
      const item = { vulns: [...(res[k]?.vulns || [])] };
      let token = res[k]?.next_page_token;
      let vueltas = 0;
      while (token && vueltas++ < 10) {
        const q = { ...cuerpo.queries[k], page_token: token };
        const extra = await pedirJson(fetchFn, `${API}/querybatch`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: [q] }) }, señal);
        item.vulns.push(...(extra.results?.[0]?.vulns || []));
        token = extra.results?.[0]?.next_page_token;
      }
      resultados.push(item);
    }
  }
  return resultados;
}

/**
 * Descarga /v1/vulns/{id} para cada id, con un máximo de `concurrencia` peticiones a la vez.
 * Los ids que fallan quedan fuera (la ficha se muestra igual, «sin clasificar»).
 */
export async function obtenerDetalles(ids, { fetchFn = fetch, concurrencia = 8, alAvanzar = () => {}, señal } = {}) {
  const detalles = {};
  const fallidos = [];
  const cola = [...new Set(ids)];
  let hechos = 0;
  const total = cola.length;
  async function trabajador() {
    while (cola.length) {
      const id = cola.shift();
      try {
        detalles[id] = await pedirJson(fetchFn, `${API}/vulns/${encodeURIComponent(id)}`, {}, señal);
      } catch (e) {
        if (e?.name === 'AbortError') throw e;
        fallidos.push(id);
      }
      alAvanzar(++hechos, total);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrencia, total) }, trabajador));
  return { detalles, fallidos };
}
