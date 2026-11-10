import { test } from 'node:test';
import assert from 'node:assert/strict';
import { consultarLote, obtenerDetalles, cuerpoConsulta, API } from '../js/osv.js';

const respuesta = (cuerpo, status = 200) => ({ ok: status < 400, status, json: async () => cuerpo });

test('cuerpoConsulta: solo nombre, ecosistema y versión', () => {
  const c = cuerpoConsulta([{ nombre: 'django', version: '2.2.0', ecosistema: 'PyPI', linea: 3, declarada: '==2.2.0' }]);
  assert.deepEqual(c, { queries: [{ package: { name: 'django', ecosystem: 'PyPI' }, version: '2.2.0' }] });
});

test('consultarLote: un POST a /querybatch y sigue next_page_token', async () => {
  const llamadas = [];
  const fetchFn = async (url, op) => {
    const q = JSON.parse(op.body).queries;
    llamadas.push({ url, n: q.length, token: q[0].page_token });
    if (q[0].page_token) return respuesta({ results: [{ vulns: [{ id: 'B' }] }] });
    return respuesta({ results: [{ vulns: [{ id: 'A' }], next_page_token: 't1' }, {}] });
  };
  const r = await consultarLote([{ nombre: 'x', version: '1', ecosistema: 'npm' }, { nombre: 'y', version: '2', ecosistema: 'npm' }], { fetchFn });
  assert.deepEqual(r, [{ vulns: [{ id: 'A' }, { id: 'B' }] }, { vulns: [] }]);
  assert.equal(llamadas[0].url, `${API}/querybatch`);
  assert.equal(llamadas[1].token, 't1');
});

test('consultarLote: parte en lotes de 1000', async () => {
  const tamaños = [];
  const fetchFn = async (_u, op) => { const n = JSON.parse(op.body).queries.length; tamaños.push(n); return respuesta({ results: Array(n).fill({}) }); };
  const deps = Array.from({ length: 2300 }, (_, i) => ({ nombre: `p${i}`, version: '1.0.0', ecosistema: 'npm' }));
  const r = await consultarLote(deps, { fetchFn });
  assert.deepEqual(tamaños, [1000, 1000, 300]);
  assert.equal(r.length, 2300);
});

test('errores explicados: sin red y HTTP 429', async () => {
  await assert.rejects(consultarLote([{ nombre: 'x', version: '1', ecosistema: 'npm' }], { fetchFn: async () => { throw new TypeError('Failed to fetch'); } }), (e) => e.tipo === 'red' && /conexión/.test(e.message));
  await assert.rejects(consultarLote([{ nombre: 'x', version: '1', ecosistema: 'npm' }], { fetchFn: async () => respuesta({}, 429) }), /429.*espera/);
});

test('obtenerDetalles: sin duplicados, informa avance y aparta los fallidos', async () => {
  let activos = 0;
  let max = 0;
  const fetchFn = async (url) => {
    activos++; max = Math.max(max, activos);
    await new Promise((r) => setTimeout(r, 5));
    activos--;
    if (url.endsWith('/MAL')) return respuesta({}, 500);
    return respuesta({ id: url.split('/').pop() });
  };
  const avance = [];
  const { detalles, fallidos } = await obtenerDetalles(['A', 'B', 'A', 'C', 'MAL', 'D'], { fetchFn, concurrencia: 2, alAvanzar: (h, t) => avance.push(`${h}/${t}`) });
  assert.deepEqual(Object.keys(detalles).sort(), ['A', 'B', 'C', 'D']);
  assert.deepEqual(fallidos, ['MAL']);
  assert.ok(max <= 2);
  assert.equal(avance.at(-1), '5/5');
});
