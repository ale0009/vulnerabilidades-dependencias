import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { agregar, agruparAlias, puntuacionSalud, recortarVuln } from '../js/agregar.js';
import { parsear } from '../js/parseo.js';
import { EJEMPLO } from '../js/ejemplo.js';

// Respuestas OSV de muestra (forma real, contenido recortado).
const muestra = JSON.parse(readFileSync(new URL('./muestra-osv.json', import.meta.url)));
const deps = [
  { nombre: 'django', version: '2.2.0', ecosistema: 'PyPI' },
  { nombre: 'pyyaml', version: '5.1', ecosistema: 'PyPI' },
  { nombre: 'python-dateutil', version: '2.8.2', ecosistema: 'PyPI' },
];

test('agruparAlias: GHSA y PYSEC con el mismo CVE son una sola vulnerabilidad', () => {
  const g = agruparAlias(['GHSA-2gwj-7jmv-h26r', 'PYSEC-2022-190', 'GHSA-sin-detalle'], muestra.detalles);
  assert.equal(g.length, 2);
  assert.deepEqual(g[0].sort(), ['GHSA-2gwj-7jmv-h26r', 'PYSEC-2022-190']);
});

test('agregar: fichas, severidad, versión que corrige y conteo', () => {
  const a = agregar(deps, muestra.resultados, muestra.detalles, [{ nombre: 'gunicorn', version: null }]);
  const dj = a.porDependencia[0];
  assert.equal(dj.idsCrudos, 4);
  assert.equal(dj.vulns.length, 3, '4 ids, 3 vulnerabilidades distintas');
  const sql = dj.vulns[0];
  assert.equal(sql.id, 'GHSA-2gwj-7jmv-h26r', 'se prefiere el id GHSA');
  assert.deepEqual(sql.cves, ['CVE-2022-28346']);
  assert.deepEqual([sql.severidad.nivel, sql.severidad.puntuacion], ['critica', 9.8]);
  assert.equal(sql.corrige, '2.2.28');
  assert.equal(sql.enlace, 'https://osv.dev/vulnerability/GHSA-2gwj-7jmv-h26r');
  assert.equal(sql.fuente, 'https://nvd.nist.gov/vuln/detail/CVE-2022-28346');
  const sinDetalle = dj.vulns.find((v) => v.id === 'GHSA-sin-detalle');
  assert.equal(sinDetalle.severidad.nivel, 'sin', 'si el detalle no llegó, queda sin clasificar');
  assert.equal(dj.corregirA, '2.2.28');
  assert.equal(dj.peor.nivel, 'critica');

  const yaml = a.porDependencia[1];
  assert.equal(yaml.vulns[0].severidad.nivel, 'alta', 'etiqueta HIGH de la fuente cuando no hay CVSS v3');
  assert.equal(yaml.vulns[0].corrige, '5.2b1');
  assert.equal(yaml.vulns[0].resumen, 'Carga insegura de YAML.', 'sin summary: primera línea de details');

  assert.deepEqual(a.conteo, { critica: 1, alta: 2, media: 0, baja: 0, sin: 1 });
  assert.equal(a.totalHallazgos, 4);
  assert.deepEqual(a.vulnerables.map((d) => d.nombre), ['django', 'pyyaml']);
  assert.deepEqual(a.limpias.map((d) => d.nombre), ['python-dateutil']);
});

test('puntuación de salud: descuento por el peor hallazgo de cada dependencia', () => {
  const a = agregar(deps, muestra.resultados, muestra.detalles, [{ nombre: 'gunicorn', version: null }]);
  // 4 dependencias → 25 puntos cada una: django crítica −25, pyyaml alta −17,5, gunicorn sin versión −2,5.
  assert.equal(a.salud.porDep, 25);
  assert.equal(a.salud.puntos, 55);
  assert.equal(a.salud.rango.letra, 'C');
  assert.deepEqual(a.salud.desglose.map((x) => [x.nombre, x.descuento]), [['django', 25], ['pyyaml', 17.5], ['gunicorn', 2.5]]);
  assert.equal(puntuacionSalud([{ nombre: 'x', vulns: [] }], []).rango.letra, 'S');
  assert.equal(puntuacionSalud([], [{ nombre: 'y' }]).puntos, 90);
  assert.equal(puntuacionSalud([], []).puntos, 100);
});

test('recortarVuln conserva lo necesario', () => {
  const r = recortarVuln({ id: 'X', details: 'a\nb', aliases: ['CVE-1'], affected: [{ package: { name: 'p', ecosystem: 'npm', purl: 'pkg:npm/p' }, ranges: [] }], references: [{ type: 'PACKAGE', url: 'u' }, { type: 'ADVISORY', url: 'v' }], database_specific: { severity: 'LOW', cwe_ids: [] } });
  assert.deepEqual(r.affected[0].package, { name: 'p', ecosystem: 'npm' });
  assert.deepEqual(r.references, [{ type: 'ADVISORY', url: 'v' }]);
  assert.deepEqual(r.database_specific, { severity: 'LOW' });
});

test('respaldo guardado: es coherente con el ejemplo y está fechado', () => {
  const r = JSON.parse(readFileSync(new URL('../datos/osv-respaldo.json', import.meta.url)));
  assert.match(r.fecha, /^\d{4}-\d{2}-\d{2}T/);
  const { deps: todas } = parsear(EJEMPLO);
  const consultadas = todas.filter((d) => d.version);
  assert.deepEqual(r.consultadas, consultadas.map((d) => `${d.nombre}@${d.version}`));
  const a = agregar(consultadas, r.resultados, r.detalles, todas.filter((d) => !d.version));
  assert.equal(Object.values(a.conteo).reduce((x, y) => x + y, 0), a.totalHallazgos);
  assert.ok(a.vulnerables.length >= 5, 'el ejemplo tiene vulnerabilidades reales');
  const dj = a.porDependencia.find((d) => d.nombre === 'django');
  assert.equal(dj.vulns.find((v) => v.id === 'GHSA-2gwj-7jmv-h26r').corrige, '2.2.28');
  assert.equal(a.porDependencia.find((d) => d.nombre === 'python-dateutil').vulns.length, 0);
});
