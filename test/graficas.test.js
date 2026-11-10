import { test } from 'node:test';
import assert from 'node:assert/strict';
import { esc, anilloSalud, barrasSeveridad, apilada, columnasSeveridad, barrasPorDependencia } from '../js/graficas.js';

test('esc escapa HTML (los nombres de paquete vienen del usuario)', () => {
  assert.equal(esc('<img src=x onerror="a">'), '&lt;img src=x onerror=&quot;a&quot;&gt;');
});

test('anillo, barras y apilada describen los datos en texto accesible', () => {
  assert.match(anilloSalud(39, 'D'), /aria-label="Puntuación de salud: 39 de 100, rango D"/);
  const b = barrasSeveridad({ critica: 9, alta: 28, media: 32, baja: 5, sin: 0 });
  assert.equal((b.match(/<li>/g) || []).length, 5);
  assert.match(b, /width: 100%/);
  const a = apilada([{ severidad: { nivel: 'critica' } }, { severidad: { nivel: 'alta' } }, { severidad: { nivel: 'alta' } }]);
  assert.match(a, /aria-label="1 crítica, 2 alta"/);
});

test('gráficas SVG del proceso: una columna por severidad y nombres escapados', () => {
  const c = columnasSeveridad({ critica: 9, alta: 28, media: 32, baja: 5, sin: 0 });
  assert.equal((c.match(/<rect /g) || []).length, 5);
  const d = barrasPorDependencia([{ nombre: '<x>', version: '1', vulns: [{ severidad: { nivel: 'media' } }] }]);
  assert.ok(d.includes('&lt;x&gt;') && !d.includes('<x>'));
});
