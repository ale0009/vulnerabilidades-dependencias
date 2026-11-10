import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compararVersiones, versionQueCorrige, maximaVersion } from '../js/versiones.js';

test('compararVersiones: numérico, ceros finales, prelanzamientos y post', () => {
  assert.equal(compararVersiones('2.10', '2.9'), 1);
  assert.equal(compararVersiones('2.2', '2.2.0'), 0);
  assert.equal(compararVersiones('5.2b1', '5.2'), -1);
  assert.equal(compararVersiones('5.2a1', '5.2b1'), -1);
  assert.equal(compararVersiones('5.2rc1', '5.2b3'), 1);
  assert.equal(compararVersiones('1.0.0-beta.2', '1.0.0'), -1);
  assert.equal(compararVersiones('1.0.post1', '1.0'), 1);
  assert.equal(compararVersiones('v1.2.3', '1.2.3'), 0);
  assert.equal(compararVersiones('2019.11.28', '2020.4.5'), -1);
});

// Rangos reales (recortados) de la vulnerabilidad GHSA-2gwj-7jmv-h26r de Django.
const DJANGO = [
  { type: 'ECOSYSTEM', events: [{ introduced: '2.2' }, { fixed: '2.2.28' }] },
  { type: 'ECOSYSTEM', events: [{ introduced: '3.2' }, { fixed: '3.2.13' }] },
  { type: 'ECOSYSTEM', events: [{ introduced: '4.0' }, { fixed: '4.0.4' }] },
];

test('versionQueCorrige: elige el rango que contiene la versión instalada', () => {
  assert.equal(versionQueCorrige('2.2.0', DJANGO), '2.2.28');
  assert.equal(versionQueCorrige('3.2.4', DJANGO), '3.2.13');
  assert.equal(versionQueCorrige('4.0', DJANGO), '4.0.4');
});

test('versionQueCorrige: eventos desordenados en un solo rango (formato PYSEC) y GIT ignorado', () => {
  const r = [
    { type: 'GIT', events: [{ introduced: '0' }, { fixed: 'eb31d84' }] },
    { type: 'ECOSYSTEM', events: [{ introduced: '4.0' }, { fixed: '4.0.4' }, { introduced: '2.2' }, { fixed: '2.2.28' }] },
  ];
  assert.equal(versionQueCorrige('2.2.0', r), '2.2.28');
});

test('versionQueCorrige: introduced 0, sin corrección (last_affected) y respaldo', () => {
  assert.equal(versionQueCorrige('0.12.2', [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '0.12.3' }] }]), '0.12.3');
  assert.equal(versionQueCorrige('1.0', [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { last_affected: '1.5' }] }]), null);
  // Ningún rango contiene la versión: se propone la menor corrección posterior.
  assert.equal(versionQueCorrige('1.5', [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0' }, { fixed: '2.0.3' }] }]), '2.0.3');
  assert.equal(versionQueCorrige('3.0', [{ type: 'ECOSYSTEM', events: [{ introduced: '2.0' }, { fixed: '2.0.3' }] }]), null);
});

test('maximaVersion ignora null', () => {
  assert.equal(maximaVersion(['2.2.4', null, '2.2.28', '2.2.10']), '2.2.28');
  assert.equal(maximaVersion([null]), null);
});
