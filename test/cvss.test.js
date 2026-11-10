import { test } from 'node:test';
import assert from 'node:assert/strict';
import { puntuacionCvss3, nivelDePuntuacion, severidadDeVuln, redondearArriba } from '../js/cvss.js';

test('CVSS v3: vectores conocidos dan la puntuación publicada por NVD', () => {
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N'), 5.3);
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(puntuacionCvss3('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), 7.5);
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
});

test('CVSS v3: vectores inválidos o de otra versión → null', () => {
  assert.equal(puntuacionCvss3('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), null);
  assert.equal(puntuacionCvss3('CVSS:3.1/AV:X/AC:L'), null);
  assert.equal(puntuacionCvss3(undefined), null);
});

test('redondeo hacia arriba de CVSS 3.1', () => {
  assert.equal(redondearArriba(4.02), 4.1);
  assert.equal(redondearArriba(4.0), 4.0);
});

test('niveles cualitativos', () => {
  assert.deepEqual([9.8, 9, 8.9, 7, 6.9, 4, 3.9, 0.1, 0, null].map(nivelDePuntuacion),
    ['critica', 'critica', 'alta', 'alta', 'media', 'media', 'baja', 'baja', 'sin', 'sin']);
});

test('severidadDeVuln: CVSS v3 > etiqueta de la fuente > sin clasificar', () => {
  const v3 = { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N' }], database_specific: { severity: 'MODERATE' } };
  assert.deepEqual(severidadDeVuln(v3).nivel, 'media');
  assert.equal(severidadDeVuln(v3).puntuacion, 5.3);
  const v4 = { severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/...' }], database_specific: { severity: 'HIGH' } };
  assert.deepEqual([severidadDeVuln(v4).nivel, severidadDeVuln(v4).puntuacion, severidadDeVuln(v4).fuente], ['alta', null, 'etiqueta (CVSS v4)']);
  assert.equal(severidadDeVuln({ id: 'PYSEC-1' }).nivel, 'sin');
});
