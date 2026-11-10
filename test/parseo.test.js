import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsearRequirements, parsearPackageJson, parsearLockfile, versionDeRangoNpm, detectarFormato, parsear, normalizarPypi, nombreDesdeRuta } from '../js/parseo.js';

const porNombre = (deps) => Object.fromEntries(deps.map((d) => [d.nombre, d]));

test('requirements: == exacta, >= y ~= aproximadas (mínima del rango), sin versión', () => {
  const { deps } = parsearRequirements('Django==2.2.0\nPyYAML>=5.1\nrequests~=2.19\ngunicorn\nnumpy<2\n');
  const d = porNombre(deps);
  assert.deepEqual([d.django.version, d.django.exacta, d.django.aproximada], ['2.2.0', true, false]);
  assert.deepEqual([d.pyyaml.version, d.pyyaml.aproximada], ['5.1', true]);
  assert.equal(d.requests.version, '2.19');
  assert.equal(d.gunicorn.version, null);
  assert.equal(d.gunicorn.declarada, '(sin versión)');
  assert.equal(d.numpy.version, null, 'solo cota superior: no hay versión consultable');
  assert.ok(deps.every((x) => x.ecosistema === 'PyPI'));
});

test('requirements: comentarios de línea completa y al final, líneas vacías', () => {
  const { deps } = parsearRequirements('# cabecera\n\nJinja2==2.10   # plantillas\n   # sangrado\nflask==0.12.2\t# con tabulador\n');
  assert.equal(deps.length, 2);
  assert.equal(deps[0].nombre, 'jinja2');
  assert.equal(deps[0].version, '2.10');
  assert.equal(deps[0].linea, 3);
});

test('requirements: extras, marcadores de entorno, espacios y rangos combinados', () => {
  const { deps } = parsearRequirements('requests[security,socks] == 2.19.1\nFlask==0.12.2 ; python_version >= "3.6"\nurllib3>=1.24,<2\n');
  const d = porNombre(deps);
  assert.equal(d.requests.version, '2.19.1');
  assert.equal(d.requests.exacta, true);
  assert.equal(d.flask.version, '0.12.2');
  assert.equal(d.urllib3.version, '1.24');
  assert.equal(d.urllib3.aproximada, true);
});

test('requirements: nombres normalizados (PEP 503) y === arbitraria', () => {
  assert.equal(normalizarPypi('Python_DateUtil'), 'python-dateutil');
  assert.equal(normalizarPypi('zope.interface'), 'zope-interface');
  const { deps } = parsearRequirements('Python_DateUtil===2.8.2\n');
  assert.equal(deps[0].nombre, 'python-dateutil');
  assert.equal(deps[0].version, '2.8.2');
});

test('requirements: ignora opciones de pip, URLs y une continuaciones con --hash', () => {
  const txt = '-r base.txt\n--index-url https://pypi.org/simple\n-e git+https://github.com/x/y.git#egg=y\nmipaquete @ https://ejemplo.org/p.whl\nhttps://ejemplo.org/otro.tar.gz\nidna==2.8 \\\n    --hash=sha256:abc123 \\\n    --hash=sha256:def456\ncertifi==2019.11.28\n';
  const { deps, ignoradas } = parsearRequirements(txt);
  assert.deepEqual(deps.map((d) => `${d.nombre}@${d.version}`), ['idna@2.8', 'certifi@2019.11.28']);
  assert.equal(deps[1].linea, 9, 'certifi conserva su número de línea real tras las líneas unidas');
  assert.equal(deps[0].linea, 6);
  assert.equal(ignoradas.length, 5);
});

test('npm: rangos → versión consultable', () => {
  assert.deepEqual(versionDeRangoNpm('4.17.20'), { version: '4.17.20', exacta: true, aproximada: false });
  assert.deepEqual(versionDeRangoNpm('=1.0.0'), { version: '1.0.0', exacta: true, aproximada: false });
  assert.deepEqual(versionDeRangoNpm('^4.17.0'), { version: '4.17.0', exacta: false, aproximada: true });
  assert.deepEqual(versionDeRangoNpm('~1.2'), { version: '1.2.0', exacta: false, aproximada: true });
  assert.deepEqual(versionDeRangoNpm('>=2.0.0 <3'), { version: '2.0.0', exacta: false, aproximada: true });
  assert.equal(versionDeRangoNpm('1.x').version, '1.0.0');
  assert.equal(versionDeRangoNpm('^1.0.0 || ^2.0.0').version, '1.0.0');
  for (const r of ['*', 'latest', '', 'x', 'github:a/b', 'git+https://x/y.git', 'file:../z', 'workspace:*', 'npm:otro@1.0.0']) {
    assert.equal(versionDeRangoNpm(r).version, null, r);
  }
});

test('package.json: dependencies y devDependencies con su grupo', () => {
  const pj = { name: 'app', dependencies: { lodash: '4.17.15', express: '^4.16.0', algo: 'latest' }, devDependencies: { '@babel/core': '~7.0.0', jest: '*' } };
  const { deps } = parsearPackageJson(JSON.stringify(pj));
  const d = porNombre(deps);
  assert.equal(deps.length, 5);
  assert.deepEqual([d.lodash.version, d.lodash.exacta, d.lodash.grupo], ['4.17.15', true, 'dependencies']);
  assert.deepEqual([d.express.version, d.express.aproximada], ['4.16.0', true]);
  assert.equal(d['@babel/core'].grupo, 'devDependencies');
  assert.equal(d['@babel/core'].version, '7.0.0');
  assert.equal(d.algo.version, null);
  assert.equal(d.jest.version, null);
  assert.ok(deps.every((x) => x.ecosistema === 'npm'));
});

const LOCK_V3 = {
  name: 'app', lockfileVersion: 3, requires: true,
  packages: {
    '': { name: 'app', version: '1.0.0', dependencies: { lodash: '^4.17.0' } },
    'node_modules/lodash': { version: '4.17.15', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz' },
    'node_modules/@babel/core': { version: '7.0.0', dev: true },
    'node_modules/a/node_modules/lodash': { version: '4.17.10' },
    'node_modules/b/node_modules/lodash': { version: '4.17.10' },
    'node_modules/mi-lib': { resolved: 'packages/mi-lib', link: true },
    'packages/mi-lib': { name: 'mi-lib', version: '0.1.0' },
  },
};

test('lockfile v3: packages, anidados, scoped, dev, enlaces y duplicados', () => {
  const { deps, ignoradas, lockfileVersion } = parsearLockfile(JSON.stringify(LOCK_V3));
  assert.equal(lockfileVersion, 3);
  assert.deepEqual(deps.map((d) => `${d.nombre}@${d.version}`).sort(), ['@babel/core@7.0.0', 'lodash@4.17.10', 'lodash@4.17.15']);
  assert.ok(deps.every((d) => d.exacta));
  assert.equal(deps.find((d) => d.nombre === '@babel/core').grupo, 'dev');
  assert.equal(ignoradas.length, 1);
  assert.equal(nombreDesdeRuta('node_modules/x/node_modules/@s/y'), '@s/y');
});

test('lockfile v2: usa "packages" aunque también traiga "dependencies" (v1)', () => {
  const v2 = { lockfileVersion: 2, packages: { '': {}, 'node_modules/minimist': { version: '1.2.0' } }, dependencies: { minimist: { version: '1.2.0' }, viejo: { version: '9.9.9' } } };
  const { deps } = parsearLockfile(JSON.stringify(v2));
  assert.deepEqual(deps.map((d) => `${d.nombre}@${d.version}`), ['minimist@1.2.0']);
});

test('lockfile v1: recorre "dependencies" anidadas', () => {
  const v1 = { lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } }, c: { version: 'github:x/c#abc' } } };
  const { deps, ignoradas } = parsearLockfile(v1);
  assert.deepEqual(deps.map((d) => `${d.nombre}@${d.version}`), ['a@1.0.0', 'b@2.0.0']);
  assert.equal(ignoradas.length, 1);
});

test('detectarFormato y parsear: errores explicados', () => {
  assert.equal(detectarFormato('Django==2.2'), 'requirements');
  assert.equal(detectarFormato('{"dependencies":{}}'), 'package.json');
  assert.equal(detectarFormato(JSON.stringify(LOCK_V3)), 'package-lock');
  assert.equal(detectarFormato('{"name":"x"}', 'package.json'), 'package.json');
  assert.equal(detectarFormato('{"a":1}'), 'json-desconocido');
  assert.equal(detectarFormato('{"a":'), 'json-invalido');
  assert.throws(() => parsear('   '), /No hay nada/);
  assert.throws(() => parsear('{"a":'), /JSON/);
  assert.throws(() => parsear('{"name":"x"}'), /package-lock/);
  assert.throws(() => parsear('# solo comentarios\n'), /ninguna dependencia/);
  assert.equal(parsear(JSON.stringify(LOCK_V3)).formato, 'package-lock');
});
