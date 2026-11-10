// Página /proceso/: gráficas del ejemplo a partir de la respuesta OSV guardada (misma lógica que la herramienta).
import { parsear } from './parseo.js';
import { agregar } from './agregar.js';
import { EJEMPLO } from './ejemplo.js';
import { columnasSeveridad, barrasPorDependencia, barrasAlias, num } from './graficas.js';
import { iniciarTema } from './tema.js';

iniciarTema(document.getElementById('tema'));

async function iniciar() {
  const r = await fetch(new URL('../datos/osv-respaldo.json', import.meta.url)).then((x) => x.json());
  const { deps } = parsear(EJEMPLO);
  const consultadas = deps.filter((d) => d.version);
  const sinVersion = deps.filter((d) => !d.version);
  const res = agregar(consultadas, r.resultados, r.detalles, sinVersion);

  document.getElementById('g-sev').innerHTML = columnasSeveridad(res.conteo);
  document.getElementById('g-deps').innerHTML = barrasPorDependencia(res.porDependencia);
  document.getElementById('g-alias').innerHTML = barrasAlias(res.porDependencia);

  const cifras = {
    fecha: new Date(r.fecha).toLocaleDateString('es-CO', { day: 'numeric', month: 'long', year: 'numeric' }),
    deps: num(deps.length),
    consultadas: num(consultadas.length),
    ids: num(res.idsCrudos),
    unicas: num(res.totalHallazgos),
    criticas: num(res.conteo.critica),
    altas: num(res.conteo.alta),
    medias: num(res.conteo.media),
    bajas: num(res.conteo.baja),
    vulnerables: num(res.vulnerables.length),
    salud: num(res.salud.puntos),
    rango: res.salud.rango.letra,
    django: num(res.porDependencia.find((d) => d.nombre === 'django')?.vulns.length ?? 0),
    cvss: num(res.vulnerables.flatMap((d) => d.vulns).filter((v) => v.severidad.fuente === 'CVSS v3').length),
  };
  for (const el of document.querySelectorAll('[data-cifra]')) el.textContent = cifras[el.dataset.cifra] ?? '–';
}

iniciar().catch(() => {
  for (const id of ['g-sev', 'g-deps', 'g-alias']) document.getElementById(id).innerHTML = '<p class="vacio">No se pudo leer el respaldo guardado (datos/osv-respaldo.json).</p>';
});
