// Regenera el respaldo sin conexión: consulta OSV.dev con el ejemplo y guarda la respuesta recortada.
// Uso: node scripts/generar-respaldo.mjs   → datos/osv-respaldo.json
import { writeFileSync } from 'node:fs';
import { parsear } from '../js/parseo.js';
import { consultarLote, obtenerDetalles } from '../js/osv.js';
import { recortarVuln } from '../js/agregar.js';
import { EJEMPLO } from '../js/ejemplo.js';

const { deps } = parsear(EJEMPLO);
const consultadas = deps.filter((d) => d.version);
const resultados = await consultarLote(consultadas);
const ids = resultados.flatMap((r) => r.vulns.map((v) => v.id));
const { detalles, fallidos } = await obtenerDetalles(ids, { concurrencia: 6 });
if (fallidos.length) console.warn('Fallaron:', fallidos);
const recortados = Object.fromEntries(Object.entries(detalles).map(([id, v]) => [id, recortarVuln(v)]));
const salida = {
  fecha: new Date().toISOString(),
  nota: 'Respuesta real de OSV.dev (/v1/querybatch + /v1/vulns/{id}) para el ejemplo precargado, recortada a los campos que usa la herramienta.',
  consultadas: consultadas.map((d) => `${d.nombre}@${d.version}`),
  resultados: resultados.map((r) => ({ vulns: r.vulns.map((v) => ({ id: v.id })) })),
  detalles: recortados,
};
writeFileSync(new URL('../datos/osv-respaldo.json', import.meta.url), JSON.stringify(salida));
console.log('ids:', ids.length, 'detalles:', Object.keys(recortados).length);
