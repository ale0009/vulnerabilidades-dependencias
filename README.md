# ¿Tus dependencias tienen vulnerabilidades?

[English](README.en.md)

Pega (o arrastra) un `requirements.txt`, `package.json` o `package-lock.json` y la herramienta te dice qué versiones tienen vulnerabilidades conocidas, según la base pública [OSV.dev](https://osv.dev/):

- un tablero tipo HUD con la **puntuación de salud** (0–100 y rango S–F) y el conteo por severidad (CVSS v3 cuando existe);
- una tarjeta por paquete vulnerable, ordenada por gravedad, con sus CVE/GHSA, la versión que corrige cada una y el enlace a la fuente;
- las dependencias sin versión fija, que no se pueden verificar.

**Privacidad:** el archivo se procesa en tu navegador. A OSV.dev solo viajan el nombre, el ecosistema y la versión de cada paquete.

Abre con un ejemplo marcado: el `requirements.txt` de un proyecto Django de 2019 sin actualizar. Si OSV.dev no responde, el ejemplo se muestra con la respuesta guardada (`datos/osv-respaldo.json`) y un aviso «sin conexión» con su fecha. `?sin-conexion` fuerza ese modo.

La página `/proceso/` explica cómo funciona OSV, el flujo de datos, el análisis del ejemplo, la fórmula de salud, las decisiones de diseño y las limitaciones.

## Uso

Es una página estática (HTML, CSS y módulos JS, sin compilación):

```bash
python3 -m http.server 8000      # y abre http://localhost:8000
node --test                      # pruebas: parseo, versiones, CVSS, agregación, cliente OSV, gráficas
node scripts/generar-respaldo.mjs  # regenera el respaldo con datos de hoy
```

Se publica tal cual en GitHub Pages.

| Archivo | Qué hace |
|---|---|
| `js/parseo.js` | requirements.txt (`==`, `>=`, `~=`, extras, marcadores, comentarios, `--hash`), package.json y package-lock v1/v2/v3 |
| `js/osv.js` | `POST /v1/querybatch` (lotes de 1000, paginación) y `GET /v1/vulns/{id}` (8 a la vez) |
| `js/cvss.js` | puntuación base CVSS v3.0/3.1 desde el vector |
| `js/versiones.js` | comparación PEP 440 / SemVer y versión que corrige |
| `js/agregar.js` | une alias (GHSA ↔ PYSEC ↔ CVE), cuenta y calcula la salud |

## De qué trabajo sale

- La tesis del consultorio de informática basado en software libre (Mario y David), donde evaluaron su sistema frente al OWASP Top 10:2021 y dejaron **A06 «Componentes vulnerables y desactualizados»** «bajo monitoreo», con `npm audit` mensual y Dependabot/Snyk como mitigación pendiente.
- Eiran, el auditor de repositorios: controles ISO/IEC 27001:2022 **A.8.19** (dependencias con versión fija, medido automáticamente) y **A.8.8** (gestión de vulnerabilidades técnicas) del estándar «Ley 1273 / ISO 27001:2022».

## Limitaciones

Solo encuentra vulnerabilidades **conocidas y publicadas**; sin lockfile no ve dependencias transitivas; con rangos (`>=`, `^`) consulta la versión mínima (peor caso). La puntuación de salud es una fórmula propia, no un estándar. No reemplaza una auditoría.

## Créditos

[Mario Puerta](https://github.com/ale0009) (github.com/ale0009) × [David Rincón «Kuronoma»](https://www.linkedin.com/in/davidalexanderrinconcorredorkuronoma/) (LinkedIn).

Datos: OSV.dev (cada registro con la licencia de su fuente). Código: [MIT](LICENSE).
