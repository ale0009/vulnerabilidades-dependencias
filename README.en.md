# Do your dependencies have vulnerabilities?

[Español](README.md)

Paste (or drop) a `requirements.txt`, `package.json` or `package-lock.json` and the tool tells you which versions have known vulnerabilities, using the public [OSV.dev](https://osv.dev/) database:

- a HUD-style dashboard with a **health score** (0–100, rank S–F) and counts by severity (CVSS v3 when available);
- one card per vulnerable package, sorted by severity, with its CVE/GHSA IDs, the version that fixes each one and a link to the source;
- dependencies without a pinned version, which cannot be checked.

**Privacy:** the file is processed in your browser. Only each package's name, ecosystem and version are sent to OSV.dev.

It opens with a clearly marked example: the `requirements.txt` of an unmaintained 2019 Django project. If OSV.dev does not answer, the example is shown with a saved, dated response (`datos/osv-respaldo.json`). `?sin-conexion` forces offline mode.

The `/proceso/` page (Spanish) explains how OSV works, the data flow, the example analysis, the health formula, design decisions and limitations.

## Usage

Static page (HTML, CSS, JS modules, no build step):

```bash
python3 -m http.server 8000
node --test
node scripts/generar-respaldo.mjs   # refresh the offline fallback
```

## Background

- Mario and David's thesis on a free-software IT consulting office, where they assessed their system against the OWASP Top 10:2021 and left **A06 "Vulnerable and Outdated Components"** "under monitoring".
- Eiran, their repository auditor: ISO/IEC 27001:2022 controls **A.8.19** (pinned dependencies) and **A.8.8** (technical vulnerability management).

## Limitations

Only finds **known, published** vulnerabilities; without a lockfile it cannot see transitive dependencies; for ranges (`>=`, `^`) it checks the minimum version (worst case). The health score is our own formula, not a standard.

## Credits

[Mario Puerta](https://github.com/ale0009) (github.com/ale0009) × [David Rincón «Kuronoma»](https://www.linkedin.com/in/davidalexanderrinconcorredorkuronoma/) (LinkedIn).

Data: OSV.dev (each record under its source's license). Code: [MIT](LICENSE).
