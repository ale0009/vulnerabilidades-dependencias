// Ejemplo precargado: un requirements.txt de un proyecto Django de 2019 que nadie actualizó.
// Son versiones reales y antiguas; OSV.dev reporta vulnerabilidades conocidas para todas
// salvo python-dateutil 2.8.2 (verificado el 2026-11-10).
export const EJEMPLO = `# EJEMPLO · requirements.txt de un proyecto Django de 2019 sin actualizar
Django==2.2.0
requests[security]==2.19.1
Jinja2==2.10        # plantillas de correo
PyYAML>=5.1         # rango: se consulta la mínima (5.1)
urllib3==1.24.1
Flask==0.12.2 ; python_version >= "3.6"
python-dateutil==2.8.2
gunicorn            # sin versión fija: no se puede verificar
`;
export const NOMBRE_EJEMPLO = 'requirements.txt (ejemplo)';
