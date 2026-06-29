# APTIA — Agente Automático de Selección

## Qué hace

1. **Monitorea** tu casilla aptia.talento@gmail.com cada 2 minutos
2. Cuando llega un email con CV adjunto (PDF o DOCX), lo **lee solo**
3. Lo **analiza con IA** contra la búsqueda activa que tengas cargada
4. Te **manda un informe** por email con score, fortalezas, brechas y preguntas de entrevista
5. Todo queda **guardado** en la base de datos y visible en el dashboard

## Cómo deployar en Railway (paso a paso)

### PASO 1: Crear contraseña de aplicación en Gmail
1. Andá a myaccount.google.com con la cuenta aptia.talento@gmail.com
2. Seguridad → Verificación en 2 pasos → ACTIVALA (si no la tenés)
3. Seguridad → Contraseñas de aplicaciones
4. Creá una nueva: nombre "APTIA Server" → te da un código tipo "abcd efgh ijkl mnop"
5. Guardá ese código (sacale los espacios: abcdefghijklmnop)

### PASO 2: Activar IMAP en Gmail
1. Abrí Gmail con aptia.talento@gmail.com
2. Configuración (engranaje) → Ver todos los ajustes
3. Pestaña "Reenvío y correo POP/IMAP"
4. En "Acceso IMAP" → Habilitar IMAP
5. Guardar cambios

### PASO 3: Conseguir API key de Claude
1. Andá a console.anthropic.com
2. Creá una cuenta o logueate
3. API Keys → Create Key → copiá la key (empieza con sk-ant-)
4. Cargá crédito (mínimo $5 USD, te alcanza para ~500 análisis de CV)

### PASO 4: Subir a Railway
1. Andá a railway.com → creá cuenta con GitHub
2. "New Project" → "Deploy from GitHub Repo"
3. Si no tenés repo, hacé "Empty Project" → "Add Service" → "Empty Service"
4. En Settings → "Source" → conectá tu repo o subí los archivos
5. En "Variables" agregá estas variables de entorno:

```
GMAIL_USER=aptia.talento@gmail.com
GMAIL_APP_PASSWORD=tucontraseñadeaplicacion
ANTHROPIC_API_KEY=sk-ant-tukey
NOTIFY_EMAIL=chersalasvigil@gmail.com
CHECK_INTERVAL=120000
PORT=3000
```

6. En Settings → Networking → "Generate Domain" (te da una URL pública)
7. Deploy → el servidor arranca solo

### PASO 5: Crear tu primera búsqueda
Una vez que el servidor esté corriendo, abrí la URL que te dio Railway.
Desde otra pestaña, mandá un POST a la API:

```
URL: https://tu-app.railway.app/api/busquedas
Método: POST
Body (JSON):
{
  "empresa": "Empresa Test",
  "puesto": "Analista de Marketing",
  "formacion_minima": "Universitario en Marketing",
  "experiencia_minima": "3 años",
  "hard_skills": "Google Ads, Meta Ads, Analytics",
  "soft_skills": "Liderazgo, comunicación"
}
```

O más fácil: pedile a Claude que te mande el request.

### PASO 6: Probar
Mandá un email a aptia.talento@gmail.com con un CV adjunto (PDF o DOCX).
En 2 minutos te llega el informe analizado a chersalasvigil@gmail.com.

## Dashboard
Abrí https://tu-app.railway.app/dashboard para ver:
- Estadísticas generales
- Últimos candidatos analizados con scores
- Búsquedas activas

## API disponible

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | /api/busquedas | Lista búsquedas |
| POST | /api/busquedas | Crear búsqueda |
| PATCH | /api/busquedas/:id/estado | Cambiar estado |
| GET | /api/candidatos | Lista candidatos |
| GET | /api/candidatos?busqueda_id=1 | Candidatos de una búsqueda |
| POST | /api/analizar | Análisis manual de CV |
| GET | /api/stats | Estadísticas |
| POST | /api/monitor/check | Forzar revisión de emails |
