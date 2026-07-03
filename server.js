require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '30mb' })); // portfolios en PDF pueden pesar (base64 infla ~33%)

// ═══════════════════════════════════════
// BASE DE DATOS (persistente en Volume /data si existe)
// ═══════════════════════════════════════
// Prioridad: DB_PATH explicito > carpeta persistente /data > local ./aptia.db
function resolverRutaDB() {
  if (process.env.DB_PATH) return process.env.DB_PATH;
  const dirPersistente = '/data';
  try {
    if (!fs.existsSync(dirPersistente)) fs.mkdirSync(dirPersistente, { recursive: true });
    // Verifico que se pueda escribir realmente (el Volume esta montado)
    fs.accessSync(dirPersistente, fs.constants.W_OK);
    return path.join(dirPersistente, 'aptia.db');
  } catch (e) {
    console.warn('[DB] /data no disponible o sin permiso de escritura, uso ./aptia.db (NO persistente entre deploys)');
    return './aptia.db';
  }
}
const DB_PATH = resolverRutaDB();
console.log('[DB] Usando base de datos en:', DB_PATH);
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS busquedas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo TEXT UNIQUE,
    empresa TEXT NOT NULL,
    rubro_empresa TEXT,
    contacto_nombre TEXT,
    contacto_email TEXT,
    puesto TEXT NOT NULL,
    area TEXT,
    reporta_a TEXT,
    ubicacion TEXT,
    modalidad TEXT DEFAULT 'Presencial',
    contratacion TEXT DEFAULT 'Relacion de dependencia',
    jornada TEXT DEFAULT 'Full-time',
    salario_desde TEXT,
    salario_hasta TEXT,
    moneda TEXT DEFAULT 'ARS',
    fecha_objetivo TEXT,
    posiciones INTEGER DEFAULT 1,
    formacion_minima TEXT,
    experiencia_minima TEXT,
    hard_skills TEXT,
    idiomas TEXT,
    certificaciones TEXT,
    disponibilidad TEXT,
    formacion_deseable TEXT,
    industrias_valoradas TEXT,
    soft_skills TEXT,
    perfil_disc TEXT,
    competencias_clave TEXT,
    motivo_busqueda TEXT,
    deal_breakers TEXT,
    proceso_cliente TEXT,
    publicar_web INTEGER DEFAULT 1,
    estado TEXT DEFAULT 'activa',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS candidatos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    busqueda_id INTEGER,
    nombre TEXT,
    email_origen TEXT,
    cv_texto TEXT,
    score INTEGER,
    formacion INTEGER,
    experiencia INTEGER,
    hard_skills_score INTEGER,
    soft_skills_score INTEGER,
    fit_cultural INTEGER,
    fortalezas TEXT,
    brechas TEXT,
    excluyentes_no_cumplidos TEXT,
    resumen TEXT,
    recomendacion TEXT,
    preguntas TEXT,
    disc_resultado TEXT,
    disc_compatibilidad INTEGER,
    notas_entrevista TEXT,
    score_final INTEGER,
    informe_final TEXT,
    estado_proceso TEXT DEFAULT 'Analizado',
    informe_enviado INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (busqueda_id) REFERENCES busquedas(id)
  );

  CREATE TABLE IF NOT EXISTS emails_procesados (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT UNIQUE,
    from_email TEXT,
    subject TEXT,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Migracion suave: agregar columnas nuevas si la DB es vieja
function ensureColumn(table, col, def) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    if (!cols.find(c => c.name === col)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
      console.log(`[migracion] Columna agregada: ${table}.${col}`);
    }
  } catch (e) { /* noop */ }
}
ensureColumn('busquedas', 'codigo', 'TEXT');
ensureColumn('busquedas', 'publicar_web', 'INTEGER DEFAULT 1');
ensureColumn('busquedas', 'tipo_puesto', "TEXT DEFAULT 'general'");
ensureColumn('candidatos', 'notas_entrevista', 'TEXT');
ensureColumn('candidatos', 'score_final', 'INTEGER');
ensureColumn('candidatos', 'informe_final', 'TEXT');
ensureColumn('candidatos', 'estado_proceso', "TEXT DEFAULT 'Analizado'");
ensureColumn('candidatos', 'lectura_humana', 'TEXT');
ensureColumn('candidatos', 'links_detectados', 'TEXT');
ensureColumn('candidatos', 'portfolio_analisis', 'TEXT');
ensureColumn('candidatos', 'portfolio_score', 'INTEGER');

// ═══════════════════════════════════════
// PONDERACION POR TIPO DE PUESTO
// Cada perfil reparte 100 puntos entre las 5 dimensiones segun lo que
// mas importa para ese tipo de rol. Un buen selector no pesa igual
// la formacion de un comercial que la de un profesional tecnico.
// ═══════════════════════════════════════
const PONDERACIONES = {
  general:      { formacion: 20, experiencia: 25, hardSkills: 25, softSkills: 15, fitCultural: 15, nota: 'Reparto equilibrado, sin sesgo por tipo de rol.' },
  comercial:    { formacion: 10, experiencia: 30, hardSkills: 20, softSkills: 25, fitCultural: 15, nota: 'Ventas/atencion: pesa mas la experiencia comercial concreta y las habilidades blandas (comunicacion, negociacion, orientacion a resultados) que el titulo.' },
  tecnico:      { formacion: 15, experiencia: 25, hardSkills: 40, softSkills: 10, fitCultural: 10, nota: 'Roles tecnicos/IT/oficios: el dominio de las herramientas y skills duros manda; el titulo formal pesa menos si demuestra capacidad real.' },
  creativo:     { formacion: 10, experiencia: 25, hardSkills: 35, softSkills: 15, fitCultural: 15, nota: 'Diseno/creativos: pesa el portfolio y el dominio de herramientas por sobre el titulo. La institucion formal no es lo central salvo que sea excluyente cargado.' },
  profesional:  { formacion: 30, experiencia: 25, hardSkills: 20, softSkills: 10, fitCultural: 15, nota: 'Profesionales matriculados (contadores, abogados, ingenieros, salud): la formacion y matricula pesan fuerte porque suelen ser requisito real del rol.' },
  liderazgo:    { formacion: 15, experiencia: 30, hardSkills: 15, softSkills: 25, fitCultural: 15, nota: 'Jefaturas/gerencias: pesa la trayectoria conduciendo equipos y las competencias de liderazgo por sobre el skill tecnico puntual.' },
  operativo:    { formacion: 10, experiencia: 30, hardSkills: 25, softSkills: 15, fitCultural: 20, nota: 'Operativos/produccion/logistica: pesa la experiencia concreta en la tarea, la confiabilidad y el encaje con el equipo; el titulo es secundario.' },
  administrativo:{ formacion: 20, experiencia: 25, hardSkills: 25, softSkills: 15, fitCultural: 15, nota: 'Administrativos: equilibrio entre formacion, experiencia y manejo de herramientas (sistemas, Excel, gestion).' }
};
function pesosDe(tipo) { return PONDERACIONES[tipo] || PONDERACIONES.general; }

// ═══════════════════════════════════════
// CLAUDE API
// ═══════════════════════════════════════
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
const CLAUDE_MODEL = 'claude-sonnet-4-6';

async function callClaude(prompt, maxTokens) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: maxTokens || 4000,
      system: 'Sos el motor de IA de APTIA, consultora de seleccion de personal en Argentina. Respondes SOLO en JSON valido, sin markdown, sin backticks, sin texto extra. Sos preciso, critico y realista con el scoring. No inflas puntajes.',
      messages: [{ role: 'user', content: prompt }]
    })
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error('Claude API error ' + res.status + ': ' + t);
  }
  const data = await res.json();
  let txt = (data.content || []).map(b => b.text || '').join('').trim();
  txt = txt.replace(/^```json/i, '').replace(/^```/, '').replace(/```$/, '').trim();
  return JSON.parse(txt);
}

// Igual que callClaude pero mandando un PDF como documento: Claude VE las paginas
// (imagenes incluidas). Es lo que permite analizar portfolios de diseno que no tienen texto.
async function callClaudeVisionPDF(promptText, pdfBase64, maxTokens) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: maxTokens || 3000,
      system: 'Sos el motor de IA de APTIA, consultora de seleccion de personal en Argentina. Respondes SOLO en JSON valido, sin markdown, sin backticks, sin texto extra. Sos preciso, critico y realista con el scoring. No inflas puntajes.',
      messages: [{
        role: 'user',
        content: [
          { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: pdfBase64 } },
          { type: 'text', text: promptText }
        ]
      }]
    })
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error('Claude API error ' + res.status + ': ' + t);
  }
  const data = await res.json();
  let txt = (data.content || []).map(b => b.text || '').join('').trim();
  txt = txt.replace(/^```json/i, '').replace(/^```/, '').replace(/```$/, '').trim();
  return JSON.parse(txt);
}

// ═══════════════════════════════════════
// DETECTOR DE LINKS EN EL CV
// Behance, Dribbble, Instagram, sitios propios, GitHub, etc.
// El texto extraido de un PDF conserva las URLs escritas; las levantamos
// para que no se pierdan y queden visibles en el panel y en el informe.
// ═══════════════════════════════════════
function detectarLinks(texto) {
  if (!texto) return [];
  const encontrados = new Set();
  // 1) URLs completas con protocolo
  const conProto = texto.match(/https?:\/\/[^\s"'<>()\[\]]+/gi) || [];
  conProto.forEach(u => encontrados.add(u.replace(/[.,;:]+$/, '')));
  // 2) dominios de portfolio tipicos escritos sin protocolo
  const dominios = ['behance.net', 'dribbble.com', 'artstation.com', 'cargocollective.com',
    'myportfolio.com', 'instagram.com', 'vimeo.com', 'youtube.com/@', 'github.com',
    'linkedin.com/in', 'wixsite.com', 'notion.site', 'flickr.com', 'coroflot.com'];
  dominios.forEach(d => {
    const re = new RegExp('(?:www\\.)?' + d.replace(/[.\/]/g, m => '\\' + m) + '[^\\s"\'<>()\\[\\]]*', 'gi');
    (texto.match(re) || []).forEach(u => {
      const limpio = u.replace(/[.,;:]+$/, '');
      // evitar duplicar si ya entro con protocolo
      if (![...encontrados].some(e => e.includes(limpio))) encontrados.add('https://' + limpio.replace(/^www\./, 'www.'));
    });
  });
  return [...encontrados].slice(0, 15);
}

// ═══════════════════════════════════════
// ANALISIS DE CV vs PUESTO
// ═══════════════════════════════════════
function perfilTexto(b) {
  return [
    'Empresa: ' + (b.empresa || '-') + ' (' + (b.rubro_empresa || 's/d') + ')',
    'Puesto: ' + (b.puesto || '-') + (b.area ? ' / Area: ' + b.area : ''),
    'Ubicacion/Modalidad: ' + (b.ubicacion || '-') + ' / ' + (b.modalidad || '-'),
    'Formacion minima: ' + (b.formacion_minima || '-'),
    'Experiencia minima: ' + (b.experiencia_minima || '-'),
    'Hard skills obligatorios: ' + (b.hard_skills || '-'),
    'Idiomas: ' + (b.idiomas || '-'),
    'Certificaciones: ' + (b.certificaciones || '-'),
    'Formacion deseable: ' + (b.formacion_deseable || '-'),
    'Industrias valoradas: ' + (b.industrias_valoradas || '-'),
    'Soft skills prioritarias: ' + (b.soft_skills || '-'),
    'Perfil DISC esperado: ' + (b.perfil_disc || '-'),
    'Competencias clave: ' + (b.competencias_clave || '-'),
    'EXCLUYENTES REALES (unico motivo de descarte automatico): ' + (b.deal_breakers || 'ninguno cargado')
  ].join('\n');
}

async function analizarCV(cvTexto, busqueda) {
  const p = pesosDe(busqueda.tipo_puesto);
  const links = detectarLinks(cvTexto);
  const esCreativo = (busqueda.tipo_puesto === 'creativo');
  const prompt = `Sos el mejor selector de RRHH: analiza este CV contra el perfil del puesto con criterio profesional real. Se critico y realista, pero justo: no descalifiques por defecto a alguien que no cumple al pie de la letra un requisito general si lo compensa con otra fortaleza real.

PERFIL DEL PUESTO:
${perfilTexto(busqueda)}

TIPO DE PUESTO: ${busqueda.tipo_puesto || 'general'} — ${p.nota}

${links.length ? 'LINKS DETECTADOS EN EL CV (portfolio / redes / trabajos): ' + links.join(' | ') + '\nTenelos en cuenta: si son de portfolio (Behance, Dribbble, sitio propio) es senal positiva de que el candidato muestra su trabajo. Genera al menos una pregunta de pre-entrevista que pida recorrer el portfolio juntos.' : ''}

CV DEL CANDIDATO:
${cvTexto.substring(0, 12000)}

LECTURA HUMANA (obligatoria, aplicala en el scoring y explicala en el campo lecturaHumana):
Un buen selector lee lo que el CV dice ENTRE lineas, no solo lo que lista. Aplica estas equivalencias con criterio:
- TITULO vs EXPERIENCIA: si pide titulo universitario y el candidato no lo tiene pero acumula anos de experiencia solida haciendo exactamente ese trabajo, la experiencia COMPENSA en gran parte la formacion (salvo que el titulo este en EXCLUYENTES REALES o sea matricula legal obligatoria). Puntualo en formacion como parcial, no como cero.
- AUTODIDACTAS: cursos, certificaciones informales, proyectos propios y trabajo freelance demostrable valen como formacion practica, especialmente en roles tecnicos y creativos.
- GAPS LABORALES: un hueco en el CV no es bandera roja automatica. Si hay contexto (estudio, maternidad/paternidad, emprendimiento, pandemia) no penalices; si no hay contexto, marcalo como pregunta de entrevista, no como descuento de score.
- CAMBIO DE RUBRO: skills transferibles cuentan. Un vendedor de otro rubro que domina negociacion y manejo de cartera puede rendir en este rubro; puntua la transferencia real, no la coincidencia literal de industria.
- SOBRECALIFICACION: si el candidato excede largamente el puesto, no es "mejor score automatico": marca el riesgo de fuga/desmotivacion como punto de atencion y pregunta de entrevista.
- TRAYECTORIA ASCENDENTE vs ROTACION: valora crecimiento sostenido dentro de empresas; muchas experiencias de menos de un ano seguidas si es senal a explorar en entrevista.
- LOGROS vs TAREAS: un CV que lista resultados concretos (numeros, proyectos entregados, equipos armados) vale mas que uno que lista responsabilidades genericas del puesto.${esCreativo ? `
- CRITERIO CREATIVO ESPECIFICO: en perfiles creativos el CV es la mitad de la historia. El portfolio es la otra mitad y suele pesar MAS que el titulo. Si el CV menciona portfolio o links, considera hardSkills como provisorio hasta verlo (decilo en lecturaHumana). Valora: variedad de clientes/estilos, dominio de herramientas (Suite Adobe, Figma, etc.), experiencia en el tipo de pieza que el puesto necesita (branding no es lo mismo que redes ni que editorial). No castigues trayectorias freelance: en creativos es la norma, no inestabilidad.` : ''}

PONDERACION PARA ESTE PUESTO (los maximos de cada dimension YA reflejan lo que mas importa en este tipo de rol; sumados dan 100):
- formacion: 0-${p.formacion}
- experiencia: 0-${p.experiencia}
- hardSkills: 0-${p.hardSkills}
- softSkills: 0-${p.softSkills}
- fitCultural: 0-${p.fitCultural}
El score total es la suma de las cinco dimensiones (0-100). Puntua cada una dentro de su maximo segun que tan bien el candidato la cumple.

Reglas de criterio:
- Formacion minima, experiencia minima, hard skills, idiomas y certificaciones son requisitos VALORADOS: si el candidato no los cumple al 100% pero compensa con trayectoria o nivel equivalente, baja solo esa dimension puntual, no el score entero.
- EXCLUYENTE REAL: unicamente lo que este listado en "EXCLUYENTES REALES" del perfil. Si el candidato incumple ESO especificamente, el score total no puede superar 40 y la recomendacion es "NO AVANZAR", sin importar el resto de sus fortalezas.
- Si el perfil no tiene excluyentes cargados ("ninguno cargado"), no inventes ninguno: puntua todo por merito normal, sin techo artificial.

Bandas de recomendacion (0-100):
- 85-100: AVANZAR (candidato fuerte)
- 70-84: AVANZAR
- 55-69: AVANZAR CON RESERVAS
- menos de 55: NO AVANZAR

Devolve SOLO este JSON:
{
  "nombre": "nombre del candidato extraido del CV",
  "score": 0-100,
  "formacion": 0-${p.formacion},
  "experiencia": 0-${p.experiencia},
  "hardSkills": 0-${p.hardSkills},
  "softSkills": 0-${p.softSkills},
  "fitCultural": 0-${p.fitCultural},
  "fortalezas": ["punto con evidencia del CV", "..."],
  "brechas": ["que le falta vs lo requerido", "..."],
  "excluyentesNoCumplidos": ["si hay excluyentes no cumplidos", "..."],
  "resumen": "3-4 lineas de resumen ejecutivo",
  "lecturaHumana": "3-5 lineas: la lectura entre lineas de este CV. Que equivalencias aplicaste (ej: sin titulo pero con experiencia que compensa), que te llama la atencion de la trayectoria, que contaria un selector experimentado tomando un cafe con el cliente. Lenguaje directo y humano.",
  "recomendacion": "AVANZAR" | "AVANZAR CON RESERVAS" | "NO AVANZAR",
  "preguntasPreEntrevista": [
    {"pregunta": "...", "objetivo": "que busca validar", "redFlag": "respuesta que seria senal de alarma"}
  ]
}
Genera entre 8 y 10 preguntas de pre-entrevista.`;

  const analisis = await callClaude(prompt, 4000);
  analisis.linksDetectados = links;
  return analisis;
}

// ═══════════════════════════════════════
// ANALISIS DISC vs PUESTO
// ═══════════════════════════════════════
async function analizarDISC(discTexto, busqueda, candidato) {
  const prompt = `Sos un analista conductual senior. Interpreta el resultado DISC de este candidato para el puesto y redacta un informe con lenguaje humano, no solo numeros. El cliente tiene que entender COMO es esta persona trabajando, no leer una tabla de porcentajes.

PERFIL DISC ESPERADO PARA EL PUESTO: ${busqueda.perfil_disc || 'no especificado, inferir del puesto: ' + busqueda.puesto}
COMPETENCIAS CLAVE: ${busqueda.competencias_clave || '-'}
PUESTO: ${busqueda.puesto} en ${busqueda.empresa}

RESULTADO DISC DEL CANDIDATO (ProfileGame / Conductual 360):
${discTexto.substring(0, 6000)}

Interpreta de verdad: que significan esos valores D/I/S/C combinados para el dia a dia del puesto, como toma decisiones, como se comunica, como reacciona bajo presion, como encaja con lo que el puesto necesita. Si hay perfil natural vs adaptado, comenta la diferencia (indica esfuerzo/desgaste). Se concreto y honesto, sin relleno.

Devolve SOLO este JSON:
{
  "compatibilidad": 0-100,
  "perfilResumen": "2-3 lineas: quien es esta persona en terminos conductuales, en lenguaje claro",
  "interpretacion": "informe interpretado de 5-8 lineas: como trabaja, como decide, como se comunica, como maneja la presion y el conflicto, y que significa concretamente para ESTE puesto. Redactado como lo escribiria un psicologo laboral para un cliente, no como bullets tecnicos.",
  "naturalVsAdaptado": "si los datos lo permiten, que dice la diferencia entre perfil natural y adaptado (esfuerzo, sostenibilidad en el tiempo); si no hay datos, 'sin datos suficientes'",
  "fortalezasConductuales": ["para este puesto, con explicacion breve", "..."],
  "areasAtencion": ["puntos a observar, con por que importan para este puesto", "..."],
  "estiloGestion": "como conviene liderar, comunicarse y motivar a esta persona para que rinda",
  "veredicto": "COMPATIBLE" | "COMPATIBLE CON OBSERVACIONES" | "BAJA COMPATIBILIDAD"
}`;

  return await callClaude(prompt, 2800);
}

// ═══════════════════════════════════════
// ANALISIS DE PORTFOLIO (creativos)
// Dos vias:
//  a) PDF del portfolio -> Claude lo VE pagina por pagina (vision)
//  b) Portfolio online (Behance, etc.) -> Hernan lo mira y carga sus
//     observaciones; el agente las estructura y puntua con el mismo criterio
// ═══════════════════════════════════════
function promptPortfolioBase(busqueda, candidato) {
  return `PUESTO: ${busqueda.puesto || '-'} en ${busqueda.empresa || '-'} (rubro: ${busqueda.rubro_empresa || 's/d'})
HARD SKILLS REQUERIDOS: ${busqueda.hard_skills || '-'}
COMPETENCIAS CLAVE: ${busqueda.competencias_clave || '-'}
CANDIDATO: ${candidato.nombre || '-'} (score tecnico CV: ${candidato.score != null ? candidato.score + '/100' : 's/d'})

Evalua como lo haria un director de arte tomando una decision de contratacion, no como un critico de arte:
1. CALIDAD DE EJECUCION: nivel tecnico real (tipografia, composicion, color, prolijidad, terminacion).
2. ADECUACION AL PUESTO: ¿el tipo de piezas que muestra es lo que este puesto necesita? Branding, redes, editorial, packaging, motion, web: no son intercambiables. Un portfolio brillante de ilustracion no garantiza un buen disenador de piezas comerciales.
3. VERSATILIDAD vs ESPECIALIZACION: ¿muestra rango o repite una formula? ¿Que le conviene mas a este puesto?
4. CRITERIO COMERCIAL: ¿las piezas resuelven problemas de comunicacion reales (jerarquia de informacion, llamado a la accion, marca) o son solo esteticas?
5. MADUREZ PROFESIONAL: consistencia, curaduria (¿eligio bien que mostrar?), presentacion del propio trabajo.
Se honesto: si el portfolio es flojo para el puesto, decilo con claridad y explica por que.

Devolve SOLO este JSON:
{
  "scorePortfolio": 0-100,
  "nivel": "JUNIOR" | "SEMI-SENIOR" | "SENIOR" | "NO DETERMINABLE",
  "resumen": "3-4 lineas: que muestra el portfolio y que nivel real demuestra",
  "adecuacionAlPuesto": "2-4 lineas: que tan alineado esta lo que muestra con lo que ESTE puesto necesita",
  "fortalezasVisuales": ["con ejemplo concreto de que pieza lo demuestra", "..."],
  "debilidades": ["que le falta o que flaquea, con ejemplo", "..."],
  "preguntasSobrePortfolio": ["pregunta para la entrevista sobre una pieza o decision concreta del portfolio", "..."],
  "veredicto": "PORTFOLIO FUERTE" | "PORTFOLIO ADECUADO" | "PORTFOLIO DEBIL PARA EL PUESTO"
}`;
}

async function analizarPortfolioPDF(pdfBase64, busqueda, candidato) {
  const prompt = `Sos un director creativo senior evaluando el portfolio adjunto (PDF) de un candidato. Mira TODAS las paginas: las imagenes son el contenido principal, no el texto.

` + promptPortfolioBase(busqueda, candidato);
  return await callClaudeVisionPDF(prompt, pdfBase64, 3000);
}

async function analizarPortfolioObservado(observaciones, links, busqueda, candidato) {
  const prompt = `Sos un director creativo senior. El consultor Hernan Salas reviso personalmente el portfolio online del candidato y anoto sus observaciones. Estructura y puntua ese material con criterio profesional. NO inventes piezas que no esten descriptas: basate solo en las observaciones.

LINKS DEL PORTFOLIO: ${(links || []).join(' | ') || 's/d'}

OBSERVACIONES DEL CONSULTOR SOBRE EL PORTFOLIO:
${(observaciones || '').substring(0, 6000)}

` + promptPortfolioBase(busqueda, candidato);
  return await callClaude(prompt, 3000);
}

// ═══════════════════════════════════════
// INFORME FINAL (tecnico + DISC + entrevista)
// ═══════════════════════════════════════
async function generarInformeFinal(candidato, busqueda) {
  const disc = candidato.disc_resultado ? JSON.parse(candidato.disc_resultado) : null;
  const hayEntrevista = candidato.notas_entrevista && candidato.notas_entrevista.trim().length > 0;
  const portfolio = candidato.portfolio_analisis ? safeParse(candidato.portfolio_analisis) : null;
  const pInforme = pesosDe(busqueda.tipo_puesto);
  const prompt = `Sos un consultor senior de seleccion de personal. Genera el informe final integrado de este candidato para presentar al cliente, con criterio profesional real, no un promedio mecanico de numeros.

PUESTO: ${busqueda.puesto} — ${busqueda.empresa}
TIPO DE PUESTO: ${busqueda.tipo_puesto || 'general'} — ${pInforme.nota}

SCORE TECNICO (CV vs puesto): ${candidato.score}/100 — ${candidato.recomendacion}
RESUMEN TECNICO: ${candidato.resumen || '-'}
LECTURA HUMANA DEL CV: ${candidato.lectura_humana || '-'}
FORTALEZAS: ${candidato.fortalezas || '[]'}
BRECHAS: ${candidato.brechas || '[]'}
LINKS DEL CANDIDATO: ${candidato.links_detectados || '-'}

ANALISIS DE PORTFOLIO: ${portfolio ? JSON.stringify(portfolio) : 'No realizado'}
${portfolio ? 'SCORE PORTFOLIO: ' + (candidato.portfolio_score != null ? candidato.portfolio_score + '/100' : 's/d') : ''}

ANALISIS DISC: ${disc ? JSON.stringify(disc) : 'No realizado'}
COMPATIBILIDAD DISC: ${candidato.disc_compatibilidad != null ? candidato.disc_compatibilidad + '/100' : 's/d'}

NOTAS DE LA ENTREVISTA (escritas por el consultor Hernan Salas):
${candidato.notas_entrevista || 'Sin entrevista registrada'}

COMO CALCULAR EL scoreFinal (importante):
- El score tecnico mide SOLO lo que se pudo leer del CV. Es un punto de partida, no la nota final.
- La entrevista tiene el peso mas alto cuando existe: es informacion de primera mano que el CV no puede capturar (fundamento, criterio, capacidad de defensa de ideas, actitud, comunicacion real).
- ${hayEntrevista
    ? 'HAY ENTREVISTA REGISTRADA: si en la entrevista el candidato demostro cosas que el CV no reflejaba (solidez conceptual, argumentacion, experiencia no documentada, madurez), el scoreFinal DEBE subir respecto del tecnico y reflejarlo. Al reves tambien: si en la entrevista mostro banderas rojas que el CV no anticipaba, el scoreFinal baja. No ancles el numero al score tecnico: la entrevista puede moverlo de forma significativa (10, 20 o mas puntos) en cualquier direccion, siempre que las notas lo justifiquen.'
    : 'NO HAY ENTREVISTA todavia: basate en tecnico + DISC, y aclaralo como informe preliminar.'}
- El DISC pondera como ajuste conductual, no como techo.
${portfolio ? '- HAY ANALISIS DE PORTFOLIO: ' + (busqueda.tipo_puesto === 'creativo'
    ? 'este es un puesto CREATIVO, asi que el portfolio pesa TANTO O MAS que el CV. Si el portfolio es fuerte y el CV era flojo en papel, el scoreFinal debe subir de forma significativa. Si el portfolio es debil para el puesto, baja el scoreFinal aunque el CV sea bueno: en creativos, lo que la persona produce manda sobre lo que el papel dice.'
    : 'integra el portfolio como evidencia concreta de capacidad, con peso proporcional a lo visual que sea el rol.') : ''}
- Explicita SIEMPRE en el resumen por que el scoreFinal quedo donde quedo (que aporto la entrevista, que sumo o resto respecto del CV${portfolio ? ' y del portfolio' : ''}).

${busqueda.deal_breakers ? 'RECORDATORIO: si el candidato incumple un excluyente real ('+busqueda.deal_breakers+'), la entrevista NO puede revertirlo: sigue siendo NO RECOMENDADO.' : ''}

Devolve SOLO este JSON:
{
  "scoreFinal": 0-100,
  "veredictoFinal": "RECOMENDADO" | "RECOMENDADO CON OBSERVACIONES" | "NO RECOMENDADO",
  "resumenEjecutivo": "4-6 lineas que sinteticen tecnico + conductual + entrevista, aclarando que aporto la instancia de entrevista",
  "fortalezasPrincipales": ["...", "..."],
  "puntosAtencion": ["...", "..."],
  "cierreConsultor": "parrafo final con la recomendacion de APTIA para el cliente, tono profesional"
}`;

  return await callClaude(prompt, 2500);
}

// ═══════════════════════════════════════
// EXTRAER TEXTO DE ADJUNTOS
// ═══════════════════════════════════════
async function extraerTexto(attachment) {
  const buffer = Buffer.isBuffer(attachment.content)
    ? attachment.content
    : Buffer.from(attachment.content, 'base64');
  const filename = (attachment.filename || '').toLowerCase();
  if (filename.endsWith('.pdf')) {
    const data = await pdfParse(buffer);
    return data.text;
  }
  if (filename.endsWith('.docx') || filename.endsWith('.doc')) {
    const result = await mammoth.extractRawText({ buffer });
    return result.value;
  }
  return buffer.toString('utf-8');
}

// ═══════════════════════════════════════
// EMAIL - CONFIG
// ═══════════════════════════════════════
const IMAP_CONFIG = {
  host: 'imap.gmail.com',
  port: 993,
  secure: true,
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD },
  logger: false
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
});

function colorScore(s) {
  return s >= 85 ? '🟢' : s >= 70 ? '🟡' : s >= 55 ? '🟠' : '🔴';
}

async function enviarInforme(analisis, busqueda) {
  const scoreColor = colorScore(analisis.score);
  const preguntasHtml = (analisis.preguntasPreEntrevista || []).map(function (p) {
    return '<div style="background:#0F1B3D;border-radius:8px;padding:12px;margin:8px 0;">' +
      '<p style="margin:0;color:#fff;"><strong>' + (p.pregunta || '') + '</strong></p>' +
      '<p style="margin:4px 0 0;color:#9FB2E0;font-size:13px;">Objetivo: ' + (p.objetivo || '') + '</p>' +
      '<p style="margin:2px 0 0;color:#FA8C8C;font-size:13px;">Red flag: ' + (p.redFlag || '') + '</p>' +
      '</div>';
  }).join('');

  const recColor = analisis.recomendacion === 'AVANZAR' ? '#0E8A53'
    : analisis.recomendacion === 'NO AVANZAR' ? '#FA232B' : '#C77700';

  const html =
    '<div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;background:#001C52;color:#F4F6FB;padding:30px;border-radius:14px;">' +
      '<div style="border-bottom:2px solid #FA232B;padding-bottom:14px;margin-bottom:20px;">' +
        '<h1 style="color:#fff;margin:0;font-size:26px;letter-spacing:.05em;">APTIA</h1>' +
        '<p style="color:#9FB2E0;margin:5px 0 0;font-size:11px;letter-spacing:.12em;">SELECCION DE PERSONAL INTELIGENTE Y HUMANA</p>' +
      '</div>' +
      '<h2 style="color:#fff;font-size:18px;">Nuevo CV analizado automaticamente</h2>' +
      '<div style="background:#0F1B3D;border-radius:10px;padding:20px;margin:15px 0;">' +
        '<p style="margin:0;"><strong>Candidato:</strong> ' + analisis.nombre + '</p>' +
        '<p style="margin:6px 0;"><strong>Puesto:</strong> ' + busqueda.puesto + ' — ' + busqueda.empresa + '</p>' +
        '<p style="margin:6px 0;"><strong>Score tecnico:</strong> ' + scoreColor + ' <strong style="font-size:24px;color:#fff;">' + analisis.score + '/100</strong></p>' +
        '<p style="margin:6px 0;"><strong>Recomendacion:</strong> <span style="color:' + recColor + ';font-weight:700;">' + analisis.recomendacion + '</span></p>' +
      '</div>' +
      '<p style="color:#C9D5F2;line-height:1.5;">' + (analisis.resumen || '') + '</p>' +
      (analisis.lecturaHumana
        ? '<div style="background:#0F1B3D;border-left:3px solid #FA232B;border-radius:8px;padding:14px;margin:14px 0;">' +
          '<p style="margin:0 0 4px;color:#FA8C8C;font-size:11px;letter-spacing:.1em;">LECTURA HUMANA</p>' +
          '<p style="margin:0;color:#E8EDFA;line-height:1.55;font-size:14px;">' + analisis.lecturaHumana + '</p></div>'
        : '') +
      (analisis.linksDetectados && analisis.linksDetectados.length
        ? '<p style="color:#9FB2E0;font-size:13px;"><strong style="color:#fff;">Links detectados en el CV:</strong><br>' +
          analisis.linksDetectados.map(function (l) { return '<a href="' + l + '" style="color:#7FA8FF;">' + l + '</a>'; }).join('<br>') + '</p>'
        : '') +
      '<h3 style="color:#fff;font-size:15px;margin-top:22px;">Preguntas para tu entrevista</h3>' +
      preguntasHtml +
      '<div style="text-align:center;margin-top:25px;padding-top:15px;border-top:1px solid rgba(255,255,255,.12);">' +
        '<p style="color:#9FB2E0;font-size:12px;">APTIA — Seleccion de Personal Inteligente y Humana</p>' +
        '<p style="color:#9FB2E0;font-size:12px;">aptiatalento.com</p>' +
      '</div>' +
    '</div>';

  await transporter.sendMail({
    from: '"APTIA IA" <' + process.env.GMAIL_USER + '>',
    to: process.env.NOTIFY_EMAIL || process.env.GMAIL_USER,
    subject: scoreColor + ' CV Analizado: ' + analisis.nombre + ' — ' + analisis.score + '/100 — ' + busqueda.puesto,
    html: html
  });
  console.log('📧 Informe enviado: ' + analisis.nombre + ' (' + analisis.score + '/100)');
}

// ═══════════════════════════════════════
// GUARDAR CANDIDATO ANALIZADO
// ═══════════════════════════════════════
function guardarCandidato(busqueda_id, email_origen, cvTexto, analisis) {
  const stmt = db.prepare(`
    INSERT INTO candidatos (busqueda_id, nombre, email_origen, cv_texto, score,
      formacion, experiencia, hard_skills_score, soft_skills_score, fit_cultural,
      fortalezas, brechas, excluyentes_no_cumplidos, resumen, recomendacion, preguntas,
      lectura_humana, links_detectados, estado_proceso)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Analizado')
  `);
  const r = stmt.run(
    busqueda_id, analisis.nombre, email_origen || null, cvTexto.substring(0, 5000), analisis.score,
    analisis.formacion, analisis.experiencia, analisis.hardSkills, analisis.softSkills, analisis.fitCultural,
    JSON.stringify(analisis.fortalezas || []), JSON.stringify(analisis.brechas || []),
    JSON.stringify(analisis.excluyentesNoCumplidos || []),
    analisis.resumen, analisis.recomendacion,
    JSON.stringify(analisis.preguntasPreEntrevista || []),
    analisis.lecturaHumana || null,
    JSON.stringify(analisis.linksDetectados || [])
  );
  return r.lastInsertRowid;
}

// ═══════════════════════════════════════
// MONITOR DE EMAILS
// ═══════════════════════════════════════
let monitorActivo = false;

// Detecta el codigo de busqueda en el asunto: [APT-XXXX] o APT-XXXX
function detectarCodigo(subject) {
  if (!subject) return null;
  const m = subject.toUpperCase().match(/APT-[A-Z0-9]{2,12}/);
  return m ? m[0] : null;
}

async function revisarEmails() {
  if (monitorActivo) return;
  monitorActivo = true;
  let client;
  try {
    client = new ImapFlow(IMAP_CONFIG);
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');
    try {
      const messages = client.fetch({ seen: false }, { envelope: true, source: true, uid: true });
      for await (const msg of messages) {
        const messageId = msg.envelope.messageId;
        const exists = db.prepare('SELECT id FROM emails_procesados WHERE message_id = ?').get(messageId);
        if (exists) continue;

        const parsed = await simpleParser(msg.source);
        const from = parsed.from && parsed.from.value && parsed.from.value[0] ? parsed.from.value[0].address : 'desconocido';
        const subject = parsed.subject || 'Sin asunto';
        console.log('\n📬 Nuevo email de: ' + from + ' | Asunto: ' + subject);

        const attachments = (parsed.attachments || []).filter(function (a) {
          const name = (a.filename || '').toLowerCase();
          return name.endsWith('.pdf') || name.endsWith('.docx') || name.endsWith('.doc');
        });

        // marcar procesado siempre
        function marcar() {
          db.prepare('INSERT OR IGNORE INTO emails_procesados (message_id, from_email, subject) VALUES (?, ?, ?)')
            .run(messageId, from, subject);
        }

        if (attachments.length === 0) {
          console.log('   ⏭️  Sin CV adjunto, ignorando');
          marcar();
          continue;
        }

        // 1) intentar por codigo en el asunto
        let busqueda = null;
        const codigo = detectarCodigo(subject);
        if (codigo) {
          busqueda = db.prepare("SELECT * FROM busquedas WHERE codigo = ? AND estado = 'activa'").get(codigo);
          if (busqueda) console.log('   🏷️  Codigo detectado: ' + codigo + ' -> ' + busqueda.puesto);
        }

        // 2) si no hay codigo: si hay UNA sola busqueda activa, usar esa
        if (!busqueda) {
          const activas = db.prepare("SELECT * FROM busquedas WHERE estado = 'activa' ORDER BY created_at DESC").all();
          if (activas.length === 1) {
            busqueda = activas[0];
            console.log('   ℹ️  Sin codigo, unica busqueda activa -> ' + busqueda.puesto);
          } else if (activas.length === 0) {
            console.log('   ⚠️  No hay busqueda activa, guardando CV sin asignar');
          } else {
            console.log('   ⚠️  Varias busquedas activas y sin codigo -> CV sin asignar (revisar en panel)');
          }
        }

        try {
          let cvTexto = '';
          for (const att of attachments) {
            cvTexto += '\n' + await extraerTexto(att);
          }
          if (!cvTexto.trim()) { console.log('   ⚠️  No se pudo extraer texto del CV'); marcar(); continue; }

          if (busqueda) {
            const analisis = await analizarCV(cvTexto, busqueda);
            guardarCandidato(busqueda.id, from, cvTexto, analisis);
            await enviarInforme(analisis, busqueda);
          } else {
            // guardar sin asignar para que Hernan lo ubique en el panel
            db.prepare(`INSERT INTO candidatos (busqueda_id, nombre, email_origen, cv_texto, estado_proceso)
                        VALUES (NULL, ?, ?, ?, 'Sin asignar')`)
              .run((from.split('@')[0] || 'Candidato'), from, cvTexto.substring(0, 5000));
            console.log('   📥 CV guardado sin asignar');
          }
          marcar();
        } catch (e) {
          console.log('   ❌ Error procesando CV: ' + e.message);
          marcar();
        }
      }
    } finally {
      lock.release();
    }
  } catch (err) {
    console.log('❌ Error monitor IMAP: ' + err.message);
  } finally {
    if (client) { try { await client.logout(); } catch (e) {} }
    monitorActivo = false;
  }
}

// ═══════════════════════════════════════
// API
// ═══════════════════════════════════════

// Generar codigo unico tipo APT-XXXX
function generarCodigo(puesto) {
  const base = (puesto || 'BUS').toUpperCase().replace(/[^A-Z]/g, '').substring(0, 4) || 'BUS';
  let codigo, intentos = 0;
  do {
    const n = Math.floor(100 + Math.random() * 900);
    codigo = 'APT-' + base + n;
    intentos++;
  } while (db.prepare('SELECT id FROM busquedas WHERE codigo = ?').get(codigo) && intentos < 20);
  return codigo;
}

// Crear busqueda
app.post('/api/busquedas', (req, res) => {
  const b = req.body || {};
  if (!b.empresa || !b.puesto) return res.status(400).json({ error: 'Faltan empresa y puesto' });
  const codigo = b.codigo || generarCodigo(b.puesto);
  const campos = ['codigo','empresa','rubro_empresa','contacto_nombre','contacto_email','puesto','area','reporta_a',
    'ubicacion','modalidad','contratacion','jornada','salario_desde','salario_hasta','moneda','fecha_objetivo',
    'posiciones','formacion_minima','experiencia_minima','hard_skills','idiomas','certificaciones','disponibilidad',
    'formacion_deseable','industrias_valoradas','soft_skills','perfil_disc','competencias_clave','motivo_busqueda',
    'deal_breakers','proceso_cliente','publicar_web','tipo_puesto'];
  const vals = campos.map(c => c === 'codigo' ? codigo : (b[c] !== undefined ? b[c] : null));
  const placeholders = campos.map(() => '?').join(',');
  const stmt = db.prepare('INSERT INTO busquedas (' + campos.join(',') + ') VALUES (' + placeholders + ')');
  const r = stmt.run.apply(stmt, vals);
  res.json({ id: r.lastInsertRowid, codigo: codigo });
});

// Listar busquedas (todas, para el panel)
app.get('/api/busquedas/all', (req, res) => {
  res.json(db.prepare('SELECT * FROM busquedas ORDER BY created_at DESC').all());
});

// Listar busquedas activas PARA LA WEB (solo las publicables)
app.get('/api/busquedas', (req, res) => {
  const rows = db.prepare("SELECT id, codigo, empresa, area, puesto, ubicacion, modalidad, jornada FROM busquedas WHERE estado = 'activa' AND publicar_web = 1 ORDER BY created_at DESC").all();
  res.json(rows);
});

// Editar busqueda (cualquier campo, incluido estado y publicar_web)
app.patch('/api/busquedas/:id', (req, res) => {
  const body = req.body || {};
  const campos = ['empresa','rubro_empresa','contacto_nombre','contacto_email','puesto','area','reporta_a',
    'ubicacion','modalidad','contratacion','jornada','salario_desde','salario_hasta','moneda','fecha_objetivo',
    'posiciones','formacion_minima','experiencia_minima','hard_skills','idiomas','certificaciones','disponibilidad',
    'formacion_deseable','industrias_valoradas','soft_skills','perfil_disc','competencias_clave','motivo_busqueda',
    'deal_breakers','proceso_cliente','estado','tipo_puesto'];
  campos.forEach(function(c){
    if (body[c] !== undefined) db.prepare('UPDATE busquedas SET ' + c + ' = ? WHERE id = ?').run(body[c], req.params.id);
  });
  if (body.publicar_web !== undefined) db.prepare('UPDATE busquedas SET publicar_web = ? WHERE id = ?').run(body.publicar_web ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

// Listar candidatos (opcional por busqueda)
app.get('/api/candidatos', (req, res) => {
  const { busqueda_id } = req.query;
  let rows;
  if (busqueda_id) {
    rows = db.prepare('SELECT * FROM candidatos WHERE busqueda_id = ? ORDER BY COALESCE(score_final, score, 0) DESC').all(busqueda_id);
  } else {
    rows = db.prepare('SELECT * FROM candidatos ORDER BY created_at DESC').all();
  }
  rows = rows.map(parseCand);
  res.json(rows);
});

app.get('/api/candidatos/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'No encontrado' });
  res.json(parseCand(row));
});

function parseCand(r) {
  return Object.assign({}, r, {
    fortalezas: JSON.parse(r.fortalezas || '[]'),
    brechas: JSON.parse(r.brechas || '[]'),
    excluyentes_no_cumplidos: JSON.parse(r.excluyentes_no_cumplidos || '[]'),
    preguntas: JSON.parse(r.preguntas || '[]'),
    disc_resultado: r.disc_resultado ? safeParse(r.disc_resultado) : null,
    informe_final: r.informe_final ? safeParse(r.informe_final) : null,
    links_detectados: r.links_detectados ? safeParse(r.links_detectados) : [],
    portfolio_analisis: r.portfolio_analisis ? safeParse(r.portfolio_analisis) : null
  });
}
function safeParse(s) { try { return JSON.parse(s); } catch (e) { return s; } }

// Analisis manual de CV (lo sube Hernan eligiendo busqueda)
app.post('/api/analizar', async (req, res) => {
  const { busqueda_id, cv_texto, candidato_id } = req.body || {};
  if (!busqueda_id || !cv_texto) return res.status(400).json({ error: 'Faltan datos' });
  const busqueda = db.prepare('SELECT * FROM busquedas WHERE id = ?').get(busqueda_id);
  if (!busqueda) return res.status(404).json({ error: 'Busqueda no encontrada' });
  try {
    const analisis = await analizarCV(cv_texto, busqueda);
    let id;
    if (candidato_id) {
      // reasignar un CV que estaba "sin asignar"
      db.prepare(`UPDATE candidatos SET busqueda_id=?, nombre=?, score=?, formacion=?, experiencia=?,
        hard_skills_score=?, soft_skills_score=?, fit_cultural=?, fortalezas=?, brechas=?,
        excluyentes_no_cumplidos=?, resumen=?, recomendacion=?, preguntas=?,
        lectura_humana=?, links_detectados=?, estado_proceso='Analizado'
        WHERE id=?`).run(
        busqueda_id, analisis.nombre, analisis.score, analisis.formacion, analisis.experiencia,
        analisis.hardSkills, analisis.softSkills, analisis.fitCultural,
        JSON.stringify(analisis.fortalezas || []), JSON.stringify(analisis.brechas || []),
        JSON.stringify(analisis.excluyentesNoCumplidos || []), analisis.resumen, analisis.recomendacion,
        JSON.stringify(analisis.preguntasPreEntrevista || []),
        analisis.lecturaHumana || null, JSON.stringify(analisis.linksDetectados || []),
        candidato_id);
      id = candidato_id;
    } else {
      id = guardarCandidato(busqueda_id, null, cv_texto, analisis);
    }
    try { await enviarInforme(analisis, busqueda); } catch (e) { console.log('aviso: no se pudo mandar mail: ' + e.message); }
    res.json(Object.assign({ id: id }, analisis));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cargar resultado DISC y calcular compatibilidad
app.post('/api/candidatos/:id/disc', async (req, res) => {
  const { disc_texto } = req.body || {};
  const cand = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(req.params.id);
  if (!cand) return res.status(404).json({ error: 'Candidato no encontrado' });
  // Texto vacio = limpiar el DISC actual para volver a cargar uno nuevo desde el panel
  if (!disc_texto || !disc_texto.trim()) {
    db.prepare("UPDATE candidatos SET disc_resultado=NULL, disc_compatibilidad=NULL WHERE id=?").run(req.params.id);
    return res.json({ ok: true, limpiado: true });
  }
  const busqueda = db.prepare('SELECT * FROM busquedas WHERE id = ?').get(cand.busqueda_id);
  try {
    const disc = await analizarDISC(disc_texto, busqueda || {}, cand);
    db.prepare("UPDATE candidatos SET disc_resultado=?, disc_compatibilidad=?, estado_proceso='Con DISC' WHERE id=?")
      .run(JSON.stringify(disc), disc.compatibilidad, req.params.id);
    res.json(disc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Analizar portfolio (creativos): PDF en base64 (Claude lo VE) u observaciones del consultor
app.post('/api/candidatos/:id/portfolio', async (req, res) => {
  const { pdf_base64, observaciones, links } = req.body || {};
  const cand = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(req.params.id);
  if (!cand) return res.status(404).json({ error: 'Candidato no encontrado' });
  // Vacio = limpiar para volver a cargar
  if (!pdf_base64 && (!observaciones || !observaciones.trim())) {
    db.prepare('UPDATE candidatos SET portfolio_analisis=NULL, portfolio_score=NULL WHERE id=?').run(req.params.id);
    return res.json({ ok: true, limpiado: true });
  }
  const busqueda = db.prepare('SELECT * FROM busquedas WHERE id = ?').get(cand.busqueda_id) || {};
  try {
    let resultado;
    if (pdf_base64) {
      resultado = await analizarPortfolioPDF(pdf_base64, busqueda, cand);
      resultado.origen = 'PDF analizado visualmente por IA';
    } else {
      const linksGuardados = cand.links_detectados ? safeParse(cand.links_detectados) : [];
      resultado = await analizarPortfolioObservado(observaciones, links || linksGuardados, busqueda, cand);
      resultado.origen = 'Observaciones del consultor sobre portfolio online';
    }
    db.prepare("UPDATE candidatos SET portfolio_analisis=?, portfolio_score=? WHERE id=?")
      .run(JSON.stringify(resultado), resultado.scorePortfolio, req.params.id);
    res.json(resultado);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Guardar notas de entrevista
app.post('/api/candidatos/:id/entrevista', (req, res) => {
  const { notas } = req.body || {};
  if (!notas) return res.status(400).json({ error: 'Faltan notas' });
  db.prepare("UPDATE candidatos SET notas_entrevista=?, estado_proceso='Entrevistado' WHERE id=?")
    .run(notas, req.params.id);
  res.json({ ok: true });
});

// Generar informe final integrado
app.post('/api/candidatos/:id/informe-final', async (req, res) => {
  const cand = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(req.params.id);
  if (!cand) return res.status(404).json({ error: 'Candidato no encontrado' });
  const busqueda = db.prepare('SELECT * FROM busquedas WHERE id = ?').get(cand.busqueda_id);
  try {
    const informe = await generarInformeFinal(cand, busqueda || {});
    db.prepare("UPDATE candidatos SET informe_final=?, score_final=?, estado_proceso='Informe final' WHERE id=?")
      .run(JSON.stringify(informe), informe.scoreFinal, req.params.id);
    res.json(informe);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Borrar candidato
app.delete('/api/candidatos/:id', (req, res) => {
  db.prepare('DELETE FROM candidatos WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Stats
app.get('/api/stats', (req, res) => {
  const { busqueda_id } = req.query;
  const where = busqueda_id ? ' WHERE busqueda_id = ' + Number(busqueda_id) : '';
  const candidatos = db.prepare('SELECT COUNT(*) t FROM candidatos' + where).get().t;
  const avanzar = db.prepare("SELECT COUNT(*) t FROM candidatos WHERE recomendacion = 'AVANZAR'" + (busqueda_id ? ' AND busqueda_id = ' + Number(busqueda_id) : '')).get().t;
  const prom = db.prepare('SELECT AVG(score) a FROM candidatos' + where).get().a || 0;
  const activas = db.prepare("SELECT COUNT(*) t FROM busquedas WHERE estado = 'activa'").get().t;
  res.json({ candidatos, avanzar, activas, scorePromedio: Math.round(prom) });
});

// Forzar revision de mails
app.post('/api/monitor/check', async (req, res) => {
  revisarEmails();
  res.json({ message: 'Revision disparada' });
});

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'aptia-server', v: '2.0.0' }));
app.get('/', (req, res) => res.json({ service: 'APTIA agente', estado: 'online', endpoints: ['/api/busquedas', '/api/candidatos', '/api/stats'] }));

// ═══════════════════════════════════════
// ARRANQUE
// ═══════════════════════════════════════
const PORT = process.env.PORT || 3000;
const CHECK_INTERVAL = parseInt(process.env.CHECK_INTERVAL || '120000', 10);

app.listen(PORT, () => {
  console.log('🚀 APTIA server v2.0.0 escuchando en puerto ' + PORT);
  console.log('📨 Monitor de Gmail cada ' + (CHECK_INTERVAL / 1000) + 's');
  setTimeout(revisarEmails, 5000);
  setInterval(revisarEmails, CHECK_INTERVAL);
});
