require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json({ limit: '12mb' }));

// ═══════════════════════════════════════
// BASE DE DATOS
// ═══════════════════════════════════════
const db = new Database(process.env.DB_PATH || './aptia.db');
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
ensureColumn('candidatos', 'notas_entrevista', 'TEXT');
ensureColumn('candidatos', 'score_final', 'INTEGER');
ensureColumn('candidatos', 'informe_final', 'TEXT');
ensureColumn('candidatos', 'estado_proceso', "TEXT DEFAULT 'Analizado'");

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
    'Deal breakers: ' + (b.deal_breakers || '-')
  ].join('\n');
}

async function analizarCV(cvTexto, busqueda) {
  const prompt = `Analiza este CV contra el perfil del puesto. Se critico y realista.

PERFIL DEL PUESTO:
${perfilTexto(busqueda)}

CV DEL CANDIDATO:
${cvTexto.substring(0, 12000)}

Reglas de scoring (0-100):
- Si NO cumple un requisito EXCLUYENTE (formacion minima, experiencia minima, hard skill obligatorio, idioma, certificacion, deal breaker): score maximo 40 y recomendacion "NO AVANZAR".
- 85-100: AVANZAR (candidato fuerte)
- 70-84: AVANZAR
- 55-69: AVANZAR CON RESERVAS
- menos de 55: NO AVANZAR

Devolve SOLO este JSON:
{
  "nombre": "nombre del candidato extraido del CV",
  "score": 0-100,
  "formacion": 0-20,
  "experiencia": 0-25,
  "hardSkills": 0-25,
  "softSkills": 0-15,
  "fitCultural": 0-15,
  "fortalezas": ["punto con evidencia del CV", "..."],
  "brechas": ["que le falta vs lo requerido", "..."],
  "excluyentesNoCumplidos": ["si hay excluyentes no cumplidos", "..."],
  "resumen": "3-4 lineas de resumen ejecutivo",
  "recomendacion": "AVANZAR" | "AVANZAR CON RESERVAS" | "NO AVANZAR",
  "preguntasPreEntrevista": [
    {"pregunta": "...", "objetivo": "que busca validar", "redFlag": "respuesta que seria senal de alarma"}
  ]
}
Genera entre 8 y 10 preguntas de pre-entrevista.`;

  return await callClaude(prompt, 4000);
}

// ═══════════════════════════════════════
// REANALISIS CON ENTREVISTA
// La entrevista es evidencia nueva que mueve el score en los dos sentidos.
// ═══════════════════════════════════════
async function reanalizarConEntrevista(cvTexto, busqueda, cand) {
  const disc = cand.disc_resultado ? safeParse(cand.disc_resultado) : null;
  const prompt = `Reanaliza a este candidato. Ya tenias su CV; ahora sumas lo que paso en la entrevista.
La entrevista es EVIDENCIA NUEVA y puede mover el puntaje para arriba o para abajo. NO devuelvas el mismo analisis sin cambios: tenes que reajustar segun lo que se confirmo o se cayo en la entrevista.

PERFIL DEL PUESTO:
${perfilTexto(busqueda)}

CV DEL CANDIDATO:
${cvTexto.substring(0, 12000)}

ANALISIS PREVIO (solo CV): score ${cand.score}/100 — ${cand.recomendacion || '-'}
DISC: ${disc ? JSON.stringify(disc) : 'No realizado'}

NOTAS DE LA ENTREVISTA (lectura del consultor):
${cand.notas_entrevista}

Reglas para reajustar el SCORE TECNICO:
- Si en la entrevista DEMOSTRO conocimiento o experiencia que el CV no dejaba ver, SUBI el tecnico y explica por que. Un CV pobre no condena a alguien que en la entrevista demuestra que sabe.
- Si NO pudo sostener lo que decia el CV (no supo explicar, se contradijo), BAJA el tecnico. La gente a veces infla el CV.
- El ajuste tiene que estar justificado por la entrevista, no por simpatia. La lectura sigue siendo rigurosa.
- Los excluyentes reales siguen siendo excluyentes, salvo que la entrevista demuestre que en realidad SI se cumplen.

Reajusta tambien formacion, experiencia, hardSkills, softSkills y fitCultural segun lo confirmado. Reescribi resumen, fortalezas y brechas integrando CV + entrevista (no solo el CV).

Devolve SOLO este JSON (mismas claves de siempre):
{
  "nombre": "nombre del candidato",
  "score": 0-100,
  "formacion": 0-20,
  "experiencia": 0-25,
  "hardSkills": 0-25,
  "softSkills": 0-15,
  "fitCultural": 0-15,
  "fortalezas": ["punto con evidencia de CV o entrevista", "..."],
  "brechas": ["que sigue faltando", "..."],
  "excluyentesNoCumplidos": ["si queda alguno sin cumplir", "..."],
  "resumen": "3-4 lineas integrando CV + entrevista; deci si el score subio o bajo respecto del CV y por que",
  "recomendacion": "AVANZAR" | "AVANZAR CON RESERVAS" | "NO AVANZAR"
}`;

  return await callClaude(prompt, 4000);
}

// ═══════════════════════════════════════
// ANALISIS DISC vs PUESTO
// ═══════════════════════════════════════
async function analizarDISC(discTexto, busqueda, candidato) {
  const prompt = `Analiza la compatibilidad conductual (DISC) del candidato con el puesto.

PERFIL DISC ESPERADO PARA EL PUESTO: ${busqueda.perfil_disc || 'no especificado, inferir del puesto: ' + busqueda.puesto}
COMPETENCIAS CLAVE: ${busqueda.competencias_clave || '-'}
PUESTO: ${busqueda.puesto} en ${busqueda.empresa}

RESULTADO DISC DEL CANDIDATO (ProfileGame / Conductual 360):
${discTexto.substring(0, 6000)}

Devolve SOLO este JSON:
{
  "compatibilidad": 0-100,
  "perfilResumen": "resumen del perfil conductual del candidato (D/I/S/C dominantes)",
  "fortalezasConductuales": ["para este puesto", "..."],
  "areasAtencion": ["puntos a observar", "..."],
  "estiloGestion": "estilo de gestion/comunicacion recomendado con esta persona",
  "veredicto": "COMPATIBLE" | "COMPATIBLE CON OBSERVACIONES" | "BAJA COMPATIBILIDAD"
}`;

  return await callClaude(prompt, 2000);
}

// ═══════════════════════════════════════
// INFORME FINAL (tecnico + DISC + entrevista)
// ═══════════════════════════════════════
async function generarInformeFinal(candidato, busqueda) {
  const disc = candidato.disc_resultado ? safeParse(candidato.disc_resultado) : null;
  const prompt = `Genera el informe final integrado de este candidato. Este informe lo LEE LA EMPRESA CLIENTE, no el consultor.

REGLAS DE REDACCION (importante):
- Escribi para la empresa cliente, en tono profesional y en tercera persona sobre el candidato. Es APTIA presentando el perfil a la empresa. No te dirijas al consultor, no uses "te recomiendo".
- No menciones a Hernan ni "el consultor" ni "segun las notas". Usa la entrevista como insumo para tu conclusion, sin citarla.
- No reproduzcas las preguntas de la entrevista ni el detalle DISC letra por letra. Solo la sintesis integrada y su conclusion.
- Se honesto: si hay reservas, decilas con criterio profesional.

PUESTO: ${busqueda.puesto} — ${busqueda.empresa}

SCORE TECNICO (CV vs puesto): ${candidato.score}/100 — ${candidato.recomendacion}
RESUMEN TECNICO: ${candidato.resumen || '-'}
FORTALEZAS: ${candidato.fortalezas || '[]'}
BRECHAS: ${candidato.brechas || '[]'}

ANALISIS DISC: ${disc ? JSON.stringify(disc) : 'No realizado'}
COMPATIBILIDAD DISC: ${candidato.disc_compatibilidad != null ? candidato.disc_compatibilidad + '/100' : 's/d'}

NOTAS DE LA ENTREVISTA (escritas por el consultor Hernan Salas):
${candidato.notas_entrevista || 'Sin entrevista registrada'}

Integra las tres capas (tecnica, conductual y la entrevista) en una sola sintesis para el cliente. Devolve SOLO este JSON:
{
  "scoreFinal": 0-100,
  "veredictoFinal": "RECOMENDADO" | "RECOMENDADO CON OBSERVACIONES" | "NO RECOMENDADO",
  "resumenEjecutivo": "4-6 lineas que sinteticen tecnico + conductual + entrevista",
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
      fortalezas, brechas, excluyentes_no_cumplidos, resumen, recomendacion, preguntas, estado_proceso)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Analizado')
  `);
  const r = stmt.run(
    busqueda_id, analisis.nombre, email_origen || null, cvTexto.substring(0, 5000), analisis.score,
    analisis.formacion, analisis.experiencia, analisis.hardSkills, analisis.softSkills, analisis.fitCultural,
    JSON.stringify(analisis.fortalezas || []), JSON.stringify(analisis.brechas || []),
    JSON.stringify(analisis.excluyentesNoCumplidos || []),
    analisis.resumen, analisis.recomendacion,
    JSON.stringify(analisis.preguntasPreEntrevista || [])
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
    'deal_breakers','proceso_cliente','publicar_web'];
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

// Cambiar estado de busqueda (activa / cerrada)
app.patch('/api/busquedas/:id', (req, res) => {
  const { estado, publicar_web } = req.body || {};
  if (estado !== undefined) db.prepare('UPDATE busquedas SET estado = ? WHERE id = ?').run(estado, req.params.id);
  if (publicar_web !== undefined) db.prepare('UPDATE busquedas SET publicar_web = ? WHERE id = ?').run(publicar_web ? 1 : 0, req.params.id);
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
    informe_final: r.informe_final ? safeParse(r.informe_final) : null
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
    let candExistente = null;
    if (candidato_id) candExistente = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(candidato_id);
    const tieneEntrevista = !!(candExistente && candExistente.notas_entrevista && candExistente.notas_entrevista.trim());

    // Si ya hay entrevista cargada, la entrevista es evidencia que mueve el score. Si no, analisis normal de CV.
    const analisis = tieneEntrevista
      ? await reanalizarConEntrevista(cv_texto, busqueda, candExistente)
      : await analizarCV(cv_texto, busqueda);

    // En el reanalisis con entrevista conservamos las preguntas ya generadas.
    if (tieneEntrevista) analisis.preguntasPreEntrevista = candExistente.preguntas ? safeParse(candExistente.preguntas) : [];

    let id;
    if (candidato_id) {
      // reasignar un CV que estaba "sin asignar" o reanalizar un candidato existente
      db.prepare(`UPDATE candidatos SET busqueda_id=?, nombre=?, score=?, formacion=?, experiencia=?,
        hard_skills_score=?, soft_skills_score=?, fit_cultural=?, fortalezas=?, brechas=?,
        excluyentes_no_cumplidos=?, resumen=?, recomendacion=?, preguntas=?, estado_proceso='Analizado'
        WHERE id=?`).run(
        busqueda_id, analisis.nombre, analisis.score, analisis.formacion, analisis.experiencia,
        analisis.hardSkills, analisis.softSkills, analisis.fitCultural,
        JSON.stringify(analisis.fortalezas || []), JSON.stringify(analisis.brechas || []),
        JSON.stringify(analisis.excluyentesNoCumplidos || []), analisis.resumen, analisis.recomendacion,
        JSON.stringify(analisis.preguntasPreEntrevista || []), candidato_id);
      if (tieneEntrevista) db.prepare("UPDATE candidatos SET estado_proceso='Reanalizado c/entrevista' WHERE id=?").run(candidato_id);
      id = candidato_id;
    } else {
      id = guardarCandidato(busqueda_id, null, cv_texto, analisis);
    }
    // El mail de "CV analizado + preguntas" solo tiene sentido antes de la entrevista.
    if (!tieneEntrevista) {
      try { await enviarInforme(analisis, busqueda); } catch (e) { console.log('aviso: no se pudo mandar mail: ' + e.message); }
    }
    res.json(Object.assign({ id: id }, analisis));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cargar resultado DISC y calcular compatibilidad
app.post('/api/candidatos/:id/disc', async (req, res) => {
  const { disc_texto } = req.body || {};
  if (!disc_texto) return res.status(400).json({ error: 'Falta el resultado DISC' });
  const cand = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(req.params.id);
  if (!cand) return res.status(404).json({ error: 'Candidato no encontrado' });
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
