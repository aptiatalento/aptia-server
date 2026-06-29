require('dotenv').config();
const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ═══════════════════════════════════════
// BASE DE DATOS
// ═══════════════════════════════════════
const db = new Database(process.env.DB_PATH || './aptia.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS busquedas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empresa TEXT NOT NULL,
    rubro_empresa TEXT,
    contacto_nombre TEXT,
    contacto_email TEXT,
    puesto TEXT NOT NULL,
    area TEXT,
    reporta_a TEXT,
    ubicacion TEXT,
    modalidad TEXT DEFAULT 'Presencial',
    contratacion TEXT DEFAULT 'Relación de dependencia',
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
    estado TEXT DEFAULT 'activa',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS candidatos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    busqueda_id INTEGER NOT NULL,
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

// ═══════════════════════════════════════
// CLAUDE API
// ═══════════════════════════════════════
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;

async function callClaude(prompt) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 4000,
      system: `Sos el motor de IA de APTIA, consultora de selección en Argentina. Respondé SOLO en JSON válido sin markdown ni backticks ni texto extra. Sé preciso y crítico con el scoring. Si un requisito excluyente no se cumple, score máximo 40 y recomendación "NO AVANZAR". Score>=85: "AVANZAR", 70-84: "AVANZAR", 55-69: "AVANZAR CON RESERVAS", <55: "NO AVANZAR".`,
      messages: [{ role: 'user', content: prompt }]
    })
  });
  const data = await res.json();
  const txt = (data.content || []).map(c => c.text || '').join('');
  return JSON.parse(txt.replace(/```json|```/g, '').trim());
}

async function analizarCV(cvTexto, busqueda) {
  const perfil = `Puesto: ${busqueda.puesto}
Empresa: ${busqueda.empresa} (${busqueda.rubro_empresa || ''})
Área: ${busqueda.area || ''}
Formación mínima: ${busqueda.formacion_minima || 'No especificada'}
Experiencia mínima: ${busqueda.experiencia_minima || 'No especificada'}
Hard skills obligatorios: ${busqueda.hard_skills || 'No especificados'}
Idiomas: ${busqueda.idiomas || 'No requeridos'}
Certificaciones: ${busqueda.certificaciones || 'No requeridas'}
Soft skills valoradas: ${busqueda.soft_skills || 'No especificadas'}
Perfil DISC esperado: ${busqueda.perfil_disc || 'No especificado'}
Deal breakers: ${busqueda.deal_breakers || 'Ninguno'}
Modalidad: ${busqueda.modalidad} | Jornada: ${busqueda.jornada}
Salario: ${busqueda.salario_desde || '?'}-${busqueda.salario_hasta || '?'} ${busqueda.moneda}`;

  const prompt = `Analizá este CV contra el perfil del puesto y devolvé el JSON.

PERFIL DEL PUESTO:
${perfil}

CV DEL CANDIDATO:
${cvTexto}

Respondé con este JSON exacto:
{"nombre":"nombre completo","score":0,"formacion":0,"experiencia":0,"hardSkills":0,"softSkills":0,"fitCultural":0,"fortalezas":["f1","f2","f3"],"brechas":["b1","b2"],"excluyentesNoCumplidos":[],"deseablesCumplidos":[],"resumen":"resumen de 3-4 lineas","recomendacion":"AVANZAR","preguntasPreEntrevista":[{"pregunta":"texto","objetivo":"que validamos","redFlag":"que seria preocupante"}]}`;

  return await callClaude(prompt);
}

// ═══════════════════════════════════════
// EXTRACCIÓN DE CV
// ═══════════════════════════════════════
async function extraerTextoCV(attachment) {
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

  // Intentar como texto plano
  return buffer.toString('utf-8');
}

// ═══════════════════════════════════════
// EMAIL - LEER Y ENVIAR
// ═══════════════════════════════════════
const IMAP_CONFIG = {
  host: 'imap.gmail.com',
  port: 993,
  secure: true,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  },
  logger: false
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

async function enviarInforme(candidato, busqueda, analisis) {
  const scoreColor = analisis.score >= 85 ? '🟢' : analisis.score >= 70 ? '🟡' : analisis.score >= 55 ? '🟠' : '🔴';

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0B1026;color:#F5F2ED;padding:30px;border-radius:12px;">
      <div style="border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:15px;margin-bottom:20px;">
        <h1 style="color:#FA232B;margin:0;font-size:24px;">APTIA <span style="color:#F5F2ED">_</span></h1>
        <p style="color:#9A9BAF;margin:5px 0 0;font-size:12px;">CONSULTORA DE TALENTO & IA</p>
      </div>

      <h2 style="color:#FA232B;font-size:18px;">Nuevo CV analizado automáticamente</h2>

      <div style="background:#131A3A;border-radius:10px;padding:20px;margin:15px 0;">
        <p style="margin:0;"><strong>Candidato:</strong> ${analisis.nombre}</p>
        <p style="margin:5px 0;"><strong>Puesto:</strong> ${busqueda.puesto} — ${busqueda.empresa}</p>
        <p style="margin:5px 0;"><strong>Score:</strong> ${scoreColor} <strong style="font-size:24px;color:#FA232B;">${analisis.score}/100</strong></p>
        <p style="margin:5px 0;"><strong>Recomendación:</strong> <span style="color:${analisis.recomendacion === 'AVANZAR' ? '#4ECB71' : analisis.recomendacion === 'NO AVANZAR' ? '#EF4444' : '#F59E0B'}">${analisis.recomendacion}</span></p>
      </div>

      <div style="background:#131A3A;border-radius:10px;padding:20px;margin:15px 0;">
        <h3 style="color:#FA232B;margin-top:0;">Desglose</h3>
        <p>Formación: ${analisis.formacion}/20 | Experiencia: ${analisis.experiencia}/25 | Hard Skills: ${analisis.hardSkills}/25</p>
        <p>Soft Skills: ${analisis.softSkills}/15 | Fit Cultural: ${analisis.fitCultural}/15</p>
      </div>

      <div style="background:#131A3A;border-radius:10px;padding:20px;margin:15px 0;">
        <h3 style="color:#4ECB71;margin-top:0;">✅ Fortalezas</h3>
        ${analisis.fortalezas.map(f => `<p style="margin:3px 0;">• ${f}</p>`).join('')}
      </div>

      <div style="background:#131A3A;border-radius:10px;padding:20px;margin:15px 0;">
        <h3 style="color:#F59E0B;margin-top:0;">⚠️ Brechas</h3>
        ${analisis.brechas.map(b => `<p style="margin:3px 0;">• ${b}</p>`).join('')}
        ${analisis.excluyentesNoCumplidos && analisis.excluyentesNoCumplidos.length > 0 ?
          `<h4 style="color:#EF4444;">🔴 Excluyentes no cumplidos:</h4>${analisis.excluyentesNoCumplidos.map(e => `<p style="color:#EF4444;margin:3px 0;">• ${e}</p>`).join('')}` : ''}
      </div>

      <div style="background:#131A3A;border-radius:10px;padding:20px;margin:15px 0;">
        <h3 style="color:#FA232B;margin-top:0;">📝 Resumen</h3>
        <p>${analisis.resumen}</p>
      </div>

      <div style="background:#131A3A;border-radius:10px;padding:20px;margin:15px 0;">
        <h3 style="color:#FA232B;margin-top:0;">🎯 Preguntas para pre-entrevista</h3>
        ${(analisis.preguntasPreEntrevista || []).map((p, i) =>
          `<div style="border-bottom:1px solid rgba(255,255,255,0.05);padding:8px 0;">
            <p style="margin:0;"><strong>${i + 1}. ${p.pregunta}</strong></p>
            <p style="margin:2px 0;color:#9A9BAF;font-size:13px;">Objetivo: ${p.objetivo}</p>
            <p style="margin:2px 0;color:#EF4444;font-size:13px;">Red flag: ${p.redFlag}</p>
          </div>`).join('')}
      </div>

      <div style="text-align:center;margin-top:25px;padding-top:15px;border-top:1px solid rgba(255,255,255,0.1);">
        <p style="color:#9A9BAF;font-size:12px;">APTIA — Consultora de Talento & IA</p>
        <p style="color:#9A9BAF;font-size:12px;">aptia-talento.netlify.app</p>
      </div>
    </div>`;

  await transporter.sendMail({
    from: `"APTIA IA" <${process.env.GMAIL_USER}>`,
    to: process.env.NOTIFY_EMAIL || process.env.GMAIL_USER,
    subject: `${scoreColor} CV Analizado: ${analisis.nombre} — ${analisis.score}/100 — ${busqueda.puesto}`,
    html
  });

  console.log(`📧 Informe enviado: ${analisis.nombre} (${analisis.score}/100)`);
}

// ═══════════════════════════════════════
// MONITOR DE EMAILS
// ═══════════════════════════════════════
let monitorActivo = false;

async function revisarEmails() {
  if (monitorActivo) return;
  monitorActivo = true;

  try {
    const client = new ImapFlow(IMAP_CONFIG);
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');

    try {
      // Buscar emails no leídos
      const messages = client.fetch({ seen: false }, {
        envelope: true,
        source: true,
        uid: true
      });

      for await (const msg of messages) {
        const messageId = msg.envelope.messageId;

        // Verificar si ya fue procesado
        const exists = db.prepare('SELECT id FROM emails_procesados WHERE message_id = ?').get(messageId);
        if (exists) continue;

        // Parsear email
        const parsed = await simpleParser(msg.source);
        const from = parsed.from?.value?.[0]?.address || 'desconocido';
        const subject = parsed.subject || 'Sin asunto';

        console.log(`\n📬 Nuevo email de: ${from} | Asunto: ${subject}`);

        // Buscar adjuntos CV
        const attachments = (parsed.attachments || []).filter(a => {
          const name = (a.filename || '').toLowerCase();
          return name.endsWith('.pdf') || name.endsWith('.docx') || name.endsWith('.doc');
        });

        if (attachments.length === 0) {
          console.log('   ⏭️  Sin CV adjunto, ignorando');
          db.prepare('INSERT OR IGNORE INTO emails_procesados (message_id, from_email, subject) VALUES (?, ?, ?)')
            .run(messageId, from, subject);
          continue;
        }

        // Obtener búsqueda activa (la más reciente)
        const busquedaActiva = db.prepare('SELECT * FROM busquedas WHERE estado = ? ORDER BY created_at DESC LIMIT 1').get('activa');

        if (!busquedaActiva) {
          console.log('   ⚠️  No hay búsqueda activa, guardando para después');
          continue;
        }

        // Procesar cada CV adjunto
        for (const att of attachments) {
          console.log(`   📄 Procesando CV: ${att.filename}`);

          try {
            const cvTexto = await extraerTextoCV(att);

            if (!cvTexto || cvTexto.trim().length < 50) {
              console.log('   ⚠️  CV vacío o muy corto, saltando');
              continue;
            }

            console.log(`   🤖 Analizando con IA...`);
            const analisis = await analizarCV(cvTexto, busquedaActiva);

            // Guardar en base de datos
            const stmt = db.prepare(`
              INSERT INTO candidatos (busqueda_id, nombre, email_origen, cv_texto, score,
                formacion, experiencia, hard_skills_score, soft_skills_score, fit_cultural,
                fortalezas, brechas, excluyentes_no_cumplidos, resumen, recomendacion, preguntas)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `);

            stmt.run(
              busquedaActiva.id,
              analisis.nombre,
              from,
              cvTexto.substring(0, 5000),
              analisis.score,
              analisis.formacion,
              analisis.experiencia,
              analisis.hardSkills,
              analisis.softSkills,
              analisis.fitCultural,
              JSON.stringify(analisis.fortalezas),
              JSON.stringify(analisis.brechas),
              JSON.stringify(analisis.excluyentesNoCumplidos || []),
              analisis.resumen,
              analisis.recomendacion,
              JSON.stringify(analisis.preguntasPreEntrevista || [])
            );

            console.log(`   ✅ ${analisis.nombre}: ${analisis.score}/100 — ${analisis.recomendacion}`);

            // Enviar informe por email
            await enviarInforme(
              { nombre: analisis.nombre, email: from },
              busquedaActiva,
              analisis
            );

            // Marcar como leído
            await client.messageFlagsAdd(msg.uid, ['\\Seen'], { uid: true });

          } catch (err) {
            console.error(`   ❌ Error procesando CV ${att.filename}:`, err.message);
          }
        }

        // Registrar email como procesado
        db.prepare('INSERT OR IGNORE INTO emails_procesados (message_id, from_email, subject) VALUES (?, ?, ?)')
          .run(messageId, from, subject);
      }
    } finally {
      lock.release();
    }

    await client.logout();
  } catch (err) {
    console.error('❌ Error revisando emails:', err.message);
  }

  monitorActivo = false;
}

// ═══════════════════════════════════════
// API REST
// ═══════════════════════════════════════

// --- BUSQUEDAS ---
app.get('/api/busquedas', (req, res) => {
  const rows = db.prepare('SELECT * FROM busquedas ORDER BY created_at DESC').all();
  res.json(rows);
});

app.get('/api/busquedas/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM busquedas WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'No encontrada' });
  res.json(row);
});

app.post('/api/busquedas', (req, res) => {
  const b = req.body;
  const stmt = db.prepare(`
    INSERT INTO busquedas (empresa, rubro_empresa, contacto_nombre, contacto_email,
      puesto, area, reporta_a, ubicacion, modalidad, contratacion, jornada,
      salario_desde, salario_hasta, moneda, fecha_objetivo, posiciones,
      formacion_minima, experiencia_minima, hard_skills, idiomas, certificaciones,
      disponibilidad, formacion_deseable, industrias_valoradas, soft_skills,
      perfil_disc, competencias_clave, motivo_busqueda, deal_breakers, proceso_cliente)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(
    b.empresa, b.rubro_empresa, b.contacto_nombre, b.contacto_email,
    b.puesto, b.area, b.reporta_a, b.ubicacion, b.modalidad, b.contratacion, b.jornada,
    b.salario_desde, b.salario_hasta, b.moneda, b.fecha_objetivo, b.posiciones || 1,
    b.formacion_minima, b.experiencia_minima, b.hard_skills, b.idiomas, b.certificaciones,
    b.disponibilidad, b.formacion_deseable, b.industrias_valoradas, b.soft_skills,
    b.perfil_disc, b.competencias_clave, b.motivo_busqueda, b.deal_breakers, b.proceso_cliente
  );
  res.json({ id: result.lastInsertRowid, message: 'Búsqueda creada' });
});

app.patch('/api/busquedas/:id/estado', (req, res) => {
  db.prepare('UPDATE busquedas SET estado = ? WHERE id = ?').run(req.body.estado, req.params.id);
  res.json({ message: 'Estado actualizado' });
});

// --- CANDIDATOS ---
app.get('/api/candidatos', (req, res) => {
  const { busqueda_id } = req.query;
  let rows;
  if (busqueda_id) {
    rows = db.prepare('SELECT * FROM candidatos WHERE busqueda_id = ? ORDER BY score DESC').all(busqueda_id);
  } else {
    rows = db.prepare('SELECT * FROM candidatos ORDER BY score DESC').all();
  }
  // Parsear JSON fields
  rows = rows.map(r => ({
    ...r,
    fortalezas: JSON.parse(r.fortalezas || '[]'),
    brechas: JSON.parse(r.brechas || '[]'),
    excluyentes_no_cumplidos: JSON.parse(r.excluyentes_no_cumplidos || '[]'),
    preguntas: JSON.parse(r.preguntas || '[]')
  }));
  res.json(rows);
});

app.get('/api/candidatos/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM candidatos WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'No encontrado' });
  row.fortalezas = JSON.parse(row.fortalezas || '[]');
  row.brechas = JSON.parse(row.brechas || '[]');
  row.excluyentes_no_cumplidos = JSON.parse(row.excluyentes_no_cumplidos || '[]');
  row.preguntas = JSON.parse(row.preguntas || '[]');
  res.json(row);
});

// --- ANÁLISIS MANUAL ---
app.post('/api/analizar', async (req, res) => {
  const { busqueda_id, cv_texto } = req.body;
  if (!busqueda_id || !cv_texto) return res.status(400).json({ error: 'Faltan datos' });

  const busqueda = db.prepare('SELECT * FROM busquedas WHERE id = ?').get(busqueda_id);
  if (!busqueda) return res.status(404).json({ error: 'Búsqueda no encontrada' });

  try {
    const analisis = await analizarCV(cv_texto, busqueda);

    const stmt = db.prepare(`
      INSERT INTO candidatos (busqueda_id, nombre, cv_texto, score,
        formacion, experiencia, hard_skills_score, soft_skills_score, fit_cultural,
        fortalezas, brechas, excluyentes_no_cumplidos, resumen, recomendacion, preguntas)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      busqueda_id, analisis.nombre, cv_texto.substring(0, 5000), analisis.score,
      analisis.formacion, analisis.experiencia, analisis.hardSkills,
      analisis.softSkills, analisis.fitCultural,
      JSON.stringify(analisis.fortalezas), JSON.stringify(analisis.brechas),
      JSON.stringify(analisis.excluyentesNoCumplidos || []),
      analisis.resumen, analisis.recomendacion,
      JSON.stringify(analisis.preguntasPreEntrevista || [])
    );

    res.json({ id: result.lastInsertRowid, ...analisis });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- ESTADÍSTICAS ---
app.get('/api/stats', (req, res) => {
  const busquedas = db.prepare('SELECT COUNT(*) as total FROM busquedas').get().total;
  const activas = db.prepare("SELECT COUNT(*) as total FROM busquedas WHERE estado = 'activa'").get().total;
  const candidatos = db.prepare('SELECT COUNT(*) as total FROM candidatos').get().total;
  const avanzar = db.prepare("SELECT COUNT(*) as total FROM candidatos WHERE recomendacion = 'AVANZAR'").get().total;
  const scorePromedio = db.prepare('SELECT AVG(score) as avg FROM candidatos').get().avg || 0;
  res.json({ busquedas, activas, candidatos, avanzar, scorePromedio: Math.round(scorePromedio) });
});

// --- MONITOR CONTROL ---
app.post('/api/monitor/check', async (req, res) => {
  await revisarEmails();
  res.json({ message: 'Revisión completada' });
});

// ═══════════════════════════════════════
// DASHBOARD HTML
// ═══════════════════════════════════════
app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APTIA — Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Libre+Caslon+Display&family=Hanken+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Hanken Grotesk',system-ui,sans-serif;background:#F4F6FB;color:#0F1B3D;min-height:100vh}
.header{background:#fff;padding:1.1rem 2rem;border-bottom:1px solid #E6EAF2;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}
.logo{font-family:'Libre Caslon Display',Georgia,serif;font-size:1.5rem;color:#002A76;letter-spacing:.03em}
.logo b{color:#FA232B;font-weight:400}
.badge{background:rgba(46,196,113,.12);color:#16A34A;padding:.35rem .9rem;border-radius:50px;font-size:.8rem;font-weight:600}
.main{max-width:1180px;margin:0 auto;padding:2rem}
h2{font-family:'Libre Caslon Display',Georgia,serif;font-size:1.7rem;margin-bottom:1.2rem;color:#002A76;font-weight:400}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.8rem}
.stat{background:#fff;border:1px solid #E6EAF2;border-radius:16px;padding:1.4rem}
.stat .ic{font-size:1.2rem;margin-bottom:.4rem}
.stat-num{font-family:'Libre Caslon Display',Georgia,serif;font-size:2.1rem;color:#FA232B}
.stat-label{font-size:.82rem;color:#6B7794;margin-top:.2rem}
.card{background:#fff;border:1px solid #E6EAF2;border-radius:16px;padding:1.5rem;margin-bottom:1.2rem}
.card h3{font-size:1.05rem;font-weight:700;margin-bottom:.9rem;color:#002A76}
.row{display:flex;align-items:center;gap:1rem;padding:.8rem 0;border-bottom:1px solid #EEF1F7}
.row:last-child{border-bottom:none}
.score{font-family:'Libre Caslon Display',Georgia,serif;font-size:1.4rem;font-weight:700;min-width:52px;text-align:center}
.score.high{color:#16A34A}.score.mid{color:#FA232B}.score.low{color:#9AA3B8}
.nm{font-weight:700;color:#0F1B3D}
.sub{font-size:.8rem;color:#6B7794}
.tag{display:inline-block;padding:.25rem .7rem;border-radius:50px;font-size:.7rem;font-weight:700;white-space:nowrap}
.tag.green{background:rgba(46,196,113,.12);color:#16A34A}
.tag.yellow{background:rgba(245,158,11,.14);color:#B45309}
.tag.red{background:rgba(250,35,43,.1);color:#FA232B}
.empty{text-align:center;padding:2.5rem;color:#9AA3B8}
.fgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
.fi{padding:.65rem .85rem;border:1px solid #E6EAF2;border-radius:10px;font-family:inherit;font-size:.9rem;color:#0F1B3D;width:100%}
.fi:focus{outline:none;border-color:#FA232B}
.fbtn{background:#FA232B;color:#fff;border:none;padding:.7rem 1.3rem;border-radius:10px;font-weight:700;cursor:pointer;font-family:inherit;font-size:.9rem}
.fmsg{margin-left:12px;font-size:.85rem;font-weight:600;color:#16A34A}
</style></head><body>
<div class="header"><div class="logo">APTIA <b>_</b></div><div class="badge">● Agente activo</div></div>
<div class="main">
<h2>Panel de control</h2>
<div class="stats" id="stats"><div class="empty">Cargando…</div></div>
<div class="card"><h3>Últimos candidatos analizados</h3><div id="cands"><div class="empty">Cargando…</div></div></div>
<div class="card"><h3>+ Nueva búsqueda</h3>
<div class="fgrid">
<input id="f_puesto" class="fi" placeholder="Puesto (ej: Agente Inmobiliario)">
<input id="f_empresa" class="fi" placeholder="Empresa (ej: Soldati Pilar)">
<input id="f_area" class="fi" placeholder="Área (ej: Real Estate)">
<input id="f_ubic" class="fi" placeholder="Ubicación (ej: Pilar, Bs As)">
<input id="f_modal" class="fi" placeholder="Modalidad (ej: Presencial)">
</div>
<button class="fbtn" onclick="crearBusqueda()">Publicar búsqueda</button><span id="f_msg" class="fmsg"></span>
</div>
<div class="card"><h3>Búsquedas</h3><div id="busqs"><div class="empty">Cargando…</div></div></div>
</div>
<script>
function esc(s){return (s||'').toString().replace(/[<>&]/g,function(c){return {'<':'&lt;','>':'&gt;','&':'&amp;'}[c];});}
async function load(){
  try{
    var r1=await fetch('/api/stats'); var stats=await r1.json();
    var r2=await fetch('/api/candidatos'); var cands=await r2.json();
    var r3=await fetch('/api/busquedas'); var busqs=await r3.json();
    document.getElementById('stats').innerHTML=
      [{n:stats.busquedas||0,l:'Búsquedas',i:'📋'},{n:stats.activas||0,l:'Activas',i:'🟢'},{n:stats.candidatos||0,l:'CVs analizados',i:'👥'},{n:stats.avanzar||0,l:'Recomendados',i:'✅'}]
      .map(function(m){return '<div class="stat"><div class="ic">'+m.i+'</div><div class="stat-num">'+m.n+'</div><div class="stat-label">'+m.l+'</div></div>';}).join('');
    document.getElementById('cands').innerHTML = (!cands||cands.length===0)?'<div class="empty">Sin candidatos todavía. Cuando llegue un CV por mail, aparece acá.</div>':
      cands.slice(0,12).map(function(c){
        var sc=c.score||0; var cls=sc>=70?'high':sc>=55?'mid':'low';
        var rec=c.recomendacion||''; var tc=rec==='AVANZAR'?'green':rec==='NO AVANZAR'?'red':'yellow';
        var resumen=esc(c.resumen).slice(0,110);
        return '<div class="row"><div class="score '+cls+'">'+sc+'</div><div style="flex:1"><div class="nm">'+esc(c.nombre)+'</div><div class="sub">'+resumen+'…</div></div><span class="tag '+tc+'">'+esc(rec)+'</span></div>';
      }).join('');
    document.getElementById('busqs').innerHTML = (!busqs||busqs.length===0)?'<div class="empty">Sin búsquedas cargadas.</div>':
      busqs.map(function(b){return '<div class="row"><div style="flex:1"><div class="nm">'+esc(b.puesto)+'</div><div class="sub">'+esc(b.empresa)+' · '+esc(b.ubicacion||'—')+'</div></div><span class="tag green">'+esc(b.estado)+'</span></div>';}).join('');
  }catch(e){
    document.getElementById('stats').innerHTML='<div class="empty">No se pudo conectar con el servidor. Refrescá en unos segundos.</div>';
  }
}
function crearBusqueda(){
  var v=function(id){return document.getElementById(id).value.trim();};
  var data={puesto:v('f_puesto'),empresa:v('f_empresa'),area:v('f_area'),ubicacion:v('f_ubic'),modalidad:v('f_modal')};
  var msg=document.getElementById('f_msg');
  if(!data.puesto||!data.empresa){msg.style.color='#FA232B';msg.textContent='Completá al menos puesto y empresa.';return;}
  msg.style.color='#6B7794';msg.textContent='Publicando…';
  fetch('/api/busquedas',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(function(r){return r.json();})
    .then(function(){msg.style.color='#16A34A';msg.textContent='✓ Publicada. Ya aparece en la web.';['f_puesto','f_empresa','f_area','f_ubic','f_modal'].forEach(function(id){document.getElementById(id).value='';});load();})
    .catch(function(){msg.style.color='#FA232B';msg.textContent='Error al publicar. Reintentá.';});
}
load(); setInterval(load, 30000);
</script></body></html>`);
});

// ═══════════════════════════════════════
// ARRANQUE
// ═══════════════════════════════════════
const PORT = process.env.PORT || 3000;
const CHECK_INTERVAL = parseInt(process.env.CHECK_INTERVAL || '120000'); // 2 min default

app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║  APTIA — Agente Automático de IA     ║
  ║  Puerto: ${PORT}                         ║
  ║  Monitor: cada ${CHECK_INTERVAL/1000}s                ║
  ╚═══════════════════════════════════════╝
  `);

  // Arrancar monitor de emails
  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    console.log(`📬 Monitoreando: ${process.env.GMAIL_USER}`);
    setInterval(revisarEmails, CHECK_INTERVAL);
    revisarEmails(); // Primera revisión inmediata
  } else {
    console.log('⚠️  Sin credenciales Gmail. Configurá GMAIL_USER y GMAIL_APP_PASSWORD.');
    console.log('   El servidor funciona en modo manual (API REST).');
  }
});
