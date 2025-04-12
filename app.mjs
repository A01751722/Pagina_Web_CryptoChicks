import express from 'express';
import mysql from 'mysql2/promise';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import bcrypt from 'bcryptjs';
import fetch from 'node-fetch';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = process.env.PORT ?? 8081;
const ip_address = process.env.C9_HOSTNAME ?? 'localhost';

const db = await mysql.createConnection({
  host: 'bd-desarrollo-web-crypto.cxat1ijc1kjd.us-east-1.rds.amazonaws.com',
  user: 'admin',
  password: '12345678',
  database: 'CriptoChicksDB'
});

app.set('view engine', 'ejs');
app.set('views', join(__dirname, 'views'));

app.use(express.static(join(__dirname, 'public')));
app.use(express.static(join(__dirname, 'unity')));
app.use(express.json());

const geminiApiKey = 'AIzaSyAckOnAMXAsVXofwLAA5r6AChCEPc-UA9U'; // <--- Ajusta tu key

// ---------------------------------------------------------------------------------------------
// 1. REGISTRO DE USUARIO
// ---------------------------------------------------------------------------------------------
app.post('/api/registro', async (req, res) => {
  const { nombre_usuario, correo, contraseña, genero } = req.body;
  if (!nombre_usuario || !correo || !contraseña) {
    return res.status(400).json({ message: 'Todos los campos son requeridos' });
  }
  try {
    const hashedPassword = await bcrypt.hash(contraseña, 10);
    await db.query(`
      INSERT INTO Usuarios (nombre_usuario, correo, contraseña, rol, genero)
      VALUES (?, ?, ?, 'usuario', ?)
    `, [nombre_usuario, correo, hashedPassword, genero]);

    res.status(200).json({ message: 'Usuario registrado con éxito' });
  } catch (err) {
    console.error('Error registrando usuario:', err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// ---------------------------------------------------------------------------------------------
// 2. LOGIN USUARIO
// ---------------------------------------------------------------------------------------------
app.post('/api/login-usuario', async (req, res) => {
  const { correo, contraseña } = req.body;
  try {
    const [rows] = await db.query(`
      SELECT usuario_id, nombre_usuario, contraseña, rol, genero
      FROM Usuarios
      WHERE correo = ?
    `, [correo]);

    if (rows.length === 0) {
      return res.status(401).json({ acceso: 'denegado' });
    }

    const validPassword = await bcrypt.compare(contraseña, rows[0].contraseña);
    if (!validPassword) {
      return res.status(401).json({ acceso: 'denegado' });
    }

    res.status(200).json({
      acceso: 'concedido',
      usuario_id: rows[0].usuario_id,
      rol: rows[0].rol,
      nombre_usuario: rows[0].nombre_usuario,
      genero: rows[0].genero
    });
  } catch (err) {
    console.error('Error login usuario:', err);
    res.status(500).json({ acceso: 'error' });
  }
});

// ---------------------------------------------------------------------------------------------
// 3. LOGIN ADMIN
// ---------------------------------------------------------------------------------------------
app.post('/api/login-admin', async (req, res) => {
  const { correo, contraseña } = req.body;
  try {
    const [rows] = await db.query(`
      SELECT rol, contraseña
      FROM Usuarios
      WHERE correo = ?
    `, [correo]);

    if (rows.length === 0) {
      return res.status(403).json({ acceso: 'denegado' });
    }

    const validPassword = await bcrypt.compare(contraseña, rows[0].contraseña);
    if (validPassword && rows[0].rol === 'admin') {
      res.json({ acceso: 'concedido' });
    } else {
      res.status(403).json({ acceso: 'denegado' });
    }
  } catch (err) {
    console.error('Error validando admin:', err);
    res.status(500).json({ acceso: 'error' });
  }
});

// ---------------------------------------------------------------------------------------------
// 4. DASHBOARD
// ---------------------------------------------------------------------------------------------
app.get('/api/dashboard/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;
  try {
    const [usuario] = await db.query(`
      SELECT nombre_usuario, genero
      FROM Usuarios
      WHERE usuario_id = ?
    `, [usuario_id]);

    if (usuario.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const [cursos] = await db.query(`
      SELECT COUNT(*) AS total
      FROM Inscripciones_Cursos
      WHERE usuario_id = ?
        AND estado = 'completado'
    `, [usuario_id]);

    const [puntaje] = await db.query(`
      SELECT COALESCE(SUM(puntuacion), 0) AS total
      FROM Resultados
      WHERE usuario_id = ?
    `, [usuario_id]);

    const [certificados] = await db.query(`
      SELECT COUNT(*) AS total
      FROM Certificados
      WHERE usuario_id = ?
    `, [usuario_id]);

    const [niveles] = await db.query(`
      SELECT nivel AS nombre,
             CASE WHEN puntuacion >= 100 THEN 'Completado'
                  ELSE 'En progreso'
             END AS estado
      FROM Resultados
      WHERE usuario_id = ?
    `, [usuario_id]);

    res.json({
      nombre_usuario: usuario[0].nombre_usuario,
      genero: usuario[0].genero,
      cursos_completados: cursos[0].total,
      puntuacion_total: puntaje[0].total,
      certificados: certificados[0].total,
      niveles
    });
  } catch (error) {
    console.error('Error en /api/dashboard:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ---------------------------------------------------------------------------------------------
// 5. FORO
// ---------------------------------------------------------------------------------------------
app.get('/api/foro', async (req, res) => {
  try {
    const [preguntas] = await db.query(`
      SELECT f.pregunta_id,
             f.titulo,
             f.palabras_clave,
             u.nombre_usuario
      FROM Foro f
      JOIN Usuarios u ON f.usuario_id = u.usuario_id
      ORDER BY f.fecha DESC
    `);
    res.json(preguntas);
  } catch (err) {
    console.error('Error obteniendo preguntas:', err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/api/foro/pregunta/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query(`
      SELECT f.pregunta_id,
             f.titulo,
             f.publicacion,
             f.palabras_clave,
             u.nombre_usuario
      FROM Foro f
      JOIN Usuarios u ON f.usuario_id = u.usuario_id
      WHERE f.pregunta_id = ?
    `, [id]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Pregunta no encontrada' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error('Error cargando pregunta:', err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post('/api/foro/nueva-pregunta', async (req, res) => {
  const usuario_id = req.header('x-user-id');
  const { titulo, palabras_clave, contenido } = req.body;

  if (!usuario_id || !titulo || !palabras_clave || !contenido) {
    return res.status(400).json({ message: 'Campos requeridos faltantes' });
  }
  try {
    await db.query(`
      INSERT INTO Foro (usuario_id, publicacion, fecha, titulo, palabras_clave)
      VALUES (?, ?, NOW(), ?, ?)
    `, [usuario_id, contenido, titulo, palabras_clave]);

    res.status(200).json({ message: 'Pregunta publicada correctamente' });
  } catch (err) {
    console.error('Error insertando pregunta:', err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/api/foro/pregunta/:id/respuestas', async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query(`
      SELECT r.respuesta_id,
             r.contenido,
             r.fecha,
             u.nombre_usuario
      FROM Respuestas_Foro r
      JOIN Usuarios u ON r.usuario_id = u.usuario_id
      WHERE r.pregunta_id = ?
      ORDER BY r.fecha ASC
    `, [id]);

    res.status(200).json(rows);
  } catch (err) {
    console.error('Error obteniendo respuestas:', err);
    res.status(500).json({ message: 'Error al cargar respuestas' });
  }
});

app.post('/api/foro/pregunta/:id/responder', async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.header('x-user-id');
  const { contenido } = req.body;

  if (!usuario_id || !contenido) {
    return res.status(400).json({ message: 'Faltan campos: user y contenido' });
  }

  try {
    const [existePregunta] = await db.query(
      'SELECT pregunta_id FROM Foro WHERE pregunta_id = ?',
      [id]
    );
    if (existePregunta.length === 0) {
      return res.status(404).json({ message: 'La pregunta no existe' });
    }

    await db.query(`
      INSERT INTO Respuestas_Foro (pregunta_id, usuario_id, contenido, fecha)
      VALUES (?, ?, ?, NOW())
    `, [id, usuario_id, contenido]);

    res.status(200).json({ message: 'Respuesta publicada con éxito' });
  } catch (err) {
    console.error('Error publicando respuesta:', err);
    res.status(500).json({ message: 'Error al publicar la respuesta' });
  }
});

// ---------------------------------------------------------------------------------------------
// 6. ADMIN
// ---------------------------------------------------------------------------------------------
app.get('/api/admin/usuarios', async (req, res) => {
  const [rows] = await db.query(`
    SELECT usuario_id, nombre_usuario, rol
    FROM Usuarios
  `);
  res.json(rows);
});

app.delete('/api/admin/usuarios/:id', async (req, res) => {
  await db.query('DELETE FROM Usuarios WHERE usuario_id = ?', [req.params.id]);
  res.sendStatus(204);
});

app.put('/api/admin/usuarios/:id/hacer-admin', async (req, res) => {
  await db.query(`
    UPDATE Usuarios
    SET rol = 'admin'
    WHERE usuario_id = ?
  `, [req.params.id]);
  res.sendStatus(200);
});

app.get('/api/admin/preguntas', async (req, res) => {
  try {
    const [preguntas] = await db.query(`
      SELECT f.pregunta_id,
             f.titulo,
             f.publicacion,
             f.palabras_clave,
             f.fecha,
             u.nombre_usuario
      FROM Foro f
      JOIN Usuarios u ON f.usuario_id = u.usuario_id
      ORDER BY f.fecha DESC
    `);
    res.json(preguntas);
  } catch (err) {
    console.error('Error listando preguntas (admin):', err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.delete('/api/admin/preguntas/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM Respuestas_Foro WHERE pregunta_id = ?', [id]);
    await db.query('DELETE FROM Foro WHERE pregunta_id = ?', [id]);
    res.sendStatus(204);
  } catch (err) {
    console.error('Error eliminando pregunta (admin):', err);
    res.status(500).json({ message: 'Error al eliminar la pregunta' });
  }
});

app.get('/api/admin/respuestas', async (req, res) => {
  try {
    const [respuestas] = await db.query(`
      SELECT r.respuesta_id,
             r.contenido,
             r.fecha,
             u.nombre_usuario
      FROM Respuestas_Foro r
      JOIN Usuarios u ON r.usuario_id = u.usuario_id
      ORDER BY r.fecha ASC
    `);
    res.json(respuestas);
  } catch (err) {
    console.error('Error listando respuestas (admin):', err);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.delete('/api/admin/respuestas/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM Respuestas_Foro WHERE respuesta_id = ?', [id]);
    res.sendStatus(204);
  } catch (err) {
    console.error('Error al eliminar respuesta (admin):', err);
    res.status(500).json({ message: 'Error al eliminar la respuesta' });
  }
});

// ---------------------------------------------------------------------------------------------
// 7. ERRORES
// ---------------------------------------------------------------------------------------------
app.get('/api/errores/:usuario_id', async (req, res) => {
  const { usuario_id } = req.params;
  try {
    const [rows] = await db.query(`
      SELECT error_id, nivel, pregunta, respuesta_usuario, es_correcta, fecha
      FROM Errores
      WHERE usuario_id = ?
    `, [usuario_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo errores del servidor:', err);
    res.status(500).json({ message: 'Error obteniendo errores del servidor.' });
  }
});

// ---------------------------------------------------------------------------------------------
// 8. Chat Inteligente con Gemini
// ---------------------------------------------------------------------------------------------
app.post('/api/chat-inteligente/:usuario_id', async (req, res) => {
  try {
    const { usuario_id } = req.params;
    const { preguntaUsuario } = req.body;
    if (!preguntaUsuario) {
      return res.status(400).json({ message: 'Falta la pregunta del usuario.' });
    }

    // 1. Datos del usuario
    const [usuarioData] = await db.query(`
      SELECT nombre_usuario, genero
      FROM Usuarios
      WHERE usuario_id = ?
    `, [usuario_id]);
    if (usuarioData.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }
    const { nombre_usuario, genero } = usuarioData[0];

    // 2. Historial de errores
    const [errores] = await db.query(`
      SELECT nivel, pregunta, respuesta_usuario
      FROM Errores
      WHERE usuario_id = ?
      ORDER BY fecha DESC
      LIMIT 10
    `, [usuario_id]);
    const erroresTexto = errores.length > 0
      ? errores.map(e => `- Nivel ${e.nivel}: "${e.pregunta}" (respuesta: "${e.respuesta_usuario}")`).join('\n')
      : 'No hay errores recientes.';

    // 3. Últimas 5 interacciones de la tabla Consultas_IA (pregunta + respuesta)
    const [ultimasConsultas] = await db.query(`
      SELECT consulta_id, pregunta, respuesta, fecha
      FROM Consultas_IA
      WHERE usuario_id = ?
      ORDER BY consulta_id DESC
      LIMIT 5
    `, [usuario_id]);
    // Orden cronológico normal
    ultimasConsultas.reverse();

    let historialConversacion = '';
    for (const row of ultimasConsultas) {
      historialConversacion += `\nUsuario: ${row.pregunta}\nCryptoGirl: ${row.respuesta}\n`;
    }

    // 4. Prompt final
    const prompt = `
Eres "CryptoGirl", una tutora experta en Web3, con una charla continua.
No te repitas saludos. Responde en base al hilo previo y errores del usuario.

Nombre de usuario: ${nombre_usuario} (género: ${genero})
Errores recientes:
${erroresTexto}

Conversación hasta ahora:
${historialConversacion}
Usuario: ${preguntaUsuario}

Responde de forma breve y amable, sin repetir introducciones excesivas. Sé clara y concisa.
    `;

    console.log("=== Prompt enviado a Gemini ===");
    console.log(prompt);

    // 5. Llamada a Gemini
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${geminiApiKey}`;

    const payload = {
      contents: [
        {
          parts: [
            { text: prompt }
          ]
        }
      ]
    };

    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const dataGemini = await resp.json();
    console.log("=== Respuesta Gemini RAW ===");
    console.log(JSON.stringify(dataGemini, null, 2));

    // 6. Extraemos el texto
    let respuestaIA = '';
    if (
      dataGemini &&
      dataGemini.candidates &&
      dataGemini.candidates[0] &&
      dataGemini.candidates[0].content &&
      dataGemini.candidates[0].content.parts &&
      dataGemini.candidates[0].content.parts[0]
    ) {
      respuestaIA = dataGemini.candidates[0].content.parts[0].text;
    } else {
      respuestaIA = "La IA no pudo generar respuesta.";
    }

    // 7. Guardar la nueva interacción
    await db.query(`
      INSERT INTO Consultas_IA (usuario_id, pregunta, respuesta)
      VALUES (?, ?, ?)
    `, [usuario_id, preguntaUsuario, respuestaIA]);

    // 8. Respuesta al frontend
    res.json({ respuesta: respuestaIA });

  } catch (error) {
    console.error('Error en /api/chat-inteligente:', error);
    res.status(500).json({ message: 'Error procesando la solicitud de IA.' });
  }
});

// ---------------------------------------------------------------------------------------------
// 9. RUTAS HTML
// ---------------------------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});
app.get('/dashboard.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'dashboard.html'));
});
app.get('/jugar.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'juego.html'));
});
app.get('/foro.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'foro.html'));
});
app.get('/enviar_pregunta.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'enviar_pregunta.html'));
});
app.get('/foro/pregunta.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'foro', 'pregunta.html'));
});
app.get('/admin.html', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'admin.html'));
});

// ---------------------------------------------------------------------------------------------
// 10. RUTA 404
// ---------------------------------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).send('404 - Recurso no encontrado');
});

// ---------------------------------------------------------------------------------------------
// INICIAR SERVIDOR
// ---------------------------------------------------------------------------------------------
app.listen(port, '0.0.0.0', () => {
  console.log(`Servidor escuchando en http://${ip_address}:${port}`);
});