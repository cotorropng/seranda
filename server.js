const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const zlib = require('zlib');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'expotecnica_secret';

// ── Extraer ZIP si no existe la carpeta public ─────────────────────────────
function extractZip(zipPath, destDir) {
    const data = fs.readFileSync(zipPath);
    let eocdOffset = -1;
    for (let i = data.length - 22; i >= 0; i--) {
        if (data[i] === 0x50 && data[i+1] === 0x4b && data[i+2] === 0x05 && data[i+3] === 0x06) {
            eocdOffset = i; break;
        }
    }
    const cdOffset = data.readUInt32LE(eocdOffset + 16);
    const numEntries = data.readUInt16LE(eocdOffset + 10);
    let pos = cdOffset;
    let extracted = 0;
    for (let i = 0; i < numEntries; i++) {
        if (data.readUInt32LE(pos) !== 0x02014b50) break;
        const compMethod = data.readUInt16LE(pos + 10);
        const compSize = data.readUInt32LE(pos + 20);
        const fnLen = data.readUInt16LE(pos + 28);
        const extraLen = data.readUInt16LE(pos + 30);
        const commentLen = data.readUInt16LE(pos + 32);
        const localHeaderOffset = data.readUInt32LE(pos + 42);
        const fn = data.slice(pos + 46, pos + 46 + fnLen).toString('utf8');
        pos += 46 + fnLen + extraLen + commentLen;
        if (fn.endsWith('/') || fn.includes('node_modules') || fn.includes('Backend/')) continue;
        const lhPos = localHeaderOffset;
        const lhFnLen = data.readUInt16LE(lhPos + 26);
        const lhExtraLen = data.readUInt16LE(lhPos + 28);
        const dataStart = lhPos + 30 + lhFnLen + lhExtraLen;
        const compData = data.slice(dataStart, dataStart + compSize);
        let uncompData;
        try { uncompData = compMethod === 8 ? zlib.inflateRawSync(compData) : compData; }
        catch (e) { continue; }
        const relPath = fn.replace(/^ExpoTecnica\/Frontend\//, '');
        const outPath = path.join(destDir, relPath);
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, uncompData);
        extracted++;
    }
    console.log('Extraidos ' + extracted + ' archivos del ZIP');
}

const publicDir = path.join(__dirname, 'public');
const zipPath = path.join(__dirname, 'ExpoTecnica.zip');
if (!fs.existsSync(publicDir) && fs.existsSync(zipPath)) {
    console.log('Extrayendo archivos del juego...');
    extractZip(zipPath, publicDir);
}

const filesToFix = [
    path.join(publicDir, 'login.html'),
    path.join(publicDir, 'admin.js'),
    path.join(publicDir, 'coordinador.js'),
    path.join(publicDir, 'profe.js'),
    path.join(publicDir, 'funcionesGenericas', 'funciongenerica.js'),
];
for (const f of filesToFix) {
    if (fs.existsSync(f)) {
        let content = fs.readFileSync(f, 'utf8');
        if (content.includes('http://localhost:3000/')) {
            content = content.replace(/http:\/\/localhost:3000\//g, '/');
            fs.writeFileSync(f, content);
        }
    }
}

// ── Base de datos PostgreSQL ───────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function query(text, params) {
    const client = await pool.connect();
    try { return await client.query(text, params); }
    finally { client.release(); }
}

async function initDB() {
    await query(`
        CREATE TABLE IF NOT EXISTS instituciones (
            id SERIAL PRIMARY KEY,
            nombre TEXT,
            codigo TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            nombre TEXT,
            usuario TEXT UNIQUE,
            password TEXT,
            rol TEXT,
            institucion_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS progreso (
            id SERIAL PRIMARY KEY,
            usuario_id INTEGER,
            juego TEXT,
            puntaje INTEGER,
            fecha DATE DEFAULT CURRENT_DATE
        );
    `);
    const { rows } = await query("SELECT * FROM usuarios WHERE rol = 'admin' LIMIT 1");
    if (rows.length === 0) {
        const hash = await bcrypt.hash('admin1234', 10);
        await query("INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1,$2,$3,$4)", ['Admin', 'admin', hash, 'admin']);
        console.log('Admin creado');
    }
}

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(publicDir));

function auth(req, res, next) {
    let token = req.headers.authorization;
    if (!token) return res.status(401).json({ error: 'Sin token' });
    if (token.startsWith('Bearer ')) token = token.slice(7);
    try { req.usuario = jwt.verify(token, SECRET); next(); }
    catch { res.status(401).json({ error: 'Token inválido' }); }
}

// ── Rutas ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.redirect('/login.html'));

app.post('/login', async (req, res) => {
    try {
        const { rows } = await query("SELECT * FROM usuarios WHERE usuario = $1", [req.body.usuario]);
        const user = rows[0];
        if (!user || !await bcrypt.compare(req.body.password, user.password)) return res.status(401).json({ error: 'Credenciales incorrectas' });
        const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol, institucion_id: user.institucion_id }, SECRET, { expiresIn: '8h' });
        res.json({ token, rol: user.rol, nombre: user.nombre });
    } catch (e) { res.status(500).json({ error: 'Error del servidor' }); }
});

app.post('/registro', async (req, res) => {
    try {
        const { nombre, usuario, password, codigo } = req.body;
        let institucion_id = null;
        if (codigo) {
            const { rows } = await query("SELECT id FROM instituciones WHERE codigo = $1", [codigo]);
            if (!rows[0]) return res.status(400).json({ error: 'Código de institución no válido' });
            institucion_id = rows[0].id;
        }
        await query("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES ($1,$2,$3,'estudiante',$4)", [nombre, usuario, await bcrypt.hash(password, 10), institucion_id]);
        res.json({ ok: true });
    } catch { res.status(400).json({ error: 'Usuario ya existe' }); }
});

app.post('/progreso', auth, async (req, res) => {
    await query("INSERT INTO progreso (usuario_id, juego, puntaje) VALUES ($1,$2,$3)", [req.usuario.id, req.body.juego, req.body.puntaje]);
    res.json({ ok: true });
});

app.get('/progreso', auth, async (req, res) => {
    const { rows } = await query("SELECT juego, MAX(puntaje) as puntaje FROM progreso WHERE usuario_id = $1 GROUP BY juego", [req.usuario.id]);
    res.json(rows);
});

app.get('/stats', auth, async (req, res) => {
    const [e, i, j] = await Promise.all([
        query("SELECT COUNT(*) as total FROM usuarios WHERE rol = 'estudiante'"),
        query("SELECT COUNT(*) as total FROM instituciones"),
        query("SELECT juego, COUNT(*) as veces FROM progreso GROUP BY juego ORDER BY veces DESC")
    ]);
    res.json({ totalEstudiantes: e.rows[0], totalInstituciones: i.rows[0], jugadas: j.rows });
});

app.get('/instituciones', auth, async (req, res) => { const { rows } = await query("SELECT * FROM instituciones"); res.json(rows); });
app.post('/instituciones', auth, async (req, res) => {
    try { await query("INSERT INTO instituciones (nombre, codigo) VALUES ($1,$2)", [req.body.nombre, req.body.codigo]); res.json({ ok: true }); }
    catch { res.status(400).json({ error: 'Código ya existe' }); }
});
app.delete('/instituciones/:id', auth, async (req, res) => {
    await query("DELETE FROM usuarios WHERE institucion_id = $1", [req.params.id]);
    await query("DELETE FROM instituciones WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
});

app.get('/coordinadores', auth, async (req, res) => { const { rows } = await query("SELECT u.id, u.nombre, u.usuario, i.nombre as institucion, i.codigo FROM usuarios u LEFT JOIN instituciones i ON u.institucion_id = i.id WHERE u.rol = 'coordinador'"); res.json(rows); });
app.post('/usuarios/coordinador', auth, async (req, res) => {
    try { await query("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES ($1,$2,$3,'coordinador',$4)", [req.body.nombre, req.body.usuario, await bcrypt.hash(req.body.password, 10), req.body.institucion_id]); res.json({ ok: true }); }
    catch { res.status(400).json({ error: 'Usuario ya existe' }); }
});
app.delete('/usuarios/coordinador/:id', auth, async (req, res) => { await query("DELETE FROM usuarios WHERE id = $1 AND rol = 'coordinador'", [req.params.id]); res.json({ ok: true }); });

app.get('/profes', auth, async (req, res) => { const { rows } = await query("SELECT u.id, u.nombre, u.usuario, i.nombre as institucion, i.codigo FROM usuarios u LEFT JOIN instituciones i ON u.institucion_id = i.id WHERE u.rol = 'profe'"); res.json(rows); });
app.get('/estudiantes', auth, async (req, res) => { const { rows } = await query("SELECT u.id, u.nombre, u.usuario, i.nombre as institucion, i.codigo FROM usuarios u LEFT JOIN instituciones i ON u.institucion_id = i.id WHERE u.rol = 'estudiante'"); res.json(rows); });

app.get('/coordinador/stats', auth, async (req, res) => {
    const id = req.usuario.institucion_id;
    const [p, e, j] = await Promise.all([
        query("SELECT COUNT(*) as total FROM usuarios WHERE rol = 'profe' AND institucion_id = $1", [id]),
        query("SELECT COUNT(*) as total FROM usuarios WHERE rol = 'estudiante' AND institucion_id = $1", [id]),
        query("SELECT p.juego, COUNT(*) as veces FROM progreso p JOIN usuarios u ON p.usuario_id = u.id WHERE u.institucion_id = $1 GROUP BY p.juego ORDER BY veces DESC", [id])
    ]);
    res.json({ totalProfes: p.rows[0], totalEstudiantes: e.rows[0], jugadas: j.rows });
});

app.get('/coordinador/profes', auth, async (req, res) => { const { rows } = await query("SELECT id, nombre, usuario FROM usuarios WHERE rol = 'profe' AND institucion_id = $1", [req.usuario.institucion_id]); res.json(rows); });
app.post('/coordinador/profes', auth, async (req, res) => {
    try { await query("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES ($1,$2,$3,'profe',$4)", [req.body.nombre, req.body.usuario, await bcrypt.hash(req.body.password, 10), req.usuario.institucion_id]); res.json({ ok: true }); }
    catch { res.status(400).json({ error: 'Usuario ya existe' }); }
});
app.delete('/coordinador/profes/:id', auth, async (req, res) => { await query("DELETE FROM usuarios WHERE id = $1 AND rol = 'profe' AND institucion_id = $2", [req.params.id, req.usuario.institucion_id]); res.json({ ok: true }); });

app.get('/profesor/estudiantes', auth, async (req, res) => { const { rows } = await query("SELECT id, nombre, usuario FROM usuarios WHERE rol = 'estudiante' AND institucion_id = $1", [req.usuario.institucion_id]); res.json(rows); });
app.post('/profesor/estudiantes', auth, async (req, res) => {
    try { await query("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES ($1,$2,$3,'estudiante',$4)", [req.body.nombre, req.body.usuario, await bcrypt.hash(req.body.password, 10), req.usuario.institucion_id]); res.json({ ok: true }); }
    catch { res.status(400).json({ error: 'Usuario ya existe' }); }
});
app.delete('/profesor/estudiantes/:id', auth, async (req, res) => { await query("DELETE FROM usuarios WHERE id = $1 AND rol = 'estudiante' AND institucion_id = $2", [req.params.id, req.usuario.institucion_id]); res.json({ ok: true }); });
app.get('/profesor/clase', auth, async (req, res) => { const { rows } = await query("SELECT id, nombre, usuario FROM usuarios WHERE rol = 'estudiante' AND institucion_id = $1 ORDER BY nombre", [req.usuario.institucion_id]); res.json(rows); });
app.get('/profesor/progreso', auth, async (req, res) => { const { rows } = await query("SELECT u.nombre as estudiante, p.juego, MAX(p.puntaje) as puntaje FROM progreso p JOIN usuarios u ON p.usuario_id = u.id WHERE u.institucion_id = $1 AND u.rol = 'estudiante' GROUP BY u.id, u.nombre, p.juego ORDER BY u.nombre, p.juego", [req.usuario.institucion_id]); res.json(rows); });

// ── Iniciar servidor ───────────────────────────────────────────────────────
initDB().then(() => {
    app.listen(PORT, () => console.log('Servidor en puerto ' + PORT));
}).catch(err => {
    console.error('Error iniciando DB:', err);
    process.exit(1);
});
