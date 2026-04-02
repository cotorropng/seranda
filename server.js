const express = require('express');
const Database = require('better-sqlite3');
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

// Aplicar fix de localhost en archivos JS/HTML si es necesario
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

// ── Base de datos ──────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'juegos.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS instituciones (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, codigo TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, usuario TEXT UNIQUE, password TEXT, rol TEXT, institucion_id INTEGER);
CREATE TABLE IF NOT EXISTS progreso (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario_id INTEGER, juego TEXT, puntaje INTEGER, fecha TEXT DEFAULT (date('now')));
`);
if (!db.prepare("SELECT * FROM usuarios WHERE rol = 'admin'").get()) {
    db.prepare("INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)").run('Admin', 'admin', bcrypt.hashSync('admin1234', 10), 'admin');
    console.log('Admin creado');
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

app.post('/login', (req, res) => {
    const user = db.prepare("SELECT * FROM usuarios WHERE usuario = ?").get(req.body.usuario);
    if (!user || !bcrypt.compareSync(req.body.password, user.password)) return res.status(401).json({ error: 'Credenciales incorrectas' });
    const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol, institucion_id: user.institucion_id }, SECRET, { expiresIn: '8h' });
    res.json({ token, rol: user.rol, nombre: user.nombre });
});

app.post('/registro', (req, res) => {
    const { nombre, usuario, password, codigo } = req.body;
    let institucion_id = null;
    if (codigo) {
        const inst = db.prepare("SELECT id FROM instituciones WHERE codigo = ?").get(codigo);
        if (!inst) return res.status(400).json({ error: 'Código de institución no válido' });
        institucion_id = inst.id;
    }
    try { db.prepare("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES (?, ?, ?, 'estudiante', ?)").run(nombre, usuario, bcrypt.hashSync(password, 10), institucion_id); res.json({ ok: true }); }
    catch { res.status(400).json({ error: 'Usuario ya existe' }); }
});

app.post('/progreso', auth, (req, res) => { db.prepare("INSERT INTO progreso (usuario_id, juego, puntaje) VALUES (?, ?, ?)").run(req.usuario.id, req.body.juego, req.body.puntaje); res.json({ ok: true }); });
app.get('/progreso', auth, (req, res) => res.json(db.prepare("SELECT juego, MAX(puntaje) as puntaje FROM progreso WHERE usuario_id = ? GROUP BY juego").all(req.usuario.id)));
app.get('/stats', auth, (req, res) => res.json({ totalEstudiantes: db.prepare("SELECT COUNT(*) as total FROM usuarios WHERE rol = 'estudiante'").get(), totalInstituciones: db.prepare("SELECT COUNT(*) as total FROM instituciones").get(), jugadas: db.prepare("SELECT juego, COUNT(*) as veces FROM progreso GROUP BY juego ORDER BY veces DESC").all() }));

app.get('/instituciones', auth, (req, res) => res.json(db.prepare("SELECT * FROM instituciones").all()));
app.post('/instituciones', auth, (req, res) => { try { db.prepare("INSERT INTO instituciones (nombre, codigo) VALUES (?, ?)").run(req.body.nombre, req.body.codigo); res.json({ ok: true }); } catch { res.status(400).json({ error: 'Código ya existe' }); } });
app.delete('/instituciones/:id', auth, (req, res) => { db.prepare("DELETE FROM usuarios WHERE institucion_id = ?").run(req.params.id); db.prepare("DELETE FROM instituciones WHERE id = ?").run(req.params.id); res.json({ ok: true }); });

app.get('/coordinadores', auth, (req, res) => res.json(db.prepare("SELECT u.id, u.nombre, u.usuario, i.nombre as institucion, i.codigo FROM usuarios u LEFT JOIN instituciones i ON u.institucion_id = i.id WHERE u.rol = 'coordinador'").all()));
app.post('/usuarios/coordinador', auth, (req, res) => { try { db.prepare("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES (?, ?, ?, 'coordinador', ?)").run(req.body.nombre, req.body.usuario, bcrypt.hashSync(req.body.password, 10), req.body.institucion_id); res.json({ ok: true }); } catch { res.status(400).json({ error: 'Usuario ya existe' }); } });
app.delete('/usuarios/coordinador/:id', auth, (req, res) => { db.prepare("DELETE FROM usuarios WHERE id = ? AND rol = 'coordinador'").run(req.params.id); res.json({ ok: true }); });

app.get('/profes', auth, (req, res) => res.json(db.prepare("SELECT u.id, u.nombre, u.usuario, i.nombre as institucion, i.codigo FROM usuarios u LEFT JOIN instituciones i ON u.institucion_id = i.id WHERE u.rol = 'profe'").all()));
app.get('/estudiantes', auth, (req, res) => res.json(db.prepare("SELECT u.id, u.nombre, u.usuario, i.nombre as institucion, i.codigo FROM usuarios u LEFT JOIN instituciones i ON u.institucion_id = i.id WHERE u.rol = 'estudiante'").all()));

app.get('/coordinador/stats', auth, (req, res) => { const id = req.usuario.institucion_id; res.json({ totalProfes: db.prepare("SELECT COUNT(*) as total FROM usuarios WHERE rol = 'profe' AND institucion_id = ?").get(id), totalEstudiantes: db.prepare("SELECT COUNT(*) as total FROM usuarios WHERE rol = 'estudiante' AND institucion_id = ?").get(id), jugadas: db.prepare("SELECT p.juego, COUNT(*) as veces FROM progreso p JOIN usuarios u ON p.usuario_id = u.id WHERE u.institucion_id = ? GROUP BY p.juego ORDER BY veces DESC").all(id) }); });
app.get('/coordinador/profes', auth, (req, res) => res.json(db.prepare("SELECT id, nombre, usuario FROM usuarios WHERE rol = 'profe' AND institucion_id = ?").all(req.usuario.institucion_id)));
app.post('/coordinador/profes', auth, (req, res) => { try { db.prepare("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES (?, ?, ?, 'profe', ?)").run(req.body.nombre, req.body.usuario, bcrypt.hashSync(req.body.password, 10), req.usuario.institucion_id); res.json({ ok: true }); } catch { res.status(400).json({ error: 'Usuario ya existe' }); } });
app.delete('/coordinador/profes/:id', auth, (req, res) => { db.prepare("DELETE FROM usuarios WHERE id = ? AND rol = 'profe' AND institucion_id = ?").run(req.params.id, req.usuario.institucion_id); res.json({ ok: true }); });

app.get('/profesor/estudiantes', auth, (req, res) => res.json(db.prepare("SELECT id, nombre, usuario FROM usuarios WHERE rol = 'estudiante' AND institucion_id = ?").all(req.usuario.institucion_id)));
app.post('/profesor/estudiantes', auth, (req, res) => { try { db.prepare("INSERT INTO usuarios (nombre, usuario, password, rol, institucion_id) VALUES (?, ?, ?, 'estudiante', ?)").run(req.body.nombre, req.body.usuario, bcrypt.hashSync(req.body.password, 10), req.usuario.institucion_id); res.json({ ok: true }); } catch { res.status(400).json({ error: 'Usuario ya existe' }); } });
app.delete('/profesor/estudiantes/:id', auth, (req, res) => { db.prepare("DELETE FROM usuarios WHERE id = ? AND rol = 'estudiante' AND institucion_id = ?").run(req.params.id, req.usuario.institucion_id); res.json({ ok: true }); });
app.get('/profesor/clase', auth, (req, res) => res.json(db.prepare("SELECT id, nombre, usuario FROM usuarios WHERE rol = 'estudiante' AND institucion_id = ? ORDER BY nombre").all(req.usuario.institucion_id)));
app.get('/profesor/progreso', auth, (req, res) => res.json(db.prepare("SELECT u.nombre as estudiante, p.juego, MAX(p.puntaje) as puntaje FROM progreso p JOIN usuarios u ON p.usuario_id = u.id WHERE u.institucion_id = ? AND u.rol = 'estudiante' GROUP BY u.id, p.juego ORDER BY u.nombre, p.juego").all(req.usuario.institucion_id)));

app.listen(PORT, () => console.log('Servidor en puerto ' + PORT));
