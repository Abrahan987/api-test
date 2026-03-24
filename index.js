const express = require('express')
const https = require('https')
const fs = require('fs')
const path = require('path')
const bcrypt = require('bcrypt')
const session = require('express-session')
const rateLimit = require('express-rate-limit')

const app = express()
const PORT = process.env.PORT || 3000

// ═══════════════════════════════════════════════════════════════
// MIDDLEWARE & CONFIGURACIÓN
// ═══════════════════════════════════════════════════════════════

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

// Configurar sesiones
app.use(session({
    secret: process.env.SESSION_SECRET || 'tu_clave_secreta_aqui',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}))

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // máximo 100 requests
    message: 'Demasiadas requests desde esta IP'
})

// ═══════════════════════════════════════════════════════════════
// DATABASE (db.json)
// ═══════════════════════════════════════════════════════════════

const DB_PATH = path.join(__dirname, 'data', 'db.json')

function loadDB() {
    try {
        const data = fs.readFileSync(DB_PATH, 'utf8')
        return JSON.parse(data)
    } catch (err) {
        console.log('DB no existe, creando...')
        return initializeDB()
    }
}

function saveDB(db) {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2))
}

function initializeDB() {
    const initialDB = {
        users: [
            {
                id: 'admin_001',
                email: 'abrahanmoises987@gmail.com',
                password: '$2b$10$abcdefghijklmnopqrstuvwxyz', // 92127026 hasheada
                role: 'admin',
                createdAt: new Date().toISOString(),
                apiKey: 'sk_admin_' + generateKey(),
                stats: {
                    totalRequests: 0,
                    bandwidthUsed: 0,
                    lastRequest: null
                }
            }
        ],
        images: {
            anime: [],
            nsfw: []
        },
        stats: {
            totalRequests: 0,
            totalUsers: 1,
            totalApiKeys: 1,
            uptime: 99.8,
            bandwidthUsed: 0,
            requestsByCategory: { anime: 0, nsfw: 0 }
        }
    }
    saveDB(initialDB)
    return initialDB
}

let DB = loadDB()

// ═══════════════════════════════════════════════════════════════
// UTILIDADES
// ═══════════════════════════════════════════════════════════════

function generateKey() {
    return Math.random().toString(36).substr(2, 32)
}

function findUserByEmail(email) {
    return DB.users.find(u => u.email === email)
}

function findUserByKey(key) {
    return DB.users.find(u => u.apiKey === key)
}

async function hashPassword(password) {
    return await bcrypt.hash(password, 10)
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash)
}

// ═══════════════════════════════════════════════════════════════
// MIDDLEWARE DE AUTENTICACIÓN
// ═══════════════════════════════════════════════════════════════

function authMiddleware(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'No autenticado' })
    }
    next()
}

function adminMiddleware(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'No autenticado' })
    }
    const user = DB.users.find(u => u.id === req.session.userId)
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Acceso denegado - Solo administradores' })
    }
    next()
}

function apiKeyMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key']
    if (!apiKey) {
        return res.status(401).json({ error: 'API Key requerida en header X-API-Key' })
    }
    const user = findUserByKey(apiKey)
    if (!user) {
        return res.status(401).json({ error: 'API Key inválida' })
    }
    req.user = user
    next()
}

// ═══════════════════════════════════════════════════════════════
// RUTAS PÚBLICAS
// ═══════════════════════════════════════════════════════════════

// Login página
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'))
})

// Signup página
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'))
})

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, confirmPassword } = req.body

        // Validaciones
        if (!email || !password || !confirmPassword) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' })
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Las contraseñas no coinciden' })
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Contraseña muy corta (mínimo 6 caracteres)' })
        }

        // Verificar si el email ya existe
        if (findUserByEmail(email)) {
            return res.status(400).json({ error: 'Este email ya está registrado' })
        }

        // Crear nuevo usuario
        const hashedPassword = await hashPassword(password)
        const newUser = {
            id: 'user_' + Date.now(),
            email,
            password: hashedPassword,
            role: 'user',
            createdAt: new Date().toISOString(),
            apiKey: 'sk_user_' + generateKey(),
            stats: {
                totalRequests: 0,
                bandwidthUsed: 0,
                lastRequest: null
            }
        }

        DB.users.push(newUser)
        DB.stats.totalUsers++
        DB.stats.totalApiKeys++
        saveDB(DB)

        res.status(201).json({
            message: 'Usuario registrado exitosamente',
            redirect: '/login'
        })
    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Error en servidor' })
    }
})

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).json({ error: 'Email y contraseña requeridos' })
        }

        const user = findUserByEmail(email)
        if (!user) {
            return res.status(401).json({ error: 'Credenciales inválidas' })
        }

        const isPasswordValid = await verifyPassword(password, user.password)
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Credenciales inválidas' })
        }

        // Crear sesión
        req.session.userId = user.id
        req.session.userEmail = user.email
        req.session.userRole = user.role

        res.json({
            message: 'Login exitoso',
            redirect: user.role === 'admin' ? '/admin' : '/dashboard'
        })
    } catch (err) {
        console.error(err)
        res.status(500).json({ error: 'Error en servidor' })
    }
})

// GET /logout
app.get('/logout', (req, res) => {
    req.session.destroy()
    res.redirect('/login')
})

// ═══════════════════════════════════════════════════════════════
// RUTAS PROTEGIDAS (Dashboard)
// ═══════════════════════════════════════════════════════════════

// GET /dashboard
app.get('/dashboard', authMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'))
})

// GET /api/user/data
app.get('/api/user/data', authMiddleware, (req, res) => {
    const user = DB.users.find(u => u.id === req.session.userId)
    res.json({
        email: user.email,
        apiKey: user.apiKey,
        role: user.role,
        stats: user.stats,
        createdAt: user.createdAt
    })
})

// POST /api/key/regenerate
app.post('/api/key/regenerate', authMiddleware, (req, res) => {
    const user = DB.users.find(u => u.id === req.session.userId)
    user.apiKey = 'sk_' + (user.role === 'admin' ? 'admin' : 'user') + '_' + generateKey()
    saveDB(DB)
    res.json({ newKey: user.apiKey })
})

// ═══════════════════════════════════════════════════════════════
// RUTAS DE API (Endpoints principales)
// ═══════════════════════════════════════════════════════════════

// GET /api/anime - Imagen aleatoria anime
app.get('/api/anime', apiKeyMiddleware, limiter, (req, res) => {
    if (DB.images.anime.length === 0) {
        return res.status(404).json({ error: 'No hay imágenes disponibles' })
    }

    const randomImage = DB.images.anime[Math.floor(Math.random() * DB.images.anime.length)]
    
    // Incrementar estadísticas
    req.user.stats.totalRequests++
    req.user.stats.lastRequest = new Date().toISOString()
    DB.stats.totalRequests++
    DB.stats.requestsByCategory.anime++
    saveDB(DB)

    https.get(randomImage.url, (response) => {
        res.setHeader('Content-Type', response.headers['content-type'] || 'image/jpeg')
        res.setHeader('X-Image-ID', randomImage.id)
        response.pipe(res)
    }).on('error', (err) => {
        console.error(err)
        res.status(500).json({ error: 'Error al obtener la imagen' })
    })
})

// GET /api/nsfw - Imagen aleatoria NSFW (requiere verificación)
app.get('/api/nsfw', apiKeyMiddleware, limiter, (req, res) => {
    if (DB.images.nsfw.length === 0) {
        return res.status(404).json({ error: 'No hay imágenes disponibles' })
    }

    const randomImage = DB.images.nsfw[Math.floor(Math.random() * DB.images.nsfw.length)]

    // Incrementar estadísticas
    req.user.stats.totalRequests++
    req.user.stats.lastRequest = new Date().toISOString()
    DB.stats.totalRequests++
    DB.stats.requestsByCategory.nsfw++
    saveDB(DB)

    https.get(randomImage.url, (response) => {
        res.setHeader('Content-Type', response.headers['content-type'] || 'image/jpeg')
        res.setHeader('X-Image-ID', randomImage.id)
        response.pipe(res)
    }).on('error', (err) => {
        console.error(err)
        res.status(500).json({ error: 'Error al obtener la imagen' })
    })
})

// GET /api/stats - Estadísticas globales
app.get('/api/stats', (req, res) => {
    res.json(DB.stats)
})

// ═══════════════════════════════════════════════════════════════
// RUTAS ADMIN
// ═══════════════════════════════════════════════════════════════

// GET /admin
app.get('/admin', adminMiddleware, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'))
})

// GET /admin/api/users
app.get('/admin/api/users', adminMiddleware, (req, res) => {
    const users = DB.users.map(u => ({
        id: u.id,
        email: u.email,
        role: u.role,
        createdAt: u.createdAt,
        stats: u.stats
    }))
    res.json(users)
})

// GET /admin/api/images/:category
app.get('/admin/api/images/:category', adminMiddleware, (req, res) => {
    const { category } = req.params
    if (!DB.images[category]) {
        return res.status(404).json({ error: 'Categoría no encontrada' })
    }
    res.json(DB.images[category])
})

// POST /admin/api/images/:category/add
app.post('/admin/api/images/:category/add', adminMiddleware, (req, res) => {
    const { category } = req.params
    const { url } = req.body

    if (!url) {
        return res.status(400).json({ error: 'URL requerida' })
    }

    if (!DB.images[category]) {
        DB.images[category] = []
    }

    const newImage = {
        id: 'img_' + Date.now(),
        url,
        addedBy: req.session.userEmail,
        createdAt: new Date().toISOString(),
        requests: 0
    }

    DB.images[category].push(newImage)
    saveDB(DB)

    res.status(201).json(newImage)
})

// DELETE /admin/api/images/:category/:imageId
app.delete('/admin/api/images/:category/:imageId', adminMiddleware, (req, res) => {
    const { category, imageId } = req.params

    if (!DB.images[category]) {
        return res.status(404).json({ error: 'Categoría no encontrada' })
    }

    const index = DB.images[category].findIndex(img => img.id === imageId)
    if (index === -1) {
        return res.status(404).json({ error: 'Imagen no encontrada' })
    }

    DB.images[category].splice(index, 1)
    saveDB(DB)

    res.json({ message: 'Imagen eliminada' })
})

// GET /admin/api/stats
app.get('/admin/api/stats', adminMiddleware, (req, res) => {
    res.json({
        ...DB.stats,
        totalAnimeImages: DB.images.anime.length,
        totalNsfwImages: DB.images.nsfw.length
    })
})

// ═══════════════════════════════════════════════════════════════
// RUTAS DE INICIO
// ═══════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
    if (req.session && req.session.userId) {
        return res.redirect('/dashboard')
    }
    res.redirect('/login')
})

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() })
})

// ═══════════════════════════════════════════════════════════════
// MANEJO DE ERRORES
// ═══════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
    console.error(err)
    res.status(500).json({
        error: 'Error en servidor',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Error interno'
    })
})

app.use((req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' })
})

// ═══════════════════════════════════════════════════════════════
// INICIAR SERVIDOR
// ═══════════════════════════════════════════════════════════════

app.listen(PORT, () => {
    console.log(`🚀 SILIUX API corriendo en puerto ${PORT}`)
    console.log(`📊 Dashboard: http://localhost:${PORT}/login`)
    console.log(`🔑 Admin: abrahanmoises987@gmail.com / 92127026`)
    console.log(`📦 DB guardada en: ${DB_PATH}`)
})

module.exports = app
