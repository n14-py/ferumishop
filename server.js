// =============================================
//               SERVER.JS - FERUMI
//             (PARTE 1 - INICIO)
// =============================================

// IMPORTACIONES Y CONFIGURACIÓN INICIAL
// =============================================
require('dotenv').config(); // Carga las variables de .env
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const ejs = require('ejs');
const { JSDOM } = require('jsdom');
const DOMPurify = require('dompurify');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy; // APP: Login con Google
const jwt = require('jsonwebtoken'); // APP: Autenticación de la app móvil
const cors = require('cors'); // APP: Permite a Flutter conectarse a la API
const crypto = require('crypto'); // Para generar IDs únicos y códigos de regalo

// Inicialización de Express y DOMPurify (para seguridad)
const app = express();

// APP: Configuración de CORS para que la aplicación móvil no sea bloqueada
app.use(cors({
    origin: '*', // Permite conexiones desde la app
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
const PORT = process.env.PORT || 3000;
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// Configuración de EJS como motor de plantillas
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

// =============================================
// CONEXIÓN A MONGODB
// =============================================
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Conectado a MongoDB para FERUMI'))
  .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// =============================================
// CONFIGURACIÓN DE CLOUDINARY (PARA FOTOS)
// =============================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configuración de Multer (para subir imágenes de productos)
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'ferumi', // Carpeta en Cloudinary
        resource_type: 'auto',
        allowed_formats: ['jpeg', 'png', 'jpg', 'webp'],
        transformation: [
            { quality: "auto:good", fetch_format: "auto" }
        ]
    }
});
const upload = multer({ storage: storage });

// Helper para extraer el public_id de una URL de Cloudinary
const getPublicId = (url) => {
    try {
        if (!url || !url.includes('cloudinary')) return null;
        const parts = url.split('/');
        const versionIndex = parts.findIndex(part => part.startsWith('v'));
        if (versionIndex === -1) return null;
        const publicIdWithFormat = parts.slice(versionIndex + 1).join('/');
        return publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));
    } catch (e) { console.error("Error extrayendo public_id:", e); return null; }
};

// =============================================
// MODELOS DE DATOS (SCHEMAS)
// =============================================

// --- Modelo de Admin (para el panel) ---
const adminUserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    username: { type: String, required: true, default: 'Admin' }
});

// Encriptar contraseña antes de guardar
adminUserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

// =============================================
// MODELOS PARA LA APP MÓVIL Y GAMIFICACIÓN
// =============================================

// --- Modelo de Usuario de la App ---
// --- Modelo de Usuario de la App ---
const appUserSchema = new mongoose.Schema({
    googleId: { type: String, unique: true, sparse: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String }, // NUEVO: Para quienes se registran con correo
    displayName: { type: String, required: true },
    photoUrl: { type: String },
    tickets: { type: Number, default: 0 }, // Los tickets para los sorteos mensuales
    referralCode: { type: String, unique: true }, // Código para invitar amigos
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'AppUser', default: null }, // Quién lo invitó
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date, default: Date.now }
});
const AppUser = mongoose.model('AppUser', appUserSchema);

// --- Modelo de Historial de Tickets ---
const ticketHistorySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'AppUser', required: true },
    amount: { type: Number, required: true }, // Ej: +10 (ganó) o -5 (gastó)
    reason: { type: String, required: true }, // Ej: "Vio un anuncio", "Compra en tienda", "Invitación"
    date: { type: Date, default: Date.now }
});
const TicketHistory = mongoose.model('TicketHistory', ticketHistorySchema);

// --- Modelo de Categoría ---
const categorySchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true }
});

const Category = mongoose.model('Category', categorySchema);

// --- Sub-esquema para las Variantes (Ej: 30D, 40D, Tonos de base) ---
const variantSchema = new mongoose.Schema({
    name: { type: String, required: true }, // Ej: "30D", "Tono Claro"
    stock: { type: Number, default: 0 },
    photoUrl: { type: String } // Foto específica de esta variante (opcional)
});

// --- Modelo de Producto ---
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    costPrice: { type: Number, default: 0 }, // NUEVO: Precio de compra (costo)
    price: { type: Number, required: true, default: 0 }, // Precio de venta al público
    stock: { type: Number, default: 0 }, // NUEVO: Stock general (si el producto no tiene variantes)
    hasVariants: { type: Boolean, default: false }, // NUEVO: Indica si usa las opciones de abajo
    variants: [variantSchema], // NUEVO: Lista de variantes disponibles
    photos: [{ type: String }], // Array de URLs de Cloudinary (Fotos generales)
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    isFeatured: { type: Boolean, default: false }, 
    isForRent: { type: Boolean, default: false }, 
    isForSale: { type: Boolean, default: true },
    views: { type: Number, default: 0 } 
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// --- Modelo de Configuración del Sitio ---
const siteConfigSchema = new mongoose.Schema({
    configKey: { type: String, default: 'main_config', unique: true },
    whatsappNumber: { type: String, default: '595987301591' },
    whatsappMessage: { type: String, default: 'Hola, vi este producto en la web y quisiera más información: ' },
    aboutUsText: { type: String, default: 'Escribe aquí la descripción de "Sobre Nosotros".' },
    logoUrl: { type: String },
    bannerImages: [{ type: String }] // URLs de Cloudinary para el banner principal
});

const SiteConfig = mongoose.model('SiteConfig', siteConfigSchema);

// --- NUEVO: Modelo de Regalo Online ---
// --- NUEVO: Modelo de Regalo Online ---
const giftSchema = new mongoose.Schema({
    senderName: { type: String, required: true }, 
    recipientName: { type: String, required: true }, 
    message: { type: String, required: true }, 
    template: { type: String, default: 'romantico' }, 
    uniqueId: { type: String, unique: true }, 
    giftCardCode: { type: String, default: null }, 
    giftCardAmount: { type: Number, default: 0 }, 
    status: { type: String, default: 'pendiente' }, 
    isRedeemed: { type: Boolean, default: false }, 
    createdAt: { type: Date, default: Date.now },
    // --- NUEVOS CAMPOS PARA CARTAS ETERNAS ---
    giftType: { type: String, default: 'basico' }, // Tipo: 1-foto, 3-fotos, 10-fotos
    spotifyUrl: { type: String, default: '' }, // Enlace de la canción
    photos: [{ type: String }] // URLs de las fotos subidas
});

const Gift = mongoose.model('Gift', giftSchema);

// --- Modelo de Sorteos Mensuales ---
const giveawaySchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    drawDate: { type: Date, required: true },
    photos: [{ type: String }],
    instagramUrl: { type: String },
    isActive: { type: Boolean, default: true },
    winner: { type: String, default: '' } // NUEVO: Para guardar "Ganadora de Mayo: @maria"
}, { timestamps: true });

const Giveaway = mongoose.model('Giveaway', giveawaySchema);



// --- NUEVO: Modelo de Transacciones (Caja / Finanzas) ---
// --- NUEVO: Modelo de Transacciones (Caja / Finanzas) ---
const transactionSchema = new mongoose.Schema({
    type: { type: String, enum: ['ingreso', 'egreso'], required: true },
    description: { type: String, required: true }, 
    amount: { type: Number, required: true }, // Total pagado por el cliente
    cost: { type: Number, default: 0 }, // Costo de Reposición
    reinvestment: { type: Number, default: 0 }, // Costo destinado a comprar producto extra
    profitNando: { type: Number, default: 0 }, // Ganancia limpia Nando
    profitMayu: { type: Number, default: 0 }, // Ganancia limpia Mayu
    date: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// =============================================
// NUEVOS MODELOS: SISTEMA DE ASOCIADAS (IMPORTACIÓN B2B)
// =============================================

// --- 1. Modelo de Asociada (Revendedora / Lashista) ---
const associateSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true }, // Contraseña generada o creada por ellas
    phone: { type: String, required: true },
    instagram: { type: String }, // Para que tú verifiques quién es antes de aprobar
    status: { type: String, enum: ['pendiente', 'aprobada', 'rechazada'], default: 'pendiente' },
    createdAt: { type: Date, default: Date.now }
});

// Encriptar contraseña de asociada por seguridad
associateSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

const Associate = mongoose.model('Associate', associateSchema);

// --- 2. Modelo de Producto de Importación (Catálogo Exclusivo) ---
const importProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    costPrice: { type: Number, required: true }, // Lo que a ti te cuesta en China
    wholesalePrice: { type: Number, required: true }, // A lo que le vendes a la asociada (ej: 50.000)
    minQuantity: { type: Number, default: 1 }, // Por si le obligas a pedir de a 3, 5, etc.
    photos: [{ type: String }],
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
    isActive: { type: Boolean, default: true } // Para ocultar productos si ya no los traes
});

const ImportProduct = mongoose.model('ImportProduct', importProductSchema);

// --- 3. Modelo de Pedido de Importación ---
const importOrderSchema = new mongoose.Schema({
    associate: { type: mongoose.Schema.Types.ObjectId, ref: 'Associate', required: true },
    items: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'ImportProduct' },
        name: String, 
        quantity: Number,
        price: Number // Precio mayorista al momento de comprar
    }],
    totalAmount: { type: Number, required: true },
    paymentStatus: { type: String, enum: ['pendiente', 'pagado_adelantado'], default: 'pendiente' },
    // El tracking o estado del envío detallado
    shippingStatus: { type: String, enum: ['esperando_corte', 'comprado_en_origen', 'en_transito', 'en_aduana', 'listo_para_entregar', 'entregado'], default: 'esperando_corte' },
    trackingNotes: { type: String, default: 'Pedido recibido. Esperando fecha de corte para procesar la compra.' }, 
    createdAt: { type: Date, default: Date.now }
});

const ImportOrder = mongoose.model('ImportOrder', importOrderSchema);



// =============================================
// MIDDLEWARES Y PASSPORT (PARA LOGIN DE ADMIN)
// =============================================

// Middlewares básicos de Express
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(require('cookie-parser')());

app.set('trust proxy', 1);

// Configuración de Sesión
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI,
  collectionName: 'sessions',
  ttl: 14 * 24 * 60 * 60 // = 14 días
});

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        maxAge: 14 * 24 * 60 * 60 * 1000, // 14 días
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    }
}));

// Configuración de Passport.js (solo para Admin)
app.use(passport.initialize());
app.use(passport.session());

// Estrategia Local de Passport (para login del admin)
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await AdminUser.findOne({ email: email.toLowerCase() });
        if (!user) {
            return done(null, false, { message: 'Email o contraseña incorrecta.' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Email o contraseña incorrecta.' });
        }
        
        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await AdminUser.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Middleware para proteger rutas del admin
// Middleware para proteger rutas del admin
const requireAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user) {
        return next();
    } else {
        res.redirect('/admin/login');
    }
};

// APP: Middleware para proteger las rutas de la API móvil usando JWT
const requireAppUser = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Token no proporcionado o formato inválido.' });
        }

        const token = authHeader.split(' ')[1];
        // Verifica el token JWT usando el secreto del entorno (.env)
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'ferumi_secret_token_key_2026');
        
        const user = await AppUser.findById(decoded.id);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Usuario de la aplicación no encontrado.' });
        }

        req.user = user; // Guardamos el usuario autenticado de la app en la request
        next();
    } catch (err) {
        console.error('Error de autenticación JWT:', err.message);
        return res.status(401).json({ success: false, message: 'Token inválido o expirado.' });
    }
};

// =============================================
// HELPERS Y MIDDLEWARE GLOBAL (PARA EJS)
// =============================================

// Helper para formatear precio a Gs.
const formatPrice = (value) => {
    if (typeof value !== 'number') {
        value = 0;
    }
    return new Intl.NumberFormat('es-PY', {
        style: 'currency',
        currency: 'PYG',
        maximumFractionDigits: 0
    }).format(value);
};

// Middleware para pasar datos a todas las vistas (EJS)
app.use(async (req, res, next) => {
    try {
        // Carga la configuración del sitio
        let config = await SiteConfig.findOne({ configKey: 'main_config' });
        if (!config) {
            config = new SiteConfig();
            await config.save();
        }
        res.locals.siteConfig = config;
        
        // Pasa el admin actual (si está logueado)
        res.locals.currentAdmin = req.user;
        
        // Pasa helpers
        res.locals.formatPrice = formatPrice;
        
        // Pasa info de la ruta (útil para el nav)
        res.locals.path = req.path;
        res.locals.query = req.query;
        res.locals.baseUrl = process.env.BASE_URL;
        
        next();
    } catch (err) {
        next(err);
    }
});

// =============================================
// RUTAS PÚBLICAS (FRONTEND - VISTA DEL CLIENTE)
// =============================================

// --- Página de Inicio ---
// Muestra banner, categorías y productos destacados
app.get('/', async (req, res, next) => {
    try {
        const featuredProducts = await Product.find({ isFeatured: true })
            .populate('category')
            .limit(8)
            .sort({ createdAt: -1 });

        const categories = await Category.find().limit(6);
        
        res.render('public/index', {
            pageTitle: 'Inicio',
            featuredProducts,
            categories
        });
    } catch (err) {
        next(err);
    }
});

// =============================================
// PORTAL PRIVADO: ASOCIADAS B2B
// =============================================

// --- Middleware de Seguridad para Asociadas ---
// Verifica que la sesión exista y que la cuenta esté APROBADA
const requireAssociate = async (req, res, next) => {
    if (req.session.associateId) {
        try {
            const associate = await Associate.findById(req.session.associateId);
            if (associate && associate.status === 'aprobada') {
                req.associate = associate; // Guardamos los datos de la chica en la request
                return next();
            }
        } catch (err) {
            console.error(err);
        }
    }
    req.session.error = 'Debes iniciar sesión y tu cuenta debe estar aprobada para ver el catálogo mayorista.';
    res.redirect('/asociada/login');
};

// --- Página de Inicio de Sesión ---
app.get('/asociada/login', (req, res) => {
    if (req.session.associateId) return res.redirect('/asociada/panel');
    res.render('public/asociada-login', {
        pageTitle: 'Ingreso Asociadas | FERUMI',
        error: req.session.error,
        success: req.session.success
    });
    delete req.session.error;
    delete req.session.success;
});

// --- Procesar el Inicio de Sesión ---
app.post('/asociada/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const associate = await Associate.findOne({ email: email.toLowerCase() });

        if (!associate) {
            req.session.error = 'El correo no está registrado.';
            return res.redirect('/asociada/login');
        }

        if (associate.status === 'pendiente') {
            req.session.error = 'Tu cuenta aún está en revisión. Te avisaremos cuando sea aprobada.';
            return res.redirect('/asociada/login');
        }

        if (associate.status === 'rechazada') {
            req.session.error = 'Tu solicitud fue rechazada por la administración.';
            return res.redirect('/asociada/login');
        }

        const isMatch = await bcrypt.compare(password, associate.password);
        if (!isMatch) {
            req.session.error = 'Contraseña incorrecta.';
            return res.redirect('/asociada/login');
        }

        // Si todo está bien, iniciamos su sesión
        req.session.associateId = associate._id;
        res.redirect('/asociada/panel');
    } catch (err) {
        req.session.error = `Error al iniciar sesión: ${err.message}`;
        res.redirect('/asociada/login');
    }
});

// --- Cerrar Sesión ---
app.get('/asociada/logout', (req, res) => {
    req.session.associateId = null;
    res.redirect('/asociada/login');
});

// --- EL PANEL PRIVADO (Catálogo y Pedidos) ---
app.get('/asociada/panel', requireAssociate, async (req, res, next) => {
    try {
        // Traemos los productos activos para importar
        const products = await ImportProduct.find({ isActive: true }).sort({ createdAt: -1 });
        // Traemos SOLO los pedidos de esta asociada
        const orders = await ImportOrder.find({ associate: req.associate._id }).sort({ createdAt: -1 });

        res.render('public/asociada-panel', {
            pageTitle: 'Mi Portal Mayorista | FERUMI',
            associate: req.associate,
            products: products,
            orders: orders,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// --- PROCESAR UN PEDIDO DE IMPORTACIÓN ---
app.post('/asociada/pedir', requireAssociate, async (req, res, next) => {
    try {
        const { quantities } = req.body; // Será un objeto tipo: { 'id_producto': 'cantidad' }
        let orderItems = [];
        let total = 0;

        // Revisar qué productos pidió y qué cantidad
        for (const [productId, qtyStr] of Object.entries(quantities)) {
            const qty = parseInt(qtyStr);
            if (qty > 0) {
                const product = await ImportProduct.findById(productId);
                if (product && qty >= product.minQuantity) {
                    orderItems.push({
                        product: product._id,
                        name: product.name,
                        quantity: qty,
                        price: product.wholesalePrice
                    });
                    total += (product.wholesalePrice * qty);
                }
            }
        }

        if (orderItems.length === 0) {
            req.session.error = 'No seleccionaste ningún producto o no alcanzaste la cantidad mínima exigida por producto.';
            return res.redirect('/asociada/panel');
        }

        // Crear el pedido en la base de datos
        const newOrder = new ImportOrder({
            associate: req.associate._id,
            items: orderItems,
            totalAmount: total,
            paymentStatus: 'pendiente',
            shippingStatus: 'esperando_corte',
            trackingNotes: 'Pedido recibido. Por favor, realiza el pago adelantado para asegurar tu lugar en el próximo corte.'
        });

        await newOrder.save();
        req.session.success = '¡Tu pedido de importación fue registrado con éxito! Escríbenos al WhatsApp para coordinar el pago adelantado y asegurar tu compra.';
        res.redirect('/asociada/panel');
    } catch (err) {
        req.session.error = `Hubo un error al procesar tu pedido: ${err.message}`;
        res.redirect('/asociada/panel');
    }
});


// =============================================
// RUTAS PÚBLICAS: CAPTACIÓN DE ASOCIADAS B2B
// =============================================

// --- Mostrar la página informativa y formulario ---
app.get('/asociate', async (req, res, next) => {
    try {
        res.render('public/asociate', {
            pageTitle: 'Asóciate con FERUMI | Precios Mayoristas',
            cartCount: req.session.cart ? req.session.cart.length : 0,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// --- Procesar la solicitud del formulario ---
app.post('/asociate/solicitar', async (req, res, next) => {
    try {
        const { fullName, email, phone, instagram, password } = req.body;
        
        // Verificar si el correo ya mandó solicitud antes
        const existingAssociate = await Associate.findOne({ email: email.toLowerCase() });
        if (existingAssociate) {
            req.session.error = 'Este correo ya ha enviado una solicitud o ya está registrado.';
            return res.redirect('/asociate');
        }

        // Crear la nueva solicitud (estado 'pendiente' por defecto)
        const newAssociate = new Associate({
            fullName: purify.sanitize(fullName),
            email: purify.sanitize(email),
            phone: purify.sanitize(phone),
            instagram: purify.sanitize(instagram),
            password: password // Se encriptará automáticamente por el modelo que hicimos en el PASO 1
        });

        await newAssociate.save();
        
        req.session.success = '¡Solicitud enviada con éxito! Revisaremos tu perfil y te contactaremos pronto.';
        res.redirect('/asociate');
    } catch (err) {
        req.session.error = `Hubo un error al procesar tu solicitud: ${err.message}`;
        res.redirect('/asociate');
    }
});


// --- Página de Tienda (Galería de Productos) ---
// Muestra todos los productos, con filtros
app.get('/tienda', async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const itemsPerPage = 12;
        let query = {};
        const { q, categoria, tipo } = req.query;

        // Búsqueda por texto
        if (q) {
            query.name = { $regex: q, $options: 'i' };
        }

        // Filtro por categoría
        if (categoria) {
            const categoryDoc = await Category.findOne({ name: categoria });
            if (categoryDoc) {
                query.category = categoryDoc._id;
            }
        }
        
        // Filtro por tipo (Venta o Alquiler)
        if (tipo === 'venta') {
            query.isForSale = true;
        } else if (tipo === 'alquiler') {
            query.isForRent = true;
        }

        const totalProducts = await Product.countDocuments(query);
        const totalPages = Math.ceil(totalProducts / itemsPerPage);
        
        const products = await Product.find(query)
            .populate('category')
            .sort({ createdAt: -1 })
            .skip((page - 1) * itemsPerPage)
            .limit(itemsPerPage);
            
        const categories = await Category.find();

        res.render('public/tienda', {
            pageTitle: 'Tienda',
            products,
            categories,
            currentPage: page,
            totalPages,
            query: req.query // Para mantener los filtros en la paginación
        });
    } catch (err) {
        next(err);
    }
});

// --- Página de Vista de Producto ---
// Muestra el detalle de un solo producto
app.get('/producto/:id', async (req, res, next) => {
    try {
        const product = await Product.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
            .populate('category');

        if (!product) {
            return res.status(404).render('public/error', { message: 'Producto no encontrado.' });
        }
        
        // Sanear descripción
        product.description = purify.sanitize(product.description, { USE_PROFILES: { html: true } });

        // Productos recomendados (de la misma categoría)
        const recommendedProducts = await Product.find({
            category: product.category._id,
            _id: { $ne: product._id } // Excluir el producto actual
        }).limit(4);

        res.render('public/producto-detalle', {
            pageTitle: product.name,
            product,
            recommendedProducts
        });
    } catch (err) {
        next(err);
    }
});

// --- Página de Categoría ---
// Muestra productos filtrados por una categoría
app.get('/categoria/:name', async (req, res, next) => {
    try {
        const categoryName = req.params.name;
        const category = await Category.findOne({ name: categoryName });

        if (!category) {
            return res.status(404).render('public/error', { message: 'Categoría no encontrada.' });
        }

        const products = await Product.find({ category: category._id })
            .populate('category')
            .sort({ createdAt: -1 });

        res.render('public/tienda', { // Reutilizamos la vista de la tienda
            pageTitle: `Categoría: ${category.name}`,
            products,
            categories: await Category.find(),
            currentPage: 1,
            totalPages: 1,
            query: req.query
        });
    } catch (err) {
        next(err);
    }
});

// --- Página "Sobre Nosotros" ---
app.get('/sobre-nosotros', (req, res) => {
    res.render('public/sobre-nosotros', {
        pageTitle: 'Sobre Nosotros'
    });
});

// --- Página "Contacto" ---
app.get('/contacto', (req, res) => {
    res.render('public/contacto', {
        pageTitle: 'Contacto'
    });
});

// Ruta para la página de Enlaces (Bio Links)
app.get('/links', (req, res) => {
    res.render('public/enlaces', { pageTitle: 'FERUMI - Enlaces' });
});



// =============================================
//               SERVER.JS - FERUMI
//             (PARTE 2 - FINAL)
// =============================================

// =============================================
// RUTAS DE REGALOS (CLIENTE - NUEVO)
// =============================================

// 1. Página para crear el regalo (Formulario)
app.get('/regalos/crear', (req, res) => {
    res.render('public/crear-regalo', {
        pageTitle: 'Enviar Regalo Online'
    });
});

// 2. Procesar la creación del regalo (Estado: Pendiente)
// 2. Procesar la creación del regalo (Estado: Pendiente)
app.post('/regalos/crear', upload.array('photos', 10), async (req, res, next) => {
    try {
        const { senderName, recipientName, message, shortMessage, template, giftType, spotifyUrl, amount } = req.body;
        
        const uniqueId = 'regalo-' + crypto.randomBytes(4).toString('hex');

        // El monto extra para que gaste en la tienda (Gift Card)
        const giftAmount = parseFloat(amount || 0);

        // Determinar qué mensaje usar (Si es solo Gift Card, usamos el título corto)
        const finalMessage = giftType === 'gift-card' ? shortMessage : message;

        // Extraer las URLs de las fotos
        let uploadedPhotos = req.files ? req.files.map(f => f.path) : [];

        const newGift = new Gift({
            senderName: purify.sanitize(senderName),
            recipientName: purify.sanitize(recipientName),
            message: purify.sanitize(finalMessage || 'Un detalle especial.'),
            template: template || 'romantico',
            giftCardAmount: giftAmount,
            uniqueId: uniqueId,
            status: 'pendiente',
            giftType: giftType || '1-foto',
            spotifyUrl: purify.sanitize(spotifyUrl || ''),
            photos: uploadedPhotos
        });

        await newGift.save();

        res.redirect(`/regalos/confirmacion/${newGift._id}`);

    } catch (err) {
        next(err); 
    }
});

// 3. Página de Confirmación / Instrucciones de Pago
app.get('/regalos/confirmacion/:id', async (req, res, next) => {
    try {
        const gift = await Gift.findById(req.params.id);
        if (!gift) return res.redirect('/regalos/crear');
        
        // Calculamos el costo del servicio en base al paquete elegido
        let serviceCost = 0;
        if (gift.giftType === '1-foto') serviceCost = 5000;
        else if (gift.giftType === '3-fotos') serviceCost = 12000;
        else if (gift.giftType === '10-fotos') serviceCost = 25000;
        else if (gift.giftType === 'gift-card') serviceCost = 0; // Solo paga el monto que eligió regalar
        
        res.render('public/pago-regalo', { 
            pageTitle: 'Confirmar Regalo',
            gift: gift,
            serviceCost: serviceCost
        });
    } catch (err) {
        next(err);
    }
});

// 4. Ver el Regalo FINAL (La carta pública)
// Esta es la URL que se le comparte a la persona regalada
app.get('/ver-regalo/:uniqueId', async (req, res, next) => {
    try {
        const gift = await Gift.findOne({ uniqueId: req.params.uniqueId });
        
        // Si no existe
        if (!gift) {
            return res.status(404).render('public/error', { message: 'Regalo no encontrado o enlace incorrecto.' });
        }
        
        // Si el regalo NO está aprobado por el admin
        if (gift.status !== 'aprobado') {
            return res.render('public/error', { 
                pageTitle: 'Regalo en proceso', 
                message: '¡Sorpresa en camino! Este regalo se está preparando. El administrador aún está confirmando el envío.' 
            });
        }

        // Renderizar la vista de la carta
// --- INICIO NUEVO SISTEMA DE PLANTILLAS SEPARADAS ---
        let plantilla = 'public/vista-regalo'; // Por defecto o si eligen "Solo Gift Card"

        if (gift.template === 'romantico') {
            plantilla = 'public/regalo-romantico';
        } else if (gift.template === 'cumpleanos') {
            plantilla = 'public/regalo-cumpleanos';
        } else if (gift.template === 'elegante') {
            plantilla = 'public/regalo-elegante';
        }

        // Renderizar la vista correspondiente a lo que eligió el cliente
        res.render(plantilla, { 
            pageTitle: `Regalo para ${gift.recipientName} ❤️`,
            gift: gift 
        });
        // --- FIN NUEVO SISTEMA ---

    } catch (err) {
        next(err);
    }
});

// =============================================
// RUTAS API (PARA FUNCIONES DINÁMICAS)
// =============================================


// --- APP: API para Registro con Correo desde la Aplicación Móvil ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, referralCodeUsed } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ success: false, message: 'Todos los campos son obligatorios.' });
        }

        // 1. Verificamos si ya existe alguien con ese correo
        let user = await AppUser.findOne({ email: email.toLowerCase() });
        if (user) {
            return res.status(400).json({ success: false, message: 'El correo ya está registrado.' });
        }

        // 2. Encriptamos la contraseña para que no se guarde en texto plano
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Generar un código de referidos exclusivo para esta usuaria
        let uniqueReferral = 'FER-' + crypto.randomBytes(2).toString('hex').toUpperCase();
        let checkingCode = await AppUser.findOne({ referralCode: uniqueReferral });
        while (checkingCode) {
            uniqueReferral = 'FER-' + crypto.randomBytes(2).toString('hex').toUpperCase();
            checkingCode = await AppUser.findOne({ referralCode: uniqueReferral });
        }

        // 4. Lógica de recompensas si fue invitada por alguien
        let referredByUserId = null;
        if (referralCodeUsed) {
            const referrer = await AppUser.findOne({ referralCode: referralCodeUsed.toUpperCase().trim() });
            if (referrer) {
                referredByUserId = referrer._id;
                referrer.tickets += 5; // Premio para la anfitriona
                await referrer.save();

                await new TicketHistory({
                    user: referrer._id,
                    amount: 5,
                    reason: `Invitó con éxito a una nueva usuaria (${email})`
                }).save();
            }
        }

        // 5. Crear la usuaria con 10 tickets de regalo
        user = new AppUser({
            email: email.toLowerCase(),
            password: hashedPassword,
            displayName: name,
            tickets: 10,
            referralCode: uniqueReferral,
            referredBy: referredByUserId
        });

        await user.save();

        await new TicketHistory({
            user: user._id,
            amount: 10,
            reason: '¡Bono de bienvenida a Ferumi Shop!'
        }).save();

        // 6. Emitir su "Llave" de sesión
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET || 'ferumi_secret_token_key_2026',
            { expiresIn: '30d' }
        );

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                displayName: user.displayName,
                email: user.email,
                photoUrl: '',
                tickets: user.tickets,
                referralCode: user.referralCode
            }
        });
    } catch (err) {
        console.error('Error crítico en /api/auth/register:', err);
        res.status(500).json({ success: false, message: 'Error interno en el servidor.' });
    }
});

// --- APP: API para Login con Correo desde la Aplicación Móvil ---
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Correo y contraseña son obligatorios.' });
        }

        // 1. Buscamos a la usuaria
        const user = await AppUser.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(400).json({ success: false, message: 'Credenciales incorrectas.' });
        }

        // 2. Si se registró con Google, no tiene contraseña, le avisamos
        if (!user.password) {
            return res.status(400).json({ success: false, message: 'Esta cuenta se creó con Google. Usa el botón de Google para entrar.' });
        }

        // 3. Verificamos que la contraseña sea exactamente la misma
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Credenciales incorrectas.' });
        }

        user.lastLogin = new Date();
        await user.save();

        // 4. Emitir su "Llave" de sesión
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET || 'ferumi_secret_token_key_2026',
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                displayName: user.displayName,
                email: user.email,
                photoUrl: user.photoUrl || '',
                tickets: user.tickets,
                referralCode: user.referralCode
            }
        });
    } catch (err) {
        console.error('Error crítico en /api/auth/login:', err);
        res.status(500).json({ success: false, message: 'Error interno en el servidor.' });
    }
});


// --- APP: API para Login / Registro con Google desde la Aplicación Móvil ---
app.post('/api/auth/google', async (req, res) => {
    try {
        const { email, displayName, photoUrl, googleId, referralCodeUsed } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: 'El correo electrónico es obligatorio.' });
        }

        // 1. Buscar si el usuario ya existe en el ecosistema de la app
        let user = await AppUser.findOne({ email: email.toLowerCase() });

        if (!user) {
            // Generar un código de referidos exclusivo para este nuevo usuario (Ej: FER-X8Z2)
            let uniqueReferral = 'FER-' + crypto.randomBytes(2).toString('hex').toUpperCase();
            let checkingCode = await AppUser.findOne({ referralCode: uniqueReferral });
            
            // Bucle de seguridad por si de forma remota se duplica el código aleatorio
            while (checkingCode) {
                uniqueReferral = 'FER-' + crypto.randomBytes(2).toString('hex').toUpperCase();
                checkingCode = await AppUser.findOne({ referralCode: uniqueReferral });
            }

            // 2. Si ingresó el código de una amiga que la invitó, buscamos a la anfitriona
            let referredByUserId = null;
            if (referralCodeUsed) {
                const referrer = await AppUser.findOne({ referralCode: referralCodeUsed.toUpperCase().trim() });
                if (referrer) {
                    referredByUserId = referrer._id;
                    
                    // Recompensa inmediata al que invitó (+5 tickets al marcador de sorteo)
                    referrer.tickets += 5;
                    await referrer.save();

                    // Registramos la acción en el historial de la asociada/amiga que invitó
                    await new TicketHistory({
                        user: referrer._id,
                        amount: 5,
                        reason: `Invitó con éxito a una nueva usuaria (${email})`
                    }).save();
                }
            }

            // 3. Crear el perfil del nuevo usuario obsequiando 10 tickets por unirse
            user = new AppUser({
                googleId,
                email: email.toLowerCase(),
                displayName,
                photoUrl,
                tickets: 10,
                referralCode: uniqueReferral,
                referredBy: referredByUserId
            });

            await user.save();

            // Guardar el registro de los puntos ganados de bienvenida
            await new TicketHistory({
                user: user._id,
                amount: 10,
                reason: '¡Bono de bienvenida a Ferumi Shop!'
            }).save();

        } else {
            // Si el usuario ya existe, actualizamos su marca de tiempo y metadatos dinámicos
            user.lastLogin = new Date();
            if (googleId) user.googleId = googleId;
            if (photoUrl) user.photoUrl = photoUrl;
            await user.save();
        }

        // 4. Emitir el token firmado por JWT para que el smartphone recuerde la sesión por 30 días
        const token = jwt.sign(
            { id: user._id, email: user.email },
            process.env.JWT_SECRET || 'ferumi_secret_token_key_2026',
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            message: 'Autenticación procesada con éxito.',
            token,
            user: {
                id: user._id,
                displayName: user.displayName,
                email: user.email,
                photoUrl: user.photoUrl,
                tickets: user.tickets,
                referralCode: user.referralCode
            }
        });

    } catch (err) {
        console.error('Error crítico en /api/auth/google:', err);
        res.status(500).json({ success: false, message: 'Error interno en el servidor backend.' });
    }
});

// --- API para Validar Cupones / Gift Cards desde el Carrito ---
app.post('/api/regalos/validar', async (req, res) => {
    try {
        const { code } = req.body;
        if (!code) return res.json({ success: false, message: 'Código no proporcionado' });

        // Busca el regalo por el código, que esté aprobado y que NO haya sido canjeado aún
        const gift = await Gift.findOne({ 
            giftCardCode: code.toUpperCase().trim(),
            status: 'aprobado',
            isRedeemed: false 
        });

        if (gift) {
            res.json({ 
                success: true, 
                regalo: { code: gift.giftCardCode, amount: gift.giftCardAmount } 
            });
        } else {
            res.json({ success: false, message: 'Código inválido o ya utilizado' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error en el servidor' });
    }
});



// --- API para el Buscador Instantáneo ---
app.get('/api/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.length < 2) {
            return res.json([]);
        }
        
        const products = await Product.find({
            name: { $regex: q, $options: 'i' }
        })
        .select('name photos _id') // Solo trae los datos necesarios
        .limit(5); // Límite de 5 resultados
        
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// =============================================
// RUTAS API (EXCLUSIVAS PARA LA APP FLUTTER)
// =============================================

// --- APP: Obtener el Catálogo de Productos ---
app.get('/api/app/productos', async (req, res) => {
    try {
        const products = await Product.find({ isForSale: true })
            .populate('category')
            .sort({ createdAt: -1 });
        res.json({ success: true, products });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error al obtener productos del servidor.' });
    }
});

// --- APP: Obtener el Sorteo Activo del Mes ---
app.get('/api/app/sorteo-activo', async (req, res) => {
    try {
        const activeGiveaway = await Giveaway.findOne({ isActive: true }).sort({ drawDate: 1 });
        if (!activeGiveaway) {
            return res.json({ success: true, giveaway: null, message: 'No hay sorteos activos en este momento.' });
        }
        res.json({ success: true, giveaway: activeGiveaway });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error al obtener el sorteo.' });
    }
});

// --- APP: Reclamar Tickets por ver un Anuncio (Ruta Protegida) ---
app.post('/api/app/tickets/anuncio', requireAppUser, async (req, res) => {
    try {
        // req.user viene del middleware requireAppUser
        const user = req.user; 
        
        // Sumamos 2 tickets por ver el anuncio en la app
        user.tickets += 2;
        await user.save();

        // Registramos la acción en su historial financiero/gamificado
        await new TicketHistory({
            user: user._id,
            amount: 2,
            reason: 'Recompensa por visualizar anuncio patrocinado'
        }).save();

        res.json({ success: true, message: '¡Felicidades! Ganaste 2 tickets.', tickets: user.tickets });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Error al procesar la recompensa en el servidor.' });
    }
});


// =============================================
// RUTAS DEL PANEL ADMINISTRATIVO (BACKEND)
// =============================================

// --- Rutas de Login de Admin ---
app.get('/admin/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/admin/dashboard');
    }
    const error = req.session.error;
    delete req.session.error;
    res.render('admin/login', { error });
});

app.post('/admin/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) {
            req.session.error = info.message;
            return res.redirect('/admin/login');
        }
        req.logIn(user, (err) => {
            if (err) return next(err);
            return res.redirect('/admin/dashboard');
        });
    })(req, res, next);
});

app.get('/admin/logout', requireAdmin, (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/admin/login');
    });
});



// --- Dashboard (Página principal del Admin) ---
app.get('/admin', requireAdmin, (req, res) => res.redirect('/admin/dashboard'));

app.get('/admin/dashboard', requireAdmin, async (req, res, next) => {
    try {
        const totalProducts = await Product.countDocuments();
        const totalCategories = await Category.countDocuments();
        const pendingGifts = await Gift.countDocuments({ status: 'pendiente' });
        
        // APP: Nuevas estadísticas para la gamificación y usuarios móviles
        const totalAppUsers = await AppUser.countDocuments();
        // Calculamos cuántos tickets hay en circulación sumando los de todos los usuarios
        const allUsers = await AppUser.find({}, 'tickets'); 
        const totalTicketsInCirculation = allUsers.reduce((sum, user) => sum + (user.tickets || 0), 0);
        
        const mostViewedProducts = await Product.find()
            .sort({ views: -1 })
            .limit(5)
            .populate('category');
        
        const stats = {
            totalProducts: totalProducts,
            totalCategories: totalCategories,
            pendingGifts: pendingGifts,
            totalAppUsers: totalAppUsers, // APP: Total usuarios en Flutter
            totalTickets: totalTicketsInCirculation // APP: Total de tickets
        };

        res.render('admin/dashboard', {
            pageTitle: 'Dashboard',
            stats: stats,
            mostViewedProducts
        });
    } catch (err) {
        next(err);
    }
});

// =============================================
// GESTIÓN DE PRODUCTOS (ADMIN)
// =============================================

// --- Ver todos los productos ---
app.get('/admin/productos', requireAdmin, async (req, res, next) => {
    try {
        const products = await Product.find().populate('category').sort({ createdAt: -1 });
        const categories = await Category.find();
        
        res.render('admin/productos', {
            pageTitle: 'Gestionar Productos',
            products,
            categories,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// --- Añadir nuevo producto ---
// --- Añadir nuevo producto ---
// --- Añadir nuevo producto ---
app.post('/admin/productos/add', requireAdmin, upload.any(), async (req, res, next) => {
    try {
        const { name, description, costPrice, price, stock, category, isForRent, isForSale, isFeatured, hasVariants, variantNames, variantStocks } = req.body;
        
        // 1. Filtrar las fotos generales (ahora SIN LÍMITE)
        const mainPhotos = req.files ? req.files.filter(f => f.fieldname === 'photos').map(f => f.path) : [];
        
        if (mainPhotos.length === 0) {
            throw new Error('Debes subir al menos una foto general del producto.');
        }

        // 2. Construir las opciones (Variantes) y atrapar la foto de cada una
        let variantsArray = [];
        let totalVariantStock = 0;

        if (hasVariants === 'on' && variantNames) {
            const names = Array.isArray(variantNames) ? variantNames : [variantNames];
            const stocks = Array.isArray(variantStocks) ? variantStocks : [variantStocks];

            for (let i = 0; i < names.length; i++) {
                if (names[i].trim() !== '') {
                    const vStock = parseInt(stocks[i]) || 0;
                    // Buscar si subiste una foto específica para esta pestaña/tono
                    const variantFile = req.files.find(f => f.fieldname === `variantPhoto_${i}`);
                    
                    variantsArray.push({
                        name: purify.sanitize(names[i]),
                        stock: vStock,
                        photoUrl: variantFile ? variantFile.path : '' // Guarda la foto del "Efecto Anime", etc.
                    });
                    totalVariantStock += vStock;
                }
            }
        }

        const finalStock = (hasVariants === 'on') ? totalVariantStock : (parseInt(stock) || 0);

        const newProduct = new Product({
            name: purify.sanitize(name),
            description: purify.sanitize(description, { USE_PROFILES: { html: true } }),
            costPrice: parseInt(costPrice.toString().replace(/\./g, '')) || 0,
            price: parseInt(price.toString().replace(/\./g, '')) || 0,
            stock: finalStock,
            hasVariants: hasVariants === 'on',
            variants: variantsArray,
            category,
            photos: mainPhotos,
            isForRent: isForRent === 'on',
            isForSale: isForSale === 'on',
            isFeatured: isFeatured === 'on'
        });
        
        await newProduct.save();
        req.session.success = '¡Producto añadido con éxito!';
        res.redirect('/admin/productos');
    } catch (err) {
        req.session.error = `Error al añadir producto: ${err.message}`;
        res.redirect('/admin/productos');
    }
});

// --- Página para editar un producto (GET) ---
// --- Página para editar un producto (GET) ---
app.get('/admin/producto/edit/:id', requireAdmin, async (req, res, next) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            req.session.error = 'Producto no encontrado.';
            return req.session.save(() => res.redirect('/admin/productos'));
        }
        const categories = await Category.find();
        
        res.render('admin/edit-producto', {
            pageTitle: `Editar: ${product.name}`,
            product,
            categories,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// --- Actualizar un producto (POST) ---
// --- Actualizar un producto (POST) ---
app.post('/admin/producto/edit/:id', requireAdmin, upload.any(), async (req, res, next) => {
    try {
        const { name, description, costPrice, price, stock, category, isForRent, isForSale, isFeatured, existing_photos, hasVariants, variantNames, variantStocks, existingVariantPhotos } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) throw new Error('Producto no encontrado.');

        // 1. Eliminar fotos principales que el admin desmarcó de la galería
        const photosToKeep = existing_photos ? (Array.isArray(existing_photos) ? existing_photos : [existing_photos]) : [];
        const photosToDelete = product.photos.filter(url => !photosToKeep.includes(url));
        
        for (const url of photosToDelete) {
            const publicId = getPublicId(url);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }
        
        // 2. Añadir nuevas fotos principales (SIN LÍMITE)
        const newMainPhotos = req.files ? req.files.filter(f => f.fieldname === 'new_photos').map(f => f.path) : [];
        
        // 3. Procesar las opciones (Efecto Anime, Efecto B) y sus fotos específicas
        let variantsArray = [];
        let totalVariantStock = 0;

        if (hasVariants === 'on' && variantNames) {
            const names = Array.isArray(variantNames) ? variantNames : [variantNames];
            const stocks = Array.isArray(variantStocks) ? variantStocks : [variantStocks];
            const oldVariantPhotos = existingVariantPhotos ? (Array.isArray(existingVariantPhotos) ? existingVariantPhotos : [existingVariantPhotos]) : [];

            for (let i = 0; i < names.length; i++) {
                if (names[i].trim() !== '') {
                    const vStock = parseInt(stocks[i]) || 0;
                    // Buscar si se subió una foto nueva exclusivamente para esta pestaña
                    const newVariantFile = req.files.find(f => f.fieldname === `variantPhoto_${i}`);
                    
                    let finalPhotoUrl = '';
                    if (newVariantFile) {
                        finalPhotoUrl = newVariantFile.path; // Se subió una foto nueva para el Efecto
                    } else if (oldVariantPhotos[i]) {
                        finalPhotoUrl = oldVariantPhotos[i]; // Conservar la foto que ya tenía
                    }

                    variantsArray.push({
                        name: purify.sanitize(names[i]),
                        stock: vStock,
                        photoUrl: finalPhotoUrl // Guardamos la foto en la base de datos
                    });
                    totalVariantStock += vStock;
                }
            }
        }

        const finalStock = (hasVariants === 'on') ? totalVariantStock : (parseInt(stock) || 0);

        // 4. Actualizar todo el producto
        product.name = purify.sanitize(name);
        product.description = purify.sanitize(description, { USE_PROFILES: { html: true } });
        product.costPrice = parseInt(costPrice?.toString().replace(/\./g, '')) || 0;
        product.price = parseInt(price?.toString().replace(/\./g, '')) || 0;
        product.stock = finalStock;
        product.hasVariants = hasVariants === 'on';
        product.variants = variantsArray;
        product.category = category;
        product.photos = [...photosToKeep, ...newMainPhotos]; // Guarda todas las fotos ilimitadas
        product.isForRent = isForRent === 'on';
        product.isForSale = isForSale === 'on';
        product.isFeatured = isFeatured === 'on';
        
        await product.save();
        req.session.success = '¡Producto actualizado con éxito!';
        req.session.save(() => res.redirect('/admin/productos'));
    } catch (err) {
        req.session.error = `Error al actualizar: ${err.message}`;
        req.session.save(() => res.redirect(`/admin/producto/edit/${req.params.id}`));
    }
});

// --- Eliminar un producto (POST) ---
app.post('/admin/producto/delete/:id', requireAdmin, async (req, res, next) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) throw new Error('Producto no encontrado.');

        // Eliminar todas las fotos de Cloudinary
        for (const url of product.photos) {
            const publicId = getPublicId(url);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }

        // Eliminar el producto de la base de datos
        await Product.findByIdAndDelete(req.params.id);
        
        req.session.success = '¡Producto eliminado con éxito!';
        res.redirect('/admin/productos');
    } catch (err) {
        req.session.error = `Error al eliminar: ${err.message}`;
        res.redirect('/admin/productos');
    }
});


// =============================================
// GESTIÓN DE SORTEOS (ADMIN Y PÚBLICO)
// =============================================

// --- PÚBLICO: Ver Sorteo Activo ---
// --- PÚBLICO: Ver Sorteo Activo y Ganadoras Anteriores ---
app.get('/sorteos', async (req, res, next) => {
    try {
        // Buscar el sorteo activo más próximo
        const activeGiveaway = await Giveaway.findOne({ isActive: true }).sort({ drawDate: 1 });
        
        // NUEVO: Buscar sorteos anteriores que ya tengan ganadora
        const pastWinners = await Giveaway.find({ isActive: false, winner: { $ne: '' } }).sort({ drawDate: -1 });

        res.render('public/sorteos', {
            pageTitle: 'Sorteos Mensuales FERUMI',
            giveaway: activeGiveaway,
            pastWinners: pastWinners
        });
    } catch (err) {
        next(err);
    }
});

// --- ADMIN: Ver lista de sorteos ---
app.get('/admin/sorteos', requireAdmin, async (req, res, next) => {
    try {
        const giveaways = await Giveaway.find().sort({ createdAt: -1 });
        res.render('admin/sorteos', {
            pageTitle: 'Gestionar Sorteos',
            giveaways,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});


// --- ADMIN: Registrar Ganadora de un Sorteo ---
app.post('/admin/sorteos/winner/:id', requireAdmin, async (req, res, next) => {
    try {
        const { winner } = req.body;
        // Al registrar ganadora, el sorteo ya no está "activo" para participar
        await Giveaway.findByIdAndUpdate(req.params.id, {
            winner: purify.sanitize(winner),
            isActive: false 
        });
        req.session.success = '¡Ganadora registrada con éxito!';
        res.redirect('/admin/sorteos');
    } catch (err) {
        req.session.error = `Error al registrar ganadora: ${err.message}`;
        res.redirect('/admin/sorteos');
    }
});

// --- ADMIN: Crear nuevo sorteo ---
app.post('/admin/sorteos/add', requireAdmin, upload.array('photos', 5), async (req, res, next) => {
    try {
        const { title, description, drawDate, instagramUrl } = req.body;
        
        const newGiveaway = new Giveaway({
            title: purify.sanitize(title),
            description: purify.sanitize(description, { USE_PROFILES: { html: true } }),
            drawDate: new Date(drawDate),
            instagramUrl: purify.sanitize(instagramUrl),
            photos: req.files ? req.files.map(f => f.path) : []
        });
        
        await newGiveaway.save();
        req.session.success = '¡Sorteo programado con éxito!';
        res.redirect('/admin/sorteos');
    } catch (err) {
        req.session.error = `Error al crear sorteo: ${err.message}`;
        res.redirect('/admin/sorteos');
    }
});

// --- ADMIN: Eliminar sorteo ---
app.post('/admin/sorteos/delete/:id', requireAdmin, async (req, res, next) => {
    try {
        const giveaway = await Giveaway.findById(req.params.id);
        if(giveaway) {
            for (const url of giveaway.photos) {
                const publicId = getPublicId(url);
                if (publicId) await cloudinary.uploader.destroy(publicId);
            }
            await Giveaway.findByIdAndDelete(req.params.id);
        }
        req.session.success = 'Sorteo eliminado correctamente.';
        res.redirect('/admin/sorteos');
    } catch (err) {
        req.session.error = `Error al eliminar: ${err.message}`;
        res.redirect('/admin/sorteos');
    }
});


// =============================================
// GESTIÓN DE CATEGORÍAS (ADMIN)
// =============================================
app.get('/admin/categorias', requireAdmin, async (req, res, next) => {
    try {
        const categories = await Category.find();
        res.render('admin/categorias', {
            pageTitle: 'Gestionar Categorías',
            categories,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

app.post('/admin/categorias/add', requireAdmin, async (req, res, next) => {
    try {
        const { name } = req.body;
        if (!name) throw new Error('El nombre es obligatorio.');
        
        const existing = await Category.findOne({ name: name });
        if (existing) throw new Error('Esa categoría ya existe.');

        await new Category({ name }).save();
        req.session.success = 'Categoría creada con éxito.';
        res.redirect('/admin/categorias');
    } catch (err) {
        req.session.error = `Error: ${err.message}`;
        res.redirect('/admin/categorias');
    }
});

app.post('/admin/categorias/delete/:id', requireAdmin, async (req, res, next) => {
    try {
        const categoryId = req.params.id;
        // Revisar si algún producto usa esta categoría
        const productCount = await Product.countDocuments({ category: categoryId });
        if (productCount > 0) {
            throw new Error(`No se puede eliminar. ${productCount} producto(s) están usando esta categoría.`);
        }
        
        await Category.findByIdAndDelete(categoryId);
        req.session.success = 'Categoría eliminada.';
        res.redirect('/admin/categorias');
    } catch (err) {
        req.session.error = `Error: ${err.message}`;
        res.redirect('/admin/categorias');
    }
});

// =============================================
// GESTIÓN DE CONTENIDO DEL SITIO (ADMIN)
// =============================================
app.get('/admin/configuracion', requireAdmin, async (req, res, next) => {
    try {
        res.render('admin/configuracion', {
            pageTitle: 'Configuración del Sitio',
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// Actualizar textos y WhatsApp
app.post('/admin/configuracion/update', requireAdmin, async (req, res, next) => {
    try {
        const { whatsappNumber, whatsappMessage } = req.body;
        
        await SiteConfig.findOneAndUpdate(
            { configKey: 'main_config' },
            {
            whatsappNumber: purify.sanitize(whatsappNumber),
            whatsappMessage: purify.sanitize(whatsappMessage)
        },
            { upsert: true, new: true } // Crea la config si no existe
        );
        
        req.session.success = 'Configuración guardada con éxito.';
        res.redirect('/admin/configuracion');
    } catch (err) {
        req.session.error = `Error: ${err.message}`;
        res.redirect('/admin/configuracion');
    }
});

// Actualizar el Logo
app.post('/admin/configuracion/logo', requireAdmin, upload.single('logo'), async (req, res, next) => {
    try {
        if (!req.file) throw new Error('No se seleccionó ningún archivo.');
        
        const config = await SiteConfig.findOne({ configKey: 'main_config' });

        // Borrar el logo anterior de Cloudinary si existe
        if (config.logoUrl) {
            const publicId = getPublicId(config.logoUrl);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }

        // Guardar el nuevo logo
        await SiteConfig.updateOne({ configKey: 'main_config' }, { logoUrl: req.file.path });
        
        req.session.success = 'Logo actualizado.';
        res.redirect('/admin/configuracion');
    } catch (err) {
        req.session.error = `Error: ${err.message}`;
        res.redirect('/admin/configuracion');
    }
});

// --- Añadir un nuevo Banner ---
app.post('/admin/configuracion/banner/add', requireAdmin, upload.single('bannerImage'), async (req, res, next) => {
    try {
        if (!req.file) throw new Error('No se seleccionó ningún archivo de imagen.');
        
        const config = await SiteConfig.findOne({ configKey: 'main_config' });
        if (!config) throw new Error('Configuración no encontrada.');

        // Añade la nueva URL de imagen al array de banners
        config.bannerImages.push(req.file.path);
        await config.save();
        
        req.session.success = 'Nuevo banner añadido con éxito.';
        res.redirect('/admin/configuracion');
    } catch (err) {
        req.session.error = `Error al añadir banner: ${err.message}`;
        res.redirect('/admin/configuracion');
    }
});

// --- Eliminar un Banner ---
app.post('/admin/configuracion/banner/delete', requireAdmin, async (req, res, next) => {
    try {
        const { bannerUrl } = req.body;
        if (!bannerUrl) throw new Error('No se especificó la URL del banner a eliminar.');

        // 1. Eliminar de Cloudinary
        const publicId = getPublicId(bannerUrl);
        if (publicId) {
            await cloudinary.uploader.destroy(publicId);
        }

        // 2. Eliminar de la base de datos (del array)
        await SiteConfig.updateOne(
            { configKey: 'main_config' },
            { $pull: { bannerImages: bannerUrl } }
        );
        
        req.session.success = 'Banner eliminado con éxito.';
        res.redirect('/admin/configuracion');
    } catch (err) {
        req.session.error = `Error al eliminar banner: ${err.message}`;
        res.redirect('/admin/configuracion');
    }
});

// =============================================
// GESTIÓN DE REGALOS (ADMIN - NUEVO)
// =============================================

// 1. Ver lista de regalos (pendientes y aprobados)
app.get('/admin/regalos', requireAdmin, async (req, res, next) => {
    try {
        // Obtenemos todos los regalos ordenados por fecha
        const gifts = await Gift.find().sort({ createdAt: -1 });
        
        res.render('admin/regalos', {
            pageTitle: 'Gestionar Regalos',
            gifts: gifts,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// 2. Aprobar un regalo (Generar Código)
// Cuando el admin confirma el pago, llama a esta ruta
app.post('/admin/regalos/approve/:id', requireAdmin, async (req, res, next) => {
    try {
        const gift = await Gift.findById(req.params.id);
        if (!gift) throw new Error('Regalo no encontrado');

        // Generar código aleatorio de Gift Card (Ej: FERUMI-X8Z2-99AA)
        const code = 'FERUMI-' + crypto.randomBytes(3).toString('hex').toUpperCase();

        gift.status = 'aprobado';
        gift.giftCardCode = code;
        await gift.save();

        req.session.success = `¡Regalo aprobado! Código generado: ${code}. El enlace del regalo ya es accesible.`;
        res.redirect('/admin/regalos');
    } catch (err) {
        req.session.error = `Error al aprobar: ${err.message}`;
        res.redirect('/admin/regalos');
    }
});

// 3. Verificar código de regalo (AJAX o Formulario desde el panel)
// Para que tú verifiques si el código que te dan ya se usó
app.post('/admin/regalos/verify', requireAdmin, async (req, res, next) => {
    try {
        const { code } = req.body;
        // Buscar código exacto (sin importar mayúsculas)
        const gift = await Gift.findOne({ giftCardCode: code.toUpperCase().trim() });

        if (!gift) {
            req.session.error = '❌ Código NO válido o no existe.';
        } else if (gift.isRedeemed) {
            req.session.error = `⚠️ Este código YA FUE USADO por ${gift.recipientName}.`;
        } else {
            // Si es válido y no usado, lo marcamos como usado (Canjeado)
            gift.isRedeemed = true;
            await gift.save();
            req.session.success = `✅ ¡Código VÁLIDO! Monto: ${formatPrice(gift.giftCardAmount)}. Se ha marcado como canjeado.`;
        }
        res.redirect('/admin/regalos');
    } catch (err) {
        req.session.error = `Error: ${err.message}`;
        res.redirect('/admin/regalos');
    }
});

// =============================================
// GESTIÓN DE SISTEMA B2B / ASOCIADAS (ADMIN) - UNIFICADO
// =============================================

// --- ÚNICA PANTALLA: Carga Asociadas, Productos y Pedidos ---
app.get('/admin/b2b', requireAdmin, async (req, res, next) => {
    try {
        const associates = await Associate.find().sort({ createdAt: -1 });
        const importProducts = await ImportProduct.find().populate('category').sort({ createdAt: -1 });
        const orders = await ImportOrder.find().populate('associate').sort({ createdAt: -1 });
        const categories = await Category.find();

        res.render('admin/b2b', {
            pageTitle: 'Centro Mayoristas B2B',
            associates,
            importProducts,
            orders,
            categories,
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// --- POST: Aprobar/Rechazar Asociada ---
app.post('/admin/asociadas/status/:id', requireAdmin, async (req, res, next) => {
    try {
        const { status } = req.body;
        await Associate.findByIdAndUpdate(req.params.id, { status: status });
        req.session.success = `Estado de la asociada actualizado a: ${status}`;
        res.redirect('/admin/b2b'); // Volvemos al panel central
    } catch (err) {
        req.session.error = `Error al actualizar: ${err.message}`;
        res.redirect('/admin/b2b');
    }
});

// --- POST: Añadir Producto al Catálogo B2B ---
app.post('/admin/importaciones/productos/add', requireAdmin, upload.array('photos', 5), async (req, res, next) => {
    try {
        const { name, description, costPrice, wholesalePrice, minQuantity, category } = req.body;
        const newImportProduct = new ImportProduct({
            name: purify.sanitize(name),
            description: purify.sanitize(description, { USE_PROFILES: { html: true } }),
            costPrice: parseInt(costPrice.toString().replace(/\./g, '')) || 0,
            wholesalePrice: parseInt(wholesalePrice.toString().replace(/\./g, '')) || 0,
            minQuantity: parseInt(minQuantity) || 1,
            category: category ? category : null,
            photos: req.files ? req.files.map(f => f.path) : []
        });
        await newImportProduct.save();
        req.session.success = 'Producto añadido al catálogo mayorista.';
        res.redirect('/admin/b2b');
    } catch (err) {
        req.session.error = `Error al añadir producto: ${err.message}`;
        res.redirect('/admin/b2b');
    }
});

// --- POST: Actualizar Tracking del Pedido ---
app.post('/admin/importaciones/pedidos/status/:id', requireAdmin, async (req, res, next) => {
    try {
        const { shippingStatus, trackingNotes } = req.body;
        await ImportOrder.findByIdAndUpdate(req.params.id, { 
            shippingStatus: shippingStatus,
            trackingNotes: purify.sanitize(trackingNotes)
        });
        req.session.success = 'Estado del envío actualizado correctamente.';
        res.redirect('/admin/b2b');
    } catch (err) {
        req.session.error = `Error al actualizar: ${err.message}`;
        res.redirect('/admin/b2b');
    }
});



// =============================================
// GESTIÓN DE CAJA Y FINANZAS (ADMIN)
// =============================================

// Ver la caja del mes actual
// Ver la caja del mes actual
app.get('/admin/caja', requireAdmin, async (req, res, next) => {
    try {
        const now = new Date();
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

        const transactions = await Transaction.find({ date: { $gte: startOfMonth, $lte: endOfMonth } }).sort({ date: -1 });
        const products = await Product.find().select('name price costPrice stock hasVariants variants');

        let totalIngresos = 0;
        let totalCostosReposicion = 0;
        let totalReinversion = 0;
        let totalNando = 0;
        let totalMayu = 0;
        let totalEgresosExtra = 0;

        transactions.forEach(t => {
            if (t.type === 'ingreso') {
                totalIngresos += t.amount;
                totalCostosReposicion += t.cost || 0;
                totalReinversion += t.reinvestment || 0;
                totalNando += t.profitNando || 0;
                totalMayu += t.profitMayu || 0;
            } else if (t.type === 'egreso') {
                totalEgresosExtra += t.amount;
            }
        });

        const gananciaNeta = totalIngresos - totalCostosReposicion - totalEgresosExtra;

        res.render('admin/caja', {
            pageTitle: 'Caja y Finanzas',
            transactions,
            products,
            stats: { 
                totalIngresos, 
                totalCostosReposicion, 
                totalReinversion,
                totalNando,
                totalMayu,
                totalEgresosExtra, 
                gananciaNeta 
            },
            mesActual: now.toLocaleString('es-PY', { month: 'long', year: 'numeric' }).toUpperCase(),
            success: req.session.success,
            error: req.session.error
        });
        delete req.session.success;
        delete req.session.error;
    } catch (err) {
        next(err);
    }
});

// Registrar un Gasto (Egreso)
app.post('/admin/caja/gasto', requireAdmin, async (req, res, next) => {
    try {
        // --- BLOQUEO ANTI DOBLE CLIC (GASTOS) ---
        const lastExpTime = req.session.lastExpTime || 0;
        const nowTime = Date.now();
        if (nowTime - lastExpTime < 3000) return res.redirect('/admin/caja');
        req.session.lastExpTime = nowTime;
        // ---------------------------------------

        const { description, amount } = req.body;
        const newTx = new Transaction({
            type: 'egreso',
            description: purify.sanitize(description),
            amount: parseInt(amount.toString().replace(/\./g, ''))
        });
        await newTx.save();
        req.session.success = 'Gasto registrado correctamente.';
        res.redirect('/admin/caja');
    } catch (err) {
        req.session.error = `Error al registrar gasto: ${err.message}`;
        res.redirect('/admin/caja');
    }
});

// Registrar una Venta Manual (Ingreso)
// Registrar una Venta Manual (Ingreso)
// Registrar una Venta Manual (Ingreso) - VERSIÓN ULTRA MEJORADA
// Registrar una Venta Manual (Ingreso)
app.post('/admin/caja/venta', requireAdmin, async (req, res, next) => {
    try {
        const lastTxTime = req.session.lastSaleTime || 0;
        const nowTime = Date.now();
        if (nowTime - lastTxTime < 3000) return res.redirect('/admin/caja');
        req.session.lastSaleTime = nowTime;

        const { productId, variantName, sellPrice, quantity } = req.body;
        const qty = parseInt(quantity) || 1;
        
        const product = await Product.findById(productId);
        if (!product) throw new Error('Producto no encontrado.');

        // 1. Total cobrado al cliente
        const totalAmount = parseInt(sellPrice.toString().replace(/\./g, '')) * qty;
        
        // 2. Costo del producto desde la base de datos (Ej: 3000)
        const unitCost = product.costPrice || 0;
        const costoReposicion = unitCost * qty;
        
        // 3. Variables para repartir
        let reinversion = 0;
        let gananciaRestante = 0;
        let gananciaNando = 0;
        let gananciaMayu = 0;

        // Si cobramos más de lo que nos costó el producto, hay ganancia bruta
        if (totalAmount > costoReposicion) {
            const gananciaBruta = totalAmount - costoReposicion;
            
            // ¿Alcanza para duplicar el producto al 100% o sobra dinero?
            if (gananciaBruta >= costoReposicion) {
                reinversion = costoReposicion; // Separamos el costo exacto para comprar 1 extra
                gananciaRestante = gananciaBruta - reinversion; // El sobrante es ganancia limpia
            } else {
                // Si la ganancia es bajita (Ej: solo sobran 300 Gs)
                // Mitad para el fondo de duplicar, mitad para ustedes. Así SIEMPRE suman plata.
                reinversion = Math.floor(gananciaBruta / 2);
                gananciaRestante = gananciaBruta - reinversion;
            }

            // Dividir la ganancia restante 50/50
            gananciaNando = Math.floor(gananciaRestante / 2);
            gananciaMayu = gananciaRestante - gananciaNando;
        }

        let desc = `Venta: ${product.name} (x${qty})`;
        if (variantName) desc = `Venta: ${product.name} - ${variantName} (x${qty})`;

        // 4. Guardar TODO en la base de datos (ahora sí lo aceptará)
        const newTx = new Transaction({ 
            type: 'ingreso', 
            description: desc, 
            amount: totalAmount, 
            cost: costoReposicion,
            reinvestment: reinversion,
            profitNando: gananciaNando,
            profitMayu: gananciaMayu
        });
        await newTx.save();

        // 5. Descontar Stock
        if (product.hasVariants && variantName) {
            const variantIndex = product.variants.findIndex(v => v.name === variantName);
            if (variantIndex > -1 && product.variants[variantIndex].stock >= qty) {
                product.variants[variantIndex].stock -= qty;
            }
        } else {
            if (product.stock >= qty) product.stock -= qty;
        }
        await product.save();

        req.session.success = 'Venta registrada con el nuevo cálculo.';
        res.redirect('/admin/caja');
    } catch (err) {
        req.session.error = `Error al registrar venta: ${err.message}`;
        res.redirect('/admin/caja');
    }
});

// Eliminar Transacción
app.post('/admin/caja/delete/:id', requireAdmin, async (req, res, next) => {
    try {
        await Transaction.findByIdAndDelete(req.params.id);
        req.session.success = 'Registro eliminado de la caja.';
        res.redirect('/admin/caja');
    } catch (err) {
        req.session.error = `Error: ${err.message}`;
        res.redirect('/admin/caja');
    }
});

// =============================================
// SITEMAP AUTOMÁTICO (Para Google Search Console)
// =============================================
app.get('/sitemap.xml', async (req, res, next) => {
    try {
        // Obtenemos todos los productos activos
        const products = await Product.find({ isForSale: true }).select('_id updatedAt');
        
        // Tu dominio principal
        const baseUrl = 'https://ferumi.shop'; 

        // Empezamos a armar el XML
        let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
        xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n`;
        
        // 1. Páginas Principales (Estáticas)
        const staticPages = [
            { url: '', priority: '1.0' },
            { url: '/tienda', priority: '0.9' },
            { url: '/sorteos', priority: '0.8' },
            { url: '/regalos/crear', priority: '0.8' },
            { url: '/sobre-nosotros', priority: '0.6' },
            { url: '/contacto', priority: '0.6' }
        ];

        staticPages.forEach(page => {
            xml += `  <url>\n`;
            xml += `    <loc>${baseUrl}${page.url}</loc>\n`;
            xml += `    <changefreq>weekly</changefreq>\n`;
            xml += `    <priority>${page.priority}</priority>\n`;
            xml += `  </url>\n`;
        });

        // 2. Páginas de Productos (Dinámicas)
        products.forEach(product => {
            // Usamos la fecha de la última modificación si existe, si no, la fecha actual
            const lastMod = product.updatedAt ? product.updatedAt.toISOString() : new Date().toISOString();
            
            xml += `  <url>\n`;
            xml += `    <loc>${baseUrl}/producto/${product._id}</loc>\n`;
            xml += `    <lastmod>${lastMod}</lastmod>\n`;
            xml += `    <changefreq>daily</changefreq>\n`;
            xml += `    <priority>0.8</priority>\n`;
            xml += `  </url>\n`;
        });

        xml += `</urlset>`;

        // Le decimos al navegador/Google que este archivo es un XML
        res.header('Content-Type', 'application/xml');
        res.send(xml);

    } catch (err) {
        console.error("Error generando sitemap:", err);
        next(err);
    }
});


// =============================================
// MANEJADORES DE ERROR Y ARRANQUE
// =============================================

// Manejador de error 404 (Página no encontrada)
app.use((req, res, next) => {
    res.status(404).render('public/error', { 
        pageTitle: 'Error 404',
        message: 'La página que buscas no fue encontrada.' 
    });
});

// Manejador de error 500 (Error general)
app.use((err, req, res, next) => {
  console.error("❌ ERROR CAPTURADO:", err.stack);
  const status = err.status || 500;
  const message = err.message || 'Ocurrió un error inesperado en el servidor.';
  
  // Distinguir entre error de admin y error público
  if (req.path.startsWith('/admin')) {
      res.status(status).render('admin/error', { message, pageTitle: 'Error' });
  } else {
      res.status(status).render('public/error', { pageTitle: 'Error', message });
  }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`🚀 Servidor FERUMI corriendo en ${process.env.BASE_URL}`);
    
    // --- Script para crear el admin por primera vez ---
    const createAdmin = async () => {
        try {
            const adminCount = await AdminUser.countDocuments();
            if (adminCount === 0) {
                const email = 'admin@ferumi.com'; // Correo actualizado
                const password = 'admin123456'; // Contraseña temporal
                
                await new AdminUser({ email, password }).save();
                
                console.log('==================================================');
                console.log('       CUENTA DE ADMINISTRADOR CREADA       ');
                console.log(` Email: ${email}`);
                console.log(` Pass:  ${password}`);
                console.log('==================================================');
                console.log('¡IMPORTANTE! Cambia esta contraseña después de tu primer login.');
            }
        } catch (err) {
            console.error('Error al crear cuenta de admin:', err.message);
        }
    };
    createAdmin();
    // --- Fin del script de admin ---
});