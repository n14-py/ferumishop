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
const crypto = require('crypto'); // NUEVO: Para generar IDs únicos y códigos de regalo

// Inicialización de Express y DOMPurify (para seguridad)
const app = express();
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

// --- Modelo de Categoría ---
const categorySchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true }
});

const Category = mongoose.model('Category', categorySchema);

// --- Modelo de Producto ---
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    price: { type: Number, required: true, default: 0 },
    photos: [{ type: String }], // Array de URLs de Cloudinary
    category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    isFeatured: { type: Boolean, default: false }, // Para "productos destacados"
    isForRent: { type: Boolean, default: false }, // Para diferenciar venta/alquiler
    isForSale: { type: Boolean, default: true },
    views: { type: Number, default: 0 } // Para estadísticas
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// --- Modelo de Configuración del Sitio ---
const siteConfigSchema = new mongoose.Schema({
    configKey: { type: String, default: 'main_config', unique: true },
    whatsappNumber: { type: String, default: '595981123456' },
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
const requireAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user) {
        return next();
    } else {
        res.redirect('/admin/login');
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
        // Nueva estadística: regalos pendientes
        const pendingGifts = await Gift.countDocuments({ status: 'pendiente' });
        
        const mostViewedProducts = await Product.find()
            .sort({ views: -1 })
            .limit(5)
            .populate('category');
        
        const stats = {
            totalProducts: totalProducts,
            totalCategories: totalCategories,
            pendingGifts: pendingGifts
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
app.post('/admin/productos/add', requireAdmin, upload.array('photos', 5), async (req, res, next) => {
    try {
        const { name, description, price, category, isForRent, isForSale, isFeatured } = req.body;
        
        if (!req.files || req.files.length === 0) {
            throw new Error('Debes subir al menos una foto del producto.');
        }

const newProduct = new Product({
            name: purify.sanitize(name),
            description: purify.sanitize(description, { USE_PROFILES: { html: true } }),
            // Ignoramos los puntos que ponga el usuario para guardar el número real
            price: parseInt(price.toString().replace(/\./g, '')) || 0,
            category,
            photos: req.files.map(f => f.path),
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
app.get('/admin/producto/edit/:id', requireAdmin, async (req, res, next) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            req.session.error = 'Producto no encontrado.';
            return res.redirect('/admin/productos');
        }
        const categories = await Category.find();
        
        res.render('admin/edit-producto', {
            pageTitle: `Editar: ${product.name}`,
            product,
            categories
        });
    } catch (err) {
        next(err);
    }
});

// --- Actualizar un producto (POST) ---
app.post('/admin/producto/edit/:id', requireAdmin, upload.array('new_photos', 5), async (req, res, next) => {
    try {
        const { name, description, price, category, isForRent, isForSale, isFeatured, existing_photos } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) throw new Error('Producto no encontrado.');

        // 1. Eliminar fotos que el admin desmarcó
        const photosToKeep = existing_photos ? [].concat(existing_photos) : [];
        const photosToDelete = product.photos.filter(url => !photosToKeep.includes(url));
        
        for (const url of photosToDelete) {
            const publicId = getPublicId(url);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }
        
        // 2. Añadir nuevas fotos
        let newPhotos = req.files ? req.files.map(f => f.path) : [];
        
// 3. Actualizar el producto
        product.name = purify.sanitize(name);
        product.description = purify.sanitize(description, { USE_PROFILES: { html: true } });
        // Ignoramos los puntos que ponga el usuario al editar
        product.price = parseInt(price.toString().replace(/\./g, '')) || 0;
        product.category = category;
        product.photos = [...photosToKeep, ...newPhotos];
        product.isForRent = isForRent === 'on';
        product.isForSale = isForSale === 'on';
        product.isFeatured = isFeatured === 'on';
        
        await product.save();
        req.session.success = '¡Producto actualizado con éxito!';
        res.redirect('/admin/productos');
    } catch (err) {
        req.session.error = `Error al actualizar: ${err.message}`;
        res.redirect(`/admin/producto/edit/${req.params.id}`);
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