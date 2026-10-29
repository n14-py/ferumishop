'use strict';

const mongoose = require('mongoose');
const shop = require('./orders');
const pagopar = require('./pagopar');
const r2 = require('./r2');
const slug = require('./wa-slug');
const deepinfra = require('./deepinfra');
const wa = require('./whatsapp');
const controlPrompt = require('./wa-control/prompt');
const controlText = require('./wa-control/text');
const controlStates = require('./wa-control/states');
const controlOutbound = require('./wa-control/outbound');
const controlVision = require('./wa-control/vision');
const checkout = require('./wa-control/checkout');

const MOTOBOLT_RULES =
    'Motobolt lo pedís VOS cuando te avisemos que el pedido ya está preparado. ' +
    'Casi todo el tiempo tenemos pedidos en curso, por eso no se puede pedir Motobolt dos veces. ' +
    'Esperá nuestro aviso. El moto retira en Ferumishop y el costo del moto lo pagás al conductor.';

const TOOLS = [
    {
        type: 'function',
        function: {
            name: 'search_catalog',
            description: 'Busca productos a la venta por nombre, efecto, variante o descripción. Usala siempre antes de afirmar stock o precio.',
            parameters: {
                type: 'object',
                properties: {
                    query: { type: 'string', description: 'Texto de búsqueda, ej: labial, efecto anime, pestañas 30D' }
                },
                required: ['query']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'get_product',
            description: 'Detalle de un producto: precio, stock, variantes/efectos, si tiene fotos y videos.',
            parameters: {
                type: 'object',
                properties: { productId: { type: 'string' } },
                required: ['productId']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'send_media',
            description: 'Envía fotos y/o videos reales del producto (Cloudinary / R2) a la clienta por WhatsApp.',
            parameters: {
                type: 'object',
                properties: {
                    productId: { type: 'string' },
                    kind: { type: 'string', enum: ['photos', 'videos', 'both'] },
                    variantName: { type: 'string', description: 'Si pide un efecto o tono concreto' }
                },
                required: ['productId']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'cart_add',
            description: 'Agrega un producto al carrito de WhatsApp.',
            parameters: {
                type: 'object',
                properties: {
                    productId: { type: 'string' },
                    quantity: { type: 'integer', minimum: 1 },
                    variantName: { type: 'string' }
                },
                required: ['productId']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'cart_update',
            description: 'Cambia cantidad o saca un ítem. quantity 0 elimina.',
            parameters: {
                type: 'object',
                properties: {
                    productId: { type: 'string' },
                    variantName: { type: 'string' },
                    quantity: { type: 'integer', minimum: 0 }
                },
                required: ['productId', 'quantity']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'cart_clear',
            description: 'Vacía el carrito.',
            parameters: { type: 'object', properties: {} }
        }
    },
    {
        type: 'function',
        function: {
            name: 'set_customer',
            description: 'Guarda los datos que pide Pagopar: nombre, cédula, correo y teléfono.',
            parameters: {
                type: 'object',
                properties: {
                    name: { type: 'string' },
                    document: { type: 'string', description: 'Cédula, solo números' },
                    email: { type: 'string' },
                    phone: { type: 'string' }
                }
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'request_location',
            description: 'Pide a la clienta que comparta su ubicación de WhatsApp para calcular Motobolt vs encomienda.',
            parameters: {
                type: 'object',
                properties: {
                    reason: { type: 'string' }
                }
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'set_shipping',
            description: 'Guarda ciudad, dirección, referencia y método de envío (motobolt, transportadora, retiro).',
            parameters: {
                type: 'object',
                properties: {
                    city: { type: 'string' },
                    address: { type: 'string' },
                    reference: { type: 'string' },
                    method: { type: 'string', enum: ['motobolt', 'transportadora', 'retiro', 'delivery_propio'] }
                }
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'preview_order',
            description: 'Muestra el resumen (productos, total, datos, envío) y pide confirmación antes de crear el pedido.',
            parameters: { type: 'object', properties: {} }
        }
    },
    {
        type: 'function',
        function: {
            name: 'create_order',
            description: 'Crea el pedido real en FERUMI y genera el enlace privado de pago Pagopar. SOLO si la clienta confirmó que los datos y el total están bien.',
            parameters: {
                type: 'object',
                properties: {
                    confirmed: { type: 'boolean' }
                },
                required: ['confirmed']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'get_payment_link',
            description: 'Devuelve el enlace de pago vigente. No crea otro si ya existe.',
            parameters: { type: 'object', properties: {} }
        }
    },
    {
        type: 'function',
        function: {
            name: 'request_human',
            description: 'Deriva la conversación a una persona. No promete respuesta inmediata.',
            parameters: { type: 'object', properties: { reason: { type: 'string' } } }
        }
    },
    {
        type: 'function',
        function: {
            name: 'lookup_orders',
            description: 'Busca pedidos de la clienta por correo, cédula, teléfono o número de pedido/ticket.',
            parameters: {
                type: 'object',
                properties: {
                    query: { type: 'string', description: 'Email, CI, teléfono, FER-... o FM-...' }
                },
                required: ['query']
            }
        }
    }
];

function systemPrompt(siteConfig, extra = {}) {
    const store = shop.storeFromConfig(siteConfig);
    return controlPrompt.buildSystemPrompt({
        ai: extra.ai,
        store,
        ops: extra.ops,
        situations: extra.situations || [],
        decisions: { method: extra.method || '' },
        stateText: 'El estado comercial del chat va en el mensaje de sistema siguiente. La base de datos manda sobre ese resumen.'
    }) + `

OPERACIÓN
- Datos para PagoPar: nombre, cédula, correo y teléfono. No los vuelvas a pedir si ya están guardados.
- Envío en Gran Asunción / Central (hasta ${store.motoboltMaxKm} km): Motobolt. Interior: transportadora. También existe delivery propio y retiro en ${store.address}.
- ${MOTOBOLT_RULES}
- El enlace de pago es uno por pedido. Si la herramienta dice que ya existe, no lo repitas.
- Idioma: español de Paraguay. Mensajes cortos.`;
}

function formatGs(n) {
    return `${new Intl.NumberFormat('es-PY').format(Math.round(Number(n) || 0))} Gs.`;
}

function escapeRegex(s) {
    return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function cartTotal(cart) {
    return (cart || []).reduce((s, i) => s + (Number(i.price) || 0) * (Number(i.quantity) || 0), 0);
}

function missingCustomer(customer = {}) {
    const miss = [];
    if (!String(customer.name || '').trim()) miss.push('nombre');
    if (!String(customer.document || '').replace(/\D/g, '')) miss.push('cédula');
    if (!String(customer.email || '').includes('@')) miss.push('correo');
    if (!String(customer.phone || '').replace(/\D/g, '')) miss.push('teléfono');
    return miss;
}

function shippingReady(shipping = {}, method) {
    const m = method || shipping.method;
    if (!['motobolt', 'transportadora', 'retiro', 'delivery_propio'].includes(m)) {
        return { ok: false, message: 'Falta elegir envío: Motobolt, encomienda o retiro en Ferumishop.' };
    }
    if (m === 'motobolt' && shipping.far) {
        return { ok: false, message: 'Motobolt no llega a esa distancia. Encomienda o retiro.' };
    }
    if (m !== 'retiro' && !shipping.address && (shipping.lat == null || shipping.lng == null)) {
        return { ok: false, message: 'Necesitamos ubicación o dirección para el envío.' };
    }
    return { ok: true };
}

function canCreateOrder(conv) {
    const cart = conv.cart || [];
    if (!cart.length) return { ok: false, message: 'El carrito está vacío.' };
    const miss = missingCustomer(conv.customer);
    if (miss.length) return { ok: false, message: `Faltan datos de Pagopar: ${miss.join(', ')}.` };
    const ship = shippingReady(conv.shipping, conv.shipping?.method);
    if (!ship.ok) return ship;
    const total = cartTotal(cart);
    if (total < 1000) return { ok: false, message: 'El total es demasiado bajo para Pagopar.' };
    return { ok: true, total };
}

function stateBlock(conv) {
    const cart = conv.cart || [];
    const c = conv.customer || {};
    const s = conv.shipping || {};
    const lines = cart.length
        ? cart.map((i) => `• ${i.quantity}x ${i.name}${i.variantName ? ` (${i.variantName})` : ''} — ${formatGs(i.price)}`).join('\n')
        : '(vacío)';
    return `ESTADO ACTUAL DEL CHAT
Carrito:
${lines}
Total: ${formatGs(cartTotal(cart))}
Cliente: nombre=${c.name || '—'} CI=${c.document || '—'} email=${c.email || '—'} tel=${c.phone || '—'}
Envío: método=${s.method || '—'} ciudad=${s.city || '—'} dir=${s.address || '—'} ref=${s.reference || '—'} km=${s.distanceKm ?? '—'} far=${Boolean(s.far)} coords=${s.lat != null ? `${s.lat},${s.lng}` : '—'}
Esperando confirmación de pedido: ${conv.awaitingConfirm ? 'SÍ' : 'no'}
Último pedido: ${conv.lastOrderNumber || '—'} slug=${conv.lastCheckoutSlug || '—'}
waId=${conv.waId}`;
}

function compactProduct(p) {
    const json = r2.botProductJson(p);
    return {
        id: json.id,
        name: json.name,
        price: json.price,
        priceLabel: formatGs(json.price),
        stock: json.stock,
        hasVariants: json.hasVariants,
        variants: json.variants,
        category: p.category?.name || '',
        photosCount: (json.photos || []).length,
        videosCount: (json.videos || []).length,
        description: (json.description || '').slice(0, 280)
    };
}

function conversationSchema() {
    return new mongoose.Schema({
        waId: { type: String, required: true, unique: true, index: true },
        profileName: { type: String, default: '' },
        history: [{
            role: { type: String, enum: ['user', 'assistant'] },
            content: String,
            at: { type: Date, default: Date.now }
        }],
        cart: [{
            productId: String,
            variantName: { type: String, default: '' },
            name: String,
            quantity: Number,
            price: Number,
            image: { type: String, default: '' }
        }],
        customer: {
            name: { type: String, default: '' },
            email: { type: String, default: '' },
            document: { type: String, default: '' },
            phone: { type: String, default: '' }
        },
        shipping: {
            lat: Number,
            lng: Number,
            city: { type: String, default: '' },
            address: { type: String, default: '' },
            reference: { type: String, default: '' },
            method: { type: String, default: '' },
            distanceKm: Number,
            far: Boolean,
            central: Boolean
        },
        housePhotoUrl: { type: String, default: '' },
        awaitingConfirm: { type: Boolean, default: false },
        lastOrderId: { type: mongoose.Schema.Types.ObjectId, ref: 'WebOrder' },
        lastOrderNumber: { type: String, default: '' },
        lastCheckoutSlug: { type: String, default: '' },
        processedWamids: { type: [String], default: [] },
        attentionStatus: { type: String, default: 'ai_active', index: true },
        aiPaused: { type: Boolean, default: false },
        pausedReason: { type: String, default: '' },
        humanOwnerId: { type: String, default: '' },
        humanOwnerName: { type: String, default: '' },
        important: { type: Boolean, default: false },
        internalNotes: [{ text: String, author: String, at: { type: Date, default: Date.now } }],
        addresses: [{
            label: String,
            city: String,
            zone: String,
            address: String,
            reference: String,
            habitual: { type: Boolean, default: false },
            at: { type: Date, default: Date.now }
        }],
        summary: { type: String, default: '' },
        lastError: { type: String, default: '' },
        processing: { token: String, until: Date },
        updatedAt: { type: Date, default: Date.now }
    });
}

const WaConversation = mongoose.models.WaConversation || mongoose.model('WaConversation', conversationSchema());

async function loadConversation(waId, profileName) {
    const conv = await WaConversation.findOneAndUpdate(
        { waId },
        {
            $setOnInsert: {
                waId,
                profileName: profileName || '',
                customer: { phone: waId },
                attentionStatus: 'ai_active'
            }
        },
        { upsert: true, new: true }
    );
    if (profileName && conv.profileName !== profileName) conv.profileName = profileName;
    if (!conv.customer) conv.customer = {};
    if (!conv.customer.phone) conv.customer.phone = waId;
    return conv;
}

function rememberWamid(conv, wamid) {
    if (!wamid) return false;
    conv.processedWamids = conv.processedWamids || [];
    if (conv.processedWamids.includes(wamid)) return true;
    conv.processedWamids.push(wamid);
    if (conv.processedWamids.length > 80) conv.processedWamids = conv.processedWamids.slice(-40);
    return false;
}

async function applyLocation(conv, location, siteConfig) {
    if (!location || location.lat == null || location.lng == null) return null;
    conv.shipping = conv.shipping || {};
    conv.shipping.lat = location.lat;
    conv.shipping.lng = location.lng;
    if (location.address) conv.shipping.address = conv.shipping.address || location.address;
    if (location.name && !conv.shipping.city) conv.shipping.city = location.name;
    const info = shop.shippingOptions({
        lat: location.lat,
        lng: location.lng,
        city: conv.shipping.city,
        siteConfig
    });
    conv.shipping.distanceKm = info.distanceKm;
    conv.shipping.far = info.far;
    conv.shipping.central = info.central;
    return info;
}

function shippingCopy(info, store) {
    if (!info) return 'Compartime tu ubicación para ver si te llega Motobolt o va por encomienda 💖';
    const km = info.distanceKm != null ? ` Estás a unos ${info.distanceKm} km de Ferumishop.` : '';
    if (info.central && !info.far) {
        return `Linda, te queda en zona Motobolt.${km} ${MOTOBOLT_RULES} Si estás en el interior o preferís, también hacemos encomienda o retiro en ${store.address}.`;
    }
    return `Amor, te queda lejos para Motobolt.${km} Te enviamos por encomienda / transportadora al interior. El despachante se comunica con vos después del pago para coordinar. También podés retirar en ${store.address}.`;
}

async function searchCatalog(Product, query) {
    const q = String(query || '').trim();
    if (!q) {
        const featured = await Product.find({ isForSale: true, isFeatured: true, aiVisible: { $ne: false } }).populate('category').limit(8);
        return featured.map(compactProduct);
    }
    const rx = new RegExp(escapeRegex(q).replace(/\s+/g, '.*'), 'i');
    const products = await Product.find({
        isForSale: true,
        aiVisible: { $ne: false },
        $or: [
            { name: rx },
            { description: rx },
            { 'variants.name': rx }
        ]
    }).populate('category').sort({ stock: -1, updatedAt: -1 }).limit(12);
    return products.map(compactProduct);
}

async function resolveProduct(Product, productId) {
    if (!productId || !mongoose.Types.ObjectId.isValid(productId)) return null;
    return Product.findById(productId).populate('category');
}

function findCartItem(cart, productId, variantName) {
    const v = String(variantName || '');
    return (cart || []).findIndex((i) => String(i.productId) === String(productId) && String(i.variantName || '') === v);
}

async function addToCart(conv, Product, { productId, quantity, variantName }) {
    const product = await resolveProduct(Product, productId);
    if (!product) return { ok: false, message: 'No encontré ese producto.' };
    const qty = Math.max(1, parseInt(quantity, 10) || 1);
    const variant = String(variantName || '').trim();
    if (product.hasVariants) {
        if (!variant) {
            return {
                ok: false,
                message: `Ese producto tiene opciones: ${(product.variants || []).map((v) => `${v.name} (stock ${v.stock || 0})`).join(', ') || 'sin stock'}. Decime el efecto/tono.`
            };
        }
        const found = (product.variants || []).find((v) => v.name.toLowerCase() === variant.toLowerCase());
        if (!found) return { ok: false, message: `No hay la variante "${variant}" en ${product.name}.` };
        if ((found.stock || 0) < qty) return { ok: false, message: `Uy, de ${product.name} (${found.name}) nos queda ${found.stock || 0}.` };
    } else if ((product.stock || 0) < qty) {
        return { ok: false, message: `Uy linda, de ${product.name} nos queda ${product.stock || 0}.` };
    }
    const name = variant ? `${product.name} - ${variant}` : product.name;
    const image = (product.hasVariants && variant
        ? (product.variants.find((v) => v.name.toLowerCase() === variant.toLowerCase()) || {}).photoUrl
        : '') || (product.photos && product.photos[0]) || '';
    conv.cart = conv.cart || [];
    const idx = findCartItem(conv.cart, product._id, variant);
    if (idx >= 0) conv.cart[idx].quantity += qty;
    else {
        conv.cart.push({
            productId: String(product._id),
            variantName: variant,
            name,
            quantity: qty,
            price: product.price,
            image
        });
    }
    conv.awaitingConfirm = false;
    return { ok: true, cart: conv.cart, total: cartTotal(conv.cart), totalLabel: formatGs(cartTotal(conv.cart)) };
}

function mediaReplies(product, kind, variantName) {
    const replies = [];
    const wantPhotos = kind !== 'videos';
    const wantVideos = kind === 'videos' || kind === 'both';
    let photos = Array.isArray(product.photos) ? product.photos.filter(Boolean) : [];
    if (variantName) {
        const v = (product.variants || []).find((x) => String(x.name).toLowerCase() === String(variantName).toLowerCase());
        if (v?.photoUrl) photos = [v.photoUrl, ...photos.filter((p) => p !== v.photoUrl)];
    }
    if (wantPhotos) {
        photos.slice(0, 4).forEach((link, i) => {
            replies.push({
                type: 'image',
                link,
                caption: i === 0 ? `${product.name}${variantName ? ` — ${variantName}` : ''} · ${formatGs(product.price)}` : undefined
            });
        });
    }
    if (wantVideos) {
        const videos = (product.videos || []).filter((v) => v && v.url).slice(0, 3);
        videos.forEach((v, i) => {
            replies.push({
                type: 'video',
                link: v.url,
                caption: i === 0 ? `Video de ${product.name}` : (v.originalName || 'Video')
            });
        });
        if (!videos.length && kind === 'videos') {
            replies.push({ type: 'text', text: `Linda, de ${product.name} todavía no cargamos video, pero te mando foto si querés 💖` });
        }
    }
    if (!replies.length) {
        replies.push({ type: 'text', text: `Aún no hay fotos cargadas de ${product.name}. Te cuento: ${formatGs(product.price)}, stock ${product.stock}.` });
    }
    return replies;
}

async function uniqueSlug(WebOrder, phone, name) {
    const base = slug.makeCheckoutSlug({ phone, name });
    if (!await WebOrder.exists({ checkoutSlug: base })) return base;
    for (let i = 2; i < 30; i++) {
        const s = slug.makeCheckoutSlug({ phone, name, suffix: String(i) });
        if (!await WebOrder.exists({ checkoutSlug: s })) return s;
    }
    return slug.makeCheckoutSlug({ phone, name, suffix: shop.randomCode(2).toLowerCase() });
}

async function cancelPendingWhatsAppOrders(WebOrder, waId, exceptId) {
    const q = {
        waFrom: waId,
        source: 'whatsapp',
        paymentStatus: 'pendiente',
        status: 'pendiente',
        deletedAt: { $exists: false }
    };
    if (exceptId) q._id = { $ne: exceptId };
    const olds = await WebOrder.find(q);
    for (const order of olds) {
        shop.appendEvent(order, shop.FULFILLMENT.CANCELADO, 'Reemplazado por un pedido nuevo de WhatsApp.');
        order.status = 'cancelado';
        order.paymentStatus = 'cancelado';
        await order.save();
    }
}

async function createWhatsAppOrder(conv, deps) {
    const gate = canCreateOrder(conv);
    if (!gate.ok && !(conv.cart || []).length) {
        return checkout.ensureConversationPayment(conv, deps, { mode: 'resend', explicit: true, siteConfig: deps.siteConfig });
    }
    if (!gate.ok) return { ok: false, message: gate.message };
    return checkout.ensureConversationPayment(conv, deps, { mode: 'confirm', siteConfig: deps.siteConfig });
}

async function lookupOrders(WebOrder, query, waId) {
    const q = String(query || '').trim();
    if (!q || q.length < 3) {
        const mine = await WebOrder.find({
            deletedAt: { $exists: false },
            $or: [{ waFrom: waId }, { customerPhone: { $regex: String(waId || '').slice(-8) } }]
        }).sort({ createdAt: -1 }).limit(8);
        return mine.map(shop.publicOrderView);
    }
    const email = q.toLowerCase();
    const doc = q.replace(/\D/g, '');
    const orders = await WebOrder.find({
        deletedAt: { $exists: false },
        $or: [
            { customerEmail: email },
            { customerDocument: doc || q },
            { ticketCode: q.toUpperCase() },
            { orderNumber: q.toUpperCase() },
            { checkoutSlug: q.toLowerCase() },
            { waFrom: waId },
            { customerPhone: { $regex: doc || q, $options: 'i' } }
        ]
    }).sort({ createdAt: -1 }).limit(20);

    return orders.filter((o) => {
        if (waId && o.waFrom === waId) return true;
        if (o.customerEmail === email) return true;
        if (doc && o.customerDocument === doc) return true;
        if (o.ticketCode === q.toUpperCase() || o.orderNumber === q.toUpperCase()) return true;
        if (o.checkoutSlug && o.checkoutSlug.toLowerCase() === q.toLowerCase()) return true;
        return shop.phonesMatch(o.customerPhone, q) || shop.phonesMatch(o.waFrom, q);
    }).map((o) => {
        const view = shop.publicOrderView(o);
        return {
            ...view,
            trackingUrl: slug.publicTrackingUrl(o.ticketCode),
            payUrl: o.paymentStatus === 'pendiente' && o.checkoutSlug ? slug.publicPayUrl(o.checkoutSlug) : undefined
        };
    });
}

function previewText(conv, siteConfig) {
    const gate = canCreateOrder(conv);
    const c = conv.customer || {};
    const s = conv.shipping || {};
    const store = shop.storeFromConfig(siteConfig);
    const items = (conv.cart || []).map((i) => `• ${i.quantity}x ${i.name} — ${formatGs(i.price * i.quantity)}`).join('\n') || '(carrito vacío)';
    const methodLabel = s.method === 'motobolt' ? 'Motobolt (vos pedís el moto cuando te avisemos)'
        : s.method === 'transportadora' ? 'Encomienda / transportadora al interior'
            : s.method === 'retiro' ? `Retiro en ${store.address}` : '—';
    let extra = '';
    if (s.method === 'motobolt') extra = `\n\n${MOTOBOLT_RULES}`;
    return `Revisá si está todo bien, linda 💖\n\n${items}\nTotal: ${formatGs(cartTotal(conv.cart))}\n\n` +
        `Nombre: ${c.name || '—'}\nCI: ${c.document || '—'}\nCorreo: ${c.email || '—'}\nTel: ${c.phone || '—'}\n` +
        `Envío: ${methodLabel}\n${s.address || s.city ? `Dirección: ${[s.address, s.city, s.reference].filter(Boolean).join(', ')}\n` : ''}` +
        (s.distanceKm != null ? `Distancia: ${s.distanceKm} km\n` : '') +
        extra +
        (gate.ok ? '\n\nSi está todo bien, creo el pedido y te paso el enlace para pagar con Pagopar.' : `\n\n⚠️ ${gate.message}`);
}

async function executeTool(name, args, ctx) {
    const { conv, deps, outgoing } = ctx;
    const { Product, WebOrder } = deps;
    const siteConfig = ctx.siteConfig;

    if (name === 'search_catalog') {
        const products = await searchCatalog(Product, args.query);
        return { count: products.length, products };
    }
    if (name === 'get_product') {
        const product = await resolveProduct(Product, args.productId);
        if (!product) return { ok: false, message: 'Producto no encontrado' };
        return compactProduct(product);
    }
    if (name === 'send_media') {
        const product = await resolveProduct(Product, args.productId);
        if (!product) return { ok: false, message: 'Producto no encontrado' };
        const replies = mediaReplies(product, args.kind || 'photos', args.variantName);
        outgoing.push(...replies);
        return { ok: true, sent: replies.length, name: product.name };
    }
    if (name === 'cart_add') {
        return addToCart(conv, Product, args);
    }
    if (name === 'cart_update') {
        conv.cart = conv.cart || [];
        const idx = findCartItem(conv.cart, args.productId, args.variantName);
        if (idx < 0) return { ok: false, message: 'Ese ítem no está en el carrito.' };
        const qty = parseInt(args.quantity, 10);
        if (!qty) conv.cart.splice(idx, 1);
        else conv.cart[idx].quantity = qty;
        conv.awaitingConfirm = false;
        return { ok: true, cart: conv.cart, total: cartTotal(conv.cart), totalLabel: formatGs(cartTotal(conv.cart)) };
    }
    if (name === 'cart_clear') {
        conv.cart = [];
        conv.awaitingConfirm = false;
        return { ok: true, cart: [] };
    }
    if (name === 'set_customer') {
        conv.customer = conv.customer || {};
        if (args.name) conv.customer.name = String(args.name).trim();
        if (args.email) conv.customer.email = String(args.email).trim().toLowerCase();
        if (args.document) conv.customer.document = String(args.document).replace(/\D/g, '');
        if (args.phone) conv.customer.phone = String(args.phone).trim();
        return { ok: true, customer: conv.customer, missing: missingCustomer(conv.customer) };
    }
    if (name === 'request_location') {
        outgoing.push({
            type: 'location_request',
            text: args.reason || 'Linda, compartime tu ubicación 📍 así vemos si te llega Motobolt (Gran Asunción / Central) o si va por encomienda al interior 💖'
        });
        return { ok: true, requested: true };
    }
    if (name === 'set_shipping') {
        conv.shipping = conv.shipping || {};
        if (args.city) conv.shipping.city = String(args.city).trim();
        if (args.address) conv.shipping.address = String(args.address).trim();
        if (args.reference) conv.shipping.reference = String(args.reference).trim();
        if (args.method) {
            const info = shop.shippingOptions({
                lat: conv.shipping.lat, lng: conv.shipping.lng, city: conv.shipping.city, siteConfig
            });
            conv.shipping.distanceKm = info.distanceKm;
            conv.shipping.far = info.far;
            conv.shipping.central = info.central;
            if (args.method === 'motobolt' && info.far) {
                return { ok: false, message: 'Motobolt no llega hasta ahí. Ofrecé encomienda o retiro.', options: info.options.map((o) => o.id) };
            }
            conv.shipping.method = args.method;
        }
        const ready = shippingReady(conv.shipping, conv.shipping.method);
        return { ok: ready.ok, shipping: conv.shipping, message: ready.ok ? 'Envío listo' : ready.message, motobolt: MOTOBOLT_RULES };
    }
    if (name === 'preview_order') {
        const text = previewText(conv, siteConfig);
        const gate = canCreateOrder(conv);
        conv.awaitingConfirm = gate.ok;
        outgoing.push({ type: 'text', text });
        outgoing.push({
            type: 'buttons',
            text: gate.ok
                ? '¿Confirmamos este pedido y te paso el enlace privado para pagar con Pagopar? 💖'
                : `Todavía falta: ${gate.message}`,
            buttons: gate.ok
                ? [
                    { id: 'confirm_order', title: 'Sí, está bien' },
                    { id: 'edit_order', title: 'Cambiar datos' }
                ]
                : [{ id: 'edit_order', title: 'Completar datos' }]
        });
        return { ok: gate.ok, missing: gate.ok ? null : gate.message };
    }
    if (name === 'create_order' || name === 'get_payment_link') {
        if (name === 'create_order' && !args.confirmed) {
            return { ok: false, message: 'La clienta todavía no confirmó. Llamá a preview_order.' };
        }
        if (ctx.paymentHandled) {
            return { ok: false, message: 'El pago de este turno ya fue resuelto. No generes otro enlace ni repitas la URL.' };
        }
        const created = await checkout.ensureConversationPayment(conv, { ...deps, siteConfig }, {
            mode: name === 'get_payment_link' ? 'resend' : 'confirm',
            explicit: name === 'get_payment_link',
            siteConfig
        });
        ctx.paymentHandled = true;
        ctx.paymentIntentKey = created.intent?.key || ctx.paymentIntentKey;
        ctx.markPaymentSent = Boolean(created.send);
        if (created.message) outgoing.push({ type: 'text', text: created.message });
        return {
            ok: Boolean(created.ok),
            reused: Boolean(created.reused),
            orderNumber: created.order?.orderNumber,
            doNotRepeatUrl: true,
            message: created.message
        };
    }
    if (name === 'request_human') {
        Object.assign(conv, controlStates.attentionAfter('request_human'));
        const text = 'Dejo tu consulta para una persona del equipo. No te puedo prometer una respuesta inmediata.';
        outgoing.push({ type: 'text', text });
        return { ok: true, handoff: true };
    }
    if (name === 'lookup_orders') {
        const orders = await lookupOrders(WebOrder, args.query, conv.waId);
        return {
            count: orders.length,
            orders: orders.map((o) => ({
                orderNumber: o.orderNumber,
                ticketCode: o.ticketCode,
                total: o.totalAmount,
                paymentStatus: o.paymentStatus,
                fulfillment: o.tracking?.title || o.fulfillmentStatus,
                trackingUrl: o.trackingUrl,
                payUrl: o.payUrl,
                items: (o.items || []).map((i) => `${i.quantity}x ${i.name}`)
            }))
        };
    }
    return { ok: false, message: `Herramienta desconocida: ${name}` };
}

function parseToolArgs(raw) {
    if (!raw) return {};
    if (typeof raw === 'object') return raw;
    try { return JSON.parse(raw); } catch { return {}; }
}

function looksLikeConfirm(text, buttonId) {
    if (buttonId === 'confirm_order') return true;
    const t = String(text || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
    return /^(si|sí|ok|dale|va|perfecto|esta bien|está bien|asi esta|así está|confirmo|de una|sii+|sip)$/.test(t);
}

function shippingButtonMethod(buttonId) {
    if (buttonId === 'ship_motobolt') return 'motobolt';
    if (buttonId === 'ship_transportadora') return 'transportadora';
    if (buttonId === 'ship_retiro') return 'retiro';
    return '';
}

function historyMessages(conv) {
    const hist = (conv.history || []).slice(-16);
    return hist.map((h) => ({ role: h.role, content: h.content }));
}

function pushHistory(conv, role, content) {
    conv.history = conv.history || [];
    conv.history.push({ role, content: String(content || '').slice(0, 4000), at: new Date() });
    if (conv.history.length > 24) conv.history = conv.history.slice(-16);
}

async function runtimeContext(conv) {
    try {
        const { controlModels } = require('./wa-control/models');
        const models = controlModels();
        const [aiDoc, settings, situations] = await Promise.all([
            models.WaAiProfile.findOne({ key: 'published' }).lean(),
            models.WaSettings.findOne({ key: 'main' }).lean(),
            models.WaSituation.find({ status: 'active' }).sort({ priority: -1 }).limit(6).lean()
        ]);
        return {
            ai: aiDoc?.snapshot,
            ops: settings || undefined,
            situations,
            method: conv.shipping?.method || ''
        };
    } catch (err) {
        console.warn('[whatsapp] configuración publicada no disponible:', err.message);
        return { method: conv.shipping?.method || '' };
    }
}

async function runModelTurn(conv, userText, deps, siteConfig, outgoing, runtime, toolCtx) {
    if (!deepinfra.config().ok) {
        outgoing.push({
            type: 'text',
            text: 'Hola. Soy Ferumi. En este momento no puedo consultar el asistente porque falta la clave de IA en el servidor. Escribime de nuevo más tarde.'
        });
        return toolCtx;
    }

    const messages = [
        { role: 'system', content: systemPrompt(siteConfig, runtime || {}) },
        { role: 'system', content: stateBlock(conv) },
        ...historyMessages(conv),
        { role: 'user', content: userText }
    ];
    const seen = new Map();
    const ctx = toolCtx || { paymentHandled: false };

    for (let i = 0; i < 5; i += 1) {
        const json = await deepinfra.chat({ messages, tools: TOOLS, temperature: 0.4, maxTokens: 900 });
        const msg = deepinfra.assistantMessage(json);
        const calls = msg.tool_calls || [];
        if (!calls.length) {
            const text = controlText.guardCustomerReply(String(msg.content || '').trim(), {
                paymentConfirmed: false,
                maxDiscount: 0,
                motoboltDispatched: false
            });
            if (text) outgoing.push({ type: 'text', text });
            return ctx;
        }
        messages.push({
            role: 'assistant',
            content: msg.content || '',
            tool_calls: calls
        });
        for (const call of calls) {
            const name = call.function?.name || call.name;
            const args = parseToolArgs(call.function?.arguments || call.arguments);
            const key = `${name}:${JSON.stringify(args)}`;
            const times = (seen.get(key) || 0) + 1;
            seen.set(key, times);
            let result;
            if (times > 1 && ['create_order', 'get_payment_link', 'send_media', 'preview_order'].includes(name)) {
                result = { ok: false, blocked: true, message: 'Esa herramienta ya se usó en este turno.' };
            } else {
                try {
                    result = await executeTool(name, args, Object.assign(ctx, { conv, deps, siteConfig, outgoing }));
                } catch (err) {
                    console.error('[whatsapp] tool', name, err);
                    result = { ok: false, message: err.message || 'Error en la herramienta' };
                }
            }
            messages.push({
                role: 'tool',
                tool_call_id: call.id,
                content: JSON.stringify(result).slice(0, 6000)
            });
        }
    }
    if (!outgoing.length) {
        outgoing.push({ type: 'text', text: 'Se me complicó armar la respuesta. Escribime de nuevo y lo retomo.' });
    }
    return ctx;
}

async function handleIncoming(incoming, deps) {
    const outgoing = [];
    const siteConfig = deps.siteConfig || await deps.SiteConfig.findOne({ configKey: 'main_config' });
    const store = shop.storeFromConfig(siteConfig);
    const conv = await loadConversation(incoming.from, incoming.contactName);

    if (rememberWamid(conv, incoming.wamid)) {
        return { duplicate: true, outgoing: [] };
    }

    const runtime = await runtimeContext(conv);

    if (!controlStates.aiMayRespond(conv)) {
        pushHistory(conv, 'user', incoming.text || incoming.buttonId || '[mensaje]');
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing: [], conv, skippedAi: true };
    }

    if (controlText.wantsHuman(incoming.text, incoming.buttonId)) {
        Object.assign(conv, controlStates.attentionAfter('request_human'));
        conv.handoffAt = new Date();
        const message = runtime.ai?.handoff || 'Dejo tu consulta para una persona del equipo. No te puedo prometer una respuesta inmediata.';
        outgoing.push({ type: 'text', text: message });
        pushHistory(conv, 'user', incoming.text || '[atención humana]');
        pushHistory(conv, 'assistant', message);
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv, handoff: true };
    }

    if (incoming.location) {
        const info = await applyLocation(conv, incoming.location, siteConfig);
        if (incoming.location.address) {
            conv.shipping.address = conv.shipping.address || incoming.location.address;
        }
        const copy = shippingCopy(info, store);
        if (info && info.central && !info.far && !conv.shipping.method) {
            outgoing.push({
                type: 'list',
                button: 'Elegir envío',
                text: copy,
                rows: [
                    { id: 'ship_motobolt', title: 'Motobolt', description: 'Moto a tu casa. Vos pedís el moto.' },
                    { id: 'ship_transportadora', title: 'Encomienda', description: 'Por si preferís transportadora' },
                    { id: 'ship_retiro', title: 'Retiro en local', description: 'Pasás por Ferumishop' }
                ]
            });
        } else if (info && (info.far || !info.central) && !conv.shipping.method) {
            outgoing.push({
                type: 'list',
                button: 'Elegir envío',
                text: copy,
                rows: [
                    { id: 'ship_transportadora', title: 'Encomienda', description: 'Transportadora al interior' },
                    { id: 'ship_retiro', title: 'Retiro en local', description: 'Pasás por Ferumishop' }
                ]
            });
        }
    }

    if (incoming.imageId) {
        const purpose = controlVision.imagePurpose({ text: incoming.text, shipping: conv.shipping, cart: conv.cart });
        if (purpose === 'house' && deps.cloudinary) {
            try {
                const { buffer, contentType } = await wa.downloadMedia(incoming.imageId);
                const check = controlVision.validateInboundImage({ mime: contentType, size: buffer.length });
                if (!check.ok) {
                    outgoing.push({ type: 'text', text: 'No pude usar esa imagen. Enviá una foto JPG, PNG o WEBP de hasta 5 MB.' });
                } else {
                    const uploaded = await deps.cloudinary.uploader.upload(
                        `data:${contentType};base64,${buffer.toString('base64')}`,
                        { folder: 'ferumi/whatsapp-casas' }
                    );
                    conv.housePhotoUrl = uploaded.secure_url;
                }
            } catch (err) {
                console.error('[whatsapp] house photo', err.message);
            }
        } else if (purpose === 'catalog') {
            const vision = controlVision.visionStatus();
            let note = vision.reason;
            if (vision.available) {
                try {
                    const { buffer, contentType } = await wa.downloadMedia(incoming.imageId);
                    const check = controlVision.validateInboundImage({ mime: contentType, size: buffer.length });
                    if (!check.ok) note = 'No pude validar esa imagen. Enviá JPG, PNG o WEBP de hasta 5 MB.';
                    else {
                        const described = await controlVision.describeProductImage({ buffer, mime: check.mime });
                        const products = await deps.Product.find({ isForSale: true, aiVisible: { $ne: false } })
                            .select('name description price stock photos variants')
                            .limit(40)
                            .lean();
                        const matches = controlVision.matchCatalogByDescription(described.text, products);
                        note = matches.length
                            ? `La coincidencia más cercana es ${matches[0].confidence}: ${matches[0].name}. Precio ${formatGs(matches[0].price)}. Stock ${matches[0].stock}. No es una confirmación de que sea el mismo producto.`
                            : 'No encontré una coincidencia suficiente en el catálogo de Ferumi. Si querés, decime el nombre.';
                    }
                } catch (err) {
                    console.error('[whatsapp] vision', err.message);
                    note = 'Recibí la foto, pero no pude analizarla. Decime el nombre del producto y lo busco en el catálogo.';
                }
            }
            outgoing.push({ type: 'text', text: note });
            pushHistory(conv, 'user', incoming.text || '[foto]');
            pushHistory(conv, 'assistant', note);
            conv.updatedAt = new Date();
            await conv.save();
            return { outgoing: controlOutbound.collapseOutgoing(outgoing), conv };
        }
    }

    const shipMethod = shippingButtonMethod(incoming.buttonId);
    if (shipMethod) {
        conv.shipping = conv.shipping || {};
        const info = shop.shippingOptions({
            lat: conv.shipping.lat, lng: conv.shipping.lng, city: conv.shipping.city, siteConfig
        });
        if (shipMethod === 'motobolt' && info.far) {
            outgoing.push({ type: 'text', text: 'Motobolt no llega hasta ahí. Puedo ofrecer encomienda o retiro.' });
        } else {
            conv.shipping.method = shipMethod;
            conv.shipping.distanceKm = info.distanceKm;
            conv.shipping.far = info.far;
            conv.shipping.central = info.central;
            if (shipMethod === 'motobolt') {
                outgoing.push({ type: 'text', text: `Perfecto, va por Motobolt 💖 ${MOTOBOLT_RULES}` });
            } else if (shipMethod === 'retiro') {
                outgoing.push({ type: 'text', text: `Genial, retirás en ${store.address}. ${store.mapsUrl}` });
            } else {
                outgoing.push({ type: 'text', text: 'Va por encomienda. Cuando pagues, el despachante se comunica con vos en unos instantes para coordinar. Puede demorar un poquito si hay muchos pedidos 💖' });
            }
        }
    }

    if (incoming.buttonId === 'edit_order') {
        conv.awaitingConfirm = false;
    }

    if (incoming.buttonId === 'confirm_order' || (conv.awaitingConfirm && looksLikeConfirm(incoming.text, incoming.buttonId))) {
        const created = await checkout.ensureConversationPayment(conv, { ...deps, siteConfig }, { mode: 'confirm', siteConfig });
        if (created.message) outgoing.push({ type: 'text', text: created.message });
        pushHistory(conv, 'user', incoming.text || incoming.buttonId || '[confirmación]');
        pushHistory(conv, 'assistant', created.message || '[sin mensaje de pago]');
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing: controlOutbound.collapseOutgoing(outgoing), conv, paymentIntentKey: created.intent?.key || '', sendPaymentLink: Boolean(created.send) };
    }

    if (controlText.detectIntent(incoming.text, incoming.buttonId) === 'pay_link') {
        const created = await checkout.ensureConversationPayment(conv, { ...deps, siteConfig }, { mode: 'resend', explicit: true, siteConfig });
        if (created.message) outgoing.push({ type: 'text', text: created.message });
        pushHistory(conv, 'user', incoming.text || '[enlace]');
        pushHistory(conv, 'assistant', created.message || 'Enlace vigente, sin reenvío.');
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing: controlOutbound.collapseOutgoing(outgoing), conv, paymentIntentKey: created.intent?.key || '', sendPaymentLink: Boolean(created.send) };
    }

    if (shipMethod) {
        const last = outgoing[outgoing.length - 1];
        pushHistory(conv, 'user', incoming.buttonId);
        pushHistory(conv, 'assistant', last?.text || 'Envío actualizado');
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv };
    }

    if (incoming.type === 'location' && outgoing.some((r) => r.type === 'list')) {
        pushHistory(conv, 'user', incoming.text);
        pushHistory(conv, 'assistant', '[opciones de envío]');
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv };
    }

    const userText = incoming.imageId && conv.housePhotoUrl
        ? `${incoming.text || ''} [Guardamos la foto de la casa para el moto.]`.trim()
        : (incoming.text || incoming.buttonId || '[mensaje]');
    const toolCtx = { paymentHandled: false, paymentIntentKey: '' };
    try {
        await runModelTurn(conv, userText, deps, siteConfig, outgoing, runtime, toolCtx);
    } catch (err) {
        console.error('[whatsapp] model turn', err);
        conv.lastError = String(err.message || '').slice(0, 240);
        outgoing.push({
            type: 'text',
            text: 'Se me complicó un segundo. Escribime de nuevo y lo retomo.'
        });
    }

    const collapsed = controlOutbound.collapseOutgoing(outgoing).map((reply) => {
        if (reply.text) reply.text = controlText.guardCustomerReply(reply.text, { paymentConfirmed: false, maxDiscount: 0, motoboltDispatched: false });
        return reply;
    });
    const lastText = [...collapsed].reverse().find((r) => r.type === 'text' || r.type === 'buttons');
    pushHistory(conv, 'user', userText);
    pushHistory(conv, 'assistant', lastText?.text || '[media/opciones]');
    conv.attentionStatus = conv.attentionStatus === 'ai_active' ? 'waiting_customer' : conv.attentionStatus;
    conv.updatedAt = new Date();
    await conv.save();
    return { outgoing: collapsed, conv, paymentIntentKey: toolCtx.paymentIntentKey || '', sendPaymentLink: Boolean(toolCtx.markPaymentSent) };
}

function paidCustomerText(order) {
    const trackingUrl = slug.publicTrackingUrl(order.ticketCode);
    let ship = 'El despachante se va a comunicar con vos en unos instantes. Puede demorar un poquito si hay muchos pedidos 💖';
    if (order.shippingMethod === 'motobolt') {
        ship = `Ahora lo preparamos. El despachante se comunica en unos instantes. ${MOTOBOLT_RULES}`;
    } else if (order.shippingMethod === 'retiro') {
        ship = 'Te avisamos por acá cuando esté listo para retirar en Ferumishop.';
    }
    return `Hola linda! Recibimos tu pago 💖 Ya estamos preparando tu pedido ${order.orderNumber}.\n\n` +
        `Seguí el estado acá:\n${trackingUrl}\n\n${ship}`;
}

async function notifyPaid(order) {
    if (!order || order.source !== 'whatsapp') return { skipped: true };
    if (!order.waFrom) return { skipped: true };
    if (!wa.config().ok) return { skipped: true };
    const WebOrder = mongoose.models.WebOrder;
    if (WebOrder) {
        const claimed = await WebOrder.findOneAndUpdate(
            { _id: order._id, waPaidNotifiedAt: { $exists: false } },
            { $set: { waPaidNotifiedAt: new Date() } },
            { new: true }
        );
        if (!claimed) return { skipped: true, already: true };
    }
    await wa.sendText(order.waFrom, paidCustomerText(order));
    return { ok: true };
}

async function notifyFulfillment(order, action) {
    if (!order || order.source !== 'whatsapp' || !order.waFrom) return { skipped: true };
    if (!wa.config().ok) return { skipped: true };
    if (action !== 'preparado' && action !== 'scan' && action !== 'entregado') return { skipped: true };
    const WebOrder = mongoose.models.WebOrder;
    const flag = action === 'entregado' ? 'waDeliveredNotifiedAt' : 'waPrepNotifiedAt';
    if (WebOrder) {
        const claimed = await WebOrder.findOneAndUpdate(
            { _id: order._id, [flag]: { $exists: false } },
            { $set: { [flag]: new Date() } },
            { new: true }
        );
        if (!claimed) return { skipped: true, already: true };
    }
    const siteConfig = await mongoose.models.SiteConfig?.findOne({ configKey: 'main_config' });
    let kind = 'preparado_envio';
    if (action === 'entregado') {
        await wa.sendText(order.waFrom, `Linda, tu pedido ${order.orderNumber} ya fue entregado 💖 Gracias por comprar en FERUMI.`);
        return { ok: true };
    }
    if (order.shippingMethod === 'motobolt') kind = 'preparado_motobolt';
    if (order.shippingMethod === 'retiro') kind = 'preparado_retiro';
    const text = shop.customerWhatsAppText(order, siteConfig, kind);
    await wa.sendText(order.waFrom, text);
    if (order.shippingMethod === 'motobolt') {
        await wa.sendText(order.waFrom, `Ojo amor: ${MOTOBOLT_RULES}`);
    }
    return { ok: true };
}

module.exports = {
    TOOLS,
    MOTOBOLT_RULES,
    WaConversation,
    formatGs,
    canCreateOrder,
    missingCustomer,
    looksLikeConfirm,
    previewText,
    paidCustomerText,
    shippingCopy,
    mediaReplies,
    compactProduct,
    handleIncoming,
    createWhatsAppOrder,
    notifyPaid,
    notifyFulfillment,
    uniqueSlug
};
