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
            name: 'calculate_shipping',
            description: 'Calcula el envío con las tarifas cargadas. Un lugar como Capiatá ruta 2 usa el precio de esa frase.',
            parameters: {
                type: 'object',
                properties: {
                    city: { type: 'string' },
                    address: { type: 'string' },
                    query: { type: 'string' },
                    method: { type: 'string', enum: ['delivery_propio', 'motobolt', 'transportadora', 'retiro'] }
                }
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'send_transfer_details',
            description: 'Envía el alias, el banco y el nombre cargados para transferencia. No inventa datos ni confirma el pago.',
            parameters: { type: 'object', properties: {} }
        }
    },
    {
        type: 'function',
        function: {
            name: 'search_catalog',
            description: 'Busca productos reales por una o varias palabras (pinza, pinzas, pestaña, labial). Usala antes de decir que no hay. Si devuelve productos, ofrecelos.',
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

HABLA COMO UNA PERSONA, EN ESTE ORDEN
1. Si no sabés su nombre, saludá y preguntale cómo se llama. La consulta que haya hecho la respondés después del nombre.
2. Respondé lo que preguntó y, si hace falta, mostrale el producto con foto y precio.
3. Cuando el pedido está listo, pasá al envío y listá, separados: delivery propio (sale a las 18:00, 6 pm), Motobolt y transportadora. Preguntale de dónde es o pedile la ubicación.
4. Cuando ya cotizaste y eligió el envío, pasá al pago: transferencia o PagoPar (tarjeta, QR, giros y Tigo). El alias se pasa recién si elige transferencia, junto con el total. Ahí también pedí nombre, si falta, y una referencia de la casa.
5. Si manda el comprobante, leé la foto. Si parece una transferencia, anotala como parcial hasta que una persona la apruebe. No digas que ya está confirmada.
6. Si elige PagoPar, pedí solo los datos del enlace: nombre, cédula, correo y teléfono.
7. Efectivo solo se agenda para el día siguiente si está en zona.
- Si manda ubicación, guardala y decile solo el costo del envío que eligió, o si está en zona o va por transportadora. No le escribas el pin, los kilómetros ni las coordenadas.
- «¿Sale a las 6?» es una consulta: respondé el horario. No es un pedido de productos.
- ${MOTOBOLT_RULES}
- Nunca cuentes un error interno.`;
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
    const total = cartTotal(cart) + (Number(conv.shipping?.quotedAmount) || 0);
    if (total <= 0) return { ok: false, message: 'El total del pedido no es válido.' };
    return { ok: true, total };
}

function stateBlock(conv, research) {
    const cart = conv.cart || [];
    const c = conv.customer || {};
    const s = conv.shipping || {};
    const lines = cart.length
        ? cart.map((i) => `• ${i.quantity}x ${i.name}${i.variantName ? ` (${i.variantName})` : ''} — ${formatGs(i.price)}`).join('\n')
        : '(vacío)';
    const found = (research?.products || []).slice(0, 6).map((product) => {
        const stock = product.stock ?? product.variants?.reduce?.((sum, variant) => sum + (variant.stock || 0), 0);
        return `• ${product.name} — ${product.priceLabel || formatGs(product.price)} — stock ${stock ?? '—'}`;
    }).join('\n');
    const quote = research?.quote?.ok
        ? `Envío ya calculado: ${formatGs(research.quote.amount)} (${research.quote.reason || research.quote.matchedPhrase || 'tarifa'}). Usá ese importe.`
        : '';
    return `ESTADO ACTUAL DEL CHAT
Carrito:
${lines}
Total productos: ${formatGs(cartTotal(cart))}
Cliente: nombre=${c.name || '—'} CI=${c.document || '—'} email=${c.email || '—'} tel=${c.phone || '—'}
Envío: método=${s.method || '—'} cobertura=${s.coverage || '—'} ciudad=${s.city || '—'} dir=${s.address || '—'} ref=${s.reference || '—'} tarifa=${s.deliveryQuote != null ? formatGs(s.deliveryQuote) : '—'}
Coordenadas guardadas: ${s.lat != null && s.lng != null ? 'sí' : 'no'}
Pago preferido: ${conv.paymentPreference || '—'}
Transferencia: ${conv.paymentState === 'confirmado' ? 'CONFIRMADA' : 'no confirmada'}
Esperando confirmación de pedido: ${conv.awaitingConfirm ? 'SÍ' : 'no'}
Último pedido: ${conv.lastOrderNumber || '—'} slug=${conv.lastCheckoutSlug || '—'}
waId=${conv.waId}
${research?.catalogBlocked ? 'ESTE MENSAJE NO PIDE UN PRODUCTO. No uses search_catalog ni send_media. No mandes fotos, nombres ni precios.' : (found ? `BÚSQUEDA REAL DE ESTE MENSAJE (no digas que no hay si esta lista tiene productos):\n${found}` : 'BÚSQUEDA REAL: todavía no hay coincidencias para este texto.')}
${quote}
${s.lat != null ? 'Ya hay ubicación guardada. No la pidas de nuevo y no se la repitas al cliente.' : ''}
Hablá como una persona de la tienda. Contestá la consulta y seguí el paso. No copies un formulario.`;
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
            central: Boolean,
            quotedAmount: { type: Number, default: null },
            deliveryQuote: { type: Number, default: null },
            coverage: { type: String, default: '' }
        },
        housePhotoUrl: { type: String, default: '' },
        awaitingConfirm: { type: Boolean, default: false },
        lastOrderId: { type: mongoose.Schema.Types.ObjectId, ref: 'WebOrder' },
        lastOrderNumber: { type: String, default: '' },
        lastCheckoutSlug: { type: String, default: '' },
        processedWamids: { type: [String], default: [] },
        attentionStatus: { type: String, default: 'ai_active', index: true },
        paymentPreference: { type: String, default: '' },
        paymentState: { type: String, default: '' },
        saleStage: { type: String, default: 'browsing' },
        awaitingName: { type: Boolean, default: false },
        pendingAsk: { type: String, default: '' },
        lastOffer: {
            productId: { type: String, default: '' },
            name: { type: String, default: '' },
            price: { type: Number, default: 0 }
        },
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
    const products = await Product.find({ isForSale: true, aiVisible: { $ne: false } })
        .populate('category')
        .select('name description price stock hasVariants variants photos aiNotes aiUsage category isFeatured')
        .limit(300);
    if (!q) {
        const featured = products.filter((product) => product.isFeatured).slice(0, 8);
        return (featured.length ? featured : products.slice(0, 8)).map(compactProduct);
    }
    const catalog = require('./wa-control/catalog');
    return catalog.rankCatalog(products, q).slice(0, 8).map(compactProduct);
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
        if (ctx.catalogBlocked) return { ok: false, count: 0, products: [], message: 'No busques productos. La clienta no pidió un producto en este mensaje.' };
        const products = await searchCatalog(Product, args.query);
        return { count: products.length, products, instruction: products.length ? 'Ofrecé estos productos. No digas que no hay.' : 'No hubo coincidencias con esas palabras. Probá una palabra más corta antes de decir que no está.' };
    }
    if (name === 'calculate_shipping') {
        const quote = await quoteConversation(conv, { query: args.query || args.city || '', city: args.city, address: args.address, method: args.method });
        if (quote?.ok && quote.amount != null) {
            conv.shipping = conv.shipping || {};
            if (args.city) conv.shipping.city = args.city;
            if (args.address) conv.shipping.address = args.address;
            if (args.method) conv.shipping.method = args.method;
            conv.shipping.quotedAmount = quote.includedInOrder === false ? 0 : quote.amount;
            conv.shipping.quoteReason = quote.matchedPhrase || quote.reason || '';
        }
        return quote;
    }
    if (name === 'send_transfer_details') {
        const { transferMessage } = require('./wa-control/transfer');
        const message = transferMessage(ctx.runtime?.ops?.transfer, { total: formatGs(cartTotal(conv.cart) + (Number(conv.shipping?.quotedAmount) || 0)) });
        conv.paymentPreference = 'transferencia';
        if (message.ok) outgoing.push({ type: 'text', text: message.text });
        return message;
    }
    if (name === 'get_product') {
        const product = await resolveProduct(Product, args.productId);
        if (!product) return { ok: false, message: 'Producto no encontrado' };
        return compactProduct(product);
    }
    if (name === 'send_media') {
        if (ctx.catalogBlocked || (conv.saleStage && conv.saleStage !== 'browsing')) {
            return { ok: false, message: 'No mandes fotos. La clienta no pidió un producto.' };
        }
        if (ctx.mediaSent) return { ok: false, message: 'Ya mostraste un producto en este turno.' };
        const product = await resolveProduct(Product, args.productId);
        if (!product) return { ok: false, message: 'Producto no encontrado' };
        const replies = mediaReplies(product, args.kind || 'photos', args.variantName);
        outgoing.push(...replies);
        ctx.mediaSent = true;
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

async function quoteConversation(conv, extra = {}) {
    const { controlModels } = require('./wa-control/models');
    const { quoteShipping } = require('./wa-control/rates');
    const rates = await controlModels().WaRate.find({ active: true }).lean();
    const shipping = conv.shipping || {};
    return quoteShipping(rates, {
        method: extra.method || shipping.method || 'delivery_propio',
        city: extra.city || shipping.city || '',
        zone: shipping.zone || '',
        address: extra.address || shipping.address || '',
        query: extra.query || '',
        subtotal: cartTotal(conv.cart),
        far: Boolean(shipping.far)
    });
}

async function researchCustomerMessage(text, conv, deps) {
    const flow = require('./wa-control/flow');
    const catalogBlocked = !flow.isProductSearch(text) || (conv.saleStage && conv.saleStage !== 'browsing');
    let products = [];
    if (!catalogBlocked) {
        try {
            products = deps.Product ? await searchCatalog(deps.Product, text) : [];
        } catch (err) {
            console.warn('[whatsapp] búsqueda de catálogo', err.message);
        }
    }
    let quote = null;
    const plain = controlText.normalizeText(text);
    const talksPlace = /ruta|envio|delivery|barrio|ciudad|lleva|retiro|moto|zona/.test(plain) || conv.shipping?.city || conv.shipping?.address;
    if (talksPlace) {
        try { quote = await quoteConversation(conv, { query: text }); } catch (err) { quote = null; }
    }
    return { products, quote, catalogBlocked };
}

async function runModelTurn(conv, userText, deps, siteConfig, outgoing, runtime, toolCtx) {
    if (!deepinfra.config().ok) {
        outgoing.push({
            type: 'text',
            text: 'Hola. Contame qué producto buscás y te muestro foto y precio.'
        });
        return toolCtx;
    }

    const messages = [
        { role: 'system', content: systemPrompt(siteConfig, runtime || {}) },
        { role: 'system', content: stateBlock(conv, toolCtx?.research) },
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
                paymentConfirmed: Boolean(ctx.paymentConfirmed),
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
                    result = await executeTool(name, args, Object.assign(ctx, { conv, deps, siteConfig, outgoing, runtime }));
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

async function applyGuide(conv, incoming, deps, siteConfig, runtime) {
    const flow = require('./wa-control/flow');
    const geo = require('./wa-control/geo');
    const store = shop.storeFromConfig(siteConfig);
    let place = null;
    if (conv.shipping?.lat != null && conv.shipping?.lng != null) {
        place = geo.describePoint({
            lat: conv.shipping.lat,
            lng: conv.shipping.lng,
            address: conv.shipping.address,
            name: conv.shipping.city,
            store
        });
        if (place.city) conv.shipping.city = place.city;
        conv.shipping.distanceKm = place.distanceKm;
        conv.shipping.far = Boolean(place.interior);
        conv.shipping.central = !place.interior;
    }
    let quote = null;
    if (place?.city) {
        try {
            quote = await quoteConversation(conv, { city: place.city, address: conv.shipping.address, method: 'delivery_propio' });
        } catch (err) {
            quote = null;
        }
    }
    if ((!quote || !quote.ok) && conv.shipping?.deliveryQuote != null && place?.city) {
        quote = { ok: true, amount: conv.shipping.deliveryQuote, includedInOrder: true };
    }
    let products = [];
    const stage = conv.saleStage || 'browsing';
    if (stage === 'browsing' && flow.isProductSearch(incoming.text, incoming.buttonId)) {
        try {
            const rows = await deps.Product.find({ isForSale: true, aiVisible: { $ne: false } })
                .select('name description price stock photos variants aiNotes aiUsage')
                .limit(300);
            const ranked = require('./wa-control/catalog').rankCatalog(rows, incoming.text).slice(0, 1);
            products = ranked;
        } catch (err) {
            products = [];
        }
    }
    const shipForTotal = Number(quote?.ok && quote.includedInOrder !== false ? quote.amount : conv.shipping?.deliveryQuote) || 0;
    const methodNow = conv.shipping?.method || '';
    const shippingPart = methodNow === 'motobolt' || methodNow === 'retiro' || methodNow === 'transportadora' ? 0 : shipForTotal;
    const totalLabel = formatGs(cartTotal(conv.cart) + shippingPart);
    let decision = flow.planTurn({
        text: incoming.text,
        buttonId: incoming.buttonId,
        hasLocation: Boolean(incoming.location),
        hasImage: Boolean(incoming.imageId),
        cart: conv.cart || [],
        stage,
        customer: conv.customer || {},
        place,
        quote,
        transfer: runtime.ops?.transfer,
        departureTime: runtime.ops?.departureTime || '18:00',
        lastOffer: conv.lastOffer,
        products,
        chosenMethod: conv.shipping?.method || '',
        awaitingName: Boolean(conv.awaitingName),
        pendingQuestion: conv.pendingAsk || '',
        totalLabel
    });
    if (decision.customer?.name) conv.customer = { ...(conv.customer || {}), ...decision.customer, phone: conv.customer?.phone || conv.waId };
    if (decision.resume) {
        const question = String(decision.resume || '').trim();
        conv.pendingAsk = '';
        conv.awaitingName = false;
        if (question) {
            let followProducts = [];
            if (flow.isProductSearch(question)) {
                try {
                    const rows = await deps.Product.find({ isForSale: true, aiVisible: { $ne: false } })
                        .select('name description price stock photos variants aiNotes aiUsage')
                        .limit(300);
                    followProducts = require('./wa-control/catalog').rankCatalog(rows, question).slice(0, 1);
                } catch (err) {
                    followProducts = [];
                }
            }
            decision = flow.planTurn({
                text: question,
                hasLocation: false,
                cart: conv.cart || [],
                stage: 'browsing',
                customer: conv.customer || {},
                place,
                quote,
                transfer: runtime.ops?.transfer,
                departureTime: runtime.ops?.departureTime || '18:00',
                lastOffer: conv.lastOffer,
                products: followProducts,
                chosenMethod: conv.shipping?.method || '',
                totalLabel
            });
        }
    }
    if (!decision.handled) return null;
    if (decision.addOffer && conv.lastOffer?.productId) {
        await addToCart(conv, deps.Product, { productId: conv.lastOffer.productId, quantity: 1 });
        conv.lastOffer = { productId: '', name: '', price: 0 };
    }
    if (decision.showProduct) {
        const product = decision.showProduct;
        outgoingPushProduct(conv, product);
        conv.lastOffer = { productId: String(product._id || product.id || ''), name: product.name, price: product.price };
    }
    conv.shipping = conv.shipping || {};
    if (decision.method) conv.shipping.method = decision.method;
    if (place) {
        conv.shipping.coverage = place.inZone && !place.interior ? 'central' : 'interior';
        if (quote?.ok && quote.amount != null && quote.includedInOrder !== false) conv.shipping.deliveryQuote = quote.amount;
        const methodNow = conv.shipping.method || '';
        if (methodNow === 'delivery_propio') conv.shipping.quotedAmount = conv.shipping.deliveryQuote != null ? conv.shipping.deliveryQuote : null;
        else if (methodNow === 'motobolt' || methodNow === 'retiro') conv.shipping.quotedAmount = 0;
    }
    if (decision.payment) conv.paymentPreference = decision.payment;
    if (decision.customer) conv.customer = { ...(conv.customer || {}), ...decision.customer };
    if (decision.customer?.name && !conv.customer.phone) conv.customer.phone = conv.waId;
    if (decision.reference) conv.shipping.reference = decision.reference;
    if (decision.holdQuestion) conv.pendingAsk = String(decision.holdQuestion).slice(0, 300);
    if (decision.resume) conv.pendingAsk = '';
    if (decision.askName && !String(conv.customer?.name || '').trim()) conv.awaitingName = true;
    if (decision.clearNameAsk || decision.customer?.name) conv.awaitingName = false;
    if (decision.stage) conv.saleStage = decision.stage;
    const replies = [...(decision.replies || [])];
    let productToShow = decision.showProduct || null;
    if (decision.createOrder === 'pagopar') {
        try {
            const created = await checkout.ensureConversationPayment(conv, { ...deps, siteConfig }, { mode: 'confirm', siteConfig });
            replies.push(created.message || 'Te dejo el enlace de PagoPar. Ahí podés pagar con QR, tarjeta, giro o Tigo.');
        } catch (err) {
            console.error('[whatsapp] enlace', err.message);
            replies.push('No pude dejar el enlace listo ahora. Si querés, lo reintento o seguimos por transferencia.');
        }
    }
    if (decision.createOrder === 'efectivo' || decision.payment === 'transferencia') {
        try {
            await createOfflineOrder(conv, deps, siteConfig, decision.createOrder || decision.payment);
        } catch (err) {
            console.error('[whatsapp] pedido local', err.message);
        }
    }
    try { await syncOpenOrder(conv, deps); } catch (err) { console.error('[whatsapp] pedido abierto', err.message); }
    const facts = replies.filter(Boolean).join('\n\n');
    let text = facts;
    if (facts && !decision.verbatim) {
        try {
            const said = await require('./wa-control/speak').speakTurn({
                text: incoming.text || (incoming.location ? 'Te mandé la ubicación.' : (incoming.buttonId || 'Seguimos.')),
                facts,
                askName: Boolean(decision.askName) && !String(conv.customer?.name || '').trim(),
                customerName: conv.customer?.name || '',
                history: conv.history || [],
                paymentConfirmed: conv.paymentState === 'confirmado'
            });
            text = said.text || facts;
        } catch (err) {
            console.error('[whatsapp] habla', err.message);
        }
    }
    return { texts: text ? [text] : [], product: productToShow };
}

function outgoingPushProduct(conv, product) {
    conv._pendingProduct = product;
}

async function createOfflineOrder(conv, deps, siteConfig, method) {
    const { WebOrder } = deps;
    const customer = conv.customer || {};
    const shipping = conv.shipping || {};
    const items = (conv.cart || []).map((item) => ({
        productId: item.productId,
        variantName: item.variantName || '',
        name: item.name,
        quantity: item.quantity,
        price: item.price,
        image: item.image || ''
    }));
    const subtotal = cartTotal(items);
    const shippingCost = Number(shipping.quotedAmount) || 0;
    const existing = await WebOrder.findOne({
        waFrom: conv.waId,
        source: 'whatsapp',
        paymentStatus: 'pendiente',
        paymentMethod: method === 'efectivo' ? 'efectivo' : 'transferencia',
        deletedAt: { $exists: false }
    }).sort({ createdAt: -1 });
    if (existing) {
        if (customer.name) existing.customerName = customer.name;
        existing.customerPhone = customer.phone || conv.waId || existing.customerPhone;
        if (shipping.city) existing.shippingCity = shipping.city;
        if (shipping.address) existing.shippingAddress = shipping.address;
        if (shipping.reference) existing.shippingReference = shipping.reference;
        if (shipping.method) existing.shippingMethod = shipping.method;
        if (shipping.lat != null) existing.shippingCoords = { lat: shipping.lat, lng: shipping.lng };
        if (shipping.distanceKm != null) existing.shippingDistanceKm = shipping.distanceKm;
        if ((conv.cart || []).length) {
            existing.subtotal = subtotal;
            existing.shippingCost = shippingCost;
            existing.totalAmount = subtotal + shippingCost;
            existing.items = items;
        }
        await existing.save();
        conv.lastOrderId = existing._id;
        conv.lastOrderNumber = existing.orderNumber;
        return existing;
    }
    const order = new WebOrder({
        orderNumber: shop.makeOrderNumber(),
        ticketCode: shop.makeTicketCode(),
        idempotencyKey: `waoff-${conv.waId}-${method}`.slice(0, 80),
        source: 'whatsapp',
        waFrom: conv.waId,
        customerName: customer.name || conv.profileName || 'Cliente WhatsApp',
        customerEmail: customer.email && customer.email.includes('@') ? customer.email : `wa.${conv.waId}@pedidos.ferumi.shop`,
        customerDocument: customer.document || '0',
        customerPhone: customer.phone || conv.waId,
        items,
        subtotal,
        shippingCost,
        totalAmount: subtotal + shippingCost,
        status: 'pendiente',
        paymentMethod: method === 'efectivo' ? 'efectivo' : 'transferencia',
        paymentStatus: 'pendiente',
        financialStatus: 'pendiente',
        shippingMethod: shipping.method || 'delivery_propio',
        shippingAddress: shipping.address || '',
        shippingCity: shipping.city || '',
        shippingReference: shipping.reference || '',
        shippingCoords: shipping.lat != null ? { lat: shipping.lat, lng: shipping.lng } : undefined,
        shippingDistanceKm: shipping.distanceKm,
        fulfillmentStatus: shop.FULFILLMENT.PENDIENTE_PAGO
    });
    shop.appendEvent(order, shop.FULFILLMENT.PENDIENTE_PAGO, method === 'efectivo'
        ? 'Efectivo agendado para el día siguiente.'
        : 'Esperando comprobante de transferencia.');
    await order.save();
    conv.lastOrderId = order._id;
    conv.lastOrderNumber = order.orderNumber;
    return order;
}

function waitingForReceipt(conv) {
    const recent = (conv.history || []).slice(-4).some((item) => item.role === 'assistant' && /alias|comprobante/i.test(String(item.content || '')));
    return conv.paymentPreference === 'transferencia' || conv.saleStage === 'receipt' || conv.saleStage === 'revision' || recent;
}

async function captureCustomerReceipt(conv, incoming, deps) {
    const flow = require('./wa-control/flow');
    const text = incoming.text || '';
    if (!incoming.imageId && /confirmad|ya confirmaron|se confirmo/.test(controlText.normalizeText(text))) {
        const models = require('./wa-control/models').controlModels();
        const existing = await models.WaReceipt.findOne({ waId: conv.waId }).sort({ createdAt: -1 });
        if (existing?.status === 'confirmado') return { text: 'Sí, tu transferencia ya está confirmada. Seguimos con el pedido.', stage: 'done' };
        if (existing?.status === 'parcial') return { text: 'La transferencia quedó anotada. Falta que una persona del local la apruebe.', stage: 'revision' };
        if (existing?.status === 'rechazado') return { text: 'Esa captura no se pudo validar. Si querés, mandame otra foto.', stage: 'receipt' };
        if (existing) return { text: 'Todavía está en revisión. Una persona la aprueba en el local. No hace falta reenviarla.', stage: 'revision' };
    }
    const claims = flow.alreadyClaimsReceipt(text) || controlText.detectIntent(text, incoming.buttonId) === 'receipt';
    const waiting = waitingForReceipt(conv);
    const bundledWithPlace = Boolean(incoming.imageId && incoming.location);
    if (incoming.imageId && !waiting && !claims && !bundledWithPlace) return null;
    if (!incoming.imageId && !claims) return null;
    if (!incoming.imageId && claims && !waiting) return null;
    const models = require('./wa-control/models').controlModels();
    const existing = await models.WaReceipt.findOne({ waId: conv.waId }).sort({ createdAt: -1 });
    if (!incoming.imageId) {
        if (existing?.status === 'confirmado') return { text: 'Tu transferencia ya está confirmada. Seguimos con el pedido.', stage: 'done' };
        if (existing) return { text: 'La captura ya está en revisión. No hace falta mandarla de nuevo.', stage: 'revision' };
        return { text: 'Todavía no me llegó la foto. Mandala como imagen.', stage: 'receipt' };
    }
    let mediaUrl = '';
    let imageData = '';
    let rawText = '';
    let parsed = { isTransfer: false, amount: null, bank: '', recipientName: '', senderName: '' };
    try {
        const { buffer, contentType } = await wa.downloadMedia(incoming.imageId);
        const reader = require('./wa-control/receipt-read');
        try {
            const read = await reader.readReceiptImage(buffer, contentType);
            parsed = read.parsed || parsed;
            rawText = read.rawText || '';
        } catch (err) {
            console.error('[whatsapp] lectura de comprobante', err.message);
        }
        if (deps.cloudinary) {
            try {
                const uploaded = await deps.cloudinary.uploader.upload(
                    `data:${contentType};base64,${buffer.toString('base64')}`,
                    { folder: 'ferumi/whatsapp-comprobantes' }
                );
                mediaUrl = uploaded.secure_url || '';
            } catch (err) {
                console.error('[whatsapp] subida de comprobante', err.message);
            }
        }
        if (!mediaUrl && buffer.length > 0 && buffer.length < 700000) {
            imageData = `data:${contentType || 'image/jpeg'};base64,${buffer.toString('base64')}`;
        }
    } catch (err) {
        console.error('[whatsapp] descarga de comprobante', err.message);
    }
    const service = require('./wa-control/service');
    const saved = await service.registerIncomingReceipt({
        waId: conv.waId,
        mediaId: incoming.imageId,
        reference: text,
        mediaUrl,
        imageData,
        senderName: parsed.senderName,
        recipientName: parsed.recipientName,
        bankName: parsed.bank,
        extractedAmount: parsed.amount,
        declaredAmount: parsed.amount,
        isTransfer: parsed.isTransfer,
        rawText
    });
    conv.paymentPreference = 'transferencia';
    const amount = parsed.amount ? `${Number(parsed.amount).toLocaleString('es-PY')} Gs` : '';
    const bits = [];
    if (amount) bits.push(amount);
    if (parsed.senderName) bits.push(`de ${parsed.senderName}`);
    if (parsed.recipientName) bits.push(`para ${parsed.recipientName}`);
    if (parsed.bank) bits.push(`por ${parsed.bank}`);
    const status = saved.receipt?.status || 'en_verificacion';
    let reply;
    if (saved.duplicate) {
        reply = 'Esa captura ya está cargada. No hace falta mandarla otra vez.';
    } else if (bits.length && status === 'parcial') {
        reply = `Leí el comprobante: ${bits.join(', ')}. La anoto como transferencia parcial hasta que la aprueben en el local.`;
    } else if (bits.length && status === 'diferencia') {
        reply = `Leí el comprobante: ${bits.join(', ')}. El monto no cierra con el pedido, así que queda para que lo revisen.`;
    } else if (bits.length) {
        reply = `Leí el comprobante: ${bits.join(', ')}. Queda para que lo aprueben en el local.`;
    } else {
        reply = 'Recibí la foto. No pude leer todo el texto, así que queda para que la revisen en el local.';
    }
    const city = conv.shipping?.city;
    const quoteAmount = conv.shipping?.deliveryQuote;
    if (city && quoteAmount != null && conv.shipping?.coverage !== 'interior') {
        reply += ` A ${city} el delivery propio sale ${Number(quoteAmount).toLocaleString('es-PY')} Gs.`;
    } else if (conv.shipping?.coverage === 'interior') {
        reply += ' Esa ubicación va por transportadora.';
    }
    if (!String(conv.customer?.name || '').trim()) {
        reply += ' ¿Cómo es tu nombre?';
    }
    return { stage: 'revision', askName: !String(conv.customer?.name || '').trim(), text: reply };
}

async function syncOpenOrder(conv, deps) {
    if (!conv?.lastOrderId || !deps?.WebOrder) return null;
    const order = await deps.WebOrder.findById(conv.lastOrderId);
    if (!order || order.deletedAt) return null;
    const customer = conv.customer || {};
    const shipping = conv.shipping || {};
    if (customer.name) order.customerName = customer.name;
    if (customer.phone || conv.waId) order.customerPhone = customer.phone || conv.waId;
    if (shipping.city) order.shippingCity = shipping.city;
    if (shipping.address) order.shippingAddress = shipping.address;
    if (shipping.reference) order.shippingReference = shipping.reference;
    if (shipping.method) order.shippingMethod = shipping.method;
    if (shipping.lat != null && shipping.lng != null) order.shippingCoords = { lat: shipping.lat, lng: shipping.lng };
    if (shipping.distanceKm != null) order.shippingDistanceKm = shipping.distanceKm;
    if ((conv.cart || []).length) {
        const subtotal = cartTotal(conv.cart);
        const shippingCost = Number(shipping.quotedAmount) || 0;
        order.subtotal = subtotal;
        order.shippingCost = shippingCost;
        order.totalAmount = subtotal + shippingCost;
    }
    await order.save();
    return order;
}

async function handleIncoming(incoming, deps) {
    const outgoing = [];
    const siteConfig = deps.siteConfig || await deps.SiteConfig.findOne({ configKey: 'main_config' });
    const store = shop.storeFromConfig(siteConfig);
    const conv = await loadConversation(incoming.from, incoming.contactName);

    const wamids = (incoming.wamids && incoming.wamids.length ? incoming.wamids : [incoming.wamid]).filter(Boolean);
    if (wamids.length && wamids.every((id) => (conv.processedWamids || []).includes(id))) {
        return { duplicate: true, outgoing: [] };
    }
    wamids.forEach((id) => rememberWamid(conv, id));

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
        const message = 'Dale, te paso con una persona del equipo 😊 Ya dejé este chat en atención humana. Te responden por acá apenas puedan.';
        conv.important = true;
        outgoing.push({ type: 'text', text: message });
        pushHistory(conv, 'user', incoming.text || '[atención humana]');
        pushHistory(conv, 'assistant', message);
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv, handoff: true };
    }

    if (incoming.location) {
        await applyLocation(conv, incoming.location, siteConfig);
        if (incoming.location.address) conv.shipping.address = incoming.location.address;
        if (incoming.location.name && !conv.shipping.city) conv.shipping.city = incoming.location.name;
        conv.shipping.lat = Number(incoming.location.lat);
        conv.shipping.lng = Number(incoming.location.lng);
    }
    if (conv.shipping?.lat != null && conv.shipping?.lng != null) {
        try {
            const geo = require('./wa-control/geo');
            const place = geo.describePoint({
                lat: conv.shipping.lat,
                lng: conv.shipping.lng,
                address: conv.shipping.address,
                name: conv.shipping.city,
                store: shop.storeFromConfig(siteConfig)
            });
            if (place.city) conv.shipping.city = place.city;
            conv.shipping.coverage = place.inZone && !place.interior ? 'central' : 'interior';
            conv.shipping.distanceKm = place.distanceKm;
            if (place.city && conv.shipping.coverage !== 'interior') {
                const quoted = await quoteConversation(conv, { city: place.city, method: 'delivery_propio' });
                if (quoted?.ok && quoted.amount != null && quoted.includedInOrder !== false) conv.shipping.deliveryQuote = quoted.amount;
            }
        } catch (err) {
            console.error('[whatsapp] zona', err.message);
        }
    }

    const captured = await captureCustomerReceipt(conv, incoming, deps);
    if (captured) {
        if (captured.stage) conv.saleStage = captured.stage;
        if (captured.askName && !String(conv.customer?.name || '').trim()) conv.awaitingName = true;
        try { await syncOpenOrder(conv, deps); } catch (err) { console.error('[whatsapp] pedido abierto', err.message); }
        outgoing.push({ type: 'text', text: captured.text });
        pushHistory(conv, 'user', incoming.text || '[foto]');
        pushHistory(conv, 'assistant', captured.text);
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv };
    }

    const receiptImage = Boolean(incoming.imageId) && (
        controlText.detectIntent(incoming.text, incoming.buttonId) === 'receipt'
        || conv.paymentPreference === 'transferencia'
        || /comprobante|transfer/.test(controlText.normalizeText(incoming.text))
    );
    if (incoming.imageId && !receiptImage) {
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
            let note = 'Recibí la foto. Decime el nombre del producto y lo busco en el catálogo.';
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

    if (!incoming.imageId && !require('./wa-control/flow').alreadyClaimsReceipt(incoming.text) && (controlText.detectIntent(incoming.text, incoming.buttonId) === 'transfer' || /transferencia|alias|ueno/.test(controlText.normalizeText(incoming.text)))) {
        const { transferMessage } = require('./wa-control/transfer');
        conv.paymentPreference = 'transferencia';
        conv.saleStage = 'receipt';
        const message = transferMessage(runtime.ops?.transfer, {});
        outgoing.push({ type: 'text', text: message.text });
        pushHistory(conv, 'user', incoming.text || '[transferencia]');
        pushHistory(conv, 'assistant', message.text);
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv };
    }

    if (controlText.detectIntent(incoming.text, incoming.buttonId) === 'receipt' || (incoming.imageId && /comprobante|transfer/.test(controlText.normalizeText(incoming.text)))) {
        let mediaUrl = '';
        if (incoming.imageId && deps.cloudinary) {
            try {
                const { buffer, contentType } = await wa.downloadMedia(incoming.imageId);
                const uploaded = await deps.cloudinary.uploader.upload(
                    `data:${contentType};base64,${buffer.toString('base64')}`,
                    { folder: 'ferumi/whatsapp-comprobantes' }
                );
                mediaUrl = uploaded.secure_url || '';
            } catch (err) {
                console.error('[whatsapp] comprobante', err.message);
            }
        }
        const service = require('./wa-control/service');
        const saved = await service.registerIncomingReceipt({
            waId: conv.waId,
            mediaId: incoming.imageId || incoming.wamid,
            reference: incoming.text || '',
            mediaUrl
        });
        const message = saved.duplicate
            ? 'Ese comprobante ya estaba cargado. No lo sumé como otro pago. Queda pendiente de revisión.'
            : 'Recibí el comprobante 😊 Lo dejé para revisión. Todavía no está confirmado el pago.';
        outgoing.push({ type: 'text', text: message });
        pushHistory(conv, 'user', incoming.text || '[comprobante]');
        pushHistory(conv, 'assistant', message);
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv };
    }

    const guided = await applyGuide(conv, incoming, deps, siteConfig, runtime);
    if (guided) {
        if (guided.product) {
            const photos = mediaReplies(guided.product, 'photos').slice(0, 1);
            outgoing.push(...photos);
        }
        for (const text of guided.texts) outgoing.push({ type: 'text', text });
        if (incoming.location && conv.lastOrderId && deps.WebOrder && conv.shipping?.lat != null) {
            const patch = {
                shippingCoords: { lat: conv.shipping.lat, lng: conv.shipping.lng },
                shippingCity: conv.shipping.city || '',
                shippingAddress: conv.shipping.address || '',
                shippingDistanceKm: conv.shipping.distanceKm
            };
            if (conv.shipping.method) patch.shippingMethod = conv.shipping.method;
            await deps.WebOrder.updateOne({ _id: conv.lastOrderId }, { $set: patch }).catch((err) => {
                console.error('[whatsapp] coordenadas del pedido', err.message);
            });
        }
        pushHistory(conv, 'user', incoming.text || incoming.buttonId || '[ubicación]');
        pushHistory(conv, 'assistant', guided.texts[0] || '[opción]');
        conv.updatedAt = new Date();
        await conv.save();
        return { outgoing, conv };
    }

    const userText = incoming.imageId && conv.housePhotoUrl
        ? `${incoming.text || ''} [Guardamos la foto de la casa para el moto.]`.trim()
        : (incoming.text || incoming.buttonId || '[mensaje]');
    const research = await researchCustomerMessage(incoming.text || userText, conv, deps);
    let paymentConfirmed = conv.paymentState === 'confirmado';
    if (!paymentConfirmed) {
        try {
            const paid = await require('./wa-control/models').controlModels().WaReceipt.findOne({ waId: conv.waId, status: 'confirmado' }).select('_id').lean();
            paymentConfirmed = Boolean(paid);
            if (paymentConfirmed) conv.paymentState = 'confirmado';
        } catch (err) {
            paymentConfirmed = false;
        }
    }
    const toolCtx = {
        paymentHandled: false,
        paymentIntentKey: '',
        research,
        runtime,
        paymentConfirmed,
        catalogBlocked: Boolean(research.catalogBlocked),
        userText
    };
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

    const catalogGuard = require('./wa-control/catalog');
    const collapsed = controlOutbound.collapseOutgoing(outgoing).map((reply) => {
        if (!reply.text) return reply;
        reply.text = controlText.guardCustomerReply(reply.text, { paymentConfirmed, maxDiscount: 0, motoboltDispatched: false });
        if (!research.catalogBlocked && catalogGuard.replyDeniesCatalog(reply.text) && (research.products || []).length) {
            reply.text = catalogGuard.catalogReply(research.products);
        }
        if (/pagopar rechazo/.test(controlText.normalizeText(reply.text))) {
            reply.text = 'No pude abrir el enlace de PagoPar en este intento. Si querés, lo reintento o te paso los datos de transferencia.';
        }
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
