'use strict';

const crypto = require('crypto');

const CENTRAL_CITIES = [
    'asuncion', 'asunción', 'fernando de la mora', 'lambare', 'lambaré',
    'san lorenzo', 'luque', 'capiata', 'capiatá', 'nemby', 'ñemby',
    'villa elisa', 'mariano roque alonso', 'limpio', 'san antonio',
    'ypane', 'ypané', 'itaugua', 'itauguá', 'guarambare', 'guarambaré',
    'j. augusto saldivar', 'julian augusto saldivar', 'j.a. saldivar',
    'aregua', 'areguá', 'ita', 'itá'
];

const DEFAULT_STORE = {
    lat: -25.28646,
    lng: -57.647,
    mapsUrl: 'https://share.google/39F8jWwL96lFY65Th',
    address: 'Ferumishop, Asunción - Paraguay',
    motoboltMaxKm: 40
};

const FULFILLMENT = {
    PENDIENTE_PAGO: 'pendiente_pago',
    PAGADO: 'pagado',
    PREPARANDO: 'preparando',
    PREPARADO: 'preparado',
    ESPERANDO_MOTOBOLT: 'esperando_motobolt',
    ENVIANDO: 'enviando',
    ESPERANDO_RETIRO: 'esperando_retiro',
    ENTREGADO: 'entregado',
    CANCELADO: 'cancelado',
    DEVUELTO: 'devuelto'
};

const TRACKING_META = {
    pendiente_pago: { title: 'Esperando pago', detail: 'Estamos esperando la confirmación de tu pago.', icon: 'fa-clock', tone: 'warn' },
    pagado: { title: 'Pagado', detail: 'Recibimos tu pago. En minutos empieza la preparación.', icon: 'fa-check-circle', tone: 'ok' },
    preparando: { title: 'Preparando', detail: 'Estamos armando tu pedido con mucho cuidado.', icon: 'fa-box-open', tone: 'info' },
    preparado: { title: 'Preparado', detail: 'Tu pedido ya está listo.', icon: 'fa-clipboard-check', tone: 'ok' },
    esperando_motobolt: { title: 'Esperando Motobolt', detail: 'Pedí tu Motobolt ahora. Te pasamos la ubicación de Ferumishop.', icon: 'fa-motorcycle', tone: 'info' },
    enviando: { title: 'En camino', detail: 'Tu pedido va con transportadora hacia el interior.', icon: 'fa-truck', tone: 'info' },
    esperando_retiro: { title: 'Listo para retirar', detail: 'Podés pasar a buscarlo por Ferumishop. Si elegiste efectivo, pagás al retirar.', icon: 'fa-store', tone: 'info' },
    entregado: { title: 'Entregado', detail: '¡Pedido entregado! Gracias por comprar en FERUMI.', icon: 'fa-heart', tone: 'ok' },
    cancelado: { title: 'Cancelado', detail: 'Este pedido fue cancelado.', icon: 'fa-times-circle', tone: 'bad' },
    devuelto: { title: 'Devuelto', detail: 'Se registró una devolución. Stock y dinero se revierten.', icon: 'fa-undo', tone: 'bad' }
};

function haversineKm(lat1, lon1, lat2, lon2) {
    const toRad = (v) => (Number(v) * Math.PI) / 180;
    const R = 6371;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a = Math.sin(dLat / 2) ** 2 +
        Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function normalizeCity(city) {
    return String(city || '')
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .trim();
}

function isCentralCity(city) {
    const n = normalizeCity(city);
    if (!n) return false;
    return CENTRAL_CITIES.some((c) => normalizeCity(c) === n || n.includes(normalizeCity(c)));
}

function storeFromConfig(siteConfig) {
    return {
        lat: Number(siteConfig?.storeLat) || DEFAULT_STORE.lat,
        lng: Number(siteConfig?.storeLng) || DEFAULT_STORE.lng,
        mapsUrl: siteConfig?.storeMapsUrl || DEFAULT_STORE.mapsUrl,
        address: siteConfig?.storeAddress || DEFAULT_STORE.address,
        motoboltMaxKm: Number(siteConfig?.motoboltMaxKm) || DEFAULT_STORE.motoboltMaxKm
    };
}

function shippingOptions({ lat, lng, city, siteConfig }) {
    const store = storeFromConfig(siteConfig);
    let distanceKm = null;
    if (lat != null && lng != null && !Number.isNaN(Number(lat)) && !Number.isNaN(Number(lng))) {
        distanceKm = Math.round(haversineKm(store.lat, store.lng, Number(lat), Number(lng)) * 10) / 10;
    }

    const central = isCentralCity(city) || (distanceKm != null && distanceKm <= store.motoboltMaxKm);
    const far = distanceKm != null ? distanceKm > store.motoboltMaxKm : !central;

    const options = [];

    if (central && !far) {
        options.push({
            id: 'motobolt',
            icon: 'fa-motorcycle',
            label: 'Motobolt (Gran Asunción / Central)',
            easyTitle: 'Moto a tu casa',
            easyText: 'Vos pedís Motobolt. En 1 hora lo despachamos.',
            cost: 0,
            eta: 'Despacho en 1 hora como máximo',
            detail: 'Cuando el pedido esté preparado te escribimos. Pedís Motobolt vos, te pasamos la ubicación de Ferumishop y el moto retira. El costo del moto lo pagás al conductor.'
        });
    }

    if (far || !central) {
        options.push({
            id: 'transportadora',
            icon: 'fa-truck',
            label: 'Transportadora al interior',
            easyTitle: 'Encomienda al interior',
            easyText: 'Va por transportadora. Te avisamos para coordinar.',
            cost: 0,
            eta: 'Coordinamos el envío al interior',
            detail: 'Estás lejos para Motobolt. Enviamos por transportadora. Nos comunicamos para coordinar agencia y datos de retiro.'
        });
    } else {
        options.push({
            id: 'transportadora',
            icon: 'fa-truck',
            label: 'Transportadora',
            easyTitle: 'Encomienda',
            easyText: 'Si preferís envío por encomienda, coordinamos agencia.',
            cost: 0,
            eta: 'Si preferís envío por encomienda',
            detail: 'Opción extra si no querés Motobolt. Coordinamos agencia.'
        });
    }

    options.push({
        id: 'retiro',
        icon: 'fa-store',
        label: 'Retiro en Ferumishop',
        easyTitle: 'Paso a buscar',
        easyText: 'Retirás en el local. Acá sí podés pagar en efectivo.',
        cost: 0,
        eta: 'Cuando esté preparado',
        detail: 'Pasás a retirar por el local. Es el único modo que admite pago en efectivo al retirar. También podés pagar online con Pagopar.'
    });

    return {
        distanceKm,
        central: Boolean(central && !far),
        far: Boolean(far),
        store,
        options
    };
}

function randomCode(bytes = 4) {
    return crypto.randomBytes(bytes).toString('hex').toUpperCase();
}

function makeTicketCode() {
    return 'FM-' + randomCode(4);
}

function makeOrderNumber() {
    const d = new Date();
    const y = String(d.getFullYear()).slice(-2);
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `FER-${y}${m}${day}-${randomCode(3)}`;
}

function parsePrice(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return Math.round(value);
    if (!value) return 0;
    return parseInt(String(value).replace(/\./g, '').replace(/,/g, ''), 10) || 0;
}

function normalizePhone(phone) {
    let p = String(phone || '').replace(/\D/g, '');
    if (p.startsWith('09')) p = '595' + p.substring(1);
    if (p.startsWith('9') && p.length === 9) p = '595' + p;
    return p;
}

function phonesMatch(stored, query) {
    const a = normalizePhone(stored);
    const b = normalizePhone(query);
    if (!a || !b) return false;
    return a === b || a.endsWith(b) || b.endsWith(a);
}

function trackingLabel(status) {
    return TRACKING_META[status] || TRACKING_META.pendiente_pago;
}

function nextAfterPrepared(order) {
    if (order.shippingMethod === 'motobolt') return FULFILLMENT.ESPERANDO_MOTOBOLT;
    if (order.shippingMethod === 'retiro') return FULFILLMENT.ESPERANDO_RETIRO;
    return FULFILLMENT.ENVIANDO;
}

function appendEvent(order, status, extraDetail) {
    const meta = trackingLabel(status);
    order.fulfillmentStatus = status;
    if (status === 'pagado' || status === 'cancelado') {
        order.status = status === 'pagado' ? 'pagado' : 'cancelado';
        order.paymentStatus = status === 'pagado' ? 'pagado' : 'cancelado';
    }
    if (status === 'devuelto') {
        order.status = 'cancelado';
        order.paymentStatus = 'reembolsado';
    }
    order.trackingEvents = order.trackingEvents || [];
    const last = order.trackingEvents[order.trackingEvents.length - 1];
    if (last && last.status === status) {
        if (extraDetail) last.detail = extraDetail;
        last.at = new Date();
        return order;
    }
    order.trackingEvents.push({
        status,
        title: meta.title,
        detail: extraDetail || meta.detail,
        at: new Date()
    });
    return order;
}

function variantNameFromItem(item) {
    if (item.variantName) return item.variantName;
    if (!item.name) return '';
    const parts = String(item.name).split(' - ');
    return parts.length > 1 ? parts.slice(1).join(' - ').trim() : '';
}

async function deductStock(Product, order) {
    if (!order || order.stockDeducted) return { ok: true, skipped: true };
    for (const item of order.items || []) {
        if (!item.productId) continue;
        const qty = parseInt(item.quantity, 10) || 1;
        const product = await Product.findById(item.productId);
        if (!product) continue;
        const variantName = variantNameFromItem(item);
        if (product.hasVariants && variantName) {
            const idx = product.variants.findIndex((v) => v.name === variantName);
            if (idx > -1) {
                if (product.variants[idx].stock < qty) {
                    throw new Error(`Sin stock suficiente: ${product.name} (${variantName})`);
                }
                product.variants[idx].stock -= qty;
                product.stock = product.variants.reduce((s, v) => s + (v.stock || 0), 0);
            }
        } else {
            if ((product.stock || 0) < qty) {
                throw new Error(`Sin stock suficiente: ${product.name}`);
            }
            product.stock -= qty;
        }
        await product.save();
    }
    order.stockDeducted = true;
    return { ok: true };
}

async function restoreStock(Product, order) {
    if (!order || !order.stockDeducted) return { ok: true, skipped: true };
    for (const item of order.items || []) {
        if (!item.productId) continue;
        const qty = parseInt(item.quantity, 10) || 1;
        const product = await Product.findById(item.productId);
        if (!product) continue;
        const variantName = variantNameFromItem(item);
        if (product.hasVariants && variantName) {
            const idx = product.variants.findIndex((v) => v.name === variantName);
            if (idx > -1) {
                product.variants[idx].stock += qty;
                product.stock = product.variants.reduce((s, v) => s + (v.stock || 0), 0);
            }
        } else {
            product.stock = (product.stock || 0) + qty;
        }
        await product.save();
    }
    order.stockDeducted = false;
    return { ok: true };
}

async function ensureStockAvailable(Product, items) {
    for (const item of items) {
        if (!item.productId) continue;
        const qty = parseInt(item.quantity, 10) || 1;
        const product = await Product.findById(item.productId);
        if (!product) throw new Error(`Producto no encontrado: ${item.name || item.productId}`);
        const variantName = variantNameFromItem(item);
        if (product.hasVariants && variantName) {
            const variant = product.variants.find((v) => v.name === variantName);
            if (!variant || variant.stock < qty) {
                throw new Error(`Sin stock: ${product.name} ${variantName || ''}`.trim());
            }
        } else if ((product.stock || 0) < qty) {
            throw new Error(`Sin stock: ${product.name}`);
        }
        item.price = product.price;
        item.name = variantName ? `${product.name} - ${variantName}` : product.name;
        item.image = item.image || (product.photos && product.photos[0]) || '';
    }
    return items;
}

function cajaSplit(totalAmount, itemsCost) {
    const costoReposicion = itemsCost || 0;
    let reinvestment = 0;
    let profitNando = 0;
    let profitMayu = 0;
    if (totalAmount > costoReposicion) {
        const gananciaBruta = totalAmount - costoReposicion;
        let gananciaRestante = 0;
        if (gananciaBruta >= costoReposicion) {
            reinvestment = costoReposicion;
            gananciaRestante = gananciaBruta - reinvestment;
        } else {
            reinvestment = Math.floor(gananciaBruta / 2);
            gananciaRestante = gananciaBruta - reinvestment;
        }
        profitNando = Math.floor(gananciaRestante / 2);
        profitMayu = gananciaRestante - profitNando;
    }
    return { cost: costoReposicion, reinvestment, profitNando, profitMayu };
}

function whatsappLink(phone, text) {
    const num = normalizePhone(phone);
    return `https://wa.me/${num}?text=${encodeURIComponent(text)}`;
}

function customerWhatsAppText(order, siteConfig, kind) {
    const store = storeFromConfig(siteConfig);
    const items = (order.items || []).map((i) => `• ${i.quantity}x ${i.name}`).join('\n');
    const maps = store.mapsUrl;
    if (kind === 'preparado_motobolt') {
        return `Hola ${order.customerName}! 💖 Tu pedido ${order.orderNumber} de FERUMI ya está PREPARADO.\n\nPedí tu Motobolt ahora.\nUbicación de Ferumishop:\n${maps}\n${store.address}\n\n${items}\nTotal: ${order.totalAmount} Gs.\nTicket: ${order.ticketCode}`;
    }
    if (kind === 'preparado_retiro') {
        return `Hola ${order.customerName}! 💖 Tu pedido ${order.orderNumber} ya está listo para RETIRAR en Ferumishop.\n\n${maps}\n${store.address}\n\n${items}\nTotal: ${order.totalAmount} Gs.${order.paymentMethod === 'efectivo_retiro' ? '\nPagás en efectivo al retirar.' : '\nYa está pagado con Pagopar.'}\nTicket: ${order.ticketCode}`;
    }
    if (kind === 'preparado_envio') {
        return `Hola ${order.customerName}! 💖 Tu pedido ${order.orderNumber} ya está preparado. En breve coordinamos la transportadora al interior.\n\n${items}\nTotal: ${order.totalAmount} Gs.\nTicket: ${order.ticketCode}`;
    }
    return `Hola ${order.customerName}! Te escribimos de FERUMI por tu pedido ${order.orderNumber}.`;
}

function publicPedidoUrl(idOrCode) {
    const base = String(process.env.BASE_URL || 'https://www.ferumi.shop').replace(/\/$/, '');
    return `${base}/pedido/${encodeURIComponent(idOrCode)}`;
}

function extractScanCode(raw) {
    let code = String(raw || '').trim();
    if (!code) return '';
    if (code.includes('|')) {
        const parts = code.split('|').map((s) => s.trim()).filter(Boolean);
        code = parts[parts.length - 1] || code;
    }
    const marker = '/pedido/';
    const idx = code.toLowerCase().lastIndexOf(marker);
    if (idx !== -1) {
        code = code.slice(idx + marker.length);
        code = code.split(/[?#]/)[0];
    }
    try { code = decodeURIComponent(code); } catch { /* keep raw */ }
    return code.replace(/\/+$/, '').trim();
}

function deliveryPedidoFromWebOrder(order) {
    const lat = order.shippingCoords && order.shippingCoords.lat != null ? order.shippingCoords.lat : '';
    const lng = order.shippingCoords && order.shippingCoords.lng != null ? order.shippingCoords.lng : '';
    const address = [order.shippingAddress, order.shippingCity, order.shippingReference].filter(Boolean).join(', ');
    return {
        id: String(order._id),
        cliente: order.customerName || 'Cliente',
        telefonoOriginal: order.customerPhone || '',
        telefonoWa: normalizePhone(order.customerPhone),
        items: (order.items || []).map((item) => ({
            nombre: `${item.quantity || 1}x ${item.name}${item.variantName ? ` (${item.variantName})` : ''}`,
            precio: (item.price || 0) * (item.quantity || 1)
        })),
        total: order.totalAmount || 0,
        lat,
        lng,
        fecha: order.createdAt || new Date(),
        address,
        housePhotoUrl: order.housePhotoUrl || '',
        orderNumber: order.orderNumber || '',
        ticketCode: order.ticketCode || '',
        shippingLabel: order.shippingMethod || ''
    };
}

function thermalPedidoFromWebOrder(order) {
    const shipLabels = {
        motobolt: 'Motobolt',
        transportadora: 'Transportadora',
        retiro: 'Retiro en local'
    };
    return {
        id: String(order._id),
        source: 'web',
        cliente: order.customerName || 'Cliente',
        phone: order.customerPhone || '',
        items: (order.items || []).map((item) => ({
            nombre: `${item.quantity || 1}x ${item.name}${item.variantName ? ` (${item.variantName})` : ''}`,
            precio: (item.price || 0) * (item.quantity || 1)
        })),
        total: order.totalAmount || 0,
        fecha: order.createdAt || new Date(),
        ticketCode: order.ticketCode || '',
        orderNumber: order.orderNumber || '',
        shippingLabel: shipLabels[order.shippingMethod] || order.shippingMethod || '',
        qrPayload: publicPedidoUrl(order.ticketCode || String(order._id)),
        qrHint: 'Preparar / Motobolt'
    };
}

function thermalPedidoFromTransaction(tx) {
    let lat = '';
    let lng = '';
    if (tx.locationCoords) {
        const coords = String(tx.locationCoords).split(',');
        if (coords.length === 2) {
            lat = coords[0].trim();
            lng = coords[1].trim();
        }
    }
    return {
        id: String(tx._id),
        source: 'caja',
        cliente: tx.customerName || 'Cliente Local',
        phone: tx.customerPhone || '',
        items: [{ nombre: tx.description, precio: tx.amount }],
        total: tx.amount,
        fecha: tx.date,
        lat,
        lng,
        ticketCode: '',
        orderNumber: '',
        shippingLabel: '',
        qrPayload: publicPedidoUrl(String(tx._id)),
        qrHint: 'Preparar / Motobolt'
    };
}

function publicOrderView(order) {
    const events = (order.trackingEvents || []).map((e) => ({
        status: e.status,
        title: e.title,
        detail: e.detail,
        at: e.at
    }));
    return {
        id: String(order._id),
        orderNumber: order.orderNumber,
        ticketCode: order.ticketCode,
        customerName: order.customerName,
        customerPhone: order.customerPhone,
        customerEmail: order.customerEmail,
        customerDocument: order.customerDocument,
        items: order.items,
        subtotal: order.subtotal,
        shippingCost: order.shippingCost || 0,
        totalAmount: order.totalAmount,
        paymentMethod: order.paymentMethod,
        paymentStatus: order.paymentStatus || order.status,
        shippingMethod: order.shippingMethod,
        shippingAddress: order.shippingAddress,
        shippingCity: order.shippingCity,
        shippingDistanceKm: order.shippingDistanceKm,
        housePhotoUrl: order.housePhotoUrl,
        fulfillmentStatus: order.fulfillmentStatus,
        tracking: trackingLabel(order.fulfillmentStatus),
        events,
        createdAt: order.createdAt,
        pagoparHash: order.pagoparHash,
        pagoparNumero: order.pagoparNumero
    };
}

module.exports = {
    CENTRAL_CITIES,
    DEFAULT_STORE,
    FULFILLMENT,
    TRACKING_META,
    haversineKm,
    isCentralCity,
    storeFromConfig,
    shippingOptions,
    randomCode,
    makeTicketCode,
    makeOrderNumber,
    parsePrice,
    normalizePhone,
    phonesMatch,
    trackingLabel,
    nextAfterPrepared,
    appendEvent,
    deductStock,
    restoreStock,
    ensureStockAvailable,
    cajaSplit,
    whatsappLink,
    customerWhatsAppText,
    publicOrderView,
    publicPedidoUrl,
    extractScanCode,
    deliveryPedidoFromWebOrder,
    thermalPedidoFromWebOrder,
    thermalPedidoFromTransaction,
    variantNameFromItem
};
